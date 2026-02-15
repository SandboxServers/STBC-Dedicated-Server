/* ================================================================
 * Function Call Tracer - lightweight C++ call tracing with optional
 * caller tracking (return address histogram).
 *
 * Two trampoline modes:
 *   COUNT_ONLY (32 bytes): INC [counter] + prologue + JMP back
 *   WITH_CALLERS (48 bytes): save regs, call C callback that records
 *     unique caller addresses, restore regs + prologue + JMP back
 *
 * Output: periodic dump to ddraw_proxy.log every 300 ticks.
 * Counters reset via Python raise "FTRACE_RESET:<label>" through
 * the ReplacementDebugConsole exception handler.
 * ================================================================ */

#define FTRACE_MAX_HOOKS    64
#define FTRACE_MAX_CALLERS  16  /* unique caller slots per hook */
#define FTRACE_TRAMP_SMALL  32  /* count-only trampoline */
#define FTRACE_TRAMP_LARGE  48  /* caller-tracking trampoline */

typedef struct {
    DWORD addr;
    volatile LONG count;
} FTraceCaller;

typedef struct {
    DWORD   addr;             /* original function address */
    char    name[40];         /* human-readable name */
    int     relocLen;         /* bytes to relocate (5-9) */
    BYTE    savedBytes[16];   /* saved prologue */
    BYTE    expectedBytes[16];/* for validation at install */
    BYTE*   trampoline;       /* ptr into trampoline block */
    volatile LONG callCount;  /* atomic counter */
    BOOL    installed;        /* TRUE if hook is active */
    BOOL    trackCallers;     /* TRUE = use large trampoline with C callback */
    FTraceCaller callers[FTRACE_MAX_CALLERS];
    volatile LONG callerCount;/* number of unique callers recorded */
} FTraceHook;

static FTraceHook g_ftHooks[FTRACE_MAX_HOOKS];
static int g_ftHookCount = 0;
static BYTE* g_ftTrampBlock = NULL;  /* VirtualAlloc'd RWX block */

/* ----------------------------------------------------------------
 * FTraceRecordCall - C callback from caller-tracking trampolines
 *
 * Called with all caller-saved regs preserved. Records the return
 * address in a per-hook histogram of unique callers.
 * ---------------------------------------------------------------- */
static void __cdecl FTraceRecordCall(int hookIdx, DWORD callerAddr) {
    FTraceHook* h;
    int i, slot;

    if (hookIdx < 0 || hookIdx >= g_ftHookCount) return;
    h = &g_ftHooks[hookIdx];

    InterlockedIncrement(&h->callCount);

    /* Search for existing caller */
    for (i = 0; i < h->callerCount && i < FTRACE_MAX_CALLERS; i++) {
        if (h->callers[i].addr == callerAddr) {
            InterlockedIncrement(&h->callers[i].count);
            return;
        }
    }

    /* Add new caller if space remains */
    slot = (int)InterlockedIncrement(&h->callerCount) - 1;
    if (slot < FTRACE_MAX_CALLERS) {
        h->callers[slot].addr = callerAddr;
        h->callers[slot].count = 1;
    } else {
        /* Table full, just decrement back */
        InterlockedDecrement(&h->callerCount);
    }
}

/* ----------------------------------------------------------------
 * FTraceRegister - register a hook (does not install yet)
 *   trackCallers=TRUE uses the large trampoline with C callback
 * ---------------------------------------------------------------- */
static int FTraceRegister(DWORD addr, int relocLen, const BYTE* expectedBytes,
                          const char* name, BOOL trackCallers) {
    FTraceHook* h;
    if (g_ftHookCount >= FTRACE_MAX_HOOKS) return -1;
    if (relocLen < 5 || relocLen > 15) return -1;

    h = &g_ftHooks[g_ftHookCount];
    h->addr = addr;
    h->relocLen = relocLen;
    h->callCount = 0;
    h->installed = FALSE;
    h->trackCallers = trackCallers;
    h->trampoline = NULL;
    h->callerCount = 0;
    lstrcpynA(h->name, name, sizeof(h->name));
    memcpy(h->expectedBytes, expectedBytes, relocLen);
    memset(h->savedBytes, 0, sizeof(h->savedBytes));
    memset(h->callers, 0, sizeof(h->callers));

    return g_ftHookCount++;
}

/* ----------------------------------------------------------------
 * FTraceResolveCaller - try to map a return address to a hook name
 *
 * If callerAddr falls within the first 0x400 bytes of a hooked
 * function, return that hook's name.  Otherwise return NULL.
 * ---------------------------------------------------------------- */
static const char* FTraceResolveCaller(DWORD callerAddr) {
    int i;
    for (i = 0; i < g_ftHookCount; i++) {
        if (callerAddr >= g_ftHooks[i].addr &&
            callerAddr < g_ftHooks[i].addr + 0x400)
            return g_ftHooks[i].name;
    }
    return NULL;
}

/* ----------------------------------------------------------------
 * FTraceInstallOne - build trampoline and patch one function
 *
 * COUNT_ONLY trampoline (32 bytes):
 *   [0]    FF 05 <addr32>          INC DWORD PTR [&callCount]
 *   [6]    <relocated prologue>    (relocLen bytes)
 *   [6+N]  E9 <rel32>             JMP (originalAddr + relocLen)
 *
 * WITH_CALLERS trampoline (48 bytes):
 *   [0]    9C                      PUSHFD
 *   [1]    50                      PUSH EAX
 *   [2]    51                      PUSH ECX
 *   [3]    52                      PUSH EDX
 *   [4]    8B 44 24 10             MOV EAX, [ESP+0x10]  ; return addr
 *   [8]    50                      PUSH EAX             ; arg2: caller
 *   [9]    68 <imm32>              PUSH hookIndex       ; arg1: index
 *   [14]   E8 <rel32>              CALL FTraceRecordCall
 *   [19]   83 C4 08                ADD ESP, 8
 *   [22]   5A                      POP EDX
 *   [23]   59                      POP ECX
 *   [24]   58                      POP EAX
 *   [25]   9D                      POPFD
 *   [26]   <relocated prologue>    (relocLen bytes)
 *   [26+N] E9 <rel32>             JMP (originalAddr + relocLen)
 * ---------------------------------------------------------------- */
static BOOL FTraceInstallOne(int idx) {
    FTraceHook* h = &g_ftHooks[idx];
    BYTE* tramp;
    BYTE* func;
    DWORD oldProt;
    DWORD jmpTarget;
    int offset;
    int trampSize = h->trackCallers ? FTRACE_TRAMP_LARGE : FTRACE_TRAMP_SMALL;

    if (h->installed) return TRUE;

    /* Validate address is readable */
    func = (BYTE*)h->addr;
    if (IsBadReadPtr(func, h->relocLen)) {
        ProxyLog("  FTrace: SKIP [%2d] %-30s @ 0x%08X - address not readable",
                 idx, h->name, h->addr);
        return FALSE;
    }

    /* Validate expected bytes match (version safety) */
    if (memcmp(func, h->expectedBytes, h->relocLen) != 0) {
        ProxyLog("  FTrace: SKIP [%2d] %-30s @ 0x%08X - bytes mismatch "
                 "(got %02X %02X %02X %02X %02X, want %02X %02X %02X %02X %02X)",
                 idx, h->name, h->addr,
                 func[0], func[1], func[2], func[3], func[4],
                 h->expectedBytes[0], h->expectedBytes[1], h->expectedBytes[2],
                 h->expectedBytes[3], h->expectedBytes[4]);
        return FALSE;
    }

    /* Save original prologue bytes */
    memcpy(h->savedBytes, func, h->relocLen);

    /* Build trampoline */
    tramp = h->trampoline;
    offset = 0;

    if (h->trackCallers) {
        /* --- Large trampoline: save regs, call C callback --- */
        DWORD callTarget;

        tramp[offset++] = 0x9C;                       /* PUSHFD */
        tramp[offset++] = 0x50;                       /* PUSH EAX */
        tramp[offset++] = 0x51;                       /* PUSH ECX */
        tramp[offset++] = 0x52;                       /* PUSH EDX */

        /* MOV EAX, [ESP+0x10] — return addr past 4 pushes */
        tramp[offset++] = 0x8B;
        tramp[offset++] = 0x44;
        tramp[offset++] = 0x24;
        tramp[offset++] = 0x10;

        tramp[offset++] = 0x50;                       /* PUSH EAX (arg2: callerAddr) */

        tramp[offset++] = 0x68;                       /* PUSH imm32 (arg1: hookIdx) */
        *(DWORD*)(tramp + offset) = (DWORD)idx;
        offset += 4;

        tramp[offset] = 0xE8;                         /* CALL FTraceRecordCall */
        callTarget = (DWORD)FTraceRecordCall - ((DWORD)(tramp + offset) + 5);
        *(DWORD*)(tramp + offset + 1) = callTarget;
        offset += 5;

        tramp[offset++] = 0x83;                       /* ADD ESP, 8 */
        tramp[offset++] = 0xC4;
        tramp[offset++] = 0x08;

        tramp[offset++] = 0x5A;                       /* POP EDX */
        tramp[offset++] = 0x59;                       /* POP ECX */
        tramp[offset++] = 0x58;                       /* POP EAX */
        tramp[offset++] = 0x9D;                       /* POPFD */
    } else {
        /* --- Small trampoline: INC counter only --- */
        tramp[offset++] = 0xFF;                       /* INC DWORD PTR [&callCount] */
        tramp[offset++] = 0x05;
        *(DWORD*)(tramp + offset) = (DWORD)&h->callCount;
        offset += 4;
    }

    /* Copy relocated prologue */
    memcpy(tramp + offset, h->savedBytes, h->relocLen);
    offset += h->relocLen;

    /* JMP back to original + relocLen */
    tramp[offset] = 0xE9;
    jmpTarget = (h->addr + h->relocLen) - ((DWORD)(tramp + offset) + 5);
    *(DWORD*)(tramp + offset + 1) = jmpTarget;
    offset += 5;

    /* NOP pad remainder */
    while (offset < trampSize)
        tramp[offset++] = 0x90;

    /* Patch original function: JMP to trampoline */
    if (!VirtualProtect(func, h->relocLen, PAGE_EXECUTE_READWRITE, &oldProt)) {
        ProxyLog("  FTrace: SKIP [%2d] %-30s @ 0x%08X - VirtualProtect failed",
                 idx, h->name, h->addr);
        return FALSE;
    }

    func[0] = 0xE9;
    *(DWORD*)(func + 1) = (DWORD)tramp - ((DWORD)func + 5);
    {
        int i;
        for (i = 5; i < h->relocLen; i++)
            func[i] = 0x90;
    }

    VirtualProtect(func, h->relocLen, oldProt, &oldProt);
    h->installed = TRUE;

    return TRUE;
}

/* ----------------------------------------------------------------
 * FTraceDump - log all non-zero counters with caller breakdown
 * ---------------------------------------------------------------- */
static void FTraceDump(const char* label) {
    int i, any = 0;
    ProxyLog("=== FTRACE DUMP: %s ===", label);
    for (i = 0; i < g_ftHookCount; i++) {
        if (!g_ftHooks[i].installed) continue;
        if (g_ftHooks[i].callCount > 0) {
            ProxyLog("  [%2d] %-30s %8ld%s", i, g_ftHooks[i].name,
                     (long)g_ftHooks[i].callCount,
                     g_ftHooks[i].trackCallers ? " [callers]" : "");
            any = 1;

            /* Print caller breakdown for tracked hooks */
            if (g_ftHooks[i].trackCallers) {
                int c;
                int nc = g_ftHooks[i].callerCount;
                if (nc > FTRACE_MAX_CALLERS) nc = FTRACE_MAX_CALLERS;
                for (c = 0; c < nc; c++) {
                    const char* resolved = FTraceResolveCaller(
                        g_ftHooks[i].callers[c].addr);
                    if (resolved) {
                        ProxyLog("         from 0x%08X (%s) x%ld",
                                 g_ftHooks[i].callers[c].addr,
                                 resolved,
                                 (long)g_ftHooks[i].callers[c].count);
                    } else {
                        ProxyLog("         from 0x%08X x%ld",
                                 g_ftHooks[i].callers[c].addr,
                                 (long)g_ftHooks[i].callers[c].count);
                    }
                }
            }
        }
    }
    if (!any)
        ProxyLog("  (all counters zero)");
}

/* ----------------------------------------------------------------
 * FTraceReset - dump snapshot then zero all counters + callers
 * ---------------------------------------------------------------- */
static void FTraceReset(const char* label) {
    int i;
    FTraceDump(label);
    ProxyLog("=== FTRACE RESET: %s ===", label);
    for (i = 0; i < g_ftHookCount; i++) {
        InterlockedExchange(&g_ftHooks[i].callCount, 0);
        if (g_ftHooks[i].trackCallers) {
            memset(g_ftHooks[i].callers, 0, sizeof(g_ftHooks[i].callers));
            InterlockedExchange(&g_ftHooks[i].callerCount, 0);
        }
    }
}

/* ----------------------------------------------------------------
 * Hook table definition and installation
 *
 * trackCallers=TRUE on hooks where we need to see WHO is calling:
 *   - Ship_AddSubsystem: our DeferredInitObject vs engine InitObject
 *   - Damage pipeline: who triggers damage events
 *   - ObjectFactory: who creates ship objects
 *   - ApplyHullDamage / DoDamage / ProcessDamage: damage chain
 *   - CheckCollision: collision entry point
 *
 * trackCallers=FALSE on high-frequency hooks (events, net state)
 *   to avoid per-call overhead on functions that fire 100s/sec.
 * ---------------------------------------------------------------- */
static void InstallFunctionTracer(void) {
    int i, installed = 0;
    int trampOffset = 0;

    /* Allocate one contiguous RWX block for all trampolines.
     * Use FTRACE_TRAMP_LARGE for all slots (wastes a few bytes
     * on small trampolines but simplifies offset math). */
    g_ftTrampBlock = (BYTE*)VirtualAlloc(NULL,
        FTRACE_MAX_HOOKS * FTRACE_TRAMP_LARGE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_ftTrampBlock) {
        ProxyLog("FTrace: FATAL - VirtualAlloc failed for trampoline block");
        return;
    }
    memset(g_ftTrampBlock, 0xCC, FTRACE_MAX_HOOKS * FTRACE_TRAMP_LARGE);

    g_ftHookCount = 0;

    /* --- Ship Creation (6) --- */
    /* trackCallers=TRUE: need to see engine vs our Python path */
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0x71,0xD9,0x87,0x00};
        FTraceRegister(0x0069f620, 7, b, "MPG_ObjectProcessor", TRUE);
    }
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0xD8,0xB5,0x87,0x00};
        FTraceRegister(0x005a1f50, 7, b, "ObjectFactory", TRUE);
    }
    {
        static const BYTE b[] = {0xA1,0x78,0xA5,0x99,0x00,0x56,0x57};
        FTraceRegister(0x006f13e0, 7, b, "TypeFactory", TRUE);
    }
    {
        static const BYTE b[] = {0x56,0x8B,0x74,0x24,0x08,0x57};
        FTraceRegister(0x0057a280, 6, b, "Ship_WriteStream", TRUE);
    }
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0xA8,0x44,0x87,0x00};
        FTraceRegister(0x0047dab0, 7, b, "NetObjTracker_ctor", FALSE);
    }
    {
        static const BYTE b[] = {0x51,0x53,0x8B,0xD9,0x56};
        FTraceRegister(0x005b3e50, 5, b, "Ship_AddSubsystem", TRUE);
    }

    /* --- Damage Pipeline (5) --- */
    /* trackCallers=TRUE: trace the full damage chain */
    {
        static const BYTE b[] = {0x53,0x55,0x56,0x8B,0x74,0x24,0x10};
        FTraceRegister(0x005af010, 7, b, "WeaponHitHandler", TRUE);
    }
    {
        static const BYTE b[] = {0x8B,0x44,0x24,0x04,0x8B,0x50,0x2C};
        FTraceRegister(0x005af420, 7, b, "ApplyHullDamage", TRUE);
    }
    {
        static const BYTE b[] = {0x64,0xA1,0x00,0x00,0x00,0x00};
        FTraceRegister(0x00594020, 6, b, "DoDamage", TRUE);
    }
    {
        static const BYTE b[] = {0x53,0x8B,0x5C,0x24,0x08};
        FTraceRegister(0x00593e50, 5, b, "ProcessDamage", TRUE);
    }
    {
        static const BYTE b[] = {0x83,0xEC,0x08,0x53,0x55,0x56,0x57};
        FTraceRegister(0x005671d0, 7, b, "CheckCollision", TRUE);
    }

    /* --- State Update (3) --- */
    /* trackCallers=FALSE: high frequency, just need counts */
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0xBB,0xB9,0x87,0x00};
        FTraceRegister(0x005b17f0, 7, b, "Ship_WriteNetState", FALSE);
    }
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0xD8,0xB9,0x87,0x00};
        FTraceRegister(0x005b21c0, 7, b, "Ship_ReadNetState", FALSE);
    }
    {
        /* MOV [ESP+4],0x0 is 8 bytes (C7 44 24 04 00 00 00 00),
         * so relocLen must be 12 to reach the next instruction boundary */
        static const BYTE b[] = {0x51,0x56,0x8B,0xF1,0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00};
        FTraceRegister(0x005b5eb0, 12, b, "SubsystemHash", FALSE);
    }

    /* --- Handshake / Join (2) --- */
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0x36,0xDC,0x87,0x00};
        FTraceRegister(0x006a1b10, 7, b, "ChecksumComplete", FALSE);
    }
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0x4B,0xDC,0x87,0x00};
        FTraceRegister(0x006a1e70, 7, b, "NewPlayerInGame", FALSE);
    }

    /* --- Python Bridge (2) --- */
    {
        static const BYTE b[] = {0x64,0xA1,0x00,0x00,0x00,0x00};
        FTraceRegister(0x006f7d90, 6, b, "PyModuleDispatcher", FALSE);
    }
    {
        static const BYTE b[] = {0x64,0xA1,0x00,0x00,0x00,0x00};
        FTraceRegister(0x006f8ab0, 6, b, "TG_CallPythonFunc", FALSE);
    }

    /* --- Event System (4) --- */
    /* trackCallers=FALSE: extremely high frequency */
    {
        static const BYTE b[] = {0x53,0x8B,0x5C,0x24,0x08,0x56,0x57};
        FTraceRegister(0x006db530, 7, b, "FireEvent", FALSE);
    }
    {
        static const BYTE b[] = {0xA1,0xFC,0xAD,0x95,0x00,0x53,0x56};
        FTraceRegister(0x006da300, 7, b, "PostEvent", FALSE);
    }
    {
        static const BYTE b[] = {0x56,0x8B,0xF1,0x57,0x8B,0x7E,0x04};
        FTraceRegister(0x006e0c30, 7, b, "InvokeHandler", FALSE);
    }
    {
        static const BYTE b[] = {0x8B,0x54,0x24,0x04,0x8B,0x42,0x1C};
        FTraceRegister(0x006d90e0, 7, b, "DispatchEvent", FALSE);
    }

    /* --- Collision / Damage Entry Points (3) --- */
    /* trackCallers=TRUE: trace what triggers collision damage */
    {
        static const BYTE b[] = {0x53,0x8B,0x5C,0x24,0x08,0x56,0x57};
        FTraceRegister(0x005b0060, 7, b, "CollisionDamageWrapper", TRUE);
    }
    {
        static const BYTE b[] = {0x83,0xEC,0x24,0x56,0x8B,0xF1};
        FTraceRegister(0x00593650, 6, b, "DoDamage_FromPosition", TRUE);
    }
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0xC8,0xAF,0x87,0x00};
        FTraceRegister(0x005952d0, 7, b, "DoDamage_CollisionContacts", TRUE);
    }

    /* --- Ship Destruction / Lifecycle (2) --- */
    /* trackCallers=TRUE: need to see what triggers destruction */
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0x68,0xDA,0x87,0x00};
        FTraceRegister(0x006a01e0, 7, b, "DestroyObject_Net", TRUE);
    }
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0x53,0xDA,0x87,0x00};
        FTraceRegister(0x006a0080, 7, b, "Explosion_Net", TRUE);
    }

    /* --- Network Objects (5) --- */
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0xA8,0xDB,0x87,0x00};
        FTraceRegister(0x006a1360, 7, b, "CreateNetworkEvent", FALSE);
    }
    {
        static const BYTE b[] = {0x64,0xA1,0x00,0x00,0x00,0x00};
        FTraceRegister(0x006a17c0, 6, b, "SendNetworkObject", FALSE);
    }
    {
        static const BYTE b[] = {0x8B,0x44,0x24,0x04,0x05,0x01,0x00,0x00,0xC0};
        FTraceRegister(0x006a19a0, 9, b, "GetPlayerSlot", FALSE);
    }
    {
        static const BYTE b[] = {0x8B,0x54,0x24,0x04,0x33,0xC0,0x53};
        FTraceRegister(0x006a19c0, 7, b, "FindPlayerByNetID", FALSE);
    }
    {
        static const BYTE b[] = {0x53,0x55,0x56,0x57,0x8B,0x78,0x2C};
        FTraceRegister(0x006a19fc, 7, b, "FindNetObjByID", FALSE);
    }

    ProxyLog("FTrace: registered %d hooks, trampBlock=0x%08X (slot size=%d)",
             g_ftHookCount, (DWORD)g_ftTrampBlock, FTRACE_TRAMP_LARGE);

    /* Assign trampoline pointers and install */
    trampOffset = 0;
    for (i = 0; i < g_ftHookCount; i++) {
        g_ftHooks[i].trampoline = g_ftTrampBlock + trampOffset;
        trampOffset += FTRACE_TRAMP_LARGE;  /* uniform slot size */
        if (FTraceInstallOne(i))
            installed++;
    }

    {
        int tracked = 0;
        for (i = 0; i < g_ftHookCount; i++)
            if (g_ftHooks[i].trackCallers && g_ftHooks[i].installed) tracked++;
        ProxyLog("FTrace: installed %d/%d hooks (%d with caller tracking)",
                 installed, g_ftHookCount, tracked);
    }
}
