/* ================================================================
 * Function Call Tracer - lightweight C++ call tracing with optional
 * caller tracking (return address histogram).
 *
 * Two trampoline modes:
 *   COUNT_ONLY (32 bytes): INC [counter] + prologue + JMP back
 *   WITH_CALLERS (64 bytes): save regs, call C callback that records
 *     unique caller addresses + damage values, restore regs + prologue + JMP back
 *
 * Part 1: Per-hook/per-caller damage meters (total/max) via damageArgOffset.
 * Part 2: Per-event damage profiler with shield/subsystem breakdown via
 *   return-address swap on CollisionDmgWrapper.
 *
 * Output: periodic dump to ddraw_proxy.log every 300 ticks.
 * Counters reset via Python raise "FTRACE_RESET:<label>" through
 * the ReplacementDebugConsole exception handler.
 * ================================================================ */

#define FTRACE_MAX_HOOKS    64
#define FTRACE_MAX_CALLERS  16  /* unique caller slots per hook */
#define FTRACE_TRAMP_SMALL  32  /* count-only trampoline */
#define FTRACE_TRAMP_LARGE  64  /* caller-tracking trampoline (4-arg callback) */

typedef struct {
    DWORD addr;
    volatile LONG count;
    double dmgTotal;          /* accumulated damage through this caller */
    float  dmgMax;            /* largest single-hit damage from this caller */
} FTraceCaller;

typedef struct {
    DWORD   addr;             /* original function address */
    char    name[40];         /* human-readable name */
    int     relocLen;         /* bytes to relocate (5-15) */
    BYTE    savedBytes[16];   /* saved prologue */
    BYTE    expectedBytes[16];/* for validation at install */
    BYTE*   trampoline;       /* ptr into trampoline block */
    volatile LONG callCount;  /* atomic counter */
    BOOL    installed;        /* TRUE if hook is active */
    BOOL    trackCallers;     /* TRUE = use large trampoline with C callback */
    int     damageArgOffset;  /* offset into origArgs for damage float, -1 = disabled */
    double  dmgTotal;         /* accumulated damage through this hook */
    float   dmgMax;           /* largest single-hit damage through this hook */
    FTraceCaller callers[FTRACE_MAX_CALLERS];
    volatile LONG callerCount;/* number of unique callers recorded */
} FTraceHook;

static FTraceHook g_ftHooks[FTRACE_MAX_HOOKS];
static int g_ftHookCount = 0;
static BYTE* g_ftTrampBlock = NULL;  /* VirtualAlloc'd RWX block */

/* ================================================================
 * Damage Event Profiler (Part 2) - per-event shield/subsystem breakdown
 *
 * Uses return-address swap on CollisionDmgWrapper to capture entry
 * state (shield HP snapshot) and exit state (post-damage shield HP +
 * per-subsystem hits collected during execution).
 * ================================================================ */
#define DMG_PROF_MAX_HITS 32

typedef struct {
    BOOL     active;
    DWORD    shipPtr;
    float    preShields[6];         /* snapshot at entry */
    float    initialDamage;         /* damage arg at entry */
    float    initialEnergy;         /* energy arg at entry */
    DWORD    savedRetAddr;          /* for return-address swap */
    int      context;               /* 0=collision, 1=weapon */
    struct {
        DWORD subsysPtr;
        float damage;
        float oldHP;
        float newHP;               /* oldHP - damage, clamped to 0 */
        char  typeName[16];
    } hits[DMG_PROF_MAX_HITS];
    int      hitCount;
} DmgProfileEvent;

static DmgProfileEvent g_dmgProf;
static BYTE* g_dmgProfExitTramp = NULL;  /* VirtualAlloc'd RWX exit trampoline */
static int g_hookIdx_CollDmgWrap = -1;   /* FTrace index for CollisionDmgWrapper */
static int g_hookIdx_PerSubsysDmg = -1;  /* FTrace index for PerSubsystemDamage */

/* Forward declarations for profiler callbacks (defined after FTraceReset) */
static void OnCollisionDmgEntry(DWORD ecx, DWORD origArgsESP);
static void OnPerSubsysDmg(DWORD ecx, DWORD origArgsESP);
static void __cdecl FlushDmgEvent(void);

/* ================================================================
 * DumpPeerTransportQueues - walk ACK-outbox and retransmit queues
 *
 * Shared by server (GameLoopTimerProc) and client (ManualInputTimerProc)
 * to dump transport-layer queue state for fragment ACK debugging.
 *
 * Queue node layout: [msg_ptr:4][next_ptr:4]
 * TGMessage fields:  +0x14 seq(u16), +0x18 retx_count(u32),
 *                    +0x39 frag_idx(u8), +0x3A is_reliable(u8),
 *                    +0x3C is_fragmented(u8)
 * TGHeaderMessage:   +0x40 is_below_0x32(u8)
 * ================================================================ */
/* Forward declaration for HandleACK hook (defined after InstallFunctionTracer) */
static void InstallHandleACKHook(void);

#define ACKDIAG_MAX_ENTRIES 10

static void DumpPeerTransportQueues(DWORD peerPtr, DWORD peerID) {
    DWORD retxHead, retxCount, ackHead, ackCount;
    DWORD node;
    int i;

    if (!peerPtr || IsBadReadPtr((void*)peerPtr, 0xC0)) return;

    retxHead  = *(DWORD*)(peerPtr + 0x80);
    retxCount = *(DWORD*)(peerPtr + 0x98);
    ackHead   = *(DWORD*)(peerPtr + 0x9C);
    ackCount  = *(DWORD*)(peerPtr + 0xB4);

    /* Skip peers with empty queues */
    if (retxCount == 0 && ackCount == 0) return;

    ProxyLog("[ACK-DIAG] peer=%u retxQ=%u ackOutQ=%u", peerID, retxCount, ackCount);

    /* Walk retransmit queue (peer+0x80) */
    node = retxHead;
    for (i = 0; i < ACKDIAG_MAX_ENTRIES && node; i++) {
        DWORD msg;
        if (IsBadReadPtr((void*)node, 8)) {
            ProxyLog("[ACK-DIAG]   retx[%d] BAD node 0x%08X", i, node);
            break;
        }
        msg = *(DWORD*)node;
        if (msg && !IsBadReadPtr((void*)msg, 0x40)) {
            WORD  seq     = *(WORD*)(msg + 0x14);
            DWORD retxCnt = *(DWORD*)(msg + 0x18);
            BYTE  fragIdx = *(BYTE*)(msg + 0x39);
            BYTE  isRel   = *(BYTE*)(msg + 0x3A);
            BYTE  isFrag  = *(BYTE*)(msg + 0x3C);
            float interval = *(float*)(msg + 0x1C);
            float lastSend = *(float*)(msg + 0x20);
            ProxyLog("[ACK-DIAG]   retx[%d] msg=0x%08X seq=0x%04X frag=%d idx=%d rel=%d retx=%u intv=%.2f last=%.2f",
                     i, msg, (unsigned)seq, isFrag, fragIdx, isRel, retxCnt, interval, lastSend);
        } else {
            ProxyLog("[ACK-DIAG]   retx[%d] msg=0x%08X (bad/null)", i, msg);
        }
        node = *(DWORD*)(node + 4);
    }
    if (retxCount > ACKDIAG_MAX_ENTRIES)
        ProxyLog("[ACK-DIAG]   ... %u more retx entries", retxCount - ACKDIAG_MAX_ENTRIES);

    /* Walk ACK-outbox queue (peer+0x9C) */
    node = ackHead;
    for (i = 0; i < ACKDIAG_MAX_ENTRIES && node; i++) {
        DWORD msg;
        if (IsBadReadPtr((void*)node, 8)) {
            ProxyLog("[ACK-DIAG]   ack[%d] BAD node 0x%08X", i, node);
            break;
        }
        msg = *(DWORD*)node;
        if (msg && !IsBadReadPtr((void*)msg, 0x44)) {
            WORD  seq     = *(WORD*)(msg + 0x14);
            DWORD retxCnt = *(DWORD*)(msg + 0x18);
            BYTE  fragIdx = *(BYTE*)(msg + 0x39);
            BYTE  isFrag  = *(BYTE*)(msg + 0x3C);
            BYTE  below32 = *(BYTE*)(msg + 0x40);
            ProxyLog("[ACK-DIAG]   ack[%d] msg=0x%08X seq=0x%04X frag=%d idx=%d below32=%d retx=%u",
                     i, msg, (unsigned)seq, isFrag, fragIdx, below32, retxCnt);
        } else {
            ProxyLog("[ACK-DIAG]   ack[%d] msg=0x%08X (bad/null)", i, msg);
        }
        node = *(DWORD*)(node + 4);
    }
    if (ackCount > ACKDIAG_MAX_ENTRIES)
        ProxyLog("[ACK-DIAG]   ... %u more ack entries", ackCount - ACKDIAG_MAX_ENTRIES);
}

/* ----------------------------------------------------------------
 * FTraceRecordCallEx - C callback from caller-tracking trampolines
 *
 * Called with all caller-saved regs preserved. Records the return
 * address in a per-hook histogram of unique callers, captures damage
 * values when damageArgOffset is set, and dispatches Part 2 profiler
 * callbacks for CollisionDmgWrapper / PerSubsystemDamage hooks.
 *
 * Args (all passed via cdecl from trampoline):
 *   hookIdx     - index into g_ftHooks[]
 *   callerAddr  - return address (who called the hooked function)
 *   ecx         - ECX at entry (this ptr for __thiscall methods)
 *   origArgsESP - pointer to first stack arg of original function
 * ---------------------------------------------------------------- */
static void __cdecl FTraceRecordCallEx(int hookIdx, DWORD callerAddr,
                                       DWORD ecx, DWORD origArgsESP) {
    FTraceHook* h;
    int i, slot;
    float dmg = 0;
    BOOL hasDmg = FALSE;

    if (hookIdx < 0 || hookIdx >= g_ftHookCount) return;
    h = &g_ftHooks[hookIdx];

    InterlockedIncrement(&h->callCount);

    /* Part 1: Read damage value once if configured */
    if (h->damageArgOffset >= 0 && origArgsESP &&
        !IsBadReadPtr((void*)(origArgsESP + h->damageArgOffset), 4)) {
        dmg = *(float*)(origArgsESP + h->damageArgOffset);
        hasDmg = TRUE;
        h->dmgTotal += dmg;
        if (dmg > h->dmgMax) h->dmgMax = dmg;
    }

    /* Search for existing caller */
    for (i = 0; i < h->callerCount && i < FTRACE_MAX_CALLERS; i++) {
        if (h->callers[i].addr == callerAddr) {
            InterlockedIncrement(&h->callers[i].count);
            if (hasDmg) {
                h->callers[i].dmgTotal += dmg;
                if (dmg > h->callers[i].dmgMax) h->callers[i].dmgMax = dmg;
            }
            goto profiler_callbacks;
        }
    }

    /* Add new caller if space remains */
    slot = (int)InterlockedIncrement(&h->callerCount) - 1;
    if (slot < FTRACE_MAX_CALLERS) {
        h->callers[slot].addr = callerAddr;
        h->callers[slot].count = 1;
        if (hasDmg) {
            h->callers[slot].dmgTotal = dmg;
            h->callers[slot].dmgMax = dmg;
        }
    } else {
        /* Table full, just decrement back */
        InterlockedDecrement(&h->callerCount);
    }

profiler_callbacks:
    /* Part 2: Damage event profiler callbacks */
    if (hookIdx == g_hookIdx_CollDmgWrap) {
        OnCollisionDmgEntry(ecx, origArgsESP);
    } else if (hookIdx == g_hookIdx_PerSubsysDmg) {
        OnPerSubsysDmg(ecx, origArgsESP);
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
    h->damageArgOffset = -1;
    h->dmgTotal = 0;
    h->dmgMax = 0;
    lstrcpynA(h->name, name, sizeof(h->name));
    memcpy(h->expectedBytes, expectedBytes, relocLen);
    memset(h->savedBytes, 0, sizeof(h->savedBytes));
    memset(h->callers, 0, sizeof(h->callers));

    return g_ftHookCount++;
}

/* ----------------------------------------------------------------
 * FTraceResolveName - binary search the static function name table
 *
 * Finds the function containing `addr` by searching for the largest
 * table entry <= addr.  If the offset is within 0x2000 bytes, returns
 * the function name and optionally the offset within it.
 * ---------------------------------------------------------------- */
static const char* FTraceResolveName(DWORD addr, DWORD* outOffset) {
    int lo = 0, hi = (int)FUNC_NAME_COUNT - 1, best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (g_funcNames[mid].addr == addr) {
            if (outOffset) *outOffset = 0;
            return g_funcNames[mid].name;
        }
        if (g_funcNames[mid].addr < addr) { best = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (best >= 0 && (addr - g_funcNames[best].addr) < 0x2000) {
        if (outOffset) *outOffset = addr - g_funcNames[best].addr;
        return g_funcNames[best].name;
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
 * WITH_CALLERS trampoline (64 bytes max):
 *   [0]    9C                      PUSHFD
 *   [1]    50                      PUSH EAX
 *   [2]    51                      PUSH ECX
 *   [3]    52                      PUSH EDX
 *                                  ; ESP is now 0x10 below entry
 *                                  ; [ESP+0x10]=retAddr [ESP+0x14]=arg1 ...
 *   [4]    8D 44 24 14             LEA EAX, [ESP+0x14]  ; &arg1 area
 *   [8]    50                      PUSH EAX             ; arg4: origArgsESP
 *   [9]    FF 74 24 08             PUSH [ESP+0x08]      ; arg3: saved ECX
 *   [13]   8B 44 24 18             MOV EAX, [ESP+0x18]  ; return addr
 *   [17]   50                      PUSH EAX             ; arg2: callerAddr
 *   [18]   68 <imm32>              PUSH hookIndex       ; arg1: index
 *   [23]   E8 <rel32>              CALL FTraceRecordCallEx
 *   [28]   83 C4 10                ADD ESP, 16
 *   [31]   5A                      POP EDX
 *   [32]   59                      POP ECX
 *   [33]   58                      POP EAX
 *   [34]   9D                      POPFD
 *   [35]   <relocated prologue>    (relocLen bytes)
 *   [35+N] E9 <rel32>             JMP (originalAddr + relocLen)
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
        /* --- Large trampoline: save regs, push 4 args, call C callback --- */
        DWORD callTarget;

        tramp[offset++] = 0x9C;                       /* PUSHFD */
        tramp[offset++] = 0x50;                       /* PUSH EAX */
        tramp[offset++] = 0x51;                       /* PUSH ECX */
        tramp[offset++] = 0x52;                       /* PUSH EDX */
        /* ESP is now 0x10 below entry. Stack layout:
         *   [ESP+0x00]=EDX [ESP+0x04]=ECX [ESP+0x08]=EAX [ESP+0x0C]=EFLAGS
         *   [ESP+0x10]=return addr  [ESP+0x14]=arg1  [ESP+0x18]=arg2 ... */

        /* arg4: origArgsESP = pointer to first stack arg */
        tramp[offset++] = 0x8D;                       /* LEA EAX, [ESP+0x14] */
        tramp[offset++] = 0x44;
        tramp[offset++] = 0x24;
        tramp[offset++] = 0x14;
        tramp[offset++] = 0x50;                       /* PUSH EAX */

        /* arg3: saved ECX (this ptr for __thiscall) */
        tramp[offset++] = 0xFF;                       /* PUSH [ESP+0x08] */
        tramp[offset++] = 0x74;
        tramp[offset++] = 0x24;
        tramp[offset++] = 0x08;

        /* arg2: callerAddr (return addr, shifted by 2 pushes) */
        tramp[offset++] = 0x8B;                       /* MOV EAX, [ESP+0x18] */
        tramp[offset++] = 0x44;
        tramp[offset++] = 0x24;
        tramp[offset++] = 0x18;
        tramp[offset++] = 0x50;                       /* PUSH EAX */

        /* arg1: hookIdx */
        tramp[offset++] = 0x68;                       /* PUSH imm32 */
        *(DWORD*)(tramp + offset) = (DWORD)idx;
        offset += 4;

        tramp[offset] = 0xE8;                         /* CALL FTraceRecordCallEx */
        callTarget = (DWORD)FTraceRecordCallEx - ((DWORD)(tramp + offset) + 5);
        *(DWORD*)(tramp + offset + 1) = callTarget;
        offset += 5;

        tramp[offset++] = 0x83;                       /* ADD ESP, 16 */
        tramp[offset++] = 0xC4;
        tramp[offset++] = 0x10;

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
            long cnt = (long)g_ftHooks[i].callCount;
            if (g_ftHooks[i].damageArgOffset >= 0 && g_ftHooks[i].dmgTotal > 0) {
                ProxyLog("  [%2d] %-30s %8ld%s  dmg: total=%.1f avg=%.1f max=%.1f",
                         i, g_ftHooks[i].name, cnt,
                         g_ftHooks[i].trackCallers ? " [callers]" : "",
                         g_ftHooks[i].dmgTotal,
                         g_ftHooks[i].dmgTotal / cnt,
                         (double)g_ftHooks[i].dmgMax);
            } else {
                ProxyLog("  [%2d] %-30s %8ld%s", i, g_ftHooks[i].name, cnt,
                         g_ftHooks[i].trackCallers ? " [callers]" : "");
            }
            any = 1;

            /* Print caller breakdown for tracked hooks */
            if (g_ftHooks[i].trackCallers) {
                int c;
                int nc = g_ftHooks[i].callerCount;
                if (nc > FTRACE_MAX_CALLERS) nc = FTRACE_MAX_CALLERS;
                for (c = 0; c < nc; c++) {
                    DWORD coff = 0;
                    const char* resolved = FTraceResolveName(
                        g_ftHooks[i].callers[c].addr, &coff);
                    long ccnt = (long)g_ftHooks[i].callers[c].count;
                    char dmgBuf[64] = "";
                    if (g_ftHooks[i].damageArgOffset >= 0 &&
                        g_ftHooks[i].callers[c].dmgTotal > 0) {
                        _snprintf(dmgBuf, sizeof(dmgBuf),
                                  "  dmg=%.1f avg=%.1f max=%.1f",
                                  g_ftHooks[i].callers[c].dmgTotal,
                                  g_ftHooks[i].callers[c].dmgTotal / ccnt,
                                  (double)g_ftHooks[i].callers[c].dmgMax);
                    }
                    if (resolved) {
                        if (coff > 0) {
                            ProxyLog("         from 0x%08X %s+0x%X x%ld%s",
                                     g_ftHooks[i].callers[c].addr,
                                     resolved, coff, ccnt, dmgBuf);
                        } else {
                            ProxyLog("         from 0x%08X %s x%ld%s",
                                     g_ftHooks[i].callers[c].addr,
                                     resolved, ccnt, dmgBuf);
                        }
                    } else {
                        ProxyLog("         from 0x%08X x%ld%s",
                                 g_ftHooks[i].callers[c].addr, ccnt, dmgBuf);
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
        g_ftHooks[i].dmgTotal = 0;
        g_ftHooks[i].dmgMax = 0;
        if (g_ftHooks[i].trackCallers) {
            memset(g_ftHooks[i].callers, 0, sizeof(g_ftHooks[i].callers));
            InterlockedExchange(&g_ftHooks[i].callerCount, 0);
        }
    }
}

/* ================================================================
 * Damage Event Profiler - Implementation (Part 2)
 *
 * Per-event damage breakdown with shield/subsystem detail.
 * CollisionDmgWrapper entry → snapshot shields, swap return addr
 * PerSubsystemDamage → collect per-subsystem hits during event
 * Exit trampoline → diff shields, log full breakdown
 * ================================================================ */

/* ----------------------------------------------------------------
 * IdentifySubsystem - name a subsystem by comparing its pointer
 * against known fixed offsets in the ship object.
 * ---------------------------------------------------------------- */
static void IdentifySubsystem(DWORD ship, DWORD subsys, char* out, int outLen) {
    if (!ship || IsBadReadPtr((void*)ship, 0x2D4)) {
        _snprintf(out, outLen, "subsys_%08lX", subsys);
        return;
    }
    if (subsys == *(DWORD*)(ship + 0x2C0)) { lstrcpynA(out, "Shields", outLen); return; }
    if (subsys == *(DWORD*)(ship + 0x2B8)) { lstrcpynA(out, "Phasers", outLen); return; }
    if (subsys == *(DWORD*)(ship + 0x2BC)) { lstrcpynA(out, "Torpedoes", outLen); return; }
    if (subsys == *(DWORD*)(ship + 0x2C4)) { lstrcpynA(out, "Reactor", outLen); return; }
    if (subsys == *(DWORD*)(ship + 0x2B4)) { lstrcpynA(out, "Repair", outLen); return; }
    if (subsys == *(DWORD*)(ship + 0x2C8)) { lstrcpynA(out, "Cloak", outLen); return; }
    if (subsys == *(DWORD*)(ship + 0x2D0)) { lstrcpynA(out, "Tractor", outLen); return; }
    if (subsys == *(DWORD*)(ship + 0x2B0)) { lstrcpynA(out, "EPS", outLen); return; }
    /* Unknown — log pointer for manual identification */
    _snprintf(out, outLen, "subsys_%08lX", subsys);
}

/* ----------------------------------------------------------------
 * FlushDmgEvent - log the per-event damage breakdown
 *
 * Called from exit trampoline when CollisionDmgWrapper returns.
 * Diffs pre/post shield HP, logs per-subsystem hits.
 * ---------------------------------------------------------------- */
static void __cdecl FlushDmgEvent(void) {
    float postShields[6] = {0};
    float totalAbsorbed = 0;
    float subsysAbsorbed = 0;
    float hullDmg;
    int i;
    static const char* faceNames[] = {"Front","Rear","Top","Bottom","Left","Right"};

    if (!g_dmgProf.active) return;
    g_dmgProf.active = FALSE;

    /* Read post-damage shield HP */
    if (g_dmgProf.shipPtr && !IsBadReadPtr((void*)g_dmgProf.shipPtr, 0x2C4)) {
        DWORD shieldClass = *(DWORD*)(g_dmgProf.shipPtr + 0x2C0);
        if (shieldClass && !IsBadReadPtr((void*)shieldClass, 0xC8))
            memcpy(postShields, (void*)(shieldClass + 0xA8), 24);
    }

    /* Log header */
    ProxyLog("[DMG-EVENT] %s ship=0x%08X damage=%.1f energy=%.1f",
             g_dmgProf.context == 0 ? "COLLISION" : "WEAPON",
             g_dmgProf.shipPtr, g_dmgProf.initialDamage, g_dmgProf.initialEnergy);

    /* Per-facing shield absorption */
    for (i = 0; i < 6; i++) {
        float absorbed = g_dmgProf.preShields[i] - postShields[i];
        if (absorbed > 0.01f || absorbed < -0.01f) {
            ProxyLog("  Shield %-6s: %.1f -> %.1f  (absorbed %.1f)",
                     faceNames[i], g_dmgProf.preShields[i], postShields[i], absorbed);
        }
        totalAbsorbed += absorbed;
    }
    ProxyLog("  Shield total absorbed: %.1f", totalAbsorbed);

    /* Per-subsystem hits */
    if (g_dmgProf.hitCount > 0) {
        ProxyLog("  Subsystem hits (%d):", g_dmgProf.hitCount);
        for (i = 0; i < g_dmgProf.hitCount; i++) {
            ProxyLog("    %-12s dmg=%.1f  HP: %.1f -> %.1f",
                     g_dmgProf.hits[i].typeName,
                     g_dmgProf.hits[i].damage,
                     g_dmgProf.hits[i].oldHP,
                     g_dmgProf.hits[i].newHP);
            subsysAbsorbed += g_dmgProf.hits[i].damage;
        }
    }

    /* Post-shield damage entering DoDamage */
    hullDmg = g_dmgProf.initialDamage - totalAbsorbed;
    if (hullDmg < 0) hullDmg = 0;
    ProxyLog("  Post-shield entering DoDamage: %.1f  (subsys absorbed: %.1f)",
             hullDmg, subsysAbsorbed);
}

/* ----------------------------------------------------------------
 * OnCollisionDmgEntry - called from FTraceRecordCallEx when
 * CollisionDmgWrapper is entered. Snapshots shield HP and swaps
 * the return address for exit-time capture.
 * ---------------------------------------------------------------- */
static void OnCollisionDmgEntry(DWORD ecx, DWORD origArgsESP) {
    DWORD shieldClass;

    /* Flush any prior event (shouldn't happen — single-threaded game) */
    if (g_dmgProf.active) FlushDmgEvent();

    memset(&g_dmgProf, 0, sizeof(g_dmgProf));
    g_dmgProf.active = TRUE;
    g_dmgProf.shipPtr = ecx;
    g_dmgProf.context = 0;  /* collision */

    /* Read damage and energy from stack args:
     * CollisionDmgWrapper(__thiscall): ECX=ship, arg1=?, arg2=energy, arg3=damage */
    if (origArgsESP && !IsBadReadPtr((void*)origArgsESP, 12)) {
        g_dmgProf.initialEnergy = *(float*)(origArgsESP + 4);
        g_dmgProf.initialDamage = *(float*)(origArgsESP + 8);
    }

    /* Snapshot shield HP: ship+0x2C0 → ShieldClass+0xA8 = float[6] */
    if (ecx && !IsBadReadPtr((void*)(ecx + 0x2C0), 4)) {
        shieldClass = *(DWORD*)(ecx + 0x2C0);
        if (shieldClass && !IsBadReadPtr((void*)(shieldClass + 0xA8), 24)) {
            memcpy(g_dmgProf.preShields, (void*)(shieldClass + 0xA8), 24);
        }
    }

    /* Return-address swap: origArgsESP-4 = return address slot on the
     * original call stack (before our trampoline's pushes, which are
     * transparently restored before the relocated prologue runs). */
    if (g_dmgProfExitTramp && origArgsESP) {
        DWORD* retAddrPtr = (DWORD*)(origArgsESP - 4);
        g_dmgProf.savedRetAddr = *retAddrPtr;
        *retAddrPtr = (DWORD)g_dmgProfExitTramp;
    }
}

/* ----------------------------------------------------------------
 * OnPerSubsysDmg - called from FTraceRecordCallEx when
 * PerSubsystemDamage (0x005af4a0) is entered during an active
 * damage event. Collects per-subsystem hit details.
 * ---------------------------------------------------------------- */
static void OnPerSubsysDmg(DWORD ecx, DWORD origArgsESP) {
    DWORD subsys;
    float damage, oldHP;
    int idx;

    if (!g_dmgProf.active) return;
    if (g_dmgProf.hitCount >= DMG_PROF_MAX_HITS) return;
    if (!origArgsESP || IsBadReadPtr((void*)origArgsESP, 8)) return;

    /* PerSubsystemDamage(__thiscall): ECX=ship, arg1=subsys*, arg2=damage */
    subsys = *(DWORD*)(origArgsESP + 0);
    damage = *(float*)(origArgsESP + 4);

    if (!subsys || IsBadReadPtr((void*)(subsys + 0x30), 4)) return;
    oldHP = *(float*)(subsys + 0x30);

    idx = g_dmgProf.hitCount++;
    g_dmgProf.hits[idx].subsysPtr = subsys;
    g_dmgProf.hits[idx].damage = damage;
    g_dmgProf.hits[idx].oldHP = oldHP;
    g_dmgProf.hits[idx].newHP = (oldHP > damage) ? (oldHP - damage) : 0.0f;
    IdentifySubsystem(ecx, subsys, g_dmgProf.hits[idx].typeName, 16);
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
    int idx_DoDamage = -1, idx_DoDmgFromPos = -1;

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
        idx_DoDamage = FTraceRegister(0x00594020, 6, b, "DoDamage", TRUE);
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

    /* --- Collision / Damage Entry Points (4) --- */
    /* trackCallers=TRUE: trace what triggers collision damage + damage meters */
    {
        static const BYTE b[] = {0x53,0x8B,0x5C,0x24,0x08,0x56,0x57};
        g_hookIdx_CollDmgWrap = FTraceRegister(0x005b0060, 7, b, "CollisionDamageWrapper", TRUE);
    }
    {
        static const BYTE b[] = {0x83,0xEC,0x24,0x56,0x8B,0xF1};
        idx_DoDmgFromPos = FTraceRegister(0x00593650, 6, b, "DoDamage_FromPosition", TRUE);
    }
    {
        static const BYTE b[] = {0x6A,0xFF,0x68,0xC8,0xAF,0x87,0x00};
        FTraceRegister(0x005952d0, 7, b, "DoDamage_CollisionContacts", TRUE);
    }
    {
        /* PerSubsystemDamage: __thiscall(ECX=ship, subsys*, float damage, ...) */
        static const BYTE b[] = {0x83,0xEC,0x08,0x57,0x8B,0xF9};
        g_hookIdx_PerSubsysDmg = FTraceRegister(0x005af4a0, 6, b, "PerSubsystemDamage", TRUE);
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

    /* --- PythonEvent Damage Chain (8) --- */
    /* Traces the collision → SetCondition → RepairList → PythonEvent(0x06) chain.
     * trackCallers=TRUE on all: need to see what triggers each step. */
    {
        /* CollisionEffect opcode 0x15 handler (SEH prologue) */
        static const BYTE b[] = {0x6A,0xFF,0x68,0x68,0xDC,0x87,0x00};
        FTraceRegister(0x006a2470, 7, b, "CollisionEffect_0x15", TRUE);
    }
    {
        /* ShipSubsystem::SetCondition — posts ET_SUBSYSTEM_HIT when health decreases */
        static const BYTE b[] = {0x8B,0x44,0x24,0x04,0x56,0x8B,0xF1};
        FTraceRegister(0x0056c470, 7, b, "SS_SetCondition", TRUE);
    }
    {
        /* RepairSubsystem::AddSubsystemToRepairList — posts ET_ADD_TO_REPAIR_LIST */
        static const BYTE b[] = {0x53,0x8B,0x5C,0x24,0x08,0x57,0x8B,0xF9};
        FTraceRegister(0x00565900, 8, b, "AddToRepairList", TRUE);
    }
    {
        /* MultiplayerGame::HostEventHandler — serializes as PythonEvent (0x06) */
        static const BYTE b[] = {0x64,0xA1,0x00,0x00,0x00,0x00,0x6A,0xFF};
        FTraceRegister(0x006a1150, 8, b, "HostEventHandler", TRUE);
    }
    {
        /* ObjectExplodingHandler — serializes explosion as PythonEvent (0x06) */
        static const BYTE b[] = {0x64,0xA1,0x00,0x00,0x00,0x00,0x6A,0xFF};
        FTraceRegister(0x006a1240, 8, b, "ObjExplodingHandler", TRUE);
    }
    {
        /* PythonEvent opcode 0x06 receiver/forwarder (SEH prologue) */
        static const BYTE b[] = {0x6A,0xFF,0x68,0x88,0xD9,0x87,0x00};
        FTraceRegister(0x0069f880, 7, b, "PythonEvent_0x06", TRUE);
    }
    {
        /* ShipClass::CollisionEffectHandler — validates and applies collision damage */
        static const BYTE b[] = {0x51,0xA0,0x89,0xFA,0x97,0x00,0x53};
        FTraceRegister(0x005af9c0, 7, b, "Ship_CollEffHandler", TRUE);
    }
    {
        /* Collision damage application — iterates contacts, applies per-subsystem damage */
        static const BYTE b[] = {0xA0,0x8A,0xFA,0x97,0x00,0x83,0xEC,0x40};
        FTraceRegister(0x005afad0, 8, b, "CollDmgApply", TRUE);
    }

    ProxyLog("FTrace: registered %d hooks, trampBlock=0x%08X (slot size=%d)",
             g_ftHookCount, (DWORD)g_ftTrampBlock, FTRACE_TRAMP_LARGE);

    /* --- Part 1: Set damageArgOffset on hooks with damage capture --- */
    /* DoDamage(this, ?, damage): arg2 = damage float at origArgs+4 */
    if (idx_DoDamage >= 0)
        g_ftHooks[idx_DoDamage].damageArgOffset = 4;
    /* CollisionDmgWrapper(this, ?, energy, damage): arg3 at origArgs+8 */
    if (g_hookIdx_CollDmgWrap >= 0)
        g_ftHooks[g_hookIdx_CollDmgWrap].damageArgOffset = 8;
    /* DoDamage_FromPosition(this, ?, damage): arg2 at origArgs+4 */
    if (idx_DoDmgFromPos >= 0)
        g_ftHooks[idx_DoDmgFromPos].damageArgOffset = 4;
    /* PerSubsystemDamage(this, subsys*, damage): arg2 at origArgs+4 */
    if (g_hookIdx_PerSubsysDmg >= 0)
        g_ftHooks[g_hookIdx_PerSubsysDmg].damageArgOffset = 4;

    /* --- Part 2: Allocate exit trampoline for damage profiler ---
     * Hand-coded x86: save regs, CALL FlushDmgEvent, restore, JMP [savedRetAddr]
     *   9C              PUSHFD
     *   50              PUSH EAX
     *   51              PUSH ECX
     *   52              PUSH EDX
     *   E8 <rel32>      CALL FlushDmgEvent
     *   5A              POP EDX
     *   59              POP ECX
     *   58              POP EAX
     *   9D              POPFD
     *   FF 25 <addr32>  JMP [g_dmgProf.savedRetAddr]
     */
    {
        BYTE* et;
        int off = 0;
        DWORD callTarget;

        g_dmgProfExitTramp = (BYTE*)VirtualAlloc(NULL, 32,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!g_dmgProfExitTramp) {
            ProxyLog("FTrace: WARNING - VirtualAlloc failed for dmg profiler exit trampoline");
        } else {
            et = g_dmgProfExitTramp;
            memset(et, 0xCC, 32);

            et[off++] = 0x9C;  /* PUSHFD */
            et[off++] = 0x50;  /* PUSH EAX */
            et[off++] = 0x51;  /* PUSH ECX */
            et[off++] = 0x52;  /* PUSH EDX */

            et[off] = 0xE8;    /* CALL FlushDmgEvent */
            callTarget = (DWORD)FlushDmgEvent - ((DWORD)(et + off) + 5);
            *(DWORD*)(et + off + 1) = callTarget;
            off += 5;

            et[off++] = 0x5A;  /* POP EDX */
            et[off++] = 0x59;  /* POP ECX */
            et[off++] = 0x58;  /* POP EAX */
            et[off++] = 0x9D;  /* POPFD */

            et[off++] = 0xFF;  /* JMP [g_dmgProf.savedRetAddr] */
            et[off++] = 0x25;
            *(DWORD*)(et + off) = (DWORD)&g_dmgProf.savedRetAddr;
            off += 4;

            ProxyLog("FTrace: dmg profiler exit trampoline at 0x%08X (%d bytes)",
                     (DWORD)et, off);
        }
    }

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

#ifdef OBSERVE_ONLY
    InstallHandleACKHook();
#endif
}

/* ================================================================
 * HandleACK Hook (OBSERVE_ONLY / client build)
 *
 * Custom argument-capturing hook on FUN_006b64d0 (HandleACK).
 * Called via DispatchReceivedMessages when an ACK (type 0x01) arrives.
 *
 * Prototype: void __stdcall HandleACK(void* ackMsg, void* peer)
 *   ackMsg = TGHeaderMessage* (ACK fields at +0x14/+0x39/+0x3C/+0x40)
 *   peer   = peer object ptr (retransmit queue at +0x80, count at +0x98)
 *
 * Prologue (7 bytes, clean boundary):
 *   8B 44 24 08   MOV EAX, [ESP+8]   ; param_2 (peer)
 *   53            PUSH EBX
 *   55            PUSH EBP
 *   56            PUSH ESI
 *
 * Trampoline layout (~45 bytes):
 *   PUSHFD / PUSH EAX,ECX,EDX          ; save caller-saved regs + flags
 *   MOV EAX, [ESP+0x18]                ; peer (param 2)
 *   PUSH EAX
 *   MOV EAX, [ESP+0x18]                ; ackMsg (param 1, shifted by push)
 *   PUSH EAX
 *   CALL LogHandleACKEntry             ; __cdecl C callback
 *   ADD ESP, 8
 *   POP EDX,ECX,EAX / POPFD            ; restore
 *   <relocated 7 prologue bytes>
 *   JMP HandleACK+7
 * ================================================================ */
#ifdef OBSERVE_ONLY

#define HANDLEACK_ADDR       0x006b64d0
#define HANDLEACK_RELOC_LEN  7
#define HANDLEACK_TRAMP_SIZE 128

static BYTE* g_handleACKTrampoline = NULL;
static volatile LONG g_handleACKHookCalls = 0;

static void __cdecl LogHandleACKEntry(DWORD ackMsg, DWORD peer) {
    WORD  ackSeq;
    BYTE  ackFrag, ackFragIdx, ackBelow32;
    DWORD retxCount, retxHead;
    DWORD node;
    int i;

    InterlockedIncrement(&g_handleACKHookCalls);

    if (!ackMsg || IsBadReadPtr((void*)ackMsg, 0x44)) return;
    if (!peer  || IsBadReadPtr((void*)peer, 0xC0)) return;

    ackSeq      = *(WORD*)(ackMsg + 0x14);
    ackFragIdx  = *(BYTE*)(ackMsg + 0x39);
    ackFrag     = *(BYTE*)(ackMsg + 0x3C);
    ackBelow32  = *(BYTE*)(ackMsg + 0x40);

    retxCount = *(DWORD*)(peer + 0x98);
    retxHead  = *(DWORD*)(peer + 0x80);

    ProxyLog("[ACK-HOOK] HandleACK: ack seq=0x%04X frag=%d idx=%d below32=%d | retxQ=%u",
             (unsigned)ackSeq, ackFrag, ackFragIdx, ackBelow32, retxCount);

    /* Walk first 5 retransmit entries to show what the matching logic will see */
    node = retxHead;
    for (i = 0; i < 5 && node; i++) {
        DWORD msg;
        if (IsBadReadPtr((void*)node, 8)) break;
        msg = *(DWORD*)node;
        if (msg && !IsBadReadPtr((void*)msg, 0x40)) {
            WORD  mSeq     = *(WORD*)(msg + 0x14);
            BYTE  mFragIdx = *(BYTE*)(msg + 0x39);
            BYTE  mFrag    = *(BYTE*)(msg + 0x3C);
            DWORD mRetx    = *(DWORD*)(msg + 0x18);
            /* Read vtable to call GetType() — vtable slot 0 returns u8 type.
             * TGMessage vtable: [0]=GetType, [1]=dtor, [2]=WriteToBuffer, ...
             * NOT NiObject layout (where slot 0 = GetRTTI). */
            DWORD vtbl = *(DWORD*)msg;
            BYTE  mType = 0xFF;
            if (vtbl && !IsBadReadPtr((void*)vtbl, 4)) {
                typedef BYTE (__fastcall *pfn_GetType)(void* ecx, void* edx);
                pfn_GetType pGetType = (pfn_GetType)(*(DWORD*)vtbl);
                if (pGetType && !IsBadReadPtr((void*)pGetType, 1))
                    mType = pGetType((void*)msg, NULL);
            }
            ProxyLog("[ACK-HOOK]   retx[%d] seq=0x%04X frag=%d idx=%d type=0x%02X retx=%u %s",
                     i, (unsigned)mSeq, mFrag, mFragIdx, mType, mRetx,
                     (mSeq == ackSeq && mFrag == ackFrag &&
                      (!mFrag || mFragIdx == ackFragIdx)) ? "<-- MATCH?" : "");
        }
        node = *(DWORD*)(node + 4);
    }
}

static void InstallHandleACKHook(void) {
    BYTE* func = (BYTE*)HANDLEACK_ADDR;
    BYTE* tramp;
    DWORD oldProt, callTarget, jmpTarget;
    int offset = 0;

    static const BYTE expected[HANDLEACK_RELOC_LEN] = {
        0x8B, 0x44, 0x24, 0x08, 0x53, 0x55, 0x56
    };

    if (IsBadReadPtr(func, HANDLEACK_RELOC_LEN)) {
        ProxyLog("HandleACK hook: address not readable");
        return;
    }
    if (memcmp(func, expected, HANDLEACK_RELOC_LEN) != 0) {
        ProxyLog("HandleACK hook: prologue mismatch (got %02X %02X %02X %02X %02X %02X %02X)",
                 func[0], func[1], func[2], func[3], func[4], func[5], func[6]);
        return;
    }

    tramp = (BYTE*)VirtualAlloc(NULL, HANDLEACK_TRAMP_SIZE,
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    if (!tramp) {
        ProxyLog("HandleACK hook: VirtualAlloc failed");
        return;
    }
    memset(tramp, 0xCC, HANDLEACK_TRAMP_SIZE);
    g_handleACKTrampoline = tramp;

    /* Build trampoline */
    tramp[offset++] = 0x9C;                       /* PUSHFD */
    tramp[offset++] = 0x50;                       /* PUSH EAX */
    tramp[offset++] = 0x51;                       /* PUSH ECX */
    tramp[offset++] = 0x52;                       /* PUSH EDX */

    /* MOV EAX, [ESP+0x18] — peer (param 2, shifted by 4 saves) */
    tramp[offset++] = 0x8B; tramp[offset++] = 0x44;
    tramp[offset++] = 0x24; tramp[offset++] = 0x18;

    tramp[offset++] = 0x50;                       /* PUSH EAX (arg2: peer) */

    /* MOV EAX, [ESP+0x18] — ackMsg (param 1, was +0x14, shifted by push) */
    tramp[offset++] = 0x8B; tramp[offset++] = 0x44;
    tramp[offset++] = 0x24; tramp[offset++] = 0x18;

    tramp[offset++] = 0x50;                       /* PUSH EAX (arg1: ackMsg) */

    /* CALL LogHandleACKEntry */
    tramp[offset] = 0xE8;
    callTarget = (DWORD)LogHandleACKEntry - ((DWORD)(tramp + offset) + 5);
    *(DWORD*)(tramp + offset + 1) = callTarget;
    offset += 5;

    /* ADD ESP, 8 (clean up cdecl args) */
    tramp[offset++] = 0x83; tramp[offset++] = 0xC4; tramp[offset++] = 0x08;

    /* Restore registers */
    tramp[offset++] = 0x5A;                       /* POP EDX */
    tramp[offset++] = 0x59;                       /* POP ECX */
    tramp[offset++] = 0x58;                       /* POP EAX */
    tramp[offset++] = 0x9D;                       /* POPFD */

    /* Relocated prologue (7 bytes) */
    memcpy(tramp + offset, func, HANDLEACK_RELOC_LEN);
    offset += HANDLEACK_RELOC_LEN;

    /* JMP back to HandleACK + 7 */
    tramp[offset] = 0xE9;
    jmpTarget = (HANDLEACK_ADDR + HANDLEACK_RELOC_LEN) - ((DWORD)(tramp + offset) + 5);
    *(DWORD*)(tramp + offset + 1) = jmpTarget;
    offset += 5;

    /* Patch original function: JMP to trampoline + NOP pad */
    if (!VirtualProtect(func, HANDLEACK_RELOC_LEN, PAGE_EXECUTE_READWRITE, &oldProt)) {
        ProxyLog("HandleACK hook: VirtualProtect failed");
        return;
    }
    func[0] = 0xE9;
    *(DWORD*)(func + 1) = (DWORD)tramp - ((DWORD)func + 5);
    func[5] = 0x90;
    func[6] = 0x90;
    VirtualProtect(func, HANDLEACK_RELOC_LEN, oldProt, &oldProt);

    ProxyLog("HandleACK hook: installed at 0x%08X -> tramp 0x%08X (%d bytes)",
             HANDLEACK_ADDR, (DWORD)tramp, offset);
}

#else
/* Server build: no HandleACK hook needed */
static void InstallHandleACKHook(void) { /* no-op */ }
#endif /* OBSERVE_ONLY */
