/* ================================================================
 * PatchRenderTick - Skip render work in the per-frame function
 *
 * Function at 0x004433E0 checks [0x00995A48] and if zero, does
 * render operations that crash on NULL pointers in stub mode.
 * Patch JNZ to JMP to always skip render work.
 *
 * At 0x004433EA: 75 4A (jnz +0x4A) -> EB 4A (jmp +0x4A)
 *
 * NOTE: This does NOT affect the game's network pump. TGNetwork_Update
 * is called from FUN_00451ac0 (scene traversal), a separate function.
 * ================================================================ */
static void PatchRenderTick(void) {
    BYTE* pTarget = (BYTE*)0x004433EA;
    DWORD oldProt;

    if (IsBadReadPtr(pTarget, 2)) {
        ProxyLog("  PatchRenderTick: address not readable");
        return;
    }
    if (pTarget[0] != 0x75 || pTarget[1] != 0x4A) {
        ProxyLog("  PatchRenderTick: bytes don't match (expected 75 4A, got %02X %02X)",
                 pTarget[0], pTarget[1]);
        return;
    }

    VirtualProtect(pTarget, 2, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[0] = 0xEB;  /* JMP rel8 (unconditional) */
    VirtualProtect(pTarget, 2, oldProt, &oldProt);
    ProxyLog("  PatchRenderTick: patched JNZ->JMP at 0x004433EA (skip render work)");
}

/* PatchSkipRendererCtor REMOVED - renderer constructor now runs normally.
 * The D3D proxy provides valid COM objects so the constructor succeeds. */

/* PatchRendererCtorEntry REMOVED - the real NiDX7Renderer constructor
 * runs so the renderer has valid internal state (arrays, matrices, frustum). */

/* ================================================================
 * PatchInitAbort - Prevent abort() when init check fails
 *
 * At 0x0043B1D2: JMP 0x0085A108 (5 bytes: E9 xx xx xx xx)
 * This abort is called if FUN_006f7d90 returns NULL. Without a
 * renderer, this check may fail. NOP the JMP so execution falls
 * through to the Python script loading at 0x0043B1D7.
 * ================================================================ */
static void PatchInitAbort(void) {
    BYTE* pTarget = (BYTE*)0x0043B1D2;
    DWORD oldProt;

    if (IsBadReadPtr(pTarget, 5)) {
        ProxyLog("  PatchInitAbort: address not readable");
        return;
    }
    if (pTarget[0] != 0xE9) {
        ProxyLog("  PatchInitAbort: bytes don't match (expected E9, got %02X)", pTarget[0]);
        return;
    }

    VirtualProtect(pTarget, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[0] = 0x90; pTarget[1] = 0x90; pTarget[2] = 0x90;
    pTarget[3] = 0x90; pTarget[4] = 0x90;
    VirtualProtect(pTarget, 5, oldProt, &oldProt);
    ProxyLog("  PatchInitAbort: NOPed JMP at 0x0043B1D2 (abort suppressed)");
}

/* ================================================================
 * PatchForceWindowed - Force windowed mode renderer creation
 *
 * FUN_00438290 (UtopiaApp renderer setup) decides fullscreen vs windowed
 * based on byte [EBP+0x2c] in the UtopiaApp object:
 *   004384e2: MOV AL, [EBP+0x2c]
 *   004384e5: TEST AL, AL
 *   004384e7: JZ 0x0043854a       ; zero = windowed (PUSH 0, CALL 007c09c0)
 *                                  ; nonzero = fullscreen (PUSH 1, CALL 007c09c0)
 *
 * Modern Windows doesn't support old D3D7 fullscreen modes (e.g. 640x480x16bpp),
 * causing "Desired fullscreen display mode not supported" error.
 *
 * Patch: 004384e7 JZ +0x61 (74 61) -> JMP +0x61 (EB 61)
 * Always takes the windowed code path.
 * ================================================================ */
static void PatchForceWindowed(void) {
    BYTE* target = (BYTE*)0x004384E7;
    DWORD oldProt;

    if (IsBadReadPtr(target, 2) || target[0] != 0x74 || target[1] != 0x61) {
        ProxyLog("  PatchForceWindowed: unexpected bytes at 0x004384E7 (%02X %02X), skipped",
                 target[0], target[1]);
        return;
    }

    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xEB; /* JZ -> JMP short */
    VirtualProtect(target, 1, oldProt, &oldProt);

    ProxyLog("  PatchForceWindowed: 004384E7 JZ->JMP (always use windowed renderer)");
}

/* PatchSkipRendererSetup REMOVED - the full renderer pipeline now runs.
 * Dev_GetDirect3D returns a valid ProxyD3D7, so pipeline ctors get valid
 * COM objects. All D3D calls go through our proxy (no real GPU needed). */

/* ================================================================
 * PatchSkipDeviceLost - Skip "device lost" recreation path
 *
 * Vtable method at 0x007C1330 (offset +0x98 in renderer wrapper vtable
 * 0x00898984) is called every frame. It calls FUN_007c45b0 to check
 * device status. When the device appears "lost" (always true for stubs),
 * it tries to destroy+recreate pipeline objects at offsets 0xC4, 0xC0,
 * 0xB8, 0xBC - which may be NULL or stub pointers from the proxy pipeline.
 *
 * Patch: 007C1346 JZ +0x49 (74 49) -> JMP +0x49 (EB 49)
 * This always skips the destruction/recreation sequence.
 * ================================================================ */
static void PatchSkipDeviceLost(void) {
    BYTE* target = (BYTE*)0x007C1346;
    DWORD oldProt;

    if (IsBadReadPtr(target, 2) || target[0] != 0x74 || target[1] != 0x49) {
        ProxyLog("  PatchSkipDeviceLost: unexpected bytes at 0x007C1346 (%02X %02X), skipped",
                 target[0], target[1]);
        return;
    }

    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xEB; /* JZ -> JMP short */
    VirtualProtect(target, 1, oldProt, &oldProt);

    ProxyLog("  PatchSkipDeviceLost: 007C1346 JZ->JMP (always skip device-lost recreation)");
}

/* ================================================================
 * PatchSkipDisplayModeSearch - Skip display mode list search
 *
 * FUN_007c9020 (NiDX7Renderer SetDisplayMode) checks this+0x190 for
 * a display mode enumeration list. If non-NULL, it searches for the
 * requested resolution+depth. On modern displays the enumerated modes
 * may not include old modes (e.g. 640x480x16bpp), failing with
 * "Desired fullscreen display mode not supported".
 *
 * The alternative path (this+0x190 == NULL) calls
 * IDirectDraw7::SetDisplayMode directly (our hook returns DD_OK).
 *
 * Patch: 007C90EE JE +0x2E (74 2E) -> JMP +0x2E (EB 2E)
 * ================================================================ */
static void PatchSkipDisplayModeSearch(void) {
    BYTE* target = (BYTE*)0x007C90EE;
    DWORD oldProt;

    if (IsBadReadPtr(target, 2) || target[0] != 0x74 || target[1] != 0x2E) {
        ProxyLog("  PatchSkipDisplayModeSearch: unexpected bytes at 0x007C90EE (%02X %02X), skipped",
                 target[0], target[1]);
        return;
    }

    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xEB; /* JE -> JMP short */
    VirtualProtect(target, 1, oldProt, &oldProt);

    ProxyLog("  PatchSkipDisplayModeSearch: 007C90EE JE->JMP (skip mode list, use direct SetDisplayMode)");
}

/* ================================================================
 * PatchRendererMethods - Patch individual renderer methods
 *
 * Some vtable methods blindly dereference pointer fields that are NULL
 * in our zero-initialized renderer or renderer wrapper. Rather than
 * a stub vtable (which breaks thiscall calling conventions), we patch
 * specific methods to return immediately with the correct stack cleanup.
 * ================================================================ */
static void PatchRendererMethods(void) {
    static const BYTE p_ret[]       = { 0xC3 };
    static const BYTE p_ret4_zero[] = { 0x33, 0xC0, 0xC2, 0x04, 0x00 };
    static const BYTE p_ret18[]     = { 0xC2, 0x18, 0x00 };
    static const struct {
        DWORD addr;
        BYTE expect;
        const BYTE* patch;
        int len;
        const char* desc;
    } fixes[] = {
        /* FUN_007e8780 (vtable+0x94): reads [this+0x190] - frustum planes
         * thiscall, no stack params → RET */
        { 0x007E8780, 0x83, p_ret, 1,
          "FUN_007e8780 (vtable+0x94 frustum calc) -> RET" },
        /* FUN_007c2a10: reads [this+0xC4] - pipeline object
         * thiscall, 1 stack param → XOR EAX,EAX; RET 4 */
        { 0x007C2A10, 0x56, p_ret4_zero, 5,
          "FUN_007c2a10 (pipeline call) -> XOR EAX,EAX; RET 4" },
        /* FUN_007c16f0 (vtable+0xa4): SetCameraData - copies camera/frustum
         * params into renderer, then calls internal functions that dereference
         * NULL pointers in headless mode. Not needed for headless server.
         * thiscall, 6 stack params (24 bytes) → RET 0x18 */
        { 0x007C16F0, 0x83, p_ret18, 3,
          "FUN_007c16f0 (vtable+0xa4 SetCameraData) -> RET 0x18" },
    };
    int i;
    for (i = 0; i < (int)(sizeof(fixes) / sizeof(fixes[0])); i++) {
        BYTE* target = (BYTE*)fixes[i].addr;
        DWORD oldProt;
        if (IsBadReadPtr(target, 1) || target[0] != fixes[i].expect) {
            ProxyLog("  PatchRendererMethods: %s - unexpected byte %02X (expected %02X), skipped",
                     fixes[i].desc, target[0], fixes[i].expect);
            continue;
        }
        VirtualProtect(target, fixes[i].len, PAGE_EXECUTE_READWRITE, &oldProt);
        memcpy(target, fixes[i].patch, fixes[i].len);
        VirtualProtect(target, fixes[i].len, oldProt, &oldProt);
        ProxyLog("  PatchRendererMethods: %s at 0x%08X", fixes[i].desc, (unsigned)fixes[i].addr);
    }
}

/* ================================================================
 * PatchDeviceCapsRawCopy - Skip raw memory copy from Device7 object
 *
 * FUN_007d1ff0 (NiD3DTextureManager ctor) copies 59 DWORDs (236 bytes)
 * directly from the IDirect3DDevice7 object starting at offset 0x00.
 * This bypasses COM and reads the internal Microsoft D3D7 memory layout.
 * Our ProxyDevice7 has a COM vtable pointer at offset 0, refCount at +4,
 * etc. - completely different from Microsoft's layout. The copied garbage
 * gets interpreted as D3D caps data by downstream pipeline constructors
 * (FUN_007ccd10), causing EIP=0x0 crash from NULL vtable entry dereference.
 *
 * Fix: Change MOV ECX,0x3B at 0x007d2118 to MOV ECX,0x00.
 * REP MOVSD with ECX=0 is a no-op. The destination stays zeroed (from
 * HEAP_ZERO_MEMORY allocation), meaning "no device caps" - safe for
 * a headless server that never renders.
 * ================================================================ */
static void PatchDeviceCapsRawCopy(void) {
    /* MOV ECX,0x3B at 0x007d2118 = B9 3B 00 00 00
     * The 0x3B immediate is at instruction_start+1 = 0x007d2119 */
    BYTE* target = (BYTE*)0x007d2119;
    DWORD oldProt;

    if (IsBadReadPtr(target, 1) || *target != 0x3B) {
        ProxyLog("  PatchDeviceCapsRawCopy: unexpected byte %02X at 0x007d2119 (expected 3B), skipped",
                 *target);
        return;
    }
    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    *target = 0x00;
    VirtualProtect(target, 1, oldProt, &oldProt);
    ProxyLog("  PatchDeviceCapsRawCopy: MOV ECX,0x3B -> MOV ECX,0x00 at 0x007d2118 (skip 236-byte Device7 raw copy)");
}

/* ================================================================
 * PatchHeadlessCrashSites - NOP out functions that crash in headless mode
 *
 * These functions try to look up UI panes via FUN_0050e1b0(DAT_009878cc, N).
 * In headless mode DAT_009878cc points to our zeroed dummy, so the lookup
 * returns NULL, and callers crash dereferencing it.
 * Rather than patching FUN_0050e1b0 (which has complex calling conventions),
 * we NOP the problematic callers that are reachable from mission Python code.
 * ================================================================ */
static void PatchHeadlessCrashSites(void) {
    static const struct {
        DWORD addr;
        BYTE expect;   /* expected first byte to verify we're patching the right spot */
        const char* desc;
    } sites[] = {
        /* FUN_0055c810: called during MainTick after checksum-complete event.
         * Looks up UI pane via FUN_0050e1b0(DAT_009878cc, 5) -> NULL in headless.
         * Passes NULL to FUN_00507f80 which dereferences this+0x50 -> CRASH.
         * __fastcall with PUSH ESI, returns via POP ESI; RET.
         * Patching to RET skips render update; caller handles result=0 fine. */
        { 0x0055c810, 0x56, "FUN_0055c810 (UI pane render update)" },
        /* FUN_0055c860: virtual method called from mission UI code.
         * Looks up pane via FUN_0050e1b0, calls FUN_00508120 on result -> NULL crash.
         * __fastcall, no stack params -> safe to RET. */
        { 0x0055c860, 0x56, "FUN_0055c860 (mission UI pane lookup)" },
        /* FUN_0055c890: subtitle remove callback - same pattern as 0x0055c810.
         * Looks up pane #5 via FUN_0050e1b0, passes NULL to FUN_00508120 -> crash.
         * __fastcall, PUSH ESI -> safe to RET. */
        { 0x0055c890, 0x56, "FUN_0055c890 (subtitle remove callback)" },
    };
    int i;
    for (i = 0; i < (int)(sizeof(sites) / sizeof(sites[0])); i++) {
        BYTE* target = (BYTE*)sites[i].addr;
        DWORD oldProt;
        if (IsBadReadPtr(target, 1) || target[0] != sites[i].expect) {
            ProxyLog("  PatchHeadlessCrashSites: %s - unexpected byte %02X (expected %02X), skipped",
                     sites[i].desc, target[0], sites[i].expect);
            continue;
        }
        VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
        target[0] = 0xC3; /* RET */
        VirtualProtect(target, 1, oldProt, &oldProt);
        ProxyLog("  PatchHeadlessCrashSites: %s -> RET at 0x%08X", sites[i].desc, (unsigned)sites[i].addr);
    }
}

/* PatchDisableDebugConsole - Disable interactive Python debug console
 *
 * FUN_006f9470 is the debug console: prints traceback, then loops on
 * ReadConsoleA waiting for "resume" or "abort".  In headless mode stdin
 * is redirected, so this hangs the server forever.
 *
 * Caller FUN_006f9b80 checks DAT_0099add6:
 *   if 1: calls FUN_006f9470 (debug console), then PyErr_Clear, return 1
 *   if 0: calls PyErr_Print (stderr), then PyErr_Clear, return 1
 *
 * Two-pronged approach:
 *   1. Patch FUN_006f9470 to RET immediately (in case flag gets set to 1
 *      later during game init at 0x00438b10)
 *   2. Set DAT_0099add6 = 0 so the normal path calls PyErr_Print instead
 *      (traceback goes to stderr = our log file) */
/* PatchDisableDebugConsole - REPLACED by PatchDebugConsoleToFile above.
 * Previously: patched FUN_006f9470 to RET and set flag to 0.
 * Now: PatchDebugConsoleToFile redirects to our file-logging replacement. */

/* ================================================================
 * PatchNullThunk_00419960 - Fix NULL dereference in vtable thunk
 *
 * The 8-byte thunk at 0x00419960 does:
 *   MOV ECX, [ECX+0x1C]   ; get sub-object pointer
 *   MOV EAX, [ECX]         ; get vtable
 *   JMP [EAX+0x34]         ; call vtable slot 13
 *
 * When [ECX+0x1C] is NULL (e.g. AsteroidField with uninitialized
 * NiAVObject member), the second instruction crashes reading [0x00000000].
 * This fires after a client connects and game objects are iterated.
 *
 * Fix: Redirect to a code cave that checks [ECX+0x1C] for NULL.
 * If NULL, return pointer to a static zeroed bounding struct so
 * callers that read floats from the return value don't crash.
 * ================================================================ */
static void PatchNullThunk_00419960(void) {
    /* Code cave layout (48 bytes total):
     * [0..23]:  6 zeroed DWORDs = dummy bounding box (min/max vectors)
     * [24]:     MOV ECX, [ECX+0x1C]    ; 8B 49 1C
     * [27]:     TEST ECX, ECX           ; 85 C9
     * [29]:     JZ .null                ; 74 05
     * [31]:     MOV EAX, [ECX]          ; 8B 01
     * [33]:     JMP [EAX+0x34]          ; FF 60 34
     * .null: [36]
     * [36]:     MOV EAX, <cave_base>    ; B8 XX XX XX XX
     * [41]:     RET                     ; C3
     */
    static BYTE cave[] = {
        /* 24 bytes of zeros = dummy bounding box (6 floats) */
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        /* code starts at offset 24 */
        0x8B, 0x49, 0x1C,       /* MOV ECX, [ECX+0x1C] */
        0x85, 0xC9,             /* TEST ECX, ECX       */
        0x74, 0x05,             /* JZ  +5 (.null)      */
        0x8B, 0x01,             /* MOV EAX, [ECX]      */
        0xFF, 0x60, 0x34,       /* JMP [EAX+0x34]      */
        /* .null: */
        0xB8, 0x00, 0x00, 0x00, 0x00,  /* MOV EAX, <cave_base> (fixup) */
        0xC3                    /* RET                  */
    };
    BYTE* pCave;
    BYTE* target = (BYTE*)0x00419960;
    DWORD oldProt;

    /* Verify expected bytes: 8B 49 1C 8B 01 FF 60 34 */
    if (IsBadReadPtr(target, 8) ||
        target[0] != 0x8B || target[1] != 0x49 || target[2] != 0x1C ||
        target[3] != 0x8B || target[4] != 0x01) {
        ProxyLog("  PatchNullThunk_00419960: unexpected bytes at 0x00419960, skipped");
        return;
    }

    pCave = (BYTE*)VirtualAlloc(NULL, sizeof(cave),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pCave) {
        ProxyLog("  PatchNullThunk_00419960: VirtualAlloc failed");
        return;
    }
    memcpy(pCave, cave, sizeof(cave));

    /* Fix up MOV EAX, <cave_base>: point to the zeroed data at start of cave */
    *(DWORD*)(pCave + 37) = (DWORD)pCave;  /* cave[0..23] = zeroed bounding box */

    /* Overwrite thunk entry: JMP to cave CODE (offset 24), 5 bytes + 3 NOPs */
    VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xE9;  /* JMP rel32 */
    *(DWORD*)(target + 1) = (DWORD)(pCave + 24) - (0x00419960 + 5);
    target[5] = 0x90;  /* NOP */
    target[6] = 0x90;  /* NOP */
    target[7] = 0x90;  /* NOP */
    VirtualProtect(target, 8, oldProt, &oldProt);

    ProxyLog("  PatchNullThunk_00419960: 0x00419960 -> cave at %p (NULL returns zeroed bound at %p)",
             pCave + 24, pCave);
}

/* ================================================================
 * PatchStreamReadNullBuffer - Fix NULL buffer in stream read function
 *
 * FUN_006CF625 is a small stream read function:
 *   MOV ESI, [ECX+0x1C]    ; get buffer pointer
 *   MOV AX, [ESI+EAX]      ; read 16-bit value at offset EAX
 *   MOV [ECX+0x24], EDX    ; store read position
 *   POP ESI
 *   RET
 *
 * Called during network state update deserialization (from 0x005B2619).
 * When the stream buffer at [ECX+0x1C] is NULL (no subsystem/weapon
 * data to deserialize), ESI=0 and the read crashes.
 *
 * Fix: Code cave checks [ECX+0x1C] for NULL, returns AX=0 if so.
 * ================================================================ */
static void PatchStreamReadNullBuffer(void) {
    /* Code cave: complete replacement of the 12-byte function
     * MOV ESI, [ECX+0x1C]  ; get buffer ptr
     * TEST ESI, ESI         ; NULL check
     * JZ .null
     * MOV AX, [ESI+EAX]    ; read 16-bit (original)
     * MOV [ECX+0x24], EDX  ; update position (original)
     * POP ESI
     * RET
     * .null:
     * XOR AX, AX            ; return 0
     * POP ESI
     * RET
     */
    static BYTE cave[] = {
        0x8B, 0x71, 0x1C,             /* MOV ESI, [ECX+0x1C] */
        0x85, 0xF6,                   /* TEST ESI, ESI       */
        0x74, 0x09,                   /* JZ  +9 (.null)      */
        0x66, 0x8B, 0x04, 0x06,       /* MOV AX, [ESI+EAX]  */
        0x89, 0x51, 0x24,             /* MOV [ECX+0x24], EDX */
        0x5E,                         /* POP ESI             */
        0xC3,                         /* RET                 */
        /* .null: */
        0x66, 0x33, 0xC0,             /* XOR AX, AX          */
        0x5E,                         /* POP ESI             */
        0xC3                          /* RET                 */
    };
    BYTE* pCave;
    BYTE* target = (BYTE*)0x006CF625;
    DWORD oldProt;

    /* Verify expected bytes: 8B 71 1C 66 8B 04 06 */
    if (IsBadReadPtr(target, 7) ||
        target[0] != 0x8B || target[1] != 0x71 || target[2] != 0x1C ||
        target[3] != 0x66 || target[4] != 0x8B) {
        ProxyLog("  PatchStreamReadNullBuffer: unexpected bytes at 0x006CF625, skipped");
        return;
    }

    pCave = (BYTE*)VirtualAlloc(NULL, sizeof(cave),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pCave) {
        ProxyLog("  PatchStreamReadNullBuffer: VirtualAlloc failed");
        return;
    }
    memcpy(pCave, cave, sizeof(cave));

    /* Overwrite function entry: JMP to cave (5 bytes) + NOP remaining 7 */
    VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xE9;  /* JMP rel32 */
    *(DWORD*)(target + 1) = (DWORD)pCave - (0x006CF625 + 5);
    memset(target + 5, 0x90, 7);  /* NOP remaining bytes */
    VirtualProtect(target, 12, oldProt, &oldProt);

    ProxyLog("  PatchStreamReadNullBuffer: 0x006CF625 -> cave at %p (NULL buffer returns AX=0)",
             pCave);

    /* Patch error path in FUN_006cf1c0 (stream cleanup/reset):
     * When buffer at [this+0x1C] is NULL, it tries to write 0xFFFFFFFE to
     * *[this+4]. If [this+4] points to read-only .rdata, this crashes.
     *
     * Original 10 bytes: 8B 41 04 C7 00 FE FF FF FF C3
     *   MOV EAX, [ECX+4]; MOV [EAX], 0xFFFFFFFE; RET
     *
     * Replacement: Also zero this+0x08 (FILE* field) to prevent fclose on
     * stale pointer in the base class destructor (STATUS_INVALID_HANDLE crash).
     *   C7 41 08 00 00 00 00 C3 90 90
     *   MOV DWORD PTR [ECX+0x8], 0; RET; NOP; NOP
     */
    {
        BYTE* target2 = (BYTE*)0x006CF1DC;
        DWORD oldProt2;
        /* Replacement: zero FILE* at this+0x08 then RET (10 bytes) */
        static const BYTE replacement[] = {
            0xC7, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00,  /* MOV DWORD PTR [ECX+8], 0 */
            0xC3,                                         /* RET */
            0x90, 0x90                                    /* NOP NOP */
        };
        if (!IsBadReadPtr(target2, 3)) {
            ProxyLog("  PatchStreamReadNullBuffer: bytes at 006CF1DC: %02X %02X %02X",
                     target2[0], target2[1], target2[2]);
            /* Check if already patched from previous run (0xC3 or 0xC7) */
            if (target2[0] == 0xC3 || target2[0] == 0xC7) {
                VirtualProtect(target2, 10, PAGE_EXECUTE_READWRITE, &oldProt2);
                memcpy(target2, replacement, 10);
                VirtualProtect(target2, 10, oldProt2, &oldProt2);
                ProxyLog("  PatchStreamReadNullBuffer: 006CF1DC -> zero FILE* + RET");
            } else if (target2[0] == 0x8B && target2[1] == 0x41 && target2[2] == 0x04) {
                VirtualProtect(target2, 10, PAGE_EXECUTE_READWRITE, &oldProt2);
                memcpy(target2, replacement, 10);
                VirtualProtect(target2, 10, oldProt2, &oldProt2);
                ProxyLog("  PatchStreamReadNullBuffer: 006CF1DC -> zero FILE* + RET");
            } else {
                ProxyLog("  PatchStreamReadNullBuffer: 006CF1DC unexpected bytes, trying scan...");
                /* Scan for the error pattern: 8B 41 04 C7 00 FE FF FF FF C3 */
                int off;
                for (off = -16; off <= 16; off++) {
                    BYTE* scan = target2 + off;
                    if (!IsBadReadPtr(scan, 10) &&
                        scan[0] == 0x8B && scan[1] == 0x41 && scan[2] == 0x04 &&
                        scan[3] == 0xC7 && scan[4] == 0x00 &&
                        scan[5] == 0xFE && scan[6] == 0xFF) {
                        VirtualProtect(scan, 10, PAGE_EXECUTE_READWRITE, &oldProt2);
                        memcpy(scan, replacement, 10);
                        VirtualProtect(scan, 10, oldProt2, &oldProt2);
                        ProxyLog("  PatchStreamReadNullBuffer: found error pattern at 0x%08X -> zero FILE* + RET",
                                 (unsigned)(scan));
                        break;
                    }
                }
            }
        }
    }
}

/* ================================================================
 * PatchCollisionNullNodeCall_005AFE2C - Skip NULL node call safely
 *
 * FUN_005afd70 iterates collision nodes and calls FUN_005af4a0 for each.
 * In some edge cases, the current node pointer is NULL and the original
 * code still calls FUN_005af4a0 with param_2=NULL, which crashes at:
 *   0x005AF4E7: FLD dword ptr [ESI+0x30]
 *
 * Original bytes at 0x005AFE2C:
 *   75 08       JNE 0x005AFE36   ; non-NULL node
 *   33 C0       XOR EAX,EAX
 *   EB 09       JMP 0x005AFE3B   ; still calls FUN_005af4a0 with EAX=0
 *
 * Patched bytes:
 *   74 27       JE  0x005AFE55   ; NULL node: skip call path, keep cleanup flow
 *   EB 06       JMP 0x005AFE36   ; non-NULL node: original processing
 *
 * This preserves the existing post-loop cleanup semantics (including
 * the native XOR EBP,EBP at 0x005AFE55) and only removes the invalid
 * NULL invocation.
 * ================================================================ */
static void PatchCollisionNullNodeCall_005AFE2C(void) {
    BYTE* target = (BYTE*)0x005AFE2C;
    DWORD oldProt;

    if (IsBadReadPtr(target, 6)) {
        ProxyLog("  PatchCollisionNullNodeCall_005AFE2C: address not readable, skipped");
        return;
    }

    /* Idempotent: allow repeated init in the same process lifetime. */
    if (target[0] == 0x74 && target[1] == 0x27 &&
        target[2] == 0xEB && target[3] == 0x06) {
        ProxyLog("  PatchCollisionNullNodeCall_005AFE2C: already patched");
        return;
    }

    if (target[0] != 0x75 || target[1] != 0x08 ||
        target[2] != 0x33 || target[3] != 0xC0 ||
        target[4] != 0xEB || target[5] != 0x09) {
        ProxyLog("  PatchCollisionNullNodeCall_005AFE2C: unexpected bytes at 0x005AFE2C "
                 "(got %02X %02X %02X %02X %02X %02X), skipped",
                 target[0], target[1], target[2], target[3], target[4], target[5]);
        return;
    }

    VirtualProtect(target, 4, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0x74;  /* JE  +0x27 -> 0x005AFE55 */
    target[1] = 0x27;
    target[2] = 0xEB;  /* JMP +0x06 -> 0x005AFE36 */
    target[3] = 0x06;
    VirtualProtect(target, 4, oldProt, &oldProt);

    ProxyLog("  PatchCollisionNullNodeCall_005AFE2C: 005AFE2C -> "
             "JE 005AFE55 / JMP 005AFE36 (skip NULL FUN_005af4a0 call)");
}

static BYTE* g_pCollisionNullNodeCallStub = NULL;

/* ================================================================
 * PatchCollisionNullNodeCallGuard_005AFE44 - Guard zero nodes before FUN_005af4a0
 *
 * Some list entries hold a NULL collision node pointer even though the
 * list node exists. The iterator still calls FUN_005af4a0 with NULL
 * param_2, which crashes inside that function at 0x005AF4E7. This
 * patch redirects the call at 0x005AFE44 through a tiny stub that
 * checks the node pointer before invoking FUN_005af4a0; if the pointer
 * is NULL, the stub simply returns 0.0 without touching the FPU stack.
 * ================================================================ */
static void PatchCollisionNullNodeCallGuard_005AFE44(void) {
    BYTE* target = (BYTE*)0x005AFE44;
    const BYTE expectedCall[5] = {0xE8, 0x57, 0xF6, 0xFF, 0xFF};

    if (g_pCollisionNullNodeCallStub != NULL) {
        ProxyLog("  PatchCollisionNullNodeCallGuard_005AFE44: already installed stub");
        return;
    }

    if (IsBadReadPtr(target, 5)) {
        ProxyLog("  PatchCollisionNullNodeCallGuard_005AFE44: call address not readable, skipped");
        return;
    }

    BYTE existingCall[5];
    memcpy(existingCall, target, sizeof(existingCall));
    if (memcmp(existingCall, expectedCall, sizeof(existingCall)) != 0) {
        ProxyLog("  PatchCollisionNullNodeCallGuard_005AFE44: unexpected bytes at 0x005AFE44, skipped");
        return;
    }

    BYTE* stub = (BYTE*)VirtualAlloc(NULL, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub) {
        ProxyLog("  PatchCollisionNullNodeCallGuard_005AFE44: stub allocation failed");
        return;
    }

    /* Stub template: mov eax,[esp+0x04]; test eax,eax; jne +5 -> real call;
     * fldz; ret 0x10; jmp FUN_005af4a0
     */
    const BYTE stubTemplate[22] = {
        0x8B, 0x44, 0x24, 0x04,
        0x85, 0xC0,
        0x0F, 0x85, 0x05, 0x00, 0x00, 0x00,
        0xD9, 0xEE,
        0xC2, 0x10, 0x00,
        0xE9, 0x00, 0x00, 0x00, 0x00
    };
    memcpy(stub, stubTemplate, sizeof(stubTemplate));

    /* Fill the JMP operand to FUN_005af4a0 */
    DWORD rel = (DWORD)((BYTE*)0x005AF4A0 - (stub + 22));
    *(DWORD*)(stub + 18) = rel;

    /* Replace the call instruction with a call to our stub */
    DWORD oldProt;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    target[0] = 0xE8; /* CALL rel32 */
    *(DWORD*)(target + 1) = (DWORD)(stub - (target + 5));
    VirtualProtect(target, 5, oldProt, &oldProt);

    g_pCollisionNullNodeCallStub = stub;
    ProxyLog("  PatchCollisionNullNodeCallGuard_005AFE44: stub installed at %p", stub);
}

/* ================================================================
 * PatchTGLFindEntry - Fix NULL+0x1C sentinel from TGL lookup
 *
 * FUN_006D1E10 (TGL::FindEntry) returns `this + 0x1C` as a pointer
 * to the default/empty entry. When the TGL file fails to load in
 * headless mode, `this` is NULL, so the function returns 0x1C --
 * a non-NULL invalid pointer that passes all NULL checks downstream
 * and crashes when dereferenced (reads at address 0x24 = 0x1C+8).
 *
 * Fix: Insert a check at function entry. If ECX (this) is NULL,
 * return NULL immediately (XOR EAX,EAX / RET 4). Otherwise, fall
 * through to the original code.
 *
 * Original bytes at 0x006D1E10:
 *   8B 44 24 04   MOV EAX,[ESP+4]   (4 bytes)
 *   56            PUSH ESI           (1 byte)
 *   85 C0         TEST EAX,EAX       (continues at 0x006D1E15)
 * ================================================================ */
static void PatchTGLFindEntry(void) {
    static BYTE cave[] = {
        0x85, 0xC9,             /* TEST ECX,ECX          */
        0x75, 0x05,             /* JNZ  +5 (.original)   */
        0x33, 0xC0,             /* XOR  EAX,EAX          */
        0xC2, 0x04, 0x00,       /* RET  4                */
        /* .original: */
        0x8B, 0x44, 0x24, 0x04, /* MOV  EAX,[ESP+4]      */
        0x56,                   /* PUSH ESI               */
        0xE9, 0x00, 0x00, 0x00, 0x00  /* JMP 0x006D1E15  (fixup) */
    };
    BYTE* pCave;
    DWORD oldProt;
    DWORD jmpFrom, jmpTo;

    pCave = (BYTE*)VirtualAlloc(NULL, sizeof(cave),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pCave) {
        ProxyLog("  PatchTGLFindEntry: VirtualAlloc failed");
        return;
    }
    memcpy(pCave, cave, sizeof(cave));

    /* Fix up JMP rel32: offset = target - (addr_after_jmp) */
    jmpFrom = (DWORD)(pCave + 19);   /* address after the JMP instruction */
    jmpTo   = 0x006D1E15;            /* original TEST EAX,EAX */
    *(DWORD*)(pCave + 15) = jmpTo - jmpFrom;

    /* Overwrite function entry: JMP to cave (exactly 5 bytes) */
    VirtualProtect((void*)0x006D1E10, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    *(BYTE*)0x006D1E10 = 0xE9;       /* JMP rel32 */
    *(DWORD*)0x006D1E11 = (DWORD)pCave - (0x006D1E10 + 5);
    VirtualProtect((void*)0x006D1E10, 5, oldProt, &oldProt);

    ProxyLog("  PatchTGLFindEntry: 0x006D1E10 -> cave at %p (NULL this returns NULL)",
             pCave);
}

/* ================================================================
 * PatchNetworkUpdateNullLists - Fix malformed update packets for headless ships
 *
 * FUN_005b17f0 (network object state update) builds a flags byte that
 * indicates which data sections follow in the update packet. Bit 0x20
 * means "subsystem data follows" and bit 0x80 means "weapon data".
 *
 * In headless mode, ship objects have no subsystems or weapons (the
 * linked lists at object+0x284 are NULL). The flags byte is written
 * to the stream with these bits set, but the loops that would write
 * the actual data crash (or are VEH-skipped). This produces a packet
 * where the flags promise data that doesn't exist, causing the client
 * to misparse the packet and interpret the ship as destroyed.
 *
 * Fix: Code cave at the flags-byte-write point (0x005b1d57). Before
 * writing the flags, check if ESI+0x284 (subsystem/weapon list) is
 * NULL. If NULL, clear bits 0x20 and 0x80 so the client knows to
 * skip those sections.
 *
 * Patched bytes at 0x005b1d57 (5 bytes):
 *   8B 4C 24 14  MOV ECX,[ESP+0x14]  (4 bytes)
 *   51           PUSH ECX            (1 byte)
 *   -> replaced with JMP to code cave
 *   Code cave executes the check, then these two instructions, then
 *   JMP back to 0x005b1d5c.
 * ================================================================ */
static void PatchNetworkUpdateNullLists(void) {
    static BYTE cave[] = {
        /* Save EAX (we need it for the check) */
        0x50,                               /* PUSH EAX                    */
        /* Check if subsystem/weapon list pointer is NULL */
        0x8B, 0x86, 0x84, 0x02, 0x00, 0x00, /* MOV EAX,[ESI+0x284]        */
        0x85, 0xC0,                         /* TEST EAX,EAX                */
        0x75, 0x05,                         /* JNZ +5 (.has_lists)         */
        /* List is NULL: clear bits 0x20 and 0x80 from flags */
        0x80, 0x64, 0x24, 0x18, 0x5F,       /* AND byte [ESP+0x18],0x5F   */
        /* .has_lists: */
        0x58,                               /* POP EAX                     */
        /* Execute original 2 instructions we overwrote */
        0x8B, 0x4C, 0x24, 0x14,             /* MOV ECX,[ESP+0x14]          */
        0x51,                               /* PUSH ECX                    */
        /* Jump back to original code */
        0xE9, 0x00, 0x00, 0x00, 0x00        /* JMP 0x005b1d5c (fixup)     */
    };
    BYTE* pCave;
    DWORD oldProt;
    DWORD jmpFrom, jmpTo;

    pCave = (BYTE*)VirtualAlloc(NULL, sizeof(cave),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pCave) {
        ProxyLog("  PatchNetworkUpdateNullLists: VirtualAlloc failed");
        return;
    }
    memcpy(pCave, cave, sizeof(cave));

    /* Fix up JMP rel32 in cave: offset = target - addr_after_jmp */
    jmpFrom = (DWORD)(pCave + sizeof(cave));   /* address after the JMP */
    jmpTo   = 0x005b1d5c;                      /* LEA ECX,[ESP+0x74] */
    *(DWORD*)(pCave + sizeof(cave) - 4) = jmpTo - jmpFrom;

    /* Overwrite 5 bytes at 0x005b1d57: JMP to cave */
    VirtualProtect((void*)0x005b1d57, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    *(BYTE*)0x005b1d57 = 0xE9;
    *(DWORD*)0x005b1d58 = (DWORD)pCave - (0x005b1d57 + 5);
    VirtualProtect((void*)0x005b1d57, 5, oldProt, &oldProt);

    ProxyLog("  PatchNetworkUpdateNullLists: 0x005b1d57 -> cave at %p "
             "(clear subsys/weapon flags when lists NULL)", pCave);
}

/* PatchChecksumAlwaysPass REMOVED - flag=0 means "no mismatches" which is
 * correct for first player connecting (no peers to compare against).
 * Forcing flag=1 corrupted the Settings packet with bogus mismatch data. */

typedef unsigned int (__attribute__((fastcall)) *SubsysHashFn)(int subsysBase);
static SubsysHashFn g_pfnSubsysHashReal = (SubsysHashFn)0x005b5eb0;

static volatile LONG g_subsysHashTraceSeq = 0;
static volatile LONG g_subsysHashTraceLines = 0;
static int g_subsysHashTraceEnabled = -1;
static unsigned int g_subsysHashLastValue = 0;
static int g_subsysHashLastShip = 0;
static DWORD g_subsysHashLastTick = 0;

static int SubsysHashTraceIsEnabled(void) {
    char val[16];
    DWORD n;
    if (g_subsysHashTraceEnabled >= 0) return g_subsysHashTraceEnabled;
    n = GetEnvironmentVariableA("STBC_TRACE_SUBSYS_HASH", val, sizeof(val));
    if (n == 0 || n >= sizeof(val)) {
        g_subsysHashTraceEnabled = 1; /* default ON for active triage */
    } else {
        char c = val[0];
        g_subsysHashTraceEnabled =
            !(c == '0' || c == 'n' || c == 'N' || c == 'f' || c == 'F');
    }
    return g_subsysHashTraceEnabled;
}

static int SubsysHashReadU32(int addr, unsigned int* out) {
    if (addr == 0 || !out) return 0;
    if (IsBadReadPtr((const void*)addr, 4)) return 0;
    *out = *(unsigned int*)addr;
    return 1;
}

static int SubsysHashReadFloat(int addr, float* out) {
    if (addr == 0 || !out) return 0;
    if (IsBadReadPtr((const void*)addr, 4)) return 0;
    *out = *(float*)addr;
    return 1;
}

static void SubsysHashTraceSlot(int subsysBase, int offset, const char* name) {
    unsigned int ptr = 0;
    unsigned int state = 0;
    float f20 = 0.0f, f28 = 0.0f, f2c = 0.0f, f30 = 0.0f, f3c = 0.0f, f40 = 0.0f, f44 = 0.0f;
    int hasCore;

    if (!SubsysHashReadU32(subsysBase + offset, &ptr) || ptr == 0) {
        ProxyLog("      %-8s ptr=NULL", name);
        return;
    }
    if (!SubsysHashReadU32((int)ptr + 0x18, &state) || state == 0) {
        ProxyLog("      %-8s ptr=0x%08X state=NULL", name, ptr);
        return;
    }

    hasCore =
        SubsysHashReadFloat((int)state + 0x20, &f20) &&
        SubsysHashReadFloat((int)state + 0x28, &f28) &&
        SubsysHashReadFloat((int)state + 0x2C, &f2c) &&
        SubsysHashReadFloat((int)state + 0x30, &f30) &&
        SubsysHashReadFloat((int)state + 0x3C, &f3c) &&
        SubsysHashReadFloat((int)state + 0x40, &f40) &&
        SubsysHashReadFloat((int)state + 0x44, &f44);

    if (!hasCore) {
        ProxyLog("      %-8s ptr=0x%08X state=0x%08X (core fields unreadable)", name, ptr, state);
        return;
    }

    ProxyLog("      %-8s ptr=0x%08X state=0x%08X hp=%.3f a=%.3f b=%.3f c=%.3f d=%.3f e=%.3f f=%.3f",
             name, ptr, state, f20, f28, f2c, f30, f3c, f40, f44);

    if (offset == 0x44) {
        int i;
        char buf[320];
        int pos = 0;
        pos += wsprintfA(buf + pos, "      HullFacings ");
        for (i = 0; i < 6 && pos < (int)sizeof(buf) - 20; i++) {
            float lo = 0.0f, hi = 0.0f;
            if (SubsysHashReadFloat((int)state + 0x60 + i * 4, &lo) &&
                SubsysHashReadFloat((int)state + 0x78 + i * 4, &hi)) {
                pos += wsprintfA(buf + pos, "[%d:%.3f/%.3f] ", i, lo, hi);
            } else {
                pos += wsprintfA(buf + pos, "[%d:??] ", i);
            }
        }
        ProxyLog("%s", buf);
    }
}

static void SubsysHashTraceSnapshot(int subsysBase, unsigned int hash32) {
    unsigned short wireHash;
    unsigned int shipObj;
    unsigned int listHead = 0;
    unsigned int listCount = 0;
    DWORD now;
    LONG seq;
    LONG lines;

    if (!SubsysHashTraceIsEnabled()) return;

    shipObj = (unsigned int)(subsysBase - 0x27C);
    now = GetTickCount();
    if ((int)shipObj == g_subsysHashLastShip &&
        hash32 == g_subsysHashLastValue &&
        now - g_subsysHashLastTick < 1000) {
        return;
    }
    g_subsysHashLastShip = (int)shipObj;
    g_subsysHashLastValue = hash32;
    g_subsysHashLastTick = now;

    lines = InterlockedIncrement(&g_subsysHashTraceLines);
    if (lines > 2000) return; /* hard cap per run */

    SubsysHashReadU32((int)shipObj + 0x284, &listHead);
    SubsysHashReadU32((int)shipObj + 0x280, &listCount);
    wireHash = (unsigned short)((hash32 >> 16) ^ (hash32 & 0xFFFF));
    seq = InterlockedIncrement(&g_subsysHashTraceSeq);

    ProxyLog("SUBHASH #%ld ship=0x%08X hash32=0x%08X wire16=0x%04X listHead=0x%08X listCount=%u",
             seq, shipObj, hash32, (unsigned int)wireHash, listHead, listCount);
    SubsysHashTraceSlot(subsysBase, 0x34, "Sensors");
    SubsysHashTraceSlot(subsysBase, 0x38, "Unk+38");
    SubsysHashTraceSlot(subsysBase, 0x3C, "Unk+3C");
    SubsysHashTraceSlot(subsysBase, 0x40, "Unk+40");
    SubsysHashTraceSlot(subsysBase, 0x44, "Hull");
    SubsysHashTraceSlot(subsysBase, 0x48, "Shield");
    SubsysHashTraceSlot(subsysBase, 0x4C, "Engine");
    SubsysHashTraceSlot(subsysBase, 0x50, "Weapons");
    SubsysHashTraceSlot(subsysBase, 0x54, "Cloak");
    SubsysHashTraceSlot(subsysBase, 0x58, "Power");
    SubsysHashTraceSlot(subsysBase, 0x5C, "Repair");
    SubsysHashTraceSlot(subsysBase, 0x60, "Crew");
}

static unsigned int __attribute__((fastcall)) SubsysHashComputeAndTrace(int subsysBase) {
    unsigned int hash32 = g_pfnSubsysHashReal(subsysBase);
    SubsysHashTraceSnapshot(subsysBase, hash32);
    return hash32;
}

/* ================================================================
 * PatchSubsystemHashCheck - Fix false-positive anti-cheat kicks
 *
 * FUN_005b21c0 (ship network state update receiver) processes incoming
 * opcode 0x1C packets. It computes a hash over all ship subsystem states
 * (shields, weapons, hull, power, sensors) via FUN_005b5eb0(this+0x27c)
 * and compares it with the hash sent by the client.
 *
 * On our headless server, ships have no subsystem objects (the linked
 * list at this+0x284 is NULL). FUN_005b5eb0 iterates this list and
 * returns 0/garbage when it's empty. This ALWAYS mismatches the client's
 * valid hash, triggering false-positive cheat detection:
 *   -> Posts ET_BOOT_PLAYER event (0x8000f6)
 *   -> BootPlayerHandler sends type=4 sub-command=4 (kick) to client
 *   -> Client disconnects: "You have been disconnected from the host"
 *
 * Fix: Code cave replaces the CALL to FUN_005b5eb0 at 0x005b22b5.
 * Before computing the hash, check if the subsystem linked list head
 * at [ESI+0x284] is NULL. If NULL (no subsystems to hash), return the
 * RECEIVED hash value (EDI) so the comparison naturally passes. If the
 * list is valid, call the real FUN_005b5eb0 for normal anti-cheat.
 *
 * This keeps anti-cheat ACTIVE for any ship that has proper subsystem
 * data, while preventing false kicks for headless ships without it.
 *
 * Assembly context at 0x005b22af-0x005b22c9:
 *   005b22af: LEA ECX,[ESI+0x27c]   ; subsystem data base
 *   005b22b5: CALL FUN_005b5eb0     ; compute hash (5 bytes: E8 xx xx xx xx)
 *   005b22ba: MOV EDX,EAX
 *   005b22bc: SAR EDX,0x10
 *   005b22bf: MOVSX ECX,DX          ; high16
 *   005b22c2: MOVSX EAX,AX          ; low16
 *   005b22c5: XOR ECX,EAX           ; computed = high16 ^ low16
 *   005b22c7: CMP ECX,EDI           ; compare computed vs received
 *   005b22c9: JZ  005b2338          ; skip boot if equal
 * ================================================================ */

/* Code cave: check subsystem list, delegate or return received hash */
static BYTE g_subsysHashCave[32];

static void PatchSubsystemHashCheck(void) {
    BYTE* callSite = (BYTE*)0x005b22b5;  /* CALL FUN_005b5eb0 */
    DWORD oldProt;

    if (IsBadReadPtr(callSite, 5)) {
        ProxyLog("  PatchSubsystemHashCheck: address 0x005b22b5 not readable, skipped");
        return;
    }

    /* Verify it's a CALL rel32 (E8 xx xx xx xx) */
    if (callSite[0] != 0xE8) {
        ProxyLog("  PatchSubsystemHashCheck: expected E8 at 0x005b22b5, got 0x%02X - skipped",
                 (int)callSite[0]);
        return;
    }

    /* Build code cave:
     *   CMP DWORD PTR [ESI+0x284], 0   ; check subsystem list head
     *   JNE .call_real                  ; if list exists, compute real hash
     *   ; No subsystems: forge a hash that will match the received value (EDI)
     *   ; We need EAX to produce the same final result as EDI after:
     *   ;   MOV EDX,EAX / SAR EDX,10 / MOVSX ECX,DX / MOVSX EAX,AX / XOR ECX,EAX
     *   ; Simplest: return to AFTER the XOR (005b22c7) with ECX=EDI
     *   ; so CMP ECX,EDI succeeds immediately
     *   MOV ECX, EDI                   ; set computed = received
     *   JMP 0x005b22c7                 ; jump to CMP ECX,EDI (will match)
     * .call_real:
     *   JMP FUN_005b5eb0              ; original hash computation
     */
    BYTE* cave = g_subsysHashCave;
    DWORD caveAddr = (DWORD)cave;
    int i = 0;

    /* CMP DWORD PTR [ESI+0x284], 0  (81 BE 84 02 00 00 00 00 00 00) */
    cave[i++] = 0x81; cave[i++] = 0xBE;
    cave[i++] = 0x84; cave[i++] = 0x02; cave[i++] = 0x00; cave[i++] = 0x00;  /* offset 0x284 */
    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;  /* imm32 = 0 */

    /* JNE .call_real (75 XX) - skip MOV/ADD/JMP so we land at the real hash call */
    cave[i++] = 0x75;
    cave[i++] = 0x0A;  /* skip MOV ECX,EDI (2) + ADD ESP,4 (3) + JMP rel32 (5) = 10 bytes */

    /* MOV ECX, EDI  (89 F9) */
    cave[i++] = 0x89; cave[i++] = 0xF9;

    /* ADD ESP, 4 - pop the return address pushed by the CALL */
    cave[i++] = 0x83; cave[i++] = 0xC4; cave[i++] = 0x04;

    /* JMP 0x005b22c7  (E9 xx xx xx xx) - jump to CMP ECX,EDI */
    cave[i++] = 0xE9;
    {
        DWORD jmpTarget = 0x005b22c7;
        DWORD jmpFrom = caveAddr + i + 4;  /* address after this JMP instruction */
        DWORD rel = jmpTarget - jmpFrom;
        cave[i++] = (BYTE)(rel);
        cave[i++] = (BYTE)(rel >> 8);
        cave[i++] = (BYTE)(rel >> 16);
        cave[i++] = (BYTE)(rel >> 24);
    }

    /* .call_real: JMP SubsysHashComputeAndTrace (E9 xx xx xx xx) */
    cave[i++] = 0xE9;
    {
        DWORD jmpTarget = (DWORD)(void*)SubsysHashComputeAndTrace;
        DWORD jmpFrom = caveAddr + i + 4;
        DWORD rel = jmpTarget - jmpFrom;
        cave[i++] = (BYTE)(rel);
        cave[i++] = (BYTE)(rel >> 8);
        cave[i++] = (BYTE)(rel >> 16);
        cave[i++] = (BYTE)(rel >> 24);
    }

    /* Make code cave executable */
    VirtualProtect(cave, sizeof(g_subsysHashCave), PAGE_EXECUTE_READWRITE, &oldProt);

    /* Patch the CALL at 0x005b22b5 to point to our cave instead of FUN_005b5eb0 */
    VirtualProtect(callSite, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    {
        DWORD rel = caveAddr - ((DWORD)callSite + 5);
        callSite[1] = (BYTE)(rel);
        callSite[2] = (BYTE)(rel >> 8);
        callSite[3] = (BYTE)(rel >> 16);
        callSite[4] = (BYTE)(rel >> 24);
    }
    VirtualProtect(callSite, 5, oldProt, &oldProt);

    ProxyLog("  PatchSubsystemHashCheck: code cave at %p, redirected CALL at 0x005b22b5",
             (void*)cave);
    ProxyLog("    -> NULL subsystem list [ESI+0x284]: skip hash (match received)");
    ProxyLog("    -> Valid subsystem list: call traced hash wrapper (FUN_005b5eb0)");
}

/* ================================================================
 * PatchCompressedVectorRead - Prevent cascading crash in FUN_006d2eb0
 *
 * FUN_006d2eb0 reads a compressed 3-byte vector from a network stream
 * using four vtable calls: three ReadByte calls (vtable+0x50) and one
 * decode call (vtable+0xB8 with 6 stack params, __thiscall, callee-clean).
 *
 * If the stream reader object's vtable pointer is corrupted (e.g. from
 * a prior memory corruption or stack misalignment), ALL four vtable calls
 * fail. The VEH handler recovers from each by popping the return address,
 * but the fourth call's callee was supposed to clean 24 bytes of params
 * via RET 0x18. Since the callee never runs, those params remain on the
 * stack. The function's epilogue (POP ESI; ADD ESP,0xC; RET 0xC) then
 * uses the wrong stack offsets, popping garbage as the return address.
 *
 * The VEH handler finds the real return address deeper on the stack and
 * adjusts ESP, but this leaves the CALLER's stack misaligned by 12 bytes.
 * The next call to FUN_006d2eb0 uses a wrong `this` pointer (offset by
 * 12 bytes into wrong memory), reads a garbage "vtable" = 1, and crashes
 * fatally at CALL [1 + 0x50] -> access violation at 0x00000051.
 *
 * Fix: Code cave at FUN_006d2eb0 entry (0x006D2EB0). Validate that the
 * vtable pointer (first DWORD of the this object) is in the valid .rdata
 * range for stbc.exe (0x00800000-0x008FFFFF). If invalid, skip the
 * function entirely: zero-fill the 3 output float params and RET 0xC.
 *
 * Overwritten bytes at 0x006D2EB0 (6 bytes):
 *   83 EC 0C     SUB ESP,0xC
 *   56           PUSH ESI
 *   8B F1        MOV ESI,ECX
 *   -> replaced with: E9 xx xx xx xx  JMP cave
 *                      90              NOP
 *   Cave executes validation, then these 6 bytes, then JMP back.
 *
 * Also protects FUN_006d2fd0 (0x006D2FD0) which has the same structure
 * and the same cascading failure risk. Its first 6 bytes are identical.
 * ================================================================ */
static void PatchCompressedVectorRead(void) {
    /* We patch TWO functions: FUN_006d2eb0 and FUN_006d2fd0.
     * Both have identical prologues and identical vtable-crash risk.
     * Each gets its own code cave. */
    static BYTE cave1[80]; /* cave for FUN_006d2eb0 (RET 0xC) */
    static BYTE cave2[80]; /* cave for FUN_006d2fd0 (RET 0x10) */
    DWORD oldProt;
    int i;

    /* --- Cave 1: FUN_006d2eb0 (3 params, RET 0xC) --- */
    {
        BYTE* site = (BYTE*)0x006D2EB0;
        BYTE* cave = cave1;
        DWORD caveAddr = (DWORD)cave;

        /* Verify original bytes: 83 EC 0C 56 8B F1 */
        if (IsBadReadPtr(site, 6)) {
            ProxyLog("  PatchCompressedVectorRead: 0x006D2EB0 not readable, skipped");
            goto patch2;
        }
        if (site[0] != 0x83 || site[1] != 0xEC || site[2] != 0x0C ||
            site[3] != 0x56 || site[4] != 0x8B || site[5] != 0xF1) {
            ProxyLog("  PatchCompressedVectorRead: unexpected bytes at 0x006D2EB0, skipped");
            goto patch2;
        }

        i = 0;
        /* Validate this pointer (ECX) and its vtable pointer */
        cave[i++] = 0x85; cave[i++] = 0xC9;             /* TEST ECX,ECX                */
        cave[i++] = 0x74;                                 /* JZ .bad_vtable              */
        cave[i++] = 0x00; /* placeholder */
        {
            int jz_offset_pos = i - 1;

            cave[i++] = 0x8B; cave[i++] = 0x01;         /* MOV EAX,[ECX]               */
            cave[i++] = 0x3D;                             /* CMP EAX, imm32              */
            cave[i++] = 0x00; cave[i++] = 0x00;
            cave[i++] = 0x80; cave[i++] = 0x00;           /* 0x00800000                  */
            cave[i++] = 0x72; /* JB .bad_vtable */
            cave[i++] = 0x00; /* placeholder */
            {
                int jb_offset_pos = i - 1;

                cave[i++] = 0x3D;                         /* CMP EAX, imm32              */
                cave[i++] = 0x00; cave[i++] = 0x00;
                cave[i++] = 0x90; cave[i++] = 0x00;       /* 0x00900000                  */
                cave[i++] = 0x73; /* JAE .bad_vtable */
                cave[i++] = 0x00; /* placeholder */
                {
                    int jae_offset_pos = i - 1;

                /* VALID vtable: execute original 6 bytes and return to function body */
                cave[i++] = 0x83; cave[i++] = 0xEC; cave[i++] = 0x0C; /* SUB ESP,0xC    */
                cave[i++] = 0x56;                                       /* PUSH ESI        */
                cave[i++] = 0x8B; cave[i++] = 0xF1;                    /* MOV ESI,ECX     */
                cave[i++] = 0xE9;                                       /* JMP back        */
                {
                    DWORD from = caveAddr + i + 4;
                    DWORD to   = 0x006D2EB6;  /* instruction after the overwritten bytes */
                    DWORD rel = to - from;
                    cave[i++] = (BYTE)(rel);
                    cave[i++] = (BYTE)(rel >> 8);
                    cave[i++] = (BYTE)(rel >> 16);
                    cave[i++] = (BYTE)(rel >> 24);
                }

                    /* .bad_vtable: zero-fill 3 output float params and return cleanly */
                    {
                        int bad_vtable_pos = i;
                        cave[jz_offset_pos]  = (BYTE)(bad_vtable_pos - (jz_offset_pos + 1));
                        cave[jb_offset_pos]  = (BYTE)(bad_vtable_pos - (jb_offset_pos + 1));
                        cave[jae_offset_pos] = (BYTE)(bad_vtable_pos - (jae_offset_pos + 1));
                    }
                    /* The 3 params are pointers to floats on the caller's stack.
                     * [ESP+4] = param_1 (float*), [ESP+8] = param_2 (float*), [ESP+C] = param_3 (float*)
                     * (ESP+0 is the return address since we haven't done SUB ESP yet) */
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x04;
                                                               /* MOV EAX,[ESP+4] (param_1)  */
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                                                               /* MOV DWORD [EAX], 0          */
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x08;
                                                               /* MOV EAX,[ESP+8] (param_2)  */
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                                                               /* MOV DWORD [EAX], 0          */
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x0C;
                                                               /* MOV EAX,[ESP+C] (param_3)  */
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                                                               /* MOV DWORD [EAX], 0          */
                    cave[i++] = 0xC2; cave[i++] = 0x0C; cave[i++] = 0x00;
                                                               /* RET 0xC (clean 3 params)    */
                }
            }
        }

        /* Make cave executable */
        VirtualProtect(cave, sizeof(cave1), PAGE_EXECUTE_READWRITE, &oldProt);

        /* Overwrite FUN_006d2eb0 entry: JMP cave + NOP */
        VirtualProtect(site, 6, PAGE_EXECUTE_READWRITE, &oldProt);
        site[0] = 0xE9;
        {
            DWORD rel = caveAddr - ((DWORD)site + 5);
            site[1] = (BYTE)(rel);
            site[2] = (BYTE)(rel >> 8);
            site[3] = (BYTE)(rel >> 16);
            site[4] = (BYTE)(rel >> 24);
        }
        site[5] = 0x90; /* NOP */
        VirtualProtect(site, 6, oldProt, &oldProt);

        ProxyLog("  PatchCompressedVectorRead: FUN_006d2eb0 -> cave at %p "
                 "(vtable validation + safe RET 0xC)", (void*)cave);
    }

patch2:
    /* --- Cave 2: FUN_006d2fd0 (4 params, RET 0x10) --- */
    {
        BYTE* site = (BYTE*)0x006D2FD0;
        BYTE* cave = cave2;
        DWORD caveAddr = (DWORD)cave;

        /* Verify original bytes: 83 EC 0C 56 8B F1 */
        if (IsBadReadPtr(site, 6)) {
            ProxyLog("  PatchCompressedVectorRead: 0x006D2FD0 not readable, skipped");
            return;
        }
        if (site[0] != 0x83 || site[1] != 0xEC || site[2] != 0x0C ||
            site[3] != 0x56 || site[4] != 0x8B || site[5] != 0xF1) {
            ProxyLog("  PatchCompressedVectorRead: unexpected bytes at 0x006D2FD0, skipped");
            return;
        }

        i = 0;
        /* Same validation logic as cave1 */
        cave[i++] = 0x85; cave[i++] = 0xC9;             /* TEST ECX,ECX                */
        cave[i++] = 0x74;                                 /* JZ .bad_vtable              */
        cave[i++] = 0x00; /* placeholder */
        {
            int jz_offset_pos = i - 1;

            cave[i++] = 0x8B; cave[i++] = 0x01;         /* MOV EAX,[ECX]               */
            cave[i++] = 0x3D;
            cave[i++] = 0x00; cave[i++] = 0x00;
            cave[i++] = 0x80; cave[i++] = 0x00;           /* CMP EAX, 0x00800000         */
            cave[i++] = 0x72;
            cave[i++] = 0x00; /* JB placeholder */
            {
                int jb_offset_pos = i - 1;

                cave[i++] = 0x3D;
                cave[i++] = 0x00; cave[i++] = 0x00;
                cave[i++] = 0x90; cave[i++] = 0x00;       /* CMP EAX, 0x00900000         */
                cave[i++] = 0x73;
                cave[i++] = 0x00; /* JAE placeholder */
                {
                    int jae_offset_pos = i - 1;

                    /* VALID: execute original bytes and continue */
                    cave[i++] = 0x83; cave[i++] = 0xEC; cave[i++] = 0x0C;
                    cave[i++] = 0x56;
                    cave[i++] = 0x8B; cave[i++] = 0xF1;
                    cave[i++] = 0xE9;
                    {
                        DWORD from = caveAddr + i + 4;
                        DWORD to   = 0x006D2FD6;
                        DWORD rel = to - from;
                        cave[i++] = (BYTE)(rel);
                        cave[i++] = (BYTE)(rel >> 8);
                        cave[i++] = (BYTE)(rel >> 16);
                        cave[i++] = (BYTE)(rel >> 24);
                    }

                    /* .bad_vtable: zero-fill 3 output params (skip param_4) and RET 0x10 */
                    {
                        int bad_vtable_pos = i;
                        cave[jz_offset_pos]  = (BYTE)(bad_vtable_pos - (jz_offset_pos + 1));
                        cave[jb_offset_pos]  = (BYTE)(bad_vtable_pos - (jb_offset_pos + 1));
                        cave[jae_offset_pos] = (BYTE)(bad_vtable_pos - (jae_offset_pos + 1));
                    }
                    /* FUN_006d2fd0 params: [ESP+4]=p1, [ESP+8]=p2, [ESP+C]=p3, [ESP+10]=p4(char) */
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x04;
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x08;
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                    cave[i++] = 0x8B; cave[i++] = 0x44; cave[i++] = 0x24; cave[i++] = 0x0C;
                    cave[i++] = 0xC7; cave[i++] = 0x00;
                    cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00; cave[i++] = 0x00;
                    cave[i++] = 0xC2; cave[i++] = 0x10; cave[i++] = 0x00;
                                                               /* RET 0x10 (clean 4 params)   */
                }
            }
        }

        VirtualProtect(cave, sizeof(cave2), PAGE_EXECUTE_READWRITE, &oldProt);

        VirtualProtect(site, 6, PAGE_EXECUTE_READWRITE, &oldProt);
        site[0] = 0xE9;
        {
            DWORD rel = caveAddr - ((DWORD)site + 5);
            site[1] = (BYTE)(rel);
            site[2] = (BYTE)(rel >> 8);
            site[3] = (BYTE)(rel >> 16);
            site[4] = (BYTE)(rel >> 24);
        }
        site[5] = 0x90;
        VirtualProtect(site, 6, oldProt, &oldProt);

        ProxyLog("  PatchCompressedVectorRead: FUN_006d2fd0 -> cave at %p "
                 "(vtable validation + safe RET 0x10)", (void*)cave);
    }
}

/* ================================================================
 * PatchDebugConsoleToFile - Replace debug console with file logging
 *
 * BC's embedded Python has ALL file I/O disabled (open, nt.open, AND
 * nt.write all fail). Python cannot write to files at all.
 *
 * Instead, we intercept the Python exception debug console function
 * (FUN_006f9470) and replace it with our own C function that:
 *   1. Calls PyErr_Fetch to get the exception
 *   2. For string exceptions (raise "text"), writes the text to state_dump.log
 *   3. Returns immediately (no popup, no "resume" prompt)
 *
 * StateDumper.py uses "raise text" to dump state. The exception propagates
 * to the C engine's exception handler (FUN_006f9b80) which calls our
 * replacement, writing the dump to file silently.
 *
 * Python C API addresses (from Ghidra analysis):
 *   PyErr_Fetch      = 0x00753110
 *   PyString_AsString = 0x007507d0  (returns ob_sval at +0x14, or 0 on type error)
 *   PyString_Type    = 0x0095e960
 *   _Py_NoneStruct   = 0x0095dd20
 * ================================================================ */
static FILE* g_pStateDump = NULL;
static FILE* g_pTraceLog = NULL;

/* Forward-declare Python C API functions needed before the main API block */
typedef void (__cdecl *pfn_PyErr_Fetch_Early)(void**, void**, void**);
#define PY_ErrFetch_Early ((pfn_PyErr_Fetch_Early)0x00753110)

#define PY_STRING_TYPE_ADDR  ((void*)0x0095e960)
typedef const char* (__cdecl *pfn_PyString_AsString)(void*);
#define PY_StringAsString ((pfn_PyString_AsString)0x007507d0)

/* Replacement for the debug console popup (FUN_006f9470).
 * Called by FUN_006f9b80 when a Python exception occurs and the
 * debug console flag (DAT_0099add6) is 1. */
static void __cdecl ReplacementDebugConsole(void) {
    static int callCount = 0;
    void *excType = NULL, *excValue = NULL, *excTB = NULL;
    const char *text = NULL;

    callCount++;

    /* Diagnostic: log every entry to confirm handler is reached */
    if (g_pStateDump) {
        fprintf(g_pStateDump, "\n[DIAG] ReplacementDebugConsole called (#%d)\n", callCount);
        fflush(g_pStateDump);
    }
    ProxyLog("  ReplacementDebugConsole: entry #%d", callCount);

    /* Fetch the current exception (this clears the error indicator;
     * caller FUN_006f9b80 calls PY_ErrClear after us anyway) */
    PY_ErrFetch_Early(&excType, &excValue, &excTB);

    if (!excType) return;

    /* For string exceptions (raise "text"), excType IS the string.
     * Check ob_type at offset +4 against PyString_Type. */
    if (!IsBadReadPtr(excType, 24) &&
        *(void**)((char*)excType + 4) == PY_STRING_TYPE_ADDR) {
        text = PY_StringAsString(excType);
    }
    /* For class exceptions, try excValue as string */
    else if (excValue && !IsBadReadPtr(excValue, 24) &&
             *(void**)((char*)excValue + 4) == PY_STRING_TYPE_ADDR) {
        text = PY_StringAsString(excValue);
    }

    if (text && g_pStateDump) {
        fprintf(g_pStateDump, "%s\n", text);
        fflush(g_pStateDump);
    }

    /* Log a short note to ddraw_proxy.log */
    if (text) {
        /* Show first 80 chars in proxy log */
        char preview[84];
        int i;
        for (i = 0; i < 80 && text[i]; i++) {
            preview[i] = (text[i] == '\n' || text[i] == '\r') ? ' ' : text[i];
        }
        preview[i] = '\0';
        ProxyLog("  Python exception -> state_dump.log: %.80s%s",
                 preview, text[i] ? "..." : "");
    }

    /* Leak excType/excValue/excTB refs - harmless for rare exception events.
     * Caller (FUN_006f9b80) will call PY_ErrClear which is now a no-op
     * since PY_ErrFetch already cleared the indicator. */
}

/* WriteTraceToFile - Same as ReplacementDebugConsole but writes to g_pTraceLog.
 * Called by TryFlushPyTrace to send function call traces to py_trace.log
 * instead of state_dump.log, keeping the two outputs separate. */
static void WriteTraceToFile(void) {
    void *excType = NULL, *excValue = NULL, *excTB = NULL;
    const char *text = NULL;

    PY_ErrFetch_Early(&excType, &excValue, &excTB);
    if (!excType) return;

    /* For string exceptions (raise "text"), excType IS the string. */
    if (!IsBadReadPtr(excType, 24) &&
        *(void**)((char*)excType + 4) == PY_STRING_TYPE_ADDR) {
        text = PY_StringAsString(excType);
    }
    /* For class exceptions, try excValue as string */
    else if (excValue && !IsBadReadPtr(excValue, 24) &&
             *(void**)((char*)excValue + 4) == PY_STRING_TYPE_ADDR) {
        text = PY_StringAsString(excValue);
    }

    if (text && g_pTraceLog) {
        fprintf(g_pTraceLog, "%s\n", text);
        fflush(g_pTraceLog);
    }
}

static void PatchDebugConsoleToFile(void) {
    char sdPath[MAX_PATH];
    BYTE* func = (BYTE*)0x006f9470;
    DWORD oldProt;

    /* Open state_dump.log (F12 state dumps go here) */
    lstrcpynA(sdPath, g_szBasePath, MAX_PATH);
    lstrcatA(sdPath, "state_dump.log");
    g_pStateDump = fopen(sdPath, "w");
    if (g_pStateDump) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_pStateDump,
                "# STBC State Dump Log\n"
                "# Session started: %04d-%02d-%02d %02d:%02d:%02d\n"
                "# Press F12 at any time to dump engine state.\n"
                "# ============================================================\n\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        fflush(g_pStateDump);
        ProxyLog("  PatchDebugConsoleToFile: opened %s", sdPath);
    } else {
        ProxyLog("  PatchDebugConsoleToFile: WARNING could not open %s", sdPath);
    }

    /* Open py_trace.log (function call trace goes here) */
    lstrcpynA(sdPath, g_szBasePath, MAX_PATH);
    lstrcatA(sdPath, "py_trace.log");
    g_pTraceLog = fopen(sdPath, "w");
    if (g_pTraceLog) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_pTraceLog,
                "# STBC Python Function Trace\n"
                "# Session started: %04d-%02d-%02d %02d:%02d:%02d\n"
                "# Format: filename:funcname(param=value, ...)\n"
                "# ============================================================\n\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        fflush(g_pTraceLog);
        ProxyLog("  PatchDebugConsoleToFile: opened %s (trace)", sdPath);
    } else {
        ProxyLog("  PatchDebugConsoleToFile: WARNING could not open trace log");
    }

    /* Patch FUN_006f9470 entry: MOV EAX, <addr>; JMP EAX (7 bytes) */
    if (!IsBadReadPtr(func, 7)) {
        VirtualProtect(func, 7, PAGE_EXECUTE_READWRITE, &oldProt);
        func[0] = 0xB8;  /* MOV EAX, imm32 */
        *(DWORD*)(func + 1) = (DWORD)ReplacementDebugConsole;
        func[5] = 0xFF;  /* JMP EAX */
        func[6] = 0xE0;
        VirtualProtect(func, 7, oldProt, &oldProt);
        ProxyLog("  PatchDebugConsoleToFile: patched FUN_006f9470 -> 0x%08X",
                 (unsigned)(DWORD)ReplacementDebugConsole);
    }

    /* Ensure debug console flag (DAT_0099add6) is 1 so our path is taken
     * in FUN_006f9b80 (the exception handler dispatcher) */
    {
        BYTE* flag = (BYTE*)0x0099add6;
        if (!IsBadReadPtr(flag, 1)) {
            VirtualProtect(flag, 1, PAGE_READWRITE, &oldProt);
            *flag = 1;
            VirtualProtect(flag, 1, oldProt, &oldProt);
        }
    }
}

/* ================================================================
 * PatchCreateAppModule - Create "App" SWIG module before init imports it
 *
 * UtopiaApp::Init at 0x0043b1b9 calls TG_ImportModule("App").
 * Normally the game provides App through a mechanism we can't replicate
 * in stub mode (no App.py on disk, not frozen, not built-in as "App").
 *
 * We inject a code cave that calls our C function CreateAppModuleCallback()
 * which creates the App module via Py_InitModule4 and runs post-init
 * diagnostics via PyRun_SimpleString (on the main thread, so thread-safe).
 *
 * Original bytes at 0x0043b1b9:
 *   53                 PUSH EBX         (param2 = 0)
 *   68 80 9c 8d 00     PUSH 0x008d9c80  (param1 = "App")
 *   E8 ...             CALL TG_ImportModule
 * ================================================================ */

/* Python C API helpers */
typedef void* (__cdecl *pfn_Py_InitModule4)(const char*, void*, const char*, void*, int);
typedef int   (__cdecl *pfn_PyRunSimple)(const char*);
typedef int   (__cdecl *pfn_PyErrOccurred)(void);
typedef void  (__cdecl *pfn_PyErrClear)(void);
typedef void  (__cdecl *pfn_PyErrPrint)(void);
typedef void* (__cdecl *pfn_PyImport_GetModuleDict)(void);
typedef void* (__cdecl *pfn_PyDict_GetItemString)(void*, const char*);
typedef void* (__cdecl *pfn_PyImport_ImportModule)(const char*);
typedef void* (__cdecl *pfn_PyObject_GetAttrString)(void*, const char*);
typedef void* (__cdecl *pfn_PyObject_Str)(void*);
typedef const char* (__cdecl *pfn_PyString_AsString)(void*);
typedef void* (__cdecl *pfn_PyImport_AddModule)(const char*);
typedef void* (__cdecl *pfn_PyModule_GetDict)(void*);
typedef void* (__cdecl *pfn_PyRun_String)(const char*, int, void*, void*);
typedef void  (__cdecl *pfn_PyErr_Fetch)(void**, void**, void**);
typedef void* (__cdecl *pfn_PyObject_Repr)(void*);

#define PY_InitModule4         ((pfn_Py_InitModule4)0x0074d140)
#define PY_RunSimpleString     ((pfn_PyRunSimple)0x0074ae80)
#define PY_ErrOccurred         ((pfn_PyErrOccurred)0x00752ec0)
#define PY_ErrClear            ((pfn_PyErrClear)0x00753140)
#define PY_ErrPrint            ((pfn_PyErrPrint)0x0074af10)
#define PY_GetModuleDict       ((pfn_PyImport_GetModuleDict)0x0075b250)
#define PY_DictGetItemString   ((pfn_PyDict_GetItemString)0x00752cd0)
#define PY_ImportModule        ((pfn_PyImport_ImportModule)0x0075bbf0)
#define PY_AddModule           ((pfn_PyImport_AddModule)0x0075b890)
#define PY_ModuleGetDict       ((pfn_PyModule_GetDict)0x00773990)
#define PY_RunString           ((pfn_PyRun_String)0x0074b640)
#define PY_ErrFetch            ((pfn_PyErr_Fetch)0x00753110)

/* Log which modules are in sys.modules (C API, no Python execution needed) */
static void LogPyModules(const char* label) {
    void *modules = PY_GetModuleDict();
    if (!modules) { ProxyLog("  %s: sys.modules = NULL", label); return; }

    const char* check[] = {"App", "Appc", "Autoexec", "Local",
                           "Custom.DedicatedServer", "cPickle", "copy_reg",
                           "TopWindow", "MainMenu", "Multiplayer",
                           "FontsAndIcons", "UITheme", "LoadInterface", NULL};
    int i;
    char buf[1024];
    int pos = 0;
    pos += wsprintfA(buf + pos, "  %s: ", label);
    for (i = 0; check[i]; i++) {
        void *m = PY_DictGetItemString(modules, check[i]);
        if (m) pos += wsprintfA(buf + pos, "%s ", check[i]);
    }
    ProxyLog("%s", buf);
}

/* ================================================================
 * RunPyCode - Execute Python code using PyRun_String directly
 *
 * PyRun_SimpleString fails from TIMERPROC due to re-entrancy: it calls
 * FUN_0074bbf0(1) to adjust the nesting counter, then PyImport_AddModule
 * which can fail during re-entrant execution.
 *
 * This helper bypasses that by:
 * 1. Getting __main__ module from sys.modules dict (C API, always works)
 * 2. Getting its __dict__
 * 3. Calling PyRun_String directly with Py_file_input (0x101)
 * ================================================================ */
static int RunPyCode(const char* code) {
    void *mainMod, *mainDict, *result;

    if (PY_ErrOccurred()) PY_ErrClear();

    /* Try PyImport_AddModule first (standard path) */
    mainMod = PY_AddModule("__main__");
    if (!mainMod) {
        /* Fallback: get __main__ from sys.modules dict manually.
           PY_GetModuleDict + PY_DictGetItemString always work (used by
           LogPyModules successfully). */
        void *modules = PY_GetModuleDict();
        if (PY_ErrOccurred()) PY_ErrClear();
        if (modules)
            mainMod = PY_DictGetItemString(modules, "__main__");
        if (!mainMod) {
            ProxyLog("    RunPyCode: cannot get __main__ module");
            return -1;
        }
        ProxyLog("    RunPyCode: got __main__ via sys.modules fallback");
    }

    mainDict = PY_ModuleGetDict(mainMod);
    if (!mainDict) {
        ProxyLog("    RunPyCode: PyModule_GetDict returned NULL");
        return -1;
    }

    result = PY_RunString(code, 0x101, mainDict, mainDict);
    if (!result) {
        void *errType = NULL, *errValue = NULL, *errTB = NULL;
        PY_ErrFetch(&errType, &errValue, &errTB);
        if (errType) {
            /* Safely read type name: PyTypeObject->tp_name at +12 */
            const char *typeName = "(bad-ptr)";
            if (!IsBadReadPtr(errType, 16)) {
                const char *namePtr = *(const char**)((char*)errType + 12);
                if (namePtr && !IsBadReadPtr(namePtr, 4))
                    typeName = namePtr;
            }
            /* Safely read value: try ob_sval at +20 (PyStringObject) */
            const char *valStr = "(no-value)";
            if (errValue && !IsBadReadPtr(errValue, 24)) {
                const char *candidate = (const char*)errValue + 20;
                if (!IsBadReadPtr(candidate, 4))
                    valStr = candidate;
            }
            ProxyLog("    RunPyCode ERROR: type=0x%08X val=0x%08X [%s]: [%s]",
                     (unsigned)(DWORD)errType, (unsigned)(DWORD)errValue,
                     typeName, valStr);
        } else {
            ProxyLog("    RunPyCode: PyRun_String returned NULL (no error set)");
        }
        /* Note: PY_ErrFetch already cleared the error; we leak the refs (harmless) */
        return -1;
    }

    /* Leak the result ref (Py_None for statements) - harmless */
    return 0;
}
