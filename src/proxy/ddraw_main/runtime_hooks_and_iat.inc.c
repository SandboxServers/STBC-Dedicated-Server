/* ================================================================
 * PatchPyFatalError - Make Py_FatalError return instead of aborting
 *
 * Py_FatalError (0x0074b9e0) ends with JMP 0x0085a108 (tail call to
 * abort). ALL abort xrefs in the binary are JMP tail calls, so our
 * abort hook's RET pops garbage (saved registers, not return addr).
 *
 * Fix: Replace the JMP at 0x0074ba10 with POP EDI; POP ESI; RET
 * which properly unwinds the function prologue (PUSH ESI; PUSH EDI)
 * and returns to the caller. This lets init continue after errors
 * like missing modules (cPickle's copy_reg, etc).
 * ================================================================ */
static void PatchPyFatalError(void) {
    BYTE* pJmp = (BYTE*)0x0074ba10;
    DWORD oldProt;

    if (IsBadReadPtr(pJmp, 5)) {
        ProxyLog("  PatchPyFatalError: address not readable");
        return;
    }
    /* Verify it's a JMP (E9 xx xx xx xx) */
    if (pJmp[0] != 0xE9) {
        ProxyLog("  PatchPyFatalError: unexpected byte %02X (expected E9), skipped",
                 pJmp[0]);
        return;
    }

    VirtualProtect(pJmp, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    pJmp[0] = 0x5F; /* POP EDI */
    pJmp[1] = 0x5E; /* POP ESI */
    pJmp[2] = 0xC3; /* RET     */
    pJmp[3] = 0x90; /* NOP     */
    pJmp[4] = 0x90; /* NOP     */
    VirtualProtect(pJmp, 5, oldProt, &oldProt);
    ProxyLog("  PatchPyFatalError: patched 0x0074ba10 JMP->abort to POP EDI; POP ESI; RET");
}

/* ================================================================
 * PatchDirectDrawCreateExCache - Pre-fill DAT_009a12a4
 *
 * FUN_007c7f80 checks: if (DAT_009a12a4 != NULL) skip GetModuleHandle/GetProcAddress.
 * By setting this to OUR DirectDrawCreateEx, the game calls us directly
 * and bypasses apphelp.dll's shim (which crashes with proxy DDraw objects).
 * The adapter enumeration via FUN_007c8eb0 still runs normally through our
 * DirectDrawEnumerateExA export, populating DAT_009a1298/129c/12a0.
 * ================================================================ */
static void PatchDirectDrawCreateExCache(void) {
    DWORD oldProt;
    DWORD* pDDCreateExCache = (DWORD*)0x009A12A4;
    if (!IsBadReadPtr(pDDCreateExCache, 4) && *pDDCreateExCache == 0) {
        HMODULE hSelf = GetModuleHandleA("ddraw.dll");
        FARPROC pfn = GetProcAddress(hSelf, "DirectDrawCreateEx");
        if (pfn) {
            VirtualProtect(pDDCreateExCache, 4, PAGE_READWRITE, &oldProt);
            *pDDCreateExCache = (DWORD)pfn;
            VirtualProtect(pDDCreateExCache, 4, oldProt, &oldProt);
            ProxyLog("  PatchDirectDrawCreateExCache: [0x009A12A4] = DirectDrawCreateEx (0x%08X)",
                     (unsigned)(DWORD)pfn);
        }
    }
}

/* ================================================================
 * SIGABRT handler
 * ================================================================ */
static void __cdecl SigAbrtHandler(int sig) {
    DWORD* ebp;
    int i;
    (void)sig;
    ProxyLog("!!! SIGABRT caught - abort() was called!");
    __asm__("movl %%ebp, %0" : "=r" (ebp));
    ProxyLog("  Call stack:");
    for (i = 0; i < 20 && ebp && !IsBadReadPtr(ebp, 8); i++) {
        DWORD retAddr = ebp[1];
        ProxyLog("    [%d] 0x%08X", i, retAddr);
        ebp = (DWORD*)ebp[0];
        if ((DWORD)ebp < 0x10000 || (DWORD)ebp > 0x7FFFFFFF) break;
    }
}

/* ================================================================
 * ExitProcess hook - captures stack trace when game exits
 * ================================================================ */
typedef void (WINAPI *PFN_ExitProcess)(UINT uExitCode);
static PFN_ExitProcess g_pfnOrigExitProcess = NULL;

static void WINAPI HookedExitProcess(UINT uExitCode) {
    DWORD* ebp;
    int i;
    char buf[256];
    ProxyLog("!!! ExitProcess called with code %u (0x%08X)", uExitCode, uExitCode);

    __asm__("movl %%ebp, %0" : "=r" (ebp));
    ProxyLog("  EBP chain walk:");
    for (i = 0; i < 15 && ebp && !IsBadReadPtr(ebp, 8); i++) {
        DWORD retAddr = ebp[1];
        ResolveAddr(retAddr, buf, sizeof(buf));
        ProxyLog("    [%d] %s", i, buf);
        ebp = (DWORD*)ebp[0];
        if ((DWORD)ebp < 0x10000 || (DWORD)ebp > 0x7FFFFFFF) break;
    }
    if (g_pfnOrigExitProcess) g_pfnOrigExitProcess(uExitCode);
    TerminateProcess(GetCurrentProcess(), uExitCode);
}

/* ================================================================
 * MessageBoxA hooks - suppress CRT abort dialogs
 * ================================================================ */
typedef int (WINAPI *PFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
static PFN_MessageBoxA g_pfnOrigMessageBoxA = NULL;

static int WINAPI HookedMessageBoxA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    ProxyLog("!!! MessageBoxA intercepted: caption='%s' text='%s'",
             caption ? caption : "(null)", text ? text : "(null)");
    if (caption && (strstr(caption, "Runtime") || strstr(caption, "Visual C++"))) {
        ProxyLog("  -> Auto-dismissed (returning IDOK)");
        return IDOK;
    }
    if (g_pfnOrigMessageBoxA) return g_pfnOrigMessageBoxA(hwnd, text, caption, type);
    return IDOK;
}

static int WINAPI InlineHookedMBA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    ProxyLog("!!! MessageBoxA (INLINE HOOK): caption='%s'",
             caption ? caption : "(null)");
    if (text) {
        const char* p = text;
        while (*p) {
            char chunk[512];
            int len = 0;
            while (*p && len < 500) chunk[len++] = *p++;
            chunk[len] = '\0';
            ProxyLog("    text: %s", chunk);
        }
    }
    return IDOK;
}

static void InlineHookMessageBoxA(void) {
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    BYTE* fn;
    DWORD oldProt;
    LONG offset;

    if (!hUser32) hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) return;
    fn = (BYTE*)GetProcAddress(hUser32, "MessageBoxA");
    if (!fn) return;

    if (!VirtualProtect(fn, 5, PAGE_EXECUTE_READWRITE, &oldProt)) return;
    fn[0] = 0xE9;
    offset = (LONG)((BYTE*)InlineHookedMBA - (fn + 5));
    memcpy(fn + 1, &offset, 4);
    VirtualProtect(fn, 5, oldProt, &oldProt);
    ProxyLog("  Inline-hooked MessageBoxA -> %p", InlineHookedMBA);
}

/* ================================================================
 * IAT patching
 * ================================================================ */
static int PatchIATEntry(FARPROC origFn, FARPROC newFn, const char* name) {
    HMODULE hExe = GetModuleHandleA(NULL);
    BYTE* pBase = (BYTE*)hExe;
    IMAGE_DOS_HEADER* pDOS = (IMAGE_DOS_HEADER*)pBase;
    IMAGE_NT_HEADERS* pNT;
    IMAGE_IMPORT_DESCRIPTOR* pImport;
    DWORD importRVA;

    if (pDOS->e_magic != 0x5A4D) return 0;
    pNT = (IMAGE_NT_HEADERS*)(pBase + pDOS->e_lfanew);
    importRVA = pNT->OptionalHeader.DataDirectory[1].VirtualAddress;
    if (!importRVA) return 0;
    pImport = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + importRVA);

    while (pImport->Name) {
        IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)(pBase + pImport->FirstThunk);
        while (pThunk->u1.Function) {
            if ((FARPROC)pThunk->u1.Function == origFn) {
                DWORD oldProt;
                VirtualProtect(&pThunk->u1.Function, sizeof(FARPROC),
                               PAGE_READWRITE, &oldProt);
                pThunk->u1.Function = (DWORD)newFn;
                VirtualProtect(&pThunk->u1.Function, sizeof(FARPROC),
                               oldProt, &oldProt);
                ProxyLog("  IAT: Hooked %s", name);
                return 1;
            }
            pThunk++;
        }
        pImport++;
    }
    return 0;
}

static void HookGameIAT(void) {
    FARPROC pfnEP = (FARPROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess");
    FARPROC pfnMBA = (FARPROC)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    FARPROC pfnODS = NULL;
    FARPROC pfnST = NULL;
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    HMODULE hWsock = GetModuleHandleA("wsock32.dll");

    if (pfnEP) {
        g_pfnOrigExitProcess = (PFN_ExitProcess)pfnEP;
        PatchIATEntry(pfnEP, (FARPROC)HookedExitProcess, "ExitProcess");
    }
    if (pfnMBA) {
        g_pfnOrigMessageBoxA = (PFN_MessageBoxA)pfnMBA;
        PatchIATEntry(pfnMBA, (FARPROC)HookedMessageBoxA, "MessageBoxA");
    }
    /* Hook sendto to monitor all outbound UDP traffic */
    if (hWs2)
        pfnST = (FARPROC)GetProcAddress(hWs2, "sendto");
    if (!pfnST && hWsock)
        pfnST = (FARPROC)GetProcAddress(hWsock, "sendto");
    if (pfnST) {
        g_pfnOrigSendto = (PFN_sendto)pfnST;
        if (!PatchIATEntry(pfnST, (FARPROC)HookedSendto, "sendto")) {
            ProxyLog("  IAT: sendto not in IAT, trying wsock32");
            /* Try the other DLL's sendto in case IAT uses a different one */
            if (hWsock) {
                FARPROC pfnST2 = (FARPROC)GetProcAddress(hWsock, "sendto");
                if (pfnST2 && pfnST2 != pfnST) {
                    g_pfnOrigSendto = (PFN_sendto)pfnST2;
                    PatchIATEntry(pfnST2, (FARPROC)HookedSendto, "sendto(wsock32)");
                }
            }
        }
    }
    /* Hook recvfrom to monitor all inbound UDP traffic */
    {
        FARPROC pfnRF = NULL;
        if (hWs2)
            pfnRF = (FARPROC)GetProcAddress(hWs2, "recvfrom");
        if (!pfnRF && hWsock)
            pfnRF = (FARPROC)GetProcAddress(hWsock, "recvfrom");
        if (pfnRF) {
            g_pfnOrigRecvfrom = (PFN_recvfrom)pfnRF;
            if (!PatchIATEntry(pfnRF, (FARPROC)HookedRecvfrom, "recvfrom")) {
                if (hWsock) {
                    FARPROC pfnRF2 = (FARPROC)GetProcAddress(hWsock, "recvfrom");
                    if (pfnRF2 && pfnRF2 != pfnRF) {
                        g_pfnOrigRecvfrom = (PFN_recvfrom)pfnRF2;
                        PatchIATEntry(pfnRF2, (FARPROC)HookedRecvfrom, "recvfrom(wsock32)");
                    }
                }
            }
        }
    }
    /* Hook OutputDebugStringA for CPyDebug and engine diagnostics */
    if (hKernel) {
        pfnODS = (FARPROC)GetProcAddress(hKernel, "OutputDebugStringA");
        if (pfnODS) {
            g_pfnOrigODS = (PFN_OutputDebugStringA)pfnODS;
            PatchIATEntry(pfnODS, (FARPROC)HookedOutputDebugStringA, "OutputDebugStringA");
        }
    }
}

#ifdef OBSERVE_ONLY
/* Observer mode: minimal IAT hooks for passive logging only */
static void ObserverHookIAT(void) {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    HMODULE hWsock = GetModuleHandleA("wsock32.dll");
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC pfn;

    /* Hook sendto */
    pfn = NULL;
    if (hWs2) pfn = GetProcAddress(hWs2, "sendto");
    if (!pfn && hWsock) pfn = GetProcAddress(hWsock, "sendto");
    if (pfn) {
        g_pfnOrigSendto = (PFN_sendto)pfn;
        if (!PatchIATEntry(pfn, (FARPROC)HookedSendto, "sendto")) {
            if (hWsock) {
                FARPROC pfn2 = GetProcAddress(hWsock, "sendto");
                if (pfn2 && pfn2 != pfn) {
                    g_pfnOrigSendto = (PFN_sendto)pfn2;
                    PatchIATEntry(pfn2, (FARPROC)HookedSendto, "sendto(wsock32)");
                }
            }
        }
    }

    /* Hook recvfrom */
    pfn = NULL;
    if (hWs2) pfn = GetProcAddress(hWs2, "recvfrom");
    if (!pfn && hWsock) pfn = GetProcAddress(hWsock, "recvfrom");
    if (pfn) {
        g_pfnOrigRecvfrom = (PFN_recvfrom)pfn;
        if (!PatchIATEntry(pfn, (FARPROC)HookedRecvfrom, "recvfrom")) {
            if (hWsock) {
                FARPROC pfn2 = GetProcAddress(hWsock, "recvfrom");
                if (pfn2 && pfn2 != pfn) {
                    g_pfnOrigRecvfrom = (PFN_recvfrom)pfn2;
                    PatchIATEntry(pfn2, (FARPROC)HookedRecvfrom, "recvfrom(wsock32)");
                }
            }
        }
    }

    /* Hook OutputDebugStringA */
    if (hKernel) {
        pfn = GetProcAddress(hKernel, "OutputDebugStringA");
        if (pfn) {
            g_pfnOrigODS = (PFN_OutputDebugStringA)pfn;
            PatchIATEntry(pfn, (FARPROC)HookedOutputDebugStringA, "OutputDebugStringA");
        }
    }

}
#endif /* OBSERVE_ONLY */
