/* ================================================================
 * Globals
 * ================================================================ */
BOOL           g_bStubMode = FALSE;
BOOL           g_bHybridMode = FALSE;  /* TRUE = use real DDraw/D3D, keep server patches */
HWND           g_hGameWindow = NULL;
static BOOL    g_bLegacyNullListSafety = TRUE; /* Default ON: prevents NULL-list crashes in state update paths */
static HMODULE g_hRealDDraw = NULL;
static FILE*   g_pLog = NULL;
static FILE*   g_pODSLog = NULL;
char           g_szBasePath[MAX_PATH] = {0};
char           g_szDeviceName[512] = "BC Dedicated Server";

/* Real DDraw function pointers (for forward mode) */
typedef HRESULT (WINAPI *PFN_DirectDrawCreate)(GUID*, void**, void*);
typedef HRESULT (WINAPI *PFN_DirectDrawCreateEx)(GUID*, void**, const GUID*, void*);
typedef HRESULT (WINAPI *PFN_DirectDrawEnumerateA)(void*, void*);
typedef HRESULT (WINAPI *PFN_DirectDrawEnumerateExA)(void*, void*, DWORD);
static PFN_DirectDrawCreate      g_pfnDDCreate = NULL;
static PFN_DirectDrawCreateEx    g_pfnDDCreateEx = NULL;
static PFN_DirectDrawEnumerateA  g_pfnDDEnumA = NULL;
static PFN_DirectDrawEnumerateExA g_pfnDDEnumExA = NULL;

/* Forwarded function pointers */
FARPROC g_pfnAcquireDDThreadLock = NULL;
FARPROC g_pfnReleaseDDThreadLock = NULL;
FARPROC g_pfnCompleteCreateSysmemSurface = NULL;
FARPROC g_pfnD3DParseUnknownCommand = NULL;
FARPROC g_pfnDDGetAttachedSurfaceLcl = NULL;
FARPROC g_pfnDDInternalLock = NULL;
FARPROC g_pfnDDInternalUnlock = NULL;
FARPROC g_pfnDSoundHelp = NULL;
FARPROC g_pfnDirectDrawCreateClipper = NULL;
FARPROC g_pfnGetDDSurfaceLocal = NULL;
FARPROC g_pfnGetOLEThunkData = NULL;
FARPROC g_pfnGetSurfaceFromDC = NULL;
FARPROC g_pfnRegisterSpecialCase = NULL;
FARPROC g_pfnSetAppCompatData = NULL;

/* External vtables (defined in other .c files) */
extern void* g_DDraw7Vtbl[];
extern void* g_Surface7Vtbl[];
extern void* g_D3D7Vtbl[];
extern void* g_Device7Vtbl[];
extern void* g_VB7Vtbl[];

static void* g_ClipperVtbl[9];

/* ================================================================
 * Logging
 * ================================================================ */
void ProxyLog(const char* fmt, ...) {
    if (!g_pLog) return;
    {
        va_list ap;
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_pLog, "[%02d:%02d:%02d.%03d] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_start(ap, fmt);
        vfprintf(g_pLog, fmt, ap);
        va_end(ap);
        fprintf(g_pLog, "\n");
        fflush(g_pLog);
    }
}

void ODSLog(const char* fmt, ...) {
    if (!g_pODSLog) return;
    {
        va_list ap;
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_pODSLog, "[%02d:%02d:%02d.%03d] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_start(ap, fmt);
        vfprintf(g_pODSLog, fmt, ap);
        va_end(ap);
        fprintf(g_pODSLog, "\n");
        fflush(g_pODSLog);
    }
}

/* ================================================================
 * IDirectDrawClipper stub
 * ================================================================ */
static HRESULT WINAPI Clip_QueryInterface(ProxyClipper* This, const GUID* riid, void** ppv) {
    *ppv = This; This->refCount++; return S_OK;
}
static ULONG WINAPI Clip_AddRef(ProxyClipper* This) { return ++This->refCount; }
static ULONG WINAPI Clip_Release(ProxyClipper* This) {
    if (--This->refCount <= 0) { HeapFree(GetProcessHeap(), 0, This); return 0; }
    return This->refCount;
}
static HRESULT WINAPI Clip_GetClipList(ProxyClipper* This, RECT* r, void* rd, DWORD* s) {
    (void)This; (void)r; (void)rd; (void)s; return DDERR_GENERIC;
}
static HRESULT WINAPI Clip_GetHWnd(ProxyClipper* This, HWND* phwnd) {
    *phwnd = This->hwnd; return DD_OK;
}
static HRESULT WINAPI Clip_Initialize(ProxyClipper* This, void* pDD, DWORD flags) {
    (void)This; (void)pDD; (void)flags; return DD_OK;
}
static HRESULT WINAPI Clip_IsClipListChanged(ProxyClipper* This, BOOL* changed) {
    (void)This; *changed = FALSE; return DD_OK;
}
static HRESULT WINAPI Clip_SetClipList(ProxyClipper* This, void* rd, DWORD flags) {
    (void)This; (void)rd; (void)flags; return DD_OK;
}
static HRESULT WINAPI Clip_SetHWnd(ProxyClipper* This, DWORD flags, HWND hwnd) {
    (void)flags; This->hwnd = hwnd; return DD_OK;
}

ProxyClipper* CreateProxyClipper(void) {
    ProxyClipper* p = (ProxyClipper*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    g_ClipperVtbl[0] = Clip_QueryInterface;
    g_ClipperVtbl[1] = Clip_AddRef;
    g_ClipperVtbl[2] = Clip_Release;
    g_ClipperVtbl[3] = Clip_GetClipList;
    g_ClipperVtbl[4] = Clip_GetHWnd;
    g_ClipperVtbl[5] = Clip_Initialize;
    g_ClipperVtbl[6] = Clip_IsClipListChanged;
    g_ClipperVtbl[7] = Clip_SetClipList;
    g_ClipperVtbl[8] = Clip_SetHWnd;
    p->lpVtbl = g_ClipperVtbl;
    p->refCount = 1;
    return p;
}

/* ================================================================
 * Factory functions for proxy objects
 * ================================================================ */

ProxyDDraw7* CreateProxyDDraw7(void) {
    ProxyDDraw7* p = (ProxyDDraw7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_DDraw7Vtbl;
    p->refCount = 1;
    p->displayWidth = 1024;
    p->displayHeight = 768;
    p->displayBpp = 16;
    ProxyLog("CreateProxyDDraw7: %p", p);
    return p;
}

ProxySurface7* CreateProxySurface7(DWORD width, DWORD height, DWORD bpp, DWORD caps) {
    ProxySurface7* p = (ProxySurface7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_Surface7Vtbl;
    p->refCount = 1;
    p->width = width ? width : 1;
    p->height = height ? height : 1;
    p->bpp = bpp ? bpp : 16;
    p->caps = caps;
    p->pitch = (LONG)(p->width * (p->bpp / 8));
    if (p->pitch < 4) p->pitch = 4;
    p->pixelDataSize = (DWORD)(p->pitch * p->height);
    p->pixelData = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p->pixelDataSize);
    if (p->bpp == 16)
        SetPixelFormat565(&p->pixelFormat);
    else if (p->bpp == 32)
        SetPixelFormat8888(&p->pixelFormat);
    else
        SetPixelFormat565(&p->pixelFormat);
    return p;
}

ProxyD3D7* CreateProxyD3D7(ProxyDDraw7* parent) {
    ProxyD3D7* p = (ProxyD3D7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_D3D7Vtbl;
    p->refCount = 1;
    p->parent = parent;
    ProxyLog("CreateProxyD3D7: %p (parent=%p)", p, parent);
    return p;
}

ProxyDevice7* CreateProxyDevice7(ProxySurface7* renderTarget, ProxyD3D7* parent) {
    ProxyDevice7* p = (ProxyDevice7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    if (!p) return NULL;
    p->lpVtbl = g_Device7Vtbl;
    p->refCount = 1;
    p->renderTarget = renderTarget;
    p->parent = parent;
    if (parent) parent->refCount++;
    ProxyLog("CreateProxyDevice7: %p (target=%p, parent=%p)", p, renderTarget, parent);
    return p;
}

ProxyVB7* CreateProxyVB7(DWORD fvf, DWORD numVertices) {
    ProxyVB7* p = (ProxyVB7*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
    DWORD vertexSize = 0;
    if (!p) return NULL;
    p->lpVtbl = g_VB7Vtbl;
    p->refCount = 1;
    p->fvf = fvf;
    p->numVertices = numVertices ? numVertices : 1;
    /* Calculate vertex size from FVF flags */
    if (fvf & 0x002) vertexSize += 12;  /* D3DFVF_XYZ */
    if (fvf & 0x004) vertexSize += 16;  /* D3DFVF_XYZRHW */
    if (fvf & 0x010) vertexSize += 12;  /* D3DFVF_NORMAL */
    if (fvf & 0x040) vertexSize += 4;   /* D3DFVF_DIFFUSE */
    if (fvf & 0x080) vertexSize += 4;   /* D3DFVF_SPECULAR */
    vertexSize += ((fvf >> 8) & 0xF) * 8; /* Texture coordinate sets */
    if (vertexSize == 0) vertexSize = 32;
    p->dataSize = vertexSize * p->numVertices;
    p->data = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p->dataSize);
    return p;
}

/* (ParseDeviceNameFromConfig removed - g_szDeviceName has static default) */

/* ================================================================
 * Utilities
 * ================================================================ */
static HANDLE g_hMainThread = NULL;
static DWORD g_dwMainThreadId = 0;

static void ResolveAddr(DWORD addr, char* out, int outLen) {
    MEMORY_BASIC_INFORMATION mbi;
    char modName[MAX_PATH];
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) && mbi.AllocationBase) {
        if (GetModuleFileNameA((HMODULE)mbi.AllocationBase, modName, MAX_PATH)) {
            char* slash = modName;
            char* p;
            for (p = modName; *p; p++)
                if (*p == '\\' || *p == '/') slash = p + 1;
            wsprintfA(out, "0x%08X [%s+0x%X]", addr, slash,
                      addr - (DWORD)mbi.AllocationBase);
            return;
        }
    }
    wsprintfA(out, "0x%08X", addr);
}

/* ================================================================
 * VEHCrashLogger - Minimal first-chance exception logger
 *
 * Catches exceptions in ALL threads (including NVIDIA driver threads)
 * that bypass SetUnhandledExceptionFilter. Only logs fatal exceptions
 * (access violations, stack overflows). Returns EXCEPTION_CONTINUE_SEARCH
 * to let normal handling proceed.
 * ================================================================ */
static LONG WINAPI VEHCrashLogger(EXCEPTION_POINTERS* ep) {
    DWORD excCode = ep->ExceptionRecord->ExceptionCode;
    static volatile LONG vehCount = 0;
    LONG count;
    /* Log ALL exception types to find the original crash that triggers cascade */
    /* Suppress cascade: only log first 10 exceptions to prevent log/stack overflow */
    count = InterlockedIncrement(&vehCount);
    if (count > 10) return EXCEPTION_CONTINUE_SEARCH;
    /* Skip benign exceptions that waste our counter */
    if (excCode == 0xE06D7363 ||  /* MSVC C++ throw */
        excCode == 0x40010006 ||  /* OutputDebugString */
        excCode == 0x406D1388) {  /* MS_VC_EXCEPTION (thread naming) */
        InterlockedDecrement(&vehCount);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    /* Log minimal crash info */
    ProxyLog("!!! VEH[%ld]: exception 0x%08X at EIP=0x%08X thread=%lu ECX=0x%08X EAX=0x%08X ESP=0x%08X",
             count, excCode, (DWORD)ep->ContextRecord->Eip,
             GetCurrentThreadId(),
             (DWORD)ep->ContextRecord->Ecx,
             (DWORD)ep->ContextRecord->Eax,
             (DWORD)ep->ContextRecord->Esp);
    /* Dump stack around ESP to find return addresses */
    if (count <= 5) {
        DWORD esp = ep->ContextRecord->Esp;
        DWORD ebp = ep->ContextRecord->Ebp;
        ProxyLog("!!! VEH[%ld]: EBP=0x%08X EDX=0x%08X ESI=0x%08X EDI=0x%08X",
                 count, ebp, (DWORD)ep->ContextRecord->Edx,
                 (DWORD)ep->ContextRecord->Esi, (DWORD)ep->ContextRecord->Edi);
        /* Dump 32 DWORDs from ESP (return addresses, saved regs, etc.) */
        if (!IsBadReadPtr((void*)esp, 128)) {
            DWORD* stk = (DWORD*)esp;
            ProxyLog("!!! VEH[%ld]: STACK[ESP+00..+3C]: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
                     count, stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7],
                     stk[8], stk[9], stk[10], stk[11], stk[12], stk[13], stk[14], stk[15]);
            ProxyLog("!!! VEH[%ld]: STACK[ESP+40..+7C]: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
                     count, stk[16], stk[17], stk[18], stk[19], stk[20], stk[21], stk[22], stk[23],
                     stk[24], stk[25], stk[26], stk[27], stk[28], stk[29], stk[30], stk[31]);
        }
        /* Walk EBP chain looking for stbc.exe return addresses */
        {
            DWORD frame = ebp;
            int i;
            for (i = 0; i < 8 && frame > 0x10000 && frame < 0x7FFFFFFF; i++) {
                if (IsBadReadPtr((void*)frame, 8)) break;
                DWORD savedEbp = *(DWORD*)frame;
                DWORD retAddr = *(DWORD*)(frame + 4);
                ProxyLog("!!! VEH[%ld]: FRAME[%d] EBP=0x%08X RET=0x%08X", count, i, frame, retAddr);
                if (savedEbp <= frame) break; /* stack grows down, EBP should increase */
                frame = savedEbp;
            }
        }
    }
    if (g_pLog) fflush(g_pLog);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ================================================================
 * CrashDumpHandler - Log full crash diagnostics then let process die
 *
 * Registered via SetUnhandledExceptionFilter. Writes detailed crash
 * info to crash_dump.log, flushes all open log files, then returns
 * EXCEPTION_CONTINUE_SEARCH so the OS terminates the process normally.
 * ================================================================ */
static LONG WINAPI CrashDumpHandler(EXCEPTION_POINTERS* ep) {
    CONTEXT* ctx = ep->ContextRecord;
    DWORD eip = (DWORD)ctx->Eip;
    DWORD excCode = ep->ExceptionRecord->ExceptionCode;
    FILE* fp;
    char path[MAX_PATH];
    char resolved[256];
    SYSTEMTIME st;
    int i;

    /* Skip benign exceptions */
    if (excCode == 0x406D1388 ||   /* SetThreadName */
        excCode == 0x40010006 ||   /* OutputDebugString */
        excCode == 0x80000003 ||   /* INT3 breakpoint */
        excCode == 0x80000004)     /* Single-step */
        return EXCEPTION_CONTINUE_SEARCH;

    /* Open crash dump log (append so multiple crashes in one session are captured) */
    if (g_szBasePath[0])
        _snprintf(path, sizeof(path), "%scrash_dump.log", g_szBasePath);
    else
        _snprintf(path, sizeof(path), "crash_dump.log");
    path[sizeof(path)-1] = '\0';
    fp = fopen(path, "a");
    if (!fp) return EXCEPTION_CONTINUE_SEARCH;

    GetLocalTime(&st);
    fprintf(fp, "========================================\n");
    fprintf(fp, "FATAL CRASH at %04d-%02d-%02d %02d:%02d:%02d.%03d\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    fprintf(fp, "========================================\n\n");

    /* Exception info */
    ResolveAddr(eip, resolved, sizeof(resolved));
    fprintf(fp, "Exception: 0x%08X at EIP=%s\n", (unsigned)excCode, resolved);
    if (excCode == 0xC0000005) {
        DWORD rw = (DWORD)ep->ExceptionRecord->ExceptionInformation[0];
        DWORD faultAddr = (DWORD)ep->ExceptionRecord->ExceptionInformation[1];
        fprintf(fp, "Access violation: %s 0x%08X\n",
                rw == 0 ? "reading" : rw == 1 ? "writing" : "executing",
                (unsigned)faultAddr);
    } else if (excCode == 0xC00000FD) {
        fprintf(fp, "STACK OVERFLOW\n");
    }

    /* Register dump */
    fprintf(fp, "\nRegisters:\n");
    fprintf(fp, "  EAX=%08X  EBX=%08X  ECX=%08X  EDX=%08X\n",
            (unsigned)ctx->Eax, (unsigned)ctx->Ebx,
            (unsigned)ctx->Ecx, (unsigned)ctx->Edx);
    fprintf(fp, "  ESI=%08X  EDI=%08X  EBP=%08X  ESP=%08X\n",
            (unsigned)ctx->Esi, (unsigned)ctx->Edi,
            (unsigned)ctx->Ebp, (unsigned)ctx->Esp);
    fprintf(fp, "  EIP=%08X  EFlags=%08X\n",
            (unsigned)ctx->Eip, (unsigned)ctx->EFlags);

    /* EBP chain stack walk */
    fprintf(fp, "\nStack trace (EBP chain):\n");
    {
        DWORD* frame = (DWORD*)ctx->Ebp;
        for (i = 0; i < 32 && frame; i++) {
            DWORD retAddr;
            if (IsBadReadPtr(frame, 8)) break;
            retAddr = frame[1];
            if (retAddr == 0) break;
            ResolveAddr(retAddr, resolved, sizeof(resolved));
            fprintf(fp, "  [%2d] %s\n", i, resolved);
            frame = (DWORD*)frame[0];
            if ((DWORD)frame < 0x10000 || (DWORD)frame > 0x7FFFFFFF) break;
        }
    }

    /* Raw stack hex dump (256 bytes from ESP) */
    fprintf(fp, "\nRaw stack (256 bytes from ESP=0x%08X):\n", (unsigned)ctx->Esp);
    if (!IsBadReadPtr((void*)ctx->Esp, 256)) {
        BYTE* sp = (BYTE*)ctx->Esp;
        for (i = 0; i < 256; i += 16) {
            int j;
            fprintf(fp, "  %08X: ", (unsigned)(ctx->Esp + i));
            for (j = 0; j < 16; j++)
                fprintf(fp, "%02X ", sp[i + j]);
            fprintf(fp, " ");
            for (j = 0; j < 16; j++) {
                BYTE b = sp[i + j];
                fprintf(fp, "%c", (b >= 0x20 && b < 0x7F) ? b : '.');
            }
            fprintf(fp, "\n");
        }
    }

    /* Code bytes around crash EIP (32 before, 32 after) */
    fprintf(fp, "\nCode bytes around EIP=0x%08X:\n  ", (unsigned)eip);
    if (!IsBadReadPtr((void*)(eip - 32), 64)) {
        BYTE* code = (BYTE*)eip;
        for (i = -32; i < 32; i++) {
            if (i == 0) fprintf(fp, "[%02X] ", code[i]);
            else        fprintf(fp, "%02X ", code[i]);
        }
        fprintf(fp, "\n");
    }

    /* Memory at key register targets */
    {
        struct { const char* name; DWORD val; } regs[] = {
            {"EAX", ctx->Eax}, {"ECX", ctx->Ecx}, {"ESI", ctx->Esi},
            {"EDI", ctx->Edi}, {"EBX", ctx->Ebx}, {"EDX", ctx->Edx}
        };
        fprintf(fp, "\nMemory at registers:\n");
        for (i = 0; i < 6; i++) {
            if (regs[i].val >= 0x10000 && !IsBadReadPtr((void*)regs[i].val, 32)) {
                DWORD* p = (DWORD*)regs[i].val;
                fprintf(fp, "  [%s=0x%08lX]: %08lX %08lX %08lX %08lX %08lX %08lX %08lX %08lX\n",
                        regs[i].name, (unsigned long)regs[i].val,
                        (unsigned long)p[0], (unsigned long)p[1],
                        (unsigned long)p[2], (unsigned long)p[3],
                        (unsigned long)p[4], (unsigned long)p[5],
                        (unsigned long)p[6], (unsigned long)p[7]);
            }
        }
    }

    fprintf(fp, "\n");
    fclose(fp);

    /* Flush all open log files */
    if (g_pLog) fflush(g_pLog);
    if (g_pPacketLog) fflush(g_pPacketLog);
    if (g_pTickLog) fflush(g_pTickLog);
    if (g_pStateDump) fflush(g_pStateDump);

    /* One-liner to main proxy log */
    ResolveAddr(eip, resolved, sizeof(resolved));
    ProxyLog("!!! FATAL CRASH: exception 0x%08X at %s - see crash_dump.log",
             (unsigned)excCode, resolved);
    if (g_pLog) fflush(g_pLog);

    return EXCEPTION_CONTINUE_SEARCH;
}

/* Find and auto-dismiss CRT abort dialogs */
static BOOL CALLBACK FindAbortDialog(HWND hwnd, LPARAM lParam) {
    char cls[64] = {0};
    char title[256] = {0};
    (void)lParam;
    GetClassNameA(hwnd, cls, sizeof(cls));
    if (lstrcmpA(cls, "#32770") == 0) {
        GetWindowTextA(hwnd, title, sizeof(title));
        if (strstr(title, "Runtime") || strstr(title, "Error") ||
            strstr(title, "Visual C++") || strstr(title, "Assert")) {
            ProxyLog("  AUTO-DISMISS: Found error dialog '%s'", title);
            {
                HWND child = GetWindow(hwnd, GW_CHILD);
                while (child) {
                    char childText[2048] = {0};
                    if (GetWindowTextA(child, childText, sizeof(childText)) > 0)
                        ProxyLog("  AUTO-DISMISS: '%s'", childText);
                    child = GetWindow(child, GW_HWNDNEXT);
                }
            }
            {
                HWND btn = FindWindowExA(hwnd, NULL, "Button", "OK");
                if (!btn) btn = FindWindowExA(hwnd, NULL, "Button", "&OK");
                if (btn)
                    PostMessageA(hwnd, WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(btn), BN_CLICKED), (LPARAM)btn);
                else
                    PostMessageA(hwnd, WM_CLOSE, 0, 0);
            }
        }
    }
    return TRUE;
}

/* ================================================================
 * Heartbeat thread - periodic logging, dialog dismissal, timer setup
 *
 * Sets up a 16ms WM_TIMER on the game window to keep the message
 * pump running even when the game has nothing to render.
 * ================================================================ */
static DWORD WINAPI HeartbeatThread(LPVOID param) {
    DWORD count = 0;
    BOOL timerSet = FALSE;
    int i;
    (void)param;

    /* For the first 30 seconds, check every 500ms for error dialogs */
    for (i = 0; i < 60; i++) {
        Sleep(500);
        EnumThreadWindows(g_dwMainThreadId, FindAbortDialog, 0);
        /* Check game state at 5s and 15s */
        if (i == 10 || i == 30) {
            DWORD pyInit = 0, wsnPtr = 0;
            if (!IsBadReadPtr((void*)0x0099EE34, 4))
                pyInit = *(DWORD*)0x0099EE34;
            if (!IsBadReadPtr((void*)0x0097FA78, 4))
                wsnPtr = *(DWORD*)0x0097FA78;
            ProxyLog("  STATE CHECK (%ds): Py_Initialized=%u WSN=0x%08X",
                     i / 2, pyInit, wsnPtr);

            /* Request Python diagnostics on main thread at 15s.
             * NEVER call Python C API from this thread - the allocator
             * has no locks and concurrent access causes heap corruption. */
            if (i == 30 && pyInit) {
                g_runPyDiag = 1;
                ProxyLog("  HEARTBEAT: Requested Python diagnostics on main thread");
            }
        }
        /* Set up timer to keep the message pump running */
        if (g_hGameWindow && !timerSet) {
            SetTimer(g_hGameWindow, 1, 16, NULL);
            timerSet = TRUE;
            ProxyLog("  Heartbeat: Set 16ms timer on game window %p", g_hGameWindow);
        }
    }
    /* Long-running heartbeat: check every 5 seconds */
    while (1) {
        Sleep(5000);
        count++;
        EnumThreadWindows(g_dwMainThreadId, FindAbortDialog, 0);
        if (count <= 6 || count % 12 == 0) {
            DWORD wsnPtr = 0;
            if (!IsBadReadPtr((void*)0x0097FA78, 4))
                wsnPtr = *(DWORD*)0x0097FA78;
            ProxyLog("HEARTBEAT #%u (%u sec) WSN=0x%08X",
                     count, count * 5 + 30, wsnPtr);
            /* NOTE: Do NOT call LogPyModules or any Python C API from this thread.
             * Python 1.5.2 allocator has no locks - concurrent access = heap corruption. */
        }
    }
    return 0;
}

/* ================================================================
 * DllMain
 * ================================================================ */
BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD reason, LPVOID reserved) {
    char sysPath[MAX_PATH];
    char filePath[MAX_PATH];
    char *lastSlash;
    HANDLE hCfg;

    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstDLL);

#ifndef OBSERVE_ONLY
        /* Install crash dump handler (logs diagnostics, lets process die) */
        SetUnhandledExceptionFilter(CrashDumpHandler);
        /* Also install VEH first-chance handler to catch driver-thread crashes
         * that bypass SetUnhandledExceptionFilter. This is MINIMAL - log only,
         * no recovery, only fires for fatal exceptions. */
        AddVectoredExceptionHandler(1, VEHCrashLogger);

        g_dwMainThreadId = GetCurrentThreadId();
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                        GetCurrentProcess(), &g_hMainThread,
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        FALSE, 0);
#endif /* !OBSERVE_ONLY */

        /* Resolve base path */
        GetModuleFileNameA(hInstDLL, g_szBasePath, MAX_PATH);
        lastSlash = g_szBasePath;
        for (char *p = g_szBasePath; *p; p++) {
            if (*p == '\\' || *p == '/') lastSlash = p;
        }
        if (lastSlash != g_szBasePath) *(lastSlash + 1) = '\0';
        else lstrcatA(g_szBasePath, "\\");

        /* Open log file */
        lstrcpynA(filePath, g_szBasePath, MAX_PATH);
        lstrcatA(filePath, "ddraw_proxy.log");
        g_pLog = fopen(filePath, "w");
        PktTraceOpen();
        /* Set CWD to game directory - critical when launched from WSL/cmd */
        SetCurrentDirectoryA(g_szBasePath);

        ProxyLog("DDraw Proxy loaded");
        ProxyLog("Base path: %s", g_szBasePath);

#ifdef OBSERVE_ONLY
        /* OBSERVER MODE: passive logging only, no patches */
        ProxyLog("OBSERVE_ONLY build - passive packet/event logging, zero patches");
        SetEnvironmentVariableA("STBC_GAME_DIR", g_szBasePath);
        ProxyLog("Set STBC_GAME_DIR=%s", g_szBasePath);

        lstrcpynA(filePath, g_szBasePath, MAX_PATH);
        lstrcatA(filePath, "pydebug.log");
        g_pODSLog = fopen(filePath, "w");
        if (g_pODSLog) {
            ODSLog("OutputDebugStringA capture enabled (observe mode)");
        } else {
            ProxyLog("WARNING: Could not open pydebug.log");
        }

        /* Write basepath file for Python to read (absolute path discovery) */
        {
            char bpPath[MAX_PATH];
            FILE* bpf;
            lstrcpynA(bpPath, g_szBasePath, MAX_PATH);
            lstrcatA(bpPath, "Scripts\\Custom\\_basepath");
            bpf = fopen(bpPath, "w");
            if (bpf) {
                fprintf(bpf, "%s", g_szBasePath);
                fclose(bpf);
                ProxyLog("Wrote _basepath: %s", bpPath);
            }
        }

        /* Write Python config module with game dir as constant string.
         * NOTE: BC's embedded Python has file writing disabled (open() for 'w'
         * fails for all paths including nt.open). Only the import machinery
         * can write .pyc files. Python logging must go through C hooks. */
        {
            char cfgPath[MAX_PATH];
            FILE* cfgf;
            const char* p;
            lstrcpynA(cfgPath, g_szBasePath, MAX_PATH);
            lstrcatA(cfgPath, "Scripts\\Custom\\_config.py");
            cfgf = fopen(cfgPath, "w");
            if (cfgf) {
                fprintf(cfgf, "GAME_DIR = \"");
                for (p = g_szBasePath; *p; p++) {
                    if (*p == '\\') fprintf(cfgf, "\\\\");
                    else fputc(*p, cfgf);
                }
                fprintf(cfgf, "\"\n");
                fclose(cfgf);
                ProxyLog("Wrote _config.py: %s", cfgPath);
            }
        }

        PatchDebugConsoleToFile();
        MsgTraceOpen();
        ObserverHookIAT();
        /* OBSERVE_ONLY can be idle between packets; poll input via timer
         * so manual left-click/F12 dumps still fire without network traffic. */
        StartManualInputTimer();
#else
        /* Check for dedicated server mode */
        lstrcpynA(filePath, g_szBasePath, MAX_PATH);
        lstrcatA(filePath, "dedicated.cfg");
        hCfg = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
        if (hCfg != INVALID_HANDLE_VALUE) {
            CloseHandle(hCfg);
            g_bStubMode = TRUE;
            g_bHybridMode = TRUE;  /* Use real renderer with server patches */
            ProxyLog("dedicated.cfg found - HYBRID MODE (real renderer + server patches)");

            lstrcpynA(filePath, g_szBasePath, MAX_PATH);
            lstrcatA(filePath, "pydebug.log");
            g_pODSLog = fopen(filePath, "w");
            if (g_pODSLog) {
                ODSLog("OutputDebugStringA capture enabled (hybrid mode)");
            } else {
                ProxyLog("WARNING: Could not open pydebug.log");
            }

            /* Redirect stdout/stderr for Python print capture.
               SetStdHandle only changes Win32 console handles, but Python 1.5
               print uses C runtime FILE* (msvcrt stdout). GUI apps have no
               console so stdout fd is disconnected. We must freopen msvcrt's
               _iob[1] (stdout) and _iob[2] (stderr) to a file. */
            {
                char logPath[MAX_PATH];
                lstrcpynA(logPath, g_szBasePath, MAX_PATH);
                lstrcatA(logPath, "dedicated_console.log");

                /* Also set Win32 handle for completeness */
                {
                    HANDLE hLogFile = CreateFileA(logPath, GENERIC_WRITE,
                                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hLogFile != INVALID_HANDLE_VALUE) {
                        SetStdHandle(STD_OUTPUT_HANDLE, hLogFile);
                        SetStdHandle(STD_ERROR_HANDLE, hLogFile);
                    }
                }

                /* Redirect CRT stdout/stderr via msvcrt.
                   Approach: use _open_osfhandle + _dup2 to redirect fd 1/2,
                   then freopen on _iob as belt-and-suspenders. */
                {
                    HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
                    if (!hCRT) hCRT = LoadLibraryA("msvcrt.dll");
                    if (hCRT) {
                        typedef int (__cdecl *pfn_open)(const char*, int, ...);
                        typedef int (__cdecl *pfn_dup2)(int, int);
                        typedef int (__cdecl *pfn_fflush)(void*);
                        typedef int (__cdecl *pfn_fprintf)(void*, const char*, ...);
                        typedef void* (__cdecl *pfn_freopen)(const char*, const char*, void*);

                        pfn_open fn_open = (pfn_open)GetProcAddress(hCRT, "_open");
                        pfn_dup2 fn_dup2 = (pfn_dup2)GetProcAddress(hCRT, "_dup2");
                        pfn_fflush fn_fflush = (pfn_fflush)GetProcAddress(hCRT, "fflush");
                        pfn_fprintf fn_fprintf = (pfn_fprintf)GetProcAddress(hCRT, "fprintf");
                        pfn_freopen fn_freopen = (pfn_freopen)GetProcAddress(hCRT, "freopen");
                        BYTE* p_iob = (BYTE*)GetProcAddress(hCRT, "_iob");

                        ProxyLog("  msvcrt: _open=%p _dup2=%p freopen=%p _iob=%p",
                                 fn_open, fn_dup2, fn_freopen, p_iob);

                        /* Method 1: _open + _dup2 at fd level */
                        if (fn_open && fn_dup2) {
                            /* _O_WRONLY=0x0001, _O_CREAT=0x0100, _O_TRUNC=0x0200 */
                            int logFd = fn_open(logPath, 0x0301, 0x180);
                            ProxyLog("  _open(\"%s\") -> fd=%d", logPath, logFd);
                            if (logFd >= 0) {
                                int r1 = fn_dup2(logFd, 1); /* stdout */
                                int r2 = fn_dup2(logFd, 2); /* stderr */
                                ProxyLog("  _dup2 stdout=%d stderr=%d", r1, r2);
                            }
                        }

                        /* Method 2: freopen on _iob (32 bytes per FILE in x86 msvcrt) */
                        if (fn_freopen && p_iob) {
                            void* msvc_stdout = (void*)(p_iob + 32);
                            void* msvc_stderr = (void*)(p_iob + 64);
                            fn_freopen(logPath, "w", msvc_stdout);
                            fn_freopen(logPath, "a", msvc_stderr);
                        }

                        /* Test: write directly to msvcrt stdout */
                        if (fn_fprintf && fn_fflush && p_iob) {
                            void* msvc_stdout = (void*)(p_iob + 32);
                            fn_fprintf(msvc_stdout, "[DDraw] Console redirect test OK\n");
                            fn_fflush(msvc_stdout);
                        }

                        ProxyLog("  Console output redirected to dedicated_console.log");
                    }
                }
            }

            /* Suppress CRT abort dialogs */
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
            {
                HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
                if (!hCRT) hCRT = LoadLibraryA("msvcrt.dll");
                if (hCRT) {
                    typedef int (__cdecl *pfn_sab)(unsigned int, unsigned int);
                    typedef void (__cdecl *sighandler_t)(int);
                    typedef sighandler_t (__cdecl *pfn_signal)(int, sighandler_t);
                    pfn_sab fn_sab = (pfn_sab)GetProcAddress(hCRT, "_set_abort_behavior");
                    pfn_signal fn_signal = (pfn_signal)GetProcAddress(hCRT, "signal");
                    if (fn_sab) fn_sab(0, 3);
                    if (fn_signal) fn_signal(22, SigAbrtHandler);
                }
            }

            /* Optional override:
             * Default keeps NULL-list safety shims enabled to avoid AVs in
             * subsystem/weapon state update loops when lists are still NULL.
             * To force fully-native behavior, drop legacy-null-list-safety-disable.cfg. */
            {
                HANDLE hOpt;
                lstrcpynA(filePath, g_szBasePath, MAX_PATH);
                lstrcatA(filePath, "legacy-null-list-safety-disable.cfg");
                hOpt = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, 0, NULL);
                if (hOpt != INVALID_HANDLE_VALUE) {
                    g_bLegacyNullListSafety = FALSE;
                    CloseHandle(hOpt);
                    ProxyLog("legacy-null-list-safety-disable.cfg found - running without NULL-list safety shims");
                } else {
                    g_bLegacyNullListSafety = TRUE;
                    ProxyLog("NULL-list safety shims enabled (default)");
                }
            }

            /* Apply patches for hybrid mode */
            HookGameIAT();
            InlineHookMessageBoxA();
            PatchInitAbort();         /* Prevent abort when init check fails */
            PatchPyFatalError();      /* Make Py_FatalError return instead of tail-calling abort */
            PatchCreateAppModule();   /* Create SWIG "App" module before init imports it */
            PatchForceWindowed();     /* Force windowed renderer (D3D7 fullscreen modes unsupported) */
            PatchSkipDeviceLost();    /* Skip device-lost recreation path (safety) */
            PatchHeadlessCrashSites(); /* NOP subtitle/notification pane lookups (pane #5 not created in dedi boot) */
            PatchTGLFindEntry();      /* TGL FindEntry: return NULL when this==NULL */
            if (g_bLegacyNullListSafety) {
            PatchNetworkUpdateNullLists(); /* Clear subsys/weapon flags when lists NULL (legacy safety) */
            PatchSubsystemHashCheck(); /* Fix false-positive anti-cheat when subsystems NULL (legacy safety) */
        }
        PatchCompressedVectorRead(); /* Validate vtable in compressed vector read (safety) */
        PatchNullThunk_00419960(); /* NULL-check [ECX+0x1C] vtable thunk (AsteroidField tick) */
        PatchStreamReadNullBuffer(); /* NULL buffer check in stream read (network deserialization) */
        PatchCollisionNullNodeCall_005AFE2C(); /* Skip NULL collision node call into FUN_005af4a0 */
        PatchCollisionNullNodeCallGuard_005AFE44(); /* Guard FUN_005af4a0 from NULL node payloads */
        PatchDebugConsoleToFile(); /* Redirect Python exceptions to state_dump.log */
            /* PatchChecksumAlwaysPass REMOVED - flag=0 means "no mismatches"
             * which is CORRECT for first player (no peers to compare against).
             * Forcing flag=1 corrupted the settings packet with bogus mismatch data. */

            /* Let the game boot and run Python naturally.
               Python automation in DedicatedServer.py drives multiplayer. */

            /* Start heartbeat thread */
            CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);
        } else {
            g_bStubMode = FALSE;
            ProxyLog("No dedicated.cfg - FORWARD MODE (normal play)");
        }
#endif /* !OBSERVE_ONLY */

        /* Always load real ddraw.dll from System32 */
        GetSystemDirectoryA(sysPath, MAX_PATH);
        lstrcatA(sysPath, "\\ddraw.dll");
        g_hRealDDraw = LoadLibraryA(sysPath);
        if (g_hRealDDraw) {
            g_pfnDDCreate = (PFN_DirectDrawCreate)GetProcAddress(g_hRealDDraw, "DirectDrawCreate");
            g_pfnDDCreateEx = (PFN_DirectDrawCreateEx)GetProcAddress(g_hRealDDraw, "DirectDrawCreateEx");
            g_pfnDDEnumA = (PFN_DirectDrawEnumerateA)GetProcAddress(g_hRealDDraw, "DirectDrawEnumerateA");
            g_pfnDDEnumExA = (PFN_DirectDrawEnumerateExA)GetProcAddress(g_hRealDDraw, "DirectDrawEnumerateExA");
            g_pfnAcquireDDThreadLock = GetProcAddress(g_hRealDDraw, "AcquireDDThreadLock");
            g_pfnReleaseDDThreadLock = GetProcAddress(g_hRealDDraw, "ReleaseDDThreadLock");
            g_pfnCompleteCreateSysmemSurface = GetProcAddress(g_hRealDDraw, "CompleteCreateSysmemSurface");
            g_pfnD3DParseUnknownCommand = GetProcAddress(g_hRealDDraw, "D3DParseUnknownCommand");
            g_pfnDDGetAttachedSurfaceLcl = GetProcAddress(g_hRealDDraw, "DDGetAttachedSurfaceLcl");
            g_pfnDDInternalLock = GetProcAddress(g_hRealDDraw, "DDInternalLock");
            g_pfnDDInternalUnlock = GetProcAddress(g_hRealDDraw, "DDInternalUnlock");
            g_pfnDSoundHelp = GetProcAddress(g_hRealDDraw, "DSoundHelp");
            g_pfnDirectDrawCreateClipper = GetProcAddress(g_hRealDDraw, "DirectDrawCreateClipper");
            g_pfnGetDDSurfaceLocal = GetProcAddress(g_hRealDDraw, "GetDDSurfaceLocal");
            g_pfnGetOLEThunkData = GetProcAddress(g_hRealDDraw, "GetOLEThunkData");
            g_pfnGetSurfaceFromDC = GetProcAddress(g_hRealDDraw, "GetSurfaceFromDC");
            g_pfnRegisterSpecialCase = GetProcAddress(g_hRealDDraw, "RegisterSpecialCase");
            g_pfnSetAppCompatData = GetProcAddress(g_hRealDDraw, "SetAppCompatData");
            ProxyLog("Real ddraw.dll loaded from %s", sysPath);
        } else {
            ProxyLog("WARNING: Could not load real ddraw.dll from %s", sysPath);
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        ProxyLog("DDraw Proxy unloading");
        if (g_hRealDDraw) {
            FreeLibrary(g_hRealDDraw);
            g_hRealDDraw = NULL;
        }
        if (g_pTickLog) {
            fflush(g_pTickLog);
            fclose(g_pTickLog);
            g_pTickLog = NULL;
        }
        if (g_pPacketLog) {
            fclose(g_pPacketLog);
            g_pPacketLog = NULL;
        }
        if (g_pLog) {
            fclose(g_pLog);
            g_pLog = NULL;
        }
        if (g_pODSLog) {
            fclose(g_pODSLog);
            g_pODSLog = NULL;
        }
    }
    return TRUE;
}

/* ================================================================
 * Hybrid mode: DDraw7 vtable intercepts
 *
 * When hybrid mode is active, we patch the real IDirectDraw7 vtable to:
 * - SetCooperativeLevel (slot 20): Passthrough, capture HWND, minimize
 * - SetDisplayMode (slot 21): Force 32bpp (16bpp not supported on modern GPUs)
 *
 * Combined with PatchSkipDisplayModeSearch (which bypasses mode enumeration),
 * this lets the engine go fullscreen exclusive at a GPU-supported bit depth.
 * ================================================================ */
typedef HRESULT (WINAPI *PFN_SetCooperativeLevel)(void*, HWND, DWORD);
typedef HRESULT (WINAPI *PFN_SetDisplayMode)(void*, DWORD, DWORD, DWORD, DWORD, DWORD);
static PFN_SetCooperativeLevel g_pfnRealSetCoopLevel = NULL;
static PFN_SetDisplayMode g_pfnRealSetDisplayMode = NULL;

static HRESULT WINAPI HybridSetCooperativeLevel(void* pThis, HWND hwnd, DWORD flags) {
    HRESULT hr;
    static int logCount = 0;
    static BOOL exclusiveSet = FALSE;

    g_hGameWindow = hwnd;
    if (logCount < 10)
        ProxyLog("HYBRID SetCooperativeLevel hwnd=%p flags=0x%08X%s", hwnd, flags,
                 (exclusiveSet && !(flags & DDSCL_EXCLUSIVE)) ? " -> BLOCKED (keep exclusive)" : "");
    logCount++;

    /* Once we're in exclusive mode, block any attempt to drop to DDSCL_NORMAL.
       The engine's "fallback to windowed" path would destroy our exclusive surface chain. */
    if (exclusiveSet && !(flags & DDSCL_EXCLUSIVE)) {
        return DD_OK;  /* Pretend it succeeded, stay in exclusive mode */
    }

    hr = g_pfnRealSetCoopLevel(pThis, hwnd, flags);
    if (logCount <= 10)
        ProxyLog("  SetCooperativeLevel result=0x%08X", hr);

    if (SUCCEEDED(hr) && (flags & DDSCL_EXCLUSIVE)) {
        exclusiveSet = TRUE;
    }

    return hr;
}

static HRESULT WINAPI HybridSetDisplayMode(void* pThis, DWORD w, DWORD h, DWORD bpp,
                                           DWORD refreshRate, DWORD flags) {
    HRESULT hr;
    DWORD origBpp = bpp;
    static int logCount = 0;
    /* Force 32bpp — 16bpp fullscreen not supported on modern displays */
    if (bpp == 16) bpp = 32;
    hr = g_pfnRealSetDisplayMode(pThis, w, h, bpp, refreshRate, flags);
    if (logCount < 5)
        ProxyLog("HYBRID SetDisplayMode %lux%lu@%lu (was %lu) result=0x%08X",
                 w, h, bpp, origBpp, hr);
    logCount++;
    return hr;
}

/* ================================================================
 * Exported functions
 * ================================================================ */
HRESULT WINAPI DirectDrawCreate(GUID* lpGUID, void** lplpDD, void* pUnkOuter) {
    ProxyLog("DirectDrawCreate called");
    if (g_bStubMode && !g_bHybridMode) {
        *lplpDD = CreateProxyDDraw7();
        return *lplpDD ? DD_OK : DDERR_GENERIC;
    }
    if (g_pfnDDCreate) return g_pfnDDCreate(lpGUID, lplpDD, pUnkOuter);
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawCreateEx(GUID* lpGUID, void** lplpDD,
                                                         const GUID* iid, void* pUnkOuter) {
    ProxyLog("DirectDrawCreateEx called (hybrid=%d)", g_bHybridMode);
    if (g_bStubMode && !g_bHybridMode) {
        *lplpDD = CreateProxyDDraw7();
        return *lplpDD ? DD_OK : DDERR_GENERIC;
    }
    if (g_pfnDDCreateEx) {
        HRESULT hr = g_pfnDDCreateEx(lpGUID, lplpDD, iid, pUnkOuter);
        ProxyLog("  DirectDrawCreateEx result=0x%08X obj=%p", hr, *lplpDD);
        /* In hybrid mode, patch the real DDraw7 vtable for windowed operation
         * DISABLED: vtable hooks are never invoked by the renderer (it creates
         * its own DDraw objects internally). Leaving them off to rule out
         * interference with renderer initialization. */
        if (g_bHybridMode && SUCCEEDED(hr) && *lplpDD) {
            void** vtbl = *(void***)(*lplpDD);  /* IDirectDraw7 vtable */
            DWORD oldProt;
            /* Patch slots 20 (SetCooperativeLevel) and 21 (SetDisplayMode) */
            if (VirtualProtect(&vtbl[20], 2 * sizeof(void*), PAGE_READWRITE, &oldProt)) {
                if (!g_pfnRealSetCoopLevel) {
                    g_pfnRealSetCoopLevel = (PFN_SetCooperativeLevel)vtbl[20];
                    g_pfnRealSetDisplayMode = (PFN_SetDisplayMode)vtbl[21];
                }
                vtbl[20] = (void*)HybridSetCooperativeLevel;
                vtbl[21] = (void*)HybridSetDisplayMode;
                VirtualProtect(&vtbl[20], 2 * sizeof(void*), oldProt, &oldProt);
                ProxyLog("HYBRID: Patched DDraw7 vtable[20,21] (SetCoopLevel + SetDisplayMode)");
            }
        }
        return hr;
    }
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawEnumerateA(void* lpCallback, void* lpContext) {
    ProxyLog("DirectDrawEnumerateA called");
    if (g_bStubMode && !g_bHybridMode) {
        typedef BOOL (CALLBACK *LPDDENUMCALLBACKA)(GUID*, char*, char*, void*);
        LPDDENUMCALLBACKA cb = (LPDDENUMCALLBACKA)lpCallback;
        if (cb) cb(NULL, g_szDeviceName, "display", lpContext);
        return DD_OK;
    }
    if (g_pfnDDEnumA) return g_pfnDDEnumA(lpCallback, lpContext);
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawEnumerateExA(void* lpCallback, void* lpContext, DWORD dwFlags) {
    ProxyLog("DirectDrawEnumerateExA called");
    if (g_bStubMode && !g_bHybridMode) {
        typedef BOOL (CALLBACK *LPDDENUMCALLBACKEXA)(GUID*, char*, char*, void*, HMONITOR);
        LPDDENUMCALLBACKEXA cb = (LPDDENUMCALLBACKEXA)lpCallback;
        if (cb) cb(NULL, g_szDeviceName, "display", lpContext, NULL);
        return DD_OK;
    }
    if (g_pfnDDEnumExA) return g_pfnDDEnumExA(lpCallback, lpContext, dwFlags);
    return DDERR_GENERIC;
}

HRESULT WINAPI DirectDrawEnumerateW(void* lpCallback, void* lpContext) {
    (void)lpCallback; (void)lpContext; return DD_OK;
}

HRESULT WINAPI DirectDrawEnumerateExW(void* lpCallback, void* lpContext, DWORD dwFlags) {
    (void)lpCallback; (void)lpContext; (void)dwFlags; return DD_OK;
}

HRESULT WINAPI DllCanUnloadNow(void) { return S_FALSE; }
HRESULT WINAPI DllGetClassObject(const GUID* rclsid, const GUID* riid, void** ppv) {
    (void)rclsid; (void)riid; (void)ppv; return E_NOTIMPL;
}

/* ================================================================
 * Naked forwarding stubs for standard ddraw.dll exports
 * ================================================================ */
__attribute__((naked)) void __cdecl ForwardStub_NullFallback(void) {
    __asm__("xorl %eax, %eax\n\tret");
}

#define FORWARD_FUNC(name) \
    __attribute__((naked)) void __stdcall name(void) { \
        __asm__("movl _g_pfn" #name ", %eax\n\t" \
                "testl %eax, %eax\n\t" \
                "jz _ForwardStub_NullFallback\n\t" \
                "jmp *%eax"); \
    }

FORWARD_FUNC(AcquireDDThreadLock)
FORWARD_FUNC(ReleaseDDThreadLock)
FORWARD_FUNC(CompleteCreateSysmemSurface)
FORWARD_FUNC(D3DParseUnknownCommand)
FORWARD_FUNC(DDGetAttachedSurfaceLcl)
FORWARD_FUNC(DDInternalLock)
FORWARD_FUNC(DDInternalUnlock)
FORWARD_FUNC(DSoundHelp)
FORWARD_FUNC(DirectDrawCreateClipper)
FORWARD_FUNC(GetDDSurfaceLocal)
FORWARD_FUNC(GetOLEThunkData)
FORWARD_FUNC(GetSurfaceFromDC)
FORWARD_FUNC(RegisterSpecialCase)
FORWARD_FUNC(SetAppCompatData)
