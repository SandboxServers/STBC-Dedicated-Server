
/* sendto hook for monitoring outbound UDP traffic */
typedef int (WSAAPI *PFN_sendto)(SOCKET, const char*, int, int,
                                  const struct sockaddr*, int);
static PFN_sendto g_pfnOrigSendto = NULL;
static volatile LONG g_sendtoCount = 0;

/* Forward declarations - defined in binary_patches_and_python_bridge.inc.c */
static void __cdecl ReplacementDebugConsole(void);
static void WriteTraceToFile(void);

/* Manual state dumps - C-level polling (avoids breaking event system).
 * Triggers on:
 *   - F12 key edge
 *
 * This is intentionally C-side so it works even when Python event handlers
 * are unstable or not yet fully installed. */
static int g_f12WasDown = 0;
static DWORD g_lastManualDump = 0;
static UINT_PTR g_manualInputTimerId = 0;

static void TriggerManualStateDump(const char* sourceTag, const char* label) {
    /* Use PyRun_String (NOT PyRun_SimpleString) so dump_state's raised text
     * stays in the Python error indicator. Then call ReplacementDebugConsole
     * to write it to state_dump.log. */
    typedef void* (__cdecl *pfn_PyImport_AddModule)(const char*);
    typedef void* (__cdecl *pfn_PyModule_GetDict)(void*);
    typedef void* (__cdecl *pfn_PyRun_String)(const char*, int, void*, void*);
    #define _AddModule  ((pfn_PyImport_AddModule)0x0075b890)
    #define _GetDict    ((pfn_PyModule_GetDict)0x00773990)
    #define _RunString  ((pfn_PyRun_String)0x0074b640)
    #define PY_FILE_INPUT 257

    void* mod;
    char pyCode[384];

    ProxyLog("  %s detected - triggering state dump from C", sourceTag);
    _snprintf(pyCode, sizeof(pyCode),
              "import sys\n"
              "import Custom.StateDumper\n"
              "if sys.modules.has_key('Custom.StateDumper'):\n"
              "    sys.modules['Custom.StateDumper'].dump_state('%s')\n"
              "else:\n"
              "    raise 'Custom.StateDumper missing in sys.modules'\n",
              label);
    pyCode[sizeof(pyCode) - 1] = '\0';

    mod = _AddModule("__main__");
    if (mod) {
        void* dict = _GetDict(mod);
        if (dict) {
            void* result = _RunString(pyCode, PY_FILE_INPUT, dict, dict);
            if (!result) {
                /* Exception raised (the dump text) - write to file */
                ReplacementDebugConsole();
            }
        }
    }

    #undef _AddModule
    #undef _GetDict
    #undef _RunString
    #undef PY_FILE_INPUT
}

static void TryManualStateDump(void) {
    SHORT f12State = GetAsyncKeyState(VK_F12);
    int f12Down = (f12State & 0x8000) ? 1 : 0;
    int f12Pressed = ((f12State & 0x0001) ? 1 : 0) || (f12Down && !g_f12WasDown);

    if (f12Pressed) {
        DWORD now = GetTickCount();

        /* Cooldown to avoid flooding from key repeat. */
        if (now - g_lastManualDump > 1200) {
            g_lastManualDump = now;
            TriggerManualStateDump("F12", "F12 MANUAL DUMP");
        }
    }

    g_f12WasDown = f12Down;
}

/* ================================================================
 * TryFlushPyTrace - Periodic flush of Python trace buffer to disk
 *
 * Called from the timer every ~100ms. Runs a Python snippet that:
 * 1. Disables sys.settrace (prevents recursion during flush)
 * 2. Joins _trace_log entries into a string
 * 3. Clears the buffer
 * 4. Re-enables tracing
 * 5. Raises the string as an exception
 *
 * The raise propagates to PyRun_String (returns NULL), then we call
 * WriteTraceToFile to write the text to py_trace.log (NOT state_dump.log).
 * ================================================================ */
static DWORD g_lastTraceFlush = 0;
#define TRACE_FLUSH_INTERVAL_MS 100

static void TryFlushPyTrace(void) {
    typedef void* (__cdecl *pfn_PyImport_AddModule)(const char*);
    typedef void* (__cdecl *pfn_PyModule_GetDict)(void*);
    typedef void* (__cdecl *pfn_PyRun_String)(const char*, int, void*, void*);
    #define _AddModule  ((pfn_PyImport_AddModule)0x0075b890)
    #define _GetDict    ((pfn_PyModule_GetDict)0x00773990)
    #define _RunString  ((pfn_PyRun_String)0x0074b640)
    #define PY_FILE_INPUT 257

    DWORD now = GetTickCount();
    void* mod;

    if (now - g_lastTraceFlush < TRACE_FLUSH_INTERVAL_MS) return;
    g_lastTraceFlush = now;

    mod = _AddModule("__main__");
    if (!mod) return;
    {
        void* dict = _GetDict(mod);
        if (!dict) return;
        {
            void* result = _RunString(
                "import sys\n"
                "if sys.modules.has_key('Custom.StateDumper'):\n"
                "    _sd = sys.modules['Custom.StateDumper']\n"
                "    if len(_sd._trace_log) > 0:\n"
                "        sys.settrace(None)\n"
                "        _sd._trace_active = 0\n"
                "        import strop\n"
                "        _msg = strop.join(_sd._trace_log, '\\n')\n"
                "        _sd._trace_total = _sd._trace_total + len(_sd._trace_log)\n"
                "        _sd._trace_log = []\n"
                "        _sd._trace_active = 1\n"
                "        sys.settrace(_sd._trace_func)\n"
                "        raise _msg\n",
                PY_FILE_INPUT, dict, dict);
            if (!result) {
                /* Exception raised = trace text. Write to py_trace.log */
                WriteTraceToFile();
            }
        }
    }

    #undef _AddModule
    #undef _GetDict
    #undef _RunString
    #undef PY_FILE_INPUT
}

static VOID CALLBACK ManualInputTimerProc(HWND hwnd, UINT msg,
                                          UINT_PTR id, DWORD time) {
    static int obsTick = 0;
    (void)hwnd; (void)msg; (void)id; (void)time;
    TryManualStateDump();
    TryFlushPyTrace();
    obsTick++;

    /* Periodic ACK diagnostic dump every 75 obs-ticks (~1.9s).
     * Walks ACK-outbox and retransmit queues for each connected peer
     * to track fragment ACK state on the client side. */
    if (obsTick > 0 && (obsTick % 75 == 0)) {
        DWORD wsnPtr = 0;
        if (!IsBadReadPtr((void*)0x0097FA78, 4))
            wsnPtr = *(DWORD*)0x0097FA78;
        if (wsnPtr) {
            int pCount = 0;
            DWORD pArray = 0;
            if (!IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
                pCount = *(int*)(wsnPtr + 0x30);
            if (!IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
                pArray = *(DWORD*)(wsnPtr + 0x2C);
            if (pCount > 0 && pArray) {
                int pi;
                for (pi = 0; pi < pCount && pi < 8; pi++) {
                    DWORD pp = 0;
                    if (!IsBadReadPtr((void*)(pArray + pi*4), 4))
                        pp = *(DWORD*)(pArray + pi*4);
                    if (pp && !IsBadReadPtr((void*)pp, 0xC0)) {
                        DWORD peerID = *(DWORD*)(pp + 0x18);
                        DumpPeerTransportQueues(pp, peerID);
                    }
                }
            }
        }
    }

    /* FTrace dump every ~10s (400 ticks * 25ms = 10s) */
    if (obsTick > 0 && (obsTick % 400 == 0)) {
        char label[32];
        wsprintfA(label, "obs_tick_%d", obsTick);
        FTraceDump(label);
    }
}

static void StartManualInputTimer(void) {
    if (g_manualInputTimerId)
        return;
    g_manualInputTimerId = SetTimer(NULL, 0, 25, ManualInputTimerProc);
    if (g_manualInputTimerId) {
        ProxyLog("Manual input timer started (25ms) for F12 dumps");
    } else {
        ProxyLog("WARN: Manual input timer failed (err=%lu)", GetLastError());
    }
}

/* ================================================================
 * Tick State Logger - CSV trace of key engine state every game tick
 *
 * Writes one line per ~33ms to tick_trace.log with key memory values.
 * Designed to be cheap: just memory reads + fprintf, no Python.
 * Called from HookedSendto (OBSERVE_ONLY) or GameLoopTimerProc (server).
 *
 * Columns:
 *   seq       - monotonic sequence number
 *   ms        - GetTickCount() timestamp
 *   gt        - gameTime float from clock object
 *   mpg       - MultiplayerGame pointer (0 = no game)
 *   players   - WSN player count
 *   conn      - WSN connection state (2=host, 3=client)
 *   isCli     - IsClient byte at 0x0097FA88 (0=host, 1=client)
 *   isHost    - IsHost byte at 0x0097FA89 (1=host, 0=client)
 *   isMp      - IsMultiplayer byte at 0x0097FA8A
 *   mpgB0     - MPG+0xB0 (object gate for message processing)
 *   mpg1F8    - MPG+0x1F8 (ReadyForNewPlayers)
 *   emQ       - Event manager queue counter
 *   pUQ       - Peer[0] unreliable send queue size
 *   pRQ       - Peer[0] reliable send queue size
 *   pPQ       - Peer[0] priority send queue size
 * ================================================================ */
static FILE* g_pTickLog = NULL;
static DWORD g_tickLastMs = 0;
static DWORD g_tickSeq = 0;

static void TickLogger(void) {
    DWORD now = GetTickCount();
    DWORD wsnPtr = 0, mpg = 0, clockPtr = 0;
    float gameTime = 0.0f;
    int playerCount = 0, connState = 0;
    BYTE isClient = 0, isHost = 0, isMp = 0, mpg1F8 = 0;
    DWORD mpgB0 = 0, emQ = 0;
    int pUQ = 0, pRQ = 0, pPQ = 0;

    /* Throttle: one sample per ~33ms (game tick rate) */
    if (now - g_tickLastMs < 33) return;
    g_tickLastMs = now;

    /* Open log on first call */
    if (!g_pTickLog) {
        char path[MAX_PATH];
        if (g_szBasePath[0])
            _snprintf(path, sizeof(path), "%stick_trace.log", g_szBasePath);
        else
            _snprintf(path, sizeof(path), "tick_trace.log");
        path[sizeof(path)-1] = '\0';
        g_pTickLog = fopen(path, "w");
        if (!g_pTickLog) return;
        fprintf(g_pTickLog, "# Tick Trace Log - session %lu\n", (unsigned long)now);
        fprintf(g_pTickLog, "# seq,ms,gt,mpg,players,conn,isCli,isHost,isMp,mpgB0,mpg1F8,emQ,pUQ,pRQ,pPQ\n");
        fflush(g_pTickLog);
    }

    /* Read key addresses */
    if (!IsBadReadPtr((void*)0x0097FA78, 4))
        wsnPtr = *(DWORD*)0x0097FA78;
    if (!IsBadReadPtr((void*)0x0097e238, 4))
        mpg = *(DWORD*)0x0097e238;
    if (!IsBadReadPtr((void*)0x009a09d0, 4))
        clockPtr = *(DWORD*)0x009a09d0;
    if (clockPtr && !IsBadReadPtr((void*)(clockPtr + 0x90), 4))
        gameTime = *(float*)(clockPtr + 0x90);
    if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
        playerCount = *(int*)(wsnPtr + 0x30);
    if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x14), 4))
        connState = *(int*)(wsnPtr + 0x14);
    if (!IsBadReadPtr((void*)0x0097FA88, 1))
        isClient = *(BYTE*)0x0097FA88;
    if (!IsBadReadPtr((void*)0x0097FA89, 1))
        isHost = *(BYTE*)0x0097FA89;
    if (!IsBadReadPtr((void*)0x0097FA8A, 1))
        isMp = *(BYTE*)0x0097FA8A;
    if (mpg && !IsBadReadPtr((void*)(mpg + 0xB0), 4))
        mpgB0 = *(DWORD*)(mpg + 0xB0);
    if (mpg && !IsBadReadPtr((void*)(mpg + 0x1F8), 1))
        mpg1F8 = *(BYTE*)(mpg + 0x1F8);
    if (!IsBadReadPtr((void*)0x0097F840, 4))
        emQ = *(DWORD*)0x0097F840;

    /* Peer[0] send queue sizes */
    if (wsnPtr && playerCount > 0) {
        DWORD pArray = 0;
        if (!IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            pArray = *(DWORD*)(wsnPtr + 0x2C);
        if (pArray) {
            DWORD pp = 0;
            if (!IsBadReadPtr((void*)pArray, 4))
                pp = *(DWORD*)pArray;
            if (pp && !IsBadReadPtr((void*)(pp + 0xB4), 4)) {
                pUQ = *(int*)(pp + 0x7C);
                pRQ = *(int*)(pp + 0x98);
                pPQ = *(int*)(pp + 0xB4);
            }
        }
    }

    /* Write CSV line */
    fprintf(g_pTickLog, "%lu,%lu,%.3f,0x%08lX,%d,%d,%d,%d,%d,0x%08lX,%d,%lu,%d,%d,%d\n",
            (unsigned long)g_tickSeq++, (unsigned long)now, gameTime,
            (unsigned long)mpg, playerCount, connState, (int)isClient, (int)isHost, (int)isMp,
            (unsigned long)mpgB0, (int)mpg1F8, (unsigned long)emQ, pUQ, pRQ, pPQ);

    /* Flush every 30 lines (~1 second) to balance I/O and data safety */
    if (g_tickSeq % 30 == 0)
        fflush(g_pTickLog);
}

static int WSAAPI HookedSendto(SOCKET s, const char* buf, int len, int flags,
                                const struct sockaddr* to, int tolen) {
    int rc;
#ifdef OBSERVE_ONLY
    if (!g_factoryHooked) TryInstallFactoryHooks();
    TryManualStateDump();
    TickLogger();
#endif
    rc = g_pfnOrigSendto(s, buf, len, flags, to, tolen);
    InterlockedIncrement(&g_sendtoCount);
    if (to && tolen >= (int)sizeof(struct sockaddr_in)) {
        PktLog("S->C", (const struct sockaddr_in*)to,
               (const unsigned char*)buf, len, rc);
    } else {
        PktLog("S->?", NULL, (const unsigned char*)buf, len, rc);
    }
    return rc;
}

/* recvfrom hook for monitoring inbound UDP traffic */
typedef int (WSAAPI *PFN_recvfrom)(SOCKET, char*, int, int,
                                    struct sockaddr*, int*);
static PFN_recvfrom g_pfnOrigRecvfrom = NULL;
static volatile LONG g_recvfromCount = 0;

static int WSAAPI HookedRecvfrom(SOCKET s, char* buf, int len, int flags,
                                  struct sockaddr* from, int* fromlen) {
    int rc;
#ifdef OBSERVE_ONLY
    if (!g_factoryHooked) TryInstallFactoryHooks();
    TryManualStateDump();
#endif
    rc = g_pfnOrigRecvfrom(s, buf, len, flags, from, fromlen);
    if (rc > 0 && !(flags & MSG_PEEK)) {
        InterlockedIncrement(&g_recvfromCount);
        if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in)) {
            PktLog("C->S", (const struct sockaddr_in*)from,
                   (const unsigned char*)buf, rc, rc);
        } else {
            PktLog("C->S", NULL, (const unsigned char*)buf, rc, rc);
        }
    }
    return rc;
}

/* TCP hooks for master server challenge-response logging.
 * The GameSpy master server auth uses TCP (connect/send/recv) to port 28964.
 * SL_master_connect (0x006aa4c0) does:
 *   connect() -> recv(\secure\<challenge>) -> send(\gamename\...\validate\...)
 *   -> send(\list\...) -> recv(binary server list) */

typedef int (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr*, int);
static PFN_connect g_pfnOrigConnect = NULL;

typedef int (WSAAPI *PFN_send)(SOCKET, const char*, int, int);
static PFN_send g_pfnOrigSend = NULL;

typedef int (WSAAPI *PFN_recv)(SOCKET, char*, int, int);
static PFN_recv g_pfnOrigRecv = NULL;

/* Track which socket is the master server TCP connection */
static SOCKET g_masterServerSocket = INVALID_SOCKET;

static int WSAAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    int rc;
    if (name && namelen >= (int)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)name;
        unsigned char* ip = (unsigned char*)&sin->sin_addr;
        int port = ntohs(sin->sin_port);
        ProxyLog("  TCP_CONNECT: socket=%d to %d.%d.%d.%d:%d",
                 (int)s, ip[0], ip[1], ip[2], ip[3], port);
        if (g_pPacketLog) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            fprintf(g_pPacketLog,
                    "[%02d:%02d:%02d.%03d] TCP_CONNECT to %d.%d.%d.%d:%d (socket=%d)\n\n",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    ip[0], ip[1], ip[2], ip[3], port, (int)s);
            fflush(g_pPacketLog);
        }
        /* Track master server socket (port 28964 = GameSpy master) */
        if (port == 28964)
            g_masterServerSocket = s;
    }
    rc = g_pfnOrigConnect(s, name, namelen);
    if (name && namelen >= (int)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)name;
        unsigned char* ip = (unsigned char*)&sin->sin_addr;
        ProxyLog("  TCP_CONNECT: result=%d (WSA=%d) to %d.%d.%d.%d:%d",
                 rc, (rc != 0) ? WSAGetLastError() : 0,
                 ip[0], ip[1], ip[2], ip[3], ntohs(sin->sin_port));
    }
    return rc;
}

static int WSAAPI HookedSend(SOCKET s, const char* buf, int len, int flags) {
    int rc = g_pfnOrigSend(s, buf, len, flags);
    if (g_pPacketLog && len > 0) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        /* Log all TCP sends, with extra detail for GameSpy text */
        if (buf[0] == '\\') {
            /* GameSpy text protocol */
            char textBuf[1500];
            int printLen = len;
            if (printLen > (int)sizeof(textBuf) - 1) printLen = (int)sizeof(textBuf) - 1;
            memcpy(textBuf, buf, printLen);
            textBuf[printLen] = '\0';
            fprintf(g_pPacketLog,
                    "[%02d:%02d:%02d.%03d] TCP_SEND socket=%d len=%d rc=%d GAMESPY_MASTER_AUTH\n"
                    "  Text: %s\n",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    (int)s, len, rc, textBuf);
        } else {
            fprintf(g_pPacketLog,
                    "[%02d:%02d:%02d.%03d] TCP_SEND socket=%d len=%d rc=%d\n",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    (int)s, len, rc);
        }
        PktHexDump(g_pPacketLog, (const unsigned char*)buf, len);
        fprintf(g_pPacketLog, "\n");
        fflush(g_pPacketLog);
    }
    return rc;
}

static int WSAAPI HookedRecv(SOCKET s, char* buf, int len, int flags) {
    int rc = g_pfnOrigRecv(s, buf, len, flags);
    if (g_pPacketLog && rc > 0) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        if (buf[0] == '\\') {
            /* GameSpy text protocol */
            char textBuf[1500];
            int printLen = rc;
            if (printLen > (int)sizeof(textBuf) - 1) printLen = (int)sizeof(textBuf) - 1;
            memcpy(textBuf, buf, printLen);
            textBuf[printLen] = '\0';
            fprintf(g_pPacketLog,
                    "[%02d:%02d:%02d.%03d] TCP_RECV socket=%d len=%d rc=%d GAMESPY_MASTER_CHALLENGE\n"
                    "  Text: %s\n",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    (int)s, len, rc, textBuf);
        } else {
            fprintf(g_pPacketLog,
                    "[%02d:%02d:%02d.%03d] TCP_RECV socket=%d len=%d rc=%d\n",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    (int)s, len, rc);
        }
        PktHexDump(g_pPacketLog, (const unsigned char*)buf, rc);
        fprintf(g_pPacketLog, "\n");
        fflush(g_pPacketLog);
    }
    return rc;
}

/* OutputDebugStringA hook - captures game debug output */
typedef void (WINAPI *PFN_OutputDebugStringA)(LPCSTR);
static PFN_OutputDebugStringA g_pfnOrigODS = NULL;

static void WINAPI HookedOutputDebugStringA(LPCSTR lpOutputString) {
    if (lpOutputString && lpOutputString[0]) {
        ODSLog("[ODS] %s", lpOutputString);
    }
    if (g_pfnOrigODS)
        g_pfnOrigODS(lpOutputString);
}

/* (VEH crash handler removed - replaced by CrashDumpHandler via SetUnhandledExceptionFilter) */
