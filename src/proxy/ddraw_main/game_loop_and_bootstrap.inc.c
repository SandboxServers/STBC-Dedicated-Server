/* ================================================================
 * GameLoopTimerProc - drives the game tick after bootstrap
 *
 * Calls UtopiaApp_MainTick (0x0043b4f0) which processes:
 *   - TGTimerManager_Update on 0x0097F898 and 0x0097F810
 *   - TGEventManager_ProcessEvents on 0x0097F838
 *   - Game subsystem updates (multiplayer, checksum exchange, etc.)
 *   - Rendering via FUN_004433e0 (patched to NOP in stub mode)
 *
 * Also explicitly calls TGNetwork::Update (0x006B4560) to pump
 * network send/recv queues. Without this, the server never reads
 * incoming UDP packets so the checksum exchange can't complete.
 *
 * MainTick has its own SEH frame so exceptions are caught safely.
 * ================================================================ */
typedef void (__fastcall *pfn_UtopiaMainTick)(void* ecx, void* edx);
typedef void (__fastcall *pfn_TGNetworkUpdate)(void* ecx, void* edx);
typedef unsigned int (__fastcall *pfn_GameSpyStartHB)(void* ecx, void* edx, unsigned char lanMode);
typedef void (__fastcall *pfn_GameSpyTick)(void* ecx, void* edx, float gameTime);
typedef void (__cdecl *pfn_qr_handle_query)(void* qr, void* buf, struct sockaddr* addr);

#define UTOPIA_MAIN_TICK     ((pfn_UtopiaMainTick)0x0043b4f0)
#define TGNETWORK_UPDATE     ((pfn_TGNetworkUpdate)0x006B4560)
#define GAMESPY_START_HB     ((pfn_GameSpyStartHB)0x0069c240)
#define GAMESPY_TICK         ((pfn_GameSpyTick)0x0069c440)
#define QR_HANDLE_QUERY      ((pfn_qr_handle_query)0x006ac1e0)
#define UTOPIA_APP_OBJ       ((void*)0x0097FA00)
#define GAMESPY_PTR          (*(DWORD*)0x0097FA7C)  /* UtopiaModule+0x7C */

/* ================================================================
 * NewPlayerInGame - FUN_006a1e70
 *
 * The engine's dispatcher at 0x0069f2a0 handles the client's 0x2A
 * (NewPlayerInGame) by calling FUN_006a1e70 internally. This does:
 *   - C-side work: sends game objects, game state (0x35/0x17) to new player
 *   - Fires ET_NEW_PLAYER_IN_GAME event -> Python NewPlayerHandler
 *   - Tries to call Python InitNetwork via FUN_006f8ab0
 *
 * PROBLEM: FUN_006f8ab0 uses PyRun_SimpleString which FAILS in TIMERPROC
 * context (nesting counter issue). So InitNetwork never runs, and the
 * client never receives MISSION_INIT_MESSAGE.
 *
 * FIX: We do NOT call FUN_006a1e70 manually (that caused duplicate
 * messages: 0x35/0x37/0x17 sent twice, ACK storms, VEH crashes).
 * Instead, we detect when a peer's checksum-complete flag transitions
 * to 1 and call InitNetwork via RunPyCode after a 30-tick delay.
 * ================================================================ */

/* Flag for HeartbeatThread to request Python diagnostics on main thread.
 * Python 1.5.2's allocator has NO locks - all Python C API calls MUST
 * happen on the main thread to avoid GIL violations and heap corruption. */
static volatile int g_runPyDiag = 0;
static int g_peerInitNetDone[8] = {0};  /* shared: set by InitNetwork, read by ship poll */

static VOID CALLBACK GameLoopTimerProc(HWND hwnd, UINT msg,
                                        UINT_PTR id, DWORD time) {
    typedef DWORD (__cdecl *pfn_GetShipFromPlayerID)(int connID);
    static int tickCount = 0;
    static int lastPlayerCount = -1;
    static DWORD lastLogTime = 0;
    DWORD wsnPtr = 0;
    (void)msg; (void)hwnd; (void)id;

    tickCount++;
    TryManualStateDump();
    TryFlushPyTrace();

    /* Periodically try to patch mission modules for headless mode.
     * Mission modules may be loaded lazily by the ET_START cascade.
     * Check every ~1s (30 ticks) until we patch or timeout (~10s). */
    {
        static int missionPatched = 0;
        if (!missionPatched && (tickCount % 30 == 1)) {
            int rc = RunPyCode(
                "import sys\n"
                "if sys.modules.has_key('Custom.DedicatedServer'):\n"
                "    ds = sys.modules['Custom.DedicatedServer']\n"
                "    n = ds.PatchLoadedMissionModules()\n"
                "    if n > 0:\n"
                "        ds._log('GAMELOOP PATCH: patched ' + str(n) + ' at tick')\n");
            (void)rc;
            if (tickCount > 300) {
                missionPatched = 1;
                ProxyLog("  GAMELOOP: PatchLoadedMissionModules polling stopped (timeout at tick %d)", tickCount);
            }
        }
    }

    /* One-shot deferred system Set creation.
     * The ET_START cascade needs a few ticks to load episode/mission modules.
     * After ~5 ticks (~165ms), call CreateSystemSet() to create the star
     * system Set with ProximityManager for collision detection. */
    {
        static int setCreated = 0;
        if (!setCreated && tickCount == 5) {
            setCreated = 1;
            ProxyLog("  GAMELOOP[%d]: Calling deferred CreateSystemSet()", tickCount);
            RunPyCode(
                "import sys\n"
                "if sys.modules.has_key('Custom.DedicatedServer'):\n"
                "    ds = sys.modules['Custom.DedicatedServer']\n"
                "    ds.CreateSystemSet()\n");
        }
    }

    /* Minimize the game window after session is fully launched.
     * Tick 10 (~330ms) gives the ET_START cascade and CreateSystemSet
     * time to complete. Safe to minimize at this point since all
     * NIF-dependent initialization is done and our renderer is a stub. */
    {
        static int windowMinimized = 0;
        if (!windowMinimized && tickCount == 10 && g_hGameWindow) {
            windowMinimized = 1;
            ShowWindow(g_hGameWindow, SW_MINIMIZE);
            ProxyLog("  GAMELOOP[%d]: Minimized game window", tickCount);
        }
    }

    /* Read WSN pointer (used in multiple places below) */
    if (!IsBadReadPtr((void*)0x0097FA78, 4))
        wsnPtr = *(DWORD*)0x0097FA78;

    /* Diagnostic logging for first 5 ticks */
    if (tickCount <= 5) {
        DWORD clockPtr = 0;
        float gameTime = 0.0f;
        int playerCount = 0;
        int connState = -1;

        if (!IsBadReadPtr((void*)0x009a09d0, 4))
            clockPtr = *(DWORD*)0x009a09d0;
        if (clockPtr && !IsBadReadPtr((void*)(clockPtr + 0x90), 4))
            gameTime = *(float*)(clockPtr + 0x90);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            playerCount = *(int*)(wsnPtr + 0x30);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x14), 4))
            connState = *(int*)(wsnPtr + 0x14);

        {
            /* Check critical WSN flags */
            int sendFlag = 0, isHost = 0, procPkts = 0;
            DWORD pendingQ = 0, incomingQ = 0;
            DWORD socketFD = 0xFFFFFFFF;
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x10C), 4)) {
                sendFlag = *(BYTE*)(wsnPtr + 0x10C);
                isHost = *(BYTE*)(wsnPtr + 0x10E);
                procPkts = *(BYTE*)(wsnPtr + 0x10D);
            }
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x38), 4))
                pendingQ = *(DWORD*)(wsnPtr + 0x38);
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x54), 4))
                incomingQ = *(DWORD*)(wsnPtr + 0x54);
            /* Socket FD at WSN+0x194 */
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x194), 4))
                socketFD = *(DWORD*)(wsnPtr + 0x194);

            ProxyLog("  GAMELOOP[%d]: clock=0x%08X time=%.3f WSN=0x%08X players=%d connState=%d",
                     tickCount, clockPtr, gameTime, wsnPtr, playerCount, connState);
            ProxyLog("    sendFlag=0x%02X isHost=%d procPkts=%d pendQ=0x%08X inQ=0x%08X sock=%d",
                     sendFlag, isHost, procPkts, pendingQ, incomingQ, (int)socketFD);
        }
    }

    /* One-time renderer pipeline verification at tick 1.
     * With PatchSkipRendererSetup active, pipeline objects at renderer offsets
     * 0xB8, 0xBC, 0xC0, 0xC4 will be NULL (pipeline creation is skipped).
     * The renderer ptr is at *(DWORD*)(appObj + 0x0C) where appObj = *(DWORD*)0x009a09d0. */
    {
        static int pipelineChecked = 0;
        if (!pipelineChecked && tickCount == 1) {
            DWORD appPtr = 0, rendPtr = 0;
            DWORD p_b8 = 0, p_bc = 0, p_c0 = 0, p_c4 = 0;
            pipelineChecked = 1;

            if (!IsBadReadPtr((void*)0x009a09d0, 4))
                appPtr = *(DWORD*)0x009a09d0;
            if (appPtr && !IsBadReadPtr((void*)(appPtr + 0x0c), 4))
                rendPtr = *(DWORD*)(appPtr + 0x0c);
            if (rendPtr) {
                if (!IsBadReadPtr((void*)(rendPtr + 0xb8), 4))
                    p_b8 = *(DWORD*)(rendPtr + 0xb8);
                if (!IsBadReadPtr((void*)(rendPtr + 0xbc), 4))
                    p_bc = *(DWORD*)(rendPtr + 0xbc);
                if (!IsBadReadPtr((void*)(rendPtr + 0xc0), 4))
                    p_c0 = *(DWORD*)(rendPtr + 0xc0);
                if (!IsBadReadPtr((void*)(rendPtr + 0xc4), 4))
                    p_c4 = *(DWORD*)(rendPtr + 0xc4);
            }
            ProxyLog("  PIPELINE CHECK: app=0x%08X renderer=0x%08X", appPtr, rendPtr);
            ProxyLog("    +0xB8=0x%08X +0xBC=0x%08X +0xC0=0x%08X +0xC4=0x%08X",
                     p_b8, p_bc, p_c0, p_c4);
            if (rendPtr && p_b8 && p_bc && p_c0 && p_c4)
                ProxyLog("    Pipeline objects ALL populated - FUN_007c3480 succeeded");
            else if (rendPtr)
                ProxyLog("    WARNING: Some pipeline objects NULL - FUN_007c3480 may have failed");
            else
                ProxyLog("    WARNING: Renderer pointer NULL - renderer not created");
        }
    }

    /* Check emQ BEFORE MainTick to see if events were pending from TGNetwork_Update */
    {
        static DWORD lastPreEmQ = 0;
        DWORD preEmQ = 0;
        if (!IsBadReadPtr((void*)0x0097F840, 4))
            preEmQ = *(DWORD*)0x0097F840;
        if (preEmQ != lastPreEmQ) {
            ProxyLog("  GAMELOOP[%d]: emQ BEFORE MainTick: %u (was %u)", tickCount, preEmQ, lastPreEmQ);
            lastPreEmQ = preEmQ;
        }
    }

    /* Call the game's main tick (processes timers, events, subsystems) */
    UTOPIA_MAIN_TICK(UTOPIA_APP_OBJ, NULL);

    /* Log tick state (server build) */
    TickLogger();

    /* After MainTick: check if event processing resulted in queued outbound packets.
     * If NewPlayerHandler was dispatched, it calls ChecksumSend which calls
     * TGNetwork::Send, queuing packets in peer send queues. */
    if (wsnPtr) {
        static int lastUQ = -1, lastRQ = -1, lastPQ = -1;
        static int postMTLogCount = 0;
        int pCount = 0;
        DWORD pArray = 0;
        if (!IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            pCount = *(int*)(wsnPtr + 0x30);
        if (!IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            pArray = *(DWORD*)(wsnPtr + 0x2C);
        if (pCount > 0 && pArray) {
            int pi;
            for (pi = 0; pi < pCount && pi < 4; pi++) {
                DWORD pp = 0;
                if (!IsBadReadPtr((void*)(pArray + pi*4), 4))
                    pp = *(DWORD*)(pArray + pi*4);
                if (pp && !IsBadReadPtr((void*)pp, 0xC0)) {
                    int uq = *(int*)(pp + 0x7C);
                    int rq = *(int*)(pp + 0x98);
                    int pq = *(int*)(pp + 0xB4);
                    /* Only log when queue sizes change */
                    if (uq != lastUQ || rq != lastRQ || pq != lastPQ) {
                        if (postMTLogCount < 50) {
                            postMTLogCount++;
                            ProxyLog("  GAMELOOP[%d]: PEER[%d] id=%u SEND QUEUES after MainTick: unreliable=%d reliable=%d priority=%d",
                                     tickCount, pi, *(DWORD*)(pp + 0x18), uq, rq, pq);
                        }
                        lastUQ = uq; lastRQ = rq; lastPQ = pq;
                    }
                }
            }
        }
    }

    /* Peek-based packet router for shared UDP socket.
     * GameSpy queries and game packets share the same UDP socket (WSN+0x194).
     * GameSpy queries are text-based, always starting with '\' (0x5C), e.g.
     * "\basic\", "\status\". Game packets are binary (first byte != '\').
     *
     * We peek at each pending packet with MSG_PEEK:
     *   - If '\' prefix: consume it and call qr_handle_query directly
     *   - If binary: leave it in the socket for TGNetwork_Update
     *
     * qr_t+0xE4 is kept at 0 so GameSpy_Tick's internal qr_process_incoming
     * returns immediately (no competing recvfrom). GameSpy_Tick is still
     * called for internal state management (counter increments, etc). */
    {
        DWORD gsPtr = 0;
        if (!IsBadReadPtr((void*)0x0097FA7C, 4))
            gsPtr = *(DWORD*)0x0097FA7C;
        if (gsPtr) {
            DWORD qrPtr = 0;
            if (!IsBadReadPtr((void*)(gsPtr + 0xDC), 4))
                qrPtr = *(DWORD*)(gsPtr + 0xDC);
            if (qrPtr) {
                SOCKET sock = *(SOCKET*)qrPtr;
                if (sock != INVALID_SOCKET) {
                    fd_set readSet;
                    struct timeval tv;
                    int routed = 0;
                    tv.tv_sec = 0;
                    tv.tv_usec = 0;
                    /* Drain all GameSpy queries, stop at first game packet */
                    for (;;) {
                        int selRc;
                        char peekByte;
                        struct sockaddr_in srcAddr;
                        int addrLen = sizeof(srcAddr);
                        int peekRc;

                        FD_ZERO(&readSet);
                        FD_SET(sock, &readSet);
                        selRc = select(0, &readSet, NULL, NULL, &tv);
                        if (selRc <= 0) break;

                        /* Peek at first byte without consuming */
                        addrLen = sizeof(srcAddr);
                        peekRc = recvfrom(sock, &peekByte, 1, MSG_PEEK,
                                          (struct sockaddr*)&srcAddr, &addrLen);
                        if (peekRc <= 0) break;

                        if (peekByte == '\\') {
                            /* GameSpy query - consume and handle */
                            char queryBuf[256];
                            int recvRc;
                            addrLen = sizeof(srcAddr);
                            recvRc = recvfrom(sock, queryBuf, sizeof(queryBuf)-1, 0,
                                              (struct sockaddr*)&srcAddr, &addrLen);
                            if (recvRc > 0) {
                                queryBuf[recvRc] = '\0';
                                ProxyLog("  GAMELOOP[%d]: GameSpy query from %d.%d.%d.%d:%d: \"%s\"",
                                         tickCount,
                                         (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b1,
                                         (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b2,
                                         (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b3,
                                         (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b4,
                                         ntohs(srcAddr.sin_port),
                                         queryBuf);
                                QR_HANDLE_QUERY((void*)qrPtr, queryBuf,
                                                (struct sockaddr*)&srcAddr);
                                routed++;
                            }
                        } else {
                            /* Binary game packet - leave for TGNetwork_Update */
                            ProxyLog("  GAMELOOP[%d]: Binary packet (0x%02X) from %d.%d.%d.%d:%d - leaving for TGNetwork",
                                     tickCount, (unsigned char)peekByte,
                                     (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b1,
                                     (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b2,
                                     (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b3,
                                     (unsigned char)srcAddr.sin_addr.S_un.S_un_b.s_b4,
                                     ntohs(srcAddr.sin_port));
                            break;
                        }
                    }
                    if (routed) {
                        ProxyLog("  GAMELOOP[%d]: Routed %d GameSpy queries", tickCount, routed);
                    }
                }
            }

            /* Still call GameSpy_Tick for internal state (counters, etc).
             * With qr_t+0xE4=0, its qr_process_incoming returns immediately. */
            {
                float gameTime = 0.0f;
                DWORD clockPtr = 0;
                if (!IsBadReadPtr((void*)0x009a09d0, 4))
                    clockPtr = *(DWORD*)0x009a09d0;
                if (clockPtr && !IsBadReadPtr((void*)(clockPtr + 0x90), 4))
                    gameTime = *(float*)(clockPtr + 0x90);
                GAMESPY_TICK((void*)gsPtr, NULL, gameTime);
            }
        }
    }

    /* Pump network AFTER GameSpy tick. TGNetwork::Update (0x006B4560) reads
     * remaining UDP packets and processes send/recv queues.
     * Host state: WSN+0x14 == 2 (Connect sets 2=host, 3=client). */
    if (wsnPtr) {
        /* Check socket data availability before Update */
        {
            static int selectLogCount = 0;
            SOCKET wsnSock = INVALID_SOCKET;
            if (!IsBadReadPtr((void*)(wsnPtr + 0x194), 4))
                wsnSock = *(SOCKET*)(wsnPtr + 0x194);
            if (wsnSock != INVALID_SOCKET && selectLogCount < 50) {
                fd_set rs;
                struct timeval tv = {0, 0};
                int sr;
                FD_ZERO(&rs);
                FD_SET(wsnSock, &rs);
                sr = select(0, &rs, NULL, NULL, &tv);
                if (sr > 0) {
                    selectLogCount++;
                    ProxyLog("  GAMELOOP[%d]: Data on WSN socket BEFORE Update (#%d)",
                             tickCount, selectLogCount);
                }
            }
        }
        TGNETWORK_UPDATE((void*)wsnPtr, NULL);
    }

    /* Check emQ AFTER TGNetwork_Update to see if events were generated */
    {
        static DWORD lastPostEmQ = 0;
        DWORD postEmQ = 0;
        if (!IsBadReadPtr((void*)0x0097F840, 4))
            postEmQ = *(DWORD*)0x0097F840;
        if (postEmQ != lastPostEmQ) {
            ProxyLog("  GAMELOOP[%d]: emQ AFTER TGNetwork_Update: %u (was %u)", tickCount, postEmQ, lastPostEmQ);
            lastPostEmQ = postEmQ;
        }
    }

    /* Monitor player connections, EM queue, and network queues */
    {
        static DWORD lastPendQ = 0, lastInQ = 0;
        int playerCount = 0;
        DWORD emCount = 0;
        DWORD playerArray = 0;
        DWORD pendingQ = 0, incomingQ = 0;
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            playerCount = *(int*)(wsnPtr + 0x30);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            playerArray = *(DWORD*)(wsnPtr + 0x2C);
        if (!IsBadReadPtr((void*)0x0097F840, 4))
            emCount = *(DWORD*)0x0097F840;
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x38), 4))
            pendingQ = *(DWORD*)(wsnPtr + 0x38);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x54), 4))
            incomingQ = *(DWORD*)(wsnPtr + 0x54);

        if (playerCount != lastPlayerCount) {
            int connState = -1;
            DWORD hostID = 0, localID = 0;
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x14), 4))
                connState = *(int*)(wsnPtr + 0x14);
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x18), 4))
                hostID = *(DWORD*)(wsnPtr + 0x18);
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x1C), 4))
                localID = *(DWORD*)(wsnPtr + 0x1C);
            ProxyLog("  GAMELOOP: *** PLAYERS CHANGED: %d -> %d (tick %d) ***",
                     lastPlayerCount, playerCount, tickCount);
            ProxyLog("    playerArray=0x%08X emQ=%u connState=%d hostID=%u localID=%u",
                     playerArray, emCount, connState, hostID, localID);
            ProxyLog("    pendQ=0x%08X inQ=0x%08X", pendingQ, incomingQ);
            /* Dump checksum-critical state on player change */
            {
                DWORD csm = 0, mpg = 0;
                BYTE mp1F8 = 0, netActive = 0;
                if (!IsBadReadPtr((void*)0x0097fa80, 4))
                    csm = *(DWORD*)0x0097fa80;
                if (!IsBadReadPtr((void*)0x0097e238, 4))
                    mpg = *(DWORD*)0x0097e238;
                if (mpg && !IsBadReadPtr((void*)(mpg + 0x1F8), 1))
                    mp1F8 = *(BYTE*)(mpg + 0x1F8);
                if (!IsBadReadPtr((void*)0x0097fa8a, 1))
                    netActive = *(BYTE*)0x0097fa8a;
                ProxyLog("    CHECKSUM DIAG: csm=0x%08X mpg=0x%08X +0x1F8=%d netActive=%d",
                         csm, mpg, mp1F8, netActive);
                /* Dump settings bytes that go into opcode 0x00 packet */
                {
                    BYTE settings1 = 0, settings2 = 0;
                    if (!IsBadReadPtr((void*)0x008e5f59, 1))
                        settings1 = *(BYTE*)0x008e5f59;
                    if (!IsBadReadPtr((void*)0x0097faa2, 1))
                        settings2 = *(BYTE*)0x0097faa2;
                    ProxyLog("    SETTINGS: DAT_008e5f59=0x%02X DAT_0097faa2=0x%02X",
                             settings1, settings2);
                    /* Dump map name from MPG->+0x70->+0x3c->+0x14 */
                    if (mpg && !IsBadReadPtr((void*)(mpg + 0x70), 4)) {
                        DWORD p70 = *(DWORD*)(mpg + 0x70);
                        if (p70 && !IsBadReadPtr((void*)(p70 + 0x3c), 4)) {
                            DWORD p3c = *(DWORD*)(p70 + 0x3c);
                            if (p3c && !IsBadReadPtr((void*)(p3c + 0x14), 4)) {
                                char* mapName = *(char**)(p3c + 0x14);
                                if (mapName && !IsBadReadPtr(mapName, 1)) {
                                    ProxyLog("    MAP NAME: '%s'", mapName);
                                } else {
                                    ProxyLog("    MAP NAME: (null or bad ptr 0x%08X)", (unsigned)(DWORD_PTR)mapName);
                                }
                            }
                        }
                    }
                }
            }
            /* Dump first peer entry details */
            if (playerCount > 0 && playerArray) {
                DWORD peerPtr = 0;
                if (!IsBadReadPtr((void*)playerArray, 4))
                    peerPtr = *(DWORD*)playerArray;
                if (peerPtr && !IsBadReadPtr((void*)peerPtr, 0xC0)) {
                    DWORD peerID = *(DWORD*)(peerPtr + 0x18);
                    DWORD peerAddr = *(DWORD*)(peerPtr + 0x1C);
                    BYTE peerBC = *(BYTE*)(peerPtr + 0xBC);
                    DWORD peerQ0 = *(DWORD*)(peerPtr + 0x20);
                    DWORD peerQ4 = *(DWORD*)(peerPtr + 0x24);
                    ProxyLog("    PEER[0]: ptr=0x%08X id=%u addr=0x%08X bc=%d q0=0x%08X q4=0x%08X",
                             peerPtr, peerID, peerAddr, peerBC, peerQ0, peerQ4);
                }
            }
            lastPlayerCount = playerCount;
        }
        if (pendingQ != lastPendQ || incomingQ != lastInQ) {
            ProxyLog("  GAMELOOP: Network queues changed (tick %d): pendQ=0x%08X->0x%08X inQ=0x%08X->0x%08X",
                     tickCount, lastPendQ, pendingQ, lastInQ, incomingQ);
            lastPendQ = pendingQ;
            lastInQ = incomingQ;
        }
    }

    /* ---------------------------------------------------------------
     * Deferred InitNetwork call after peer connects.
     *
     * The engine sends Settings + GameInit immediately after the
     * checksum exchange (~1-2 ticks from connect).  The client sends
     * NewPlayerInGame (0x2A), which the engine handles at 0x0069f2a0
     * by calling FUN_006a1e70.  FUN_006a1e70 does C-side work but
     * its Python InitNetwork call via FUN_006f8ab0 fails in TIMERPROC
     * context (PyRun_SimpleString nesting issue).
     *
     * OLD: waited for peer+0xBC (bc flag) to flip 0->1.  This took
     * 200+ ticks because bc is set late in the checksum pipeline.
     * NEW: detect when a peer ID first appears in the peer array.
     * This fires at connect time (tick ~174), matching stock timing.
     * --------------------------------------------------------------- */
    {
        static DWORD peerSeenID[8] = {0};
        static BYTE peerNeedsInitNet[8] = {0}; /* 1 = waiting for FUN_006a1e70 trigger */
        static BYTE peerInitNetCalledByID[16] = {0}; /* per-ID dedup (prevents array reshuffle dupes) */
        static LONG lastNewPlayerCount = 0; /* track FUN_006a1e70 (hook #15) call count */
        int pCount = 0;
        DWORD pArray = 0;
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            pCount = *(int*)(wsnPtr + 0x30);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            pArray = *(DWORD*)(wsnPtr + 0x2C);

        if (pCount > 0 && pArray) {
            int pi;
            /* Check if FUN_006a1e70 (NewPlayerInGame) fired since last tick.
             * Hook #15 in function tracer tracks this. When the engine processes
             * client's 0x2A, it calls FUN_006a1e70 which does C++ work but its
             * Python InitNetwork call fails. We fire our Python InitNetwork
             * immediately after detecting this, so MISSION_INIT_MESSAGE arrives
             * in the same frame as the engine's NewPlayerHandler. */
            LONG curNewPlayerCount = 0;
            BOOL newPlayerFired = FALSE;
            if (g_ftHookCount > 15)
                curNewPlayerCount = g_ftHooks[15].callCount;
            if (curNewPlayerCount > lastNewPlayerCount) {
                newPlayerFired = TRUE;
                lastNewPlayerCount = curNewPlayerCount;
            }

            for (pi = 0; pi < pCount && pi < 8; pi++) {
                DWORD pp = 0;
                if (!IsBadReadPtr((void*)(pArray + pi*4), 4))
                    pp = *(DWORD*)(pArray + pi*4);
                if (pp) {
                    DWORD peerID = 0;
                    if (!IsBadReadPtr((void*)(pp + 0x18), 4))
                        peerID = *(DWORD*)(pp + 0x18);
                    /* Detect new peer: record in per-slot tracking */
                    if (peerID > 0 && peerSeenID[pi] != peerID) {
                        peerSeenID[pi] = peerID;
                        g_peerInitNetDone[pi] = 0;
                        peerNeedsInitNet[pi] = 0;
                        /* Skip host (ID=1) — only mark clients as needing InitNetwork.
                         * Per-ID dedup prevents duplicate calls when peer array reshuffles. */
                        if (peerID > 1 && peerID < 16 && !peerInitNetCalledByID[peerID]) {
                            peerNeedsInitNet[pi] = 1;
                            ProxyLog("  GAMELOOP[%d]: Peer[%d] id=%u appeared, InitNetwork pending (waiting for 0x2A)",
                                     tickCount, pi, peerID);
                        } else if (peerID == 1) {
                            ProxyLog("  GAMELOOP[%d]: Peer[%d] id=%u is host, skipping InitNetwork",
                                     tickCount, pi, peerID);
                        }
                    }
                    /* Execute InitNetwork when FUN_006a1e70 fires (engine processed 0x2A).
                     * This ensures MISSION_INIT_MESSAGE arrives right after the engine's
                     * NewPlayerInGame handling, before client interacts with ship selection. */
                    if (peerNeedsInitNet[pi] && newPlayerFired) {
                        char pyCmd[512];
                        peerNeedsInitNet[pi] = 0;
                        g_peerInitNetDone[pi] = 1;
                        if (peerID < 16) peerInitNetCalledByID[peerID] = 1;
                        wsprintfA(pyCmd,
                            "import sys\n"
                            "if sys.modules.has_key('Multiplayer.Episode.Mission1.Mission1'):\n"
                            "    _m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']\n"
                            "    _m1.InitNetwork(%u)\n",
                            peerID);
                        ProxyLog("  GAMELOOP[%d]: Calling InitNetwork(%u) for peer[%d] (triggered by 0x2A handler)",
                                 tickCount, peerID, pi);
                        RunPyCode(pyCmd);
                    }
                }
            }
        }
        /* Reset tracking for disconnected peers */
        {
            int pi;
            for (pi = pCount; pi < 8; pi++) {
                /* Clear per-ID dedup so peer can re-InitNetwork on reconnect */
                if (peerSeenID[pi] > 0 && peerSeenID[pi] < 16)
                    peerInitNetCalledByID[peerSeenID[pi]] = 0;
                peerSeenID[pi] = 0;
                peerNeedsInitNet[pi] = 0;
                g_peerInitNetDone[pi] = 0;
            }
        }
    }

    /* ---------------------------------------------------------------
     * Deferred ship InitObject after player joins.
     *
     * The engine's TG_CallPythonFunction calls SpeciesToShip.InitObject
     * during ship ReadStream deserialization, but the call fails
     * silently on the headless server.  Without InitObject, ships have
     * no NIF model, no subsystems, and no collision geometry (damage
     * doesn't work).
     *
     * Fix: after InitNetwork fires for a peer, poll every ~1s for
     * their ship via GetShipFromPlayerID.  When found, call InitObject
     * ourselves through RunPyCode (which works in any context).
     * --------------------------------------------------------------- */
    {
        static int shipPollStart[8] = {0};  /* tick to begin polling */
        int pCount = 0;
        DWORD pArray = 0;
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            pCount = *(int*)(wsnPtr + 0x30);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            pArray = *(DWORD*)(wsnPtr + 0x2C);

        if (pCount > 0 && pArray) {
            int pi;
            for (pi = 0; pi < pCount && pi < 8; pi++) {
                /* Detect when InitNetwork has fired for this peer.
                 * Start polling 90 ticks (~3s) later to give the client
                 * time to reach ship selection. */
                DWORD pp = 0;
                if (!IsBadReadPtr((void*)(pArray + pi*4), 4))
                    pp = *(DWORD*)(pArray + pi*4);
                if (g_peerInitNetDone[pi] && shipPollStart[pi] == 0) {
                    shipPollStart[pi] = tickCount + 90;
                    ProxyLog("  GAMELOOP[%d]: Ship init poll scheduled for peer[%d] starting tick %d",
                             tickCount, pi, shipPollStart[pi]);
                }
                /* Poll for ship changes: fast (every 30 ticks) for first 600 ticks,
                 * then slow (every 90 ticks) indefinitely. DeferredInitObject is
                 * idempotent — returns 0 immediately if ship type unchanged.
                 * Stagger per-peer with +pi*10 to avoid all peers polling same tick. */
                if (shipPollStart[pi] > 0 && tickCount >= shipPollStart[pi]) {
                    int rate = (tickCount < shipPollStart[pi] + 600) ? 30 : 90;
                    if ((tickCount + pi * 10) % rate == 0) {
                        DWORD peerID = 0;
                        char pyCmd[512];
                        if (pp && !IsBadReadPtr((void*)(pp + 0x18), 4))
                            peerID = *(DWORD*)(pp + 0x18);
                        wsprintfA(pyCmd,
                            "import sys\n"
                            "if sys.modules.has_key('Custom.DedicatedServer'):\n"
                            "    sys.modules['Custom.DedicatedServer'].DeferredInitObject(%u)\n",
                            peerID);
                        RunPyCode(pyCmd);
                    }
                }
            }
        }
        /* Reset for disconnected peers */
        {
            int pi;
            for (pi = pCount; pi < 8; pi++) {
                shipPollStart[pi] = 0;
            }
        }
    }

    /* ---------------------------------------------------------------
     * Ship field diagnostics + DmgTarget fixup.
     *
     * After DeferredInitObject sets up a ship, ship+0x140 (DmgTarget)
     * stays NULL because SetupModel takes Path 2 (registry miss) in
     * headless mode.  DoDamage gates on +0x140 != NULL, so ALL damage
     * is silently dropped without this fixup.
     *
     * Fix: copy +0x18 (NiNode) into +0x140.  This block also tracks
     * ship pointer changes to re-fire on respawn (engine may reuse or
     * allocate a new ship object after death).
     *
     * Gate fields checked:
     *   +0x18  NiNode (DoDamage gate)
     *   +0x140 Damage target ref (DoDamage gate) — FIXED UP HERE
     *   +0x128 Handler array ptr (ProcessDamage subsystems)
     *   +0x130 Handler count (should be ~33)
     *   +0x1B8 Resistance multiplier (0.0 = invulnerable)
     *   +0x1BC Falloff multiplier (0.0 = formula breaks)
     *   +0xD8  Mass (collision formula, div-by-zero risk)
     * --------------------------------------------------------------- */
    {
        static BYTE shipDiagDone[8] = {0};
        static DWORD lastShipPtr[8] = {0};  /* track pointer for respawn detection */
        int pCount = 0;
        DWORD pArray = 0;
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            pCount = *(int*)(wsnPtr + 0x30);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
            pArray = *(DWORD*)(wsnPtr + 0x2C);

        if (pCount > 0 && pArray) {
            int pi;
            for (pi = 0; pi < pCount && pi < 8; pi++) {
                DWORD pp = 0;
                DWORD peerID = 0;
                DWORD shipPtr;
                if (!IsBadReadPtr((void*)(pArray + pi*4), 4))
                    pp = *(DWORD*)(pArray + pi*4);
                if (pp && !IsBadReadPtr((void*)(pp + 0x18), 4))
                    peerID = *(DWORD*)(pp + 0x18);
                if (peerID <= 1) continue;  /* skip host */

                shipPtr = ((pfn_GetShipFromPlayerID)0x006a1aa0)((int)peerID);

                /* Respawn detection: if ship pointer changed, reset diag
                 * so the fixup runs again for the new ship object. */
                if (shipPtr && shipPtr != lastShipPtr[pi]) {
                    if (lastShipPtr[pi] != 0) {
                        ProxyLog("  SHIP_CHANGE peer[%d] id=%u: 0x%08X -> 0x%08X (respawn?)",
                                 pi, peerID, lastShipPtr[pi], shipPtr);
                        shipDiagDone[pi] = 0;
                    }
                    lastShipPtr[pi] = shipPtr;
                }

                if (g_peerInitNetDone[pi] && !shipDiagDone[pi]) {
                    if (shipPtr && !IsBadReadPtr((void*)shipPtr, 0x300)) {
                        DWORD niNode = 0, dmgTarget = 0, hArray = 0, hCount = 0;
                        float resist = 0.0f, falloff = 0.0f, mass = 0.0f;

                        if (!IsBadReadPtr((void*)(shipPtr + 0x18), 4))
                            niNode = *(DWORD*)(shipPtr + 0x18);
                        if (!IsBadReadPtr((void*)(shipPtr + 0x140), 4))
                            dmgTarget = *(DWORD*)(shipPtr + 0x140);
                        if (!IsBadReadPtr((void*)(shipPtr + 0x128), 4))
                            hArray = *(DWORD*)(shipPtr + 0x128);
                        if (!IsBadReadPtr((void*)(shipPtr + 0x130), 4))
                            hCount = *(DWORD*)(shipPtr + 0x130);
                        if (!IsBadReadPtr((void*)(shipPtr + 0x1B8), 4))
                            resist = *(float*)(shipPtr + 0x1B8);
                        if (!IsBadReadPtr((void*)(shipPtr + 0x1BC), 4))
                            falloff = *(float*)(shipPtr + 0x1BC);
                        if (!IsBadReadPtr((void*)(shipPtr + 0xD8), 4))
                            mass = *(float*)(shipPtr + 0xD8);

                        /* DmgTarget fixup: copy NiNode into +0x140 so
                         * DoDamage doesn't gate out all damage. */
                        if (niNode && !dmgTarget) {
                            *(DWORD*)(shipPtr + 0x140) = niNode;
                            dmgTarget = niNode;
                            ProxyLog("  SHIP_FIXUP peer[%d] id=%u: +0x140 was NULL, set to +0x18 (0x%08X)",
                                     pi, peerID, niNode);
                        }

                        ProxyLog("  SHIP_DIAG peer[%d] id=%u ship=0x%08X:", pi, peerID, shipPtr);
                        ProxyLog("    +0x018 NiNode       = 0x%08X %s", niNode, niNode ? "PASS" : "** FAIL **");
                        ProxyLog("    +0x140 DmgTarget    = 0x%08X %s", dmgTarget, dmgTarget ? "PASS" : "** FAIL **");
                        ProxyLog("    +0x128 HandlerArray = 0x%08X %s", hArray, hArray ? "PASS" : "** FAIL **");
                        ProxyLog("    +0x130 HandlerCount = %u %s", hCount, (hCount > 0) ? "PASS" : "** FAIL **");
                        ProxyLog("    +0x1B8 Resistance   = %.4f %s", resist, (resist > 0.0f) ? "PASS" : "WARN(0)");
                        ProxyLog("    +0x1BC Falloff      = %.4f %s", falloff, (falloff > 0.0f) ? "PASS" : "WARN(0)");
                        ProxyLog("    +0x0D8 Mass         = %.4f %s", mass, (mass > 0.0f) ? "PASS" : "WARN(0)");

                        /* Only mark done if +0x140 is now set.
                         * If NiNode is also NULL, ship isn't ready yet. */
                        if (dmgTarget)
                            shipDiagDone[pi] = 1;
                    }
                }
            }
        }
        /* Reset for disconnected peers */
        {
            int pi;
            for (pi = pCount; pi < 8; pi++) {
                shipDiagDone[pi] = 0;
                lastShipPtr[pi] = 0;
            }
        }
    }

    /* Run deferred Python diagnostics requested by HeartbeatThread.
     * Must execute on main thread to avoid GIL/allocator corruption. */
    if (g_runPyDiag) {
        g_runPyDiag = 0;
        ProxyLog("  PY_DIAG: Running deferred diagnostics on main thread");
        {
            DWORD* pFrozenPtr = (DWORD*)0x00975860;
            if (!IsBadReadPtr(pFrozenPtr, 4)) {
                BYTE* entry = (BYTE*)(*(DWORD*)pFrozenPtr);
                int idx;
                ProxyLog("  PY_DIAG: FrozenModules table at %p", entry);
                for (idx = 0; idx < 5 && entry; idx++) {
                    char* name = *(char**)entry;
                    if (!name || IsBadReadPtr(name, 1)) break;
                    ProxyLog("  FROZEN[%d]: '%s' code=%p size=%d",
                             idx, name,
                             *(void**)(entry + 4),
                             *(int*)(entry + 8));
                    entry += 12;
                }
            }
        }
        {
            void *modules = PY_GetModuleDict();
            ProxyLog("  PY_DIAG: sys.modules = %p", modules);
        }
        RunPyCode("pass\n");
        ProxyLog("  PY_DIAG: RunPyCode('pass') OK");
    }

    /* Periodic ACK diagnostic dump every 90 ticks (~3s).
     * Walks ACK-outbox and retransmit queues for each connected peer
     * to track fragment ACK state for the fragmented reliable msg bug. */
    if (tickCount > 0 && (tickCount % 90 == 0)) {
        int pCount = 0;
        DWORD pArray = 0;
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
            pCount = *(int*)(wsnPtr + 0x30);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
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

    /* Periodic status every ~10s */
    if (time - lastLogTime >= 10000) {
        DWORD clockPtr = 0;
        float gameTime = 0.0f;
        int connState = -1;
        DWORD emCount = 0;
        if (!IsBadReadPtr((void*)0x009a09d0, 4))
            clockPtr = *(DWORD*)0x009a09d0;
        if (clockPtr && !IsBadReadPtr((void*)(clockPtr + 0x90), 4))
            gameTime = *(float*)(clockPtr + 0x90);
        if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x14), 4))
            connState = *(int*)(wsnPtr + 0x14);
        if (!IsBadReadPtr((void*)0x0097F840, 4))
            emCount = *(DWORD*)0x0097F840;
        {
            int pCount = 0;
            DWORD pArray = 0;
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x30), 4))
                pCount = *(int*)(wsnPtr + 0x30);
            if (wsnPtr && !IsBadReadPtr((void*)(wsnPtr + 0x2C), 4))
                pArray = *(DWORD*)(wsnPtr + 0x2C);
            ProxyLog("  GAMELOOP: tick=%d gameTime=%.3f connState=%d emQ=%u peers=%d sendtos=%ld",
                     tickCount, gameTime, connState, emCount, pCount, g_sendtoCount);
            /* Dump peer details if connected */
            if (pCount > 0 && pArray && !IsBadReadPtr((void*)pArray, 4)) {
                int pi2;
                for (pi2 = 0; pi2 < pCount && pi2 < 4; pi2++) {
                    DWORD pp = 0;
                    if (!IsBadReadPtr((void*)(pArray + pi2*4), 4))
                        pp = *(DWORD*)(pArray + pi2*4);
                    if (pp && !IsBadReadPtr((void*)pp, 0xC0)) {
                        ProxyLog("    PEER[%d]: id=%u bc=%d addr=0x%08X sendQ: unrel=%d rel=%d pri=%d",
                                 pi2, *(DWORD*)(pp + 0x18), *(BYTE*)(pp + 0xBC),
                                 *(DWORD*)(pp + 0x1C),
                                 *(int*)(pp + 0x7C), *(int*)(pp + 0x98), *(int*)(pp + 0xB4));
                    }
                }
            }
        }
        lastLogTime = time;
    }

    /* Periodic function tracer dump every 300 ticks (~10s) */
    if (tickCount > 0 && (tickCount % 300 == 0)) {
        char label[32];
        wsprintfA(label, "tick_%d", tickCount);
        FTraceDump(label);
    }
}

/* ================================================================
 * DedicatedServerTimerProc - TIMERPROC that bootstraps the dedicated server
 *
 * Runs on the MAIN THREAD via SetTimer. Phases:
 *   0: Set multiplayer/host flags (direct memory + SWIG via RunPyCode)
 *   1: Initialize network (create WSN) via direct C++ call to FUN_00445d90
 *   2: Create MultiplayerGame (creates TopWindow) via FUN_00504f10
 *   3: Trigger DedicatedServer.TopWindowInitialized via RunPyCode
 *   4: Start game loop timer (GameLoopTimerProc at 33ms)
 * ================================================================ */
static int g_iDedState = 0;

static VOID CALLBACK DedicatedServerTimerProc(HWND hwnd, UINT msg,
                                               UINT_PTR id, DWORD time) {
    static int polls = 0;
    int nestLvl;
    polls++;
    (void)msg; (void)time;

    /* Log Python nesting level for diagnostics */
    nestLvl = *(int*)0x0099EE38;

    switch (g_iDedState) {
    case 0: {
        /* Phase 0: Set multiplayer/host flags
         * Direct memory writes guarantee flags are set even if Python fails.
         * Then try SWIG methods via RunPyCode for any side effects. */
        DWORD oldProt;
        int rc;

        ProxyLog("  DS_TIMER[0]: Setting flags (poll %d, nest=%d)", polls, nestLvl);

        /* Direct memory writes for critical flags
         * 0x0097FA88 = IsClient (0=host, 1=client) - NOT "IsHost"!
         * 0x0097FA89 = IsHost   (1=host, 0=client) - the REAL IsHost flag
         * 0x0097FA8A = IsMultiplayer (1=MP active)
         * Stock host: IsClient=0, IsHost=1, IsMp=1
         * Stock client: IsClient=1, IsHost=0, IsMp=0
         */
        VirtualProtect((void*)0x0097FA88, 4, PAGE_READWRITE, &oldProt);
        *(BYTE*)0x0097FA88 = 0;  /* IsClient = 0 (we are the host, NOT a client) */
        *(BYTE*)0x0097FA89 = 1;  /* IsHost = 1 (we ARE the host) */
        *(BYTE*)0x0097FA8A = 1;  /* IsMultiplayer = 1 */
        VirtualProtect((void*)0x0097FA88, 4, oldProt, &oldProt);

        ProxyLog("  DS_TIMER[0]: Direct flags: IsClient=%d IsHost=%d IsMultiplayer=%d",
                 (int)*(BYTE*)0x0097FA88, (int)*(BYTE*)0x0097FA89,
                 (int)*(BYTE*)0x0097FA8A);

        /* Also call SWIG methods for any side effects (non-critical) */
        rc = RunPyCode(
            "import App\n"
            "App.g_kUtopiaModule.SetMultiplayer(1)\n"
            "App.g_kUtopiaModule.SetIsHost(1)\n"
            "App.g_kUtopiaModule.SetIsClient(0)\n");
        ProxyLog("  DS_TIMER[0]: SWIG SetFlags rc=%d", rc);

        /* Set config values (game name, player name, password) */
        rc = RunPyCode(
            "try:\n"
            "    import App\n"
            "    App.g_kConfigMapping.SetStringValue(\n"
            "        'Multiplayer Options', 'Game_Name', 'Dedicated Server')\n"
            "    App.g_kConfigMapping.SetStringValue(\n"
            "        'Multiplayer Options', 'Player_Name', 'Dedicated Server')\n"
            "    App.g_kConfigMapping.SetStringValue(\n"
            "        'Multiplayer Options', 'Password', '')\n"
            "except:\n"
            "    pass\n");
        ProxyLog("  DS_TIMER[0]: Config rc=%d", rc);

        g_iDedState = 1;
        break;
    }
    case 1: {
        /* Phase 1: Initialize network - create WSN (TGWinsockNetwork)
         *
         * FUN_00445d90 is __thiscall:
         *   this = 0x0097FA00 (UtopiaModule)
         *   param_1 = 0 (address, 0 = host/listen)
         *   param_2 = ptr to TGString-like struct for password (length at +8)
         *   param_3 = 0x5655 (port 22101)
         *
         * Use __fastcall trick: ECX=this, EDX=dummy */
        typedef int (__fastcall *pfn_InitNet)(void* ecx, void* edx,
                                               int addr, void* pw, int port);
        pfn_InitNet pInitNet = (pfn_InitNet)0x00445d90;
        int rc;
        DWORD wsnPtr;
        char fakePw[16];

        ProxyLog("  DS_TIMER[1]: Initializing network (poll %d, nest=%d)", polls, nestLvl);
        memset(fakePw, 0, sizeof(fakePw));

        rc = pInitNet((void*)0x0097FA00, NULL, 0, fakePw, 0x5655);

        wsnPtr = 0;
        if (!IsBadReadPtr((void*)0x0097FA78, 4))
            wsnPtr = *(DWORD*)0x0097FA78;

        ProxyLog("  DS_TIMER[1]: InitNet rc=%d WSN=0x%08X", rc, wsnPtr);

        if (wsnPtr != 0) {
            /* Set SkipChecksum flag - tells the server to skip per-file
             * version mismatch checks during checksum verification.
             * Without this, clients with different .pyc versions get
             * "Disconnected: File version mismatch" errors. */
            {
                DWORD oldProt;
                VirtualProtect((void*)0x0097f94c, 1, PAGE_READWRITE, &oldProt);
                *(BYTE*)0x0097f94c = 1;
                VirtualProtect((void*)0x0097f94c, 1, oldProt, &oldProt);
                ProxyLog("  DS_TIMER[1]: Set SkipChecksum flag at 0x0097f94c = 1");
            }
            g_iDedState = 2;
        } else if (polls > 30) {
            ProxyLog("  DS_TIMER[1]: WSN still NULL after 30 polls, giving up");
            g_iDedState = 99;
        }
        break;
    }
    case 2: {
        /* Phase 2: Create MultiplayerGame
         * FUN_00504f10 allocates a MultiplayerGame object and calls
         * FUN_0069e590 (constructor) which calls FUN_00405c10 (TopWindow
         * constructor), setting DAT_0097e238 = game object pointer.
         * It also runs AI_Setup.GameInit and loads Multiplayer.tgl.
         *
         * NOTE: pCreate() enters an internal message loop, so our timer
         * fires recursively inside it. Guard against re-entrancy. */
        typedef void (__cdecl *pfn_CreateMPGame)(void);
        pfn_CreateMPGame pCreate = (pfn_CreateMPGame)0x00504f10;
        DWORD twPtr;
        static BOOL inCreate = FALSE;

        if (inCreate) {
            /* Re-entrant timer tick inside pCreate()'s message loop.
               Check if TopWindow was created while pCreate() is running. */
            twPtr = 0;
            if (!IsBadReadPtr((void*)0x0097e238, 4))
                twPtr = *(DWORD*)0x0097e238;
            if (twPtr != 0) {
                static int logOnce = 0;
                if (!logOnce) {
                    ProxyLog("  DS_TIMER[2]: TopWindow created inside pCreate(): 0x%08X", twPtr);
                    logOnce = 1;
                }
                /* Set ReadyForNewPlayers=1 EARLY so clients connecting during
                 * Phase 3 Python execution aren't deferred. Without this, the
                 * engine's NewPlayerHandler finds +0x1F8==0 and defers via a
                 * timer that doesn't work in our TIMERPROC environment, causing
                 * the first connection to always time out. */
                if (!IsBadWritePtr((void*)(twPtr + 0x1F8), 1)) {
                    *(BYTE*)(twPtr + 0x1F8) = 1;
                    ProxyLog("  DS_TIMER[2]: Set +0x1F8=1 EARLY (re-entrant path)");
                }
                g_iDedState = 3;
            }
            break;
        }
        ProxyLog("  DS_TIMER[2]: Creating MultiplayerGame (poll %d, nest=%d)", polls, nestLvl);
        inCreate = TRUE;
        pCreate();
        inCreate = FALSE;

        twPtr = 0;
        if (!IsBadReadPtr((void*)0x0097e238, 4))
            twPtr = *(DWORD*)0x0097e238;

        ProxyLog("  DS_TIMER[2]: TopWindow=0x%08X", twPtr);


        if (twPtr != 0) {
            /* Set ReadyForNewPlayers=1 EARLY (normal path) */
            if (!IsBadWritePtr((void*)(twPtr + 0x1F8), 1)) {
                *(BYTE*)(twPtr + 0x1F8) = 1;
                ProxyLog("  DS_TIMER[2]: Set +0x1F8=1 EARLY (normal path)");
            }
            g_iDedState = 3;
        } else {
            ProxyLog("  DS_TIMER[2]: TopWindow creation failed");
            g_iDedState = 99;
        }
        break;
    }
    case 3: {
        /* Phase 3: Trigger DedicatedServer automation via Python.
         * App.TopWindow_GetTopWindow() returns the SWIG-wrapped TopWindow. */
        int rc;

        ProxyLog("  DS_TIMER[3]: Triggering automation (poll %d, nest=%d)", polls, nestLvl);

        /* First check if Custom.DedicatedServer is loaded */
        {
            int chk = RunPyCode(
                "import sys\n"
                "_has_ds = sys.modules.has_key('Custom.DedicatedServer')\n"
                "_mods = filter(lambda k: k[:6]=='Custom', sys.modules.keys())\n"
                "print 'DS_TIMER3: has_DS=' + str(_has_ds) + ' custom_mods=' + str(_mods)\n");
            ProxyLog("  DS_TIMER[3]: pre-check rc=%d", chk);
        }

        rc = RunPyCode(
            "import sys\n"
            "try:\n"
            "    import App\n"
            "    tw = App.TopWindow_GetTopWindow()\n"
            "    print 'DS_TIMER3: tw=' + str(tw) + ' type=' + str(type(tw))\n"
            "    if tw is not None:\n"
            "        if sys.modules.has_key('Custom.DedicatedServer'):\n"
            "            ds = sys.modules['Custom.DedicatedServer']\n"
            "            print 'DS_TIMER3: calling TopWindowInitialized'\n"
            "            ds.TopWindowInitialized(tw)\n"
            "            n = ds.PatchLoadedMissionModules()\n"
            "            f = open('dedicated_init.log', 'a')\n"
            "            f.write('DS_TIMER: TopWindowInitialized called OK\\n')\n"
            "            f.write('DS_TIMER: PatchLoadedMissionModules = ' + str(n) + '\\n')\n"
            "            f.close()\n"
            "        else:\n"
            "            print 'DS_TIMER3: Custom.DedicatedServer NOT in sys.modules!'\n"
            "            f = open('dedicated_init.log', 'a')\n"
            "            f.write('DS_TIMER ERROR: Custom.DedicatedServer not loaded\\n')\n"
            "            f.close()\n"
            "    else:\n"
            "        print 'DS_TIMER3: TopWindow is None'\n"
            "        f = open('dedicated_init.log', 'a')\n"
            "        f.write('DS_TIMER: TopWindow_GetTopWindow returned None\\n')\n"
            "        f.close()\n"
            "except:\n"
            "    ei = sys.exc_info()\n"
            "    print 'DS_TIMER3 ERROR: ' + str(ei[0]) + ': ' + str(ei[1])\n"
            "    try:\n"
            "        f = open('dedicated_init.log', 'a')\n"
            "        f.write('DS_TIMER Phase3 ERROR: ' + str(ei[0]) + ': ' + str(ei[1]) + '\\n')\n"
            "        f.close()\n"
            "    except:\n"
            "        print 'DS_TIMER3: ALSO FAILED to write log!'\n");

        ProxyLog("  DS_TIMER[3]: TopWindowInit rc=%d", rc);

        /* Enable GameSpy LAN query handler.
         * GameSpy_StartHeartbeat (0x0069c240) allocates the qr_t struct,
         * stores it at GameSpy+0xDC, and enables LAN browser responses.
         * The qr_t reuses the UDP socket from WSN+0x194.
         * param_1=1 means LAN mode (process queries + send heartbeats). */
        {
            DWORD gsPtr = 0;
            if (!IsBadReadPtr((void*)0x0097FA7C, 4))
                gsPtr = *(DWORD*)0x0097FA7C;
            if (gsPtr) {
                unsigned int gsRc;
                ProxyLog("  DS_TIMER[3]: GameSpy object at 0x%08X, calling StartHeartbeat", gsPtr);
                gsRc = GAMESPY_START_HB((void*)gsPtr, NULL, 1);
                ProxyLog("  DS_TIMER[3]: GameSpy_StartHeartbeat rc=0x%08X", gsRc);

                /* Log GameSpy state after StartHeartbeat */
                if (!IsBadReadPtr((void*)(gsPtr + 0xDC), 4)) {
                    DWORD qrPtr = *(DWORD*)(gsPtr + 0xDC);
                    BYTE initFlag = *(BYTE*)(gsPtr + 0xED);
                    BYTE hbActive = *(BYTE*)(gsPtr + 0xEE);
                    BYTE lanMode = *(BYTE*)(gsPtr + 0xEF);
                    ProxyLog("  DS_TIMER[3]: GameSpy qr_t=0x%08X init=%d hbActive=%d lan=%d",
                             qrPtr, initFlag, hbActive, lanMode);

                    /* Keep qr_t+0xE4=0 (disable GameSpy's internal recvfrom).
                     * Our peek-based router in the game loop handles query/game
                     * packet demuxing on the shared UDP socket instead. */
                    if (qrPtr && !IsBadReadPtr((void*)(qrPtr + 0xE4), 4)) {
                        *(DWORD*)(qrPtr + 0xE4) = 0;
                        ProxyLog("  DS_TIMER[3]: qr_t+0xE4=0 (peek router handles queries)");
                    }
                }
            } else {
                ProxyLog("  DS_TIMER[3]: GameSpy object is NULL, LAN discovery disabled");
            }
        }

        /* Verify socket consistency: qr_t[0] should equal WSN+0x194 */
        {
            DWORD wsnPtr2 = 0, wsnSock = 0xFFFFFFFF, qrSock = 0xFFFFFFFF;
            DWORD gsPtr2 = 0, qrPtr2 = 0;
            if (!IsBadReadPtr((void*)0x0097FA78, 4))
                wsnPtr2 = *(DWORD*)0x0097FA78;
            if (wsnPtr2 && !IsBadReadPtr((void*)(wsnPtr2 + 0x194), 4))
                wsnSock = *(DWORD*)(wsnPtr2 + 0x194);
            if (!IsBadReadPtr((void*)0x0097FA7C, 4))
                gsPtr2 = *(DWORD*)0x0097FA7C;
            if (gsPtr2 && !IsBadReadPtr((void*)(gsPtr2 + 0xDC), 4))
                qrPtr2 = *(DWORD*)(gsPtr2 + 0xDC);
            if (qrPtr2 && !IsBadReadPtr((void*)qrPtr2, 4))
                qrSock = *(DWORD*)qrPtr2;
            ProxyLog("  DS_TIMER[3]: Socket check: WSN+0x194=%d qr_t[0]=%d %s",
                     (int)wsnSock, (int)qrSock,
                     (wsnSock == qrSock) ? "MATCH" : "*** MISMATCH ***");
        }

        /* Set IsClient=0 (DAT_0097fa89) for dedicated server mode.
         * The MultiplayerGame constructor ALWAYS sets IsClient=1 at the end.
         * In vanilla, the config reader at ~0x00438880 reads "Dedicated Server"
         * from config and restores IsClient=0 post-construction. We bypass that
         * code path, so we must set it directly.
         * Reinforce correct flag state after MultiplayerGame creation:
         *   0x0097FA88 = IsClient = 0 (we are the host)
         *   0x0097FA89 = IsHost = 1 (we ARE the host)
         * This is needed because CreateMultiplayerGame may alter these flags. */
        {
            DWORD oldProt;
            VirtualProtect((void*)0x0097FA88, 2, PAGE_READWRITE, &oldProt);
            *(BYTE*)0x0097FA88 = 0;  /* IsClient = 0 */
            *(BYTE*)0x0097FA89 = 1;  /* IsHost = 1 */
            VirtualProtect((void*)0x0097FA88, 2, oldProt, &oldProt);
            ProxyLog("  DS_TIMER[3]: Reinforced IsClient=0 IsHost=1 for dedicated server mode");
        }

        /* Set MultiplayerGame+0x1F8 = 1 to enable immediate new player handling.
         * When 0 (default), NewPlayerHandler defers via timer and checksum exchange stalls.
         * When 1, it processes immediately (assigns slot, sends checksum request). */
        {
            DWORD mpGame = 0;
            if (!IsBadReadPtr((void*)0x0097e238, 4))
                mpGame = *(DWORD*)0x0097e238;
            if (mpGame && !IsBadWritePtr((void*)(mpGame + 0x1F8), 1)) {
                *(BYTE*)(mpGame + 0x1F8) = 1;
                ProxyLog("  DS_TIMER[3]: Set MultiplayerGame+0x1F8=1 (enable immediate new player handling)");
            } else {
                ProxyLog("  DS_TIMER[3]: WARNING - Could not set MultiplayerGame+0x1F8 (mpGame=0x%08X)", mpGame);
            }
        }

        /* Diagnose ChecksumManager at 0x0097fa80 - FUN_006a3820 uses this as 'this'.
         * If NULL, no checksum requests will ever be sent to clients. */
        {
            DWORD csm = 0;
            if (!IsBadReadPtr((void*)0x0097fa80, 4))
                csm = *(DWORD*)0x0097fa80;
            ProxyLog("  DS_TIMER[3]: ChecksumManager(0x0097fa80)=0x%08X", csm);
            if (csm) {
                /* Also check 0x0097fa8a (IsMultiplayer/networking-active flag) */
                BYTE netActive = 0;
                if (!IsBadReadPtr((void*)0x0097fa8a, 1))
                    netActive = *(BYTE*)0x0097fa8a;
                ProxyLog("  DS_TIMER[3]: DAT_0097fa8a(netActive)=%d", netActive);
            } else {
                ProxyLog("  DS_TIMER[3]: WARNING - ChecksumManager is NULL! Checksum exchange will fail.");
            }
        }

        /* Ensure the map/mission name chain is valid.
         * ChecksumCompleteHandler (FUN_006a1b10) reads the map name from:
         *   MultiplayerGame+0x70 -> +0x3c -> +0x14 (char*)
         * Game_LoadEpisode + Episode_LoadMission set +0x70 to a real Episode
         * object, but +0x3c->+0x14 may hold a TGString ptr instead of char*.
         * We patch the inner chain to point to our known-good char* string. */
        {
            static const char g_missionName[] = "Multiplayer.Episode.Mission1.Mission1";
            DWORD mpGame = 0;
            if (!IsBadReadPtr((void*)0x0097e238, 4))
                mpGame = *(DWORD*)0x0097e238;
            if (mpGame) {
                DWORD p70 = 0;
                if (!IsBadReadPtr((void*)(mpGame + 0x70), 4))
                    p70 = *(DWORD*)(mpGame + 0x70);

                if (p70 == 0) {
                    /* Episode not loaded - build full fake chain.
                     * objA[0] must be a valid vtable (main tick dispatches through it).
                     * We create a dummy vtable where all entries point to a RET stub. */
                    BYTE *objA = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x80);
                    BYTE *objB = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x20);
                    DWORD *vtbl = (DWORD*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x80);
                    BYTE *retStub = (BYTE*)VirtualAlloc(NULL, 4, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                    if (objA && objB && vtbl && retStub) {
                        int i;
                        retStub[0] = 0xC3;
                        for (i = 0; i < 32; i++)
                            vtbl[i] = (DWORD)retStub;
                        *(DWORD**)(objA + 0x00) = vtbl;
                        *(BYTE**)(objA + 0x3c) = objB;
                        *(const char**)(objB + 0x14) = g_missionName;
                        {
                            DWORD oldProt;
                            VirtualProtect((void*)(mpGame + 0x70), 4, PAGE_READWRITE, &oldProt);
                            *(BYTE**)(mpGame + 0x70) = objA;
                            VirtualProtect((void*)(mpGame + 0x70), 4, oldProt, &oldProt);
                        }
                        ProxyLog("  DS_TIMER[3]: Installed full fake mission chain: '%s'", g_missionName);
                    } else {
                        ProxyLog("  DS_TIMER[3]: WARNING - Alloc failed for mission chain");
                    }
                } else {
                    /* Episode object exists (from Game_LoadEpisode).
                     * Patch the inner chain: ensure +0x3c->+0x14 has a valid char*.
                     * The real Mission object may store a TGString* at +0x14 instead. */
                    DWORD p3c = 0;
                    if (!IsBadReadPtr((void*)(p70 + 0x3c), 4))
                        p3c = *(DWORD*)(p70 + 0x3c);
                    if (p3c) {
                        /* Patch Mission+0x14 to point to our raw char* string */
                        DWORD oldProt;
                        VirtualProtect((void*)(p3c + 0x14), 4, PAGE_READWRITE, &oldProt);
                        *(const char**)(p3c + 0x14) = g_missionName;
                        VirtualProtect((void*)(p3c + 0x14), 4, oldProt, &oldProt);
                        ProxyLog("  DS_TIMER[3]: Patched Mission+0x14 -> '%s' (p3c=0x%08X)",
                                 g_missionName, p3c);
                    } else {
                        /* Episode+0x3c is NULL - allocate a Mission stub */
                        BYTE *objB = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x20);
                        if (objB) {
                            DWORD oldProt;
                            *(const char**)(objB + 0x14) = g_missionName;
                            VirtualProtect((void*)(p70 + 0x3c), 4, PAGE_READWRITE, &oldProt);
                            *(BYTE**)(p70 + 0x3c) = objB;
                            VirtualProtect((void*)(p70 + 0x3c), 4, oldProt, &oldProt);
                            ProxyLog("  DS_TIMER[3]: Installed Mission stub at Episode+0x3c -> '%s'",
                                     g_missionName);
                        }
                    }
                }
            }
        }

        ProxyLog("  DS_TIMER[3]: Breakpoints DISABLED (were causing crashes)");

        g_iDedState = 4;
        KillTimer(hwnd, id);

        /* Start the game loop timer - drives UtopiaApp_MainTick at ~30fps.
         * This processes network timers, events, and game subsystems.
         * Timer ID 0xBCBC chosen to avoid conflicts. */
        SetTimer(hwnd, 0xBCBC, 33, GameLoopTimerProc);
        ProxyLog("  DS_TIMER: Bootstrap done, game loop timer started (33ms)");

        /* Window will be minimized by GameLoopTimerProc at tick 10,
         * after the ET_START cascade and CreateSystemSet have completed. */
        break;
    }
    default:
        KillTimer(hwnd, id);
        ProxyLog("  DS_TIMER: Terminated in state %d", g_iDedState);
        break;
    }
}

/* This callback runs from the code cave on the MAIN thread during init.
   It creates the App module before TG_ImportModule("App") runs. */
static void __cdecl CreateAppModuleCallback(void) {
    void* appModule;

    ProxyLog("  CreateAppModuleCallback: ENTERED");

    if (PY_ErrOccurred()) {
        ProxyLog("  CreateAppModuleCallback: clearing pre-existing error");
        PY_ErrClear();
    }

    appModule = PY_InitModule4("App", (void*)0x008e6438, NULL, NULL, 1009);
    ProxyLog("  CreateAppModuleCallback: Py_InitModule4('App') = %p", appModule);

    if (PY_ErrOccurred()) {
        ProxyLog("  CreateAppModuleCallback: ERROR after Py_InitModule4");
        PY_ErrClear();
    }

    LogPyModules("PRE-INIT modules");

    ProxyLog("  CreateAppModuleCallback: DONE");
}

/* This callback runs AFTER TG_ImportModule("Autoexec") completes.
   We hook 0x0043b204 (the PyErr_Print after Autoexec import).
   At this point, Autoexec.py should have loaded Local.py and DedicatedServer.py. */
static void __cdecl PostAutoexecCallback(void) {
    void* localMod;
    int rc;

    ProxyLog("  PostAutoexecCallback: ENTERED");
    LogPyModules("POST-AUTOEXEC");

    /* Autoexec.py fails partway through in stub mode (Tactical.TacticalIcons,
       UITheme, LoadInterface need rendering). The "try: import Local" at line 38
       never executes. We manually import Local here to start DedicatedServer. */

    /* First clear any error left from Autoexec's failed imports */
    if (PY_ErrOccurred()) {
        ProxyLog("  PostAutoexecCallback: clearing Autoexec errors");
        PY_ErrClear();
    }

    /* Fix sys.path: in headless mode, Autoexec.py may not set up Scripts path.
       Use absolute paths derived from g_szBasePath for reliability. */
    {
        char pyFixPath[1024];
        char fwdPath[MAX_PATH];
        int pi, prc;
        lstrcpynA(fwdPath, g_szBasePath, MAX_PATH);
        for (pi = 0; fwdPath[pi]; pi++)
            if (fwdPath[pi] == '\\') fwdPath[pi] = '/';
        wsprintfA(pyFixPath,
            "import sys\n"
            "sys.path.insert(0, '%sScripts')\n"
            "sys.path.insert(1, '%s')\n"
            "sys.path.append('%sscripts/Icons')\n"
            "sys._ds_base_path = '%s'\n",
            fwdPath, fwdPath, fwdPath, fwdPath);
        prc = PY_RunSimpleString(pyFixPath);
        ProxyLog("  PostAutoexecCallback: path-fix rc=%d", prc);
    }

    /* Import Local.py directly via C API */
    localMod = PY_ImportModule("Local");
    ProxyLog("  PostAutoexecCallback: import Local = %p", localMod);

    if (PY_ErrOccurred()) {
        void *errType = NULL, *errValue = NULL, *errTB = NULL;
        PY_ErrFetch(&errType, &errValue, &errTB);
        if (errType) {
            const char *typeName = "(bad-ptr)";
            if (!IsBadReadPtr(errType, 16)) {
                const char *namePtr = *(const char**)((char*)errType + 12);
                if (namePtr && !IsBadReadPtr(namePtr, 4))
                    typeName = namePtr;
            }
            const char *valStr = "(no-value)";
            if (errValue && !IsBadReadPtr(errValue, 24)) {
                const char *candidate = (const char*)errValue + 20;
                if (!IsBadReadPtr(candidate, 4))
                    valStr = candidate;
            }
            ProxyLog("  PostAutoexecCallback: Local import error: %s: %s",
                     typeName, valStr);
        } else {
            ProxyLog("  PostAutoexecCallback: Local import failed (no error info)");
        }
    }

    LogPyModules("POST-LOCAL");

    /* Also try running the remaining Autoexec setup that was skipped */
    rc = PY_RunSimpleString(
        "try:\n"
        "    import UITheme\n"
        "except:\n"
        "    pass\n"
        "try:\n"
        "    import LoadInterface\n"
        "    LoadInterface.SetupColors()\n"
        "except:\n"
        "    pass\n"
        "try:\n"
        "    import KeyboardBinding\n"
        "except:\n"
        "    pass\n");
    ProxyLog("  PostAutoexecCallback: remaining imports rc=%d", rc);
    if (PY_ErrOccurred()) PY_ErrClear();

    /* Schedule a timer on the main thread to bootstrap the dedicated server.
       TopWindow.Initialize is never called in stub mode because TopWindow/Game
       objects only exist when a multiplayer game starts (FUN_00405c10 sets
       DAT_0097e238). We use a timer to:
       1. Set multiplayer/host flags
       2. Initialize the network (create WSN)
       3. Create the MultiplayerGame (which creates TopWindow)
       4. Trigger DedicatedServer.TopWindowInitialized via Python */
    if (g_hGameWindow) {
        SetTimer(g_hGameWindow, 42 /*DEDICATED_TIMER_ID*/, 500,
                 DedicatedServerTimerProc);
        ProxyLog("  PostAutoexecCallback: Scheduled DedicatedServerTimer (500ms)");
    } else {
        ProxyLog("  PostAutoexecCallback: WARNING - no game window for timer!");
    }

    ProxyLog("  PostAutoexecCallback: DONE");
}

static void PatchCreateAppModule(void) {
    BYTE* pTarget = (BYTE*)0x0043b1b9;
    BYTE* cave;
    DWORD oldProt;
    LONG jmpOffset;
    int c;

    /* Verify original bytes: 53 68 80 9C 8D 00 */
    if (IsBadReadPtr(pTarget, 6)) {
        ProxyLog("  PatchCreateAppModule: address not readable");
        return;
    }
    if (pTarget[0] != 0x53 || pTarget[1] != 0x68) {
        ProxyLog("  PatchCreateAppModule: unexpected bytes %02X %02X (expected 53 68), skipped",
                 pTarget[0], pTarget[1]);
        return;
    }

    cave = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!cave) {
        ProxyLog("  PatchCreateAppModule: VirtualAlloc failed");
        return;
    }

    c = 0;
    /* PUSHAD - save all registers */
    cave[c++] = 0x60;

    /* CALL CreateAppModuleCallback (our C function, __cdecl, no args) */
    cave[c++] = 0xE8;
    jmpOffset = (LONG)((BYTE*)CreateAppModuleCallback - (cave + c + 4));
    memcpy(cave + c, &jmpOffset, 4); c += 4;

    /* POPAD - restore all registers */
    cave[c++] = 0x61;

    /* Reproduce original instructions */
    cave[c++] = 0x53; /* PUSH EBX (original param2 = 0) */
    cave[c++] = 0x68; /* PUSH 0x008d9c80 (original param1 = "App") */
    *(DWORD*)(cave + c) = 0x008d9c80; c += 4;

    /* JMP back to 0x0043b1bf (the CALL TG_ImportModule instruction) */
    cave[c++] = 0xE9;
    jmpOffset = (LONG)(0x0043b1bf - (DWORD)(cave + c + 4));
    *(LONG*)(cave + c) = jmpOffset; c += 4;

    ProxyLog("  PatchCreateAppModule: cave at %p (%d bytes)", cave, c);

    /* Patch the original code: JMP to cave + NOP */
    VirtualProtect(pTarget, 6, PAGE_EXECUTE_READWRITE, &oldProt);
    pTarget[0] = 0xE9;
    jmpOffset = (LONG)((DWORD)cave - (DWORD)(pTarget + 5));
    memcpy(pTarget + 1, &jmpOffset, 4);
    pTarget[5] = 0x90;
    VirtualProtect(pTarget, 6, oldProt, &oldProt);

    ProxyLog("  PatchCreateAppModule: patched 0x0043B1B9 -> JMP %p (create App module)", cave);

    /* Also hook AFTER TG_ImportModule("Autoexec") to check what loaded.
     * At 0x0043b204: CALL 0x0074af10 (PyErr_Print) - 5 bytes
     * We replace with CALL PostAutoexecCave which calls PostAutoexecCallback
     * then does the original PyErr_Print call and continues. */
    {
        BYTE* pPost = (BYTE*)0x0043b204;
        BYTE* cave2;
        DWORD oldProt2;
        int c2 = 0;

        if (!IsBadReadPtr(pPost, 5) && pPost[0] == 0xE8) {
            cave2 = cave + 256; /* reuse same page, offset 256 */

            /* PUSHAD */
            cave2[c2++] = 0x60;
            /* CALL PostAutoexecCallback */
            cave2[c2++] = 0xE8;
            jmpOffset = (LONG)((BYTE*)PostAutoexecCallback - (cave2 + c2 + 4));
            memcpy(cave2 + c2, &jmpOffset, 4); c2 += 4;
            /* POPAD */
            cave2[c2++] = 0x61;
            /* Original: CALL PyErr_Print (0x0074af10) */
            cave2[c2++] = 0xE8;
            jmpOffset = (LONG)(0x0074af10 - (DWORD)(cave2 + c2 + 4));
            memcpy(cave2 + c2, &jmpOffset, 4); c2 += 4;
            /* JMP back to 0x0043b209 (instruction after the original CALL) */
            cave2[c2++] = 0xE9;
            jmpOffset = (LONG)(0x0043b209 - (DWORD)(cave2 + c2 + 4));
            memcpy(cave2 + c2, &jmpOffset, 4); c2 += 4;

            VirtualProtect(pPost, 5, PAGE_EXECUTE_READWRITE, &oldProt2);
            pPost[0] = 0xE9;
            jmpOffset = (LONG)((DWORD)cave2 - (DWORD)(pPost + 5));
            memcpy(pPost + 1, &jmpOffset, 4);
            VirtualProtect(pPost, 5, oldProt2, &oldProt2);

            ProxyLog("  PatchCreateAppModule: post-Autoexec hook at 0x0043B204 -> cave2 %p (%d bytes)", cave2, c2);
        } else {
            ProxyLog("  PatchCreateAppModule: post-Autoexec hook SKIPPED (unexpected bytes at 0x0043b204)");
        }
    }
}
