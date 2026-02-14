# Dedicated Server - Bootstrap & Architecture

## Current Bootstrap Sequence (4 Phases + Game Loop)

### Phase 0: Flag Setting
- Direct memory writes: IsClient=0 (0x0097FA88), IsHost=1 (0x0097FA89), IsMultiplayer=1 (0x0097FA8A)
- SWIG SetFlags via Python (may fail, non-fatal)
- Config loading

### Phase 1: Network Initialization
- Python: UtopiaModule_InitializeNetwork(um, wsn, name)
- Gets WSN pointer from UtopiaModule_GetNetwork
- Port defaults to 22101 (game default)

### Phase 2: MultiplayerGame Creation
- Python: TopWindow_SetupMultiplayerGame() -> FUN_00504f10
- TopWindow stored at 0x0097e238

### Phase 3: Automation & GameSpy
- Runs DedicatedServer.py TopWindowInitialized()
- Sets game name, captain name, ReadyForNewPlayers=1, MaxPlayers=16
- Creates GameSpy (UtopiaModule_CreateGameSpy), starts heartbeat
- Sets qr_t+0xE4=0 (disable GameSpy's recvfrom, peek router handles it)
- Sets MultiplayerGame+0x1F8=1 (enable immediate new player handling)
- Transitions to Phase 4 (game loop)

### Phase 4: Game Loop (33ms timer = ~30fps)
GameLoopTimerProc runs (in `game_loop_and_bootstrap.inc.c`):
1. Get game time from clock object
2. Call UtopiaApp_MainTick (0x0043b4f0)
   - TimerManager updates
   - EventManager::ProcessEvents
   - Subsystem updates
   - Render (patched to skip per-frame work)
3. Call TGNetwork::Update (0x006B4560) on WSN
4. Peek-based UDP router for GameSpy queries
5. Call GAMESPY_TICK for internal state
6. **Peer detection**: Scan WSN peer array for new peer IDs → schedule InitNetwork
7. **InitNetwork**: After 30-tick delay, call `Mission1.InitNetwork(peerID)` via RunPyCode
8. **DeferredInitObject**: After InitNetwork, poll for new ship objects → call Python to load NIF model and create subsystems
9. Monitoring/diagnostics

#### Peer Detection (InitNetwork Scheduling)
The game loop detects new peers by scanning the WSN peer array (`WSN+0x2C` pointer,
`WSN+0x30` count). Each peer at `pp+0x18` has a peer ID. When a new ID appears that
hasn't been seen before, InitNetwork is scheduled for 30 ticks later.

**Why not use peer+0xBC (bc flag)?** The `bc` flag was originally used to detect checksum
completion, but it takes 200+ ticks to transition (or never flips). The actual checksum
exchange completes within 1-2 ticks. Peer-array detection fires at connect time, matching
stock server timing (~1.4s vs stock's ~2s).

#### DeferredInitObject (Ship Creation)
After InitNetwork fires, the game loop polls for new ship objects owned by the connecting
player. When found (ship+0x2E0 ShipRef is NULL = not yet initialized):
1. Python determines ship class from species index
2. Calls `ship.LoadModel(nifPath)` to load the NIF file
3. Engine creates subsystem objects (33 for Sovereign class)
4. Ship+0x284 linked list is populated
5. StateUpdate now sends flags=0x20 with real subsystem health data

## Crash Handling

### CrashDumpHandler (SetUnhandledExceptionFilter)
Registered via `SetUnhandledExceptionFilter(CrashDumpHandler)` in DllMain.
On any unhandled exception:
1. Writes detailed diagnostics to `crash_dump.log`:
   - Timestamp, exception code, faulting EIP with module resolution
   - Access violation details (read/write, target address)
   - Full register dump (EAX-EDI, EBP, ESP, EIP, EFlags)
   - EBP chain stack walk (up to 32 frames)
   - Raw stack hex dump (256 bytes from ESP with ASCII sidebar)
   - Code bytes around crash EIP (32 before, 32 after)
   - Memory at register targets (EAX, ECX, ESI, EDI, EBX, EDX)
2. Flushes all open log files
3. Logs one-liner to ddraw_proxy.log
4. Returns EXCEPTION_CONTINUE_SEARCH (process terminates)

### SIGABRT Handler
CRT signal handler for SIGABRT (signal 22). Logs the abort source and calls ExitProcess(99).
Registered via msvcrt `signal()` in DllMain.

## Binary Patching Summary

### Active Patches (called during DllMain initialization)
| Patch | Address(es) | Effect |
|-------|-------------|--------|
| HookGameIAT | IAT entries | Hooks sendto/recvfrom for packet logging |
| InlineHookMessageBoxA | MessageBoxA | Suppresses modal error dialogs |
| PatchRenderTick | 0x004433EA | JNZ->JMP skip per-frame render work |
| PatchInitAbort | 0x0043B1D2 | NOP JMP that calls abort on init failure |
| PatchPyFatalError | Py_FatalError entry | Make Py_FatalError return instead of abort |
| PatchCreateAppModule | (before init) | Create SWIG "App" module before init imports it |
| PatchDirectDrawCreateExCache | 0x009A12A4 | Pre-fill DDCreateEx function cache |
| PatchSkipDeviceLost | 0x007C1346 | JZ->JMP skip device-lost recreation path |
| PatchRendererMethods | 0x007E8780, 0x007C2A10, 0x007C16F0 | Stub SetCameraData/frustum during pipeline setup |
| PatchDeviceCapsRawCopy | 0x007D2119 | Skip 236-byte raw Device7 memory copy in NI pipeline |
| PatchHeadlessCrashSites | 0x0055C810, 0x0055C860 | RET at mission UI functions that crash headless |
| PatchTGLFindEntry | 0x006D1E10 | Code cave: return NULL when this==NULL |
| PatchNetworkUpdateNullLists | 0x005B1D57 | Code cave: clear SUB/WPN flags when ship+0x284 NULL |
| PatchSubsystemHashCheck | 0x005B22B5 | Code cave: prevent false anti-cheat kicks when subsystems NULL |
| PatchCompressedVectorRead | 0x006D2EB0, 0x006D2FD0 | Code cave: validate vtable before compressed vector read |
| PatchDebugConsoleToFile | FUN_006f9470 | Redirect Python debug console output to state_dump.log |
| PatchNullSurface | 0x007CB322 | JNZ fix (displacement 0x05 not 0x06) in GGM ctor |

### Critical: PatchNetworkUpdateNullLists MUST Stay Enabled
This patch at 0x005B1D57 clears SUB/WPN flags when ship+0x284 (subsystem linked list) is
NULL. **Disabling this patch causes a fatal crash** at 0x005B1EDB when the state update loop
tries to iterate a NULL linked list. The crash is unrecoverable (MOV EAX,[ECX] → CALL
[EAX+0x70] chain through zeroed vtable). Even with DeferredInitObject creating subsystems
for client ships, the server's own player-0 ship still has NULL subsystems.

### Removed Patches (no longer in codebase)
| Patch | Reason Removed |
|-------|----------------|
| PatchInitSkipPython | No longer needed - Python init runs naturally |
| PatchHostDequeueLoop | No longer needed - normal dequeue path works |
| PatchInitTraversal | No longer needed - traversal runs normally |
| PatchNullSurface | Was part of VEH system - removed with VEH |
| PatchChecksumAlwaysPass | Incorrect - flag=0 means "no mismatches" which is correct for first player |
| PatchSkipRendererSetup | Removed - let full pipeline run; D3D proxy provides valid COM objects |
| PatchRendererCtorEntry | Removed - let real NiDX7Renderer constructor run for valid internal state |

### Defined But Not Called (kept for reference)
| Patch | Address | Notes |
|-------|---------|-------|
| PatchSkipRendererCtor | 0x0043ADB6 | Available but not called - renderer ctor allowed to run |

## Key Architecture Notes
- UtopiaApp_MainTick does NOT call TGNetwork_Update (confirmed)
- FUN_00451ac0 calls TGNetwork_Update in normal game (from simulation pipeline)
- TGNetwork connState=2 for HOST (counterintuitive), 3 for CLIENT
- GameSpy and TGNetwork share same UDP socket (WSN+0x194)
- Python nesting counter at 0x0099EE38 (must be 0 for PyRun_String)

## Key Globals
| Address | What |
|---------|------|
| 0x0097FA00 | UtopiaModule base |
| 0x0097FA78 | TGWinsockNetwork* (UtopiaModule+0x78) |
| 0x0097FA7C | GameSpy ptr (+0xDC=qr_t) |
| 0x0097FA80 | NetFile/ChecksumMgr (UtopiaModule+0x80) |
| 0x0097FA88 | IsClient (BYTE) - 0=host, 1=client |
| 0x0097FA89 | IsHost (BYTE) - 1=host, 0=client |
| 0x0097FA8A | IsMultiplayer (BYTE) |
| 0x008E5F59 | Settings byte 1 (collision damage toggle) |
| 0x0097FAA2 | Settings byte 2 (friendly fire toggle) |
| 0x0097E238 | TopWindow/MultiplayerGame ptr |
| 0x009A09D0 | Clock object ptr (+0x90=gameTime, +0x54=frameTime) |
| 0x0097F838 | EventManager |

## Normal Game Initialization (FUN_00445d90)
Called as __thiscall on UtopiaModule (0x0097FA00):
1. Creates TGWinsockNetwork (0x34C bytes) -> stored at +0x78 (0x0097FA78)
2. FUN_006b9bb0 sets port on WSN (+0x338 = port)
3. TGNetwork_HostOrJoin (0x006b3ec0) creates socket, sets state
4. Creates NetFile (0x48 bytes) via FUN_006a30c0 -> stored at +0x80 (0x0097FA80)
5. Creates GameSpy (0xF4 bytes) -> stored at +0x7C (0x0097FA7C)
Our Phase 1 calls this function correctly with (this=0x0097FA00, addr=0, pw=empty, port=0x5655).
