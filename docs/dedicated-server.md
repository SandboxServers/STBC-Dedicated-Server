# Dedicated Server - Bootstrap & Architecture

## Current Bootstrap Sequence (4 Phases + Game Loop)

### Phase 0: Flag Setting
- Direct memory writes: IsHost=1 (0x0097FA88), IsMultiplayer=1 (0x0097FA8A)
- SWIG SetFlags via Python (may fail, non-fatal)
- Config loading

### Phase 1: Network Initialization
- Python: UtopiaModule_InitializeNetwork(um, wsn, name)
- Gets WSN pointer from UtopiaModule_GetNetwork
- Port defaults to 22101 (game default)

### Phase 2: MultiplayerGame Creation
- Python: TopWindow_SetupMultiplayerGame() -> FUN_00504f10
- Triggers VEH fixups (bad EIP, NULL deref) - non-deterministic
- TopWindow stored at 0x0097e238

### Phase 3: Automation & GameSpy
- Runs DedicatedServer.py TopWindowInitialized()
- Sets game name, captain name, ReadyForNewPlayers=1, MaxPlayers=16
- Creates GameSpy (UtopiaModule_CreateGameSpy), starts heartbeat
- Sets qr_t+0xE4=0 (disable GameSpy's recvfrom, peek router handles it)
- Sets MultiplayerGame+0x1F8=1 (enable immediate new player handling)
- Installs software breakpoints on key functions (for debugging)
- Transitions to Phase 4 (game loop)

### Phase 4: Game Loop (33ms timer = ~30fps)
GameLoopTimerProc runs:
1. Get game time from clock object
2. Call UtopiaApp_MainTick (0x0043b4f0)
   - TimerManager updates
   - EventManager::ProcessEvents
   - Subsystem updates
   - Render (patched to skip)
3. Call TGNetwork::Update (0x006B4560) on WSN
4. Peek-based UDP router for GameSpy queries
5. Call GAMESPY_TICK for internal state
6. Monitoring/diagnostics

## Software Breakpoint System
VEH-based INT3 breakpoint hooks:
- Saves original byte, writes 0xCC
- VEH handler catches breakpoint, logs, restores byte, enables single-step (TF flag)
- Single-step handler re-installs INT3
- Pages left RWX for handler access
- Currently installed on: NewPlayerHandler, ChecksumSend, TGNetwork::Send

## Binary Patching Summary
| Patch | Address | Effect |
|-------|---------|--------|
| PatchInitSkipPython | 0x0043B1D7 | JMP over Python calls in UtopiaApp::Init |
| PatchHostDequeueLoop | 0x6B467C | Redirect host JMP to client's dequeue loop (0x6B4779) |
| PatchInitAbort | 0x0043B1D2 | NOP abort jump in Init |
| PatchInitTraversal | 0x00438AE6 | NOP linked list traversal calls |
| PatchRenderTick | 0x004433EA | JNZ->JMP skip render work |
| PatchNullSurface | 0x7CB322 | JMP to code cave for NULL->dummy surface |

## VEH Crash Handler
Handles multiple exception types:
- Bad EIP (executing NULL/stale pointer): scans stack for return address
- NULL pointer writes: redirects register to dummy buffer
- NULL pointer reads: redirects to 64KB zeroed buffer
- Mipmap code range: injects dummy surface
- Software breakpoints: custom INT3 handler for function tracing

## Key Architecture Notes
- UtopiaApp_MainTick does NOT call TGNetwork_Update (confirmed)
- FUN_00451ac0 calls TGNetwork_Update in normal game (from simulation pipeline)
- TGNetwork connState=2 for HOST (counterintuitive), 3 for CLIENT
- GameSpy and TGNetwork share same UDP socket (WSN+0x194)
- Python nesting counter at 0x0099EE38 (must be 0 for PyRun_String)
