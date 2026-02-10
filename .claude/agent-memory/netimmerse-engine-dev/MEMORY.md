# NetImmerse Engine Dev - Agent Memory

## Project: STBC Dedicated Server (DDraw Proxy DLL)
Cross-compiled from WSL2, drives STBC headlessly via C code + embedded Python 1.5.

## Key Architecture Findings

### Event Type Constants (from constructor at FUN_0069e590)
- `0x60001` = ET_NETWORK_MESSAGE_EVENT (ReceiveMessageHandler)
- `0x60003` = ET_NETWORK_DISCONNECT
- `0x60004` = ET_NETWORK_NEW_PLAYER (NewPlayerHandler)
- `0x60005` = ET_NETWORK_DELETE_PLAYER
- `0x8000e6` = ET_CHECKSUM_COMPLETE_PER_PLAYER -> ChecksumCompleteHandler (FUN_006a1b10)
- `0x8000e7` = ET_SYSTEM_CHECKSUM_FAILED -> SystemChecksumFailedHandler
- `0x8000e8` = ET_SYSTEM_CHECKSUM_PASSED -> SystemChecksumPassedHandler
- `0x8000f1` = ET_NEW_PLAYER_IN_GAME -> NewPlayerInGameHandler (FUN_006a1e70)
- See [event-types.md](event-types.md) for full list

### Critical Flow: ChecksumComplete -> InitNetwork (REVISED)
1. NetFile fires `0x8000e6` (per-player checksum done)
2. ChecksumCompleteHandler (FUN_006a1b10) sends opcode 0x00 (settings) + 0x01 (ready)
3. Client receives opcode 0x00/0x01, processes, sends ack opcode back
4. Server ReceiveMessageHandler (LAB_0069f2a0) at offset 0x0069f30d
   **directly calls** FUN_006a1e70 (NOT via event system!)
5. FUN_006a1e70 calls Python InitNetwork(playerID) via FUN_006f8ab0
6. InitNetwork sends MISSION_INIT_MESSAGE with system/limits
7. Client receives MISSION_INIT_MESSAGE -> BuildMission1Menus -> ship select

### Key Insight: InitNetwork trigger is opcode-driven, NOT event-driven
- FUN_006a1e70 is called directly from ReceiveMessageHandler opcode switch (xref 0x0069f30d)
- 0x8000f1 is only CREATED by FUN_006a1e70 itself (re-broadcast) and constructor (host)
- 0x8000e8 / SystemChecksumPassedHandler does NOT fire 0x8000f1
- The C-side harness InitNetwork scheduling may be DOUBLE-CALLING because native code
  already handles it when the client ack opcode arrives
- See [native-handoff-analysis.md](native-handoff-analysis.md) for full dispatch map

### SOLVED: Black Screen
Fixed by replacing Mission1.InitNetwork with Appc functional API version (raw SWIG).
Client now gets ship selection UI and can fly in-game.

### SOLVED: Server Crash During InitNetwork
**Root cause: Python GIL violation.** HeartbeatThread (background) calls PyRun_String
for 15s diagnostics at the exact same time GameLoopTimerProc (main thread) fires
InitNetwork via PyRun_String. Python 1.5.2's allocator at 0x0099C478 has zero thread
safety. Concurrent malloc/free corrupts free lists -> cascading crashes.
- See [crash-analysis-initnetwork.md](crash-analysis-initnetwork.md) for full details
- See [memory-allocator.md](memory-allocator.md) for allocator structure
- **Fix: Remove ALL Python API calls from HeartbeatThread**

### Ship Selection Disconnect (First Connect Fails, Second Works)
- See [ship-selection-disconnect-analysis.md](ship-selection-disconnect-analysis.md)
- **Root cause**: SetClass_Create() returns raw SWIG pointer, .SetRegionModule() fails
- No Set on server -> FUN_006a1e70 skips object sync loop (DAT_0097e9cc == 0)
- Client ship creation (opcode 0x02) arrives but server has no Set to place it in
- Second connection may work due to cached Python module state or partial init
- **Fix**: Use Appc functional API for Set creation (SetClass_Create + SetClass_SetRegionModule)

### Phase 2 Crash: 0x1C Used as Pointer
- See [phase2-crash-analysis.md](phase2-crash-analysis.md) for full details
- **Root cause**: `FUN_006D1E10` (TGL entry lookup) returns `this+0x1C` as sentinel
- When TGL object is NULL (load failed), sentinel = `0+0x1C = 0x1C` (non-NULL but invalid)
- 0x1C passes NULL checks but crashes on dereference at `[0x1C+8]` = address 0x24
- Three crash sites: 0x006F4DA1 (handled), 0x006F4EEC, 0x00731D43 (unhandled)
- **Best fix**: patch at source in FUN_00504F10 to null-check TGL load result
- TGL = "Totally Games Layout" - UI descriptor format loaded from data/TGL/*.tgl

### CURRENT: Game-Over Screen After Ship Selection
- See [game-over-analysis.md](game-over-analysis.md) for full details
- Likely root cause: GetBoundingBox crash (vtable+0xe4 returns NULL) -> malformed state packets
- FUN_004360c0 = GetBoundingBox: vtable[57]=GetWorldBound() returns NiBound* (center[3]+radius)
- NULL return -> 0+0xC crash, VEH redirects to zeroed dummy -> ship appears at (0,0,0) with radius=0
- FUN_005b17f0 = NetworkObjectStateUpdate: builds per-tick state packets for each ship
- Client interprets zero-bound/zero-position ship as dead -> ObjectDestroyedHandler -> end-game
- 0x00419963 crash: vtable slot at base+0xe0 (slot 56), fires 3x on connect, adjacent to GetWorldBound
- Scoring dict fix rc=-1 means Python exception in PyRun_SimpleString (dict init may fail)

### PROPOSED FIX: Renderer Pipeline Restoration
- See [renderer-restoration-analysis.md](renderer-restoration-analysis.md) for full analysis
- Remove PatchSkipRendererSetup, let FUN_007c3480 build pipeline objects fully
- Requires Dev_EnumTextureFormats to enumerate real pixel formats (critical gate)
- NIF loading is DECOUPLED from renderer for geometry/transforms/bounds
- NiBound computed CPU-side from vertex data in NiAVObject::UpdateWorldBound()
- Subsystems/weapons come from Python hardpoint files, NOT NIF scene graph
- loadspacehelper.CreateShip: LoadModel -> ShipClass_Create -> LoadPropertySet -> SetupProperties
- FUN_007c3480 pipeline objects: +0xb8 texmgr, +0xbc rendstate, +0xc0 shader, +0xc4 geom-accum

### Key Engine Classes Identified
- `FUN_006D1E10` = TGL::FindEntry(name) - binary search by hash, returns entry or this+0x1C
- `FUN_006D03D0` = TGL::Load(path, flag) - loads .tgl file from disk
- `FUN_006F4D90` / `FUN_006F4EE0` = wstring assign (two variants, with/without NULL check)
- `FUN_00731BB0` = TGAnimAction constructor (0x94 bytes, vtable PTR_FUN_00896E60)
- `FUN_00731D20` = TGAnimAction::Init - reads wstring param at [param+8] for length
- `FUN_00734F70` = Animation name lookup in linked list at 0x0099D8E0
- `FUN_005054B0` = Scene graph navigation + window setup (vtable calls 0x11C, 0x160)

## Build
- `make build` cross-compiles ddraw.dll from WSL2
- `make deploy` kills stbc.exe, copies dll+scripts+config
- `make run` = deploy + launch

## Files
- `src/proxy/ddraw_main.c` - ALL C code (~3600 lines)
- `src/scripts/Custom/DedicatedServer.py` - Python automation
- `reference/decompiled/09_multiplayer_game.c` - MP game logic
- `reference/decompiled/10_netfile_checksums.c` - Checksums + NewPlayerInGameHandler
- `reference/decompiled/11_tgnetwork.c` - Network layer

## Strategic: Standalone Server Feasibility
- See [standalone-server-analysis.md](standalone-server-analysis.md)
- STBC MP is client-authoritative message relay (NOT server-authoritative simulation)
- Standalone server ~5K-8K lines C, no engine/Python/game-data needed
- Strategy: finish proxy first (research), then standalone from protocol spec (release)
- Clean room: write protocol spec from captures, implement from spec only

## Headless Approaches Analysis (2026-02-09)
- See [headless-approaches-analysis.md](headless-approaches-analysis.md)
- NI 3.1 has NO headless/null renderer (NiHeadlessRenderer = Gamebryo 2.3+)
- NIF loading (NiStream::Load at FUN_008176b0) does NOT need renderer
- NiBound computed CPU-side; needs NiAVObject::Update() called after load
- **Best approach: Fix proxy COM to let pipeline objects build (7/10 feasibility)**
- Pipeline constructors (FUN_007d4950/007d2230/007ccd10/007d11a0) call COM methods
- If proxy returns D3D_OK for all, pipeline objects at 0xB8-0xC4 become non-NULL
- Non-NULL pipeline = NIF loading works = bounds valid = state packets correct
- **Fallback: Hook bounds injection after ship creation (5/10 feasibility)**

## Network Serialization (FULLY REVERSED)
- See [serialization-formats.md](serialization-formats.md) for complete reference
- TGBufferStream class: vtable at 0x00895C58, base at 0x00895D60
- Position-based serialization (caller knows field order), NO type tags
- Compressed vectors: direction as 3 signed bytes (x127), magnitude as uint16 (log10)
- Magnitude encoding: [S:1][E:3][M:12], base-10 ranges from 0.001 to 10000
- State update (opcode 0x1C): dirty-flag delta compression, 8 field types
- Object IDs: uint32, assigned by server, looked up via hash table
- Bool packing: up to 5 bools per byte (3-bit count in high bits)
- Subsystem/weapon state: round-robin serialization (N items per tick, wraps)
