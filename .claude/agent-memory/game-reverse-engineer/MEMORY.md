# Game Reverse Engineer Memory

## Project: STBC Dedicated Server (Star Trek: Bridge Commander)
- DDraw proxy DLL (`ddraw_main.c`, ~3600 lines C), cross-compiled from WSL2
- NetImmerse 3.1 engine, Winsock UDP, embedded Python 1.5.2 (SWIG 1.x)
- stbc.exe: 32-bit Windows, base 0x400000, ~5.9MB

## State Dump Baseline (2026-02-12, no custom client connected)
- Stock-dedi `state_dump.log` shows lifecycle:
  - Dumps #1-#3: `CurrentGame: None`
  - Dumps #4-#17: `CurrentGame: <C Game instance ...>` (in-game)
  - Dumps #18-#19: `CurrentGame: None`
- In stock in-game dumps, `CurrentGame` is a real SWIG object with `this/thisown`;
  `.GetPlayer() = None` for dedicated host role.
- `g_pStartingSet` flips from `None` to `<C SetClass ...>` beginning at dump #6.
- Custom dedicated dump #1 is already in-game but reports raw-pointer
  `CurrentGame: _<addr>_p_Game` (`0 attributes`), indicating wrapper mismatch
  versus stock object exposure.

## App Wrapper Parity Fix (2026-02-12)
- `reference/scripts/App.py` shows stock pattern:
  `Game_GetCurrentGame -> Appc.Game_GetCurrentGame -> GamePtr(...)`.
- Added dedicated compat wrappers in `src/scripts/Custom/DedicatedServer.py`
  to wrap raw builtin App returns into Ptr objects for key APIs.

## Key Architecture Discoveries
- See [architecture.md](architecture.md) for detailed notes
- See [crash-analysis.md](crash-analysis.md) for InitNetwork crash chain analysis
- See [open-source-analysis.md](open-source-analysis.md) for dependency/legal analysis
- See [client-join-flow.md](client-join-flow.md) for post-checksum message sequence
- See [stock-baseline-analysis.md](stock-baseline-analysis.md) for stock host vs our server comparison
- See [encryption-analysis.md](encryption-analysis.md) for TGNetwork encryption/cipher analysis
- **Wire format spec**: `docs/wire-format-spec.md` - packet decoder (NEEDS CORRECTION, see below)
- See [torpedo-beam-network.md](torpedo-beam-network.md) for corrected opcode table

## BREAKTHROUGH: Black Screen SOLVED
- Fix: Replace Mission1.InitNetwork with functional Appc API version
- Root cause: TGMessage_Create() returns raw SWIG pointer, not shadow class
- Client now sees ship selection screen and can fly in-game

## CRITICAL DISCOVERY: 0x0097FA88 is IsClient, NOT IsHost (2026-02-08)
- See [stock-baseline-analysis.md](stock-baseline-analysis.md) for full evidence
- 0x0097FA88 = **IsClient**: 0 on host, 1 on client
- 0x0097FA89 = **IsHost**: 1 on host, 0 on client
- 0x0097FA8A = **IsMultiplayer**: 1 on host, 0 on client (our server=1, CORRECT)
- Our server correctly sets IsClient=0, IsHost=1, IsMp=1
- Stock host: GetPlayer()=None (no player ship), ReadyForNewPlayers=1, conn=2
- Stock client: conn transitions 3->2, gameTime syncs with server at join
- 0x1C state updates flow at ~10Hz after client joins in working sessions
- Stock host runs 163 unique Python calls during gameplay (full game logic server-side)

## 0x1C State Update & Subsystem Analysis (2026-02-09)
- See [subsystem-state-update-analysis.md](subsystem-state-update-analysis.md) for full analysis
- FUN_005b17f0 builds flags byte: 0x20=subsystems, 0x80=weapons
- 0x80 (weapons) only in single-player; 0x20 (subsystems) in MP during initial sync
- Subsystem lists at ship+0x284 populated by FUN_005b3e50, driven by FUN_005b3fb0
- Subsystems come from: hardpoint .py -> RegisterLocalTemplate -> AddToSet("Scene Root")
- AddToSet requires NIF model loaded (NiNode "Scene Root" in scene graph)
- PatchNetworkUpdateNullLists WORKS: clears 0x20/0x80 when lists NULL, prevents malformed packets
- **Server has NO game objects** -> FUN_005b17f0 never called -> no 0x1C packets sent
- Ship creation is client-side; server only receives replication via FUN_0069f620

## Client Join Message Sequence (CRITICAL ORDER)
1. C++ opcode 0x00 (settings: gameTime, settings bytes, playerSlot, mapName, checksumFlag)
2. C++ opcode 0x01 (single byte -> creates MultiplayerGame, runs GameInit)
3. Python MISSION_INIT_MESSAGE (game config: playerLimit, system, timeLimit, fragLimit)
4. Python SCORE_MESSAGE (one per existing player - empty for first joiner)
- Client FUN_00504c10 checks `this+0xb0 != 0` gate before processing ANY messages
- For first player joining empty game: NO game objects to replicate (loop is no-op)

## CRITICAL: 0x0078xxxx = Python 1.5.2 Parser (NOT NIF)
- FUN_007840f0 = PyNode_AddChild, FUN_0078b530 = token processor
- FUN_0074b640 = compile + run (used by PyRun_SimpleString)
- "shift: no mem in addchild", "s_push: parser stack overflow"

## Memory Allocator (shared between engine + Python)
- FUN_00717840 = NiAlloc (malloc with 4-byte size header)
- FUN_00717960 = NiFree, FUN_007179c0 = NiRealloc
- Small allocs (<= 0x80) use pool; large allocs use CRT malloc
- 4-byte size header at [ptr-4] is critical -- corruption here = fatal

## Key Functions
| Address | Name | Role |
|---------|------|------|
| 0x006a1b10 | ChecksumCompleteHandler | Server: sends opcode 0x00 + 0x01 (does NOT post 0x8000f1) |
| 0x006a1e70 | NewPlayerInGameHandler | Calls Python InitNetwork + replicates objects |
| 0x00504c10 | MW::ReceiveMessageHandler | Client: dispatches 0x00/0x01/0x16 |
| 0x00504d30 | Client opcode 0x00 handler | Extracts settings, loads mission TGL |
| 0x00504f10 | Client opcode 0x01 handler | Creates MultiplayerGame, runs GameInit |
| 0x005054b0 | UI transition helper | Shows/hides panes |
| 0x0069f620 | MP game object processor | Deserializes game objects from network |
| 0x006f3f30 | Checksum match data writer | Appends checksum data to stream |
| 0x006d1e10 | TGLFile::FindEntry | Returns entry ptr; returns this+0x1c as default |
| 0x006d03d0 | TGLManager::LoadFile | __thiscall on 0x997fd8; returns NULL if fopen fails |
| 0x006d11d0 | TGLManager::LoadOrCache | Allocates + parses TGL; returns NULL on failure |
| 0x00731d20 | NiTexture::Init(entry) | Uses TGL entry; has NULL check (TEST EDI/JZ) |
| 0x00731bb0 | NiTexture::ctor | Constructor; calls Init at 0x00731d20 |
| 0x006f4d90 | NiString::Assign(src) | String copy; has NULL check (TEST EBP/JZ) |
| 0x00504890 | MW::StartGameHandler | ET_START handler; creates WSN or forwards to MultiplayerGame |
| 0x005b17f0 | Ship network state writer | Writes pos/orient/subsys/weapons to stream |
| 0x004360c0 | GetBoundingBox | vtable[0xE8], computes AABB from NiBound; see [bounding-box-crash.md](bounding-box-crash.md) |
| 0x00419960 | GetModelBound | vtable[0xE4], returns NiBound*; NOT in Ghidra func DB (tiny function) |
| 0x006d2eb0 | ReadCompressedVector3 | 3 vtable calls + decode; see [compressed-vector-crash.md] |
| 0x006d2fd0 | ReadCompressedVector4 | Same pattern, 4 params; patched with vtable validation |
| 0x006cefe0 | StreamReader ctor | Derived; vtable=PTR_LAB_00895c58; base=FUN_006d1fc0 |
| 0x005b21c0 | ShipStateUpdateReceiver | Processes 0x1C packets; calls FUN_006d2eb0/FUN_006d2fd0 |

## SOLVED: 0x1C Bad Pointer (Phase 2 Boot Crash)
- See [tgl-null-crash.md](tgl-null-crash.md) for full analysis
- Root cause: FUN_006d1e10 (TGLFile::FindEntry) returns `this+0x1c` as default
- When TGL file fails to load, `this==NULL`, so returns `0+0x1c = 0x1c`
- 0x1c passes all `TEST reg,reg / JZ` NULL checks but is an invalid pointer
- Fix: Patch FUN_006d1e10 with code cave adding `TEST ECX,ECX / JZ return_null`
- Single-point fix eliminates ALL downstream 0x1C crashes across dozens of callers

## Bug Analysis: InitNetwork Duplicates (2026-02)
- See [initnet-duplicates.md](initnet-duplicates.md) for full analysis
- Engine's native C++ NewPlayerInGameHandler (FUN_006a1e70) already calls InitNetwork
- Our GameLoopTimerProc was ALSO calling FUN_006a1e70 manually, causing duplicates
- Double call caused: duplicate 0x35/0x37/0x17 packets, ACK storms, double ObjNotFound
- FIX: Remove manual FUN_006a1e70 call from GameLoopTimerProc

## Bug Analysis: Collision Damage Missing (2026-02)
- See [collision-damage.md](collision-damage.md) for full analysis
- Root cause: DedicatedServer.py stubs ALL MultiplayerMenus functions as noop
- This prevents HandleStartGame -> StartMission -> CreateSystemFromSpecies
- No system loaded = no SetClass = no ProximityManagerActive = no collisions
- FIX: Call CreateSystemFromSpecies directly in DedicatedServer.py after Initialize

## Bug Analysis: SetClass_Create Returns Raw String (2026-02)
- See [set-creation-analysis.md](set-creation-analysis.md) for full analysis
- Multi1.Initialize() does App.SetClass_Create() but gets raw SWIG ptr, not shadow class
- Root cause: App module may be raw Appc (no shadow wrappers) in headless bootstrap
- Ship creation is CLIENT-SIDE (server never creates client ships)
- Server needs Set in SetManager for object replication + ProximityManager for collisions
- FIX: Use Appc functional API directly (SetClass_Create, SetRegionModule, AddSet, etc.)
- Missing Set does NOT cause disconnect - it only affects collision damage
- Second connection works because Python/C++ state persists from first attempt

## Normal Host Flow for System Loading
1. Host clicks Start -> HandleHostStartClicked fires ET_START
2. ET_START -> HandleStartGame (UI cleanup only, calls CallNextHandler first)
3. Player selects ship -> ET_FINISHED_SELECT -> FinishedSelectHandler -> StartMission
4. StartMission (Mission1Menus.py:740) -> CreateSystemFromSpecies (line 758)

## ET_START C++ Path (FUN_00504890)
- If DAT_0097e238 (MultiplayerGame) != NULL AND IsMultiplayer:
  - Increments event counter at param+0x1a
  - Calls MultiplayerGame vtable[0x68](event) -- forwards to C++ handler
  - Goes to LAB_00504bc2 -> FUN_006d90e0 (event dispatch cleanup)
- If DAT_0097e238 == NULL:
  - Sets up network from scratch (FUN_00445d90)
  - This is the INITIAL setup path for fresh start

## Open Source Viability Assessment (2026-02)
- See [open-source-analysis.md](open-source-analysis.md) for full analysis

## DISCONNECT ROOT CAUSE FOUND: TGBootPlayerMessage sub-cmd 4 (2026-02-09)
- See [boot-player-analysis.md](boot-player-analysis.md) for full analysis
- Server sends `04 07 C0 02 00 04 02` = TGBootPlayerMessage, reason=4 (kicked)
- Sub-command 4 = "boot player" (host kicking a player)
- Sender: MultiplayerWindow::BootPlayerHandler at 0x00506170
- Triggered by event ET_BOOT_PLAYER (0x8000f6)
- ONLY source of ET_BOOT_PLAYER: FUN_005b21c0 (ship state update receiver)
- FUN_005b21c0 has anti-cheat: computes subsystem hash via FUN_005b5eb0
- If received_hash != computed_hash -> fires ET_BOOT_PLAYER -> kicks player
- Server has NO ship objects -> hash=0 -> client sends valid hash != 0 -> FALSE POSITIVE
- FIX OPTIONS: (1) suppress ET_BOOT_PLAYER on server, (2) patch FUN_005b21c0 hash check,
  (3) ensure server has matching ship objects, (4) NOP the hash comparison

## Renderer Pipeline Analysis (2026-02-09)
- See [renderer-pipeline-analysis.md](renderer-pipeline-analysis.md) for initial analysis
- See [renderer-pipeline-trace.md](renderer-pipeline-trace.md) for FULL Ghidra disasm trace
- See [renderer-device7-overread.md](renderer-device7-overread.md) for Device7 copy crash
- PatchRendererMethods ACTIVE (stubs 3 renderer vtable methods)
- PatchDeviceCapsRawCopy zeroes the MOV ECX count in FUN_007d1ff0 (prevents raw copy)
- FUN_007c4850 (at 0x007C4879) = logging helper, NOT crash source

### SOLVED: Dev_GetDirect3D Returns NULL (Previous Pipeline Crash)
- Fixed by adding ProxyD3D7* back-ref to ProxyDevice7

### SOLVED: ProxyDevice7 Raw Copy Crash (2026-02-09)
- See [renderer-device7-overread.md](renderer-device7-overread.md) for full analysis
- FUN_007d1ff0 copies 59 DWORDs (236 bytes) FROM Device7 into texture format manager
- FIX: PatchDeviceCapsRawCopy zeroes the REP MOVSD count at 0x007d2119
- This prevents the raw memcpy entirely; NI gets zeroed caps (safe, means "no features")

### Active Renderer Patches
- **PatchRendererMethods** - stubs 3 vtable methods: FUN_007e8780 (RET), FUN_007c2a10 (RET 4), FUN_007c16f0 (RET 0x18)
- **PatchSkipDeviceLost** - always skip device-lost recreation path
- **PatchRenderTick** - JMP skip render work (no GPU cost)
- **PatchDeviceCapsRawCopy** - zero the 236-byte raw copy count

## Subsystem Creation Chain (2026-02-09)
- See [subsystem-creation-analysis.md](subsystem-creation-analysis.md) for full analysis
- See [nif-loading-pipeline.md](nif-loading-pipeline.md) for full NIF->subsystem trace (2026-02-10)
- PatchSubsystemHashCheck ALREADY bypasses hash when subsystem list is NULL

## NIF Loading Pipeline Analysis (2026-02-10)
- See [nif-loading-pipeline.md](nif-loading-pipeline.md) for full call chain
- See [ship-creation-callchain.md](ship-creation-callchain.md) for full HOST-side analysis (2026-02-13)

## Ship Creation Call Chain (2026-02-13)
- FUN_0069f620 (ObjCreateTeam handler) -> FUN_005a1f50 (deserialize) -> FUN_005b0e80 (InitObject)
- FUN_005b0e80 is a VTABLE ENTRY (never called directly) in Ship ReadStream chain
- FUN_006f8ab0 (TG_CallPythonFunction) does NOT use PyRun_SimpleString
  - Uses: FUN_006f7d90 (__import__) + FUN_0074c140 (getattr) + FUN_00776cf0 (PyObject_CallObject)
  - SHOULD work in TIMERPROC context (different code path)
- FUN_006f7d90 converts dots to underscores for sys.modules key
- Possible InitObject failure: import fails, Python exception, or deserialization never reaches vtable

## SOLVED: Compressed Vector Read Crash (2026-02-09)
- See [compressed-vector-crash.md](compressed-vector-crash.md) for full analysis
- FUN_006d2eb0 / FUN_006d2fd0: read compressed vectors via 4 vtable calls
- If vtable corrupted, callee-clean stack params strand 24 bytes -> misaligned ESP -> crash
- FIX: PatchCompressedVectorRead validates vtable in .rdata range before entering function

## CRITICAL: Wire Format Opcode Table CORRECTED (2026-02-09)
- See [torpedo-beam-network.md](torpedo-beam-network.md) for full corrected table
- Spec was WRONG about opcodes 0x07-0x0B. Switch table at 0x0069F534 (base=opcode-2)
- 0x09 is NOT TorpedoFire, it's StopFiringAtTarget (event forward 0x008000DB)
- 0x0A is NOT BeamFire, it's SubsystemStatusChanged (event forward 0x0080006C)
- ACTUAL TorpedoFire = opcode 0x19, sent by FUN_0057cb10 (TorpedoSystem::SendFireMessage)
- ACTUAL BeamFire = opcode 0x1A, sent by FUN_00575480 (PhaserSystem::SendFireMessage)
- Opcodes 0x07-0x0B, 0x0E-0x10, 0x1B all go through FUN_0069FDA0 (generic event forward)
- Torpedoes are game OBJECTS: fire creates projectile, replicated via 0x02/0x03 (ObjectCreate)

## Dump Baseline Delta (2026-02-12)
- Stock dedicated `state_dump.log` shows canonical host-start path in dump #2:
  `HandleHostStartClicked -> HandleStartGame -> ProcessMessageHandler -> MissionShared.Initialize -> MissionShared.SetupEventHandlers -> SpeciesToSystem.CreateSystemFromSpecies`.
- Stock transitions from menu baseline to valid game state in one run:
  `CurrentGame: None` at dump #1, then `CurrentGame: <C Game instance>` at dump #2.
- Custom server dump currently captures only 3 code paths (`_ds_safe_import`, `PatchLoadedMissionModules`, `<string>:?`), indicating bootstrap bypass of the canonical menu/start path.
- This bypass is a primary suspect when behavior diverges despite `CurrentGame` existing.

## Stock 4-Stage Startup Baseline (2026-02-12, new capture)
- Dump #1 (main menu): `CurrentGame=None`, `sys.modules=142`, `g_pDatabase=None`, `g_pStartingSet=None`.
- Dump #2 (host game screen): still `CurrentGame=None`, `sys.modules=158` after `BuildMultiplayerPreGameMenus/BuildHostPane/BuildMissionMenu`.
- Dump #3 (system select lobby): `CurrentGame` created, `sys.modules=334`, `g_pDatabase!=None`, but `g_pStartingSet=None`.
- Dump #4 (scoreboard): `StartMission -> SpeciesToSystem.CreateSystemFromSpecies -> App.InitializeAllSets -> Systems.Multi1.Initialize`, `sys.modules=348`, `g_pStartingSet!=None`.
- Therefore `CurrentGame` appears one stage BEFORE starting set/system creation.
