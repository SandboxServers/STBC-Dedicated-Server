# Game Reverse Engineer Memory

## Project: STBC Dedicated Server (Star Trek: Bridge Commander)
- DDraw proxy DLL (`ddraw_main.c`, ~3600 lines C), cross-compiled from WSL2
- NetImmerse 3.1 engine, Winsock UDP, embedded Python 1.5.2 (SWIG 1.x)
- stbc.exe: 32-bit Windows, base 0x400000, ~5.9MB

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

## CRITICAL DISCOVERY: IsHost Flag is INVERTED (2026-02-08)
- See [stock-baseline-analysis.md](stock-baseline-analysis.md) for full evidence
- 0x0097FA88 ("IsHost") = **0 on stock host**, **1 on stock client**
- Semantics: 0 = "I am the host", 1 = "I have a host" (i.e., IsClient)
- Our server INCORRECTLY sets this to 1 (ddraw_main.c line 2607 + SetIsHost(1))
- FIX: Set to 0 -- could resolve game-over/disconnect if C++ dispatcher uses this flag
- 0x0097FA8A ("IsMultiplayer") = 1 on host, 0 on client (our server=1, CORRECT)
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
- VEH EIP-SKIP entries (005b1edb, 005b1f82) NOT being hit = cave is effective
- **Server has NO game objects** -> FUN_005b17f0 never called -> no 0x1C packets sent
- 0x004360CB + 0x00419963 crash pair (100s/sec, VEH-fixed) = see [bounding-box-crash.md](bounding-box-crash.md)
- Fix: code cave at 0x004360c0 entry, NULL-check ECX (this) + EAX (GetModelBound return)
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

## VEH Handler Behavior & Risks
- NULL write: redirects register to g_pNullDummy (64KB zeroed buffer)
- NULL read: injects dummy surface/buffer for NULL registers
- DANGER: VEH write fixes to g_pNullDummy can corrupt shared allocator state
- EBX=0x003F003F ("??") crash = garbage from corrupted Python parse tree

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
| 0x005b17f0 | Ship network state writer | Writes pos/orient/subsys/weapons to stream; VEH skips loops |
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
- C-side scheduling (ddraw_main.c:1581-1687) is REDUNDANT
- Native C++ NewPlayerInGameHandler (FUN_006a1e70) already calls InitNetwork
- C-side `already` check only looks at PENDING entries; fired entries get re-scheduled
- FIX: Remove C-side InitNetwork scheduling entirely

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
- PatchSkipRendererSetup REMOVED; PatchRendererMethods ACTIVE (stubs 3 methods)
- Crash: FUN_007d1ff0 copies 59 DWORDs from Device7 into texture fmt mgr
- Our vtable ptr at Device7+0 misinterpreted as caps data -> EIP=0 in FUN_007ccd10
- FUN_007c4850 (at 0x007C4879) = logging helper, NOT crash source
- FIX: Fill _niPadding with D3DCAPS7 data, OR re-enable PatchSkipRendererSetup

### SOLVED: Dev_GetDirect3D Returns NULL (Previous Pipeline Crash)
- Fixed by adding ProxyD3D7* back-ref to ProxyDevice7

### SOLVED: ProxyDevice7 Heap Over-Read (Current Pipeline Crash, 2026-02-09)
- See [renderer-device7-overread.md](renderer-device7-overread.md) for full analysis
- FUN_007d1ff0 copies 59 DWORDs (236 bytes) FROM Device7 into texture format manager
- Our ProxyDevice7 is only 20 bytes -> reads 216 bytes of heap garbage
- Garbage propagates as corrupted vtable ptrs -> EIP=0x0 crash in FUN_007ce9c0
- **FIX: Enlarge ProxyDevice7 to >= 256 bytes, zero-initialized**
- Zero-init is safe: NI treats zero as NULL ptrs / disabled features

### Patch Removal Recommendations (for full pipeline restoration)
- **REMOVE PatchSkipRendererSetup** - SAFE after Device7 size fix (confidence: HIGH)
- **REMOVE PatchSkipDeviceLost** - SAFE: Surf_IsLost returns DD_OK, never "lost" (HIGH)
- **KEEP PatchRendererMethods (FUN_007e8780)** - frustum calc reads this+0x190 (NULL) (HIGH)
- **KEEP PatchRendererMethods (FUN_007c16f0)** - SetCameraData called in ctor, before pipeline (MED)
- **EVALUATE PatchRendererMethods (FUN_007c2a10)** - accesses 0xC4 pipeline, may work (MED)
- **EVALUATE PatchRenderTick** - may work with pipeline, but unnecessary CPU cost (LOW)

## Subsystem Creation Chain (2026-02-09)
- See [subsystem-creation-analysis.md](subsystem-creation-analysis.md) for full analysis
- PatchSubsystemHashCheck ALREADY bypasses hash when subsystem list is NULL

## SOLVED: Compressed Vector Read Cascade Crash (2026-02-09)
- See [compressed-vector-crash.md](compressed-vector-crash.md) for full analysis
- FUN_006d2eb0 / FUN_006d2fd0: read compressed vectors via 4 vtable calls
- If vtable corrupted: VEH recovers from each call but CANNOT clean callee-clean stack params
- 24 bytes stranded on stack -> misaligned ESP -> second call uses wrong this ptr -> fatal crash
- FIX: PatchCompressedVectorRead validates vtable in .rdata range before entering function
- KEY LESSON: VEH cannot safely recover from callee-clean vtable calls (stdcall/thiscall)

## CRITICAL: Wire Format Opcode Table CORRECTED (2026-02-09)
- See [torpedo-beam-network.md](torpedo-beam-network.md) for full corrected table
- Spec was WRONG about opcodes 0x07-0x0B. Switch table at 0x0069F534 (base=opcode-2)
- 0x09 is NOT TorpedoFire, it's StopFiringAtTarget (event forward 0x008000DB)
- 0x0A is NOT BeamFire, it's SubsystemStatusChanged (event forward 0x0080006C)
- ACTUAL TorpedoFire = opcode 0x19, sent by FUN_0057cb10 (TorpedoSystem::SendFireMessage)
- ACTUAL BeamFire = opcode 0x1A, sent by FUN_00575480 (PhaserSystem::SendFireMessage)
- Opcodes 0x07-0x0B, 0x0E-0x10, 0x1B all go through FUN_0069FDA0 (generic event forward)
- Torpedoes are game OBJECTS: fire creates projectile, replicated via 0x02/0x03 (ObjectCreate)
