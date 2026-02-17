# Game Reverse Engineer Memory

## Project: STBC Dedicated Server (Star Trek: Bridge Commander)
- DDraw proxy DLL (`ddraw_main.c`, ~3600 lines C), cross-compiled from WSL2
- NetImmerse 3.1 engine, Winsock UDP, embedded Python 1.5.2 (SWIG 1.x)
- stbc.exe: 32-bit Windows, base 0x400000, ~5.9MB

## State Dump Baseline (2026-02-12)
- Stock-dedi: CurrentGame transitions None->SWIG object->None over lifecycle
- Custom server: raw SWIG ptr (wrapper mismatch) - fixed with App compat wrappers

## Key Architecture Discoveries
- See [architecture.md](architecture.md) for detailed notes
- See [crash-analysis.md](crash-analysis.md) for InitNetwork crash chain analysis
- See [ebp-corruption-crash.md](ebp-corruption-crash.md) for EBP/RunPyCode crash (SOLVED 2026-02-15)
- See [open-source-analysis.md](open-source-analysis.md) for dependency/legal analysis
- See [client-join-flow.md](client-join-flow.md) for post-checksum message sequence
- See [stock-baseline-analysis.md](stock-baseline-analysis.md) for stock host vs our server comparison
- See [encryption-analysis.md](encryption-analysis.md) for TGNetwork encryption/cipher analysis
- See [torpedo-beam-network.md](torpedo-beam-network.md) for corrected opcode table
- See [swig-method-tables.md](swig-method-tables.md) for App/Appc SWIG method table analysis (3990 entries at 0x008e6438)
- See [complete-opcode-table.md](complete-opcode-table.md) for FULL verified opcode table (all 41 entries + Python msg types)

## RTTI / Type System (2026-02-15)
- **NO MSVC RTTI** for game/engine code (compiled with /GR-)
- Only 22 MSVC TypeDescriptors: all CRT/STL + `TGStreamException`
- Uses **NetImmerse NiRTTI**: custom factory hash table at DAT_009a2b98
- Registration pattern: `push factory_fn; push "ClassName"; call hash_insert`
- Example: FUN_007e3670 registers "NiNode" with factory FUN_007e5450
- ~670 unique C++ classes identified; 129 Ni*, 124 TG*, ~420 game-specific
- 114 TG classes have SWIG Python bindings (~1340 wrapper methods)
- Full catalog: [docs/rtti-class-catalog.md](../../docs/rtti-class-catalog.md)

## NiRTTI Factory Registration (COMPLETE, 2026-02-15)
- **117 classes** registered in DAT_009a2b98 hash table (113 Ni* + 2 TG* + 2 DD*)
- Full mapping: [docs/nirtti-factory-catalog.md](../../docs/nirtti-factory-catalog.md)
- Hash table: 37 buckets, 0xC-byte linked-list nodes {className, factoryFn, next}
- Vtable at PTR_FUN_0088b7c4: hash(+0x04), compare(+0x08), setEntry(+0x0C), deleteEntry(+0x10)
- Temp vtable PTR_LAB_0088b7d8 used during construction, then swapped to final
- ALL registrations use identical template code (100% consistent pattern)
- TG classes (TGDimmerController, TGFuzzyTriShape) share the SAME hash table as Ni classes
- Consumer: FUN_008176b0 (NiStream::LoadObject) reads NIF class names, looks up factory
- Error on lookup failure: "NiStream: Unable to find loader for..."
- Guard flags span 0x0098d298 - 0x009b32f0 (one byte per class, set to 1 after registration)

## NetImmerse Vtable Map (2026-02-15)
- See [docs/netimmerse-vtables.md](../../docs/netimmerse-vtables.md) for FULL analysis
- **CRITICAL**: NI 3.1 vtable slot 0 = GetRTTI (NOT destructor like Gb 1.2)
- Destructor (scalar_deleting_dtor) is at slot 10 (+0x28)
- Slot 11 (+0x2C) = 0x0040da50 = never-overridden no-op across ALL classes
- NiObject: 12 slots at 0x00898b94 | NiObjectNET: 12 slots at 0x00898c48
- NiAVObject: 39 slots at 0x00898ca8 | NiNode: 43 slots at 0x00898f2c
- NiGeometry: 64 slots at 0x00899164 | NiTriShape: 68 slots at 0x00899264
- Constructor chain: NiObject(007d87a0) -> NiObjectNET(007dac80) -> NiAVObject(007dc0c0)
- NiObjectNET adds ZERO new virtuals (same 12 as NiObject)
- NiAVObject adds 27 virtuals (slots 12-38), much more than Gb 1.2's ~14
- NiNode adds 4 (AttachChild/DetachChild/DetachChildAt/SetAt) at slots 39-42
- Vtable+0x28 = dtor pattern: `if(param&1) free(this)` = scalar_deleting_destructor

## BREAKTHROUGH: Black Screen SOLVED
- Fix: Replace Mission1.InitNetwork with functional Appc API version
- Root cause: TGMessage_Create() returns raw SWIG pointer, not shadow class
- Client now sees ship selection screen and can fly in-game

## CRITICAL: 0x0097FA88 is IsClient, NOT IsHost (2026-02-08)
- 0x0097FA88=IsClient(0=host), 0x0097FA89=IsHost(1=host), 0x0097FA8A=IsMultiplayer
- See [stock-baseline-analysis.md](stock-baseline-analysis.md) for full evidence

## 0x1C State Update & Subsystem Analysis (2026-02-09)
- See [subsystem-state-update-analysis.md](subsystem-state-update-analysis.md)
- FUN_005b17f0 flags: 0x20=subsystems, 0x80=weapons; ship+0x284=subsystem list
- Ship creation is client-side; server receives replication via FUN_0069f620

## Client Join Message Sequence (CRITICAL ORDER)
- 0x00 (settings) -> 0x01 (GameInit) -> 0x35 (MISSION_INIT) -> 0x37 (SCORE)
- See [client-join-flow.md](client-join-flow.md)

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

## Bug Fixes Summary
- **InitNetwork duplicates**: removed manual FUN_006a1e70 call (see [initnet-duplicates.md])
- **Collision damage missing**: call CreateSystemFromSpecies directly (see [collision-damage.md])
- **SetClass_Create raw string**: use Appc functional API directly (see [set-creation-analysis.md])

## Normal Host Flow for System Loading
- HandleHostStartClicked -> ET_START -> HandleStartGame -> ship select -> StartMission -> CreateSystemFromSpecies
- FUN_00504890 (ET_START): if MultiplayerGame exists, forwards to C++ handler; else sets up network fresh

## DISCONNECT ROOT CAUSE: TGBootPlayerMessage sub-cmd 4 (2026-02-09)
- See [boot-player-analysis.md](boot-player-analysis.md)
- Subsystem hash mismatch -> ET_BOOT_PLAYER -> kicks player
- Server has no ship objects -> hash=0 -> false positive kick
- FIX: PatchSubsystemHashCheck bypasses when list is NULL

## Renderer Pipeline (2026-02-09)
- See [renderer-pipeline-analysis.md](renderer-pipeline-analysis.md), [renderer-device7-overread.md](renderer-device7-overread.md)
- Active patches: PatchRendererMethods, PatchSkipDeviceLost, PatchRenderTick, PatchDeviceCapsRawCopy

## Subsystem Creation Chain (2026-02-09)
- See [subsystem-creation-analysis.md](subsystem-creation-analysis.md) for full analysis
- See [nif-loading-pipeline.md](nif-loading-pipeline.md) for full NIF->subsystem trace (2026-02-10)
- PatchSubsystemHashCheck ALREADY bypasses hash when subsystem list is NULL

## NIF Loading Pipeline Analysis (2026-02-10)
- See [nif-loading-pipeline.md](nif-loading-pipeline.md) for full call chain
- See [ship-creation-callchain.md](ship-creation-callchain.md) for full HOST-side analysis (2026-02-13)

## Ship+0x140 DamageTarget Analysis (2026-02-15)
- See [ship-0x140-analysis.md](ship-0x140-analysis.md) for full analysis
- +0x140 = NiNode for damage coordinate transforms; gate check in DoDamage (FUN_00594020)
- +0x128/+0x130 = damage handler array/count for ProcessDamage (FUN_00593e50)
- ALL set by FUN_00591b60 (SetModelName/vtable[0x128]) called via SetupModel SWIG wrapper
- TWO code paths: registry lookup (0x00980798) success -> sets +0x140; failure -> DOES NOT
- Root cause: headless server takes Path 2 (registry empty), +0x140 stays NULL

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

## Wire Format Opcode Table CORRECTED (2026-02-09)
- See [torpedo-beam-network.md](torpedo-beam-network.md), [complete-opcode-table.md](complete-opcode-table.md)
- TorpedoFire=0x19, BeamFire=0x1A (not 0x09/0x0A as spec said)

## GameSpy Master Server & LAN Discovery (2026-02-16)
- See [docs/gamespy-master-server.md](../../docs/gamespy-master-server.md) for complete analysis
- GameSpy object: 0xF4 bytes at UtopiaModule+0x7C, vtable PTR_FUN_00895564
- QR (heartbeat) code EXISTS but is **DEAD CODE** -- qr_init at 0x006ab558 never called
- Static qr_t at 0x0095a740 is zeroed, active flag=0, master sockaddr zeroed
- Game name: "bcommander", Secret key: "Nm3aZ9", Master port: 27900 (UDP heartbeat), 28900 (TCP browser)
- Default master: stbridgecmnd01.activision.com, override via masterserver.txt
- LAN: UDP broadcast to 255.255.255.255, query format `\status\`, port range scan

## Dump Baseline Delta (2026-02-12)
- See [stock-baseline-analysis.md](stock-baseline-analysis.md) for detailed 4-stage startup baseline
- Stock host: CurrentGame appears one stage BEFORE starting set/system creation
- Custom server bypasses canonical menu/start path (direct bootstrap)
