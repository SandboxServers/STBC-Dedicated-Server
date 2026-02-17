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
- See [docs/gamespy-crypto-analysis.md](../../docs/gamespy-crypto-analysis.md) for challenge-response crypto
- GameSpy object: 0xF4 bytes at UtopiaModule+0x7C, vtable PTR_FUN_00895564
- QR (heartbeat) code EXISTS but is **DEAD CODE** -- qr_init at 0x006ab558 never called
- Static qr_t at 0x0095a740 is zeroed, active flag=0, master sockaddr zeroed
- Game name: "bcommander", Secret key: "Nm3aZ9", Master port: 27900 (UDP heartbeat), 28900 (TCP browser)
- Default master: stbridgecmnd01.activision.com, override via masterserver.txt
- LAN: UDP broadcast to 255.255.255.255, query format `\status\`, port range scan
- **Crypto**: Modified RC4 (PRGA uses `i = data[n]+1+i` instead of `i = i+1`) + standard Base64 encoding
- Fully reimplementable; see crypto analysis doc for standalone C code

## Cut Content Analysis (2026-02-16)
- See [docs/cut-content-analysis.md](../../docs/cut-content-analysis.md) for full report
- **TestMenuState** at g_Clock+0xB8: set to 2 to enable all debug cheats (god mode, kill target, quick repair)
- **TGConsole**: Full Python REPL, TopWindow.ToggleConsole(), TGConsole.EvalString()
- **PlacementEditor**: In-game level editor with save/load (requires edit mode)
- **Self-destruct**: Ctrl+D bound, SELF_DESTRUCT_REQUEST_MESSAGE exists (0 xrefs), handler commented out
- **Tractor docking**: 6 modes (HOLD/TOW/PULL/PUSH/DOCK_STAGE_1/DOCK_STAGE_2), ship+0x1E6=IsDocked
- **Friendly fire**: Full penalty system with progressive warnings + game-over threshold
- **Opcodes 0x04/0x05 truly dead**; 0x17=DeletePlayerUI, 0x18=PlayerLeftText, 0x1C=SendObjectResponse

## Repair System & Tractor Beam (2026-02-17)
- See [docs/repair-tractor-analysis.md](../../docs/repair-tractor-analysis.md) for full analysis
- **RepairSubsystem**: vtable 0x00892e24, size 0xC0, ctor FUN_00565090
- **NO queue size limit** (OpenBC claims 8 -- WRONG); uses dynamic pool allocator
- Queue is doubly-linked list at +0xA8(count)/+0xAC(head)/+0xB0(tail)
- AddSubsystem (FUN_00565520): rejects duplicates, rejects condition<=0.0 (destroyed)
- Repair() (FUN_0056bd90): `condition += repairPoints / repairComplexity`
- RepairSubsystemProperty: +0x4C=MaxRepairPoints(float), +0x50=NumRepairTeams(int)
- RepairSubsystem::Update at 0x005652a0 is **UNDEFINED IN GHIDRA** (vtable slot 25)
- **TractorBeamSystem**: vtable 0x00893794, size 0x100, ctor FUN_00582080
- 6 modes: HOLD(0)/TOW(1)/PULL(2)/PUSH(3)/DOCK1(4)/DOCK2(5); default=1(TOW)
- Mode field at +0xF4; AI config mode at +0xA0
- TractorBeamSystem::Update at 0x00582460 also **UNDEFINED IN GHIDRA**
- **TractorBeamProjector**: vtable 0x008936f0, size 0x100, ctor FUN_0057ec70
- Projector::Update (FUN_00581020): caches maxDamage at +0xA0
- EnergyWeaponProperty: +0x68=MaxDamage, +0x7C=MaxDamageDistance
- Galaxy: forward tractor MaxDamage=50.0, aft=80.0, MaxDamageDistance=118.0
- FriendlyTractorTime/Warning/Max at UtopiaModule +0x4C/+0x50/+0x54

## Weapon Firing Mechanics (2026-02-17)
- See [docs/weapon-firing-mechanics.md](../../docs/weapon-firing-mechanics.md) for full analysis
- **Class hierarchy**: Weapon -> EnergyWeapon -> PhaserBank; Weapon subclass -> TorpedoTube
- **PhaserBank vtable**: 0x00893194, EnergyWeapon: 0x008930D8, TorpedoTube: 0x00893630
- **Key vtable slots**: +0x78=StopFiring, +0x7C=Fire, +0x84=CanFire, +0x90=SetPowerSetting
- **Phaser charge**: `charge += recharge_rate * power_level * dt * power_mult [* AI_mult]`
- **Phaser discharge**: intensity-dependent (LOW/MED/HIGH) at DAT_0089317C/80/84
- **Property layout**: +0x68=MaxCharge, +0x6C=RechargeRate, +0x70=DischargeRate, +0x74=MinFiringCharge
- **Weapon +0x88**: is_firing flag; +0xA0: charge_level(phaser) / num_ready(torpedo)
- **Torpedo reload**: FUN_0057D8A0; ammo check + num_ready++; timer array at +0xAC
- **Type switch**: FUN_0057B230; unloads all tubes, clears timers; immediate=1 -> NO instant reload
- **Type switch "lockout"**: implicit (tubes empty after switch, must wait ReloadDelay)
- **TorpedoTube::Fire**: FUN_0057C9E0; checks CanFire, decrements num_ready, posts ET_TORPEDO_FIRED
- **Network**: 0x19=TorpedoFire(FUN_0057CB10), 0x1A=BeamFire(FUN_005762B0)
- **WeaponSystem::UpdateWeapons**: FUN_00584930; per-frame tick, iterates weapons, calls TryFire

## Cloaking Device State Machine (2026-02-17)
- See [docs/cloaking-state-machine.md](../../docs/cloaking-state-machine.md) for full analysis
- Vtable 0x00892EAC, ctor FUN_00566d10, tick FUN_0055e500
- **4 active states**: DECLOAKED(0), CLOAKING(2), CLOAKED(3), DECLOAKING(5)
- States 1 and 4 are GHOST STATES (checked but never assigned -- dead code)
- OpenBC spec is WRONG: claims states 0,1,2,3 -- actual values are 0,2,3,5
- Timer at +0xB4, state at +0xB0, tryingToCloak at +0xAD, isFullyCloaked at +0xAC
- CloakTime (DAT_008e4e1c) and ShieldDelay (DAT_008e4e20) are CLASS-LEVEL GLOBALS
- Shields: NOT zeroed during cloak; subsystem disabled, HP preserved, re-enable after ShieldDelay
- Weapons: NOT directly gated in C++; checked at AI/Python level via IsCloaked()
- Network: 0x40 flag serializes +0x9C (isOn), client runs local state machine
- Energy failure: auto-decloak when efficiency < DAT_0088d4ec threshold
- ET_CLOAKED_COLLISION event exists but is DEAD CODE (0 xrefs)

## Shield System (2026-02-17)
- See [docs/shield-system.md](../../docs/shield-system.md) for full analysis
- ShieldClass: vtable 0x00892f34, size 0x15C, ctor FUN_0056a000
- ShieldProperty: vtable 0x00892fc4, size 0x88, ctor FUN_0056b970
- **6 facings**: FRONT(0)/REAR(1)/TOP(2)/BOTTOM(3)/LEFT(4)/RIGHT(5); NO_SHIELD=-1
- Facing determined by max-component projection of ship-local normal (FUN_0056a8d0)
- curShields[6] at shieldClass+0xA8; maxShields[6] at property+0x60; chargePerSec[6] at property+0x78
- **Key constant**: DAT_0088bacc = 1/6 (0.16667) -- per-facing share
- **Area damage**: equal 1/6 distribution, per-facing clamp, overflow to hull (FUN_00593c10)
- **Directed damage**: shield zone intersection via FUN_004b4b40, deferred hit list processing
- **Recharge**: BoostShield (FUN_0056a420) converts power to HP using chargePerSecond
- **Event-driven**: HandleSetShieldState at 0x0056aae0, events 0x0080006d-0x00800071
- **Cloak interaction**: shield +0x9C set to 0 after ShieldDelay(1.0s), HP preserved, re-enabled on decloak
- **Unanalyzed range**: 0x0056a210-0x0056aad0 (event handlers, shield tick, RedistributeShields)
