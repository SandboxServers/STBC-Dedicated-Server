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
- See [transport-layer.md](transport-layer.md) for FULL transport layer: 7 factory types, wire formats, fragments
- See [torpedo-beam-network.md](torpedo-beam-network.md) for corrected opcode table
- See [swig-method-tables.md](swig-method-tables.md) for App/Appc SWIG method table analysis (3990 entries at 0x008e6438)
- See [complete-opcode-table.md](complete-opcode-table.md) for FULL verified opcode table (all 41 entries + Python msg types)
- See [tgmessage-wire-format.md](tgmessage-wire-format.md) for TGMessage Python script message framing

## TGMessage Routing System (2026-02-17, COMPLETE)
- See [docs/tgmessage-routing-analysis.md](../../docs/tgmessage-routing-analysis.md) for FULL analysis
- **TWO SEPARATE TYPE SYSTEMS**: Transport types (7 registered, 256 max) vs Game opcodes (in payload)
- **Transport factory table**: 256 entries at 0x009962d4, indexed by `byte & 0xFF`
- **Stock transport types**: 0=game_msg, 1=ACK, 2=keepalive, 3=connect, 4=disconnect, 5=heartbeat, 0x32=base
- **RELAY-ALL**: Host forwards ALL messages opaquely via FUN_006b51e0 (unconditional broadcast)
- **No type inspection on relay**: FUN_006bc6a0 (factory) copies payload via BufferCopy without examining
- **No bounds check on dispatch**: C++ switch at 0x0069f2a0 has NO default case; unknown opcodes fall through silently
- **Star topology**: All client-to-client traffic goes through host; no direct peer connections
- **MAX_MESSAGE_TYPES = 0x2B** (43); Python types: CHAT=0x2C, SCORE=0x37, END_GAME=0x38
- **Mod compatibility**: Custom types (KM=205, BCR=53-57) work because C++ ignores unknown opcodes
- **"NoMe" group**: All peers except self; routing only, no content filtering
- **TGNetwork_RegisterMessageType** (0x005e4860): registers TRANSPORT types, not game opcodes; never called from stock Python
- **Key relay functions**: FUN_006b51e0=BroadcastToOthers, FUN_006b4ec0=SendToGroupMembers
- **Key receive path**: FUN_006b5c90=ProcessIncoming -> factory lookup -> FUN_006b6ad0=QueueForDispatch

## RTTI / Type System (2026-02-15)
- NO MSVC RTTI (compiled /GR-); uses NiRTTI hash table at DAT_009a2b98
- 117 factory registrations (113 Ni* + 2 TG* + 2 DD*); ~670 classes total
- Full catalogs: [docs/rtti-class-catalog.md], [docs/nirtti-factory-catalog.md]

## NetImmerse Vtable Map (2026-02-15)
- See [docs/netimmerse-vtables.md](../../docs/netimmerse-vtables.md) for FULL analysis
- **CRITICAL**: NI 3.1 slot 0 = GetRTTI (NOT dtor); slot 10 = dtor (+0x28)
- NiObject:12 | NiObjectNET:12 | NiAVObject:39 | NiNode:43 | NiGeometry:64 | NiTriShape:68

## BREAKTHROUGH: Black Screen SOLVED
- Fix: Replace Mission1.InitNetwork with functional Appc API version
- Root cause: TGMessage_Create() returns raw SWIG pointer, not shadow class
- Client now sees ship selection screen and can fly in-game

## CRITICAL: 0x0097FA88 is IsClient, NOT IsHost (2026-02-08)
- 0x0097FA88=IsClient(0=host), 0x0097FA89=IsHost(1=host), 0x0097FA8A=IsMultiplayer
- See [stock-baseline-analysis.md](stock-baseline-analysis.md) for full evidence

## Power Distribution Network Path (2026-02-18, COMPLETE)
- **NO dedicated network message** for power slider changes
- ET_SUBSYSTEM_POWER_CHANGED (0x0080008c) is LOCAL ONLY -- NOT in MP forwarding table
- Power percentages propagate via **StateUpdate 0x1C flag 0x20** (PoweredSubsystem::WriteState/ReadState)
- WriteState: if `isOwnShip==0`, writes `(int)(powerPercentageWanted * 100.0)` as byte
- ReadState: reconstructs via `byte * 0.01f`, applies via SetPowerPercentageWanted (FUN_00562430)
- Sign bit encoding: negative byte = subsystem OFF, positive = ON
- Resolution: 1% steps, range 0-125%, ~1-2s convergence via round-robin
- Host does NOT validate power percentages -- applies whatever client sends
- See [docs/power-system.md] "Multiplayer Network Propagation" section
- Key functions: FUN_00562960 (WriteState), FUN_005629d0 (ReadState), FUN_00562430 (setter)
- EngPowerCtrl: FUN_0054dde0 (HandlePowerChange), FUN_0054e690 (posts 0x0080008c event)

## 0x1C State Update & Subsystem Wire Format (COMPLETE 2026-02-18)
- See [docs/stateupdate-subsystem-wire-format.md](../../docs/stateupdate-subsystem-wire-format.md) for FULL analysis
- **Flag 0x20 = round-robin subsystem health**: walks ship+0x284 linked list (top-level only)
- **NO fixed index table**: wire byte positions = linked list order = hardpoint AddToSet order
- **Children REMOVED from 0x284**: individual weapons/engines become children of parent systems
- **Variable-length per-subsystem**: base writes condition byte + recursively writes children
- **3 WriteState variants**: Base(0x0056d320), PoweredSS(0x00562960), PowerSS(0x005644b0)
- **10-byte budget per tick**: round-robin continues across ticks via per-object cursor at tracking+0x30/+0x34
- **Key linking function**: FUN_005b5030 (LinkSubsystemToParent) removes weapons/engines from 0x284
- **Sovereign has 11 top-level subsystems** (not 33; 33 includes children)

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
| 0x005b17f0 | Ship_WriteStateUpdate | Writes pos/orient/subsys/weapons to stream |
| 0x005b21c0 | Ship_ReadStateUpdate | Receives and applies state update from network |
| 0x005b3e20 | Ship_LinkAllSubsystemsToParents | Post-creation: moves children from 0x284 to parent arrays |
| 0x005b3e50 | Ship_AddSubsystemToLists | Adds subsystem to 0x284 (+ optionally 0x29C) |
| 0x005b5030 | Ship_LinkSubsystemToParent | Identifies parent, AddChild, removes from 0x284 |
| 0x0056c5c0 | ShipSubsystem_AddChildSubsystem | Grows child array at +0x20, increments +0x1C |
| 0x0056d320 | ShipSubsystem_WriteState (base) | Condition byte + recurse children |
| 0x00562960 | PoweredSubsystem_WriteState | Base + on/off bit + count byte |
| 0x005644b0 | PowerSubsystem_WriteState | Base + 2 power pct bytes |
| 0x0056c310 | ShipSubsystem_GetCondition | Returns property+0x20 (float) or 1.0 |
| 0x0056c570 | ShipSubsystem_GetChildSubsystem | Returns array[index] from +0x20 |
| 0x004360c0 | GetBoundingBox | vtable[0xE8], computes AABB from NiBound; see [bounding-box-crash.md](bounding-box-crash.md) |
| 0x00419960 | GetModelBound | vtable[0xE4], returns NiBound*; NOT in Ghidra func DB (tiny function) |
| 0x006d2eb0 | ReadCompressedVector3 | 3 vtable calls + decode; see [compressed-vector-crash.md] |
| 0x006d2fd0 | ReadCompressedVector4 | Same pattern, 4 params; patched with vtable validation |
| 0x006cefe0 | TGBufferStream ctor | Derived; vtable=PTR_LAB_00895c58; base=FUN_006d1fc0 |
| 0x006b4c10 | TGNetwork::SendTGMessage | __thiscall(this, targetID, msg, opt); 0=broadcast |
| 0x006b4de0 | TGNetwork::SendTGMessageToGroup | __thiscall(this, groupName, msg) |
| 0x006b4ec0 | TGNetwork::SendToGroupMembers | Iterates group, sends to each valid peer |
| 0x006b5080 | TGNetwork::SendHelper | Queues msg to peer, manages reliable seq counters |
| 0x006b82a0 | TGMessage ctor | Size 0x40, vtable 0x008958d0; GetType()=0x32 |
| 0x006b8340 | TGMessage::WriteToBuffer | Serializer: type + flags_len + [seq] + payload |
| 0x006b83f0 | TGMessage::ReadFromBuffer | Factory/deserializer for type 0x32 |
| 0x006b8530 | TGMessage::GetData | Returns +0x04 (data_ptr), optionally writes +0x08 (len) |
| 0x006b89e0 | TGMessage::GetBufferStream | Returns singleton at 0x996810 with msg data |
| 0x006b8a00 | TGMessage::SetDataFromStream | Copies stream buffer into message data |
| 0x006b4560 | TGWinsockNetwork::Update | Main loop: send states, process incoming, post events |
| 0x006b52b0 | TGNetwork::GetNextReceivedMsg | Dequeues with reliable ordering + reassembly |
| 0x006b70d0 | TGNetwork::AddGroup | Registers named group for SendTGMessageToGroup |
| 0x0069e590 | MultiplayerGame ctor | Creates "NoMe"/"Forward" groups, registers all handlers |
| 0x005b21c0 | ShipStateUpdateReceiver | Processes 0x1C packets; calls FUN_006d2eb0/FUN_006d2fd0 |
| 0x005652a0 | RepairSubsystem::Update | vtable[25]; repair rate + multi-team loop (raw disasm) |
| 0x00565520 | RepairSubsystem::AddSubsystem | Rejects dupes + condition<=0; no size limit |
| 0x0056bd90 | ShipSubsystem::Repair | condition += repairPoints / repairComplexity |
| 0x00582460 | TractorBeamSystem::Update | vtable[25]; sums MaxDamage, resets forceUsed (raw disasm) |
| 0x00582280 | TractorBeamSystem::SumProjectorMaxDamage | Iterates children, sums property+0x78 |
| 0x005822d0 | TractorBeamSystem::GetForceRatio | Returns +0xFC / +0xF8 |
| 0x0057f8c0 | TractorBeamProjector::FireTick | Mode switch + force accumulation |
| 0x00580f50 | ComputeTractorForce | maxDamage * condPct * distRatio * dt |
| 0x00561180 | ImpulseEngineSubsystem::Update | vtable[25]; applies tractor drag (raw disasm) |
| 0x00561230 | ComputeEffectiveMaxSpeed | Tractor drag: effective *= (1.0-forceRatio) |
| 0x00561050 | ImpulseEngineSubsystem::ctor | vtable 0x00892d10, size 0xBC |

## Solved Crashes & Fixes (see individual memory files for details)
- **0x1C bad pointer**: TGLFile::FindEntry NULL this -> code cave fix. See [tgl-null-crash.md]
- **Compressed vector crash**: corrupted vtable -> PatchCompressedVectorRead. See [compressed-vector-crash.md]
- **Boot player kick**: subsystem hash=0 false positive -> PatchSubsystemHashCheck. See [boot-player-analysis.md]
- **InitNetwork dupes**: see [initnet-duplicates.md]; **Collision damage**: see [collision-damage.md]
- **Ship+0x140 NULL**: headless server Path 2, registry empty. See [ship-0x140-analysis.md]

## Key Pipelines (see individual memory files)
- Renderer: [renderer-pipeline-analysis.md]; NIF loading: [nif-loading-pipeline.md]
- Ship creation: [ship-creation-callchain.md]; Subsystems: [subsystem-creation-analysis.md]
- Ship Creation: FUN_0069f620 -> FUN_005a1f50 -> FUN_005b0e80 (vtable entry, InitObject)
- **ObjCreate unknown species**: relay AFTER local create; empty hull persists; NO rejection. See [docs/objcreate-unknown-species-analysis.md]
- TG_CallPythonFunction (FUN_006f8ab0): __import__ + getattr + PyObject_CallObject
- Wire format: TorpedoFire=0x19, BeamFire=0x1A. See [complete-opcode-table.md]

## GameSpy & LAN Discovery (2026-02-16)
- Game "bcommander", key "Nm3aZ9", master port 27900/28900; QR code is DEAD CODE
- LAN: UDP broadcast `\status\` to 255.255.255.255:22101-22201
- Crypto: Modified RC4 + Base64. See [docs/gamespy-master-server.md], [docs/gamespy-crypto-analysis.md]

## Cut Content (2026-02-16)
- See [docs/cut-content-analysis.md](../../docs/cut-content-analysis.md)
- TestMenuState(g_Clock+0xB8)=2: all debug cheats. TGConsole: Python REPL. PlacementEditor.
- Self-destruct: Ctrl+D bound, handler commented out. Tractor docking: 6 modes, ship+0x1E6=IsDocked
- Friendly fire: progressive penalties. Opcodes 0x04/0x05 truly dead.

## Repair System & Tractor Beam (2026-02-17, COMPLETE)
- See [docs/repair-tractor-analysis.md](../../docs/repair-tractor-analysis.md) for full verified analysis
- **RepairSubsystem**: vtable 0x00892e24, size 0xC0, ctor FUN_00565090
- **RepairSubsystem::Update** at 0x005652a0: DECOMPILED via raw objdump (undefined in Ghidra)
- **NO queue size limit** (OpenBC claims 8 -- WRONG); uses dynamic pool allocator
- Queue is doubly-linked list at +0xA8(count)/+0xAC(head)/+0xB0(tail)
- **Repair formula**: `MaxRepairPoints * repairSystemHealthPct * dt / min(queueCount,numTeams) / RepairComplexity`
- **Multiple subsystems repaired simultaneously** (up to NumRepairTeams) -- OpenBC "only top priority" is WRONG
- Repair system's OWN health scales output (damaged repair bay = slower repairs)
- RepairSubsystemProperty: +0x4C=MaxRepairPoints(float), +0x50=NumRepairTeams(int)
- **TractorBeamSystem**: vtable 0x00893794, size 0x100, ctor FUN_00582080
- **TractorBeamSystem::Update** at 0x00582460: DECOMPILED via raw objdump
- 6 modes: HOLD(0)/TOW(1)/PULL(2)/PUSH(3)/DOCK1(4)/DOCK2(5); default=1(TOW)
- Mode at +0xF4; +0xF8=totalMaxDamage (sum all projectors); +0xFC=forceUsed (reset each tick)
- **Tractor drag**: multiplicative `effectiveSpeed *= (1.0 - forceUsed/totalMaxDamage)` -- OpenBC additive formula WRONG
- **NO tractor damage**: none of 5 mode handlers call any damage function -- OpenBC claim NOT FOUND
- **Distance falloff**: `min(1.0, maxDamageDistance/beamDistance)` -- new finding, not in OpenBC
- **Health scaling**: force *= systemCondPct * projectorCondPct -- new finding
- **ImpulseEngineSubsystem**: vtable 0x00892d10, ctor FUN_00561050, size 0xBC
- +0xA8=TractorBeamSystem* (set via SetTractorBeamSystem), couples tractor to engine
- ComputeEffectiveMaxSpeed at FUN_00561230: applies tractor ratio to all 4 stats
- **EnergyWeaponProperty CORRECTED**: +0x68=MaxCharge, +0x78=MaxDamage, +0x7C=MaxDamageDistance
- FriendlyTractorTime/Warning/Max at UtopiaModule +0x4C/+0x50/+0x54

## Fragmented Reliable ACK Bug (2026-02-19, Ghidra-VERIFIED)
- See [docs/fragmented-ack-bug.md](../../docs/fragmented-ack-bug.md) for FULL analysis
- **ACK factory at 0x006bd1f0**: NOT in Ghidra func DB; decompiled via raw objdump
- Factory correctly deserializes seq/is_fragmented/is_below_0x32/frag_idx from wire
- HandleACK (0x006b64d0): 4-field matching logic is provably correct
- ProcessIncomingMessages (0x006b5c90): ACK gets is_reliable=0, skips ACK-of-ACK creation
- QueueForDispatch (0x006b6ad0): ACK routes to unreliable queue (this+0x70), no seq filtering
- DispatchReceivedMessages (0x006b5f70): type 1 dispatches to HandleACK correctly
- **ALL static code paths verified correct -- bug requires runtime instrumentation to diagnose**
- ACK-outbox has retransmit limit of 3 sends per ACK entry
- TGHeaderMessage: vtable 0x008959ac, size 0x44, GetType()=0x01, ctor 0x006bd120

## Ghidra Undefined Code Workaround (2026-02-17)
- Some vtable entries point to addresses NOT in Ghidra's function database
- All Ghidra MCP calls (decompile/disassemble/rename/set_prototype) fail on these
- **Workaround**: `i686-w64-mingw32-objdump -d -M intel --start-address=X --stop-address=Y stbc.exe`
- PE offset calc: file_offset = (VA - section_VA) + section_file_offset
- Successfully decompiled: RepairSubsystem::Update, TractorBeamSystem::Update, ImpulseEngine::Update, ComputeEffectiveMaxSpeed
- DAT_0088b9c0 = **1.0 as DOUBLE** (8 bytes) -- `fcomp QWORD PTR` reads double, not float

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
- ShieldClass: vtable 0x00892f34, size 0x15C; ShieldProperty: vtable 0x00892fc4, size 0x88
- **6 facings**: FRONT(0)/REAR(1)/TOP(2)/BOTTOM(3)/LEFT(4)/RIGHT(5); NO_SHIELD=-1
- curShields[6] at +0xA8; maxShields[6] at property+0x60; chargePerSec[6] at property+0x78
- Area damage: 1/6 per-facing, overflow to hull; Directed: shield zone intersection
- Cloak: shield disabled (HP preserved), re-enabled after ShieldDelay(1.0s) on decloak

## Collision Detection System (2026-02-17)
- See [docs/collision-detection-system.md](../../docs/collision-detection-system.md) for full analysis
- 3-tier: sweep-and-prune -> bounding sphere -> per-type narrow; CLIENT-AUTHORITATIVE
- ProximityManager vtable 0x008942D4; CheckCollision FUN_005671d0 (79K calls/session)
- Energy: `clamp((force/mass/numContacts)*SCALE+OFFSET, 0, 0.5) * 6000`

## CompressedFloat16 (CF16) Encoding (2026-02-17, CORRECTED)
- See [docs/cf16-precision-analysis.md](../../docs/cf16-precision-analysis.md) for full analysis
- **Encoder**: FUN_006d3a90 (__fastcall); **Decoder**: FUN_006d3b30 (__cdecl)
- Format: [sign:1][scale:3][mantissa:12]; 8 log scales covering [0, 10000)
- Constants: BASE=0.001 (DAT_00888b4c), MULT=10.0 (DAT_0088c548)
- **ENC_SCALE=4095.0** (DAT_00895f50), **DEC_SCALE=float32(1/4095)** (DAT_00895f54)
- NOTE: Decoder uses 1/4095, NOT 1/4096; mantissa 4095 = top of range (symmetric)
- Encoder truncates (floor), decoder divides by 4095: always slightly LOSSY
- **Explosion sender**: FUN_00595c60; writes opcode, objID, CV4 pos, CF16 **radius**, CF16 **damage**
- **Explosion receiver**: 0x006A0080; field order is radius THEN damage (NOT damage then radius)
- ExplosionDamage struct (0x38): +0x14=radius, +0x18=radius^2, +0x1C=damage
- **Mod damage identifiers DO NOT survive CF16**: 15.0->14.99, 2063.0->2061.54 (always rounds down)
