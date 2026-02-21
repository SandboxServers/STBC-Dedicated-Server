# Game Reverse Engineer Memory

## Project: STBC Dedicated Server (Star Trek: Bridge Commander)
- DDraw proxy DLL (`ddraw_main.c`, ~3600 lines C), cross-compiled from WSL2
- NetImmerse 3.1 engine, Winsock UDP, embedded Python 1.5.2 (SWIG 1.x)
- stbc.exe: 32-bit Windows, base 0x400000, ~5.9MB

## Key Architecture Discoveries (topic files)
- [architecture.md](architecture.md) - Detailed architecture notes
- [crash-analysis.md](crash-analysis.md) - InitNetwork crash chain
- [ebp-corruption-crash.md](ebp-corruption-crash.md) - EBP/RunPyCode crash (SOLVED)
- [open-source-analysis.md](open-source-analysis.md) - Dependency/legal analysis
- [client-join-flow.md](client-join-flow.md) - Post-checksum message sequence
- [stock-baseline-analysis.md](stock-baseline-analysis.md) - Stock host vs our server
- [encryption-analysis.md](encryption-analysis.md) - TGNetwork encryption/cipher
- [transport-layer.md](transport-layer.md) - FULL transport layer: 7 factory types, wire formats, fragments
- [torpedo-beam-network.md](torpedo-beam-network.md) - Corrected opcode table
- [swig-method-tables.md](swig-method-tables.md) - App/Appc SWIG method table (3990 entries)
- [complete-opcode-table.md](complete-opcode-table.md) - FULL verified opcode table (41 + Python)
- [tgmessage-wire-format.md](tgmessage-wire-format.md) - TGMessage Python script framing
- [main-loop-timing.md](main-loop-timing.md) - Main loop architecture, NiApp vtable, clock sources, frame budget scheduler

## TGMessage Routing (2026-02-17)
- See [docs/tgmessage-routing-analysis.md](../../docs/tgmessage-routing-analysis.md) for FULL analysis
- TWO SEPARATE TYPE SYSTEMS: Transport types (7 registered, 256 max) vs Game opcodes (payload)
- RELAY-ALL: Host forwards ALL messages opaquely (no whitelist, no type inspection)
- Star topology; MAX_MESSAGE_TYPES=0x2B(43); Python types: CHAT=0x2C, SCORE=0x37, END_GAME=0x38

## RTTI / Type System
- NO MSVC RTTI (/GR-); NiRTTI hash table at DAT_009a2b98; 117 factory registrations; ~670 classes
- Full catalogs: [docs/rtti-class-catalog.md], [docs/nirtti-factory-catalog.md]

## NI 3.1 Vtable Layout (CRITICAL)
- See [docs/netimmerse-vtables.md](../../docs/netimmerse-vtables.md)
- Slot 0 = GetRTTI (NOT dtor); slot 10 = dtor (+0x28)
- NiObject:12 | NiObjectNET:12 | NiAVObject:39 | NiNode:43 | NiGeometry:64 | NiTriShape:68

## CRITICAL FLAGS
- 0x0097FA88=IsClient(0=host), 0x0097FA89=IsHost(1=host), 0x0097FA8A=IsMultiplayer

## Main Loop & Timing (2026-02-20, COMPLETE)
- See [main-loop-timing.md](main-loop-timing.md) for full details
- PeekMessage busy loop (NiApplication pattern), NO Sleep in main loop
- NiClock at 0x0099c6b0: timeGetTime() * 0.001f, optional QPC
- Frame rate limiter (1/60) only gates rendering, NOT game logic
- Stock dedicated = 100% CPU busy loop; our proxy = SetTimer ~60Hz
- Frame budget scheduler (FUN_0046f420): 4 priority tiers, round-robin

## Power Distribution (2026-02-18)
- NO dedicated network message; propagates via StateUpdate 0x1C flag 0x20
- Sign bit encoding: negative byte = subsystem OFF; 1% resolution, 0-125% range
- See [docs/power-system.md] for full analysis

## 0x1C State Update & Subsystem Wire Format (2026-02-18)
- See [docs/stateupdate-subsystem-wire-format.md](../../docs/stateupdate-subsystem-wire-format.md)
- Flag 0x20 = round-robin subsystem health; linked list order (no fixed index)
- 3 WriteState variants: Base(0x0056d320), PoweredSS(0x00562960), PowerSS(0x005644b0)
- 10-byte budget per tick; Sovereign has 11 top-level (not 33)

## Client Join Sequence
- 0x00 (settings) -> 0x01 (GameInit) -> 0x35 (MISSION_INIT) -> 0x37 (SCORE)

## Memory Allocator
- FUN_00717840=NiAlloc (4-byte size header), FUN_00717960=NiFree, FUN_007179c0=NiRealloc
- Small allocs (<=0x80) use pool; large use CRT malloc; [ptr-4] corruption = fatal

## TGObject ID System (2026-02-20)
- ALL game objects (ships, subsystems, events) inherit from TGObject (FUN_006f0a70)
- `obj+0x04` = unique network object ID, auto-assigned from global counter DAT_0095b078
- `DAT_0099a67c` = global hash table: objectID -> object pointer
- `FUN_006f0ee0` = hash lookup by ID (returns object ptr or NULL)
- Subsystem IDs are NOT derived from ship base ID; they are sequential from global counter
- See [docs/repair-event-object-ids.md](../../docs/repair-event-object-ids.md)

## TGEvent System (2026-02-20)
- TGEvent (0x28 bytes, factory 0x101): +0x08=source ptr, +0x0C=dest ptr, +0x10=eventType
- TGCharEvent (0x2C bytes, factory 0x10C): extends TGEvent, +0x28=charData (int)
- FUN_006d6270=SetSource(+0x08), FUN_006d62b0=SetDest(+0x0C)
- WriteToStream: writes factoryType, eventType, *(source+0x04), *(dest+0x04)
- HostEventHandler (0x006a1150): serializes events as opcode 0x06 PythonEvent
- SUBSYSTEM_HIT=0x0080006B (TGCharEvent), ADD_TO_REPAIR_LIST=0x008000DF (TGEvent)

## Key Functions
| Address | Name | Role |
|---------|------|------|
| 0x006a1b10 | ChecksumCompleteHandler | Sends 0x00 + 0x01 |
| 0x006a1e70 | NewPlayerInGameHandler | InitNetwork + replicates objects |
| 0x00504c10 | MW::ReceiveMessageHandler | Client: dispatches 0x00/0x01/0x16 |
| 0x0069f620 | MP game object processor | Deserializes game objects from network |
| 0x006d1e10 | TGLFile::FindEntry | NULL this -> patched |
| 0x005b17f0 | Ship_WriteStateUpdate | Pos/orient/subsys/weapons to stream |
| 0x005b21c0 | Ship_ReadStateUpdate | Receives state update |
| 0x005b3e20 | Ship_LinkAllSubsystemsToParents | Moves children from 0x284 to parents |
| 0x005b5030 | Ship_LinkSubsystemToParent | Identifies parent, AddChild |
| 0x006b4c10 | TGNetwork::SendTGMessage | __thiscall(this, targetID, msg, opt) |
| 0x006b4560 | TGWinsockNetwork::Update | Main loop: send/receive/events |
| 0x0069e590 | MultiplayerGame ctor | "NoMe"/"Forward" groups, all handlers |
| 0x0043b4f0 | UtopiaApp::MainTick | Clock, timers, events, scheduler, scene |
| 0x006cdd20 | UtopiaApp::OnIdle | UpdateTime, frame limiter, sound, states |
| 0x007b8790 | NiApp::Process | PeekMessage loop (NOT overridden by BC) |
| 0x0071a9e0 | NiClock::Update | timeGetTime/QPC delta computation |
| 0x006dc490 | TGTimerManager::Update | Walk sorted timer list, fire expired |
| 0x0046f420 | FrameBudgetScheduler | 16-sample ring, 4 priority tiers |

## Solved Crashes & Fixes (see topic files)
- TGL FindEntry NULL: [tgl-null-crash.md]; Compressed vector: [compressed-vector-crash.md]
- Boot player: [boot-player-analysis.md]; InitNetwork dupes: [initnet-duplicates.md]
- Collision damage: [collision-damage.md]; Ship+0x140 NULL: [ship-0x140-analysis.md]

## Key Pipelines (see topic files)
- Renderer: [renderer-pipeline-analysis.md]; NIF: [nif-loading-pipeline.md]
- Ship creation: [ship-creation-callchain.md]; Subsystems: [subsystem-creation-analysis.md]
- Ship Creation: FUN_0069f620 -> FUN_005a1f50 -> FUN_005b0e80 (vtable, InitObject)

## GameSpy & LAN Discovery (2026-02-16)
- Game "bcommander", key "Nm3aZ9"; LAN: UDP `\status\` to 255.255.255.255:22101-22201
- See [docs/gamespy-master-server.md], [docs/gamespy-crypto-analysis.md]

## Cut Content (2026-02-16)
- See [docs/cut-content-analysis.md](../../docs/cut-content-analysis.md)
- TestMenuState=2: debug cheats. Self-destruct (Ctrl+D). Tractor docking (6 modes). Opcodes 0x04/0x05 dead.

## Combat Systems (2026-02-17, see docs/)
- **Repair**: [docs/repair-tractor-analysis.md] - NO queue limit (OpenBC wrong); multi-team simultaneous
- **Tractor**: Same doc - multiplicative drag (OpenBC additive WRONG); NO direct damage; 6 modes
- **Weapons**: [docs/weapon-firing-mechanics.md] - Phaser charge/discharge; torpedo reload/type-switch
- **Cloak**: [docs/cloaking-state-machine.md] - States 0/2/3/5 (not 0/1/2/3); OpenBC WRONG
- **Shields**: [docs/shield-system.md] - 6-facing ellipsoid; area vs directed absorption
- **Collision**: [docs/collision-detection-system.md] - 3-tier; client-authoritative
- **CF16**: [docs/cf16-precision-analysis.md] - [sign:1][scale:3][mantissa:12]; BASE=0.001, MULT=10.0

## Fragmented Reliable ACK Bug (2026-02-19)
- See [docs/fragmented-ack-bug.md](../../docs/fragmented-ack-bug.md)
- All static code paths verified correct; bug requires runtime instrumentation
- ACK factory at 0x006bd1f0 (NOT in Ghidra func DB; decompiled via objdump)

## Ghidra Workarounds
- Some vtable entries NOT in Ghidra function DB; use objdump raw disasm
- `i686-w64-mingw32-objdump -d -M intel --start-address=X --stop-address=Y stbc.exe`
- DAT_0088b9c0 = 1.0 as DOUBLE (8 bytes); `fcomp QWORD PTR` reads double not float
- 0x0078xxxx = Python 1.5.2 Parser (NOT NIF): FUN_007840f0=PyNode_AddChild
