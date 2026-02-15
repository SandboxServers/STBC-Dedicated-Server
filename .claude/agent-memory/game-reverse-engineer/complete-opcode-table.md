# Complete Game Opcode Table (Verified 2026-02-14)

## Methodology
Jump table at 0x0069F534, 41 entries, indexed by (opcode - 2).
Verified by: (1) xrefs_to for each case target to find jump table entry,
(2) reading raw binary bytes at thunk addresses for opcode constants,
(3) decompiling handler functions.

## MultiplayerGame Dispatcher (ReceiveMessageHandler at LAB_0069f2a0)
Handles opcodes 0x02-0x2A via switch/jump table.

| Opcode | Case Addr  | Handler Func | Recv Event    | Name                    | Description |
|--------|-----------|-------------|---------------|-------------------------|-------------|
| 0x02   | 0x69f31e  | FUN_0069F620 | (team=0)     | ObjectCreate            | Create game object (no team) |
| 0x03   | 0x69f334  | FUN_0069F620 | (team=1)     | ObjCreateTeam           | Create game object (with team) |
| 0x04   | 0x69f525  | DEFAULT      | --            | (unhandled)             | Falls through; boot handled at transport layer |
| 0x05   | 0x69f525  | DEFAULT      | --            | (unhandled)             | Falls through |
| 0x06   | 0x69f3f1  | FUN_0069F880 | --            | PythonEvent             | Deserialize+post Python event locally |
| 0x07   | 0x69f34a  | FUN_0069FDA0 | 0x008000D7    | StartFiring             | Event forward: StartFiring |
| 0x08   | 0x69f363  | FUN_0069FDA0 | 0x008000D9    | StopFiring              | Event forward: StopFiring |
| 0x09   | 0x69f37c  | FUN_0069FDA0 | 0x008000DB    | StopFiringAtTarget      | Event forward: StopFiringAtTarget |
| 0x0A   | 0x69f395  | FUN_0069FDA0 | 0x0080006C    | SubsystemStatusChanged  | Event forward: SubsystemStatus |
| 0x0B   | 0x69f3ae  | FUN_0069FDA0 | 0x008000DF    | AddToRepairList         | Event forward: repair subsystem |
| 0x0C   | 0x69f3c7  | FUN_0069FDA0 | (preserve=0)  | ClientEvent             | Event forward: keep stream event code |
| 0x0D   | 0x69f3f1  | FUN_0069F880 | --            | PythonEvent2            | Same handler as 0x06 |
| 0x0E   | 0x69f405  | FUN_0069FDA0 | 0x008000E3    | StartCloaking           | Event forward: StartCloaking |
| 0x0F   | 0x69f41e  | FUN_0069FDA0 | 0x008000E5    | StopCloaking            | Event forward: StopCloaking |
| 0x10   | 0x69f437  | FUN_0069FDA0 | 0x008000ED    | StartWarp               | Event forward: StartWarp |
| 0x11   | 0x69f3c7  | FUN_0069FDA0 | (preserve=0)  | RepairListPriority      | Same handler as 0x0C (preserve stream event code) |
| 0x12   | 0x69f3c7  | FUN_0069FDA0 | (preserve=0)  | SetPhaserLevel          | Same handler as 0x0C (preserve stream event code) |
| 0x13   | 0x69f2f6  | FUN_006A01B0 | --            | HostMsg/SelfDestruct    | Host-only damage processing (obj+0x2C4 subsystem) |
| 0x14   | 0x69f47d  | FUN_006A01E0 | --            | DestroyObject           | Destroy a game object |
| 0x15   | 0x69f491  | FUN_006A2470 | 0x008000FC    | CollisionEffect         | Collision between two objects; distance check + HostCollisionEvent |
| 0x16   | 0x69f525  | DEFAULT      | --            | (unhandled here)        | Handled by MultiplayerWindow dispatcher (FUN_00504c10) |
| 0x17   | 0x69f4a5  | FUN_006A1360 | --            | DeletePlayerUI          | Deserialize event + broadcast (generic event post) |
| 0x18   | 0x69f4b9  | FUN_006A1420 | --            | DeletePlayerAnim        | Load TGL "Delete Player" script + play animation |
| 0x19   | 0x69f4cd  | FUN_0069F930 | --            | TorpedoFire             | Torpedo projectile creation + replication |
| 0x1A   | 0x69f4e1  | FUN_0069FBB0 | --            | BeamFire                | Phaser beam creation + replication |
| 0x1B   | 0x69f450  | FUN_0069FDA0 | 0x008000FD    | TorpedoTypeChange       | Event forward: TorpedoTypeChanged |
| 0x1C   | 0x69f3dd  | FUN_0069FF50 | --            | StateUpdate             | Ship position/orientation/subsystem/weapon update |
| 0x1D   | 0x69f4f5  | FUN_006A0490 | --            | ObjNotFound             | Request for unknown object ID |
| 0x1E   | 0x69f51d  | FUN_006A02A0 | --            | RequestObject           | Request object data |
| 0x1F   | 0x69f509  | FUN_006A05E0 | --            | EnterSet                | Player entering a set (scene) |
| 0x20-28| 0x69f525  | DEFAULT      | --            | (unhandled)             | 0x20-0x27 handled by NetFile dispatcher; 0x28 unhandled |
| 0x29   | 0x69f469  | FUN_006A0080 | --            | Explosion               | Object explosion effect |
| 0x2A   | 0x69f30a  | FUN_006A1E70 | --            | NewPlayerInGame         | Player joined the game |

## Sender Thunk -> Opcode Mapping (verified from binary bytes)

| Thunk Address | Handler Name             | Sender Event | Opcode |
|--------------|--------------------------|-------------|--------|
| 0x006a1790   | StartFiringHandler       | 0x008000D8  | 0x07   |
| 0x006a17a0   | StartWarpHandler         | 0x008000EC  | 0x10   |
| 0x006a17b0   | TorpedoTypeChangeHandler | 0x008000FE  | 0x1B   |
| 0x006a18d0   | StopFiringHandler        | 0x008000DA  | 0x08   |
| 0x006a18e0   | StopFiringAtTargetHandler| 0x008000DC  | 0x09   |
| 0x006a18f0   | StartCloakingHandler     | 0x008000E2  | 0x0E   |
| 0x006a1900   | StopCloakingHandler      | 0x008000E4  | 0x0F   |
| 0x006a1910   | SubsystemStatusHandler   | 0x008000DD  | 0x0A   |
| 0x006a1920   | AddToRepairListHandler   | 0x008000DF  | 0x0B   |
| 0x006a1930   | ClientEventHandler       | (generic)   | 0x0C   |
| 0x006a1940   | RepairListPriorityHandler| 0x00800076  | 0x11   |
| 0x006a1970   | SetPhaserLevelHandler    | 0x008000E0  | 0x12   |
| 0x006a1a70   | ChangedTargetHandler     | 0x00800058  | 0x0D   |
| 0x005afa79   | HostCollisionEffectHandler| 0x008000FC | 0x15   |

## Event Code Pairing (Sender -> Receiver)

| Sender Event | Recv Event | Name |
|-------------|------------|------|
| 0x008000D8  | 0x008000D7 | StartFiring |
| 0x008000DA  | 0x008000D9 | StopFiring |
| 0x008000DC  | 0x008000DB | StopFiringAtTarget |
| 0x008000DD  | 0x0080006C | SubsystemStatus |
| 0x008000E2  | 0x008000E3 | StartCloaking |
| 0x008000E4  | 0x008000E5 | StopCloaking |
| 0x008000EC  | 0x008000ED | StartWarp |
| 0x008000FE  | 0x008000FD | TorpedoTypeChange |
| 0x008000DF  | 0x008000DF | AddToRepairList (SAME code) |

## MultiplayerWindow Dispatcher (FUN_00504c10)
Handles opcodes received at reliable message layer when this+0xb0 gate is set.

| Opcode | Handler      | Name                 | Description |
|--------|-------------|----------------------|-------------|
| 0x00   | FUN_00504d30 | Settings             | Game settings (gameTime, player slot, map name) |
| 0x01   | FUN_00504f10 | GameInit             | Create MultiplayerGame, run GameInit |
| 0x16   | FUN_00504c70 | UICollisionSetting   | Toggle collision on/off (updates DAT_008e5f59) |

## NetFile Dispatcher (FUN_006a3cd0)
Handles checksum/file transfer opcodes.

| Opcode | Handler      | Name |
|--------|-------------|------|
| 0x20   | FUN_006a5df0 | ChecksumRequest |
| 0x21   | FUN_006a4260 | ChecksumResponse |
| 0x22   | FUN_006a4c10 | VersionMismatch |
| 0x23   | FUN_006a4c10 | SysChecksumFail |
| 0x25   | FUN_006a3ea0 | FileTransfer |
| 0x27   | FUN_006a4250 | FileTransferACK |

## Python-Level Message Types (via PythonEvent 0x06/0x0D or SendTGMessage)
These are NOT game opcodes -- they're first-byte subtypes within Python message payloads.
MAX_MESSAGE_TYPES = 43 (0x2B).

| Value | Constant Name          | Description |
|-------|----------------------|-------------|
| 0x2C  | CHAT_MESSAGE          | MAX+1: Chat text message |
| 0x2D  | TEAM_CHAT_MESSAGE     | MAX+2: Team-only chat message |
| 0x35  | MISSION_INIT_MESSAGE  | MAX+10: Game config (playerLimit, system, timeLimit, fragLimit) |
| 0x36  | SCORE_CHANGE_MESSAGE  | MAX+11: Score change notification |
| 0x37  | SCORE_MESSAGE         | MAX+12: Full score sync (one per player) |
| 0x38  | END_GAME_MESSAGE      | MAX+13: Game ended notification |
| 0x39  | RESTART_GAME_MESSAGE  | MAX+14: Game restart notification |

## Handler Prologue Bytes (for hooking)

| Handler      | Prologue (12 bytes) |
|-------------|---------------------|
| FUN_006A2470 (0x15 Collision) | 6A FF 68 68 DC 87 00 64 A1 00 00 00 |
| FUN_006A01B0 (0x13 HostMsg)   | A0 8A FA 97 00 84 C0 74 21 8B 44 24 |
| FUN_006A01E0 (0x14 Destroy)   | 6A FF 68 68 DA 87 00 64 A1 00 00 00 |
| FUN_006A1360 (0x17 DelPlrUI)  | 6A FF 68 A8 DB 87 00 64 A1 00 00 00 |
| FUN_006A1420 (0x18 DelPlrAnim)| 6A FF 68 CB DB 87 00 64 A1 00 00 00 |
| FUN_0069F880 (0x06 PyEvent)   | 6A FF 68 88 D9 87 00 64 A1 00 00 00 |
| FUN_0069FDA0 (0x07+ EvtFwd)   | 6A FF 68 E8 D9 87 00 64 A1 00 00 00 |
| FUN_00504C70 (0x16 UISetting) | 6A FF 68 98 85 87 00 64 A1 00 00 00 |

All handlers with `6A FF 68` prologue use SEH frame setup:
`PUSH -1 / PUSH seh_handler / MOV EAX, FS:[0] / PUSH EAX / MOV FS:[0], ESP`
