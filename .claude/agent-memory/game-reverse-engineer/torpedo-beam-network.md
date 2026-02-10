# Torpedo & Beam Fire Network Protocol Analysis

## Key Finding: Opcode Table Was WRONG

The wire format spec had incorrect opcode-to-handler mappings for game opcodes 0x07-0x0B.
Root cause: the spec guessed handler assignments without verifying the switch table.

## Corrected Game Opcode Dispatch (switch table at 0x0069F534)

The ReceiveMessageHandler at 0x0069f2a0 reads first payload byte, subtracts 2, indexes into
a 41-entry jump table. All entries are inline cases within the same function.

| Opcode | Handler | Description |
|--------|---------|-------------|
| 0x02 | FUN_0069F620(msg, 0) | ObjectCreate (no team) |
| 0x03 | FUN_0069F620(msg, 1) | ObjectCreate (with team) |
| 0x06 | FUN_0069F880(msg) | PythonEvent (generic local dispatch) |
| 0x07 | FUN_0069FDA0(0x008000D7) | StartFiring (event forward) |
| 0x08 | FUN_0069FDA0(0x008000D9) | StopFiring (event forward) |
| 0x09 | FUN_0069FDA0(0x008000DB) | StopFiringAtTarget (event forward) |
| 0x0A | FUN_0069FDA0(0x0080006C) | SubsystemStatusChanged (event forward) |
| 0x0B | FUN_0069FDA0(0x008000DF) | Event 0xDF forward |
| 0x0C | FUN_0069FDA0(msg, 0) | Event forward (null event code = keep stream code) |
| 0x0D | FUN_0069F880(msg) | PythonEvent (same as 0x06) |
| 0x0E | FUN_0069FDA0(0x008000E3) | StartCloaking (event forward) |
| 0x0F | FUN_0069FDA0(0x008000E5) | StopCloaking (event forward) |
| 0x10 | FUN_0069FDA0(0x008000ED) | StartWarp (event forward) |
| 0x13 | FUN_006A01B0(msg) | Host message dispatch |
| 0x14 | FUN_006A01E0(msg) | DestroyObject |
| 0x15 | FUN_006A2470(msg) | Unknown handler |
| 0x17 | FUN_006A1360(msg) | DeletePlayerUI |
| 0x18 | FUN_006A1420(msg) | DeletePlayer animation |
| 0x19 | FUN_0069F930(msg) | **TorpedoFire** (actual!) |
| 0x1A | FUN_0069FBB0(msg) | **BeamFire** (actual!) |
| 0x1B | FUN_0069FDA0(0x008000FD) | TorpedoTypeChange (event forward) |
| 0x1C | FUN_0069FF50(msg) | StateUpdate |
| 0x1D | FUN_006A0490(msg) | ObjectNotFound |
| 0x1E | FUN_006A02A0(msg) | RequestObject |
| 0x1F | FUN_006A05E0(msg) | EnterSet |
| 0x29 | FUN_006A0080(msg) | Explosion |
| 0x2A | FUN_006A1E70(msg) | NewPlayerInGame |

## Sender Functions

### TorpedoSystem::SendFireMessage = FUN_0057cb10 (opcode 0x19)
- Writes: 0x19, objectId(i32v), flags1(u8), flags2(u8), velocity(cv3), [targetId(i32v), impactPoint(cv4)]
- Sends to "Forward" distribution list
- Called by torpedo subsystem when torpedo fires

### PhaserSystem::SendFireMessage = FUN_00575480 (opcode 0x1A)
- Writes: 0x1A, objectId(i32v), flags(u8), targetPos(cv3), moreFlags(u8), [targetId(i32v)]
- Sends to "Forward" distribution list
- Called by phaser subsystem when beam fires

### MultiplayerGame Event Thunks = via FUN_006a17c0
Serialize local game events into network messages with opcodes:
- 0x07: StartFiring (event 0x008000D8 -> recv as 0x008000D7)
- 0x08: StopFiring (event 0x008000DA -> recv as 0x008000D9)
- 0x09: StopFiringAtTarget (event 0x008000DC -> recv as 0x008000DB)
- 0x0A: SubsystemStatus (event 0x008000DD -> recv as 0x0080006C)
- 0x0E: StartCloaking, 0x0F: StopCloaking, 0x10: StartWarp, 0x1B: TorpedoTypeChange

### Event Code Pairing
Sender uses one event code, receiver uses a different (paired) code:
- Sender D8 (StartFiring local) -> Receiver D7 (StartFiring remote)
- Sender DA -> D9, DC -> DB, DD -> 6C, E2 -> E3, E4 -> E5, EC -> ED, FE -> FD

## Torpedo Flow (Complete)
1. TorpedoSystem decides to fire (FUN_0057d8a0)
2. Creates torpedo projectile game object locally
3. Posts event 0x00800065
4. TorpedoSystem::SendFireMessage (FUN_0057cb10) writes opcode 0x19 directly
5. ObjectCreatedHandler may also replicate the object via 0x02/0x03
6. StateUpdate 0x1C carries ongoing position for the torpedo object

## Beam Flow (Complete)
1. PhaserSystem::StartFiring called (FUN_00573ea0)
2. Posts event 0x008000D8 -> MultiplayerGame sends opcode 0x07 (StartFiring event)
3. PhaserSystem::SendFireMessage (FUN_00575480) writes opcode 0x1A directly
4. When beam stops: posts 0x008000DA -> opcode 0x08 (StopFiring event)
