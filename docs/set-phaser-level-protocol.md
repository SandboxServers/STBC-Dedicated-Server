# Opcode 0x12 — SetPhaserLevel Protocol Analysis

Complete decompilation and wire format analysis of the phaser power level network message
(opcode 0x12) in Star Trek: Bridge Commander multiplayer.

## Overview

Opcode 0x12 (SetPhaserLevel) carries a phaser beam intensity change from the originating
player to all other peers. This controls the LOW/MEDIUM/HIGH phaser power toggle — **not**
the engineering power distribution sliders (which use a separate mechanism). The message
contains a serialized `TGCharEvent` (factory ID `0x105`) with a single payload byte
representing the power level.

**Direction**: Bidirectional (any peer → all other peers, relayed by host)
**Sender thunk**: `MultiplayerGame::SetPhaserLevelHandler` at `0x006A1970`
**Serializer**: `SendEventMessage` at `0x006A17C0`
**Receiver**: `FUN_0069fda0` (generic event forward, shared with opcodes 0x07-0x11, 0x1B)
**Applier**: `PhaserSystem::SetPhaserLevelHandler` at `0x00574180`
**Frequency**: ~33 per 15-minute stock session (infrequent — players rarely toggle phaser level)

## Wire Format

### Complete Packet Layout

```
Offset  Size  Type    Field                    Notes
------  ----  ----    -----                    -----
0       1     u8      opcode                   Always 0x12
1       4     i32     factory_id               Always 0x00000105 (TGCharEvent factory)
5       4     i32     event_type               Always 0x008000E0 (ET_SET_PHASER_LEVEL)
9       4     i32     source_object_ref        Object ID of the ship (or 0 for NULL)
13      4     i32     target_object_ref        Related object ref (-1 for sentinel, 0 for NULL)
17      1     u8      phaser_level             Power level: 0=LOW, 1=MEDIUM, 2=HIGH
```

**Total size**: 18 bytes (fixed — no variable-length fields).

All multi-byte values are **little-endian**.

### Serialization Detail

The payload is produced by `SendEventMessage` (0x006A17C0):
1. Writes the opcode byte (0x12) as a raw byte prefix
2. Calls `TGCharEvent::WriteToStream` (vtable+0x34 at `0x006D6940`), which:
   a. Calls base `TGEvent::WriteToStream` (0x006D6130):
      - `WriteInt32(GetFactoryID())` → 0x105
      - `WriteInt32(event+0x10)` → event type 0x008000E0
      - `WriteObjectRef(event+0x08)` → source object reference
      - `WriteObjectRef(event+0x0C)` → target/related object reference
   b. Appends `WriteByte(event+0x28)` → the phaser level byte

### Object Reference Encoding

The `WriteObjectRef` function handles three cases:
- **NULL object**: writes `0x00000000`
- **Sentinel value** (0x0095ADFC): writes `0xFFFFFFFF` (-1)
- **Valid object**: writes the object's ID from `obj+0x40`

### Phaser Power Level Values

| Value | Constant | Python API | Effect |
|-------|----------|------------|--------|
| 0 | PP_LOW | `App.PhaserSystem.PP_LOW` | Low intensity — less damage, lower power draw |
| 1 | PP_MEDIUM | `App.PhaserSystem.PP_MEDIUM` | Medium intensity — balanced |
| 2 | PP_HIGH | `App.PhaserSystem.PP_HIGH` | High intensity — more damage, higher power draw |

These values are stored as a single byte on the wire (`event+0x28`) and as an `int` in the
PhaserSystem object (`PhaserSystem+0xF0`).

### Example Packet Decode

**SetPhaserLevel to HIGH** (18 bytes):
```
12                    opcode = 0x12 (SetPhaserLevel)
05 01 00 00           factory_id = 0x00000105 (TGCharEvent)
E0 00 80 00           event_type = 0x008000E0 (ET_SET_PHASER_LEVEL)
FF FF FF 3F           source_obj_ref = 0x3FFFFFFF (Player 0 ship)
00 00 00 00           target_obj_ref = NULL
02                    phaser_level = 2 (PP_HIGH)
```

**SetPhaserLevel to LOW** (18 bytes):
```
12                    opcode = 0x12 (SetPhaserLevel)
05 01 00 00           factory_id = 0x00000105 (TGCharEvent)
E0 00 80 00           event_type = 0x008000E0 (ET_SET_PHASER_LEVEL)
FF FF 03 40           source_obj_ref = 0x400003FF (Player 1 ship)
00 00 00 00           target_obj_ref = NULL
00                    phaser_level = 0 (PP_LOW)
```

## TGCharEvent Class Layout (0x2C bytes)

```
Offset  Size  Type           Field               Notes
------  ----  ----           -----               -----
0x00    4     void**         vtable               0x008932DC
0x04    4     int            ni_refcount          NiObject reference count
0x08    4     void*          source_object        Source object ptr (ship that changed level)
0x0C    4     void*          related_object       Related object ptr (typically NULL)
0x10    4     uint32         event_type           0x008000E0 (ET_SET_PHASER_LEVEL)
0x14    4     float          time_stamp           Event timestamp (-1.0f initially)
0x18    2     uint16         flags_a              Event flags
0x1A    2     uint16         flags_b              Ref tracking flags
0x1C    4     void*          (reserved)
0x20    4     void*          (reserved)
0x24    4     void*          parent_event         Cleared to 0 on receive
0x28    1     char           phaser_level         Power level: 0, 1, or 2
0x29-2B 3     -              padding              Struct padding to 0x2C
```

### Class Hierarchy

```
NiObject
  └── TGEvent (factory 0x02, size 0x28)
        └── TGSubsystemEvent (factory 0x101)
              └── TGCharEvent (factory 0x105, size 0x2C)
```

`TGCharEvent` adds a single `char` field at `+0x28` to the base `TGEvent` layout. This
field carries the phaser level value (or any other single-byte event payload — the class
is generic, reused by multiple subsystem events).

### Constructor (0x00574C20)

```
this = TGEvent::ctor(this, 0)          // base init
this->vtable = 0x008932DC             // TGCharEvent vtable
this->charValue = 0                   // +0x28 = 0 (default)
```

### SWIG Factory Registration

The factory for `TGCharEvent` (ID 0x105) is registered in the event factory hash table,
allowing `FUN_006d6200` (ReadObjectFromStream) to construct it from the factory ID on the wire.

### IsA Chain

`TGCharEvent::IsA(id)` (vtable+0x08 at `0x00574C50`) returns true for:
- `0x105` (TGCharEvent)
- `0x101` (TGSubsystemEvent)
- `0x02` (TGEvent)

## Sender Flow

### Local Action: PhaserSystem::SetPowerLevel (0x00574200)

When the player toggles phaser intensity (key press or UI action):

```
PhaserSystem::SetPowerLevel(int level):
  1. Allocate TGCharEvent (NiAlloc 0x2C bytes)
  2. Call TGCharEvent::ctor (FUN_00574C20)
  3. Set event+0x28 = (byte)level                    // the power level
  4. Set event source to this PhaserSystem            // FUN_006d62b0
  5. Set event+0x10 = 0x008000E0                      // ET_SET_PHASER_LEVEL
  6. Post event to event system                       // FUN_006da2a0
  7. Loop over child subsystems (this+0x1C = count):
     a. Get child at index i (FUN_0056c570)
     b. dynamic_cast<EnergyWeapon*>(child) via FUN_00570b20
     c. If cast succeeds: call child->SetPowerSetting(level)
        via vtable+0x90 (vtable slot 36)
  8. Store level at PhaserSystem+0xF0
```

The sender **immediately applies** the level to all child EnergyWeapon subsystems and
stores it locally. The event post in step 6 triggers the multiplayer handler (below) to
serialize and send it to other peers.

### Multiplayer Bridge: SetPhaserLevelHandler Thunk (0x006A1970)

The MultiplayerGame object registers a handler for event `0x008000E0`. When the event
fires (from step 6 above), this thunk decides whether to forward it over the network:

```
MultiplayerGame::SetPhaserLevelHandler(TGCharEvent* event):
  1. If event->source == NULL: return (ignore)
  2. If event->source->objectID != this->localPlayerObjectID: return
     (only forward OUR events — prevents re-broadcasting received events)
  3. Call SendEventMessage(event, 0x12)
```

**Gate check at this+0x54**: The handler reads the source object's ID from `source+0x40`
and compares it against `MultiplayerGame+0x54` (the local player's object ID). This
ensures only locally-originated events are sent over the network.

### SendEventMessage (0x006A17C0)

```
SendEventMessage(TGEvent* event, byte opcode):
  1. Store opcode byte in local buffer
  2. Create TGBufferStream wrapping a 1023-byte stack buffer
  3. Call event->WriteToStream(stream) via vtable+0x34
  4. Get stream position (bytes written)
  5. Allocate TGMessage (NiAlloc 0x40 bytes)
  6. Copy data into message: [opcode_byte][stream_data] (total = position + 1)
  7. Mark message as reliable (msg+0x3A = 1)
  8. If IsMultiplayer: SendTGMessageToGroup("NoMe")
     Else: SendTGMessage to host peer
```

## Receiver Flow

### Jump Table Dispatch

The `MultiplayerGame` dispatcher at `0x0069F2A0` reads the opcode byte (0x12), subtracts 2
to get jump table index 16, and jumps to case `0x0069F3C7`. This case is shared with
opcodes 0x0B, 0x0C, and 0x11:

```asm
push  0x0              ; event type override = 0 (use event's own type)
push  esi              ; TGMessage*
call  FUN_0069fda0     ; generic event forward
```

**No event type override**: Unlike opcodes 0x07-0x0A (which override the event type on
receive), opcode 0x12 passes `0` for the override parameter. The event arrives and is
posted with its original type `0x008000E0`. This is because `ET_SET_PHASER_LEVEL` has
no sender/receiver code pairing — the same event code is used on both sides.

### Generic Event Forward: FUN_0069fda0

This handler processes all event-forward opcodes (0x07-0x12, 0x1B). For opcode 0x12:

```
FUN_0069fda0(TGMessage* msg, int eventTypeOverride):
  --- HOST RELAY ---
  1. If IsMultiplayer:
     a. Clone/extract message data
     b. Look up "Forward" group in TGWinsockNetwork+0xF4
     c. Remove sender from "Forward" group (prevent echo back)
     d. Forward message to all remaining group members
     e. Re-add sender to "Forward" group

  --- LOCAL DISPATCH ---
  2. If sender != self:
     a. Extract message buffer via FUN_006b8530
     b. Create TGBufferStream, init with buffer+1 (skip opcode byte)
     c. Deserialize event from stream via FUN_006d6200:
        - Read factory ID (0x105) → look up TGCharEvent factory
        - Allocate TGCharEvent (0x2C bytes)
        - Call TGCharEvent::ReadFromStream (vtable+0x38)
     d. Resolve object references (FUN_006f13c0)
     e. Clear event+0x24 (parent event pointer)
     f. If eventTypeOverride != 0: set event+0x10 = override
        (For 0x12: override is 0, so event keeps its original 0x008000E0)
     g. Post event to local event system (FUN_006da300)
```

### Applier: PhaserSystem::SetPhaserLevelHandler (0x00574180)

The locally-posted event triggers the PhaserSystem's handler:

```
PhaserSystem::SetPhaserLevelHandler(TGCharEvent* event):
  1. Read event+0x28 as signed byte → sign-extend to int
  2. Store into PhaserSystem+0xF0
  3. Release event (FUN_006d90e0)
```

**Critical asymmetry**: The receiver does **NOT** call `SetPowerSetting()` on child
EnergyWeapon subsystems. It only stores the level value. The actual intensity change on
remote machines propagates through a different mechanism — either the `PhaserSystem::Update()`
tick reads `+0xF0` and applies it, or individual weapon intensity values are carried in
`StateUpdate` (opcode 0x1C) serialization.

## Event Type Codes

| Code | Name | Used By |
|------|------|---------|
| 0x008000E0 | ET_SET_PHASER_LEVEL | Both sender and receiver (no pairing) |

**No event code pairing**: Most event-forward opcodes have a sender/receiver code pair
(e.g., StartFiring uses 0xD8 locally, 0xD7 on receive). SetPhaserLevel is simpler — the
same code `0x008000E0` is used on both sides, and the generic forward handler passes
`override = 0` (no override).

## Shared Handler Group

Opcode 0x12 shares `FUN_0069fda0` with these other opcodes:

| Opcode | Name | Event Override | Override Code |
|--------|------|----------------|---------------|
| 0x07 | StartFiring | Yes | 0x008000D7 |
| 0x08 | StopFiring | Yes | 0x008000D9 |
| 0x09 | StopFiringAtTarget | Yes | 0x008000DB |
| 0x0A | SubsystemStatusChanged | Yes | 0x0080006C |
| 0x0B | AddToRepairList | No | 0 |
| 0x0C | ClientEvent | No | 0 |
| 0x0E | StartCloaking | Yes | 0x008000E3 |
| 0x0F | StopCloaking | Yes | 0x008000E5 |
| 0x10 | StartWarp | Yes | 0x008000ED |
| 0x11 | RepairListPriority | No | 0 |
| **0x12** | **SetPhaserLevel** | **No** | **0** |
| 0x1B | TorpedoTypeChange | Yes | 0x008000FD |

Opcodes with `override = 0` use the event's own type code from the wire. Opcodes with an
override replace the deserialized event's type before posting locally — this implements the
sender/receiver event code pairing.

## Event Registration

### PhaserSystem (registered in FUN_00573DE0 + FUN_00573E40)

```
Handler: PhaserSystem::SetPhaserLevelHandler (0x00574180)
Trigger: ET_SET_PHASER_LEVEL (0x008000E0)
Registration: FUN_006d92b0 with name "PhaserSystem::SetPhaserLevelHandler"
```

### MultiplayerGame (registered in ctor at 0x0069E590)

```
Handler: MultiplayerGame::SetPhaserLevelHandler thunk (0x006A1970)
Trigger: ET_SET_PHASER_LEVEL (0x008000E0)
Registration: FUN_006db380 with name "MultiplayerGame::__SetPhaserLevelHandler"
Flags: priority=1, enabled=1
```

Both handlers fire for the same event type. The MultiplayerGame handler serializes and sends
over the network; the PhaserSystem handler applies the level locally. On the sender side,
both fire. On the receiver side, only the PhaserSystem handler fires (because the MP handler's
gate check rejects events from non-local sources).

## Related Functions

| Address | Name | Role |
|---------|------|------|
| 0x00574200 | PhaserSystem::SetPowerLevel | Local action: creates event, applies to weapons, stores level |
| 0x00574180 | PhaserSystem::SetPhaserLevelHandler | Receiver: stores level byte from event into +0xF0 |
| 0x006A1970 | MultiplayerGame::SetPhaserLevelHandler | MP sender thunk: gates on local player, calls SendEventMessage |
| 0x006A17C0 | SendEventMessage | Serializes event + opcode into TGMessage, sends reliably |
| 0x0069fda0 | MultiplayerGame::GenericEventForward | Receive-side: relay to "Forward" group + deserialize + post locally |
| 0x0069F2A0 | MultiplayerGame::ReceiveMessage | Jump table dispatcher (opcode-2 indexed) |
| 0x006D6940 | TGCharEvent::WriteToStream | Network serialization (base + charValue byte) |
| 0x006D6960 | TGCharEvent::ReadFromStream | Network deserialization (base + charValue byte) |
| 0x006D6130 | TGEvent::WriteToStream | Base event serialization (factoryID, type, source, target) |
| 0x006D61C0 | TGEvent::ReadFromStream | Base event deserialization |
| 0x006D6200 | ReadObjectFromStream | Factory-based event construction from stream |
| 0x006DA2A0 | EventManager::PostEvent | Posts event for handler dispatch |
| 0x006DA300 | EventManager::PostEvent (auto-release) | Posts event with automatic reference release |
| 0x006D90E0 | EventManager::ReleaseEvent | Releases/frees an event object |
| 0x00574C20 | TGCharEvent::ctor | Constructor (allocates 0x2C bytes, sets vtable) |
| 0x00574CB0 | TGCharEvent::scalar_deleting_dtor | Destructor |
| 0x00570B20 | dynamic_cast\<EnergyWeapon\> | IsA check for factory 0x802C |
| 0x0056C570 | GetChildSubsystem | Returns child subsystem at index |

## TGCharEvent Vtable Map (0x008932DC)

| Offset | Target | Name |
|--------|--------|------|
| +0x00 | 0x00574CB0 | scalar_deleting_dtor |
| +0x04 | 0x00574C40 | GetFactoryID → returns 0x105 |
| +0x08 | 0x00574C50 | IsA(id) → true for 0x105, 0x101, 0x02 |
| +0x0C | 0x006F1650 | (inherited from NiObject) |
| +0x10 | 0x006D6980 | WriteStream (persistence) |
| +0x14 | 0x006D69B0 | ReadStream (persistence) |
| +0x18 | 0x006D6050 | ReadClassName (inherited) |
| +0x1C | 0x006D60B0 | WriteClassName (inherited) |
| +0x20 | 0x006F15C0 | (inherited from NiObject) |
| +0x24 | 0x00574C80 | GetClassName → "TGCharEvent" |
| +0x28 | 0x00574C90 | GetSWIGName → "_p_TGCharEvent" |
| +0x2C | 0x00574CA0 | GetPtrName → "TGCharEventPtr" |
| +0x30 | 0x006D6920 | CopyFrom (copies base fields + charValue) |
| +0x34 | 0x006D6940 | WriteToStream (network — base + WriteByte) |
| +0x38 | 0x006D6960 | ReadFromStream (network — base + ReadByte) |
| +0x3C | 0x005750E0 | PostProcess / destructor chain |
