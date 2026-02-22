> [docs](../README.md) / [protocol](README.md) / pythonevent-wire-format.md

# Opcode 0x06 — PythonEvent Wire Format

Complete decompilation and wire format analysis of the PythonEvent network message
(opcode 0x06) in Star Trek: Bridge Commander multiplayer.

## Overview

Opcode 0x06 (PythonEvent) is a **polymorphic serialized-event transport**. It carries
game events from the host to all clients, using a factory-based serialization system
where the first 4 bytes of the payload identify which event class follows. This is the
primary mechanism for broadcasting repair-list changes, explosion notifications, and
forwarded script events.

**Direction**: Host → All Clients (via "NoMe" routing group)
**Reliability**: Sent reliably (ACK required, `msg+0x3A = 1`)
**Frequency**: ~251 per 15-minute 3-player combat session (3,432 total observed in a
34-minute session — the most frequent game opcode)

Three distinct producers generate opcode 0x06 messages, each triggered by different
event types but using the same serialization pattern. The receiver is a single generic
handler that deserializes based on factory ID and dispatches locally.

### Opcode 0x0D (PythonEvent2)

Opcode 0x0D shares the same receiver function (`FUN_0069f880`) and has identical wire
format. Its distinct opcode provides an alternate event path; in practice both opcodes
are decoded identically.

## Wire Format

### Message Structure

```
Offset  Size  Type    Field          Notes
------  ----  ----    -----          -----
0       1     u8      opcode         Always 0x06
1       4     i32     factory_id     Event class factory type ID (determines payload)
5       4     i32     event_type     Event type constant (0x008000xx)
9       4     i32     source_obj_id  Source object (0=NULL, -1=sentinel, else obj+0x40)
13      4     i32     dest_obj_id    Dest/related object (same encoding)
[class-specific extension follows]
```

The first 17 bytes are common to all event classes (base `TGEvent` fields). The payload
after byte 16 depends on `factory_id`.

All multi-byte values are **little-endian**.

### Four Event Classes

| Factory ID | Class Name | Payload Size | Extension Fields |
|-----------|------------|-------------|-----------------|
| `0x00000101` | TGSubsystemEvent | 16 bytes | (none — base TGEvent only) |
| `0x00000105` | TGCharEvent | 17 bytes | `+1 byte: char_value` |
| `0x0000010C` | TGObjPtrEvent | 20 bytes | `+4 int32: obj_ptr_id` |
| `0x00008129` | ObjectExplodingEvent | 24 bytes | `+4 int32: firing_player_id`, `+4 float: lifetime` |

### Object Reference Encoding

The `WriteObjectRef` function at the stream level handles three cases:
- **NULL pointer** → writes `0x00000000`
- **Sentinel** (global at `0x0095ADFC`) → writes `0xFFFFFFFF` (-1)
- **Valid object** → writes `*(int*)(obj + 0x04)` (TGObject network ID)

On read, `ReadObjectRef` performs the inverse: ID → hash table lookup via `FUN_006f0ee0`.

**Ship IDs**: Player N base = `0x3FFFFFFF + N * 0x40000` (assigned in player join).
**Subsystem IDs**: Auto-assigned from global counter `DAT_0095B078` at construction time.
Subsystem IDs are NOT derived from the ship's base ID — they are sequential globals.
Resolved on the receiving end via the TGObject hash table at `DAT_0099A67C`.

## Event Class 1: TGSubsystemEvent (factory 0x101)

Used for repair-list events in the collision damage chain. This is the most common
event class seen in opcode 0x06 messages (~13 of every 14 collision-related messages).

### Wire Layout

```
Offset  Size  Type    Field            Notes
------  ----  ----    -----            -----
0       1     u8      opcode           0x06
1       4     i32     factory_id       0x00000101
5       4     i32     event_type       See table below
9       4     i32     source_obj_id    Damaged subsystem (TGObject ID from obj+0x04)
13      4     i32     dest_obj_id      RepairSubsystem that queued it (TGObject ID from obj+0x04)
```

**Total**: 17 bytes (fixed).

### Event Types

| Event Type | Constant | Meaning |
|-----------|----------|---------|
| `0x008000DF` | ET_ADD_TO_REPAIR_LIST | Subsystem damaged, added to repair queue |
| `0x00800074` | ET_REPAIR_COMPLETED | Subsystem condition reached max (repair finished) |
| `0x00800075` | ET_REPAIR_CANNOT_BE_COMPLETED | Subsystem destroyed while in repair queue (condition reached 0.0) |

### TGSubsystemEvent Class Layout (0x28 bytes in memory)

```
Offset  Size  Type        Field           Notes
------  ----  ----        -----           -----
0x00    4     void**      vtable          0x008932A4
0x04    4     int         ni_refcount     NiObject reference count
0x08    4     void*       source_object   Source object ptr
0x0C    4     void*       related_object  Related object ptr
0x10    4     uint32      event_type      Event type constant
0x14    4     float       timestamp       -1.0f initially
0x18    2     uint16      flags_a         Event flags
0x1A    2     uint16      flags_b         Ref tracking flags
0x1C    4     void*       (reserved)
0x20    4     void*       (reserved)
0x24    4     void*       parent_event    Cleared to 0 on receive
```

### Class Hierarchy

```
NiObject
  └── TGEvent (factory 0x02, size 0x28)
        └── TGSubsystemEvent (factory 0x101, size 0x28)
              ├── TGCharEvent (factory 0x105, size 0x2C, +0x28 = byte)
              └── TGObjPtrEvent (factory 0x10C, size 0x2C, +0x28 = int32 object ID)
        └── ObjectExplodingEvent (factory 0x8129, size 0x30, +0x28 = int32, +0x2C = float)
```

### Serialization Functions

| Address | Function | Role |
|---------|----------|------|
| 0x006D6130 | TGEvent::WriteToStream | Writes factory_id, event_type, source_ref, dest_ref |
| 0x006D61C0 | TGEvent::ReadFromStream | Reads event_type, source_ref, dest_ref (factory_id already consumed) |
| 0x006D6200 | ReadObjectFromStream | Reads factory_id → factory lookup → construct → call ReadFromStream |

### Example: ADD_TO_REPAIR_LIST (17 bytes)

```
06                    opcode = 0x06 (PythonEvent)
01 01 00 00           factory_id = 0x00000101 (TGSubsystemEvent)
DF 00 80 00           event_type = 0x008000DF (ET_ADD_TO_REPAIR_LIST)
2A 00 00 00           source_obj = 0x0000002A (damaged subsystem's TGObject ID)
1E 00 00 00           dest_obj = 0x0000001E (RepairSubsystem's TGObject ID)
```

Note: subsystem IDs are small sequential integers from the global counter, not
player-base-derived IDs like ship objects.

## Event Class 2: TGCharEvent (factory 0x105)

Extends TGSubsystemEvent with a single byte payload. Used by opcodes 0x07-0x12 and
0x1B (weapon/cloak/warp events via GenericEventForward), but NOT typically seen as
opcode 0x06. Documented here for completeness since the polymorphic deserializer can
reconstruct any registered factory type.

### Wire Layout

```
Offset  Size  Type    Field            Notes
------  ----  ----    -----            -----
0       1     u8      opcode           0x06 (if sent as PythonEvent)
1       4     i32     factory_id       0x00000105
5       4     i32     event_type       Depends on specific event
9       4     i32     source_obj_id    Source object
13      4     i32     dest_obj_id      Related object
17      1     u8      char_value       Single-byte payload
```

**Total**: 18 bytes (fixed).

### TGCharEvent Class Layout (0x2C bytes in memory)

```
Offset  Size  Type        Field           Notes
------  ----  ----        -----           -----
0x00    4     void**      vtable          0x008932DC
0x04-0x27     (inherited from TGSubsystemEvent)
0x28    1     char        char_value      Single-byte payload
0x29-2B 3     -           padding         Struct padding to 0x2C
```

### Serialization Functions

| Address | Function | Role |
|---------|----------|------|
| 0x006D6940 | TGCharEvent::WriteToStream | Base fields + WriteByte(+0x28) |
| 0x006D6960 | TGCharEvent::ReadFromStream | Base fields + ReadByte → +0x28 |

See [set-phaser-level-protocol.md](set-phaser-level-protocol.md) for detailed analysis
of TGCharEvent usage in opcode 0x12.

## Event Class 3: TGObjPtrEvent (factory 0x10C)

Extends TGSubsystemEvent with a 4-byte int32 object pointer (TGObject network ID).
This is the **most common event class during weapon combat** — 45% of all PythonEvents
in a 33.5-minute battle trace (1,718 of 3,825). Used by weapon fire/stop events,
tractor beam events, and repair priority events.

### Wire Layout

```
Offset  Size  Type    Field            Notes
------  ----  ----    -----            -----
0       1     u8      opcode           0x06 (if sent as PythonEvent)
1       4     i32     factory_id       0x0000010C
5       4     i32     event_type       Depends on specific event
9       4     i32     source_obj_id    Source object
13      4     i32     dest_obj_id      Related object
17      4     i32     obj_ptr_id       Third object reference (TGObject network ID)
```

**Total**: 21 bytes (fixed).

### TGObjPtrEvent Class Layout (0x2C bytes in memory)

```
Offset  Size  Type        Field           Notes
------  ----  ----        -----           -----
0x00    4     void**      vtable          0x0088869C
0x04-0x27     (inherited from TGSubsystemEvent)
0x28    4     int32       obj_ptr         TGObject network ID (third object reference)
```

### Key Difference from TGCharEvent

TGCharEvent (0x105) writes a single **byte** at +0x28 via WriteByte (18 bytes on wire).
TGObjPtrEvent (0x10C) writes a full **int32** at +0x28 via WriteInt32 (21 bytes on wire).
Both are 0x2C bytes in memory. They are distinct classes with different vtables and constructors.

### Serialization Functions

| Address | Function | Role |
|---------|----------|------|
| 0x006D6DC0 | TGObjPtrEvent::WriteToStream | Base fields + WriteInt32(+0x28) |
| 0x006D6DF0 | TGObjPtrEvent::ReadFromStream | Base fields + ReadInt32 → +0x28 |

### Event Types Using TGObjPtrEvent (Complete — 11 C++ event types)

**Network-forwarded** (cross the wire via opcode 0x06/0x0D or generic event forward):

| Event Type | Constant | Producer | obj_ptr Contains |
|-----------|----------|---------|-----------------|
| `0x0080007C` | ET_WEAPON_FIRED | FUN_00571f40, FUN_0057c9e0, FUN_0057f580 | Target ID or 0 |
| `0x00800081` | ET_PHASER_STARTED_FIRING | FUN_00571f40 (Phaser::Fire) | Target ID |
| `0x00800083` | ET_PHASER_STOPPED_FIRING | vtable xref ~0x005712FE | Target ID |
| `0x0080007D` | ET_TRACTOR_BEAM_STARTED_FIRING | FUN_0057f580 (Tractor::Fire) | Target ID |
| `0x00800076` | ET_REPAIR_INCREASE_PRIORITY | FUN_005519e0 | Subsystem ID |
| `0x008000DC` | ET_STOP_FIRING_AT_TARGET_NOTIFY | FUN_00574010, FUN_005825a0 | Target ID (host-only) |

**Local-only** (never serialized to the wire):

| Event Type | Constant | Producer | obj_ptr Contains |
|-----------|----------|---------|-----------------|
| `0x0080000E` | ET_SET_PLAYER | FUN_004066d0 | New player ship ID |
| `0x00800058` | ET_TARGET_WAS_CHANGED | FUN_005ae210 | **Previous** target ID |
| `0x0080006B` | ET_SUBSYSTEM_HIT | FUN_0056c470 (SetCondition) | Subsystem's own ID |
| `0x00800085` | ET_TRACTOR_TARGET_DOCKED | FUN_00580910 | Docked ship ID |
| `0x00800088` | ET_SENSORS_SHIP_IDENTIFIED | FUN_00568ad0, FUN_005678b0 | Identified ship ID |

**Dual-fire pattern**: Phaser fire creates ET_PHASER_STARTED_FIRING + ET_WEAPON_FIRED
simultaneously. Tractor fire does the same. Torpedo creates only ET_WEAPON_FIRED. This means
every phaser/tractor cycle generates 4+ ObjPtrEvent messages (start_specific + weapon_fired +
stopped_specific + stop_notify).

Python scripts also use TGObjPtrEvent for 27+ additional local-only event types (72 call
sites). The SWIG functions (SetObjPtr, GetObjPtr, Create) have zero C++ xrefs — Python-only.

### TGObjPtrEvent Vtable (0x0088869C)

| Slot | Offset | Address | Name |
|------|--------|---------|------|
| 0 | +0x00 | 0x00403310 | scalar_deleting_dtor |
| 1 | +0x04 | 0x004032B0 | GetFactoryID → returns 0x10C |
| 2 | +0x08 | 0x004032C0 | IsA(id) → true for 0x10C, 0x101, 0x02 |
| 9 | +0x24 | 0x004032F0 | GetClassName → "TGObjPtrEvent" |
| 10 | +0x28 | 0x00403300 | GetSWIGName → "_p_TGObjPtrEvent" |
| 12 | +0x30 | 0x006D6DA0 | CopyFrom (base + obj_ptr) |
| 13 | +0x34 | 0x006D6DC0 | **WriteToStream** (network) |
| 14 | +0x38 | 0x006D6DF0 | **ReadFromStream** (network) |

(Slots 3-8, 11, 15-17 inherited from TGEvent base.)

See [tgobjptrevent-class.md](tgobjptrevent-class.md) for full analysis including C++
producers, Python API, and constructor details.

## Event Class 4: ObjectExplodingEvent (factory 0x8129)

Carries ship destruction notifications. Extends TGEvent with a firing player ID
(who killed the ship) and an explosion lifetime (visual effect duration).

### Wire Layout

```
Offset  Size  Type    Field              Notes
------  ----  ----    -----              -----
0       1     u8      opcode             0x06
1       4     i32     factory_id         0x00008129
5       4     i32     event_type         Always 0x0080004E (ET_OBJECT_EXPLODING)
9       4     i32     source_obj_id      Object that is exploding
13      4     i32     dest_obj_id        Target (typically NULL or sentinel)
17      4     i32     firing_player_id   Connection ID of the killer
21      4     f32     lifetime           Explosion effect duration (seconds)
```

**Total**: 25 bytes (fixed).

### ObjectExplodingEvent Class Layout (0x30 bytes in memory)

```
Offset  Size  Type        Field              Notes
------  ----  ----        -----              -----
0x00    4     void**      vtable             0x0088A178
0x04    4     int         ni_refcount        NiObject reference count
0x08    4     void*       source_object      Object that is exploding
0x0C    4     void*       dest_object        Target object
0x10    4     uint32      event_type         0x0080004E
0x14    4     float       timestamp          -1.0f initially
0x18    2     uint16      flags_a            Event flags
0x1A    2     uint16      flags_b            Ref tracking flags
0x1C    4     void*       (reserved)
0x20    4     void*       (reserved)
0x24    4     void*       parent_event       Cleared to 0 on receive
0x28    4     int32       firing_player_id   Killer's connection ID
0x2C    4     float       lifetime           Explosion duration (seconds)
```

### Constructor (0x0043F8B0)

```
this = TGEvent::ctor(this, 0)
this->vtable = 0x0088A178
this->firing_player_id = 0
this->lifetime = 0.0f
```

### Serialization Functions

| Address | Function | Role |
|---------|----------|------|
| 0x0043F990 | ObjectExplodingEvent::WriteToStream | Base fields + WriteInt(+0x28) + WriteFloat(+0x2C) |
| 0x0043F9C0 | ObjectExplodingEvent::ReadFromStream | Base fields + ReadInt → +0x28 + ReadFloat → +0x2C |

### IsA Chain

`ObjectExplodingEvent::IsA` (vtable+0x08 at `0x0043F8F0`) returns true for:
- `0x8129` (ObjectExplodingEvent)
- `0x02` (TGEvent)

### Example: Ship Destroyed (25 bytes)

```
06                    opcode = 0x06 (PythonEvent)
29 81 00 00           factory_id = 0x00008129 (ObjectExplodingEvent)
4E 00 80 00           event_type = 0x0080004E (ET_OBJECT_EXPLODING)
FF FF FF 3F           source_obj = 0x3FFFFFFF (Player 0's ship, exploding)
FF FF FF FF           dest_obj = sentinel (-1)
02 00 00 00           firing_player_id = 2 (killed by player 2)
00 00 80 3F           lifetime = 1.0f (1 second explosion)
```

## Three Producers

### 1. HostEventHandler (0x006A1150)

Handles repair-related events in multiplayer. Registered in the `MultiplayerGame`
constructor (`0x0069E590`) for three event types:

| Event Type | Constant | Trigger |
|-----------|----------|---------|
| `0x008000DF` | ET_ADD_TO_REPAIR_LIST | Subsystem added to repair queue |
| `0x00800074` | ET_REPAIR_COMPLETED | Subsystem condition reached max (repair finished) |
| `0x00800075` | ET_REPAIR_CANNOT_BE_COMPLETED | Subsystem destroyed while queued (condition ≤ 0.0) |

**Registration gate**: Only registered when `g_IsMultiplayer != 0`.

**Behavior**:
```
HostEventHandler(MultiplayerGame* this, TGEvent* event):
  1. Read g_TGWinsockNetwork from [0x0097FA78]; if NULL, return
  2. Create TGBufferStream, store opcode byte 0x06 in buffer
  3. Call event->WriteToStream(stream) via vtable+0x34
  4. Get stream position (bytes written)
  5. Allocate TGMessage (0x40 bytes)
  6. Copy [opcode_byte][stream_data] into message (position + 1 bytes)
  7. Set msg+0x3A = 1 (reliable flag)
  8. SendTGMessageToGroup(WSN, "NoMe", msg)
```

### 2. ObjectExplodingHandler (0x006A1240)

Handles ship destruction events. Registered for `0x0080004E` (ET_OBJECT_EXPLODING).

**Dual path**:
- **Multiplayer**: Identical to HostEventHandler — serialize event with opcode 0x06,
  send reliably to "NoMe" group
- **Single-player**: Directly sets `ship+0x14C = event->lifetime` and calls
  `FUN_005ac250` (which invokes `Effects.ObjectExploding(ship)` via Python)

**Registration gate**: Always registered (not gated on multiplayer), but the handler
internally checks `g_IsMultiplayer` to select the path.

### 3. GenericEventForward / SendEventMessage (0x006A17C0)

Used by all other event-forwarding handlers (StartFiring, StopFiring, SubsystemStatus,
StartCloak, etc.). This function writes the **specific opcode** for each event type
(0x07, 0x08, 0x0A, 0x0E, etc.), **NOT** 0x06. It shares the same serialization pattern
but produces different opcodes.

Included here for completeness — GenericEventForward is NOT a producer of opcode 0x06,
but the serialization mechanism is identical (opcode byte + WriteToStream + TGMessage).

## Two Receiver Paths

### Path 1: PythonEvent Handler (FUN_0069f880) — Opcodes 0x06, 0x0D

Generic event deserializer. Handles both opcode 0x06 (PythonEvent) and 0x0D
(PythonEvent2).

```
FUN_0069f880(MultiplayerGame* this, TGMessage* msg):
  1. Extract buffer pointer and length from TGMessage via FUN_006b8530
  2. Create TGBufferStream from buffer+1 (skip opcode byte)
  3. Call FUN_006d6200 (ReadObjectFromStream):
     a. Read factory_id via stream->ReadSmallInt (vtable+0x60)
     b. Look up factory for factory_id in hash table (FUN_006f13e0)
     c. Allocate and construct event object of the correct class
     d. Call event->ReadFromStream(stream) via vtable+0x38
  4. Call FUN_006f13c0 to resolve object references
  5. Clear event+0x24 (parent event pointer = 0)
  6. Post event to local event system via FUN_006da300
  7. Release event (free if refcount reaches 0)
```

**Key characteristic**: This handler does NOT relay the message. It only deserializes
and dispatches locally. Collision-damage PythonEvents originate on the host and are
sent directly to clients via "NoMe" — no relay is needed.

**Client-originated opcode 0x06**: If a client sends an opcode 0x06 message to the
host (rare — script events), the `MultiplayerGame` dispatcher at `0x0069F2A0` hits
jump table entry for opcode 0x06 (index 4), which calls a relay function that:
1. Looks up "Forward" group in `WSN+0xF4`
2. Temporarily removes sender from group
3. Forwards message to remaining members
4. Re-adds sender
5. Then falls through to `FUN_0069f880` for local dispatch

### Path 2: Generic Event Forward (FUN_0069fda0) — Opcodes 0x07-0x12, 0x1B

Handles relay + dispatch for the specific event opcodes. These are NOT opcode 0x06
messages, but they share the same TGEvent serialization format.

**Key difference from Path 1**: Path 2 performs host relay (forwards to "Forward" group)
AND applies an event type override before local dispatch. Path 1 does neither.

### Event Type Override Table (Path 2 only)

| Opcode | Name | Sender Event | Receiver Override |
|--------|------|-------------|-------------------|
| 0x07 | StartFiring | 0x008000D8 | 0x008000D7 |
| 0x08 | StopFiring | 0x008000DA | 0x008000D9 |
| 0x09 | StopFiringAtTarget | 0x008000DC | 0x008000DB |
| 0x0A | SubsysStatus | 0x0080006C | 0x0080006C (no change) |
| 0x0B | AddToRepairList | 0x008000DF | 0 (preserve original) |
| 0x0C | ClientEvent | varies | 0 (preserve original) |
| 0x0E | StartCloak | 0x008000E2 | 0x008000E3 |
| 0x0F | StopCloak | 0x008000E4 | 0x008000E5 |
| 0x10 | StartWarp | 0x008000EC | 0x008000ED |
| 0x11 | RepairListPriority | 0x00800076 | 0 (preserve) |
| 0x12 | SetPhaserLevel | 0x008000E0 | 0 (preserve) |
| 0x1B | TorpTypeChange | 0x008000FE | 0x008000FD |

Override value `0` means the event's original type from the wire is preserved.

## Collision Damage → PythonEvent Chain

When two ships collide, the host generates approximately **14 PythonEvent messages**
— one per damaged subsystem on each ship. The complete chain:

```
1. ProximityManager detects collision
2. Posts ET_COLLISION_EFFECT (0x00800050)

3. ShipClass::CollisionEffectHandler (0x005AF9C0):
   a. Validates sender is host (checks g_IsHost at 0x0097FA89)
   b. Sends CollisionEffect (opcode 0x15) to "NoMe" group
   c. Falls through to FUN_005AFAD0 (collision damage application)

4. FUN_005AFAD0 → per-contact → FUN_005AF4A0 (per-subsystem damage):
   a. Reads subsystem condition (property+0x30)
   b. Reduces by damage amount
   c. Calls FUN_0056C470 (ShipSubsystem::SetCondition)

5. FUN_0056C470 (SetCondition):
   a. Stores new condition at this+0x30
   b. If newCondition < maxCondition AND ship alive:
      → Posts ET_SUBSYSTEM_HIT (0x0080006B)

6. RepairSubsystem::HandleHitEvent (0x005658D0) catches ET_SUBSYSTEM_HIT:
   a. Calls FUN_00565900 (AddSubsystemToRepairList)
   b. Adds to repair queue (rejects duplicates)
   c. If successful AND g_IsHost!=0 AND g_IsMultiplayer!=0:
      → Posts ET_ADD_TO_REPAIR_LIST (0x008000DF)

7. HostEventHandler (0x006A1150) catches ET_ADD_TO_REPAIR_LIST:
   → Serializes as opcode 0x06, sends to "NoMe" group
```

### Why ~14 Messages

- Two ships collide → each takes damage
- Each ship has ~7 top-level subsystems in the damage volume
- Each damaged subsystem → one SUBSYSTEM_HIT → one ADD_TO_REPAIR_LIST → one PythonEvent
- 7 subsystems × 2 ships = ~14 PythonEvent messages

The exact count varies with collision geometry and whether subsystems are already
in the repair queue (duplicates are rejected by `FUN_00565520`).

> **Stock trace confirmation**: A 33.5-minute 3-player combat session with 84 collisions
> produced 3,825 PythonEvents total. Per-collision event counts of 12-14 confirmed.

### Worked Example from Stock Dedi Packet Trace

A single collision between two ships produced these 14 messages in sequence:

| # | Factory | Event Type | Meaning |
|---|---------|-----------|---------|
| 1 | 0x8129 | 0x0080004E | ObjectExplodingEvent (ship destroyed) |
| 2-14 | 0x0101 | 0x008000DF | ADD_TO_REPAIR_LIST (13 subsystems) |

When the collision is non-lethal, all 14 are ADD_TO_REPAIR_LIST. The
ObjectExplodingEvent appears only when a ship is destroyed.

## Event Registration

### RepairSubsystem Per-Instance (0x00565220)

Registered per ship instance when the repair subsystem is created. NOT gated on
multiplayer — always active.

| Event | Handler | String Ref |
|-------|---------|-----------|
| 0x0080006B (SUBSYSTEM_HIT) | HandleHitEvent | `0x008E5058` |
| 0x00800074 (REPAIR_COMPLETE) | HandleRepairComplete | `0x008E5030` |
| 0x00800070 (SUBSYSTEM_DAMAGED) | HandleSubsystemDamaged | `0x008E5008` |
| 0x00800075 (REPAIR_CANCELLED) | HandleRepairCancelled | `0x008E4FD8` |

### MultiplayerGame HostEventHandler (0x0069E590)

Registered in MultiplayerGame constructor. Gated on `g_IsMultiplayer != 0`.

| Event | Handler |
|-------|---------|
| 0x008000DF (ADD_TO_REPAIR_LIST) | HostEventHandler (0x006A1150) |
| 0x00800074 (REPAIR_COMPLETE) | HostEventHandler (0x006A1150) |
| 0x00800075 (REPAIR_CANCELLED) | HostEventHandler (0x006A1150) |
| 0x0080004E (OBJECT_EXPLODING) | ObjectExplodingHandler (0x006A1240) |

### ShipClass Static Registration (0x005AB7C0)

Class-level registration for collision processing (not per-instance).

| Event | Handler |
|-------|---------|
| 0x00800050 (COLLISION_EFFECT) | CollisionEffectHandler |
| 0x008000FC (HOST_COLLISION_EFFECT) | Same handler, alternate path |

## TGEvent Vtable Maps

### TGEvent Base Vtable (0x00895FF4)

| Slot | Offset | Address | Name |
|------|--------|---------|------|
| 0 | +0x00 | 0x006D5D40 | scalar_deleting_dtor |
| 1 | +0x04 | 0x006D5CE0 | GetFactoryID → returns factory type |
| 2 | +0x08 | 0x006D5CF0 | IsA(id) |
| 3 | +0x0C | 0x006F1650 | (no-op, inherited from NiObject) |
| 4 | +0x10 | 0x006D5EC0 | WriteToStream_Full (persistent) |
| 5 | +0x14 | 0x006D5FF0 | ReadFromStream_Full (persistent) |
| 6 | +0x18 | 0x006D6050 | (init step) |
| 7 | +0x1C | 0x006D60B0 | (init step) |
| 8 | +0x20 | 0x006F15C0 | (no-op, inherited) |
| 9 | +0x24 | 0x006D5D10 | GetClassName → "TGEvent" |
| 10 | +0x28 | 0x006D5D20 | GetSWIGName → "_p_TGEvent" |
| 11 | +0x2C | 0x006D5D30 | GetPtrName → "TGEventPtr" |
| 12 | +0x30 | 0x006D6230 | CopyFrom |
| 13 | +0x34 | 0x006D6130 | **WriteToStream** (network) |
| 14 | +0x38 | 0x006D61C0 | **ReadFromStream** (network) |
| 15 | +0x3C | 0x006D8520 | dtor2 |
| 16 | +0x40 | 0x006D84C0 | (unknown) |
| 17 | +0x44 | 0x006D84D0 | (unknown) |

### ObjectExplodingEvent Vtable (0x0088A178)

| Slot | Offset | Address | Name |
|------|--------|---------|------|
| 0 | +0x00 | 0x0043F950 | scalar_deleting_dtor |
| 1 | +0x04 | 0x0043F8E0 | GetFactoryID → returns 0x8129 |
| 2 | +0x08 | 0x0043F8F0 | IsA(id) → true for 0x8129, 0x02 |
| 9 | +0x24 | 0x0043F920 | GetClassName → "ObjectExplodingEvent" |
| 10 | +0x28 | 0x0043F930 | GetSWIGName → "_p_ObjectExplodingEvent" |
| 11 | +0x2C | 0x0043F940 | GetPtrName → "ObjectExplodingEventPtr" |
| 13 | +0x34 | 0x0043F990 | **WriteToStream** (network) |
| 14 | +0x38 | 0x0043F9C0 | **ReadFromStream** (network) |

(Slots 3-8, 12, 15-17 inherited from TGEvent base.)

### TGCharEvent Vtable (0x008932DC)

| Slot | Offset | Address | Name |
|------|--------|---------|------|
| 0 | +0x00 | 0x00574CB0 | scalar_deleting_dtor |
| 1 | +0x04 | 0x00574C40 | GetFactoryID → returns 0x105 |
| 2 | +0x08 | 0x00574C50 | IsA(id) → true for 0x105, 0x101, 0x02 |
| 9 | +0x24 | 0x00574C80 | GetClassName → "TGCharEvent" |
| 10 | +0x28 | 0x00574C90 | GetSWIGName → "_p_TGCharEvent" |
| 11 | +0x2C | 0x00574CA0 | GetPtrName → "TGCharEventPtr" |
| 12 | +0x30 | 0x006D6920 | CopyFrom (base + char_value) |
| 13 | +0x34 | 0x006D6940 | **WriteToStream** (network) |
| 14 | +0x38 | 0x006D6960 | **ReadFromStream** (network) |

## Traffic Statistics (15-minute 3-player session)

| Direction | Count | Notes |
|-----------|-------|-------|
| PythonEvent S→C | ~251 | Repair list + explosions + script events |
| PythonEvent C→S | 0 | Clients never send 0x06 in the collision path |
| CollisionEffect C→S | ~84 | Client collision reports (opcode 0x15) |

All collision-path PythonEvents are **host-generated, server-to-client only**.

## Related Functions

| Address | Name | Role |
|---------|------|------|
| 0x006A1150 | HostEventHandler | Serializes repair events as opcode 0x06 |
| 0x006A1240 | ObjectExplodingHandler | Serializes explosion events as opcode 0x06 |
| 0x006A17C0 | SendEventMessage | Generic: serialize event + opcode → TGMessage |
| 0x0069F880 | PythonEvent receiver | Deserialize + dispatch (opcodes 0x06, 0x0D) |
| 0x0069FDA0 | GenericEventForward | Relay + deserialize (opcodes 0x07-0x12, 0x1B) |
| 0x0069F2A0 | MultiplayerGame::ReceiveMessage | Jump table dispatcher |
| 0x006D6130 | TGEvent::WriteToStream | Base event serialization |
| 0x006D61C0 | TGEvent::ReadFromStream | Base event deserialization |
| 0x006D6200 | ReadObjectFromStream | Factory-based event construction from stream |
| 0x006DA300 | EventManager::PostEvent | Posts event with auto-release |
| 0x006F13E0 | TGEventFactory::Create | Factory lookup + object allocation |
| 0x0043F990 | ObjectExplodingEvent::WriteToStream | Network serialization |
| 0x0043F9C0 | ObjectExplodingEvent::ReadFromStream | Network deserialization |
| 0x0043F8B0 | ObjectExplodingEvent::ctor | Constructor (0x30 bytes) |
| 0x006D6940 | TGCharEvent::WriteToStream | Network serialization |
| 0x006D6960 | TGCharEvent::ReadFromStream | Network deserialization |
| 0x00574C20 | TGCharEvent::ctor | Constructor (0x2C bytes) |
| 0x006D6DC0 | TGObjPtrEvent::WriteToStream | Network serialization |
| 0x006D6DF0 | TGObjPtrEvent::ReadFromStream | Network deserialization |
| 0x00403290 | TGObjPtrEvent::ctor | Constructor (0x2C bytes) |
| 0x0056C470 | ShipSubsystem::SetCondition | Posts SUBSYSTEM_HIT on damage |
| 0x00565900 | RepairSubsystem::AddToRepairList | Posts ADD_TO_REPAIR_LIST (host+MP gate) |
| 0x005658D0 | RepairSubsystem::HandleHitEvent | Catches SUBSYSTEM_HIT |
| 0x005AF9C0 | ShipClass::CollisionEffectHandler | Collision validation + damage |

## Event Type Constants

| Code | Name | Producer | Notes |
|------|------|----------|-------|
| 0x008000DF | ET_ADD_TO_REPAIR_LIST | HostEventHandler | Most common in collision chain |
| 0x00800074 | ET_REPAIR_COMPLETED | HostEventHandler | Condition reached max |
| 0x00800075 | ET_REPAIR_CANNOT_BE_COMPLETED | HostEventHandler | Subsystem destroyed while queued |
| 0x0080004E | ET_OBJECT_EXPLODING | ObjectExplodingHandler | Ship destruction |
| 0x0080006B | ET_SUBSYSTEM_HIT | (internal only) | Triggers repair queue add |
| 0x00800050 | ET_COLLISION_EFFECT | (internal only) | Starts collision chain |
| 0x008000FC | ET_HOST_COLLISION_EFFECT | (internal only) | Client-reported collision |
| 0x00800053 | ET_COLLISION_DAMAGE | (internal only) | Auto-repair trigger |
| 0x00800070 | ET_SUBSYSTEM_DAMAGED | (internal only) | Damage tracking |
| 0x0000010C | TGObjPtrEvent (factory ID) | Weapon/tractor/repair events | **45% of all PythonEvents in combat** (1,718 of 3,825 in 33.5-min battle trace). NOTE: 0x010C is a factory_id, not an event_type. Carries ET_WEAPON_FIRED, ET_PHASER_STOPPED_FIRING, ET_TRACTOR_BEAM_STOPPED_FIRING, ET_REPAIR_INCREASE_PRIORITY, ET_SUBSYSTEM_HIT. See [tgobjptrevent-class.md](tgobjptrevent-class.md). |

## Collision Chain Event Count (Verified from Stock Traces)

Stock dedi traces confirm exactly **12-14 PythonEvents per collision**:
- 1 ET_WEAPON_HIT (0x8129) or equivalent per-ship damage event
- 11 ET_SUBSYSTEM_DAMAGED (0x0101) repair-list additions
- 2 delayed events (repair completion / re-queuing)

Total count varies with collision geometry and pre-existing repair queue state.

## Related Documents

- [tgobjptrevent-class.md](tgobjptrevent-class.md) — TGObjPtrEvent (factory 0x10C) class layout, vtable, 5 C++ producers
- [collision-effect-protocol.md](collision-effect-protocol.md) — Opcode 0x15 wire format (client collision reports)
- [collision-detection-system.md](../gameplay/collision-detection-system.md) — 3-tier collision detection pipeline
- [set-phaser-level-protocol.md](set-phaser-level-protocol.md) — TGCharEvent (0x105) detailed analysis, GenericEventForward
- [damage-system.md](../gameplay/damage-system.md) — Full damage pipeline: collision, weapon, explosion paths
- [cf16-explosion-encoding.md](cf16-explosion-encoding.md) — CompressedFloat16 format used in opcode 0x29 (Explosion)
- [repair-tractor-analysis.md](../gameplay/repair-tractor-analysis.md) — Repair queue mechanics, no queue limit
- [combat-mechanics-re.md](../gameplay/combat-mechanics-re.md) — Consolidated combat RE
