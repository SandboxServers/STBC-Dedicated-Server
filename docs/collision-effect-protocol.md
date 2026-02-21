# Opcode 0x15 - CollisionEffect Protocol Analysis

Complete decompilation and wire format analysis of the collision effect network message
(opcode 0x15) in Star Trek: Bridge Commander multiplayer.

## Overview

Opcode 0x15 (CollisionEffect) carries collision event data from the detecting client to
the host. The host validates the report, then applies authoritative collision damage and
broadcasts visual effects. The message contains a serialized `CollisionEvent` object
(TGEvent class type `0x8124`) with compressed contact points and a force magnitude.

**Direction**: Client -> Host
**Handler**: `Handler_CollisionEffect_0x15` at `0x006a2470`
**Write method**: `CollisionEvent::WriteToStream` at `0x005871a0` (vtable+0x34)
**Read method**: `CollisionEvent::ReadFromStream` at `0x00587300` (vtable+0x38)
**Frequency**: ~84 per 15-minute stock session (4th most common combat opcode)

## Wire Format

### Complete Packet Layout

```
Offset  Size  Type    Field                    Notes
------  ----  ----    -----                    -----
0       1     u8      opcode                   Always 0x15
1       4     i32     event_type_class_id      Always 0x00008124 (CollisionEvent factory ID)
5       4     i32     event_code               Always 0x00800050 (ET_OBJECT_COLLISION)
9       4     i32v    source_object_id         Other colliding object (0 = environment/NULL)
13      4     i32v    target_object_id         Ship reporting the collision (BC object ID)
17      1     u8      contact_count            Number of contact points (typically 1-2)
[repeated contact_count times:]
  +0    1     s8      dir_x                    Compressed direction X (signed byte)
  +1    1     s8      dir_y                    Compressed direction Y
  +2    1     s8      dir_z                    Compressed direction Z
  +3    1     u8      magnitude_byte           Compressed distance from ship center
[end repeat]
+0      4     f32     collision_force          IEEE 754 float: impact force magnitude
```

**Total size**: `22 + contact_count * 4` bytes (typically 26 for 1 contact, 30 for 2).

All multi-byte values are **little-endian**.

### Constant Prefix (13 bytes)

The first 13 bytes are constant across all observed CollisionEffect packets:

```
15 24 81 00 00 50 00 80 00 00 00 00 00
```

- `15` = opcode (0x15)
- `24 81 00 00` = class type ID `0x00008124` (CollisionEvent factory)
- `50 00 80 00` = event code `0x00800050` (ET_OBJECT_COLLISION)
- `00 00 00 00` = source object ID = 0 (environment collision, no specific object)

### Contact Point Compression

Each contact point is 4 bytes on the wire, representing a compressed ship-relative position.
The engine uses a "CompressedVec4_Byte" format (`stream->vtable+0x98`/`+0x9C`).

**Compression** (WriteToStream at `0x005871a0`, via `stream->vtable+0xA0` at `0x006d29a0`):

1. **Ship-relative transform**: World-space contact position is transformed to ship-local coords:
   - Subtract ship NiNode world position (NiNode+0x88/0x8C/0x90)
   - Apply inverse rotation via matrix multiply (`FUN_00813aa0` with NiNode+0x64 rotation matrix)
   - Scale by `DAT_00888860 / NiNode+0x94` (bounding sphere normalization)

2. **Direction compression** (`vtable+0xA0` at `0x006d29a0`):
   - Compute magnitude = sqrt(x^2 + y^2 + z^2)
   - If magnitude > threshold: normalize each component by (SCALE / magnitude)
   - Convert normalized components to signed bytes via ftol
   - Output: 3 signed direction bytes (dir_x, dir_y, dir_z)

3. **Magnitude compression** (`vtable+0xAC` at `0x006d2d10`):
   - Divides magnitude by reference value (bounding radius)
   - Multiplies by scale constant at `DAT_0088b9ac`
   - Converts to unsigned byte via ftol

**Decompression** (ReadFromStream at `0x00587300`, via `stream->vtable+0x9C` at `FUN_006d30e0`):

1. Reads 4 bytes (ReadByte x4)
2. Gets bounding sphere radius from target object (vtable+0xE4 GetBoundingBox, radius at bbox+0x0C)
3. If target not found: uses 1.0 as default radius; if radius is 0: uses 0.01
4. Calls `vtable+0xBC` to decompress 4 bytes back to Vec3 using radius as scale
5. Allocates Vec3 (12 bytes) and stores in contact point array at event+0x2C

### Two Serialization Paths

The CollisionEvent class has **two** serialization formats:

| Path | Write Function | Read Function | Format |
|------|---------------|---------------|--------|
| **Network** (vtable+0x34/+0x38) | `0x005871a0` | `0x00587300` | Compressed: u8 count, 4-byte contacts, f32 force |
| **Persistence** (vtable+0x10/+0x14) | `0x00586fb0` | `0x00587030` | Full: u32 count, 12-byte Vec3 contacts, f32 force |

The network path uses WriteToStream/ReadFromStream (compact, compressed).
The persistence path uses WriteStream/ReadStream (full, uncompressed, includes all TGEvent base fields).

**Only the network format appears on the wire.** The persistence format is for NiStream save/load.

### Example Packet Decodes

**P1** (26 bytes, Sovereign hitting asteroid on Multi1):
```
15                    opcode = 0x15 (CollisionEffect)
24 81 00 00           type_class_id = 0x00008124
50 00 80 00           event_code = 0x00800050 (ET_COLLISION_EFFECT)
00 00 00 00           source_obj_id = 0x00000000 (environment collision)
FF FF FF 3F           target_obj_id = 0x3FFFFFFF (Player 0 ship)
01                    contact_count = 1
0D 7E 00 D9           contact[0]: dir=(+13, +126, +0) mag=217
BB 20 A0 44           force = 1281.02f (0x44A020BB)
```

**P4** (30 bytes, 2 contact points):
```
15                    opcode = 0x15
24 81 00 00           type_class_id = 0x00008124
50 00 80 00           event_code = 0x00800050
00 00 00 00           source_obj_id = 0x00000000
FF FF FF 3F           target_obj_id = 0x3FFFFFFF
02                    contact_count = 2
0F 7E 00 DA           contact[0]: dir=(+15, +126, +0) mag=218
00 7E FF D8           contact[1]: dir=(+0, +126, -1) mag=216
51 C3 67 44           force = 927.05f (0x4467C351)
```

**P6** (26 bytes, 3-player combat, different ship):
```
15                    opcode = 0x15
24 81 00 00           type_class_id = 0x00008124
50 00 80 00           event_code = 0x00800050
00 00 00 00           source_obj_id = 0x00000000
FF FF 03 40           target_obj_id = 0x400003FF (Player 0 range, offset +1024)
01                    contact_count = 1
27 77 11 B8           contact[0]: dir=(+39, +119, +17) mag=184
9D 47 25 44           force = 661.12f (0x4425479D)
```

## CollisionEvent Class Layout (0x44 bytes)

```
Offset  Size  Type           Field               Notes
------  ----  ----           -----               -----
0x00    4     void**         vtable_primary       0x0089395c
0x04    4     int            ni_refcount          NiObject reference count
0x08    4     void*          source_object        Source object ptr (resolved from ID)
0x0C    4     void*          target_object        Target object ptr (resolved from ID)
0x10    4     uint32         event_type           0x00800050 = ET_OBJECT_COLLISION
0x14    4     float          time_stamp           Event timestamp
0x18    2     uint16         flags_a              Event flags
0x1A    2     uint16         flags_b              Event flags
0x1C    4     void*          (reserved)
0x20    4     void*          (reserved)
0x24    4     void*          parent_event         Parent event ptr (resolved from ID)
0x28    4     void**         vtable_secondary     0x0089399c (embedded base class)
0x2C    4     Vec3**         point_array          Array of pointers to Vec3 contact points
0x30    4     int            array_capacity       Allocated capacity (init=1)
0x34    4     int            point_count_alloc    Actual count of allocated point entries
0x38    4     int            num_points           Serialized point count (GetNumPoints)
0x3C    4     int            (unknown)            Init=1, possibly max_points or flag
0x40    4     float          collision_force      Force magnitude (GetCollisionForce)
```

### Constructor (0x00586d00)

```
this+0x28 = vtable 0x0089399c    (embedded base class)
this+0x2C = NiAlloc(4)           (point array, initial capacity 1)
this+0x30 = 1                    (capacity)
this+0x34 = 0                    (used count)
this+0x38 = 0                    (num_points)
this+0x3C = 1                    (unknown)
this+0x40 = 0.0                  (collision_force)
this[0]   = vtable 0x0089395c    (primary vtable, set LAST)
```

### Destructor (0x00586e20)

Frees each Vec3 in point_array (loop over point_count entries), then frees
the point_array itself, then calls base destructor FUN_006d5d70.

### SWIG Python API

| Function | C++ Target | Field |
|----------|-----------|-------|
| `CollisionEvent_GetNumPoints(event)` | this+0x38 | Returns point count |
| `CollisionEvent_GetPoint(event, idx)` | FUN_00595410 | Copies Vec3 from point_array[idx] |
| `CollisionEvent_GetCollisionForce(event)` | this+0x40 | Returns force float |

## Handler Logic (0x006a2470)

### Receive-Side Flow

```
Handler_CollisionEffect_0x15(TGMessage* msg):
  1. Extract buffer from message (FUN_006b8530)
  2. Create StreamReader (vtable 0x00895c58), init with (buffer+1, size-1)
  3. Deserialize CollisionEvent from stream (FUN_006d6200):
     a. Read class_type_id (u32) = 0x8124
     b. Factory lookup in hash table (FUN_006f13e0)
     c. Factory creates CollisionEvent (0x44 bytes)
     d. Call CollisionEvent::ReadFromStream (vtable+0x38 = 0x00587300)
  4. Resolve object ID references (FUN_006f13c0)
  5. Call PostProcess (vtable+0x3C = 0x005874a0)
  6. Clear parent_event (this+0x24 = 0)

  7. Get sender's ship: GetShipFromPlayerID(msg+0x0C) [FUN_006a1aa0]

  VALIDATION 1 - Ownership:
  8. sender_ship must equal event.source OR event.target
     If neither matches: REJECT (free event, return)

  VALIDATION 2 - Self-collision filter:
  9. If sender_ship == event.source:
     - Get target: CastToShipClass(event.target) [FUN_005ab670]
     - Check: IsLocalPlayerShip(target) [FUN_005ae140]
     - If target IS local player: REJECT (prevents double-processing)

  VALIDATION 3 - Distance check:
  10. Get positions of both ships (vtable+0x94 = GetWorldTranslation)
      Get bounding radii of both (vtable+0xE4 = GetModelBound, radius at +0xC)
      Compute: gap = distance(ship1, ship2) - radius1 - radius2
      If gap >= DAT_008955c8 (threshold): REJECT (too far apart)

  ACCEPT:
  11. Set event type to 0x008000FC (ET_HOST_OBJECT_COLLISION)
  12. Post to event queue at DAT_0097f838
```

### Validation Summary

| Check | Purpose | Anti-abuse |
|-------|---------|-----------|
| Ownership | Sender must own source or target object | Prevents spoofing damage to unrelated ships |
| Self-collision | Won't process if target is local player's ship | Prevents double-counting when both sides report |
| Distance | Objects must be within bounding-sphere proximity | Prevents phantom collisions at range |

### Event Type Transformation

The event arrives as `ET_OBJECT_COLLISION` (0x00800050) but is re-posted as
`ET_HOST_OBJECT_COLLISION` (0x008000FC). This allows the host's event handlers to
distinguish locally-detected collisions from network-reported ones.

## Send-Side Flow

The send side is triggered when a CLIENT detects a collision locally:

1. Collision detection fires `ET_OBJECT_COLLISION` (0x00800050) event
2. `ShipClass::CollisionEffectHandler` (0x005af9c0) handles it
3. Handler calls `CollisionEvent::WriteToStream` (vtable+0x34 = 0x005871a0):
   - Transforms each contact point to ship-relative coordinates
   - Compresses via CompressedVec4_Byte format (4 bytes per contact)
   - Writes collision_force as raw f32
4. Wraps in TGMessage with opcode 0x15, sends to host via TGWinsockNetwork

## Host-Side Damage Processing

After the handler re-posts the event as `ET_HOST_OBJECT_COLLISION` (0x008000FC):

1. **ShipClass::HostCollisionEffectHandler** (0x005afad0):
   - If multiplayer: creates secondary event `0x00800053` for effect broadcast
   - Iterates contact points, transforms each relative to the ship's NiNode
   - **Per-contact damage scaling** (constants verified from binary):
     ```
     raw = (collisionEnergy / ship.mass) / contactCount
     if (raw > 0.01):                          // dead zone filter
         scaled = raw * 900.0 + 500.0          // absolute HP damage
         SubsystemDamageDistributor(ship, dir, &scaled, 1.5, attacker, 1)
     ```
   - Output range: 500.0+ absolute HP (NOT fractional like DoDamage_CollisionContacts)
   - `FUN_005afd70` -> `FUN_005aecc0` (subsystem lookup) -> `FUN_005af4a0` (damage per subsystem)
   - Each subsystem receives the full scaled damage; overflow accumulated across all subsystems

2. **DamageableObject::CollisionEffectHandler** also fires (registered for both 0x00800050 and 0x008000FC)

3. **Effects.CollisionEffect** (Python handler) creates visual explosions at contact points

## Event Registration

### ShipClass Event Handlers (registered in FUN_005ab7c0)

```
ET_OBJECT_COLLISION (0x00800050)      -> ShipClass::CollisionEffectHandler     (0x005af9c0)
ET_HOST_OBJECT_COLLISION (0x008000FC) -> ShipClass::HostCollisionEffectHandler (0x005afab0)
```

### DamageableObject Event Handlers (registered in FUN_00590bb0)

```
ET_OBJECT_COLLISION (0x00800050)      -> DamageableObject::CollisionEffectHandler
ET_HOST_OBJECT_COLLISION (0x008000FC) -> DamageableObject::CollisionEffectHandler  (same handler)
ET_OBJECT_COLLISION (0x00800050)      -> "Effects.CollisionEffect"  (Python, via FUN_006d92d0)
```

## Related Functions

| Address | Name | Role |
|---------|------|------|
| 0x006a2470 | Handler_CollisionEffect_0x15 | Network receive handler (opcode 0x15 dispatcher) |
| 0x005871a0 | CollisionEvent::WriteToStream | Network serialization (vtable+0x34) |
| 0x00587300 | CollisionEvent::ReadFromStream | Network deserialization (vtable+0x38) |
| 0x005874a0 | CollisionEvent::PostProcess | Post-deserialization reference resolution (vtable+0x3C) |
| 0x00586fb0 | CollisionEvent::WriteStream | Persistence serialization (vtable+0x10) |
| 0x00587030 | CollisionEvent::ReadStream | Persistence deserialization (vtable+0x14) |
| 0x00586d00 | CollisionEvent::ctor | Constructor (size 0x44) |
| 0x00586df0 | CollisionEvent::dtor | Scalar deleting destructor |
| 0x00586e20 | CollisionEvent::Destroy | Frees points array + base cleanup |
| 0x005af9c0 | ShipClass::CollisionEffectHandler | Client-side: serializes + sends to host |
| 0x005afad0 | ShipClass::HostCollisionEffectHandler | Host-side: applies collision damage |
| 0x005afd70 | CollisionDamageWrapper_Helper | Per-contact-point damage distribution |
| 0x005aecc0 | SubsystemLookupByPosition | Finds nearest subsystem to contact point |
| 0x005af4a0 | ApplySubsystemDamage | Applies damage to specific subsystem |
| 0x005ae140 | IsLocalPlayerShip | Checks if ship is local player's |
| 0x005ab670 | CastToShipClass | Returns ship if class type 0x8008 |
| 0x006a1aa0 | GetShipFromPlayerID | Maps connection ID to ship ptr (__cdecl) |
| 0x006b8530 | TGMessage::GetBuffer | Extracts data ptr + size from message |
| 0x006cefe0 | StreamReader::ctor | Constructs stream reader |
| 0x006cf180 | StreamReader::Init | Sets buffer, offset, size |
| 0x006d6200 | ReadObjectFromStream | Creates + deserializes TGEvent |
| 0x006f13e0 | TGEventFactory::Lookup | Hash table factory for event classes |
| 0x006f13c0 | ResolveReferences | Resolves object IDs to pointers |
| 0x00595410 | CollisionEvent::GetPointInternal | Copies Vec3 from point_array |
| 0x006d29a0 | CompressVec4_Byte_Direction | Normalizes + compresses to 3 signed bytes |
| 0x006d2d10 | CompressVec4_Byte_Magnitude | Compresses magnitude to unsigned byte |
| 0x006d30e0 | DecompressVec4_Byte | Decompresses 4 bytes to Vec3 using bounding radius |

## CollisionEvent Vtable Map (0x0089395c)

| Offset | Target     | Name |
|--------|-----------|------|
| +0x00  | 0x00586df0 | scalar_deleting_dtor |
| +0x04  | 0x00586d80 | (unknown) |
| +0x08  | 0x00586d90 | (unknown) |
| +0x0C  | 0x006f1650 | (inherited from NiObject) |
| +0x10  | 0x00586fb0 | WriteStream (persistence) |
| +0x14  | 0x00587030 | ReadStream (persistence, full TGEvent fields) |
| +0x18  | 0x006d6050 | ReadClassName (inherited) |
| +0x1C  | 0x006d60b0 | WriteClassName (inherited) |
| +0x20  | 0x006f15c0 | (inherited from NiObject) |
| +0x24  | 0x00586dc0 | GetName / GetRTTI ("CollisionEvent") |
| +0x28  | 0x00586dd0 | (unknown) |
| +0x2C  | 0x00586de0 | (unknown) |
| +0x30  | 0x00586e70 | CopyFrom |
| +0x34  | 0x005871a0 | WriteToStream (network, compressed) |
| +0x38  | 0x00587300 | ReadFromStream (network, compressed) |
| +0x3C  | 0x005874a0 | PostProcess / ResolveLinks |

## TGEvent Base Vtable (0x00895ff4) for Reference

| Offset | Target     | Name |
|--------|-----------|------|
| +0x00  | 0x006d5d40 | scalar_deleting_dtor |
| +0x04  | 0x006d5ce0 | (unknown) |
| +0x08  | 0x006d5cf0 | (unknown) |
| +0x0C  | 0x006f1650 | (inherited) |
| +0x10  | 0x006d5ec0 | TGEvent::WriteStream |
| +0x14  | 0x006d5ff0 | TGEvent::ReadStream |
| +0x18  | 0x006d6050 | ReadClassName |
| +0x1C  | 0x006d60b0 | WriteClassName |
| +0x20  | 0x006f15c0 | (inherited) |
| +0x24  | 0x006d5d10 | GetName |
| +0x28  | 0x006d5d20 | (unknown) |
| +0x2C  | 0x006d5d30 | (unknown) |
| +0x30  | 0x006d6230 | CopyFrom |
| +0x34  | 0x006d6130 | WriteToStream (network) |
| +0x38  | 0x006d61c0 | ReadFromStream (network) |
| +0x3C  | 0x006d8520 | PostProcess |
| +0x40  | 0x006d84c0 | (unknown, not overridden by CollisionEvent) |

## Stream Reader Vtable (0x00895c58)

| Vtable Offset | Function     | Type    | Size |
|---------------|-------------|---------|------|
| +0x50         | 0x006cf5e0  | ReadByte | 1 byte (u8/s8) |
| +0x58         | 0x006cf600  | ReadU16 | 2 bytes |
| +0x60         | 0x006cf640  | ReadU32 | 4 bytes (class type ID) |
| +0x68         | 0x006cf670  | ReadU32 | 4 bytes (general purpose) |
| +0x70         | 0x006cf6b0  | ReadF32 | 4 bytes |
| +0x80         | 0x006cf6a0  | ReadObjID | Thunks to ReadU32 at +0x68 |
| +0x9C         | 0x006d30e0  | DecompressVec4_Byte | 4 bytes -> Vec3 |
| +0xB8         | (varies)    | DecompressVec3 | 3 bytes -> Vec3 |
| +0xBC         | (varies)    | DecompressVec4_ByteCore | 4 bytes -> Vec3 (with magnitude) |
