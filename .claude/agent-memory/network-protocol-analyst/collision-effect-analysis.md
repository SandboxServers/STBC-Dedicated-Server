# CollisionEffect (Opcode 0x15) - Complete Analysis

## Wire Format

```
Offset  Size  Type    Field                    Notes
------  ----  ----    -----                    -----
0       1     u8      opcode                   Always 0x15
1       4     i32     event_type_class_id      Always 0x00008124 (collision event factory)
5       4     i32     event_code               Always 0x00800050 (ET_COLLISION_EFFECT)
9       4     i32v    source_object_id         Other colliding object (0x00000000 = environment)
13      4     i32v    target_object_id         Ship reporting collision (BC network object ID)
17      1     u8      contact_count            Number of collision contact points (1-2 typical)
[per contact, 4 bytes each:]
  +0    1     s8      dir_x                    Normalized direction X (signed byte)
  +1    1     s8      dir_y                    Normalized direction Y (signed byte)
  +2    1     s8      dir_z                    Normalized direction Z (signed byte)
  +3    1     u8      magnitude_byte           Distance from ship center (compressed)
[end per contact]
+0      4     f32     collision_force          Impact force magnitude (IEEE 754 float)
```

Total: 22 + contact_count * 4 bytes

## Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x005871a0 | CollisionEvent::Write | Serializes to stream (vtable+0x34) |
| 0x00587300 | CollisionEvent::Read | Deserializes from stream (vtable+0x38) |
| 0x006a2470 | Handler_CollisionEffect_0x15 | Server-side handler in MP game dispatcher |
| 0x006a17c0 | Event forwarder | Generic sender (writes opcode + event->Write) |
| 0x006d6130 | TGEvent::Write | Base class Write (typeId, code, src, tgt) |
| 0x006d61c0 | TGEvent::Read | Base class Read (code, src, tgt) |
| 0x006d6200 | TGEvent factory reader | Reads typeId, creates event, calls Read |
| 0x006d3070 | WriteCompressedVec4Byte | Writes 4 bytes: 3 dir + 1 mag |
| 0x006d30e0 | ReadCompressedVec4Byte | Reads 4 bytes, decompresses |
| 0x006d29a0 | CompressVec3ToDirBytes | Normalize Vec3 -> 3 signed bytes + mag |
| 0x006d2d10 | CompressVec4ByteMagnitude | Wraps CompressVec3, adds magnitude byte |
| 0x005afad0 | HostCollisionEffectHandler | Host-side damage application |

## Collision Event Object Layout (size 0x44)

| Offset | Type | Field |
|--------|------|-------|
| +0x00 | vtable* | Primary vtable (0x0089395c) |
| +0x04 | int | Instance ID |
| +0x08 | obj* | Source object (other collider) |
| +0x0C | obj* | Target object (reporting ship) |
| +0x10 | int | Event code (0x00800050) |
| +0x14 | float | Timestamp/delay (-1.0 default) |
| +0x18 | short | Reserved (0) |
| +0x1A | short | Reserved (0) |
| +0x28 | vtable* | Secondary vtable for contact array container (0x0089399c) |
| +0x2C | ptr | Contact point array (each entry = Vec3 ptr) |
| +0x30 | int | Array capacity |
| +0x34 | int | Used count in array |
| +0x38 | int | Contact count (written as u8 on wire) |
| +0x3C | int | Grow amount |
| +0x40 | float | Collision force magnitude |

## Compression Algorithm

### Write Path (0x005871a0)
1. Call parent TGEvent::Write (writes typeClassId, eventCode, srcObjId, tgtObjId)
2. WriteByte: event+0x38 (contact count)
3. For each contact point in event+0x2C array:
   a. Load contact Vec3 (X, Y, Z world position)
   b. If target object exists:
      - Subtract ship NiNode position (+0x88, +0x8C, +0x90)
      - Transform by inverse rotation matrix (NiNode+0x64)
      - Scale by DAT_00888860 / NiNode+0x94 (bounding radius normalization)
   c. If no target: use raw position, magnitude = sqrt(x^2+y^2+z^2)
   d. Call stream vtable+0x98 (WriteCompressedVec4Byte) which:
      - Calls vtable+0xA0 (CompressVec3): magnitude=sqrt(sum squares),
        normalize each component by scale/magnitude, ftol to signed byte
      - Calls vtable+0xAC wrapper: divides magnitude by reference,
        multiplies by DAT_0088b9ac, ftol to unsigned byte
      - Writes 4 bytes via WriteByte
4. WriteFloat: event+0x40 (collision force)

### Read Path (0x00587300)
1. Call parent TGEvent::Read (reads eventCode, srcObjId, tgtObjId)
2. Look up target object bounding radius:
   - If found: bbox+0xC (bounding sphere radius)
   - If radius == 0: use 0.01 as default
   - If not found: use 1.0 as default
3. ReadByte: contact count
4. For each contact:
   - Call stream vtable+0x9C (ReadCompressedVec4Byte):
     reads 4 bytes, decompresses using bounding radius
   - Allocate Vec3 (12 bytes), store decompressed XYZ
   - Insert into contact array at event+0x2C
5. ReadFloat: force -> store at event+0x40

## Handler Flow (0x006a2470)

1. Extract raw buffer from TGMessage
2. Create TGBufferStream from buffer+1, len-1 (skip opcode)
3. Reconstruct TGEvent via FUN_006d6200 (factory + Read)
4. Resolve object references via FUN_006f13c0
5. Clear event+0x24 (unknown cleanup)
6. Get sender's ship via GetShipFromPlayerID
7. Anti-spoof: verify sender owns one of the collision objects
8. Deduplication: if sender==source AND target is player-controlled, drop
   (the target player should report their own collision separately)
9. Proximity check: distance - radius1 - radius2 < DAT_008955c8
10. Change event code: 0x00800050 -> 0x008000fc (HostCollisionEffect)
11. Post modified event to event manager (0x0097f838)

## Sample Decodes

| Packet | Src | Target | Contacts | Force | Notes |
|--------|-----|--------|----------|-------|-------|
| P1 | NULL | Player 0 | 1: (+13,+126,0) m=217 | 1281.0 | Hard environment hit |
| P2 | NULL | Player 0 | 1: (+13,+126,0) m=217 | 0.07 | Light bump, same spot |
| P3 | NULL | Player 0 | 1: (+5,+126,0) m=216 | 1234.2 | Heavy, mostly +Y |
| P4 | NULL | Player 0 | 2: (+15,+126,0), (0,+126,-1) | 927.1 | Two contact points |
| P5 | NULL | Player 0 | 1: (-10,+126,-2) m=217 | 580.7 | Slight negative X |
| P6 | NULL | Player 1 | 1: (+39,+119,+17) m=184 | 661.1 | Diagonal hit |
