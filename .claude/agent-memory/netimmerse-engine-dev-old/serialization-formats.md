# STBC Network Serialization Formats

## TGBufferStream Class (Totally Games custom, NOT stock NetImmerse)

### Class Layout
- `+0x00`: vtable pointer
- `+0x04`: error status pointer (int*)
- `+0x08`: unused
- `+0x0C`: stream position (write cursor for base class)
- `+0x1C`: buffer pointer (byte*)
- `+0x20`: buffer capacity (int)
- `+0x24`: read/write cursor position (int)
- `+0x28`: bool-pack byte position (int)
- `+0x2C`: bool-pack bit counter (byte, 0=need new byte)

### Vtables
- Derived (TGBufferStream): `0x00895C58`
- Base (TGStream):          `0x00895D60`

### Constructor Chain
- `FUN_006d1fc0` = TGStream base ctor (vtable=0x895D60, allocs 0x14-byte status object)
- `FUN_006cefe0` = TGBufferStream ctor (vtable=0x895C58, zeroes buffer fields)
- `FUN_006cf180` = TGBufferStream::Init(buffer, capacity) - sets buffer ptr + size

### Vtable Slots (0x00895C58)
| Offset | Read Function | Write Function | Type |
|--------|--------------|----------------|------|
| 0x48/0x4C | FUN_006cf580 | FUN_006cf770 | Bool (bit-packed) |
| 0x50/0x54 | FUN_006cf540 | FUN_006cf730 | Byte (uint8) |
| 0x58/0x5C | FUN_006cf600 | FUN_006cf7f0 | Short (uint16 LE) |
| 0x60/0x64 | FUN_006cf640 | FUN_006cf830 | Dword24 (24-bit LE) |
| 0x68/0x6C | FUN_006cf670 | FUN_006cf870 | Dword (uint32 LE) |
| 0x70/0x74 | FUN_006cf6b0 | FUN_006cf8b0 | Float (IEEE 754 LE) |
| 0x78/0x7C | FUN_006cf6f0 | FUN_006cf8f0 | Double (IEEE 754 LE) |
| 0x80/0x84 | FUN_006cf6a0 | FUN_006cf930 | Int32 (signed, LE) |
| 0x88/0x8C | FUN_006d2e50 / FUN_006d2eb0 | Write/ReadCompressedVec3 |
| 0x90/0x94 | FUN_006d2f10 / FUN_006d2fd0 | Write/ReadCompressedVec4 |
| 0x98/0x9C | FUN_006d3070 / FUN_006d30e0 | Write/ReadCompressedPos |
| 0xA0 | FUN_006d29a0 | EncodeVec3_unsigned (direction only) |
| 0xA4 | FUN_006d2ad0 | EncodeVec3_signed (direction + magnitude) |
| 0xA8 | FUN_006d2c10 | EncodeDirection (normalize * 127) |
| 0xAC | FUN_006d2d10 | EncodeDirection variant |
| 0xB0 | FUN_006d2a60 | DecodeVec3_unsigned |
| 0xB4 | FUN_006d2ba0 | DecodeVec3_signed |
| 0xB8 | FUN_006d2c60 | DecodeDirection (* 127 inverse) |
| 0xBC | FUN_006d2d70 | DecodeDirection variant |

### Utility
- `FUN_006cf9b0` = GetPosition() - returns cursor at +0x24

## Bool Bit-Packing (FUN_006cf580 read / FUN_006cf770 write)
Packs up to 5 boolean values into a single byte:
- High 3 bits (7-5): count of bools stored (1-5, stored as count value)
- Low 5 bits (4-0): the boolean values, one per bit
- Read: mask=1, shifts left each read. When mask exceeds (1<<count), byte exhausted
- Write: accumulates bits. When count reaches 5, byte is finalized

## Compressed Direction Vector (3 bytes)
**Encoding** (`FUN_006d2ad0` / `FUN_006d2c10`):
1. Compute magnitude = sqrt(x^2 + y^2 + z^2)
2. If magnitude > 1e-6 (0x00888b58): normalize (x,y,z) /= magnitude
3. Multiply each normalized component by 127.0 (0x00895e50)
4. Truncate to signed byte via __ftol

**Wire format**: `[sx:int8] [sy:int8] [sz:int8]` = 3 bytes

**Decoding** (`FUN_006d2c60`):
- Each byte / 127.0 = float component in [-1.0, +1.0]
- Multiply by separately-transmitted magnitude to reconstruct

## Logarithmic Magnitude Compression (2 bytes)
**Encoding** (`FUN_006d3a90`):
1. If value < 0: set sign flag, negate
2. Find bucket E (0-7): range_low = 0.001 * 10^E, searching until value < range_high
3. Compute mantissa M = ((value - range_low) / (range_high - range_low)) * 4095.0
4. Pack: `result = (E << 12) | M; if (sign) E |= 8`

**Bit layout**: `[S:1][E:3][M:12]` = uint16
- S = sign (bit 15)
- E = exponent 0-7 (bits 14-12)
- M = mantissa 0-4095 (bits 11-0)

**Range table** (base-10 logarithmic):
| E | Low | High | Resolution |
|---|-----|------|-----------|
| 0 | 0.0 | 0.001 | ~0.000000244 |
| 1 | 0.001 | 0.01 | ~0.00000220 |
| 2 | 0.01 | 0.1 | ~0.0000220 |
| 3 | 0.1 | 1.0 | ~0.000220 |
| 4 | 1.0 | 10.0 | ~0.00220 |
| 5 | 10.0 | 100.0 | ~0.0220 |
| 6 | 100.0 | 1000.0 | ~0.220 |
| 7 | 1000.0 | 10000.0 | ~2.20 |

Overflow: if value >= 10000 (all 8 buckets exhausted), clamps to E=7, M=0xFFF

**Decoding** (`FUN_006d3b30`):
```
S = (raw >> 12) & 8  (actually bit 15)
E = (raw >> 12) & 7  (bits 14-12)
M = raw & 0xFFF      (bits 11-0)
range_low = iterate: start at 0.001, multiply by 10.0 E times
range_high = range_low * 10.0 (one more iteration)
value = range_low + (M / 4095.0) * (range_high - range_low)
if S: value = -value
```

## Key Constants
| Address | Value | Usage |
|---------|-------|-------|
| 0x00888b4c | 0.001f | Base range for magnitude compression |
| 0x00888b54 | 0.0f | Zero constant / epsilon |
| 0x0088c548 | 10.0f | Range multiplier (base-10 logarithmic) |
| 0x00895e50 | 127.0f | Direction component scale factor |
| 0x00895f50 | 4095.0f | Mantissa scale (encoding) |
| 0x00895f54 | 1/4095.0f | Mantissa inverse (decoding) |
| 0x00888860 | 1.0f | Timestamp delta threshold |
| 0x00888b58 | 1e-6f | Near-zero magnitude epsilon |
| 0x008944c4 | 1/204.0f | Weapon health byte->float scale |

## State Update Packet (opcode 0x1C)
Built by `FUN_005b17f0`, received by `FUN_005b21c0`.

### Header (10 bytes always)
```
[0x1C:u8] [objectID:u32] [timestamp:f32] [dirtyFlags:u8]
```

### Dirty Flags
| Bit | Mask | Field |
|-----|------|-------|
| 0 | 0x01 | POSITION (absolute, 3 floats + auth bool + optional checksum) |
| 1 | 0x02 | VELOCITY (compressed vec4 signed = 5 bytes) |
| 2 | 0x04 | ORIENTATION_FWD (compressed vec3 = 3 bytes) |
| 3 | 0x08 | ORIENTATION_UP (compressed vec3 = 3 bytes) |
| 4 | 0x10 | SPEED (compressed magnitude = 2 bytes) |
| 5 | 0x20 | SUBSYSTEMS (round-robin, variable length) |
| 6 | 0x40 | CLOAK_STATE (1 bool, bit-packed) |
| 7 | 0x80 | WEAPONS (round-robin, variable length) |

### Object IDs
- 32-bit unsigned integer (uint32)
- Assigned by server at object creation time
- Stored at object+0x04 (piVar17[1])
- Looked up via hash table in network manager

### Delta Compression Strategy
- NOT snapshot-based: uses dirty flags per field
- Position: absolute (not delta) when changed beyond threshold
- Velocity: delta from last known position (compressed)
- Orientation: stored as two axes (forward + up), compressed
- Subsystems/weapons: round-robin serialization (N items per tick, wraps)
- Timestamp ordering: field only applied if newer than last received
