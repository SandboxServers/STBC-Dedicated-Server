> [docs](../README.md) / [protocol](README.md) / stream-primitives.md

# Stream Primitives & Compressed Data Types

All serialization uses a `TGBufferStream` object (`FUN_006cefe0` constructor). The stream has:
- `+0x1C` = buffer pointer
- `+0x20` = buffer capacity
- `+0x24` = current write/read position
- `+0x28` = bit-packing bookmark position
- `+0x2C` = bit-packing state (0 = no active bit group)

## Write Functions (Server -> Wire)

| Function | Type | Size | Description |
|----------|------|------|-------------|
| `FUN_006cf730` | WriteByte | 1 byte | Writes `uint8` at current position |
| `FUN_006cf770` | WriteBit | 0-1 bytes | Packs boolean bits into a shared byte (see Bit Packing) |
| `FUN_006cf7f0` | WriteShort | 2 bytes | Writes `uint16` (little-endian) |
| `FUN_006cf870` | WriteInt32 | 4 bytes | Writes `int32` / `uint32` |
| `FUN_006cf8b0` | WriteFloat | 4 bytes | Writes `float32` (IEEE 754) |
| `FUN_006cf2b0` | WriteBytes | N bytes | Writes raw byte array (memcpy) |
| `FUN_006cf9b0` | GetPosition | - | Returns current stream position (uint32) |

## Read Functions (Wire -> Client)

| Function | Type | Size | Description |
|----------|------|------|-------------|
| `FUN_006cf540` | ReadByte | 1 byte | Reads `uint8` |
| `FUN_006cf580` | ReadBit | 0-1 bytes | Reads packed boolean bit |
| `FUN_006cf600` | ReadShort | 2 bytes | Reads `uint16` (little-endian) |
| `FUN_006cf670` | ReadInt32 | 4 bytes | Reads `int32` / `uint32` |
| `FUN_006cf6b0` | ReadFloat | 4 bytes | Reads `float32` (IEEE 754) |
| `FUN_006cf6a0` | ReadInt32v | 4 bytes | Reads via vtable (variant read) |
| `FUN_006cf230` | ReadBytes | N bytes | Reads raw byte array |

## Bit Packing Format

`WriteBit` / `ReadBit` (`FUN_006cf770` / `FUN_006cf580`) use a compact bit-packing scheme:

A single byte encodes up to 5 boolean values:
```
Byte layout:  [count:3][bits:5]
              MSB          LSB

count (bits 7-5): Number of bits packed (1-5), stored as the actual count
bits  (bits 4-0): The actual boolean values, one per bit position
```

The packing state machine:
- First `WriteBit` call allocates a new byte at the current position and sets bit 0, count=1
- Subsequent calls OR the value into the next bit position and increment count
- The count field (upper 3 bits) tracks how many bits are stored (1=one bit, 5=full)
- After 5 bits, the byte is "full" and the next WriteBit starts a new byte
- The `+0x2C` field in the stream tracks whether we're mid-pack (non-zero) or not

On read, `ReadBit` extracts each bit in order, advancing the count. When all packed bits in the current byte have been consumed, the next ReadBit starts reading a fresh byte.

---

## Compressed Data Types

### CompressedFloat16 (Logarithmic Scale Compression)

Used for: speed values, damage amounts, distances. Full analysis in [cf16-precision-analysis.md](cf16-precision-analysis.md).

**Constants** (extracted from .rdata):
- `DAT_00888b4c` (BASE) = 0.001 (float32, hex `3A83126F`)
- `DAT_0088c548` (MULT) = 10.0 (float32, hex `41200000`)
- `DAT_00895f50` (ENC_SCALE) = 4095.0 (encoder mantissa multiplier)
- `DAT_00895f54` (DEC_SCALE) = float32(1/4095) = 0.000244200258... (decoder inverse)

**Encoding** (`FUN_006d3a90`):
```
Input:  float value
Output: uint16

Format: [sign:1][scale:3][mantissa:12]
        Bit 15=sign, Bits 14-12=scale exponent (0-7), Bits 11-0=mantissa (0-4095)

Algorithm:
1. If value < 0: set sign bit, negate
2. Find scale (0-7) such that value < BASE * MULT^scale
   Scale 0=[0, 0.001), Scale 1=[0.001, 0.01), ..., Scale 7=[1000, 10000)
3. frac = (value - range_lo) / (range_hi - range_lo)
4. mantissa = ftol(frac * 4095.0)  // truncate toward zero
5. If scale overflows (>=8): clamp to scale=7, mantissa=0xFFF
6. Result = ((sign << 3) | scale) << 12 | mantissa
```

**Decoding** (`FUN_006d3b30`):
```
Input:  uint16 encoded
Output: float

Algorithm:
1. mantissa = encoded & 0xFFF
2. sign = (encoded >> 15) & 1
3. scale = (encoded >> 12) & 0x7
4. Compute range: lo=0, hi=BASE; for i in 0..scale: lo=hi, hi=lo*MULT
5. result = (hi - lo) * mantissa * float32(1/4095) + lo
6. If sign: result = -result
```

8 logarithmic decades from 0 to 10000, each with 4096 discrete levels (~0.022% relative precision per level). The decoder uses `1/4095` (not `1/4096`), making mantissa 4095 decode to exactly the top of the range. Encoding is LOSSY -- values always round down due to truncation. See [cf16-precision-analysis.md](cf16-precision-analysis.md) for full precision tables and [cf16-explosion-encoding.md](cf16-explosion-encoding.md) for explosion opcode analysis and mod weapon-type ID compatibility.

### CompressedVector3 (Position Delta)

Used for: position offsets, velocity components.

**Write** (`FUN_006d2ad0`):
```
Input:  float dx, dy, dz (delta from last known position)
Output: byte dirX, byte dirY, byte dirZ, uint16 magnitude

Algorithm:
1. magnitude = sqrt(dx*dx + dy*dy + dz*dz)
2. If magnitude <= epsilon: magnitude = 0.0
3. dirX = ftol(dx / magnitude * some_scale)  // normalized direction as byte
4. dirY = ftol(dy / magnitude * some_scale)
5. dirZ = ftol(dz / magnitude * some_scale)
6. magnitude_compressed = CompressedFloat16(magnitude)
```

Wire format: `[dirX:u8][dirY:u8][dirZ:u8][magnitude:u16]` = **5 bytes total**

**Read** (`FUN_006d2eb0` / `ReadCompressedVector3`):
```
1. Read 3 bytes via vtable+0x50 (ReadByte)
2. Call vtable+0xB8 to decompress: (outX, outY, outZ, byte1, byte2, byte3)
```

### CompressedVector4 (Position Delta with Extra Param)

Used for: position + rotation, position + scale.

**Write** (`FUN_006d2f10`):
```
If param4 == 0 (use float for 4th component):
  Compress 3 floats via vtable+0xA0, write 3 bytes via vtable+0x54
  Write float via vtable+0x74
If param4 != 0 (use uint16 for 4th component):
  Compress 3 floats via vtable+0xA4, write 3 bytes via vtable+0x54
  Write uint16 via vtable+0x5C
```

**Read** (`FUN_006d2fd0` / `ReadCompressedVector4`):
```
1. Read 3 bytes via vtable+0x50
2. If param4 != 0: read uint16 via vtable+0x58
   Call vtable+0xB4 to decompress with uint16 magnitude
3. If param4 == 0: read float via vtable+0x70
   Call vtable+0xB0 to decompress with float magnitude
```

Wire format (param4=1): `[dirX:u8][dirY:u8][dirZ:u8][magnitude:u16]` = **5 bytes**
Wire format (param4=0): `[dirX:u8][dirY:u8][dirZ:u8][magnitude:f32]` = **7 bytes**
