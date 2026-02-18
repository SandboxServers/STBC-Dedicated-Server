# CompressedFloat16 (CF16) Encoding — Explosion Damage Wire Format

## Overview

Bridge Commander's explosion event (opcode `0x29`) encodes damage and radius as
**CompressedFloat16** (CF16), a custom 16-bit floating point format used throughout
the engine's network serialization. This document details the exact encoding algorithm,
extracted constants, and precision analysis for mod weapon-type identification.

## CF16 Constants (from stbc.exe)

| Symbol | Address | Hex Bytes | Value | Purpose |
|--------|---------|-----------|-------|---------|
| BASE | `DAT_00888b4c` | `6F 12 83 3A` | 0.001 (float32) | First scale boundary |
| ZERO | `DAT_00888b54` | `00 00 00 00` | 0.0 | Negative check / range_lo for scale 0 |
| MULT | `DAT_0088c548` | `00 00 20 41` | 10.0 | Scale multiplier |
| ENC_MULT | `DAT_00895f50` | `00 F0 7F 45` | 4095.0 | Encoder mantissa multiplier |
| DEC_MULT | `DAT_00895f54` | `01 08 80 39` | 1/4095 (float32) | Decoder mantissa divisor |

## Wire Format

```
[sign:1][scale:3][mantissa:12]  = 16 bits total
```

- **sign** (bit 15): 0 = positive, 1 = negative
- **scale** (bits 14-12): 3-bit index selecting the value range (0-7)
- **mantissa** (bits 11-0): 12-bit value within the selected range (0-4095)

## Scale Table

| Scale | Range Low | Range High | Step Size | Notes |
|-------|-----------|------------|-----------|-------|
| 0 | 0.0 | 0.001 | 2.44e-7 | Sub-thousandths |
| 1 | 0.001 | 0.01 | 2.20e-6 | Thousandths |
| 2 | 0.01 | 0.1 | 2.20e-5 | Hundredths |
| 3 | 0.1 | 1.0 | 2.20e-4 | Fractions |
| 4 | 1.0 | 10.0 | 2.20e-3 | Single digits |
| 5 | 10.0 | 100.0 | 2.20e-2 | Tens |
| 6 | 100.0 | 1000.0 | 2.20e-1 | Hundreds |
| 7 | 1000.0 | 10000.0 | 2.20 | Thousands |

Each scale covers one decimal order of magnitude. The 4096 mantissa values (0-4095)
divide the range into equal steps. Mantissa 0 = range_lo, mantissa 4095 = range_hi.

## Encoder Algorithm (FUN_006d3a90)

```c
// __fastcall: float param_3 on stack (x87 convention)
// Returns uint16 in EAX (low 16 bits)
uint16_t CF16_Encode(float value) {
    bool negative = (value < 0.0f);
    if (negative) value = -value;

    uint32_t scale = 0;
    float boundary = BASE;       // 0.001
    float prev_boundary = ZERO;  // 0.0

    while (scale < 8) {
        if (value < boundary) {
            // Found the bin: value is in [prev_boundary, boundary)
            int mantissa = (int)((value - prev_boundary)
                                / (boundary - prev_boundary)
                                * 4095.0f);
            break;
        }
        prev_boundary = boundary;
        boundary *= MULT;  // boundary *= 10.0
        scale++;
    }

    if (scale == 8) {
        // Overflow: clamp to maximum representable
        mantissa = 0xFFF;
        scale = 7;
    }

    if (negative) scale |= 0x8;

    return (uint16_t)((scale << 12) | mantissa);
}
```

**Key detail**: The encoder uses `int()` truncation (x87 `__ftol`), NOT rounding.
This means the encoded value is always <= the original value within the bin.

## Decoder Algorithm (FUN_006d3b30)

```c
// __cdecl: uint16 param_1 on stack
// Returns float (x87 ST0)
float CF16_Decode(uint16_t encoded) {
    uint32_t mantissa = encoded & 0xFFF;
    uint8_t scale_nibble = (encoded >> 12) & 0xF;

    bool negative = (scale_nibble & 0x8) != 0;
    if (negative) scale_nibble &= 0x7;

    float range_lo = 0.0f;    // ZERO
    float range_hi = 0.001f;  // BASE

    for (int i = 0; i < scale_nibble; i++) {
        range_lo = range_hi;
        range_hi = range_lo * 10.0f;  // * MULT
    }

    float result = (range_hi - range_lo) * (float)mantissa * (1.0f/4095.0f) + range_lo;

    if (negative) result = -result;
    return result;
}
```

**Key detail**: The decoder uses `1.0f/4095.0f` (stored as a float32 constant at
`DAT_00895f54`), NOT `1.0f/4096.0f`. This is a proper inverse of the encoder's
4095.0 multiplier.

## Explosion Packet (Opcode 0x29) Wire Format

```
[0x29]                        opcode (1 byte)
[objectID]                    source object ID (uint32, 4 bytes)
[position]                    CompressedVector4 (variable, ~7 bytes)
[damage: CF16]                explosion damage (uint16, 2 bytes)
[radius: CF16]                explosion radius (uint16, 2 bytes)
```

**Sender**: `FUN_00595c60` at `0x00595c60` (`__thiscall`)
- Iterates the explosion list at `this+0x13C`
- Reads damage from explosion struct offset `+0x14`
- Reads radius from explosion struct offset `+0x1C`
- Called from: `FUN_006a02a0` (RequestObj handler), `Handler_NewPlayerInGame_0x2A`

**Receiver**: `Handler_Explosion_0x29` at `0x006A0080`
- Dispatched from `MultiplayerGame_ReceiveMessage` jump table
- Decodes position, then two CF16 values (damage, radius)
- Creates damage info struct via `FUN_004bbde0`
- Calls `ProcessDamage` to apply to target ship

## Precision Analysis: BC Remastered Weapon Type IDs

BC Remastered uses specific damage float values as weapon type identifiers:
**15.0**, **25.0**, **273.0**, **2063.0**

### Round-Trip Results

| Original | Encoded | Scale | Mantissa | Decoded | Error | Rel Error |
|----------|---------|-------|----------|---------|-------|-----------|
| 15.0 | 0x50E3 | 5 | 227 | 14.989012 | 0.011 | 0.073% |
| 25.0 | 0x52AA | 5 | 682 | 24.989013 | 0.011 | 0.044% |
| 273.0 | 0x6313 | 6 | 787 | 272.967056 | 0.033 | 0.012% |
| 2063.0 | 0x71E3 | 7 | 483 | 2061.538623 | 1.461 | 0.071% |

### Uniqueness Check

All four values produce **unique encoded uint16 values** (0x50E3, 0x52AA, 0x6313, 0x71E3).
No two mod values collide. However, the **decoded** values are NOT equal to the originals.

### Can `round(decoded) == original` Work?

| Value | round(decoded) | Matches? |
|-------|---------------|----------|
| 15.0 | 15 | YES |
| 25.0 | 25 | YES |
| 273.0 | 273 | YES |
| 2063.0 | **2062** | **NO** |

**2063.0 FAILS round-trip matching** because at scale 7 (1000-10000), the step size
is ~2.198, meaning 2062 and 2063 map to the **same mantissa** (483). The decoded value
2061.54 rounds to 2062, not 2063.

### Integer Collision at Scale 7

At scale 7, every ~2.2 integer values share the same mantissa:

| Mantissa | Integers | Decoded |
|----------|----------|---------|
| 482 | 2060, 2061 | 2059.34 |
| **483** | **2062, 2063** | **2061.54** |
| 484 | 2064, 2065 | 2063.74 |

### Recommended Matching Strategies

**Strategy 1: Tolerance window (RECOMMENDED)**
```python
def identify_weapon_type(decoded_damage):
    targets = {15.0: "type_A", 25.0: "type_B", 273.0: "type_C", 2063.0: "type_D"}
    for target, name in targets.items():
        if abs(decoded_damage - target) < 1.5:
            return name
    return "unknown"
```
All four values pass with a 1.5 tolerance. The minimum separation between any two
mod values is 10.0 (between 15.0 and 25.0), so a 1.5 tolerance has no overlap risk.

**Strategy 2: Encode target and compare uint16 (EXACT)**
```python
# Pre-compute expected encoded values at mod init
EXPECTED = {0x50E3: "type_A", 0x52AA: "type_B", 0x6313: "type_C", 0x71E3: "type_D"}

def identify_weapon_type(received_cf16_uint16):
    return EXPECTED.get(received_cf16_uint16, "unknown")
```
This is perfectly reliable but requires access to the raw uint16 before decoding,
which is only available via C-level hooks, not Python.

**Strategy 3: Range-based matching**
```python
def identify_weapon_type(decoded_damage):
    if 14.0 < decoded_damage < 16.0: return "type_A"
    if 24.0 < decoded_damage < 26.0: return "type_B"
    if 272.0 < decoded_damage < 274.0: return "type_C"
    if 2060.0 < decoded_damage < 2064.0: return "type_D"
    return "unknown"
```

## Extended Precision Reference

| Value | Encoded | Decoded | round() | Match? |
|-------|---------|---------|---------|--------|
| 0.5 | 0x371B | 0.4998 | 0 | YES |
| 1.0 | 0x3FFE | 0.9998 | 1 | YES |
| 5.0 | 0x471B | 4.9978 | 5 | YES |
| 10.0 | 0x4FFE | 9.9978 | 10 | YES |
| 15.0 | 0x50E3 | 14.9890 | 15 | YES |
| 25.0 | 0x52AA | 24.9890 | 25 | YES |
| 100.0 | 0x5FFE | 99.9780 | 100 | YES |
| 273.0 | 0x6313 | 272.967 | 273 | YES |
| 1000.0 | 0x6FFE | 999.780 | 1000 | YES |
| 1500.0 | 0x70E3 | 1498.90 | 1499 | **NO** |
| 2000.0 | 0x71C6 | 1997.80 | 1998 | **NO** |
| 2063.0 | 0x71E3 | 2061.54 | 2062 | **NO** |
| 5000.0 | 0x771B | 4997.80 | 4998 | **NO** |
| 9999.0 | 0x7FFE | 9997.80 | 9998 | **NO** |

**General rule**: `round(decoded) == original` works reliably for values below ~1000.
Above 1000 (scale 7), the step size of ~2.2 means `round()` frequently fails.

## Assessment

**Can mods reliably use damage values as weapon type identifiers through the explosion
wire protocol?**

**YES**, with caveats:

1. The four specific BC Remastered values (15, 25, 273, 2063) all produce **unique
   CF16 encodings** and can be discriminated.

2. **Simple `round()` matching fails for 2063** and all values >= 1000. Mods MUST
   use tolerance-based matching (`abs(decoded - target) < threshold`) instead of
   exact integer comparison.

3. A tolerance of **1.5** works for all four values with no risk of cross-matching
   (minimum inter-value distance is 10.0).

4. For values in scale 7 (1000-10000), integer-level precision is lost. Two different
   integer damage values that are within ~2.2 of each other will be indistinguishable
   after CF16 round-trip. Mod designers choosing new weapon type IDs in this range
   should space them at least 3 apart.

5. For values below 1000, precision is sufficient that every integer value gets a
   unique CF16 encoding. This is the safe range for weapon type identification.
