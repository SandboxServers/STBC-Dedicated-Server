> [docs](../README.md) / [protocol](README.md) / cf16-precision-analysis.md

# CompressedFloat16 (CF16) Precision Analysis

Reverse-engineered from stbc.exe encoder (`FUN_006d3a90`) and decoder (`FUN_006d3b30`).
Constants extracted from .rdata section. All findings verified against decompiled code.

## Format

```
Bit layout: [sign:1][scale:3][mantissa:12] = 16 bits total
  Bit 15     = sign (1=negative, 0=positive)
  Bits 14-12 = scale exponent (0-7)
  Bits 11-0  = mantissa (0-4095)
```

## Constants (from stbc.exe .rdata)

| Symbol | Address | Hex Bytes | Value | Role |
|--------|---------|-----------|-------|------|
| BASE | DAT_00888b4c | 6F 12 83 3A | 0.001 (float32) | Scale range base |
| ZERO | DAT_00888b54 | 00 00 00 00 | 0.0 | Negative comparison |
| MULT | DAT_0088c548 | 00 00 20 41 | 10.0 (float32, exact) | Scale multiplier |
| ENC_SCALE | DAT_00895f50 | 00 F0 7F 45 | 4095.0 (float32, exact) | Encoder mantissa scale |
| DEC_SCALE | DAT_00895f54 | 01 08 80 39 | float32(1/4095) = 0.000244200258... | Decoder mantissa inverse |

**Critical finding**: The decoder constant is `1/4095`, NOT `1/4096`. This makes the system symmetric:
- Encoder: `mantissa = floor(fraction * 4095.0)`
- Decoder: `value = range * mantissa * (1/4095) + range_lo`
- Mantissa 4095 decodes to exactly the top of the range (range_hi)
- 4096 discrete levels: 0, 1/4095, 2/4095, ..., 4095/4095

## Encoder Algorithm (FUN_006d3a90)

```c
uint16 CF16_Encode(float value) {
    bool sign = (value < 0.0f);
    if (sign) value = -value;

    uint scale = 0;
    float boundary = BASE;  // 0.001
    while (scale < 8) {
        if (value < boundary) break;
        boundary *= MULT;   // *= 10.0
        scale++;
    }

    if (scale >= 8) {
        // Overflow: clamp to max
        return (sign ? 0xFFFF : 0x7FFF);  // scale=7, mantissa=0xFFF
    }

    // Compute range for this scale
    float lo, hi;
    if (scale == 0) { lo = 0.0; hi = BASE; }
    else { lo = BASE * pow(MULT, scale-1); hi = BASE * pow(MULT, scale); }

    // Fractional position in range, scaled to [0, 4095]
    float frac = (value - lo) / (hi - lo);
    int mantissa = (int)(frac * 4095.0f);  // __ftol: truncate toward zero
    mantissa = min(mantissa, 4095);

    return ((sign << 3) | scale) << 12 | mantissa;
}
```

## Decoder Algorithm (FUN_006d3b30)

```c
float CF16_Decode(uint16 raw) {
    int mantissa = raw & 0xFFF;
    int scale = (raw >> 12) & 0x7;
    bool sign = (raw >> 15) & 1;

    // Rebuild range iteratively (matches x87 FPU behavior)
    float lo = 0.0f;    // starts at DAT_00888b54 = 0.0
    float hi = BASE;    // starts at DAT_00888b4c = 0.001
    for (int i = 0; i < scale; i++) {
        lo = hi;
        hi = lo * MULT;  // *= 10.0
    }

    // Decode: uses float32(1/4095) loaded into x87 extended precision
    float result = (hi - lo) * (float)mantissa * DEC_SCALE + lo;

    if (sign) result = -result;
    return result;
}
```

## Scale Table

| Scale | Range Low | Range High | Step Size | Relative Precision |
|-------|-----------|------------|-----------|-------------------|
| 0 | 0 | 0.001 | 2.442e-7 | ~0.024% |
| 1 | 0.001 | 0.01 | 2.198e-6 | ~0.022% |
| 2 | 0.01 | 0.1 | 2.198e-5 | ~0.022% |
| 3 | 0.1 | 1 | 2.198e-4 | ~0.022% |
| 4 | 1 | 10 | 2.198e-3 | ~0.022% |
| 5 | 10 | 100 | 2.198e-2 | ~0.022% |
| 6 | 100 | 1000 | 2.198e-1 | ~0.022% |
| 7 | 1000 | 10000 | 2.198 | ~0.022% |

Maximum encodable value: ~10000.0 (clamped at scale=7, mantissa=4095).
Dynamic range: 0 to 10000 in 8 logarithmic decades, each with 4096 steps.

## Precision Characteristics

The encoding always introduces error because the mantissa is truncated (floor), not rounded.
Maximum error per scale is one step size (the truncation residual).

For scale S, step size = (range_hi - range_lo) / 4095.

The decoder's `float32(1/4095)` constant introduces a tiny additional bias:
- `float32(1/4095)` = 0.000244200258... vs exact `1/4095` = 0.000244200244...
- Relative error: ~6e-6% (negligible compared to quantization)

## Explosion Packet (Opcode 0x29) Wire Format

**Sender**: `FUN_00595c60` (iterates explosion damage list at `this+0x13C`)
**Receiver**: `Handler_Explosion_0x29` at `0x006A0080`

```
Offset  Size  Encoding     Field
------  ----  -----------  --------------------------------
0       1     byte         opcode = 0x29
1       4     uint32       objectID (target ship)
5       5     CV4          impact_position (3 dir bytes + CF16 magnitude)
10      2     CF16         radius
12      2     CF16         damage
------
Total: 14 bytes
```

**Field order verified**: The sender writes `CF16(source+0x14)` = radius first,
then `CF16(source+0x1C)` = damage second. The receiver passes them to the
ExplosionDamage constructor as `(position, radius, damage)`.

The receiver creates a 0x38-byte ExplosionDamage object:
```
+0x00: vtable (0x0088c6c4)
+0x04: (base class)
+0x08: position.x (float)
+0x0C: position.y (float)
+0x10: position.z (float)
+0x14: radius (float)
+0x18: radius^2 (float, precomputed)
+0x1C: damage (float)
+0x20: bounding box min (3 floats: position - radius)
+0x2C: bounding box max (3 floats: position + radius)
```

Then calls `ProcessDamage(ship, explosionDamageObj)` to apply the damage.

**ALL float fields in this packet are compressed -- there are NO raw float32 values.**

## Mod Damage Value Round-Trip Analysis

BC Remastered mods use specific damage float values as weapon type identifiers.
Client-side scripts check `pEvent.GetDamage()` for these exact values to apply
special visual effects. These values pass through CF16 compression when sent
over the network via opcode 0x29.

| Value | Name | Scale | Mantissa | Decoded | Error | int() Match |
|-------|------|-------|----------|---------|-------|-------------|
| 15.0 | Borg Inversion Pulse | 5 | 227 | 14.989 | 0.011 (0.073%) | FAIL (14) |
| 25.0 | Breen Drain | 5 | 682 | 24.989 | 0.011 (0.044%) | FAIL (24) |
| 273.0 | Hellbore | 6 | 787 | 272.967 | 0.033 (0.012%) | FAIL (272) |
| 2063.0 | Plasma Snare | 7 | 483 | 2061.539 | 1.461 (0.071%) | FAIL (2061) |

**None of these values survive the round-trip.**

The truncation is always downward (floor), so:
- `int(decoded)` is always `original - 1` for these values
- Values at scale 7 (1000-10000) lose up to 2.2 per step

### Implications for Mods

The stock vanilla `Effects.py` does NOT check `GetDamage()` -- it only uses
`GetRadius()` for visual effect sizing. The damage-as-type-identifier pattern
is purely a mod invention.

For mod compatibility, scripts checking damage values must use one of:
1. **Tolerance comparison**: `abs(damage - expected) < step_size`
   - Safe threshold per scale: scale 4=0.003, scale 5=0.03, scale 6=0.3, scale 7=3.0
2. **Round to nearest integer**: `int(damage + 0.5) == expected`
3. **Range comparison**: `expected - 1 < damage < expected + 1`
4. **Different encoding**: Use a field that doesn't go through CF16

### Integer Values That Nearly Survive

At scale 4 (1-10): all integers decode within 0.003 of original.
At scale 5 (10-100): all integers decode within 0.022 of original.
At scale 6 (100-1000): all integers decode within 0.22 of original.
At scale 7 (1000-10000): all integers decode within 2.2 of original.

No integer value exactly survives a CF16 round-trip. The closest are values
at range boundaries (e.g., 1.0, 10.0, 100.0, 1000.0) which decode within
~0.0002 to ~0.002 of the original.

## Other Uses of CF16

CF16 is used throughout the multiplayer protocol:
- **StateUpdate (0x1C)**: speed field (flag 0x10)
- **Explosion (0x29)**: radius and damage fields
- **CompressedVector3/4**: magnitude component (positions, velocities)
- **Ship_WriteStateUpdate** (`FUN_005b1e38`): calls encoder for speed value

All callers confirmed via xref analysis of FUN_006d3a90 (4 call sites total).
