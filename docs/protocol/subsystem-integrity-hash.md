> [docs](../README.md) / [protocol](README.md) / subsystem-integrity-hash.md

# Subsystem Integrity Hash — Reverse Engineering Analysis

## Overview

The subsystem integrity hash is a tamper-detection system that hashes all ship subsystem property values (health, weapon stats, shield facings, etc.) into a 32-bit checksum, XOR-folded to 16 bits for wire transmission. It was designed to detect client-side cheating by comparing a locally-computed hash against the one received in StateUpdate packets.

**Dead code in multiplayer**: The sender (FUN_005b17f0) only writes the hash when `isMultiplayer == 0` (single-player). The receiver (FUN_005b21c0) only validates it when `isMultiplayer == 1` (multiplayer). These conditions are mutually exclusive in stock gameplay — the hash is never sent AND checked in the same session.

### Function Table

| Address | Name | Signature | Purpose |
|---------|------|-----------|---------|
| 0x005b6c10 | hash_fold | `void(float value, uint32_t* acc)` | XOR + rotate accumulator |
| 0x005b6170 | base_subsystem_hash | `float(ShipSubsystem* subsys)` | 7 floats + children + 4 booleans + powered extra |
| 0x005b5eb0 | ComputeSubsystemHash | `uint32_t __fastcall(void* container)` | 12 slots in fixed order, type-specific extras |
| 0x005b6330 | weapon_system_hash | `float(ShipSubsystem* weaponSys)` | base + 2 booleans + per-child dispatch + torpedo data |
| 0x005b6560 | individual_weapon_hash | `float(EnergyWeapon* weapon)` | 5-way type dispatch per weapon |
| 0x005b17f0 | StateUpdate sender | — | Writes hash only when `!isMultiplayer` AND flag 0x01 |
| 0x005b21c0 | StateUpdate receiver | — | Checks hash only when `isMultiplayer` AND `has_hash != 0` |

---

## hash_fold (0x005b6c10)

Core accumulator function. Called once per hashed value.

```c
void hash_fold(float value, uint32_t* accumulator) {
    // Convert float to absolute integer (truncation via x87 __ftol)
    bool negative = (value < 0.0f);
    int32_t ival = (int32_t)value;
    if (negative) ival = -ival;

    // XOR each byte of ival into accumulator
    uint8_t* acc_bytes = (uint8_t*)accumulator;
    uint8_t* val_bytes = (uint8_t*)&ival;
    for (int i = 0; i < 4; i++) {
        acc_bytes[i] ^= val_bytes[i];
    }

    // Rotate left by 1 bit
    *accumulator = (*accumulator << 1) | (*accumulator >> 31);
}
```

**Note**: The absolute-value step means positive and negative values of the same magnitude produce identical hash contributions (e.g., 3.7f and -3.7f both contribute integer 3).

---

## base_subsystem_hash (0x005b6170)

Called for every subsystem. Contributes a minimum of 11 `hash_fold` calls (7 property floats + 4 boolean sentinels), plus 1 more if it is a PoweredSubsystem, plus N more for N children (recursive).

```c
float base_subsystem_hash(ShipSubsystem* subsys) {
    float hash = 0.0f;
    SubsystemProperty* prop = subsys->property;  // *(subsys + 0x18)

    // --- 7 base property floats (hashed in this exact order) ---
    hash_fold(prop->maxCondition,      &hash);  // property+0x20
    hash_fold(prop->currentPower,      &hash);  // property+0x40
    hash_fold(prop->field_0x28,        &hash);  // property+0x28
    hash_fold(prop->field_0x2C,        &hash);  // property+0x2C
    hash_fold(prop->field_0x30,        &hash);  // property+0x30
    hash_fold(prop->field_0x44,        &hash);  // property+0x44
    hash_fold(prop->repairComplexity,  &hash);  // property+0x3C

    // --- Recursively hash all child subsystems ---
    int childCount = *(int*)(subsys + 0x1C);
    for (int i = 0; i < childCount; i++) {
        ShipSubsystem* child = FUN_0056c570(subsys, i);  // GetChildSubsystem
        float childHash = base_subsystem_hash(child);     // RECURSIVE
        hash_fold(childHash, &hash);
    }

    // --- 4 boolean sentinel values (AFTER children) ---
    bool flag1 = FUN_0056c330(subsys);            // property+0x24 (disableable)
    hash_fold(flag1 ? 64.0002f : 76.6f, &hash);

    bool flag2 = *(uint8_t*)((char*)subsys + 0x44);  // subsys+0x44 (operational state)
    hash_fold(flag2 ? 98.6f : 100.0f, &hash);

    bool flag3 = FUN_0056c340(subsys);            // property+0x25 (repairable)
    hash_fold(flag3 ? 14.3f : 456.1f, &hash);

    bool flag4 = *(uint8_t*)(prop + 0x26);        // property+0x26 (primary flag)
    hash_fold(flag4 ? 27.3f : 16.1f, &hash);

    // --- PoweredSubsystem extra field ---
    PoweredSubsystem* powered = FUN_00562210(subsys);  // CastToPowered, type 0x801C
    if (powered != NULL) {
        PoweredSubsystemProperty* powProp = FUN_005621b0(powered);
        hash_fold(powProp->field_0x48, &hash);  // property+0x48 (energy field)
    }

    return hash;
}
```

**Critical ordering**: Children are hashed BEFORE the boolean sentinels. Child hash values feed into the accumulator state that the booleans then modify.

---

## ComputeSubsystemHash (0x005b5eb0)

Called as `__fastcall` with `ship + 0x27C` (subsystem container pointer) in ECX. Hashes 12 subsystem slots in a fixed order, with type-specific extra fields per slot.

### Subsystem Slot Table

| Hash Order | Container Offset | Ship Offset | Subsystem | Hash Method | Extra Fields |
|---|---|---|---|---|---|
| 1 | +0x48 | +0x2C4 | Power Reactor | base_subsystem_hash | none |
| 2 | +0x44 | +0x2C0 | Shield Generator | base + type-specific | 12 floats: 6 maxShield facings (prop+0x60 array) + 6 chargePerSecond facings (prop+0x78 array) |
| 3 | +0x34 | +0x2B0 | Powered Master | base + type-specific | 5 floats: prop+0x48, 0x4C, 0x50, 0x54, 0x58 |
| 4 | +0x4C | +0x2C8 | Cloak Device | base + type-specific | 1 float: prop+0x4C |
| 5 | +0x50 | +0x2CC | Impulse Engine | base + type-specific | 4 floats: prop+0x50, 0x58, 0x54, 0x4C (this order) |
| 6 | +0x54 | +0x2D0 | Sensor Array | base_subsystem_hash | none |
| 7 | +0x5C | +0x2D8 | Warp Drive | base + type-specific | 1 float: prop+0x4C |
| 8 | +0x60 | +0x2DC | Crew / Unknown-A | base_subsystem_hash | calls FUN_0055e220 (side-effect getter) |
| 9 | +0x38 | +0x2B4 | Torpedo System | weapon_system_hash | children + torpedo type data |
| 10 | +0x3C | +0x2B8 | Phaser System | weapon_system_hash | children (no torpedo data) |
| 11 | +0x40 | +0x2BC | Pulse Weapon System | weapon_system_hash | children (no torpedo data) |
| 12 | +0x58 | +0x2D4 | Tractor Beam System | weapon_system_hash | children (no torpedo data) |

Each slot is NULL-checked before hashing. If a slot pointer is NULL, it is skipped.

**Corrections from prior analysis**: ship+0x2C0 was previously misidentified as "Repair" — it is **Shield Generator** (proven by 6-facing hash pattern matching ShieldProperty layout). ship+0x2B4 was misidentified as "Shield" — it is **Torpedo System** (confirmed by "Torpedoes" string reference). The Repair subsystem (ship+0x2C0 in the main container table) does NOT appear in the hash.

---

## weapon_system_hash (0x005b6330)

Called for slots 9–12 (the 4 weapon-system slots). Extends base_subsystem_hash with weapon-specific data.

```c
float weapon_system_hash(ShipSubsystem* weaponSys) {
    float hash = 0.0f;
    WeaponSystemProperty* wsProp = FUN_00584050(weaponSys);  // GetWeaponSystemProperty

    // Step 1: base_subsystem_hash (7 floats + 4 booleans + children + powered extra)
    float baseHash = base_subsystem_hash(weaponSys);
    hash_fold(baseHash, &hash);

    // Step 2: 2 weapon-system boolean sentinels
    bool wsEnabled = *(uint8_t*)(wsProp + 0x50);
    hash_fold(wsEnabled ? 0.4f : 99.1f, &hash);
    bool wsOnline = *(uint8_t*)(wsProp + 0x51);
    hash_fold(wsOnline ? 32.6f : 487.1f, &hash);

    // Step 3: Hash each weapon child via individual_weapon_hash
    int childCount = *(int*)(weaponSys + 0x1C);
    for (int i = 0; i < childCount; i++) {
        ShipSubsystem* child = FUN_0056c570(weaponSys, i);
        EnergyWeapon* weapon = FUN_00583200(child);   // CastToWeapon, type 0x802A
        float weapHash = individual_weapon_hash(weapon);
        hash_fold(weapHash, &hash);
    }

    // Step 4: Torpedo data (gated behind type check 0x801E)
    TorpedoSystem* torpSys = FUN_0057aff0(weaponSys);  // CastToTorpedoSystem
    if (torpSys != NULL) {
        TorpedoSystemProperty* torpProp = torpSys->property;
        int numTypes = *(int*)(torpProp + 0xA4);

        for (int t = 0; t < numTypes; t++) {
            // Hash maxTorpedoes
            int maxTorps = FUN_006944d0(torpProp, t);  // GetMaxTorpedoes
            hash_fold((float)maxTorps, &hash);

            // Torpedo script name — mirror convolution
            char* torpName = FUN_006944e0(torpProp, t);  // GetTorpedoScript
            int nameLen = strlen(torpName);
            for (int j = 0; j < nameLen; j++) {
                int val = (int)torpName[j] * (int)torpName[nameLen - 1 - j];
                hash_fold((float)val, &hash);
            }

            // Torpedo type object name — mirror convolution
            TorpedoType* torpType = FUN_006944c0(torpProp, t);
            char* typeName = FUN_00694330(torpType);  // GetName via Python
            int typeLen = strlen(typeName);
            for (int j = 0; j < typeLen; j++) {
                int val = (int)typeName[j] * (int)typeName[typeLen - 1 - j];
                hash_fold((float)val, &hash);
            }

            // Two int fields product
            hash_fold((float)(torpType->field_0x08 * torpType->field_0x00), &hash);
        }
    }

    return hash;
}
```

### Torpedo Mirror Convolution

For a string "ABCD" (length 4), the hash contributions are:
- `A * D`, `B * C`, `C * B`, `D * A`

Each character is multiplied by its mirror-position character. This makes the hash palindrome-sensitive. Two strings are hashed per torpedo type: the script name and the type object name.

Only subsystems that pass the 0x801E type cast (actual torpedo systems) contribute torpedo data. Phaser, Pulse, and Tractor systems skip step 4 entirely.

---

## individual_weapon_hash (0x005b6560)

Each individual weapon child is first hashed with `base_subsystem_hash`, then checked against 5 type IDs. A weapon can match multiple types due to class inheritance (e.g., a phaser bank matches both 0x802B EnergyWeapon and 0x802C PhaserBank).

### Type 0x802B: EnergyWeapon (CT_ENERGY_WEAPON)

Cast via FUN_0056f8a0. Hashes 7 weapon property floats:

| Property Offset | Field | Getter |
|-----------------|-------|--------|
| prop+0x54 | maxDamagePerShot | FUN_00583260 |
| prop+0x68 | maxCharge | FUN_0056f900 |
| prop+0x78 | maxDamage | FUN_0056f930 |
| prop+0x7C | maxDamageDistance | FUN_0056f940 |
| prop+0x74 | rechargeRate | FUN_0056f910 |
| prop+0x70 | dischargeRate | FUN_0056f8f0 |
| prop+0x6C | minDamageRange | FUN_0056f8e0 |

### Type 0x802C: PhaserBank (CT_PHASER_BANK)

Cast via FUN_00570b20. Hashes:
- 2 firing arc direction vectors (6 floats via FUN_004e74e0, FUN_004e7510)
- 6 property floats: prop+0x140, 0x144, 0xA0, 0x9C, 0x98, 0x94

### Type 0x802D: PulseWeapon (CT_PULSE_WEAPON)

Cast via FUN_00574f00. Hashes:
- 3 vectors — position + 2 directions (9 floats via FUN_00484a20, FUN_00575d50, FUN_00575d80)
- 5 property floats: prop+0xA0, 0x9C, 0x98, 0x94, 0xC8
- Weapon name string mirror convolution: `sum += name[j] * name[len-1-j]`, folded as a single float

### Type 0x802E: TractorBeamProjector (CT_TRACTOR_BEAM_PROJECTOR)

Cast via FUN_0057ea60. Hashes:
- 3 vectors (9 floats via FUN_0057ead0, FUN_0057eb30, FUN_0057f530)
- 4 property floats: prop+0xA0, 0x9C, 0x98, 0x94

### Type 0x802F: TorpedoTube (CT_TORPEDO_TUBE)

Cast via FUN_0057c480. Hashes:
- 2 firing direction vectors (6 floats at prop+0x6C..0x80 via FUN_0057c370, FUN_0057c3d0)
- 3 fields: prop+0x84, prop+0x88, and `(float)*(int*)(prop+0x8C)` (int cast to float)

---

## Boolean Sentinel Magic Constants

Boolean flags are hashed as arbitrary float constants rather than 0/1, making the hash sensitive to boolean state changes.

### base_subsystem_hash (4 pairs)

| # | Source | True Constant | True Hex | False Constant | False Hex | Meaning |
|---|--------|---------------|----------|----------------|-----------|---------|
| 1 | property+0x24 | 64.0002f | 0x42800083 | 76.6f | 0x42993333 | Disableable |
| 2 | subsys+0x44 | 98.6f | 0x42c53333 | 100.0f | 0x42c80000 | Operational state |
| 3 | property+0x25 | 14.3f | 0x4164cccd | 456.1f | 0x43e40ccd | Repairable |
| 4 | property+0x26 | 27.3f | 0x41da6666 | 16.1f | 0x4180cccd | Primary flag |

### weapon_system_hash (2 pairs)

| # | Source | True Constant | True Hex | False Constant | False Hex | Meaning |
|---|--------|---------------|----------|----------------|-----------|---------|
| 5 | wsProp+0x50 | 0.4f | 0x3ecccccd | 99.1f | 0x42c63333 | WS enabled |
| 6 | wsProp+0x51 | 32.6f | 0x42026666 | 487.1f | 0x43f38ccd | WS online |

---

## Sender (0x005b17f0)

Inside the StateUpdate writer, within the flag 0x01 (POSITION_ABSOLUTE) block:

```c
bVar19 = DAT_0097fa8a == '\0';   // bVar19 = !isMultiplayer

// ... within flag 0x01 processing:
if (bVar19) {     // NOT multiplayer (single-player only)
    WriteByte(stream, '\x01');   // has_subsystem_hash = 1
    hash = ComputeSubsystemHash(ship + 0x27C);  // __fastcall via ECX
    WriteShort(stream, (hash >> 16) ^ (hash & 0xFFFF));  // 32→16 bit XOR fold
} else {          // IS multiplayer
    WriteByte(stream, '\0');     // has_subsystem_hash = 0
}
```

**The hash is ONLY written when `isMultiplayer == 0` (single-player mode)**. In multiplayer, `has_subsystem_hash` is always 0.

---

## Receiver (0x005b21c0)

Inside the StateUpdate reader, within the flag 0x01 (POSITION_ABSOLUTE) block:

```c
uint8_t hasHash = ReadByte(stream);
if (hasHash != 0) {
    uint16_t receivedHash = ReadShort(stream);

    if (isMultiplayer) {  // DAT_0097fa8a != 0
        uint32_t localHash = ComputeSubsystemHash((int)this + 0x27C);
        uint16_t localWire = (uint16_t)(localHash >> 16) ^ (uint16_t)(localHash & 0xFFFF);

        if (localWire != receivedHash) {
            // CHEAT DETECTED — post ET_BOOT_PLAYER event
            void* mpWindow = FUN_0050e1b0(DAT_009878cc, 8);
            void* mpGame = FUN_00504360(mpWindow);
            void* eventMem = FUN_00717b70(0x2C);
            void* eventObj = FUN_00718010(eventMem);
            TGEvent* event = FUN_006bb840(eventObj);
            event->eventType = 0x8000F6;              // ET_BOOT_PLAYER
            FUN_006d62b0(event, (int)mpGame);
            event->data[0x28] = this->playerSlot;     // *(this + 0x2E4)
            FUN_006da2a0(&DAT_0097f838, event);       // Post to global event queue
        }
    }
}
```

The kick path: ET_BOOT_PLAYER (0x8000F6) → BootPlayerHandler (0x00506170) → TGBootPlayerMessage (reason=4) → broadcast → client disconnects.

---

## Wire Encoding

The 32-bit hash is XOR-folded to 16 bits:

```c
uint16_t wire_hash = (uint16_t)(hash32 >> 16) ^ (uint16_t)(hash32 & 0xFFFF);
```

Carried in the StateUpdate packet after position data, gated behind flag 0x01 (POSITION_ABSOLUTE):

```
[position data] [has_hash: byte] [if has_hash != 0: hash16: ushort]
```

---

## Dead Code Proof

| Mode | Sender writes hash? | Receiver checks hash? | Outcome |
|------|---------------------|-----------------------|---------|
| Single-player | YES (has_hash=1, hash16 follows) | NO (isMultiplayer is false) | Hash sent but ignored |
| Multiplayer | NO (has_hash=0) | YES (would check if has_hash were 1) | Check never reached |

The sender and receiver conditions are mutually exclusive. The subsystem integrity hash has **never been functional in any stock multiplayer session**.

This confirms that `PatchSubsystemHashCheck` at 0x005b22b5 (which prevents false-positive kicks when the dedicated server has no ship subsystems) is safe — stock gameplay already never triggers this code path.

---

## Decompiled Source Reference

All analysis performed against `reference/decompiled/05_game_mission.c`:

| Function | Decompiled Line |
|----------|-----------------|
| ComputeSubsystemHash (0x005b5eb0) | ~56151 |
| base_subsystem_hash (0x005b6170) | ~56253 |
| weapon_system_hash (0x005b6330) | ~56321 |
| individual_weapon_hash (0x005b6560) | ~56431 |
| hash_fold (0x005b6c10) | ~56617 |
| StateUpdate sender (0x005b17f0) | ~53987 |
| StateUpdate receiver (0x005b21c0) | ~53747 |
