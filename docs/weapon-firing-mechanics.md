# Weapon Firing Mechanics - Reverse Engineering Analysis

## Overview

Bridge Commander has two primary weapon types: **phasers** (continuous beam weapons, aka "energy weapons") and **torpedoes** (projectile weapons). Both share a common base class hierarchy and are managed by a **WeaponSystem** container.

### Class Hierarchy

```
Weapon (vtable 0x00892FC4, size ~0x90)
  +-- EnergyWeapon (vtable 0x008930D8, size ~0xC8)
  |     +-- PhaserBank (vtable 0x00893194, size 0x128)
  +-- Weapon subclass (vtable 0x00893834, base for Torpedo/Pulse)
        +-- TorpedoTube (vtable 0x00893630, size 0xB0)

WeaponSystem (container, holds N weapons)
  +-- PhaserSystem (inherits WeaponSystem)
  +-- TorpedoSystem (inherits WeaponSystem)
```

### Key Vtable Slots (Weapon hierarchy)

| Slot | Offset | Name | Notes |
|------|--------|------|-------|
| 30 | +0x78 | StopFiring | Called when charge depletes |
| 31 | +0x7C | Fire(dt, flag) | Actually fires the weapon |
| 32 | +0x80 | TryFire(dt, flag) | Called from WeaponSystem update |
| 33 | +0x84 | CanFire() | Returns bool - all gate conditions |
| 36 | +0x90 | SetPowerSetting(int) | Sets phaser intensity enum |

---

## Part 1: Phaser (Energy Weapon) System

### 1.1 Object Layout - EnergyWeapon / PhaserBank

Field offsets on the EnergyWeapon/PhaserBank object (`this`):

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x18 | ptr | property | EnergyWeaponProperty* (hardpoint config) |
| +0x24 | ptr | parent | TorpedoSystem/PhaserSystem* parent container |
| +0x28-0x2C | short[3] | colorRGB | Weapon color (0xFFFF default) |
| +0x30 | float | power_scale | Always 1.0f initially |
| +0x34 | float | power_level | Power allocation (0.0-1.0), default 1.0 |
| +0x40 | ptr | owner_ship | Parent ship ptr |
| +0x48 | float | random_delay | Random initial delay (rand() * scale) |
| +0x88 | byte | is_firing | 0=not firing, 1=currently firing |
| +0xA0 | float | charge_level | Current charge (EW: float, TT: int numReady) |
| +0xBC | float | charge_percentage | Cached charge % (for display) |
| +0xC0 | char* | fire_start_sound | Concatenated sound name (lazy init) |
| +0xC4 | char* | fire_loop_sound | Concatenated sound name (lazy init) |
| +0xF4 | int | intensity_mode | PhaserBank-specific: 0=LOW, 1=MED, 2=HIGH |

#### EnergyWeaponProperty (the hardpoint config, at +0x18)

| Offset | Type | Name | Accessor | Example (Sovereign) |
|--------|------|------|----------|---------------------|
| +0x40 | float | condition | (base subsystem) | 1000.0 |
| +0x68 | float | max_charge | GetMaxCharge() (FUN_0056f900) | 5.0 |
| +0x6C | float | recharge_rate | GetRechargeRate() (FUN_0056f8e0) | 0.08 |
| +0x70 | float | normal_discharge_rate | GetNormalDischargeRate() (FUN_0056f8f0) | 1.0 |
| +0x74 | float | min_firing_charge | GetMinFiringCharge() (FUN_0056f910) | 3.0 |
| +0x78 | float | max_damage | GetMaxDamage() (FUN_0056f930) | 300.0 |
| +0x7C | float | max_damage_distance | GetMaxDamageDistance() (FUN_0056f940) | 70.0 |

### 1.2 Phaser Charge Recharge Formula

**Function**: `PhaserBank::UpdateCharge` at **0x00572B80** (vtable slot for UpdateCharge, called via SWIG wrapper `swig_PhaserBank_UpdateCharge` at 0x00618FA0)

**Signature**: `void PhaserBank::UpdateCharge(float dt, float power_multiplier)`

The function has two operating modes based on the `is_firing` flag (offset +0x88):

#### Mode 1: NOT FIRING (this+0x88 == 0) - Recharging

```c
// Pseudocode reconstruction of FUN_00572b80 recharge branch
float power_level = this->power_level;    // +0x34
float recharge_rate = GetRechargeRate();   // property+0x6C
float delta_charge = recharge_rate * power_level * dt * power_multiplier;

// Non-owner ship penalty (other player's ship gets slower recharge)
bool isOwnerShip = true;
if (g_IsHost) {
    isOwnerShip = (g_TopWindow->playerShip == this->owner_ship);  // +0x40
}
if (!isOwnerShip) {
    delta_charge *= DAT_00890550;  // AI/remote recharge multiplier
}

this->charge_level += delta_charge;  // +0xA0

// Clamp to max
float max_charge = GetMaxCharge();  // property+0x68
if (this->charge_level > max_charge) {
    this->charge_level = max_charge;
}
```

**Recharge Formula**: `charge += recharge_rate * power_level * dt * power_multiplier [* AI_multiplier]`

**CONFIRMED**: The OpenBC claim of `recharge_rate * power_level * dt` is correct. There is an additional `power_multiplier` parameter passed in by the caller (param_2 from the SWIG wrapper), plus an AI/remote-ship penalty multiplier (`DAT_00890550`).

#### Mode 2: FIRING (this+0x88 == 1) - Discharging

The discharge path only activates when the phaser intensity mode (+0xF4) is 2 (HIGH) or 3 (STOP/DEPLETED):

```c
if (this->is_firing == 1 && (this->intensity_mode == 3 || this->intensity_mode == 2)) {
    float discharge_rate = GetDischargeRateForIntensity();  // FUN_00572b00
    this->charge_level -= discharge_rate * dt;  // +0xA0

    if (this->charge_level <= 0.0f) {
        this->charge_level = 0.0f;
        StopFiring();  // vtable+0x78
        return;
    }
}
```

#### Phaser Intensity Discharge Rate (FUN_00572B00)

The discharge rate during firing depends on the phaser intensity setting (field at `this->parent+0xF0`, which is the TorpedoSystem/PhaserSystem intensity mode):

| Mode | Value | Constant Address | Meaning |
|------|-------|------------------|---------|
| 0 (LOW) | DAT_0089317C | 0x0089317C | Slowest drain |
| 1 (MED) | DAT_00893180 | 0x00893180 | Medium drain |
| 2 (HIGH) | DAT_00893184 | 0x00893184 | Fastest drain |
| other | 0.0 | (constant 0.0) | No drain |

#### Phaser Damage Scaling by Intensity (FUN_00572A50)

The per-tick damage during phaser fire is also intensity-dependent:

```c
float damage = max_damage * (power_level * parent_power) * charge_ratio * intensity_scale * dt;
// Where:
//   charge_ratio = min(current_charge / max_damage_distance, 1.0)
//   intensity_scale = {DAT_00893170, DAT_00893174, DAT_00893178} for modes {0,1,2}
```

### 1.3 Phaser CanFire Gate Conditions

**PhaserBank::CanFire** is at vtable+0x84 = **0x00571E60** (overrides EnergyWeapon::CanFire at 0x0056FA10).

Unfortunately, both 0x00571E60 and 0x0056FA10 are not auto-analyzed in Ghidra's function database (small functions, likely inlined or at the boundary of an unanalyzed block). However, we can reconstruct the gate conditions from the callers and the base class logic.

**Base class Weapon::CanFire** (vtable+0x84) is called at several sites. From FUN_00584E40 (the per-weapon fire attempt in WeaponSystem::UpdateWeapons):

```c
// FUN_00584E40 - Per-weapon fire attempt
this->weapon->timer += dt;  // +0x27*4 = randomized delay timer

if (!weapon->is_firing) {
    if (timer < FIRE_DELAY_THRESHOLD) {
        return DELAY;  // Not ready yet
    }
}

// Randomize the timer
weapon->timer = rand_float();  // Random small value
if (timer < FIRE_DELAY_THRESHOLD) {
    weapon->timer = 0.0f;
}

// THE KEY CANFIRE CHECK:
bool canFire = weapon->vtable->CanFire();  // vtable+0x84

if (!canFire) {
    weapon->vtable->StopFiring();  // vtable+0x78
    return CANNOT_FIRE;
}

// Try to actually fire:
bool fired = weapon->vtable->Fire(dt, 1);  // vtable+0x7C
```

**EnergyWeapon::GetChargePercentage** (FUN_0056FDF0) reveals a key gate condition:

```c
float GetChargePercentage() {
    ShipClass* ship = GetShipFromParent(this->parent);  // FUN_00562210
    if (ship != NULL && ship->is_alive) {               // +0x27 byte != 0
        if (!IsSubsystemAlive(ship)) {                  // FUN_0056c350 checks condition
            return this->charge_percentage;              // +0xBC
        }
    }
    return 0.0f;  // Dead ship/subsystem = 0% charge = can't fire
}
```

The **FUN_0056c350** "IsSubsystemAlive" check:
```c
bool IsSubsystemAlive(Weapon* weapon) {
    float condition = weapon->property->condition;  // property+0x40
    float power_level = weapon->power_level;        // +0x34

    // Base check: power_level >= condition? (actually HP check)
    if (GetCurrentHP() >= power_level) {  // FUN_0056b960 reads property+0x40
        return true;
    }

    // Recursive check: all child weapons must also be alive
    for (int i = 0; i < weapon->num_children; i++) {
        Weapon* child = GetChild(i);
        if (child != NULL && !IsSubsystemAlive(child)) {
            return false;
        }
    }
    return true;
}
```

**Additionally**, from FUN_00583270, the WeaponSystem checks a "can fire" flag at property offset +0x48:

```c
bool WeaponSystem_CanFireFlag() {
    return weapon->property->can_fire_flag;  // property+0x48
}
```

#### Reconstructed Gate Conditions for PhaserBank::CanFire

Based on the callers, the charge logic, and the subsystem alive checks, the gate conditions are:

1. **Ship is alive**: `GetShipFromParent(parent)` returns non-NULL and ship's alive flag is set (FUN_00562210 checks vtable+0x08 for class type 0x801C)
2. **Subsystem is alive (HP > 0)**: FUN_0056c350 checks that `current_hp >= threshold` (condition field)
3. **Charge >= MinFiringCharge**: `this->charge_level >= property->min_firing_charge` (property+0x74)
4. **Weapon system "can fire" flag**: property+0x48 byte
5. **Cloaking gate**: The phaser fire decision goes through WeaponSystem::UpdateWeapons which calls individual weapon CanFire - the cloaking check happens at a higher level via the event system (ET_START_CLOAKING disables weapon systems)
6. **Subsystem not disabled**: The `DisabledPercentage` check (SetDisabledPercentage in hardpoint files, typically 0.75) gates at the subsystem level

**OpenBC's 6 conditions are essentially confirmed**, though the exact mechanism differs slightly:
- "Ship is alive" = confirmed (GetShipFromParent returns NULL for dead ships)
- "Ship is fully DECLOAKED" = confirmed but at event/system level, not individual CanFire
- "Bank index is valid" = implicit (only valid banks exist in the weapon list)
- "Subsystem is alive (HP > 0)" = confirmed (FUN_0056c350)
- "Subsystem is not disabled" = confirmed (disabled percentage check)
- "Charge >= minimum firing charge" = confirmed (property+0x74 vs +0xA0)

### 1.4 What Happens on Fire

When a phaser fires (PhaserBank::Fire at **0x00570FE0** / EnergyWeapon Fire at vtable+0x7C):

1. The phaser beam object is created via `FUN_00578180` (creates a beam visual from spawn point to target)
2. Beam velocity is set from the weapon's direction vectors
3. `is_firing` (+0x88) is set to 1
4. The sound system is triggered
5. In multiplayer (host), `FUN_005762b0` / `FUN_0057d110` serialize the fire event over the network
6. The beam damage is applied via the normal damage pipeline (see docs/damage-system.md)
7. During subsequent UpdateCharge ticks, the discharge branch runs (Mode 2 above), draining charge

When charge depletes to 0:
- `this->charge_level = 0.0f`
- `StopFiring()` is called (vtable+0x78)
- The beam visual ends

### 1.5 Network Wire Format: BeamFire (Opcode 0x1A)

Handler: **FUN_0069FBB0** (called from MultiplayerGame dispatch)

The handler:
1. Forwards the packet to all other players (via the "Forward" forwarding group)
2. Deserializes from the stream:
   - Object ID of the firing weapon (via FUN_006CF6A0 = ReadInt)
   - Byte flags (FUN_006CF540 = ReadByte)
   - Compressed hit position (ReadCompressedVector3)
   - Another byte for additional flags
   - Optional target object ID
3. Looks up the weapon via FUN_006F0EE0 (GetObjectByID)
4. Calls FUN_005762B0 (the beam fire initialization) with the deserialized data

### 1.6 Phaser Power Setting (Opcode 0x12)

The phaser intensity (LOW/MED/HIGH) is set via `SetPowerSetting` (vtable+0x90). In multiplayer, this is forwarded as opcode 0x12 (SetPhaserLevel) through the shared event handler FUN_0069FDA0.

The intensity mode stored at `parent+0xF0` controls:
- Discharge rate during firing (faster for higher settings)
- Damage output per tick (higher damage for higher settings)
- Charge consumption speed

---

## Part 2: Torpedo System

### 2.1 Object Layout - TorpedoTube

Field offsets on TorpedoTube (`this`, size 0xB0):

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x18 | ptr | property | TorpedoTubeProperty* |
| +0x24 | ptr | parent | TorpedoSystem* parent |
| +0x34 | float | power_level | Power allocation (default 1.0) |
| +0x40 | ptr | owner_ship | Parent ship ptr |
| +0x8C | int | target_id | Current target |
| +0xA0 | int | num_ready | Count of loaded torpedoes |
| +0xA4 | float | last_fire_time | Game time when last fired (init: -1000.0f = 0xC47A0000) |
| +0xA8 | byte | is_skew_fire | Skew fire flag |
| +0xAC | ptr | reload_timers | float[] array, one per tube slot |

#### TorpedoTubeProperty (the hardpoint config, at +0x18)

| Offset | Type | Name | Accessor | Example (Sovereign) |
|--------|------|------|----------|---------------------|
| +0x88 | float | reload_delay | GetReloadDelay() (FUN_0057C410 -> prop+0x88) | 40.0 |
| +0x8C | int | max_ready | GetMaxReady() | 1 |
| ?? | float | immediate_delay | GetImmediateDelay() (FUN_0057C400-ish) | 0.25 |

#### TorpedoSystem Fields (parent, at +0x24)

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x1C | int | num_weapons | Count of TorpedoTubes in this system |
| +0xF0 | float | last_system_fire_time | Last fire timestamp for the entire system |
| +0xF4+N*4 | int[] | ammo_counts | Per-type ammo remaining |
| +0x114 | int | current_ammo_type | Currently selected ammo type index |
| +0x118 | int | total_ammo_consumed | Running counter |

### 2.2 Torpedo Reload/Cooldown Logic

**Function**: `TorpedoTube::ReloadTorpedo` at **0x0057D8A0** (called via SWIG wrapper `swig_TorpedoTube_ReloadTorpedo` at 0x00613750)

```c
// FUN_0057D8A0 - TorpedoTube::ReloadTorpedo
void TorpedoTube::ReloadTorpedo() {
    TorpedoSystem* system = this->parent;   // +0x24
    TorpedoTubeProperty* prop = GetProperty(); // via FUN_0057c330 -> +0x18
    int max_ready = prop->max_ready;         // property+0x8C

    // Gate: already at max loaded?
    if (this->num_ready >= max_ready) return;

    // Gate: ammo available for current type?
    int ammo_type = system->current_ammo_type;   // parent+0x114
    int ammo_remaining = system->ammo_counts[ammo_type]; // parent+0xF4+type*4
    int total_consumed = system->total_ammo_consumed;     // parent+0x118

    if (ammo_remaining == total_consumed) return;  // No ammo left
    if (ammo_remaining - total_consumed < 0) return; // Sanity check

    // RELOAD: increment ready count
    this->num_ready++;  // +0xA0

    // Increment system-wide ammo consumed counter
    system->total_ammo_consumed++;  // parent+0x118 via FUN_0057b560

    // Find the tube with the LONGEST remaining cooldown and reset it
    float max_timer = -1.0f;
    int max_idx = -1;
    int num_tubes = GetNumTubes();  // FUN_0057c420 -> property+0x8C
    for (int i = 0; i < num_tubes; i++) {
        if (this->reload_timers[i] > max_timer) {  // +0xAC array
            max_timer = this->reload_timers[i];
            max_idx = i;
        }
    }
    if (max_idx != -1) {
        this->reload_timers[max_idx] = -1.0f;  // 0xBF800000 = -1.0f (mark as loaded)
    }

    // Post RELOAD_TORPEDO event (0x00800065)
    TGMessage* msg = new TGMessage();
    msg->event = 0x00800065;  // ET_RELOAD_TORPEDO
    msg->preserve = 0;
    msg->SetSubject(this);
    PostMessage(msg);
}
```

### 2.3 Torpedo Fire Logic

**Function**: `TorpedoTube::Fire` at **0x0057C9E0** (vtable+0x7C for TorpedoTube)

```c
// FUN_0057C9E0 - TorpedoTube::Fire(dt, flag)
bool TorpedoTube::Fire(float dt, char flag) {
    // FIRST: Check CanFire
    bool canFire = this->vtable->CanFire();  // vtable+0x84
    if (!canFire) return false;

    // Create the torpedo projectile object
    Torpedo* torpedo = CreateTorpedoProjectile();  // FUN_0057cd90

    // Set target on torpedo
    torpedo->target_id = 0;

    TorpedoSystem* system = this->parent;  // +0x24

    // Record fire time (global game clock)
    this->last_fire_time = g_Clock->gameTime;  // g_Clock+0x90 -> +0xA4

    // Decrement ready count
    this->num_ready--;  // +0xA0

    // Decrement system-wide available count
    system->available_count--;  // FUN_0057b4d0
    system->total_available--;  // FUN_0057b570

    // Find a tube slot with completed cooldown and start new cooldown
    int num_tubes = GetNumTubes();
    for (int i = 0; i < num_tubes; i++) {
        if (this->reload_timers[i] <= 0.0f) {
            this->reload_timers[i] = 0.0f;  // Mark as "cooldown started"
            break;
        }
    }

    // Set up the torpedo with launch parameters
    SetupTorpedo(this, torpedo);  // FUN_0057da20

    // Post WEAPON_FIRED event (0x0080007C)
    TGMessage* msg = new TGMessage();
    msg->SetSource(this);
    msg->SetSubject(this->owner_ship);
    msg->event = 0x0080007C;  // ET_WEAPON_FIRED (NOT ET_TORPEDO_FIRED which is 0x00800066)
    msg->preserve = 0;
    PostMessage(msg);

    // Record system-level fire time
    system->last_system_fire_time = g_Clock->gameTime;  // parent+0xF0

    // If host, send network packet
    if (g_IsHost) {
        SendTorpedoFirePacket(this, torpedo, flag, true);  // FUN_0057cb10
    }

    return true;
}
```

### 2.4 Network Wire Format: TorpedoFire (Opcode 0x19)

**Serialization** (FUN_0057CB10):
```
[0x19]                          // opcode
[int32: weapon_obj_id]          // this->obj_id (+0x04)
[byte: torpedo_model_index]     // from torpedo object (+0x14C)
[byte: flags]                   // bit0=skew, bit1=isSkewFire(+0xA8), bit2=noTarget
[compressed_vec3: velocity]     // torpedo velocity (normalized direction * speed)
[if !noTarget: int32 targetID]  // target object ID
[if !noTarget: compressed_vec4] // target offset/radius
```

**Deserialization** handler at **0x0069F930**:
1. Forwards packet to all other players
2. Reads weapon object ID, torpedo model index, flags
3. Reads compressed velocity vector
4. If has target (bit2 not set): reads target ID, gets target's bounding sphere radius, reads compressed impact offset
5. Calls `FUN_0057D110` (TorpedoSystem-level fire handler) with all parameters

### 2.5 Torpedo Type Switch (SetAmmoType)

**Function**: `TorpedoSystem::SetAmmoType` at **0x0057B230**

```c
// FUN_0057B230 - TorpedoSystem::SetAmmoType(int newType, char immediate)
void TorpedoSystem::SetAmmoType(int newType, char immediate) {
    // Step 1: UNLOAD all tubes - decrement ready count to 0
    for (int i = 0; i < this->num_weapons; i++) {
        TorpedoTube* tube = GetWeapon(i);  // FUN_0056c570

        // Unload all loaded torpedoes
        while (tube->num_ready > 0) {
            UnloadTorpedo(tube);  // FUN_0057d9a0 - decrements num_ready
        }

        // Clear ALL cooldown timers
        ClearTimers(tube);  // FUN_0057c740 - sets all timer slots to 0.0

        // If NOT immediate: reload all tubes with new type
        if (immediate == 0) {
            int num_tubes = GetNumTubes(tube);
            for (int j = 0; j < num_tubes; j++) {
                ReloadTorpedo(tube);  // FUN_0057d8a0
            }
        }
    }

    // Step 2: Post ammo-change events
    // ET_AMMO_TYPE_CHANGED (0x00800067)
    // If immediate: also ET_AMMO_SWITCH_STARTED (0x00800068)
    // ...

    // Step 3: If type actually changed AND is host, send network event
    if (this->current_ammo_type != newType && g_IsHost) {
        // Send ET_TORP_TYPE_CHANGE (0x008000FE) for MP sync
    }

    // Step 4: Update current type
    this->current_ammo_type = newType;  // +0x114
}
```

#### Type Switch "Lockout" Analysis

The OpenBC doc claims: "Type switch lockout = max(reload_delay) across all tubes."

**FINDING**: The code does NOT implement an explicit timer-based lockout. Instead:

1. When `SetAmmoType(type, immediate=1)` is called (the normal MP path via SWIG):
   - All tubes are unloaded (`num_ready` set to 0)
   - All cooldown timers are cleared (set to 0.0)
   - Tubes are NOT immediately reloaded (the `immediate == 0` branch is skipped)
   - This means tubes start empty and must go through their normal reload cycle

2. The "lockout" is therefore **implicit**: after a type switch, all tubes have `num_ready == 0` and must be reloaded. The effective lockout duration equals the time it takes for the first tube to reload, which is governed by the `ReloadDelay` property (e.g., 40.0 seconds for Sovereign torpedoes).

3. When `SetAmmoType(type, immediate=0)` is called (local/offline):
   - All tubes are unloaded AND immediately reloaded with the new type
   - This results in NO lockout - tubes are instantly ready

**CONCLUSION**: The "lockout" is real in multiplayer (immediate=1 path) but is not a separate timer. It is a side effect of unloading + clearing + not reloading. The effective duration is the longest ReloadDelay across all tubes in the system, because all tubes restart their reload cycle simultaneously.

### 2.6 Torpedo Cooldown Mechanism

Each TorpedoTube has an array of `float` reload timers at offset +0xAC, one per "slot" (the number of slots = `max_ready` from the property, typically 1).

**Timer states**:
- `-1.0f` (0xBF800000): Slot is loaded/ready (torpedo available)
- `0.0f`: Slot cooldown just started (will count up)
- `> 0.0f`: Slot is cooling down (time elapsed since fire)
- `<= 0.0f` (other negative): Available for reload

The reload is managed by the `ReloadTorpedo` function (FUN_0057D8A0) which:
1. Checks `num_ready < max_ready` AND ammo available
2. Increments `num_ready`
3. Finds the slot with the longest timer value and resets it to `-1.0f` (marking it loaded)
4. Posts ET_RELOAD_TORPEDO event

**UnloadTorpedo** (FUN_0057D9A0) does the reverse:
1. Decrements `num_ready`
2. Finds the first slot with timer <= 0.0 and resets it to 0.0 (marking it as empty)

**Cooldown timer progression**: The tubes do NOT have an explicit "tick down" function visible in the analyzed code. The reload appears to be event-driven: the game's subsystem update loop posts events at the right time, and ReloadTorpedo is called when the cooldown expires. The `last_fire_time` (+0xA4) records when the tube last fired, and comparison against `g_Clock->gameTime` + `ReloadDelay` determines when to reload.

### 2.7 TorpedoTube::CanFire

The TorpedoTube CanFire (vtable+0x84 at 0x0057D780) was not auto-analyzed by Ghidra, but from the TorpedoTube::Fire function (FUN_0057C9E0), we can see:
- It is called first in the Fire method
- If it returns false, Fire returns false immediately
- The fire path then checks `num_ready > 0` implicitly (via the ammo count checks)

Based on the Weapon base class pattern and the TorpedoTube fields, the CanFire conditions are:

1. **Ship is alive** (same as phaser - base class check)
2. **Subsystem is alive (HP > 0)** (same as phaser - base class check)
3. **Subsystem is not disabled** (same as phaser)
4. **num_ready > 0** (at least one torpedo loaded)
5. **Ammo available** (ammo_remaining > total_consumed for current type)
6. **Cooldown expired**: `current_game_time - last_fire_time >= immediate_delay` (the ImmediateDelay property, typically 0.25s, prevents rapid double-fires)

---

## Part 3: WeaponSystem Update Loop

### 3.1 WeaponSystem::UpdateWeapons (FUN_00584930)

This is the main weapon tick function, called every frame by the game loop.

**Signature**: `Weapon* WeaponSystem::UpdateWeapons(float dt, char* didFire)`

```c
// High-level pseudocode of FUN_00584930
Weapon* WeaponSystem::UpdateWeapons(float dt, char* didFire) {
    *didFire = false;

    // Gate: ship is dead?
    if (this->owner_ship->isDead) return NULL;  // +0x40 -> +0x210

    // Clean up dead targets from target list
    CleanupTargetList();  // FUN_00584cc0

    // Get current firing chain configuration
    FiringChain* chain = GetFiringChain(this->current_chain_index);  // +0xB8
    int groupId = (chain != NULL) ? GetFirstGroup(chain) : 0;

    // Determine start weapon index for round-robin
    int startIdx = (this->last_weapon_idx + 1);  // +0xB4
    if (IsSingleFire()) startIdx = max(0, this->last_weapon_idx);

    // Build list of weapons that can fire at current target/group
    List weaponsToFire;
    for (int i = startIdx; i < startIdx + num_weapons; i++) {
        Weapon* w = GetWeapon(i % num_weapons);
        if (groupId == 0 || w->IsInGroup(groupId)) {
            weaponsToFire.add(w);
        }
    }

    // Try firing each weapon in the list
    for (Weapon* w : weaponsToFire) {
        result = TryFireWeapon(w, dt);  // FUN_00584e40
        if (result == FIRED) {
            *didFire = true;
            this->last_weapon_idx = GetIndex(w);
            this->last_group_id = groupId;
            if (IsSingleFire()) break;  // Only fire one at a time
        } else if (result == CANNOT_FIRE) {
            // Weapon's own CanFire returned false
            w->timer = 0;  // Reset its delay timer

            // Check if we should try direct fire (no target list)
            if (this->target_list_count == 0 &&
                w->canFireFlag &&
                w->vtable->TryFire(dt, 1)) {
                // Weapon fired without target
                this->last_weapon_idx = GetIndex(w);
                this->last_group_id = groupId;
            }
        }
    }

    // If no weapons fired and using firing chain, try next group
    if (!*didFire && chain != NULL) {
        groupId = GetNextGroup(chain, groupId);
        if (groupId == originalGroupId) {
            // Cycled through all groups, nothing can fire
            this->last_group_id = -1;
            return NULL;
        }
        // Retry with new group...
    }

    return lastFiredWeapon;
}
```

### 3.2 Per-Weapon Fire Attempt (FUN_00584E40)

```c
// FUN_00584E40 - Try to fire a specific weapon
int TryFireWeapon(Weapon* weapon, float dt) {
    // Update random fire delay timer
    if (!this->aim_assisted) {
        weapon->timer += dt;
    } else {
        weapon->timer = FIRE_DELAY_MAX;  // DAT_00893830
    }

    // If not already firing, check if delay timer expired
    if (!weapon->is_firing) {
        if (weapon->timer < FIRE_DELAY_MAX) {
            return DELAY;  // Still waiting
        }
    }

    // Re-randomize timer
    weapon->timer = rand_float();
    if (weapon->timer < FIRE_DELAY_MAX) {
        weapon->timer = 0.0f;
    }

    // THE KEY CHECK: Can this weapon fire?
    bool canFire = weapon->CanFire();  // vtable+0x84
    if (!canFire) {
        weapon->StopFiring();  // vtable+0x78
        return CANNOT_FIRE;
    }

    // Try to fire at a target from the target list
    bool fired = weapon->Fire(dt, 1);  // vtable+0x7C
    if (fired) return FIRED;

    // If weapon didn't fire at queued target, try targets from the supplementary list
    if (this->supplementary_target_list != NULL) {
        for (TargetEntry* entry : supplementary_target_list) {
            Ship* target = GetObjectByID(entry->targetID);
            if (target != NULL && IsShip(target)) {
                SetupWeaponTarget(weapon, entry);
                fired = weapon->Fire(dt, 1);
                if (fired) return FIRED;
            }
        }
    }

    return CANNOT_FIRE;
}
```

### 3.3 Shared Event Forwarding Handler (FUN_0069FDA0)

Opcodes 0x07-0x0C and 0x0E-0x12 all route to this function. It:
1. Gets the raw packet data from the message
2. Deserializes it into a TGMessage
3. If multiplayer, forwards to all clients (via FUN_006B4EC0 broadcast)
4. Posts the message to the local event queue (FUN_006DA300)
5. The Python/C++ event handlers then process the event

This means weapon control commands (start firing, stop firing, phaser level change, torpedo type change, etc.) are all just **events forwarded from one client to the server and then broadcast to all clients**.

---

## Part 4: Summary of Key Constants

| Address | Type | Name | Used In |
|---------|------|------|---------|
| 0x00888B54 | float | 0.0f | Zero constant (used everywhere) |
| 0x00888B58 | float | ~epsilon | Near-zero threshold |
| 0x00888860 | float | 1.0f | One constant |
| 0x00890550 | float | AI_recharge_mult | Non-owner ship recharge penalty |
| 0x00893170 | float | damage_scale_LOW | Phaser damage scale, intensity 0 |
| 0x00893174 | float | damage_scale_MED | Phaser damage scale, intensity 1 |
| 0x00893178 | float | damage_scale_HIGH | Phaser damage scale, intensity 2 |
| 0x0089317C | float | discharge_rate_LOW | Phaser discharge, intensity 0 |
| 0x00893180 | float | discharge_rate_MED | Phaser discharge, intensity 1 |
| 0x00893184 | float | discharge_rate_HIGH | Phaser discharge, intensity 2 |
| 0x00893830 | float | FIRE_DELAY_THRESH | Minimum fire delay timer threshold |
| 0x008936C0 | float | SKEW_FIRE_SCALE | Torpedo skew fire direction multiplier |
| 0x0088B9C0 | float | 1.0f | Max charge ratio cap |
| 0x0088BEAC | float | ?? | Torpedo damage/speed scaler |
| 0x0088BF24 | float | ?? | Torpedo local lifetime scale |
| 0x008E53DC | float | RANGE_SCALE | Phaser beam range normalization |

---

## Part 5: Function Address Reference

### Phaser (EnergyWeapon / PhaserBank)

| Address | Name | Description |
|---------|------|-------------|
| 0x00572B80 | PhaserBank::UpdateCharge | Recharge (not firing) / discharge (firing) |
| 0x0056FD70 | EnergyWeapon::UpdateCharge | Base class recharge (no discharge branch) |
| 0x00572B00 | PhaserBank::GetDischargeRate | Intensity-dependent discharge rate lookup |
| 0x00572A50 | PhaserBank::CalcDamagePerTick | Intensity-dependent damage calculation |
| 0x00571E60 | PhaserBank::CanFire | Fire gate conditions (vtable+0x84) |
| 0x0056FA10 | EnergyWeapon::CanFire | Base class fire gate (vtable+0x84) |
| 0x00570FE0 | PhaserBank::Fire | Beam creation + fire (vtable+0x7C) |
| 0x00572C50 | PhaserBank::GetFireDirection | Calculate beam direction from arc angles |
| 0x005762B0 | BeamFire_NetworkSend | Serialize beam fire for network (called by host) |
| 0x0056F8D0 | GetProperty() | Returns this->property (+0x18) |
| 0x0056F8E0 | GetRechargeRate() | Returns property+0x6C |
| 0x0056F900 | GetMaxCharge() | Returns property+0x68 |
| 0x0056F910 | GetMinFiringCharge() | Returns property+0x74 |
| 0x0056F8F0 | GetNormalDischargeRate() | Returns property+0x70 |
| 0x0056F930 | GetMaxDamage() | Returns property+0x78 |
| 0x0056F940 | GetMaxDamageDistance() | Returns property+0x7C |
| 0x0056FDF0 | GetChargePercentage() | Returns charge % if alive, else 0.0 |
| 0x0056C350 | IsSubsystemAlive() | Recursive HP check on weapon tree |

### Torpedo (TorpedoTube / TorpedoSystem)

| Address | Name | Description |
|---------|------|-------------|
| 0x0057C9E0 | TorpedoTube::Fire | Fire torpedo (vtable+0x7C) |
| 0x0057D780 | TorpedoTube::CanFire | Fire gate conditions (vtable+0x84) |
| 0x0057D8A0 | TorpedoTube::ReloadTorpedo | Load one torpedo into tube |
| 0x0057D9A0 | TorpedoTube::UnloadTorpedo | Remove one torpedo from tube |
| 0x0057C740 | TorpedoTube::ClearTimers | Reset all reload timer slots to 0.0 |
| 0x0057B230 | TorpedoSystem::SetAmmoType | Change torpedo type (unload+reload) |
| 0x0057B560 | TorpedoSystem::IncrementConsumed | total_ammo_consumed++ (parent+0x118) |
| 0x0057CB10 | TorpedoFire_NetworkSend | Serialize torpedo fire (opcode 0x19) |
| 0x0057CD90 | CreateTorpedoProjectile | Create torpedo scene object |
| 0x0057C330 | TorpedoTube::GetProperty() | Returns this->property (+0x18) |
| 0x0057C410 | TorpedoTube::GetReloadDelay() | Returns property+0x88 |
| 0x0057C420 | TorpedoTube::GetNumTubes() | Returns property+0x8C |
| 0x0057DE90 | TorpedoTube::GetFirePosition | Calculate world-space launch position |

### WeaponSystem

| Address | Name | Description |
|---------|------|-------------|
| 0x00584930 | WeaponSystem::UpdateWeapons | Main weapon tick (per-frame) |
| 0x00584E40 | WeaponSystem::TryFireWeapon | Per-weapon fire attempt |
| 0x00584CC0 | WeaponSystem::CleanupTargets | Remove dead targets from list |
| 0x00584060 | WeaponSystem::IsSingleFire | Check single-fire mode |
| 0x00583270 | Weapon::GetCanFireFlag | Property+0x48 byte |

### Network Handlers

| Address | Opcode | Name | Description |
|---------|--------|------|-------------|
| 0x0069FBB0 | 0x1A | BeamFire_Handler | Deserialize + replay beam fire |
| 0x0069F930 | 0x19 | TorpedoFire_Handler | Deserialize + replay torpedo fire |
| 0x0069FDA0 | 0x07-0x12 | SharedEvent_Handler | Forward event to all + local dispatch |
| 0x0057D110 | (called) | TorpedoFire_Replay | Process received torpedo fire data |
| 0x005762B0 | (called) | BeamFire_Replay | Process received beam fire data |

---

## Part 6: Vtable Comparison Table

### PhaserBank vtable (0x00893194) vs TorpedoTube vtable (0x00893630)

| Slot | Offset | PhaserBank | TorpedoTube | Name |
|------|--------|------------|-------------|------|
| 0 | +0x00 | 0x00570EB0 (dtor) | 0x005833F0 | scalar_deleting_dtor |
| 30 | +0x78 | 0x0056D250 | 0x0057C770 | StopFiring |
| 31 | +0x7C | 0x00570FE0 | 0x0057C9E0 | Fire(dt, flag) |
| 32 | +0x80 | 0x0056FA00 | 0x005833F0 | TryFire / Reset |
| 33 | +0x84 | 0x00571E60 | 0x0057D780 | CanFire() |
| 34 | +0x88 | 0x00572C50 | 0x0057DE90 | GetFireDirection/Position |
| 36 | +0x90 | inherited | inherited | SetPowerSetting |
