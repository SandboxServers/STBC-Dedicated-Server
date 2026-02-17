# Bridge Commander Shield System

Reverse-engineered from stbc.exe via Ghidra decompilation and binary analysis. High confidence -- all addresses and constants verified against the game binary.

## Overview

Bridge Commander ships have 6 shield facings (front, rear, top, bottom, left, right), each with independent HP and recharge rate. The shield subsystem is modeled as an ellipsoidal shell around the ship; incoming damage is projected onto this ellipsoid to determine which facing absorbs it. Each facing can independently absorb damage up to its current HP, with overflow damage passing through to hull and subsystems.

## Shield Facing Enum

```c
enum ShieldFacing {
    NO_SHIELD      = -1,
    FRONT_SHIELDS  = 0,   // +Y axis (forward)
    REAR_SHIELDS   = 1,   // -Y axis (aft)
    TOP_SHIELDS    = 2,   // +Z axis (up)
    BOTTOM_SHIELDS = 3,   // -Z axis (down)
    LEFT_SHIELDS   = 4,   // -X axis (port)
    RIGHT_SHIELDS  = 5,   // +X axis (starboard)
    NUM_SHIELDS    = 6
};
```

Opposite pairs: FRONT(0)<->REAR(1), TOP(2)<->BOTTOM(3), LEFT(4)<->RIGHT(5).

## Shield Object Layout

### ShieldClass (vtable at 0x00892f34, size 0x15C)

Inherits from PoweredSubsystem. The ShieldClass is the runtime instance that tracks current shield HP per facing.

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x00 | vtable* | vtable | PTR_FUN_00892f34 |
| +0x18 | ShieldProperty* | property | Pointer to ShieldProperty (max values, charge rates) |
| +0x20 | void* | shipRef | Reference to parent ship |
| +0x38 | byte | hasActiveHits | Set to 1 when any shield zone has pending damage hits |
| +0x40 | void* | shieldZoneList | Linked list of shield zone objects for intersection |
| +0x9C | byte | isEnabled | 0 = shields off (e.g., during cloak), nonzero = shields active |
| +0xA8 | float[6] | curShields | Current HP per facing (indexed by ShieldFacing enum) |
| +0xC0 | float[6] | shieldPercentage | Cached percentage per facing |
| +0xDC | struct[7] | shieldWatchers | 0xC-byte watcher structs (one per facing + 1 overall) |
| +0x124 | void* | overallWatcher | Pointer to overall shield health watcher |
| +0x14C | byte[6] | shieldDamaged | Per-facing "damaged" flag |
| +0x154 | float | envDamageRadius | Environmental shield damage radius |
| +0x158 | float | envDamageRate | Environmental shield damage rate |

### ShieldProperty (vtable at 0x00892fc4, size 0x88)

Inherits from PoweredSubsystemProperty. Read-only template defining max shield values and charge rates. Set by hardpoint scripts.

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x00 | vtable* | vtable | PTR_FUN_00892fc4 |
| +0x14 | void* | parent | Parent subsystem property |
| +0x18 | void* | shieldClass | Back-reference to ShieldClass |
| +0x20 | float | maxHP | Maximum HP (subsystem overall health) |
| +0x28-0x2C | ushort[3] | colorIndices | Shield glow color indices (init 0xFFFF) |
| +0x30 | float | colorScale1 | Shield glow scale (init 1.0) |
| +0x34 | float | colorScale2 | Shield glow decay (init 1.0) |
| +0x38 | float | colorScale3 | (init 1.0) |
| +0x3C | float | minPowerThreshold | Minimum power for operation (init 0.001) |
| +0x40 | float | currentPower | Current power level (0.0 = unpowered) |
| +0x44-0x45 | byte[2] | flags | (init 0) |
| +0x48 | float | tickPhaseOffset | Random phase for staggered event scheduling |
| +0x60 | float[6] | maxShields | Maximum shield HP per facing (set by SetMaxShields) |
| +0x78 | float[6] | chargePerSecond | Shield charge rate per facing (set by SetShieldChargePerSecond) |
| +0x84 | int | (unused) | (init 0) |

Constructor default for maxShields: `0x447a0000` = 1000.0 per facing.

## Shield Facing Determination (FUN_0056a8d0 at 0x0056a8d0)

### Algorithm: Maximum Component Projection

The shield facing is determined by finding which of the 6 cardinal directions most closely aligns with the damage impact normal vector, expressed in the ship's local coordinate system.

**Input**: A 3D normal vector in ship-local space (X, Y, Z components)

**Process**:
1. Rearrange components to `{Y, Z, X}` (forward, up, right)
2. Find the maximum positive component among the first 3 values (indices 0-2)
3. Find the maximum negated component among indices 3-5 (equivalent to most-negative of Y, Z, X)
4. The overall maximum determines the dominant direction
5. Map dominant direction to facing via switch table

**Switch mapping**:
```c
// Input reordering: [0]=Y, [1]=Z, [2]=X, [3]=-Y, [4]=-Z, [5]=-X
switch(dominant_index) {
    case 0: return 0;  // +Y (forward)  -> FRONT_SHIELDS
    case 1: return 2;  // +Z (up)       -> TOP_SHIELDS
    case 2: return 5;  // +X (right)    -> RIGHT_SHIELDS
    case 3: return 1;  // -Y (aft)      -> REAR_SHIELDS
    case 4: return 3;  // -Z (down)     -> BOTTOM_SHIELDS
    case 5: return 4;  // -X (left)     -> LEFT_SHIELDS
}
```

This is NOT a dot-product projection in the traditional sense. It is an **axis-aligned maximum component test** (equivalent to finding the dominant face of a cube that encloses the unit normal). This is computationally cheap (no trig, no dot products -- just comparisons) and gives correct results for a symmetric shield ellipsoid.

### Full Ray-Ellipsoid Path (FUN_0056a690 at 0x0056a690)

When a weapon fires at a ship, the ray-to-facing calculation is:

1. Transform ray endpoints from world space to the shield ellipsoid's local space
2. Normalize by the ellipsoid semi-axes (making it a unit sphere)
3. Perform ray-sphere intersection test (FUN_004570d0) against the unit sphere
4. Compute the outward normal at the intersection point
5. Un-normalize back to ship-local space
6. Pass the normal to FUN_0056a8d0 to determine the facing

The ellipsoid semi-axes are stored in the ship's NiNode at offsets `+0x24C`, `+0x250`, `+0x254` (accessed as `piVar1[0x93]`, `piVar1[0x94]`, `piVar1[0x95]`).

## Shield Absorption

### Two Damage Paths

Bridge Commander has two distinct shield absorption paths:

#### Path 1: Area-Effect Damage (FUN_00593c10 at 0x00593c10)

Used for environmental/explosion damage. Distributes damage equally across all 6 facings.

```
For each target in range:
    totalAbsorbed = 0
    damagePerFacing = totalDamage * (1/6)   // DAT_0088bacc = 0.16667

    For each facing (0..5):
        absorption = min(damagePerFacing, curShields[facing])
        curShields[facing] -= absorption
        totalAbsorbed += absorption

    overflowDamage = totalDamage - totalAbsorbed
    if overflowDamage > 0:
        apply to hull (visual effect + damage)
```

**Key constant**: `_DAT_0088bacc` = `1/6` = `0.16667` (at 0x0088bacc, hex `0x3E2AAAAB`).

This is NOT all-or-nothing. Each facing independently absorbs up to its current HP for that facing's share. If any facing is depleted, its share of damage passes through. A ship with 5 full facings and 1 empty facing would still lose 1/6 of incoming area damage to hull.

#### Path 2: Directed Damage (ProcessDamage at 0x00593E50)

Used for weapon hits and collisions. Damage is directed at a specific location, hitting specific shield geometry.

1. **ProcessDamage** iterates the handler array (ship+0x128, count at ship+0x130)
2. Per handler, **FUN_004b1ff0** checks:
   - Shield path: `handler+0x20` -> shield zone object, gated on `zone+0x18 != 0` (shield active)
   - Hull path: `handler+0x1C` -> AABB overlap test
3. Shield zone intersection (FUN_004b4b40) finds which shield geometry nodes are hit:
   - Transforms the DamageVolume into the shield ellipsoid's local space
   - Tests intersection using FUN_00464770 (sphere-geometry test)
   - For each hit, looks up the shield facing via FUN_004b8e80 (zone list at `shield+0x40`)
   - Adds the DamageVolume to the facing's hit list
   - Sets dirty flag (`facing[7] |= 1`)
4. Hull overlap test (FUN_004bd9f0) checks AABB intersection for subsystem damage
5. After all handlers, **FUN_00593ee0** applies remaining damage to hull

The shield facing's hit list is processed through the event system, with actual HP decrement happening via FUN_0056a5c0 (SetCurShields). The weapon hit handler at FUN_005af010 checks `weaponHitInfo+0x58` to determine if the hit passed through shields:
- `+0x58 == 0`: Shield absorbed the hit (shield visual effect, no hull damage)
- `+0x58 != 0`: Shields breached (hull hit effect + DoDamage to hull)

### Shield Absorption is Per-Facing, Not All-or-Nothing

Shields absorb damage up to the current HP of the specific facing that was hit. If the shield facing's HP is depleted mid-hit, the overflow damage passes through to hull. This is clamp-based absorption:

```c
// FUN_0056a5c0 (SetCurShields)
void SetCurShields(ShieldClass* this, int facing, float newHP) {
    float maxHP = this->property->maxShields[facing];  // property+0x60+facing*4
    if (maxHP < newHP) newHP = maxHP;  // cap at max
    if (newHP < 0.0) newHP = 0.0;     // floor at zero (DAT_00888b54)
    this->curShields[facing] = newHP;  // store at this+0xA8+facing*4
}
```

## Shield Recharge (BoostShield at 0x0056a420)

### Recharge Formula

```c
float10 BoostShield(ShieldClass* this, int facing, float powerAmount) {
    float normalizedPower = this->property->currentPower * (1.0/6.0);
    // property+0x48 * DAT_0088bacc (= 1/6)
    // NormalPowerPerSecond divided by 6 facings

    if (normalizedPower <= 0.0) return powerAmount;  // no power, no recharge

    float chargeRate = this->property->chargePerSecond[facing];
    // property+0x78+facing*4

    float hpGain = (chargeRate * powerAmount) / normalizedPower;
    float newHP = this->curShields[facing] + hpGain;
    this->curShields[facing] = newHP;

    if (newHP > this->property->maxShields[facing]) {
        // Shield full -- calculate and return excess
        float ratio = chargeRate / normalizedPower;
        if (ratio <= 0.0) ratio = 0.0;
        float excess = (newHP - maxShields[facing]) / ratio;
        this->curShields[facing] = maxShields[facing];  // cap at max
        return excess;  // return unused power for redistribution
    }
    return 0.0;  // all power consumed
}
```

**Key details**:
- `powerAmount` is NOT frame time -- it is a "power budget" in energy units
- The power budget comes from the PoweredSubsystem's per-tick energy allocation
- `chargeRate` (chargePerSecond) is the conversion factor from power to shield HP
- The `1/6` factor distributes the subsystem's total power equally across 6 facings
- **Overflow power is returned** to the caller for redistribution to other facings

### Recharge Scheduling (Event System)

Shield recharge runs through the event system, NOT through a direct per-tick call:

1. **ShieldProperty constructor** (FUN_0056b970) initializes a random phase offset at `+0x48`:
   ```c
   this->tickPhaseOffset = rand() * 0.33 * 3.05e-05;  // stagger events across ticks
   ```

2. **FUN_0056bde0** (called when power level changes) schedules periodic events:
   - Event `0x0080006d`: Primary shield recharge tick
   - Event `0x0080006e`: Secondary recharge (different rate)
   - Events `0x0080006f`-`0x00800071`: Additional periodic events
   - Uses `FUN_0044c2d0` to create periodic timer events with the phase offset

3. **HandleSetShieldState** (registered at 0x0056aae0, debug string "ShieldClass::HandleSetShieldState"):
   - This is the event handler called when shield tick events fire
   - Address range 0x0056a230 through 0x0056aad0 (not in Ghidra function database)
   - Calls `FUN_0056a420` (BoostShield) per facing at addresses 0x0056a2e6 and 0x0056a392
   - Handles redistribution of overflow power between facings

4. **Registration** (FUN_0056a1f0 at 0x0056a1f0):
   ```c
   FUN_006da130(&LAB_0056aae0, "ShieldClass::HandleSetShieldState");
   ```
   Called from the ship event handler registration function (FUN_005ab6a0).

### Typical Recharge Values (from hardpoint scripts)

| Ship | Facing | MaxShields | ChargePerSecond |
|------|--------|-----------|-----------------|
| Sovereign | All | 6000 | 15 |
| Galaxy | All | 5600 | 12 |
| Akira | All | 3600 | 11 |
| Warbird | All | 4000 | 8 |
| Vor'cha | Front | 24000 | 28 |
| Vor'cha | Others | varies | 2-9 |

## Cloak / Shield Interaction

### Shield Disable During Cloak (FUN_0055f110 at 0x0055f110)

When the cloaking subsystem activates:

1. **StartCloaking** (FUN_0055f360) sets `cloakObj+0xAD = 1` (trying to cloak)
2. The cloak handler (FUN_0055f110) schedules a **delayed** shield disable:
   - Creates an event sequence with event `0x00800077` (shield off event)
   - The delay is `DAT_008e4e20` = **1.0 second** (the CloakingSubsystem ShieldDelay value)
   - Sets cloak state to `+0xB0 = 2` (cloaking in progress)
3. After the delay, event `0x00800077` fires, setting `shieldClass+0x9C = 0` (shields disabled)

### Shield Re-enable During Decloak

When the cloaking subsystem deactivates:

1. The handler is called with `param_1 != 1` (decloaking)
2. Posts event `0x00800079` (shield on event) immediately
3. Sets cloak state to `+0xB0 = 5` (decloaking in progress)
4. Shields re-enable: `shieldClass+0x9C` is set back to nonzero

### Shield Recharge While Cloaked

Shield recharge effectively **STOPS** while cloaked because:

1. The `+0x9C` (isEnabled) flag is set to 0
2. Shield absorption checks test `+0x9C != 0` before absorbing damage
3. The BoostShield function at FUN_0056a420 depends on `property+0x48` (current power)
4. The `FUN_0056c350` (subsystem fully destroyed check) is used as a guard in the shield code

The CloakingSubsystem ShieldDelay (default 1.0 second) controls how long after engaging cloak before shields drop. This creates the classic Trek mechanic: there's a brief window where a ship is cloaking but still has shields.

**Note**: `CloakingSubsystem.SetShieldDelay(n)` modifies the global at `DAT_008e4e20` (0x008e4e20), affecting ALL cloaking subsystems. The default and initial value is `1.0f`.

## Gate Conditions Summary

| Condition | Where Checked | Effect |
|-----------|--------------|--------|
| `shieldClass == NULL` | FUN_00593c10 | No shield subsystem -> all damage to hull |
| `shieldClass+0x9C == 0` | FUN_00593c10, FUN_0056a620 | Shields disabled (cloak) -> all damage to hull |
| `FUN_0056c350() == true` | FUN_00593c10, FUN_00485360 | Shield subsystem destroyed -> shields down |
| `handler+0x20+0x18 == 0` | FUN_004b1ff0 | Per-handler shield zone inactive -> skip shield test |
| `curShields[facing] == 0` | FUN_0056a620 (IsShieldBreached) | Individual facing depleted |
| `property+0x48 <= 0` | FUN_0056a420 (BoostShield) | No power -> no recharge |

## Verified Constants

| Address | Hex | Float | Meaning |
|---------|-----|-------|---------|
| 0x0088bacc | 0x3E2AAAAB | 1/6 (0.16667) | Per-facing share (6 facings) |
| 0x00888b54 | 0x00000000 | 0.0 | Zero constant (floor) |
| 0x00888860 | 0x3F800000 | 1.0 | One constant |
| 0x008887a8 | 0x3F000000 | 0.5 | Half constant (weapon damage radius scale) |
| 0x008e4e20 | 0x3F800000 | 1.0 | CloakingSubsystem ShieldDelay (seconds) |
| 0x008e4e1c | 0x40A00000 | 5.0 | Cloak rate |
| 0x00892fc0 | 0x3EA8F5C3 | 0.33 | Random phase scale for shield tick stagger |
| 0x00888b58 | 0x358637BD | ~1e-6 | Epsilon (near-zero threshold) |

## Key Function Reference

| Address | Name | Purpose |
|---------|------|---------|
| 0x0056a000 | ShieldClass::ctor | Constructor, initializes 6 facings at 1000 HP each |
| 0x0056a190 | ShieldClass::dtor | Destructor |
| 0x0056a1f0 | RegisterShieldEvents | Registers HandleSetShieldState handler |
| 0x0056a420 | BoostShield | Per-facing power-to-HP conversion, returns overflow |
| 0x0056a540 | GetShieldPercentage | Returns min(curHP/maxHP) across all 6 facings |
| 0x0056a5c0 | SetCurShields | Sets curShields[facing], clamped to [0, max] |
| 0x0056a620 | IsShieldBreached | Checks if specific facing is depleted |
| 0x0056a670 | IsAnyShieldBreached | Checks all 6 facings for breach |
| 0x0056a690 | GetShieldFacingFromRay | Ray-ellipsoid intersection, returns facing index |
| 0x0056a8d0 | NormalToFacing | Converts ship-local normal to ShieldFacing enum |
| 0x0056a9c0 | RedistributeShields | (unanalyzed) Redistributes HP between facings |
| 0x0056aae0 | HandleSetShieldState | Event handler: shield recharge tick (calls BoostShield) |
| 0x0056acc0 | AreAllWatchersTriggered | Checks if all shield watcher thresholds exceeded |
| 0x0056ae10 | ShieldClass::ReadStream | Network deserialization (reads 6 maxShield values) |
| 0x0056b960 | GetCurrentPower | Returns property+0x40 |
| 0x0056b970 | ShieldProperty::ctor | Constructor with vtable 0x00892fc4 |
| 0x0056bc50 | SetPower | Sets power level, triggers event scheduling |
| 0x0056bde0 | ScheduleShieldEvents | Creates periodic timer events (0x6d-0x71) |
| 0x0056c310 | GetMaxHP | Returns property+0x20 |
| 0x0056c350 | IsSubsystemDestroyed | Recursive check if subsystem is non-functional |
| 0x0056c470 | SetCurrentHP | Sets current HP, updates ratio, fires events |
| 0x004b1ff0 | DamageHandler_Process | Per-handler: shield intersection + hull AABB test |
| 0x004b4b40 | ShieldZone_Intersect | Shield zone geometry intersection test |
| 0x004b8e80 | ShieldZone_LookupFacing | Looks up facing from shield zone's node list |
| 0x004bd9f0 | HullAABB_Overlap | AABB overlap test for hull/subsystem damage |
| 0x00593c10 | AreaEffectDamage | Environmental/explosion with explicit per-facing absorption |
| 0x005af010 | WeaponHitHandler | Checks shield absorption flag, calls effects + DoDamage |
| 0x0055f110 | CloakShieldHandler | Enables/disables shields during cloak state changes |

## Dedicated Server Implications

1. **Shield HP is authoritative on the server**: curShields[6] at shieldClass+0xA8 is the ground truth
2. **Shield recharge requires the event system**: The HandleSetShieldState event handler must fire for recharge to work. If the PoweredSubsystem doesn't get power, shields won't recharge.
3. **Area-effect damage bypass**: FUN_00593c10 directly calls SetCurShields, so shields are always correctly decremented for AOE damage regardless of event system state
4. **Cloaking shield delay is a GLOBAL**: Modifying ShieldDelay via SWIG changes the value for ALL ships (DAT_008e4e20 at 0x008e4e20)
5. **StateUpdate serialization**: Shield facing HP is serialized via the subsystem linked list at ship+0x284 (separate from the damage handler array at ship+0x128)
