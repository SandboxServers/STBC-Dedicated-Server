# Combat Mechanics — Consolidated Reverse Engineering

Comprehensive RE analysis of Bridge Commander's combat systems. All findings verified against the stbc.exe binary via Ghidra decompilation, raw disassembly (objdump), and cross-referenced against shipped hardpoint scripts and live packet traces.

This document consolidates findings from:
- [damage-system.md](damage-system.md) — Damage pipeline, DoDamage/ProcessDamage
- [shield-system.md](shield-system.md) — Shield facing, absorption, recharge
- [cloaking-state-machine.md](cloaking-state-machine.md) — Cloak state machine, shield/weapon interactions
- [weapon-firing-mechanics.md](weapon-firing-mechanics.md) — Phaser charge, torpedo reload, fire gates
- [repair-tractor-analysis.md](repair-tractor-analysis.md) — Repair queue, tractor beam drag

---

## 1. Damage Pipeline

### Entry Points

| Path | Entry Function | Address |
|------|---------------|---------|
| Collision (single-point) | CollisionDamageWrapper → DoDamage_FromPosition | 0x005B0060 → 0x00593650 |
| Collision (multi-contact) | DoDamage_CollisionContacts | 0x005952D0 |
| Weapon hit | WeaponHitHandler → ApplyWeaponDamage | 0x005AF010 → 0x005AF420 |
| Explosion (opcode 0x29) | Explosion_Net → ProcessDamage (direct) | 0x006A0080 |

All paths converge at **DoDamage** (0x00594020) → **ProcessDamage** (0x00593E50), except Explosion which bypasses DoDamage and calls ProcessDamage directly.

### Gate Conditions (DoDamage)

| Gate | Offset | Condition | Effect if NULL |
|------|--------|-----------|----------------|
| Scene graph | ship+0x18 | NiNode* must be non-NULL | ALL damage silently dropped |
| Damage target | ship+0x140 | Reference must be non-NULL | ALL damage silently dropped |

### Collision Damage Formula (DoDamage_CollisionContacts)

```
raw = (collision.energy / ship.mass) / contact_count
scaled = raw * DAT_00893f28 + DAT_0088bf28
damage = min(scaled, 0.5)    // hard cap at 0.5 per contact
radius = 6000.0              // fixed (0x45BB8000)
```

### Weapon Damage Scaling (ApplyWeaponDamage)

- Damage is **doubled**: `hit.damage * 2.0`
- Radius is **halved**: `hit.radius * 0.5`
- Only processes phaser (type 0) and torpedo (type 1)

### Resistance Scaling (ProcessDamage)

| Offset | Type | Effect |
|--------|------|--------|
| ship+0x1B8 | float | Damage radius multiplier (1.0 = normal, 0.0 = immune) |
| ship+0x1BC | float | Damage falloff multiplier (1.0 = normal) |

### Subsystem Damage Distribution

ProcessDamage iterates the **handler array** at ship+0x128 (count at ship+0x130). This is a SEPARATE structure from the subsystem linked list at ship+0x284.

Per handler (FUN_004b1ff0):
- **Shield path**: handler+0x20 → zone+0x18 flag → FUN_004b4b40 (shield geometry intersection)
- **Hull path**: handler+0x1C → flags +0x08/+0x09 → FUN_004bd9f0 (**AABB overlap test**, NOT distance-based)

**Important correction**: Subsystem damage uses AABB (axis-aligned bounding box) overlap testing, NOT Euclidean distance to the nearest subsystem. There is no "50% overflow" mechanic.

### Damage Notification

FUN_00593f30 — **CLIENT ONLY** (gated on IsHost==0 at 0x0097FA89). Server applies damage silently; clients get visual/audio feedback.

---

## 2. Shield System

### 6 Shield Facings

| Index | Facing | Ship-Local Axis |
|-------|--------|-----------------|
| 0 | FRONT | +Y (forward) |
| 1 | REAR | -Y (aft) |
| 2 | TOP | +Z (up) |
| 3 | BOTTOM | -Z (down) |
| 4 | LEFT | -X (port) |
| 5 | RIGHT | +X (starboard) |

### Facing Determination (FUN_0056a8d0)

**Algorithm**: Maximum component projection (NOT dot products).

1. Rearrange impact normal {X,Y,Z} to {Y,Z,X}
2. Find maximum positive value among {+Y,+Z,+X} (indices 0-2)
3. Find maximum negated value among {-Y,-Z,-X} (indices 3-5)
4. Dominant axis → facing via switch table

This is an axis-aligned maximum component test (equivalent to finding dominant face of a cube enclosing the unit normal). Computationally cheap — no trig, no dot products, just comparisons.

Full ray-to-facing path (FUN_0056a690) uses ray-ellipsoid intersection:
1. Transform ray to shield ellipsoid's local space
2. Normalize by semi-axes (NiNode+0x24C/0x250/0x254)
3. Ray-unit-sphere intersection (FUN_004570d0)
4. Compute outward normal at hit point
5. Pass normal to NormalToFacing

### Shield Data Layout

- **Current HP per facing**: shieldClass+0xA8 (float[6])
- **Max HP per facing**: shieldProperty+0x60 (float[6])
- **Charge per second per facing**: shieldProperty+0x78 (float[6])
- **Shield enabled flag**: shieldClass+0x9C (byte, 0=disabled during cloak)

### Shield Absorption

**Two distinct paths**:

#### Area-Effect Damage (FUN_00593c10)
Distributes damage equally across all 6 facings:
```
damagePerFacing = totalDamage * (1/6)    // DAT_0088bacc = 0.16667

For each facing (0..5):
    absorption = min(damagePerFacing, curShields[facing])
    curShields[facing] -= absorption
    totalAbsorbed += absorption

overflowToHull = totalDamage - totalAbsorbed
```

NOT all-or-nothing. Each facing independently absorbs its share. A ship with 5 full facings and 1 depleted absorbs 5/6 of damage; 1/6 goes to hull.

#### Directed Damage (via ProcessDamage)
Uses geometry intersection against shield ellipsoid mesh. The weapon hit handler checks `weaponHitInfo+0x58`:
- `== 0`: Shield absorbed the hit (visual effect, no hull damage)
- `!= 0`: Shield breached (hull hit + DoDamage applied)

### Shield Recharge (FUN_0056a420 — BoostShield)

```c
float normalizedPower = property->currentPower * (1.0/6.0);
float hpGain = (chargePerSecond[facing] * powerBudget) / normalizedPower;
curShields[facing] += hpGain;
// Overflow returned for redistribution to other facings
```

**Key**: `powerBudget` is NOT frame time — it is an energy budget from the PoweredSubsystem allocation. Recharge runs through the event system (events 0x0080006d-0x00800071), NOT a direct per-tick call.

### Sovereign Shield HP (from sovereign.py hardpoint script)

| Facing | Max HP | Charge/sec |
|--------|--------|------------|
| Front | 11,000 | 12.0 |
| Rear | 5,500 | 12.0 |
| Top | 11,000 | 12.0 |
| Bottom | 11,000 | 12.0 |
| Left | 5,500 | 12.0 |
| Right | 5,500 | 12.0 |

Shield Generator MaxCondition: 10,000.

---

## 3. Cloaking Device

### State Machine (4 active states)

| Value | State | Timer Behavior |
|-------|-------|----------------|
| 0 | DECLOAKED | — |
| 2 | CLOAKING | Timer counts UP by dt |
| 3 | CLOAKED | — |
| 5 | DECLOAKING | Timer counts DOWN by dt |

**Ghost states 1 and 4** are checked in IsCloaking/IsDecloaking but NEVER written. Dead code from a planned 6-state design.

### Transition Flow

```
DECLOAKED(0) → CLOAKING(2) → CLOAKED(3) → DECLOAKING(5) → DECLOAKED(0)
```

Energy failure auto-decloak: if efficiency < DAT_0088d4ec while CLOAKED, forces DECLOAKING.

### Key Globals

| Address | Type | Name |
|---------|------|------|
| 0x008e4e1c | float | CloakTime (transition duration, class-level global) |
| 0x008e4e20 | float | ShieldDelay (1.0s default, class-level global) |

### Tick Function (FUN_0055e500)

- CLOAKING: `timer += dt`, `progress = timer / CloakTime`, at 1.0 → CloakComplete (state=3)
- DECLOAKING: `timer -= dt`, `progress = timer / CloakTime`, at 0.0 → DecloakComplete (state=0)

### Shield Interaction

**Shields do NOT immediately drop to 0 HP when cloaking.**

1. On cloak start: shields are **functionally disabled** via PoweredSubsystem (shieldClass+0x9C=0). HP is PRESERVED.
2. A delayed event fires after ShieldDelay (1.0s default) to hide shield visuals.
3. On decloak complete: shields re-enable after another ShieldDelay delay.
4. If shield HP was <=0 during cloak, reset to 1.0 HP on decloak.

### Weapon Interaction

Weapons are NOT directly gated by cloak state in C++ weapon code. The gating happens through:
1. **Subsystem disable mechanism**: Cloaking calls PoweredSubsystem::Disable on weapon systems
2. **AI/Python layer**: Scripts check `ShipClass.IsCloaked()` before initiating fire
3. **IsCloaked** (FUN_005ac450): returns true ONLY when state==3, NOT during transitions

### Network Serialization

StateUpdate flag 0x40 serializes `isOn` byte (+0x9C), NOT the state machine value. Client receives boolean and runs its own local state machine.

### Object Layout

| Offset | Type | Field |
|--------|------|-------|
| +0x9C | byte | isOn (PoweredSubsystem enable) |
| +0xAC | byte | isFullyCloaked (true only in state 3) |
| +0xAD | byte | tryingToCloak (user intent) |
| +0xB0 | int | state (0/2/3/5) |
| +0xB4 | float | timer |

Ship stores CloakingSubsystem at **ship+0x2DC**.

---

## 4. Weapon Systems

### Class Hierarchy

```
Weapon (vtable 0x00892FC4)
  → EnergyWeapon (vtable 0x008930D8, size ~0xC8)
    → PhaserBank (vtable 0x00893194, size 0x128)
  → TorpedoTube (vtable 0x00893630, size 0xB0)
```

### Phaser Charge Formula (FUN_00572B80)

**Recharging** (not firing):
```
charge += recharge_rate * power_level * dt * power_multiplier
// Non-owner ships: *= DAT_00890550 (AI/remote penalty)
// Clamped to max_charge
```

**Discharging** (firing at intensity HIGH or mode 3):
```
charge -= discharge_rate * dt
// If charge <= 0: stop firing
```

Discharge rate varies by intensity mode:

| Mode | Constant |
|------|----------|
| LOW (0) | DAT_0089317C |
| MED (1) | DAT_00893180 |
| HIGH (2) | DAT_00893184 |

### Phaser CanFire Gate Conditions

1. Ship is alive (FUN_00562210 checks class type 0x801C)
2. Subsystem is alive — HP > 0 (FUN_0056c350 recursive check)
3. Subsystem not disabled (DisabledPercentage threshold)
4. Charge >= MinFiringCharge (property+0x74 vs charge at +0xA0)
5. Weapon can-fire flag (property+0x48)
6. Not cloaked (system-level: ET_START_CLOAKING disables weapon systems)

### Phaser EnergyWeaponProperty Offsets

| Offset | Field | Sovereign Default |
|--------|-------|-------------------|
| +0x68 | MaxCharge | 5.0 |
| +0x6C | RechargeRate | 0.08 |
| +0x70 | NormalDischargeRate | 1.0 |
| +0x74 | MinFiringCharge | 3.0 |
| +0x78 | MaxDamage | 300.0 |
| +0x7C | MaxDamageDistance | 70.0 |

### Torpedo Cooldown

Each tube has independent reload timers at +0xAC (float array, one per max_ready slot):
- `-1.0f` = loaded/ready
- `0.0f` = cooldown just started
- `> 0.0f` = cooling down

**ReloadTorpedo** (FUN_0057D8A0): checks num_ready < max_ready AND ammo available, increments num_ready, finds slot with longest timer and resets to -1.0f.

**Fire** (FUN_0057C9E0): calls CanFire, creates projectile, decrements num_ready, marks a timer slot as 0.0f, sends opcode 0x19 if host.

### Torpedo Type Switch (FUN_0057B230)

**No explicit lockout timer.** The "lockout" is implicit:

1. `SetAmmoType(type, immediate=1)` (multiplayer path): unloads all tubes, clears all timers, does NOT reload
2. Tubes must go through normal reload cycle from empty
3. Effective lockout = ReloadDelay (40.0s for Sovereign)
4. `SetAmmoType(type, immediate=0)` (local path): unloads + immediately reloads = no lockout

### Torpedo Wire Format (Opcode 0x19)

```
[0x19] [int32:weapon_obj_id] [byte:torpedo_model_idx] [byte:flags]
[compressed_vec3:velocity] [if has_target: int32 target_id] [compressed_vec4:target_offset]
```

---

## 5. Repair System

### RepairSubsystem Layout

| Offset | Type | Field |
|--------|------|-------|
| +0x9C | byte | isOn |
| +0xA8 | int | queue count |
| +0xAC | ptr | queue head (linked list) |
| +0xB0 | ptr | queue tail |

Property: +0x4C = MaxRepairPoints (float), +0x50 = NumRepairTeams (int).

### Repair Rate Formula (FUN_005652a0 — VERIFIED)

```
rawRepairAmount = MaxRepairPoints * repairSystem.conditionPct * deltaTime
divisor = min(queueCount, NumRepairTeams)
perSubsystemRepair = rawRepairAmount / divisor
actualConditionGain = perSubsystemRepair / subsystem.RepairComplexity
```

**Key characteristics**:
1. Repair system's OWN health scales output (damaged repair bay = slower)
2. **Multiple subsystems repaired simultaneously** (up to NumRepairTeams)
3. Repair amount divided equally among min(queueCount, numTeams) items
4. RepairComplexity is a final divisor (higher = slower)
5. Destroyed subsystems (condition <= 0) are SKIPPED (post ET_REPAIR_CANNOT_BE_COMPLETED)

### Queue Rules

- **No maximum queue size** — dynamically growing linked list, no hardcoded limit
- **Duplicates rejected** — walks list to check before adding
- **0 HP subsystems excluded** — explicit `condition > 0.0f` check in AddSubsystem
- **Auto-remove on full repair** — ET_REPAIR_COMPLETED when condition/maxCondition >= 1.0
- **Host/standalone only** — gated on IsHost or not-multiplayer

### Sovereign Repair Values

- MaxRepairPoints: 50.0
- NumRepairTeams: 3
- Repair subsystem MaxCondition: 8,000

---

## 6. Tractor Beam

### Class Hierarchy

```
WeaponSystem → TractorBeamSystem (vtable 0x00893794, size 0x100)
EnergyWeapon → TractorBeamProjector (vtable 0x008936f0, size 0x100)
```

### 6 Tractor Modes

| Value | Mode | Behavior |
|-------|------|----------|
| 0 | HOLD | Zero target velocity |
| 1 | TOW | Move target toward source (default) |
| 2 | PULL | Pull target closer |
| 3 | PUSH | Push target away |
| 4 | DOCK_STAGE_1 | Docking approach |
| 5 | DOCK_STAGE_2 | Final docking alignment |

### Tractor Force Formula (FUN_00580f50)

```c
distanceRatio = min(1.0, maxDamageDistance / beamDistance);
force = maxDamage * (systemCondPct * projectorCondPct) * distanceRatio;
if (targetTracker != NULL) force *= targetCondition;
return force * deltaTime;
```

Features NOT in OpenBC spec:
- **Distance falloff**: linear beyond maxDamageDistance
- **Health scaling**: both system and projector condition affect force
- **Target condition** scaling (optional)

### Speed Drag (ImpulseEngineSubsystem, FUN_00561230)

**Multiplicative**, not additive:
```
tractorRatio = forceUsed / totalMaxDamage    // from TractorBeamSystem +0xFC / +0xF8
effectiveSpeed *= (1.0 - tractorRatio)
```

At full tractor output, speed drops to zero. At half output, speed is halved. Same ratio applied to acceleration, angular velocity, and angular acceleration.

ImpulseEngine stores TractorBeamSystem pointer at +0xA8.

### Tractor Beam Does NOT Apply Direct Damage

All five mode handlers (HOLD, TOW, PULL, PUSH, DOCK_STAGE_2) only manipulate target velocity/angular velocity. **No damage function is called on the target.**

### Sovereign Tractor Values (from sovereign.py)

- Per-projector MaxDamage: 80.0
- MaxDamageDistance: 114.0
- MaxCharge: 5.0, MinFiringCharge: 3.0
- RechargeRate: 0.3 (aft), 0.5 (forward)
- 4 projectors (2 forward, 2 aft)

---

## 7. Ship Death and Respawn

When hull HP <= 0:
1. Server sends **DestroyObject (0x14)**: `[0x14][object_id:i32]`
2. Server sends **Explosion (0x29)**: `[0x29][object_id:i32][impact:cv4][damage:cf16][radius:cf16]`
3. Ship marked dead via vtable[0x138](1,0)
4. Destructor called via vtable[0](1)

**No dedicated respawn mechanism.** Destroy old object + create new one (ObjCreateTeam 0x03 with fresh HP).

---

## 8. Sovereign Class Reference Values (from sovereign.py)

### Hull
- Hull MaxCondition: **12,000**

### Subsystem HP

| Subsystem | MaxCondition | RepairComplexity |
|-----------|-------------|------------------|
| Shield Generator | 10,000 | — |
| Sensor Array | 8,000 | 1.0 |
| Warp Core (reactor) | 7,000 | 2.0 |
| Impulse Engines (system) | 3,000 | 3.0 |
| Port/Star Impulse (each) | 3,000 | — |
| Torpedo System | 6,000 | — |
| Forward Torpedo (each, x4) | 2,200 | — |
| Aft Torpedo (each, x2) | 2,200 | — |
| Phaser Emitter (each, x8) | 1,000 | — |
| Phaser Controller | 8,000 | — |
| Repair | 8,000 | 1.0 |
| Warp Engines (system) | 8,000 | — |
| Port/Star Warp (each) | 4,500 | — |
| Tractor System | 3,000 | 7.0 |
| Tractor (each, x4) | 1,500 | 7.0 |
| Bridge | 10,000 | 4.0 |
| Hull | 12,000 | 3.0 |

---

## 9. OpenBC Corrections Summary

| OpenBC Claim | Verdict | Actual |
|-------------|---------|--------|
| Cloak states: 0,1,2,3 | **WRONG** | States are 0,2,3,5 (ghost states 1,4 never assigned) |
| Shields drop to 0 on cloak | **WRONG** | HP preserved, subsystem functionally disabled |
| Subsystem damage: 50% overflow to nearest by distance | **WRONG** | AABB overlap test, no distance-based selection, no 50% split |
| Shield absorption: all-or-nothing per facing | **PARTIALLY WRONG** | Area damage splits 1/6 per facing; directed damage uses geometry intersection |
| Shield recharge: rate * dt | **WRONG** | Power-budget based: (chargePerSec * powerBudget) / (totalPower/6) |
| Repair queue max 8 | **WRONG** | No limit — dynamically growing linked list |
| Only top-priority repaired | **WRONG** | Up to NumRepairTeams subsystems repaired simultaneously |
| Repair rate: max_repair_points * num_repair_teams * dt | **WRONG** | MaxRepairPoints * healthPct * dt / min(queueCount,numTeams) / RepairComplexity |
| Tractor drag: max_damage * dt * 0.1 | **WRONG** | Multiplicative: effectiveSpeed *= (1.0 - forceUsed/totalMaxDamage) |
| Tractor damage: max_damage * dt * 0.02 | **NOT FOUND** | No damage applied by any tractor mode |
| Torpedo type switch = explicit lockout timer | **WRONG** | Implicit: all tubes emptied, must reload from scratch |
| Sovereign shield HP: 6,000 uniform | **WRONG** | Front=11,000, Rear=5,500, Top=11,000, Bottom=11,000, Left=5,500, Right=5,500 |
| Sovereign hull HP: 12,011 | **WRONG** | 12,000 |
| Sovereign reactor HP: 12,011 | **WRONG** | Warp Core = 7,000 |
| Sovereign torpedo tube HP: 550 | **WRONG** | 2,200 each |
| Sovereign shield generator HP: 6,000 | **WRONG** | 10,000 |
| Sovereign sensor HP: 1,000 | **WRONG** | 8,000 |
| Phaser charge: recharge_rate * power_level * dt | **MOSTLY CORRECT** | Adds power_multiplier param + AI/remote penalty multiplier |
| Phaser 6 fire gates | **CONFIRMED** | Essentially correct, cloak check at system level not per-CanFire |
| Torpedo per-tube independent cooldown | **CONFIRMED** | Timer array at +0xAC, one per slot |
| 0 HP subsystems not auto-queued | **CONFIRMED** | Explicit condition > 0.0f check |
