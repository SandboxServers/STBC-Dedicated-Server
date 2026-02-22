> [docs](../README.md) / [gameplay](README.md) / collision-shield-interaction.md

# Collision-Shield Interaction

Reverse-engineered from stbc.exe via Ghidra decompilation. High confidence — decompiled from live binary with Ghidra MCP.

**Corrects** an error in `damage-system.md` line 10, which labels `FUN_005afd70` as "visual/shield effect". It is actually the **SubsystemDamageDistributor** — the primary shield absorption and subsystem damage function for both collision and weapon paths.

## Executive Summary

Collision damage does **not** bypass shields. It goes through the same `FUN_005afd70` (SubsystemDamageDistributor) that weapon damage uses, which walks the ship+0x284 subsystem linked list and applies directional damage to shield facings. Shields absorb collision damage per facing, and only the overflow reaches hull and subsystems.

The key difference between damage paths is **where** shields are checked, not **whether** they are:

| Path | Shield Check Location | Type |
|------|----------------------|------|
| **Weapon** | Pre-DoDamage (ray-ellipsoid gate at FUN_0056a690) + inside FUN_005afd70 | Binary gate + per-subsystem |
| **Collision** | Inside FUN_005afd70 only (no pre-gate) | Per-subsystem only |
| **AoE Explosion** | Separate explicit loop (FUN_00593c10, uniform 1/6 per facing) | Area-effect |

## CollisionDamageWrapper (0x005b0060) — Two-Step Process

The collision entry point calls two damage functions **sequentially**, not independently:

```c
void __thiscall CollisionDamageWrapper(void *this, int collider, float energy, float damage)
{
    // STEP 1: Subsystem-level damage (includes shield absorption)
    // damage is modified IN-PLACE — reduced by whatever shields/subsystems absorb
    FUN_005afd70(this, (float*)(collider + 0x88), &damage, energy, NULL, 1);

    // STEP 2: Remaining damage → DamageVolume → ProcessDamage → hull
    DoDamage_FromPosition(this, collider, energy, damage);  // damage is now REDUCED
}
```

**Critical detail**: `FUN_005afd70` takes `&damage` (pointer), not `damage` (value). It modifies the damage amount in place. By the time `DoDamage_FromPosition` runs, the damage has been reduced by whatever shields and subsystems absorbed.

## FUN_005afd70 — SubsystemDamageDistributor (0x005afd70)

This is the **primary shield interaction function** for both collision and weapon damage.

### Signature

```c
void __thiscall FUN_005afd70(
    void *this,         // ship
    float *position,    // damage origin (world-space 3D point)
    float *damage,      // POINTER to damage amount (modified in place!)
    float energy,       // damage radius / energy
    int *source,        // attacker weapon pointer (NULL for collisions)
    int *isCollision    // 0x1=collision, 0x0=weapon (controls power subsystem exclusion)
);
```

### Behavior

1. **Find subsystems in range** via `FUN_005aecc0`:
   - Walks `ship+0x284` linked list (state serialization list)
   - Checks each subsystem's distance from the damage origin point
   - Builds a hit list of subsystems within the energy/radius
   - **Shield facings ARE in this list** — they are regular subsystems

2. **Power subsystem exclusion** (weapon-only):
   ```c
   if (((char)isCollision == '\0') && (hit_count > 1)) {
       // Find and remove power subsystem (ship+0x2C4) from hit list
   }
   ```
   When `isCollision=0` (weapon) and multiple subsystems are hit, the power subsystem is removed from the list. When `isCollision=1` (collision), power subsystem stays in. This is the **only** behavioral difference between collision and weapon paths through this function.

3. **Per-subsystem damage** via `FUN_005af4a0`:
   ```c
   // 5th arg is HARDCODED '\0' regardless of collision/weapon
   overflow = FUN_005af4a0(this, subsystem, *damage, source, '\0');
   total_overflow += overflow;
   ```
   The `param_5` passed to the per-subsystem function is always `'\0'` — collision and weapon damage follow identical logic from this point.

4. **Write remaining damage back**:
   ```c
   *damage = total_overflow;  // reduced amount for DoDamage_FromPosition
   ```

## FUN_005af4a0 — Per-Subsystem Damage (0x005af4a0)

Applies damage to a single subsystem (including shield facings). Returns overflow (damage the subsystem couldn't absorb).

```c
float10 __thiscall FUN_005af4a0(void *ship, void *subsystem, float damage,
                                 int *source, char param_5)
{
    float curHP  = *(float*)(subsystem + 0x30);     // current HP
    float maxHP  = FUN_0056c310(subsystem);          // max HP
    float newHP  = curHP - damage;
    float overflow = 0.0f;

    if (newHP <= 0.0f) {
        overflow = -newHP;      // damage exceeded HP
        // ... destruction checks ...
    }

    // Apply new HP
    FUN_0056c470(ship, newHP);  // SetCondition — clamps, fires SUBSYSTEM_HIT event

    return overflow;
}
```

When the subsystem is a shield facing:
- `subsystem+0x30` is the current shield facing HP
- Damage is subtracted directly from facing HP
- Overflow = damage that wasn't absorbed
- `FUN_0056c470` fires SUBSYSTEM_HIT event (0x0080006B)

## FUN_0056c470 — SetCondition / Shield HP Setter (0x0056c470)

```c
void __thiscall FUN_0056c470(void *this, float newCondition)
{
    *(float*)(this + 0x30) = newCondition;  // set new HP

    // Clamp to max
    float maxHP = FUN_0056c310(this);
    if (*(float*)(this + 0x30) > maxHP)
        *(float*)(this + 0x30) = maxHP;

    // Compute condition ratio
    *(float*)(this + 0x34) = *(float*)(this + 0x30) / maxHP;

    // Fire SUBSYSTEM_HIT event if HP < max AND ship alive
    if (*(float*)(this + 0x30) < maxHP && ship_is_alive) {
        // Create TGCharEvent with eventType = 0x0080006B (SUBSYSTEM_HIT)
        event[4] = 0x0080006B;
        event[10] = *(int*)(this + 0x04);  // subsystem object ID
        FUN_006da2a0(&DAT_0097f838, event);
    }
}
```

## Comparison: Weapon Path

### WeaponHitHandler (FUN_005af010 at 0x005af010)

Weapons have a **pre-gate** that stops most hits before reaching the subsystem distributor:

```
Projectile flight → ray-ellipsoid intersection test (FUN_0056a690)
  → weaponHitInfo+0x58 = 0 (shield absorbed) or != 0 (passed through)

WeaponHitHandler:
  if (hitInfo+0x58 == 0):       // ~72% of hits
      play shield visual
      RETURN                    // DoDamage is NEVER called

  if (hitInfo+0x58 != 0):       // ~28% pass shields
      play hull hit visual
      ApplyWeaponDamage → DoDamage → ProcessDamage
```

After passing this gate, weapon damage ALSO calls `FUN_005afd70` (via `FUN_005af630`), which does the same per-subsystem damage distribution with shield absorption.

### FUN_005af630 — Weapon Subsystem Damage Caller

```c
// isCollision param for weapons:
int *isCollision = (int*)1;  // default
if (weapon_type == 1) {      // torpedo check
    torpedo = FUN_00570b20(weapon);
    if (torpedo != NULL && torpedo[0x2B] == 0) {
        isCollision = (int*)0;  // some torpedoes set to 0 → power subsystem excluded
    }
}
FUN_005afd70(ship, position, &damage, radius, weapon, isCollision);
```

## Comparison: AoE Explosion Path

### FUN_00593c10 — AoE Shield Drain (0x00593c10)

Explosions use a completely different mechanism — an explicit loop over all 6 shield facings with uniform damage distribution:

```c
void* shieldSubsys = ship[0xB0];  // ship+0x2C0 = ShieldClass*
if (shieldSubsys != NULL && shields_enabled && !cloaked) {
    float *shieldHP = (float*)(shieldSubsys + 0xA8);  // curShields[6]
    float perFacing = totalDamage * DAT_0088bacc;      // * 1/6

    for (int i = 0; i < 6; i++) {
        float absorbed = min(perFacing, shieldHP[i]);
        shieldHP[i] -= absorbed;
        FUN_0056a5c0(shieldSubsys, i, shieldHP[i]);  // SetCurShields
        totalAbsorbed += absorbed;
    }
    remainingDamage = totalDamage - totalAbsorbed;
}

if (remainingDamage > 0) {
    FUN_005afd70(ship, pos, &remainingDamage, radius, source, param);
}
```

The AoE path drains shields FIRST (uniformly), THEN passes remaining damage to `FUN_005afd70` for hull/subsystem distribution.

## Summary: Three Damage Paths Through Shields

```
COLLISION:
  CollisionDamageWrapper
    ├─ FUN_005afd70(&damage)     ← shield facings absorb, damage reduced in-place
    └─ DoDamage_FromPosition(damage)  ← gets REDUCED damage
         └─ ProcessDamage              ← handler array (shield geometry + hull AABB)

WEAPON:
  WeaponHitHandler
    ├─ ray-ellipsoid gate        ← 72% stopped here (shield absorbed)
    └─ if passed:
         ├─ FUN_005afd70(&damage) ← same path as collision
         └─ ApplyWeaponDamage
              └─ DoDamage(damage * 2.0, radius * 0.5)
                   └─ ProcessDamage

AoE EXPLOSION:
  FUN_00593c10
    ├─ explicit 6-facing drain   ← uniform 1/6 per facing
    └─ FUN_005afd70(remaining)   ← hull/subsystem damage with reduced amount
```

## Why Collision Damage Often Appears to Bypass Shields

Several factors create the **perception** that collisions bypass shields:

1. **No pre-gate**: Weapons have the ray-ellipsoid test that stops 72% of hits before any damage function runs. Collisions have no such gate — 100% reach the damage path. This makes collision damage feel more impactful.

2. **Power subsystem stays in hit list**: Collisions with `isCollision=1` do NOT exclude the power subsystem, so collision damage can hit the warp core directly. Weapons exclude it (when `isCollision=0` and multiple subsystems hit).

3. **Multiple contact points**: Multi-contact collisions (`DoDamage_CollisionContacts`) apply damage once per contact point, each going through shield absorption independently. This can overwhelm a single shield facing faster than a single weapon hit.

4. **Stock trace ratios**: In a 15-minute stock combat session:
   - 79,605 collision checks → 229 actual damage events (0.3% trigger rate)
   - 1,939 weapon hits → 536 pass shields (28% pass rate)
   - All 229 collision damage events reach DoDamage (100%)
   - Only 536/1939 weapon hits reach DoDamage (28%)

## Implications for OpenBC

The OpenBC `bc_combat_apply_damage` function currently uses `area_effect=true` for collision damage, which applies `damage/6` uniformly across all 6 shield facings. This is **incorrect** — it matches the AoE explosion path (`FUN_00593c10`), not the collision path.

The stock collision path does **directional** shield absorption via `FUN_005afd70`, which finds subsystems (including shield facings) within range of the collision point and absorbs damage per facing based on spatial proximity. This means:

- A head-on collision drains **front shields** primarily, not all 6 facings equally
- Front shields can be depleted by collision while other facings remain full
- Once front shields are depleted, overflow hits hull + subsystems immediately

OpenBC should switch collision damage from area-effect to directed shield absorption.
