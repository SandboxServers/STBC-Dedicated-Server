# Bridge Commander Damage System

Reverse-engineered from stbc.exe via Ghidra decompilation and runtime function tracing (stock dedi observer build). High confidence — all addresses verified against live game behavior.

## Call Graph Overview

```
COLLISION INPUT:
  CollisionDamageWrapper (0x005B0060)
    ├─> visual/shield effect (0x005AFD70)
    └─> DoDamage_FromPosition (0x00593650) ─┐
                                              ├─> DoDamage (0x00594020)
  DoDamage_CollisionContacts (0x005952D0) ──┘     │
    └─> loops over contact points, calls DoDamage  │
                                                    │
WEAPON INPUT:                                       │
  WeaponHitHandler (0x005AF010)                     │
    ├─> shield visual (0x005AF160)                  │
    └─> ApplyWeaponDamage (0x005AF420) ─────────────┘
          (damage * 2.0, radius * 0.5)

EXPLOSION INPUT (network opcode 0x29):
  Explosion_Net (0x006A0080)
    └─> reads objectID, decompresses position
    └─> calls ProcessDamage directly (skips DoDamage)

ALL DAMAGE FLOWS THROUGH:
  DoDamage (0x00594020)
    ├─ GATE: this+0x18 (NiNode) must be non-NULL
    ├─ GATE: this+0x140 (damage target ref) must be non-NULL
    ├─ creates DamageVolume (0x38 bytes)
    │   - transforms hit direction: world → source local → target local
    │   - builds AABB from center + radius
    └─> ProcessDamage (0x00593E50)

  ProcessDamage (0x00593E50)
    ├─ scale damage by this+0x1B8 (resistance multiplier)
    ├─ scale falloff by this+0x1BC (falloff multiplier)
    ├─ SUBSYSTEM LOOP: this+0x128 (handler array), this+0x130 (count)
    │   └─ per handler (FUN_004b1ff0):
    │       ├─ shield path: handler+0x20 → FUN_004b4b40 (shield intersection)
    │       └─ hull path: handler+0x1C → FUN_004bd9f0 (AABB overlap test)
    ├─ hull damage: this+0x13C → FUN_00593ee0
    └─ damage notification: FUN_00593f30
        └─ CLIENT ONLY (gated on IsHost==0 at 0x0097FA89)
        └─ creates callback at 0x005927E0 → DamageTickUpdate (0x00592960)

DESTRUCTION (network opcode 0x14):
  DestroyObject_Net (0x006A01E0)
    └─ reads objectID from stream
    └─ looks up object (FUN_00434e00, type 0x8003)
    └─ if ship (type 0x8006): vtable[0x138](1,0) = mark dead/hide
    └─ vtable[0](1) = destructor with cleanup
```

## Function Reference

### DoDamage (0x00594020)
- **Convention**: `__thiscall(ECX=ship, float* hitDir, float damage, DWORD radius)`
- **Stack cleanup**: `RET 0x0C` (callee cleans 3 params)
- Central damage dispatcher. ALL damage flows through here.
- **Gate checks** (damage silently dropped if either fails):
  - `this+0x18` (NiNode) must be non-NULL — ship must have a loaded model
  - `this+0x140` (damage target reference) must be non-NULL
- Creates a DamageVolume (0x38 bytes) via `FUN_004bbde0`:
  - Transforms hit direction from world space → source model local → target model local
  - Uses NiNode bounding sphere radius (`node+0x94`) for scaling
  - Uses rotation matrix at `node+0x64` (3x3) for coordinate transforms
  - Builds AABB (axis-aligned bounding box) from center point + radius
- Calls ProcessDamage with the DamageVolume

### ProcessDamage (0x00593E50)
- **Convention**: `__thiscall(ECX=ship, DamageVolume* dmgVol)`
- **Stack cleanup**: `RET 0x04`
- Distributes damage from the DamageVolume to subsystems and hull.
- **Resistance scaling** (per-ship multipliers):
  - `this+0x1B8`: damage radius multiplier (1.0 = normal, 0.0 = immune)
  - `this+0x1BC`: damage falloff multiplier
- **Subsystem damage loop**:
  - Array at `this+0x128`, count at `this+0x130`
  - **This is a SEPARATE structure from the subsystem linked list at `this+0x284`**
  - Per handler (`FUN_004b1ff0`):
    - Shield check: `handler+0x20` → if `+0x18` flag set, `FUN_004b4b40` (shield intersection)
    - Hull/component check: `handler+0x1C` → if flags `+0x08` or `+0x09` set, `FUN_004bd9f0` (AABB overlap)
  - AABB overlap test checks all 6 planes of the damage volume vs subsystem bounding box
- **Hull damage**: forwarded via `this+0x13C` → `FUN_00593ee0`
- **Notification**: `FUN_00593f30` — **CLIENT ONLY** (gated on `DAT_0097fa89 == 0`)
  - On server (IsHost=1), damage still applied but no event callback fires
  - On client (IsHost=0), creates notification object with callback at `0x005927E0`

### DoDamage_FromPosition (0x00593650) — Collision Caller 1
- **Convention**: `__thiscall(ECX=ship, NiNode* collider, float damage, DWORD radius)`
- **Stack cleanup**: `RET 0x0C`
- Single-point collision damage. Computes hit direction from the difference between the two objects' world positions, transforms to local coordinates, calls DoDamage.
- Called by `CollisionDamageWrapper` (0x005B0060)

### DoDamage_CollisionContacts (0x005952D0) — Collision Caller 2
- **Convention**: `__thiscall(ECX=ship, CollisionResult* contacts)`
- **Stack cleanup**: `RET 0x04`
- Multi-contact-point collision damage. Distributes collision energy evenly across contact points.
- **Per-contact damage formula**:
  ```
  raw = (collision.energy / ship.mass) / contact_count
  scaled = raw * DAT_00893f28 + DAT_0088bf28
  damage = min(scaled, 0.5)  ← hard cap at 0.5 per contact
  ```
- Calls DoDamage once per contact point with radius 6000.0 (`0x45BB8000`)
- CollisionResult layout: `+0x38` = contact count, `+0x2C` = contact point array, `+0x40` = total energy

### CollisionDamageWrapper (0x005B0060)
- **Convention**: `__thiscall(ECX=ship, int collider, float amount, float type)`
- **Stack cleanup**: `RET 0x0C`
- Top-level entry point for collision events. Calls visual effect function (0x005AFD70) then DoDamage_FromPosition.

### ApplyWeaponDamage (0x005AF420) — Weapon Path
- **Convention**: `__thiscall(ECX=ship, WeaponHitInfo* hit)`
- **Stack cleanup**: `RET 0x04`
- Only processes phaser (type 0) and torpedo (type 1)
- **Doubles damage** (`hit+0x4C * 2.0`) and **halves radius** (`hit+0x54 * 0.5`)
- WeaponHitInfo layout: `+0x2C` = type, `+0x3C` = direction[3], `+0x4C` = damage, `+0x54` = radius

### DestroyObject_Net (0x006A01E0) — Opcode 0x14
- **Convention**: `__cdecl(void* stream)`, `RET 0x04`
- Reads objectID from network stream, looks up object via `FUN_00434e00` (type 0x8003)
- If object has parent (`obj+0x20`): calls `parent->vtable[0x5C](objectID)`
- If ship (type 0x8006): calls `vtable[0x138](1, 0)` to mark dead/hide
- Then calls `vtable[0](1)` = destructor with full cleanup

### Explosion_Net (0x006A0080) — Opcode 0x29
- **Convention**: `__cdecl(void* stream)`, `RET 0x04`
- Reads objectID, decompresses 3D position, reads damage values
- Looks up target via `FUN_00590a50` (type 0x8007)
- Creates DamageVolume and calls ProcessDamage directly (bypasses DoDamage)

## Ship Object Damage-Related Offsets

| Offset | Type | Description |
|--------|------|-------------|
| `+0x18` | NiNode* | Scene graph root — must be non-NULL for DoDamage to work |
| `+0xD8` | float | Ship mass (used in collision damage formula) |
| `+0x128` | void** | Subsystem damage handler array (for ProcessDamage) |
| `+0x130` | int | Subsystem damage handler count |
| `+0x13C` | void* | Hull damage receiver |
| `+0x140` | NiNode* | Damage target reference node — must be non-NULL for DoDamage |
| `+0x1B8` | float | Damage resistance multiplier (1.0 = normal) |
| `+0x1BC` | float | Damage falloff multiplier (1.0 = normal) |
| `+0x1C4` | void* | Active damage notification handler (if non-NULL, one already pending) |
| `+0x280` | int | Subsystem count (linked list, separate from +0x128 array) |
| `+0x284` | void* | Subsystem linked list HEAD (for state updates, separate from +0x128) |

## Conditions That Disable Damage

| Condition | Location | Effect |
|-----------|----------|--------|
| `this+0x18 == NULL` | DoDamage gate | No NiNode → ALL damage silently dropped |
| `this+0x140 == NULL` | DoDamage gate | No damage target → ALL damage silently dropped |
| `this+0x128 == NULL` or `+0x130 == 0` | ProcessDamage | No subsystem handlers → subsystem damage loop is a no-op |
| `this+0x13C == NULL` | ProcessDamage | No hull receiver → hull damage skipped |
| `this+0x1B8 == 0.0` | ProcessDamage | Damage radius zeroed → effectively immune |
| `this+0x1BC == 0.0` | ProcessDamage | Damage falloff zeroed → effectively immune |
| Shield active (`handler+0x20+0x18 != 0`) | Per-subsystem handler | Shields absorb damage before hull |
| Hull damage flags (`+0x08`, `+0x09`) both zero | AABB handler | Subsystem won't take damage |
| `DAT_0097fa89 == 1` (IsHost) | Notification callback | Damage applied but NO event callback fires (by design) |
| `DAT_008e5c1c == 0` | Notification callback | Global damage events disabled |

## Dedicated Server Implications

### What Must Be Set for Damage to Work
1. **`ship+0x18` (NiNode)**: Our DeferredInitObject creates ships with NIF models, so this is set. Verified working for collision damage.
2. **`ship+0x140` (damage target)**: Must verify this is populated by DeferredInitObject. If NULL, all damage is silently dropped with no error or log message.
3. **`ship+0x128`/`+0x130` (subsystem damage handler array)**: This is a DIFFERENT structure from the subsystem linked list at `+0x284`. The `+0x284` list is for state serialization; the `+0x128` array is for damage distribution. Both must be populated.
4. **`ship+0xD8` (mass)**: Used in collision damage formula. If zero, division by zero.
5. **`ship+0x1B8` and `+0x1BC` (resistance/falloff)**: Should be 1.0 for normal damage. If our ship creation leaves these as 0.0, the ship is effectively invulnerable.

### Damage Notification is Client-Only (By Design)
The damage event callback at `FUN_00593f30` is gated on `IsHost == 0`. This means on the dedicated server (IsHost=1), damage is applied to subsystem health values but no notification callback fires. This is normal stock behavior — the server silently applies damage, clients get visual/audio feedback.

## Stock Dedi Trace Data (Baseline)

### Session 1: Solo Asteroid Ramming (1 player, ~60s)

Sovereign ramming asteroids at 100% and 125% speed, then switching to Nebula:

```
Ship 1 (Sovereign): Ship_AddSubsystem x33 (from 0x005B4E3D)
Ship 2 (Nebula):    Ship_AddSubsystem x31 (from 0x005B4E3D)

DoDamage callers:
  0x005936E5 (inside DoDamage_FromPosition) — single-point collision
  0x005953E1 (inside DoDamage_CollisionContacts) — multi-contact collision

ProcessDamage callers:
  0x0059418F (inside DoDamage) — all ProcessDamage calls originate from DoDamage
```

### Session 2: Multi-Player Combat (3 players, ~15 min, 11 ship spawns)

Full combat session with weapons fire, collisions, and ship destructions/respawns.

**Verified caller chains (return addresses):**
```
Physics tick loop:
  0x005857FF → CheckCollision (79,605 calls)

Collision damage path:
  0x00608DF2 → CollisionDamageWrapper (107 calls)
  CollisionDamageWrapper (0x005B0093) → DoDamage_FromPosition (107, 1:1)
  0x005952BE → DoDamage_CollisionContacts (122 calls)

Weapon damage path:
  InvokeHandler (0x006E0D05) → WeaponHitHandler (1,939 calls)
  WeaponHitHandler (0x005AF145) → ApplyHullDamage (536 calls, 28% pass shields)
  ApplyHullDamage (0x005AF44F) → DoDamage (536)

Central damage:
  DoDamage total: 765 = 536 weapon + 122 collision_contacts + 107 collision_position
  DoDamage (0x0059418F) → ProcessDamage (765, always 1:1)

Ship creation:
  0x0069F33E → MPG_ObjectProcessor (11 calls)
  MPG_ObjectProcessor (0x0069F6B4) → ObjectFactory (11, always 1:1)
  ObjectFactory (0x005A1FDE) → TypeFactory (11 of 2498 total)
  0x005B4E3D → Ship_AddSubsystem (331 total, sole caller)
```

**Key ratios (high confidence):**
- Collision check → actual damage: **0.3%** (79,605 checks → 229 damage events)
- Weapon hit → shield penetration: **28%** (1,939 hits → 536 pass shields)
- All DoDamage calls produce exactly 1 ProcessDamage call (1:1, no filtering between them)

**Per-ship subsystem counts (empirical, 11 ships):**
24, 26, 29, 31, 31, 33, 34, 34 observed — varies by ship class, always from single caller 0x005B4E3D.

**Ship lifecycle (11 ObjectFactory calls for ~3 players):**
Ships are destroyed and respawned as entirely new objects through the same ObjectFactory path. No special respawn function exists — it's destroy + create new.

**Functions that NEVER fire on the host (by design):**
- `Ship_WriteStream` (0x0057A280) — not part of network path, only disk serialization
- `DestroyObject_Net` (0x006A01E0) — host SENDS opcode 0x14, doesn't receive it
- `Explosion_Net` (0x006A0080) — host SENDS opcode 0x29, doesn't receive it
- `CreateNetworkEvent` (0x006A1360) — not used during gameplay
- `FindNetObjByID` (0x006A19FC) — not used during gameplay
- `FireEvent` fires exactly **once** per session (game start), then never again

**Functions that fire rarely on the host:**
- `SendNetworkObject`: 2 calls total (object registration at join)
- `GetPlayerSlot`: 5 calls (during player join flow)
- `FindPlayerByNetID`: 6 calls (during player join flow)

## Upstream Caller Addresses (Not Hooked)

These addresses call into our hooked functions but are not themselves hooked. Important for understanding the full chain:

| Address | Calls | Context |
|---------|-------|---------|
| `0x005857FF` | CheckCollision | Physics tick — collision detection loop |
| `0x00608DF2` | CollisionDamageWrapper | Physics collision response handler |
| `0x005952BE` | DoDamage_CollisionContacts | Collision contact processor wrapper |
| `0x005B4E3D` | Ship_AddSubsystem | Inside SetupProperties (sole subsystem creator) |
| `0x0069F33E` | MPG_ObjectProcessor | MultiplayerGame message dispatcher |
| `0x006E0D05` | WeaponHitHandler | InvokeHandler (event system dispatch) |
