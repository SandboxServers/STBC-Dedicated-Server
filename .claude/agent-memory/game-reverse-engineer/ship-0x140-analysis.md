# Ship+0x140 Analysis (DamageableObject damage target node)

## What is ship+0x140?
- **An NiNode pointer** used as the "damage target" geometry node for hit-point coordinate transforms
- Set by `FUN_00591b60` (DamageableObject::SetModelName / vtable[0x128])
- In `DoDamage` (FUN_00594020): used to convert damage impact position from world coords to local model coords
  - Reads +0x94 (world scale), +0x88/+0x8c/+0x90 (world translation), +0x64 (rotation matrix)
- **Gate check in DoDamage**: `if (ship+0x18 == NULL || ship+0x140 == NULL) return;` -- ALL damage silently dropped

## What is ship+0x128/+0x130?
- **+0x128** = pointer to an array of damage handler objects (SubsystemDamageHandler*)
- **+0x130** = count of handlers in that array
- Populated by `FUN_00451ac0` (called from FUN_00591b60's successful path)
- Used in `ProcessDamage` (FUN_00593e50): iterates array to distribute damage to subsystem handlers
- +0x124 is the managed array header (vtable + metadata), +0x128 is the raw data pointer

## Key function: FUN_00591b60 (SetModelName)
- Called from: DamageableObject constructors, vtable[0x128], and FUN_005abda8
- Takes: `(this, byte* modelName)`
- Stores model name at `this+0x108`
- **Two code paths based on DAT_00980798 (model property registry) lookup:**

### Path 1: Registry lookup SUCCEEDS (FUN_004526d0 returns non-NULL)
- Calls FUN_00451ac0 to load LOD model, populate +0x10c/+0x124 arrays (damage handlers)
- Sets `+0x140 = loaded NiNode` (the damage target node)
- This is the NORMAL path on a graphical client

### Path 2: Registry lookup FAILS (returns NULL)
- Falls through to `FUN_006c3f00(&DAT_009976b0, name)` (NIF cache lookup)
- Calls vtable[0xC0] with the loaded NiNode
- **DOES NOT SET +0x140** -- leaves it NULL!
- This appears to be the path taken on our headless server

## DAT_00980798 = Model Property Registry
- Hash table mapping model names to LOD/property data
- Populated during save/load and set initialization
- Cleared by FUN_00452320 after set loading
- FUN_00452ac0(0x980798) returns the current entry count

## Root cause of +0x140 == NULL on dedicated server
The model property registry (DAT_00980798) is likely empty or not populated for
the ship model when SetupModel is called. This causes FUN_00591b60 to take Path 2
which loads the NIF model but does NOT populate +0x140 or the damage handler array.

## DamageableObject constructor chain
```
FUN_00591200 (or FUN_00591410)  -- DamageableObject ctor
  -> FUN_0059ff50              -- parent ctor (ObjectClass)
    -> FUN_00434f00            -- parent ctor (TGObject)
      -> FUN_00430a10          -- base ctor
  -> FUN_00590cb0              -- DamageableObject field init
    -> Sets +0x140 = 0, +0x144 = 0, +0x13c = collision list
  -> FUN_00591b60(this, name)  -- SetModelName (WHERE +0x140 SHOULD be set)
```

## Ship object layout (DamageableObject fields)
| Offset | Size | Field | Set By |
|--------|------|-------|--------|
| +0x108 | 4 | Model name string ptr | FUN_00591b60 |
| +0x10C | 20 | LOD handler array header | FUN_00451ac0 |
| +0x124 | 20 | Damage handler array header | FUN_00451ac0 |
| +0x128 | 4 | Damage handler array DATA ptr | FUN_00451ac0 |
| +0x130 | 4 | Damage handler COUNT | FUN_00451ac0 |
| +0x13C | 4 | Collision list (refcounted) | FUN_00590cb0 |
| +0x140 | 4 | **Damage target NiNode** | FUN_00591b60 (Path 1 only!) |
| +0x144 | 4 | Event handler object | DamageableObject ctor |
| +0x148 | 4 | Alternate NiNode | (unknown) |

## SWIG binding
- `PhysicsObjectClass_SetupModel` (sig "OO") -> vtable[0x128] -> FUN_00591b60
- Called from Python as `self.SetupModel(name)` in SpeciesToShip.InitObject
