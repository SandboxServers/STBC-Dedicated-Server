# Ship +0x284 Subsystem Linked List Population Analysis

## Date: 2026-02-13

## Summary

The linked list at ship+0x284 is populated by FUN_005b3e50 (AddSubsystemToList), called from
FUN_005b3fb0 (SubsystemFactory/per-property handler). FUN_005b3fb0 is invoked via vtable dispatch
from the C++ SetupProperties method (SWIG: `DamageableObject_SetupProperties`).

The list remains NULL on the headless server because the 5-step chain has a hard dependency on
NIF model loading at step 2 (AddToSet requires "Scene Root" NiNode from loaded NIF).

## Data Structure at ship+0x280

```
+0x280: int    count          (number of items in subsystem list)
+0x284: Node*  head           (first node in linked list, NULL if empty)
+0x288: Node*  tail           (last node in linked list)
+0x28C: Node*  free_list      (pool of recycled nodes)
+0x290: ...
+0x298: int    count2         (number of items in secondary/weapon list)
+0x29C: Node*  head2          (weapon subsystem list head)
+0x2A0: Node*  tail2          (weapon subsystem list tail)
```

Node format: 12 bytes = `[data_ptr:4, next_ptr:4, prev_ptr:4]`
Allocated via FUN_00486be0 (pool allocator with batch preallocation).

## FUN_005b3e50 (AddSubsystemToList) - Address 0x005b3e50

```
void __thiscall FUN_005b3e50(void *this, int *param_1)
  this = ship object
  param_1 = newly created subsystem object
```

1. ALWAYS adds param_1 to the primary list at +0x284 (append to tail)
2. Then checks subsystem type via vtable[8](typeID) cascade:
   - If type matches 0x8021, 0x802c, 0x802f, 0x802e, 0x802d, 0x8025, or 0x8024:
     subsystem is NOT added to secondary list (it's a "primary" subsystem)
   - If type matches NONE of those: added to secondary list at +0x29c (weapons)
3. Increments count at +0x280

## FUN_005b3fb0 (SubsystemFactory) - Address 0x005b3fb0

```
void __thiscall FUN_005b3fb0(void *this, int *param_1)
  this = ship object
  param_1 = single TGModelPropertyInstance from the property set
```

Called via vtable dispatch (vtable entry at 0x008944a0).
Processes ONE property at a time:
1. Gets property type ID via vtable[4] on param_1
2. Switch on type ID (0x812e through 0x813f)
3. For each type: allocate subsystem, construct it, call vtable[0x60](property) to init
4. Store in named slot (e.g., +0x2B4 for shields, +0x2B8 for phaser system, etc.)
5. If piVar11 != NULL: calls FUN_005b3e50(this, piVar11) to add to +0x284 list
6. Then calls vtable[0x58](this) on subsystem to finalize

## The 5-Step Chain (from Python InitObject to populated +0x284)

```
1. self.SetupModel(name)
   -> C++ loads NIF file (FUN_00817a40 NiStream::Load)
   -> FUN_006c9520 finds "Scene Root" NiNode in loaded NIF
   -> Creates TGModelPropertyInstance (0x150 bytes)
   FAILURE: If NIF doesn't load, no "Scene Root" node exists

2. mod.LoadPropertySet(pPropertySet)
   -> For each subsystem: pObj.AddToSet("Scene Root", prop)
   -> AddToSet searches for NiNode named "Scene Root"
   -> Links property to NiNode, stores in property set
   FAILURE: If no "Scene Root" (step 1 failed), AddToSet returns 0
   -> Property NOT added to property set

3. self.SetupProperties()
   -> C++ iterates property set's property list
   -> For each property: calls this->vtable[N](property) -> FUN_005b3fb0
   FAILURE: If property set is EMPTY (step 2 failed), nothing to iterate
   -> No subsystem objects created, +0x284 stays NULL

4. Subsystem objects created (FUN_005b3fb0)
   -> Allocates concrete subsystem (Hull, Shield, Sensor, etc.)
   -> Calls vtable[0x60] to initialize from property data
   -> Stores in named slot (+0x2B0 through +0x2E0)
   -> Calls FUN_005b3e50 to add to +0x284 linked list

5. FUN_005b3e50 populates +0x284
   -> Allocates node from pool (FUN_00486be0)
   -> Links into doubly-linked list
   -> Increments count at +0x280
```

## Why Server Has NULL +0x284

The server's ship objects receive client ships via network deserialization
(FUN_0069f620 -> FUN_005a1f50 -> FUN_005b0e80). The C++ calls Python
`Multiplayer.SpeciesToShip.InitObject(self, iType)` which runs the 5-step chain.

On the headless server:
- Step 1 (SetupModel): MAY fail if NIF files aren't present or NiStream::Load
  hits a headless-mode issue (e.g., texture objects that need D3D)
- Step 2 (AddToSet): FAILS if Step 1 failed - property set remains empty
- Step 3 (SetupProperties): iterates empty property set - NO-OP
- Result: +0x284 = NULL, no subsystems, GetHull()/GetShields() return NULL

## Possible Fixes

### Option A: Ensure NIF files load headlessly
- NIF loading (NiStream::Load at 0x00817a40) is FILE I/O, not renderer-dependent
- If NIF files are present on server, loading may succeed
- But NiTexture creation may fail in headless mode (needs D3D texture objects)
- Would need to patch texture creation to return dummy objects

### Option B: Populate +0x284 without NIF
- Would need to bypass the AddToSet NiNode requirement
- Create subsystem objects directly via the factory (FUN_005b3fb0)
- But FUN_005b3fb0 needs valid TGModelPropertyInstance objects

### Option C: Direct list population from C code
- After SetupProperties() returns (even if empty), manually call FUN_005b3e50
  with dummy subsystem objects
- Risk: subsystem objects need proper initialization for hash checks

### Option D: Patch SetupProperties to not require NiNode linkage
- Modify the property set iteration to use the registered local templates directly
- Skip the NiNode linkage step
- This would be a significant architectural change

## Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x005b3e50 | AddSubsystemToList | Adds subsystem to +0x284 and optionally +0x29c |
| 0x005b3fb0 | SubsystemFactory | Creates subsystem from property, calls AddSubsystemToList |
| 0x005b3e20 | IterateSubsystems | Iterates +0x284 list, calls FUN_005b5030 on each |
| 0x005b0bb0 | UpdateSubsystems | Iterates +0x284 list, calls vtable[0x90] on each |
| 0x00486be0 | PoolAllocNode | Allocates 12-byte node for linked list |
| 0x006c9520 | ExtractModel/AddToSet | Finds "Scene Root" NiNode - THE NIF dependency |
| 0x00817a40 | NiStream::Load | File I/O to load NIF binary |
| 0x008944a0 | vtable entry | Points to FUN_005b3fb0 (SubsystemFactory) |
