# TG Hierarchy Vtable Layout

## Key Difference from NiObject Hierarchy

The TG class hierarchy (TGObject -> TGStreamedObject -> ... -> Ship) uses a **completely different** vtable layout from the NiObject hierarchy. The critical difference:

- **NiObject**: Slot 0 = `GetRTTI`, slot 10 (+0x28) = scalar_deleting_dtor
- **TGObject**: Slot 0 = `scalar_deleting_dtor`, slot 3 (+0x0C) = DebugPrint

Ship does NOT inherit from NiObject. It inherits from TGObject through this chain:

```
TGObject (vtable 0x00896278)
  -> TGStreamedObject (vtable 0x008962F4)
    -> TGStreamedObjectEx (vtable 0x008962A8)
      -> TGEventHandlerObject (vtable 0x00896044)
        -> TGSceneObject (vtable 0x00889708)
          -> ObjectClass (vtable 0x00889950)
            -> PhysicsObjectClass (vtable 0x00894128)
              -> DamageableObject (vtable 0x00893D88)
                -> Ship (vtable 0x00894340)
```

NOTE: 0x008963BC is NOT TGObject's vtable. It is an unrelated class (TGHashTable or similar).
The correct TGObject vtable is at 0x00896278 (confirmed by reading its contents).

## TGObject Vtable (12 slots, vtable 0x00896278)

**CORRECTED from 0x008963BC** — that was wrong.

| Slot | Offset | Name | Address | Notes |
|------|--------|------|---------|-------|
| 0 | +0x00 | scalar_deleting_dtor | 0x006f0b70 | TGObject__scalar_deleting_dtor |
| 1 | +0x04 | GetTypeID | 0x006f0b60 | Returns 2 (TGObject type ID constant) |
| 2 | +0x08 | IsTypeID | 0x00518ab0 | Checks if param == 2 (renamed TGObject__IsTypeID) |
| 3 | +0x0C | DebugPrint | 0x006f1650 | Debug print object info |
| 4 | +0x10 | WriteToStream | 0x006f0bc0 | Serialize to stream |
| 5 | +0x14 | ReadFromStream | stub | (NULL stub 0x00859a0b) |
| 6 | +0x18 | ResolveObjectRefs | stub | (NULL stub 0x00859a0b) |
| 7 | +0x1C | PostDeserialize | stub | (NULL stub 0x00859a0b) |
| 8 | +0x20 | InvokePythonHandler | 0x006f15c0 | Call Python event handler |
| 9 | +0x24 | GetClassName | 0x006f1540 | Returns ptr to "TGObject" string |
| 10 | +0x28 | GetSwigTypeName | 0x006f1550 | Returns ptr to "_p_TGObject" |
| 11 | +0x2C | GetObjectPtrTypeName | 0x006f1560 | Returns ptr to "TGObjectPtr" |

TGEventHandlerObject overrides all of 0-2, 4-5, 9-11 (for its own type ID, names, stream methods).
The "GetTypeID/IsTypeID/GetClassName/GetSwigTypeName/GetObjectPtrTypeName" pattern is universal
across ALL TG hierarchy classes — each class overrides these to return its own type info.

## TGStreamedObject Additions (vtable 0x008962F4)

| Slot | Offset | Name | Address | Notes |
|------|--------|------|---------|-------|
| 12 | +0x30 | WriteToStreamChain | 0x006f2750 | Chained serialize |
| 13 | +0x34 | ??? | 0x006f2790 | Unknown |
| 14 | +0x38 | AddEventHandler | 0x006f3400 | Register event callback |
| 15 | +0x3C | ??? | 0x006f3500 | Unknown |

## TGStreamedObjectEx Additions (vtable 0x008962A8)

Inherits TGStreamedObject slots. Overrides:
- Slot 7 (+0x1C): PostDeserialize -> 0x006f2810

## TGEventHandlerObject Additions (vtable 0x00896044)

| Slot | Offset | Name | Address | Notes |
|------|--------|------|---------|-------|
| 16 | +0x40 | ??? | varies | Unknown |
| 17 | +0x44 | ??? | varies | Unknown |
| 18 | +0x48 | ??? | varies | Unknown |
| 19 | +0x4C | ??? | varies | Unknown |
| 20 | +0x50 | HandleEvent | 0x006d9240 | Main event dispatch |
| 21 | +0x54 | Update | (pure?) | Per-tick update |
| 22 | +0x58 | ??? | 0x00430d30 | TGSceneObject overrides |

Also adds:
- RegisterConditionHandler at 0x006da4e0 (not virtual)

## TGSceneObject Additions (vtable 0x00889708)

| Slot | Offset | Name | Address | Notes |
|------|--------|------|---------|-------|
| 21 | +0x54 | Update | 0x00430cf0 | TGSceneObject override |
| 22 | +0x58 | SetScene | 0x00430e20 | |
| 23-25 | +0x5C-64 | ??? | stubs | Various stubs (0x00419880/0x00419890) |
| 26 | +0x68 | SetDatabaseName | 0x004315c0 | |
| 27-47 | +0x6C-BC | ??? | varies | Scene object management slots |
| 48 | +0xC0 | SetModel | 0x00430b70 | Assign NiNode model |

Overrides:
- Slot 6 (+0x18): ResolveObjectRefs -> 0x00431e20

## ObjectClass (vtable 0x00889950)

Adds slots through ~66. Key additions:
- CreateCollisionProxy at slot position via 0x004356a0

## PhysicsObjectClass (vtable 0x00894128)

PhysicsObjectClass extends the hierarchy with network serialization and physics integration slots.
Slots 67+ are the PhysicsObjectClass-specific additions to the vtable.

| Slot | Offset | Name | Address | Notes |
|------|--------|------|---------|-------|
| 67 | +0x10C | SerializeToBuffer | 0x005a1cf0 | Network buffer serialization |
| 68 | +0x110 | WriteNetworkHeader | 0x005a1d80 | Writes type ID + object ID to stream |
| 69 | +0x114 | WriteNetworkState | 0x005a1dc0 | Writes pos/rot(euler)/vel/name to stream |
| 70 | +0x118 | InitObject | 0x005a2030 | DamageableObject__InitObject: read species byte from stream |
| 71 | +0x11C | DeserializeFromNetwork | 0x005a2060 | PhysicsObjectClass__DeserializeFromNetwork |
| 72 | +0x120 | WriteStateUpdate | 0x005a26c0 | Base state update serialization |
| 73 | +0x124 | ReadStateUpdate | 0x005a2bf0 | Base state update deserialization |
| 74 | +0x128 | SetModel | 0x00591b60 | DamageableObject__SetModel |
| 75 | +0x12C | GetCollisionRadius? | 0x005910d0 | Returns float constant from [0x00888b54] |
| 76 | +0x130 | SetVelocityPair | 0x00578500 | Writes 2 floats to this+0xA8/AC |
| 77 | +0x134 | SetTargetObject | 0x005a15a0 | PhysicsObjectClass__SetTargetObject |
| 78 | +0x138 | UpdateAIForTarget | 0x005a16b0 | Ship__UpdateAIForTarget |
| 79 | +0x13C | CheckCollisionRateLimit | 0x005a22a0 | Rate limiting for collision checks |
| 80 | +0x140 | RayIntersect | 0x005a39f0 | PhysicsObjectClass level (DamageableObject overrides) |
| 81 | +0x144 | ??? | 0x005a38b0 | Unknown |

Ship overrides (vtable 0x00894340) for PhysicsObjectClass-added slots:
- Slot 69: 0x005b0d80 Ship__WriteNetworkState (calls parent WriteNetworkState)
- Slot 70: 0x005b0e80 Ship__InitObject (full NIF + subsystem init)
- Slot 71: 0x005b0dc0 Ship__DeserializeFromNetwork (calls parent, also iterates ship+0x284)
- Slot 72: 0x005b17f0 Ship__WriteStateUpdate
- Slot 73: 0x005b21c0 Ship__ReadStateUpdate
- Slot 74: 0x005abda0 Ship__SetModel (calls DamageableObject__SetModel + ComputeBounds)
- Slot 77: 0x005ae5a0 Ship slot 77 override

Also identified (non-virtual):
- SetTargetObject at 0x005a15a0 (IS virtual, slot 77)

## DamageableObject (vtable 0x00893D88, 92 slots, 0-91)

NOTE: DamageableObject has 92 slots, not 90. Slots 90-91 are destructor variants (scalar_deleting_dtor
and an array destructor). Ship also has 92 slots (0-91) — it does NOT add extra slots beyond DO's 92.

Key virtual slots:
| Slot | Offset | Name | DO Address | Ship Address | Notes |
|------|--------|------|------------|--------------|-------|
| 70 | +0x118 | InitObject | varies | 0x005b0e80 | Object init |
| 71 | +0x11C | ??? | varies | 0x005b0dc0 | Ship override, unknown |
| 72 | +0x120 | WriteStateUpdate | varies | 0x005b17f0 | State serialization |
| 73 | +0x124 | ReadStateUpdate | varies | 0x005b21c0 | State deserialization |
| 74-77 | +0x128-134 | ??? | varies | varies | Unknown |
| 78 | +0x138 | ClearTargets | varies | 0x005ae600 | Clear targeting |
| 79 | +0x13C | CheckCollisionRateLimit | 0x005a22a0 | 0x005a22a0 | Rate limiting (inherited) |
| 80 | +0x140 | RayIntersect | 0x00594310 | 0x005ae730 | Ray/bounding sphere test |
| 81 | +0x144 | ??? | 0x00594430 | 0x005aed90 | Very short (zeros struct, returns 1) |
| 82 | +0x148 | CollisionTest_A | 0x00594440 | 0x005af7d0 | Narrow collision test A |
| 83 | +0x14C | CollisionTest_B | 0x005945b0 | 0x005af830 | Narrow collision test B |
| 84 | +0x150 | CheckCollision | 0x00594840 | 0x005af890 | Full collision resolution |
| 85 | +0x154 | ApplyCollisionDamage | 0x00593650 | 0x005b0060 | Damage from collision |
| 86 | +0x158 | ??? | 0x005935d0 | 0x005935d0 | Collision notify loop (inherited) |
| 87 | +0x15C | ??? | 0x00595e40 | 0x005b3480 | Base=RET stub; Ship overrides |
| 88 | +0x160 | SetupProperties | 0x00591190 | 0x005b3fb0 | Property-to-subsystem |
| 89 | +0x164 | LinkAllSubsystemsToParents | 0x005911a0 | 0x005b3e20 | Parent-child link |
| 90 | +0x168 | scalar_deleting_dtor | 0x00596340 | 0x005ac5e0 | Destructor variant |
| 91 | +0x16C | array_deleting_dtor | 0x005962f0 | 0x005abf30 | Destructor variant |

**CORRECTED from earlier doc**: Previous version had slot 82 = "RayIntersect / CollisionTest_A" combining
two separate slots. Correct mapping: RayIntersect=80, slot 81=small stub, CollisionTest_A=82.

Also identified:
- RegisterEventHandlers at 0x00590980 (not virtual)
- UnregisterEventHandlers at 0x005909b0 (not virtual)

## Ship Vtable (92 slots, vtable 0x00894340, object size 0x328)

Ship has the same 92-slot layout as DamageableObject. It does NOT add new slots; it overrides
slots 90-91 (destructors) with its own destructor implementations.

### Complete Ship Vtable Map

| Slot | Offset | Address | Name | Override? |
|------|--------|---------|------|-----------|
| 0 | +0x00 | 0x005abfe0 | Ship__scalar_deleting_dtor | Override |
| 1 | +0x04 | 0x005abe60 | (unknown dtor variant) | Override |
| 2 | +0x08 | 0x005abe70 | (unknown dtor variant) | Override |
| 3 | +0x0C | 0x006f1650 | TGObject__DebugPrint | Inherited |
| 4 | +0x10 | 0x005b0f00 | Ship__WriteToStream | Override |
| 5 | +0x14 | 0x005b1220 | Ship__ReadFromStream | Override |
| 6 | +0x18 | 0x005b1500 | Ship__ResolveObjectRefs | Override |
| 7 | +0x1C | 0x005b1550 | Ship__PostDeserialize | Override |
| 8 | +0x20 | 0x006f15c0 | TGObject__InvokePythonHandler | Inherited |
| 9 | +0x24 | (unknown) | | |
| 10 | +0x28 | (unknown) | | |
| 11 | +0x2C | (unknown) | | |
| 12 | +0x30 | 0x006f2750 | TGStreamedObject__WriteToStreamChain | Inherited |
| 13 | +0x34 | 0x006f2790 | TGStreamedObject__ReadFromStreamChain? | Inherited |
| 14 | +0x38 | 0x006f3400 | TGStreamedObject__AddEventHandler | Inherited |
| 15 | +0x3C | 0x006f3500 | TGStreamedObject__RemoveEventHandler? | Inherited |
| 16-18 | +0x40-48 | varies | (inherited TG methods) | Inherited |
| 19 | +0x4C | 0x005abf10 | (Ship override, unknown) | Override |
| 20 | +0x50 | 0x006d9240 | TGEventHandlerObject__HandleEvent | Inherited |
| 21 | +0x54 | 0x005adae0 | Ship__Update | Override |
| 22 | +0x58 | 0x00430d30 | TGSceneObject__AttachDefaultProperty? (calls NiAVObject::AttachProperty(this+0x18, 0); NOT SetScene) | Inherited |
| 23 | +0x5C | 0x00419880 | (stub) | Inherited |
| 24 | +0x60 | 0x005b35a0 | Ship__SetScene (stops all sounds via TGSoundManager, then calls PhysicsObjectClass__SetScene) | Override |
| 25 | +0x64 | 0x00419890 | (stub) | Inherited |
| 26 | +0x68 | 0x004315c0 | TGSceneObject__SetDatabaseName | Inherited |
| 27-34 | +0x6C-88 | varies | (TGSceneObject/ObjectClass) | Mixed |
| 35 | +0x8C | 0x005abaa0 | (Ship override, near ComputeBounds) | Override |
| 36-47 | +0x90-BC | varies | (mixed inherited/override) | Mixed |
| 48 | +0xC0 | 0x00430b70 | TGSceneObject__SetModel | Inherited |
| 49-57 | +0xC4-E4 | varies | (mixed) | Mixed |
| 58 | +0xE8 | 0x005abc30 | Ship__GetBoundingBox | Override |
| 59-66 | +0xEC-108 | varies | (mixed) | Mixed |
| 67 | +0x10C | 0x005a1cf0 | PhysicsObjectClass__SerializeToBuffer | Inherited |
| 68 | +0x110 | 0x005a1d80 | PhysicsObjectClass__WriteNetworkHeader (writes type ID + object ID to stream) | Inherited |
| 69 | +0x114 | 0x005b0d80 | Ship__WriteNetworkState (calls PhysicsObjectClass__WriteNetworkState then Ship fields) | Override |
| 70 | +0x118 | 0x005b0e80 | Ship__InitObject | Override |
| 71 | +0x11C | 0x005b0dc0 | Ship__DeserializeFromNetwork (calls PhysicsObjectClass__DeserializeFromNetwork) | Override |
| 72 | +0x120 | 0x005b17f0 | Ship__WriteStateUpdate | Override |
| 73 | +0x124 | 0x005b21c0 | Ship__ReadStateUpdate | Override |
| 74 | +0x128 | 0x005abda0 | Ship__SetModel (calls PhysicsObjectClass__SetModel then ComputeBoundsFromGeometry) | Override |
| 75 | +0x12C | 0x005abf90 | (Ship override, unknown) | Override |
| 76 | +0x130 | 0x00578500 | (inherited? unknown) | |
| 77 | +0x134 | 0x005ae5a0 | (Ship, unknown) | |
| 78 | +0x138 | 0x005ae600 | Ship__ClearTargets | Override |
| 79 | +0x13C | 0x005a22a0 | Ship__CheckCollisionRateLimit | Inherited |
| 80 | +0x140 | 0x005ae730 | Ship__RayIntersect | Override |
| 81 | +0x144 | 0x005aed90 | (Ship override, unknown) | Override |
| 82 | +0x148 | 0x005af7d0 | Ship__CollisionTest_A | Override |
| 83 | +0x14C | 0x005af830 | Ship__CollisionTest_B | Override |
| 84 | +0x150 | 0x005af890 | Ship__CheckCollision | Override |
| 85 | +0x154 | 0x005b0060 | Ship__CollisionDamageWrapper | Override |
| 86 | +0x158 | 0x005935d0 | DamageableObject__CollisionNotifyLoop | Inherited |
| 87 | +0x15C | 0x005b3480 | (Ship override; DO base=RET stub 0x595e40) | Override |
| 88 | +0x160 | 0x005b3fb0 | Ship__SetupProperties | Override |
| 89 | +0x164 | 0x005b3e20 | Ship__LinkAllSubsystemsToParents | Override |
| 90 | +0x168 | 0x005ac5e0 | Ship__scalar_deleting_dtor_2 | Override |
| 91 | +0x16C | 0x005abf30 | Ship__array_dtor_wrapper | Override |

### Key Observations

1. **Ship has 92 slots (0-91), same count as DamageableObject** — NOT "adds 2 extra slots"
2. **Slot 87 and 91 differ**: slot 87 (0x005abf30) is a wrapper; slot 91 is a separate wrapper
3. **~40 vtable entries** point to addresses Ghidra hasn't recognized as function starts (small stubs/thunks)
3. **~40 vtable entries** point to addresses Ghidra hasn't recognized as function starts (small stubs/thunks)
4. **Slot 20 (HandleEvent)** is inherited from TGEventHandlerObject, NOT overridden by Ship
5. **Slots 82-85** form the collision detection/damage pipeline
6. **Slots 88-89** are the property-to-subsystem setup pipeline

### Identified Ship Overrides (21 of 92 slots)

Slots where Ship provides its own implementation (vs inheriting from parent):
0, 1, 2, 4, 5, 6, 7, 19, 21, 24, 35, 58, 69, 70, 71, 72, 73, 74, 75, 78, 80, 81, 82, 83, 84, 85, 88, 89, 90

### Network-Critical Slots

| Slot | Name | Role |
|------|------|------|
| 4 | WriteToStream | Full ship serialization for ObjCreate |
| 5 | ReadFromStream | Full ship deserialization from ObjCreate |
| 67 | SerializeToBuffer | Network buffer serialization |
| 70 | InitObject | Ship creation from network data |
| 72 | WriteStateUpdate | Per-tick state sync (opcode 0x1C) |
| 73 | ReadStateUpdate | Per-tick state receive |
| 85 | CollisionDamageWrapper | Collision damage relay (opcode 0x15) |
