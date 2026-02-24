# TG Hierarchy Vtable Layout

## Key Difference from NiObject Hierarchy

The TG class hierarchy (TGObject -> TGStreamedObject -> ... -> Ship) uses a **completely different** vtable layout from the NiObject hierarchy. The critical difference:

- **NiObject**: Slot 0 = `GetRTTI`, slot 10 (+0x28) = scalar_deleting_dtor
- **TGObject**: Slot 0 = `scalar_deleting_dtor`, slot 3 (+0x0C) = DebugPrint

Ship does NOT inherit from NiObject. It inherits from TGObject through this chain:

```
TGObject (vtable 0x008963BC)
  -> TGStreamedObject (vtable 0x008962F4)
    -> TGStreamedObjectEx (vtable 0x008962A8)
      -> TGEventHandlerObject (vtable 0x00896044)
        -> TGSceneObject (vtable 0x00889708)
          -> ObjectClass (vtable 0x00889950)
            -> PhysicsObjectClass (vtable 0x00894128)
              -> DamageableObject (vtable 0x00893D88)
                -> Ship (vtable 0x00894340)
```

## TGObject Vtable (12 slots, vtable 0x008963BC)

| Slot | Offset | Name | Address | Notes |
|------|--------|------|---------|-------|
| 0 | +0x00 | scalar_deleting_dtor | 0x006f0b70 | Destructor |
| 1 | +0x04 | ??? | varies | Unknown |
| 2 | +0x08 | ??? | varies | Unknown |
| 3 | +0x0C | DebugPrint | 0x006f1650 | Debug print object info |
| 4 | +0x10 | WriteToStream | 0x006f2670 | Serialize to stream |
| 5 | +0x14 | ReadFromStream | 0x006f26b0 | Deserialize from stream |
| 6 | +0x18 | ResolveObjectRefs | 0x006f27f0 | Post-load reference fixup |
| 7 | +0x1C | PostDeserialize | (none) | Post-load rebuild |
| 8 | +0x20 | InvokePythonHandler | 0x006f15c0 | Call Python event handler |
| 9-11 | +0x24-2C | ??? | varies | Unknown |

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

| Slot | Offset | Name | Address | Notes |
|------|--------|------|---------|-------|
| 67 | +0x10C | SerializeToBuffer | 0x005a1cf0 | Network serialization |
| 68 | +0x110 | WriteNetworkState | 0x005a1dc0 | Write pos/rot/vel/name |
| 69 | +0x114 | ??? | 0x005a1d80 | Unknown |
| 70 | +0x118 | InitObject | varies | Object initialization |

Also identified:
- SetTargetObject at 0x005a15a0
- DeserializeFromNetwork at 0x005a2060

## DamageableObject (vtable 0x00893D88, 90 slots, 0-89)

Key virtual slots:
| Slot | Offset | Name | Address | Notes |
|------|--------|------|---------|-------|
| 70 | +0x118 | InitObject | varies | Object init |
| 71 | +0x11C | ??? | varies | Unknown |
| 72 | +0x120 | WriteStateUpdate | varies | State serialization |
| 73 | +0x124 | ReadStateUpdate | varies | State deserialization |
| 74-77 | +0x128-134 | ??? | varies | Unknown |
| 78 | +0x138 | ClearTargets | varies | Clear targeting |
| 79 | +0x13C | CheckCollisionRateLimit | 0x005a22a0 | Rate limiting |
| 80-81 | +0x140-144 | ??? | varies | Unknown |
| 82 | +0x148 | RayIntersect / CollisionTest_A | 0x00594310/0x00594440 | |
| 83 | +0x14C | CollisionTest_B | 0x005945b0 | |
| 84 | +0x150 | CheckCollision | varies | Main collision |
| 85 | +0x154 | CollisionDamageWrapper | varies | Damage from collision |
| 86 | +0x158 | ??? | varies | Unknown |
| 87 | +0x15C | ??? | varies | Unknown |
| 88 | +0x160 | SetupProperties | varies | Property-to-subsystem |
| 89 | +0x164 | LinkAllSubsystemsToParents | varies | Parent-child link |

Also identified:
- RegisterEventHandlers at 0x00590980 (not virtual)
- UnregisterEventHandlers at 0x005909b0 (not virtual)

## Ship Vtable (92 slots, vtable 0x00894340, object size 0x328)

Ship extends DamageableObject by 2 extra slots (90-91).

### Complete Ship Vtable Map

| Slot | Offset | Address | Name | Override? |
|------|--------|---------|------|-----------|
| 0 | +0x00 | 0x005abfe0 | Ship__scalar_deleting_dtor | Override |
| 1 | +0x04 | 0x005abe60 | (unknown) | Override |
| 2 | +0x08 | 0x005abe70 | (unknown) | Override |
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
| 13 | +0x34 | 0x006f2790 | (unknown) | Inherited |
| 14 | +0x38 | 0x006f3400 | TGStreamedObject__AddEventHandler | Inherited |
| 15 | +0x3C | 0x006f3500 | (unknown) | Inherited |
| 16-18 | +0x40-48 | varies | (inherited TG methods) | Inherited |
| 19 | +0x4C | 0x005abf10 | (Ship override, unknown) | Override |
| 20 | +0x50 | 0x006d9240 | TGEventHandlerObject__HandleEvent | Inherited |
| 21 | +0x54 | 0x005adae0 | Ship__Update | Override |
| 22 | +0x58 | 0x00430d30 | (TGSceneObject, unknown) | Inherited |
| 23 | +0x5C | 0x00419880 | (stub) | Inherited |
| 24 | +0x60 | 0x005b35a0 | (Ship override, unknown) | Override |
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
| 68 | +0x110 | 0x005a1d80 | (unknown) | Inherited? |
| 69 | +0x114 | 0x005b0d80 | (Ship override, unknown) | Override |
| 70 | +0x118 | 0x005b0e80 | Ship__InitObject | Override |
| 71 | +0x11C | 0x005b0dc0 | (Ship override, unknown) | Override |
| 72 | +0x120 | 0x005b17f0 | Ship__WriteStateUpdate | Override |
| 73 | +0x124 | 0x005b21c0 | Ship__ReadStateUpdate | Override |
| 74 | +0x128 | 0x005abda0 | (Ship override, unknown) | Override |
| 75 | +0x12C | 0x005abf90 | (Ship override, unknown) | Override |
| 76 | +0x130 | 0x00578500 | (inherited? unknown) | |
| 77 | +0x134 | 0x005ae5a0 | (Ship, unknown) | |
| 78 | +0x138 | 0x005ae600 | Ship__ClearTargets | Override |
| 79 | +0x13C | 0x005a22a0 | Ship__CheckCollisionRateLimit | Inherited |
| 80 | +0x140 | 0x005ae730 | (Ship override, unknown) | Override |
| 81 | +0x144 | 0x005aed90 | (Ship override, unknown) | Override |
| 82 | +0x148 | 0x005af7d0 | Ship__CheckCollisionWithCulling | Override |
| 83 | +0x14C | 0x005af830 | Ship__CheckCollisionWithCulling_B | Override |
| 84 | +0x150 | 0x005af890 | Ship__CheckCollision | Override |
| 85 | +0x154 | 0x005b0060 | Ship__CollisionDamageWrapper | Override |
| 86 | +0x158 | 0x005935d0 | (inherited DamageableObject?) | |
| 87 | +0x15C | 0x005abf30 | (wrapper calling vtable+0x168) | |
| 88 | +0x160 | 0x005b3fb0 | Ship__SetupProperties | Override |
| 89 | +0x164 | 0x005b3e20 | Ship__LinkAllSubsystemsToParents | Override |
| 90 | +0x168 | 0x005ac5e0 | (Ship-only addition, unknown) | New |
| 91 | +0x16C | 0x005abf30 | (same as slot 87, wrapper) | New |

### Key Observations

1. **Ship adds 2 slots** beyond DamageableObject's 90 (slots 90-91)
2. **Slot 87 and 91 are identical** (0x005abf30) - a wrapper that calls through vtable+0x168 (slot 90)
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
