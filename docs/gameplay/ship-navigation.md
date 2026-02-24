# Ship Navigation & Targeting

Reverse-engineered implementation details of Bridge Commander's ship targeting pipeline, movement model, turn computation, and in-system warp. These are the C++ functions that AI scripts and player input call to control ship movement.

---

## 1. Targeting Pipeline

### SetTarget → SetTargetInternal → OnTargetChanged

The full call chain when a target is set (by AI, player, or network):

```
Ship__SetTarget (0x005ae1e0)
  ├── TGSceneGraph__FindObjectByID (0x00434e70)   // resolve target name → object
  └── Ship__SetTargetInternal (0x005ae210)
        ├── Fire ET_TARGET_WAS_CHANGED (0x800058)  // TGObjPtrEvent with old target ID
        ├── Ship__StopFiringWeapons (0x005b0bb0)   // stop current weapon fire
        └── Ship__OnTargetChanged (0x005ae2c0)
              ├── Ship__UpdateWeaponTargets (0x005ae430)  // walk +0x284 subsystem list
              └── Fire ET_TARGET_SUBSYSTEM_SET (0x80005A)
```

### Function Details

| Function | Address | Calling Convention | Description |
|----------|---------|-------------------|-------------|
| Ship__SetTarget | 0x005ae1e0 | __thiscall | SWIG `ShipClass_SetTarget` target. Takes target name string, calls FindObjectByID + SetTargetInternal |
| Ship__GetTarget | 0x005ae170 | __thiscall | Reads +0x21C (target object ID), validates target is alive, returns object or NULL |
| Ship__SetTargetInternal | 0x005ae210 | __thiscall | Core implementation. Fires ET_TARGET_WAS_CHANGED (0x800058), stops weapons, updates subsystems |
| Ship__OnTargetChanged | 0x005ae2c0 | __thiscall | Post-change hook. Updates weapon target entries, fires ET_TARGET_SUBSYSTEM_SET |
| Ship__UpdateWeaponTargets | 0x005ae430 | __thiscall | Walks +0x284 subsystem linked list, updates each weapon system's target entry |
| Ship__StopFiringWeapons | 0x005b0bb0 | __thiscall | Walks +0x284, finds WeaponSystems via `IsA(0x801D)`, stops each |
| Ship__GetTargetOffset | 0x005ae650 | __thiscall | Returns +0x228 target offset (manual aim point or auto-computed from target bounding box) |
| Ship__GetTargetSubsystemObject | 0x005ae630 | __thiscall | Resolves +0x220 target subsystem ID via ForwardEvent |

### Target Cycling

| Function | Address | Description |
|----------|---------|-------------|
| Ship__GetNextTarget | 0x005ae6d0 | Cycles through sorted target list via index at ship+0x87 |

The target list is maintained as a sorted array. `GetNextTarget` increments the index, wraps at the boundary, and returns the next valid target. This is what the "cycle targets" key binding calls.

### Target Fields on Ship

| Offset | Type | Field |
|--------|------|-------|
| +0x87 | byte | Target list cycle index |
| +0x21C | int32 | Current target object ID |
| +0x220 | int32 | Target subsystem ID (for precision targeting) |
| +0x228 | TGPoint3 | Target offset (aim point relative to target origin) |

---

## 2. Turn Computation

### Entry Points

Three entry points for directing a ship's rotation:

| Function | Address | Input | Description |
|----------|---------|-------|-------------|
| Ship__TurnTowardLocation | 0x005ad3a0 | TGPoint3 (world position) | Normalizes direction to target point, calls TurnTowardDirection |
| Ship__TurnTowardDirection | 0x005ad450 | TGPoint3 (unit direction) | Gets current orientation, computes turn via ComputeTurnAngularVelocity |
| Ship__TurnTowardDifference | 0x005ad4d0 | TGPoint3 (direction delta) | SWIG `ShipClass_TurnTowardDifference` target. Direct delta input |

All paths converge on `ComputeTurnAngularVelocity`:

### ComputeTurnAngularVelocity

| Function | Address | Description |
|----------|---------|-------------|
| Ship__ComputeTurnAngularVelocity | 0x005ad910 | Quaternion slerp-style turn with constraints |

This function computes the angular velocity needed to rotate the ship from its current orientation toward the target direction. Key behaviors:
- Uses quaternion-based interpolation (slerp-style) for smooth rotation
- Constrains rotation to preserve the ship's up axis (prevents roll)
- Forward axis is the primary alignment target
- Maximum angular velocity is determined by ship properties (from ImpulseEngineSubsystem)
- The result is a 3-component angular velocity vector applied to the physics object

### SetTargetAngularVelocityDirect

| Function | Address | Description |
|----------|---------|-------------|
| Ship__SetTargetAngularVelocityDirect | 0x005ad290 | SWIG target. Bypasses turn computation, sets angular velocity directly |

Used by AI scripts that compute their own rotation (e.g., manual maneuver patterns).

### Supporting Math

| Function | Address | Description |
|----------|---------|-------------|
| NiMatrix3__TransformVector | 0x00813a40 | 3x3 matrix * vec3 (rotation transform) |
| NiMatrix3__TransposeTransformVector | 0x00813aa0 | Transpose multiply (inverse rotation for world→model) |
| TGPoint3__Cross | 0x0045c1a0 | Cross product |
| TGPoint3__UnitCross | 0x00581e60 | Normalized cross product |
| TGPoint3__MultMatrix | 0x0045e8d0 | Point * matrix transform |
| GetForwardDirection | 0x00434cd0 | Returns global forward direction vector (from DAT_00980df0) |

---

## 3. Impulse Movement Model

### SetImpulse / SetSpeed

| Function | Address | Calling Convention | Description |
|----------|---------|-------------------|-------------|
| Ship__SetImpulse | 0x005ac470 | __thiscall | Clamps speed to 0.0–1.0, stores at ship+0x1F8 (direction) / +0x1FC (speed scalar) |
| Ship__SetSpeed | 0x005ac590 | __thiscall | Divides input by max speed, then calls SetImpulse |

`SetImpulse` takes a normalized speed (0.0 = stop, 1.0 = full impulse), a direction vector, and a coordinate space flag (`DIRECTION_MODEL_SPACE` or `DIRECTION_WORLD_SPACE`).

`SetSpeed` is a convenience wrapper: it takes an absolute speed value, divides by `GetMaxSpeed()`, and delegates to `SetImpulse`. Used by AI scripts that compute speed in absolute units.

### Effective Speed

The actual speed a ship achieves depends on impulse engine health and power efficiency:

| Function | Address | Description |
|----------|---------|-------------|
| ImpulseEngineSubsystem__GetEffectiveSpeed | 0x00561330 | max_speed * (child_health * power_efficiency) |
| ImpulseEngineSubsystem__GetEffectiveAcceleration | 0x00561230 | Same pattern for acceleration |
| ImpulseEngineSubsystem__ctor | 0x00561050 | Constructor |

Effective speed formula:
```
effective_max_speed = base_max_speed * health_factor * power_efficiency
```

Where:
- `base_max_speed` comes from the ship's impulse engine property
- `health_factor` = aggregate health of impulse engine child subsystems
- `power_efficiency` = `PoweredSubsystem__GetEfficiency` (0x005822d0) = received_power / wanted_power, clamped to [0, 1]

A damaged or under-powered impulse engine directly reduces maximum achievable speed and acceleration.

### Ship Velocity Fields

| Offset | Type | Field |
|--------|------|-------|
| +0x1F8 | float[3] | Impulse direction (model or world space) |
| +0x1FC | float | Impulse speed scalar (0.0–1.0) |

These are the *commanded* values. Actual velocity is on the NiAVObject at the standard NI offsets (+0x98/+0x9C/+0xA0 via ship+0x18 NiNode).

---

## 4. In-System Warp

| Function | Address | Description |
|----------|---------|-------------|
| Ship__InSystemWarp | 0x005ac6e0 | SWIG `ShipClass_InSystemWarp` target. Pathfinding + obstacle avoidance |
| Ship__StopInSystemWarp | 0x005acdb0 | Clears warp state, fires ET_EXITED_WARP, restores velocity |

In-system warp moves a ship at very high speed to a distant object within the same set. Used by the Intercept AI when the target is farther than `fInSystemWarpDistance` (default 295 units).

Behaviors:
- Engages when distance exceeds threshold and speed is uncapped
- Fires `ET_IN_SYSTEM_WARP` event on start
- Includes obstacle avoidance (planets, large ships) — see Intercept.AdjustDestinationForLargeObstacles
- Fires `ET_EXITED_WARP` event on completion or interruption
- `StopInSystemWarp` restores normal velocity state

### Network Opcode

Opcode 0x10 (`StartWarp`) exists in the multiplayer game opcode table but is unused in stock multiplayer. In-system warp is only triggered by AI scripts in single-player.

---

## 5. Weapon System Integration

When a target changes, the targeting pipeline updates all weapon systems:

| Function | Address | Description |
|----------|---------|-------------|
| WeaponSystem__FindTargetEntry | 0x00585360 | Searches +0xC4 target list by object ID |
| WeaponSystem__FindTargetByObjectID | 0x00584080 | Extracts obj+4 ID, delegates to FindTargetEntry |
| WeaponSystem__SetTargetOffset | 0x00585580 | Updates target entry offset, clears child subsystem targets |
| Subsystem__AsWeaponSystem | 0x00583f60 | IsA(0x801D) cast check |

The weapon target list at WeaponSystem+0xC4 maps object IDs to aim data. When `Ship__UpdateWeaponTargets` runs (after target change), it walks all subsystems via the +0x284 linked list and updates weapon entries.

---

## 6. Scene Graph Lookups

| Function | Address | Description |
|----------|---------|-------------|
| TGSceneGraph__FindObjectByID | 0x00434e70 | Searches by ID across scene roots |
| TGSceneGraph__GetObjectByID | 0x00434e00 | Hash lookup then IsA(0x8003) cast |
| TGObjectTree__FindByHashAndTrack | 0x0040fe00 | Hash bucket walk + tracking call |
| TGObjectTree__GetNextSorted | 0x0040fe80 | Binary search in sorted array, wraps on boundary |
| TGObject__AsShip | 0x005ab670 | IsA(0x8008) cast, returns NULL if not ship |
| TGObject__SetVelocity | 0x005a04c0 | Sets NiAVObject+0x98/+0x9C/+0xA0 velocity via +0x18 |
| TGObject__SetDirtyFlag | 0x006d5e80 | Sets/clears bit 2 of +0x18 flags (marks for state update) |

Ship__SetTarget calls FindObjectByID to resolve a target name to an object pointer before passing it to SetTargetInternal.

---

## 7. Subsystem Helpers

| Function | Address | Description |
|----------|---------|-------------|
| Ship__StartGetSubsystemMatch | 0x005ac370 | Allocates iterator for type-matching subsystem traversal |
| Ship__GetNextSubsystemMatch | 0x005ac390 | Returns next subsystem matching requested type ID |
| Ship__AddSubsystem | 0x005b3e50 | Adds to +0x280 list, classifies by IsA checks |
| Subsystem__IsActive | 0x0056c340 | Reads property+0x25 active flag via +0x18 |
| Subsystem__GetRadius | 0x0056b940 | Reads property+0x44 (radius float) |
| Subsystem__GetChild | 0x0056c570 | Array bounds check, returns child at index from +0x20 |
| Subsystem__GetProperty | 0x00560fc0 | Returns +0x18 (SubsystemProperty pointer) |
| PoweredSubsystem__GetEfficiency | 0x005822d0 | Returns +0xFC / +0xF8 (received/wanted), clamped |

---

## 8. Collision Queries

Used by AI obstacle avoidance (Intercept.AdjustDestinationForLargeObstacles):

| Function | Address | Description |
|----------|---------|-------------|
| CollisionQuery__Execute | 0x005a7cf0 | Sweep-and-prune collision query for spatial search |
| CollisionQuery__GetNextResult | 0x005a8320 | Iterator over collision results |
| CollisionQuery__Destroy | 0x005a8350 | Cleanup/free |
| RaySphereIntersect | 0x004570d0 | Line-sphere intersection test, returns 0/1/2 hits |

The proximity manager (`pSet.GetProximityManager()`) provides `GetLineIntersectObjects()` for line-of-sight and obstacle detection.

---

## 9. Network Authority

Position and orientation are **client-authoritative** in stock Bridge Commander multiplayer. Each client controls its own ship's movement; the host does not validate or simulate other players' physics.

Replication path:
1. Client runs AI/player input → calls SetImpulse/TurnTowardLocation → physics updates position
2. Client serializes position/orientation/velocity into StateUpdate (opcode 0x1C, dirty flag bits 0x01+0x02)
3. Host receives StateUpdate → forwards to all other clients (relay-all architecture)
4. Other clients apply received position/orientation to remote ship objects

There is no server-side movement simulation or desync correction in stock BC.

### Relevant Opcodes

| Opcode | Name | Relevance |
|--------|------|-----------|
| 0x1C | StateUpdate | Position (flag 0x01) + orientation (flag 0x02) replication |
| 0x10 | StartWarp | In-system warp (exists but unused in stock MP) |
| 0x07 | StartFiring | Weapon fire begin (movement-adjacent) |
| 0x08 | StopFiring | Weapon fire end |

---

## Related Documents

- [ai-architecture.md](ai-architecture.md) — AI behavior tree that drives these navigation functions
- [damage-system.md](damage-system.md) — Damage affecting impulse engine efficiency
- [power-system.md](power-system.md) — Power delivery affecting engine performance
- [collision-detection-system.md](collision-detection-system.md) — Collision system that obstacle avoidance queries
- [../protocol/stateupdate.md](../protocol/stateupdate.md) — StateUpdate wire format for position/orientation replication
