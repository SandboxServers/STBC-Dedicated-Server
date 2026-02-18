# Collision Detection System - Full Reverse Engineering Analysis

Complete analysis of the physics-level collision detection algorithm in Star Trek: Bridge
Commander. This covers how the engine determines two objects have collided, BEFORE any
damage calculation occurs.

## Architecture Overview

Bridge Commander uses a **three-tier collision detection system**:

1. **Broad Phase**: `ProximityManager` -- 3-axis sweep-and-prune (sort-and-sweep) AABB
2. **Hierarchical Bounding Sphere**: `ObjectClass::CheckCollision` (FUN_005671d0) -- recursive bounding sphere tests
3. **Narrow Phase**: Varies by object type -- ship-ship, ship-torpedo, ship-environment

The collision system is NOT part of NetImmerse's built-in collision (NiCollisionSwitch exists
but is only used for toggling). Instead, Bridge Commander implements a completely custom
collision detection pipeline at the game layer.

## System Manager: ProximityManager

**Class**: ProximityManager (custom, not NI)
**Size**: 0x64 (100 bytes)
**Vtable**: 0x008942D4
**Constructor**: FUN_005a7420
**Global flag**: DAT_008e5f58 = collisions enabled (SetPlayerCollisionsEnabled)

### ProximityManager Layout

```
Offset  Size  Type         Field                    Notes
------  ----  ----         -----                    -----
0x00    4     void**       vtable                   0x008942D4
0x04    4     int          (unknown)                Init 0
0x08    1     byte         (flag)
0x0C    4     void*        collision_pairs_list     Circular doubly-linked list of active pairs
0x10    4     int          num_collision_pairs      Active pair count
0x14    20    AxisSort[0]  x_axis_sort              Axis 0 sort structure (5 DWORDs each)
0x28    20    AxisSort[1]  y_axis_sort              Axis 1 sort structure
0x3C    20    AxisSort[2]  z_axis_sort              Axis 2 sort structure
0x50    4     int          object_count             Number of tracked objects
0x54    4     void*        object_table             Array of object entries (0x1C bytes each)
0x58    4     void*        overlap_tracker          Tracks axis overlap counts between pairs
0x5C    4     void*        (reserved)
0x60    4     void*        (reserved)
```

### ProximityManager Ownership

- Each game `Set` holds a ProximityManager at Set+0xF4 (accessed via `GetProximityManager()`)
- Objects are added via `ProximityManager_AddObject` (FUN_005a7640)
- Updated every frame via `ProximityManager_Update` (FUN_005a83a0)

## Tier 1: Broad Phase -- Sweep-and-Prune

### Overview

The ProximityManager implements **3-axis sweep-and-prune** (also called sort-and-sweep),
a well-known broad-phase collision detection algorithm.

### How It Works

**Initialization** (FUN_005a7640 - AddObject):

1. Compute AABB for the object: calls `FUN_00436130` (GetBoundingBox, vtable+0xE8)
2. The AABB produces 6 floats: min(x,y,z), max(x,y,z)
3. For each of the 3 axes, insert min and max interval endpoints into sorted lists
4. Each endpoint entry is 12 bytes: `{ float value, int next_ptr, int object_index }`
5. Insertion uses `FUN_005a8cc0` which maintains the sorted order

**Per-Frame Update** (FUN_005a83a0):

1. For each object: recompute AABB (`FUN_005a8470`)
2. Update endpoint values in the sorted lists
3. Call `FUN_005a8500` (SweepAxis) for each of the 3 axes (indices 0, 1, 2)
4. Call `FUN_005a8740` (ProcessCollisionPairs) for all overlapping pairs

### Sweep-and-Prune Algorithm (FUN_005a8500)

The sweep step uses **bubble-sort-like** incremental update:

```c
// Pseudocode for SweepAxis(axis_index)
axis = &manager->axis_sort[axis_index * 5];
repeat {
    swapped = false;
    for (i = 0; i < axis->count - 1; i++) {
        if (axis->endpoints[i+1].value < axis->endpoints[i].value) {
            // Swap the two endpoints
            SwapEndpoints(axis, i, i+1);
            swapped = true;

            // Check if this swap represents an interval START overlapping END
            if (endpoint[i].is_max == false && endpoint[i+1].is_min == false) {
                // Two intervals now overlap on this axis
                // If they overlap on ALL 3 axes (count == 3):
                if (IncrementOverlap(pair) == 3) {
                    // Check collision flags compatibility
                    if (CollisionFlagsCompatible(obj_a, obj_b)) {
                        // Add to collision pairs list
                        AddCollisionPair(obj_a, obj_b);
                    }
                }
            }
            // Check if this swap represents intervals SEPARATING
            else if (endpoint[i].is_max == true && endpoint[i+1].is_min == true) {
                if (DecrementOverlap(pair) == 2) {
                    // No longer overlapping on all 3 axes
                    // Remove from collision pairs list
                    RemoveCollisionPair(obj_a, obj_b);
                }
            }
        }
    }
} while (swapped);
```

**Key insight**: Because objects move incrementally frame-to-frame, the sorted arrays are
*nearly sorted* each frame, making the bubble-sort O(n) in practice (vs O(n^2) for naive
all-pairs testing).

### AABB Computation (FUN_00436130)

```c
void GetAABB(NiAVObject* obj, Vec3* out_min, Vec3* out_max) {
    // First: get bounding box from geometry (vtable+0xE8)
    obj->GetBoundingBox(out_min, out_max);

    // If object has custom extents at +0x3D flag:
    if (obj->byte_0x3D) {
        // Clamp to custom bounds at +0x40..+0x54
        out_min->x = min(out_min->x, obj->custom_min_x);  // +0x40
        out_min->y = min(out_min->y, obj->custom_min_y);  // +0x44
        out_min->z = min(out_min->z, obj->custom_min_z);  // +0x48
        out_max->x = max(out_max->x, obj->custom_max_x);  // +0x4C
        out_max->y = max(out_max->y, obj->custom_max_y);  // +0x50
        out_max->z = max(out_max->z, obj->custom_max_z);  // +0x54
    }
}
```

### Collision Flags Compatibility (FUN_005a7890)

Two objects can only collide if their collision flags at object+0x3C are compatible:

```c
bool CollisionFlagsCompatible(int obj_a, int obj_b) {
    byte flags_a = *(byte*)(obj_a + 0x3C);
    byte flags_b = *(byte*)(obj_b + 0x3C);

    // Check: (a's collision-with mask) & (b's collision-as type) & 0x2A
    if (((flags_b >> 1) & flags_a & 0x2A) != 0) return true;
    if (((flags_a >> 1) & flags_b & 0x2A) != 0) return true;
    return false;
}
```

The flag byte uses a bitmask where:
- Bits 0,2,4 = "collides AS type X" (what this object IS)
- Bits 1,3,5 = "collides WITH type X" (what this object can hit)
- 0x2A = 0b00101010 = mask for "with" bits

Accessible via Python: `ObjectClass_GetCollisionFlags` (reads byte at object+0x3C)

## Tier 2: Hierarchical Bounding Sphere Test

### CheckCollision (FUN_005671d0)

After sweep-and-prune finds overlapping AABBs, the game performs a **bounding sphere
intersection test** via `FUN_005671d0` (called 79,605 times per 15-min session).

```c
// this = ObjectClass checking against, param_1 = other object
bool ObjectClass::CheckCollision(Object* other) {
    // 1. Early-out: already dead/marked
    if (this->IsDead_0x34()) return false;
    if (!this->collision_active_0x9C) return false;

    // 2. Ship-type check: if other is a ship with collision disabled
    Ship* ship = CastToShip(other);
    if (ship && ship->collisionManager_0x2DC && ship->collisionManager_0x2DC->disabled_0xAC)
        return false;

    // 3. Same-set check: both objects must be in same game set
    int this_set = this->gameObject_0x40->set_id_0x20;
    if (this_set != other->set_id_0x20)
        return false;

    // 4. Exclusion list: check event-based exclusion list at this_set+0x14
    //    (objects recently collided are temporarily excluded)
    for each exclusion in GetExclusionList(this_set, 0x800E) {
        if (IsInExclusionList(exclusion, this_gameObject))
            return true;  // Already known collision
        other_gameObj = GetGameObjectFromOther(other);
        if (IsInExclusionList(exclusion, other_gameObj))
            return true;  // Already known collision
    }

    // 5. TIMER CHECK: if collision cooldown expired AND no exclusion hit
    if (this->timer_0x98 > DAT_0089054c && !exclusion_found) {
        return true;  // Still in cooldown, report collision
    }

    // 6. NARROW PHASE: bounding sphere intersection
    result = CheckSphereIntersection(other);
    if (result) return true;

    // 7. RECURSIVE CHECK: check attached sub-objects
    for each child in this->attached_objects_0xB0 {
        child_obj = LookupObject(child_id);
        if (child_obj && child_obj->collisionData_0x2C8) {
            if (child_obj->collisionData->CheckCollision(other))
                return true;
        }
    }

    // 8. STATIC COLLISION: check against static/terrain geometry
    return CheckStaticCollision(other);
}
```

### Bounding Sphere Distance Test (FUN_00567640)

This is the core geometric test:

```c
bool CheckSphereIntersection(Object* other) {
    NiNode* this_node = this->gameObject_0x40;

    // Same set check
    if (this_node->set_id != other->set_id) return false;

    // Get world positions via vtable+0x94 (GetWorldTranslation)
    Vec3* pos_a = this_node->GetWorldTranslation();
    Vec3* pos_b = other->GetWorldTranslation();

    // Compute Euclidean distance
    float distance = ComputeDistance(this_node->set_id, pos_a, pos_b);
    //   distance = sqrt((bx-ax)^2 + (by-ay)^2 + (bz-az)^2)
    //   + adjustments from child bounding volumes

    // Compute combined collision radius
    float combined_radius = GetCombinedRadius(this);
    //   = NiNode->bound_radius_0x4C * this->scale_0x98 * this->radiusMult_0x34

    // TEST: distance < combined_radius
    if (distance < combined_radius) {
        return false;  // Inside combined sphere = possible collision, check children
    }

    // Recurse into child objects
    for each child in this->attached_objects_0xB0 {
        child_obj = LookupObject(child_id);
        if (child_obj && child_obj->collisionData_0x2C8) {
            if (child_obj->collisionData->CheckSphereIntersection(other))
                return true;
        }
    }
    return true;  // Spheres intersect at leaf level
}
```

### Distance Computation (FUN_00410570)

```c
float ComputeDistance(int set_id, Vec3* pos_a, Vec3* pos_b) {
    float dx = pos_b->x - pos_a->x;
    float dy = pos_b->y - pos_a->y;
    float dz = pos_b->z - pos_a->z;
    float base_distance = sqrt(dx*dx + dy*dy + dz*dz);

    // Apply child bounding volume adjustments
    for (int i = 0; i < set_id->num_modifiers_0xF8; i++) {
        float modifier = set_id->modifiers_0xFC[i]->ComputeAdjustment(base_distance, pos_a, pos_b);
        base_distance += (modifier - base_distance);
    }
    return base_distance;
}
```

### Collision Radius (FUN_00567190)

```c
float GetCombinedRadius(CollisionData* this) {
    if (this->IsDead()) return DAT_00888b54;  // max float sentinel
    if (!this->collision_active_0x9C) return DAT_00888b54;

    float ni_bound_radius = *(float*)(this->niNode_0x18 + 0x4C);
    float scale_factor = this->scale_0x98;
    float radius_mult = this->radiusMult_0x34;

    return ni_bound_radius * scale_factor * radius_mult;
}
```

**NiBound layout** (at NiNode + 0x40):
```
+0x00  float  center_x
+0x04  float  center_y
+0x08  float  center_z
+0x0C  float  radius
```

The bounding sphere radius at NiNode+0x4C is the NiBound radius computed from the 3D model.

## Tier 3: Narrow Phase -- Per-Type Collision Resolution

### Collision Pair Dispatch (FUN_005a8810)

After sweep-and-prune identifies overlapping pairs and bounding spheres confirm proximity,
the collision pair is dispatched based on object types:

```c
void ProcessCollisionPair(int* pair_data) {
    int* obj_a = pair_data;
    int* obj_b = pair_data;  // Second object from pair

    // Check object types via vtable RTTI (class ID 0x8125 = DamageableObject/Ship)
    if (IsType(obj_a, 0x8125)) {
        // Ship-to-ship collision (or ship-to-damageable)
        HandleShipShipCollision(obj_a, obj_b);  // FUN_005a61c0
    }
    else if (IsType(obj_a, 0x8009) || IsType(obj_b, 0x8009)) {
        // Torpedo collision (class 0x8009)
        Torpedo_DetectCollision(projectile, target);  // FUN_00579010
    }
    else if (IsType(obj_a, 0x8007) && IsType(obj_b, 0x8007)) {
        // Generic physics object collision
        HandlePhysicsCollision(obj_a, obj_b);  // FUN_005a88e0
    }
}
```

### Ship-Ship Collision (FUN_005a61c0)

```c
void HandleShipShipCollision(Ship* ship_a, Ship* ship_b) {
    // Check if overlap is real (hash table lookup)
    if (!CheckOverlap(ship_a, ship_b)) return;

    // Get world positions via vtable+0x94
    Vec3* pos_a = ship_a->GetWorldTranslation();
    Vec3* pos_b = ship_b->GetWorldTranslation();

    // Get bounding radii via vtable+0xE4 (GetModelBound)
    float radius_a = GetBoundRadius(ship_a);  // *(float*)(GetModelBound(a) + 0x0C)
    float radius_b = GetBoundRadius(ship_b);  // (if ship_a->byte_0x7C == 0)

    // Compute gap = distance - radius_a - radius_b
    float gap = sqrt(dist_sq) - radius_a;
    if (!ship_a->byte_0x7C)
        gap -= radius_b;

    // If gap < 0 (spheres overlap): post collision event
    if (gap < 0.0) {
        PostCollisionEvent(ship_a, ship_b);  // FUN_005a63a0
    }
    else if (gap > 0.0 && was_previously_colliding) {
        // Separation: post end-collision event
        PostCollisionEvent(ship_a, ship_b);
    }
}
```

### Physics Object Collision (FUN_005a88e0)

For generic physics objects (type 0x8007), the collision includes:

1. **Eligibility check** (FUN_005946a0): both objects must have `collision_enabled_0x1A8` flag set
2. **Velocity threshold**: both objects must have velocity^2 > DAT_008942dc (minimum speed for collision)
3. **Angular momentum check**: rotational energy is also checked against threshold
4. **Contact history check**: prevents re-triggering if already in contact
5. **Detailed intersection**: Uses `vtable+0x148` (BeginIntersectionTest) and `vtable+0x150` (detailed mesh test)

```c
void HandlePhysicsCollision(Object* obj_a, Object* obj_b) {
    if (!CollisionEligible(obj_a, obj_b)) return;
    if (!g_CollisionDamageEnabled) return;  // DAT_008e5f58 check

    // Velocity threshold check
    Vec3* vel_a = GetVelocity(obj_a);  // FUN_005a05a0 -> NiNode+0x98
    Vec3* vel_b = GetVelocity(obj_b);
    float speed_sq_a = vel_a->x^2 + vel_a->y^2 + vel_a->z^2;
    float speed_sq_b = vel_b->x^2 + vel_b->y^2 + vel_b->z^2;

    // Both must be below velocity threshold (rest check)
    if (speed_sq_a <= DAT_008942dc && speed_sq_b <= DAT_008942dc) {
        // Also check angular momentum...
        // If both are essentially stationary: skip
        if (angular_energy_a <= threshold && angular_energy_b <= threshold) {
            if (NotAlreadyInContact(obj_a, obj_b))
                return;  // Both at rest, not already touching
        }
    }

    // Initialize collision result structure
    CollisionResult result;  // 88 bytes (0x58)
    InitCollisionResult(&result);  // FUN_0058a1a0

    // Perform intersection test
    if (obj_a->BeginIntersectionTest()) {
        // Fill result for obj_a
        FillCollisionData(&result, 0, obj_a->frame_0x36, velocity_a, position_a, angular_vel_a);
        // Fill result for obj_b
        FillCollisionData(&result, 1, obj_b->frame_0x36, velocity_b, position_b, angular_vel_b);

        // Execute detailed mesh intersection
        obj_a->PerformIntersection();  // vtable+0x150
        obj_b->PerformIntersection();
    }

    // Cleanup
    DestroyCollisionResult(&result);  // FUN_0058a1c0
}
```

### Torpedo Collision (FUN_00579010)

Torpedoes use a different intersection method:

```c
void Torpedo_DetectCollision(Torpedo* torpedo, Object* target) {
    if (target == NULL) return;
    if (torpedo->dead_0x24) return;
    if (target->dead_0x24) return;  // target->byte[0x24*4 + 0x24]
    if (target->object_id == torpedo->owner_id_0x128) return;  // Can't hit launcher

    // Branch based on target type
    if (IsType(target, 0x8007)) {
        // Mesh-level intersection test
        Vec3 contact_point, velocity;
        torpedo->GetWorldTranslation(&contact_point, &velocity);

        bool hit = target->TestIntersection(torpedo->collision_shape + 0x150, contact_point);

        if (hit) {
            // Time-of-impact refinement (up to 2 iterations)
            while (iterations < 2) {
                if (contact_distance <= 0.0) {
                    torpedo->dead = true;
                    torpedo->TriggerDestruction();  // vtable+0x50
                    break;
                }
                // Refine time of impact
                torpedo->time_to_impact = contact_distance / speed * torpedo->original_toi;
                hit = target->TestIntersection(torpedo->collision_shape, updated_position);
            }
        }
    }
    else {
        // Simpler check for non-mesh objects
        HandleSimpleTorpedoCollision(torpedo, target);
    }
}
```

## Collision Result Structure (0x58 bytes)

Used by FUN_005a88e0 for physics collisions.

```
Offset  Size  Type         Field                    Notes
------  ----  ----         -----                    -----
0x00    1     byte         initialized              Set by InitCollisionResult
0x04    28    PerObj[0]    object_a_data            7 floats: frame, pos(3), vel(3)
0x20    28    PerObj[1]    object_b_data            Same layout for object B
0x3C    4     int          (unknown)                Init 0
0x40    4     int          contact_count            Number of contact entries
0x44    4     void*        contact_list_head        Linked list of contact nodes
0x48    4     void*        contact_list_tail
0x4C    4     void*        contact_free_pool        Free pool for reuse
0x50    4     void*        contact_chunk_list       Allocated memory chunks
0x54    4     int          mode                     Init 2
```

### Per-Object Collision Data (FUN_005a8c70)

Written at `this + param_1 * 0x1C + 4`:
```
+0x00  int    frame_number          Object's physics frame counter
+0x04  float  position_x            World position X
+0x08  float  position_y            World position Y
+0x0C  float  position_z            World position Z
+0x10  float  velocity_x            Linear velocity X
+0x14  float  velocity_y            Linear velocity Y
+0x18  float  velocity_z            Linear velocity Z
```

## Collision Energy Calculation

### DoDamage_CollisionContacts (FUN_005952D0)

The collision energy/force that feeds into the damage system is computed as follows:

```c
void DoDamage_CollisionContacts(Ship* this, CollisionEvent* event) {
    int num_contacts = event->num_points;        // event+0x38
    float total_force = event->collision_force;   // event+0x40
    float mass = this->mass_0xD8;                 // ship mass from property

    // Compute damage per contact point
    float raw_damage = (total_force / mass) / num_contacts;
    float damage = raw_damage * DAT_00893f28 + DAT_0088bf28;
    //                          ^scale factor   ^base offset

    // Clamp to maximum
    if (damage > DAT_008887a8) {
        damage = 0.5;  // 0x3f000000 = 0.5f
    }

    for (int i = 0; i < num_contacts; i++) {
        Vec3 contact_point = event->GetPoint(i);

        // Transform to ship-local coordinates
        Vec3 local = contact_point - ship->NiNode->world_position;
        float inv_scale = DAT_00888860 / ship->NiNode->bound_radius;
        Vec3 normalized = MatrixMultiply(local, ship->NiNode->rotation_matrix) * inv_scale;

        // Apply damage at this position
        DoDamage(this, &normalized, damage, DAT_45bb8000);
        //                                  ^6000.0 max damage cap
    }
}
```

### Force Computation in CollisionEvent

The `collision_force` float (event+0x40) is computed by the collision response system
during the physics tick. It represents the magnitude of the impulse applied during the
collision, which depends on:

- **Relative velocity** of the two objects at the contact point
- **Mass** of the objects involved
- **Coefficient of restitution** (bounce factor)

The force is computed in the physics engine's collision response phase (the mesh intersection
handlers at vtable+0x150), which runs AFTER detection confirms overlap.

### Damage Formula Summary

```
per_contact_damage = clamp((force / mass / num_contacts) * SCALE + OFFSET, 0, 0.5)
total_damage_per_contact = per_contact_damage * 6000.0 (max damage cap)
```

Where:
- `force` = CollisionEvent+0x40 (collision impulse magnitude)
- `mass` = ship+0xD8 (from ShipProperty)
- `num_contacts` = CollisionEvent+0x38
- `SCALE` = DAT_00893f28 (tuning constant)
- `OFFSET` = DAT_0088bf28 (base damage threshold)

## Call Graph Summary

```
FUN_0040ffb0 (SimulationTick)
  |
  +-> FUN_005856d0 (BuildCollisionPairsForSets)    <-- 0x005857FF is here
  |     |
  |     +-> FUN_00585910 (CollectObjectsFromSet)     -- per-Set object enumeration
  |     +-> FUN_005671d0 (CheckCollision)             -- 79,605 calls/15-min
  |     |     |
  |     |     +-> FUN_0056c350 (IsDead check)
  |     |     +-> FUN_005ab670 (CastToShip)
  |     |     +-> FUN_00599290 (ExclusionListCheck)   -- event 0x800E filter
  |     |     +-> FUN_00567640 (SphereIntersection)   -- bounding sphere test
  |     |     |     |
  |     |     |     +-> vtable+0x94 (GetWorldTranslation) x2
  |     |     |     +-> FUN_00410570 (ComputeDistance)     -- Euclidean + modifiers
  |     |     |     +-> FUN_00567190 (GetCombinedRadius)   -- NiBound * scale * mult
  |     |     |
  |     |     +-> FUN_00567830 (StaticCollisionCheck)  -- terrain/static geometry
  |     |
  |     +-> [Results stored in global collision pair set at 0x0098d328-0x0098d33C]
  |
  +-> FUN_005a83a0 (ProximityManager::Update)
        |
        +-> FUN_005a8470 (UpdateAABBEndpoints)     -- per-object AABB refresh
        +-> FUN_005a8500 (SweepAxis) x3            -- sweep-and-prune per axis
        |     |
        |     +-> FUN_005a9250 (SwapEndpoints)     -- bubble-sort swap
        |     +-> FUN_005a9850/FUN_005a9820 (IncrementOverlap/DecrementOverlap)
        |     +-> FUN_005a7890 (CollisionFlagsCompatible)
        |     +-> FUN_005a9360 (CreateCollisionPair)
        |     +-> FUN_005a9390 (PairEquals)
        |
        +-> FUN_005a8740 (ProcessAllPairs)
              |
              +-> FUN_005a8810 (DispatchCollisionPair)
                    |
                    +-> FUN_005a61c0 (Ship-Ship)      -- class 0x8125
                    +-> FUN_00579010 (Torpedo-Object)  -- class 0x8009
                    +-> FUN_005a88e0 (Physics-Physics) -- class 0x8007
```

## Global Variables

| Address | Type | Name | Notes |
|---------|------|------|-------|
| 0x008e5f58 | byte | g_CollisionEnabled | SetPlayerCollisionsEnabled |
| 0x0098d328 | int | collisionPairCount | Active collision pair count |
| 0x0098d32c | void* | collisionPairListHead | Linked list head |
| 0x0098d330 | void* | collisionPairListTail | Linked list tail |
| 0x0098d334 | void* | collisionPairFreePool | Free pool for reuse |
| 0x0098d338 | void* | collisionPairChunks | Allocated memory chunks |
| 0x0098d33c | int | collisionPairPoolSize | Init 2 (entries per chunk) |
| 0x008942dc | float | velocityThresholdSq | Min speed^2 for physics collision |
| 0x0089054c | float | collisionCooldownTime | Timer threshold for re-collision |
| 0x00893f28 | float | damageScaleFactor | Collision damage tuning constant |
| 0x0088bf28 | float | damageBaseOffset | Collision damage base threshold |
| 0x008887a8 | float | maxDamagePerContact | 0.5 clamp value |
| 0x00888860 | float | normalizationConstant | Used in contact point normalization |
| 0x00888b54 | float | sentinelValue | Large float used as "infinite" distance |

## Event Types

| Event Code | Name | Notes |
|------------|------|-------|
| 0x00800050 | ET_OBJECT_COLLISION | Client-detected collision |
| 0x008000FC | ET_HOST_OBJECT_COLLISION | Host-validated collision |
| 0x00800053 | ET_COLLISION_BROADCAST | Effect broadcast to clients |
| 0x0000800E | (exclusion event) | Temporary collision cooldown |
| 0x00008124 | CT_COLLISION_EVENT | CollisionEvent class type ID |

## Object Type IDs (used in collision dispatch)

| Type ID | Name | Collision Behavior |
|---------|------|-------------------|
| 0x8125 | DamageableObject/Ship | Ship-ship: bounding sphere + event |
| 0x8009 | Torpedo/Projectile | Ray/sphere intersection, time-of-impact |
| 0x8008 | ShipClass | Subtype of DamageableObject |
| 0x8007 | PhysicsObject | Full mesh intersection, velocity-based |
| 0x8003 | GenericObject | Basic AABB overlap only |

## Key Design Decisions

1. **No triangle-mesh ship-ship detection**: Ship-to-ship collisions use ONLY bounding
   spheres. The NiBound radius (NiNode+0x4C) determines the collision volume. This is
   why large ships with elongated shapes can collide before they visually touch.

2. **Torpedoes use mesh intersection**: Unlike ships, torpedoes DO use detailed geometry
   tests (vtable+0x140/+0x150) to determine exact impact points.

3. **Sweep-and-prune is the workhorse**: With 79,605 CheckCollision calls per session,
   the broad-phase filtering is critical. The incremental sort means most frames only
   need a handful of swaps.

4. **Collision cooldown timer**: Object+0x98 acts as a cooldown to prevent
   rapid-fire collision events when two ships grind against each other.

5. **Client-authoritative detection**: Collision detection runs on the CLIENT, not the
   server. Clients send opcode 0x15 to the host, which validates distance and applies
   damage. This is why the dedicated server headless mode does NOT need to run collision
   detection itself.

6. **Velocity threshold for physics**: Objects at rest (velocity^2 < DAT_008942dc) are
   excluded from physics collision to avoid constant collision events from resting objects.

## Related Documents

- [docs/collision-effect-protocol.md](collision-effect-protocol.md) -- Network protocol for opcode 0x15
- [docs/damage-system.md](damage-system.md) -- Damage pipeline (collision -> hull/subsystem damage)
- [docs/cut-content-analysis.md](cut-content-analysis.md) -- Collision mesh voxelizer (cut debug tool)
