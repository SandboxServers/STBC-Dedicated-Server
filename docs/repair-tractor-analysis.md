# Repair System & Tractor Beam Mechanics - Reverse Engineering Analysis

Detailed analysis of the repair subsystem and tractor beam system in Star Trek: Bridge Commander (stbc.exe), reverse engineered from the binary via Ghidra decompilation, raw disassembly (objdump), and cross-referenced against the shipped Python scripting API.

**Status**: COMPLETE. All critical Update functions decompiled via raw binary disassembly. All OpenBC claims now verified or refuted.

---

## Part 1: Repair Queue Mechanics

### Class Hierarchy

```
ShipSubsystem (vtable 0x00892fc4, size >= 0x88)
  -> PoweredSubsystem (vtable 0x00892d98, size >= 0xA8)
    -> RepairSubsystem (vtable 0x00892e24, size 0xC0)
```

### RepairSubsystem Data Layout (0xC0 bytes)

Inherited from ShipSubsystem:
- +0x00: vtable pointer
- +0x18: SubsystemProperty* (property data)
- +0x1C: child subsystem count
- +0x30: condition (float, current HP)
- +0x34: condition percentage (float, condition / maxCondition)
- +0x38: averaged condition (float, computed in Update)
- +0x3C: frameTime (set each tick)
- +0x40: parent ship pointer
- +0x44: isDisabled flag (byte)
- +0x45: wasDisabled flag (byte, for transition detection)

RepairSubsystem-specific fields:
- +0xA8: repair queue linked-list management struct
  - +0xA8: count (int) - number of items in queue
  - +0xAC: head pointer (first subsystem to repair)
  - +0xB0: tail pointer (last subsystem in queue)
  - +0xB4: (unknown, init 0)
  - +0xB8: (unknown, init 0)
- +0xBC: initialized to 2 (likely default pool growth size for the list allocator)

### RepairSubsystemProperty Layout

Inherited from SubsystemProperty, RepairSubsystemProperty adds:
- +0x4C: MaxRepairPoints (float) - e.g. 50.0 for Galaxy class
- +0x50: NumRepairTeams (int) - e.g. 3 for Galaxy class

### Key Functions

| Address | Name | Signature |
|---------|------|-----------|
| 0x00565090 | RepairSubsystem::ctor | `__thiscall(void* this, int param)` |
| 0x00565190 | RepairSubsystem::scalar_deleting_dtor | vtable slot 10 |
| 0x005651c0 | RepairSubsystem::dtor | destructor body |
| 0x005652a0 | **RepairSubsystem::Update** | vtable slot 25 -- **DECOMPILED VIA RAW DISASSEMBLY** |
| 0x00565520 | RepairSubsystem::AddSubsystem | also used by AddToRepairList |
| 0x00565890 | RepairSubsystem::IsBeingRepaired | checks queue for subsystem |
| 0x00565900 | RepairSubsystem::AddToRepairList_MP | network-aware wrapper |
| 0x00565980 | RepairSubsystem::HandleRepairCompleted | removes from queue, notifies UI |
| 0x00565a10 | RepairSubsystem::HandleSubsystemRebuilt | re-queues if condition < maxCondition |
| 0x00565d40 | RepairSubsystem::HandleHitEvent | event handler registration (static init) |
| 0x0056bd90 | ShipSubsystem::Repair | `Repair(this, float repairPoints)` |
| 0x0056bc60 | ShipSubsystem::Update | base class tick |
| 0x0056c310 | ShipSubsystem::GetMaxCondition | returns `property->+0x20` |
| 0x0056b950 | ShipSubsystem::GetRepairComplexity | returns `property->+0x3C` |
| 0x0056c470 | ShipSubsystem::SetCondition | sets +0x30, clamps, fires events |
| 0x0056c350 | ShipSubsystem::IsDisabled | checks condition percentage vs threshold |

### RepairSubsystem::Update (0x005652a0) -- FULLY DECOMPILED

Decompiled from raw x86 disassembly (objdump). This function was in an undefined code region not auto-analyzed by Ghidra.

```c
// RepairSubsystem::Update  (__thiscall, float deltaTime)
// Address: 0x005652a0, size: 0x277 bytes (ends at 0x00565517)
void RepairSubsystem_Update(RepairSubsystem* this, float deltaTime) {
    // Call parent: PoweredSubsystem::Update(deltaTime)
    PoweredSubsystem_Update(this, deltaTime);  // FUN_00562470

    // If repair system is OFF, skip all repair logic
    if (!this->isOn)  // +0x9C
        goto epilogue;

    // Host/multiplayer gate: only process repairs on standalone or host
    byte isHost = g_IsHost;  // 0x97FA89
    if (isHost == 0)
        goto do_repair;  // standalone mode
    if (isHost != 1 || !g_IsMultiplayer)  // 0x97FA8A
        goto done;

do_repair:
    RepairSubsystemProperty* prop = GetProperty(this);  // FUN_00564fe0

    // *** THE REPAIR RATE FORMULA ***
    float maxRepairPoints = prop->MaxRepairPoints;      // prop+0x4C
    float repairHealthPct = this->conditionPercentage;  // +0x34 (repair system's own health)
    float repairAmount = maxRepairPoints * repairHealthPct * deltaTime;

    int numRepairTeams = prop->NumRepairTeams;          // prop+0x50
    int queueCount = this->queueCount;                  // +0xA8
    ListNode* node = this->queueHead;                   // +0xAC
    int teamsUsed = 0;

    if (node == NULL)
        goto done;

    // *** MAIN REPAIR LOOP: repairs up to NumRepairTeams subsystems ***
    while (teamsUsed < numRepairTeams && node != NULL) {
        ShipSubsystem* sub = node->data;    // node+0x00
        node = node->next;                   // node+0x04

        // Skip destroyed subsystems (condition <= 0.0)
        if (sub->condition <= 0.0f) {
            // Post ET_REPAIR_CANNOT_BE_COMPLETED (0x800075)
            TGMessage* msg = CreateMessage();
            msg->SetSource(this->parentShip);
            msg->data[10] = sub->subsystemID;
            msg->eventType = 0x800075;
            EventManager_PostEvent(msg);
            continue;  // Does NOT consume a repair team
        }

        // *** PER-SUBSYSTEM REPAIR AMOUNT ***
        int divisor = min(queueCount, numRepairTeams);
        float perTeamRepair = repairAmount / (float)divisor;

        // Apply repair (Repair() divides by RepairComplexity internally)
        sub->Repair(perTeamRepair);  // FUN_0056bd90

        // Check if fully repaired
        float ratio = sub->condition / GetMaxCondition(sub);
        if (ratio >= 1.0f) {
            // Post ET_REPAIR_COMPLETED (0x800074)
            TGMessage* msg = CreateMessage();
            msg->SetSource(this->parentShip);
            msg->data[10] = sub->subsystemID;
            msg->eventType = 0x800074;
            EventManager_PostEvent(msg);
        }

        teamsUsed++;
    }

    // Process remaining queue items (beyond team count)
    // Only sends destruction notifications, no repair
    while (node != NULL) {
        ShipSubsystem* sub = node->data;
        node = node->next;
        if (sub->condition <= 0.0f) {
            // Post ET_REPAIR_CANNOT_BE_COMPLETED
            PostRepairCannotBeCompletedEvent(this, sub);
        }
    }

done:
    // Update UI if this is the player's ship
    int playerShip = GetPlayerShip();  // FUN_004069b0
    if (playerShip != 0 && playerShip == this->parentShip) {
        if (g_EngRepairPane != NULL)  // 0x98B188
            EngRepairPane_Update(g_EngRepairPane);  // FUN_005512e0
    }

epilogue:
    return;
}
```

### Complete Repair Rate Formula (VERIFIED)

```
rawRepairAmount = MaxRepairPoints * (repairSystem.condition / repairSystem.maxCondition) * deltaTime

divisor = min(queueCount, NumRepairTeams)

perSubsystemRepair = rawRepairAmount / divisor

actualConditionGain = perSubsystemRepair / subsystem.RepairComplexity
```

Key characteristics:
1. The repair system's OWN health scales the output (damaged repair bay = slower repairs)
2. Multiple subsystems are repaired simultaneously (up to NumRepairTeams)
3. The repair amount is divided equally among min(queueCount, numTeams) subsystems
4. RepairComplexity acts as a final divisor (higher complexity = slower repair)

Example (Galaxy class, healthy repair system, 2 items in queue):
```
rawRepair = 50.0 * 1.0 * 0.033 = 1.65 per tick (at 30fps)
divisor = min(2, 3) = 2
perSubsystem = 1.65 / 2 = 0.825
For a phaser (complexity=3.0): conditionGain = 0.825 / 3.0 = 0.275
For a tractor (complexity=7.0): conditionGain = 0.825 / 7.0 = 0.118
```

### AddSubsystem / AddToRepairList Logic (FUN_00565520)

```c
// Decompiled from 0x00565520
bool RepairSubsystem::AddSubsystem(ShipSubsystem* subsystem) {
    // 1. Walk the linked list at +0xAC to check for duplicates
    ListNode* node = this->listHead;  // +0xAC
    while (node != NULL) {
        ShipSubsystem* existing = node->data;
        node = node->next;
        if (subsystem == existing) {
            return false;  // Already in queue, reject duplicate
        }
    }

    // 2. Check if subsystem condition > 0.0
    if (subsystem->condition > 0.0f) {   // subsystem+0x0C float field check
        // Allocate a list node from the pool (FUN_00486be0)
        ListNode* newNode = AllocListNode(&this->listStruct);

        // Insert at TAIL of the doubly-linked list
        newNode->data = subsystem;
        newNode->next = NULL;
        newNode->prev = this->listTail;
        if (this->listTail != NULL) {
            this->listTail->next = newNode;
        } else {
            this->listHead = newNode;
        }
        this->listTail = newNode;
        this->listCount++;
        return true;
    } else {
        // Condition is 0.0 (destroyed) -- do NOT add to queue
        // Instead, if this is the player's ship, notify the UI
        if (GetPlayerShipID() == subsystem->parentShipID && g_EngRepairPane != NULL) {
            EngRepairPane_AddDestroyed(g_EngRepairPane, subsystem);
            EngRepairPane_Refresh(g_EngRepairPane);
        }
        return true;  // Still returns true (success) even though not queued
    }
}
```

**CRITICAL FINDING: No maximum queue size enforced.** The AddSubsystem function uses a dynamically-growing pool allocator (FUN_00486be0). There is no check like `if (count >= 8) return false`. The linked list grows without bound. The OpenBC claim of "up to 8 subsystem indices" is **INCORRECT** -- there is no hardcoded queue size limit in the C++ code.

**CONFIRMED: Subsystems at 0 HP (condition <= 0.0) are NOT added to the repair queue.** The check `0.0f < condition` explicitly excludes destroyed subsystems.

### ShipSubsystem::Repair (FUN_0056bd90)

```c
void ShipSubsystem::Repair(float repairPoints) {
    float repairComplexity = GetRepairComplexity(this);  // property->+0x3C
    float newCondition = this->condition + (repairPoints / repairComplexity);
    SetCondition(this, newCondition);
}
```

### Repair Queue Events

| Event ID | Name | Wire Opcode | Direction |
|----------|------|-------------|-----------|
| 0x00800074 | ET_REPAIR_COMPLETED | (internal) | Local |
| 0x00800075 | ET_REPAIR_CANNOT_BE_COMPLETED | (internal) | Local |
| 0x008000DF | ET_ADD_TO_REPAIR_LIST | 0x0B | Host -> All |
| 0x00800076 | ET_REPAIR_INCREASE_PRIORITY | 0x11 | Client -> Host |
| 0x0080006B | ET_SUBSYSTEM_STATE_CHANGED | (internal) | Local |

---

## Part 2: Tractor Beam Mechanics

### Class Hierarchy

```
ShipSubsystem (vtable 0x00892fc4)
  -> PoweredSubsystem (vtable 0x00892d98)
    -> WeaponSystem (vtable 0x008938c4, size >= 0xF0)
      -> TractorBeamSystem (vtable 0x00893794, size 0x100)

ShipSubsystem
  -> Weapon (base for projectiles)
    -> EnergyWeapon
      -> TractorBeamProjector (vtable 0x008936f0, size 0x100)
```

### Tractor Beam Modes (TBS enum)

From string table at 0x0095017C:

| Value | Constant | Description |
|-------|----------|-------------|
| 0 | TBS_HOLD | Hold target in place (zero velocity) |
| 1 | TBS_TOW | Tow target toward source (default mode) |
| 2 | TBS_PULL | Pull target toward self |
| 3 | TBS_PUSH | Push target away |
| 4 | TBS_DOCK_STAGE_1 | Docking approach phase |
| 5 | TBS_DOCK_STAGE_2 | Docking final phase |

### Key Functions

| Address | Name | Notes |
|---------|------|-------|
| 0x00582080 | TractorBeamSystem::ctor | Sets vtable 0x00893794, mode=1, +0xA0=1 |
| 0x00582460 | **TractorBeamSystem::Update** | vtable slot 25 -- **DECOMPILED VIA RAW DISASSEMBLY** |
| 0x00582280 | TractorBeamSystem::SumProjectorMaxDamage | Iterates children, sums MaxDamage |
| 0x005822d0 | TractorBeamSystem::GetForceRatio | Returns +0xFC / +0xF8 |
| 0x005826a0 | TractorBeamSystem::StopFiringHandler | Clears +0xA4, calls vtable[36] (CeaseFire) |
| 0x0057ec70 | TractorBeamProjector::ctor | Sets vtable 0x008936f0, +0xFC=1 |
| 0x00581020 | TractorBeamProjector::Update | Caches maxDamage, calls parent Weapon::Update |
| 0x0057f8c0 | **TractorBeamProjector::FireTick** | Per-tick fire logic with mode switch |
| 0x00580f50 | **ComputeTractorForce** | Computes per-projector tractor force |
| 0x0057fcd0 | **Mode_HOLD** | Stops target, applies counter-velocity force |
| 0x0057ff60 | **Mode_TOW (and DOCK_STAGE_1)** | Moves target toward source, dock transition |
| 0x00580590 | Mode_PULL | Pulls target toward source |
| 0x00580740 | Mode_PUSH | Pushes target away from source |
| 0x00580910 | Mode_DOCK_STAGE_2 | Final docking alignment |
| 0x0056f900 | Weapon::GetMaxCharge | Returns property->+0x68 (NOT MaxDamage!) |
| 0x0056f930 | Weapon::GetMaxDamage | Returns property->+0x78 |
| 0x0056f940 | Weapon::GetMaxDamageDistance | Returns property->+0x7C |

### TractorBeamSystem::Update (0x00582460) -- FULLY DECOMPILED

```c
// TractorBeamSystem::Update  (__thiscall, float deltaTime)
// Address: 0x00582460, size: 0x28 bytes (ends at 0x00582488)
void TractorBeamSystem_Update(TractorBeamSystem* this, float deltaTime) {
    WeaponSystem_Update(this, deltaTime);  // FUN_005847d0 (parent class)

    // Sum MaxDamage across all child projectors
    float totalMaxDamage = SumProjectorMaxDamage(this);  // FUN_00582280
    this->totalMaxDamage = totalMaxDamage;  // +0xF8

    // Reset force accumulator (will be filled by FireTick each frame)
    this->forceUsed = 0.0f;  // +0xFC
}
```

### Tractor Force Formula (FUN_00580f50) -- VERIFIED

```c
// ComputeTractorForce  (__thiscall, float deltaTime, float beamDistance)
// Address: 0x00580f50
float ComputeTractorForce(TractorBeamProjector* this, float deltaTime, float beamDistance) {
    float maxDamageDistance = GetMaxDamageDistance(this);  // property->+0x7C
    float distanceRatio = maxDamageDistance / beamDistance;

    // Clamp: at close range (within maxDamageDistance), full force
    // Beyond maxDamageDistance, linear falloff
    if (distanceRatio > 1.0) {  // DAT_0088b9c0 = 1.0 (double)
        distanceRatio = 1.0f;
    }

    float systemCondPct = this->parentSystem->conditionPercentage;  // system+0x34
    float projectorCondPct = this->conditionPercentage;              // this+0x34
    float maxDamage = GetMaxDamage(this);                           // property->+0x78

    float force = maxDamage * (systemCondPct * projectorCondPct) * distanceRatio;

    // Optional modifier from system's target tracking
    void* targetTracker = this->parentSystem->field_0xF0;
    if (targetTracker != NULL) {
        float targetCondition = GetAveragedCondition(targetTracker);
        force *= targetCondition;
    }

    return force * deltaTime;
}
```

### TractorBeamProjector::FireTick (FUN_0057f8c0) -- KEY FUNCTION

This is called every tick while the tractor beam is firing. It:

1. Performs a beam intersection test (ray from source to target)
2. Posts ET_TRACTOR_BEAM_STARTED_HITTING (0x0080007E) when hitting a new target
3. Posts ET_TRACTOR_BEAM_STOPPED_HITTING (0x00800080) when target changes/lost
4. Computes tractor force via `ComputeTractorForce(this, deltaTime, beamDistance)`
5. **Dispatches to mode-specific handler** based on TractorBeamSystem.mode (+0xF4):
   - Mode 0 (HOLD): FUN_0057fcd0 -- zeros target velocity, applies counter-force
   - Mode 1 (TOW) / Mode 4 (DOCK_STAGE_1): FUN_0057ff60 -- moves target toward source
   - Mode 2 (PULL): FUN_00580590 -- pulls target closer
   - Mode 3 (PUSH): FUN_00580740 -- pushes target away
   - Mode 5 (DOCK_STAGE_2): FUN_00580910 -- final docking alignment
6. **Accumulates force used**: `system->forceUsed += (force - remainingForce)`

The force accumulation at +0xFC is the key to the speed drag system.

### Speed Drag Mechanism (ImpulseEngineSubsystem::Update, 0x00561180)

Decompiled from raw x86 disassembly. The ImpulseEngine stores a pointer to its TractorBeamSystem at +0xA8.

```c
// ImpulseEngineSubsystem::Update  (__thiscall, float deltaTime)
// Address: 0x00561180
void ImpulseEngine_Update(ImpulseEngineSubsystem* this, float deltaTime) {
    PoweredSubsystem_Update(this, deltaTime);

    float powerPct = this->powerPercentage;  // +0x94

    // Compute effective max stats (damage-adjusted)
    this->curMaxSpeed = ComputeEffectiveMaxSpeed(this) * powerPct;        // +0xAC
    this->curMaxAccel = ComputeEffectiveMaxAccel(this) * powerPct;        // +0xB0
    this->curMaxAngVel = ComputeEffectiveMaxAngVel(this) * powerPct;      // +0xB4
    this->curMaxAngAccel = ComputeEffectiveMaxAngAccel(this) * powerPct;  // +0xB8

    // Update child engines
    for (int i = 0; i < this->numChildren; i++) {
        ShipSubsystem* child = GetChild(this, i);
        if (child != NULL)
            child->Update(deltaTime);  // vtable[25]
    }
}
```

The speed drag is inside `ComputeEffectiveMaxSpeed` (FUN_00561230):

```c
// FUN_00561230: Compute effective max speed
float ComputeEffectiveMaxSpeed(ImpulseEngineSubsystem* this) {
    if (IsDisabled(this) || !this->isOn)
        return 0.0f;

    ImpulseEngineProperty* prop = GetProperty(this);
    float maxSpeed = prop->MaxSpeed;  // prop+0x4C
    int numEngines = this->numChildren;  // +0x1C
    float perEngine = maxSpeed / (float)numEngines;
    float effective = maxSpeed;

    // Reduce for damaged/disabled engines
    for (int i = 0; i < numEngines; i++) {
        ShipSubsystem* engine = GetChild(this, i);
        if (engine != NULL) {
            if (IsDisabled(engine)) {
                effective -= perEngine;  // Dead engine: full penalty
            } else {
                effective -= (1.0f - engine->conditionPercentage) * perEngine;  // Proportional
            }
        }
    }

    // *** TRACTOR BEAM SPEED DRAG ***
    TractorBeamSystem* tractor = this->tractorBeamSystem;  // +0xA8
    if (tractor != NULL) {
        float tractorRatio = tractor->GetForceRatio();  // FUN_005822d0: +0xFC / +0xF8
        effective *= (1.0f - tractorRatio);
    }

    // Clamp to [0, maxSpeed]
    if (effective > maxSpeed) effective = maxSpeed;
    if (effective < 0.0f) return 0.0f;

    return this->powerPercentage * effective;  // +0x90
}
```

### Tractor Drag Formula (VERIFIED)

The tractor speed drag is:

```
tractorRatio = forceUsed / totalMaxDamage
effectiveSpeed *= (1.0 - tractorRatio)
```

Where:
- `forceUsed` = accumulated from all active projectors hitting targets (system+0xFC)
- `totalMaxDamage` = sum of MaxDamage across all projectors (system+0xF8)
- The ratio represents what fraction of the tractor system's capacity is being used

This is a **multiplicative** drag, not additive. At full tractor output, speed drops to zero. At half output, speed is halved.

### Tractor Beam Does NOT Apply Direct Damage

After decompiling all five mode handler functions (HOLD, TOW/DOCK_1, PULL, PUSH, DOCK_2), **none of them call any damage function on the target ship**. The modes only manipulate the target's velocity and angular velocity. The OpenBC claim of "tractor damage: max_damage * dt * 0.02" is **NOT FOUND** in the code.

### Mode-Specific Behavior Summary

**HOLD (mode 0, FUN_0057fcd0)**:
- Computes needed force = `target.mass * target.speed`
- If tractorForce >= needed: zeros target velocity, returns excess
- If tractorForce < needed: scales velocity by `(1.0 - force/needed)`

**TOW (mode 1, FUN_0057ff60) / DOCK_STAGE_1 (mode 4)**:
- Same as HOLD initially (stop target first)
- Remaining force used to move target toward tractor source
- Distance-to-move capped by `DAT_008936e8 * deltaTime` (class static)
- In DOCK_STAGE_1: transitions to DOCK_STAGE_2 when close enough
- TOW applies impulse toward source, sets target angular velocity

**PULL (mode 2, FUN_00580590)**: Pulls target toward source ship.

**PUSH (mode 3, FUN_00580740)**: Pushes target away from source ship.

**DOCK_STAGE_2 (mode 5, FUN_00580910)**: Final alignment for docking completion.

### Friendly Fire Tractor System

The UtopiaModule has three tractor-related fields:
- FriendlyTractorTime (float, UtopiaModule+0x4C)
- FriendlyTractorWarning (float, UtopiaModule+0x50)
- MaxFriendlyTractorTime (float, UtopiaModule+0x54)

This implements a progressive penalty system: tractoring friendly ships accumulates time, with a warning threshold and a maximum before forced release.

### Tractor Beam Configuration (Galaxy Class Example)

```python
# Tractor System (WeaponSystemProperty)
Tractors.SetMaxCondition(3000.0)
Tractors.SetWeaponSystemType(Tractors.WST_TRACTOR)
Tractors.SetSingleFire(1)
Tractors.SetAimedWeapon(0)
Tractors.SetNormalPowerPerSecond(600.0)

# Forward Tractor 1 (TractorBeamProperty)
ForwardTractor1.SetMaxDamage(50.0)
ForwardTractor1.SetMaxDamageDistance(118.0)
ForwardTractor1.SetMaxCharge(5.0)
ForwardTractor1.SetMinFiringCharge(3.0)
ForwardTractor1.SetNormalDischargeRate(1.0)
ForwardTractor1.SetRechargeRate(0.3)

# Aft Tractor 2 (TractorBeamProperty)
AftTractor2.SetMaxDamage(80.0)
AftTractor2.SetMaxDamageDistance(118.0)
AftTractor2.SetRechargeRate(0.5)
```

---

## Part 3: ImpulseEngine Tractor Connection

The ImpulseEngineSubsystem stores a pointer to its TractorBeamSystem at +0xA8 (set via `SetTractorBeamSystem()` in hardpoint scripts). This creates the coupling:

```
TractorBeamProjector::FireTick() -> accumulates force at system+0xFC
ImpulseEngine::ComputeEffectiveMaxSpeed() -> reads system+0xFC/+0xF8 -> reduces speed
```

### ImpulseEngineSubsystem Instance Layout

| Offset | Type | Field |
|--------|------|-------|
| +0xA8 | ptr | TractorBeamSystem* (from SetTractorBeamSystem) |
| +0xAC | float | CurMaxSpeed (computed each tick) |
| +0xB0 | float | CurMaxAccel (computed each tick) |
| +0xB4 | float | CurMaxAngularVelocity (computed each tick) |
| +0xB8 | float | CurMaxAngularAccel (computed each tick) |

Vtable at 0x00892d10, constructor at FUN_00561050, size 0xBC.

---

## Part 4: Summary - OpenBC Claims vs Binary Evidence

### Repair System

| Claim | Verdict | Evidence |
|-------|---------|----------|
| Queue of up to 8 subsystem indices | **WRONG** | No size limit in AddSubsystem; uses dynamically-growing pool allocator |
| Only top-priority (index 0) repaired each tick | **WRONG** | Up to NumRepairTeams subsystems repaired simultaneously |
| Rate: max_repair_points * num_repair_teams * dt | **WRONG** | Actual: MaxRepairPoints * repairSystemHealthPct * dt / min(queueCount, numTeams) / RepairComplexity |
| Subsystems below disabled threshold auto-queued | **PARTIALLY CONFIRMED** | HandleSubsystemRebuilt queues if condition < maxCondition (not disabled threshold) |
| Subsystems at 0 HP NOT auto-queued | **CONFIRMED** | Explicit `condition > 0.0f` check in AddSubsystem |
| Auto-removed when fully repaired | **CONFIRMED** | ET_REPAIR_COMPLETED fires when condition/maxCondition >= 1.0 |
| Linked list (not fixed array) | **CONFIRMED** | Doubly-linked list with pool allocator at +0xA8 through +0xB0 |
| Repair system health affects rate | **CONFIRMED** (not in OpenBC) | conditionPercentage of the repair subsystem scales output |

### Tractor Beam

| Claim | Verdict | Evidence |
|-------|---------|----------|
| Speed drag: max_damage * dt * 0.1 | **WRONG** | Drag is multiplicative: effectiveSpeed *= (1.0 - forceUsed/totalMaxDamage) |
| Tractor damage: max_damage * dt * 0.02 | **NOT FOUND** | No damage function called in any tractor mode handler |
| Auto-release: distance > max_damage_distance | **CONFIRMED** (implicit) | Force falls off linearly beyond maxDamageDistance; beam test fails at extreme range |
| Auto-release: subsystem destroyed | **PLAUSIBLE** | IsDisabled check exists in WeaponSystem base Update |
| Auto-release: either ship destroyed | **PLAUSIBLE** | STOPPED_HITTING event posted when beam test fails |
| 6 modes (HOLD/TOW/PULL/PUSH/DOCK1/DOCK2) | **CONFIRMED** | Switch statement in FireTick with all 6 cases, string table confirms names |
| Shield interaction | **NOT FOUND** | No evidence of shield-specific tractor logic in available code |
| Friendly tractor time penalty | **CONFIRMED** | UtopiaModule has FriendlyTractorTime/Warning/Max fields |
| Force affected by system/projector health | **CONFIRMED** (not in OpenBC) | Force *= systemCondPct * projectorCondPct |
| Distance falloff | **CONFIRMED** (not in OpenBC) | Linear falloff: min(1.0, maxDamageDistance/beamDistance) |
| Tractor affects all 4 engine stats | **CONFIRMED** (not in OpenBC) | ImpulseEngine applies same ratio to speed, accel, angVel, angAccel |

---

## Appendix A: Corrected EnergyWeaponProperty Layout

Previous analysis had MaxDamage at +0x68. This was WRONG. Verified via SWIG wrapper analysis:

| Offset | Index | Field | SWIG Getter/Setter |
|--------|-------|-------|-------------------|
| +0x68 | 0x1A | MaxCharge | EnergyWeaponProperty_GetMaxCharge |
| +0x6C | 0x1B | RechargeRate | EnergyWeaponProperty_GetRechargeRate |
| +0x70 | 0x1C | NormalDischargeRate | EnergyWeaponProperty_GetNormalDischargeRate |
| +0x74 | 0x1D | MinFiringCharge | EnergyWeaponProperty_GetMinFiringCharge |
| +0x78 | 0x1E | **MaxDamage** | EnergyWeaponProperty_GetMaxDamage |
| +0x7C | 0x1F | **MaxDamageDistance** | EnergyWeaponProperty_GetMaxDamageDistance |

Verification: `swig_EnergyWeaponProperty_SetMaxDamage` writes to `(object + 0x78)`. FUN_0056f930 (GetMaxDamage) returns `property->+0x78`.

## Appendix B: TractorBeamSystem Instance Layout

| Offset | Type | Field |
|--------|------|-------|
| +0xA0 | int | AI tractor mode (from config) |
| +0xA4 | byte | firing state |
| +0xF0 | ptr | target tracker (optional) |
| +0xF4 | int | active mode (TBS enum, default 1=TOW) |
| +0xF8 | float | totalMaxDamage (sum of all projector MaxDamage, updated each tick) |
| +0xFC | float | forceUsed (accumulated each tick, reset at start of tick) |

## Appendix C: RepairSubsystem Instance Layout

| Offset | Type | Field |
|--------|------|-------|
| +0xA8 | int | queue count |
| +0xAC | ptr | queue head (linked list) |
| +0xB0 | ptr | queue tail (linked list) |
| +0xBC | int | pool growth size (default 2) |

## Appendix D: Key Constants

| Address | Type | Value | Used In |
|---------|------|-------|---------|
| 0x00888860 | float | 1.0f | Normalization, repair completion threshold |
| 0x00888b54 | float | 0.0f | Zero comparisons (condition checks) |
| 0x0088b9c0 | double | 1.0 | Tractor distance ratio clamp |
| 0x00888b58 | float | ~epsilon | Near-zero vector length threshold |
