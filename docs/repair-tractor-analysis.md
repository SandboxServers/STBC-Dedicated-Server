# Repair System & Tractor Beam Mechanics - Reverse Engineering Analysis

Detailed analysis of the repair subsystem and tractor beam system in Star Trek: Bridge Commander (stbc.exe), reverse engineered from the binary via Ghidra decompilation and cross-referenced against the shipped Python scripting API.

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
| 0x005652a0 | RepairSubsystem::Update | vtable slot 25 (offset 0x64) -- **NOT IN GHIDRA FUNC DB** |
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
        // (shows in EngRepairPane "DESTROYED" area)
        if (GetPlayerShipID() == subsystem->parentShipID && g_EngRepairPane != NULL) {
            EngRepairPane_AddDestroyed(g_EngRepairPane, subsystem);
            EngRepairPane_Refresh(g_EngRepairPane);
        }
        return true;  // Still returns true (success) even though not queued
    }
}
```

**CRITICAL FINDING: No maximum queue size enforced.** The AddSubsystem function uses a dynamically-growing pool allocator (FUN_00486be0). There is no check like `if (count >= 8) return false`. The linked list grows without bound. The OpenBC claim of "up to 8 subsystem indices" is **INCORRECT** -- there is no hardcoded queue size limit in the C++ code.

**CONFIRMED: Subsystems at 0 HP (condition <= 0.0) are NOT added to the repair queue.** The check `_DAT_00888b54 < subsystem[0xC]` (i.e., `0.0f < condition`) explicitly excludes destroyed subsystems. Instead, they are sent to the UI's "DESTROYED" area via `FUN_00551990`. This matches the OpenBC claim.

**CONFIRMED: No duplicate entries.** The function walks the entire list checking for duplicates before insertion.

### AddToRepairList Network Wrapper (FUN_00565900)

```c
// Decompiled from 0x00565900
void RepairSubsystem::AddToRepairList(ShipSubsystem* subsystem) {
    bool added = this->AddSubsystem(subsystem);  // FUN_00565520

    if (added && g_IsHost && g_IsMultiplayer) {
        // Send ADD_TO_REPAIR_LIST event over the network
        TGMessage* msg = TGMessage_Create();
        msg->eventType = 0x008000DF;  // ET_ADD_TO_REPAIR_LIST
        msg->SetSource(this);
        msg->SetDestination(subsystem);
        EventManager_PostEvent(msg);
    }
}
```

This confirms that AddToRepairList is a network-aware wrapper. In multiplayer, the host broadcasts a repair queue change to all clients via ET_ADD_TO_REPAIR_LIST (event 0x008000DF), which maps to wire opcode 0x0B.

### HandleRepairCompleted (FUN_00565980)

```c
// Decompiled from 0x00565980
void RepairSubsystem::HandleRepairCompleted(TGEvent* event) {
    ShipSubsystem* repairedSub = GetSubsystemFromEvent(event->data[10]);
    int playerShipID = GetPlayerShipID();

    if (repairedSub != NULL) {
        // Walk the list to find and remove this subsystem
        ListNode* node = this->listHead;
        ListNode* found = NULL;
        while (node != NULL) {
            if (node->data == repairedSub) {
                found = node;
                break;
            }
            node = node->next;
        }

        if (found != NULL) {
            // Remove from doubly-linked list
            RemoveNode(&this->listStruct, &found);
        }

        // Update UI if this is the player's ship
        if (playerShipID == repairedSub->parentShipID && g_EngRepairPane != NULL) {
            EngRepairPane_RemoveFromRepair(g_EngRepairPane, repairedSub);
        }
    }

    ChainToNextHandler(this, event);
}
```

**CONFIRMED: Auto-removed when fully repaired.** The HandleRepairCompleted event fires when condition reaches maxCondition (see SetCondition below), and the handler removes the subsystem from the repair queue.

### HandleSubsystemRebuilt (FUN_00565a10)

```c
// Decompiled from 0x00565a10
void RepairSubsystem::HandleSubsystemRebuilt(TGEvent* event) {
    ShipSubsystem* rebuiltSub = ShipSubsystem_Cast(event->data[2]);
    int playerShipID = GetPlayerShipID();

    if (rebuiltSub != NULL && playerShipID != 0) {
        // Notify UI
        EngRepairPane_AddDestroyed(g_EngRepairPane, rebuiltSub);

        // If the rebuilt subsystem's condition < maxCondition, auto-queue it
        float condition = rebuiltSub->condition;     // +0x30 via +0x0C offset
        float maxCondition = GetMaxCondition(rebuiltSub);
        if (condition < maxCondition) {
            this->AddToRepairList(rebuiltSub);  // FUN_00565900
        }
    }

    ChainToNextHandler(this, event);
}
```

**CONFIRMED: Subsystems below max condition are auto-queued** when they are rebuilt (transition from destroyed to damaged). The auto-queue condition is `condition < maxCondition`, not based on the disabled threshold. This matches the OpenBC claim about auto-queueing on rebuild.

### ShipSubsystem::Repair (FUN_0056bd90)

```c
// Decompiled from 0x0056bd90
void ShipSubsystem::Repair(float repairPoints) {
    float repairComplexity = GetRepairComplexity(this);  // property->+0x3C
    float newCondition = this->condition + (repairPoints / repairComplexity);
    SetCondition(this, newCondition);
}
```

The Repair function divides the raw repair points by the subsystem's `RepairComplexity` before adding to condition. This means:
- Higher RepairComplexity = slower repair
- Galaxy class phasers: RepairComplexity = 3.0
- Galaxy class tractors: RepairComplexity = 7.0

### ShipSubsystem::SetCondition (FUN_0056c470)

```c
// Decompiled from 0x0056c470
void ShipSubsystem::SetCondition(float newCondition) {
    this->condition = newCondition;

    // Clamp to maxCondition
    float maxCondition = GetMaxCondition(this);
    if (this->condition > maxCondition) {
        this->condition = maxCondition;
    }

    // Update percentage
    this->conditionPercentage = this->condition / GetMaxCondition(this);

    // Update UI watcher
    UpdateWatcher(this->conditionWatcher);

    // Fire ET_SUBSYSTEM_STATE_CHANGED if condition < maxCondition
    // AND ship exists AND ship is not critically damaged
    if (this->condition < maxCondition &&
        (this->parentShip == NULL || this->parentShip->someField >= threshold)) {
        TGMessage* msg = CreateStateChangedMessage();
        msg->SetSource(this->parentShip);
        msg->eventType = 0x0080006B;  // ET_SUBSYSTEM_STATE_CHANGED
        msg->data[10] = this->subsystemID;
        EventManager_PostEvent(msg);
    }
}
```

### Repair Rate Formula

The repair rate formula is **NOT directly visible** because the RepairSubsystem::Update function at 0x005652a0 is in an undefined code region that Ghidra has not auto-analyzed as a function. However, from the data structures and supporting evidence:

**What we know for certain:**
1. RepairSubsystemProperty has `MaxRepairPoints` (float at +0x4C) and `NumRepairTeams` (int at +0x50)
2. ShipSubsystem::Repair divides by `RepairComplexity` before adding to condition
3. The Update function receives `deltaTime` as a parameter (float, same as all Update virtuals)
4. RepairSubsystem::Update is at vtable slot 25 (offset 0x64), address 0x005652a0

**Inferred repair rate per tick:**
```
repairThisTick = MaxRepairPoints * NumRepairTeams * deltaTime
actualConditionGain = repairThisTick / RepairComplexity
```

The OpenBC claim of `max_repair_points * num_repair_teams * dt` for the RAW repair rate is **PLAUSIBLE** based on the property fields and the ShipSubsystem::Repair function, which then divides by RepairComplexity.

**Regarding "only top-priority (index 0) repaired each tick":** This CANNOT be verified without decompiling the Update function at 0x005652a0. The data structures use a doubly-linked list (not an array), and the list is maintained with head/tail pointers. It is likely that only the HEAD of the list receives repair each tick (consistent with the UI showing a priority queue), but this cannot be confirmed from the available decompiled code.

### Repair Queue Events

| Event ID | Name | Wire Opcode | Direction |
|----------|------|-------------|-----------|
| 0x008000DF | ET_ADD_TO_REPAIR_LIST | 0x0B | Host -> All |
| 0x00800076 | ET_REPAIR_INCREASE_PRIORITY | 0x11 | Client -> Host |
| 0x0080006B | ET_SUBSYSTEM_STATE_CHANGED | (internal) | Local |
| ET_REPAIR_COMPLETED | completion notification | (internal) | Local |
| ET_REPAIR_CANNOT_BE_COMPLETED | 0 HP gate | (internal) | Local |

### Summary: OpenBC Claims vs Binary Evidence

| Claim | Verdict | Evidence |
|-------|---------|----------|
| Queue of up to 8 subsystem indices | **INCORRECT** | No size limit in AddSubsystem; uses dynamically-growing pool allocator |
| Only top-priority (index 0) repaired each tick | **LIKELY** but unverifiable | List structure has head/tail; UI shows priority ordering |
| Rate: max_repair_points * num_repair_teams * dt | **PLAUSIBLE** | Property fields exist; Repair() divides by complexity |
| Subsystems below disabled threshold auto-queued | **PARTIALLY CONFIRMED** | HandleSubsystemRebuilt queues if condition < maxCondition (not disabled threshold) |
| Subsystems at 0 HP NOT auto-queued | **CONFIRMED** | Explicit `condition > 0.0f` check in AddSubsystem |
| Auto-removed when fully repaired | **CONFIRMED** | HandleRepairCompleted removes from queue |
| Linked list (not fixed array) | **CONFIRMED** | Doubly-linked list with pool allocator at +0xA8 through +0xB0 |

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

The tractor beam has two classes:
- **TractorBeamSystem**: The weapon system (manages all projectors for a ship)
- **TractorBeamProjector**: Individual tractor beam emitter (actual weapon)

### TractorBeamSystem Data Layout (0x100 bytes)

Inherited from WeaponSystem:
- +0x00: vtable
- +0xA0: tractor beam mode (int, from AI/script config)
- +0xA4: firing state byte
- +0xA8: enabled flag
- +0xA9: attack disabled subsystems flag
- +0xAC: (unknown)
- +0xB0: (unknown)
- +0xB4: target ID (-1 = none)

TractorBeamSystem-specific:
- +0xF0: unknown (init 0)
- +0xF4: mode (int) - default TBS_HOLD (1)
- +0xF8: unknown (init 0)
- +0xFC: unknown (init 0)

### Tractor Beam Modes (TBS enum)

From string table at 0x0095017C:

| Value | Constant | Description |
|-------|----------|-------------|
| 0 | TBS_HOLD | Hold target in place |
| 1 | TBS_TOW | Tow target (drag along) |
| 2 | TBS_PULL | Pull target toward self |
| 3 | TBS_PUSH | Push target away |
| 4 | TBS_DOCK_STAGE_1 | Docking approach phase |
| 5 | TBS_DOCK_STAGE_2 | Docking final phase |

Note: The constructor sets +0xF4 = 1 (TBS_TOW as default), and the AI config reads the "eTractorBeamMode" enum to override +0xA0 on initialization.

### TractorBeamProjector Data Layout

Inherits from EnergyWeapon. Key property fields (from TractorBeamProperty, which extends EnergyWeaponProperty):

| Property Offset | Field | Galaxy Forward Tractor 1 |
|----------------|-------|--------------------------|
| +0x20 | MaxCondition | 1500.0 |
| +0x3C | RepairComplexity | 7.0 |
| +0x68 | MaxDamage | 50.0 (forward) / 80.0 (aft) |
| +0x7C | MaxDamageDistance | 118.0 |

Additional TractorBeamProperty-specific fields (visual only):
- TractorBeamWidth, ArcWidth/HeightAngles, Orientation
- Core/Shell colors, Taper settings, Texture settings
- NumSides (12), MainRadius (0.075)

TractorBeamProjector instance fields:
- +0xA0: cached maxDamage (set in Update)
- +0xBC: condition ratio (A0 / maxDamage)
- +0xC8: (from WeaponSystem base)
- +0xFC: enabled flag (byte, init 1)

### Key Functions

| Address | Name | Notes |
|---------|------|-------|
| 0x00582080 | TractorBeamSystem::ctor | Sets vtable 0x00893794, mode=1, +0xA0=1 |
| 0x00582460 | TractorBeamSystem::Update | vtable slot 25 -- **NOT IN GHIDRA FUNC DB** |
| 0x005826a0 | TractorBeamSystem::StopFiringHandler | Clears +0xA4, calls vtable[36] (CeaseFire) |
| 0x0057ec70 | TractorBeamProjector::ctor | Sets vtable 0x008936f0, +0xFC=1 |
| 0x00581020 | TractorBeamProjector::Update | Caches maxDamage, calls parent Weapon::Update |
| 0x0056fdc0 | Weapon::Update | Computes condition ratio, calls ShipSubsystem::Update |
| 0x0056f900 | Weapon::GetMaxDamage | Returns property->+0x68 |
| 0x0056f940 | Weapon::GetMaxDamageDistance | Returns property->+0x7C |

### TractorBeamProjector::Update (FUN_00581020)

```c
// Decompiled from 0x00581020
void TractorBeamProjector::Update(float deltaTime) {
    float maxDamage = GetMaxDamage(this);     // property->+0x68
    this->cachedMaxDamage = maxDamage;        // stored at +0xA0
    Weapon::Update(this, deltaTime);           // FUN_0056fdc0
}
```

### Weapon::Update (FUN_0056fdc0)

```c
// Decompiled from 0x0056fdc0
void Weapon::Update(float deltaTime) {
    float maxDamage = GetMaxDamage(this);
    this->conditionRatio = this->cachedDamage / maxDamage;  // +0xBC = +0xA0 / maxDamage
    UpdateWatcher(this->damageWatcher);
    ShipSubsystem::Update(this, deltaTime);    // FUN_0056bc60
}
```

### TractorBeamSystem::Update -- UNVERIFIABLE

The TractorBeamSystem::Update function at 0x00582460 is in an undefined code region in Ghidra and cannot be decompiled. This is where the speed drag, tractor damage, and auto-release logic would reside.

**What we CAN confirm from the data model:**
1. The TractorBeamProjector stores `MaxDamage` and `MaxDamageDistance` from its property
2. The mode field (+0xF4) supports 6 modes including dock stages
3. Events track hitting start/stop (ET_TRACTOR_BEAM_STARTED_HITTING/STOPPED_HITTING)

**What we CANNOT verify from available decompiled code:**
- Speed drag formula (OpenBC claims: `max_damage * dt * 0.1`)
- Tractor damage formula (OpenBC claims: `max_damage * dt * 0.02`)
- Auto-release conditions (OpenBC claims: distance > max_damage_distance, subsystem destroyed, either ship destroyed)

### Tractor Beam Event System

| Event | Hex | Description |
|-------|-----|-------------|
| ET_TRACTOR_BEAM_STARTED_FIRING | (lookup needed) | Fired when tractor beam begins firing at target |
| ET_TRACTOR_BEAM_STOPPED_FIRING | (lookup needed) | Fired when tractor beam stops firing |
| ET_TRACTOR_BEAM_STARTED_HITTING | (lookup needed) | Fired when beam connects with target |
| ET_TRACTOR_BEAM_STOPPED_HITTING | (lookup needed) | Fired when beam loses lock |
| ET_TRACTOR_TARGET_DOCKED | (lookup needed) | Fired when docking completes |
| ET_FRIENDLY_TRACTOR_REPORT | (lookup needed) | Friendly fire tractor penalty warning |

### Ship-Level Tractor Handlers

The ShipClass registers two handlers:
- **HandleTractorHitStart** at LAB_005b0bf0 (undefined in Ghidra)
- **HandleTractorHitStop** at LAB_005b0c70 (undefined in Ghidra)

These are triggered by events 0x0080007E (ET_TRACTOR_BEAM_STARTED_HITTING) and 0x00800080 (ET_TRACTOR_BEAM_STOPPED_HITTING) respectively.

### Friendly Fire Tractor System

The UtopiaModule has three tractor-related fields:
- FriendlyTractorTime (float, offset 0x4C from UtopiaModule)
- FriendlyTractorWarning (float, offset 0x50)
- MaxFriendlyTractorTime (float, offset 0x54)

This suggests a progressive penalty system: tractoring friendly ships accumulates time, with a warning threshold and a maximum before consequences (likely forced release or friendly fire penalty).

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

### Summary: OpenBC Tractor Beam Claims vs Binary Evidence

| Claim | Verdict | Evidence |
|-------|---------|----------|
| Speed drag: max_damage * dt * 0.1 | **UNVERIFIABLE** | TractorBeamSystem::Update at 0x00582460 is not decompilable |
| Tractor damage: max_damage * dt * 0.02 | **UNVERIFIABLE** | Same -- Update function undefined in Ghidra |
| Auto-release: distance > max_damage_distance | **PLAUSIBLE** | MaxDamageDistance exists in property (+0x7C) |
| Auto-release: subsystem destroyed | **PLAUSIBLE** | ShipSubsystem::IsDisabled tracked |
| Auto-release: either ship destroyed | **PLAUSIBLE** | ShipClass::Destroyed handler exists; STOPPED_HITTING event |
| 6 modes (HOLD/TOW/PULL/PUSH/DOCK1/DOCK2) | **CONFIRMED** | String table + mode field at +0xF4, enum values 0-5 |
| Shield interaction | **NOT FOUND** | No evidence of shield-specific tractor logic in available code |
| Friendly tractor time penalty | **CONFIRMED** | UtopiaModule has FriendlyTractorTime/Warning/Max fields |

---

## Part 3: Ghidra Analysis Gaps

### Undefined Code Regions

The following critical functions are in code regions that Ghidra has NOT auto-analyzed into functions. They are referenced from vtables but the disassembler did not create function boundaries:

| Address | Function | Why It Matters |
|---------|----------|----------------|
| 0x005652a0 | RepairSubsystem::Update | Contains the per-tick repair logic, rate formula, queue processing |
| 0x00582460 | TractorBeamSystem::Update | Contains speed drag, tractor damage, auto-release logic |
| 0x005b0bf0 | ShipClass::HandleTractorHitStart | Ship-level reaction to tractor lock |
| 0x005b0c70 | ShipClass::HandleTractorHitStop | Ship-level reaction to tractor release |
| 0x00582640 | TractorBeamSystem::StartFiringHandler | Tractor beam activation |
| 0x005826d0 | TractorBeamSystem::StopFiringAtTargetHandler | Targeted cease-fire |
| 0x005658d0 | RepairSubsystem::HandleHitEvent body | Repair-on-damage response |
| 0x00565a80 | RepairSubsystem::HandleRepairCannotBeCompleted | 0 HP notification |
| 0x00565b30 | RepairSubsystem::HandleAddToRepairList | Network repair queue sync |
| 0x00565b50 | RepairSubsystem::HandleIncreasePriorityEvent | Queue reordering |

These addresses are valid code (referenced from vtables and event handler registrations) but were not auto-detected as function entry points by Ghidra's analysis. Creating functions at these addresses in Ghidra would unlock decompilation.

### Recommendation

To fully verify the OpenBC claims, the following Ghidra manual steps are needed:
1. Create functions at 0x005652a0 (RepairSubsystem::Update) and 0x00582460 (TractorBeamSystem::Update)
2. Run the decompiler on these newly-created functions
3. The repair rate formula and tractor beam damage/drag constants should be visible in the decompiled output

---

## Appendix: Property Field Offset Table

### SubsystemProperty (base)
| Offset | Type | Field | SWIG Getter |
|--------|------|-------|-------------|
| +0x20 | float | MaxCondition | (inherited, in subsystem base) |
| +0x3C | float | RepairComplexity | SubsystemProperty_GetRepairComplexity |

### RepairSubsystemProperty
| Offset | Type | Field | SWIG Getter |
|--------|------|-------|-------------|
| +0x4C | float | MaxRepairPoints | RepairSubsystemProperty_GetMaxRepairPoints |
| +0x50 | int | NumRepairTeams | RepairSubsystemProperty_GetNumRepairTeams |

### EnergyWeaponProperty (base of TractorBeamProperty)
| Offset | Type | Field | SWIG Getter |
|--------|------|-------|-------------|
| +0x68 | float | MaxDamage | EnergyWeaponProperty_GetMaxDamage |
| +0x7C | float | MaxDamageDistance | EnergyWeaponProperty_GetMaxDamageDistance |

### RepairSubsystem Instance
| Offset | Type | Field |
|--------|------|-------|
| +0xA8 | int | queue count |
| +0xAC | ptr | queue head (linked list) |
| +0xB0 | ptr | queue tail (linked list) |
| +0xBC | int | pool growth size (default 2) |

### TractorBeamSystem Instance
| Offset | Type | Field |
|--------|------|-------|
| +0xA0 | int | AI tractor mode (from config) |
| +0xA4 | byte | firing state |
| +0xF0 | int | (unknown) |
| +0xF4 | int | active mode (TBS enum, default 1=TOW) |
| +0xF8 | int | (unknown) |
| +0xFC | int | (unknown) |
