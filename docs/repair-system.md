# Repair System — Complete Reverse Engineering

Comprehensive RE of Bridge Commander's repair subsystem: queue data structure, repair rate formula, priority toggle algorithm, event handler chain, Engineering panel UI integration, and all three network paths. Verified against the stbc.exe binary via Ghidra decompilation and live packet traces.

Consolidates findings from:
- [repair-tractor-analysis.md](repair-tractor-analysis.md) — Initial repair queue RE (Update, AddSubsystem, IsBeingRepaired)
- [repair-event-object-ids.md](repair-event-object-ids.md) — TGObject ID assignment, event serialization chain
- [pythonevent-wire-format.md](pythonevent-wire-format.md) — PythonEvent (opcode 0x06) wire format, 3 event classes
- [combat-mechanics-re.md](combat-mechanics-re.md) — Repair summary in consolidated combat doc

---

## Class Hierarchy

```
ShipSubsystem (vtable 0x00892fc4, size >= 0x88)
  -> PoweredSubsystem (vtable 0x00892d98, size >= 0xA8)
    -> RepairSubsystem (vtable 0x00892e24, size 0xC0)
```

One RepairSubsystem per ship, stored at ship+0x2D8.

---

## RepairSubsystem Data Layout (0xC0 bytes)

### Inherited from ShipSubsystem

| Offset | Type | Field |
|--------|------|-------|
| +0x00 | ptr | vtable |
| +0x04 | int | TGObject network ID (auto-assigned from global counter) |
| +0x18 | ptr | SubsystemProperty* (RepairSubsystemProperty) |
| +0x1C | int | child subsystem count |
| +0x30 | float | condition (current HP) |
| +0x34 | float | conditionPercentage (condition / maxCondition) |
| +0x38 | float | averagedCondition |
| +0x3C | float | frameTime (set each tick) |
| +0x40 | ptr | parent ship pointer |
| +0x44 | byte | isDisabled flag |
| +0x45 | byte | wasDisabled flag (transition detection) |

### Inherited from PoweredSubsystem

| Offset | Type | Field |
|--------|------|-------|
| +0x9C | byte | isOn (subsystem enabled) |

### RepairSubsystem-specific

| Offset | Type | Field |
|--------|------|-------|
| +0xA8 | int | queue count |
| +0xAC | ptr | queue head (ListNode*) |
| +0xB0 | ptr | queue tail (ListNode*) |
| +0xB4 | ptr | free list (recycled nodes) |
| +0xB8 | ptr | block list (for bulk deallocation) |
| +0xBC | int | pool growth size (default 2) |

---

## RepairSubsystemProperty Layout

Inherits SubsystemProperty. Repair-specific fields:

| Offset | Type | Field |
|--------|------|-------|
| +0x20 | float | MaxCondition (from SubsystemProperty) |
| +0x3C | float | RepairComplexity (from SubsystemProperty) |
| +0x4C | float | MaxRepairPoints (e.g. 50.0 for Sovereign) |
| +0x50 | int | NumRepairTeams (e.g. 3 for Sovereign) |

---

## Queue Data Structure

### Linked List Nodes (12 bytes each)

```
ListNode:
  +0x00: data   (void*)     -- pointer to the queued ShipSubsystem
  +0x04: next   (ListNode*) -- next node toward tail
  +0x08: prev   (ListNode*) -- previous node toward head
```

### Pool Allocator

Nodes are allocated from a pool managed by the linked list struct at +0xA8:
- `FUN_00486be0` — allocate node from pool (grows pool if free list empty)
- `FUN_00486ca0` — free node back to free list
- Pool growth size (default 2): allocates this many nodes when pool exhausted
- No maximum queue size — dynamically growing, no hardcoded limit

---

## Complete Function Table

| Address | Name | Signature |
|---------|------|-----------|
| 0x00565090 | RepairSubsystem::ctor | `__thiscall(void* this, int param)` |
| 0x00565190 | RepairSubsystem::scalar_deleting_dtor | vtable slot 10 |
| 0x005651c0 | RepairSubsystem::dtor | destructor body |
| 0x005652a0 | **RepairSubsystem::Update** | vtable slot 25, main repair tick |
| 0x00565520 | **RepairSubsystem::AddSubsystem** | internal queue-add (duplicate check, 0 HP gate) |
| 0x00565890 | **RepairSubsystem::IsBeingRepaired** | walks first N nodes |
| 0x00565900 | **RepairSubsystem::AddToRepairList_MP** | network-aware wrapper |
| 0x00565980 | **RepairSubsystem::HandleRepairCompleted** | removes from queue |
| 0x00565a10 | **RepairSubsystem::HandleSubsystemRebuilt** | re-queues if condition < max |
| 0x00565a80 | **RepairSubsystem::HandleRepairCannotBeCompleted** | removes from queue + shows destroyed UI |
| 0x00565b30 | **RepairSubsystem::HandleAddToRepairList** | SP-only gate |
| 0x00565b50 | **RepairSubsystem::HandleIncreasePriority** | TOGGLE algorithm |
| 0x005658d0 | **RepairSubsystem::HandleHitEvent** | catches SUBSYSTEM_HIT |
| 0x00565cd0 | **RepairSubsystem::HandleSetPlayer** | UI config on player assignment |
| 0x00565d30 | RepairSubsystem::UpdateRepairPane | updates EngRepairPane if player's ship |
| 0x00565d40 | RepairSubsystem::RegisterHandlers | 7 handler registrations (static init) |
| 0x00565dd0 | RepairSubsystem::RegisterEventTypes | 3 event-to-handler bindings |
| 0x00564fe0 | RepairSubsystem::GetProperty | returns this->property (cast) |

### Related Functions (other classes)

| Address | Name | Notes |
|---------|------|-------|
| 0x0056bd90 | ShipSubsystem::Repair | `condition += repairPoints / RepairComplexity` |
| 0x0056c310 | ShipSubsystem::GetMaxCondition | returns property->+0x20 |
| 0x0056b950 | ShipSubsystem::GetRepairComplexity | returns property->+0x3C |
| 0x0056c470 | ShipSubsystem::SetCondition | posts SUBSYSTEM_HIT when damaged |
| 0x004069b0 | GetPlayerShip | returns local player's ship ptr |
| 0x005666e0 | LinkedList::RemoveNode | removes and frees a node |
| 0x00486be0 | LinkedList::AllocNode | allocate from pool |
| 0x00486ca0 | LinkedList::FreeNode | return to free list |
| 0x006f0ee0 | TGObject::LookupByID | hash table lookup by network ID |
| 0x006d90e0 | TGEventResponder::ForwardEvent | forwards event to next handler |
| 0x006da300 | EventManager::PostEvent | posts event with auto-release |
| 0x006a1150 | HostEventHandler | serializes repair events as opcode 0x06 |

---

## Decompiled Functions

### Update (0x005652a0) — Main Repair Tick

The core repair loop, runs every frame on host/standalone only.

```c
void RepairSubsystem_Update(RepairSubsystem* this, float deltaTime) {
    PoweredSubsystem_Update(this, deltaTime);  // FUN_00562470

    if (!this->isOn)  // +0x9C
        return;

    // Host/multiplayer gate: only process repairs on standalone or host
    byte isHost = g_IsHost;  // 0x97FA89
    if (isHost == 0)
        goto do_repair;  // standalone mode
    if (isHost != 1 || !g_IsMultiplayer)  // 0x97FA8A
        return;

do_repair:
    RepairSubsystemProperty* prop = GetProperty(this);  // FUN_00564fe0

    // THE REPAIR RATE FORMULA
    float maxRepairPoints = prop->MaxRepairPoints;      // prop+0x4C
    float repairHealthPct = this->conditionPercentage;  // +0x34
    float repairAmount = maxRepairPoints * repairHealthPct * deltaTime;

    int numRepairTeams = prop->NumRepairTeams;          // prop+0x50
    int queueCount = this->queueCount;                  // +0xA8
    ListNode* node = this->queueHead;                   // +0xAC
    int teamsUsed = 0;

    if (node == NULL)
        goto done;

    // MAIN REPAIR LOOP: repairs up to NumRepairTeams subsystems
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

        // PER-SUBSYSTEM REPAIR AMOUNT
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
}
```

### AddSubsystem (0x00565520) — Internal Queue-Add

```c
bool RepairSubsystem::AddSubsystem(ShipSubsystem* subsystem) {
    // 1. Walk the linked list to check for duplicates
    ListNode* node = this->queueHead;  // +0xAC
    while (node != NULL) {
        ShipSubsystem* existing = node->data;
        node = node->next;
        if (subsystem == existing)
            return false;  // Already in queue, reject duplicate
    }

    // 2. Check if subsystem condition > 0.0
    if (subsystem->condition > 0.0f) {
        // Allocate a list node from the pool
        ListNode* newNode = AllocListNode(&this->listStruct);  // FUN_00486be0

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
        return true;  // Returns true (success) even though not queued
    }
}
```

### AddToRepairList_MP (0x00565900) — Network-Aware Wrapper

```c
void RepairSubsystem::AddToRepairList_MP(RepairSubsystem* this, ShipSubsystem* subsystem) {
    bool added = AddSubsystem(this, subsystem);  // FUN_00565520

    if (added && g_IsHost && g_IsMultiplayer) {
        // Create TGEvent (factory 0x0101 — TGSubsystemEvent)
        TGEvent* evt = TGEvent_ctor(alloc(0x28), 0);  // auto-assign ID

        evt->eventType = 0x008000DF;      // ET_ADD_TO_REPAIR_LIST
        TGEvent_SetDest(evt, this);        // dest = RepairSubsystem (evt+0x0C)
        TGEvent_SetSource(evt, subsystem); // source = damaged subsystem (evt+0x08)

        EventManager_PostEvent(evt);       // FUN_006da2a0
        // HostEventHandler catches this and sends opcode 0x06 to "NoMe" group
    }
}
```

### IsBeingRepaired (0x00565890)

```c
bool RepairSubsystem::IsBeingRepaired(RepairSubsystem* this, ShipSubsystem* target) {
    ListNode* node = this->queueHead;     // +0xAC
    RepairSubsystemProperty* prop = GetProperty(this);  // FUN_00564fe0
    int numTeams = prop->NumRepairTeams;  // prop+0x50
    int checked = 0;

    while (checked < numTeams && node != NULL) {
        ShipSubsystem* sub = node->data;
        node = node->next;
        if (sub == target)
            return true;  // target is within the active repair slots
        checked++;
    }
    return false;  // target is waiting or not in queue
}
```

### HandleRepairCompleted (0x00565980)

Called when a subsystem reaches max HP. Removes from queue and updates UI.

```c
void RepairSubsystem::HandleRepairCompleted(RepairSubsystem* this, TGCharEvent* event) {
    int subsysID = event->charData;  // event+0x28 (subsystem's TGObject network ID)
    ShipSubsystem* subsystem = TGObject_LookupByID(subsysID);  // FUN_006f0ee0
    int playerShip = GetPlayerShip();  // FUN_004069b0

    if (subsystem != NULL) {
        // Walk the queue to find the node
        ListNode* cursor = this->queueHead;  // +0xAC
        ListNode* foundNode = NULL;
        while (cursor != NULL) {
            foundNode = cursor;
            ShipSubsystem* nodeData = cursor->data;
            cursor = cursor->next;
            if (subsystem == nodeData) break;
        }

        // Remove from queue if found
        if (foundNode != NULL) {
            LinkedList_RemoveNode(&this->listStruct, &foundNode);  // FUN_005666e0
        }

        // If this is the player's ship, update the repair pane
        if (playerShip == subsystem->parentShip && g_EngRepairPane != NULL) {
            EngRepairPane_RefreshRepairItem(g_EngRepairPane, subsystem);  // FUN_00551990
        }
    }

    TGEventResponder_ForwardEvent(this, event);  // FUN_006d90e0
}
```

### HandleRepairCannotBeCompleted (0x00565a80)

Called when a subsystem is destroyed while in the repair queue. Removes from queue AND shows the "destroyed" UI indicator (unlike HandleRepairCompleted which only removes).

```c
void RepairSubsystem::HandleRepairCannotBeCompleted(RepairSubsystem* this, TGCharEvent* event) {
    int subsysID = event->charData;  // event+0x28
    ShipSubsystem* subsystem = TGObject_LookupByID(subsysID);  // FUN_006f0ee0
    int playerShip = GetPlayerShip();  // FUN_004069b0

    if (subsystem != NULL) {
        // Walk the queue to find the node
        ListNode* cursor = this->queueHead;  // +0xAC
        ListNode* foundNode = NULL;
        while (cursor != NULL) {
            foundNode = cursor;
            ShipSubsystem* nodeData = cursor->data;
            cursor = cursor->next;
            if (subsystem == nodeData) break;
        }

        // Remove from queue if found
        if (foundNode != NULL) {
            LinkedList_RemoveNode(&this->listStruct, &foundNode);  // FUN_005666e0
        }

        // If this is the player's ship, update UI AND show "destroyed" indicator
        if (playerShip == subsystem->parentShip && g_EngRepairPane != NULL) {
            EngRepairPane_RefreshRepairItem(g_EngRepairPane, subsystem);  // FUN_00551990
            EngRepairPane_ShowDestroyed(g_EngRepairPane, subsystem);      // FUN_00551870
        }
    }

    TGEventResponder_ForwardEvent(this, event);  // FUN_006d90e0
}
```

### HandleSubsystemRebuilt (0x00565a10)

Called when a destroyed subsystem is rebuilt (e.g. via script). Re-queues if not yet at full HP.

```c
void RepairSubsystem::HandleSubsystemRebuilt(RepairSubsystem* this, TGEvent* event) {
    ShipSubsystem* subsystem = GetSubsystemFromEvent(event);  // FUN_0056b8f0(event+0x08)
    int playerShip = GetPlayerShip();  // FUN_004069b0

    if (subsystem != NULL && playerShip != 0) {
        // Refresh UI
        EngRepairPane_RefreshRepairItem(g_EngRepairPane, subsystem);  // FUN_00551990

        // If condition < maxCondition, re-queue for continued repair
        float condition = subsystem->condition;  // +0x30
        float maxCondition = GetMaxCondition(subsystem);  // FUN_0056c310
        if (condition < maxCondition) {
            AddToRepairList_MP(this, subsystem);  // FUN_00565900
        }
    }

    TGEventResponder_ForwardEvent(this, event);  // FUN_006d90e0
}
```

### HandleAddToRepairList (0x00565b30) — Singleplayer-Only Gate

In multiplayer, opcode 0x0B handles AddToRepairList via GenericEventForward. This local handler is only active in singleplayer.

```c
void RepairSubsystem::HandleAddToRepairList(RepairSubsystem* this, TGEvent* event) {
    if (g_IsMultiplayer != 0) return;  // SP-ONLY gate

    ShipSubsystem* subsystem = event->source;  // event+0x08
    AddToRepairList_MP(this, subsystem);        // FUN_00565900
}
```

### HandleIncreasePriority (0x00565b50) — The Toggle Algorithm

This is the priority reordering handler, triggered by opcode 0x11 (RepairListPriority). The algorithm is a **binary toggle**, NOT "move up one position":

- If the subsystem IS currently being actively repaired (within the first `NumRepairTeams` nodes): **demote to TAIL**
- If the subsystem is NOT being actively repaired (waiting area): **promote to HEAD**

```c
void RepairSubsystem::HandleIncreasePriority(RepairSubsystem* this, TGObjPtrEvent* event) {
    int subsysID = event->obj_ptr;  // event+0x28 (int32 TGObject network ID)
    ShipSubsystem* targetSub = TGObject_LookupByID(subsysID);  // FUN_006f0ee0

    if (targetSub == NULL) goto done;

    // Walk the queue to find the node containing this subsystem
    ListNode* head = this->queueHead;  // +0xAC
    if (head == NULL) goto update_ui;

    ListNode* foundNode = head;
    while (true) {
        ShipSubsystem* nodeData = foundNode->data;
        ListNode* nextNode = foundNode->next;
        if (targetSub == nodeData) break;
        if (nextNode == NULL) goto update_ui;
        foundNode = nextNode;
    }

    if (foundNode == NULL) goto update_ui;

    // Check if this subsystem is currently being actively repaired
    bool wasBeingRepaired = IsBeingRepaired(this, targetSub);  // FUN_00565890

    // === REMOVE THE NODE FROM THE DOUBLY-LINKED LIST ===
    LinkedList* list = &this->listStruct;  // this+0xA8

    if (foundNode == list->head) {
        ListNode* newHead = foundNode->next;
        list->head = newHead;
        if (newHead == NULL) list->tail = NULL;
        else newHead->prev = NULL;
    } else if (foundNode == list->tail) {
        ListNode* newTail = foundNode->prev;
        list->tail = newTail;
        if (newTail == NULL) list->head = NULL;
        else newTail->next = NULL;
    } else {
        ListNode* prevNode = foundNode->prev;
        ListNode* nextNode = foundNode->next;
        if (prevNode != NULL) prevNode->next = nextNode;
        if (nextNode != NULL) nextNode->prev = prevNode;
    }

    LinkedList_FreeNode(list, foundNode);  // FUN_00486ca0
    list->count--;

    // === RE-INSERT AT NEW POSITION (THE TOGGLE) ===
    if (wasBeingRepaired) {
        // WAS BEING REPAIRED → INSERT AT TAIL (demote)
        ListNode* newNode = LinkedList_AllocNode(list);
        newNode->data = targetSub;
        newNode->next = NULL;
        newNode->prev = list->tail;
        if (list->tail != NULL) {
            list->tail->next = newNode;
            list->tail = newNode;
        } else {
            list->head = newNode;
            list->tail = newNode;
        }
    } else {
        // WAS NOT BEING REPAIRED → INSERT AT HEAD (promote)
        ListNode* newNode = LinkedList_AllocNode(list);
        newNode->data = targetSub;
        newNode->prev = NULL;
        newNode->next = list->head;
        if (list->head != NULL) {
            list->head->prev = newNode;
        } else {
            list->tail = newNode;
        }
        list->head = newNode;
    }

    list->count++;

update_ui:
    RepairSubsystem_UpdateRepairPane(this);  // FUN_00565d30

done:
    TGEventResponder_ForwardEvent(this, event);  // FUN_006d90e0
}
```

### HandleHitEvent (0x005658d0)

Catches SUBSYSTEM_HIT events and auto-adds the damaged subsystem to the repair queue.

```c
void RepairSubsystem::HandleHitEvent(RepairSubsystem* this, TGObjPtrEvent* event) {
    int subsystemID = event->obj_ptr;  // event+0x28 (int32 TGObject network ID)
    ShipSubsystem* sub = TGObject_LookupByID(subsystemID);  // FUN_006f0ee0

    if (sub != NULL) {
        AddToRepairList_MP(this, sub);  // FUN_00565900
    }

    TGEventResponder_ForwardEvent(this, event);  // FUN_006d90e0
}
```

### HandleSetPlayer (0x00565cd0)

Called when the player's ship changes (e.g. at game start or spectator switch). Reconfigures the Engineering repair pane to track the new ship's repair subsystem.

```c
void RepairSubsystem::HandleSetPlayer(TGEvent* event) {
    void* repairPane = g_EngRepairPane;  // DAT_0098b188
    int playerShip = GetPlayerShip();    // FUN_004069b0
    if (repairPane == NULL) return;

    ShipClass* ship = CastToShipClass(event->source);  // FUN_005ab670

    if (playerShip == ship) return;  // already tracking this ship

    EngRepairPane_ClearAll(repairPane);  // FUN_00551230
    if (playerShip == 0) return;

    RepairSubsystem* newRepairSub = playerShip->repairSubsystem;  // ship+0x2D8
    EngRepairPane_SetRepairSubsystem(repairPane, newRepairSub);    // FUN_00550ef0

    RepairSubsystemProperty* prop = GetProperty(newRepairSub);     // FUN_00564fe0
    int numTeams = prop->NumRepairTeams;                            // prop+0x50
    EngRepairPane_SetNumTeams(repairPane, numTeams);                // FUN_00550ee0
}
```

### ShipSubsystem::Repair (0x0056bd90)

```c
void ShipSubsystem::Repair(float repairPoints) {
    float repairComplexity = GetRepairComplexity(this);  // property->+0x3C
    float newCondition = this->condition + (repairPoints / repairComplexity);
    SetCondition(this, newCondition);  // FUN_0056c470
}
```

---

## Event Handler Registration

### Handler Registration (0x00565d40) — 7 Handlers

Two registration functions (`FUN_006da130` for per-instance handlers, `FUN_006da160` for static handlers):

| Address | Handler | Debug String | Registration Type |
|---------|---------|-------------|-------------------|
| 0x005658d0 | HandleHitEvent | `RepairSubsystem::HandleHitEvent` | Per-instance (006da130) |
| 0x00565980 | HandleRepairCompleted | `RepairSubsystem::HandleRepairCompleted` | Per-instance (006da130) |
| 0x00565a10 | HandleSubsystemRebuilt | `RepairSubsystem::HandleSubsystemRebuilt` | Per-instance (006da130) |
| 0x00565a80 | HandleRepairCannotBeCompleted | `RepairSubsystem::HandleRepairCannotBeCompleted` | Per-instance (006da130) |
| 0x00565b50 | HandleIncreasePriority | `RepairSubsystem::HandleIncreasePriorityEvent` | Per-instance (006da130) |
| 0x00565b30 | HandleAddToRepairList | `RepairSubsystem::HandleAddToRepairList` | Per-instance (006da130) |
| 0x00565cd0 | HandleSetPlayer | `RepairSubsystem::HandleSetPlayer` | Static (006da160) |

### Event Type Registration (0x00565dd0) — 3 Event-to-Handler Bindings

```c
void RepairSubsystem_RegisterEventTypes(void) {
    // Per-instance event handlers (FUN_006d92b0)
    RegisterEventHandler(0x00800076, "HandleIncreasePriorityEvent");  // ET_REPAIR_INCREASE_PRIORITY
    RegisterEventHandler(0x008000DF, "HandleAddToRepairList");        // ET_ADD_TO_REPAIR_LIST

    // Static event handler (FUN_006db380)
    RegisterStaticHandler(0x0080000E, "HandleSetPlayer");             // ET_SET_PLAYER
}
```

---

## Event Type Constants

| Code | Constant Name | Direction | Description |
|------|--------------|-----------|-------------|
| 0x008000DF | ET_ADD_TO_REPAIR_LIST | Host → All (opcode 0x06) | Subsystem added to repair queue |
| 0x00800074 | ET_REPAIR_COMPLETED | Host → All (opcode 0x06) | Subsystem fully repaired, removed from queue |
| 0x00800075 | ET_REPAIR_CANNOT_BE_COMPLETED | Host → All (opcode 0x06) | Subsystem destroyed while queued |
| 0x00800076 | ET_REPAIR_INCREASE_PRIORITY | Client → Host (opcode 0x11) | Priority toggle (via GenericEventForward) |
| 0x0080006B | ET_SUBSYSTEM_HIT | Internal only | Triggers auto-add to repair queue |
| 0x00800070 | ET_SUBSYSTEM_DAMAGED | Internal only | Damage tracking |
| 0x0080000E | ET_SET_PLAYER | Internal only | Player's ship changed |

---

## Repair Rate Formula (Verified)

```
rawRepairAmount = MaxRepairPoints * (repairSystem.condition / repairSystem.maxCondition) * deltaTime

divisor = min(queueCount, NumRepairTeams)

perSubsystemRepair = rawRepairAmount / divisor

actualConditionGain = perSubsystemRepair / subsystem.RepairComplexity
```

### Key Characteristics

1. The repair system's **own health** scales the output (damaged repair bay = slower)
2. **Multiple subsystems repaired simultaneously** (up to NumRepairTeams)
3. The repair amount is **divided equally** among min(queueCount, numTeams) subsystems
4. **RepairComplexity** acts as a final divisor (higher complexity = slower repair)
5. **Destroyed subsystems** (condition <= 0) are SKIPPED but NOT removed — they generate ET_REPAIR_CANNOT_BE_COMPLETED instead

### Example (Sovereign class, healthy repair system, 2 items in queue)

```
rawRepair = 50.0 * 1.0 * 0.033 = 1.65 per tick (at 30fps)
divisor = min(2, 3) = 2
perSubsystem = 1.65 / 2 = 0.825
For a phaser (complexity=3.0): conditionGain = 0.825 / 3.0 = 0.275 HP/tick
For a tractor (complexity=7.0): conditionGain = 0.825 / 7.0 = 0.118 HP/tick
```

---

## Three Network Paths for Repair Events

### Path 1: Opcode 0x06 (PythonEvent) — Host-Initiated Auto-Repair Notifications

**Direction**: Host → All Clients (via "NoMe" routing group)
**Reliability**: Reliable (ACK required, msg+0x3A = 1)
**Factory**: TGSubsystemEvent (0x0101), 17 bytes total

Used for 3 event types that the host generates automatically during the repair tick:

| Event | Trigger |
|-------|---------|
| ET_ADD_TO_REPAIR_LIST (0x008000DF) | Subsystem damaged, added to queue |
| ET_REPAIR_COMPLETED (0x00800074) | Subsystem reached max HP |
| ET_REPAIR_CANNOT_BE_COMPLETED (0x00800075) | Subsystem destroyed while queued |

**Wire format**:
```
Offset  Size  Type    Field            Notes
------  ----  ----    -----            -----
0       1     u8      opcode           0x06
1       4     i32     factory_id       0x00000101 (TGSubsystemEvent)
5       4     i32     event_type       0x008000DF, 0x00800074, or 0x00800075
9       4     i32     source_obj_id    Damaged subsystem's TGObject ID
13      4     i32     dest_obj_id      RepairSubsystem's TGObject ID
```

**Note**: Both source and dest contain **subsystem-level** TGObject IDs (auto-assigned from global counter at construction time), NOT ship IDs.

### Path 2: Opcode 0x0B (AddToRepairList) — Client-Initiated Manual Repair

**Direction**: Client → Host → All (via GenericEventForward relay)
**Handler**: FUN_0069fda0 (GenericEventForward)
**Event type override**: 0 (preserve original type 0x008000DF)

Sent when a player manually requests repair of a subsystem from the Engineering panel. The GenericEventForward handler relays to all peers and dispatches locally.

**Wire format**: Standard TGCharEvent serialization (18 bytes total):
```
Offset  Size  Type    Field            Notes
------  ----  ----    -----            -----
0       1     u8      opcode           0x0B
1       4     i32     factory_id       0x00000105 (TGCharEvent)
5       4     i32     event_type       0x008000DF (ET_ADD_TO_REPAIR_LIST)
9       4     i32     source_obj_id    Source object
13      4     i32     dest_obj_id      Related object
17      1     u8      char_value       Extra data byte
```

### Path 3: Opcode 0x11 (RepairListPriority) — Client-Initiated Priority Toggle

**Direction**: Client → Host → All (via GenericEventForward relay)
**Handler**: FUN_0069fda0 (GenericEventForward)
**Event type**: 0x00800076 (ET_REPAIR_INCREASE_PRIORITY)
**Event type override**: 0 (preserve original)

Sent when a player clicks a subsystem in the repair queue to change its priority. The handler on the receiving end is HandleIncreasePriority (toggle algorithm).

**Wire format**: TGObjPtrEvent serialization (21 bytes total):
```
Offset  Size  Type    Field            Notes
------  ----  ----    -----            -----
0       1     u8      opcode           0x11
1       4     i32     factory_id       0x0000010C (TGObjPtrEvent)
5       4     i32     event_type       0x00800076 (ET_REPAIR_INCREASE_PRIORITY)
9       4     i32     source_obj_id    Source object
13      4     i32     dest_obj_id      Related object
17      4     i32     obj_ptr          Subsystem TGObject network ID
```

---

## Collision → Repair Chain

The complete event chain from collision to repair queue entry:

```
1. ProximityManager detects collision
2. Posts ET_COLLISION_EFFECT (0x00800050)

3. ShipClass::CollisionEffectHandler (0x005AF9C0):
   a. Validates sender is host
   b. Sends CollisionEffect (opcode 0x15) to "NoMe" group
   c. Falls through to collision damage application

4. Collision damage → per-subsystem damage:
   a. Reads subsystem condition
   b. Reduces by damage amount
   c. Calls ShipSubsystem::SetCondition (FUN_0056C470)

5. SetCondition:
   a. Stores new condition
   b. If newCondition < maxCondition AND ship alive:
      → Posts ET_SUBSYSTEM_HIT (0x0080006B) as TGObjPtrEvent (factory 0x10C)
        source = NULL, dest = owner ship, obj_ptr = subsystem object ID

6. RepairSubsystem::HandleHitEvent catches ET_SUBSYSTEM_HIT:
   a. Looks up subsystem by obj_ptr (TGObject ID)
   b. Calls AddToRepairList_MP (FUN_00565900)
   c. AddSubsystem rejects duplicates, rejects 0 HP
   d. If successful AND g_IsHost AND g_IsMultiplayer:
      → Posts ET_ADD_TO_REPAIR_LIST (0x008000DF) as TGSubsystemEvent (factory 0x0101)

7. HostEventHandler (0x006A1150) catches ET_ADD_TO_REPAIR_LIST:
   → Serializes as opcode 0x06, sends reliably to "NoMe" group

8. Clients receive opcode 0x06:
   → FUN_0069f880 deserializes factory 0x0101
   → Posts ET_ADD_TO_REPAIR_LIST locally
   → Client's RepairSubsystem::HandleAddToRepairList runs (SP gate blocks it)
   → Instead, the event's source/dest are resolved via hash table and the local
     repair subsystem adds the subsystem to its queue
```

### Why ~14 PythonEvent Messages Per Collision

- Two ships collide → each takes damage
- Each ship has ~7 top-level subsystems in the damage volume
- Each damaged subsystem → SUBSYSTEM_HIT → ADD_TO_REPAIR_LIST → PythonEvent
- 7 subsystems x 2 ships = ~14 PythonEvent messages
- Exact count varies with collision geometry and duplicate rejection

---

## Engineering Panel UI

### Three Display Areas

The Engineering panel (EngRepairPane, global at 0x0098B188) displays repair queue items in three areas:

| Area | Content |
|------|---------|
| REPAIR_AREA | Active repair slots (first NumRepairTeams items from queue head) |
| WAITING_AREA | Queued but not yet being repaired (remaining items after NumRepairTeams) |
| DESTROYED_AREA | Subsystems that are destroyed (condition <= 0.0) |

### UI Update Functions

| Address | Function | Purpose |
|---------|----------|---------|
| 0x005512e0 | EngRepairPane_Update | Full refresh (called each tick from Update) |
| 0x00551990 | EngRepairPane_RefreshRepairItem | Refresh a specific subsystem's display |
| 0x00551870 | EngRepairPane_ShowDestroyed | Move item to DESTROYED_AREA |
| 0x00551230 | EngRepairPane_ClearAll | Clear all items (on player ship change) |
| 0x00550ef0 | EngRepairPane_SetRepairSubsystem | Point pane at a ship's repair subsystem |
| 0x00550ee0 | EngRepairPane_SetNumTeams | Set number of active repair slots |

### Player Interaction

- **Click in REPAIR_AREA**: Sends ET_REPAIR_INCREASE_PRIORITY → HandleIncreasePriority → demotes to tail
- **Click in WAITING_AREA**: Sends ET_REPAIR_INCREASE_PRIORITY → HandleIncreasePriority → promotes to head
- **Click in DESTROYED_AREA**: No action (destroyed subsystems cannot be repaired)

---

## Sovereign-Class Reference Values

### Repair Subsystem

| Property | Value |
|----------|-------|
| MaxRepairPoints | 50.0 |
| NumRepairTeams | 3 |
| MaxCondition | 8,000 |
| RepairComplexity | 1.0 |

### Subsystem HP and RepairComplexity

| Subsystem | MaxCondition | RepairComplexity |
|-----------|-------------|------------------|
| Shield Generator | 10,000 | — |
| Sensor Array | 8,000 | 1.0 |
| Warp Core (reactor) | 7,000 | 2.0 |
| Impulse Engines (system) | 3,000 | 3.0 |
| Port/Star Impulse (each) | 3,000 | — |
| Torpedo System | 6,000 | — |
| Forward Torpedo (each, x4) | 2,200 | — |
| Aft Torpedo (each, x2) | 2,200 | — |
| Phaser Emitter (each, x8) | 1,000 | — |
| Phaser Controller | 8,000 | — |
| Repair | 8,000 | 1.0 |
| Warp Engines (system) | 8,000 | — |
| Port/Star Warp (each) | 4,500 | — |
| Tractor System | 3,000 | 7.0 |
| Tractor (each, x4) | 1,500 | 7.0 |
| Bridge | 10,000 | 4.0 |
| Hull | 12,000 | 3.0 |

---

## Related Documents

- [repair-tractor-analysis.md](repair-tractor-analysis.md) — Repair queue + tractor beam combined RE (initial decompilations)
- [repair-event-object-ids.md](repair-event-object-ids.md) — TGObject ID assignment, event serialization deep-dive
- [pythonevent-wire-format.md](pythonevent-wire-format.md) — PythonEvent (opcode 0x06) polymorphic transport
- [combat-mechanics-re.md](combat-mechanics-re.md) — Consolidated combat RE (shields, cloak, weapons, repair, tractor)
- [damage-system.md](damage-system.md) — Full damage pipeline (collision → ProcessDamage → subsystem distribution)
- [collision-effect-protocol.md](collision-effect-protocol.md) — CollisionEffect (opcode 0x15) wire format
- [set-phaser-level-protocol.md](set-phaser-level-protocol.md) — GenericEventForward pattern (shared by opcodes 0x0B and 0x11)
