# ADD_TO_REPAIR_LIST Event Object ID Analysis

## Summary

The ADD_TO_REPAIR_LIST event (0x008000DF) sent as PythonEvent (opcode 0x06) contains
**subsystem object IDs** in both the source and dest fields — NOT ship IDs. Each subsystem
has its own globally unique network object ID assigned at construction time from a global
auto-increment counter at `DAT_0095b078`.

## TGObject Class Hierarchy (Subsystems)

All subsystems inherit from TGObject (the base game object class). The full constructor
chain for a RepairSubsystem is:

```
FUN_006f0a70  TGObject          — assigns +0x04 = unique network object ID
  FUN_006f31a0  TGSourceObject  — +0x08 = 0  (source ref slot)
    FUN_006f2590  TGDestObject  — +0x0C = 0  (dest ref slot)
      FUN_006d8f90  TGHandler   — +0x10 = 0  (handler flags)
        FUN_0056b970  ShipSubsystem       — +0x40 = 0 (owner ship ptr, set later)
          FUN_00562240  PoweredSubsystem   — +0x88..+0xA0
            FUN_00565090  RepairSubsystem  — +0xA8..+0xBC
```

### TGObject ID Assignment (FUN_006f0a70)

```c
// Base game object constructor
void __thiscall TGObject_ctor(void *this, int objectID) {
    if (objectID == 0) {
        // Auto-assign: use global counter, then increment
        *(int*)(this + 0x04) = DAT_0095b078;
        objectID = DAT_0095b078;
    } else {
        *(int*)(this + 0x04) = objectID;
        if (DAT_0095b07d == 0 || objectID < DAT_0095b078) goto skip;
    }
    DAT_0095b078 = objectID + 1;  // increment counter
skip:
    // Register in global hash table DAT_0099a67c for lookup by ID
    FUN_006f0f30(this);
}
```

- `DAT_0095b078` = global auto-increment object ID counter
- `DAT_0099a67c` = global hash table mapping object ID -> object pointer
- `FUN_006f0ee0` = hash table lookup: `objectID -> object*` (returns NULL if not found)

### Subsystem +0x40 = Owner Ship Pointer

In Ship_SetupProperties (FUN_005b3fb0), after creating each subsystem:
```c
// vtable+0x58 = SetOwnerShip — at 0x0056bc50
(**(code **)(*subsystem + 0x58))(ship);
```

FUN_0056bc50:
```c
void __thiscall SetOwnerShip(void *this, void *ship) {
    *(void**)(this + 0x40) = ship;  // store ship pointer
    FUN_0056bde0(this);             // additional setup
}
```

All subsystems are created with `param_1=0` (auto-assign ID) in Ship_SetupProperties.

## TGEvent Layout

### TGEvent (base, factory type 0x101, size 0x28)

| Offset | Type | Field | Description |
|--------|------|-------|-------------|
| +0x00 | ptr | vtable | TGEvent vtable (0x895ff4) |
| +0x04 | int | objectID | Event's own network object ID (auto-assigned) |
| +0x08 | ptr | source | Source game object pointer (TGObject*) |
| +0x0C | ptr | dest | Dest/related game object pointer (TGObject*) |
| +0x10 | int | eventType | Game event type code (e.g. 0x008000DF) |
| +0x14 | float | timestamp | -1.0f (init) |
| +0x18 | short | field_18 | 0 |
| +0x1A | short | field_1A | 0 |
| +0x1C | int | field_1C | 0 |
| +0x20 | int | field_20 | 0 |
| +0x24 | int | field_24 | 0 |

### TGCharEvent (factory type 0x10C, size 0x2C)

Inherits TGEvent, adds:

| Offset | Type | Field | Description |
|--------|------|-------|-------------|
| +0x28 | int | charData | Extra int data (raw value, NOT a pointer) |

## Setter Functions

- **FUN_006d6270**: `event->source (+0x08) = param_1` — sets source object pointer
- **FUN_006d62b0**: `event->dest (+0x0C) = param_1` — sets dest/related object pointer

Both functions also manage reference counting via the object tracking hash table at
`DAT_009983a8`.

## Event Wire Format

### TGEvent::WriteToStream (FUN_006d6130)

WriteToStream serializes via the stream (vtable calls):

```
[int32] factoryType      — vtable+0x04 result (0x101 for TGEvent, 0x10C for TGCharEvent)
[int32] eventType        — event+0x10 (e.g. 0x008000DF)
[int32] source_obj_id    — *(event->source + 0x04), or 0 if source==NULL
[int32] dest_obj_id      — *(event->dest + 0x04), or 0 if NULL, or -1 if sentinel
```

### TGCharEvent::WriteToStream (FUN_006d6dc0)

Calls TGEvent::WriteToStream first, then appends:

```
[int32] charData         — event+0x28 (raw integer value)
```

### WriteObjectRef encoding for dest field

The dest field (event+0x0C) has three special cases:
1. **NULL** (dest == 0): writes `0`
2. **Sentinel** (dest == DAT_0095adfc, the "global" marker): writes `0xFFFFFFFF` (-1)
3. **Valid object**: writes `*(dest + 0x04)` — the object's network ID

The source field (event+0x08) has two cases:
1. **NULL** (source == 0): writes `0`
2. **Valid object**: writes `*(source + 0x04)` — the object's network ID

## ADD_TO_REPAIR_LIST (0x008000DF) Event Chain

### 1. Damage triggers SUBSYSTEM_HIT

**SetCondition** (FUN_0056c470) — called when a subsystem's condition changes:

```c
void __thiscall SetCondition(ShipSubsystem *this, float newCondition) {
    this->condition = newCondition;  // +0x30
    // Clamp to max
    if (GetMaxCondition(this) < this->condition)
        this->condition = GetMaxCondition(this);
    // Calculate percentage
    this->conditionPct = this->condition / GetMaxCondition(this);  // +0x34

    // If damaged (condition < max) AND owner ship exists AND not too soon:
    Ship *ship = this->ownerShip;  // +0x40
    if (this->condition < GetMaxCondition(this)
        && (ship == NULL || ship->timeSinceSpawn >= DAMAGE_REPORT_THRESHOLD)) {
        // Create TGCharEvent (factory 0x10C)
        TGCharEvent *evt = new TGCharEvent(0);  // auto-assign ID

        // Source = NULL (no source for damage notification)
        SetSource(evt, 0);           // FUN_006d6270: evt+0x08 = NULL

        // Dest = owner ship pointer
        SetDest(evt, this->ownerShip);  // FUN_006d62b0: evt+0x0C = ship ptr

        // Event type = SUBSYSTEM_HIT
        evt->eventType = 0x0080006B;    // evt+0x10

        // CharData = this subsystem's own object ID
        if (this != NULL)
            evt->charData = this->objectID;  // evt+0x28 = *(this+0x04)
        else
            evt->charData = 0;

        PostEvent(evt);
    }
}
```

**SUBSYSTEM_HIT wire format** (via HostEventHandler as opcode 0x06):
```
[byte]  0x06              — PythonEvent opcode
[int32] 0x010C            — TGCharEvent factory type (NOT 0x0101)
[int32] 0x0080006B        — SUBSYSTEM_HIT event type
[int32] 0                 — source_obj_id (NULL, no source)
[int32] ship_obj_id       — dest_obj_id (*(ownerShip+0x04), the ship's network ID)
[int32] subsystem_obj_id  — charData (*(subsystem+0x04), the subsystem's own ID)
```

### 2. RepairSubsystem handles SUBSYSTEM_HIT

**RepairSubsystem::HandleHitEvent** (at 0x005658d0, NOT in Ghidra func DB):

```c
void __thiscall HandleHitEvent(RepairSubsystem *this, TGCharEvent *event) {
    // Look up the damaged subsystem by its object ID
    int subsystemID = event->charData;  // event+0x28
    ShipSubsystem *sub = LookupObjectByID(subsystemID);  // FUN_006f0ee0

    if (sub != NULL) {
        AddSubsystemToRepairList(this, sub, 1);  // FUN_00565900
    }

    // Forward to base handler
    ForwardEvent(this, event);  // FUN_006d90e0
}
```

### 3. AddSubsystemToRepairList posts ADD_TO_REPAIR_LIST

**FUN_00565900** (RepairSubsystem::AddSubsystemToRepairList):

```c
void __thiscall AddSubsystemToRepairList(RepairSubsystem *this, ShipSubsystem *damagedSub) {
    bool added = AddToList(this, damagedSub);  // FUN_00565520

    if (added && g_IsHost && g_IsMultiplayer) {
        // Create TGEvent (factory 0x101) — NOT TGCharEvent
        TGEvent *evt = new TGEvent(0);  // auto-assign ID

        evt->eventType = 0x008000DF;    // ADD_TO_REPAIR_LIST

        // Source = RepairSubsystem (this)
        SetDest(evt, this);              // FUN_006d62b0: evt+0x0C = this
        // NOTE: despite the function name, this sets +0x0C ("dest")

        // Dest = damaged subsystem
        SetSource(evt, damagedSub);      // FUN_006d6270: evt+0x08 = damagedSub
        // NOTE: despite the function name, this sets +0x08 ("source")

        PostEvent(evt);
    }
}
```

**ADD_TO_REPAIR_LIST wire format** (via HostEventHandler as opcode 0x06):
```
[byte]  0x06              — PythonEvent opcode
[int32] 0x0101            — TGEvent factory type (plain TGEvent, NOT TGCharEvent)
[int32] 0x008000DF        — ADD_TO_REPAIR_LIST event type
[int32] damaged_sub_id    — source_obj_id: *(damagedSub+0x04) = damaged subsystem's unique ID
[int32] repair_sub_id     — dest_obj_id: *(repairSubsystem+0x04) = RepairSubsystem's unique ID
```

## Answer to the Core Question

**Both `source_obj_id` and `dest_obj_id` contain subsystem-level unique network object IDs.**
They are NOT ship base IDs. They are NOT subsystem indices.

- **source_obj_id** = the damaged subsystem's own globally unique object ID (from +0x04)
- **dest_obj_id** = the RepairSubsystem's own globally unique object ID (from +0x04)

These IDs are auto-assigned from the global counter `DAT_0095b078` at subsystem construction
time. They are NOT derived from the ship's base ID by any formula. Each subsystem gets the
next sequential value from the counter at the time it is created. The mapping is:

```
Ship created with base ID N (e.g. 0x3FFFFFFF for player 0)
  → subsystem 1 gets ID = counter_at_creation_time
  → subsystem 2 gets ID = counter_at_creation_time + 1
  → subsystem 3 gets ID = counter_at_creation_time + 2
  → ... etc
```

The counter value depends on what other objects were created before the ship's subsystems.
There is NO fixed offset formula from ship base to subsystem ID. The only way to resolve
a subsystem ID on the receiving end is to use the global hash table lookup (FUN_006f0ee0).

## Related Handler Registration

From RepairSubsystem_HandleHitEvent (FUN_00565d40), the event handler registrations:

| Address | Handler | Event |
|---------|---------|-------|
| 0x005658d0 | HandleHitEvent | SUBSYSTEM_HIT (0x0080006B) |
| FUN_00565980 | HandleRepairComplete | REPAIR_COMPLETE |
| FUN_00565a10 | HandleSubsystemRepair | SUBSYSTEM_REPAIR |
| 0x00565a80 | HandleRepairCancel | REPAIR_CANCEL |
| 0x00565b50 | HandleIncreasePriority | INCREASE_PRIORITY |
| 0x00565b30 | HandleAddToRepairList | ADD_TO_REPAIR_LIST (0x008000DF) |
| 0x00565cd0 | HandleSetPlayer | SET_PLAYER |

## HostEventHandler (0x006a1150)

The HostEventHandler is responsible for serializing events to the network. It:

1. Creates a TGFlatBufferStream with a 1023-byte buffer
2. Sets the first byte to 0x06 (PythonEvent opcode)
3. Calls `event->WriteToStream(stream)` via vtable+0x34
4. Gets the stream size, allocates a TGMessage
5. Copies the buffer to the message via FUN_006b84d0 (buffer copy)
6. Sets message+0x3A = 1 (reliable flag)
7. Sends via TGNetwork::BroadcastTGMessage (FUN_006b4de0) with target "Forward"

This means ALL events serialized through HostEventHandler become opcode 0x06 PythonEvent
messages on the wire, regardless of the event type. The event type is INSIDE the payload.

## Key Addresses

| Address | Symbol | Description |
|---------|--------|-------------|
| 0x006f0a70 | TGObject::ctor | Assigns +0x04 = network object ID |
| 0x0095b078 | g_NextObjectID | Global auto-increment object ID counter |
| 0x0099a67c | g_ObjectHashTable | Hash table: object ID -> object pointer |
| 0x006f0ee0 | LookupObjectByID | Hash table lookup by ID |
| 0x006d6130 | TGEvent::WriteToStream | Serializes event to network stream |
| 0x006d6dc0 | TGCharEvent::WriteToStream | Adds +0x28 charData after base |
| 0x006d5c00 | TGEvent::ctor | Event constructor (size 0x28) |
| 0x00403290 | TGCharEvent::ctor | CharEvent constructor (size 0x2C) |
| 0x006d62b0 | TGEvent::SetDest | Sets event+0x0C (dest object ptr) |
| 0x006d6270 | TGEvent::SetSource | Sets event+0x08 (source object ptr) |
| 0x00565900 | RepairSubsystem::AddToRepairList | Creates ADD_TO_REPAIR_LIST event |
| 0x005658d0 | RepairSubsystem::HandleHitEvent | Catches SUBSYSTEM_HIT |
| 0x0056c470 | ShipSubsystem::SetCondition | Posts SUBSYSTEM_HIT when damaged |
| 0x0056bc50 | ShipSubsystem::SetOwnerShip | Sets subsystem+0x40 = ship ptr |
| 0x006a1150 | HostEventHandler | Serializes events as opcode 0x06 |
