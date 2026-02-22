> [docs](../README.md) / [protocol](README.md) / tgobjptrevent-class.md

# TGObjPtrEvent — Factory 0x010C

Complete reverse engineering analysis of TGObjPtrEvent, a fourth TGEvent subclass that
carries an int32 object network ID. This class accounts for **45% of all PythonEvent
messages** during combat — the single most common event class in weapon combat.

## Summary

| Property | Value |
|----------|-------|
| **Factory ID** | 0x010C (decimal 268) |
| **Class Name** | `TGObjPtrEvent` |
| **SWIG Name** | `_p_TGObjPtrEvent` |
| **Vtable Address** | 0x0088869C |
| **Object Size** | 0x2C (44 bytes) |
| **IsA Chain** | 0x010C → 0x0101 (TGSubsystemEvent) → 0x02 (TGEvent) |
| **Constructor** | 0x00403290 |
| **Wire Size** | 21 bytes (17-byte base + 4-byte int32) |

## Class Layout (0x2C bytes)

```
Offset  Size  Type       Field              Notes
0x00    4     void**     vtable             0x0088869C
0x04    4     int        ni_refcount        NiObject reference count
0x08    4     void*      source_object      Source object ptr
0x0C    4     void*      dest_object        Related/destination object ptr
0x10    4     uint32     event_type         Event type constant (0x008000xx)
0x14    4     float      timestamp          -1.0f initially
0x18    2     uint16     flags_a            Event flags
0x1A    2     uint16     flags_b            Ref tracking flags
0x1C    4     void*      (reserved)
0x20    4     void*      (reserved)
0x24    4     void*      parent_event       Cleared to 0 on receive
0x28    4     int32      obj_ptr            TGObject network ID (third object reference)
```

### Key Difference from TGCharEvent (factory 0x105)

Both TGObjPtrEvent and TGCharEvent are 0x2C bytes in memory with a field at +0x28,
but they are **different classes**:

| Property | TGObjPtrEvent (0x10C) | TGCharEvent (0x105) |
|----------|----------------------|---------------------|
| Constructor | 0x00403290 | 0x00574C20 |
| Vtable | 0x0088869C | 0x008932DC |
| Field at +0x28 | int32 (TGObject ID) | byte (single char) |
| WriteToStream | vtable[0x84] (WriteInt32) | vtable[0x54] (WriteByte) |
| Wire extension | 4 bytes | 1 byte |
| Total wire size | 21 bytes | 18 bytes |

## IsA Chain

`TGObjPtrEvent::IsA` at 0x004032C0 returns true for:
- `0x010C` (TGObjPtrEvent)
- `0x0101` (TGSubsystemEvent)
- `0x02` (TGEvent)

## Class Hierarchy (Updated)

```
NiObject
  └── TGEvent (factory 0x02, size 0x28)
        └── TGSubsystemEvent (factory 0x101, size 0x28, no extra fields)
              ├── TGCharEvent (factory 0x105, size 0x2C, +0x28 = byte)
              └── TGObjPtrEvent (factory 0x10C, size 0x2C, +0x28 = int32 object ID)
        └── ObjectExplodingEvent (factory 0x8129, size 0x30, +0x28 = int32, +0x2C = float)
```

## Wire Format (opcode 0x06 or 0x0D)

```
Offset  Size  Type    Field            Notes
0       1     u8      opcode           0x06 or 0x0D
1       4     i32     factory_id       0x0000010C
5       4     i32     event_type       0x008000xx (varies by event)
9       4     i32     source_obj_id    Source object (0=NULL, -1=sentinel, else obj+0x04)
13      4     i32     dest_obj_id      Dest object (same encoding)
17      4     i32     obj_ptr_id       Third object reference (TGObject network ID)
```

**Total**: 21 bytes (fixed).

### Decoded Packet Example: ET_WEAPON_FIRED

```
06                    opcode = 0x06 (PythonEvent)
0C 01 00 00           factory_id = 0x0000010C (TGObjPtrEvent)
7C 00 80 00           event_type = 0x0080007C (ET_WEAPON_FIRED)
FF FF FF 3F           source_obj = 0x3FFFFFFF (Player 0's ship)
FF FF FF 3F           dest_obj = 0x3FFFFFFF (same ship — self-reference)
2A 00 00 00           obj_ptr = 0x0000002A (weapon subsystem's TGObject ID)
```

## Serialization Functions

| Address | Function | Stream Vtable | Description |
|---------|----------|---------------|-------------|
| 0x006D6DC0 | WriteToStream | vtable[0x84] = WriteInt32 | Base fields + WriteInt32(this+0x28) |
| 0x006D6DF0 | ReadFromStream | vtable[0x80] = ReadInt32 | Base fields + ReadInt32 → this+0x28 |
| 0x006D6DA0 | CopyFrom | (direct copy) | Base CopyFrom + copy +0x28 word |

### WriteToStream (0x006D6DC0)

```c
void __thiscall TGObjPtrEvent_WriteToStream(TGObjPtrEvent* this, TGStream* stream) {
    // Write base TGEvent fields (factory_id, event_type, source_ref, dest_ref)
    TGEvent_WriteToStream(this, stream);  // 0x006D6130
    // Write the int32 object pointer field
    stream->vtable[0x84](stream, this->obj_ptr);  // WriteInt32(+0x28)
}
```

### ReadFromStream (0x006D6DF0)

```c
void __thiscall TGObjPtrEvent_ReadFromStream(TGObjPtrEvent* this, TGStream* stream) {
    // Read base TGEvent fields (event_type, source_ref, dest_ref)
    TGEvent_ReadFromStream(this, stream);  // 0x006D61C0
    // Read the int32 object pointer field
    this->obj_ptr = stream->vtable[0x80](stream);  // ReadInt32 → +0x28
}
```

## Vtable Map (0x0088869C)

| Slot | Offset | Address | Name |
|------|--------|---------|------|
| 0 | +0x00 | 0x00403310 | scalar_deleting_dtor |
| 1 | +0x04 | 0x004032B0 | GetFactoryID → returns 0x10C |
| 2 | +0x08 | 0x004032C0 | IsA(id) → true for 0x10C, 0x101, 0x02 |
| 9 | +0x24 | 0x004032F0 | GetClassName → "TGObjPtrEvent" (0x8D8594) |
| 10 | +0x28 | 0x00403300 | GetSWIGName → "_p_TGObjPtrEvent" |
| 12 | +0x30 | 0x006D6DA0 | CopyFrom (base + obj_ptr) |
| 13 | +0x34 | 0x006D6DC0 | **WriteToStream** (network) |
| 14 | +0x38 | 0x006D6DF0 | **ReadFromStream** (network) |

(Slots 3-8, 11, 15-17 inherited from TGEvent base.)

## Python API (SWIG)

| SWIG Function | Address | Description |
|---------------|---------|-------------|
| `swig_new_TGObjPtrEvent` | 0x005C7F10 | Constructor |
| `swig_TGObjPtrEvent_Cast` | 0x005C7F90 | Type cast |
| `swig_TGObjPtrEvent_Create` | 0x005C8000 | Factory create |
| `swig_TGObjPtrEvent_GetObjPtr` | 0x005C8070 | Get object reference (resolves ID via hash table) |
| `swig_TGObjPtrEvent_SetObjPtr` | 0x005C80E0 | Set object reference |

### Python Usage Pattern (from game scripts)

```python
pEvent = App.TGObjPtrEvent_Create()
pEvent.SetSource(source_object)
pEvent.SetDestination(dest_object)
pEvent.SetObjPtr(third_object)      # sets +0x28 field
pEvent.SetEventType(App.ET_WEAPON_FIRED)
App.g_kEventManager.AddEvent(pEvent)
```

## Complete C++ Event Type Catalog (30 xref sites, 11 event types + 1 timer)

Constructor xref analysis found **30 call sites** to FUN_00403290. After decompilation,
11 distinct game event types + 1 internal timer delivery were identified.

### Game Event Types

| Event Type | ET_ Constant | Producer | obj_ptr Contains | Network? |
|-----------|-------------|----------|-----------------|----------|
| 0x0080000E | ET_SET_PLAYER | FUN_004066d0 (Game::SetPlayer) | New player ship ID | No (local) |
| 0x00800058 | ET_TARGET_WAS_CHANGED | FUN_005ae210 (Ship::SetTarget) | **Previous** target ID | No (local) |
| 0x0080006B | ET_SUBSYSTEM_HIT | FUN_0056c470 (SetCondition) | Subsystem's own ID | No (local, triggers repair chain) |
| 0x00800076 | ET_REPAIR_INCREASE_PRIORITY | FUN_005519e0 | Repair target subsystem ID | Yes (opcode 0x11) |
| 0x0080007C | ET_WEAPON_FIRED | FUN_00571f40, FUN_0057c9e0, FUN_0057f580 | Target ID or 0 | Yes (opcode 0x06/0x0D) |
| 0x0080007D | ET_TRACTOR_BEAM_STARTED_FIRING | FUN_0057f580 (Tractor::Fire) | Target ID | Yes (opcode 0x06/0x0D) |
| 0x00800081 | ET_PHASER_STARTED_FIRING | FUN_00571f40 (Phaser::Fire) | Target ID | Yes (opcode 0x06/0x0D) |
| 0x00800083 | ET_PHASER_STOPPED_FIRING | vtable xref ~0x005712FE | Target ID | Yes (opcode 0x06/0x0D) |
| 0x00800085 | ET_TRACTOR_TARGET_DOCKED | FUN_00580910 | Docked ship ID | No (local) |
| 0x00800088 | ET_SENSORS_SHIP_IDENTIFIED | FUN_00568ad0, FUN_005678b0 | Identified ship ID | No (local) |
| 0x008000DC | ET_STOP_FIRING_AT_TARGET_NOTIFY | FUN_00574010, FUN_005825a0 | Target ship ID or 0 | Yes (opcode 0x09, **host-only**) |

### Timer Delivery (non-game event)

| Event Type | Producer | obj_ptr Contains |
|-----------|----------|-----------------|
| 0x00050001 | FUN_007022f0, FUN_007023e0 | Timer source ID |

### Dual-Fire Pattern

Weapon fire functions create **two** TGObjPtrEvent events simultaneously:

- **Phaser fire** (FUN_00571f40): `ET_PHASER_STARTED_FIRING` (0x81) + `ET_WEAPON_FIRED` (0x7C)
- **Tractor fire** (FUN_0057f580): `ET_TRACTOR_BEAM_STARTED_FIRING` (0x7D) + `ET_WEAPON_FIRED` (0x7C)
- **Torpedo fire** (FUN_0057c9e0): `ET_WEAPON_FIRED` (0x7C) only

This dual-fire pattern means every phaser/tractor firing cycle generates at least 4
TGObjPtrEvent messages (start_specific + weapon_fired + stopped_specific + stop_notify).

### ET_TARGET_WAS_CHANGED — Previous Target

Uniquely, ET_TARGET_WAS_CHANGED (0x00800058) stores the **previous** target's ID in
obj_ptr, not the new target. This allows handlers to clean up references to the old
target before the new one is applied.

### ET_STOP_FIRING_AT_TARGET_NOTIFY — Host-Only Gate

Both producers of ET_STOP_FIRING_AT_TARGET_NOTIFY (FUN_00574010 for phasers,
FUN_005825a0 for tractors) gate on `g_IsHost != 0` before creating the event.
This event is only generated on the host.

### Network vs Local Classification

**Network-forwarded** (cross the wire as opcode 0x06/0x0D or generic event forward):
- ET_WEAPON_FIRED (0x7C) — opcode 0x06/0x0D
- ET_PHASER_STARTED_FIRING (0x81) — opcode 0x06/0x0D
- ET_PHASER_STOPPED_FIRING (0x83) — opcode 0x06/0x0D
- ET_TRACTOR_BEAM_STARTED_FIRING (0x7D) — opcode 0x06/0x0D
- ET_REPAIR_INCREASE_PRIORITY (0x76) — opcode 0x11
- ET_STOP_FIRING_AT_TARGET_NOTIFY (0xDC) — opcode 0x09 (host-only)

**Local-only** (never serialized to wire):
- ET_SET_PLAYER (0x0E)
- ET_TARGET_WAS_CHANGED (0x58)
- ET_SUBSYSTEM_HIT (0x6B) — triggers ADD_TO_REPAIR_LIST (TGSubsystemEvent 0x101) on wire
- ET_TRACTOR_TARGET_DOCKED (0x85)
- ET_SENSORS_SHIP_IDENTIFIED (0x88)

## Python Script Usage (72 call sites)

SWIG functions (SetObjPtr, GetObjPtr, Create) have **zero C++ xrefs** — called
exclusively from Python. The scripts use TGObjPtrEvent for 27+ event types, all
**local-only** (not network-forwarded). Most common:

| ET_ Constant | Usage Count | Game System |
|-------------|-------------|-------------|
| ET_ACTION_COMPLETED | 54 | Action/sequence management |
| ET_CHARACTER_ANIMATION_DONE | 46 | Bridge crew animations |
| ET_SET_ALERT_LEVEL | 15 | Alert level changes |
| ET_MISSION_START | 11 | Mission initialization |
| ET_PLAYER_BOOT_EVENT | 8 | Player boot |
| ET_HAIL | 2 | Ship hailing |
| ET_TRACTOR_TARGET_DOCKED | 1 | AI docking completion |

### Python Usage Patterns

**Action completion** (most common):
```python
pEvent = App.TGObjPtrEvent_Create()
pEvent.SetDestination(App.g_kTGActionManager)
pEvent.SetEventType(App.ET_ACTION_COMPLETED)
pEvent.SetObjPtr(pAction)
```

**Hailing**:
```python
pHailEvent = App.TGObjPtrEvent_Create()
pHailEvent.SetSource(pObject)
pHailEvent.SetDestination(pHelmMenu)
pHailEvent.SetObjPtr(pObject)  # target ship
pHailEvent.SetEventType(App.ET_HAIL)
```

## Why 45% of Combat PythonEvents

In a 33.5-minute 3-player battle (59 kills, 84 collisions):

- **1,718 of 3,825 PythonEvents** use factory 0x010C (TGObjPtrEvent)
- The dual-fire pattern is the primary driver: each phaser cycle produces
  ET_PHASER_STARTED_FIRING + ET_WEAPON_FIRED + ET_PHASER_STOPPED_FIRING
- Torpedo launches add ET_WEAPON_FIRED events
- In a 3-player battle with 2,283 StartFiring events and 897 TorpedoFire events,
  the weapon event volume explains the 1,718 TGObjPtrEvent count

The events flow through the PythonEvent path (opcode 0x06 S→C, opcode 0x0D C→S)
or GenericEventForward path (opcodes 0x09, 0x11) for relay.

## ET_ Constant Mapping

Base: `ET_TEMP_TYPE = 0x00800001` (App.py line 12835).
Formula: `value = 0x00800001 + (line_number - 12835)`.

### C++ Event Types Using TGObjPtrEvent

| Line | Constant | Hex Value | Network? |
|------|----------|-----------|----------|
| 12849 | ET_SET_PLAYER | 0x0080000E | No |
| 12923 | ET_TARGET_WAS_CHANGED | 0x00800058 | No |
| 12942 | ET_SUBSYSTEM_HIT | 0x0080006B | No (triggers 0x101 on wire) |
| 12952 | ET_REPAIR_INCREASE_PRIORITY | 0x00800076 | Yes (opcode 0x11) |
| 12958 | ET_WEAPON_FIRED | 0x0080007C | Yes (opcode 0x06/0x0D) |
| 12959 | ET_TRACTOR_BEAM_STARTED_FIRING | 0x0080007D | Yes (opcode 0x06/0x0D) |
| 12961 | ET_TRACTOR_BEAM_STOPPED_FIRING | 0x0080007F | Yes (opcode 0x06/0x0D) |
| 12963 | ET_PHASER_STARTED_FIRING | 0x00800081 | Yes (opcode 0x06/0x0D) |
| 12965 | ET_PHASER_STOPPED_FIRING | 0x00800083 | Yes (opcode 0x06/0x0D) |
| 12967 | ET_TRACTOR_TARGET_DOCKED | 0x00800085 | No |
| 12970 | ET_SENSORS_SHIP_IDENTIFIED | 0x00800088 | No |
| — | ET_STOP_FIRING_AT_TARGET_NOTIFY | 0x008000DC | Yes (opcode 0x09, host-only) |

Note: **ET_TORPEDO_FIRED is a separate constant** at 0x00800066 (line 12936). The
constant 0x0080007C = ET_WEAPON_FIRED covers both phaser and torpedo fire events at
the subsystem level.

Note: ET_SUBSYSTEM_HIT is not exposed to Python (not in App.py). It is an internal
C++ event only.

## Full Factory ID Table (0x01xx range + 0x8129)

| Factory ID | Class Name | Size | Extension at +0x28 | Wire Bytes |
|-----------|------------|------|---------------------|------------|
| 0x0002 | TGEvent | 0x28 | (none) | 17 |
| 0x0101 | TGSubsystemEvent | 0x28 | (none) | 17 |
| 0x0105 | TGCharEvent | 0x2C | char (1 byte) | 18 |
| **0x010C** | **TGObjPtrEvent** | **0x2C** | **int32 (TGObject ID)** | **21** |
| 0x8129 | ObjectExplodingEvent | 0x30 | int32 + float | 25 |

## C++ Producers in Unanalyzed Code Regions

The following xref addresses are in code regions Ghidra has not fully analyzed into functions. Based on surrounding function boundaries and handler registration names, these are:

| Address Range | Likely Function | Event Type | Evidence |
|--------------|----------------|------------|---------|
| ~0x0059d18E | ObjectGroup::EnteredSet (LAB_0059d140) | ET_OBJECT_GROUP_OBJECT_ENTERED_SET | Handler name "ObjectGroup__EnteredSet" at 0x8e5dbc |
| ~0x0059d210 | ObjectGroup::ExitedSet (LAB_0059d1d0) | ET_OBJECT_GROUP_OBJECT_EXITED_SET | Handler name "ObjectGroup__ExitedSet" at 0x8e5dd4 |
| ~0x0059d31F | ObjectGroup::ObjectDestroyed (LAB_0059d250) | ET_OBJECT_GROUP_OBJECT_DESTROYED | Handler name "ObjectGroup__ObjectDestroyed" at 0x8e5d9c |
| ~0x00565376, ~0x00565419, ~0x005654AE | RepairSubsystem (between 0x5651c0-0x565520) | Likely ET_REPAIR_COMPLETED / ET_REPAIR_CANNOT_BE_COMPLETED / ET_SUBSYSTEM_STATE_CHANGED | Three calls in one function; repair subsystem handlers registered nearby |
| ~0x00575413 | PhaserSystem (between 0x575270-0x575480) | Likely ET_PHASER_STOPPED_FIRING (0x00800083) | Vtable xref at 0x005712FE confirms phasers use this event |
| ~0x0057C961 | TorpedoSystem (between 0x57c740-0x57c9e0) | Likely ET_WEAPON_FIRED (0x0080007C) | Pattern matches FUN_0057c9e0 torpedo fire |
| ~0x00543EF0 | Unknown (no function boundaries found) | Unknown | Deep in mission code area |
| ~0x006D49B5 | TGEvent infrastructure (between 0x6D4A20-) | Factory create / deserialization | Near event manager code |
| ~0x007031A7, ~0x007032D0 | Weapon fire (between 0x7030c0-0x7033b0) | 0x00800081 + 0x0080007C or similar | SWIG/weapon bridge code area |
| ~0x0070857D | Unknown (before 0x7085d0) | Unknown | SWIG/streaming area |

### Vtable DATA References (vtable = 0x0088869C)

5 locations write this vtable into objects:
1. **0x0040329D** -- TGObjPtrEvent constructor (canonical)
2. **0x00551A5B** -- FUN_005519e0 (ET_REPAIR_INCREASE_PRIORITY) -- manual vtable write instead of calling ctor
3. **0x0057F185** -- TractorBeam::Fire area (ET_TRACTOR_BEAM_STOPPED_FIRING = 0x0080007F)
4. **0x005712FE** -- PhaserSystem area (ET_PHASER_STOPPED_FIRING = 0x00800083)
5. **0x005768C5** -- WeaponSystem area (ET_WEAPON_FIRED = 0x0080007C)

Note: Sites 3-5 are in unanalyzed code but the vtable write confirms they create TGObjPtrEvents. The event types are identified from handler registrations for those subsystem classes.

### Infrastructure / Non-Event-Producer Calls

| Address | Context | Purpose |
|---------|---------|---------|
| 0x004028DD | thunk_FUN_006ff7b0 area (destructor) | TGObjPtrEvent destructor -- cleans up refcounted obj_ptr |
| 0x00403570 | thunk_FUN_006ff7b0 area (destructor) | Another TGObjPtrEvent destructor variant (size 0x34 subclass?) |

## Complete Python Event Type Table

Python scripts create TGObjPtrEvents via `App.TGObjPtrEvent_Create()` + `SetEventType()` + `SetObjPtr()`. The SWIG functions `swig_TGObjPtrEvent_Create` (0x005C8000) and `swig_TGObjPtrEvent_SetObjPtr` (0x005C80E0) have zero C++ xrefs -- they are called exclusively from Python.

| ET_ Constant | Python File(s) | obj_ptr Contains | Context |
|-------------|----------------|-----------------|---------|
| ET_ACTION_COMPLETED | MissionLib.py, Bridge/*CharacterHandlers.py, E*M*.py, WarpSequence.py | The action object that completed | Action system callback: sequences, sounds, fades, character speech |
| ET_HAIL | Bridge/HelmMenuHandlers.py | Ship being hailed | Helm menu button activation event |
| ET_SET_ALERT_LEVEL | Bridge/XOMenuHandlers.py, QuickBattle.py | Ship to set alert on | Bridge/XO menu: Red/Yellow/Green alert |
| ET_MISSION_START | Maelstrom/Episode*/Episode*.py, QuickBattle.py, Tutorial | Mission object | Episode initialization |
| ET_CHARACTER_ANIMATION_DONE | Bridge/Characters/SmallAnimations.py, PicardAnimations.py | Character object | Animation completion callback |
| ET_ORBIT_PLANET | Bridge/HelmMenuHandlers.py | Planet object | Helm: orbit planet command |
| ET_SCAN | Bridge/ScienceMenuHandlers.py | Target object | Science: scan target |
| ET_LAUNCH_PROBE | Bridge/ScienceMenuHandlers.py | Probe object | Science: launch probe |
| ET_MANEUVER | Bridge/TacticalMenuHandlers.py | Target/waypoint object | Tactical menu maneuver command |
| ET_AI_TIMER | Conditions/ConditionTimer.py, ConditionInLineOfSight.py | Condition source object | AI condition timer expiry |
| ET_AI_SHIELD_WATCHER | Conditions/ConditionSingleShieldBelow.py | Ship object | AI shield monitoring |
| ET_AI_CONDITION_CHANGED | Conditions/ConditionCriticalSystemBelow.py | Ship object | AI condition state change |
| ET_AI_ORBITTING | AI/Player/OrbitPlanet.py | Planet object | AI orbit completion |
| ET_SUBSYSTEM_POWER_CHANGED | Bridge/EngineerMenuHandlers.py | Subsystem object | Engineering power slider adjustment |
| ET_DELETE_OBJECT_PUBLIC | loadspacehelper.py | Object to delete | Object deletion request |
| ET_MUSIC_CONDITION_CHANGED | DynamicMusic.py | Condition source | Music system condition transition |
| ET_OTHER_BEAM_TOGGLE_CLICKED | BridgeHandlers.py | Button/UI object | Tactical: beam weapon toggle |
| ET_OTHER_CLOAK_TOGGLE_CLICKED | BridgeHandlers.py | Button/UI object | Tactical: cloak toggle |
| ET_RADAR_TOGGLE_CLICKED | Bridge/TacticalMenuHandlers.py | Radar display object | Radar display toggle |
| ET_OKAY | WarpSequence.py, KeyboardConfig.py | Context-dependent | Generic OK/confirm event |
| ET_CANCEL_BINDING | MainMenu/KeyboardConfig.py | Config object | Cancel keyboard binding |
| ET_CLEAR_BINDINGS | MainMenu/KeyboardConfig.py | Config object | Clear all bindings |
| ET_NEW_GAME | MainMenu/mainmenu.py | Game/config object | Start new game |
| ET_START | Multiplayer/MultiplayerMenus.py | Lobby/game object | Start multiplayer game |
| ET_SORT_SERVER_LIST | Multiplayer/MultiplayerMenus.py | Server list object | Sort server browser |
| ET_SELECT_SERVER_ENTRY | Multiplayer/MultiplayerMenus.py | Server entry object | Select server in browser |
| ET_REFRESH_SERVER_LIST | Multiplayer/MultiplayerMenus.py | Server list object | Refresh server browser |

## Consolidated Event Type Hex Map

Based on handler registration cross-references (handler name strings contain the ET_ constant name):

| Hex | ET_ Constant | Handler Name Evidence |
|-----|-------------|----------------------|
| 0x0080000E | ET_SET_PLAYER | "Game__HandleSetPlayer", "Mission__PlayerChanged", "SetPlayerHandler" |
| 0x00800058 | ET_TARGET_WAS_CHANGED | "ChangedTarget", "HandleTargetChanged", "TargetChangedHandler" |
| 0x0080006B | ET_SUBSYSTEM_HIT | "DamageDisplay__HandleSubsystemEv", "HandleSubsystemEvent" |
| 0x00800076 | ET_REPAIR_INCREASE_PRIORITY | "RepairSubsystem__HandleIncreaseP", "RepairListPri" |
| 0x0080007C | ET_WEAPON_FIRED | (multiple weapon fire functions, confirmed by vtable + code) |
| 0x0080007D | ET_TRACTOR_BEAM_STARTED_FIRING | "TacWeaponsCtrl__HandleTractorB" (same handler as 0x7F) |
| 0x0080007F | ET_TRACTOR_BEAM_STOPPED_FIRING | "TacWeaponsCtrl__HandleTractorB" |
| 0x00800081 | ET_PHASER_STARTED_FIRING | (vtable xref at 0x005712FE in phaser code) |
| 0x00800083 | ET_PHASER_STOPPED_FIRING | (vtable xref at 0x005712FE in phaser code) |
| 0x00800085 | ET_TRACTOR_TARGET_DOCKED | (FUN_00580910 tractor docking code) |
| 0x00800088 | ET_SENSORS_SHIP_IDENTIFIED | "STTargetMenu__ObjectIdentified", "ShieldsDisplay__ShipIdentified" |
| 0x008000DB | ET_STOP_FIRING_AT_TARGET | "PhaserSystem__StopFiringAtTarget", "TractorBeamSystem__StopFiringAtT" (command) |
| 0x008000DC | ET_STOP_FIRING_AT_TARGET_NOTIFY | "MultiplayerGame____StopFiringAtT" (notification) |
| 0x00050001 | (AI/Timer internal) | Timer delivery mechanism, not a game event |

## Related Documents

- [pythonevent-wire-format.md](pythonevent-wire-format.md) — PythonEvent (0x06) wire format (4 event classes)
- [repair-event-object-ids.md](../gameplay/repair-event-object-ids.md) — ADD_TO_REPAIR_LIST event chain, TGObject ID assignment
- [set-phaser-level-protocol.md](set-phaser-level-protocol.md) — TGCharEvent (0x105) detailed analysis
- [weapon-firing-mechanics.md](../gameplay/weapon-firing-mechanics.md) — Weapon fire/stop events (TGObjPtrEvent producers)
- [repair-system.md](../gameplay/repair-system.md) — Repair queue, ET_REPAIR_INCREASE_PRIORITY
- [stock-trace-analysis.md](../analysis/stock-trace-analysis.md) — Ground truth traces confirming 45% volume
