# TGObjPtrEvent Complete Catalog

## Class Details

- **Factory ID**: 0x010C
- **Constructor**: `FUN_00403290` (0x00403290)
- **Vtable**: `PTR_FUN_0088869c` (0x0088869C)
- **Base class**: TGEvent (factory 0x0101, constructor `FUN_006d5c00`)
- **Size**: 0x2C bytes (44 bytes) -- TGEvent is 0x28, +4 for obj_ptr
- **Layout**:
  - `+0x00`: vtable pointer
  - `+0x04`: object ID (from TGObject)
  - `+0x08`: source pointer (TGObject*)
  - `+0x0C`: destination pointer (TGObject*)
  - `+0x10`: eventType (int, the ET_ constant)
  - `+0x14-0x27`: remaining TGEvent fields (refcount at +0x1A, stream data at +0x20/0x24)
  - `+0x28`: **obj_ptr** (int -- object ID, NOT a raw pointer)

## Wire Format (Serialized via TGStreamedObject)

When sent over network as opcode 0x06 (PythonEvent):
```
[short: factoryType=0x010C] [int: eventType] [int: sourceObjID] [int: destObjID] [int: objPtrObjID]
```
Total: 16 bytes payload (after the 2-byte factory header).

## Complete Event Type Table

### C++ Producers (from constructor xrefs)

30 xref sites to the constructor produce TGObjPtrEvents. After de-duplicating (some functions create multiple events, some are infrastructure/factory code), here are the distinct event types:

| Hex Code | ET_ Constant | Producer Function | obj_ptr Contains | Trigger |
|----------|-------------|-------------------|-----------------|---------|
| 0x0080000E | ET_SET_PLAYER | FUN_004066d0 (Game::SetPlayer) | New player ship's object ID | Player assignment changes (start of game, player switch) |
| 0x00050001 | (AI timer callback) | FUN_007022f0, FUN_007023e0 | Timer source object ID | Timer-delivered event: fires when a TGTimer expires, dest=0x99b010 (global timer singleton) |
| 0x00800058 | ET_TARGET_WAS_CHANGED | FUN_005ae210 (Ship::SetTarget) | **Previous** target's object ID (or 0 if none) | Ship changes its targeting lock |
| 0x0080006B | ET_SUBSYSTEM_HIT | FUN_0056c470 (SubsystemClass::SetCondition) | Subsystem's own object ID | Subsystem takes damage (HP set below max); gated on ship+0x14C time threshold |
| 0x00800076 | ET_REPAIR_INCREASE_PRIORITY | FUN_005519e0 (RepairSubsystem::IncreasePriority) | Repair target subsystem's object ID | Player manually increases repair priority for a subsystem |
| 0x0080007C | ET_WEAPON_FIRED | FUN_00571f40 (PhaserSystem::Fire), FUN_0057c9e0 (TorpedoSystem::Fire), FUN_0057f580 (TractorBeam::Fire) | Target object ID (via FUN_006f0ee0 lookup of +0x8C), or 0 if untargeted | Any weapon system begins firing |
| 0x0080007D | ET_TRACTOR_BEAM_STARTED_FIRING | FUN_0057f580 (TractorBeam::Fire) | Target object ID | Tractor beam specifically begins firing (fired alongside ET_WEAPON_FIRED) |
| 0x00800081 | ET_PHASER_STARTED_FIRING | FUN_00571f40 (PhaserSystem::Fire) | Target object ID | Phaser specifically begins firing (fired alongside ET_WEAPON_FIRED) |
| 0x00800085 | ET_TRACTOR_TARGET_DOCKED | FUN_00580910 (TractorBeam::Update/Dock) | Docked ship's object ID | Tractor beam successfully docks with target |
| 0x00800088 | ET_SENSORS_SHIP_IDENTIFIED | FUN_00568ad0 (SensorSubsystem::IdentifyShip), FUN_005678b0 (SensorSubsystem::ScanComplete) | Identified ship's object ID | Sensor scan completes and identifies a ship |
| 0x008000DC | ET_STOP_FIRING_AT_TARGET_NOTIFY | FUN_00574010 (PhaserSystem::StopFiringAtTarget), FUN_005825a0 (TractorBeam::StopFiringAtTarget) | Target ship's object ID (or 0) | Weapon system stops firing at a specific target; host-only gated |

### C++ Producers in Unanalyzed Code Regions

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

### Python Producers (via TGObjPtrEvent_Create SWIG API)

Python scripts create TGObjPtrEvents via `App.TGObjPtrEvent_Create()` + `SetEventType()` + `SetObjPtr()`. The SWIG functions `swig_TGObjPtrEvent_Create` (0x005C8000) and `swig_TGObjPtrEvent_SetObjPtr` (0x005C80E0) have zero C++ xrefs -- they are called exclusively from Python.

Unique event types used with TGObjPtrEvent in Python scripts:

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

## Multiplayer Relevance

Events that cross the network boundary (via opcode 0x06 PythonEvent relay):
- **ET_SUBSYSTEM_HIT** (0x0080006B): Fired by `SetCondition` when subsystem takes damage. Serialized as TGObjPtrEvent factory 0x010C.
- **ET_STOP_FIRING_AT_TARGET_NOTIFY** (0x008000DC): Host-only gated. Forwarded via GenericEventForward (opcode 0x09/0x0C).
- **ET_WEAPON_FIRED** (0x0080007C): Forwarded via StartFiring (opcode 0x07).
- **ET_REPAIR_INCREASE_PRIORITY** (0x00800076): Forwarded via RepairListPriority (opcode 0x11).

Most other TGObjPtrEvent types are local-only (UI updates, bridge menus, action callbacks).

## Notes

1. **obj_ptr is an object ID, not a raw pointer**: The field at +0x28 stores `obj->GetObjID()` (obj+0x04), retrieved by the receiver via `FUN_006f0ee0` (hash lookup). This is safe for network serialization.

2. **FUN_005519e0 manually sets vtable**: Instead of calling `FUN_00403290`, it calls `FUN_006d5c00` (TGEvent ctor) then manually writes `*this = &PTR_FUN_0088869c`. Functionally identical.

3. **Dual-fire pattern**: Phaser and tractor beam fire functions create TWO TGObjPtrEvents -- one specific (ET_PHASER_STARTED_FIRING / ET_TRACTOR_BEAM_STARTED_FIRING) and one generic (ET_WEAPON_FIRED). Torpedo fire only creates ET_WEAPON_FIRED.

4. **ET_TARGET_WAS_CHANGED obj_ptr = PREVIOUS target**: Unusual -- most events store the new state, but this one stores the old target so handlers can clean up references to it.

5. **Timer events (0x00050001)**: These use TGObjPtrEvent as a delivery vehicle for timer callbacks. The event is wrapped in a TGTimer, and when the timer fires, the event is dispatched. dest = 0x99b010 (global timer target). Not a game event per se.
