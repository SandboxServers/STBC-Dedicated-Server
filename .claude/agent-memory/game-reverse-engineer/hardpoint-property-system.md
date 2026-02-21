# Hardpoint/Property System RE

## Overview
Ship hardpoints in BC are defined by Python scripts (`ships/Hardpoints/<name>.py`) that:
1. Create property objects via `App.<Type>Property_Create("Name")`
2. Configure them with setter calls
3. Register them as local templates via `App.g_kModelPropertyManager.RegisterLocalTemplate(prop)`
4. Attach them to the ship model via `pObj.AddToSet("Scene Root", prop)` in `LoadPropertySet(pObj)`

The engine then walks all properties attached to "Scene Root" and creates corresponding subsystem objects.

## AddToSet (0x006c9520 = TGModelContainer::ExtractModel)

The address 0x006c9520 is actually `TGModelContainer::ExtractModel`, which handles model extraction and property attachment. The SWIG wrapper `swig_TGModelPropertySet_AddToSet` at 0x005dec60 has format string "OOO" = 3 arguments:
- arg1: self (TGModelPropertySet, the ship model)
- arg2: node name string (always "Scene Root" in practice)
- arg3: property instance (TGModelPropertyInstance)

The C++ implementation at 0x006eb220 (called from SWIG wrapper) takes a NIF node name and a property, searches the scene graph for the named node, and attaches the property to it. The "Scene Root" string is compared at 0x008daec8.

## Property Type Constants (CT_ IDs)

The `vtable+8` function is `IsA(typeID)` which returns true if the object is of the given type or a subclass. The `vtable+4` function is `GetType()` which returns the exact type.

### Property Type IDs (0x812x range)
| ID | CT_ Name | Python Create | Cast Function |
|----|----------|---------------|---------------|
| 0x812b | CT_SUBSYSTEM_PROPERTY (base) | - | FUN_006923f0 |
| 0x812e | CT_SHIP_PROPERTY | ShipProperty_Create | FUN_00691190 |
| 0x812f | CT_WEAPON_SYSTEM_PROPERTY | WeaponSystemProperty_Create | FUN_0069af60 |
| 0x8130 | CT_POSITION_ORIENTATION_PROPERTY | (viewscreens, etc.) | - |
| 0x8131 | (unknown, used in AI) | - | - |
| 0x8132 | CT_PHASER_PROPERTY | PhaserProperty_Create | FUN_00685800 |
| 0x8133 | CT_TORPEDO_SYSTEM_PROPERTY | TorpedoSystemProperty_Create | FUN_00693ed0 |
| 0x8134 | CT_TORPEDO_TUBE_PROPERTY | TorpedoTubeProperty_Create | FUN_00694fe0 |
| 0x8135 | CT_PULSE_WEAPON_PROPERTY | PulseWeaponProperty_Create | FUN_0068c0f0 |
| 0x8136 | CT_ENERGY_WEAPON_PROPERTY | (base, not directly created?) | FUN_006966b0 |
| 0x8137 | CT_SHIELD_PROPERTY | ShieldProperty_Create | - |
| 0x8138 | CT_POWER_PROPERTY | PowerProperty_Create | - |
| 0x8139 | CT_SENSOR_PROPERTY | SensorProperty_Create | - |
| 0x813a | CT_CLOAKING_SUBSYSTEM_PROPERTY | CloakingSubsystemProperty_Create | - |
| 0x813b | CT_REPAIR_SUBSYSTEM_PROPERTY | RepairSubsystemProperty_Create | - |
| 0x813c | CT_HULL_PROPERTY | HullProperty_Create | - |
| 0x813d | CT_ENGINE_GLOW_PROPERTY | EngineGlowProperty_Create | FUN_006821c0 |
| 0x813e | CT_POWERED_SUBSYSTEM_PROPERTY (base) | PoweredSubsystemProperty_Create | - |
| 0x813f | CT_ENGINE_PROPERTY (base) | EngineProperty_Create | - |
| 0x8145 | (unknown, used in SetupProperties) | - | - |

### Related Parent Type IDs (0x80xx range for subsystems)
| ID | Meaning | Used in |
|----|---------|---------|
| 0x801c | PoweredSubsystem (base type) | LinkSubsystemToParent: adds child to Powered master |
| 0x8021 | (unknown subsystem check) | FUN_005b3e50 classification |
| 0x8024 | (unknown subsystem check) | FUN_005b3e50 classification |
| 0x8025 | (unknown subsystem check) | FUN_005b3e50 classification |
| 0x802a | Weapon (base type) | LinkSubsystemToParent: triggers parent dispatch |
| 0x802c | PhaserBank | LinkSubsystemToParent: parent = ship+0x2B8 |
| 0x802d | PulseWeapon | LinkSubsystemToParent: parent = ship+0x2BC |
| 0x802e | TractorBeam | LinkSubsystemToParent: parent = ship+0x2D4 |
| 0x802f | TorpedoTube | LinkSubsystemToParent: parent = ship+0x2B4 |

## WeaponSystemType (WST_) Enum
| Value | Name | Created Subsystem | Vtable | Ship Field |
|-------|------|-------------------|--------|------------|
| 0 | WST_UNKNOWN | (none) | - | - |
| 1 | WST_PHASER | PhaserSystem (FUN_00573c90) | 0x893240 | ship+0x2B8 |
| 2 | WST_TORPEDO | TorpedoSystem (FUN_0057b020) | 0x893598 | ship+0x2B4 |
| 3 | WST_PULSE | PulseWeaponSystem (FUN_005773b0) | 0x8933B0 | ship+0x2BC |
| 4 | WST_TRACTOR | TractorBeamSystem (FUN_00582080) | 0x893794 | ship+0x2D4 |

NOTE: WST_TORPEDO (2) is NOT handled in the 0x812f/WeaponSystemProperty switch in SetupProperties! Torpedo systems use their own property type (0x8133, CT_TORPEDO_SYSTEM_PROPERTY, case 0x8133 in SetupProperties), NOT WeaponSystemProperty with WST_TORPEDO. The WST_TORPEDO enum exists but the SetupProperties switch for 0x812f only handles 1 (PHASER), 3 (PULSE), 4 (TRACTOR).

## SetupProperties (0x005b3fb0) - Complete Switch Table

Called for EACH property attached to the scene graph. Dispatches on property type:

| Case | Type ID | Property Type | Action |
|------|---------|---------------|--------|
| 0x812e | ShipProperty | Sets up ship metadata (FUN_005b5240) |
| 0x8145 | (unknown) | FUN_005b5280 |
| 0x812f | WeaponSystemProperty | Creates WeaponSystem subsystem based on WST_ type; if IsPrimary: assigns to ship field |
| 0x8132 | PhaserProperty | Creates PhaserBank (FUN_00570d70, size 0x128), sets up arc angles and orientation |
| 0x8133 | TorpedoSystemProperty | Creates TorpedoSystem (FUN_0057b020, size 0x11C); if IsPrimary: ship+0x2B4 |
| 0x8134 | TorpedoTubeProperty | Creates TorpedoTube (FUN_0057c4b0, size 0xB0), sets up direction vectors |
| 0x8135 | PulseWeaponProperty | Creates PulseWeapon (FUN_00574fd0, size 0xD4), sets up orientation |
| 0x8136 | EnergyWeaponProperty | Creates EnergyWeapon (FUN_0057ec70, size 0x100), sets up orientation |
| 0x8137 | ShieldProperty | Creates ShieldSubsystem (FUN_0056a000, size 0x15C); if IsPrimary: ship+0x2C0 |
| 0x8138 | PowerProperty | Creates PowerSubsystem (FUN_00560470, size 0x88); if IsPrimary: ship+0x2C4 |
| 0x8139 | SensorProperty | Creates SensorSubsystem (FUN_00566d10, size 0xCC); if IsPrimary: ship+0x2C8 |
| 0x813a | CloakingSubsystemProperty | Creates CloakingSubsystem (FUN_0055e2b0, size 0xBC); if IsPrimary: ship+0x2DC |
| 0x813b | RepairSubsystemProperty | Creates RepairSubsystem (FUN_0056de70, size 0xD4); if IsPrimary: ship+0x2D0 |
| 0x813c | HullProperty | Creates HullSubsystem (FUN_00561050, size 0xBC); if IsPrimary: ship+0x2CC |
| 0x813d | EngineGlowProperty | Creates EngineGlow (FUN_0056b970, size 0x88); NO ship field assignment |
| 0x813e | PoweredSubsystemProperty | Creates Powered master (FUN_00563530, size 0xDC); if IsPrimary: ship+0x2B0 |
| 0x813f | EngineProperty | Creates EngineSubsystem (FUN_00565090, size 0xC0); if IsPrimary: ship+0x2D8 |

After creating ANY subsystem (except ShipProperty/0x8145):
1. `FUN_005b3e50(ship, subsystem)` - adds to ship+0x284 linked list AND classifies
2. `vtable+0x58(ship)` - calls subsystem->SetShip(ship)

## IsPrimary Flag (property+0x26)

The `IsPrimary` flag at property offset +0x26 determines whether the created subsystem is assigned to the ship's primary pointer for that type. If IsPrimary==1, the subsystem is stored in the corresponding ship field (e.g., ship+0x2B8 for PhaserSystem). If IsPrimary==0, the subsystem is still created and added to ship+0x284 list, but NOT assigned to the ship's primary pointer.

In practice: system containers (Phasers, Torpedoes, Tractors, Shield Generator, etc.) have IsPrimary=1. Individual weapons and engine glows usually have IsPrimary=0 except when they are the ONLY instance.

## Ship Field Map (subsystem primary pointers)
| Offset | Type | Set By |
|--------|------|--------|
| ship+0x2B0 | Powered (EPS master) | 0x813e PoweredSubsystemProperty |
| ship+0x2B4 | TorpedoSystem | 0x8133 TorpedoSystemProperty OR 0x812f WST_TORPEDO=2 (see note) |
| ship+0x2B8 | PhaserSystem | 0x812f WST_PHASER=1 |
| ship+0x2BC | PulseWeaponSystem | 0x812f WST_PULSE=3 |
| ship+0x2C0 | ShieldSubsystem | 0x8137 ShieldProperty |
| ship+0x2C4 | PowerSubsystem (reactor) | 0x8138 PowerProperty |
| ship+0x2C8 | SensorSubsystem | 0x8139 SensorProperty |
| ship+0x2CC | HullSubsystem | 0x813c HullProperty |
| ship+0x2D0 | RepairSubsystem | 0x813b RepairSubsystemProperty |
| ship+0x2D4 | TractorBeamSystem | 0x812f WST_TRACTOR=4 |
| ship+0x2D8 | EngineSubsystem | 0x813f EngineProperty |
| ship+0x2DC | CloakingSubsystem | 0x813a CloakingSubsystemProperty |

## Parent-Child Assignment (LinkSubsystemToParent, FUN_005b5030)

Called by Ship_LinkAllSubsystemsToParents (FUN_005b3e20) which walks ship+0x284 linked list.

For each subsystem in the linked list:
1. **PoweredSubsystem check** (IsA 0x801c): Adds subsystem as child of Powered master (ship+0x2B0) via FUN_005623c0 -> FUN_00563d50 (adds to Powered+0xC4/+0xC8/+0xCC linked list)

2. **Weapon check** (IsA 0x802a): Gets exact weapon type via GetType(), dispatches:
   - 0x802c (PhaserBank) -> parent = ship+0x2B8 (PhaserSystem)
   - 0x802d (PulseWeapon) -> parent = ship+0x2BC (PulseWeaponSystem)
   - 0x802e (TractorBeam) -> parent = ship+0x2D4 (TractorBeamSystem)
   - 0x802f (TorpedoTube) -> parent = ship+0x2B4 (TorpedoSystem)

   Parent assignment uses FUN_0056c5c0 (AddChild): grows child array at parent+0x20, increments count at parent+0x1C. Then REMOVES the child from ship+0x284 list.

3. **EngineGlow check** (IsA 0x813d): Gets glow type field at +0x48:
   - 0 -> parent = ship+0x2CC (HullSubsystem)
   - 1 -> parent = ship+0x2D0 (RepairSubsystem)

   Same AddChild + remove from ship+0x284 pattern.

### KEY INSIGHT: Parent-child is NOT based on AddToSet order!

The linking is entirely based on TYPE CHECKING, not on property registration order. The engine:
1. Creates ALL subsystems (flat list in ship+0x284)
2. THEN runs LinkAllSubsystemsToParents which reparents children based on their type

Individual phasers (type 0x802c) get assigned to whatever PhaserSystem (ship+0x2B8) exists. Individual torpedo tubes (type 0x802f) get assigned to whatever TorpedoSystem (ship+0x2B4) exists. The order of AddToSet calls does not matter for parent-child relationships.

## AddChild (FUN_0056c5c0)

`__thiscall(parent, child_subsystem)`:
- Reallocates child array at parent+0x20 (grows by 1)
- Copies existing children from old array
- Appends new child at end
- Increments parent+0x1C (child count)
- Calls `child->vtable+0x5C(parent)` (SetParent)
- Calls `child->vtable+0x58(parent+0x40)` (SetShip? or set owner)

## Powered Master AddChild (FUN_005623c0 -> FUN_00563d50)

Different structure: uses a linked list at Powered+0xC4/+0xC8/+0xCC (count/tail/head), NOT an array.

## Classification (FUN_005b3e50)

When a subsystem is first added to ship+0x284, it is also classified:
- IsA checks cascade: 0x801c (PoweredSS) > 0x8021 > 0x802c/0x802d/0x802e/0x802f > 0x8025 > 0x8024
- Non-matching subsystems (non-powered, non-weapon) go into ship+0x298/+0x29C/+0x2A0 secondary list

## Multiple PowerProperty

SetupProperties creates a PowerSubsystem for EACH PowerProperty encountered. The `if (IsPrimary)` check assigns it to ship+0x2C4. If a second PowerProperty with IsPrimary=1 is added, it OVERWRITES ship+0x2C4 (last-wins). In practice, ships only have ONE PowerProperty ("Warp Core"). Multiple non-primary PowerProperty instances would create subsystems in ship+0x284 but not be the ship's primary reactor.

## Sovereign Hardpoint AddToSet Order (45 properties)
1. Hull, Shield Generator, Sensor Array, Warp Core, Impulse Engines
2. Torpedoes (system), Forward Torpedo 1-4, Aft Torpedo 1-2
3. Ventral Phaser 1-4, Dorsal Phaser 1-4
4. Port Impulse, Star Impulse (engine glows)
5. Port Warp, Star Warp (engine glows)
6. Repair, Probe Launcher
7. Sovereign (ShipProperty)
8. Shuttle Bay
9. Phasers (WeaponSystemProperty WST_PHASER)
10. Tractors (WeaponSystemProperty WST_TRACTOR)
11. Warp Engines
12. Bridge (HullProperty)
13. Aft Tractor 1-2
14. Decoy launcher
15. Viewscreens (6), FirstPerson
16. Forward Tractor 1-2, Shuttle Bay 2

NOTE: System containers (Phasers, Tractors, Torpedoes) are added AFTER their individual weapons. This is fine because parent-child linking happens AFTER all properties are processed.
