# Subsystem Class Hierarchy - Vtable Map

## Class Hierarchy
```
TGObject
  TGStreamedObject
    TGStreamedObjectEx
      TGEventHandlerObject (vtable 0x00896044, 22 slots)
        ShipSubsystem (vtable 0x00892fc4, 30 slots)
          PoweredSubsystem (vtable 0x00892d98, 34 slots)
            ShieldSubsystem (vtable 0x00892f34)
            ImpulseEngineSubsystem (vtable 0x00892d10)
            WarpEngineSubsystem (vtable 0x00893040)
            SensorSubsystem (vtable 0x00892eac)
            RepairSubsystem (vtable 0x00892e24)
            CloakingSubsystem (vtable 0x00892c04)
            WeaponSystem (vtable 0x008938c4, 55 slots)
              PhaserSystem (vtable 0x00893240)
              TorpedoSystem (vtable 0x00893598)
              TractorBeamSystem (vtable 0x00893794)
              PulseWeaponSystem (vtable 0x008933b0)
            PoweredMaster "Powered" (vtable 0x0088a1f0) [EPS system]
          PowerSubsystem (vtable 0x00892c98) [reactor, NOT PoweredSubsystem]
          WeaponSubsystem (vtable 0x00893834)
            PhaserSubsystem/EnergyWeapon (vtable 0x008930d8)
              PulseWeapon (vtable 0x00893318)
```

Note: WeaponSubsystem and PowerSubsystem inherit from ShipSubsystem directly (NOT PoweredSubsystem).
WeaponSystem inherits from PoweredSubsystem (weapon SYSTEM is powered; weapon SUBSYSTEM is the individual gun).

## ShipSubsystem Vtable Slots (30 slots, base at 0x00892fc4)

| Slot | Offset | Method | Evidence |
|------|--------|--------|----------|
| 0 | 0x00 | ScalarDeletingDtor | Standard C++ |
| 1 | 0x04 | dtor variant 1 | Standard C++ |
| 2 | 0x08 | dtor variant 2 | Standard C++ |
| 3 | 0x0C | GetRTTI | TGObject hierarchy |
| 4 | 0x10 | **WriteToStream** | Named, confirmed multiple classes |
| 5 | 0x14 | **ReadFromStream** | Named, confirmed |
| 6 | 0x18 | **ResolveObjectRefs** | Decompiled: checks all refs resolvable |
| 7 | 0x1C | **FixupObjectRefs** | Decompiled: replaces IDs with ptrs |
| 8 | 0x20 | (inherited TGObject) | |
| 9-11 | 0x24-0x2C | (inherited TGEHO) | |
| 12-18 | 0x30-0x48 | (inherited TGObject) | |
| 19 | 0x4C | (TGEHO virtual) | |
| 20 | 0x50 | ProcessEvent | Decompiled: event dispatch |
| 21 | 0x54 | **GetPosition** | SWIG: vtable+0x54, copies prop+0x28/2C/30 |
| 22 | 0x58 | **SetParentShip** | SWIG: vtable+0x58 |
| 23 | 0x5C | (base no-op at 0x440120) | Shared by ALL classes, never overridden |
| 24 | 0x60 | **SetProperty** | SWIG: vtable+0x60 |
| 25 | 0x64 | **Update** | SWIG: vtable+0x64 |
| 26 | 0x68 | **WriteState_A** | Named, child dispatch via vtable+0x68 |
| 27 | 0x6C | **ReadState_A** | Named |
| 28 | 0x70 | **WriteState_B** | Named |
| 29 | 0x74 | **ReadState_B** | Named |

## PoweredSubsystem New Slots (slots 30-33)

| Slot | Offset | Method | Evidence |
|------|--------|--------|----------|
| 30 | 0x78 | **GetNormalPowerWanted** | SWIG: vtable+0x78 |
| 31 | 0x7C | **TurnOn (PostEnabledEvent)** | SWIG: vtable+0x7C |
| 32 | 0x80 | **TurnOff (PostDisabledEvent)** | SWIG: vtable+0x80 |
| 33 | 0x84 | unknown (0x00562a40) | Not yet defined in Ghidra |

## WeaponSystem New Slots (slots 34-54)

| Slot | Offset | Method | Evidence |
|------|--------|--------|----------|
| 34 | 0x88 | **StartFiringAtTarget** | Named, decompiled |
| 35 | 0x8C | unknown | |
| 36 | 0x90 | **StopFiringAll** | Named, decompiled |
| 37 | 0x94 | unknown (overridden by TorpedoSystem) | |
| 38 | 0x98 | (small helper dtor) | |
| 39-54 | 0x9C-0xD8 | weapon-specific virtuals | Need further analysis |

## Override Map (which subclasses override which slots)

### WriteToStream / ReadFromStream (slots 4-5)
- ShieldSubsystem: OVERRIDES (0x0056ab60 / 0x0056ac10) [undefined in Ghidra]
- ImpulseEngineSubsystem: OVERRIDES (named)
- WarpEngineSubsystem: OVERRIDES (named)
- SensorSubsystem: OVERRIDES (0x00568190 / 0x00568210) [undefined]
- RepairSubsystem: OVERRIDES (0x00565e20 / named ReadFromStream)
- CloakingSubsystem: OVERRIDES (named)
- WeaponSystem: OVERRIDES (named)
- WeaponSubsystem: OVERRIDES (named)
- EnergyWeapon/PhaserSubsystem: OVERRIDES (named)
- PulseWeapon: OVERRIDES (named)
- PowerSubsystem: INHERITS from ShipSubsystem
- PoweredMaster: OVERRIDES (WriteToStream named, ReadFromStream undefined)

### Update (slot 25)
- PoweredSubsystem: OVERRIDES (named)
- ShieldSubsystem: OVERRIDES (0x0056a230) [undefined]
- ImpulseEngineSubsystem: OVERRIDES (0x00561180) [undefined]
- SensorSubsystem: OVERRIDES (0x005670b0) [undefined]
- RepairSubsystem: OVERRIDES (0x005652a0) [undefined]
- CloakingSubsystem: OVERRIDES (named)
- WeaponSystem: OVERRIDES (named)
- WeaponSubsystem: OVERRIDES (named, delegates to ShipSubsystem__Update)
- PowerSubsystem: INHERITS from ShipSubsystem
- PoweredMaster: OVERRIDES (named)

### SetParentShip (slot 22)
- PoweredSubsystem: OVERRIDES (also calls ScheduleShieldEvents)
- CloakingSubsystem: OVERRIDES (0x0055f0d0) [undefined]
- All others: INHERIT from PoweredSubsystem or ShipSubsystem

### SetProperty (slot 24)
- ShieldSubsystem: OVERRIDES (0x0056a4f0) [undefined]
- SensorSubsystem: OVERRIDES (0x00567080) [undefined]
- EnergyWeapon: OVERRIDES (named as EnergyWeapon__SetPropertyAndInit)
- All others: INHERIT ShipSubsystem__SetProperty

### TurnOff (slot 32)
- CloakingSubsystem: OVERRIDES (named CloakingSubsystem__TurnOff) - auto-decloaks
- WeaponSystem: OVERRIDES (named WeaponSystem__OnDisabled) - clears target list
- All others: INHERIT PoweredSubsystem__PostDisabledEvent

## Naming Corrections Applied This Session
1. ShieldProperty__SetPower -> ShipSubsystem__SetParentShip (vtable slot 22, writes this+0x40)
2. ShieldSubsystem__SetPowerLevel -> PoweredSubsystem__SetParentShip (override)
3. Subsystem__IsActive -> ShipSubsystem__IsTargetable (reads prop+0x25)
4. ShieldProperty__GetCurrentPower -> ShipSubsystem__GetDisabledPercentage (reads prop+0x40)
5. ShieldSubsystem__ReadState -> ShieldSubsystem__WriteState_B (calls WriteState, not Read)
6. ShipSubsystem__SetPropertyAndRestoreHP -> ShipSubsystem__SetProperty (SWIG name)
7. Subsystem__GetRadius -> ShipSubsystem__GetRadius
8. Subsystem__GetChild -> ShipSubsystem__GetChild
