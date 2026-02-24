# Weapon & Projectile Class Hierarchy (Phase 8J, 2026-02-24)

## Inheritance Tree
```
ShipSubsystem (base for individual weapon instances)
  -> WeaponSubsystem (0x583280, size varies)
       +0x8C = target entry (objectID + offset)
       +0x9C = enabled flag
       -> EnergyWeapon (0x56f950)
            +0xA0 = current charge
            +0xA4/A8 = fire state
            +0xAC = ammo/mode
            +0xB0 = fire target NiSmartPtr
            +0xBC = charge ratio (charge/maxCharge)
            -> PhaserBank (0x570d70, size 0x128)
                 +0x11C/120/124 = rest position (beam at arc center)
                 +0x118 = accumulated damage time
                 +0x88 = hasBeam flag
            -> TractorBeam (0x581350)
                 +0xFC = operating mode (0-5)
            -> PulseWeapon (0x574fd0, size 0xD4)
                 +0xC8/CC/D0 = pulse-specific fields
       -> TorpedoTube (0x57c4b0, size 0xB0)
            +0xA0 = loaded ammo count
            +0xA4 = reload timer
            +0xA8 = fire state flag
            +0xAC = ready slots array pointer

PoweredSubsystem -> WeaponSystem (0x5840a0, size 0xF0)
  +0x9C = active flag
  +0xA8 = firing requested
  +0xA9 = was firing
  +0xAB = any child firing
  +0xAC = single fire flag
  +0xB4 = last fired weapon index
  +0xBC = chain index
  +0xC0 = target count
  +0xC4 = target list (linked list of WeaponTargetEntry*)
  +0xCC = free pool
  +0xD8 = firing chain count
  +0xDC = firing chain list
  -> PhaserSystem (0x573c90, size 0xF4)
       +0xF0 = power level (0/1/2)
  -> TorpedoSystem (0x57b020, size 0x11C)
       +0x114 = current ammo type byte
  -> TractorBeamSystem (0x582080, powerMode=1 backup-first)
  -> PulseWeaponSystem (0x5773b0, size 0xF0)

PhysicsObjectClass -> Torpedo (0x5783d0, size 0x170, vtable 0x00893458)
  +0x108 = sub-object
  +0x118 = target object ID (for homing)
  +0x11C-0x124 = target offset position
  +0x128 = owner ship ID (for kill credit)
  +0x12C = Python script name
  +0x134 = turn rate scale (default 0.125)
  +0x138 = max speed (default 60.0)
  +0x13C/140 = turn rate params (default 4.0)
  +0x144 = damage radius (default 100.0)
  +0x148 = has skew fire
  +0x14C = is dumb fire (no homing)
  +0x150-0x15C = last known target position
  +0x15C-0x168 = current target position
  +0x16C = is new torpedo flag
```

## Serialization Methods Summary
| Class | WriteToStream | ReadFromStream | WriteState | ReadState |
|-------|--------------|----------------|------------|-----------|
| WeaponSubsystem | 0x583400 | 0x583440 | - | - |
| EnergyWeapon | 0x56fe30 | 0x56feb0 | - | - |
| PhaserBank | 0x573040 | 0x5730a0 | - | - |
| PulseWeapon | 0x5769a0 | 0x5769f0 | - | - |
| TractorBeam | 0x5814f0 | 0x581550 | - | - |
| TorpedoTube | 0x57df40 | 0x57dfd0 | - | - |
| WeaponSystem | 0x585a70 | 0x585b80 | 0x585a10 | 0x585a40 |
| PhaserSystem | - | - | 0x5741a0 | 0x5741d0 |
| TorpedoSystem | 0x57b780 | 0x57b7b0 | - | - |
| Torpedo | 0x57a280 | 0x57a400 | (net: 0x579cc0) | - |

## Key Weapon Mechanics
- **Phaser charge**: EnergyWeapon +0xA0=charge, +0xBC=ratio. Discharge scales by power level (3 constants).
  Client non-player ships recharge at 2x rate (DAT_00890550).
- **Torpedo homing**: Torpedo__UpdateGuidance predicts target position, clamps turn rate. Dumb-fire torpedoes skip guidance.
- **FiringChain**: Bitmask (32-bit), parsed from string like "123:456". Groups weapons into fire sequences.
- **Tractor modes**: 0=drag, 1=push, 2=hold, 3=repel, 4=push-variant, 5=dock. Energy tracked at +0xFC.
- **Difficulty scaling**: GetDifficultyDamageScale(0x004068c0) returns 3 different multipliers.
- **WeaponHitEvent**: 0x60 bytes. +0x2C=weaponType (0=phaser, 1=torpedo), +0x44=firingPlayerID.
