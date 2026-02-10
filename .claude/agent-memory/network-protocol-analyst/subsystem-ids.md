# Subsystem / Weapon Object ID Mapping

## Object ID Structure
```
Bits 31-14: Owner prefix
  0x4000xxxx = Peer#0 (Sep) owned objects
  0x4004xxxx = Peer#3 (Cady) owned objects
  0x3FFFxxxx = Peer#0 initial (first spawn, before respawn)
  0x0000xxxx = Global objects (e.g., cloak subsystem)
Bits 13-0:  Sequential instance ID within owner's namespace
```

## Subsystem Object IDs by Phase

### Phase 1 (22:09:10 - 22:09:59)
- Sep ship: 0x3FFFFFFF (Type A, 53-byte config)
  - Weapon indices (StateUpdate): 1, 2, 4, 5, 6, 7, 8, 9
  - No fire events from Sep in Phase 1
- Cady ship: 0x4003FFFF (Type B, 54-byte config)
  - Weapon indices (StateUpdate): 2, 3, 4, 5, 6, 7, 8, 10
  - Torpedo tubes: 0x40040005, 0x40040006, 0x40040007, 0x40040008, 0x40040009, 0x4004000A

### Phase 2 (22:10:00 - 22:13:13)
- Sep ship: 0x40000025 (BoP, 34-byte config, cloaked)
  - Beam turrets: 0x4000002A, 0x4000002B (BeamFire at target 0x4003FFFF)
  - Torpedo tube: 0x4000002D
  - Weapon indices (StateUpdate): 1, 3, 4, 5, 6, 7
  - Cloak subsystem: 0x00000104 (SubsysStatus events)
- Cady ship: 0x4003FFFF (still alive from Phase 1)

### Phase 3 (22:13:14 - 22:18:14)
- Sep ship: 0x40000090 (Cruiser, 51-byte config)
  - Torpedo tubes: 0x4000009E, 0x4000009F, 0x400000A0, 0x400000A1, 0x400000A2, 0x400000A3
  - Weapon indices: 1, 2, 4, 5, 6, 7
  - subsysHash: 0xFB37
- Cady ship: 0x40040080 (Cruiser, 51-byte config)
  - Torpedo tubes: 0x4004008E, 0x4004008F, 0x40040090, 0x40040091, 0x40040092, 0x40040093
  - Weapon indices: 1, 2, 4, 5, 6, 7, 8, 9
  - subsysHash: 0xFB37 (same as Sep = same ship class)

### Phase 4 (22:18:15+)
- Sep ship: 0x400000E2 (Cruiser, 51-byte config)
  - Weapon indices: 1, 2, 4, 5, 6, 7, 8, 9
  - subsysHash: 0x040C
- Cady ship: 0x40040080 (still alive from Phase 3)

## Subsystem ID Offset Pattern
Subsystem objIDs = shipObjID + offset:
- Ship 0x40000025 -> beams at +5 (0x2A), +6 (0x2B), torpedo at +8 (0x2D)
- Ship 0x40000090 -> torpedoes at +14 (0x9E) through +19 (0xA3)
- Ship 0x40040080 -> torpedoes at +14 (0x8E) through +19 (0x93)

Offset +14 to +19 = 6 torpedo tubes for cruiser-class ships.

## StartFiring (0x07) Object
All StartFiring events use obj=0x00008128 (constant).
This appears to be a global "firing system" object, not per-weapon.
The payload (20 bytes) contains the actual weapon/target data.

## Cloak Subsystem (0x0A SubsysStatus)
- obj=0x00000104 is the cloak control object
- All SubsysStatus events target this same object
- Data format: 13 bytes: [DD 00 80 00 00 00 00 00 33 00 00 40 00/01]
  - Last byte: 0x00 = cloak off, 0x01 = cloak on
