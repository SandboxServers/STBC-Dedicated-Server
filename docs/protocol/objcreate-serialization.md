> [docs](../README.md) / [protocol](README.md) / objcreate-serialization.md

# ObjCreate/ObjCreateTeam Serialization Format (Opcodes 0x02/0x03)

Reverse-engineered from the stbc.exe binary and verified against stock dedicated server packet traces.

## Overview

Opcodes 0x02 and 0x03 carry serialized game objects (ships, torpedoes, asteroids, stations) over the network. The handler at `0x0069f620` processes both opcodes — 0x02 creates unaffiliated objects, 0x03 creates objects with a team assignment.

These are bidirectional: the host creates objects and relays them to all clients.

## Message Envelope

After type 0x32 transport framing is stripped (reliable header + flags_len + seq), the game payload is:

```
Offset  Size  Type    Field
------  ----  ----    -----
0       1     u8      opcode              0x02 or 0x03
1       1     i8      owner_player_slot   0-15, which player owns this object
[if opcode == 0x03:]
2       1     i8      team_id             Team assignment (typically 2 or 3)
[end if]
+0      var   data    serialized_object   TG factory-created object stream
```

Header size: 2 bytes for opcode 0x02, 3 bytes for opcode 0x03.

## Serialized Object Stream

The serialized_object blob is produced by `obj->vtable[0x10C](buffer, maxlen)` (WriteStream) on the sender, and consumed by `Ship_Deserialize` (`0x005a1f50`) on the receiver.

### Stream Header (8 bytes, common to all object types)

```
Offset  Size  Type    Field
------  ----  ----    -----
0       4     i32     factory_class_id    TG factory class ID (see table below)
4       4     i32     object_id           Network object ID (player_base + offset)
```

The factory_class_id is looked up in the TG object factory (`DAT_0099a67c`) to instantiate the correct C++ class. The object_id is checked against the object hash table (`FUN_00430730`) — if an object with that ID already exists, deserialization aborts.

### Factory Class IDs

| ClassID | Hex Bytes (LE) | Object Type | Network Tracker |
|---------|----------------|-------------|-----------------|
| 0x00008008 | `08 80 00 00` | Ship/Station (ShipClass) | Yes — position/velocity tracker created |
| 0x00008009 | `09 80 00 00` | Torpedo/Projectile | No — skipped (has own fire messages) |

After creating the object via the factory, the handler calls:
1. `obj->vtable[0x118](stream)` — **ReadStream**: deserialize all fields
2. `obj->vtable[0x11C](stream)` — **PostLoad**: finalize after deserialization

### Ship ReadStream (class_id = 0x8008)

The ReadStream for ships is `FUN_005a2030` → `FUN_005b0e80` (InitObject), called as part of the vtable chain:

```
Offset  Size  Type    Field               Notes
------  ----  ----    -----               -----
8       1     u8      species_type        SpeciesToShip enum (1=Akira, 5=Sovereign, etc.)
9       4     f32     position_x          World X coordinate
13      4     f32     position_y          World Y coordinate
17      4     f32     position_z          World Z coordinate
21      4     f32     orientation_w        Quaternion W
25      4     f32     orientation_x        Quaternion X
29      4     f32     orientation_y        Quaternion Y
33      4     f32     orientation_z        Quaternion Z
37      4     f32     speed               Speed magnitude (usually 0.0 at spawn)
41      3     u8[3]   padding             Always 0x00 0x00 0x00
44      1     u8      player_name_len     Length of player name string
45      var   ascii   player_name         ASCII, not null-terminated
+0      1     u8      set_name_len        Length of set/system name string
+1      var   ascii   set_name            ASCII (e.g., "Multi1" = star system name)
+0      var   data    subsystem_state     Ship-type-dependent subsystem health data
```

#### species_type (offset 8)

Read by `FUN_005a2030`, stored at `ship+0xEC`. Passed to `Multiplayer.SpeciesToShip.InitObject(ship, iType)` which:
1. Looks up ship stats via `GetShipFromSpecies(iType)` → loads ship script module
2. Calls `ship.SetupModel(kStats['Name'])` — loads NIF model
3. Imports `ships.Hardpoints.<HardpointFile>` and calls `LoadPropertySet()`
4. Calls `ship.SetupProperties()` — creates all subsystems
5. Calls `ship.UpdateNodeOnly()`

#### set_name (variable offset)

**This is the star system name, NOT the ship class.** The ship class is determined by `species_type`. The set_name maps to `Multiplayer.SpeciesToSystem` entries:

| System ID | Name | Script |
|-----------|------|--------|
| 1 | Multi1 | Systems.Multi1.Multi1 |
| 2 | Multi2 | Systems.Multi2.Multi2 |
| 3 | Multi3 | Systems.Multi3.Multi3 |
| 4 | Multi4 | Systems.Multi4.Multi4 |
| 5 | Multi5 | Systems.Multi5.Multi5 |
| 6 | Multi6 | Systems.Multi6.Multi6 |
| 7 | Multi7 | Systems.Multi7.Multi7 |
| 8 | Albirea | Systems.Albirea.Albirea |
| 9 | Poseidon | Systems.Poseidon.Poseidon |

### Torpedo ReadStream (class_id = 0x8009)

Torpedoes use `Multiplayer.SpeciesToTorp.InitObject(self, iType)` instead of SpeciesToShip. The species_type byte indexes into the torpedo table:

| ID | Torpedo Type | ID | Torpedo Type |
|----|-------------|----|-------------|
| 1 | Disruptor | 9 | FusionBolt |
| 2 | PhotonTorpedo | 10 | CardassianDisruptor |
| 3 | QuantumTorpedo | 11 | KessokDisruptor |
| 4 | AntimatterTorpedo | 12 | PhasedPlasma |
| 5 | CardassianTorpedo | 13 | Positron2 |
| 6 | KlingonTorpedo | 14 | PhotonTorpedo2 |
| 7 | PositronTorpedo | 15 | RomulanCannon |
| 8 | PulseDisruptor | | |

## SpeciesToShip Complete Mapping

Source: `scripts/Multiplayer/SpeciesToShip.py`

### Playable Ships (species 1-15)

| ID | Constant | Ship Script | Faction |
|----|----------|------------|---------|
| 1 | AKIRA | Akira | Federation |
| 2 | AMBASSADOR | Ambassador | Federation |
| 3 | GALAXY | Galaxy | Federation |
| 4 | NEBULA | Nebula | Federation |
| 5 | SOVEREIGN | Sovereign | Federation |
| 6 | BIRDOFPREY | BirdOfPrey | Klingon |
| 7 | VORCHA | Vorcha | Klingon |
| 8 | WARBIRD | Warbird | Romulan |
| 9 | MARAUDER | Marauder | Ferengi |
| 10 | GALOR | Galor | Cardassian |
| 11 | KELDON | Keldon | Cardassian |
| 12 | CARDHYBRID | CardHybrid | Cardassian |
| 13 | KESSOKHEAVY | KessokHeavy | Kessok |
| 14 | KESSOKLIGHT | KessokLight | Kessok |
| 15 | SHUTTLE | Shuttle | Federation |

MAX_FLYABLE_SHIPS = 16 (IDs 1-15 inclusive; ID 0 = UNKNOWN).

### Non-Playable Objects (species 16-45)

| ID | Script | Faction | ID | Script | Faction |
|----|--------|---------|----|----|---------|
| 16 | CardFreighter | Cardassian | 31 | Asteroid | Neutral |
| 17 | Freighter | Federation | 32 | Asteroid1 | Neutral |
| 18 | Transport | Federation | 33 | Asteroid2 | Neutral |
| 19 | SpaceFacility | Federation | 34 | Asteroid3 | Neutral |
| 20 | CommArray | Federation | 35 | Amagon | Cardassian |
| 21 | CommLight | Cardassian | 36 | BiranuStation | Neutral |
| 22 | DryDock | Federation | 37 | Enterprise | Federation |
| 23 | Probe | Federation | 38 | Geronimo | Federation |
| 24 | Decoy (Probetype2) | Federation | 39 | Peregrine | Federation |
| 25 | Sunbuster | Kessok | 40-42 | Asteroidh1-3 | Neutral |
| 26 | CardOutpost | Cardassian | 43 | Escapepod | Neutral |
| 27 | CardStarbase | Cardassian | 44 | KessokMine | Kessok |
| 28 | CardStation | Cardassian | 45 | BorgCube | Borg |
| 29 | FedOutpost | Federation | | | |
| 30 | FedStarbase | Federation | | | |

MAX_SHIPS = 46 (IDs 0-45).

## Handler Pipeline Detail

### Receive path (0x0069f620)

```
Handler_ObjCreate_0x02_0x03(MultiplayerGame *this, TGMessage *msg, char isTeam)
  │
  ├─ Extract raw buffer: FUN_006b8530(msg) → data_ptr + size
  ├─ Read owner_slot (byte 1), team_id (byte 2, only if isTeam)
  │
  ├─ Swap active player context:
  │    Save DAT_0097FA84 (current slot) and DAT_0097FA8C (current obj ID base)
  │    Set DAT_0097FA84 = owner_slot
  │    Load DAT_0097FA8C from MultiplayerGame+0x84[owner_slot*0x18]
  │
  ├─ Ship_Deserialize(data + header_len, size - header_len)  [0x005a1f50]
  │    ├─ StreamReader::Init(buffer, size)              [0x006cf180]
  │    ├─ ReadInt32() → factory_class_id                [0x006cf670]
  │    ├─ ReadInt32() → object_id                       [0x006cf670]
  │    ├─ FUN_00430730(NULL, object_id) → duplicate check
  │    ├─ FUN_006f13e0(class_id) → TG factory create
  │    ├─ obj->vtable[0x118](stream) → ReadStream
  │    │    ├─ FUN_005a2030: ReadByte → ship+0xEC (species)
  │    │    ├─ Python: SpeciesToShip.InitObject(ship, species)
  │    │    │    ├─ GetShipFromSpecies(species) → load ship module
  │    │    │    ├─ ship.SetupModel(name) → load NIF
  │    │    │    ├─ Hardpoints.LoadPropertySet()
  │    │    │    ├─ ship.SetupProperties() → create subsystems
  │    │    │    └─ ship.UpdateNodeOnly()
  │    │    └─ Continue reading: position, orientation, velocity, name, set, subsystems
  │    ├─ obj->vtable[0x11C](stream) → PostLoad
  │    └─ return ship*
  │
  ├─ Restore player context
  ├─ If isTeam: ship+0x2E4 = team_id
  │
  ├─ Relay to other peers (iterate 16 slots):
  │    For each connected peer != sender && != self:
  │      Clone message, send via FUN_006b4c10(WSN, peer_connID, cloned_msg, 0)
  │    For sender's slot: update stored object_id
  │
  ├─ If obj->vtable[0x04]() != 0x8009:  (skip for torpedoes)
  │    ├─ NiAlloc(0x58) → network tracking object
  │    ├─ FUN_0047dab0(tracker, ship, "Network") → init position/velocity tracker
  │    └─ ship->vtable[0x134](tracker, 1, 1) → attach tracker
  │
  └─ ship+0xF0 = 0 (clear flag)
```

### Player context slot table

`MultiplayerGame+0x84` contains a 16-entry array with stride 0x18 (24 bytes per slot). Each entry tracks a player's network object ID base. The swap ensures that `DAT_0097FA8C` (current object ID allocator base) is set correctly before `Ship_Deserialize` creates objects in that player's ID range.

Object ID range per player: `0x3FFFFFFF + N * 0x40000` (262,143 IDs each).

## Decoded Trace Examples

### Trace 1 (Akira, spawn position 88/-66/-73)

Full message (after TGNetwork framing):
```
03 00 02 08 80 00 00 FF FF FF 3F 01 00 00 B0 42 00 00 84 C2 00 00 92 C2 ...
^^ ^^ ^^ ^^^^^^^^^^^ ^^^^^^^^^^^ ^^ ^^^^^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^^^^
|  |  |  class 8008   obj 3FFF..  |  X=88.0      Y=-66.0     Z=-73.0
|  |  team=2                      species=1 (AKIRA)
|  owner=0 (host)
opcode 0x03
```

### Trace 2 (Sovereign, spawn position 38/-49/-35)

```
03 00 02 08 80 00 00 FF FF FF 3F 05 00 00 18 42 00 00 44 C2 00 00 0C C2 ...
^^ ^^ ^^ ^^^^^^^^^^^ ^^^^^^^^^^^ ^^ ^^^^^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^^^^
|  |  |  class 8008   obj 3FFF..  |  X=38.0      Y=-49.0     Z=-35.0
|  |  team=2                      species=5 (SOVEREIGN)
|  owner=0 (host)
opcode 0x03
```

Both: same player (slot 0), same team (2), same object ID base — but different ship species and spawn positions.

## Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x0069f620 | Handler_ObjCreate_0x02_0x03 | Dispatcher for both opcodes |
| 0x005a1f50 | Ship_Deserialize | Stream reader → factory create → ReadStream |
| 0x005a2030 | ReadSpeciesByte | Reads species byte into ship+0xEC |
| 0x005b0e80 | InitObject | Ship field deserialization (position, name, subsystems) |
| 0x006f13e0 | TGFactoryCreate | Class ID → C++ constructor lookup |
| 0x00430730 | ObjectLookupByID | Hash table lookup for duplicate check |
| 0x006b8530 | TGMessage::GetBuffer | Extract raw data pointer + size |
| 0x006cf670 | StreamReader::ReadInt32 | Read 4-byte LE integer |
| 0x006b4c10 | SendToPeer | Relay serialized message to a peer |
| 0x0047dab0 | InitNetworkTracker | Create position/velocity tracker |

## Open Questions

- Exact content of the 3 padding bytes at offset 41-43 (always observed as zeros — could be flags for cloak/warp/shield state)
- Complete subsystem_state blob format (varies by ship type, appears to encode per-subsystem health floats)
- Whether orientation is stored as quaternion (4 floats) or Euler angles (3 floats) — quaternion is more likely given 4 consecutive floats after position
