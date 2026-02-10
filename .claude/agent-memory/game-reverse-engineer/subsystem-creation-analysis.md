# Ship Subsystem Creation Chain (STBC Multiplayer)

## Date: 2026-02-09

## Overview
Ship subsystems are created through a 5-step chain that requires both Python and C++ cooperation.
The key NIF dependency is at step 3 (AddToSet requires NiNode "Scene Root" from loaded model).

## Step 1: Hardpoint Definition (Python)
- Files: `ships/Hardpoints/<shipname>.py` (e.g., galaxy.py, sovereign.py)
- Each subsystem defined via `App.<Type>Property_Create(name)`:
  - HullProperty, ShieldProperty, SensorProperty, ImpulseEngineProperty
  - WarpEngineProperty, PowerProperty, RepairSubsystemProperty
  - PhaserProperty, TorpedoTubeProperty, CloakingSubsystemProperty
- Registered: `App.g_kModelPropertyManager.RegisterLocalTemplate(prop)`

## Step 2: LoadPropertySet (Python)
- `LoadPropertySet(pPropertySet)` at end of each hardpoint file
- Calls `pObj.AddToSet("Scene Root", prop)` for every subsystem
- Requires `g_kModelPropertyManager.FindByName(name, LOCAL_TEMPLATES)`

## Step 3: AddToSet (C++, FUN_006c9520) -- NIF DEPENDENCY
- Searches NIF model scene graph for NiNode named "Scene Root"
- Creates TGModelPropertyInstance (0x150 bytes, FUN_006c4a70)
- Links property to NiNode
- **WITHOUT LOADED NIF: returns 0 (failure), subsystem not linked**

## Step 4: SetupProperties / FUN_005b3fb0 (C++ Subsystem Factory)
- Called via vtable at 0x008944a0
- Dispatches on property type ID to create concrete subsystem objects
- Each subsystem: allocate -> construct -> add to linked list (+0x284)

### Type ID to Subsystem Mapping
| Type ID | Subsystem | Constructor | Size | Slot Offset |
|---------|-----------|-------------|------|-------------|
| 0x812e | ShipRef | (direct store) | - | +0x2E0 |
| 0x812f | WeaponSystem | FUN_00573c90/005773b0/00582080 | 0xF4/F0/100 | +0x2B8/2BC/2D4 |
| 0x8132 | Hull | FUN_00570d70 | 0x128 | - |
| 0x8133 | Shield | FUN_0057b020 | 0x11c | +0x2B4 |
| 0x8134 | Sensor | FUN_0057c4b0 | 0xB0* | - |
| 0x8135 | Impulse | FUN_00574fd0 | 0xD4 | - |
| 0x8136 | Warp | FUN_0057ec70 | 0x100* | - |
| 0x8137 | Repair | FUN_0056a000 | 0x15c | +0x2C0 |
| 0x8138 | Power | FUN_00560470 | 0x88 | +0x2C4 |
| 0x8139 | Cloaking | FUN_00566d10 | 0xCC | +0x2C8 |
| 0x813a | Unknown-A | FUN_0055e2b0 | 0xBC | +0x2DC |
| 0x813b | Unknown-B | FUN_0056de70 | 0xD4 | +0x2D0 |
| 0x813c | Unknown-C | FUN_00561050 | 0xBC | +0x2CC |
| 0x813d | Unknown-D | FUN_0056b970 | 0x88 | - |
| 0x813e | Powered | FUN_00563530 | 0xDC | +0x2B0 |
| 0x813f | Unknown-E | FUN_00565090 | 0xC0 | +0x2D8 |

*Size via different allocator (FUN_00717b70 instead of FUN_0040f030)

## Step 5: Anti-Cheat Hash (FUN_005b5eb0)
- Iterates subsystem container at this+0x27c
- XOR-rotate hash over each subsystem's state floats (FUN_005b6c10)
- Hash compared with client-sent hash in FUN_005b21c0
- Mismatch fires ET_BOOT_PLAYER (0x8000f6) -> client kicked

## Subsystem Container Layout (inline in ship object)
| Offset | Field |
|--------|-------|
| +0x280 | List count |
| +0x284 | List HEAD (subsystem linked list) |
| +0x288 | List TAIL |
| +0x298 | Secondary list count |
| +0x29c | Secondary list HEAD |
| +0x2a0 | Secondary list TAIL |
| +0x2B0-0x2E0 | Named subsystem slot pointers (see table above) |
| +0x2E4 | Player slot ID |

## Linked List Node Format
- 12 bytes: [data_ptr, prev_ptr, next_ptr]
- Allocated via FUN_00486be0

## Key Functions
| Address | Name | Purpose |
|---------|------|---------|
| 0x005b3fb0 | SubsystemFactory | Creates subsystem from property type |
| 0x005b3e50 | AddSubsystemToList | Adds to linked list +0x284 |
| 0x005b5eb0 | ComputeSubsystemHash | Anti-cheat hash over all subsystems |
| 0x005b6c10 | HashAccumulate | XOR float + rotate left 1 bit |
| 0x005b6170 | SubsystemStateValue | Gets hash-relevant float from subsystem |
| 0x005b21c0 | StateUpdateReceiver | Processes 0x1C, checks hash |
| 0x006c9520 | AddToSet | Links property to NiNode "Scene Root" |
| 0x005b0e80 | ShipDeserialize | Calls Python InitObject |

## Server-Side Ship Creation via Network
1. Client creates ship locally (SpeciesToShip.CreateShip)
2. C++ engine serializes ship and sends to server
3. Server FUN_005a1f50 deserializes -> FUN_006f13e0 factory
4. Factory creates ShipClass object
5. FUN_005b0e80 calls Python "Multiplayer.SpeciesToShip.InitObject(self, iType)"
6. InitObject calls: self.SetupModel(name) + LoadPropertySet + SetupProperties
7. SetupModel loads LOD model (NIF) -> provides "Scene Root" NiNode
8. AddToSet links properties -> SetupProperties creates subsystems

## Can Server Skip NIF?
- PatchSubsystemHashCheck ALREADY handles NULL subsystem list (returns matching hash)
- NIF loading is FILE I/O only (NiStream::Load), not renderer-dependent
- If NIF loads headlessly, entire InitObject chain works automatically
- If not: hash bypass is sufficient to prevent kicks
- Other server needs for subsystems: collision damage, object replication state
