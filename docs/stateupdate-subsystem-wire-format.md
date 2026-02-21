# StateUpdate (0x1C) Subsystem Health Wire Format

## Date: 2026-02-18
## Status: VERIFIED (decompiled from binary + hardpoint cross-reference)

## Executive Summary

The StateUpdate flag 0x20 (subsystem health) uses a **round-robin serializer** that walks
the ship's **top-level subsystem linked list** (ship+0x284). Each subsystem's `WriteState`
virtual function writes a **variable-length** block: its own condition byte, then recursively
writes all child subsystems. There is **no fixed index table** and **no fixed maximum**.
The wire byte positions are determined entirely by the order subsystems appear in the
ship's linked list, which is determined by the order `AddToSet()` is called in the
hardpoint Python file.

## Answers to Key Questions

### Q1: Fixed index table or per-ship order?

**Per-ship linked list order.** There is no global index mapping table. The serializer walks
ship+0x284 (a doubly-linked list of subsystem pointers) and each subsystem writes its own
state via `vtable+0x70` (WriteState). The linked list order is determined by the Python
hardpoint file's `LoadPropertySet()` function, which calls `AddToSet("Scene Root", prop)`
in a specific order for each ship class.

### Q2: How are missing subsystems handled?

**They simply don't exist in the list.** If a ship doesn't have a cloaking device, there
is no cloak entry in ship+0x284. The serializer only iterates what's present. Both sender
and receiver use the **same** linked list (ship+0x284), built from the **same** hardpoint
file, so they always agree on subsystem count and order.

### Q3: What drives the round-robin count?

The **ship's actual subsystem count** in ship+0x280 (list length). There is no fixed maximum
of 33. The round-robin writes subsystems until either:
- 10 bytes of stream space are consumed (budget limit), OR
- It has wrapped back to its starting position (full cycle complete)

### Q4: Is there a mapping array?

**No mapping array.** The wire protocol position is implicitly defined by the linked list
traversal order. Sender and receiver must have identical linked lists (same subsystems in
same order). This is guaranteed because both sides execute the same hardpoint Python file
and the same C++ `SetupProperties` + `LinkAllSubsystemsToParents` functions.

## Detailed Wire Format

### Flag 0x20 Block Structure

```
[startIndex: byte]    // Which subsystem index the round-robin starts from this tick
[subsystem_0 data]    // WriteState output for subsystem at startIndex
[subsystem_1 data]    // WriteState output for subsystem at startIndex+1
...                   // Continues until 10-byte budget exhausted or full wrap
```

### Per-Subsystem WriteState Output

Each subsystem's WriteState is a **virtual function** (vtable+0x70). There are three
implementations:

#### 1. Base ShipSubsystem::WriteState (0x0056d320)
Used by: HullSubsystem, ShieldGenerator, PhaserBank, TorpedoTube, PulseWeapon,
         TractorBeamProjector, Engine (individual)

```
[condition: byte]     // (int)(currentCondition / GetMaxCondition() * 255.0)
                      //   currentCondition = this+0x30, GetMaxCondition (0x0056c310) = property+0x20
                      //   0xFF = 100% health, 0x00 = destroyed, truncated toward zero
[child_0 WriteState]  // Recursive: each child subsystem writes its own block
[child_1 WriteState]
...
[EndMarker]           // No-op (function at 0x006cdae0 is just RET)
```

#### 2. PoweredSubsystem::WriteState (0x00562960)
Used by: CloakDevice, ImpulseEngine, RepairSubsystem, SensorSubsystem, WarpEngine,
         PhaserSystem, TorpedoSystem, TractorBeamSystem, WeaponSystem

```
[base WriteState]     // Calls ShipSubsystem::WriteState first (condition + children)
if (isOwnShip == 0):  // Remote ship — include power data
    [hasData: bit=1]
    [powerPctWanted: byte]    // (int)(powerPercentageWanted * 100.0)
                              //   this+0x90 = PowerPercentageWanted (0.0-1.0 ratio)
                              //   constant 100.0 at 0x0088ce78, result range 0-100
    [EndMarker]               // No-op
else:                 // Own ship — owner has local state, skip power data
    [hasData: bit=0]
    [EndMarker]               // No-op
```

#### 3. PowerSubsystem::WriteState (0x005644b0)
Used by: PowerSubsystem only (reactor/warp core)

NOTE: PowerSubsystem ALWAYS writes both battery bytes regardless of isOwnShip.
The isOwnShip parameter is only passed through to the base class for children.

```
[base WriteState]              // Calls ShipSubsystem::WriteState (condition + children)
[mainBatteryPct: byte]         // (int)(mainBatteryPower / mainBatteryLimit * 255.0)
                               //   mainBatteryPower = this+0xAC
                               //   mainBatteryLimit = GetMainBatteryLimit (0x005634c0) -> property+0x48
[backupBatteryPct: byte]       // (int)(backupBatteryPower / backupBatteryLimit * 255.0)
                               //   backupBatteryPower = this+0xB4
                               //   backupBatteryLimit = GetBackupBatteryLimit (0x005634d0) -> property+0x4C
[EndMarker]                    // No-op
```

### Receiver (flag 0x20 in FUN_005b21c0)

```c
startIndex = ReadByte(stream);
node = ship->subsystemListHead;  // ship+0x284
// Skip to startIndex position
for (i = startIndex; i > 0; i--) {
    if (node) node = node->next;
}
// Read subsystem data until stream exhausted
while (streamPos < dataLength) {
    if (!node) break;
    subsystem = node->data;
    node = node->next;
    if (!subsystem) break;
    subsystem->ReadState(stream, timestamp);  // vtable+0x74
    if (!node) node = ship->subsystemListHead;  // wrap to beginning
}
```

## Ship+0x284 Linked List Contents

### What's IN the list (top-level subsystems)
These subsystems remain in ship+0x284 after `LinkAllSubsystemsToParents` runs:

| Runtime Type ID | Name | WriteState | Notes |
|----------------|------|------------|-------|
| 0x8027 | HullSubsystem | Base | One or more hulls per ship |
| 0x8028 | ShieldGenerator | Base | Has 6 shield-facing children |
| 0x8023 | SensorSubsystem | Override | |
| 0x8022 | PowerSubsystem | PowerSS | Writes 2 extra power bytes |
| 0x8026 | ImpulseEngine | Override | Children: individual engines |
| 0x8025 | WarpEngine | Override | Children: individual engines |
| 0x801D | WeaponSystem | Override | Generic weapon system container |
| 0x801E | TorpedoSystem | Override | Children: TorpedoTubes |
| 0x801F | PhaserSystem | Override | Children: PhaserBanks |
| 0x8021 | TractorBeamSystem | Override | Children: TractorBeamProjectors |
| 0x8024 | CloakDevice | Override | Only on ships with cloak |
| 0x8029 | RepairSubsystem | Override | |

### What's REMOVED from the list (linked as children)
These are removed from ship+0x284 by `FUN_005b5030` and added as children of parent systems:

| Runtime Type ID | Name | Parent Location | Parent Type |
|----------------|------|----------------|-------------|
| 0x802C | PhaserBank | ship+0x2B8 | PhaserSystem |
| 0x802D | PulseWeapon | ship+0x2BC | PulseWeaponSystem |
| 0x802E | TractorBeamProjector | ship+0x2D4 | TractorBeamSystem |
| 0x802F | TorpedoTube | ship+0x2B4 | TorpedoSystem |
| 0x813D (Engine) | Individual Engine | ship+0x2CC or 0x2D0 | ImpulseEngine (EP_IMPULSE=0) or WarpEngine (EP_WARP=1), determined by property+0x48 tag |

### What's NEVER in the list
Properties that are not subsystems (handled in SetupProperties but never added to 0x284):
- ObjectEmitterProperty (Probe Launcher, Shuttle Bay, Decoy Launcher)
- ShipProperty
- ViewscreenProperty
- FirstPersonProperty
- BridgeProperty_Create creates HullSubsystem -- actually IS in the list

## Sovereign-Class Example

Based on `sovereign.py` LoadPropertySet order, after `LinkAllSubsystemsToParents`:

| List Index | Subsystem | Children | Bytes per WriteState (remote) |
|-----------|-----------|----------|-------------------------------|
| 0 | Hull (HullSubsystem) | 0 | 1 (condition) |
| 1 | Shield Generator (ShieldGenerator) | 0 visible | 1 (condition; shield facing HP via flag 0x40) |
| 2 | Sensor Array (SensorSubsystem) | 0 | 3 (cond + bit + powerPct) |
| 3 | Warp Core (PowerSubsystem) | 0 | 3 (cond + 2 battery bytes) |
| 4 | Impulse Engines (ImpulseEngine) | 2 (Port + Star) | 5 (cond + 2 children + bit + powerPct) |
| 5 | Torpedoes (TorpedoSystem) | 6 tubes | 9 (cond + 6 children + bit + powerPct) |
| 6 | Repair (RepairSubsystem) | 0 | 3 (cond + bit + powerPct) |
| 7 | Phasers (PhaserSystem) | 8 banks | 11 (cond + 8 children + bit + powerPct) |
| 8 | Tractors (TractorBeamSystem) | 4 projectors | 7 (cond + 4 children + bit + powerPct) |
| 9 | Warp Engines (WarpEngine) | 2 (Port + Star) | 5 (cond + 2 children + bit + powerPct) |
| 10 | Bridge (HullSubsystem) | 0 | 1 (condition) |

**Total top-level subsystems: 11** (not 33 -- the "33" count includes individual weapons/engines)

## Round-Robin Serializer Algorithm

From `Ship_WriteStateUpdate` (0x005b17f0), flag 0x20 section:

```
// Per-object tracking structure at iVar7:
//   +0x30: linked list cursor (current node pointer)
//   +0x34: subsystem index counter (integer)

if (cursor == 0) {           // First time or reset
    cursor = ship->subsystemListHead;  // ship+0x284 = piVar17[0xA1]
    index = 0;
}

initialCursor = cursor;       // Remember starting position for wrap detection
WriteByte(stream, index);     // Write the startIndex

bytesWritten = 0;
while (bytesWritten < 10) {   // 10-byte budget per tick
    node = cursor;
    if (node == NULL) { subsystem = NULL; }
    else { subsystem = node->data; cursor = node->next; }

    subsystem->WriteState(stream, isLocalPlayer);  // vtable+0x70
    index++;

    if (cursor == 0) {        // End of list: wrap
        cursor = ship->subsystemListHead;
        index = 0;
    }
    if (cursor == initialCursor) break;  // Full cycle: stop
    bytesWritten = stream.position - startPosition;
}
```

## Key Implementation Details

### Linked List Node Structure
```c
struct SubsystemListNode {
    ShipSubsystem* data;   // +0x00: pointer to subsystem object
    SubsystemListNode* next;  // +0x04
    SubsystemListNode* prev;  // +0x08 (doubly-linked, maintained by ship+0x288 tail)
};
```

### Ship Subsystem List Fields
```c
// ship+0x280: count (int) -- number of entries in list
// ship+0x284: head (SubsystemListNode*) -- first node
// ship+0x288: tail (SubsystemListNode*) -- last node
// ship+0x28C: free list (SubsystemListNode*) -- reusable removed nodes
```

### Key Functions
| Address | Name | Role |
|---------|------|------|
| 0x005b17f0 | Ship_WriteStateUpdate | Main serializer (flag 0x20 = subsystems) |
| 0x005b21c0 | Ship_ReadStateUpdate | Main deserializer (flag 0x20 receiver) |
| 0x005b3fb0 | Ship_SetupProperties | Creates ALL subsystems from NIF properties |
| 0x005b3e20 | Ship_LinkAllSubsystemsToParents | Removes children from 0x284, adds to parents |
| 0x005b3e50 | Ship_AddSubsystemToLists | Adds to 0x284 (all) and optionally 0x29C |
| 0x005b5030 | Ship_LinkSubsystemToParent | Identifies parent, calls AddChild, removes from 0x284 |
| 0x0056c5c0 | ShipSubsystem_AddChildSubsystem | Grows child array at +0x20, increments +0x1C |
| 0x0056d320 | ShipSubsystem_WriteState (base) | Writes condition byte + recurses children |
| 0x00562960 | PoweredSubsystem_WriteState | Base + hasData bit + power percentage byte |
| 0x005644b0 | PowerSubsystem_WriteState | Base + 2 battery percentage bytes (unconditional) |
| 0x0056d390 | ShipSubsystem_ReadState (base) | Reads condition byte + recurses children |
| 0x005629d0 | PoweredSubsystem_ReadState | Base + reads hasData bit + power percentage |
| 0x00564530 | PowerSubsystem_ReadState | Base + reads 2 battery bytes |
| 0x0056c310 | ShipSubsystem_GetMaxCondition | Returns property+0x20 (float max HP), or 1.0 if no property |
| 0x0056c570 | ShipSubsystem_GetChildSubsystem | Returns child array[index] from +0x20 |

### CT_ Type Constants (from SWIG constant table)
| Value | Name | Category |
|-------|------|----------|
| 0x801B | CT_SHIP_SUBSYSTEM | Base type |
| 0x801C | CT_POWERED_SUBSYSTEM | Base powered |
| 0x801D | CT_WEAPON_SYSTEM | System-level |
| 0x801E | CT_TORPEDO_SYSTEM | System-level |
| 0x801F | CT_PHASER_SYSTEM | System-level |
| 0x8020 | CT_PULSE_WEAPON_SYSTEM | System-level |
| 0x8021 | CT_TRACTOR_BEAM_SYSTEM | System-level |
| 0x8022 | CT_POWER_SUBSYSTEM | System-level |
| 0x8023 | CT_SENSOR_SUBSYSTEM | System-level |
| 0x8024 | CT_CLOAKING_SUBSYSTEM | System-level |
| 0x8025 | CT_WARP_ENGINE_SUBSYSTEM | System-level |
| 0x8026 | CT_IMPULSE_ENGINE_SUBSYSTEM | System-level |
| 0x8027 | CT_HULL_SUBSYSTEM | System-level |
| 0x8028 | CT_SHIELD_SUBSYSTEM | System-level |
| 0x8029 | CT_REPAIR_SUBSYSTEM | System-level |
| 0x802A | CT_WEAPON | Individual weapon base |
| 0x802B | CT_ENERGY_WEAPON | Individual weapon |
| 0x802C | CT_PHASER_BANK | Individual (child of 0x801F) |
| 0x802D | CT_PULSE_WEAPON | Individual (child of 0x8020) |
| 0x802E | CT_TRACTOR_BEAM_PROJECTOR | Individual (child of 0x8021) |
| 0x802F | CT_TORPEDO_TUBE | Individual (child of 0x801E) |

### Property Type Constants (from SWIG constant table)
| Value | Name | Creates Runtime Type |
|-------|------|---------------------|
| 0x812B | CT_SUBSYSTEM_PROPERTY | Base |
| 0x812C | CT_POWERED_SUBSYSTEM_PROPERTY | Base powered |
| 0x812F | CT_WEAPON_SYSTEM_PROPERTY | PhaserSystem/TorpedoSystem/TractorBeamSystem |
| 0x8132 | CT_PHASER_PROPERTY | PhaserBank |
| 0x8133 | CT_TORPEDO_SYSTEM_PROPERTY | TorpedoSystem |
| 0x8134 | CT_TORPEDO_TUBE_PROPERTY | TorpedoTube |
| 0x8135 | CT_PULSE_WEAPON_PROPERTY | PulseWeapon |
| 0x8136 | CT_TRACTOR_BEAM_PROPERTY | TractorBeamProjector |
| 0x8137 | CT_SHIELD_PROPERTY | ShieldGenerator |
| 0x8138 | CT_HULL_PROPERTY | HullSubsystem |
| 0x8139 | CT_SENSOR_PROPERTY | SensorSubsystem |
| 0x813A | CT_CLOAKING_SUBSYSTEM_PROPERTY | CloakDevice |
| 0x813B | CT_WARP_ENGINE_PROPERTY | WarpEngine |
| 0x813C | CT_IMPULSE_ENGINE_PROPERTY | ImpulseEngine |
| 0x813D | CT_ENGINE_PROPERTY | Individual Engine |
| 0x813E | CT_POWER_PROPERTY | PowerSubsystem |
| 0x813F | CT_REPAIR_SUBSYSTEM_PROPERTY | RepairSubsystem |

### Engine Parent-Child Linking Mechanism

Individual engines (`CT_ENGINE_PROPERTY`, 0x813D) are the **only** child subsystem type that can belong to either of two different parent systems: `ImpulseEngineSubsystem` (0x8026) or `WarpEngineSubsystem` (0x8025). All other child types have unambiguous parents (phasers → PhaserSystem, torpedoes → TorpedoSystem, etc.).

The disambiguation mechanism is an **explicit enum tag** stored at `property+0x48`, set via the Python API `SetEngineType()`:

| Enum Value | Constant | Meaning |
|-----------|----------|---------|
| 0 | `EP_IMPULSE` | Attach to ImpulseEngineSubsystem |
| 1 | `EP_WARP` | Attach to WarpEngineSubsystem |

**Default**: `EP_IMPULSE` (0) — the EngineProperty constructor initializes `property+0x48 = 0`.

#### Python API Usage (from hardpoint scripts)

```python
# Individual engines are created with EngineProperty_Create (CT_ENGINE_PROPERTY)
PortImpulse = App.EngineProperty_Create("Port Impulse")
PortImpulse.SetEngineType(PortImpulse.EP_IMPULSE)   # property+0x48 = 0

PortWarp = App.EngineProperty_Create("Port Warp")
PortWarp.SetEngineType(PortWarp.EP_WARP)             # property+0x48 = 1
```

Note: the *system-level* containers use different property types entirely:
- `App.ImpulseEngineProperty_Create()` → `CT_IMPULSE_ENGINE_PROPERTY` (0x813C)
- `App.WarpEngineProperty_Create()` → `CT_WARP_ENGINE_PROPERTY` (0x813B)

These are never ambiguous — only individual `EngineProperty` children need the tag.

#### Linking Implementation

`Ship_LinkSubsystemToParent` (FUN_005b5030) reads `property+0x48` for `CT_ENGINE_PROPERTY` subsystems:
- `0` (EP_IMPULSE) → attach to `ship+0x2CC` (ImpulseEngineSubsystem pointer)
- `1` (EP_WARP) → attach to `ship+0x2D0` (WarpEngineSubsystem pointer)

#### Named Ship Subsystem Slots

| Offset | Subsystem | Notes |
|--------|-----------|-------|
| ship+0x2B0 | Powered master (EPS) | Power distribution |
| ship+0x2B4 | TorpedoSystem | |
| ship+0x2B8 | PhaserSystem | |
| ship+0x2BC | PulseWeaponSystem | |
| ship+0x2C4 | PowerSubsystem (reactor) | |
| ship+0x2CC | ImpulseEngineSubsystem | EP_IMPULSE engines attach here |
| ship+0x2D0 | WarpEngineSubsystem | EP_WARP engines attach here |
| ship+0x2D4 | TractorBeamSystem | |
| ship+0x2D8 | RepairSubsystem | |

#### Stock Ship Verification

All 16 stock multiplayer ships explicitly call `SetEngineType()` on every individual engine — no ship relies on the default. However, mods may omit the call, in which case the engine defaults to `EP_IMPULSE` and attaches to the impulse engine system.

### Subsystem Classification in FUN_005b3e50
After adding ALL subsystems to ship+0x284, the function classifies them:

**Types that ONLY go to ship+0x284** (weapon systems, weapon children, cloak, warp):
- 0x801F PhaserSystem
- 0x8021 TractorBeamSystem
- 0x802C PhaserBank
- 0x802F TorpedoTube
- 0x802E TractorBeamProjector
- 0x802D PulseWeapon
- 0x8025 WarpEngine
- 0x8024 CloakDevice

**Types that go to BOTH ship+0x284 AND ship+0x29C** (everything else):
- 0x8027 HullSubsystem
- 0x8028 ShieldGenerator
- 0x8023 SensorSubsystem
- 0x8022 PowerSubsystem
- 0x8026 ImpulseEngine
- 0x8029 RepairSubsystem

ship+0x29C list is used for non-weapon iteration (damage distribution, repair queue, etc.)

## Implications for Dedicated Server

1. **Ship+0x284 must have identical order on server and client** -- both must run the same
   hardpoint file, which they do (checksum-verified)
2. **The server must have real subsystem objects** -- DeferredInitObject handles this
3. **The round-robin ensures all subsystems get updated** -- over multiple ticks, every
   subsystem gets its health synchronized
4. **Variable-length blocks** mean the receiver must read exactly the same WriteState
   format the sender wrote -- subsystem vtable must match on both sides
5. **No need for a fixed 33-slot array** -- the wire format is self-describing via the
   startIndex + linked list walk + recursive children
