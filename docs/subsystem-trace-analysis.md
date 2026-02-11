# Ship Subsystem Trace Analysis

**Source**: Stock dedicated server trace via JMP detour hooks (`subsystem_trace.log`)
**Validated**: 2026-02-10, 223,888 lines / 15.8 MB trace data
**Test session**: 2x Sovereign, 1x Galaxy class spawns

---

## Overview

Six engine functions were hooked via JMP detour code caves to capture the complete
ship creation pipeline on the **stock dedicated server** (real renderer, real NIF loading):

| Hook | Address | Function | Purpose |
|------|---------|----------|---------|
| InitObject_Cpp | 0x005b0e80 | FUN_005b0e80 | Ship object initialization (called when engine deserializes a ship) |
| AddToSet | 0x006c9520 | FUN_006c9520 | Links NiPropertySet to "Scene Root" NiNode |
| SetupProperties | 0x005b3fb0 | FUN_005b3fb0 | Creates runtime subsystem objects from properties |
| AddSubsystemToList | 0x005b3e50 | FUN_005b3e50 | Adds single subsystem to ship's linked list |
| SubsystemHash | 0x005b5eb0 | FUN_005b5eb0 | Anti-cheat hash calculation |
| StateUpdateSerialize | 0x005b17f0 | FUN_005b17f0 | Per-frame state update serialization for network |

---

## Ship Creation Timeline

All 3 ships used the **same object address** (0x0ED84C70) — the engine reuses the allocation slot.

| # | Ship Class | InitObject Time | Duration | Subsystem Count | ShipRef Ptr |
|---|-----------|----------------|----------|-----------------|-------------|
| 1 | Sovereign | 17:52:49.461 | ~222ms | 33 | 0x0EE96C08 |
| 2 | Sovereign | 17:53:03.471 | ~41ms | 33 | 0x0EE93A28 |
| 3 | Galaxy | 17:53:18.532 | ~312ms | 33-34 | 0x0EE97628 |

The ShipRef pointer at `+2E0` changes each time (different NiNode scene graph instance).
Ship #2 is faster (41ms vs 222ms) because NIF assets are cached from ship #1.

---

## Vtable-to-Subsystem Type Catalog

**Validated by trace data**: vtable address, named slot assignment, instance count, and HP values
all confirmed from hex dumps of live subsystem objects.

### Named Slot Subsystems (11 types)

| vtable | Named Slot | Offset | Type | HP (Sovereign) | Notes |
|--------|-----------|--------|------|-----------------|-------|
| 0x0088A1F0 | Powered | +2B0 | PoweredSubsystem (base) | 7,000 | Master powered subsystem |
| 0x00893598 | Shield | +2B4 | ShieldGenerator | 6,000 | Shield bubble |
| 0x00893240 | Phaser | +2B8 | PhaserController | 32,000 | Master controller for beam weapons |
| -- | (empty) | +2BC | (unused) | -- | Slot +2BC always NULL |
| 0x00892F34 | Repair | +2C0 | RepairSubsystem | 10,000 | Auto-repair |
| 0x00892C98 | Power | +2C4 | PowerReactor | 12,011 | Main power generation |
| 0x00892EAC | Cloak | +2C8 | CloakingDevice | 32,000 | Present even on non-cloaking ships |
| 0x00892D10 | Unk_C | +2CC | LifeSupport/Structural | 3,000 | Powered variant, purpose TBD |
| 0x00893040 | Unk_B | +2D0 | SensorArray | 1,000 | Sensors |
| 0x00893794 | Pulse | +2D4 | PulseWeapon | 6,000 | Present even on non-pulse ships |
| 0x00892E24 | Unk_E | +2D8 | WarpDrive | 32,000 | Single instance, high HP |
| -- | (empty) | +2DC | (unused) | -- | Slot +2DC always NULL |
| 0x00895340 | ShipRef | +2E0 | NiNode backpointer | -- | NOT added via AddSubsystemToList |

### Linked-List-Only Subsystems (4 types, multiple instances)

| vtable | Count (Sovereign) | Type | HP each | Notes |
|--------|-------------------|------|---------|-------|
| 0x00893630 | 6 | TorpedoTube | 550 | 4 forward, 2 aft |
| 0x00893194 | 8 | PhaserEmitter | 1,000 | Individual phaser bank hardpoints |
| 0x00892FC4 | 4 | ImpulseEngine | 10,000 | Nacelle engines |
| 0x008936F0 | 4 | TractorBeam | 1,500 | Tractor beam emitters |
| 0x00892C98 | 1 (extra) | PowerReactor2 | 10,000 | Secondary power (same vtable as Power slot) |

**Total**: 33 subsystems via AddSubsystemToList + 1 ShipRef (set separately) = 34 entries.

### Instance Summary (Sovereign class)

```
Index  vtable      Type              Named Slot
-----  ----------  ----------------  ----------
0x00   0x00892C98  PowerReactor      +2C4 Power
0x01   0x00892F34  RepairSubsystem   +2C0 Repair
0x02   0x00892EAC  CloakingDevice    +2C8 Cloak
0x03   0x0088A1F0  PoweredSubsystem  +2B0 Powered
0x04   0x00892D10  LifeSupport       +2CC Unk_C
0x05   0x00893598  ShieldGenerator   +2B4 Shield
0x06   0x00893630  TorpedoTube #1    --
0x07   0x00893630  TorpedoTube #2    --
0x08   0x00893630  TorpedoTube #3    --
0x09   0x00893630  TorpedoTube #4    --
0x0A   0x00893630  TorpedoTube #5    --
0x0B   0x00893630  TorpedoTube #6    --
0x0C   0x00893194  PhaserEmitter #1  --
0x0D   0x00893194  PhaserEmitter #2  --
0x0E   0x00893194  PhaserEmitter #3  --
0x0F   0x00893194  PhaserEmitter #4  --
0x10   0x00893194  PhaserEmitter #5  --
0x11   0x00893194  PhaserEmitter #6  --
0x12   0x00893194  PhaserEmitter #7  --
0x13   0x00893194  PhaserEmitter #8  --
0x14   0x00892FC4  ImpulseEngine #1  --
0x15   0x00892FC4  ImpulseEngine #2  --
0x16   0x00892FC4  ImpulseEngine #3  --
0x17   0x00892FC4  ImpulseEngine #4  --
0x18   0x00892E24  WarpDrive         +2D8 Unk_E
0x19   0x00893240  PhaserController  +2B8 Phaser
0x1A   0x00893794  PulseWeapon       +2D4 Pulse
0x1B   0x00893040  SensorArray       +2D0 Unk_B
0x1C   0x00892C98  PowerReactor2     --
0x1D   0x008936F0  TractorBeam #1    --
0x1E   0x008936F0  TractorBeam #2    --
0x1F   0x008936F0  TractorBeam #3    --
0x20   0x008936F0  TractorBeam #4    --
```

---

## Ship Object Memory Layout (Subsystem Region)

```
Offset   Size   Field
------   ----   -----
+0x27C   4      Subsystem list container vtable (0x008944C8)
+0x280   4      Subsystem count (33 for Sovereign)
+0x284   4      HEAD pointer (first node in doubly-linked list)
+0x288   4      TAIL pointer (last node)
+0x28C   12     (padding/secondary list header?)
+0x298   4      Secondary list count (12-13 entries)
+0x29C   4      Secondary list HEAD
+0x2A0   4      Secondary list TAIL
+0x2A4   12     (padding)
+0x2B0   4      Named slot: Powered (vtable 0x0088A1F0)
+0x2B4   4      Named slot: Shield (vtable 0x00893598)
+0x2B8   4      Named slot: Phaser (vtable 0x00893240)
+0x2BC   4      Named slot: (unused, always NULL)
+0x2C0   4      Named slot: Repair (vtable 0x00892F34)
+0x2C4   4      Named slot: Power (vtable 0x00892C98)
+0x2C8   4      Named slot: Cloak (vtable 0x00892EAC)
+0x2CC   4      Named slot: Unk_C/LifeSupport (vtable 0x00892D10)
+0x2D0   4      Named slot: Unk_B/SensorArray (vtable 0x00893040)
+0x2D4   4      Named slot: Pulse (vtable 0x00893794)
+0x2D8   4      Named slot: Unk_E/WarpDrive (vtable 0x00892E24)
+0x2DC   4      Named slot: (unused, always NULL)
+0x2E0   4      Named slot: ShipRef/NiNode (vtable 0x00895340)
```

### Linked List Node Structure (12 bytes each)

```
Offset   Size   Field
------   ----   -----
+0x00    4      data_ptr (subsystem object pointer)
+0x04    4      next_ptr
+0x08    4      prev_ptr
```

### Subsystem Object Header (common fields, first 64 bytes)

```
Offset   Size   Field
------   ----   -----
+0x00    4      vtable pointer
+0x04    4      subsystem_index (DWORD, monotonic from global counter, byte at +4 = index & 0xFF)
+0x08    28     (unknown, mostly zero)
+0x24    4      unknown_ptr (NiNode related?)
+0x28    8      (zero padding)
+0x2C    2      0xFFFF (sentinel)
+0x2E    2      type_flags (varies per subsystem type)
+0x30    4      HP (float) — hit points
+0x34    4      HP_max (float) — usually 1.0
+0x38    4      HP_ratio (float) — usually 1.0
+0x3C    4      unknown_float
+0x40    4      back_pointer to ship object
+0x44    4      status_flags
```

---

## Creation Pipeline (Verified Sequence)

1. **InitObject** (FUN_005b0e80) — Engine deserializes ship from network.
   - `ECX` = ship object pointer
   - `[ESP+4]` = stream/param pointer
   - Ship has vtable at `+0x00`, object ID at `+0x04` (0x3FFFFFFF before init)

2. **AddToSet** (FUN_006c9520) — Links NiPropertySet entries to NiNode scene graph.
   - Called 4-6 times per ship immediately after InitObject
   - Property data starts with "3.1\0" version tag
   - Byte at +0x04 = property type (0x00, 0x4F, 0x0C, 0x33, etc.)
   - Requires valid "Scene Root" NiNode from loaded NIF model

3. **SetupProperties** (FUN_005b3fb0) — Creates runtime subsystem objects.
   - Called ~45 times per ship (once per property type + intermediate linking)
   - `ECX` = ship `this` pointer
   - Subsystem count increments by 1 between most calls
   - Some calls do property linking only (count stays same)

4. **AddSubsystemToList** (FUN_005b3e50) — Inserts single subsystem into linked list.
   - `ECX` = ship, `[ESP+4]` = subsystem object pointer
   - Also populates named slot if the subsystem type has one
   - Called 33 times for Sovereign class

5. **SubsystemHash** (FUN_005b5eb0) — Anti-cheat hash.
   - `ECX` = ship+0x27C (list container base)
   - Fires ~once per second during gameplay
   - Hash input includes list container vtable + count + node pointers

6. **StateUpdateSerialize** (FUN_005b17f0) — Network state serialization.
   - `ECX` = ship, `[ESP+4]` = output stream
   - Fires ~2,500 times/second (every frame tick)
   - Round-robins through subsystem list with ~10 byte budget per tick
   - Uses 0x20 (SUB) flag in server->client direction

---

## Event Frequencies (from trace)

| Event | Total Count | Frequency |
|-------|-------------|-----------|
| InitObject | 3 | Per ship spawn |
| AddToSet | 14 | 4-6 per ship |
| SetupProperties | ~134 | ~45 per ship |
| AddSubsystemToList | ~100 | ~33 per ship |
| SubsystemHash | 44 | ~1/second |
| StateUpdateSerialize | 194,045 | ~2,500/second |

---

## Implications for Headless Server

1. **NIF loading is the key dependency**: AddToSet requires a valid "Scene Root" NiNode,
   which comes from NIF file loading (NiStream::Load). NIF loading is file I/O, NOT
   renderer-dependent. The headless server CAN load NIF files.

2. **If NIF loading works, everything works**: The entire chain from InitObject through
   StateUpdateSerialize is driven by NIF-based property sets. No renderer calls.

3. **33 subsystems is the minimum viable set**: The state serializer round-robins through
   ALL subsystems. If the headless server creates fewer, the round-robin will be shorter
   but still functional. If it creates zero (current state), flags=0x00 and the client
   gets empty state updates, eventually disconnecting.

4. **Named slots MUST be populated**: Python scripts and AI access subsystems via named
   slots (ship+0x2B0 through +0x2E0). NULL slots cause Python AttributeError or C++ NULL
   dereference. At minimum, Power (+2C4) and Shield (+2B4) must be valid.

5. **ShipRef (+2E0) is set separately**: Not via AddSubsystemToList. Must be set by
   the NIF loading / scene graph construction path.
