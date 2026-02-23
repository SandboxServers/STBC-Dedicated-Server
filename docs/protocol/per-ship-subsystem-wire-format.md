> [docs](../README.md) / [protocol](README.md) / per-ship-subsystem-wire-format.md

# Per-Ship Subsystem Wire Format Catalog

## Date: 2026-02-22
## Status: HIGH-CONFIDENCE (hardpoint script analysis + stock dedi trace verification)

## Overview

The StateUpdate flag 0x20 (subsystem health) serializes the ship's **top-level subsystem
linked list** (ship+0x284) using a round-robin algorithm with a 10-byte budget per tick.
Each ship class has a **different** top-level subsystem list determined by its hardpoint
Python script's `LoadPropertySet()` function. Both the order and composition of subsystems
vary per ship.

This document catalogs the exact wire format for all 16 stock multiplayer ships
(species 1–15 plus Enterprise at species slot 37), verified against stock dedicated server
traces from a 2026-02-22 collision test session.

For the round-robin algorithm, WriteState implementations, and linked list structure, see
[stateupdate-subsystem-wire-format.md](stateupdate-subsystem-wire-format.md).

## Species ID Mapping

From `Multiplayer/SpeciesToShip.py`:

| Species ID | Ship | Faction | Hardpoint File | Species Code |
|-----------|------|---------|----------------|--------------|
| 1 | Akira | Federation | akira.py | 103 |
| 2 | Ambassador | Federation | ambassador.py | 104 |
| 3 | Galaxy | Federation | galaxy.py | 101 |
| 4 | Nebula | Federation | nebula.py | 105 |
| 5 | Sovereign | Federation | sovereign.py | 102 |
| 6 | Bird of Prey | Klingon | birdofprey.py | 401 |
| 7 | Vor'cha | Klingon | vorcha.py | 402 |
| 8 | Warbird | Romulan | warbird.py | 301 |
| 9 | Marauder | Ferengi | marauder.py | 601 |
| 10 | Galor | Cardassian | galor.py | 201 |
| 11 | Keldon | Cardassian | keldon.py | 202 |
| 12 | CardHybrid | Cardassian | cardhybrid.py | 204 |
| 13 | KessokHeavy | Kessok | kessokheavy.py | 501 |
| 14 | KessokLight | Kessok | kessoklight.py | 502 |
| 15 | Shuttle | Federation | shuttle.py | 106 |
| 37 | Enterprise | Federation | enterprise.py | 102 (=Sovereign) |

`MAX_FLYABLE_SHIPS = 16`. Enterprise (slot 37) inherits from Sovereign and has an
identical subsystem layout — only HP/capacity values differ.

## WriteState Type Reference

Three virtual implementations of WriteState (vtable+0x70) exist:

| Class | Address | Used By | Bytes (remote) | Format |
|-------|---------|---------|----------------|--------|
| Base ShipSubsystem | 0x0056d320 | HullSubsystem, ShieldGenerator | 1 + N_children | `[cond:u8][child conds...]` |
| PoweredSubsystem | 0x00562960 | SensorSS, ImpulseEngine, WarpEngine, PhaserSystem, TorpedoSystem, TractorBeamSystem, PulseWeaponSystem, CloakDevice, RepairSS | 1 + N_children + 2 | `[cond:u8][child conds...][hasData:bit=1][powerPct:u8]` |
| PowerSubsystem | 0x005644b0 | PowerSubsystem (reactor) | 1 + 2 | `[cond:u8][mainBatt:u8][backupBatt:u8]` |

- **condition**: `(int)(currentCondition / maxCondition * 255.0)`, 0xFF=100%, 0x00=destroyed
- **powerPct**: `(int)(powerPercentageWanted * 100.0)`, range 0–100
- **mainBatt/backupBatt**: `(int)(batteryPower / batteryLimit * 255.0)`, range 0x00–0xFF
- PowerSubsystem ALWAYS writes battery bytes regardless of isOwnShip
- PoweredSubsystem only writes power data for remote ships (isOwnShip==0)
- Child subsystems always use Base WriteState (1 byte each)

## Summary Table

| Sp | Ship | Top-Level | Children | Total | Cycle Bytes | Cloak | Pulse | Tractors | Bridge |
|----|------|-----------|----------|-------|-------------|-------|-------|----------|--------|
| 1 | Akira | 11 | 20 | 31 | 47 | — | — | 2 | Yes |
| 2 | Ambassador | 11 | 18 | 29 | 45 | — | — | 2 | Yes |
| 3 | Galaxy | 11 | 23 | 34 | 50 | — | — | 4 | Yes |
| 4 | Nebula | 11 | 20 | 31 | 47 | — | — | 2 | Yes |
| 5 | Sovereign | 11 | 22 | 33 | 49 | — | — | 4 | Yes |
| 6 | Bird of Prey | 10 | 6 | 16 | 32 | Yes | 2 | — | — |
| 7 | Vor'cha | 12 | 12 | 24 | 44 | Yes | 2 | 2 | — |
| 8 | Warbird | 13 | 13 | 26 | 46 | Yes | 4 | 2 | Yes |
| 9 | Marauder | 10 | 9 | 19 | 35 | — | 2 | 2 | — |
| 10 | Galor | 9 | 8 | 17 | 31 | — | — | — | — |
| 11 | Keldon | 10 | 13 | 23 | 39 | — | — | 2 | — |
| 12 | CardHybrid | 11 | 18 | 29 | 47 | — | 1 | 2 | — |
| 13 | KessokHeavy | 10 | 14 | 24 | 40 | Yes | — | — | — |
| 14 | KessokLight | 10 | 13 | 23 | 39 | Yes | — | — | — |
| 15 | Shuttle | 9 | 6 | 15 | 29 | — | — | 1 | — |
| 37 | Enterprise | 11 | 22 | 33 | 49 | — | — | 4 | Yes |

- **Top-Level**: Subsystems in ship+0x284 after LinkAllSubsystemsToParents (FUN_005b3e20)
- **Children**: Subsystems removed from ship+0x284 and nested under parent systems
- **Total**: All subsystems created by Ship_SetupProperties (FUN_005b3fb0)
- **Cycle Bytes**: Total bytes to serialize all top-level subsystems once (flag 0x20 full cycle)

### Stock Dedi Verification

From function tracer Ship_AddSubsystem counts (2026-02-22 collision test, 15 species):

| Species | Ship | Hardpoint Count | Tracer Count | Match |
|---------|------|----------------|--------------|-------|
| 1 | Akira | 31 | 31 | ✓ |
| 2 | Ambassador | 29 | 29 | ✓ |
| 3 | Galaxy | 34 | 34 | ✓ |
| 4 | Nebula | 31 | 31 | ✓ |
| 5 | Sovereign | 33 | 33 | ✓ |
| 6 | Bird of Prey | 16 | 16 | ✓ |
| 7 | Vor'cha | 24 | 24 | ✓ |
| 8 | Warbird | 26 | 26 | ✓ |
| 9 | Marauder | 19 | 19 | ✓ |
| 10 | Galor | 17 | 17 | ✓ |
| 11 | Keldon | 23 | 23 | ✓ |
| 12 | CardHybrid | 29 | 29 | ✓ |
| 13 | KessokHeavy | 24 | 24 | ✓ |
| 14 | KessokLight | 23 | 23 | ✓ |
| 15 | Shuttle | 15 | 15 | ✓ |

All 15 hardpoint-derived counts match the runtime function tracer exactly.

## Per-Ship Detail

Each ship section shows:
1. Top-level subsystem list (ship+0x284 order after child linking)
2. Children per top-level subsystem
3. WriteState type and byte count for a remote ship
4. The AddToSet order determines the linked list order

---

### Species 1: Akira (Akira-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Sensor Array | SensorSubsystem | 0 | 3 |
| 3 | Warp Core | PowerSubsystem | 0 | 3 |
| 4 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 5 | Phasers | PhaserSystem | 8 (Ventral 1–4, Dorsal 1–4) | 11 |
| 6 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 7 | Torpedoes | TorpedoSystem | 6 (Fwd 1–2, Aft 1, Fwd 3–4, Aft 2) | 9 |
| 8 | Engineering | RepairSubsystem | 0 | 3 |
| 9 | Tractors | TractorBeamSystem | 2 (Forward, Aft) | 5 |
| 10 | Bridge | HullSubsystem | 0 | 1 |

**11 top-level, 20 children, 31 total. Full cycle: 47 bytes.**

---

### Species 2: Ambassador (Ambassador-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Sensor Array | SensorSubsystem | 0 | 3 |
| 3 | Warp Core | PowerSubsystem | 0 | 3 |
| 4 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 5 | Phasers | PhaserSystem | 8 (Ventral 1–3, Dorsal 1–3, Aft 1–2) | 11 |
| 6 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 7 | Torpedoes | TorpedoSystem | 4 (Fwd 1–2, Aft 1–2) | 7 |
| 8 | Engineering | RepairSubsystem | 0 | 3 |
| 9 | Bridge | HullSubsystem | 0 | 1 |
| 10 | Tractors | TractorBeamSystem | 2 (Forward, Aft) | 5 |

**11 top-level, 18 children, 29 total. Full cycle: 45 bytes.**

Note: Bridge at index 9 and Tractors at index 10 (reversed vs. most Federation ships).

---

### Species 3: Galaxy (Galaxy-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Warp Core | PowerSubsystem | 0 | 3 |
| 2 | Shield Generator | ShieldGenerator | 0 | 1 |
| 3 | Sensor Array | SensorSubsystem | 0 | 3 |
| 4 | Torpedoes | TorpedoSystem | 6 (Fwd 1–4, Aft 1–2) | 9 |
| 5 | Phasers | PhaserSystem | 8 (Ventral 1–4, Dorsal 1–4) | 11 |
| 6 | Impulse Engines | ImpulseEngine | 3 (Port, Star, Center) | 6 |
| 7 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 8 | Tractors | TractorBeamSystem | 4 (Aft 1–2, Fwd 1–2) | 7 |
| 9 | Bridge | HullSubsystem | 0 | 1 |
| 10 | Engineering | RepairSubsystem | 0 | 3 |

**11 top-level, 23 children, 34 total. Full cycle: 50 bytes.**

Notable: Warp Core at index 1 (before Shield Generator). **3 impulse engines** (unique
among Federation ships). Engineering at index 10 (last).

---

### Species 4: Nebula (Nebula-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Sensor Array | SensorSubsystem | 0 | 3 |
| 3 | Warp Core | PowerSubsystem | 0 | 3 |
| 4 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 5 | Phasers | PhaserSystem | 8 (Ventral 1–4, Dorsal 1–4) | 11 |
| 6 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 7 | Torpedoes | TorpedoSystem | 6 (Fwd 1–4, Aft 1–2) | 9 |
| 8 | Repair | RepairSubsystem | 0 | 3 |
| 9 | Tractors | TractorBeamSystem | 2 (Aft, Forward) | 5 |
| 10 | Bridge | HullSubsystem | 0 | 1 |

**11 top-level, 20 children, 31 total. Full cycle: 47 bytes.**

---

### Species 5: Sovereign (Sovereign-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Sensor Array | SensorSubsystem | 0 | 3 |
| 3 | Warp Core | PowerSubsystem | 0 | 3 |
| 4 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 5 | Torpedoes | TorpedoSystem | 6 (Fwd 1–4, Aft 1–2) | 9 |
| 6 | Repair | RepairSubsystem | 0 | 3 |
| 7 | Phasers | PhaserSystem | 8 (Ventral 1–4, Dorsal 1–4) | 11 |
| 8 | Tractors | TractorBeamSystem | 4 (Aft 1–2, Fwd 1–2) | 7 |
| 9 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 10 | Bridge | HullSubsystem | 0 | 1 |

**11 top-level, 22 children, 33 total. Full cycle: 49 bytes.**

Enterprise (species 37) has an identical layout — it inherits from Sovereign via
`ParentModule.LoadPropertySet()` and only overrides 4 property values (Hull HP, Shield HP,
Warp Core capacity, Engineering repair capacity).

---

### Species 6: Bird of Prey (Klingon B'rel-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Warp Core | PowerSubsystem | 0 | 3 |
| 3 | Disruptor Cannons | PulseWeaponSystem | 2 (Port, Star) | 5 |
| 4 | Torpedoes | TorpedoSystem | 1 (Forward) | 4 |
| 5 | Impulse Engines | ImpulseEngine | 1 (single engine) | 4 |
| 6 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 7 | Cloaking Device | CloakDevice | 0 | 3 |
| 8 | Sensor Array | SensorSubsystem | 0 | 3 |
| 9 | Engineering | RepairSubsystem | 0 | 3 |

**10 top-level, 6 children, 16 total. Full cycle: 32 bytes.**

Notable: No phasers — uses PulseWeaponSystem (disruptor cannons) only. Single impulse
engine, single torpedo tube. Has cloaking device. No Bridge, no tractors.

---

### Species 7: Vor'cha (Klingon Vor'cha-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Warp Core | PowerSubsystem | 0 | 3 |
| 3 | Disruptor Beams | PhaserSystem | 1 (single disruptor) | 4 |
| 4 | Disruptor Cannons | PulseWeaponSystem | 2 (Port, Star) | 5 |
| 5 | Torpedoes | TorpedoSystem | 3 (Fwd 1–2, Aft) | 6 |
| 6 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 7 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 8 | Cloaking Device | CloakDevice | 0 | 3 |
| 9 | Sensor Array | SensorSubsystem | 0 | 3 |
| 10 | Repair System | RepairSubsystem | 0 | 3 |
| 11 | Tractors | TractorBeamSystem | 2 (Aft, Forward) | 5 |

**12 top-level, 12 children, 24 total. Full cycle: 44 bytes.**

Notable: Has BOTH PhaserSystem (1 disruptor beam) AND PulseWeaponSystem (2 cannons).
12 top-level is the most of any non-Romulan ship. Has cloaking device.

---

### Species 8: Warbird (Romulan D'deridex-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Power Plant | PowerSubsystem | 0 | 3 |
| 3 | Disruptor Beam | PhaserSystem | 1 (single disruptor) | 4 |
| 4 | Disruptor Cannons | PulseWeaponSystem | 4 (Port 1–2, Star 1–2) | 7 |
| 5 | Torpedoes | TorpedoSystem | 2 (Forward, Aft) | 5 |
| 6 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 7 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 8 | Cloaking Device | CloakDevice | 0 | 3 |
| 9 | Sensor Array | SensorSubsystem | 0 | 3 |
| 10 | Engineering | RepairSubsystem | 0 | 3 |
| 11 | Bridge | HullSubsystem | 0 | 1 |
| 12 | Tractors | TractorBeamSystem | 2 (Aft, Forward) | 5 |

**13 top-level, 13 children, 26 total. Full cycle: 46 bytes.**

Notable: **13 top-level** — the most of any stock ship. Reactor named "Power Plant".
4 pulse weapons (most of any ship). Only non-Federation ship with Bridge hull.
Has both PhaserSystem and PulseWeaponSystem.

---

### Species 9: Marauder (Ferengi D'Kora-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Warp Core | PowerSubsystem | 0 | 3 |
| 3 | Phasers | PhaserSystem | 1 (Ventral Phaser) | 4 |
| 4 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 5 | Warp Engines | WarpEngine | 2 (Star, Port) | 5 |
| 6 | Tractors | TractorBeamSystem | 2 (Forward, Aft) | 5 |
| 7 | Sensor Array | SensorSubsystem | 0 | 3 |
| 8 | Repair Subsystem | RepairSubsystem | 0 | 3 |
| 9 | Plasma Emitters | PulseWeaponSystem | 2 (Port, Star) | 5 |

**10 top-level, 9 children, 19 total. Full cycle: 35 bytes.**

Notable: NO torpedoes at all — only stock ship without them. Only 1 phaser bank. Has
Plasma Emitters (PulseWeaponSystem). No Bridge.

---

### Species 10: Galor (Cardassian Galor-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Warp Core | PowerSubsystem | 0 | 3 |
| 3 | Compressors | PhaserSystem | 4 (Forward, Port, Star, Aft Beam) | 7 |
| 4 | Torpedoes | TorpedoSystem | 1 (Forward) | 4 |
| 5 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 6 | Warp Engine | WarpEngine | 1 (single engine) | 4 |
| 7 | Repair Subsystem | RepairSubsystem | 0 | 3 |
| 8 | Sensor Array | SensorSubsystem | 0 | 3 |

**9 top-level, 8 children, 17 total. Full cycle: 31 bytes.**

Notable: Only **9 top-level** — smallest non-shuttle ship. Phaser system named
"Compressors". Single warp engine. Single torpedo tube. No tractors, no Bridge, no cloak.

---

### Species 11: Keldon (Cardassian Keldon-class)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Shield Generator | ShieldGenerator | 0 | 1 |
| 2 | Warp Core | PowerSubsystem | 0 | 3 |
| 3 | Compressors | PhaserSystem | 4 (Forward, Port, Star, Aft Beam) | 7 |
| 4 | Torpedoes | TorpedoSystem | 2 (Forward, Aft) | 5 |
| 5 | Impulse Engines | ImpulseEngine | 4 (Engine 1–4) | 7 |
| 6 | Warp Engine | WarpEngine | 1 (single engine) | 4 |
| 7 | Sensor Array | SensorSubsystem | 0 | 3 |
| 8 | Repair Subsystem | RepairSubsystem | 0 | 3 |
| 9 | Tractors | TractorBeamSystem | 2 (Ventral, Dorsal) | 5 |

**10 top-level, 13 children, 23 total. Full cycle: 39 bytes.**

Notable: **4 impulse engines** — unique among all stock ships. Like Galor, uses
"Compressors" for phasers and has single warp engine.

---

### Species 12: CardHybrid (Cardassian Hybrid)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Warp Core | PowerSubsystem | 0 | 3 |
| 2 | Torpedoes | TorpedoSystem | 3 (Torpedo 1–2, Aft Torpedo) | 6 |
| 3 | Repair System | RepairSubsystem | 0 | 3 |
| 4 | Shield Generator | ShieldGenerator | 0 | 1 |
| 5 | Sensor Array | SensorSubsystem | 0 | 3 |
| 6 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 7 | Warp Engines | WarpEngine | 3 (Port, Star, Center) | 6 |
| 8 | Beams | PhaserSystem | 7 (Fwd Compressor, Fwd 1–2, Ventral 1–2, Dorsal 1–2) | 10 |
| 9 | Disruptor Cannons | PulseWeaponSystem | 1 (single cannon) | 4 |
| 10 | Tractors | TractorBeamSystem | 2 (Forward, Aft) | 5 |

**11 top-level, 18 children, 29 total. Full cycle: 47 bytes.**

Notable: Unusual AddToSet order — Warp Core at index 1, Repair at index 3, Shield at
index 4. Has BOTH PhaserSystem ("Beams", 7 banks — most phaser banks) AND PulseWeaponSystem
(1 cannon). **3 warp engines** (Port, Star, Center) — unique among stock ships.

---

### Species 13: KessokHeavy (Kessok Heavy Cruiser)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Warp Core | PowerSubsystem | 0 | 3 |
| 2 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 3 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 4 | Positron Beams | PhaserSystem | 8 (Fwd 1–4, Ventral 1–2, Dorsal 1–2) | 11 |
| 5 | Torpedoes | TorpedoSystem | 2 (Tube 1–2) | 5 |
| 6 | Repair System | RepairSubsystem | 0 | 3 |
| 7 | Shield Generator | ShieldGenerator | 0 | 1 |
| 8 | Sensor Array | SensorSubsystem | 0 | 3 |
| 9 | Cloaking Device | CloakDevice | 0 | 3 |

**10 top-level, 14 children, 24 total. Full cycle: 40 bytes.**

Notable: Has Cloaking Device. Phasers named "Positron Beams" (8 banks). Shield Generator
at index 7 (unusual). No tractors, no Bridge.

---

### Species 14: KessokLight (Kessok Destroyer)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Warp Core | PowerSubsystem | 0 | 3 |
| 2 | Torpedoes | TorpedoSystem | 1 (single torpedo) | 4 |
| 3 | Repair System | RepairSubsystem | 0 | 3 |
| 4 | Shield Generator | ShieldGenerator | 0 | 1 |
| 5 | Sensor Array | SensorSubsystem | 0 | 3 |
| 6 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 7 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 8 | Beams | PhaserSystem | 8 (Fwd 1–2, Port 1–2, Star 1–2, Aft 1–2) | 11 |
| 9 | Cloaking Device | CloakDevice | 0 | 3 |

**10 top-level, 13 children, 23 total. Full cycle: 39 bytes.**

Notable: Has Cloaking Device. 8 phaser banks ("Beams"). Only 1 torpedo tube.
No tractors, no Bridge.

---

### Species 15: Shuttle (Federation Shuttlecraft)

| Idx | Subsystem | Type | Children | WriteState Bytes |
|-----|-----------|------|----------|-----------------|
| 0 | Hull | HullSubsystem | 0 | 1 |
| 1 | Impulse Engines | ImpulseEngine | 2 (Port, Star) | 5 |
| 2 | Warp Core | PowerSubsystem | 0 | 3 |
| 3 | Sensor Array | SensorSubsystem | 0 | 3 |
| 4 | Shield Generator | ShieldGenerator | 0 | 1 |
| 5 | Phasers | PhaserSystem | 1 (single phaser) | 4 |
| 6 | Repair | RepairSubsystem | 0 | 3 |
| 7 | Warp Engines | WarpEngine | 2 (Port, Star) | 5 |
| 8 | Tractors | TractorBeamSystem | 1 (Forward) | 4 |

**9 top-level, 6 children, 15 total. Full cycle: 29 bytes.**

Notable: Smallest combat ship. No torpedoes. Only 1 phaser bank, 1 tractor beam.
Impulse Engines at index 1 (before Warp Core). No Bridge, no cloak.

---

## Universal Subsystem Patterns

All 16 stock MP ships share these 7 subsystem types (always present):
1. **HullSubsystem** — at least 1 hull (5 Federation capital ships have 2: Hull + Bridge)
2. **ShieldGenerator** — always 1 (shield facing data is in flag 0x40, not flag 0x20)
3. **PowerSubsystem** — always 1 reactor (named "Warp Core" or "Power Plant")
4. **SensorSubsystem** — always 1
5. **ImpulseEngine** — always 1 system (1–4 child engines)
6. **WarpEngine** — always 1 system (1–3 child engines)
7. **RepairSubsystem** — always 1

Optional subsystem types:
- **PhaserSystem** — present on all ships except Bird of Prey (1–8 child banks)
- **TorpedoSystem** — present on all ships except Marauder (1–6 child tubes)
- **TractorBeamSystem** — absent from: Bird of Prey, Galor, KessokHeavy, KessokLight
- **PulseWeaponSystem** — present on: Bird of Prey, Vor'cha, Warbird, Marauder, CardHybrid
- **CloakDevice** — present on: Bird of Prey, Vor'cha, Warbird, KessokHeavy, KessokLight
- **Bridge (HullSubsystem)** — present on: all 5 Federation capital ships + Warbird

## Round-Robin Timing

With the 10-byte budget per tick at ~10 Hz:

| Cycle Bytes | Ticks per Full Cycle | Full Cycle Time |
|-------------|---------------------|-----------------|
| 29 (Shuttle) | ~3 | ~0.3s |
| 31 (Galor) | ~4 | ~0.4s |
| 32 (BoP) | ~4 | ~0.4s |
| 35 (Marauder) | ~4 | ~0.4s |
| 39 (Keldon, KLight) | ~4 | ~0.4s |
| 40 (KHeavy) | ~4 | ~0.4s |
| 44 (Vorcha) | ~5 | ~0.5s |
| 45 (Ambassador) | ~5 | ~0.5s |
| 46 (Warbird) | ~5 | ~0.5s |
| 47 (Akira, Nebula, CHybrid) | ~5 | ~0.5s |
| 49 (Sovereign, Enterprise) | ~5 | ~0.5s |
| 50 (Galaxy) | ~5 | ~0.5s |

All ships complete a full subsystem health cycle in under 1 second.

## Implications for Reimplementation

1. **Subsystem list order is ship-specific.** A reimplementation must build the same
   linked list for each ship class, in the same order as the original hardpoint scripts.
   Mismatches cause the receiver to apply subsystem health to the wrong subsystem.

2. **The receiver and sender must agree on the list.** Both sides run the same hardpoint
   file (verified by checksum exchange), so both build identical linked lists via
   `SetupProperties` + `LinkAllSubsystemsToParents`.

3. **Only top-level subsystems are in the round-robin.** Children are serialized
   recursively inside their parent's WriteState call.

4. **Shield facing data is NOT in flag 0x20.** The ShieldGenerator in the subsystem list
   only writes 1 condition byte. Actual shield facing HP uses flag 0x40 (CLOAK_STATE
   bit — overloaded for shield data on non-cloaking ships or as a separate data path).

5. **WriteState format is determined by the subsystem's vtable.** Base subsystems write
   1 byte, Powered subsystems write 1+N+2 bytes, PowerSubsystem writes 1+2 bytes.
   The vtable is determined by the property type used in `AddToSet`.

6. **Mod ships will have different layouts.** This catalog only covers the 16 stock ships.
   Any mod-added ship will have its own AddToSet order and subsystem composition.
