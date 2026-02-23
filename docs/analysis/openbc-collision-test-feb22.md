> [docs](../README.md) / [analysis](README.md) / openbc-collision-test-feb22.md

# OpenBC Collision Test — Per-Species Power & Rate Limiting Analysis

**Date**: 2026-02-22
**Status**: HIGH-CONFIDENCE (live OpenBC server + client, observational testing)
**Test scenario**: Client connects to OpenBC server, spawns as each species sequentially, collides with environment objects

---

## 1. Session Overview

Two test sessions covering 13 of 16 flyable ship species. Session 1 tested Federation ships (species 1-5). Session 2 tested Klingon, Cardassian, and Kessok ships (species 6-8, 10-13).

### Session 1 — Federation Ships

| Property | Value |
|----------|-------|
| Duration | ~8 minutes |
| Ships tested | Sovereign, Nebula, Galaxy, Ambassador, Akira (×2) |
| Species covered | 1 (Akira), 2 (Ambassador), 3 (Galaxy), 4 (Nebula), 5 (Sovereign) |
| Total collisions | 16 |
| Total deaths | 6 (all collision kills) |
| CollisionEffect packets | 73 |
| Disconnects/crashes | 0 |

### Session 2 — Klingon/Cardassian/Kessok Ships

| Property | Value |
|----------|-------|
| Duration | ~11 minutes |
| Ships tested | Warbird, Bird of Prey, Vorcha, Galor, Keldon, CardHybrid, KessokHeavy |
| Species covered | 6 (BoP), 7 (Vorcha), 8 (Warbird), 10 (Galor), 11 (Keldon), 12 (CardHybrid), 13 (KessokHeavy) |
| CollisionEffect packets | 28,504 |
| Total deaths | Many (KessokHeavy alone: 26 respawns) |
| Disconnects/crashes | 0 |

---

## 2. Per-Species Results

### Session 1: Federation Ships (Species 1-5)

All Federation ships had functional power systems. Hull tracking worked correctly — ships died at believable hull thresholds. The primary finding was that **no PythonEvents were generated on collision damage**, leaving the repair queue empty on all ships.

| Ship | Species | Hull | Collisions | Died? | Shields UI | F5 Tactical | Repair Queue |
|------|---------|------|------------|-------|------------|-------------|--------------|
| Sovereign | 5 | 12,000 | 4 (~29,500 total) | Yes | ? | ? | ? |
| Nebula | 4 | — | — | — | ? | Death only | ? |
| Galaxy | 3 | — | — | — | Works | ? | Empty |
| Ambassador | 2 | — | — | — | Works | ? | ? |
| Akira | 1 | 9,000 | 1 (12,651) | Yes, one-shot | ? | ? | ? |

**Key observations:**
- Shields UI updates from StateUpdate shield health data (works)
- F5 tactical screen only shows damage at death when everything goes to zero
- Repair queue requires PythonEvent damage notifications, which are not generated on collision
- Opcode summary shows only: StateUpdate (3496), CollisionEffect (73), ChecksumResp (10), ObjCreateTeam (6), NewPlayerInGame (2)
- Notably absent: PythonEvent, SubsysStatus, AddToRepairList

### Session 2: Klingon/Cardassian/Kessok Ships (Species 6-13)

| Ship | Species | Hull | Collisions | Died? | Power Status | Notes |
|------|---------|------|------------|-------|-------------|-------|
| Warbird | 8 | 24,000 | ~510 (flood) | Yes | OK | Already tested in prior session |
| Bird of Prey | 6 | 4,000 | 1 (11,644) | Yes, one-shot | OK | Could fly, just fragile |
| Vorcha | 7 | 18,000 | 2 (12,925 + 12,598) | **No** | OK | Shield absorption confirmed working |
| Galor | 10 | 5,000 | 0 | No | **ZERO** | Engines non-functional, couldn't move |
| Keldon | 11 | 6,000 | 1 (11,187) | Yes, one-shot | **BROKEN** | Batteries/reserves not charged |
| CardHybrid | 12 | 11,000 | ~12 (flood) | Yes | **BROKEN** | Warp core at ~85% |
| KessokHeavy | 13 | 18,000 | Massive flood | 26 respawns | **BROKEN** | Warp core at ~87%, collision respawn loop |

---

## 3. Per-Species Power Table

Summary of power system status across all tested species:

| Species | Ship | Power Status | Symptom |
|---------|------|-------------|---------|
| 1 | Akira | OK | Full power, normal operation |
| 2 | Ambassador | OK | Full power, normal operation |
| 3 | Galaxy | OK | Full power, normal operation |
| 4 | Nebula | OK | Full power, normal operation |
| 5 | Sovereign | OK | Full power, normal operation |
| 6 | Bird of Prey | OK | Full power, normal operation |
| 7 | Vorcha | OK | Full power, shields absorbing correctly |
| 8 | Warbird | OK | Full power (prior session confirmed) |
| 9 | Marauder | UNTESTED | — |
| 10 | Galor | **BROKEN** | Zero effective power output; engines non-functional |
| 11 | Keldon | **BROKEN** | Power output exists but batteries/reserves not charged |
| 12 | CardHybrid | **BROKEN** | Warp core initialized at ~85% instead of 100% |
| 13 | KessokHeavy | **BROKEN** | Warp core initialized at ~87% instead of 100% |
| 14 | KessokLight | UNTESTED | — |
| 15 | Shuttle | UNTESTED | — |
| 16 | CardFreighter | UNTESTED | — |

Each BC "species" is a per-ship-class ID with its own power tables, subsystem definitions, and hardpoint configs. The Galor (species 10) having zero power and the Keldon (species 11) having uncharged batteries are two different bugs in two different species data entries, not a single "Cardassian faction" problem.

**Pattern**: Species 1-8 (Federation + Klingon + Romulan) all work correctly. Species 10-13 (Cardassian + Kessok) all have different power failures. The data files themselves are correct (verified: Galor has power_output=500 in its data). The bug is in code — either species-specific parsing or power initialization logic.

---

## 4. Collision Rate Analysis

### Stock BC Rate (Reference)

From the Valentine's Day stock trace (33.5 minutes, 3 players):
- **84 CollisionEffect packets** total
- Rate: ~0.04/sec (2.5 per minute)

See: [valentines-day-battle-analysis.md](valentines-day-battle-analysis.md)

### OpenBC Session 1 (Federation)

- **73 CollisionEffect packets** in ~8 minutes
- Rate: ~0.15/sec (9.1 per minute)
- Slightly elevated but reasonable — all intentional ram-testing

### OpenBC Session 2 (Klingon/Cardassian/Kessok)

- **28,504 CollisionEffect packets** in ~11 minutes
- Rate: **~43/sec** (2,591 per minute)
- **1,033× higher than stock** reference rate

The collision flood is caused by the client sending a CollisionEffect every ~30ms (~33/second) when a ship grinds against an asteroid. Stock BC has collision cooldown logic that prevents this. The KessokHeavy respawn loop (26 deaths in ~2 minutes) was caused by: spawn → immediately collide with same asteroid → die → respawn at same spot → repeat.

### Rate Limiting in Stock BC

Stock BC applies collision rate limiting at the collision detection level. The exact mechanism (cooldown timer, minimum velocity threshold, or contact deduplication) has not been RE'd, but the effect is clear: a maximum of ~0.04 CollisionEffect/sec in normal gameplay vs the uncapped ~43/sec in OpenBC.

---

## 5. Vorcha Shield Absorption (Positive Finding)

The Vorcha (species 7) provided the strongest evidence that the collision-shield absorption pipeline works correctly:

- **Hit 1**: 12,925 collision energy
- **Hit 2**: 12,598 collision energy (24 seconds later)
- **Total collision energy**: 25,523
- **Ship hull**: 18,000
- **Result**: Ship survived

The 25,523 total collision energy exceeds the 18,000 hull, but the ship survived because shields absorbed a portion of each hit. The 24-second gap between hits gave shields time to recharge. The damage values in the log represent pre-shield collision energy, not actual hull damage applied.

This confirms:
- Shield directional absorption is functional
- Shield recharge between hits works
- The collision → shield check → hull damage pipeline is correct

See: [collision-shield-interaction.md](../gameplay/collision-shield-interaction.md)

---

## 6. Missing PythonEvents on Collision Damage

Both sessions confirmed that **zero PythonEvent opcodes** were generated on collision damage. This affects all species equally — it's not a per-species issue.

**Impact:**
- Repair queue is always empty (repair queue entries are added by TGSubsystemEvent damage notifications)
- F5 engineering screen only shows damage at death (when everything zeroes out via StateUpdate)
- Shields UI works because it reads from StateUpdate shield health, not PythonEvents

**Root cause**: OpenBC's collision damage pipeline does not call the `generate_damage_events()` function (or equivalent) that produces TGSubsystemEvent notifications. In stock BC, the DoDamage → ProcessDamage chain fires TGSubsystemEvents for each damaged subsystem.

See: [damage-system.md](../gameplay/damage-system.md), [repair-system.md](../gameplay/repair-system.md)

---

## 7. Collision Ownership Validation

Session 2 logged 5,116 collision ownership failures at the KessokHeavy phase:
```
[WARN] collision ownership fail (sender=0x40040071 src=0 tgt=0x40040053)
```

These are stale object IDs from previous ship spawns (CardHybrid era). The client reports collisions for objects it still tracks, but the server rejects them because they don't match the current ship. This is the same post-respawn collision ownership bug documented in [collision-trace-comparison.md](collision-trace-comparison.md) (Bug 1), but manifesting across ship changes rather than respawns.

---

## 8. Cross-References

- [collision-trace-comparison.md](collision-trace-comparison.md) — Stock vs OpenBC wire format comparison (same day, session 1)
- [valentines-day-battle-analysis.md](valentines-day-battle-analysis.md) — Stock collision rate baseline (84 packets / 33.5 min)
- [docs/gameplay/damage-system.md](../gameplay/damage-system.md) — Complete damage pipeline RE
- [docs/gameplay/collision-shield-interaction.md](../gameplay/collision-shield-interaction.md) — Shield absorption mechanics
- [docs/gameplay/power-system.md](../gameplay/power-system.md) — Per-species power tables and initialization
- [docs/gameplay/repair-system.md](../gameplay/repair-system.md) — Repair queue and PythonEvent dependency
