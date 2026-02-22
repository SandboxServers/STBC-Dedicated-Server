> [docs](../README.md) / [networking](README.md) / ship-death-lifecycle.md

# Ship Death Lifecycle in Multiplayer

## Date: 2026-02-21 (updated 2026-02-21)
## Status: VERIFIED (from stock dedi packet traces — 59 deaths in 33.5-minute battle session + 6 deaths in self-destruct session)

## Overview

When a ship is destroyed in Bridge Commander multiplayer, the stock dedicated server
uses a specific sequence of network messages. Two critical findings:

1. **DestroyObject (0x14) is NOT used** for any ship death (combat or self-destruct)
2. **The server NEVER auto-respawns** — ALL respawns are client-initiated

## Key Finding: Stock Server Never Auto-Respawns

**All ObjCreateTeam (0x03) messages in the battle trace are client-initiated relays,
NOT server-originated spawns.** The stock server uses star topology: client messages
are relayed to all other peers. When a client sends ObjCreateTeam after picking a new
ship, the server relays it to all other clients. There are zero server-originated
ObjCreateTeam messages after any death type.

Evidence from battle trace (33.5 min, 3 players, 59 deaths):
- 62 ObjCreateTeam total: 3 initial spawns + 59 respawns
- All 62 are client-initiated (client sends 0x03, server relays to other peers)
- Zero server-originated ObjCreateTeam after any death

Evidence from self-destruct trace (6 deaths, 3 ship types):
- Zero server-originated ObjCreateTeam after any self-destruct
- Client returns to ship selection, picks new ship, sends 0x03

## Death Sequence

### 1. Ship HP reaches 0

The damage pipeline (collision, weapon, or explosion path) reduces hull condition to 0.
The engine posts `ET_OBJECT_EXPLODING` (0x0080004E) to the event system.

### 2. ObjectExplodingHandler sends PythonEvent + Explosion

`ObjectExplodingHandler` at `0x006A1240` catches `ET_OBJECT_EXPLODING`:
- Serializes the event as PythonEvent (opcode 0x06) with factory `0x8129`
- Sends reliably to "NoMe" group (all clients)
- Payload includes `firing_player_id` (killer's connection ID) and `lifetime` (explosion duration)

For combat kills, the engine also sends Explosion (opcode 0x29) which carries:
- Object ID (the dying ship)
- Impact position (compressed Vec4)
- Damage amount (CompressedFloat16)
- Explosion radius (CompressedFloat16)

For self-destruct, Explosion (0x29) is NOT sent — only ObjectExplodingEvent.

### 3. Client returns to ship selection and respawns

After the 9.5-second explosion animation, the client returns to the ship selection
screen. The **client** picks a new ship and sends ObjCreateTeam (0x03). The server
relays this to all other clients. The server does NOT initiate the respawn.

### 4. DestroyObject (0x14) is NOT sent

**Zero** DestroyObject (0x14) packets were observed across 59 combat deaths and
6 self-destruct deaths. The handler exists at `FUN_006A01E0` but is not invoked for
MP ship deaths.

DestroyObject may be reserved for:
- Non-ship object cleanup (torpedoes, projectiles)
- Player disconnect cleanup (removing the ship when a player leaves)
- Single-player object destruction

## SCORE_CHANGE Anomaly

In the collision test trace (28s, 2 players, 1 collision kill), a SCORE_CHANGE (0x36)
was sent for the kill.

In the battle trace (33.5 min, 3 players, 59 weapon kills), **zero** SCORE_CHANGE
messages were observed. This suggests:
- Collision kills correctly trigger SCORE_CHANGE
- Weapon kills may NOT trigger SCORE_CHANGE on stock dedicated servers
- This may be a stock BC bug — the scoring handler may not be registered for
  weapon-path destruction events

**Follow-up needed**: RE the ObjectKilledHandler to determine why weapon kills
don't produce SCORE_CHANGE.

## Packet Counts from Stock Traces

### Collision Test (28s, 2 players)
| Opcode | Name | Count |
|--------|------|-------|
| 0x29 | Explosion | 1 |
| 0x03 | ObjCreateTeam | 1 (client-initiated relay) |
| 0x14 | DestroyObject | 0 |
| 0x36 | SCORE_CHANGE | 1 |

### Battle of Valentine's Day (33.5 min, 3 players, 59 deaths)
| Opcode | Name | Count |
|--------|------|-------|
| 0x29 | Explosion | 59 |
| 0x03 | ObjCreateTeam | 62 (3 initial + 59 client-initiated respawn relays) |
| 0x14 | DestroyObject | 0 |
| 0x36 | SCORE_CHANGE | 0 |

The 3 extra ObjCreateTeam vs Explosion correspond to initial ship spawns at game start.
All 62 are client-initiated messages relayed through the server's star topology.

## Self-Destruct vs Combat Death (Verified 2026-02-21)

Self-destruct and combat kills follow **different** network message sequences on the stock
dedicated server. Verified by comparing stock traces: a self-destruct test session and the
33.5-minute battle session with 59 combat kills.

### Combat Kills

```
Ship HP -> 0 (weapon/collision/explosion damage)
  -> ObjectExplodingEvent (0x06, factory 0x8129)
     source=killer_ship, dest=dying_ship, lifetime=9.5s
  -> Explosion (0x29): position, damage, radius
  -> SCORE_CHANGE (0x36): kill + death credited (collision kills; may not fire for weapon kills)
  -> Client returns to ship selection, sends ObjCreateTeam (0x03)
```

Battle trace counts: 59 Explosion (0x29), 62 ObjCreateTeam (0x03, all client relays), 0 DestroyObject (0x14).

### Self-Destruct (Opcode 0x13)

```
Client sends HostMsg (0x13, 1 byte)
  -> ObjectExplodingEvent (0x06, factory 0x8129)
     source=NULL (0x00000000), dest=dying_ship, lifetime=9.5s
  -> SCORE_CHANGE (0x36): death counted, no kill credit
  -> 6x TGSubsystemEvent (ET_ADD_TO_REPAIR_LIST)
  -> 9.5 seconds: explosion animation, StateUpdates continue
  -> Client returns to ship selection (spawn menu)
  -> Client sends ObjCreateTeam (0x03) when player picks new ship
```

**Key differences from combat death:**
- **NO Explosion (0x29)** — only ObjectExplodingEvent triggers the animation
- **NO DestroyObject (0x14)** — ship exists as wreckage during explosion
- **source=NULL** in ObjectExplodingEvent (no attacker)
- Death counted but no kill credit awarded
- 6 TGSubsystemEvents (ET_ADD_TO_REPAIR_LIST) for primary subsystems

**Common between both:**
- **NO server-initiated respawn** — client picks a new ship and sends ObjCreateTeam
- **NO DestroyObject (0x14)** — ship is never explicitly destroyed

## Self-Destruct TGSubsystemEvent Detail (Stock)

Stock self-destruct sends exactly **6 TGSubsystemEvents** (ET_ADD_TO_REPAIR_LIST, event
0x008000DF, factory 0x0101). These route damaged subsystems TO the RepairSubsystem for
crew auto-repair queuing.

### 4 Immediate (with ObjectExplodingEvent):
| source_obj | dest_obj | Subsystem |
|------------|----------|-----------|
| PowerReactor obj | RepairSubsystem obj | Reactor → Repair |
| ShieldGenerator obj | RepairSubsystem obj | Shields → Repair |
| PhaserController obj | RepairSubsystem obj | Phaser → Repair |
| PulseWeapon obj | RepairSubsystem obj | Pulse Weapon → Repair |

### 2 Late (at T+9.5s, during debris collision phase):
| source_obj | dest_obj | Subsystem |
|------------|----------|-----------|
| PoweredSubsystem obj | RepairSubsystem obj | EPS → Repair |
| RepairSubsystem obj | RepairSubsystem obj | Repair → Repair |

Stock only sends repair events for **primary subsystems** (6 total), NOT for every
individual phaser bank and torpedo tube. This is significant for implementations that
iterate all subsystems — sending 18-25 events (one per subsystem) overflows the reliable
retransmit queue.

## Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x006A1240 | ObjectExplodingHandler | Serializes explosion as PythonEvent (0x06) |
| 0x006A0080 | Handler_Explosion_0x29 | Receives Explosion opcode on client |
| 0x0069F620 | Handler_ObjCreate_0x02_0x03 | Receives ObjCreateTeam respawn on client |
| 0x006A01E0 | Handler_DestroyObject_0x14 | NOT used for MP ship deaths |

## Related Documents

- [cf16-explosion-encoding.md](../protocol/cf16-explosion-encoding.md) — CompressedFloat16 encoding for damage/radius
- [pythonevent-wire-format.md](../protocol/pythonevent-wire-format.md) — ObjectExplodingEvent (factory 0x8129) wire format
- [collision-effect-protocol.md](../protocol/collision-effect-protocol.md) — Collision damage path
- [damage-system.md](../gameplay/damage-system.md) — Complete damage pipeline
- [disconnect-flow.md](disconnect-flow.md) — Player disconnect (may use 0x14)
- [self-destruct-pipeline.md](../gameplay/self-destruct-pipeline.md) — Full self-destruct pipeline + stock vs OpenBC comparison
