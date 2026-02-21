# Ship Death Lifecycle in Multiplayer

## Date: 2026-02-21
## Status: VERIFIED (from stock dedi packet traces — 59 deaths in 33.5-minute battle session)

## Overview

When a ship is destroyed in Bridge Commander multiplayer, the stock dedicated server
uses a specific sequence of network messages. Notably, **DestroyObject (0x14) is NOT
used** for ship deaths — instead, ships die via an explosion broadcast followed by
immediate respawn.

## Death Sequence

### 1. Ship HP reaches 0

The damage pipeline (collision, weapon, or explosion path) reduces hull condition to 0.
The engine posts `ET_OBJECT_EXPLODING` (0x0080004E) to the event system.

### 2. ObjectExplodingHandler sends Explosion (0x29)

`ObjectExplodingHandler` at `0x006A1240` catches `ET_OBJECT_EXPLODING`:
- Serializes the event as PythonEvent (opcode 0x06) with factory `0x8129`
- Sends reliably to "NoMe" group (all clients)
- Payload includes `firing_player_id` (killer's connection ID) and `lifetime` (explosion duration)

Simultaneously, the engine sends Explosion (opcode 0x29) which carries:
- Object ID (the dying ship)
- Impact position (compressed Vec4)
- Damage amount (CompressedFloat16)
- Explosion radius (CompressedFloat16)

### 3. Server sends ObjCreateTeam (0x03) to respawn

The server immediately creates a new ship object for the same player and sends
ObjCreateTeam (0x03) to all clients. This replaces the destroyed ship with a fresh
instance at full health.

### 4. DestroyObject (0x14) is NOT sent

**Zero** DestroyObject (0x14) packets were observed across 59 ship deaths in the
battle trace. The handler exists at `FUN_006A01E0` but is not invoked for MP ship deaths.

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
| 0x03 | ObjCreateTeam | 1 |
| 0x14 | DestroyObject | 0 |
| 0x36 | SCORE_CHANGE | 1 |

### Battle of Valentine's Day (33.5 min, 3 players, 59 deaths)
| Opcode | Name | Count |
|--------|------|-------|
| 0x29 | Explosion | 59 |
| 0x03 | ObjCreateTeam | 62 |
| 0x14 | DestroyObject | 0 |
| 0x36 | SCORE_CHANGE | 0 |

The 3 extra ObjCreateTeam vs Explosion may correspond to initial ship spawns at game start.

## Key Functions

| Address | Name | Role |
|---------|------|------|
| 0x006A1240 | ObjectExplodingHandler | Serializes explosion as PythonEvent (0x06) |
| 0x006A0080 | Handler_Explosion_0x29 | Receives Explosion opcode on client |
| 0x0069F620 | Handler_ObjCreate_0x02_0x03 | Receives ObjCreateTeam respawn on client |
| 0x006A01E0 | Handler_DestroyObject_0x14 | NOT used for MP ship deaths |

## Related Documents

- [cf16-explosion-encoding.md](cf16-explosion-encoding.md) — CompressedFloat16 encoding for damage/radius
- [pythonevent-wire-format.md](pythonevent-wire-format.md) — ObjectExplodingEvent (factory 0x8129) wire format
- [collision-effect-protocol.md](collision-effect-protocol.md) — Collision damage path
- [damage-system.md](damage-system.md) — Complete damage pipeline
- [disconnect-flow.md](disconnect-flow.md) — Player disconnect (may use 0x14)
