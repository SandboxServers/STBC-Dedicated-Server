# Stock Trace Analysis — Ground Truth Reference

## Date: 2026-02-21
## Status: HIGH-CONFIDENCE (OBSERVE_ONLY stock dedi traces, zero patches)

## Overview

Analysis of two stock Bridge Commander dedicated server packet captures, used as ground
truth to validate and correct existing documentation. Both traces captured with the
OBSERVE_ONLY instrumentation mode (passive packet logging, zero binary patches).

## Trace Sessions

### Collision Test
- **Duration**: ~28 seconds
- **Players**: 2
- **Total packets**: 481
- **Ship deaths**: 1 (collision kill)
- **Purpose**: Short collision interaction test

### Battle of Valentine's Day
- **Duration**: ~33.5 minutes (2,007 seconds)
- **Players**: 3
- **Total packets**: 138,695
- **Ship deaths**: 59
- **Explosions**: 59
- **Purpose**: Extended weapon combat session

## 10 High-Confidence Findings

### 1. MISSION_INIT (0x35) byte[1] = current player count

Stock sends `0x01` in the 2-player session and `0x03` in the 3-player session.
This field tracks the number of currently connected players, NOT a fixed config value.

**Correction**: Previous docs stated "stock sends 0x09" — this was incorrect.
Our implementation already sends `0x01`, which is correct for a 2-player session.

### 2. StateUpdate SUB/WPN flag split is ~96%, not absolute

The host's own ship sends WPN (0x80) in the S→C direction: 7,876 packets with flag
0x80 in server-to-client StateUpdates in the battle trace. The split is approximately
96% direction-correlated, not 100%.

**Reason**: The host is also a player. Its own ship object sends weapon health data
in server-to-client packets because the host needs weapon state broadcast like any
other player.

### 3. CollisionEffect (0x15) is C→S only

The server never relays CollisionEffect packets. All 84 instances in the battle trace
flow client-to-server. The server processes them locally and distributes damage results
via PythonEvent (0x06).

### 4. Ship death = Explosion (0x29) + ObjCreateTeam (0x03)

Zero DestroyObject (0x14) packets across 59 ship deaths. The death sequence is:
1. Server sends Explosion (0x29) to all clients
2. Server sends ObjCreateTeam (0x03) for respawn

### 5. SCORE_CHANGE (0x36) absent in weapon combat

| Trace | Kill Type | SCORE_CHANGE Count |
|-------|-----------|-------------------|
| Collision test | Collision kill | 1 |
| Battle trace | Weapon kills (59) | 0 |

Collision kills correctly produce SCORE_CHANGE. Weapon kills do not. This may be
a stock BC dedicated server bug.

### 6. PythonEvent factory 0x0000010C = TGObjPtrEvent (RESOLVED)

1,718 of 3,825 PythonEvents (45%) in the battle trace use factory 0x010C (TGObjPtrEvent).
This is a fourth TGEvent subclass carrying an int32 TGObject network ID at +0x28.
High volume is explained by weapon events: ET_WEAPON_FIRED (0x7C),
ET_PHASER_STOPPED_FIRING (0x83), ET_TRACTOR_BEAM_STOPPED_FIRING (0x7F).
See [tgobjptrevent-class.md](tgobjptrevent-class.md) for full analysis.

### 7. Weapon relay ratio exactly (N-1):1

TorpedoFire (0x19) in the 3-player battle trace:
- Sent by server: 1,794 packets
- Received by server: 897 packets
- Ratio: exactly 2:1 (3 players - 1 = 2)

Server receives from 1 peer, relays to all other N-1 peers. No filtering or dedup.

### 8. Checksum+Settings+GameInit bundled in single UDP datagram

After checksums pass, the server bundles three messages in one datagram:
- 0x28 (ChecksumComplete)
- 0x00 (Settings)
- 0x01 (GameInit)

This appears intentional for join reliability.

### 9. NewPlayerInGame (0x2A) direction is C→S

The client sends 0x2A to the server after ship selection. Previous documentation
listed direction as S→C. Our implementation sends both C→S and S→C from
GameLoopTimerProc — the S→C send may be unnecessary.

### 10. Collision chain produces 12-14 PythonEvents

Confirmed from trace analysis:
- 1 ET_WEAPON_HIT or equivalent
- 11 ET_SUBSYSTEM_DAMAGED repair-list additions
- 2 delayed events
Total: 12-14 per collision, matching prior decompilation analysis.

## Opcode Frequency Tables

### Battle of Valentine's Day — Top 15 Opcodes

| Opcode | Name | Sent | Received | Total | % |
|--------|------|------|----------|-------|---|
| 0x1C | StateUpdate | 113,802 | 24,918 | 138,720 | — |
| 0x06 | PythonEvent | 3,432 | — | 3,432 | — |
| 0x19 | TorpedoFire | 1,794 | 897 | 2,691 | — |
| 0x07 | StartFiring | 1,522 | 761 | 2,283 | — |
| 0x0D | PythonEvent2 | — | 393 | 393 | — |
| 0x08 | StopFiring | 254 | 127 | 381 | — |
| 0x15 | CollisionEffect | — | 84 | 84 | — |
| 0x29 | Explosion | 59 | — | 59 | — |
| 0x03 | ObjCreateTeam | 62 | — | 62 | — |
| 0x0A | SubsysStatus | varies | varies | — | — |
| 0x37 | SCORE_MESSAGE | varies | — | — | — |
| 0x35 | MISSION_INIT | varies | — | — | — |
| 0x2A | NewPlayerInGame | — | varies | — | — |
| 0x14 | DestroyObject | 0 | 0 | 0 | — |
| 0x36 | SCORE_CHANGE | 0 | 0 | 0 | — |

### Collision Test — All Opcodes

| Opcode | Name | Count |
|--------|------|-------|
| 0x1C | StateUpdate | ~400 |
| 0x15 | CollisionEffect | 6 |
| 0x06 | PythonEvent | 14 |
| 0x29 | Explosion | 1 |
| 0x03 | ObjCreateTeam | 3 |
| 0x36 | SCORE_CHANGE | 1 |
| 0x14 | DestroyObject | 0 |

## Doc Corrections Applied

| Finding | Affected Docs |
|---------|--------------|
| 0x35 player count | CLAUDE.md (removed known issue), wire-format-spec.md |
| SUB/WPN ~96% | (OpenBC stateupdate-wire-format.md) |
| 0x15 C→S only | wire-format-spec.md, collision-effect-protocol.md |
| Ship death lifecycle | NEW: ship-death-lifecycle.md |
| SCORE_CHANGE absence | ship-death-lifecycle.md, (OpenBC gamemode-system.md) |
| 0x010C = TGObjPtrEvent (RESOLVED) | pythonevent-wire-format.md, tgobjptrevent-class.md |
| 0x2A direction C→S | wire-format-spec.md |
| Collision chain count | pythonevent-wire-format.md |

## Related Documents

- [wire-format-spec.md](wire-format-spec.md) — Complete wire format reference
- [ship-death-lifecycle.md](ship-death-lifecycle.md) — Ship death/respawn sequence
- [collision-effect-protocol.md](collision-effect-protocol.md) — CollisionEffect (0x15) protocol
- [pythonevent-wire-format.md](pythonevent-wire-format.md) — PythonEvent (0x06) wire format
- [message-trace-vs-packet-trace.md](message-trace-vs-packet-trace.md) — Earlier stock-dedi cross-reference
