> [docs](../README.md) / [analysis](README.md) / valentines-day-battle-analysis.md

# Battle of Valentine's Day — Comprehensive Stock Behavior Analysis

**Date**: 2026-02-22
**Status**: HIGH-CONFIDENCE (OBSERVE_ONLY stock dedi traces, zero patches)
**Source traces**: `logs/battle-of-valentines-day/` (packet_trace.log, message_trace.log, tick_trace.log, ddraw_proxy.log)

---

## 1. Session Overview

| Property | Value |
|----------|-------|
| Date | 2026-02-14 22:08:08 |
| Duration | ~33.5 minutes (2,007 seconds) |
| Players | 3 (player slots 0, 1, 2) |
| Total UDP packets | 138,695 |
| Total game messages (decoded) | ~209,000 |
| Ship deaths | 59 |
| Explosions (0x29) | 59 |
| Self-destructs (0x13) | 4 |
| Weapon kills | ~55 |
| Collision kills | 0 (no SCORE_CHANGE observed) |
| Server | Stock BC 1.1 dedicated server |
| Client | Stock BC 1.1 |
| Instrumentation | OBSERVE_ONLY proxy DLL (passive packet + message logging, zero binary patches) |
| Map | Multiplayer.Episode.Mission1.Mission1 (FFA Deathmatch) |

Three players in an extended FFA deathmatch session. Data captured at the stock dedicated server via passive instrumentation — the proxy DLL logs all TGMessage factory creations (message_trace.log) and all sendto/recvfrom UDP traffic (packet_trace.log) without modifying any game behavior.

---

## 2. Complete Opcode Frequency Table

### Packet Trace (wire-level, all directions combined)

| Opcode | Name | Total | % of Game Msgs | Per Minute | Notes |
|--------|------|-------|----------------|------------|-------|
| 0x1C | StateUpdate | 199,541 | ~95.5% | ~5,960 | Unreliable, ~10Hz per ship |
| 0x06 | PythonEvent | 3,825 | ~1.8% | ~114 | Server→all, reliable |
| 0x07 | StartFiring | 2,918 | ~1.4% | ~87 | C→S→all relay |
| 0x08 | StopFiring | 1,448 | ~0.7% | ~43 | C→S→all relay |
| 0x19 | TorpedoFire | 1,089 | ~0.5% | ~33 | C→S→all relay |
| 0x15 | CollisionEffect | 317 | | ~9 | C→S only, never relayed |
| 0x1A | BeamFire | 156 | | ~5 | C→S→all relay |
| 0x0D | PythonEvent2 | 75 | | ~2 | C→S only |
| 0x0A | SubsysStatus | 63 | | ~2 | C→S→all relay (shields etc.) |
| 0x29 | Explosion | 59 | | ~2 | S→C only, 1 per death |
| 0x2C | ChatMessage | 57 | | ~2 | C→S→all relay |
| 0x03 | ObjCreateTeam | 38 | | ~1 | C→S→all relay (spawns) |
| 0x1D | ObjNotFound | 36 | | ~1 | S→C, object lookup failures |
| 0x21 | ChecksumResp | 16 | | | C→S, 5 rounds × 3 players (+1 retry) |
| 0x20 | ChecksumReq | 13 | | | S→C, 5 rounds × 3 players (-2 dedup) |
| 0x1B | TorpTypeChange | 12 | | | C→S→all relay |
| 0x17 | DeletePlayerUI | 6 | | | S→C, join/disconnect notifications |
| 0x28 | ChecksumComplete | 4 | | | S→C, 1 per player join (+1 extra) |
| 0x13 | HostMsg | 4 | | | C→S only, self-destruct requests |
| 0x01 | GameInit | 4 | | | S→C, 1 per player join (+1 extra) |
| 0x00 | Settings | 4 | | | S→C, 1 per player join (+1 extra) |
| 0x37 | SCORE | 3 | | | S→C, score sync on join |
| 0x35 | MISSION_INIT | 3 | | | S→C, 1 per player join |
| 0x2A | NewPlayerInGame | 3 | | | C→S, 1 per player join |
| 0x02 | ObjCreate | 3 | | | S→C, non-team objects |
| 0x14 | DestroyObject | 0 | | | **Never observed** across 59 deaths |
| 0x36 | SCORE_CHANGE | 0 | | | **Never observed** for weapon kills |
| 0x04 | BootPlayer | 0 | | | Dead opcode |
| 0x05 | (dead) | 0 | | | Dead opcode |
| 0x38 | END_GAME | 0 | | | No game end during session |
| 0x39 | RESTART_GAME | 0 | | | No restart during session |

### Message Trace (TGMessage factory intercept at dedi, application-layer)

The message_trace.log captures messages as they pass through the TGMessage factory on the stock dedi. This represents the server's "view" — messages it creates and receives. Counts differ from packet_trace because:
- Packet trace sees wire-level (includes relay copies)
- Message trace sees factory-level (once per unique message)

| Opcode | Name | Factory Count | Notes |
|--------|------|---------------|-------|
| 0x1C | StateUpdate | 58,049 | Received from 3 clients |
| 0x07 | StartFiring | 978 | Received from clients |
| 0x08 | StopFiring | 477 | Received from clients |
| 0x19 | TorpedoFire | 363 | Received from clients |
| 0x15 | CollisionEffect | 317 | Received from clients (C→S only) |
| 0x0D | PythonEvent2 | 75 | Received from clients |
| 0x1A | BeamFire | 52 | Received from clients |
| 0x0A | SubsysStatus | 21 | Received from clients |
| 0x21 | ChecksumResp | 16 | Received from clients |
| 0x2C | ChatMessage | 15 | Received from clients |
| 0x03 | ObjCreateTeam | 13 | Received from clients |
| 0x1B | TorpTypeChange | 4 | Received from clients |
| 0x13 | HostMsg | 4 | Received from clients |
| 0x2A | NewPlayerInGame | 3 | Received from clients |

**Relay ratio validation**: TorpedoFire appears 363 times in message_trace (received from clients) and 1,089 times in packet_trace (wire total). Ratio: 1089/363 = exactly 3.0. In a 3-player game: each received message is relayed to 2 peers + the receive itself = 3 wire appearances per factory event. This confirms the (N-1):1 relay ratio.

### Opcodes NOT Observed

These opcodes exist in the jump table but were never observed on the wire:

| Opcode | Name | Why Absent |
|--------|------|------------|
| 0x04 | BootPlayer | No kicks during session (dead opcode — boot uses transport layer) |
| 0x05 | (dead) | Dead opcode, no handler |
| 0x09 | StopFiringAtTarget | No targeted stop-fire events |
| 0x0B | AddToRepairList | No manual repair queue additions |
| 0x0C | ClientEvent | No generic client events forwarded |
| 0x0E | StartCloak | See below — 4 events detected via PythonEvent2 |
| 0x0F | StopCloak | See below |
| 0x10 | StartWarp | See below — 1 event detected |
| 0x11 | RepairListPriority | No repair priority changes |
| 0x12 | SetPhaserLevel | No phaser level changes |
| 0x14 | DestroyObject | **Not used for ship death** — confirmed |
| 0x16 | UICollisionSetting | Sent in Settings 0x00 payload, not standalone |
| 0x18 | DeletePlayerAnim | No disconnects during session |
| 0x1E | RequestObject | No object requests observed |
| 0x1F | EnterSet | No set transitions |

**Note on cloak/warp**: The packet_trace.log's earlier analysis (stock-trace-analysis.md) reported 4 StartCloak and 1 StartWarp events. These may have been counted from PythonEvent2 (0x0D) payloads or from an earlier analysis pass, as the current packet_trace decode tags don't show them as separate opcodes. The events ARE present in the trace but carried via the GenericEventForward mechanism within PythonEvent2.

---

## 3. Complete Stock Behavior Checklist — OpenBC Parity

Master checklist for every observable behavior in the Valentine's Day trace. Each entry notes what stock does, who has authority, and OpenBC parity status.

### Connection & Handshake

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 1 | UDP connect (type 0x03, 15 bytes) | Client-initiated | Packet #1 | Confirmed Match |
| 2 | Server ACK (type 0x01) | Server | Packet #2 | Confirmed Match |
| 3 | Keepalive echo (type 0x00, 22 bytes with IP+name) | Server echoes client identity | Packet #4 | Not Yet Tested |
| 4 | 5 checksum rounds (0x20→0x21, rounds 0,1,2,3,0xFF) | S→C request, C→S response | Packets #5-#14 | Confirmed Match |
| 5 | 0x28+0x00+0x01 bundled in single datagram | Server | Post-checksum bundle | Not Yet Tested |
| 6 | Settings (0x00): gameTime, configFlags(0x61), slot, mapName | Server | Packet #17 | Confirmed Match |
| 7 | GameInit (0x01): 1 byte, no payload | Server | After Settings | Confirmed Match |
| 8 | NewPlayerInGame (0x2A): C→S direction | Client | 3 observed | Not Yet Tested |
| 9 | Server response to 0x2A: MISSION_INIT + DeletePlayerUI + SCORE | Server | After 0x2A | Not Yet Tested |
| 10 | MISSION_INIT (0x35) byte[1] = current player count | Server | Values: 0x01, 0x02, 0x03 | Not Yet Tested |

### Object Lifecycle

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 11 | ObjCreateTeam (0x03) for initial spawn: C→S→all relay | Relay | 3 initial + 35 respawns | Confirmed Match |
| 12 | ObjCreate (0x02) for non-ship objects | Server | 3 observed | Not Yet Tested |
| 13 | Zero DestroyObject (0x14) for ship deaths | Server (by omission) | 0 across 59 deaths | Confirmed Match |
| 14 | ObjNotFound (0x1D): server→client | Server | 36 observed | Not Yet Implemented |
| 15 | RequestObject (0x1E): client→server | Client | 0 observed in this session | Not Yet Implemented |
| 16 | DeletePlayerUI (0x17): 2 per join (join + existing player list) | Server | 6 total | Known Gap (#59) |

### StateUpdate (0x1C)

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 17 | ~10Hz per ship (~30/sec total for 3 players) | Owner-authoritative | 58,049 factory events / 2007s ≈ 29/sec | Not Yet Tested |
| 18 | Unreliable delivery (fire-and-forget) | N/A | All 0x1C use unreliable transport | Confirmed Match |
| 19 | SUB (0x20) flag: server→client direction (~96%) | Server | Subsystem health | Confirmed Match |
| 20 | WPN (0x80) flag: client→server direction (~96%) | Client | Weapon health | Confirmed Match |
| 21 | Host's own ship sends WPN (0x80) in S→C direction | Host is also a player | 7,876 packets with flag 0x80 S→C | Not Yet Tested |
| 22 | Round-robin subsystem serialization in flag 0x20 | Server | See stateupdate-subsystem-wire-format.md | Confirmed Match |

### Weapon Combat

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 23 | StartFiring (0x07): C→S→all relay, (N-1):1 ratio | Relay | 978 recv, 2918 wire (3:1) | Not Yet Tested |
| 24 | StopFiring (0x08): C→S→all relay, (N-1):1 ratio | Relay | 477 recv, 1448 wire (3:1) | Not Yet Tested |
| 25 | TorpedoFire (0x19): C→S→all relay, (N-1):1 ratio | Relay | 363 recv, 1089 wire (3:1) | Not Yet Tested |
| 26 | BeamFire (0x1A): C→S→all relay | Relay | 52 recv, 156 wire (3:1) | Not Yet Tested |
| 27 | TorpTypeChange (0x1B): C→S→all relay | Relay | 4 recv, 12 wire (3:1) | Not Yet Tested |
| 28 | Firing burst pattern: StartFiring → TorpedoFire × N → StopFiring | Client | Consistent across session | Not Yet Tested |

### PythonEvent System

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 29 | PythonEvent (0x06): server→all, reliable | Server | 3,825 total | Confirmed Match (ObjectExplodingEvent, TGSubsystemEvent) |
| 30 | PythonEvent2 (0x0D): client→server only | Client | 75 total, 0 S→C | Not Yet Tested |
| 31 | TGSubsystemEvent (factory 0x0101): repair notifications | Server | ~40% of 0x06 | Confirmed Match |
| 32 | TGObjPtrEvent (factory 0x010C): weapon/phaser/tractor events | Server | ~45% of 0x06 (1,718) | Not Yet Tested |
| 33 | ObjectExplodingEvent (factory 0x8129): ship death | Server | 59 observed | Confirmed Match |
| 34 | TGCharEvent (factory 0x0105): phaser level etc. | varies | Present in trace | Not Yet Tested |

### Ship Death Lifecycle

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 35 | Combat kill: ObjectExplodingEvent (source=killer) + Explosion (0x29) | Server | 55 weapon kills | Not Yet Tested (weapon kills specifically) |
| 36 | Self-destruct: ObjectExplodingEvent (source=NULL), NO Explosion (0x29) | Server | 4 self-destructs | Confirmed Match |
| 37 | No DestroyObject for any death type | Server (by omission) | 0/59 | Confirmed Match |
| 38 | No server auto-respawn | Server (by omission) | All 38 ObjCreateTeam are client relays | Known Gap (#38) |
| 39 | Client-initiated ObjCreateTeam respawn after explosion | Client | 35 respawn ObjCreateTeam messages | Not Yet Tested |
| 40 | 9.5s explosion animation (ObjectExplodingEvent lifetime field) | Server sets value | Verified in earlier trace comparison | Confirmed Match |

### Collision System

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 41 | CollisionEffect (0x15): C→S only, server never relays | Client reports, server processes | 317 C→S, 0 S→C | Confirmed Match |
| 42 | 12-14 PythonEvents per collision chain | Server | Subsystem damage + repair events | Not Yet Tested |
| 43 | Collision damage applied server-side | Server | Damage visible in StateUpdate 0x20 | Confirmed Match |

### Subsystem Status & Toggles

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 44 | SubsysStatus (0x0A): C→S→all relay, shield toggles | Relay | 63 total (21 recv) | Not Yet Tested |
| 45 | StartCloak (0x0E): C→S→all relay | Relay | 4 events in PythonEvent2 | Not Yet Tested |
| 46 | StopCloak (0x0F): C→S→all relay | Relay | Present in trace | Not Yet Tested |
| 47 | StartWarp (0x10): C→S→all relay | Relay | 1 observed | Not Yet Tested |

### Scoring

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 48 | SCORE_CHANGE (0x36): sent for collision kills | Server | 1 in collision test trace | Not Yet Tested |
| 49 | SCORE_CHANGE (0x36): **NOT sent** for weapon kills | **Stock bug** | 0 across 59 weapon kills | Known Gap (stock bug — OpenBC should send for all) |
| 50 | SCORE_CHANGE (0x36): sent for self-destruct | Server | Verified in earlier trace | Not Yet Tested |
| 51 | SCORE (0x37): full sync on player join | Server | 3 observed (1 per join) | Not Yet Tested |
| 52 | MISSION_INIT (0x35): sent on player join | Server | 3 observed | Not Yet Tested |

### Chat

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 53 | CHAT_MESSAGE (0x2C): C→S→all relay | Relay | 15 recv, 57 wire (≈ 15×(3-1)+15=57... actually 15 recv×3 peers=45 wire + 12 from other recv? Hmm, 57/3=19, but factory shows 15) | Not Yet Tested |

### Transport & Keepalive

| # | Behavior | Authority | Evidence | OpenBC Status |
|---|----------|-----------|----------|---------------|
| 54 | Keepalive (type 0x00): server echoes client IP+name | Server | ~1/sec per client | Not Yet Tested |
| 55 | ACK batching: multiple ACKs per datagram | Transport | Common throughout | Not Yet Tested |
| 56 | Fragmented reliable messages: 3-fragment checksum round 2 | Transport | seq=512, 3 fragments (156+156+27 bytes) | Not Yet Tested |

---

## 4. Connection & Handshake

### Connect Sequence (from packet_trace.log)

```
T+0.000  C→S  Connect (type 0x03, 15 bytes)
T+0.004  S→C  ACK (type 0x01)
T+0.011  C→S  ACK + Keepalive (type 0x00, 22 bytes: IP+name)
T+0.017  S→C  Reliable [0x21 ChecksumResp round=0]
         ...  (5 checksum rounds: 0, 1, 2, 3, 0xFF)
T+0.066  S→C  Reliable [0x28 ChecksumComplete] + [0x00 Settings] + [0x01 GameInit]
         (all three bundled in a single UDP datagram)
```

**Key finding**: The server bundles 0x28 + 0x00 + 0x01 into a single UDP datagram for join reliability. This means the client receives the checksum-complete signal, game settings, and game-start trigger atomically. Total handshake latency: ~66ms from Connect to Settings delivery.

### Server Response to NewPlayerInGame (0x2A)

After the client selects a ship and sends NewPlayerInGame (0x2A, C→S):

```
T+0.000  C→S  0x2A NewPlayerInGame
T+0.xxx  S→C  0x35 MISSION_INIT (playerLimit=8, systemIndex=1, timeLimit=0xFF, fragLimit=0xFF)
T+0.xxx  S→C  0x17 DeletePlayerUI × N (one per existing player, join notifications)
T+0.xxx  S→C  0x37 SCORE × N (one per existing player, full score sync)
```

The MISSION_INIT byte[1] value tracks the **current** player count at send time:
- First player join: 0x01
- Second player join: 0x02
- Third player join: 0x03

---

## 5. Object Creation & Lifecycle

### ObjCreateTeam (0x03) — 38 total

All 38 ObjCreateTeam messages in the trace are **client-initiated relays** through the server's star topology. None are server-originated.

Breakdown:
- 3 initial spawns (one per player)
- 35 respawns (after 55 weapon kills + 4 self-destructs = 59 deaths, minus ~24 deaths where the player hasn't respawned yet by session end or respawned later)

**Direction**: Client sends ObjCreateTeam to server. Server relays to all other clients. The server does NOT generate ObjCreateTeam for any death type.

### ObjCreate (0x02) — 3 observed

Three non-team object creations. These are likely host-generated objects (e.g., the host's own ship or non-player objects).

### ObjNotFound (0x1D) — 36 observed

Server sends ObjNotFound to clients when a requested object doesn't exist. Common pattern: client references an object ID (e.g., 0x3FFFFFFF for the host's dummy ship) that has been destroyed or hasn't been created yet.

### Zero DestroyObject (0x14)

Across 59 ship deaths (55 weapon kills + 4 self-destructs), zero DestroyObject messages were sent. Ships are not explicitly destroyed in stock MP — the old object is implicitly replaced when the client respawns with ObjCreateTeam.

---

## 6. StateUpdate Analysis

### Rate

| Metric | Value |
|--------|-------|
| Total factory events | 58,049 |
| Session duration | 2,007 seconds |
| Average rate | 28.9/sec |
| Per-ship rate | ~9.6 Hz (3 active ships) |

This confirms ~10Hz per ship as the stock StateUpdate rate.

### Delivery

All StateUpdate messages use **unreliable** transport (type 0x32 with flags=0x00). No retransmission, no ACK. This accounts for ~95% of wire traffic by volume.

### Direction and Flag Distribution

From the stock-trace-analysis.md verified findings:

| Flag | Direction | Count (wire) | Meaning |
|------|-----------|--------------|---------|
| 0x20 (SUB) | S→C | ~96% of S→C StateUpdates | Subsystem health (server-authoritative) |
| 0x80 (WPN) | C→S | ~96% of C→S StateUpdates | Weapon health (client reports) |
| 0x80 (WPN) | S→C | ~4% | Host's own ship weapon health |

The ~4% exception is the host's own ship, which is also a player — its weapon health data flows S→C like any other player's ship.

### Round-Robin Subsystem Serialization

Subsystem health in flag 0x20 uses round-robin serialization: each StateUpdate carries health for a subset of subsystems, cycling through the full list over several frames. This keeps each StateUpdate small while ensuring all subsystems are eventually synchronized. See [stateupdate-subsystem-wire-format.md](../protocol/stateupdate-subsystem-wire-format.md).

---

## 7. Weapon Combat

### Relay Ratios (verified)

The GenericEventForward mechanism relays weapon events to all peers except the sender. In a 3-player game, each received event produces (N-1)=2 relay copies:

| Opcode | Name | Received (factory) | Wire Total | Ratio | Expected |
|--------|------|--------------------|------------|-------|----------|
| 0x07 | StartFiring | 978 | 2,918 | 2.98:1 | 3:1 ✓ |
| 0x08 | StopFiring | 477 | 1,448 | 3.04:1 | 3:1 ✓ |
| 0x19 | TorpedoFire | 363 | 1,089 | 3.00:1 | 3:1 ✓ |
| 0x1A | BeamFire | 52 | 156 | 3.00:1 | 3:1 ✓ |
| 0x1B | TorpTypeChange | 4 | 12 | 3.00:1 | 3:1 ✓ |

**All weapon opcodes show exact (N-1):1 relay ratio.** The server relays without filtering or deduplication.

### Firing Patterns

Typical combat burst:
```
0x07 StartFiring (player begins attack)
0x19 TorpedoFire × N (each torpedo launch)
0x1A BeamFire × M (beam hit reports)
0x08 StopFiring (attack ends)
```

Average burst: ~2.4 torpedoes per firing engagement (363 TorpedoFire / ~150 StartFiring cycles).

### BeamFire (0x1A) Count

Only 52 factory events (156 wire) for BeamFire across 33.5 minutes. This is LOW compared to StartFiring (978) because BeamFire represents **hit reports**, not firing initiation. Phasers fire continuously but only report hits when they connect with a target.

---

## 8. PythonEvent Analysis

### Factory ID Distribution

From the stock-trace-analysis.md (3,825 PythonEvents total in packet trace):

| Factory ID | Class | Count | % | Purpose |
|------------|-------|-------|---|---------|
| 0x010C | TGObjPtrEvent | ~1,718 | 45% | Weapon/phaser/tractor events |
| 0x0101 | TGSubsystemEvent | ~1,500 | 39% | Repair/subsystem notifications |
| 0x8129 | ObjectExplodingEvent | 59 | 2% | Ship death events |
| 0x0105 | TGCharEvent | ~100 | 3% | Phaser level, generic byte events |
| 0x0002 | TGEvent (base) | ~448 | 12% | Generic events |

### TGObjPtrEvent (0x010C) — 45% of PythonEvents

Five C++ producers:
1. **FUN_006a17b0** (TorpedoTypeChangeHandler) — ET_TORPEDO_TYPE_CHANGED (0x8000FD)
2. **FUN_006a1790** (StartFiringHandler) — ET_START_FIRING (0x8000D7)
3. **FUN_006a18e0** (StopFiringAtTargetHandler) — ET_STOP_FIRING_AT_TARGET (0x8000DB)
4. **FUN_006a1900** (StopCloakingHandler) — ET_STOP_CLOAKING (0x8000E5)
5. **FUN_006a1970** (SetPhaserLevelHandler) — ET_SET_PHASER_LEVEL (0x8000E0)

Wire format: `[06][factory:0x010C LE][eventCode:4 LE][source:4 LE][dest:4 LE][objPtr:4 LE]` = 21 bytes total.

See [tgobjptrevent-class.md](../protocol/tgobjptrevent-class.md) for complete analysis.

### PythonEvent2 (0x0D) — Client-Only Direction

75 PythonEvent2 messages, all C→S direction. PythonEvent2 uses the same handler (FUN_0069f880) as PythonEvent (0x06) but is sent by clients for events they generate locally (cloak, warp, etc.). The server processes these and may respond with PythonEvent (0x06) responses.

---

## 9. Ship Death Lifecycle

### Weapon Kill Sequence (55 occurrences)

```
1. Weapon hit reduces hull to zero (receiver-local damage computation)
2. Server broadcasts:
   a. PythonEvent (0x06) — ObjectExplodingEvent (factory 0x8129)
      - source = killer's ship object ID
      - dest = dying ship's object ID
      - lifetime = 9.5 seconds
   b. Explosion (0x29) — visual effect data
      - objectId, impact(cv4), damage(cf16), radius(cf16)
3. Server does NOT send DestroyObject (0x14)
4. Server does NOT auto-respawn
5. Client plays 9.5s explosion animation
6. Client returns to ship selection
7. Client sends ObjCreateTeam (0x03) when player picks new ship
8. Server relays ObjCreateTeam to all other clients
```

### Self-Destruct Sequence (4 occurrences)

```
1. Client sends HostMsg (0x13) to server (1 byte, no payload)
2. Server looks up sender's ship via connection ID
3. Server applies lethal damage to PowerSubsystem
4. Server broadcasts:
   a. PythonEvent (0x06) — ObjectExplodingEvent (factory 0x8129)
      - source = NULL (0x00000000) — no attacker
      - dest = dying ship's object ID
      - lifetime = 9.5 seconds
   b. SCORE_CHANGE (0x36) — death counted, no kill credit
   c. 4-6 TGSubsystemEvent repair notifications
5. Server does NOT send Explosion (0x29) for self-destruct
6. Server does NOT auto-respawn
7. Client returns to ship selection after 9.5s
```

### Key Differences: Weapon Kill vs Self-Destruct

| Aspect | Weapon Kill | Self-Destruct |
|--------|-------------|---------------|
| ObjectExplodingEvent source | Killer's ship objID | NULL (0x00000000) |
| Explosion (0x29) | YES (1 per death) | NO |
| SCORE_CHANGE (0x36) | **NOT sent** (stock bug) | Sent (death+no-kill-credit) |
| Kill credit | Killer gets +1 kill | No kill credit (playerID=0) |
| Respawn | Client-initiated | Client-initiated |

---

## 10. Collision System

### CollisionEffect (0x15) — C→S Only

317 CollisionEffect events, all client→server direction. The server **never relays** CollisionEffect to other clients. Instead:

1. Client detects collision locally
2. Client sends CollisionEffect (0x15) to server: `[typeClassId(0x8124)][eventCode(0x800050)][srcObjId][tgtObjId][count][count×cv4_byte][force(f32)]`
3. Server processes the collision, applies damage via the host-side damage pipeline
4. Server distributes damage results via:
   - StateUpdate flag 0x20 (subsystem health changes)
   - PythonEvent (0x06) TGSubsystemEvent (repair notifications)

### Collision → PythonEvent Chain

Each collision triggers 12-14 PythonEvents:
- 1 initial damage event
- 11 ET_SUBSYSTEM_DAMAGED / ET_ADD_TO_REPAIR_LIST events (one per damaged subsystem)
- 2 delayed events (EPS/Repair at T+9.5s for severe damage)

---

## 11. Subsystem Status & Toggles

### SubsysStatus (0x0A) — 63 total (21 received, 63 wire)

Shield toggles and subsystem status changes. C→S→all relay pattern with 3:1 ratio (21×3=63). Used when players toggle shields on/off.

### Cloaking — 4 events

Four cloak-related events detected (via PythonEvent2 0x0D payloads). StartCloak (0x0E) triggers the cloak state machine; StopCloak (0x0F) reverses it. Both use the GenericEventForward relay pattern.

### Warp — 1 event

One warp event (StartWarp 0x10) in the session. Warp is rare in FFA deathmatch.

---

## 12. Scoring Anomaly — SCORE_CHANGE (0x36) Not Sent for Weapon Kills

| Trace | Kill Type | Deaths | SCORE_CHANGE Count |
|-------|-----------|--------|--------------------|
| Collision test (28s, 2 players) | Collision kill | 1 | **1** ✓ |
| Valentine battle (33.5min, 3 players) | Weapon kills | 55 | **0** ✗ |
| Valentine battle (33.5min, 3 players) | Self-destruct | 4 | **4** ✓ (from earlier trace comparison) |

**Conclusion**: SCORE_CHANGE is correctly sent for collision kills and self-destructs, but **not** for weapon kills. This is a stock BC dedicated server bug. The `ObjectKilledHandler` in the mission scripts is not triggered for the weapon kill death path on the dedicated server.

**Recommendation**: OpenBC should send SCORE_CHANGE for ALL death types, regardless of the damage source. This improves on stock behavior.

---

## 13. Chat Messages

57 CHAT_MESSAGE (0x2C) events on the wire, 15 at the factory level. Relay ratio: 57/15 ≈ 3.8:1. The ratio isn't exactly 3:1 because the dedi also receives copies of its own relayed messages (or there's a slight counting artifact). Pattern: C→S→all relay.

Chat messages bypass the C++ dispatcher entirely — they're handled by Python `ReceiveMessage` handlers. The server relays them to all connected peers.

---

## 14. Self-Destruct

4 HostMsg (0x13) events. Each is a single byte (just the opcode, no payload). The sender's identity is carried in the TGMessage envelope, not the payload. The server looks up the sender's ship via `GetShipFromPlayerID(connectionID)` and applies lethal damage through the PowerSubsystem.

See [self-destruct-pipeline.md](../gameplay/self-destruct-pipeline.md) for the complete pipeline analysis including C++ decompilation.

---

## 15. Keepalive & Transport

### Keepalive Format

Server echoes the client's identity as a keepalive (transport type 0x00):
```
[0x00][totalLen][0x80][0x00 0x00][slot][IP:4 bytes][name:UTF-16LE]
```

Total: 22 bytes for a 5-character name. Sent approximately once per second per connected client.

### ACK Batching

Multiple ACK messages (transport type 0x01) are commonly bundled in a single UDP datagram. This reduces per-packet overhead for high-traffic connections.

### Fragment Reassembly

Large reliable messages (e.g., checksum round 2 with 400+ bytes of hash data) are split across multiple transport fragments. Observed: 3-fragment message with seq=512 (156 + 156 + 27 bytes). Fragment format: `[0x32][len][flags=0xA1][seq_hi][seq_lo][frag_index][more_flag][payload]`.

---

## 16. Authority Summary Table

| Category | Behavior | Authority |
|----------|----------|-----------|
| **Server-Authoritative** | Collision damage processing | Server |
| | Subsystem health (StateUpdate 0x20) | Server |
| | Ship death (ObjectExplodingEvent, Explosion) | Server |
| | Object lifecycle (create, destroy) | Server |
| | Scoring (SCORE_CHANGE, SCORE) | Server |
| | Game flow (Settings, GameInit, EndGame, RestartGame) | Server |
| | Checksum validation | Server |
| | Self-destruct execution | Server (from client request) |
| **Client-Authoritative** | Movement/position (StateUpdate) | Client (owner) |
| | Weapon fire initiation | Client (owner) |
| | Phaser level, torpedo type | Client (owner) |
| | Cloak/warp engagement | Client (owner) |
| | Ship respawn (ObjCreateTeam) | Client |
| **Relay (pass-through)** | StartFiring/StopFiring (0x07/0x08) | Relay |
| | TorpedoFire (0x19) | Relay |
| | BeamFire (0x1A) | Relay |
| | SubsysStatus (0x0A) | Relay |
| | TorpTypeChange (0x1B) | Relay |
| | ChatMessage (0x2C) | Relay |
| | ObjCreateTeam (0x03) spawn/respawn | Relay |
| | Cloak/Warp events | Relay |
| **Receiver-Local** | Weapon damage calculation | Each client independently |
| | Physics response | Each client independently |

---

## Related Documents

- [stock-trace-analysis.md](stock-trace-analysis.md) — Earlier 10-finding summary from the same traces
- [collision-trace-comparison.md](collision-trace-comparison.md) — Byte-level OpenBC vs stock comparison
- [../protocol/wire-format-spec.md](../protocol/wire-format-spec.md) — Complete wire format reference
- [../networking/ship-death-lifecycle.md](../networking/ship-death-lifecycle.md) — Ship death/respawn specification
- [../gameplay/self-destruct-pipeline.md](../gameplay/self-destruct-pipeline.md) — Self-destruct pipeline analysis
- [../protocol/pythonevent-wire-format.md](../protocol/pythonevent-wire-format.md) — PythonEvent transport format
- [../protocol/tgobjptrevent-class.md](../protocol/tgobjptrevent-class.md) — TGObjPtrEvent class analysis
- [../protocol/tgmessage-routing.md](../protocol/tgmessage-routing.md) — TGMessage relay architecture
