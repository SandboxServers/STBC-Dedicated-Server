> [docs](../README.md) / [analysis](README.md) / collision-trace-comparison.md

# Collision Test Trace Comparison — Stock Dedi vs OpenBC

**Date**: 2026-02-22
**Status**: HIGH-CONFIDENCE (stock trace = OBSERVE_ONLY, OpenBC trace = live server + packet capture)
**Test scenario**: Client connects, spawns Sovereign, collides with environment until death, respawns, collides again

---

## Overview

Side-by-side comparison of packet traces from two servers running the same collision test
scenario. Identifies byte-level wire format matches and behavioral gaps.

**Bottom line**: Wire format encoding is correct (ObjCreateTeam, CollisionEffect, Score,
StateUpdate structure, and transport layer are all byte-for-byte identical). The gaps are
behavioral: post-respawn ownership tracking, subsystem object ID allocation, missing
DeletePlayerUI at join, spurious Explosion on collision kills, and insufficient
SubsystemDamage events.

---

## Test Sessions

### Stock Dedicated Server (2026-02-19)

| Property | Value |
|----------|-------|
| Duration | ~28s active (86s total) |
| Players | 2 (dedi host + 1 client) |
| Ship | Sovereign (Cady2) |
| Map | Multiplayer.Episode.Mission1.Mission1 |
| Ship deaths | 1 (collision kill at t=33.40) |
| Client IP | 10.10.10.239 |
| Game time range | t=25.59 to t=46.20 |

### OpenBC Server (2026-02-22)

| Property | Value |
|----------|-------|
| Duration | ~113s active (187s total) |
| Players | 2 (OpenBC host + 1 client) |
| Ship | Sovereign (Cady2) |
| Map | Multiplayer.Episode.Mission1.Mission1 |
| Ship deaths | 1 (collision kill at t=~51.5, respawn at t=64.13) |
| Client IP | 127.0.0.1 (localhost) |
| Game time range | t=18.30 to t=112.75 |

---

## Session Timelines

### Stock Dedi Join → Death → End

```
#2   ConnectAck (0x03)
#3-5 ChecksumReq (0x20) rounds 0-2
#15  ChecksumReq (0x20) round 3
#19  ChecksumReq (0x20) round 255
#20  ChecksumComplete (0x28)
#21  Settings (0x00) gameTime=21.58
#22  GameInit (0x01)
#33  GameState (0x35) [08 01 FF FF]
#34  DeletePlayerUI (0x17) [66 08 00 00 F1 00 80 00...]
#69  ObjNotFound (0x1D) obj=0x3FFFFFFF
#70+ StateUpdates begin (t=26.31)
      --- 7 seconds of gameplay ---
#182 ObjectExplodingEvent (0x06 factory 0x8129)    death burst begins
#183 SCORE_CHANGE (0x36)
#184-194  12x TGSubsystemEvent (0x06 factory 0x0101)
      --- 13 seconds of post-death StateUpdates ---
#341-342  2x late TGSubsystemEvent (debris collision)
      --- session ends ---
```

### OpenBC Join → Death → Respawn → End

```
#1   ConnectAck (0x03)
#2-6 ChecksumReq (0x20) rounds 0-2
#10  ChecksumReq (0x20) round 3
#12  ChecksumReq (0x20) round 255
#14  ChecksumComplete (0x28)
#15  Settings (0x00) gameTime=15.01
#16  GameInit (0x01)
#17  PlayerRoster (0x37) [02 00 00 00 00...]          <-- EXTRA (stock doesn't send)
#20  GameState (0x35) [07 01 FF FF]                    <-- byte[0]=0x07, stock=0x08
                                                        <-- NO DeletePlayerUI (0x17)
#23+ StateUpdates begin (t=18.30)
      --- collisions at T+29 and T+50: damage applied, 3 PythonEvents ---
#288 1x TGSubsystemEvent (subsysIdx=42, INVALID)      death burst
#289 ObjectExplodingEvent (0x06 factory 0x8129)
#290 Explosion (0x29)                                  <-- EXTRA (stock doesn't send)
#291 SCORE_CHANGE (0x36)
      --- client respawns as obj=0x40000021 ---
      --- 7/7 post-respawn collisions REJECTED (ownership fail) ---
      --- client disconnects ---
```

### Key Timing Points

| Event | Stock (game time) | OpenBC (game time) |
|-------|-------------------|-------------------|
| Connect | - | - |
| Settings sent | t=21.58 | t=15.01 |
| First StateUpdate | t=26.31 | t=18.30 |
| Death event | t=33.40 | t=~51.5 |
| Respawn | (none — session ended) | t=64.13 |
| Last message | t=46.20 | t=112.75 |

---

## Opcode Frequency Comparison

### Game Opcodes

| Opcode | Name | Stock S→C | OpenBC S→C | Delta | Note |
|--------|------|-----------|-----------|-------|------|
| 0x00 | Settings | 1 | 1 | 0 | |
| 0x01 | GameInit | 1 | 1 | 0 | |
| 0x03 | ObjCreateTeam | 1 | 1 | 0 | |
| 0x06 | PythonEvent | **14** | **5** | **-9** | Missing SubsystemDamage events |
| 0x15 | CollisionEffect | 2 (C→S) | 2+ (C→S) | 0 | C→S only, both correct |
| 0x17 | DeletePlayerUI | **1** | **0** | **-1** | Missing at join |
| 0x1C | StateUpdate | 201 | 562 | +361 | Longer session + dual objects |
| 0x1D | ObjNotFound | 1 | 0 | -1 | Minor |
| 0x28 | ChecksumComplete | 1 | 1 | 0 | |
| 0x29 | Explosion | **0** | **1** | **+1** | Spurious for collision kill |
| 0x2A | NewPlayerInGame | 1 (C→S) | 1 (C→S) | 0 | |
| 0x35 | MissionInit | 1 | 1 | 0 | Content differs (0x08 vs 0x07) |
| 0x36 | ScoreChange | 1 | 1 | 0 | Byte-for-byte identical |
| 0x37 | PlayerRoster | 0 | **1** | **+1** | Extra (harmless) |

### PythonEvent (0x06) Breakdown by Factory

| Factory | Name | Stock | OpenBC |
|---------|------|-------|--------|
| 0x8129 | ObjectExplodingEvent | 1 | 1 |
| 0x0101 | TGSubsystemEvent | **13** | **4** |
| **Total** | | **14** | **5** |

Stock subsystem indices (order): 2, 13, 14, 17, 18, 31, 32, 28, 5, 25, 26, 3, 1
OpenBC subsystem indices (order): 16, 19, 30, 42 (INVALID — beyond 33 subsystems)

No overlap between the two sets.

### Transport-Level

| Type | Stock S→C | OpenBC S→C | Note |
|------|-----------|-----------|------|
| 0x00 DataMsg | 1 | **67** | Client retransmits ~every 1.4s |
| 0x01 ACK | 243 | 22 | 5.4x fewer ACKs from OpenBC |
| 0x03 ConnectAck | 1 | 1 | |
| 0x32 GameData | 212 | 579 | Longer session |

---

## Byte-Level Wire Format Comparisons

### ObjCreateTeam (0x03) — IDENTICAL

```
Stock (118 bytes):
03 00 02 08 80 00 00 FF FF FF 3F 05 00 00 18 42
00 00 44 C2 00 00 0C C2 52 93 45 3F BB C9 22 BF
E2 58 10 B3 25 8D 6C B2 00 00 00 00 00 00 00 05
43 61 64 79 32 06 4D 75 6C 74 69 31 FF FF 64 FF
FF FF FF FF FF FF 64 FF FF FF FF FF FF 64 FF FF
FF FF FF FF FF 64 60 00 FF 64 FF FF FF FF FF FF
FF FF FF 64 01 FF FF FF FF FF 64 01 FF FF FF 64
FF

OpenBC (118 bytes):
03 00 02 08 80 00 00 FF FF FF 3F 05 00 00 18 42
00 00 44 C2 00 00 0C C2 52 93 45 3F BB C9 22 BF
E2 58 10 B3 25 8D 6C B2 00 00 00 00 00 00 00 05
43 61 64 79 32 06 4D 75 6C 74 69 31 FF FF 64 FF
FF FF FF FF FF FF 64 FF FF FF FF FF FF 64 FF FF
FF FF FF FF FF 64 60 00 FF 64 FF FF FF FF FF FF
FF FF FF 64 01 FF FF FF FF FF 64 01 FF FF FF 64
FF
```

Field decode:
```
03             opcode (ObjCreateTeam)
00             team=0 (WriteInt32v)
02             owner=2 (WriteInt32v)
08 80 00 00    ship serialization header
FF FF FF 3F    objectID = 0x3FFFFFFF
05             position encoding type
00 00 18 42... position: (38.0, -49.0, -35.0)
...            orientation (fwd/up vectors), speed, angular velocity
05 43 61 64 79 32   nameLen=5, name="Cady2"
06 4D 75 6C 74 69 31   setLen=6, set="Multi1"
FF FF 64...    subsystem maxHP table (CompressedFloat16 health values)
```

**VERDICT: BYTE-FOR-BYTE IDENTICAL.** Same object ID, position, subsystem health table.

### CollisionEffect (0x15) — IDENTICAL STRUCTURE

```
Stock:   15 24 81 00 00 50 00 80 00 00 00 00 00 FF FF FF 3F 01 F9 7E 02 D8 65 C2 92 44
OpenBC:  15 24 81 00 00 50 00 80 00 00 00 00 00 FF FF FF 3F 01 00 7E 03 D2 99 B6 91 44
```

| Field | Stock | OpenBC | Match |
|-------|-------|--------|-------|
| typeClassId | 0x00008124 | 0x00008124 | IDENTICAL |
| eventCode | 0x00800050 | 0x00800050 | IDENTICAL |
| srcObjId | 0x00000000 | 0x00000000 | IDENTICAL |
| tgtObjId | 0x3FFFFFFF | 0x3FFFFFFF | IDENTICAL |
| contactCount | 1 | 1 | IDENTICAL |
| contact dir | (-7, 126, 2) | (0, 126, 3) | Expected variation |
| contact mag | 216 | 210 | Expected variation |
| force (f32) | 1174.07 | 1165.41 | Expected variation |

### Settings (0x00) — IDENTICAL STRUCTURE

```
Stock:   00 00 A0 AC 41 61 00 25 00 4D 75 6C...31 32 06 80 07 00 01
OpenBC:  00 58 3D 70 41 61 00 25 00 4D 75 6C...31 32 06 80 07 00 01
```

Only the gameTime float differs (stock=21.58, OpenBC=15.01). Field order, bit byte (0x61),
map string, and checksum correction data are all identical.

### ObjectExplodingEvent (0x06 factory 0x8129) — IDENTICAL STRUCTURE

```
Stock:   06 29 81 00 00 4E 00 80 00 00 00 00 00 FF FF FF 3F 00 00 00 00 66 66 4E 41
OpenBC:  06 29 81 00 00 4E 00 80 00 00 00 00 00 FF FF FF 3F 00 00 00 00 00 00 18 41
```

| Field | Stock | OpenBC |
|-------|-------|--------|
| factory_id | 0x8129 | 0x8129 |
| event_type | 0x0080004E | 0x0080004E |
| source (killer) | 0x00000000 | 0x00000000 |
| dest (dying ship) | 0x3FFFFFFF | 0x3FFFFFFF |
| firing_player | 0 | 0 |
| lifetime (float) | 12.9 | 9.5 |

Lifetime difference: stock=12.9s for environment collision kill, OpenBC=9.5s (the standard
self-destruct lifetime). The 12.9 value may be collision-specific — pending further investigation.

### ScoreChange (0x36) — BYTE-FOR-BYTE IDENTICAL

```
Stock:   36 00 00 00 00 02 00 00 00 01 00 00 00 00
OpenBC:  36 00 00 00 00 02 00 00 00 01 00 00 00 00
```

Decoded: killer=0 (environment), victim=2, deaths=1, kill_credit=0.

### MissionInit (0x35) — Off-by-One

```
Stock:   35 08 01 FF FF
OpenBC:  35 07 01 FF FF
```

byte[0]: stock=0x08 (8 max players), OpenBC=0x07 (7).

### DeletePlayerUI (0x17) — Stock Only

```
Stock:   17 66 08 00 00 F1 00 80 00 00 00 00 00 A8 06 00 00 02
```

Decoded: factory=0x0866, event=ET_NEW_PLAYER_IN_GAME (0x008000F1), src=0, tgt=0x000006A8,
peer_id=2. OpenBC does not send this at join time.

---

## Key Findings

### Finding 1: Subsystem Object ID Allocation (ROOT CAUSE)

TGSubsystemEvent (factory 0x0101) messages carry subsystem TGObject network IDs. Stock
allocates these in the player's ID range (0x40000000+ for player 1). OpenBC allocates
from the global sequential counter (0x10, 0x13, 0x1E, etc.).

**Stock CloakingDevice event (subsys idx 2):**
```
06 01 01 00 00 DF 00 80 00 02 00 00 40 18 00 00 40
                               ^^^^^^^^^^^  ^^^^^^^^^^^
                               0x40000002   0x40000018
```

**OpenBC PhaserEmitter event (subsys idx 16):**
```
06 01 01 00 00 DF 00 80 00 10 00 00 00 1E 00 00 00
                               ^^^^^^^^^^^  ^^^^^^^^^^^
                               0x00000010   0x0000001E
```

The critical bytes are at offsets +12 and +16: stock has `40` (high word of 0x40xxxxxx),
OpenBC has `00` (global counter range). ALL 14 stock events use 0x40xxxxxx IDs; ALL 4
OpenBC events use 0x000000xx IDs.

**Impact**: Client calls `ReadObjectRef` → looks up ID in TGObject hash table → lookup
FAILS because the client's subsystems were created with 0x40000000+ range IDs. Damage
events are silently dropped. No visual damage feedback on client.

### Finding 2: Post-Respawn Collision Ownership Failure

After death (obj=0x3FFFFFFF) and respawn (new obj=0x40000021), the server's player-to-ship
mapping still points to the dead ship. ALL subsequent collision validation fails:

```
[WARN] collision ownership fail (sender=0x3FFFFFFF src=0 tgt=0x40000021)
```

7/7 post-respawn collisions rejected. Zero damage applied post-respawn.

Timeline:
```
T+22.157  First ship spawns as obj=0x3FFFFFFF
T+55.641  Ship destroyed
T+67.922  Client sends ObjCreateTeam for respawn (obj=0x40000021)
T+84.688  First post-respawn collision → REJECTED
...       (7 total rejections, all with sender=0x3FFFFFFF tgt=0x40000021)
T+116.782 Client disconnects
```

### Finding 3: Stock Sends 13 SubsystemDamage Events at Death, OpenBC Sends 4

Stock death burst (13 TGSubsystemEvents, factory 0x0101, code 0x800000DF):
```
#184  subsysIdx=2   CloakingDevice
#185  subsysIdx=13  PhaserEmitter#2
#186  subsysIdx=14  PhaserEmitter#3
#187  subsysIdx=17  PhaserEmitter#6
#188  subsysIdx=18  PhaserEmitter#7
#189  subsysIdx=31  TractorBeam#3
#190  subsysIdx=32  TractorBeam#4
#191  subsysIdx=28  PowerReactor#2
#192  subsysIdx=5   ShieldGenerator
#193  subsysIdx=25  PhaserController
#194  subsysIdx=26  PulseWeapon
  ... 13s later (debris collision) ...
#341  subsysIdx=3   PoweredSubsystem
#342  subsysIdx=1   RepairSubsystem
```

OpenBC death burst (4 TGSubsystemEvents total, 3 pre-death + 1 at death):
```
#247  subsysIdx=16  PhaserEmitter#5
#248  subsysIdx=19  PhaserEmitter#8
#249  subsysIdx=30  TractorBeam#2
#288  subsysIdx=42  INVALID (beyond 33 subsystems)
```

### Finding 4: Stock Does NOT Send Explosion (0x29) for Collision Kills

Stock collision kill death sequence: ObjectExplodingEvent + ScoreChange + 13 SubsystemEvents.
No Explosion (0x29).

OpenBC collision kill death sequence: 1 SubsystemEvent + ObjectExplodingEvent + **Explosion (0x29)** + ScoreChange.

The Explosion message is only expected for weapon kills (59/59 in the Valentine's Day
battle trace had Explosion). Environment collision kills do not produce it.

### Finding 5: Missing DeletePlayerUI (0x17) at Join

Stock sends DeletePlayerUI (0x17) after NewPlayerInGame (0x2A), carrying event
ET_NEW_PLAYER_IN_GAME (0x008000F1). This adds the player to the engine's internal
TGPlayerList, which is required for scoreboard display.

OpenBC does not send this. See [../protocol/delete-player-ui-wire-format.md](../protocol/delete-player-ui-wire-format.md).

### Finding 6: MissionInit maxPlayers Off-by-One

Stock MissionInit (0x35) byte[0] = 0x08 (8 players). OpenBC sends 0x07 (7 players).

---

## Confirmed Matches (Byte-for-Byte Identical)

| Component | Evidence |
|-----------|----------|
| Transport layer framing | Header, ACK, reliable/unreliable encoding |
| Connect handshake (0x03) | Slot assignment, flags |
| ObjCreateTeam (0x03) | 118-byte payload identical |
| CollisionEffect (0x15) | Factory ID, event code, contact encoding, force float |
| ScoreChange (0x36) | `36 00 00 00 00 02 00 00 00 01 00 00 00 00` |
| Settings (0x00) | Field order, bit byte (0x61), map, checksum correction |
| GameInit (0x01) | Single byte, no payload |
| StateUpdate (0x1C) | Dirty flags, CF16, CompressedVector format |
| Checksum exchange (0x20-0x27) | Rounds 0-3 + 0xFF format |
| ObjectExplodingEvent (0x06 0x8129) | Factory, event code, field layout |
| TGSubsystemEvent (0x06 0x0101) | Factory, event code, field layout (IDs wrong) |

---

## StateUpdate Comparison

### Server Object (player 0 — dedi host)

| Metric | Stock | OpenBC |
|--------|-------|--------|
| Flags sent | 0x8E, 0x9E, 0x96, 0x9D, 0x86, 0x80 (motion+WPN) | 0x20 (SUB only) |
| Subsystem data | Full health + weapon data | Subsystem health only |
| Motion data | Position, heading, speed | None (headless, no ship) |

Stock dedi sends motion+weapon data for the host's ship because the host IS a player.
OpenBC's headless server has no real ship, so SUB-only is expected.

### Client Ship StateUpdate (from server)

OpenBC sends StateUpdates for the CLIENT's ship (obj=0x40000021) back to the client:
328 StateUpdates with flags=0x20 (SUB). This looks like "echoed" data but is actually
server-authoritative subsystem health. In a 1-player test it appears redundant but is
correct behavior for multi-player scenarios.

### Subsystem Round-Robin Cycling

| Server | startIdx values | Cycle length |
|--------|----------------|-------------|
| Stock | 0, 2, 6, 8, 10 | 5 positions |
| OpenBC | 0, 5, 7, 9 | 4 positions |

Different cycle patterns but both use the same round-robin mechanism.

---

## Collision Processing Log (OpenBC Server)

| Time | Damage | Result | PythonEvents |
|------|--------|--------|-------------|
| T+29.375 | 10,991.4 | Processed OK | 0 |
| T+29.391 | (follow-up) | Processed OK | 0 |
| T+50.922 | 11,776.0 | Processed, 3 events | 3 |
| T+55.625 | 7,281.5 | **Ship destroyed** | 1 + ObjectExploding |
| T+84.688 | (unknown) | **REJECTED** — ownership fail | 0 |
| T+90.266 | (unknown) | **REJECTED** — ownership fail | 0 |
| T+100.891 (x2) | (unknown) | **REJECTED** — ownership fail | 0 |
| T+104.750 (x2) | (unknown) | **REJECTED** — ownership fail | 0 |
| T+107.047 | (unknown) | **REJECTED** — ownership fail | 0 |

All 7 post-respawn collision failures show the same pattern:
`sender=0x3FFFFFFF src=0 tgt=0x40000021`

The sender ID (0x3FFFFFFF) is the DEAD ship. The target (0x40000021) is the new ship.
The ownership table was not updated on respawn.

---

## Discarded Findings (Low Confidence)

| Finding | Why Discarded |
|---------|---------------|
| "328 wasted StateUpdates echoed to client" | Server SHOULD send authoritative subsystem health. Only looks redundant in 1-player test. |
| "ACK deficit: 118 vs 22" | Session length difference. OpenBC has zero retransmissions. |
| "Server ship missing motion/weapon data" | Headless server has no ship. Expected behavior. |
| "DataMsg retransmit bug (67x)" | Insufficient evidence. Could be client reliable queue working normally. |
| "Invalid subsystem index 42" | Likely artifact of wrong ID range allocation, not a separate issue. |
| "ObjectExplodingEvent magnitude 12.9 vs 9.5" | Collision-specific vs standard lifetime. Different damage amounts may produce different values. |
| "Extra PlayerRoster (0x37) at join" | Harmless — client handles it gracefully. |

---

## Related Documents

- [stock-trace-analysis.md](stock-trace-analysis.md) — Earlier stock trace analysis (Valentine's Day battle + collision test)
- [../protocol/wire-format-spec.md](../protocol/wire-format-spec.md) — Complete opcode table
- [../protocol/delete-player-ui-wire-format.md](../protocol/delete-player-ui-wire-format.md) — DeletePlayerUI (0x17) wire format
- [../protocol/pythonevent-wire-format.md](../protocol/pythonevent-wire-format.md) — PythonEvent (0x06) factories
- [../protocol/collision-effect-protocol.md](../protocol/collision-effect-protocol.md) — CollisionEffect (0x15) wire format
- [../networking/ship-death-lifecycle.md](../networking/ship-death-lifecycle.md) — Ship death/respawn sequence
