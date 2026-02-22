> [docs](../README.md) / [protocol](README.md) / delete-player-ui-wire-format.md

# DeletePlayerUI (Opcode 0x17) Wire Format

**Date**: 2026-02-21
**Binary**: stbc.exe (32-bit, ~5.9MB, base 0x400000)
**Method**: Ghidra decompilation + stock dedicated server packet trace analysis
**Status**: VERIFIED against stock dedi traces (self-destruct test, 2026-02-21)

---

## Overview

Opcode 0x17 ("DeletePlayerUI") is a **generic player-list-update event transport** that carries a serialized TGEvent to the client's engine event system. Despite its name, it is used for **both** player addition (at join time) and player removal (at disconnect time).

The handler at `FUN_006a1360` deserializes a TGEvent from the wire using the factory system (`FUN_006d6200`) and posts it to the global event manager. The engine's `NewPlayerInGameHandler` at `0x006a1590` (registered for `ET_NEW_PLAYER_IN_GAME` / `0x008000F1`) processes the event and adds the player to the internal `TGPlayerList`.

---

## Wire Format

```
Offset  Size  Type     Field           Notes
------  ----  ----     -----           -----
0       1     u8       opcode          Always 0x17
1       4     u32le    factory_id      TGEvent class factory ID (0x00000866)
5       4     u32le    event_code      Event type code
9       4     u32le    src_obj_id      Source object ID (typically 0x00000000)
13      4     u32le    tgt_obj_id      Target object ID (ship or player object)
17      1     u8       wire_peer_id    Wire peer slot (1-based)
```

**Total**: 18 bytes (1 opcode + 17 payload).

### Factory ID

The factory ID `0x00000866` identifies the base `TGEvent` class. The handler calls `FUN_006d6200` (TGStreamedObject factory deserializer) which looks up class ID `0x866` and constructs a TGEvent from the stream. This is the same factory system used by PythonEvent (opcode 0x06) for polymorphic event transport.

### Event Codes

| Context | Event Code | Constant | Effect |
|---------|-----------|----------|--------|
| Player join | `0x008000F1` | ET_NEW_PLAYER_IN_GAME | Adds player to TGPlayerList |
| Player disconnect | `0x00060005` | ET_NETWORK_DELETE_PLAYER | Removes player from TGPlayerList |

### Field Values by Context

**Join time** (sent alongside MissionInit 0x35 after NewPlayerInGame 0x2A):
- `factory_id` = `0x00000866`
- `event_code` = `0x008000F1`
- `src_obj_id` = `0x00000000`
- `tgt_obj_id` = varies per session (ship/player object ID)
- `wire_peer_id` = joining player's wire peer slot

**Disconnect time** (sent to remaining clients when a player leaves):
- `factory_id` = `0x00000866`
- `event_code` = `0x00060005`
- `src_obj_id` = `0x00000000`
- `tgt_obj_id` = disconnecting player's object ID
- `wire_peer_id` = disconnecting player's wire peer slot

---

## Stock Trace Evidence

### Join-Time (from stock dedi self-destruct test, 2026-02-21)

Packet #25, sent S→C after NewPlayerInGame (0x2A) and alongside MissionInit (0x35):

```
17 66 08 00 00 F1 00 80 00 00 00 00 00 4F 06 00 00 02
```

Decoded:
- `17` — opcode 0x17 (DeletePlayerUI)
- `66 08 00 00` — factory_id = 0x00000866 (TGEvent)
- `F1 00 80 00` — event_code = 0x008000F1 (ET_NEW_PLAYER_IN_GAME)
- `00 00 00 00` — src_obj_id = 0x00000000 (no source)
- `4F 06 00 00` — tgt_obj_id = 0x0000064F (session-specific)
- `02` — wire_peer_id = 2 (joining client)

### Trace Frequency

| Trace | 0x17 Count | Context |
|-------|-----------|---------|
| Stock dedi self-destruct test | 1 | Join time (player 2 joins) |
| Battle of Valentine's Day (33.5 min) | 6 | All at join time (3 players, slot reuse) |
| Stock dedi 91-second session | 1 | Join time |

**Zero** 0x17 instances observed at disconnect time across all available traces. Disconnect cleanup may use 0x17 internally (the C++ DeletePlayerHandler at `FUN_006a0ca0` sends it), but the available traces didn't capture a disconnect with remaining clients to observe the message.

---

## Handler Chain

### Sending (Server Side)

**At join time**: Sent by the server after processing NewPlayerInGame (0x2A). The ChecksumCompleteHandler or post-join logic constructs a TGEvent with `ET_NEW_PLAYER_IN_GAME`, serializes it, and sends it alongside MissionInit (0x35).

**At disconnect time**: The C++ `DeletePlayerHandler` (`FUN_006a0ca0`, registered for `ET_NETWORK_DELETE_PLAYER`) sends opcode 0x17 to remaining clients as part of the disconnect cleanup cascade (along with 0x14 DestroyObject and 0x18 DeletePlayerAnim).

### Receiving (Client Side)

```
FUN_006a1360 (opcode 0x17 handler)
  │
  ├── FUN_006d6200(stream)              // TGStreamedObject factory deserialize
  │     └── Looks up factory_id (0x866) // Constructs TGEvent from stream
  │     └── Reads event_code, src_obj_id, tgt_obj_id, wire_peer_id
  │
  ├── FUN_006da2a0(eventMgr, event)     // Post event to global event manager
  │
  └── Event dispatched to registered handlers:
        ├── [if ET_NEW_PLAYER_IN_GAME (0x008000F1)]
        │     └── NewPlayerInGameHandler (0x006a1590)
        │           └── Adds player to TGPlayerList
        │
        └── [if ET_NETWORK_DELETE_PLAYER (0x00060005)]
              └── DeletePlayerHandler (0x006a0ca0)
                    └── Removes player from TGPlayerList
                    └── Python RebuildPlayerList()
```

---

## Scoreboard Population Requirements

The client's scoreboard (Mission1Menus.py `RebuildPlayerList`) requires **both** conditions to display a player:

1. **TGPlayerList entry**: Player must exist in `pNetwork.GetPlayerList()` — populated by opcode 0x17 carrying `ET_NEW_PLAYER_IN_GAME`
2. **Score dictionary entry**: Player's `GetNetID()` must appear in `g_kKillsDictionary` — populated by `SCORE_MESSAGE` (0x37) or `SCORE_CHANGE` (0x36)

```python
# Mission1Menus.py line 267
if (pDict.has_key(pPlayer.GetNetID()) and pPlayer.IsDisconnected() == 0):
```

If either is missing, the player won't appear on the scoreboard:
- Missing 0x17 → TGPlayerList empty → no players to iterate
- Missing 0x37/0x36 → dictionary empty → players filtered out

On a completely fresh server with no kills, the stock behavior is that a new joiner won't see themselves on the scoreboard until the first kill or death triggers a `SCORE_CHANGE` (0x36). This is stock behavior, not a bug.

---

## Naming Clarification

The name "DeletePlayerUI" is inherited from the opcode's role in the disconnect flow (where it was first identified). However, the opcode is fundamentally a **TGEvent transport** — the same handler processes both join and disconnect events. A more accurate name would be "PlayerListEvent" or "PlayerEvent", but the existing name is retained for consistency with the codebase.

---

## Related Documents

- [wire-format-spec.md](wire-format-spec.md) — Summary opcode table
- [game-opcodes.md](game-opcodes.md) — Full game opcode reference
- [pythonevent-wire-format.md](pythonevent-wire-format.md) — PythonEvent (0x06), similar factory-based event transport
- [../networking/disconnect-flow.md](../networking/disconnect-flow.md) — Disconnect cleanup cascade (sends 0x17 at disconnect)
- [../networking/multiplayer-flow.md](../networking/multiplayer-flow.md) — Join flow (sends 0x17 at join)
