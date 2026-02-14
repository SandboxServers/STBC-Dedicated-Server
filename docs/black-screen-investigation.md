# Client Disconnect Investigation (RESOLVED)

## Resolution Summary

The client disconnect issue has been **resolved**. Two independent fixes were required:

### Fix 1: DeferredInitObject (NIF Model Loading)
The headless server now creates ship objects with real NIF models and subsystems via a
Python-driven deferred initialization path. When a client selects a ship and an ObjCreateTeam
packet arrives, the C-side `GameLoopTimerProc` detects the new ship object and calls Python
to load the NIF model, triggering the full subsystem creation pipeline:

```
ObjCreateTeam received → ship object exists at ship+0x2E0 (ShipRef) = NULL
→ DeferredInitObject(playerID) called from GameLoopTimerProc
→ Python: ship.LoadModel(nifPath) loads the NIF file
→ Engine: AddToSet links properties to "Scene Root" NiNode
→ Engine: SetupProperties creates 33 runtime subsystem objects
→ ship+0x284 now populated → StateUpdate sends flags=0x20 with real health data
```

### Fix 2: InitNetwork Peer-Array Detection
The `MISSION_INIT_MESSAGE` was arriving 13+ seconds after connect instead of ~2 seconds.
Root cause: the `bc` flag at `peer+0xBC` was used to detect checksum completion, but it
takes 200+ ticks to transition (or never transitions at all). Replaced with peer-array
appearance detection — detects new peers within 1-2 ticks of connection.

| Metric | Before Fix | After Fix | Stock Server |
|--------|-----------|-----------|-------------|
| Peer detection | tick ~417 | tick ~51 | tick ~50 |
| InitNetwork call | ~13s after connect | ~1.4s after connect | ~2s after connect |
| MISSION_INIT_MESSAGE | Too late (client silent) | On time | On time |
| Collision damage | Not working | **Working** | Working |
| Subsystem damage | Not working | **Working** | Working |

---

## Original Problem (Historical)

### Symptom
Client connects to dedicated server, checksums pass (4 rounds), reaches ship selection screen,
player appears on scoreboard, ship model is visible. Then ~3 seconds later:
**"You have been disconnected from the host computer"**

### Previously Solved: Black Screen (no longer occurs)
The original black screen issue was caused by missing NewPlayerInGame handshake.
Fixed by GameLoopTimerProc calling FUN_006a1e70 (opcode 0x2A handler) when player count
increases. Client now receives Settings (0x00), GameInit (0x01), ObjCreateTeam (0x03),
and transitions to ship selection UI.

## Root Cause Analysis (Two Independent Issues)

### Issue 1: Empty StateUpdate packets (flags=0x00)
The server sent StateUpdate packets with `flags=0x00` (empty) instead of `flags=0x20`
(subsystem health data). This was caused by a 5-step causal chain:

1. NIF models didn't load headlessly (stubbed renderer)
2. AddToSet("Scene Root", prop) failed (no NiNode in scene graph)
3. Subsystem linked list at ship+0x284 was NULL
4. PatchNetworkUpdateNullLists correctly cleared flags to prevent malformed packets
5. Client received no subsystem health data

**Fix**: DeferredInitObject loads NIF models via Python API, breaking the chain at step 1.
See [empty-stateupdate-root-cause.md](empty-stateupdate-root-cause.md) for full analysis.

### Issue 2: MISSION_INIT_MESSAGE timing (13s instead of 2s)
The `bc` flag at `peer+0xBC` in the TGWinsockNetwork peer structure was used to detect when
checksum exchange completed. This flag:
- Takes 200+ ticks (~7 seconds) to transition from 0 to 1
- In some cases, **never transitions at all** (remained 0 after 1000+ ticks)
- Is set deep in the checksum pipeline, NOT at completion time

The actual checksum exchange completes within 1-2 ticks of connection. By the time our code
detected "checksum complete" via the bc flag, the client had already gone silent.

**Fix**: Detect new peers by scanning the WSN peer array (`WSN+0x2C` = array pointer,
`WSN+0x30` = count). When a new peer ID appears, schedule InitNetwork immediately (30 tick
delay for safety). This fires at connect time, matching stock timing.

## What Works Now (Confirmed)

- Headless boot through all 4 phases
- GameSpy LAN discovery, checksum exchange (4 rounds)
- Settings + GameInit sent within ~1.4s of connect
- Client reaches ship selection, picks ship
- DeferredInitObject creates ship with 33 subsystems
- StateUpdate flags=0x20 with real subsystem health cycling
- Collision damage between ships
- Individual subsystem damage (shields, weapons, engines, etc.)
- Client stays connected for extended sessions

## Remaining Issues (Not Related to Disconnect)

- First connection always times out (client must reconnect once)
- Server's own ship (player 0) still sends flags=0x00 (harmless)
- 0x35 GameState byte wrong: 0x01 vs stock's 0x09
- Double NewPlayerInGame (engine + our timer both fire)

## Key Addresses
| Address | Function | Role |
|---------|----------|------|
| 0x005b17f0 | FUN_005b17f0 | StateUpdate serializer (per-ship per-tick) |
| 0x005b21c0 | FUN_005b21c0 | StateUpdate receiver/deserializer |
| 0x005b1d57 | (patch site) | PatchNetworkUpdateNullLists - clears flags when +0x284 NULL |
| 0x006a1e70 | FUN_006a1e70 | NewPlayerInGame handler (opcode 0x2A) |
| 0x006a1b10 | FUN_006a1b10 | ChecksumCompleteHandler (sends 0x00 + 0x01) |
| 0x005b0e80 | FUN_005b0e80 | InitObject (ship deserialization from network) |
| 0x006c9520 | FUN_006c9520 | AddToSet (links properties to NiNode scene graph) |
| 0x005b3fb0 | FUN_005b3fb0 | SetupProperties (creates runtime subsystem objects) |
