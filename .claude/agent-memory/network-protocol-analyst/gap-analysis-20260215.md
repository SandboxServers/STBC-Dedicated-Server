# Gap Analysis: Custom Dedicated Server vs Stock Dedicated Server

Date: 2026-02-15

## Methodology
- Compared all opcodes in the wire-format-spec.md (verified jump table) against implementation
- Cross-referenced stock 15-minute packet trace (30K+ packets) with our Python/C code
- Checked event handler registrations vs stock Mission1.SetupEventHandlers
- Verified END_GAME, RESTART_GAME, and SCORE_CHANGE message implementations

## Summary

| # | Gap | Severity | Category |
|---|-----|----------|----------|
| 1 | DamageEventHandler not registered | **HIGH** | Scoring |
| 2 | Time limit timer not created | **MEDIUM** | Game flow |
| 3 | 0x35 MISSION_INIT byte[1] wrong | **MEDIUM** | Join flow |
| 4 | ProcessNameChangeHandler missing | **LOW** | Cosmetic |
| 5 | DeletePlayerHandler not registered | **LOW** | Cosmetic |

## Detailed Findings

### GAP 1: DamageEventHandler Not Registered (HIGH)

**Stock behavior**: Mission1.SetupEventHandlers registers `DamageEventHandler` on
`ET_WEAPON_HIT` (host-only). This handler tracks per-player damage in
`g_kDamageDictionary` keyed by ship object ID. When a ship explodes,
`ObjectKilledHandler` reads this dictionary to compute damage-based scores.

**Our behavior**: Our `_headless_ms_seh` in DedicatedServer.py registers 5 handlers
but does NOT register DamageEventHandler. Our `_ds_ObjectKilledHandler` reads
`g_kDamageDictionary` but nobody populates it (always empty).

**Impact**: Kills and deaths are tracked correctly (from ObjectKilledHandler).
But damage-based scoring (`g_kScoresDictionary`) is always zero because the
damage dictionary is never populated. The scoreboard shows kills/deaths but
scores are all 0.

**Fix**: Register `Mission1.DamageEventHandler` on `ET_WEAPON_HIT` in
`_headless_ms_seh`. The stock handler uses shadow class methods
(pEvent.GetFiringPlayerID, pShip.GetNetType) which should work since we
have real ship objects from DeferredInitObject. If shadow class issues arise,
write a headless replacement using Appc functional API.

### GAP 2: Time Limit Timer Not Created (MEDIUM)

**Stock behavior**: When `g_iTimeLimit != -1`, the host calls
`MissionShared.CreateTimeLeftTimer(iTimeLimit * 60)` during the game start
sequence (from Mission1Menus.HandleStartGame or from ProcessMessageHandler
on the client side). This creates a repeating timer that decrements
`g_iTimeLeft` every second and calls `EndGame(END_TIME_UP)` when it hits 0.

**Our behavior**: Our server stubs all Mission1Menus functions (they crash
headless). The `HandleStartGame` path never executes. With `SERVER_TIME_LIMIT = -1`
(default), this is harmless. But if someone sets a time limit, the game never ends.

**Impact**: Only matters when `SERVER_TIME_LIMIT != -1`. With default config (-1),
no impact. But timed games would run forever.

**Fix**: After the mission cascade completes (tick 5 CreateSystemSet area), if
`SERVER_TIME_LIMIT != -1`, call `MissionShared.CreateTimeLeftTimer(SERVER_TIME_LIMIT * 60)`.
The timer mechanism uses `MissionLib.CreateTimer` which is engine-level and should work headless.

### GAP 3: 0x35 MISSION_INIT_MESSAGE byte[1] Wrong Value (MEDIUM)

**Stock behavior**: The `MISSION_INIT_MESSAGE` (opcode 0x35) byte[1] is the player limit,
written by `kStream.WriteChar(chr(MissionMenusShared.g_iPlayerLimit))`. Stock trace shows
byte[1] = 0x08 (for 8-player limit).

**Our behavior**: We write `chr(_mms.g_iPlayerLimit)` which should also be 8 since we set
`mms.g_iPlayerLimit = SERVER_PLAYER_LIMIT` (default 8).

**However**: The MEMORY.md notes "0x35 byte wrong: we send 0x01, stock sends 0x09".
The 0x35 opcode is sent TWO ways:
1. Our Python `_ds_InitNetwork` sends MISSION_INIT_MESSAGE correctly (byte[1] = g_iPlayerLimit = 8)
2. The C++ engine's `FUN_006a1e70` also sends 0x35 with different data (the 4-byte game state:
   `[maxPlayers][totalSlots][FF][FF]`). We send totalSlots=0x01, stock sends 0x09.

**Impact**: The client reads the player limit from the MISSION_INIT_MESSAGE (our Python path),
which is correct. The 0x35 from the C++ path goes to a different handler. The C++ 0x35
totalSlots byte affects the lobby display but not gameplay. Cosmetic impact.

**Fix**: To match stock behavior, the C++ 0x35's byte[1] (totalSlots) should be
`maxPlayers + 1` (8+1=9). This comes from `FUN_006a1e70`'s internal logic reading
`MultiplayerGame+0x1FC` (maxPlayers). Since we set maxPlayers=8, this should read 0x09.
If it reads 0x01, something is wrong with our `MultiplayerGame+0x1FC` setup. Investigate
whether `MultiplayerGame_SetMaxPlayers` is being called or if the default is 1.

### GAP 4: ProcessNameChangeHandler Not Registered (LOW)

**Stock behavior**: `Mission1.SetupEventHandlers` registers `ProcessNameChangeHandler`
on `ET_NETWORK_NAME_CHANGE_EVENT`. This handler rebuilds the player info pane when a
player changes their name.

**Our behavior**: Not registered. We don't have a UI to update.

**Impact**: None for dedicated server. Player name changes during the session won't be
reflected on any hypothetical admin UI, but we have no admin UI.

### GAP 5: DeletePlayerHandler Not Registered (LOW)

**Stock behavior**: `Mission1.SetupEventHandlers` registers `DeletePlayerHandler` on
`ET_NETWORK_DELETE_PLAYER`. This handler rebuilds the player list UI when a player
disconnects. Importantly, it does NOT delete the player from scoring dictionaries
(scores are preserved for reconnect).

**Our behavior**: Not registered. The C++ engine handles the disconnect at the network
level (sends 0x17 DeletePlayerUI and 0x18 DeletePlayerAnim to clients). Score dictionaries
are naturally preserved since nothing deletes them.

**Impact**: None for gameplay. The scoring preservation works by default (nothing to delete).

## Things That WORK Correctly

### Complete Opcode Coverage
Comparing the stock packet trace against our implementation:

| Category | Opcodes | Our Handling | Status |
|----------|---------|-------------|--------|
| Checksum exchange | 0x20-0x27 | Engine handles (FUN_006a3cd0) | WORKING |
| Settings + GameInit | 0x00, 0x01 | Engine sends (FUN_006a1b10) | WORKING |
| Object create/team | 0x02, 0x03 | Engine handles (FUN_0069f620) | WORKING |
| Boot player | 0x04 | Engine handles | WORKING |
| Python events | 0x06, 0x0D | Engine relays (FUN_0069f880) | WORKING |
| Event forwards | 0x07-0x12, 0x1B | Engine relays (FUN_0069fda0) | WORKING |
| Host messages | 0x13 | Engine handles (FUN_006a0d90) | WORKING |
| Destroy object | 0x14 | Engine handles (FUN_006a01e0) | WORKING |
| Collision effect | 0x15 | Engine handles (FUN_006a2470) | WORKING |
| UI collision | 0x16 | Engine handles (FUN_00504c70) | WORKING |
| Delete player UI | 0x17 | Engine handles | WORKING |
| Delete player anim | 0x18 | Engine handles | WORKING |
| Torpedo fire | 0x19 | Engine relays (FUN_0069f930) | WORKING |
| Beam fire | 0x1A | Engine relays (FUN_0069fbb0) | WORKING |
| State update | 0x1C | Engine handles (FUN_005b17f0/21c0) | WORKING |
| Object not found | 0x1D | Engine handles | WORKING |
| Request object | 0x1E | Engine handles (FUN_006a02a0) | WORKING |
| Enter set | 0x1F | Engine handles (FUN_006a05e0) | WORKING |
| Explosion | 0x29 | Engine handles (FUN_006a0080) | WORKING |
| New player in game | 0x2A | Engine handles (FUN_006a1e70) | WORKING |
| Chat messages | 0x2C, 0x2D | ChatRelayHandler | WORKING |
| MISSION_INIT | 0x35 | _ds_InitNetwork | WORKING |
| SCORE_CHANGE | 0x36 | _ds_ObjectKilledHandler | WORKING |
| SCORE_MESSAGE | 0x37 | _ds_InitNetwork (at join) | WORKING |
| END_GAME | 0x38 | _ds_EndGame | IMPLEMENTED |
| RESTART_GAME | 0x39 | _ds_RestartGame | IMPLEMENTED |

### Settings Packet (0x00) Mystery Bytes RESOLVED
- **DAT_008e5f59** at offset 2 in the Settings packet = **collision damage toggle**
  - Written as a BIT via `WriteBit(stream, DAT_008e5f59)`, not a full byte
  - Our server sets this to 1 via `App.ProximityManager_SetPlayerCollisionsEnabled(1)`
  - This is the `SERVER_COLLISIONS` config value
- **DAT_0097faa2** at offset 3 in the Settings packet = **friendly fire toggle**
  - Written as a BIT via `WriteBit(stream, DAT_0097faa2)`, not a full byte
  - Our server leaves this as 0 (default = no friendly fire warnings at threshold)
  - This controls whether friendly fire tracking is enabled

Both are handled correctly by the engine's `FUN_006a1b10` (ChecksumCompleteHandler)
which reads these globals directly when building the Settings packet.

### END_GAME_MESSAGE (0x38) and RESTART_GAME_MESSAGE (0x39)
Both are implemented in `DSNetHandlers.py`:
- `_ds_EndGame(iReason)`: Sends END_GAME_MESSAGE via Appc, sets g_bGameOver=1, disables new players
- `_ds_RestartGame()`: Resets scoring dicts, clears g_bGameOver, sends RESTART_GAME_MESSAGE
- EndGame is triggered by `_ds_CheckFragLimit()` when frag limit is reached
- RestartGame is patched onto `Mission1.RestartGame` and can be triggered by the restart flow

### Player Disconnect/Reconnect
The C++ engine handles the core disconnect flow:
- `DeletePlayerHandler` (0x006a0ca0) fires on `ET_NETWORK_DELETE_PLAYER`
- Engine sends opcode 0x17 (DeletePlayerUI) and 0x18 (DeletePlayerAnim) to other clients
- Score dictionaries are NOT cleared on disconnect (stock behavior preserved by default)
- If the same player reconnects, their scoring keys persist with accumulated values
