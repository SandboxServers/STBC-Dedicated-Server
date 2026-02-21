# Gamemode / Mission System RE

Complete reverse engineering of the multiplayer gamemode architecture: mission loading, scoring, game flow messages, team support, and end/restart conditions.

## Architecture: Two-Layer Design

The system is cleanly separated:

- **C++ layer** (mission-agnostic): network transport, object lifecycle, event dispatch, state sync. The C++ code does not know or care what mission is running.
- **Python layer** (game-mode-specific): mission selection, scoring, time/frag limits, team assignment, end game, restart. All game mode logic lives in Python scripts under `scripts/Multiplayer/`.

The C++ layer provides three call points into Python:
1. `TG_CallPythonFunction("AI.Setup", "GameInit")` during CreateMultiplayerGame (FUN_00504F10)
2. `FUN_006f8650("Multiplayer.MissionMenusShared", "g_iPlayerLimit")` to read max players
3. `TG_CallPythonFunction(missionScript, "InitNetwork", connID, "i")` during NewPlayerInGame (FUN_006a1e70)

## Mission Loading Chain

```
Settings(opcode 0x00, FUN_00504d30):
  Parses: [float:gameTime] [byte:settings1] [byte:collision] [byte:playerSlot]
          [short:mapNameLen] [bytes:mapName] [byte:checksumFlag]
  Stores mission name in VarManager("Multiplayer", "Mission", mapName)

GameInit(opcode 0x01, FUN_00504F10):
  1. TG_CallPythonFunction("AI.Setup", "GameInit") — preloads 73 AI scripts
  2. Constructs MultiplayerGame object (FUN_0069e590)
     - Initializes 16 player slots (0x18 bytes each at +0x74)
     - Creates "NoMe" group (0x008e5528) — all peers except self
     - Creates "Forward" group (0x008d94a0) — all peers including self
     - Registers 26 C++ event handlers (8 host-only)
  3. Reads g_iPlayerLimit from Python to set max players

MultiplayerGame constructor → LoadEpisode("Multiplayer.Episode.Episode")
  → Episode.Initialize reads VarManager("Multiplayer","Mission")
    → LoadMission(missionScript)
      → Mission1.Initialize → MissionShared.Initialize
        → Registers ET_NETWORK_MESSAGE_EVENT handler
        → Registers ET_OBJECT_EXPLODING for scoring (host only)
```

## Available Missions

| ID | Script | Type | Teams | AI Required | Shipped |
|----|--------|------|-------|-------------|---------|
| Mission1 | `Multiplayer.Episode.Mission1.Mission1` | FFA Deathmatch | No | No | Yes |
| Mission2 | `Multiplayer.Episode.Mission2.Mission2` | Team Deathmatch (generic) | 2 | No | Yes |
| Mission3 | `Multiplayer.Episode.Mission3.Mission3` | Team Deathmatch (faction) | 2 | No | Yes |
| Mission4 | — | — | — | — | **Cut** |
| Mission5 | `Multiplayer.Episode.Mission5.Mission5` | Starbase Defense | 2 | **Yes** (StarbaseAI) | Yes |
| Mission6 | — | Starbase variant | — | Yes | **Cut** (referenced in MissionShared.py line 242) |
| Mission7 | — | Borg Hunt | — | Yes | **Cut** (END_BORG_DEAD, referenced in MissionShared.py line 253) |
| Mission9 | — | Enterprise Defense | — | Yes | **Cut** (END_ENTERPRISE_DEAD, referenced in MissionShared.py line 264) |

### Mission3 vs Mission2

Mission3 is functionally identical to Mission2 except:
- Team names use `"Federation Team Name"` / `"NonFed Team Name"` (from localization DB) instead of generic `"Team"` + number
- Kill subtitle uses these faction names

Team assignment in both Mission2 and Mission3 is **player-chosen** via TEAM_MESSAGE — the faction names in Mission3 are just labels, not auto-assignment based on ship species.

### Mission5 (Starbase Defense) — Requires AI

- **Team 0** = Attackers, **Team 1** = Defenders
- Host spawns a FedStarbase via `CreateShip()` with collision damage disabled
- Starbase gets `StarbaseAI` controller targeting the attacker group
- Attackers win by destroying the starbase; defenders win by reaching frag limit
- Includes cutscene on starbase destruction
- **Excluded from OpenBC Phase 1** because it requires in-game AI

## Shared Infrastructure (MissionShared.py)

### Message Type Constants

```python
MISSION_INIT_MESSAGE    = App.MAX_MESSAGE_TYPES + 10  # 0x35
SCORE_CHANGE_MESSAGE    = App.MAX_MESSAGE_TYPES + 11  # 0x36
SCORE_MESSAGE           = App.MAX_MESSAGE_TYPES + 12  # 0x37
END_GAME_MESSAGE        = App.MAX_MESSAGE_TYPES + 13  # 0x38
RESTART_GAME_MESSAGE    = App.MAX_MESSAGE_TYPES + 14  # 0x39
```

### End Game Reason Codes

```python
END_ITS_JUST_OVER       = 0   # Generic
END_TIME_UP             = 1   # Time limit expired
END_NUM_FRAGS_REACHED   = 2   # Frag limit reached
END_SCORE_LIMIT_REACHED = 3   # Score limit reached
END_STARBASE_DEAD       = 4   # Starbase destroyed (Mission5)
END_BORG_DEAD           = 5   # Borg destroyed (cut Mission7)
END_ENTERPRISE_DEAD     = 6   # Enterprise destroyed (cut Mission9)
```

### Team-Mode Extra Message Types (Mission2/3 only)

```python
SCORE_INIT_MESSAGE      = App.MAX_MESSAGE_TYPES + 20  # 0x3F
TEAM_SCORE_MESSAGE      = App.MAX_MESSAGE_TYPES + 21  # 0x40
TEAM_MESSAGE            = App.MAX_MESSAGE_TYPES + 22  # 0x41
INVALID_TEAM            = 255
```

### Time Management

- `CreateTimeLeftTimer(iTimeLeft)` creates a 1-second countdown timer
- `UpdateTimeLeftHandler()` decrements `g_iTimeLeft` each second
- When `g_iTimeLeft` reaches 0, host calls `EndGame(END_TIME_UP)`
- Time is stored in seconds (`g_iTimeLimit * 60`)

### EndGame Flow

1. Host calls `EndGame(iReason)`
2. Constructs END_GAME_MESSAGE with reason code
3. Sends to all players via `SendTGMessage(0, pMessage)` (0 = broadcast)
4. Sets `ReadyForNewPlayers(0)` — no new connections accepted
5. Clients receive END_GAME_MESSAGE in `MissionShared.ProcessMessageHandler`
6. Client sets `g_bGameOver = 1`, calls `ClearShips()`, shows end game dialog

### RestartGame Flow

1. Host receives ET_RESTART_GAME event (from UI button)
2. Sends RESTART_GAME_MESSAGE to all via `SendTGMessage(0, pMessage)`
3. All nodes execute `RestartGame()`:
   - Zero all scoring dicts (kills, deaths, scores, damage) — keys preserved
   - Zero team dicts (team assignments, team scores, team kills)
   - Clear `g_bGameOver` flag
   - Call `ClearShips()` (deletes all player ships and torpedoes)
   - Reset `g_iTimeLeft = g_iTimeLimit * 60`
   - Show ship selection screen

## Wire Formats

All messages use TGMessage with `SetGuaranteed(1)` (reliable delivery). Data is written via `TGBufferStream`. The first byte is always the message type.

### MISSION_INIT_MESSAGE (0x35) — Host → Joining Client

Sent during `InitNetwork(iToID)` when a new player joins.

```
[char:0x35]
[char:playerLimit]          # max players (1-8)
[char:systemSpecies]        # map/system ID (SpeciesToSystem enum)
[char:timeLimitOrNone]      # 255 = no time limit, else minutes
  [if != 255: int:endTime]  # absolute game time when round ends
[char:fragLimitOrNone]      # 255 = no frag limit, else frag count
```

**Size**: 4-8 bytes (4 without time limit, 8 with time limit)

The `endTime` field is computed as `g_iTimeLeft + int(GetGameTime())` — it's the absolute game clock value at which the round should end. The client calculates remaining time as `endTime - int(GetGameTime())`.

### SCORE_CHANGE_MESSAGE (0x36) — Host → All Clients (via "NoMe" group)

Sent on every kill event from `ObjectKilledHandler`.

```
[char:0x36]
[long:killerPlayerID]       # 0 if no player killed (self-destruct/AI)
  [if killerPlayerID != 0:
    long:killerKills         # updated kill count
    long:killerScore]        # updated total score
[long:killedPlayerID]       # player who died
[long:killedDeaths]         # updated death count
[char:additionalScoreCount] # N players who got score updates (damage contributors)
  [N times:
    long:playerID
    long:playerScore]
```

**Size**: variable, 10+ bytes minimum

### SCORE_MESSAGE (0x37) — Host → Joining Client

Sent during `InitNetwork` for each existing player (full score sync).

```
[char:0x37]
[long:playerID]
[long:kills]
[long:deaths]
[long:score]
```

**Size**: 17 bytes fixed

### END_GAME_MESSAGE (0x38) — Host → All (broadcast)

```
[char:0x38]
[int:reason]                # END_* enum value (0-6)
```

**Size**: 5 bytes fixed

### RESTART_GAME_MESSAGE (0x39) — Host → All (broadcast)

```
[char:0x39]
```

**Size**: 1 byte fixed

### SCORE_INIT_MESSAGE (0x3F) — Team Modes Only — Host → Joining Client

Extended version of SCORE_MESSAGE that includes team assignment.

```
[char:0x3F]
[long:playerID]
[long:kills]
[long:deaths]
[long:score]
[char:teamID]               # 0 or 1 (255 = INVALID_TEAM)
```

**Size**: 18 bytes fixed

### TEAM_SCORE_MESSAGE (0x40) — Team Modes Only — Host → All Clients

```
[char:0x40]
[char:teamID]               # 0 or 1
[long:teamKills]
[long:teamScore]
```

**Size**: 10 bytes fixed

### TEAM_MESSAGE (0x41) — Client → Host, then Host → All Clients

Client sends team selection; host forwards to all other players.

```
[char:0x41]
[long:playerID]
[char:teamID]               # 0 or 1
```

**Size**: 6 bytes fixed

**Forwarding**: When host receives TEAM_MESSAGE, it copies the message and sends to "NoMe" group via `SendTGMessageToGroup`.

## Scoring System

### Damage Tracking (Host Only)

- **Event**: `ET_WEAPON_HIT` triggers `DamageEventHandler`
- **Filter**: Only tracks damage to player ships (`IsPlayerShip() == 1`)
- **Data structure**: `g_kDamageDictionary[shipObjID][attackerPlayerID] = [shieldDmg, hullDmg]`
- **Ship class modifier**: Damage is multiplied by `Modifier.GetModifier(attackerClass, targetClass)`
  - All stock ships are class 1, so the modifier table entry is `g_kModifierTable[1][1] = 1.0` (no change)
  - Class 2 killing class 2 gets 3.0x modifier (unused in stock — no class 2 ships exist)
- **Team mode friendly fire**: If attacker and target are on the same team, damage is NEGATED (`fDamage = -fDamage`), resulting in negative score accumulation

### Kill Processing (Host Only)

- **Event**: `ET_OBJECT_EXPLODING` triggers `ObjectKilledHandler`
- **Filter**: Only awards kills/deaths for player ships
- **Kill credit**: Goes to `pEvent.GetFiringPlayerID()` — the player who fired the killing shot
- **Score formula**: `score = (shieldDamage + hullDamage) / 10.0` for ALL players who damaged the destroyed ship
- **FFA mode**: Kill awards +1 frag to killer, +1 death to killed
- **Team mode**: Kill only awards frag if killer and killed are on different teams. Team kill counter also incremented.

### Score Sync

1. **On kill**: Host sends SCORE_CHANGE_MESSAGE (0x36) to "NoMe" group
2. **On player join**: Host sends one SCORE_MESSAGE (0x37) per existing player to the new joiner
3. **Team mode join**: Host sends SCORE_INIT_MESSAGE (0x3F) instead of 0x37, plus TEAM_SCORE_MESSAGE (0x40) for each team

### Frag/Score Limit Check

After every kill, `CheckFragLimit()` runs:

**FFA mode (Mission1)**:
- If `g_iUseScoreLimit`: check if any player's score >= `fragLimit * 10000`
- Else: check if any player's kills >= `fragLimit`

**Team mode (Mission2/3)**:
- If `g_iUseScoreLimit`: check if any team's score >= `fragLimit * 10000`
- Else: check if any team's kills >= `fragLimit`

If limit reached: `EndGame(END_SCORE_LIMIT_REACHED)` (note: uses score reason even for frag check)

### Score Preservation on Disconnect

When a player disconnects (`ET_NETWORK_DELETE_PLAYER`), their scoring dict entries are **NOT deleted**. If the player reconnects, their previous scores are preserved and synced back.

## Event Handler Registration

### All Modes (MissionShared.Initialize)

```python
ET_NETWORK_MESSAGE_EVENT    → MissionShared.ProcessMessageHandler  # Python-level message dispatch
ET_SCAN                     → MissionShared.ScanHandler            # Bridge scan UI
ET_SUBTITLED_SOUND_DONE     → MissionShared.SoundDoneHandler
```

### Mission1 (FFA)

```python
# Host only:
ET_OBJECT_EXPLODING         → Mission1.ObjectKilledHandler
ET_WEAPON_HIT               → Mission1.DamageEventHandler

# All:
ET_NEW_PLAYER_IN_GAME       → Mission1.NewPlayerHandler
ET_NETWORK_DELETE_PLAYER    → Mission1.DeletePlayerHandler
ET_OBJECT_CREATED_NOTIFY    → Mission1.ObjectCreatedHandler
ET_NETWORK_NAME_CHANGE_EVENT → Mission1.ProcessNameChangeHandler
ET_NETWORK_MESSAGE_EVENT    → Mission1.ProcessMessageHandler        # Mission-specific dispatch
ET_RESTART_GAME             → Mission1.RestartGameHandler           # Per-instance on Mission object
```

### Mission2/3 (Team)

Same as Mission1 but with Mission2/Mission3 module references. No additional event types.

## InitNetwork Sequence

When a new player joins, the C++ NewPlayerInGame handler (FUN_006a1e70) calls `<mission>.InitNetwork(connID)`. This function:

### FFA (Mission1)

1. Send MISSION_INIT_MESSAGE (0x35) with game settings
2. For each player in scoring dicts: send SCORE_MESSAGE (0x37) with their kills/deaths/score

### Team (Mission2/3)

1. Send MISSION_INIT_MESSAGE (0x35) with game settings
2. For each player in scoring dicts: send SCORE_INIT_MESSAGE (0x3F) with kills/deaths/score + team
3. For each team in team score dict: send TEAM_SCORE_MESSAGE (0x40) with team kills/score

## Enemy/Friendly Group Management

### FFA (Mission1)

- All other player ships added to `EnemyGroup`
- No `FriendlyGroup` used
- Rebuilt on every `ObjectCreatedHandler`

### Team (Mission2/3)

- Ships on same team → `FriendlyGroup`
- Ships on different team → `EnemyGroup`
- Team determined from `g_kTeamDictionary[playerID]`
- Local player's team from `Mission2Menus.g_iTeam` / `Mission3Menus.g_iTeam`
- Rebuilt on every `ObjectCreatedHandler`

## Species and Faction Data

### SpeciesToShip (46 entries)

```
ID 0:  UNKNOWN     (null)
ID 1:  AKIRA       Federation  class=1  flyable
ID 2:  AMBASSADOR  Federation  class=1  flyable
...
ID 15: SHUTTLE     Federation  class=1  flyable
ID 16: CARDFREIGHTER  Cardassian  class=1  non-flyable
...
ID 45: BORGCUBE    Borg        class=1  non-flyable
```

MAX_FLYABLE_SHIPS = 16 (IDs 1-15 + CardFreighter at 16 which is technically in the flyable range)
MAX_SHIPS = 46

Faction field: "Federation", "Klingon", "Romulan", "Ferengi", "Cardassian", "Kessok", "Borg", "Neutral"

### Ship Class Modifier Table

```python
g_kModifierTable = (
    (1.0, 1.0, 1.0),   # Class 0 (unknown) attacking class 0/1/2
    (1.0, 1.0, 1.0),   # Class 1 (all stock ships)
    (1.0, 3.0, 1.0))   # Class 2 (none in stock) — 3x bonus killing class 1
```

All stock ships are class 1, so the modifier is always 1.0 in vanilla. The class 2 → class 1 bonus (3.0x) exists for potential modding use but is never triggered.

## Friendly Fire System

```python
App.g_kUtopiaModule.SetFriendlyFireWarningPoints(100)
```

This is a C++ threshold for UI warnings. The actual scoring penalty is implemented in Python: same-team damage is stored as negative values, which reduces the attacker's score.

## Key Addresses

| Address | Name | Role |
|---------|------|------|
| FUN_00504d30 | Settings handler (opcode 0x00) | Stores mission name in VarManager |
| FUN_00504F10 | CreateMultiplayerGame (opcode 0x01) | Creates MultiplayerGame, loads mission |
| FUN_0069e590 | MultiplayerGame constructor | 16 player slots, "NoMe"/"Forward" groups, 26 event handlers |
| FUN_006a1e70 | NewPlayerInGame (opcode 0x2A) | Posts ET_NEW_PLAYER_IN_GAME, calls InitNetwork, replicates objects |
| FUN_006a05e0 | EnterSet (opcode 0x1F) | Map/set transitions, relay if object not found locally |
| FUN_006a0080 | Explosion handler (opcode 0x29) | Wire: [int:targetObjID] [CompressedVec4:pos] [CF16:radius] [CF16:damage] |
| FUN_006a1150 | HostEventHandler | Serializes events → opcode 0x06, sends to "NoMe" group |
| FUN_006a1240 | ObjectExplodingHandler | Serializes explosion → opcode 0x06, sends to "NoMe" group |
| FUN_006f8650 | ReadPythonVariable | Reads Python global variables (used for g_iPlayerLimit) |
| 0x008e5528 | "NoMe" group | Network group: all peers except self |
| 0x008d94a0 | "Forward" group | Network group: all peers including self |

## OpenBC: Relevant for Clean-Room

See `../OpenBC/docs/gamemode-system.md` for the clean-room behavioral spec suitable for reimplementation. The key insight is that gamemodes are **entirely server-side logic** — the server tracks damage, awards kills, computes scores, checks limits, and broadcasts updates. Clients are passive receivers of score data.
