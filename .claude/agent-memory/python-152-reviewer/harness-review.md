# DedicatedServer.py Harness Review - 2026-02-07

## Summary
Comprehensive review of initialization sequence, collision damage pipeline, MissionShared.Initialize
crash impact, InitNetwork correctness, and Python 1.5.2 compliance.

## 1. Initialization Sequence Analysis

### Current Order (TopWindowInitialized)
1. Set UtopiaModule flags (multiplayer, host, not client)
2. Check network status
3. Load episode + mission into Game object
4. Store g_kUtopiaModule on Appc
5. Set MissionMenusShared variables (system, timelimit, fraglimit, playerlimit)
6. Set game name on UtopiaModule + TGNetwork
7. Set captain name
8. Enable packet processing
9. Set collision flags (ProximityManager)
10. Set difficulty
11. Set connection timeout
12. Set friendly fire warning points
13. Create GameSpy
14. Pre-import modules, stub GUI functions, wrap handlers
15. Call Mission1.Initialize(pMission) -> calls MissionShared.Initialize
16. Fire ET_START event
17. Set ms.g_bGameStarted = 1 (BUG: wrong module)
18. Replace InitNetwork with functional-API version
19. Wrap ProcessMessageHandler

### Issues with Order
- **g_bGameStarted on wrong module** (see Bug #1 below)
- **Missing CreateTimeLeftTimer** - Normal flow calls this in StartMission for timed games
- **Missing g_pStartingSet creation** - Normal flow calls CreateSystemFromSpecies in StartMission
- Otherwise the ordering is reasonable for headless mode

### What Normal Game Flow Does (that we skip)
1. MainMenu loads Options.cfg -> sets collision/difficulty/etc (we do this manually - OK)
2. Player enters multiplayer lobby -> MultiplayerMenus builds UI (we skip UI - OK)
3. Host selects system/timelimit/fraglimit -> stored in MissionMenusShared (we set directly - OK)
4. Host clicks Start -> ET_START fires -> Mission1.Initialize called (we do this - OK)
5. **Host selects ship -> FinishedSelectHandler -> StartMission called** (we SKIP this)
6. StartMission calls CreateSystemFromSpecies -> g_pStartingSet set (we SKIP this)
7. StartMission sets g_bGameStarted=1 on MissionMenusShared (we set on WRONG module)
8. StartMission calls CreateTimeLeftTimer for timed games (we SKIP this)

## 2. Critical Bugs

### Bug #1: g_bGameStarted Set on Wrong Module
**File:** `src/scripts/Custom/DedicatedServer.py` line 987
**Code:** `ms.g_bGameStarted = 1` where `ms = sys.modules['Multiplayer.MissionShared']`
**Should be:** `mms.g_bGameStarted = 1` where `mms = sys.modules['Multiplayer.MissionMenusShared']`

The `g_bGameStarted` variable is defined on `MissionMenusShared` (line 208 of that file).
It is READ by `Mission1Menus.StartMission` at line 757 to decide whether to create a new
star system set or reuse the existing one. Setting it on MissionShared creates a new
attribute that nothing reads.

**Impact:** If StartMission is ever invoked (e.g., by a future ship-select flow), the
system set gets re-created every time instead of being reused. Currently low impact since
the dedicated server never calls StartMission, but it's semantically wrong.

### Bug #2: InitNetwork Missing SCORE_MESSAGE Section
**File:** `src/scripts/Custom/DedicatedServer.py` lines 1012-1071
The replacement `_ds_InitNetwork` only sends a `MISSION_INIT_MESSAGE` to the joining player.

The **original** `Mission1.InitNetwork` (lines 337-449 of Mission1.py) sends TWO things:
1. MISSION_INIT_MESSAGE (player limit, system, time limit, frag limit)
2. For EACH player key in kills/deaths/scores dicts: a SCORE_MESSAGE packet

The SCORE_MESSAGE section (lines 386-448) loops over all tracked players and sends their
current kills/deaths/score to the joining player so they see an accurate scoreboard.

**Impact:** When a player joins mid-game, they will see everyone at 0 kills/deaths/score
until the next score change event. This is a functional bug but not a crash.

### Bug #3: Missing g_pStartingSet / CreateSystemFromSpecies
The dedicated server never calls `CreateSystemFromSpecies` to create the star system.
In normal flow, this happens in `StartMission` (called when host finishes ship select).

The **client** creates its own system set when it receives `MISSION_INIT_MESSAGE` (line 263
of Mission1.py: `MissionShared.g_pStartingSet = SpeciesToSystem.CreateSystemFromSpecies(...)`).

**Impact on server:** `MissionShared.g_pStartingSet` stays None on the server. This means:
- No "Set" (star system) exists on the server for ships to be placed into
- When a client's ship is network-replicated to the server, there may be no set to hold it
- Score tracking might still work (DamageEventHandler gets events from the engine)
- But any server-side code that calls `MissionLib.GetMission().GetStartingSet()` could fail

### Bug #4: Missing CreateTimeLeftTimer for Timed Games
If `SERVER_TIME_LIMIT != -1`, the server should call `MissionShared.CreateTimeLeftTimer()` to
start a countdown timer. Currently this never happens.

In normal flow, `Mission1Menus.StartMission` line 869-870 does this:
```python
if (Multiplayer.MissionMenusShared.g_iTimeLimit != -1):
    Multiplayer.MissionShared.CreateTimeLeftTimer(Multiplayer.MissionMenusShared.g_iTimeLimit * 60)
```

**Impact:** Timed games will never end due to time expiry on the server. The `g_iTimeLeft`
value sent to clients in InitNetwork will be 0.0 (the initial value), which is wrong.
Since SERVER_TIME_LIMIT defaults to -1, this only matters if someone enables time limits.

## 3. Collision Damage Analysis

### How Collision Damage Works in Normal MP
Collision damage in multiplayer is tracked through two event handler chains:

**Chain 1: Weapon hit damage tracking (host only)**
- `Mission1.SetupEventHandlers` registers `ET_WEAPON_HIT -> DamageEventHandler` (line 196)
- `DamageEventHandler` records damage per-player in `g_kDamageDictionary`
- This runs ONLY on the host (`if (App.g_kUtopiaModule.IsHost())` guard at line 193)

**Chain 2: Object explosion scoring (host only)**
- `Mission1.SetupEventHandlers` registers `ET_OBJECT_EXPLODING -> ObjectKilledHandler` (line 195)
- `ObjectKilledHandler` awards kills/deaths, sends SCORE_CHANGE_MESSAGE to all clients

**Chain 3: Friendly fire warning (all players)**
- `MissionShared.Initialize` line 151 calls `MissionLib.SetupFriendlyFireNoGameOver()`
- This registers `ET_WEAPON_HIT -> FriendlyFireHandler` (tracks damage to friendly ships)
- Also registers `ET_FRIENDLY_FIRE_REPORT -> FriendlyFireWarningHandler` (shows warning text)
- This is CLIENT-SIDE only (checks if local player is the attacker)

### What the Dedicated Server Does
- `Mission1.SetupEventHandlers` IS called (via Mission1.Initialize line 173)
- The handler is wrapped in try/except but the core registrations (lines 195-204) should succeed
- DamageEventHandler and ObjectKilledHandler should be registered on the host

### What Could Be Wrong with Collisions
The `DamageEventHandler` and `ObjectKilledHandler` depend on:
1. Ships existing as objects in a Set (for GetDestination, ShipClass_Cast, etc.)
2. Ships having `IsPlayerShip()` return true
3. Ships having valid `GetNetPlayerID()` and `GetObjID()`
4. `g_kDamageDictionary`, `g_kKillsDictionary`, `g_kDeathsDictionary` being populated

Since the server never creates a star system Set (Bug #3), ships may not be properly
registered. The engine creates ship objects via network replication, but they need to be
in a Set to participate in proximity/collision detection.

**Root cause hypothesis:** Without `g_pStartingSet` being created on the server via
`CreateSystemFromSpecies`, there is no Set for ships to exist in on the server side.
The ProximityManager flags are set (collisions enabled), but if ships aren't in a proper
Set, the collision system may never fire ET_WEAPON_HIT events.

### The MissionLib Stub Red Herring
Lines 815-821 stub `SetupFriendlyFireNoGameOver` if it's NOT found on MissionLib.
But `MissionLib.SetupFriendlyFireNoGameOver` DOES exist (it's defined at line 3605).
So the stub condition `if not hasattr(ml, fn_name)` is False, and the stub is never applied.
The real function runs normally via `MissionShared.Initialize`.

## 4. MissionShared.Initialize Crash Analysis

### What Executes Before the Crash (line 173)
```python
def Initialize(pMission):
    import Multiplayer.MultiplayerMenus       # line 144 - OK (module loads)
    import LoadBridge                          # line 145 - OK
    import MissionLib                          # line 146 - OK
    LoadBridge.CreateCharacterMenus()          # line 148 - STUBBED (noop)
    MissionLib.SetupFriendlyFireNoGameOver()   # line 151 - EXECUTES (registers FF handlers)
    App.g_kUtopiaModule.SetFriendlyFireWarningPoints(100)  # line 152 - EXECUTES
    g_pDatabase = App.g_kLocalizationManager.Load(...)     # line 160 - EXECUTES
    g_pShipDatabase = App.g_kLocalizationManager.Load(...) # line 161 - EXECUTES
    g_pSystemDatabase = App.g_kLocalizationManager.Load(...)# line 162 - EXECUTES
    SetupEventHandlers(pMission)               # line 165 - EXECUTES (registers ET_NETWORK_MESSAGE_EVENT etc)
    g_idTimeLeftTimer = App.NULL_ID            # line 168 - EXECUTES
    g_bGameOver = 0                            # line 171 - EXECUTES
    Multiplayer.MultiplayerMenus.g_bExitPressed = 0  # line 173 - CRASHES HERE
```

### What's Lost After Crash
```python
    # These lines never execute:
    pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
    pGame = App.Game_GetCurrentGame()
    pGame.LoadDatabaseSoundInGroup(pDatabase, "MiguelScan", "BridgeGeneric")
    pGame.LoadDatabaseSoundInGroup(pDatabase, "gs038", "BridgeGeneric")
    App.g_kLocalizationManager.Unload(pDatabase)
```

### Impact Assessment
- **g_bExitPressed = 0**: Cosmetic. Only used by exit button handler in MultiplayerMenus.
  Server doesn't have an exit button.
- **Sound database loading**: Cosmetic. Server doesn't play sounds. The scan handler
  would fail if someone scans, but that's a client-side action.
- **ALL critical items execute**: Database loads, event handler registration, game over flag,
  timer init all happen before the crash point.

**Verdict:** The crash is benign. Everything critical is initialized before line 173.

## 5. Python 1.5.2 Compliance

Quick scan of the current DedicatedServer.py found NO Python 1.5.2 compatibility issues.
All constructs used are valid:
- `strop` module for string operations
- `dict.has_key()` for membership testing
- `except Exception, e:` syntax
- `count = count + 1` (no augmented assignment)
- No list comprehensions, no True/False, no string methods
- `print` as statement
- Proper `*args` in function definitions
- `sys.exc_info()` available in 1.5.2
