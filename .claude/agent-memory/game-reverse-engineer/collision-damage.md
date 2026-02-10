# Bug Analysis: Collision Damage Not Working

## Problem
Collision damage does not work despite DedicatedServer.py setting both global
ProximityManager flags:
- `App.ProximityManager_SetPlayerCollisionsEnabled(1)` (line 512)
- `App.ProximityManager_SetMultiplayerPlayerCollisionsEnabled(1)` (line 518)

## Root Cause: Star System Never Loaded on Server

### The Collision Pipeline
Collision damage in BC works through three layers:
1. **ProximityManager** (C++ engine): Detects object proximity/overlap per-set
   - Requires: global flags enabled + per-set `pSet.SetProximityManagerActive(1)`
   - Computes actual physics damage when objects collide
2. **SetClass** (C++ engine): Container for game objects (ships, asteroids)
   - Each set has its own ProximityManager instance
   - Sets are created by system initialization scripts (e.g., Multi1.py)
3. **Python handlers** (scoring only): ET_WEAPON_HIT, ET_OBJECT_COLLISION
   - These track kills/deaths for scoreboard, NOT actual damage
   - Registered by MissionLib.SetupFriendlyFireNoGameOver()

### Why No System Gets Loaded

In the NORMAL (non-dedicated) host flow:
1. Host clicks Start -> HandleHostStartClicked fires ET_START
2. Player goes to ship selection screen (Mission1Menus)
3. Player picks ship, clicks Ready -> ET_FINISHED_SELECT fires
4. FinishedSelectHandler (Mission1Menus.py:642) calls StartMission()
5. StartMission (Mission1Menus.py:740) calls CreateSystemFromSpecies at line 758
6. CreateSystemFromSpecies loads the system module (e.g., Systems.Multi1.Multi1)
7. Multi1.Initialize() creates SetClass with SetProximityManagerActive(1) + asteroids

In the DEDICATED SERVER flow:
1. DedicatedServer.py stubs ALL MultiplayerMenus functions as noop (lines 792-797):
   ```python
   for fn_name in dir(mm):
       obj = getattr(mm, fn_name)
       if hasattr(obj, 'func_code'):
           setattr(mm, fn_name, _noop_gui)
   ```
2. This stubs HandleStartGame, HandleHostStartClicked, FinishedSelectHandler, etc.
3. DedicatedServer.py fires ET_START (line 966), but HandleStartGame is now a noop
4. Nobody ever fires ET_FINISHED_SELECT on the server
5. StartMission is never called -> CreateSystemFromSpecies is never called
6. No SetClass exists -> no ProximityManager -> no collision detection

### What HandleStartGame Actually Does
HandleStartGame (MultiplayerMenus.py:3018) is mostly UI cleanup:
- Calls pMultWindow.CallNextHandler(pEvent) first
- Clears game list UI elements
- Sets connection timeout to 45 seconds
- It does NOT load the system directly

The system loading happens later via ET_FINISHED_SELECT -> StartMission.
But for a dedicated server (no UI), this event never fires.

### On the CLIENT Side (works correctly)
1. Client receives MISSION_INIT_MESSAGE from server's InitNetwork
2. ProcessMessageHandler (Mission1.py:220) handles it
3. Line 263: `CreateSystemFromSpecies(g_iSystem)` creates the system CLIENT-side
4. BuildMission1Menus() shows ship selection UI
5. Client picks ship -> FinishedSelectHandler -> StartMission (creates ship in set)

## Additional Finding: MissionShared.g_pStartingSet
Even if we load the system, `MissionShared.g_pStartingSet` must be set.
StartMission (Mission1Menus.py:754-759) checks IsHost and sets it:
```python
if (App.g_kUtopiaModule.IsHost()):
    if (not Multiplayer.MissionMenusShared.g_bGameStarted):
        pSet = Multiplayer.SpeciesToSystem.CreateSystemFromSpecies(iSystem)
        Multiplayer.MissionShared.g_pStartingSet = pSet
```

## Recommendation
Add a direct call to CreateSystemFromSpecies in DedicatedServer.py after
Mission1.Initialize() completes and before ET_START fires. Something like:

1. Import Multiplayer.SpeciesToSystem
2. Call CreateSystemFromSpecies(g_iSystem) to load the map
3. Store the returned set in MissionShared.g_pStartingSet
4. This must happen BEFORE players join (before InitNetwork can be called)

The g_iSystem value comes from MissionMenusShared.g_iSystem, which should
already be set by DedicatedServer.py's configuration.

Alternative: Instead of stubbing ALL MultiplayerMenus functions, selectively
stub only the UI functions and leave StartMission/FinishedSelectHandler intact.
However, these functions reference UI elements (pMissionPane, etc.) that don't
exist in headless mode, so they would crash. The direct-call approach is safer.
