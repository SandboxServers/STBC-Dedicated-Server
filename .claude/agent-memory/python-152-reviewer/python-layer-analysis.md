# Python Layer Analysis for Dedicated Server Brainstorm

## Date: 2026-02-09
## Context: 7-agent brainstorm evaluating alternative approaches

### Q1: Python vs C++ Game Logic Split
- Combat simulation (physics, damage calc, projectile tracking): C++
- Scoring (who killed whom, damage credit): Python
- Ship creation/configuration: Python calls C++ (App.ShipClass_Create, SetupProperties)
- Network state replication: C++ (FUN_005b17f0 iterates subsystem/weapon lists)
- Game flow (mission init, end game, restart): Python
- UI (all menus, panes, dialogs): Python (100% needs stubbing)

### Q2: SWIG API Surface Count
Key functions used by MP scripts (extracted from grep):
- ~15 global singletons (g_kUtopiaModule, g_kEventManager, g_kSetManager, etc.)
- ~30 creation functions (ShipClass_Create, TGMessage_Create, TGBufferStream, etc.)
- ~20 MultiplayerGame methods (Cast, SetReadyForNewPlayers, GetShipFromPlayerID, etc.)
- ~15 event system functions (AddBroadcastPythonFuncHandler, ProcessEvent, etc.)
- ~10 network functions (GetNetwork, SendTGMessage, GetPlayerList, etc.)
- Total: ~90 SWIG functions actively used by multiplayer Python

### Q3: Minimal Script Set for MP Dedicated Server
Essential (cannot avoid):
1. Multiplayer/MissionShared.py - message constants, event handlers, game flow
2. Multiplayer/MissionMenusShared.py - global state (g_bGameStarted, limits, etc.)
3. Multiplayer/Episode/Episode.py - episode loader
4. Multiplayer/Episode/Mission1/Mission1.py - scoring, InitNetwork, handlers
5. Multiplayer/SpeciesToShip.py - ship type mapping + InitObject (called from C)
6. Multiplayer/SpeciesToSystem.py - system creation
7. Multiplayer/SpeciesToTorp.py - torpedo type mapping + InitObject
8. Multiplayer/Modifier.py - damage scoring multiplier table
9. Systems/Multi1/Multi1.py (+ other system scripts) - set/level creation
10. loadspacehelper.py - ship creation helper
11. MissionLib.py - timer creation, mission utilities
12. ships/*.py - ship stats, model loading, hardpoints

Can be stubbed/eliminated:
- Multiplayer/MultiplayerMenus.py (~1800 lines, 100% UI)
- Multiplayer/Episode/Mission1/Mission1Menus.py (~900 lines, 100% UI)
- LoadBridge.py, Bridge/*.py - bridge crew UI
- DynamicMusic.py - music system
- All Tactical/Interface/*.py - HUD elements
- MainMenu/*.py - main menu system

### Q4: Mock SWIG Feasibility Assessment
VERDICT: Extremely difficult, likely impractical.

The problem is that C++ objects hold internal state that Python reads back:
- pShip.GetHull().GetMaxCondition() - queries C++ object graph
- pNetwork.GetPlayerList().GetNumPlayers() - queries C++ network state
- pSet.IsLocationEmptyTG(kPos, radius, 1) - queries C++ spatial index
- App.g_kUtopiaModule.GetGameTime() - queries C++ clock

You would need to reimplement the entire game object model, not just stub functions.
