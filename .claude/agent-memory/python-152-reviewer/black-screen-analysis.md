# Black Screen Analysis - Python Angle

## Root Cause Hypothesis
`InitNetwork` crashes because `App.g_kUtopiaModule` is a raw SWIG pointer string,
not a shadow class wrapper. The original game code in InitNetwork calls
`App.g_kUtopiaModule.GetNetwork()` using shadow class method syntax.

## Key Diagnostic
Check `dedicated_init.log` for `">>> InitNetwork called"`:
- Never appears -> C++ not calling InitNetwork (handler registration failed or cached ref)
- Appears + EXCEPTION -> InitNetwork crashing (likely App.g_kUtopiaModule issue)
- Appears + returned OK -> InitNetwork works, problem is elsewhere

## g_bGameStarted Bug
DedicatedServer.py line 949 sets `ms.g_bGameStarted = 1` where `ms = MissionShared`.
Should be set on `MissionMenusShared` instead. `MissionShared` does not define this var.

## Event Handler Registration
MissionShared.SetupEventHandlers registers ET_NETWORK_MESSAGE_EVENT BEFORE the crash
point (GetWarpButton returning None). So the message handler IS registered.

Mission1.SetupEventHandlers registers all handlers including ET_NEW_PLAYER_IN_GAME.
Need to verify this completes without error via the log.

## Client-Side Flow
Client receives MISSION_INIT_MESSAGE -> ProcessMessageHandler -> CreateSystemFromSpecies
-> BuildMission1Menus. Without this message, client shows black screen.
