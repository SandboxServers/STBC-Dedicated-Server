# SWIG API Reference (Appc module)

## Overview
The game uses SWIG 1.x to bind C++ classes to Python 1.5 as flat C functions on the `Appc` module.
Pattern: `ClassName_MethodName(self, args...)` or `FunctionName(args...)`
All accessible via `import Appc` then `Appc.FunctionName(...)`.

## TGNetwork / TGWinsockNetwork Functions
```
TGNetwork_AddClassHandlers()              # 0 args! Registers class-level handlers
TGNetwork_AddGroup(net, ?)
TGNetwork_Connect(net)                    # Returns 0=success, makes IsHost=1, binds UDP
TGNetwork_CreateLocalPlayer(net, TGString_name)  # Returns player_id. DON'T CALL for hosting!
TGNetwork_DeleteGroup(net, ?)
TGNetwork_DeleteLocalPlayer(net, ?)
TGNetwork_Disconnect(net)
TGNetwork_EnableProfiling(net, ?)
TGNetwork_GetBootReason(net)
TGNetwork_GetCName(net)
TGNetwork_GetConnectStatus(net)           # Returns int (2=hosting, 3=host-active)
TGNetwork_GetEncryptor(net)
TGNetwork_GetGroup(net, ?)
TGNetwork_GetHostID(net)                  # Returns int (1 when hosting)
TGNetwork_GetHostName(net)
TGNetwork_GetIPPacketHeaderSize(net)
TGNetwork_GetLocalID(net)                 # Returns int (1 when hosting)
TGNetwork_GetLocalIPAddress(net)
TGNetwork_GetName(net)
TGNetwork_GetNextMessage(net)             # Returns message or None - USE FOR MANUAL POLLING
TGNetwork_GetNumPlayers(net)
TGNetwork_GetPassword(net)
TGNetwork_GetPlayerList(net)              # Returns '_p_TGPlayerList' object
TGNetwork_GetTGNetworkList(net)
TGNetwork_GetTimeElapsedSinceLastHostPing(net)
TGNetwork_IsHost(net)                     # Returns 1 if hosting
TGNetwork_ReceiveMessageHandler(net, msg?) # Handler for received messages - INVESTIGATE SIGNATURE
TGNetwork_RegisterHandlers()              # 0 args! Registers network handlers
TGNetwork_RegisterMessageType(net, ?)
TGNetwork_SendTGMessage(net, msg?)
TGNetwork_SendTGMessageToGroup(net, group?, msg?)
TGNetwork_SetBootReason(net, reason?)
TGNetwork_SetConnectionTimeout(net, seconds)  # e.g., 30
TGNetwork_SetEncryptor(net, ?)
TGNetwork_SetName(net, TGString)
TGNetwork_SetPassword(net, TGString)
TGNetwork_SetSendTimeout(net, seconds)        # e.g., 30
TGNetwork_Update(net)                     # Main network tick - ReceiveFromSockets → Process → Dispatch

# TGWinsockNetwork-specific:
new_TGWinsockNetwork()                    # Creates new network object
TGWinsockNetwork_SetPortNumber(wsn, port) # e.g., 22000. Expects _p_TGWinsockNetwork type!

# Constants:
TGNetwork_DEFAULT_BOOT
TGNetwork_INCORRECT_PASSWORD
TGNetwork_SERVER_BOOTED_YOU
TGNetwork_TIMED_OUT
TGNetwork_TOO_MANY_PLAYERS
TGNetwork_YOU_ARE_BANNED
TGNetwork_TGNETWORK_GAMESPY_PLAYER_ID
TGNetwork_TGNETWORK_INVALID_ID
TGNetwork_TGNETWORK_MAX_LOG_ENTRIES
TGNetwork_TGNETWORK_MAX_SENDS_PENDING
TGNetwork_TGNETWORK_MAX_SEQUENCE_DIFFERENCE
TGNetwork_TGNETWORK_NULL_ID
```

**IMPORTANT**: After `UtopiaModule_InitializeNetwork()`, the global network is a `_p_TGNetwork` (NOT `_p_TGWinsockNetwork`). Functions like `TGWinsockNetwork_SetPortNumber` expect the WinsockNetwork type and will fail with "Expected _p_TGWinsockNetwork" on the global network.

## Event System Functions
```
TGEvent_Create()                          # Create new event
TGEvent_SetEventType(evt, type_int)       # e.g., App.ET_START = 8388819
TGEvent_SetDestination(evt, target_obj)

TGEventHandlerObject_Cast(obj)            # Cast to event handler object
TGEventHandlerObject_AddPythonFuncHandlerForInstance(eho, evt_type, 'Module.FuncName')
TGEventHandlerObject_AddPythonMethodHandlerForInstance(eho, evt_type, 'Module.FuncName')
TGEventHandlerObject_CallNextHandler(eho, evt)
TGEventHandlerObject_ProcessEvent(eho, evt)  # Dispatches to registered handlers
TGEventHandlerObject_RemoveAllInstanceHandlers(eho)
TGEventHandlerObject_RemoveHandlerForInstance(eho, ?)
delete_TGEventHandlerObject(eho)

TGEventManager_AddBroadcastPythonFuncHandler(em, evt_type, 'Module.FuncName')
TGEventManager_AddBroadcastPythonMethodHandler(em, evt_type, 'Module.FuncName')
TGEventManager_AddEvent(em, evt)
TGEventManager_RemoveAllBroadcastHandlersForObject(em, obj)
TGEventManager_RemoveBroadcastHandler(em, ?)
```

## Game / MultiplayerGame Functions
```
Game_GetCurrentGame()
Game_LoadEpisode(game, TGString_episode)
MultiplayerGame_Cast(game)
MultiplayerGame_Create(game)              # Creates MP game from base game
MultiplayerGame_GetNumberPlayersInGame(mg)
MultiplayerGame_IsReadyForNewPlayers(mg)
MultiplayerGame_SetMaxPlayers(mg, n)
MultiplayerGame_SetReadyForNewPlayers(mg, flag)
new_MultiplayerGame()                     # DON'T USE - needs 1 arg

LoadEpisodeAction_Create(game)
LoadEpisodeAction_Play(lea)
```

## UtopiaModule Functions
```
UtopiaModule_InitializeNetwork(um, wsn, TGString_name)  # 3 args!
UtopiaModule_GetNetwork(um)                # Returns global network (_p_TGNetwork)
UtopiaModule_CreateGameSpy(um, ?)
UtopiaModule_GetCamera(um)
UtopiaModule_GetCaptainName(um)
UtopiaModule_GetCurrentFriendlyFire(um)
UtopiaModule_GetDataPath(um)
UtopiaModule_SetGameName(um, TGString)
# ... many more
```

## Config Functions
```
TGConfigMapping_GetIntValue(cm, section, key)          # 3 args (NOT 4!)
TGConfigMapping_GetStringValue(cm, section, key)
TGConfigMapping_GetTGStringValue(cm, section, key)
TGConfigMapping_GetFloatValue(cm, section, key)
TGConfigMapping_HasValue(cm, section, key)
TGConfigMapping_SetIntValue(cm, section, key, value)
TGConfigMapping_SetStringValue(cm, section, key, value)
TGConfigMapping_SetTGStringValue(cm, section, key, TGString)
TGConfigMapping_SetFloatValue(cm, section, key, value)
TGConfigMapping_LoadConfigFile(cm, filename)
TGConfigMapping_SaveConfigFile(cm, filename)
```

## VarManager Functions
```
VarManagerClass_SetStringVariable(vm, scope, key, TGString_val)  # Note: VarManagerClass_ prefix!
VarManagerClass_SetFloatVariable(vm, scope, key, float_val)
VarManagerClass_GetStringVariable(vm, scope, key)
VarManagerClass_GetFloatVariable(vm, scope, key)
VarManagerClass_DeleteAllScopedVariables(vm, scope)
VarManagerClass_DeleteAllVariables(vm)
VarManagerClass_MakeEpisodeEventType(vm, ?)
```

## TopWindow Functions
```
TopWindow_GetTopWindow()
TopWindow_Initialize(tw)
# Child windows accessed via:
# tw.FindMainWindow(App.MWT_MULTIPLAYER)  # MWT_8 = MultiplayerWindow
```

## TGString
```
new_TGString('text')                      # Create new string
```

## Key Event Type Constants (App.ET_*)
- `ET_START` = 8388819 (0x800053)
- `ET_CREATE_SERVER` = 8388810 (0x80004A)
- `ET_CHECKSUM_COMPLETE`
- `ET_SYSTEM_CHECKSUM_COMPLETE`
- `ET_SYSTEM_CHECKSUM_FAILED`
- `ET_NETWORK_NEW_PLAYER`
- `ET_NETWORK_DELETE_PLAYER`
- `ET_NETWORK_MESSAGE_EVENT`
- `ET_NETWORK_CONNECT_EVENT`
- `ET_NETWORK_DISCONNECT_EVENT`
- `ET_LOAD_EPISODE`
- `ET_KILL_GAME`
- Event type 0x60001 = ReceiveMessageHandler events (from dequeue loop)

## App Module Globals (registered by register_globals)
```python
App.g_kConfigMapping   # SWIG ptr to TGConfigMapping
App.g_kUtopiaModule    # SWIG ptr to UtopiaModule
App.g_kVarManager      # SWIG ptr to VarManagerClass
App.g_kEventManager    # SWIG ptr to TGEventManager
```

## Condition Handler Functions
```
TGConditionHandler_AddCondition(ch, ?)
TGConditionHandler_ConditionChanged(ch, ?)
TGConditionHandler_RemoveCondition(ch, ?)
TGCondition_AddHandler(cond, ?)
TGCondition_RemoveHandler(cond, ?)
```
