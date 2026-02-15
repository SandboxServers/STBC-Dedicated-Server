###############################################################################
#   DSNetHandlers.py - Network handler replacements for dedicated server
#
#   Replaces Mission1.InitNetwork with functional-API version,
#   wraps ProcessMessageHandler with logging, patches
#   SpeciesToShip.InitObject with tracing, and provides headless-safe
#   ObjectKilledHandler, EndGame, and RestartGame.
#
#   Python 1.5 compatible.
###############################################################################
import App
import Appc
import sys

def _log(msg):
    """Delegate to DedicatedServer._log via sys.modules."""
    ds = sys.modules.get('Custom.DedicatedServer')
    if ds and hasattr(ds, '_log'):
        ds._log(msg)

###############################################################################
#   ObjectKilledHandler - headless scoring via Appc functional API
#
#   Stock Mission1.ObjectKilledHandler uses shadow class methods
#   (pMessage.SetGuaranteed, App.TGBufferStream()) which fail headless.
#   This replacement uses Appc functional API exclusively.
#
#   Registered on ET_OBJECT_EXPLODING by _headless_ms_seh in DedicatedServer.py.
###############################################################################
_last_killed_objID = [0]  # mutable container for dedup (2x dispatch)

def _ds_ObjectKilledHandler(pObject, pEvent):
    try:
        __import__('Multiplayer.MissionShared')
        _ms = sys.modules['Multiplayer.MissionShared']
        if _ms.g_bGameOver:
            return

        _m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']

        # Get attacker player ID from event.
        # Use Appc functional API to avoid shadow class issues in headless mode.
        iFiringPlayerID = Appc.ObjectExplodingEvent_GetFiringPlayerID(pEvent)

        # Get killed object via Appc (pEvent may be raw SWIG pointer)
        pKilledObject = Appc.TGEvent_GetDestination(pEvent)
        if not pKilledObject:
            return
        if not Appc.TGObject_IsTypeOf(pKilledObject, App.CT_SHIP):
            return
        pShip = App.ShipClass_Cast(pKilledObject)
        if Appc.ShipClass_IsPlayerShip(pShip) == 0:
            return

        iKilledPlayerID = Appc.ShipClass_GetNetPlayerID(pShip)
        iShipID = Appc.TGObject_GetObjID(pShip)

        # Dedup: events fire twice due to double dispatch
        # (UTOPIA_MAIN_TICK + TGNetwork_Update process same event).
        if iShipID == _last_killed_objID[0]:
            return
        _last_killed_objID[0] = iShipID

        _log(">>> ObjectKilledHandler: killer=%d victim=%d shipID=%d" %
             (iFiringPlayerID, iKilledPlayerID, iShipID))

        # Update kills
        iKills = 0
        if iFiringPlayerID != 0:
            if _m1.g_kKillsDictionary.has_key(iFiringPlayerID):
                iKills = _m1.g_kKillsDictionary[iFiringPlayerID]
            iKills = iKills + 1
            _m1.g_kKillsDictionary[iFiringPlayerID] = iKills

        # Update deaths
        iDeaths = 0
        if _m1.g_kDeathsDictionary.has_key(iKilledPlayerID):
            iDeaths = _m1.g_kDeathsDictionary[iKilledPlayerID]
        iDeaths = iDeaths + 1
        _m1.g_kDeathsDictionary[iKilledPlayerID] = iDeaths

        # Compute score from damage dictionary
        iScoreUpdateCount = 0
        iFiringPlayerScore = 0
        pDamageByDict = None
        if iShipID != App.NULL_ID:
            if _m1.g_kDamageDictionary.has_key(iShipID):
                pDamageByDict = _m1.g_kDamageDictionary[iShipID]

        if pDamageByDict:
            for iPlayerID in pDamageByDict.keys():
                pDamageList = pDamageByDict[iPlayerID]
                fDamageDone = (pDamageList[0] + pDamageList[1]) / 10.0
                fScore = 0.0
                if _m1.g_kScoresDictionary.has_key(iPlayerID):
                    fScore = _m1.g_kScoresDictionary[iPlayerID]
                fScore = fScore + fDamageDone
                if iPlayerID == iFiringPlayerID:
                    iFiringPlayerScore = int(fScore)
                else:
                    iScoreUpdateCount = iScoreUpdateCount + 1
                _m1.g_kScoresDictionary[iPlayerID] = int(fScore)

        _log("  kills=%d deaths=%d firingScore=%d scoreUpdates=%d" %
             (iKills, iDeaths, iFiringPlayerScore, iScoreUpdateCount))

        # Build SCORE_CHANGE_MESSAGE via Appc functional API
        pNetwork = App.UtopiaModule_GetNetwork(App.g_kUtopiaModule)
        if not pNetwork:
            _log("  ObjectKilledHandler: no network")
            return

        pMessage = Appc.TGMessage_Create()
        Appc.TGMessage_SetGuaranteed(pMessage, 1)
        kStream = Appc.new_TGBufferStream()
        Appc.TGBufferStream_OpenBuffer(kStream, 256)

        # Message type
        Appc.TGBufferStream_WriteChar(kStream, chr(_ms.SCORE_CHANGE_MESSAGE))
        # Killer ID
        Appc.TGBufferStream_WriteLong(kStream, iFiringPlayerID)
        if iFiringPlayerID != 0:
            Appc.TGBufferStream_WriteLong(kStream, iKills)
            Appc.TGBufferStream_WriteLong(kStream, iFiringPlayerScore)
        # Killed player ID
        Appc.TGBufferStream_WriteLong(kStream, iKilledPlayerID)
        Appc.TGBufferStream_WriteLong(kStream, iDeaths)

        # Score update count and per-player scores
        Appc.TGBufferStream_WriteChar(kStream, chr(iScoreUpdateCount))
        _iCount = 0
        if pDamageByDict:
            for iPlayerID in pDamageByDict.keys():
                if iPlayerID != iFiringPlayerID and iPlayerID != 0:
                    Appc.TGBufferStream_WriteLong(kStream, iPlayerID)
                    _pScore = 0
                    if _m1.g_kScoresDictionary.has_key(iPlayerID):
                        _pScore = _m1.g_kScoresDictionary[iPlayerID]
                    Appc.TGBufferStream_WriteLong(kStream, _pScore)
                    _iCount = _iCount + 1
        # Filler for any missing entries
        while _iCount < iScoreUpdateCount:
            Appc.TGBufferStream_WriteLong(kStream, 0)
            _iCount = _iCount + 1

        Appc.TGMessage_SetDataFromStream(pMessage, kStream)
        pNetwork = App.UtopiaModule_GetNetwork(App.g_kUtopiaModule)
        Appc.TGNetwork_SendTGMessageToGroup(pNetwork, "NoMe", pMessage)
        Appc.TGBufferStream_CloseBuffer(kStream)

        # Clear damage dictionary for dead ship
        if iShipID != App.NULL_ID:
            if _m1.g_kDamageDictionary.has_key(iShipID):
                del _m1.g_kDamageDictionary[iShipID]

        _log("  SCORE_CHANGE_MESSAGE sent OK")

        # Check frag limit
        _ds_CheckFragLimit()
    except:
        ei = sys.exc_info()
        _log(">>> ObjectKilledHandler EXCEPT: %s: %s" % (str(ei[0]), str(ei[1])))

###############################################################################
#   CheckFragLimit - check if frag/score limit reached, end game if so
###############################################################################
def _ds_CheckFragLimit():
    try:
        __import__('Multiplayer.MissionShared')
        __import__('Multiplayer.MissionMenusShared')
        _ms = sys.modules['Multiplayer.MissionShared']
        _mms = sys.modules['Multiplayer.MissionMenusShared']
        _m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']

        if _ms.g_bGameOver:
            return

        iFragLimit = _mms.g_iFragLimit
        if iFragLimit == -1:
            return

        bOver = 0
        if _mms.g_iUseScoreLimit:
            for iKey in _m1.g_kScoresDictionary.keys():
                if _m1.g_kScoresDictionary[iKey] >= iFragLimit * 10000:
                    bOver = 1
                    break
        else:
            for iKey in _m1.g_kKillsDictionary.keys():
                if _m1.g_kKillsDictionary[iKey] >= iFragLimit:
                    bOver = 1
                    break

        if bOver:
            _log(">>> CheckFragLimit: limit reached, ending game")
            _ds_EndGame(_ms.END_SCORE_LIMIT_REACHED)
    except:
        ei = sys.exc_info()
        _log(">>> CheckFragLimit EXCEPT: %s: %s" % (str(ei[0]), str(ei[1])))

###############################################################################
#   EndGame - headless-safe game end via Appc functional API
#
#   Stock MissionShared.EndGame uses shadow class methods. This replacement
#   sends END_GAME_MESSAGE via Appc, sets g_bGameOver, disables new players.
###############################################################################
def _ds_EndGame(iReason=0):
    try:
        __import__('Multiplayer.MissionShared')
        _ms = sys.modules['Multiplayer.MissionShared']

        _log(">>> EndGame: iReason=%d" % iReason)

        pNetwork = App.UtopiaModule_GetNetwork(App.g_kUtopiaModule)
        if not pNetwork:
            _log("  EndGame: no network")
            return

        pMessage = Appc.TGMessage_Create()
        Appc.TGMessage_SetGuaranteed(pMessage, 1)
        kStream = Appc.new_TGBufferStream()
        Appc.TGBufferStream_OpenBuffer(kStream, 256)
        Appc.TGBufferStream_WriteChar(kStream, chr(_ms.END_GAME_MESSAGE))
        Appc.TGBufferStream_WriteInt(kStream, iReason)
        Appc.TGMessage_SetDataFromStream(pMessage, kStream)
        Appc.TGNetwork_SendTGMessage(pNetwork, 0, pMessage)
        Appc.TGBufferStream_CloseBuffer(kStream)

        _ms.g_bGameOver = 1

        # Disable new players
        pGame = App.MultiplayerGame_Cast(App.Game_GetCurrentGame())
        if pGame is not None:
            App.MultiplayerGame_SetReadyForNewPlayers(pGame, 0)

        _log("  END_GAME_MESSAGE sent, g_bGameOver=1, ReadyForNewPlayers=0")
    except:
        ei = sys.exc_info()
        _log(">>> EndGame EXCEPT: %s: %s" % (str(ei[0]), str(ei[1])))

###############################################################################
#   RestartGame - headless-safe game restart
#
#   Resets scoring dicts, clears game-over, re-enables new players,
#   sends RESTART_GAME_MESSAGE to all clients.
###############################################################################
def _ds_RestartGame():
    try:
        __import__('Multiplayer.MissionShared')
        __import__('Multiplayer.MissionMenusShared')
        _ms = sys.modules['Multiplayer.MissionShared']
        _mms = sys.modules['Multiplayer.MissionMenusShared']
        _m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']

        _log(">>> RestartGame")

        # Reset scoring dicts (keep keys, zero values)
        for iKey in _m1.g_kKillsDictionary.keys():
            _m1.g_kKillsDictionary[iKey] = 0
        for iKey in _m1.g_kDeathsDictionary.keys():
            _m1.g_kDeathsDictionary[iKey] = 0
        for iKey in _m1.g_kScoresDictionary.keys():
            _m1.g_kScoresDictionary[iKey] = 0
        for iKey in _m1.g_kDamageDictionary.keys():
            _m1.g_kDamageDictionary[iKey] = 0

        # Clear game-over flag
        _ms.g_bGameOver = 0

        # Reset time limit
        if _mms.g_iTimeLimit != -1:
            _ms.g_iTimeLeft = _mms.g_iTimeLimit * 60

        # Re-enable new players
        pGame = App.MultiplayerGame_Cast(App.Game_GetCurrentGame())
        if pGame is not None:
            App.MultiplayerGame_SetReadyForNewPlayers(pGame, 1)

        # Send RESTART_GAME_MESSAGE to all
        pNetwork = App.UtopiaModule_GetNetwork(App.g_kUtopiaModule)
        if pNetwork:
            pMessage = Appc.TGMessage_Create()
            Appc.TGMessage_SetGuaranteed(pMessage, 1)
            kStream = Appc.new_TGBufferStream()
            Appc.TGBufferStream_OpenBuffer(kStream, 256)
            Appc.TGBufferStream_WriteChar(kStream, chr(_ms.RESTART_GAME_MESSAGE))
            Appc.TGMessage_SetDataFromStream(pMessage, kStream)
            Appc.TGNetwork_SendTGMessage(pNetwork, 0, pMessage)
            Appc.TGBufferStream_CloseBuffer(kStream)
            _log("  RESTART_GAME_MESSAGE sent")

        _log("  RestartGame OK: scores reset, g_bGameOver=0, ReadyForNewPlayers=1")
    except:
        ei = sys.exc_info()
        _log(">>> RestartGame EXCEPT: %s: %s" % (str(ei[0]), str(ei[1])))

def _init_network_handlers():
    """Replace InitNetwork, wrap ProcessMessageHandler, patch SpeciesToShip."""
    # --- Replace InitNetwork with functional-API version ---
    # The original Mission1.InitNetwork uses shadow class methods like
    # pMessage.SetGuaranteed(1) which fail when App.TGMessage_Create()
    # returns a raw SWIG pointer string instead of a shadow class instance.
    # This replacement uses Appc functional API directly to avoid the issue.
    try:
        import Appc
        __import__('Multiplayer.Episode.Mission1.Mission1')
        _m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']
        __import__('Multiplayer.MissionShared')
        __import__('Multiplayer.MissionMenusShared')
        _ms = sys.modules['Multiplayer.MissionShared']
        _mms = sys.modules['Multiplayer.MissionMenusShared']

        def _ds_InitNetwork(iToID, _logfn=_log, _App=App, _Appc=Appc,
                            _ms=_ms, _mms=_mms, _m1=_m1):
            _logfn(">>> InitNetwork called: iToID=%s" % str(iToID))
            # Clear _initobj_done so DeferredInitObject re-runs for this player.
            # Handles reconnects (same peerID) and ship changes.
            _ds = sys.modules.get('Custom.DedicatedServer')
            if _ds:
                if hasattr(_ds, '_initobj_done') and _ds._initobj_done.has_key(iToID):
                    del _ds._initobj_done[iToID]
                    _logfn(">>> InitNetwork: cleared _initobj_done[%s]" % str(iToID))
                if hasattr(_ds, '_initobj_dead') and _ds._initobj_dead.has_key(iToID):
                    del _ds._initobj_dead[iToID]
                    _logfn(">>> InitNetwork: cleared _initobj_dead[%s]" % str(iToID))
                if hasattr(_ds, '_initobj_known') and _ds._initobj_known.has_key(iToID):
                    del _ds._initobj_known[iToID]
                    _logfn(">>> InitNetwork: cleared _initobj_known[%s]" % str(iToID))
                if hasattr(_ds, '_initobj_poll_count') and _ds._initobj_poll_count.has_key(iToID):
                    _ds._initobj_poll_count[iToID] = 0
            try:
                # Get network via functional API
                pNetwork = _App.UtopiaModule_GetNetwork(_App.g_kUtopiaModule)
                if not pNetwork:
                    _logfn(">>> InitNetwork: no network, bailing")
                    return
                _logfn(">>> InitNetwork: network=%s" % str(pNetwork))

                # Create message via raw Appc (avoids shadow class issue)
                pMessage = _Appc.TGMessage_Create()
                _logfn(">>> InitNetwork: msg=%s type=%s" %
                       (str(pMessage), str(type(pMessage))))
                _Appc.TGMessage_SetGuaranteed(pMessage, 1)

                # Create buffer stream via raw Appc
                kStream = _Appc.new_TGBufferStream()
                _Appc.TGBufferStream_OpenBuffer(kStream, 256)

                # Write MISSION_INIT_MESSAGE header
                _Appc.TGBufferStream_WriteChar(kStream,
                    chr(_ms.MISSION_INIT_MESSAGE))
                _Appc.TGBufferStream_WriteChar(kStream,
                    chr(_mms.g_iPlayerLimit))
                _Appc.TGBufferStream_WriteChar(kStream,
                    chr(_mms.g_iSystem))

                # Time limit
                if _mms.g_iTimeLimit == -1:
                    _Appc.TGBufferStream_WriteChar(kStream, chr(255))
                else:
                    _Appc.TGBufferStream_WriteChar(kStream,
                        chr(_mms.g_iTimeLimit))
                    gameTime = _App.UtopiaModule_GetGameTime(
                        _App.g_kUtopiaModule)
                    _Appc.TGBufferStream_WriteInt(kStream,
                        _ms.g_iTimeLeft + int(gameTime))

                # Frag limit
                if _mms.g_iFragLimit == -1:
                    _Appc.TGBufferStream_WriteChar(kStream, chr(255))
                else:
                    _Appc.TGBufferStream_WriteChar(kStream,
                        chr(_mms.g_iFragLimit))

                # Attach data to message and send
                _Appc.TGMessage_SetDataFromStream(pMessage, kStream)
                _Appc.TGNetwork_SendTGMessage(pNetwork, iToID, pMessage)
                _Appc.TGBufferStream_CloseBuffer(kStream)

                _logfn(">>> InitNetwork: MISSION_INIT_MESSAGE sent OK")

                # Send current scores to joining player (SCORE_MESSAGE)
                # Builds merged key set from kills/deaths/scores dicts,
                # sends one message per player with their current stats.
                _kKills = _m1.g_kKillsDictionary
                _kDeaths = _m1.g_kDeathsDictionary
                _kScores = _m1.g_kScoresDictionary
                _pDict = {}
                for _ik in _kKills.keys():
                    _pDict[_ik] = 1
                for _ik in _kDeaths.keys():
                    _pDict[_ik] = 1
                for _ik in _kScores.keys():
                    _pDict[_ik] = 1
                _scoreCount = 0
                for _ik in _pDict.keys():
                    _iKills = 0
                    _iDeaths = 0
                    _iScore = 0
                    if _kKills.has_key(_ik):
                        _iKills = _kKills[_ik]
                    if _kDeaths.has_key(_ik):
                        _iDeaths = _kDeaths[_ik]
                    if _kScores.has_key(_ik):
                        _iScore = _kScores[_ik]
                    _sMsg = _Appc.TGMessage_Create()
                    _Appc.TGMessage_SetGuaranteed(_sMsg, 1)
                    _sStream = _Appc.new_TGBufferStream()
                    _Appc.TGBufferStream_OpenBuffer(_sStream, 256)
                    _Appc.TGBufferStream_WriteChar(_sStream,
                        chr(_ms.SCORE_MESSAGE))
                    _Appc.TGBufferStream_WriteLong(_sStream, _ik)
                    _Appc.TGBufferStream_WriteLong(_sStream, _iKills)
                    _Appc.TGBufferStream_WriteLong(_sStream, _iDeaths)
                    _Appc.TGBufferStream_WriteLong(_sStream, _iScore)
                    _Appc.TGMessage_SetDataFromStream(_sMsg, _sStream)
                    _Appc.TGNetwork_SendTGMessage(pNetwork, iToID, _sMsg)
                    _Appc.TGBufferStream_CloseBuffer(_sStream)
                    _scoreCount = _scoreCount + 1
                if _scoreCount > 0:
                    _logfn(">>> InitNetwork: sent %d SCORE_MESSAGEs" %
                           _scoreCount)

            except:
                ei = sys.exc_info()
                _logfn(">>> InitNetwork EXCEPTION: %s: %s" %
                       (str(ei[0]), str(ei[1])))

        _m1.InitNetwork = _ds_InitNetwork
        _log("  Replaced InitNetwork with functional-API version")
    except:
        ei = sys.exc_info()
        _log("  InitNetwork replace FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

    # --- Also wrap ProcessMessageHandler for server-side diagnostics ---
    try:
        _m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']
        if hasattr(_m1, 'ProcessMessageHandler'):
            _orig_pmh = _m1.ProcessMessageHandler
            def _logged_pmh(self, pEvent, _orig=_orig_pmh, _logfn=_log):
                _logfn(">>> ProcessMessageHandler called on server")
                try:
                    return _orig(self, pEvent)
                except:
                    ei = sys.exc_info()
                    _logfn(">>> ProcessMessageHandler EXCEPTION: %s: %s" %
                           (str(ei[0]), str(ei[1])))
            _m1.ProcessMessageHandler = _logged_pmh
            _log("  Wrapped ProcessMessageHandler with logging")
    except:
        ei = sys.exc_info()
        _log("  ProcessMessageHandler wrap FAILED: %s: %s" %
             (str(ei[0]), str(ei[1])))

    # ---------------------------------------------------------------
    # Monkey-patch SpeciesToShip.InitObject to trace ship creation.
    # The C engine calls InitObject(self, iType) when a ship object
    # arrives over the network. We need to know if it's called at all
    # and where it fails on the headless server.
    # ---------------------------------------------------------------
    try:
        _sts_temp = __import__("Multiplayer.SpeciesToShip")
        _sts_mod = sys.modules["Multiplayer.SpeciesToShip"]
        # Ensure parent package has the attribute (ships/*.py do
        # "import Multiplayer.SpeciesToShip" then access constants)
        _mp_pkg = sys.modules.get('Multiplayer', None)
        if _mp_pkg is not None:
            setattr(_mp_pkg, 'SpeciesToShip', _sts_mod)
        _orig_InitObject = _sts_mod.InitObject
        _orig_GetShipFromSpecies = _sts_mod.GetShipFromSpecies

        def _wrapped_InitObject(self, iType,
                _origIO=_orig_InitObject,
                _origGSFS=_orig_GetShipFromSpecies,
                _logfn=_log):
            _logfn(">>> SpeciesToShip.InitObject(self=%s, iType=%d)" % (str(self), iType))
            try:
                kStats = _origGSFS(iType)
                _logfn("  GetShipFromSpecies -> %s" % str(kStats))
            except:
                ei = sys.exc_info()
                _logfn("  GetShipFromSpecies FAILED: %s: %s" % (str(ei[0]), str(ei[1])))
            try:
                iResult = _origIO(self, iType)
                _logfn("  Native InitObject returned %s" % str(iResult))
            except:
                ei = sys.exc_info()
                _logfn("  Native InitObject FAILED: %s: %s" % (str(ei[0]), str(ei[1])))
                _logfn("<<< InitObject done (FAIL)")
                return 0

            try:
                pPropertySet = self.GetPropertySet()
                _logfn("  GetPropertySet(after native) -> %s" % str(pPropertySet))
            except:
                ei = sys.exc_info()
                _logfn("  GetPropertySet(after native) FAILED: %s: %s" %
                     (str(ei[0]), str(ei[1])))

            _logfn("<<< InitObject done")
            return iResult

        _sts_mod.InitObject = _wrapped_InitObject
        # Set __dummy__ so the C++ dispatcher (FUN_006f7d90) uses
        # this cached module directly instead of reimporting via
        # PyImport_ImportModule (which returns the top-level package).
        _sts_mod.__dummy__ = 1
        _log("  Monkey-patched SpeciesToShip.InitObject with tracing (+ __dummy__)")
    except:
        ei = sys.exc_info()
        _log("  SpeciesToShip monkey-patch FAILED: %s: %s" %
             (str(ei[0]), str(ei[1])))

    # --- Patch EndGame and RestartGame with headless-safe versions ---
    try:
        _ms2 = sys.modules['Multiplayer.MissionShared']
        _ms2.EndGame = _ds_EndGame
        _log("  Replaced MissionShared.EndGame with headless version")
    except:
        ei = sys.exc_info()
        _log("  MissionShared.EndGame replace FAILED: %s: %s" %
             (str(ei[0]), str(ei[1])))

    try:
        _m1_2 = sys.modules['Multiplayer.Episode.Mission1.Mission1']
        _m1_2.RestartGame = _ds_RestartGame
        _m1_2.ObjectKilledHandler = _ds_ObjectKilledHandler
        _log("  Replaced Mission1.RestartGame and ObjectKilledHandler")
    except:
        ei = sys.exc_info()
        _log("  Mission1.RestartGame replace FAILED: %s: %s" %
             (str(ei[0]), str(ei[1])))
