###############################################################################
#   DSHandlers.py - Event handlers for dedicated server
#
#   ChatRelayHandler: Forwards in-game chat messages to all clients.
#   ShipCreatedHandler: Captures newly created ships for respawn fallback.
#   DeferredInitObject: Initializes ship models/subsystems for players.
#
#   These are referenced by C code and event registrations via
#   "Custom.DedicatedServer.*" -- DedicatedServer.py keeps aliases.
#
#   Python 1.5 compatible.
###############################################################################
import App
import sys

def _log(msg):
    """Delegate to DedicatedServer._log via sys.modules."""
    ds = sys.modules.get('Custom.DedicatedServer')
    if ds and hasattr(ds, '_log'):
        ds._log(msg)

###############################################################################
#   Chat relay handler
#
#   On the stock game, MultiplayerMenus.ProcessMessageHandler handles
#   CHAT_MESSAGE and TEAM_CHAT_MESSAGE relay.  That handler is never
#   registered on the headless server (no GUI/BuildMultiplayerWindow).
#   This handler does the relay: copy the incoming message and forward
#   to all other clients via SendTGMessageToGroup("NoMe").
#
#   Dedup: The handler fires twice per message due to double event
#   dispatch (UTOPIA_MAIN_TICK + TGNetwork_Update both process the
#   same event).  Track last relayed message key to skip the second.
###############################################################################

_last_chat_key = None  # "type:senderID:text" of last relayed message

def ChatRelayHandler(self, pEvent):
    global _last_chat_key
    try:
        pMessage = pEvent.GetMessage()
        if not pMessage:
            return
        kStream = pMessage.GetBufferStream()
        cType = ord(kStream.ReadChar())
        _CHAT = App.MAX_MESSAGE_TYPES + 1
        _TEAM_CHAT = App.MAX_MESSAGE_TYPES + 2
        if cType == _CHAT or cType == _TEAM_CHAT:
            # Read sender ID and message text for dedup
            iFromID = kStream.ReadLong()
            iLen = kStream.ReadShort()
            pcMsg = ""
            for _ci in range(iLen):
                pcMsg = pcMsg + kStream.ReadChar()
            # Dedup: skip consecutive identical messages (double dispatch)
            _key = "%d:%d:%s" % (cType, iFromID, pcMsg)
            if _key == _last_chat_key:
                _last_chat_key = None  # clear so next legit repeat goes through
                return
            _last_chat_key = _key
            pNetwork = App.g_kUtopiaModule.GetNetwork()
            if pNetwork and App.g_kUtopiaModule.IsHost():
                pNewMessage = pMessage.Copy()
                pNetwork.SendTGMessageToGroup("NoMe", pNewMessage)
    except:
        pass  # _log doesn't work from event handler context

###############################################################################
#   Ship created handler (ObjectCreatedHandler fallback)
#
#   GetShipFromPlayerID scans all ships in all Sets checking ship+0x2E4
#   (NetPlayerID).  After respawn, the new ship may not be linked to the
#   player ID, so GetShipFromPlayerID returns NULL.
#
#   This handler captures newly created ships via ET_OBJECT_CREATED_NOTIFY.
#   DeferredInitObject uses _pending_ships as a fallback when the primary
#   lookup fails.
#
#   NOTE: _log doesn't work from event handler context (C++ catches the
#   raise before it reaches our patched debug console handler).
###############################################################################

_pending_ships = []  # list of pShip references from ObjectCreatedHandler

def ShipCreatedHandler(self, pEvent):
    """Capture newly created ships. Called by ET_OBJECT_CREATED_NOTIFY.
    Filters by ShipClass_Cast only; _find_pending_ship filters by netType>0.
    Cannot use IsPlayerShip() here — NetPlayerID not set yet at creation time."""
    global _pending_ships
    try:
        pObj = pEvent.GetDestination()
        pShip = App.ShipClass_Cast(pObj)
        if pShip is not None:
            _pending_ships.append(pShip)
    except:
        pass

###############################################################################
#   Deferred ship initialization
#
#   The engine's TG_CallPythonFunction (FUN_006f8ab0) calls
#   SpeciesToShip.InitObject during ship ReadStream deserialization.
#   This call fails silently on our headless server (the monkey-patched
#   wrapper never fires, no errors in state_dump.log).  Without InitObject,
#   ships have no NIF model, no subsystems, no collision geometry.
#
#   Fix: after a player joins and selects a ship, find the ship via
#   MultiplayerGame.GetShipFromPlayerID and call InitObject ourselves
#   through Python (which works).  Called periodically from C GameLoop
#   until the ship is found or timeout.
#
#   Respawn: GetShipFromPlayerID may return the OLD destroyed ship or
#   NULL after respawn (the new ship isn't linked to the player ID).
#   Fallback: check _pending_ships from ShipCreatedHandler for any
#   uninitialized ship with a valid NetType.
###############################################################################

_initobj_done = {}       # playerID -> (netType, shipPtr) of CURRENT active ship
_initobj_poll_count = {} # playerID -> call count (for periodic verbose logging)
_initobj_dead = {}       # playerID -> shipPtr for ships known to be destroyed
_initobj_known = {}      # playerID -> {shipPtr: 1, ...} ALL ptrs ever initialized

def _is_known_ship(playerID, shipPtr):
    """Check if this ship pointer was already initialized for this player."""
    if not _initobj_known.has_key(playerID):
        return 0
    return _initobj_known[playerID].has_key(shipPtr)

def _mark_known_ship(playerID, shipPtr):
    """Record that we initialized this ship pointer for this player."""
    if not _initobj_known.has_key(playerID):
        _initobj_known[playerID] = {}
    _initobj_known[playerID][shipPtr] = 1

def _find_pending_ship(playerID):
    """Try to find a new ship from _pending_ships that we haven't initialized.
    Returns pShip or None.  Removes stale entries from _pending_ships."""
    global _pending_ships
    _newList = []
    _found = None
    for _pShip in _pending_ships:
        try:
            _nt = _pShip.GetNetType()
        except:
            _nt = -1  # stale reference, drop it
        if _nt <= 0:
            pass  # skip non-player objects and stale refs
        else:
            _ptr = str(_pShip)
            # Skip ships we've already initialized (check ALL known ptrs)
            if _is_known_ship(playerID, _ptr):
                _newList.append(_pShip)
            elif _found is None:
                _found = _pShip
            else:
                _newList.append(_pShip)
    _pending_ships = _newList
    return _found

def DeferredInitObject(playerID):
    global _initobj_done, _initobj_poll_count, _initobj_dead
    try:
        # Increment poll counter for periodic verbose logging
        if not _initobj_poll_count.has_key(playerID):
            _initobj_poll_count[playerID] = 0
        _initobj_poll_count[playerID] = _initobj_poll_count[playerID] + 1
        _pollN = _initobj_poll_count[playerID]
        _verbose = (_pollN <= 3) or (_pollN % 10 == 0)

        pGame = App.MultiplayerGame_Cast(App.Game_GetCurrentGame())
        if pGame is None:
            if _verbose:
                _log(">>> DeferredInitObject(%d) poll#%d: no game" % (playerID, _pollN))
            return 0

        # Step 1: Get ship from engine lookup
        pShip = pGame.GetShipFromPlayerID(playerID)
        _shipPtr = None
        iType = 0
        if pShip is not None:
            _shipPtr = str(pShip)
            iType = pShip.GetNetType()

        # Step 2: If engine returns a known-initialized ship, check hull health
        if _shipPtr is not None and _is_known_ship(playerID, _shipPtr):
            # We already initialized this ship. Check if still alive.
            _isDead = 0
            _hullInfo = "?"
            try:
                _hull = pShip.GetHull()
                if _hull:
                    _hp = _hull.GetCondition()
                    _hullInfo = "hp=%.1f" % _hp
                    if _hp <= 0:
                        _isDead = 1
                else:
                    _isDead = 1
                    _hullInfo = "hull=None"
            except:
                _isDead = 1
                _hullInfo = "hull=EXCEPT"
            if _isDead:
                _initobj_dead[playerID] = _shipPtr
                if _initobj_done.has_key(playerID):
                    del _initobj_done[playerID]
                if _initobj_known.has_key(playerID):
                    _initobj_known[playerID] = {}
                _initobj_poll_count[playerID] = 0
                _log(">>> DeferredInitObject(%d): ship DESTROYED (%s)" %
                     (playerID, _hullInfo))
                # Fall through to step 3 to find pending ship
                pShip = None
                _shipPtr = None
                iType = 0
            else:
                # Ship alive — but check for new pending player ships
                # (client-side respawn). Server hull may never reach 0 because
                # C++ damage pipeline doesn't run properly headless.
                _pendShip = _find_pending_ship(playerID)
                if _pendShip is not None:
                    _log(">>> DeferredInitObject(%d) poll#%d: respawn (old %s alive %s), init pending" %
                         (playerID, _pollN, _shipPtr, _hullInfo))
                    pShip = _pendShip
                    _shipPtr = str(pShip)
                    iType = pShip.GetNetType()
                    # Fall through to Step 4 (init the new ship)
                else:
                    if _verbose:
                        _nPend = len(_pending_ships)
                        _log(">>> DeferredInitObject(%d) poll#%d: alive %s %s pending=%d (skip)" %
                             (playerID, _pollN, _shipPtr, _hullInfo, _nPend))
                    return 0

        # Step 3: Try to find an un-initialized ship
        # Prefer pending ships (from ShipCreatedHandler) over GetShipFromPlayerID
        _pendShip = _find_pending_ship(playerID)
        if _pendShip is not None:
            pShip = _pendShip
            _shipPtr = str(pShip)
            iType = pShip.GetNetType()
            _log(">>> DeferredInitObject(%d) poll#%d: using pending ship: %s type=%d" %
                 (playerID, _pollN, _shipPtr, iType))
        elif _shipPtr is not None and not _is_known_ship(playerID, _shipPtr) and iType > 0:
            # GetShipFromPlayerID returned a ship we haven't seen before
            _log(">>> DeferredInitObject(%d) poll#%d: new ship from engine: %s type=%d" %
                 (playerID, _pollN, _shipPtr, iType))
        else:
            # No ship available
            if _verbose:
                _nPend = len(_pending_ships)
                _log(">>> DeferredInitObject(%d) poll#%d: no new ship (pending=%d)" %
                     (playerID, _pollN, _nPend))
            return 0

        if iType <= 0:
            if _verbose:
                _log(">>> DeferredInitObject(%d) poll#%d: ship=%s netType=%d (<=0, skip)" %
                     (playerID, _pollN, _shipPtr, iType))
            return 0

        # Step 4: Initialize this ship
        # NOTE: _initobj_done/_mark_known_ship are set AFTER SetupProperties
        # succeeds, so a failed init can be retried on the next poll.
        _log(">>> DeferredInitObject(%d): ship=%s netType=%d" % (playerID, str(pShip), iType))

        # Inline InitObject logic (avoids SpeciesToShip cross-module
        # attribute issues with Multiplayer.SpeciesToShip.CONSTANT).
        # Uses sys.modules to get correct submodules after __import__.
        __import__('Multiplayer.SpeciesToShip')
        _sts = sys.modules['Multiplayer.SpeciesToShip']

        # Ensure Multiplayer package has SpeciesToShip attribute
        # (ships/*.py access Multiplayer.SpeciesToShip.CONSTANT)
        _mp = sys.modules['Multiplayer']
        _mp.SpeciesToShip = _sts

        if iType <= 0 or iType >= _sts.MAX_SHIPS:
            _log(">>> DeferredInitObject(%d): species %d out of range" % (playerID, iType))
            return 0

        pSpecTuple = _sts.kSpeciesTuple[iType]
        pcScript = pSpecTuple[0]
        if pcScript is None:
            _log(">>> DeferredInitObject(%d): species %d has no script" % (playerID, iType))
            return 0
        _log("  ship script = %s" % pcScript)

        # Import ship module and get it from sys.modules
        # (__import__ in Python 1.5 returns the top-level package)
        _shipmod_name = "ships." + pcScript
        __import__(_shipmod_name)
        _shipmod = sys.modules[_shipmod_name]
        _log("  ship module = %s" % str(_shipmod))

        # Ensure the ship module's Multiplayer ref has SpeciesToShip
        # (ships/*.py cache their own Multiplayer reference at import time)
        if hasattr(_shipmod, 'Multiplayer'):
            _shipmod.Multiplayer.SpeciesToShip = _sts

        _shipmod.LoadModel()
        kStats = _shipmod.GetShipStats()
        _log("  kStats = %s" % str(kStats))

        # SetupModel
        pShip.SetupModel(kStats['Name'])
        _log("  SetupModel OK")

        # Load hardpoints
        pPropertySet = pShip.GetPropertySet()
        _log("  GetPropertySet = %s" % str(pPropertySet))

        _hpmod_name = "ships.Hardpoints." + kStats['HardpointFile']
        # Remove stale partial module from any prior failed import
        if sys.modules.has_key(_hpmod_name):
            del sys.modules[_hpmod_name]

        App.g_kModelPropertyManager.ClearLocalTemplates()
        __import__(_hpmod_name)
        _hpmod = sys.modules[_hpmod_name]
        _hpmod.LoadPropertySet(pPropertySet)
        _log("  Hardpoints loaded")

        try:
            pShip.SetupProperties()
            _log("  SetupProperties OK")
        except:
            _log("  SetupProperties FAILED: %s" % str(sys.exc_info()[1]))
            return 0
        try:
            pShip.UpdateNodeOnly()
            _log("  UpdateNodeOnly OK")
        except:
            _log("  UpdateNodeOnly FAILED: %s" % str(sys.exc_info()[1]))
            # SetupProperties succeeded so subsystems exist; continue

        # Mark as done AFTER setup succeeds
        _initobj_done[playerID] = (iType, _shipPtr)
        _mark_known_ship(playerID, _shipPtr)

        # Diagnostic: subsystem count and critical field verification
        _subsysCount = 0
        try:
            for _si in range(64):
                _sub = pShip.GetSubsystem(_si)
                if _sub is None:
                    break
                _subsysCount = _subsysCount + 1
        except:
            pass
        _log("  SubsystemCount = %d (via GetSubsystem iteration)" % _subsysCount)
        try:
            _pwr = pShip.GetPowerSubsystem()
            _log("  PowerSubsystem = %s" % str(_pwr))
        except:
            _log("  PowerSubsystem FAILED: %s" % str(sys.exc_info()[1]))
        # Ship SWIG pointer for C-side cross-reference
        _log("  ShipPtr = %s" % str(pShip))

        # Diagnostic: check subsystem state after init
        _log("  LODModelManager.Contains(%s) = %s" % (kStats['Name'],
             str(App.g_kLODModelManager.Contains(kStats['Name']))))
        try:
            _hull = pShip.GetHull()
            _log("  GetHull = %s" % str(_hull))
        except:
            _log("  GetHull FAILED: %s" % str(sys.exc_info()[1]))
        try:
            _shld = pShip.GetShields()
            _log("  GetShields = %s" % str(_shld))
        except:
            _log("  GetShields FAILED: %s" % str(sys.exc_info()[1]))
        try:
            _sens = pShip.GetSensorSubsystem()
            _log("  GetSensorSubsystem = %s" % str(_sens))
        except:
            _log("  GetSensorSubsystem FAILED: %s" % str(sys.exc_info()[1]))
        # Check UtopiaModule flags
        _log("  IsMultiplayer(0x97FA8A) via SWIG = %s" % str(App.g_kUtopiaModule.IsMultiplayer()))
        _log(">>> DeferredInitObject(%d): InitObject OK" % playerID)
        return 1
    except:
        ei = sys.exc_info()
        _log(">>> DeferredInitObject(%d) EXCEPT: %s: %s" % (playerID, str(ei[0]), str(ei[1])))
        return 0
