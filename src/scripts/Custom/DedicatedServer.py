###############################################################################
#   DedicatedServer.py
#
#   Automated dedicated server startup for Star Trek: Bridge Commander.
#   Lives in scripts/Custom/ which is EXEMPT from multiplayer checksums,
#   so vanilla clients can connect to this server.
#
#   Called from Local.py during game startup.
#   The C-side DDraw proxy (ddraw_main.c) handles heavy lifting:
#     - Phase 0: Sets multiplayer/host flags (direct memory + SWIG)
#     - Phase 1: Creates WSN (TGWinsockNetwork) via FUN_00445d90
#     - Phase 2: Creates MultiplayerGame/TopWindow via FUN_00504f10
#     - Phase 3: Calls this module's TopWindowInitialized()
#
#   This module uses the FUNCTIONAL SWIG API (App.Class_Method(obj, args))
#   instead of shadow class methods (obj.Method(args)) because the App
#   module is the raw C module without shadow wrapper classes.
#
#   Python 1.5 compatible (no parens on print, except Exception,e syntax)
###############################################################################
import App
import strop
import sys

print "DedicatedServer.py loading"

###############################################################################
#   Headless import hook - wraps mission Python handlers with try/except
#   so that GUI-related AttributeErrors don't crash the headless server.
#   Mission scripts assume GUI widgets exist (KillChildren, etc.) but in
#   headless mode those references are None.
###############################################################################
try:
    import __builtin__
    _ds_orig_import = __builtin__.__import__
    _ds_patched = {}

    def _ds_log(msg):
        try:
            _bp = getattr(sys, '_ds_base_path', '')
            f = open(_bp + "dedicated_init.log", "a")
            f.write(msg + "\n")
            f.close()
        except:
            pass

    def _ds_patch_handler(mod, hname):
        """Patch a handler function IN-PLACE using func_code replacement.

        The event system holds a direct reference to the original function
        object, so replacing the module attribute doesn't help.  Instead we:
        1. Copy the original function (preserving its code)
        2. Create a wrapper that calls the copy inside try/except
        3. Replace the original function's func_code with the wrapper's code
        4. Set func_defaults so the copy is passed as a default argument

        This way the event system's reference to the original function object
        now executes our safe wrapper code when called.

        Python 1.5 lacks closures, so we use default args to capture values.
        """
        orig_fn = getattr(mod, hname)
        if not hasattr(orig_fn, 'func_code'):
            return 0
        # Create a copy of the original function with its original code
        import new
        copy_fn = new.function(orig_fn.func_code, orig_fn.func_globals,
                               hname + '_orig')
        if orig_fn.func_defaults:
            copy_fn.func_defaults = orig_fn.func_defaults
        # Create wrapper - default args capture copy_fn and _ds_log
        # Python 1.5: no closures, use default args instead
        def wrapper(pObject, pEvent, _orig=copy_fn, _log=_ds_log):
            try:
                _orig(pObject, pEvent)
            except Exception, e:
                _log("HANDLER CAUGHT: " + str(e))
            except:
                _log("HANDLER CAUGHT: (unknown)")
        # Replace the original function's code IN-PLACE
        # The event system's reference to orig_fn now executes wrapper's code
        orig_fn.func_code = wrapper.func_code
        orig_fn.func_defaults = (copy_fn, _ds_log)
        return 1

    def _ds_safe_import(name, globals=None, locals=None, fromlist=None):
        """Import hook that patches mission modules for headless mode.

        In Python 1.5, __import__('A.B.C') returns module A (top-level).
        The actual submodule C is in sys.modules['A.B.C'].
        We must look there to find the handler functions.
        """
        # Always trace Multiplayer imports with fromlist (debug MissionShared)
        trace = (str(name) == 'Multiplayer' and fromlist is not None)
        if trace:
            _ds_log("HOOK PRE: from %s import %s" % (str(name), str(fromlist)))
        if fromlist is not None:
            mod = _ds_orig_import(name, globals, locals, fromlist)
        elif locals is not None:
            mod = _ds_orig_import(name, globals, locals)
        elif globals is not None:
            mod = _ds_orig_import(name, globals)
        else:
            mod = _ds_orig_import(name)
        # Fix: ensure parent packages have submodule attributes set.
        # Python 1.5's embedded import doesn't always set pkg.submod,
        # causing LOAD_ATTR 'submod' to raise AttributeError.
        modname = str(name)
        if strop.find(modname, '.') >= 0:
            parts = strop.split(modname, '.')
            for _i in range(len(parts) - 1):
                _pfull = strop.join(parts[:_i+1], '.')
                _cname = parts[_i+1]
                _cfull = strop.join(parts[:_i+2], '.')
                _pmod = sys.modules.get(_pfull, None)
                _cmod = sys.modules.get(_cfull, None)
                if _pmod is not None and _cmod is not None:
                    if not hasattr(_pmod, _cname):
                        setattr(_pmod, _cname, _cmod)
        # Also fix fromlist: from X import Y needs X.Y as attribute
        if fromlist is not None:
            for _attr in fromlist:
                if str(_attr) == '*':
                    continue
                _full = modname + '.' + str(_attr)
                if sys.modules.has_key(_full) and not hasattr(mod, str(_attr)):
                    setattr(mod, str(_attr), sys.modules[_full])
        if trace:
            _ds_log("HOOK POST: mod=%s has_attr=%s" % (
                str(mod), str(hasattr(mod, str(fromlist[0])))))
        if not _ds_patched.has_key(modname):
            # Check if this is a mission module (any multiplayer episode)
            # NOTE: Python 1.5 'in' on strings requires single-char left operand
            # (raises TypeError otherwise), so use strop.find for substring search
            is_mission = 0
            for mname in ['Mission1', 'Mission2', 'Mission3', 'Mission5']:
                if strop.find(modname, mname) >= 0:
                    is_mission = 1
                    break
            if is_mission:
                _ds_patched[modname] = 1
                # Get the ACTUAL submodule from sys.modules
                # (not the top-level package returned by __import__)
                try:
                    actual_mod = sys.modules[modname]
                except:
                    actual_mod = None
                if actual_mod:
                    _ds_log("IMPORT HOOK: Patching " + modname)
                    handler_names = [
                        'NewPlayerHandler', 'DeletePlayerHandler',
                        'RebuildPlayerList', 'StartGame',
                        'RebuildInfoPane', 'RebuildShipPane',
                        'RebuildTeamPane', 'RebuildReadyButton',
                    ]
                    for hname in handler_names:
                        if hasattr(actual_mod, hname):
                            try:
                                ok = _ds_patch_handler(actual_mod, hname)
                                if ok:
                                    _ds_log("  Patched " + hname + " (func_code)")
                                else:
                                    _ds_log("  Skipped " + hname + " (not a function)")
                            except Exception, e:
                                _ds_log("  FAILED " + hname + ": " + str(e))
        return mod

    __builtin__.__import__ = _ds_safe_import
    print "DedicatedServer: import hook installed"
except:
    print "DedicatedServer: import hook FAILED"

###############################################################################
#   File-based logging (more reliable than print in stub mode)
###############################################################################
def _log(msg):
    try:
        _bp = getattr(sys, '_ds_base_path', '')
        f = open(_bp + "dedicated_init.log", "a")
        f.write(msg + "\n")
        f.close()
    except:
        pass

###############################################################################
#   Explicit mission module patching
#
#   The import hook may not fire if the engine loads mission .pyc files
#   through C code (bypassing __builtin__.__import__).  This function
#   scans sys.modules for any already-loaded mission modules and patches
#   them for headless safety.
#
#   Two strategies:
#   1. EVENT HANDLERS (called by event system with direct func reference):
#      Replace func_code IN-PLACE with try/except wrapper.
#      Signature: (pObject, pEvent) - standard event handler args.
#   2. GUI HELPERS (called by handlers via module attribute lookup):
#      Replace module attribute with a safe no-op function.
#      This prevents crashes even if the handler wrapper doesn't fire.
###############################################################################

# Event handlers called by the C event system (hold direct func references)
_EVENT_HANDLERS = [
    'NewPlayerHandler', 'DeletePlayerHandler', 'StartGame',
]

# GUI functions that access UI widgets (called via module.func())
_GUI_FUNCTIONS = [
    'RebuildPlayerList', 'RebuildInfoPane', 'RebuildShipPane',
    'RebuildTeamPane', 'RebuildReadyButton',
    'UpdateShipList', 'UpdatePlayerList',
    'ConfigureTeamPane', 'ConfigureInfoPane',
    'ConfigureShipPane', 'ConfigureReadyButton',
    'CreateInfoPane', 'CreateShipPane', 'CreateTeamPane',
]

def _noop_gui(*args):
    """No-op replacement for GUI functions in headless mode."""
    pass

def PatchLoadedMissionModules():
    """Scan sys.modules and patch any mission module handlers for headless mode."""
    import new
    count = 0
    keys = sys.modules.keys()
    for modname in keys:
        is_mission = 0
        for mname in ['Mission1', 'Mission2', 'Mission3', 'Mission5']:
            if strop.find(modname, mname) >= 0:
                is_mission = 1
                break
        if not is_mission:
            continue
        if _ds_patched.has_key(modname):
            continue
        _ds_patched[modname] = 1
        mod = sys.modules[modname]
        if mod is None:
            continue
        _log("EXPLICIT PATCH: " + modname)

        # Strategy 1: Wrap event handlers with try/except via func_code swap
        for hname in _EVENT_HANDLERS:
            if not hasattr(mod, hname):
                continue
            orig_fn = getattr(mod, hname)
            if not hasattr(orig_fn, 'func_code'):
                continue
            try:
                copy_fn = new.function(orig_fn.func_code, orig_fn.func_globals,
                                       hname + '_orig')
                if orig_fn.func_defaults:
                    copy_fn.func_defaults = orig_fn.func_defaults
                # Wrapper with exact event handler signature (pObject, pEvent)
                # Default args capture the copy and logger (no closures in 1.5)
                def wrapper(pObject, pEvent,
                            _orig=copy_fn, _logfn=_log, _fname=hname):
                    try:
                        _orig(pObject, pEvent)
                    except:
                        ei = sys.exc_info()
                        _logfn("HANDLER CAUGHT [" + _fname + "]: " + str(ei[0]) + ": " + str(ei[1]))
                # Replace func_code IN-PLACE so event system's reference works
                orig_fn.func_code = wrapper.func_code
                orig_fn.func_defaults = wrapper.func_defaults
                _log("  Wrapped " + hname + " (func_code)")
                count = count + 1
            except Exception, e:
                _log("  FAILED " + hname + ": " + str(e))

        # Strategy 2: Replace GUI helpers with no-ops at module level
        for hname in _GUI_FUNCTIONS:
            if not hasattr(mod, hname):
                continue
            orig_fn = getattr(mod, hname)
            if not hasattr(orig_fn, 'func_code'):
                continue
            try:
                setattr(mod, hname, _noop_gui)
                _log("  Replaced " + hname + " (noop)")
                count = count + 1
            except Exception, e:
                _log("  FAILED " + hname + ": " + str(e))

    if count > 0:
        _log("EXPLICIT PATCH: done, patched " + str(count) + " functions")
    return count

###############################################################################
#   Configuration - edit these for your server
###############################################################################
SERVER_GAME_NAME = "Dedicated Server"
SERVER_PASSWORD = ""
SERVER_SYSTEM = 1           # 1=first system in list (e.g. Albirea)
SERVER_TIME_LIMIT = -1      # -1 = no limit, or minutes (5,10,15...)
SERVER_FRAG_LIMIT = -1      # -1 = no limit, or kill count
SERVER_PLAYER_LIMIT = 8     # max 8
SERVER_GAME_MODE = "Multiplayer.Episode.Mission1.Mission1"
SERVER_COLLISIONS = 1       # 1=collision damage on, 0=off
SERVER_DIFFICULTY = 1       # 0=Easy, 1=Normal, 2=Hard
SERVER_CONNECTION_TIMEOUT = 45.0  # seconds before dropping unresponsive player
SERVER_FRIENDLY_FIRE_POINTS = 100 # FF warning threshold (0=disabled)

###############################################################################
#   State
###############################################################################
g_pTopWindow = None

def Initialize():
    print "DedicatedServer: Initialize()"
    _log("DedicatedServer: Initialize()")

###############################################################################
#   TopWindowInitialized - called from C-side DS_TIMER Phase 3
#
#   At this point, the C code has already:
#   - Set IsHost=1, IsMultiplayer=1
#   - Created WSN (network listening on port 22101)
#   - Created MultiplayerGame (which creates the TopWindow/Game object)
#
#   We just need to set config values and report status.
###############################################################################
def TopWindowInitialized(pTopWindow):
    global g_pTopWindow
    g_pTopWindow = pTopWindow
    _log("TopWindowInitialized called, pTopWindow=" + str(pTopWindow))
    _log("  pTopWindow type = " + str(type(pTopWindow)))
    print "DedicatedServer: TopWindowInitialized"

    # --- Construct SWIG pointers manually for global singletons ---
    # The g_k* module attributes aren't set because we bypass the SWIG init.
    # We know the memory address of UtopiaModule (0x0097FA00) from binary analysis.
    # SWIG pointer format: _HEXADDR_p_TypeName (lowercase hex, no 0x prefix)
    um = "_97fa00_p_UtopiaModule"
    _log("  Using manual UtopiaModule ptr: " + um)

    # --- Set UtopiaModule flags ---
    try:
        App.UtopiaModule_SetMultiplayer(um, 1)
        App.UtopiaModule_SetIsHost(um, 1)
        App.UtopiaModule_SetIsClient(um, 0)
        _log("  UtopiaModule flags set OK via SWIG")
    except Exception, e:
        _log("  UtopiaModule flags FAILED: " + str(e))

    # --- Check network status ---
    try:
        network = App.UtopiaModule_GetNetwork(um)
        _log("  Network = " + str(network))
    except Exception, e:
        _log("  GetNetwork FAILED: " + str(e))

    # --- Try to find ConfigMapping address ---
    # We can try getting it via UtopiaModule if there's a getter, or
    # scan known addresses. For now, try the game path as diagnostic.
    try:
        gamePath = App.UtopiaModule_GetGamePath(um)
        _log("  GamePath = " + str(gamePath))
        gameName = App.UtopiaModule_GetGameName(um)
        _log("  GameName = " + str(gameName))
    except Exception, e:
        _log("  GamePath/Name FAILED: " + str(e))

    # --- Check and configure game object ---
    try:
        game = App.Game_GetCurrentGame()
        _log("  Game = " + str(game))
        if game is not None:
            mpGame = App.MultiplayerGame_Cast(game)
            _log("  MultiplayerGame = " + str(mpGame))
            if mpGame is not None:
                # Set ReadyForNewPlayers = 1 so clients can connect
                try:
                    App.MultiplayerGame_SetReadyForNewPlayers(mpGame, 1)
                    _log("  SetReadyForNewPlayers(1) OK")
                except Exception, e:
                    _log("  SetReadyForNewPlayers FAILED: " + str(e))

                try:
                    ready = App.MultiplayerGame_IsReadyForNewPlayers(mpGame)
                    _log("  ReadyForNewPlayers = " + str(ready))
                except Exception, e:
                    _log("  IsReadyForNewPlayers failed: " + str(e))
                try:
                    maxP = App.MultiplayerGame_GetMaxPlayers(mpGame)
                    _log("  MaxPlayers = " + str(maxP))
                except Exception, e:
                    _log("  GetMaxPlayers failed: " + str(e))
    except Exception, e:
        _log("  Game check FAILED: " + str(e))

    # --- Load mission/episode into Game object ---
    # Game+0x70 (episode ptr) starts as NULL. ChecksumCompleteHandler reads the
    # map name from Game+0x70->0x3c->0x14 to build opcode 0x00 for clients.
    # Without this, the server can't tell clients which mission to load.
    try:
        game = App.Game_GetCurrentGame()
        if game is not None:
            # Diagnostic: check current episode before loading
            try:
                curEp = App.Game_GetCurrentEpisode(game)
                _log("  CurrentEpisode (before) = " + str(curEp))
            except Exception, e:
                _log("  GetCurrentEpisode FAILED: " + str(e))

            # Load the mission episode
            epName = App.new_TGString(SERVER_GAME_MODE)
            try:
                App.Game_LoadEpisode(game, epName)
                _log("  LoadEpisode OK: " + SERVER_GAME_MODE)
            except Exception, e:
                _log("  LoadEpisode FAILED: " + str(e))

            # Verify episode loaded
            try:
                curEp = App.Game_GetCurrentEpisode(game)
                _log("  CurrentEpisode (after) = " + str(curEp))
            except Exception, e:
                _log("  GetCurrentEpisode verify FAILED: " + str(e))

            # Now load the mission WITHIN the episode
            # Episode+0x3c -> Mission object, Mission+0x14 -> name string
            # This is what the host "selects" from the lobby mission menu
            try:
                curEp = App.Game_GetCurrentEpisode(game)
                if curEp is not None:
                    # Check current mission before loading
                    try:
                        curMis = App.Episode_GetCurrentMission(curEp)
                        _log("  CurrentMission (before) = " + str(curMis))
                    except Exception, e:
                        _log("  GetCurrentMission FAILED: " + str(e))

                    # Load the mission within the episode
                    misName = App.new_TGString(SERVER_GAME_MODE)
                    try:
                        App.Episode_LoadMission(curEp, misName)
                        _log("  Episode_LoadMission OK: " + SERVER_GAME_MODE)
                    except Exception, e:
                        _log("  Episode_LoadMission FAILED: " + str(e))

                    # Verify
                    try:
                        curMis = App.Episode_GetCurrentMission(curEp)
                        _log("  CurrentMission (after) = " + str(curMis))
                    except Exception, e:
                        _log("  GetCurrentMission verify FAILED: " + str(e))
            except Exception, e:
                _log("  Mission loading FAILED: " + str(e))

    except Exception, e:
        _log("  Episode loading FAILED: " + str(e))

    # --- Also store UtopiaModule pointer on Appc for future use ---
    try:
        import Appc
        Appc.g_kUtopiaModule = um
        _log("  Stored g_kUtopiaModule on Appc")
    except Exception, e:
        _log("  Store g_kUtopiaModule failed: " + str(e))

    # --- Set MissionMenusShared variables for GameSpy browser ---
    # The GameSpy rules callback (FUN_0069c8e0) reads g_iSystem, g_iTimeLimit,
    # g_iFragLimit from Multiplayer.MissionMenusShared to build the response.
    # g_iSystem is passed to SpeciesToSystem.GetScriptFromSpecies() to get
    # the system script name (e.g. "Multi1"), which clients look up in
    # data/TGL/systems.tgl for the display name.
    # The basic info callback (FUN_0069c580) reads g_iPlayerLimit.
    try:
        __import__('Multiplayer.MissionMenusShared')
        mms = sys.modules['Multiplayer.MissionMenusShared']
        mms.g_iSystem = SERVER_SYSTEM
        mms.g_iTimeLimit = SERVER_TIME_LIMIT
        mms.g_iFragLimit = SERVER_FRAG_LIMIT
        mms.g_iPlayerLimit = SERVER_PLAYER_LIMIT
        mms.g_iUseScoreLimit = 0
        _log("  MissionMenusShared: system=%d timelimit=%d fraglimit=%d playerlimit=%d" %
             (SERVER_SYSTEM, SERVER_TIME_LIMIT, SERVER_FRAG_LIMIT, SERVER_PLAYER_LIMIT))
    except Exception, e:
        _log("  MissionMenusShared FAILED: " + str(e))

    # --- Set game name on UtopiaModule ---
    try:
        gameName = App.new_TGString(SERVER_GAME_NAME)
        App.UtopiaModule_SetGameName(um, gameName)
        _log("  SetGameName OK: " + SERVER_GAME_NAME)
    except Exception, e:
        _log("  SetGameName FAILED: " + str(e))

    # --- Set game name on network ---
    try:
        network = App.UtopiaModule_GetNetwork(um)
        netName = App.new_TGString(SERVER_GAME_NAME)
        App.TGNetwork_SetName(network, netName)
        _log("  TGNetwork_SetName OK: " + SERVER_GAME_NAME)
    except Exception, e:
        _log("  TGNetwork_SetName FAILED: " + str(e))

    # --- Set captain name for host ---
    try:
        captainName = App.new_TGString("Dedicated Server")
        App.UtopiaModule_SetCaptainName(um, captainName)
        _log("  SetCaptainName OK: Dedicated Server")
    except Exception, e:
        _log("  SetCaptainName FAILED: " + str(e))

    # --- Enable packet processing ---
    try:
        App.UtopiaModule_SetProcessingPackets(um, 1)
        _log("  SetProcessingPackets(1) OK")
    except Exception, e:
        _log("  SetProcessingPackets FAILED: " + str(e))

    # --- Enable collision damage (off by default, normally set by main menu) ---
    try:
        App.ProximityManager_SetPlayerCollisionsEnabled(SERVER_COLLISIONS)
        App.ProximityManager_SetMultiplayerPlayerCollisionsEnabled(SERVER_COLLISIONS)
        _log("  Collisions = %d" % SERVER_COLLISIONS)
    except Exception, e:
        _log("  SetCollisions FAILED: " + str(e))

    # --- Set difficulty level (normally set by main menu from Options.cfg) ---
    try:
        App.Game_SetDifficulty(SERVER_DIFFICULTY)
        _log("  Difficulty = %d" % SERVER_DIFFICULTY)
    except Exception, e:
        _log("  SetDifficulty FAILED: " + str(e))

    # --- Set connection timeout (normally set by HandleStartGame) ---
    try:
        pNetwork = App.UtopiaModule_GetNetwork(um)
        if pNetwork:
            import Appc
            Appc.TGNetwork_SetConnectionTimeout(pNetwork, SERVER_CONNECTION_TIMEOUT)
            _log("  ConnectionTimeout = %.1f sec" % SERVER_CONNECTION_TIMEOUT)
        else:
            _log("  ConnectionTimeout: no network yet (will set later)")
    except Exception, e:
        _log("  SetConnectionTimeout FAILED: " + str(e))

    # --- Set friendly fire warning threshold ---
    try:
        App.UtopiaModule_SetFriendlyFireWarningPoints(um, SERVER_FRIENDLY_FIRE_POINTS)
        _log("  FriendlyFireWarningPoints = %d" % SERVER_FRIENDLY_FIRE_POINTS)
    except Exception, e:
        _log("  SetFriendlyFireWarningPoints FAILED: " + str(e))

    # --- Verify game name was set ---
    try:
        gn = App.UtopiaModule_GetGameName(um)
        _log("  Verified GameName = " + str(gn))
    except Exception, e:
        _log("  Verify GameName FAILED: " + str(e))

    # --- Create GameSpy handler (enables LAN browser query responses) ---
    try:
        gs = App.UtopiaModule_CreateGameSpy(um)
        _log("  CreateGameSpy OK: " + str(gs))
    except Exception, e:
        _log("  CreateGameSpy FAILED: " + str(e))

    # --- Check network details ---
    try:
        network = App.UtopiaModule_GetNetwork(um)
        hostID = App.TGNetwork_GetHostID(network)
        localID = App.TGNetwork_GetLocalID(network)
        numPlayers = App.TGNetwork_GetNumPlayers(network)
        isHost = App.TGNetwork_IsHost(network)
        _log("  Network: hostID=%s localID=%s numPlayers=%s isHost=%s" % (str(hostID), str(localID), str(numPlayers), str(isHost)))
    except Exception, e:
        _log("  Network details FAILED: " + str(e))

    # --- Initialize game (replicate "Start Game" button) ---
    # In normal flow: host clicks Start → fires ET_START → Mission1.Initialize
    # → CreateSystemFromSpecies → system loads → GAME_INITIALIZE_MESSAGE sent
    # Without this, clients get black screen (no star system).
    try:
        # Get mission pointer for Initialize call
        game = App.Game_GetCurrentGame()
        curEp = App.Game_GetCurrentEpisode(game)
        pMission = App.Episode_GetCurrentMission(curEp)
        _log("  pMission = " + str(pMission))

        # Set up MissionShared variables
        __import__('Multiplayer.MissionShared')
        ms = sys.modules['Multiplayer.MissionShared']
        ms.g_iSystem = SERVER_SYSTEM
        ms.g_iTimeLimit = SERVER_TIME_LIMIT
        ms.g_iFragLimit = SERVER_FRAG_LIMIT
        ms.g_iPlayerLimit = SERVER_PLAYER_LIMIT

        # Get system script name
        __import__('Multiplayer.SpeciesToSystem')
        sts = sys.modules['Multiplayer.SpeciesToSystem']
        systemName = sts.GetScriptFromSpecies(SERVER_SYSTEM)
        _log("  SpeciesToSystem(%d) = %s" % (SERVER_SYSTEM, str(systemName)))

        # Import and introspect Mission1
        __import__('Multiplayer.Episode.Mission1.Mission1')
        m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']

        # Log all module-level functions for debugging
        m1_funcs = []
        for attr in dir(m1):
            obj = getattr(m1, attr)
            if hasattr(obj, 'func_code'):
                co = obj.func_code
                m1_funcs.append("%s(%d)" % (attr, co.co_argcount))
        _log("  Mission1 functions: " + str(m1_funcs))

        # Check Initialize function signature
        if hasattr(m1, 'Initialize'):
            init_fn = m1.Initialize
            if hasattr(init_fn, 'func_code'):
                co = init_fn.func_code
                _log("  Initialize: argcount=%d varnames=%s" %
                     (co.co_argcount, str(co.co_varnames[:co.co_argcount])))

        # Also introspect MissionShared functions
        ms_funcs = []
        for attr in dir(ms):
            obj = getattr(ms, attr)
            if hasattr(obj, 'func_code'):
                co = obj.func_code
                ms_funcs.append("%s(%d)" % (attr, co.co_argcount))
        _log("  MissionShared functions: " + str(ms_funcs))

        # Log key MissionShared variables
        for vname in ['GAME_INITIALIZE_MESSAGE', 'GAME_INITIALIZE_DONE_MESSAGE',
                      'g_bGameStarted', 'g_bShipSelectState', 'g_pStartingSet',
                      'g_pChosenSystem', 'g_pSystemDatabase']:
            if hasattr(ms, vname):
                _log("  ms.%s = %s" % (vname, str(getattr(ms, vname))))

        # Ensure all Multiplayer submodules are properly set as package attributes.
        # Mission1.Initialize may do "from Multiplayer import MissionShared" which
        # requires Multiplayer package object to have MissionShared as an attribute.
        # Even if sys.modules['Multiplayer.MissionShared'] exists, the package
        # attribute might not be set in headless mode.
        mult_pkg = sys.modules.get('Multiplayer', None)
        if mult_pkg is None:
            __import__('Multiplayer')
            mult_pkg = sys.modules['Multiplayer']
        _log("  Multiplayer pkg = %s" % str(mult_pkg))

        # Ensure key submodules are set as attributes on the package
        sub_mods = ['MissionShared', 'SpeciesToSystem', 'MissionMenusShared',
                    'Episode']
        for subname in sub_mods:
            full = 'Multiplayer.' + subname
            if not sys.modules.has_key(full):
                try:
                    __import__(full)
                except:
                    pass
            sub = sys.modules.get(full, None)
            if sub is not None and not hasattr(mult_pkg, subname):
                setattr(mult_pkg, subname, sub)
                _log("  Set Multiplayer.%s on package" % subname)

        # Also ensure Episode.Mission1 subpackages are properly linked
        ep_pkg = sys.modules.get('Multiplayer.Episode', None)
        if ep_pkg is not None:
            m1_pkg = sys.modules.get('Multiplayer.Episode.Mission1', None)
            if m1_pkg is not None and not hasattr(ep_pkg, 'Mission1'):
                ep_pkg.Mission1 = m1_pkg
                _log("  Set Episode.Mission1 on package")

        # Verify Mission1's func_globals can see MissionShared
        init_fn = m1.Initialize
        if hasattr(init_fn, 'func_globals'):
            fg = init_fn.func_globals
            _log("  Initialize func_globals has MissionShared: %s" %
                 str(fg.has_key('MissionShared')))
            # If not in globals, inject directly
            if not fg.has_key('MissionShared'):
                fg['MissionShared'] = ms
                _log("  Injected MissionShared into func_globals")
            if not fg.has_key('SpeciesToSystem'):
                fg['SpeciesToSystem'] = sts
                _log("  Injected SpeciesToSystem into func_globals")
            if not fg.has_key('MissionMenusShared'):
                fg['MissionMenusShared'] = sys.modules.get(
                    'Multiplayer.MissionMenusShared', None)
                _log("  Injected MissionMenusShared into func_globals")

        # Force-set all Multiplayer submodule attributes on package object
        # The IMPORT_FROM bytecode (from X import Y) does getattr(X, Y),
        # so the package must have the attribute set.
        mult_pkg = sys.modules['Multiplayer']
        for subname in ['MissionShared', 'SpeciesToSystem', 'MissionMenusShared',
                        'MissionShared2']:
            full = 'Multiplayer.' + subname
            sub = sys.modules.get(full, None)
            if sub is not None:
                setattr(mult_pkg, subname, sub)
        _log("  Force-set Multiplayer submodule attrs")
        _log("  Verify: hasattr(Multiplayer, MissionShared) = %s" %
             str(hasattr(mult_pkg, 'MissionShared')))
        _log("  Verify: Multiplayer.MissionShared = %s" %
             str(getattr(mult_pkg, 'MissionShared', 'MISSING')))

        # --- Find shadow class for Mission to wrap raw SWIG pointer ---
        # Mission scripts use shadow class methods (pMission.AddPythonFunc...)
        # but we have a raw SWIG pointer string. Need to find the shadow class.
        pMissionObj = pMission  # fallback: raw pointer
        shadow_classes = []
        for attr in dir(App):
            if strop.find(attr, 'Ptr') >= 0 or strop.find(attr, 'Class') >= 0:
                shadow_classes.append(attr)
        _log("  App shadow classes (sample): %s" % str(shadow_classes[:30]))

        # Try to wrap pMission in shadow class
        for clsname in ['MissionPtr', 'Mission']:
            if hasattr(App, clsname):
                try:
                    cls = getattr(App, clsname)
                    pMissionObj = cls(pMission)
                    _log("  Wrapped pMission via App.%s: %s" % (clsname, str(pMissionObj)))
                    break
                except Exception, e:
                    _log("  App.%s(%s) failed: %s" % (clsname, pMission, str(e)))

        # Inject module-level imports into Mission1 and MissionShared
        # Mission1.py has "from Multiplayer import X" that fails in headless mode.
        # Pre-populate the module namespaces with all needed references.
        for mod_to_patch in [m1, ms]:
            for fname in dir(mod_to_patch):
                fn = getattr(mod_to_patch, fname)
                if hasattr(fn, 'func_globals'):
                    fg = fn.func_globals
                    if not fg.has_key('MissionShared'):
                        fg['MissionShared'] = ms
                    if not fg.has_key('SpeciesToSystem'):
                        fg['SpeciesToSystem'] = sts
                    if not fg.has_key('MissionMenusShared'):
                        fg['MissionMenusShared'] = sys.modules.get(
                            'Multiplayer.MissionMenusShared', None)
                    if not fg.has_key('App'):
                        fg['App'] = App

        # Also fix the Multiplayer package for any from-import statements
        mult_pkg = sys.modules['Multiplayer']
        mult_pkg.MissionShared = ms
        mult_pkg.SpeciesToSystem = sts
        mult_pkg.MissionMenusShared = sys.modules.get(
            'Multiplayer.MissionMenusShared', None)
        _log("  Injected imports into Mission1/MissionShared/Multiplayer")

        # --- Pre-import ALL modules that MissionShared and Mission1 need ---
        # co_names analysis shows these modules are accessed inside Initialize:
        needed_modules = {
            'MissionLib': 'MissionLib',
            'LoadBridge': 'LoadBridge',
            'Multiplayer.MultiplayerMenus': 'MultiplayerMenus',
        }
        for full_name, short_name in needed_modules.items():
            try:
                __import__(full_name)
                mod = sys.modules[full_name]
                # Set on Multiplayer package for from-import resolution
                if strop.find(full_name, '.') >= 0:
                    setattr(mult_pkg, short_name, mod)
                # Inject into MissionShared func_globals
                for fn in dir(ms):
                    obj = getattr(ms, fn)
                    if hasattr(obj, 'func_globals'):
                        obj.func_globals[short_name] = mod
                _log("  Pre-imported %s as %s" % (full_name, short_name))
            except Exception, e:
                _log("  Pre-import %s FAILED: %s" % (full_name, str(e)))

        # --- Stub GUI functions that crash in headless mode ---
        gui_stubs = 0
        # LoadBridge GUI functions
        try:
            lb = sys.modules.get('LoadBridge', None)
            if lb:
                for fn_name in ['CreateCharacterMenus', 'CreateMenus',
                                'CreateBridgeMenus', 'CreateScienceMenus',
                                'CreateEngineeringMenus', 'CreateCommunicationsMenus',
                                'CreateTacticalMenus', 'CreateHelmMenus',
                                'CreateBridge', 'CreateCharacterMenuBitmaps']:
                    if hasattr(lb, fn_name):
                        setattr(lb, fn_name, _noop_gui)
                        gui_stubs = gui_stubs + 1
        except Exception, e:
            _log("  LoadBridge stub FAILED: " + str(e))

        # MultiplayerMenus GUI functions
        try:
            mm = sys.modules.get('Multiplayer.MultiplayerMenus', None)
            if mm:
                for fn_name in dir(mm):
                    obj = getattr(mm, fn_name)
                    if hasattr(obj, 'func_code'):
                        # Stub all functions - it's all UI code
                        setattr(mm, fn_name, _noop_gui)
                        gui_stubs = gui_stubs + 1
        except Exception, e:
            _log("  MultiplayerMenus stub FAILED: " + str(e))

        # Mission1 GUI functions
        if hasattr(m1, 'CreateMenus'):
            m1.CreateMenus = _noop_gui
            gui_stubs = gui_stubs + 1

        # Stub missing game-rule functions on MissionLib
        try:
            ml = sys.modules.get('MissionLib', None)
            if ml:
                ml_fns = []
                for x in dir(ml):
                    if x[0] != '_':
                        ml_fns.append(x)
                _log("  MissionLib functions: %s" % str(ml_fns[:30]))
                for fn_name in ['SetupFriendlyFireNoGameOver',
                                'SetupFriendlyFire',
                                'LoadDatabaseSoundInGroup']:
                    if not hasattr(ml, fn_name):
                        setattr(ml, fn_name, _noop_gui)
                        gui_stubs = gui_stubs + 1
                        _log("  Stubbed MissionLib.%s (missing)" % fn_name)
        except Exception, e:
            _log("  MissionLib stub FAILED: " + str(e))

        # Replace MissionShared.SetupEventHandlers with safe wrapper
        # Original crashes at SortedRegionMenu_GetWarpButton() returning None.
        # The broadcast handlers (network msg, scan, sound) register BEFORE the
        # warp button, so we wrap in try/except to keep the working registrations.
        import new
        _orig_ms_seh = new.function(ms.SetupEventHandlers.func_code,
                                     ms.SetupEventHandlers.func_globals,
                                     'SetupEventHandlers_orig')
        if ms.SetupEventHandlers.func_defaults:
            _orig_ms_seh.func_defaults = ms.SetupEventHandlers.func_defaults
        def _safe_ms_seh(pMission, _orig=_orig_ms_seh, _logfn=_log):
            try:
                _orig(pMission)
            except:
                ei = sys.exc_info()
                _logfn("  SetupEventHandlers caught: %s: %s (continuing)" %
                       (str(ei[0]), str(ei[1])))
        ms.SetupEventHandlers = _safe_ms_seh
        _log("  Wrapped MissionShared.SetupEventHandlers with try/except")

        # Wrap MissionShared.Initialize itself with try/except.
        # It crashes at line ~173 accessing Multiplayer.MultiplayerMenus;
        # wrapping lets Mission1.Initialize continue past it.
        _orig_ms_init = ms.Initialize
        def _safe_ms_init(pMission, _orig=_orig_ms_init, _logfn=_log):
            try:
                _orig(pMission)
            except:
                ei = sys.exc_info()
                _logfn("  MissionShared.Initialize caught: %s: %s (continuing)" %
                       (str(ei[0]), str(ei[1])))
        ms.Initialize = _safe_ms_init
        _log("  Wrapped MissionShared.Initialize with try/except")

        # Stub Mission1Menus GUI functions (BuildMission1Menus crashes headless)
        try:
            m1menus = sys.modules.get('Multiplayer.Episode.Mission1.Mission1Menus', None)
            if m1menus is None:
                __import__('Multiplayer.Episode.Mission1.Mission1Menus')
                m1menus = sys.modules.get('Multiplayer.Episode.Mission1.Mission1Menus', None)
            if m1menus:
                for fn_name in ['BuildMission1Menus', 'RebuildPlayerList',
                                'RebuildInfoPane', 'RebuildShipPane',
                                'ConfigureTeamPane', 'CreateMenus',
                                'BuildShipSelect', 'BuildTeamSelect']:
                    if hasattr(m1menus, fn_name):
                        setattr(m1menus, fn_name, _noop_gui)
                        gui_stubs = gui_stubs + 1
                _log("  Stubbed Mission1Menus GUI functions")
                # Set on Mission1 package for from-import resolution
                m1_pkg = sys.modules.get('Multiplayer.Episode.Mission1', None)
                if m1_pkg is not None:
                    m1_pkg.Mission1Menus = m1menus
                # Also inject into Mission1 func_globals for all functions
                for fname in dir(m1):
                    fn = getattr(m1, fname)
                    if hasattr(fn, 'func_globals'):
                        fn.func_globals['Mission1Menus'] = m1menus
        except Exception, e:
            _log("  Mission1Menus stub FAILED: " + str(e))

        # Wrap Mission1.SetupEventHandlers with try/except
        # (may crash on None GUI widget handlers like MissionShared's)
        if hasattr(m1, 'SetupEventHandlers'):
            _orig_m1_seh = m1.SetupEventHandlers
            def _safe_m1_seh(pMission, _orig=_orig_m1_seh, _logfn=_log):
                try:
                    _orig(pMission)
                except:
                    ei = sys.exc_info()
                    _logfn("  Mission1.SetupEventHandlers caught: %s: %s (continuing)" %
                           (str(ei[0]), str(ei[1])))
            m1.SetupEventHandlers = _safe_m1_seh
            _log("  Wrapped Mission1.SetupEventHandlers with try/except")

        _log("  Stubbed %d GUI functions total" % gui_stubs)

        # --- Introspect key functions ---
        for modname, mod, fnname in [('MissionShared', ms, 'Initialize'),
                                      ('Mission1', m1, 'Initialize'),
                                      ('MissionShared', ms, 'SetupEventHandlers')]:
            if hasattr(mod, fnname):
                co = getattr(mod, fnname).func_code
                _log("  %s.%s co_names: %s" % (modname, fnname, str(co.co_names)))
                if fnname == 'Initialize':
                    _log("  %s.%s co_consts: %s" % (modname, fnname, str(co.co_consts[:20])))

        # Check key App globals
        for gname in ['g_kUtopiaModule', 'g_kSetManager', 'g_kEventManager',
                      'g_kLocalizationManager']:
            try:
                val = getattr(App, gname, 'MISSING')
                _log("  App.%s = %s" % (gname, str(val)))
            except Exception, e:
                _log("  App.%s ERROR: %s" % (gname, str(e)))

        # --- Pre-check: verify key attributes before Initialize ---
        _mult = sys.modules.get('Multiplayer', None)
        if _mult:
            _log("  PRE-CHECK: Multiplayer.MultiplayerMenus = %s" %
                 str(hasattr(_mult, 'MultiplayerMenus')))
            _log("  PRE-CHECK: Multiplayer.MissionShared = %s" %
                 str(hasattr(_mult, 'MissionShared')))
            _ep_pkg = sys.modules.get('Multiplayer.Episode.Mission1', None)
            if _ep_pkg:
                _log("  PRE-CHECK: Episode.Mission1.Mission1Menus = %s" %
                     str(hasattr(_ep_pkg, 'Mission1Menus')))

        # --- START GAME SESSION ---
        # Call Mission1.Initialize() to register event handlers and load
        # databases.  MissionShared.Initialize may partially fail (caught)
        # but the critical handlers (ET_NETWORK_MESSAGE_EVENT etc.) and
        # TGL databases get registered/loaded before the crash point.
        _log("  Calling Mission1.Initialize(%s)..." % str(type(pMissionObj)))
        try:
            m1.Initialize(pMissionObj)
            _log("  Mission1.Initialize OK!")
        except:
            ei = sys.exc_info()
            _log("  Mission1.Initialize FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

        # --- Create the star system Set on the server ---
        # In the normal game, StartMission() calls CreateSystemFromSpecies()
        # which calls Multi1.Initialize(). That function uses shadow class
        # methods (pSet.SetRegionModule()) which fail in headless mode because
        # Appc.SetClass_Create() returns a raw SWIG pointer string, not a
        # shadow class instance. We use Appc functional API directly.
        # The server only needs the Set container + ProximityManager active.
        # Visual elements (asteroids, lights, backdrops) are created
        # independently by each client using the same deterministic seed.
        try:
            import Appc
            _sysName = sts.GetScriptFromSpecies(SERVER_SYSTEM)
            if _sysName:
                _regionModule = 'Systems.' + _sysName + '.' + _sysName

                # Create Set via raw Appc (returns raw SWIG pointer string)
                _pSetRaw = Appc.SetClass_Create()
                _log("  CreateSystem: raw Set = %s" % str(_pSetRaw))

                # Configure using functional API
                Appc.SetClass_SetRegionModule(_pSetRaw, _regionModule)

                # Register with SetManager (SWIG extracts .this from shadow)
                Appc.SetManager_AddSet(App.g_kSetManager, _pSetRaw, _sysName)

                # Activate ProximityManager for collision detection
                Appc.SetClass_SetProximityManagerActive(_pSetRaw, 1)

                # Store as shadow class for MissionShared
                ms.g_pStartingSet = App.SetClassPtr(_pSetRaw)
                _log("  CreateSystem: %s -> Set=%s (ProximityManager active)" %
                     (_sysName, str(ms.g_pStartingSet)))
            else:
                _log("  CreateSystem: no script for species %d" % SERVER_SYSTEM)
        except:
            ei = sys.exc_info()
            _log("  CreateSystem FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

        # Fire ET_START to transition game state (replicates host Start button)
        # TGEvent_Create returns a raw SWIG pointer string, so use functional API
        try:
            game = App.Game_GetCurrentGame()
            pStartEvent = App.TGEvent_Create()
            _log("  TGEvent_Create = %s (type=%s)" % (str(pStartEvent), str(type(pStartEvent))))
            # Try functional SWIG API first
            try:
                App.TGEvent_SetEventType(pStartEvent, App.ET_START)
            except AttributeError:
                # Maybe it's SetEventTypes (plural)?
                App.TGEvent_SetEventTypes(pStartEvent, App.ET_START)
            try:
                App.TGEvent_SetDestination(pStartEvent, game)
            except AttributeError:
                try:
                    App.TGEvent_SetDestinations(pStartEvent, game)
                except AttributeError:
                    pass  # Destination not required
            try:
                App.TGEventManager_AddEvent(App.g_kEventManager, pStartEvent)
            except AttributeError:
                try:
                    App.TGEventManager_AddEvents(App.g_kEventManager, pStartEvent)
                except AttributeError:
                    # Last resort: try shadow class wrapper
                    pEvt = App.TGEventPtr(pStartEvent)
                    pEvt.SetEventType(App.ET_START)
                    pEvt.SetDestination(game)
                    App.g_kEventManager.AddEvent(pEvt)
            _log("  ET_START event fired OK")
        except:
            ei = sys.exc_info()
            _log("  ET_START fire FAILED: %s: %s" % (str(ei[0]), str(ei[1])))
            # Log available TGEvent methods for debugging
            evt_methods = []
            for a in dir(App):
                if strop.find(a, 'TGEvent') >= 0:
                    evt_methods.append(a)
            _log("  App.TGEvent* methods: %s" % str(evt_methods))

        ms.g_bGameStarted = 1
        ms.g_bGameOver = 0
        # Also set on MissionMenusShared (game reads it from there too)
        try:
            _mms_ref = sys.modules.get('Multiplayer.MissionMenusShared', None)
            if _mms_ref:
                _mms_ref.g_bGameStarted = 1
        except:
            pass
        _log("  g_bGameStarted = %d, g_bGameOver = %d" %
             (ms.g_bGameStarted, ms.g_bGameOver))
        _log("  Scoring dicts: kills=%s deaths=%s" %
             (str(type(m1.g_kKillsDictionary)),
              str(type(m1.g_kDeathsDictionary))))
    except:
        ei = sys.exc_info()
        _log("  Game start FAILED: " + str(ei[0]) + ": " + str(ei[1]))

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
        _orig_InitObject = _sts_mod.InitObject
        _orig_CreateShip = _sts_mod.CreateShip
        _orig_GetShipFromSpecies = _sts_mod.GetShipFromSpecies

        def _wrapped_InitObject(self, iType):
            _log(">>> SpeciesToShip.InitObject(self=%s, iType=%d)" % (str(self), iType))
            try:
                kStats = _orig_GetShipFromSpecies(iType)
                _log("  GetShipFromSpecies -> %s" % str(kStats))
            except:
                ei = sys.exc_info()
                _log("  GetShipFromSpecies FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

            try:
                _log("  Calling SetupModel...")
                self.SetupModel(kStats['Name'])
                _log("  SetupModel OK")
            except:
                ei = sys.exc_info()
                _log("  SetupModel FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

            try:
                pPropertySet = self.GetPropertySet()
                _log("  GetPropertySet -> %s" % str(pPropertySet))
            except:
                ei = sys.exc_info()
                _log("  GetPropertySet FAILED: %s: %s" % (str(ei[0]), str(ei[1])))
                pPropertySet = None

            try:
                import App
                hpfile = kStats['HardpointFile']
                _log("  Importing ships.Hardpoints.%s..." % hpfile)
                hpmod = __import__("ships.Hardpoints." + hpfile)
                hpmod = sys.modules["ships.Hardpoints." + hpfile]
                App.g_kModelPropertyManager.ClearLocalTemplates()
                reload(hpmod)
                _log("  Hardpoint module loaded OK")
            except:
                ei = sys.exc_info()
                _log("  Hardpoint load FAILED: %s: %s" % (str(ei[0]), str(ei[1])))
                hpmod = None

            if pPropertySet and hpmod:
                try:
                    hpmod.LoadPropertySet(pPropertySet)
                    _log("  LoadPropertySet OK")
                except:
                    ei = sys.exc_info()
                    _log("  LoadPropertySet FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

                try:
                    self.SetupProperties()
                    _log("  SetupProperties OK")
                except:
                    ei = sys.exc_info()
                    _log("  SetupProperties FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

                try:
                    self.UpdateNodeOnly()
                    _log("  UpdateNodeOnly OK")
                except:
                    ei = sys.exc_info()
                    _log("  UpdateNodeOnly FAILED: %s: %s" % (str(ei[0]), str(ei[1])))
            else:
                _log("  SKIPPED LoadPropertySet (pPropertySet=%s hpmod=%s)" %
                     (str(pPropertySet), str(hpmod)))

            _log("<<< InitObject done")
            return 1

        _sts_mod.InitObject = _wrapped_InitObject
        _log("  Monkey-patched SpeciesToShip.InitObject with tracing")
    except:
        ei = sys.exc_info()
        _log("  SpeciesToShip monkey-patch FAILED: %s: %s" %
             (str(ei[0]), str(ei[1])))

    _log("DedicatedServer: Setup complete - server should be listening")
    print "DedicatedServer: Setup complete - server should be listening"
