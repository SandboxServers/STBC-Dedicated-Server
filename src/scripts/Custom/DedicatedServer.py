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

_gPyDebug = None

def _pydbg(msg):
    global _gPyDebug
    try:
        if _gPyDebug is None:
            if hasattr(App, "CPyDebug"):
                _gPyDebug = App.CPyDebug("DedicatedServer").Print
            else:
                _gPyDebug = 0
        if _gPyDebug:
            _gPyDebug(msg)
    except:
        pass

_pydbg("DedicatedServer.py loading")

# Headless import hook (extracted to Custom/DSImportHook.py)
__import__('Custom.DSImportHook')

###############################################################################
#   File-based logging (more reliable than print in stub mode)
###############################################################################
def _log(msg):
    try:
        _bp = getattr(sys, '_ds_base_path', '')
        f = open(_bp + "dedicated_init.log", "a")
        f.write(msg + "\n")
        f.close()
        if strop.find(msg, "DedicatedServer:") == 0:
            _pydbg(msg)
    except:
        pass

# Mission module patching (extracted to Custom/DSPatches.py)
__import__('Custom.DSPatches')
_patches = sys.modules['Custom.DSPatches']
PatchLoadedMissionModules = _patches.PatchLoadedMissionModules
_noop_gui = _patches._noop_gui

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

# SWIG compatibility wrappers (extracted to Custom/DSSwig.py)
__import__('Custom.DSSwig')
_swig = sys.modules['Custom.DSSwig']
EnsureAppPointerWrappers = _swig.EnsureAppPointerWrappers
FixAppShadowWrappers = _swig.FixAppShadowWrappers

def Initialize():
    print "DedicatedServer: Initialize()"
    _log("DedicatedServer: Initialize()")
    _pydbg("DedicatedServer: Initialize()")
    EnsureAppPointerWrappers()
    FixAppShadowWrappers()

###############################################################################
#   CreateSystemSet - creates the star system Set with ProximityManager
#
#   Extracted from TopWindowInitialized so it can be called from
#   GameLoopTimerProc AFTER the ET_START cascade has had time to
#   load the episode/mission modules.
###############################################################################
def CreateSystemSet():
    """Create the star system Set. Called from GameLoopTimerProc after cascade."""
    try:
        import Appc
        __import__('Multiplayer.SpeciesToSystem')
        sts = sys.modules['Multiplayer.SpeciesToSystem']
        __import__('Multiplayer.MissionShared')
        ms = sys.modules['Multiplayer.MissionShared']

        _sysName = sts.GetScriptFromSpecies(SERVER_SYSTEM)
        if _sysName:
            _regionModule = 'Systems.' + _sysName + '.' + _sysName
            _pSetRaw = Appc.SetClass_Create()
            _log("CreateSystemSet: raw Set = %s" % str(_pSetRaw))
            Appc.SetClass_SetRegionModule(_pSetRaw, _regionModule)
            Appc.SetManager_AddSet(App.g_kSetManager, _pSetRaw, _sysName)
            Appc.SetClass_SetProximityManagerActive(_pSetRaw, 1)
            ms.g_pStartingSet = App.SetClassPtr(_pSetRaw)
            _log("CreateSystemSet: %s -> Set=%s (ProximityManager active)" %
                 (_sysName, str(ms.g_pStartingSet)))
        else:
            _log("CreateSystemSet: no script for species %d" % SERVER_SYSTEM)
    except:
        ei = sys.exc_info()
        _log("CreateSystemSet FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

###############################################################################
#   _init_game_config - Phase 2: Configure network, GameSpy, game settings
###############################################################################
def _init_game_config(um):
    """Phase 2: Configure network, GameSpy, game settings."""
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

    # --- Set VarManager mission variable ---
    # Episode.Initialize reads this via g_kVarManager.GetStringVariable()
    # to determine which mission to load. Must be set BEFORE the ET_START
    # cascade fires (which triggers Episode.Initialize -> LoadMission).
    # NOTE: Manual LoadEpisode/LoadMission calls were REMOVED. The stock
    # cascade (ET_START -> MultiplayerGame.Initialize -> Episode.Initialize
    # -> Mission1.Initialize) now handles loading via C++ callbacks.
    try:
        App.g_kVarManager.SetStringVariable("Multiplayer", "Mission", SERVER_GAME_MODE)
        _log("  VarManager: Set Multiplayer.Mission = %s" % SERVER_GAME_MODE)
    except Exception, e:
        _log("  VarManager.SetStringVariable FAILED: " + str(e))

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

# Network handler replacements (extracted to Custom/DSNetHandlers.py)
__import__('Custom.DSNetHandlers')
_nethnd = sys.modules['Custom.DSNetHandlers']
_init_network_handlers = _nethnd._init_network_handlers

###############################################################################
#   TopWindowInitialized - called from C-side DS_TIMER Phase 3
#
#   At this point, the C code has already:
#   - Set IsHost=1, IsMultiplayer=1
#   - Created WSN (TGWinsockNetwork) via FUN_00445d90
#   - Created MultiplayerGame/TopWindow via FUN_00504f10
#   - Phase 3: Calls this module's TopWindowInitialized()
#
#   We just need to set config values and report status.
###############################################################################
def TopWindowInitialized(pTopWindow):
    EnsureAppPointerWrappers()
    global g_pTopWindow
    g_pTopWindow = pTopWindow
    _log("TopWindowInitialized called, pTopWindow=" + str(pTopWindow))
    _log("  pTopWindow type = " + str(type(pTopWindow)))
    print "DedicatedServer: TopWindowInitialized"
    _pydbg("DedicatedServer: TopWindowInitialized")

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

    _init_game_config(um)

    # --- Initialize game (replicate "Start Game" button) ---
    # Stock flow: host clicks Start -> fires ET_START to TopWindow -> C++ cascade:
    #   MultiplayerGame.Initialize -> LoadEpisode -> Episode.Initialize
    #   -> LoadMission -> Mission1.Initialize -> SetupEventHandlers
    # We pre-import modules, set up stubs/wrappers, then fire ET_START.
    try:
        game = App.Game_GetCurrentGame()
        _log("  game = " + str(game))

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
        sub_mods = ['MissionShared', 'SpeciesToSystem', 'SpeciesToShip',
                    'MissionMenusShared', 'Episode']
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
        for subname in ['MissionShared', 'SpeciesToSystem', 'SpeciesToShip',
                        'MissionMenusShared', 'MissionShared2']:
            full = 'Multiplayer.' + subname
            sub = sys.modules.get(full, None)
            if sub is not None:
                setattr(mult_pkg, subname, sub)
        _log("  Force-set Multiplayer submodule attrs")
        _log("  Verify: hasattr(Multiplayer, MissionShared) = %s" %
             str(hasattr(mult_pkg, 'MissionShared')))
        _log("  Verify: Multiplayer.MissionShared = %s" %
             str(getattr(mult_pkg, 'MissionShared', 'MISSING')))

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

        # --- Headless MissionShared.SetupEventHandlers ---
        # Stock version crashes at SortedRegionMenu_GetWarpButton() (None headless).
        # Full replacement: register the 3 broadcast handlers, skip warp button.
        _ms_modname = 'Multiplayer.MissionShared'
        def _headless_ms_seh(pMission, _logfn=_log, _App=App,
                             _ms_modname=_ms_modname,
                             _ET_SUB_SOUND_DONE=ms.ET_SUBTITLED_SOUND_DONE):
            _logfn("MissionShared.SetupEventHandlers (headless)")
            _App.g_kEventManager.AddBroadcastPythonFuncHandler(
                _App.ET_NETWORK_MESSAGE_EVENT, pMission,
                _ms_modname + ".ProcessMessageHandler")
            _App.g_kEventManager.AddBroadcastPythonFuncHandler(
                _App.ET_SCAN, pMission,
                _ms_modname + ".ScanHandler")
            _App.g_kEventManager.AddBroadcastPythonFuncHandler(
                _ET_SUB_SOUND_DONE, pMission,
                _ms_modname + ".SoundDoneHandler")
            # Chat relay: replaces MultiplayerMenus.ProcessMessageHandler
            # which is never registered headless (no BuildMultiplayerWindow)
            _App.g_kEventManager.AddBroadcastPythonFuncHandler(
                _App.ET_NETWORK_MESSAGE_EVENT, pMission,
                "Custom.DedicatedServer.ChatRelayHandler")
            # Ship created: captures new ships for respawn fallback
            # (GetShipFromPlayerID returns NULL after respawn)
            _App.g_kEventManager.AddBroadcastPythonFuncHandler(
                _App.ET_OBJECT_CREATED_NOTIFY, pMission,
                "Custom.DedicatedServer.ShipCreatedHandler")
            # NOTE: ObjectKilledHandler is NOT registered here because
            # Mission1.SetupEventHandlers already registers it on
            # ET_OBJECT_EXPLODING.  We patched _m1.ObjectKilledHandler
            # in DSNetHandlers._init_network_handlers() to point to
            # _ds_ObjectKilledHandler, so the stock registration works.
            # Registering here too would cause 2x calls (× 2x dispatch = 4x).
            _logfn("  Registered 5 broadcast handlers (skip warp button, +chat, +ship created)")
            return 0
        ms.SetupEventHandlers = _headless_ms_seh
        _log("  Replaced MissionShared.SetupEventHandlers with headless version")

        # --- Headless MissionShared.Initialize ---
        # Stock version crashes on: LoadBridge GUI, MultiplayerMenus access,
        # LoadDatabaseSoundInGroup (audio). Full replacement: load TGL databases
        # safely, call our headless SetupEventHandlers, set state globals.
        def _headless_ms_init(pMission, _logfn=_log, _App=App, _ms=ms):
            _logfn("MissionShared.Initialize (headless)")
            # FriendlyFire (already set in TopWindowInitialized, but harmless)
            try:
                _App.g_kUtopiaModule.SetFriendlyFireWarningPoints(100)
            except:
                pass
            # Load TGL databases (may return None in headless - that's OK,
            # only used for localized UI strings we don't need)
            for _dbname, _dbattr in [
                ("data/TGL/Multiplayer.tgl", "g_pDatabase"),
                ("data/TGL/Ships.tgl", "g_pShipDatabase"),
                ("data/TGL/Systems.tgl", "g_pSystemDatabase"),
            ]:
                try:
                    _dbval = _App.g_kLocalizationManager.Load(_dbname)
                    setattr(_ms, _dbattr, _dbval)
                    _logfn("  %s = %s" % (_dbattr, str(_dbval)))
                except:
                    setattr(_ms, _dbattr, None)
                    _logfn("  %s FAILED (set to None)" % _dbattr)
            # Register event handlers (our headless version)
            _ms.SetupEventHandlers(pMission)
            # Set state globals
            _ms.g_idTimeLeftTimer = _App.NULL_ID
            _ms.g_bGameOver = 0
            # Skip: LoadBridge.CreateCharacterMenus() (GUI)
            # Skip: Multiplayer.MultiplayerMenus.g_bExitPressed (GUI)
            # Skip: LoadDatabaseSoundInGroup (audio)
            _logfn("MissionShared.Initialize (headless) OK")
        ms.Initialize = _headless_ms_init
        _log("  Replaced MissionShared.Initialize with headless version")

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

        # --- Install headless replacements for cascade functions ---
        # MultiplayerGame.Initialize loads sounds + UI (crashes headless).
        # Replace with headless version that only calls LoadEpisode.
        try:
            __import__('Multiplayer.MultiplayerGame')
            _mg_mod = sys.modules['Multiplayer.MultiplayerGame']
            def _headless_mg_init(pGame, _logfn=_log, _App=App):
                _logfn("MultiplayerGame.Initialize (headless)")
                try:
                    _App.g_kSetManager.ClearRenderedSet()
                except:
                    pass
                try:
                    _epName = _App.new_TGString("Multiplayer.Episode.Episode")
                    _App.Game_LoadEpisode(pGame, _epName)
                    _logfn("  LoadEpisode OK")
                except:
                    ei = sys.exc_info()
                    _logfn("  LoadEpisode FAILED: %s: %s" % (str(ei[0]), str(ei[1])))
            _mg_mod.Initialize = _headless_mg_init
            _log("  Replaced MultiplayerGame.Initialize with headless version")
        except:
            ei = sys.exc_info()
            _log("  MultiplayerGame.Initialize replace FAILED: %s: %s" %
                 (str(ei[0]), str(ei[1])))

        # Episode.Initialize crashes on GetChatWindow().
        # Replace with headless version that reads VarManager and calls LoadMission.
        try:
            __import__('Multiplayer.Episode.Episode')
            _ep_mod = sys.modules['Multiplayer.Episode.Episode']
            def _headless_ep_init(pEpisode, _logfn=_log, _App=App):
                _logfn("Episode.Initialize (headless)")
                try:
                    pcMission = _App.g_kVarManager.GetStringVariable(
                        "Multiplayer", "Mission")
                    _logfn("  VarManager Mission = %s" % str(pcMission))
                    _misName = _App.new_TGString(pcMission)
                    _App.Episode_LoadMission(pEpisode, _misName)
                    _logfn("  LoadMission OK")
                except:
                    ei = sys.exc_info()
                    _logfn("  Episode.Initialize FAILED: %s: %s" %
                           (str(ei[0]), str(ei[1])))
            _ep_mod.Initialize = _headless_ep_init
            _log("  Replaced Episode.Initialize with headless version")
        except:
            ei = sys.exc_info()
            _log("  Episode.Initialize replace FAILED: %s: %s" %
                 (str(ei[0]), str(ei[1])))

        _log("  Headless cascade replacements installed")

        # --- Fire ET_START event (may or may not trigger C++ cascade) ---
        try:
            pTopWindow = App.TopWindow_GetTopWindow()
            pStartEvent = App.TGEvent_Create()
            _log("  TGEvent_Create = %s" % str(pStartEvent))
            App.TGEvent_SetEventType(pStartEvent, App.ET_START)
            App.TGEvent_SetDestination(pStartEvent, pTopWindow)
            App.TGEventManager_AddEvent(App.g_kEventManager, pStartEvent)
            _log("  ET_START event fired to TopWindow OK")
        except:
            ei = sys.exc_info()
            _log("  ET_START fire FAILED: %s: %s" % (str(ei[0]), str(ei[1])))

        # --- Manual cascade fallback ---
        # C++ TopWindow doesn't dispatch ET_START to MultiplayerGame.Initialize.
        # Manually execute the headless cascade:
        #   LoadEpisode -> LoadMission -> Mission1.Initialize
        # Step 1: Headless MultiplayerGame.Initialize (calls LoadEpisode)
        try:
            _log("  Cascade fallback: calling headless MultiplayerGame.Initialize")
            _mg_mod.Initialize(game)
        except:
            ei = sys.exc_info()
            _log("  Cascade fallback: MG.Initialize FAILED: %s: %s" %
                 (str(ei[0]), str(ei[1])))

        # Step 2: Headless Episode.Initialize (calls LoadMission)
        try:
            curEp = App.Game_GetCurrentEpisode(game)
            _log("  Cascade fallback: Episode = %s" % str(curEp))
            if curEp is not None:
                _log("  Cascade fallback: calling headless Episode.Initialize")
                _ep_mod.Initialize(curEp)
        except:
            ei = sys.exc_info()
            _log("  Cascade fallback: Episode.Initialize FAILED: %s: %s" %
                 (str(ei[0]), str(ei[1])))

        # Step 3: Mission1.Initialize (with all stubs/wrappers pre-installed)
        # The raw SWIG pointer string (e.g. "_ccff288_p_Mission") must be
        # wrapped with a Ptr class so shadow class methods like
        # AddPythonFuncHandlerForInstance are available to SetupEventHandlers.
        try:
            curEp = App.Game_GetCurrentEpisode(game)
            if curEp is not None:
                pMissionObj = App.Episode_GetCurrentMission(curEp)
                _log("  Cascade fallback: Mission raw = %s (type=%s)" %
                     (str(pMissionObj), str(type(pMissionObj))))
                if pMissionObj is not None:
                    # Wrap raw SWIG pointer with shadow class
                    _wrapped = 0
                    for _ptrName in ['MissionPtr', 'TGObjectPtr']:
                        _ptrCls = getattr(App, _ptrName, None)
                        if _ptrCls is not None:
                            try:
                                pMissionObj = _ptrCls(pMissionObj)
                                _log("  Cascade fallback: wrapped as %s -> %s" %
                                     (_ptrName, str(type(pMissionObj))))
                                _wrapped = 1
                                break
                            except:
                                pass
                    if not _wrapped:
                        _log("  Cascade fallback: WARNING no Ptr wrapper found")
                    _log("  Cascade fallback: calling Mission1.Initialize")
                    m1.Initialize(pMissionObj)
                    _log("  Cascade fallback: Mission1.Initialize OK")
                else:
                    _log("  Cascade fallback: Mission object is None!")
            else:
                _log("  Cascade fallback: Episode is None after LoadEpisode!")
        except:
            ei = sys.exc_info()
            _log("  Cascade fallback: Mission1.Initialize FAILED: %s: %s" %
                 (str(ei[0]), str(ei[1])))

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

    _init_network_handlers()
    _log("DedicatedServer: Setup complete - server should be listening")
    print "DedicatedServer: Setup complete - server should be listening"
    _pydbg("DedicatedServer: Setup complete - server should be listening")

# Event handlers (extracted to Custom/DSHandlers.py)
__import__('Custom.DSHandlers')
_handlers = sys.modules['Custom.DSHandlers']
ChatRelayHandler = _handlers.ChatRelayHandler
ShipCreatedHandler = _handlers.ShipCreatedHandler
DeferredInitObject = _handlers.DeferredInitObject
_initobj_done = _handlers._initobj_done
_initobj_dead = _handlers._initobj_dead
_initobj_known = _handlers._initobj_known
_pending_ships = _handlers._pending_ships

# Scoring and game flow handlers (from DSNetHandlers.py)
ObjectKilledHandler = _nethnd._ds_ObjectKilledHandler
