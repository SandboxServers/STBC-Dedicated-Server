###############################################################################
#   DSSwig.py - SWIG compatibility wrappers for headless dedicated server
#
#   When BC's App.py stops executing partway through (headless boot),
#   App.*_Create/*_Cast functions remain as raw Appc builtins that return
#   SWIG pointer strings instead of shadow class instances.  These wrappers
#   intercept the calls and wrap the results with the correct Ptr classes.
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
#   Pointer wrapper helpers
###############################################################################

g_bAppWrapCompatInstalled = 0
g_pfnRaw_Game_GetCurrentGame = None
g_pfnRaw_TopWindow_GetTopWindow = None
g_pfnRaw_MultiplayerGame_Cast = None
g_pfnRaw_Game_GetCurrentPlayer = None

def _WrapPtrResult(pRawFn, pPtrClass, args, kwargs):
    """Call raw SWIG function and wrap pointer-string result to Ptr object."""
    val = apply(pRawFn, args, kwargs)
    if val and pPtrClass is not None:
        try:
            val = pPtrClass(val)
        except:
            pass
    return val

def _Compat_Game_GetCurrentGame(*args, **kwargs):
    global g_pfnRaw_Game_GetCurrentGame
    return _WrapPtrResult(g_pfnRaw_Game_GetCurrentGame,
                          getattr(App, 'GamePtr', None), args, kwargs)

def _Compat_TopWindow_GetTopWindow(*args, **kwargs):
    global g_pfnRaw_TopWindow_GetTopWindow
    return _WrapPtrResult(g_pfnRaw_TopWindow_GetTopWindow,
                          getattr(App, 'TopWindowPtr', None), args, kwargs)

def _Compat_MultiplayerGame_Cast(*args, **kwargs):
    global g_pfnRaw_MultiplayerGame_Cast
    return _WrapPtrResult(g_pfnRaw_MultiplayerGame_Cast,
                          getattr(App, 'MultiplayerGamePtr', None), args, kwargs)

def _Compat_Game_GetCurrentPlayer(*args, **kwargs):
    global g_pfnRaw_Game_GetCurrentPlayer
    return _WrapPtrResult(g_pfnRaw_Game_GetCurrentPlayer,
                          getattr(App, 'ShipClassPtr', None), args, kwargs)

###############################################################################
#   EnsureAppPointerWrappers - install Ptr wrappers for raw C API functions
###############################################################################

def EnsureAppPointerWrappers():
    """Install stock-like wrappers when App is raw C API (builtins only)."""
    global g_bAppWrapCompatInstalled
    global g_pfnRaw_Game_GetCurrentGame
    global g_pfnRaw_TopWindow_GetTopWindow
    global g_pfnRaw_MultiplayerGame_Cast
    global g_pfnRaw_Game_GetCurrentPlayer

    if g_bAppWrapCompatInstalled:
        return
    g_bAppWrapCompatInstalled = 1

    try:
        fn = getattr(App, 'Game_GetCurrentGame', None)
        if fn and not hasattr(fn, 'func_code'):
            g_pfnRaw_Game_GetCurrentGame = fn
            App.Game_GetCurrentGame = _Compat_Game_GetCurrentGame
            _log("Installed App compat wrapper: Game_GetCurrentGame -> GamePtr")
    except Exception, e:
        _log("App compat wrap failed (Game_GetCurrentGame): " + str(e))

    try:
        fn = getattr(App, 'TopWindow_GetTopWindow', None)
        if fn and not hasattr(fn, 'func_code'):
            g_pfnRaw_TopWindow_GetTopWindow = fn
            App.TopWindow_GetTopWindow = _Compat_TopWindow_GetTopWindow
            _log("Installed App compat wrapper: TopWindow_GetTopWindow -> TopWindowPtr")
    except Exception, e:
        _log("App compat wrap failed (TopWindow_GetTopWindow): " + str(e))

    try:
        fn = getattr(App, 'MultiplayerGame_Cast', None)
        if fn and not hasattr(fn, 'func_code'):
            g_pfnRaw_MultiplayerGame_Cast = fn
            App.MultiplayerGame_Cast = _Compat_MultiplayerGame_Cast
            _log("Installed App compat wrapper: MultiplayerGame_Cast -> MultiplayerGamePtr")
    except Exception, e:
        _log("App compat wrap failed (MultiplayerGame_Cast): " + str(e))

    try:
        fn = getattr(App, 'Game_GetCurrentPlayer', None)
        if fn and not hasattr(fn, 'func_code'):
            g_pfnRaw_Game_GetCurrentPlayer = fn
            App.Game_GetCurrentPlayer = _Compat_Game_GetCurrentPlayer
            _log("Installed App compat wrapper: Game_GetCurrentPlayer -> ShipClassPtr")
    except Exception, e:
        _log("App compat wrap failed (Game_GetCurrentPlayer): " + str(e))

###############################################################################
#   _SWIGWrapper class + FixAppShadowWrappers
###############################################################################

class _SWIGWrapper:
    """Callable wrapper: calls raw_fn and wraps result with ptr_cls."""
    def __init__(self, raw_fn, ptr_cls):
        self.raw_fn = raw_fn
        self.ptr_cls = ptr_cls
    def __call__(self, *args):
        val = apply(self.raw_fn, args)
        if val:
            val = self.ptr_cls(val)
        return val

def FixAppShadowWrappers():
    """Install shadow wrappers for App.*_Create/*_Cast that are raw Appc builtins.

    App.py does 'from Appc import *' then defines shadow wrapper functions later.
    If App.py stops executing partway, the wrapper functions are missing and
    App.*_Create returns raw SWIG pointer strings instead of wrapped objects.
    This fixes that by installing wrappers for all known _Create/_Cast functions.
    """
    import Appc
    _builtin_type = type(getattr(Appc, 'ShipProperty_Create', None))
    _fixed = 0

    # All property _Create/_Cast functions and their Ptr class names
    _wrapper_map = [
        # Properties
        ('TGModelProperty', 'TGModelPropertyPtr'),
        ('TGModelPropertySet', 'TGModelPropertySetPtr'),
        ('PositionOrientationProperty', 'PositionOrientationPropertyPtr'),
        ('SubsystemProperty', 'SubsystemPropertyPtr'),
        ('PoweredSubsystemProperty', 'PoweredSubsystemPropertyPtr'),
        ('WeaponSystemProperty', 'WeaponSystemPropertyPtr'),
        ('WeaponProperty', 'WeaponPropertyPtr'),
        ('EnergyWeaponProperty', 'EnergyWeaponPropertyPtr'),
        ('PhaserProperty', 'PhaserPropertyPtr'),
        ('PulseWeaponProperty', 'PulseWeaponPropertyPtr'),
        ('TractorBeamProperty', 'TractorBeamPropertyPtr'),
        ('TorpedoTubeProperty', 'TorpedoTubePropertyPtr'),
        ('TorpedoSystemProperty', 'TorpedoSystemPropertyPtr'),
        ('EngineGlowProperty', 'EngineGlowPropertyPtr'),
        ('ShieldProperty', 'ShieldPropertyPtr'),
        ('HullProperty', 'HullPropertyPtr'),
        ('SensorProperty', 'SensorPropertyPtr'),
        ('CloakingSubsystemProperty', 'CloakingSubsystemPropertyPtr'),
        ('RepairSubsystemProperty', 'RepairSubsystemPropertyPtr'),
        ('ShipProperty', 'ShipPropertyPtr'),
        ('PowerProperty', 'PowerPropertyPtr'),
        ('ImpulseEngineProperty', 'ImpulseEnginePropertyPtr'),
        ('WarpEngineProperty', 'WarpEnginePropertyPtr'),
        ('EngineProperty', 'EnginePropertyPtr'),
        ('EffectEmitterProperty', 'EffectEmitterPropertyPtr'),
        ('SmokeEmitterProperty', 'SmokeEmitterPropertyPtr'),
        ('SparkEmitterProperty', 'SparkEmitterPropertyPtr'),
        ('ExplodeEmitterProperty', 'ExplodeEmitterPropertyPtr'),
        ('BlinkingLightProperty', 'BlinkingLightPropertyPtr'),
        ('ObjectEmitterProperty', 'ObjectEmitterPropertyPtr'),
        # Events
        ('TGEvent', 'TGEventPtr'),
        ('TGBoolEvent', 'TGBoolEventPtr'),
        ('TGCharEvent', 'TGCharEventPtr'),
        ('TGShortEvent', 'TGShortEventPtr'),
        ('TGIntEvent', 'TGIntEventPtr'),
        ('TGFloatEvent', 'TGFloatEventPtr'),
        ('TGStringEvent', 'TGStringEventPtr'),
        ('TGVoidPtrEvent', 'TGVoidPtrEventPtr'),
        ('TGObjPtrEvent', 'TGObjPtrEventPtr'),
        ('TGMouseEvent', 'TGMouseEventPtr'),
        ('TGKeyboardEvent', 'TGKeyboardEventPtr'),
        ('TGGamepadEvent', 'TGGamepadEventPtr'),
        # Game objects
        ('SetClass', 'SetClassPtr'),
        ('Game', 'GamePtr'),
        ('BaseObjectClass', 'BaseObjectClassPtr'),
        ('ObjectClass', 'ObjectClassPtr'),
        ('ShipClass', 'ShipClassPtr'),
        ('PlayerClass', 'PlayerClassPtr'),
        # Other
        ('TGMessage', 'TGMessagePtr'),
        ('TGSequence', 'TGSequencePtr'),
        ('TGTimer', 'TGTimerPtr'),
        ('TGSound', 'TGSoundPtr'),
        ('TGLocalizationDatabase', 'TGLocalizationDatabasePtr'),
    ]

    for base_name, ptr_name in _wrapper_map:
        ptr_cls = getattr(App, ptr_name, None)
        if ptr_cls is None:
            continue
        # Fix _Create
        create_name = base_name + '_Create'
        app_fn = getattr(App, create_name, None)
        if app_fn is not None and type(app_fn) == _builtin_type:
            raw_fn = getattr(Appc, create_name, None)
            if raw_fn is not None:
                setattr(App, create_name, _SWIGWrapper(raw_fn, ptr_cls))
                _fixed = _fixed + 1
        # Fix _Cast
        cast_name = base_name + '_Cast'
        app_fn = getattr(App, cast_name, None)
        if app_fn is not None and type(app_fn) == _builtin_type:
            raw_fn = getattr(Appc, cast_name, None)
            if raw_fn is not None:
                setattr(App, cast_name, _SWIGWrapper(raw_fn, ptr_cls))
                _fixed = _fixed + 1

    _log("FixAppShadowWrappers: installed %d wrappers" % _fixed)
