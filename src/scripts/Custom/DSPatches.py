###############################################################################
#   DSPatches.py - Mission module patching for headless dedicated server
#
#   Scans sys.modules for mission modules (Mission1-5) and patches their
#   handler functions for headless safety.  Two strategies:
#   1. EVENT HANDLERS: Replace func_code IN-PLACE with try/except wrapper
#   2. GUI HELPERS: Replace module attribute with safe no-op function
#
#   Python 1.5 compatible.
###############################################################################
import strop
import sys

def _log(msg):
    """Delegate to DedicatedServer._log via sys.modules."""
    ds = sys.modules.get('Custom.DedicatedServer')
    if ds and hasattr(ds, '_log'):
        ds._log(msg)

# Get _ds_patched from import hook module
__import__('Custom.DSImportHook')
_ds_patched = sys.modules['Custom.DSImportHook']._ds_patched

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
