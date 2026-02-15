###############################################################################
#   DSImportHook.py - Headless import hook for dedicated server
#
#   Wraps mission Python handlers with try/except so that GUI-related
#   AttributeErrors don't crash the headless server.  Mission scripts
#   assume GUI widgets exist (KillChildren, etc.) but in headless mode
#   those references are None.
#
#   Also fixes Python 1.5's package attribute linkage: ensures parent
#   packages have submodule attributes set (needed for IMPORT_FROM).
#
#   Python 1.5 compatible.
###############################################################################
import strop
import sys

_ds_orig_import = None
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

# Install the import hook
try:
    import __builtin__
    _ds_orig_import = __builtin__.__import__
    __builtin__.__import__ = _ds_safe_import
    print "DSImportHook: import hook installed"
except:
    print "DSImportHook: import hook FAILED"
