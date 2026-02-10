# Custom/StateDumper.py - Bridge Commander State Dumper
# Python 1.5.2 Compatible - Place in scripts/Custom/ (checksum exempt)
#
# Usage:
#   Press F12 at ANY time to dump full engine state to state_dump.log.
#
#   Or from Python:
#     import Custom.StateDumper
#     Custom.StateDumper.dump_state("label")
#
# Output goes to state_dump.log via the DDraw proxy's C-level intercept
# of the debug console function. Python "raise text" propagates to C,
# which writes to file silently (no popup, no "resume" needed).
# Trace recording captures all code paths between dumps.

import sys
import strop

# --- Trace machinery ---
_trace_log = []
_trace_active = 0
_trace_seen = {}
_dump_count = 0

def _safe_str(obj):
    try:
        s = str(obj)
        if len(s) > 120:
            s = s[:120] + "..."
        return s
    except:
        return "<str err>"

def _safe_dir(obj):
    try:
        return dir(obj)
    except:
        return []

# ---------------------------------------------------------------
# Trace: records unique function calls between dump points
# ---------------------------------------------------------------
def _trace_func(frame, event, arg):
    global _trace_log, _trace_active, _trace_seen
    if not _trace_active:
        return None
    if event == 'call':
        co = frame.f_code
        fn = co.co_filename
        # Skip our own module
        if strop.find(fn, "StateDumper") >= 0:
            return _trace_func
        key = "%s:%s" % (fn, co.co_name)
        if not _trace_seen.has_key(key):
            _trace_seen[key] = 1
            _trace_log.append(key)
            # Cap at 800 unique calls to avoid huge output
            if len(_trace_log) >= 800:
                _trace_active = 0
                sys.settrace(None)
                return None
    return _trace_func

def start_trace():
    """Begin recording unique function calls."""
    global _trace_log, _trace_active, _trace_seen
    _trace_log = []
    _trace_seen = {}
    _trace_active = 1
    sys.settrace(_trace_func)

def stop_trace():
    """Stop recording. Returns list of 'file:func' strings."""
    global _trace_active
    _trace_active = 0
    sys.settrace(None)
    return _trace_log

# ---------------------------------------------------------------
# State collectors
# ---------------------------------------------------------------

def _collect_sys_info():
    lines = []
    lines.append("sys.version: %s" % _safe_str(sys.version))
    lines.append("sys.platform: %s" % _safe_str(sys.platform))
    lines.append("sys.path (%d entries):" % len(sys.path))
    for p in sys.path:
        lines.append("  %s" % p)
    keys = sys.modules.keys()
    keys.sort()
    lines.append("sys.modules (%d loaded):" % len(keys))
    for k in keys:
        m = sys.modules[k]
        if m is None:
            lines.append("  %-45s None" % k)
        else:
            lines.append("  %-45s <module>" % k)
    return lines

def _collect_app_attrs():
    lines = []
    try:
        import App
    except:
        return ["  App module not importable"]
    attrs = _safe_dir(App)
    lines.append("App: %d attributes" % len(attrs))
    # Separate into categories
    constants = []
    functions = []
    objects = []
    for a in attrs:
        if a[0] == '_':
            continue
        try:
            val = getattr(App, a)
        except:
            objects.append("  %-40s <getattr failed>" % a)
        else:
            t = type(val).__name__
            if t == 'int' or t == 'float' or t == 'long':
                constants.append("  %-40s = %s" % (a, _safe_str(val)))
            elif t == 'builtin_function_or_method' or t == 'function':
                functions.append("  %-40s (%s)" % (a, t))
            else:
                s = _safe_str(val)
                objects.append("  %-40s %-15s = %s" % (a, "(" + t + ")", s))

    if len(constants) > 0:
        lines.append("-- Constants/Values (%d) --" % len(constants))
        lines = lines + constants
    if len(objects) > 0:
        lines.append("-- Objects (%d) --" % len(objects))
        lines = lines + objects
    if len(functions) > 0:
        lines.append("-- Functions (%d) --" % len(functions))
        lines = lines + functions
    return lines

def _collect_appc_attrs():
    lines = []
    try:
        import Appc
    except:
        return ["  Appc module not importable"]
    attrs = _safe_dir(Appc)
    lines.append("Appc: %d attributes" % len(attrs))
    objects = []
    for a in attrs:
        if a[0] == '_':
            continue
        try:
            val = getattr(Appc, a)
        except:
            pass
        else:
            t = type(val).__name__
            if t != 'builtin_function_or_method' and t != 'function':
                s = _safe_str(val)
                objects.append("  %-40s %-15s = %s" % (a, "(" + t + ")", s))
    if len(objects) > 0:
        lines = lines + objects
    else:
        lines.append("  (no non-function attributes)")
    return lines

def _inspect_game_attr(lines, game, a):
    """Inspect a single game attribute, appending to lines if it is a value."""
    try:
        val = getattr(game, a)
    except:
        return
    t = type(val).__name__
    if t != 'builtin_function_or_method' and t != 'instance method':
        lines.append("    %-34s = %s" % (a, _safe_str(val)))

def _collect_game_state():
    lines = []
    try:
        import App
        game = App.Game_GetCurrentGame()
        lines.append("CurrentGame: %s" % _safe_str(game))
        if game is not None:
            gattrs = _safe_dir(game)
            lines.append("  %d attributes" % len(gattrs))
            for a in gattrs:
                if a[0] != '_':
                    _inspect_game_attr(lines, game, a)
            # Try known methods
            _try_method(lines, game, "GetPlayerName", [])
            _try_method(lines, game, "GetPlayer", [])
            _try_method(lines, game, "GetNumPlayers", [])
    except:
        ei = sys.exc_info()
        lines.append("  error: %s: %s" % (str(ei[0]), str(ei[1])))
    return lines

def _try_method(lines, obj, method, args):
    try:
        fn = getattr(obj, method)
        result = apply(fn, args)
        lines.append("    .%s() = %s" % (method, _safe_str(result)))
    except:
        pass

def _inspect_obj_attr(lines, obj, a, prefix):
    """Inspect a single object attribute, appending to lines if it is a value."""
    try:
        val = getattr(obj, a)
    except:
        return
    t = type(val).__name__
    if t != 'builtin_function_or_method' and t != 'instance method':
        lines.append("  %s%-34s = %s" % (prefix, a, _safe_str(val)))

def _collect_set_info():
    lines = []
    try:
        import App
        sm = App.g_kSetManager
        lines.append("SetManager: %s" % _safe_str(sm))
        if sm is not None:
            smattrs = _safe_dir(sm)
            for a in smattrs:
                if a[0] != '_':
                    _inspect_obj_attr(lines, sm, a, ".")
    except:
        ei = sys.exc_info()
        lines.append("  error: %s: %s" % (str(ei[0]), str(ei[1])))
    return lines

def _collect_network_state():
    lines = []
    try:
        import App
        # Try to access multiplayer game
        try:
            mpg = App.Game_GetCurrentGame()
            if mpg is not None:
                _try_method(lines, mpg, "GetMaxPlayers", [])
                _try_method(lines, mpg, "GetNumPlayers", [])
        except:
            pass

        # Check UtopiaModule for network ptrs
        try:
            um = App.g_kUtopiaModule
            lines.append("UtopiaModule: %s" % _safe_str(um))
            if um is not None:
                umattrs = _safe_dir(um)
                for a in umattrs:
                    if a[0] != '_':
                        _inspect_obj_attr(lines, um, a, ".")
        except:
            lines.append("  UtopiaModule not available")
    except:
        ei = sys.exc_info()
        lines.append("  error: %s: %s" % (str(ei[0]), str(ei[1])))
    return lines

def _inspect_module_value(vals, m, a):
    """Inspect a single module attribute, appending to vals if it is a data value."""
    try:
        val = getattr(m, a)
    except:
        return
    t = type(val).__name__
    if t != 'function' and t != 'builtin_function_or_method' and t != 'module':
        s = _safe_str(val)
        vals.append("  %-36s = %s" % (a, s))

def _collect_mission_globals():
    lines = []
    target_mods = [
        "MissionShared",
        "Multiplayer.MissionShared",
        "LoadTriggers",
        "MissionLib",
        "Multiplayer.MultiplayerMenus",
        "Custom.DedicatedServer",
    ]
    for mname in target_mods:
        if not sys.modules.has_key(mname):
            continue
        m = sys.modules[mname]
        if m is None:
            lines.append("%s: None (failed import)" % mname)
            continue
        attrs = _safe_dir(m)
        vals = []
        for a in attrs:
            if a[0] != '_':
                _inspect_module_value(vals, m, a)
        if len(vals) > 0:
            lines.append("%s (%d values):" % (mname, len(vals)))
            lines = lines + vals
    if len(lines) == 0:
        lines.append("  (no mission modules loaded yet)")
    return lines

# ---------------------------------------------------------------
# Main dump function
# ---------------------------------------------------------------

def dump_state(label):
    """Collect all accessible state and write to state_dump.log.
    Falls back to raising to the debug console if file logging unavailable."""
    global _dump_count
    _dump_count = _dump_count + 1

    # Stop trace and grab log
    trace = stop_trace()

    sections = []
    sections.append("=" * 70)
    sections.append("  STATE DUMP #%d: %s" % (_dump_count, label))
    sections.append("=" * 70)

    # Trace results
    if len(trace) > 0:
        sections.append("")
        sections.append("--- CODE PATHS SINCE LAST DUMP (%d unique calls) ---" % len(trace))
        for entry in trace:
            sections.append("  %s" % entry)

    # System info
    sections.append("")
    sections.append("--- SYSTEM INFO ---")
    sections = sections + _collect_sys_info()

    # App module
    sections.append("")
    sections.append("--- APP MODULE ---")
    sections = sections + _collect_app_attrs()

    # Appc module
    sections.append("")
    sections.append("--- APPC MODULE ---")
    sections = sections + _collect_appc_attrs()

    # Game state
    sections.append("")
    sections.append("--- GAME STATE ---")
    sections = sections + _collect_game_state()

    # Network
    sections.append("")
    sections.append("--- NETWORK STATE ---")
    sections = sections + _collect_network_state()

    # Sets
    sections.append("")
    sections.append("--- SET MANAGER ---")
    sections = sections + _collect_set_info()

    # Mission globals
    sections.append("")
    sections.append("--- MISSION MODULE GLOBALS ---")
    sections = sections + _collect_mission_globals()

    sections.append("")
    sections.append("=" * 70)
    sections.append("  END DUMP #%d" % _dump_count)
    sections.append("=" * 70)

    # Restart trace for next dump
    start_trace()

    # Raise as exception - the DDraw proxy intercepts the debug console
    # function (FUN_006f9470) and writes the text to state_dump.log.
    # No popup, no user interaction needed.
    raise strop.join(sections, "\n")


# ---------------------------------------------------------------
# F12 keyboard handler - press F12 anywhere to dump state
# ---------------------------------------------------------------

_f12_installed = 0

def HandleF12(pWindow, pEvent):
    """Global keyboard handler - triggers state dump on F12.
    dump_state() raises a string exception which propagates to the
    C engine's exception handler. Our replacement (PatchDebugConsoleToFile)
    intercepts it and writes to state_dump.log silently."""
    import App
    cKey = pEvent.GetUnicode()
    eState = pEvent.GetKeyState()
    # Only fire on key DOWN, not repeats
    if cKey == App.WC_F12 and eState == App.TGKeyboardEvent.KS_KEYDOWN:
        pEvent.SetHandled()
        dump_state("F12 MANUAL DUMP")

def install_f12():
    """Register F12 as global state dump trigger on the root window."""
    global _f12_installed
    if _f12_installed:
        return
    try:
        import App
        App.g_kRootWindow.AddPythonFuncHandlerForInstance(
            App.ET_KEYBOARD,
            "Custom.StateDumper.HandleF12"
        )
        _f12_installed = 1
    except:
        pass
