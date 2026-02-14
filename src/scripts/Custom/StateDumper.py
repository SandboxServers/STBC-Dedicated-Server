# Custom/StateDumper.py - Bridge Commander State Dumper
# Python 1.5.2 Compatible - Place in scripts/Custom/ (checksum exempt)
#
# Trace accumulates in _trace_log list. The C-side timer (TryFlushPyTrace)
# periodically calls into Python to grab the buffer, raise it as an
# exception, and write it to state_dump.log via PatchDebugConsoleToFile.
# Python never needs to write to disk itself.

import sys
import strop

# --- Configuration ---
MAX_CALLS = 5000000  # Hard cap

# --- Trace machinery ---
_trace_log = []
_trace_active = 0
_trace_total = 0

def _safe_str(obj):
    try:
        s = str(obj)
        if len(s) > 120:
            s = s[:120] + "..."
        return s
    except:
        return "<str err>"

def _trace_func(frame, event, arg):
    global _trace_log, _trace_active, _trace_total
    if not _trace_active:
        return None
    if event == 'call':
        co = frame.f_code
        fn = co.co_filename
        # Skip our own module to prevent recursion
        if strop.find(fn, "StateDumper") >= 0:
            return _trace_func
        # Build parameter string from locals matching arg names
        params = ""
        try:
            names = co.co_varnames[:co.co_argcount]
            parts = []
            for n in names:
                if frame.f_locals.has_key(n):
                    parts.append("%s=%s" % (n, _safe_str(frame.f_locals[n])))
            if len(parts) > 0:
                params = "(" + strop.join(parts, ", ") + ")"
        except:
            pass
        entry = "%s:%s%s" % (fn, co.co_name, params)
        _trace_log.append(entry)
        # Hard cap - stop tracing to avoid memory exhaustion
        if _trace_total + len(_trace_log) >= MAX_CALLS:
            _trace_active = 0
            sys.settrace(None)
            return None
    return _trace_func

def start_trace():
    """Begin recording all function calls."""
    global _trace_log, _trace_active, _trace_total
    _trace_log = []
    _trace_active = 1
    _trace_total = 0
    sys.settrace(_trace_func)

def stop_trace():
    """Stop recording."""
    global _trace_active
    _trace_active = 0
    sys.settrace(None)

# ---------------------------------------------------------------
# State dump - collects engine state snapshot
# Called from C via TriggerManualStateDump (F12 key).
# Raises the dump text as a string exception so C can write it
# to state_dump.log via ReplacementDebugConsole.
# ---------------------------------------------------------------
def dump_state(label):
    """Collect engine state and raise it for C to write to state_dump.log."""
    parts = []
    parts.append("=" * 60)
    parts.append("STATE DUMP: %s" % label)
    parts.append("=" * 60)

    # --- sys.modules ---
    parts.append("")
    parts.append("--- sys.modules (%d loaded) ---" % len(sys.modules))
    mods = sys.modules.keys()
    mods.sort()
    for m in mods:
        obj = sys.modules[m]
        if obj is None:
            parts.append("  %s = None" % m)
        else:
            parts.append("  %s = %s" % (m, _safe_str(obj)))

    # --- Key game state ---
    parts.append("")
    parts.append("--- Game State ---")
    try:
        import App
        parts.append("  App module loaded: yes")
    except:
        parts.append("  App module loaded: FAILED")
        App = None

    if App:
        try:
            parts.append("  App.g_kUtopiaModule: %s" % _safe_str(App.g_kUtopiaModule))
        except:
            parts.append("  App.g_kUtopiaModule: <error>")
        try:
            parts.append("  App.g_kEventManager: %s" % _safe_str(App.g_kEventManager))
        except:
            parts.append("  App.g_kEventManager: <error>")
        try:
            parts.append("  App.g_kSetManager: %s" % _safe_str(App.g_kSetManager))
        except:
            parts.append("  App.g_kSetManager: <error>")
        game = None
        try:
            game = App.Game_GetCurrentGame()
            parts.append("  CurrentGame: %s" % _safe_str(game))
        except:
            parts.append("  CurrentGame: <error>")
        ep = None
        try:
            if game is not None:
                ep = App.Game_GetCurrentEpisode(game)
            parts.append("  CurrentEpisode: %s" % _safe_str(ep))
        except:
            parts.append("  CurrentEpisode: <error>")
        try:
            if ep is not None:
                mis = App.Episode_GetCurrentMission(ep)
            else:
                mis = None
            parts.append("  CurrentMission: %s" % _safe_str(mis))
        except:
            parts.append("  CurrentMission: <error>")
        try:
            tw = App.TopWindow_GetTopWindow()
            parts.append("  TopWindow: %s" % _safe_str(tw))
        except:
            parts.append("  TopWindow: <error>")

    # --- MissionShared state ---
    parts.append("")
    parts.append("--- MissionShared ---")
    if sys.modules.has_key('Multiplayer.MissionShared'):
        ms = sys.modules['Multiplayer.MissionShared']
        for attr in ['g_pStartingSet', 'g_pDatabase', 'g_pShipDatabase',
                      'g_bGameStarted', 'g_bGameOver', 'g_iTimeLeft']:
            try:
                val = getattr(ms, attr)
                parts.append("  %s = %s" % (attr, _safe_str(val)))
            except:
                parts.append("  %s = <missing>" % attr)
    else:
        parts.append("  (not loaded)")

    # --- MissionMenusShared state ---
    parts.append("")
    parts.append("--- MissionMenusShared ---")
    if sys.modules.has_key('Multiplayer.MissionMenusShared'):
        mms = sys.modules['Multiplayer.MissionMenusShared']
        for attr in ['g_bGameStarted', 'g_iSpecies', 'g_iSystem',
                      'g_iTimeLimit', 'g_iFragLimit', 'g_iPlayerLimit']:
            try:
                val = getattr(mms, attr)
                parts.append("  %s = %s" % (attr, _safe_str(val)))
            except:
                parts.append("  %s = <missing>" % attr)
    else:
        parts.append("  (not loaded)")

    # --- DedicatedServer state ---
    parts.append("")
    parts.append("--- DedicatedServer ---")
    if sys.modules.has_key('Custom.DedicatedServer'):
        ds = sys.modules['Custom.DedicatedServer']
        for attr in ['SERVER_GAME_MODE', 'SERVER_SYSTEM', 'SERVER_TIME_LIMIT',
                      'SERVER_PLAYER_LIMIT', 'SERVER_GAME_NAME']:
            try:
                val = getattr(ds, attr)
                parts.append("  %s = %s" % (attr, _safe_str(val)))
            except:
                parts.append("  %s = <missing>" % attr)
    else:
        parts.append("  (not loaded)")

    # --- Mission1 state ---
    parts.append("")
    parts.append("--- Mission1 ---")
    if sys.modules.has_key('Multiplayer.Episode.Mission1.Mission1'):
        m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']
        for attr in ['g_kKillsDictionary', 'g_kDeathsDictionary',
                      'g_kScoresDictionary']:
            try:
                val = getattr(m1, attr)
                parts.append("  %s = %s" % (attr, _safe_str(val)))
            except:
                parts.append("  %s = <missing>" % attr)
    else:
        parts.append("  (not loaded)")

    # --- Trace stats ---
    parts.append("")
    parts.append("--- Trace Stats ---")
    parts.append("  _trace_active = %d" % _trace_active)
    parts.append("  _trace_total = %d" % _trace_total)
    parts.append("  _trace_log buffered = %d" % len(_trace_log))

    parts.append("")
    parts.append("=" * 60)

    msg = strop.join(parts, "\n")
    raise msg

# ---------------------------------------------------------------
# Tracing is OFF by default. Call start_trace() explicitly or
# use F12 (TriggerManualStateDump) for on-demand state dumps.
# Auto-start was removed because it generates 100s of MB on
# the client (traces every Python call including rendering).
# ---------------------------------------------------------------
