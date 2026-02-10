# DiagLocal.py - Diagnostic version of Local.py
# Copy this to scripts/Local.py in a STOCK game install (checksum exempt).
#
# What it does:
#   1. Game boots -> TopWindowInitialized -> automatic DUMP #1
#   2. F12 key registered as manual dump trigger - press ANY TIME
#   3. Import hooks auto-dump when multiplayer modules first load
#   4. Code path tracing records all function calls between dumps
#
# At each debug console popup: copy-paste the text, click OK to continue.
# The trace section shows every unique function called since last dump.

import sys
import strop

# Modules we want to auto-dump on first import
_WATCH_KEYWORDS = [
    "Multiplayer",
    "MissionShared",
    "LoadTriggers",
    "MultiplayerGame",
    "QuickBattle",
]

_seen_modules = {}
_orig_import = None

def _should_watch(name):
    """Check if module name matches any watch keyword."""
    for kw in _WATCH_KEYWORDS:
        if strop.find(name, kw) >= 0:
            return 1
    return 0

def _diag_import(*args):
    """Override __import__ to auto-dump state on key module loads."""
    global _orig_import, _seen_modules

    # Call real import first so module is available for state dump
    result = apply(_orig_import, args)

    name = args[0]
    if _should_watch(name) and not _seen_modules.has_key(name):
        _seen_modules[name] = 1
        try:
            import Custom.StateDumper
            Custom.StateDumper.dump_state("AUTO: import %s" % name)
        except:
            pass  # dump_state raises intentionally

    return result

def _install_import_hook():
    """Replace __import__ with diagnostic version."""
    global _orig_import
    try:
        import __builtin__
        _orig_import = __builtin__.__import__
        __builtin__.__import__ = _diag_import
    except:
        pass

def TopWindowInitialized():
    """Called by engine when main menu is ready.
    This is our entry point for all diagnostics."""

    # 1. Install F12 key handler for manual dumps
    try:
        import Custom.StateDumper
        Custom.StateDumper.install_f12()
    except:
        pass

    # 2. Install import hook for auto-dumps on screen transitions
    _install_import_hook()

    # 3. First automatic state dump - main menu baseline
    #    This raises an exception to show the debug console.
    #    Copy the text, click OK, then game continues normally.
    #    Press F12 at any time for another dump.
    import Custom.StateDumper
    Custom.StateDumper.dump_state("MAIN MENU (TopWindowInitialized)")
