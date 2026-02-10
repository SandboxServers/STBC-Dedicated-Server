###############################################################################
#   Observer.py
#
#   Passive event/state observer for Star Trek: Bridge Commander.
#   Place in Scripts/Custom/ (checksum-exempt directory).
#   Load from Local.py with: import Custom.Observer
#
#   Wraps TGEventManager.AddEvent to count all game events.
#   Also wraps key multiplayer handlers for tracing.
#
#   NOTE: BC's embedded Python has file writing disabled. Event data
#   is kept in memory only. Use LogEventSummary() to print counts.
#   All file-based logging goes through C hooks (message_trace.log).
#
#   Python 1.5 compatible. Zero gameplay impact.
###############################################################################
import sys, new

def _obs_log(msg):
    """Log to stdout (goes to BC console, not a file)."""
    try:
        print msg
    except:
        pass

_obs_log("=== Observer.py loaded ===")

# Build reverse lookup table: event type int -> name string
_evt_names = {}

def _build_event_names():
    """Build event type number -> name mapping from App module."""
    try:
        import App
        _g = vars(App)
        for k in _g.keys():
            if k[:3] == 'ET_':
                v = _g[k]
                if type(v) == type(0):
                    _evt_names[v] = k
        _obs_log("  Built event name table: %d entries" % len(_evt_names))
    except:
        _obs_log("  WARNING: Could not build event name table")

def _evt_name(etype):
    """Get human-readable name for an event type."""
    if _evt_names.has_key(etype):
        return _evt_names[etype]
    return "ET_?(%d)" % etype

# Event counter to avoid flooding the log with high-frequency events
_evt_counts = {}
_evt_suppress_threshold = 50  # log first N of each type, then summarize

def _wrap_add_event():
    """Wrap TGEventManager.AddEvent to count all events."""
    try:
        import App
        _orig = App.TGEventManager.AddEvent.im_func
    except:
        _obs_log("  WARNING: Could not get AddEvent method")
        return 0

    def _logged_add_event(self, pEvent, _orig=_orig,
                          _names=_evt_name, _counts=_evt_counts,
                          _thresh=_evt_suppress_threshold):
        try:
            etype = pEvent.GetEventType()
            if _counts.has_key(etype):
                _counts[etype] = _counts[etype] + 1
            else:
                _counts[etype] = 1
        except:
            pass
        return _orig(self, pEvent)

    try:
        import App
        App.TGEventManager.AddEvent = new.instancemethod(
            _logged_add_event, None, App.TGEventManager)
        _obs_log("  Wrapped TGEventManager.AddEvent")
        return 1
    except:
        _obs_log("  WARNING: Failed to wrap AddEvent")
        return 0


def _wrap_multiplayer_handlers():
    """Wrap key multiplayer Python handlers for tracing."""
    count = 0

    # ProcessMessageHandler in MissionShared
    try:
        __import__('Multiplayer.MissionShared')
        _ms = sys.modules['Multiplayer.MissionShared']
        if hasattr(_ms, 'ProcessMessageHandler'):
            _orig = _ms.ProcessMessageHandler
            def _logged(self, pEvent, _orig=_orig):
                return _orig(self, pEvent)
            _ms.ProcessMessageHandler = _logged
            _obs_log("  Wrapped MissionShared.ProcessMessageHandler")
            count = count + 1
    except:
        _obs_log("  MissionShared not loaded yet")

    # MultiplayerMenus.ProcessMessageHandler
    try:
        __import__('Multiplayer.MultiplayerMenus')
        _mm = sys.modules['Multiplayer.MultiplayerMenus']
        if hasattr(_mm, 'ProcessMessageHandler'):
            _orig = _mm.ProcessMessageHandler
            def _logged(self, pEvent, _orig=_orig):
                return _orig(self, pEvent)
            _mm.ProcessMessageHandler = _logged
            _obs_log("  Wrapped MultiplayerMenus.ProcessMessageHandler")
            count = count + 1
    except:
        _obs_log("  MultiplayerMenus not loaded yet")

    return count


def InstallHooks():
    """Install all observer hooks. Call after mission modules load."""
    _obs_log("Observer: Installing hooks...")
    _build_event_names()
    _wrap_add_event()
    n = _wrap_multiplayer_handlers()
    _obs_log("Observer: %d multiplayer handlers wrapped" % n)
    _obs_log("Observer: Hook installation complete")


def LogEventSummary():
    """Print summary of all events seen so far."""
    print "--- Event Summary ---"
    keys = _evt_counts.keys()
    keys.sort()
    for k in keys:
        print "  %s: %d times" % (_evt_name(k), _evt_counts[k])
    print "--- End Summary ---"


def GetEventCounts():
    """Return the event counts dict for programmatic access."""
    return _evt_counts


_obs_log("Observer: Ready (call InstallHooks() after mission modules load)")
