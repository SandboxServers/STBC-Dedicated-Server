###############################################################################
#   ClientLogger.py
#
#   Client-side diagnostic logging for Star Trek: Bridge Commander multiplayer.
#   Place this file in Scripts/Custom/ (checksum-exempt directory).
#   Load from Local.py with: import Custom.ClientLogger
#
#   Hooks ProcessMessageHandler and DoEndGameDialog to log what the
#   client receives and why disconnects happen.
#
#   Python 1.5 compatible.
###############################################################################
import sys

_cl_logfile = None

def _cl_log(msg):
    global _cl_logfile
    try:
        if _cl_logfile is None:
            _bp = getattr(sys, '_cl_base_path', '')
            _cl_logfile = open(_bp + "client_debug.log", "a")
        _cl_logfile.write(msg + "\n")
        _cl_logfile.flush()
    except:
        pass

_cl_log("=== ClientLogger.py loaded ===")


def _hook_mission1():
    """Hook Mission1 ProcessMessageHandler only."""
    try:
        __import__('Multiplayer.Episode.Mission1.Mission1')
        _m1 = sys.modules['Multiplayer.Episode.Mission1.Mission1']
    except:
        _cl_log("ClientLogger: Mission1 not loaded yet")
        return 0

    if hasattr(_m1, 'ProcessMessageHandler'):
        _orig_pmh = _m1.ProcessMessageHandler
        def _logged_pmh(self, pEvent, _orig=_orig_pmh, _logfn=_cl_log):
            _logfn(">>> CLIENT Mission1.ProcessMessageHandler called")
            try:
                result = _orig(self, pEvent)
                _logfn("    Mission1.PMH returned OK")
                return result
            except:
                ei = sys.exc_info()
                _logfn("    Mission1.PMH EXCEPTION: %s: %s" %
                       (str(ei[0]), str(ei[1])))

        _m1.ProcessMessageHandler = _logged_pmh
        _cl_log("  Hooked Mission1.ProcessMessageHandler")

    _cl_log("  Mission1 hooks installed")
    return 1


def _hook_missionshared():
    """Hook MissionShared ProcessMessageHandler."""
    try:
        __import__('Multiplayer.MissionShared')
        _ms = sys.modules['Multiplayer.MissionShared']
    except:
        _cl_log("ClientLogger: MissionShared not loaded yet")
        return 0

    if hasattr(_ms, 'ProcessMessageHandler'):
        _orig = _ms.ProcessMessageHandler
        def _logged(self, pEvent, _orig=_orig, _logfn=_cl_log):
            _logfn(">>> CLIENT MissionShared.ProcessMessageHandler called")
            try:
                result = _orig(self, pEvent)
                _logfn("    MissionShared.PMH returned OK")
                return result
            except:
                ei = sys.exc_info()
                _logfn("    MissionShared.PMH EXCEPTION: %s: %s" %
                       (str(ei[0]), str(ei[1])))

        _ms.ProcessMessageHandler = _logged
        _cl_log("  Hooked MissionShared.ProcessMessageHandler")

    return 1


def _hook_endgame():
    """Hook DoEndGameDialog to see WHY it's called."""
    try:
        __import__('Multiplayer.MissionMenusShared')
        _mms = sys.modules['Multiplayer.MissionMenusShared']
    except:
        _cl_log("ClientLogger: MissionMenusShared not loaded yet")
        return 0

    if hasattr(_mms, 'DoEndGameDialog'):
        _orig = _mms.DoEndGameDialog
        def _logged(bRestartable=0, pReasonString=None, bDoChat=0,
                    _orig=_orig, _logfn=_cl_log):
            _logfn(">>> CLIENT DoEndGameDialog: restartable=%s reason=%s doChat=%s" %
                   (str(bRestartable), str(pReasonString), str(bDoChat)))
            try:
                result = _orig(bRestartable, pReasonString, bDoChat)
                _logfn("    DoEndGameDialog returned: %s" % str(result))
                return result
            except:
                ei = sys.exc_info()
                _logfn("    DoEndGameDialog EXCEPTION: %s: %s" %
                       (str(ei[0]), str(ei[1])))

        _mms.DoEndGameDialog = _logged
        _cl_log("  Hooked MissionMenusShared.DoEndGameDialog")

    return 1


def _hook_multiplayermenus():
    """Hook MultiplayerMenus ProcessMessageHandler."""
    try:
        __import__('Multiplayer.MultiplayerMenus')
        _mm = sys.modules['Multiplayer.MultiplayerMenus']
    except:
        _cl_log("ClientLogger: MultiplayerMenus not loaded yet")
        return 0

    if hasattr(_mm, 'ProcessMessageHandler'):
        _orig = _mm.ProcessMessageHandler
        def _logged(self, pEvent, _orig=_orig, _logfn=_cl_log):
            _logfn(">>> CLIENT MultiplayerMenus.ProcessMessageHandler called")
            try:
                result = _orig(self, pEvent)
                _logfn("    MultiplayerMenus.PMH returned OK")
                return result
            except:
                ei = sys.exc_info()
                _logfn("    MultiplayerMenus.PMH EXCEPTION: %s: %s" %
                       (str(ei[0]), str(ei[1])))

        _mm.ProcessMessageHandler = _logged
        _cl_log("  Hooked MultiplayerMenus.ProcessMessageHandler")

    return 1


def InstallHooks():
    """Install all client-side diagnostic hooks."""
    _cl_log("ClientLogger: Installing hooks...")
    _hook_mission1()
    _hook_missionshared()
    _hook_endgame()
    _hook_multiplayermenus()
    _cl_log("ClientLogger: Hook installation complete")


_cl_log("ClientLogger: Ready (call InstallHooks() after mission modules load)")
