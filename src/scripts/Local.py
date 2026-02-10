###############################################################################
#   Local.py
#
#   Local customization hook for Star Trek: Bridge Commander
#   This file is automatically loaded by the game during startup.
#   It is EXEMPT from multiplayer checksums.
#
#   Features:
#     - Dedicated Server mode (if dedicated.cfg exists)
#
###############################################################################

# File-based logging (stdout redirect may not work for Python in stub mode)
def _log(msg):
    try:
        import sys
        _bp = getattr(sys, '_ds_base_path', '')
        f = open(_bp + "dedicated_init.log", "a")
        f.write(msg + "\n")
        f.close()
    except:
        pass

_log("=== Local.py loading ===")

import sys
_log("sys.path = " + str(sys.path))
_log("sys.modules keys = " + str(sys.modules.keys()))

try:
    import App
    _log("import App: OK, App=" + str(App))
    _log("App type = " + str(type(App)))
except Exception, e:
    _log("import App: FAILED: " + str(e))

print "Local.py loaded"

try:
    import Custom.StateDumper
    _log("Custom.StateDumper imported OK")
    print "StateDumper module loaded OK"
except Exception, e:
    _log("StateDumper FAILED: " + str(e))
    print "StateDumper load FAILED: " + str(e)

# Import dedicated server module from Custom directory
try:
    import Custom.DedicatedServer
    _log("Custom.DedicatedServer imported OK")
    print "Custom.DedicatedServer imported OK"
    Custom.DedicatedServer.Initialize()
    _log("Initialize() called OK")
    print "Initialize() called OK"
except Exception, e:
    _log("DedicatedServer FAILED: " + str(e))
    import traceback, cStringIO
    sio = cStringIO.StringIO()
    traceback.print_exc(file=sio)
    _log(sio.getvalue())
    print "DedicatedServer FAILED: " + str(e)

###############################################################################
#   TopWindowInitialized()
#
#   Called by TopWindow.py when the main window is ready.
###############################################################################
def TopWindowInitialized(pTopWindow):
    _log("TopWindowInitialized CALLED")
    try:
        _log("TopWindowInitialized pTopWindow type = " + str(type(pTopWindow)))
    except:
        _log("TopWindowInitialized str(type) failed")
    try:
        import Custom.DedicatedServer
        Custom.DedicatedServer.TopWindowInitialized(pTopWindow)
        _log("TopWindowInitialized: DedicatedServer hook OK")
    except Exception, e:
        _log("DedicatedServer TopWindow hook failed: " + str(e))
        import traceback, cStringIO
        sio = cStringIO.StringIO()
        traceback.print_exc(file=sio)
        _log(sio.getvalue())
        print "DedicatedServer TopWindow hook failed: %s" % str(e)
