###############################################################################
#   ClientLocal.py
#
#   Drop-in replacement for Local.py on the CLIENT machine.
#   Copy to: <game dir>/Scripts/Local.py
#
#   Loads the ClientLogger and Observer diagnostic modules.
#
#   NOTE: BC's embedded Python has file writing disabled (open() for 'w'
#   fails). Python-level logging is NOT possible. All logging goes through
#   C-level hooks in the DDraw proxy (message_trace.log, packet_trace.log).
#
#   This file is checksum-exempt so vanilla clients can use it.
###############################################################################

print "ClientLocal.py loaded (debug logging + observer enabled)"

try:
    import Custom.ClientLogger
    print "ClientLogger module loaded OK"
except Exception, e:
    print "ClientLogger load FAILED: " + str(e)

try:
    import Custom.Observer
    print "Observer module loaded OK"
except Exception, e:
    print "Observer load FAILED: " + str(e)

try:
    import Custom.StateDumper
    print "StateDumper module loaded OK"
except Exception, e:
    print "StateDumper load FAILED: " + str(e)

###############################################################################
#   TopWindowInitialized()
#
#   Called by TopWindow.py when the main window is ready.
#   Mission modules should be loaded by this point, so we can
#   safely install our diagnostic hooks.
###############################################################################
def TopWindowInitialized(pTopWindow):
    try:
        import Custom.ClientLogger
        Custom.ClientLogger.InstallHooks()
        print "ClientLogger hooks installed"
    except Exception, e:
        print "ClientLogger hooks FAILED: " + str(e)
    try:
        import Custom.Observer
        Custom.Observer.InstallHooks()
        print "Observer hooks installed"
    except Exception, e:
        print "Observer hooks FAILED: " + str(e)
    # Manual state dumps are handled by C code (TryManualStateDump in ddraw proxy)
    # and trigger on F12 or left-click edge.
    # to avoid breaking the event system with Python raise propagation
