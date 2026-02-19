###############################################################################
#   PowerBarReorder.py
#
#   Reorders the power sliders on the F5 Engineering screen.
#   Place in scripts/Custom/ (checksum-exempt).
#
#   The C++ EngPowerCtrl widget hardcodes slider creation order as:
#       Weapons -> Engines -> Shields -> Sensors
#
#   This script monkey-patches Bridge.PowerDisplay.Init to rearrange
#   the bar positions after creation, similar to DOM reordering in HTML.
#
#   Usage:
#       import Custom.PowerBarReorder
#       Custom.PowerBarReorder.Install()
#
#   Call Install() once after bridge modules are loaded (e.g. from a
#   mission init script, or from an ET_ENTERED_SET handler for "bridge").
#
#   Edit DESIRED_ORDER below to set your preferred top-to-bottom order.
#
#   Python 1.5.2 compatible.
###############################################################################

import App

###############################################################################
#   Configuration
###############################################################################

# Stock order: ["Weapons", "Engines", "Shields", "Sensors"]
# Edit this to your preferred order:
DESIRED_ORDER = ["Engines", "Weapons", "Shields", "Sensors"]

###############################################################################
#   Internal state
###############################################################################

_installed = 0

###############################################################################
#   _getBar(pCtrl, pPlayer, name)
#
#   Returns the STNumericBar for a named subsystem group, matching the
#   C++ fallback logic in EngPowerCtrl::SetupForShip (FUN_0054d410):
#     Weapons: phasers > torpedoes > pulse
#     Engines: impulse > warp
###############################################################################
def _getBar(pCtrl, pPlayer, name):
    if name == "Weapons":
        pSys = pPlayer.GetPhaserSystem()
        if pSys:
            pBar = pCtrl.GetBarForSubsystem(pSys)
            if pBar:
                return pBar
        pSys = pPlayer.GetTorpedoSystem()
        if pSys:
            pBar = pCtrl.GetBarForSubsystem(pSys)
            if pBar:
                return pBar
        pSys = pPlayer.GetPulseWeaponSystem()
        if pSys:
            pBar = pCtrl.GetBarForSubsystem(pSys)
            if pBar:
                return pBar
    elif name == "Engines":
        pSys = pPlayer.GetImpulseEngineSubsystem()
        if pSys:
            pBar = pCtrl.GetBarForSubsystem(pSys)
            if pBar:
                return pBar
        pSys = pPlayer.GetWarpEngineSubsystem()
        if pSys:
            pBar = pCtrl.GetBarForSubsystem(pSys)
            if pBar:
                return pBar
    elif name == "Shields":
        pSys = pPlayer.GetShields()
        if pSys:
            return pCtrl.GetBarForSubsystem(pSys)
    elif name == "Sensors":
        pSys = pPlayer.GetSensorSubsystem()
        if pSys:
            return pCtrl.GetBarForSubsystem(pSys)
    return None

###############################################################################
#   ReorderSliders()
#
#   Rearranges power bar positions inside the EngPowerCtrl pane.
#
#   Strategy:
#     1. Get each bar via GetBarForSubsystem, record its current position
#     2. Sort the Y values to get the slot positions (top to bottom)
#     3. Compute a Y delta for each bar (current Y -> desired slot Y)
#     4. Walk ALL children of EngPowerCtrl; any child whose Y matches
#        a bar's original Y (within tolerance) gets moved by that delta
#        (this catches both the bar and its associated label icon)
###############################################################################
def ReorderSliders():
    pCtrl = App.EngPowerCtrl_GetPowerCtrl()
    if not pCtrl:
        return

    pPlayer = App.Game_GetCurrentPlayer()
    if not pPlayer:
        return

    STOCK = ["Weapons", "Engines", "Shields", "Sensors"]

    # --- Collect bars and their original positions ---
    bars = {}     # name -> STNumericBar
    origPos = {}  # name -> NiPoint2 (original position)
    for name in STOCK:
        pBar = _getBar(pCtrl, pPlayer, name)
        if pBar:
            bars[name] = pBar
            origPos[name] = pBar.GetPosition()

    if len(bars) < 2:
        return

    # --- Get slot Y positions sorted top to bottom ---
    slotYs = []
    for name in STOCK:
        if origPos.has_key(name):
            slotYs.append(origPos[name].y)
    slotYs.sort()

    # --- Assign slot Y to each bar per DESIRED_ORDER ---
    targetY = {}    # name -> desired Y
    idx = 0
    for name in DESIRED_ORDER:
        if bars.has_key(name):
            if idx < len(slotYs):
                targetY[name] = slotYs[idx]
                idx = idx + 1

    # --- Compute delta per bar group ---
    deltas = {}     # name -> float delta
    for name in bars.keys():
        if targetY.has_key(name):
            deltas[name] = targetY[name] - origPos[name].y

    # --- Walk all children; move those matching a bar's original Y ---
    # Each bar has an associated label icon as the previous sibling,
    # both positioned at the same Y.  The tolerance catches both.
    # Tick-mark icons at unrelated Y values are left untouched.
    moves = []      # list of (child, deltaY) -- collect first, apply later
    pChild = pCtrl.GetFirstChild()
    while pChild:
        kPos = pChild.GetPosition()
        bestName = None
        bestDist = 999.0
        for name in origPos.keys():
            dist = kPos.y - origPos[name].y
            if dist < 0:
                dist = -dist
            if dist < bestDist:
                bestDist = dist
                bestName = name

        if bestName and bestDist < 0.005 and deltas.has_key(bestName):
            d = deltas[bestName]
            if d < -0.001 or d > 0.001:    # skip if no movement needed
                moves.append((pChild, d))

        pChild = pCtrl.GetNextChild(pChild)

    # --- Apply all moves ---
    for i in range(len(moves)):
        child = moves[i][0]
        delta = moves[i][1]
        kPos = child.GetPosition()
        child.SetPosition(kPos.x, kPos.y + delta, 0)

    pCtrl.Layout()

###############################################################################
#   Install()
#
#   Monkey-patches Bridge.PowerDisplay.Init so that ReorderSliders()
#   runs automatically every time the power display is (re)initialized.
#
#   Safe to call multiple times -- only patches once.
###############################################################################
def Install():
    global _installed
    if _installed:
        return

    try:
        import Bridge.PowerDisplay
    except:
        print "PowerBarReorder: Bridge.PowerDisplay not loaded yet"
        return

    _origInit = Bridge.PowerDisplay.Init

    def _hookedInit(pPowerDisplay, _orig=_origInit):
        _orig(pPowerDisplay)
        try:
            ReorderSliders()
        except Exception, e:
            print "PowerBarReorder: reorder failed: " + str(e)

    Bridge.PowerDisplay.Init = _hookedInit
    _installed = 1
    print "PowerBarReorder: installed (order: %s)" % str(DESIRED_ORDER)

###############################################################################
#   InstallDeferred()
#
#   Registers an ET_ENTERED_SET broadcast handler that installs the
#   monkey-patch the first time the player enters the bridge set.
#   Use this if Bridge.PowerDisplay isn't loaded yet at call time.
###############################################################################
def InstallDeferred():
    if _installed:
        return

    pTop = App.TopWindow_GetTopWindow()
    if not pTop:
        print "PowerBarReorder: no TopWindow, cannot defer"
        return

    App.g_kEventManager.AddBroadcastPythonFuncHandler(
        App.ET_ENTERED_SET, pTop,
        __name__ + "._HandleEnteredSet")
    print "PowerBarReorder: deferred install registered"

def _HandleEnteredSet(pObject, pEvent):
    if _installed:
        # Already done, remove ourselves
        pObject.CallNextHandler(pEvent)
        return

    # Try to install now that bridge modules may be loaded
    Install()

    if _installed:
        # Success -- remove the handler so we don't fire again
        pTop = App.TopWindow_GetTopWindow()
        if pTop:
            App.g_kEventManager.RemoveBroadcastHandler(
                App.ET_ENTERED_SET, pTop,
                __name__ + "._HandleEnteredSet")

    pObject.CallNextHandler(pEvent)
