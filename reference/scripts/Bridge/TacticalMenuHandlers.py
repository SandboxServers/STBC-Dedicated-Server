###############################################################################
#	Filename:	TacticalMenuHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Create bridge tactical interface and handle bridge tactical menu events.
#	(i.e. Felix's menu)
#	
#	Created:	9/20/00 -	Alberto Fonseca
###############################################################################

import App
import BridgeHandlers
import BridgeUtils
import MissionLib

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " module...")

# We're one of those modules that shouldn't be unloaded until the game
# is gone.  During serialization/unserialization, the current game will
# be None, and we don't want to call AddPersistentModule then anyways.
if App.Game_GetCurrentGame():
	App.Game_GetCurrentGame().AddPersistentModule(__name__)

# Various subevent types for the ET_MANEUVER events.
EST_FIRST_ORDER					= 1
EST_ORDER_DESTROY				= 1
EST_ORDER_DISABLE				= 2
EST_ORDER_STOP					= 3
EST_ORDER_DEFENSE				= 4
EST_LAST_ORDER					= 9

EST_FIRST_TACTIC				= 10
EST_TACTIC_ATWILL				= 10
EST_TACTIC_LEFT					= 11
EST_TACTIC_RIGHT				= 12
EST_TACTIC_FORE					= 13
EST_TACTIC_AFT					= 14
EST_TACTIC_TOP					= 15
EST_TACTIC_BOTTOM				= 16
EST_LAST_TACTIC					= 19

EST_FIRST_MANEUVER				= 20
EST_MANEUVER_ATWILL				= 20
EST_MANEUVER_CLOSE				= 21
EST_MANEUVER_MAINTAIN			= 22
EST_MANEUVER_SEPARATE			= 23
EST_LAST_MANEUVER				= 29

g_bIgnoreNextAIDone				= 0
g_fLastWarnTime					= 0


# The ID's of all the firing AI's in the player's current AI tree.
g_lPlayerFireAIs			= []
g_idCurrentAI				= None
g_idTacticalMenu			= App.NULL_ID

# Counting the number of times the automatic target selection changes
# a target.  This is so TargetChanged knows when it's changed the target,
# and when the player has changed the target, since it needs to handle these
# differently.
g_iAutoTargetChange = 0

# Orders, and subevent types associated with those orders.
g_iOrderState = -1	# Defaults to nothing.
g_lOrders = [
	("OrderDestroy",	EST_ORDER_DESTROY),
	("OrderDisable",	EST_ORDER_DISABLE),
	("OrderStop",		EST_ORDER_STOP),
	("OrderDefense",	EST_ORDER_DEFENSE),
	]
g_pOrdersStatusUI = None
g_pOrdersStatusUIPane = None

g_idOrdersStatusDisplay = App.NULL_ID

# Which orders are "Attack" orders.
g_lAttackOrders = [
	g_lOrders[0][0],
	g_lOrders[1][0]
	]

# Tactics.  With information about what's available
# when that tactic is active.
g_iTacticState = 0
g_lTactics = [
	("TacticAtWill",	EST_TACTIC_ATWILL),
	("TacticLeft",		EST_TACTIC_LEFT),
	("TacticRight",		EST_TACTIC_RIGHT),
	("TacticFore",		EST_TACTIC_FORE),
	("TacticAft",		EST_TACTIC_AFT),
	("TacticTop",		EST_TACTIC_TOP),
	("TacticBottom",	EST_TACTIC_BOTTOM),
	]

# Maneuvers; how tactics are carried out.  Dictionary contains information
# about what's available when that maneuver is active.
g_iManeuverState = 0
g_lManeuvers = [
	("ManeuverAtWill",		EST_MANEUVER_ATWILL),
	("ManeuverClose",		EST_MANEUVER_CLOSE),
	("ManeuverMaintain",	EST_MANEUVER_MAINTAIN),
	("ManeuverSeparate",	EST_MANEUVER_SEPARATE),
	]

# Vectors needed for the parameters in g_dAIs:
def Mix(vMain, vSecondary):
	vMain.Scale(2.0)
	vMain.Add( vSecondary )
	vMain.Unitize()
	return vMain
vLeftBack	= Mix(App.TGPoint3_GetModelLeft(), App.TGPoint3_GetModelForward())
vLeft		= App.TGPoint3_GetModelLeft()
vLeftFwd	= Mix(App.TGPoint3_GetModelLeft(), App.TGPoint3_GetModelForward())
vFwd		= App.TGPoint3_GetModelForward()
vRightFwd	= Mix(App.TGPoint3_GetModelRight(), App.TGPoint3_GetModelForward())
vRight		= App.TGPoint3_GetModelRight()
vRightBack	= Mix(App.TGPoint3_GetModelRight(), App.TGPoint3_GetModelForward())
vUpFwd		= Mix(App.TGPoint3_GetModelUp(), App.TGPoint3_GetModelForward())
vUp			= App.TGPoint3_GetModelUp()
vUpBack		= Mix(App.TGPoint3_GetModelUp(), App.TGPoint3_GetModelBackward())
vDownFwd	= Mix(App.TGPoint3_GetModelDown(), App.TGPoint3_GetModelForward())
vDown		= App.TGPoint3_GetModelDown()
vDownBack	= Mix(App.TGPoint3_GetModelDown(), App.TGPoint3_GetModelBackward())
del Mix

# Which AI's to use, with what parameters.  The player's ship and
# the player's target are always prefixed to the list of parameters..
g_dAIs = {
	("OrderDestroy",	"TacticAtWill",	"ManeuverAtWill")	: ("DestroyFreely", ()),
	("OrderDestroy",	"TacticAtWill",	"ManeuverClose")	: ("DestroyFreelyClose", ()),
	("OrderDestroy",	"TacticAtWill",	"ManeuverMaintain")	: ("DestroyFreelyMaintain", ()),
	("OrderDestroy",	"TacticAtWill",	"ManeuverSeparate")	: ("DestroyFreelySeparate", ()),
	("OrderDestroy",	"TacticLeft",	"ManeuverAtWill")	: ("DestroyFromSide", (vLeft, 45.0)),
	("OrderDestroy",	"TacticLeft",	"ManeuverClose")	: ("DestroyFromSide", (vLeftFwd, 45.0)),
	("OrderDestroy",	"TacticLeft",	"ManeuverMaintain")	: ("DestroyFromSide", (vLeft, 45.0)),
	("OrderDestroy",	"TacticLeft",	"ManeuverSeparate")	: ("DestroyFromSide", (vLeftBack, 45.0)),
	("OrderDestroy",	"TacticRight",	"ManeuverAtWill")	: ("DestroyFromSide", (vRight, 45.0)),
	("OrderDestroy",	"TacticRight",	"ManeuverClose")	: ("DestroyFromSide", (vRightFwd, 45.0)),
	("OrderDestroy",	"TacticRight",	"ManeuverMaintain")	: ("DestroyFromSide", (vRight, 45.0)),
	("OrderDestroy",	"TacticRight",	"ManeuverSeparate")	: ("DestroyFromSide", (vRightBack, 45.0)),
	("OrderDestroy",	"TacticFore",	"ManeuverAtWill")	: ("DestroyForeClose", ()),
	("OrderDestroy",	"TacticFore",	"ManeuverClose")	: ("DestroyForeClose", ()),
	("OrderDestroy",	"TacticFore",	"ManeuverMaintain")	: ("DestroyFore", ()),
	("OrderDestroy",	"TacticAft",	"ManeuverAtWill")	: ("DestroyAft", ()),
	("OrderDestroy",	"TacticAft",	"ManeuverMaintain")	: ("DestroyAft", ()),
	("OrderDestroy",	"TacticAft",	"ManeuverSeparate")	: ("DestroyAftSeparate", ()),
	("OrderDestroy",	"TacticTop",	"ManeuverAtWill")	: ("DestroyFaceSide", (vUpFwd,)),
	("OrderDestroy",	"TacticTop",	"ManeuverClose")	: ("DestroyFaceSide", (vUpFwd,)),
	("OrderDestroy",	"TacticTop",	"ManeuverMaintain")	: ("DestroyFaceSide", (vUp,)),
	("OrderDestroy",	"TacticTop",	"ManeuverSeparate")	: ("DestroyFaceSide", (vUpBack,)),
	("OrderDestroy",	"TacticBottom",	"ManeuverAtWill")	: ("DestroyFaceSide", (vDownFwd,)),
	("OrderDestroy",	"TacticBottom",	"ManeuverClose")	: ("DestroyFaceSide", (vDownFwd,)),
	("OrderDestroy",	"TacticBottom",	"ManeuverMaintain")	: ("DestroyFaceSide", (vDown,)),
	("OrderDestroy",	"TacticBottom",	"ManeuverSeparate")	: ("DestroyFaceSide", (vDownBack,)),

	("OrderDisable",	"TacticAtWill",	"ManeuverAtWill")	: ("DisableFreely", ()),
	("OrderDisable",	"TacticAtWill",	"ManeuverClose")	: ("DisableFreelyClose", ()),
	("OrderDisable",	"TacticAtWill",	"ManeuverMaintain")	: ("DisableFreelyMaintain", ()),
	("OrderDisable",	"TacticAtWill",	"ManeuverSeparate")	: ("DisableFreelySeparate", ()),
	("OrderDisable",	"TacticLeft",	"ManeuverAtWill")	: ("DisableFromSide", (vLeft, 45.0)),
	("OrderDisable",	"TacticLeft",	"ManeuverClose")	: ("DisableFromSide", (vLeftFwd, 45.0)),
	("OrderDisable",	"TacticLeft",	"ManeuverMaintain")	: ("DisableFromSide", (vLeft, 45.0)),
	("OrderDisable",	"TacticLeft",	"ManeuverSeparate")	: ("DisableFromSide", (vLeftBack, 45.0)),
	("OrderDisable",	"TacticRight",	"ManeuverAtWill")	: ("DisableFromSide", (vRight, 45.0)),
	("OrderDisable",	"TacticRight",	"ManeuverClose")	: ("DisableFromSide", (vRightFwd, 45.0)),
	("OrderDisable",	"TacticRight",	"ManeuverMaintain")	: ("DisableFromSide", (vRight, 45.0)),
	("OrderDisable",	"TacticRight",	"ManeuverSeparate")	: ("DisableFromSide", (vRightBack, 45.0)),
	("OrderDisable",	"TacticFore",	"ManeuverAtWill")	: ("DisableForeClose", ()),
	("OrderDisable",	"TacticFore",	"ManeuverClose")	: ("DisableForeClose", ()),
	("OrderDisable",	"TacticFore",	"ManeuverMaintain")	: ("DisableFore", ()),
	("OrderDisable",	"TacticAft",	"ManeuverAtWill")	: ("DisableAft", ()),
	("OrderDisable",	"TacticAft",	"ManeuverMaintain")	: ("DisableAft", ()),
	("OrderDisable",	"TacticAft",	"ManeuverSeparate")	: ("DisableAftSeparate", ()),
	("OrderDisable",	"TacticTop",	"ManeuverAtWill")	: ("DisableFaceSide", (vUpFwd,)),
	("OrderDisable",	"TacticTop",	"ManeuverClose")	: ("DisableFaceSide", (vUpFwd,)),
	("OrderDisable",	"TacticTop",	"ManeuverMaintain")	: ("DisableFaceSide", (vUp,)),
	("OrderDisable",	"TacticTop",	"ManeuverSeparate")	: ("DisableFaceSide", (vUpBack,)),
	("OrderDisable",	"TacticBottom",	"ManeuverAtWill")	: ("DisableFaceSide", (vDownFwd,)),
	("OrderDisable",	"TacticBottom",	"ManeuverClose")	: ("DisableFaceSide", (vDownFwd,)),
	("OrderDisable",	"TacticBottom",	"ManeuverMaintain")	: ("DisableFaceSide", (vDown,)),
	("OrderDisable",	"TacticBottom",	"ManeuverSeparate")	: ("DisableFaceSide", (vDownBack,)),

	("OrderDefense",	None,			None)				: ("Defense", ()),
	("OrderStop",		None,			None)				: ("Stay", ()),
	("OrderStopSelect",	None,			None)				: ("StaySelectTarget", ())
	}

###############################################################################
#	CreateMenus()
#	
#	Creates the menu interface
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def CreateMenus():
	# Event types only used in this file:
	global ET_TARGETING_TOGGLED, ET_PHASERS_ONLY
	ET_TARGETING_TOGGLED			= App.Game_GetNextEventType()
	ET_PHASERS_ONLY					= App.Game_GetNextEventType()

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Variable for Attack on / off
	App.g_kVarManager.SetFloatVariable('global', 'atoggle', 0)
	
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalWindow = App.TacticalControlWindow_Create()

	# Create interface pane. This pane is sized to the screen and
	# all interface objects are added to it.
	kInterfacePane = App.TGPane_Create(LCARS.SCREEN_WIDTH, LCARS.SCREEN_HEIGHT)
	kBackgroundPane = App.TGPane_Create(LCARS.SCREEN_WIDTH, LCARS.SCREEN_HEIGHT)
	kBackgroundPane.SetNoFocus()
	
	# Create and add tactical menu.
	pTacticalMenuPane = CreateTacticalMenu()
	kInterfacePane.AddChild(pTacticalMenuPane, 0.0, 0.0, 0)
	#pTacticalMenuPane.Resize(LCARS.TACTICAL_MENU_WIDTH, LCARS.TACTICAL_MENU_HEIGHT)
	pTacticalMenuPane.Layout()
	pTacticalMenu = App.STMenu_Cast(pTacticalMenuPane.GetInteriorPane().GetFirstChild())
	if (pTacticalMenu != None):
		pTacticalMenu.ForceUpdate()
		pTacticalWindow.AddMenuToList(pTacticalMenu)

	# Create and add enemy ship display.
	pESDisplayPane = CreateEnemyShipDisplay(pTacticalWindow)
	kInterfacePane.AddChild(pESDisplayPane, 0.0, 0.0, 0)
	pESDisplayPane.AlignTo(pTacticalMenuPane, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL)
		
	# Create Radar Display.
	pRadarDisplayPane = CreateRadarDisplay(pTacticalWindow)
	#pRadarDisplayPane.Resize(LCARS.RADAR_PANE_WIDTH, LCARS.RADAR_PANE_HEIGHT)
	pRadarDisplayPane.ResizeUI()
	pRadarDisplayPane.RepositionUI()

	# Create target list
	pTargetListPane = CreateTargetList(pTacticalWindow)
	TARGET_LIST_WIDTH = LCARS.TACTICAL_MENU_WIDTH
	TARGET_LIST_HEIGHT = (LCARS.SCREEN_HEIGHT - pTacticalMenuPane.GetHeight() - 
						pRadarDisplayPane.GetHeight() - LCARS.SEPERATOR_GAP_Y - 
						pESDisplayPane.GetHeight())
	kInterfacePane.AddChild(pTargetListPane, 0.0, 0.0, 0)
	pTargetListPane.Resize(TARGET_LIST_WIDTH, TARGET_LIST_HEIGHT, 0)
	pTargetListPane.AlignTo(pESDisplayPane, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL)
	pTargetList = App.STMenu_Cast(pTargetListPane.GetFirstChild())
	if (pTargetList != None):
		pTargetList.ForceUpdate()
	
	# Create radar/enemy ship display toggle.
	pRadarTogglePane = CreateRadarToggle(pTacticalWindow)

	# Create player's ship display
	pShipDisplayPane = CreateShipDisplay(pTacticalWindow)

	# Add the stuff created just above. We add it later because
	# we want to add the radar toggle in front of everything else.
	kInterfacePane.AddChild(pRadarTogglePane, 
							pRadarDisplayPane.GetWidth() - pRadarTogglePane.GetWidth(),
							LCARS.SCREEN_HEIGHT - pRadarDisplayPane.GetHeight())
	pRadarTogglePane.SetNotVisible()

	kInterfacePane.AddChild(pRadarDisplayPane, 0.0, LCARS.SCREEN_HEIGHT - pRadarDisplayPane.GetHeight())

	# Add ship display. It will be positioned below.
	kInterfacePane.AddChild(pShipDisplayPane, 0.0, 0.0, 0)

	# Add the orders status display. It will be positioned later.
	pOrdersStatusPane = CreateOrdersStatusDisplay(LCARS.SCREEN_WIDTH - LCARS.TACTICAL_MENU_WIDTH - pTacticalMenuPane.GetBorderWidth(), 
												  pTacticalMenuPane.GetFirstChild())
	kInterfacePane.AddChild(pOrdersStatusPane, LCARS.SCREEN_WIDTH - pOrdersStatusPane.GetWidth(), 0.0, 0)
	if (App.g_kUtopiaModule.IsMultiplayer ()):
		if (App.g_kUtopiaModule.GetTestMenuState () < 3):
			pOrdersStatusPane.SetNotVisible ()

	# Create weapons display.
	pWeaponsDisplayPane = CreateWeaponsDisplay(pTacticalWindow)
	# Add weapons display to interface pane.
	kInterfacePane.AddChild(pWeaponsDisplayPane, 0.0, 0.0, 0)
	pWeaponsDisplayPane.SetPosition(LCARS.SCREEN_WIDTH - pWeaponsDisplayPane.GetWidth() -
							LCARS.WEAPONS_DISPLAY_GAP_X,
							LCARS.SCREEN_HEIGHT - pWeaponsDisplayPane.GetHeight(), 0)
	
	# Create weapons control.
	pWeaponsControlPane = CreateWeaponsControl(pTopWindow, pTacticalWindow)
	# Add weapons control to interface pane.
	kInterfacePane.AddChild(pWeaponsControlPane, 0.0, 0.0, 0)
	pWeaponsControlPane.AlignTo(pWeaponsDisplayPane, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_UR)

	# Position the ship display.
	pShipDisplayPane.AlignTo(pWeaponsControlPane, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_UR)

	kInterfacePane.SetFocus(pTargetListPane)
	pTacticalWindow.AddChild(kInterfacePane, 0, 0)
	pTacticalWindow.AddChild(kBackgroundPane, 0, 0)

	# The tactical control window initially starts attached to the Tactical mainwindow.
	# This is just so that it's attached to /something/, which is important for
	# save/load.  The first time it's actually needed, it'll be attached to
	# whatever window needs it.
	pTacControlParent = pTopWindow.FindMainWindow(App.MWT_TACTICAL)
	if pTacControlParent:
		pTacControlParent.AddChild(pTacticalWindow, 0, 0)
#	else:
#		debug("No tactical window under topwindow.  Can't attach tactical control window.")

	# Update our current orders, now that the orders menus exist.
	UpdateOrderMenus()

	import Tactical.Interface.TacticalControlWindow
	Tactical.Interface.TacticalControlWindow.ResizeUI()
	Tactical.Interface.TacticalControlWindow.RepositionUI()
	

###############################################################################
#	CreateTacticalMenu()
#
#	Create tactical menu
#	
#	Event types are defined in Common/UtopiaTypes.h
#	Event sub-types are defined in Bridge/Character.h
#
#	Args:	none
#
#	Return:	pTacticalPane
###############################################################################
def CreateTacticalMenu():
	# Create tactical menu pane. This contains the tactical menu itself.
	#pTacticalMenuPane = App.TGPane_Create(0.0, 0.0)

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	
	pTacticalMenu = App.STTopLevelMenu_CreateW(pDatabase.GetString("Tactical"))
	if pTacticalMenu:
		global g_idTacticalMenu
		g_idTacticalMenu = pTacticalMenu.GetObjID()

	pTacticalMenuPane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Tactical"), 0.0, 0.0)
	pTacticalMenuPane.SetMaximumSize(LCARS.TACTICAL_MENU_WIDTH + pTacticalMenuPane.GetBorderWidth(), LCARS.TACTICAL_MENU_HEIGHT + pTacticalMenuPane.GetBorderHeight())
	pTacticalMenuPane.AddChild(pTacticalMenu, 0.0, 0.0, 0)

	# We don't want the "skip parent" behavior in this case, because otherwise
	# menu items would think that the window was their parent.
	pTacticalMenu.SetNoSkipParent()

	pTacticalMenu.AddPythonFuncHandlerForInstance(App.ET_ST_BUTTON_CLICKED,	
												"Bridge.BridgeMenus.ButtonClicked")
	
	import BridgeMenus
	pCommunicate = BridgeMenus.CreateCommunicateButton("Tactical", pTacticalMenu)
	pTacticalMenu.AddChild(pCommunicate)


	pFireButton = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Manual Aim"), 
						App.ET_FIRE, 0, pTacticalMenu)
	pFireButton.SetAutoChoose(1)
	pFireButton.SetChosen(0)
	pFireButton.SetChoosable(1)
	pTacticalMenu.AddChild(pFireButton)

	pPhasersOnlyButton = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("PhasersOnly"), 
						ET_PHASERS_ONLY, 0, pTacticalMenu)
	pPhasersOnlyButton.SetAutoChoose(1)
	pPhasersOnlyButton.SetChosen(0)
	pPhasersOnlyButton.SetChoosable(1)
	pTacticalMenu.AddChild(pPhasersOnlyButton)

	pTargetingButton = BridgeUtils.CreateBridgeMenuButton(pDatabase.GetString("Target At Will"), 
						ET_TARGETING_TOGGLED, 0, pTacticalMenu)
	pTargetingButton.SetAutoChoose(1)
	pTargetingButton.SetChosen(1)
	pTargetingButton.SetChoosable(1)
	pTacticalMenu.AddChild(pTargetingButton)


	# If in multiplayer, disable all single-player specific buttons	
	if (App.g_kUtopiaModule.IsMultiplayer()):
		pCommunicate.SetDisabled()
		pPhasersOnlyButton.SetDisabled ()
		pFireButton.SetDisabled ()
		pTargetingButton.SetDisabled ()

	# Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	pTacticalMenu.ForceUpdate()

	# Add Python function handlers for menu buttons.
	pTacticalMenu.AddPythonFuncHandlerForInstance(App.ET_MANEUVER,				__name__ + ".Maneuver")
	pTacticalMenu.AddPythonFuncHandlerForInstance(App.ET_FIRE,					__name__ + ".Fire")
	pTacticalMenu.AddPythonFuncHandlerForInstance(ET_PHASERS_ONLY,				__name__ + ".PhasersOnlyToggled")
	pTacticalMenu.AddPythonFuncHandlerForInstance(ET_TARGETING_TOGGLED,			__name__ + ".TargetingModeToggled")
	pTacticalMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,			"Bridge.Characters.CommonAnimations.NothingToAdd")

	# A handler for when the player's target changes.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TARGET_WAS_CHANGED, pTacticalMenu, 
													  __name__ + ".TargetChanged")
	# A handler for when the player's target is restored from persistent info.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_RESTORE_PERSISTENT_TARGET, pTacticalMenu,
													  __name__ + ".PersistentTargetRestored")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pTacticalMenu, __name__ + ".SetPlayer")
	SetPlayer(None, None)

	pTopWindow = App.TopWindow_GetTopWindow()
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacWindow.SetTacticalMenu(pTacticalMenu)

	return pTacticalMenuPane

def SetPlayer(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_CANT_FIRE,					__name__ + ".PlayerCantFire")
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_PLAYER_TORPEDO_TYPE_CHANGED,	__name__ + ".PlayerTorpChanged")
#	else:
#		debug("Can't get player..")

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	CreateOrderMenu
#	
#	Create an Order menu (Orders/Tactics/Maneuvers).
#	
#	Args:	sHeader		- Header string for the menu
#			lInfo		- List of item/subeventtype pairs for menu items.
#			pEventDest	- Destination for menu events
#			sFocus		- Menu item that starts with the focus, if any.
#	
#	Return:	A new order menu.
###############################################################################
def CreateOrderMenu(sHeader, lInfo, pEventDest, sFocus):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pMenu = App.STCharacterMenu_CreateW(pDatabase.GetString(sHeader))
	for sString, eSubType in ( lInfo ):
		pButton = BridgeUtils.CreateBridgeMenuButton(
			pDatabase.GetString(sString),
			App.ET_MANEUVER, 
			eSubType,
			pEventDest)
		pMenu.AddChild(pButton)

		# Set the focus, if this matches...
		if sString == sFocus:
			pMenu.SetFocus(pButton)

	App.g_kLocalizationManager.Unload(pDatabase)
	return pMenu

###############################################################################
#	CreateRadarDisplay(pTacticalWindow)
#
#	Create Radar display. Register it with the bridge window so that
#	update can be called on it every frame.
#	
#	Args:	pTacticalWindow - tactical control window updates the radar display.
#
#	Return:	pRadarDisplayPane
###############################################################################
def CreateRadarDisplay(pTacticalWindow):
	# Create radar display object.
	pRadarDisplay = App.RadarDisplay_Create(0.0, 0.0)
	pRadarDisplay.SetUseScrolling(0)
	pTacticalWindow.SetRadarDisplay(pRadarDisplay)
	return pRadarDisplay

###############################################################################
#	CreateTargetList(pTacticalWindow)
#
#	Create target list. Register it with the bridge window so that
#	it can be grabbed by the tactical interface. This component is shared 
#	accross both interfaces and is moved where needed.
#	
#	Args:	pTacticalWindow - Bridge window updates the target list.
#
#	Return:	pTargetListPane
###############################################################################
def CreateTargetList(pTacticalWindow):
	# Create the target menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTargetListMenu = App.STTargetMenu_CreateW(pDatabase.GetString("Targets"))
	App.g_kLocalizationManager.Unload(pDatabase)

	pTacticalWindow.SetTargetMenu(pTargetListMenu)

	#pTargetMenuPane = App.TGPane_Create(0.0, 0.0)
	pTargetMenuPane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Targets"), 0.0, 0.0)
	pTargetMenuPane.AddChild(pTargetListMenu)
	pTargetMenuPane.SetUseFocusGlass(1)

	return pTargetMenuPane

###############################################################################
#	CreateShipDisplay(pTacticalWindow)
#
#	Create player's ship display. Register it with the bridge window so that
#	it can be grabbed by the tactical interface. This component is shared 
#	accross both interfaces and is moved where needed.
#	
#	Args:	pTacticalWindow - Bridge window we register ourselves with.
#
#	Return:	TGPane - the ship display pane
###############################################################################
def CreateShipDisplay(pTacticalWindow):
	# Create the ship display object, same size as pane.
	pShipDisplay = App.ShipDisplay_Create()
	pShipDisplay.SetUseScrolling(0)

	# Set the title of this display...
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pShipDisplay.SetName( pDatabase.GetString("Shields") )
	App.g_kLocalizationManager.Unload(pDatabase)

	# Here we set the parent in the bridge so that it can be switched
	# back and forth to the tactical interface.
	pTacticalWindow.SetShipDisplay(pShipDisplay)
	pShipDisplay.InteriorChangedSize(1)
	
	return pShipDisplay

###############################################################################
#	CreateOrdersStatusDisplay
#	
#	Create the Orders Status display.  This displays the current
#	status of Felix's Orders, Tactics, and Maneuvers settings.
#	
#	Args:	None
#	
#	Return:	The orders status display pane.
###############################################################################
def CreateOrdersStatusDisplay(fWidth, pTacticalMenu):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	lDisplays = [
		( "Tactics",		"TacticAtWill",		g_lTactics,		"g_pTacticsStatusUI" ),
		( "Maneuvers",		"ManeuverAtWill",	g_lManeuvers,	"g_pManeuversStatusUI" )
		]

	# Create the orders pane first, since it is irregularly sized.
	global g_pOrdersStatusUI
	global g_pOrdersStatusUIPane
	global g_idOrdersStatusDisplay

	# Delete old stuff, if it exists.
	try:
		if (g_idOrdersStatusDisplay != App.NULL_ID):
			pOrdersStatusDisplay = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idOrdersStatusDisplay))
			if (pOrdersStatusDisplay != None):
				pOrdersStatusDisplay.KillChildren()
			else:
				g_idOrdersStatusDisplay = App.NULL_ID
	except:
		pass

	lOrdersButtons = []
	fOrdersStatusPaneWidth = 0.0

	for lOrder in g_lOrders:
		sString, eSubType = lOrder
		pEvent = App.TGIntEvent_Create()
		pEvent.SetEventType(App.ET_MANEUVER)
		pEvent.SetInt(eSubType)
		pEvent.SetDestination(pTacticalMenu)

		pButton = App.STButton_CreateW(pDatabase.GetString(sString), pEvent, 
									   App.STBSF_SIZE_TO_TEXT)
		pButton.SetChoosable(1)
		pButton.SetAutoChoose(1)
		pButton.SetUseEndCaps(0)
		if (sString == "OrderStop"):
			pButton.SetChosen(1)
		else:
			pButton.SetChosen(0)

		lOrdersButtons.append(pButton)
		pButton.Layout()
		fOrdersStatusPaneWidth = fOrdersStatusPaneWidth + pButton.GetWidth() + App.globals.DEFAULT_ST_INDENT_HORIZ

	# The UI (for the orders status only) is the pane containing the glass, and the "real" pane.
	g_pOrdersStatusUIPane = App.TGPane_Create(fOrdersStatusPaneWidth / 2.0, (pButton.GetHeight() + (2.0 * App.globals.DEFAULT_ST_INDENT_VERT)) * 2.0)
	g_pOrdersStatusUI = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Orders"), 0.0, 0.0, g_pOrdersStatusUIPane)
	g_pOrdersStatusUI.SetUseScrolling(0)
	g_pOrdersStatusUI.SetUseFocusGlass(1)

	# Add the keyboard handlers for the orders status pane.
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pTCW.RemoveHandlerForInstance(App.ET_INPUT_SELECT_OPTION, __name__ + ".HandleOrdersStatusKeyboard")
	pTCW.RemoveHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".HandleOrdersStatusKeyboard")
	pTCW.AddPythonFuncHandlerForInstance(App.ET_INPUT_SELECT_OPTION, __name__ + ".HandleOrdersStatusKeyboard")
	pTCW.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".HandleOrdersStatusKeyboard")

	fXPos = 0.0
	fYPos = App.globals.DEFAULT_ST_INDENT_VERT
	bSecond = 0
	bHasSecondPos = 0
	for pButton in lOrdersButtons:
		if (bSecond == 1) and (bHasSecondPos == 1):
			g_pOrdersStatusUIPane.AddChild(pButton, fSecondPos, fYPos, 0)
		else:
			g_pOrdersStatusUIPane.AddChild(pButton, fXPos, fYPos, 0)

		if bSecond == 1:
			fXPos = 0.0
			fYPos = fYPos + pButton.GetHeight() + App.globals.DEFAULT_ST_INDENT_VERT
			bSecond = 0
		else:
			fXPos = fXPos + pButton.GetWidth() + App.globals.DEFAULT_ST_INDENT_HORIZ
			bSecond = 1

			if (bHasSecondPos == 0):
				bHasSecondPos = 1
				fSecondPos = fXPos

	g_pOrdersStatusUIPane.SetEnabled()
	g_pOrdersStatusUI.SetEnabled()
	g_pOrdersStatusUI.InteriorChangedSize()
	g_pOrdersStatusUI.Layout()

	fNumDisplays = float(len(lDisplays))
	fPaneWidth = ((fWidth - g_pOrdersStatusUI.GetWidth()) / fNumDisplays) - ((g_pOrdersStatusUI.GetWidth() - g_pOrdersStatusUIPane.GetWidth()))
	#fPaneWidth = fPaneWidth / 2.0

	fMaxHeight = 0.0
	lOrdersPanes = []
	for sHeader, sDetail, lInfo, sUIVar in lDisplays:
		pPane = App.STSubPane_Create(0.0, 0.0, 0)
		globals()[sUIVar + "Pane"] = pPane

		# Pop-up menu:
		pPopupMenu = CreateOrderMenu(sHeader, lInfo, pTacticalMenu, None)
		globals()[sUIVar + "Menu"] = pPopupMenu

		App.STSubPane_Cast(pPopupMenu.GetSubPane()).SetExpandToFillParent(0)

		pPane.AddChild(pPopupMenu)

		lOrdersPanes.append( pPane )

	if (g_idOrdersStatusDisplay == App.NULL_ID):
		pOrdersDisplay = App.TGPane_Create(fWidth, 1.0)
		g_idOrdersStatusDisplay = pOrdersDisplay.GetObjID()
	else:
		pOrdersDisplay = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idOrdersStatusDisplay))

		if (pOrdersDisplay != None):
			pOrdersDisplay.Resize(fWidth, 1.0)
		else:
			pOrdersDisplay = App.TGPane_Create(fWidth, 1.0)
			g_idOrdersStatusDisplay  = pOrdersDisplay.GetObjID()

	fLeft = 0.0

	pOrdersDisplay.AddChild(g_pOrdersStatusUI, 0.0, 0.0, 0)
	fLeft = fLeft + fOrdersStatusPaneWidth

	# Create the stylized window to contain the tactics/maneuvers stuff.
	pManeuversPane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Maneuvers"))
	pManeuversPane.SetUseScrolling(0)
	pManeuversPane.SetUseFocusGlass(1)
	pManeuversPane.AddChild(g_pManeuversStatusUIPane)
	g_pManeuversStatusUIMenu.Open()
	kSize = App.NiPoint2(0.0, 0.0)
	g_pManeuversStatusUIMenu.GetDesiredSize(kSize)
	g_pManeuversStatusUIPane.Resize(kSize.x, g_pManeuversStatusUIPane.GetHeight())
	pManeuversPane.SetMaximumSize(kSize.x + pManeuversPane.GetBorderWidth(), 1.0)
	g_pManeuversStatusUIMenu.Close()
	pManeuversPane.InteriorChangedSize()
	pManeuversPane.Layout() # Need to do a layout so its width is accurate.

	pTacticsPane = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Tactics"))
	pTacticsPane.SetUseScrolling(0)
	pTacticsPane.SetUseFocusGlass(1)
	pTacticsPane.SetMaximumSize(fPaneWidth + pTacticsPane.GetBorderWidth(), 1.0)
	pTacticsPane.AddChild(g_pTacticsStatusUIPane, 0.0, 0.0, 0)
	g_pTacticsStatusUIMenu.Open()
	kSize = App.NiPoint2(0.0, 0.0)
	g_pTacticsStatusUIMenu.GetDesiredSize(kSize)
	g_pTacticsStatusUIPane.Resize(kSize.x, g_pTacticsStatusUIPane.GetHeight())
	pTacticsPane.SetMaximumSize(kSize.x + pTacticsPane.GetBorderWidth(), 1.0)
	g_pTacticsStatusUIMenu.Close()
	pTacticsPane.InteriorChangedSize()

	pOrdersDisplay.AddChild(pTacticsPane, pOrdersDisplay.GetWidth() - pTacticsPane.GetWidth(), 0.0, 0)
	pOrdersDisplay.AddChild(pManeuversPane, pTacticsPane.GetLeft() - pManeuversPane.GetWidth(), 0.0, 0)

	App.g_kLocalizationManager.Unload(pDatabase)

	return pOrdersDisplay

###############################################################################
#	CreateEnemyShipDisplay(pWindow)
#	
#	Create enemy ship display. Register it with the bridge window so that
#	it can be grabbed by the tactical interface. This component is shared 
#	accross both interfaces and is moved where needed.
#	
#	Args:	pWindow - Bridge window we register ourselves with.
#
#	Return:	TGPane - the enemy ship display pane
###############################################################################
def CreateEnemyShipDisplay(pWindow):
	# Create the ship display object, same size as pane.
	pShipDisplay = App.ShipDisplay_Create()
	pShipDisplay.SetUseScrolling(0)

	# Set the title of this display...
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pShipDisplay.SetName( pDatabase.GetString("TargetShields") )
	App.g_kLocalizationManager.Unload(pDatabase)

	# Here we set the parent in the bridge so that it can be switched
	# back and forth to the tactical interface.
	pWindow.SetEnemyShipDisplay(pShipDisplay)
	pShipDisplay.InteriorChangedSize(1)

	return pShipDisplay

###############################################################################
#	CreateRadarToggle(pWindow)
#	
#	Creates the button that toggles radar/enemy ship display. Register it
#	with the bridge window so that it can be grabbed by the tactical
#	interface. This component is shared across both interfaces and is
#	moved where needed.
#	
#	Args:	pWindow - Bridge window we register ourselves with.
#
#	Return:	TGPane - the pane containing the button
###############################################################################
def CreateRadarToggle(pWindow):
	# Create the button. The button will alternate between the
	# "Target" and "Sensors" strings.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Setup the event that will be sent when the button is clicked. Note that
	# this event gets reset when the tactical and bridge windows grab the
	# interface.
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pWindow)
	pEvent.SetEventType(App.ET_RADAR_TOGGLE_CLICKED)
	pRadarToggleButton = App.STButton_CreateW(pDatabase.GetString("Target"), pEvent, 0)
	pRadarToggleButton.Resize(LCARS.RADAR_TOGGLE_WIDTH, LCARS.RADAR_TOGGLE_HEIGHT)
	pRadarToggleButton.SetUseEndCaps(0, 0)

	App.g_kLocalizationManager.Unload(pDatabase)

	pWindow.SetRadarToggle(pRadarToggleButton)

	return(pRadarToggleButton)

###############################################################################
#	CreateWeaponsDisplay(pTacticalWindow)
#
#	Create weapons display. Register it with the bridge window so that
#	it can be grabbed by the tactical interface. This component is shared 
#	across both interfaces and is moved where needed.
#	
#	Args:	pTacticalWindow - Bridge window we register ourselves with.
#
#	Return:	pWeaponsDisplayPane
###############################################################################
def CreateWeaponsDisplay(pTacticalWindow):
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Create the weapons display object, same size as pane.
	pWeaponsDisplay = App.WeaponsDisplay_Create(LCARS.WEAPONS_PANE_WIDTH, 
												LCARS.WEAPONS_PANE_HEIGHT)
	pWeaponsDisplay.SetUseScrolling(0)

	# Here we set the parent in the bridge window so that 
	# it can be accessed from the the tactical interface.
	pTacticalWindow.SetWeaponsDisplay(pWeaponsDisplay)

	import Tactical.Interface.WeaponsDisplay
	Tactical.Interface.WeaponsDisplay.ResizeUI(pWeaponsDisplay)
	
	return pWeaponsDisplay

###############################################################################
#	OverrideButtonColors(pButton)
#	
#	Sets up a button for the weapons control so that it doesn't use the
#	regular UI colors.
#	
#	Args:	pButton		- the button to change
#	
#	Return:	none
###############################################################################
def OverrideButtonColors(pButton):
	pButton.SetUseUIHeight(0)
	pButton.SetNormalColor(App.g_kSTMenu2NormalBase)
	kDimColor = App.NiColorA()
	kDimColor.r = App.g_kSTMenu2NormalBase.r * 0.5
	kDimColor.g = App.g_kSTMenu2NormalBase.g * 0.5
	kDimColor.b = App.g_kSTMenu2NormalBase.b * 0.5
	pButton.SetSelectedColor(kDimColor)
	pButton.SetHighlightedColor(App.g_kSTMenu2HighlightedBase)
	pButton.SetDisabledColor(App.g_kSTMenu2Disabled)

	pButton.SetColorBasedOnFlags(0)


###############################################################################
#	CreateWeaponsControl(pTopWindow, pTacticalWindow)
#
#	Create weapons control. Register it with the bridge window so that
#	it can be grabbed by the tactical interface. This component shares
#	buttons/toggles accross interfaces which are moved where needed.
#	
#	FIXME: Move this into its own C++ class.
#
#	Args:	pTopWindow - Top window handles events for weapons control buttons.
#			pTacticalWindow - Bridge window we register ourselves with.
#
#	Return:	pWeaponsControlPane
###############################################################################
def CreateWeaponsControl(pTopWindow, pTacticalWindow):
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Create weapons control.
	pWeaponsControl = App.TacWeaponsCtrl_Create(LCARS.WEAPONS_CTRL_PANE_WIDTH, 
												LCARS.WEAPONS_CTRL_PANE_HEIGHT)
	pWeaponsControl.SetUseScrolling(0)
	pWeaponsControl.SetFixedSize(LCARS.WEAPONS_CTRL_PANE_WIDTH + pWeaponsControl.GetBorderWidth(),
								 LCARS.WEAPONS_CTRL_PANE_HEIGHT + pWeaponsControl.GetBorderHeight())

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pWeaponsControl.SetName( pDatabase.GetString("Weapons") )
	pWeaponsControl.InteriorChangedSize(1)
	App.g_kLocalizationManager.Unload(pDatabase)

	# Here we set the parent in the bridge window so that 
	# it can be accessed from the the tactical interface.
	pTacticalWindow.SetWeaponsControl(pWeaponsControl)

	# Update the weapons control now, if possible. This will ensure that if
	# another character takes over, the interface will still be correct.
	pWeaponsControl.RefreshPhaserSettings()
	pWeaponsControl.RefreshTorpedoSettings()

	pWeaponsControl.SetNotHighlighted(0)

	return pWeaponsControl

###############################################################################
#	TargetingModeToggled
#	
#	Toggle the targeting mode between "As Ordered" and "Free Will".
#	If an AI is running, make sure it's updated with the new targeting mode.
#	
#	Args:	pMenu	- The tactical menu.
#			pEvent	- The ET_TARGETING_TOGGLED event that triggered us.
#	
#	Return:	None
###############################################################################
def TargetingModeToggled(pMenu, pEvent):
	# Let other handlers process this event first...
	pMenu.CallNextHandler(pEvent)

	# Check the Targeting button to see if we're autotargeting or not.
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacWindow.GetTacticalMenu()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTargetingButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Target At Will")))
	App.g_kLocalizationManager.Unload(pDatabase)

	# If it's chosen, we're autotargeting.
	if pTargetingButton.IsChosen() == 1:
		# We're autotargeting.
		UpdateOrders(0)

	# Check how our AI is handling subsystem targeting.
	CheckSubsystemTargeting()

###############################################################################
#	TargetChanged(pObject, pEvent)
#
#	Broadcast handler function for target changed event.
#
#	Args:	pObject 	- target for this event.
#			pEvent		- Event we are handling.
#
#	Return:	none
###############################################################################
def TargetChanged(pObject, pEvent):
	# Is it the player's target that changed?  Get the player, and
	# see if the player is the destination for this event...
	pPlayer = App.Game_GetCurrentGame().GetPlayer()
	if (not pPlayer or pEvent.GetDestination () == None) or (pPlayer.GetObjID() != pEvent.GetDestination().GetObjID()):
		# Player doesn't exist or it's not the player's target that changed.
		return

	# If the new target is None, it has no effect on autotargetting.
	if not pPlayer.GetTarget():
		# This should clear Destroy or Disable AIs (but not the orders settings) so we
		# don't try to attack the old target.
		if GetHighLevelOrder() in g_lAttackOrders:
			if MissionLib.GetPlayerShipController() == "Tactical":
				StartAI(1)
		return

	# Get the Tactical station's menu.
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacWindow.GetTacticalMenu()
	
	# Get the "Target At Will" button
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTargetingButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Target At Will")))
	App.g_kLocalizationManager.Unload(pDatabase)

	if pTargetingButton is None:
#		debug("TargetChanged: ERROR in script- unable to get fire button.")
		return

	# Decrement the AutoTargetChanged count.  If it's already zero
	# before decrementing, make sure the Targeting button is set to
	# not autotarget.
	global g_iAutoTargetChange
	#debug("Target changed.  Autochange count at %d." % g_iAutoTargetChange)
	if g_iAutoTargetChange == 0:
		# If Felix has control of the ship, turn off autotargeting.
		if MissionLib.GetPlayerShipController() == "Tactical":
			pTargetingButton.SetChosen(0)
	else:
		g_iAutoTargetChange = g_iAutoTargetChange - 1

	pSet = App.g_kSetManager.GetSet("bridge")
	pTactical = App.CharacterClass_GetObject(pSet, "Tactical")

	UpdateOrders(0)

###############################################################################
#	PersistentTargetRestored
#	
#	The player's target is being restored from persistent target
#	information.  Make sure this target change doesn't turn off
#	Felix's Target At Will setting.
#	
#	Args:	pObject	- The tactical menu
#			pEvent	- The ET_RESTORE_PERSISTENT_TARGET event.
#	
#	Return:	None
###############################################################################
def PersistentTargetRestored(pObject, pEvent):
	# The player's target is being restored from persistent info.
	# This doesn't count as the player selecting a new target, so this
	# shouldn't disable Felix's Target At Will setting.  Increment
	# the AutoTargetChange count so that TargetChanged doesn't unselect
	# the Target At Will setting.
	global g_iAutoTargetChange
	g_iAutoTargetChange = g_iAutoTargetChange + 1

###############################################################################
#	AutoTargetChange
#	
#	The AI wants to set our target.  If we're allowing it to do so,
#	and the target is different from our current target, then change
#	it.
#	
#	Args:	sTarget	- Name of the new target to attack.
#	
#	Return:	None
###############################################################################
def AutoTargetChange(sTarget):
	# Get the player..
	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		return

	# If the player has a target and Felix wants to change the
	# target to None, ignore Felix.
	if not sTarget:
		return

	# Is this target different from our current target?
	pTarget = pPlayer.GetTarget()
	if pTarget and (pTarget.GetName() == sTarget):
		# Nope, it's the same target.  Do nothing.
		return

	# Must be a different target.  Check the Targeting button to see
	# if we should pay attention to the AI.
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacWindow.GetTacticalMenu()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTargetingButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Target At Will")))
	App.g_kLocalizationManager.Unload(pDatabase)

	# If it's chosen, we're autotargeting.
	if pTargetingButton.IsChosen() == 1:
		# Autotarget.  Change our target.
		pPlayer.SetTarget(sTarget)

		# Increment the count of the number of times we automatically
		# changed the target.  This count is needed for TargetChanged.
		global g_iAutoTargetChange
		g_iAutoTargetChange = g_iAutoTargetChange + 1

###############################################################################
#	Fire(pObject, pEvent)
#
#	Handler function for Fire button click event.
#
#	Args:	pObject 	- target for this event.
#			pEvent		- Event we are handling.
#
#	Return:	none
###############################################################################
def Fire(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	
	# Let other handlers handle the event...
	pObject.CallNextHandler(pEvent)

	# If Manual Aim is now Off, firing at will needs to be turned on.
	UpdateManualAim()

	# Check the player's AI, and set it to fire or not fire, based on the
	# button state..
	CheckFiring(pPlayer)
	UpdateOrderMenus()

###############################################################################
#	ResetPickFireButton()
#	
#	Resets the pick fire button to match the state of Pick Fire
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def ResetPickFireButton():
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacWindow.GetTacticalMenu()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pFireButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Manual Aim")))
	App.g_kLocalizationManager.Unload(pDatabase)

	if (pFireButton):
		pFireButton.SetChosen(pTacWindow.GetMousePickFire())

###############################################################################
#	UpdateManualAim
#	
#	Update mouse pick fire, based on the current status of tactical's
#	Manual Aim button.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def UpdateManualAim():
	# If Manual Aim is now On, manual aim needs to be turned on.
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacWindow.GetTacticalMenu()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pFireButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Manual Aim")))
	App.g_kLocalizationManager.Unload(pDatabase)

	if pFireButton.IsChosen():
		# Manual Aim is on.  Make sure manual aim is on.
		pTacWindow.SetMousePickFire(1)
	else:
		# Manual Aim is off.  Make sure manual aim is off.
		pTacWindow.SetMousePickFire(0)

###############################################################################
#	PhasersOnlyToggled
#
#	Handler for when the "Phasers Only" button is toggled.
#
#	Args:	pObject 	- target for this event.
#			pEvent		- ET_PHASERS_ONLY event.
#
#	Return:	none
###############################################################################
def PhasersOnlyToggled(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	
	# Get the player's Target
	pTarget = pPlayer.GetTarget()
	if (pTarget == None):
		return

	# Let other handlers handle the event...
	pObject.CallNextHandler(pEvent)

	# Check the player's AI, and set it to fire or not fire, based on the
	# button state..
	CheckFiring(pPlayer)

###############################################################################
#	Maneuver(pObject, pEvent)
#
#	Handler function for Maneuver button click event.
#
#	Args:	pObject 	- target for this event.
#			pEvent		- Event we are handling.
#
#	Return:	none
###############################################################################
def Maneuver(pObject, pEvent):
	# We're taking control of the ship.
	MissionLib.SetPlayerAI("Tactical", None)

	# Update the global status indices based on which menu item
	# was just selected.
	bAcknowledge = 1
	iSubType = pEvent.GetInt()
	if iSubType <= EST_LAST_ORDER:
		global g_iOrderState
		iNewOrderState = iSubType - EST_FIRST_ORDER
		if iNewOrderState != g_iOrderState:
			#debug("Changing order state from %s to %s" % (g_iOrderState, iNewOrderState))
			g_iOrderState = iNewOrderState
			bAcknowledge = 1 # Major change.
		else:
			bAcknowledge = 0 # No change.
		#debug("Set order state to %d (%s)" % (g_iOrderState, GetHighLevelOrder()))
	elif iSubType <= EST_LAST_TACTIC:
		global g_iTacticState
		bAcknowledge = 2 # Minor change.
		g_iTacticState = iSubType - EST_FIRST_TACTIC
		#debug("Set tactic state to %d (%s)" % (g_iTacticState, GetTactic()))
	elif iSubType <= EST_LAST_MANEUVER:
		global g_iManeuverState
		bAcknowledge = 2 # Minor change.
		g_iManeuverState = iSubType - EST_FIRST_MANEUVER
		#debug("Set maneuver state to %d (%s)" % (g_iManeuverState, GetManeuver()))
	else:
#		debug("Invalid maneuver subtype: %d" % iSubType)
		return

	UpdateOrders(bAcknowledge)

	# Done
	pObject.CallNextHandler(pEvent)

###############################################################################
#	UpdateOrders
#	
#	Update the Orders menus, based on our current selections..
#	And update the AI that's controlling the ship.
#	
#	Args:	bAcknowledge	- True if Felix should verbally acknowledge the orders.
#	
#	Return:	None
###############################################################################
def UpdateOrders(bAcknowledge = 1):
	global g_iOrderState

	# If we can't be in control of the ship, clear our orders.
	if MissionLib.GetPlayerShipController() not in (None, "Tactical"):
		g_iOrderState = -1

	# If we're in Starbase 12, don't allow Felix to take orders.
	if g_iOrderState != -1:
		if MissionLib.IsPlayerInsideStarbase12():
			g_iOrderState = -1
#			debug("Someone's trying to give Felix orders while inside Starbase12.")

	# Based on the current menu selections, enable or disable
	# various orders buttons.
	UpdateOrderMenus()

	# If neither the Bridge window nor the Character Menu window is visible,
	# don't do any acknowledgement or AI changes.
	pTopWindow = App.TopWindow_GetTopWindow()

	# Get the Tactical character...
	pTactical = None
	pSet = App.g_kSetManager.GetSet("bridge")
	if pSet:
		pTactical = App.CharacterClass_GetObject(pSet, "Tactical")

	# If Tactical is in control of the player's ship, assign AI.
	if MissionLib.GetPlayerShipController() in ( None, "Tactical" ):
		# Acknowledge the orders, if we're supposed to...
		pSequence = App.TGSequence_Create()

		# Check the player's current target.  If it's not an enemy ship,
		# and our current orders are some form of attack orders, Felix
		# needs to tell you he won't attack it.
		bNoAttack = 0
		if GetHighLevelOrder() in g_lAttackOrders:
			pPlayer = App.Game_GetCurrentPlayer()
			if pPlayer:
				pTarget = pPlayer.GetTarget()
				if pTarget:
					# Only allow Felix to attack if the target is a ship.
					if not App.ShipClass_Cast(pTarget):
						bNoAttack = 1

					pMission = MissionLib.GetMission()
					if pMission:
						if pMission.GetFriendlyGroup().IsNameInGroup(pTarget.GetName()):
							# Player wants Felix to attack a friendly target.  Bad Player.
							# If the player still has this target after a few seconds,
							# Felix needs to tell the player he won't attack it.
							pWontFireLine = App.TGScriptAction_Create(__name__, "FelixWontFire", pTarget.GetName())
							pSequence.AddAction(pWontFireLine, None, 5.0)
							bAcknowledge = 0
							bNoAttack = 1

		if bAcknowledge and pTactical:
			# Only say the "Initiating tactical maneuver" line if the ship
			# isn't currently being controlled by an AI.
			# Load localization database.
			pDatabase = pTactical.GetDatabase()

			pPlayer = App.Game_GetCurrentPlayer()
			if pPlayer and (not pPlayer.GetAI()):
				sHighOrder = GetHighLevelOrder()

				pTorps = pPlayer.GetTorpedoSystem()
				bTorpsOn = 0
				if (pTorps):
					bTorpsOn = pTorps.IsOn()
				pPhasers = pPlayer.GetPhaserSystem()
				bPhasersOn = 0
				if (pPhasers):
					pPhasersOn = pPhasers.IsOn()

				# Tell Tactical to stop the attack
				if bAcknowledge == 2:
					# Just adjusting maneuvers.
					pSequence.AppendAction(App.CharacterAction_Create(pTactical,
										App.CharacterAction.AT_SAY_LINE, 
										pTactical.GetCharacterName() + "Yes%d" % (App.g_kSystemWrapper.GetRandomNumber(4) + 1),
										None, 1, pDatabase, App.CSP_SPONTANEOUS))
				else:
					if (sHighOrder == "OrderStop"):
						pSequence.AppendAction(App.CharacterAction_Create(pTactical,
											App.CharacterAction.AT_SAY_LINE, "Disengaging",
											None, 1, pDatabase, App.CSP_SPONTANEOUS))

						pSequence.AppendAction(App.CharacterAction_Create(pTactical,
											App.CharacterAction.AT_SAY_LINE, 
											pTactical.GetCharacterName() + "Yes%d" % (App.g_kSystemWrapper.GetRandomNumber(4) + 1),
											None, 1, pDatabase, App.CSP_SPONTANEOUS))

					# Evasive maneuvers!!
					elif (sHighOrder == "OrderDefense"):
						pSequence.AppendAction(App.CharacterAction_Create(pTactical,
											App.CharacterAction.AT_SAY_LINE, "EvasiveManuvers",
											None, 1, pDatabase, App.CSP_SPONTANEOUS))

					# Make sure our weapons have power for these functions...
					# KILL!
					elif (sHighOrder == "OrderDestroy"):
						if (not bTorpsOn and not bPhasersOn):
							g_iOrderState = -1
							UpdateOrders()
							pSequence.AppendAction(App.CharacterAction_Create(pTactical,
											App.CharacterAction.AT_SAY_LINE, "NeedPower",
											None, 1, pDatabase, App.CSP_SPONTANEOUS))
						else:
							# Do we have a target? =P
							if not (pPlayer.GetTarget()):
								pSequence.AppendAction(App.CharacterAction_Create(pTactical,
												App.CharacterAction.AT_SAY_LINE, "AdjustTactic",
												None, 1, pDatabase, App.CSP_SPONTANEOUS))
							else:
								pSequence.AppendAction(App.CharacterAction_Create(pTactical,
												App.CharacterAction.AT_SAY_LINE, "gt213",
												None, 1, pDatabase, App.CSP_SPONTANEOUS))

					# Just hurt 'em a bit..
					elif (sHighOrder == "OrderDisable"):
						if (not bTorpsOn and not bPhasersOn):
							g_iOrderState = -1
							UpdateOrders()
							pSequence.AppendAction(App.CharacterAction_Create(pTactical,
											App.CharacterAction.AT_SAY_LINE, "NeedPower",
											None, 1, pDatabase, App.CSP_SPONTANEOUS))
						else:
							# Do we have a target? =P
							if not (pPlayer.GetTarget()):
								pSequence.AppendAction(App.CharacterAction_Create(pTactical,
												App.CharacterAction.AT_SAY_LINE, "AdjustTactic",
												None, 1, pDatabase, App.CSP_SPONTANEOUS))
							else:
								pSequence.AppendAction(App.CharacterAction_Create(pTactical,
												App.CharacterAction.AT_SAY_LINE, "gt212",
												None, 1, pDatabase, App.CSP_SPONTANEOUS))

					# Just in case...
					else:
						pSequence.AppendAction(App.CharacterAction_Create(pTactical,
											App.CharacterAction.AT_SAY_LINE,
											"TacticalManuver",
											None, 1, pDatabase, App.CSP_SPONTANEOUS))
						# Always say "Yes, sir."
						pSequence.AppendAction(App.CharacterAction_Create(pTactical,
											App.CharacterAction.AT_SAY_LINE, 
											pTactical.GetCharacterName() + "Yes%d" % (App.g_kSystemWrapper.GetRandomNumber(4) + 1),
											None, 1, pDatabase, App.CSP_SPONTANEOUS))

		pSequence.Play()

		# Start the AI to fulfull the current orders.
		bActive = StartAI(bNoAttack)
		if pTactical:
			pTactical.SetActive(bActive)

			if (bActive):
				# Set the new orders in our status box
				pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
				pcHighLevelOrder = GetHighLevelOrder()
				if (pcHighLevelOrder == "OrderDestroy"):
					pTactical.SetStatus(pDatabase.GetString("Attacking"))
				elif (pcHighLevelOrder == "OrderDisable"):
					pTactical.SetStatus(pDatabase.GetString("Disabling"))
				elif (pcHighLevelOrder == "OrderDefense"):
					pTactical.SetStatus(pDatabase.GetString("Defending"))

				App.g_kLocalizationManager.Unload(pDatabase)

				global g_bIgnoreNextAIDone
				g_bIgnoreNextAIDone = 1

	elif pTactical:
		pTactical.SetActive(0)

###############################################################################
#	FelixWontFire
#	
#	If the player targeted a friendly ship for felix, Felix won't fire
#	on it.  Felix needs to say so...
#	
#	Args:	pAction			- The script action calling this function.
#			sOldTargetName	- The name of the target when the action was created.
#	
#	Return:	0
###############################################################################
def FelixWontFire(pAction, sOldTargetName):
	# Check if our orders are still attack orders.
	if not (GetHighLevelOrder() in g_lAttackOrders):
		return 0

	# Check if the player still has that target.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pTarget = pPlayer.GetTarget()
		if pTarget and (pTarget.GetName() == sOldTargetName):
			# Yep, player is still targeting it.  Check to make sure it's
			# still in the Friendly group, so Felix doesn't sound dumb...
			pMission = MissionLib.GetMission()

			if pMission:
				if pMission.GetFriendlyGroup().IsNameInGroup(pTarget.GetName()):

					# Yep, it's still a friendly.  Felix speaks up...
					pBridgeSet = App.g_kSetManager.GetSet("bridge")
					pTactical = App.CharacterClass_GetObject(pBridgeSet, "Tactical")
					if (pTactical):
						pDatabase = pTactical.GetDatabase()
						pWontFireLine = App.CharacterAction_Create(pTactical,
								App.CharacterAction.AT_SAY_LINE,
								"BadTarget%d" % (App.g_kSystemWrapper.GetRandomNumber(2) + 1),
								None, 1, pDatabase, App.CSP_SPONTANEOUS)
						pWontFireLine.Play()

	return 0

###############################################################################
#	ClearOrderMenus
#	
#	Reset felixs meneuvers and orders to default state.	
#
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def ClearOrderMenus ():
	global g_iOrderState
	g_iOrderState = 2	# default to stop
	global g_iTacticState
	g_iTacticState = 0
	global g_iManeuverState
	g_iManeuverState = 0
		
	sTactic = GetTactic()
	sManeuver = GetManeuver()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Set the values of the text for these 2 buttons...
	g_pTacticsStatusUIMenu.SetName(pDatabase.GetString(sTactic))
	g_pManeuversStatusUIMenu.SetName(pDatabase.GetString(sManeuver))

	App.g_kLocalizationManager.Unload(pDatabase)

	g_pTacticsStatusUIMenu.Close()
	g_pManeuversStatusUIMenu.Close()

	UpdateOrderMenus ()

###############################################################################
#	UpdateOrderMenus
#	
#	Update the state of the various Orders menus, enabling and disabling
#	options as necessary.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def UpdateOrderMenus():
	# Based on the current menu selections, enable or disable
	# various orders buttons.
	sCurrentOrder = GetHighLevelOrder()
	sCurrentTactic = GetTactic()
	sCurrentManeuver = GetManeuver()

	# This is a flag to determine whether the "disable" order should be ignored
	# at the end of this function (i.e. if the "Attack Maneuver" button is
	# visible).
	bNotDisable = 0

	# If the player has no target, all menus need to be disabled.
	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		# Tactics, Maneuvers, and Target Side menus are disabled.
		CallFuncOnMenuAndChildren("SetDisabled", g_pTacticsStatusUIMenu, len(g_lTactics))
		CallFuncOnMenuAndChildren("SetDisabled", g_pManeuversStatusUIMenu, len(g_lManeuvers))
	else:
		# The player has a target.  Make sure the menus are available.
		CallFuncOnMenuAndChildren("SetEnabled", g_pOrdersStatusUIPane, len(g_lOrders))
		CallFuncOnMenuAndChildren("SetEnabled", g_pTacticsStatusUIMenu, len(g_lTactics))
		CallFuncOnMenuAndChildren("SetEnabled", g_pManeuversStatusUIMenu, len(g_lManeuvers))

		# If "Manual Aim" is disabled, then the buttons in the orders pane should be
		# "destroy" and "disable". Otherwise, hide one of them, and change the name of
		# the other to "Attack Maneuver".
		pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pMenu = pTacWindow.GetTacticalMenu()
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

		pFireButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Manual Aim")))
		bAttackToggle = pFireButton.IsChosen()

		pDestroyButton = App.STButton_Cast(g_pOrdersStatusUIPane.GetNthChild(0))
		pDisableButton = App.STButton_Cast(g_pOrdersStatusUIPane.GetNthChild(1))

		kString = App.TGString()
		pDestroyButton.GetName(kString)
		sHighOrder = GetHighLevelOrder()
		#debug("high level order is " + str(sHighOrder))
		if (bAttackToggle == 0):
			# Should have "destroy" and "disable" buttons.
			pDisableButton.SetVisible(0)

			if (kString.Compare(pDatabase.GetString("OrderDestroy"), 1) != 0):
				# Check our current orders to see which button should be chosen.
				if (sHighOrder == "OrderDestroy"):
					pDisableButton.SetChosen(0)
					pDestroyButton.SetChosen(1)
				elif (sHighOrder == "OrderDisable"):
					pDestroyButton.SetChosen(0)
					pDisableButton.SetChosen(1)
				else:
					pDestroyButton.SetChosen(0)
					pDisableButton.SetChosen(0)

				pDestroyButton.SetName(pDatabase.GetString("OrderDestroy"))
		else:
			# Should have "attack maneuver" button.
			pDisableButton.SetNotVisible(0)
			bNotDisable = 1
			if (kString.Compare(pDatabase.GetString("OrderAttackManeuver"), 1) != 0):
				# Switch from the disable button to the destroy button, if it was
				# selected.
				if (sHighOrder == "OrderDestroy") or (sHighOrder == "OrderDisable"):
					pDisableButton.SetChosen(0)
					pDestroyButton.SetChosen(1)

				else:
					pDestroyButton.SetChosen(0, 0)
					pDisableButton.SetChosen(0, 0)

				pDestroyButton.SetName(pDatabase.GetString("OrderAttackManeuver"))

		App.g_kLocalizationManager.Unload(pDatabase)

		# All children in the Orders menu are available now.
		pStatusButton = g_pOrdersStatusUIPane.GetFirstChild()
		for iButton in range(len(g_lOrders)):
			pStatusButton.SetEnabled()
			pStatusButton = g_pOrdersStatusUIPane.GetNextChild(pStatusButton)

		# Enabling the orders menu may have updated our orders (from None to something).
		sCurrentOrder = GetHighLevelOrder()

		#
		# First, based on Orders, check if any tactics should be enabled/disabled:
		lEnabledTactics = []
		for sOrder, sTactic, sManeuver in g_dAIs.keys():
			if sOrder == sCurrentOrder:
				# Check for tactics that appear.
				if not (sTactic in lEnabledTactics):
					lEnabledTactics.append(sTactic)

		# Enable or disable the various tactics options.
		pStatusButton = g_pTacticsStatusUIMenu.GetFirstChild()
		bOneAvailable = 0
		for sTactic, eEvent in g_lTactics:
			if sTactic in lEnabledTactics:
				# This one should be available.
				bOneAvailable = 1
				pStatusButton.SetEnabled()
			else:
				# Not available.
				pStatusButton.SetDisabled()
				pass
			pStatusButton = g_pTacticsStatusUIMenu.GetNextChild(pStatusButton)

		# If no tactics are available, disable the tactics menu.  And disable
		# the Target Side menu.  It's disabled at the same times this menu is.
		if not bOneAvailable:
			#CallFuncOnMenuAndChildren("SetDisabled", g_pTacticsStatusUIMenu, len(g_lTactics))
			pass

		# The current tactic may have changed...
		sCurrentTactic = GetTactic()


		#
		# Next, based on the current combination of orders and tactics,
		# check if any maneuvers should be enabled/disabled.
		lEnabledManeuvers = []
		for sOrder, sTactic, sManeuver in g_dAIs.keys():
			if (sOrder == sCurrentOrder)  and  (sTactic == sCurrentTactic):
				# Check for maneuvers that appear.
				if not (sManeuver in lEnabledManeuvers):
					lEnabledManeuvers.append(sManeuver)

		# Enable or disable the various maneuvers options.
		pStatusButton = g_pManeuversStatusUIMenu.GetFirstChild()
		bOneAvailable = 0
		for sManeuver, eEvent in g_lManeuvers:
			if sManeuver in lEnabledManeuvers:
				# This one should be available.
				bOneAvailable = 1
				pStatusButton.SetEnabled()
			else:
				# Not available.
				pStatusButton.SetDisabled()
				pass
			pStatusButton = g_pManeuversStatusUIMenu.GetNextChild(pStatusButton)

		# If no maneuvers are available, disable the maneuvers menu.
		if not bOneAvailable:
			#CallFuncOnMenuAndChildren("SetDisabled", g_pManeuversStatusUIMenu, len(g_lManeuvers))
			pass

		# The current maneuver may have changed...
		sCurrentManeuver = GetManeuver()

	# Update selected order
	pStatusButton = App.STButton_Cast(g_pOrdersStatusUIPane.GetFirstChild())
	for sOrder, eEvent in g_lOrders:
		if (sOrder == sCurrentOrder):
			# If we're in the special 'attack maneuver' mode, we need some
			# special handling.

			if ((sOrder == "OrderDisable") and (bNotDisable == 1)):
				pStatusButton.SetChosen(0)
			else:
				pStatusButton.SetChosen(1)
		else:
			# Same situation here. If the saved order is 'disable', then
			# we need to do special handling for the destroy button.
			if ((sOrder == "OrderDestroy") and (bNotDisable == 1) and
				(sCurrentOrder == "OrderDisable")):
				pStatusButton.SetChosen(1)
			else:
				pStatusButton.SetChosen(0)

		pStatusButton = App.STButton_Cast(g_pOrdersStatusUIPane.GetNextChild(pStatusButton))

	# Finally, update the status buttons.
	UpdateOrderStatusButtons(sCurrentOrder, sCurrentTactic, sCurrentManeuver,
		g_pOrdersStatusUIPane.IsEnabled(), g_pTacticsStatusUIMenu.IsEnabled(), g_pManeuversStatusUIMenu.IsEnabled())

###############################################################################
#	CallFuncOnMenuAndChildren
#	
#	Call the given function on a menu and its first
#	iNumChildren children.
#	
#	Args:	sFunc			- Name of the function to call.
#			pMenu			- The menu
#			iNumChildren	- Number of children to disable.
#	
#	Return:	None
###############################################################################
def CallFuncOnMenuAndChildren(sFunc, pMenu, iNumChildren):
	pFunc = getattr(pMenu, sFunc)
	pFunc()

	pChild = pMenu.GetFirstChild()
	for iChild in range(iNumChildren):
		pFunc = getattr(pChild, sFunc)
		pFunc()

		pChild = pMenu.GetNextChild(pChild)

###############################################################################
#	UpdateOrderStatusButtons
#	
#	Update the buttons that display the current status of Felix's orders.
#	
#	Args:	Undocumented.
#	
#	Return:	None
###############################################################################
def UpdateOrderStatusButtons(sOrder, sTactic, sManeuver,
	bOrderEnabled, bTacticEnabled, bManeuverEnabled):

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Set the values of the text for these 3 buttons...
	#debug("TacticStatusButton(%d/%s)" % (bTacticEnabled, sTactic))
	if bTacticEnabled and sTactic:
		g_pTacticsStatusUIMenu.SetEnabled()
		g_pTacticsStatusUIMenu.SetName(pDatabase.GetString(sTactic))
	else:
		if sTactic:
			g_pTacticsStatusUIMenu.SetName(pDatabase.GetString(sTactic))
		else:
			g_pTacticsStatusUIMenu.SetName(pDatabase.GetString(g_lTactics[0][0]))
		pass

	#debug("ManeuverStatusButton(%d/%s)" % (bManeuverEnabled, sManeuver))
	if bManeuverEnabled and sManeuver:
		g_pManeuversStatusUIMenu.SetEnabled()
		g_pManeuversStatusUIMenu.SetName(pDatabase.GetString(sManeuver))
	else:
		if sManeuver:
			g_pManeuversStatusUIMenu.SetName(pDatabase.GetString(sManeuver))
		else:
			g_pManeuversStatusUIMenu.SetName(pDatabase.GetString(g_lManeuvers[0][0]))
		pass

	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	CheckFiring
#	
#	Check whether or not the player's AI should be firing.  If
#	it should be firing, make sure it's firing.  If it shouldn't
#	be, make sure it's not.
#	
#	Args:	pPlayer	- The player's ship.
#	
#	Return:	None
###############################################################################
def CheckFiring(pPlayer):
	#debug("Checking firing for player ship AI..")
	lAIScripts = GetPlayerFiringAIScripts()

	# Check if the player's ship should be firing at will or not.
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacWindow.GetTacticalMenu()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	
	pFireButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Manual Aim")))
	bAttackToggle = not pFireButton.IsChosen()

	# Also check if the player's ship should only be firing
	# phasers, or if it can use all weapons.
	pPhasersOnlyButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("PhasersOnly")))
	bPhasersOnly = pPhasersOnlyButton.IsChosen()
	App.g_kLocalizationManager.Unload(pDatabase)

	# Loop through all the firing AI's, and set their Enabled flags to bAttackToggle.
	# And set the systems they're firing based on the bPhasersOnly flag.
	#debug("Setting %d fire AI's to (%d)" % (len(lAIs), bAttackToggle))
	for pScript in lAIScripts:
		pScript.SetEnabled(bAttackToggle)
		if bPhasersOnly:
			lWeaponSystems = [ pPlayer.GetPhaserSystem() ]
		else:
			lWeaponSystems = [ pPlayer.GetPhaserSystem(), pPlayer.GetTorpedoSystem(), pPlayer.GetPulseWeaponSystem() ]

		# Check if the current systems are different...
		bDifferent = 0
		lScriptWeapons = pScript.GetWeapons()
		if len(lScriptWeapons) != len(lWeaponSystems):
			bDifferent = 1
		else:
			for iIndex in range(len(lWeaponSystems)):
				if lScriptWeapons[iIndex].GetObjID() != lWeaponSystems[iIndex].GetObjID():
					bDifferent = 1
					break

		if bDifferent:
			pScript.RemoveAllWeaponSystems()
			for pSystem in lWeaponSystems:
				if pSystem:
					pScript.AddWeaponSystem( pSystem )

###############################################################################
#	CheckSubsystemTargeting
#	
#	Check the player AI's firing AIs.  If AutoTarget is on, the
#	firing AI's should have their own list of subsystems to target.  If
#	it's off, the firing AI's shouldn't have any subsystems in their
#	target list.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def CheckSubsystemTargeting():
	#debug(__name__ + ": Checking subsystem targeting...")
	lFireScripts = GetPlayerFiringAIScripts()
	if not lFireScripts:
		#debug(__name__ + ": Checking subsystem targeting...No Fire scripts")
		return

	# Check the Targeting button to see if we're autotargeting or not.
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacWindow.GetTacticalMenu()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTargetingButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Target At Will")))
	App.g_kLocalizationManager.Unload(pDatabase)

	# If it's chosen, we're autotargeting.
	if pTargetingButton.IsChosen() == 1:
		#debug(__name__ + ": Checking subsystem targeting...Autotargeting.")
		# We're autotargeting.  Ensure that the script has a
		# list of target subsystems.
		iRestored = 0
		for pScript in lFireScripts:
			# Make sure the script has a list of target subsystems.
			if not pScript.HasSubsystemTargets():
				# It doesn't have any subsystem targets.  Add some.
				pScript.RestoreSubsystemTargets()
				iRestored = iRestored + 1
		#debug(__name__ + ": Checking subsystem targeting...%d systems restored" % iRestored)
	else:
		#debug(__name__ + ": Checking subsystem targeting...Not autotargeting.")
		# Not autotargeting.  Make sure the fire scripts have no
		# targets.
		iIgnored = 0
		for pScript in lFireScripts:
			if pScript.HasSubsystemTargets():
				# It has targets.  It needs to ignore them.
				pScript.IgnoreSubsystemTargets()
				iIgnored = iIgnored + 1
		#debug(__name__ + ": Checking subsystem targeting...%d systems changed to ignore" % iIgnored)

###############################################################################
#	GetPlayerFiringAIScripts
#	
#	Get the script instances from all the Fire AI's in the
#	player's currently running AI.  This assumes the g_lPlayerFireAIs
#	list has already been setup.
#	
#	Args:	None
#	
#	Return:	A list of all the Fire AI scripts (not the AI's themselves).
###############################################################################
def GetPlayerFiringAIScripts():
	# Get the list of firing AI's.
	lFireScripts = []
	for idAI in g_lPlayerFireAIs:
		# Get the AI, and make sure it's a preprocessing AI.
		pAI = App.PreprocessingAI_Cast( App.ArtificialIntelligence_GetAIByID(idAI) )
		if pAI:
			# Get the preprocess script instance.
			pScript = pAI.GetPreprocessingInstance()
			if pScript:
				lFireScripts.append(pScript);
	return lFireScripts

###############################################################################
#	StartAI
#	
#	Handy wrapper for setting up the attack maneuvers.  Takes
#	care of target groups, setting up firing or not firing, etc.
#	
#	Args:	bNoAttack	- True if this shouldn't start any attack AI's.
#						  If the current AI would be an attack, this uses
#						  the Stay AI.
#	
#	Return:	None
###############################################################################
def StartAI(bNoAttack):
	# Get the player's ship:
	pGame = App.Game_GetCurrentGame()
	if not pGame:
		return 0

	pPlayer = pGame.GetPlayer()
	if not pPlayer:
		return 0

	# Clear the player's current AI.
	pPlayer.ClearAI()

	# Get the player's Target
	pTarget = pPlayer.GetTarget()
	#if not pTarget:
		#return 0

	# Get the AI to use, for our current orders.
	if bNoAttack  and  (GetHighLevelOrder() in g_lAttackOrders):
		# Orders say attack, but bNoAttack says no attack.  Use Stay.
		sModule, lParams = ChooseAIFromOrders("OrderStopSelect", None, None)
	else:
		sModule, lParams = ChooseAIFromOrders(GetHighLevelOrder(), GetTactic(), GetManeuver())
		#debug("Chose AI from (%s,%s,%s) to  %s(%s)" % (GetHighLevelOrder(), GetTactic(), GetManeuver(), sModule, lParams))

	if (sModule is None) or (lParams is None):
		#debug ("*** in start AI no sModule")
		return 0

	# Setup the AI.
	pAIModule = __import__(sModule)
	lFullParams = (pPlayer, pTarget) + lParams
	pPlayerAI = apply(pAIModule.CreateAI, lFullParams)

	# Save the ID of the firing AIs, so firing can be turned on and
	# off at will.
	global g_lPlayerFireAIs
	g_lPlayerFireAIs = []
	lAIs = pPlayerAI.GetAllAIsInTree()
	for pAI in lAIs:
		# Check if it's a preprocessing AI.
		pPreAI = App.PreprocessingAI_Cast(pAI)
		if pPreAI:
			# Yes, it is.  Get its script.
			pScript = pPreAI.GetPreprocessingInstance()

			# Check if it's a FireScript instance.
			import AI.Preprocessors
			if isinstance(pScript, App.OptimizedFireScript): #AI.Preprocessors.FireScript):
				# This is a firing AI.  Save its ID.
				g_lPlayerFireAIs.append( pAI.GetID() )
	#debug("Found %d fire scripts in attack maneuver %s" % (len(lAIs), sModule))

	# Check whether or not this should actually fire.
	CheckFiring(pPlayer)
	# And how it should deal with subsystems.
	CheckSubsystemTargeting()

	# Give the player the AI.
	MissionLib.SetPlayerAI("Tactical", pPlayerAI)

	# Save the ID of the AI.
	global g_idCurrentAI
	g_idCurrentAI = pPlayerAI.GetID()

	# Return 1 to say that we're active UNLESS our AI is the "Stay" AI.
	if sModule == g_dAIs[("OrderStop", None, None)]:
		return 0

	return 1

###############################################################################
#	GetHighLevelOrder
#	
#	Get the current high-level orders for tactical.
#	
#	Args:	None
#	
#	Return:	One of the high-level orders strings ("Destroy", "None", etc.)
###############################################################################
def GetHighLevelOrder():
	return GetOrderString(g_pOrdersStatusUIPane, g_iOrderState, g_lOrders)

def GetOrderString(pMenu, iIndex, lOrders):
	# If someone other than Tactical is in control of the ship, we have no orders.
	if MissionLib.GetPlayerShipController() not in ( None, "Tactical" ):
		return None

	if iIndex == -1:
		return None

	if pMenu  and  pMenu.IsEnabled():
		# This menu is available.  If the current order is
		# disabled, Change it to be the first enabled item
		# in the menu.
		pButton = pMenu.GetNthChild(iIndex)
		if not pButton.IsEnabled():
			pButton = pMenu.GetFirstChild()
			for sOrder, eEvent in lOrders:
				if pButton.IsEnabled():
					return sOrder
				pButton = pMenu.GetNextChild(pButton)

		return lOrders[iIndex][0]

	return None

###############################################################################
#	GetTactic
#	
#	Get the current tactics setting.
#	
#	Args:	None
#	
#	Return:	One of the tactics strings ("AtWill", "Left", "Fore", etc.)
#			or None.
###############################################################################
def GetTactic():
	return GetOrderString(g_pTacticsStatusUIMenu, g_iTacticState, g_lTactics)

###############################################################################
#	GetManeuver
#	
#	Get the current Maneuver setting.
#	
#	Args:	None
#	
#	Return:	One of the Maneuver strings ("AtWill", "Close", "Maintain", etc.)
#			or None.
###############################################################################
def GetManeuver():
	return GetOrderString(g_pManeuversStatusUIMenu, g_iManeuverState, g_lManeuvers)

###############################################################################
#	ChooseAIFromOrders
#	
#	Choose which AI to run, based on the current settings for our
#	orders (and tactics and maneuvers).  If we have a valid combination
#	of orders, this returns the module name of the AI file to use and the
#	parameters to pass to that module.
#	Otherwise, it returns None, None.
#	
#	Args:	None
#	
#	Return:	The module name of the AI to use, or None, followed by
#			the parameters to give that module, or None.
###############################################################################
def ChooseAIFromOrders(sOrder, sTactic, sManeuver):
	#debug("Looking for AI for O(%s) T(%s) M(%s)" % ( sOrder, sTactic, sManeuver ))

	# Check if this combination is valid..
	if not g_dAIs.has_key((sOrder, sTactic, sManeuver)):
		# Not valid.  There's no appropriate AI for this
		# combination of orders.
		if not g_dAIs.has_key((sOrder, None, None)):
			return None, None
		else:
			sTactic = None
			sManeuver = None

	# It's a valid AI order.  Figure out which AI module it should use,
	# with what parameters.
	sModule, lParams = g_dAIs[( sOrder, sTactic, sManeuver )]
	sModule = "AI.Player." + sModule
	#debug("Valid combination of orders.  Using AI module: " + sModule)
	return sModule, lParams

###############################################################################
#	PlayerCantFire()
#	
#	The player just attempted to fire, but can't.  Find out why, and report
#	the condition if necessary
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def PlayerCantFire(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	# Figure out what just fired...
	pTorps = App.TorpedoSystem_Cast(pEvent.GetSource())
	pPhasers = App.PhaserSystem_Cast(pEvent.GetSource())
	pTractors = App.TractorBeamSystem_Cast(pEvent.GetSource())

	global g_fLastWarnTime
	if (App.g_kUtopiaModule.GetGameTime() - g_fLastWarnTime < 2):
		pObject.CallNextHandler(pEvent)
		return

	if (pTorps):
		if (pTorps.GetNumReady() > 0):
			pObject.CallNextHandler(pEvent)
			return

		if (pTorps.GetNumAvailableTorpsToType(pTorps.GetAmmoTypeNumber()) <= 0):
			# We're out of torps of that type
			App.g_kSoundManager.PlaySound("UITorpsNoAmmo")
			g_fLastWarnTime = App.g_kUtopiaModule.GetGameTime()
		else:
			# We haven't reloaded yet
			App.g_kSoundManager.PlaySound("UITorpsNotLoaded")
			g_fLastWarnTime = App.g_kUtopiaModule.GetGameTime()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	PlayerTorpChanged()
#	
#	The player just changed the type of torpedo they're using
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def PlayerTorpChanged(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	pTorps = App.TorpedoSystem_Cast(pEvent.GetSource())

	#global g_fLastWarnTime
	#if (App.g_kUtopiaModule.GetGameTime() - g_fLastWarnTime < 2):
	#	pObject.CallNextHandler(pEvent)
	#	return

	if not (pTorps):
		pObject.CallNextHandler(pEvent)
		return

	#g_fLastWarnTime = App.g_kUtopiaModule.GetGameTime()
		
	pObject.CallNextHandler(pEvent)

###############################################################################
#	HandleOrdersStatusKeyboard(pOrdersPane, pEvent)
#	
#	Keyboard handler for the orders status pane.
#	
#	Args:	pTCW		- the tactical control window
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def HandleOrdersStatusKeyboard(pTCW, pEvent):
	pOrdersPane = g_pOrdersStatusUIPane

	if pOrdersPane.IsInTrueFocusPath() == 0:
		pTCW.CallNextHandler(pEvent)
		return

	# Check the event type, since this is used for multiple types of keyboard
	# events.
	iFocus = pOrdersPane.FindPos(pOrdersPane.GetFocus())

	if pEvent.GetEventType() == App.ET_INPUT_SELECT_OPTION:
		iMove = pEvent.GetInt()

		if iMove == 0:
			# Right.
			if iFocus == -1:
				pOrdersPane.SetFocus(pOrdersPane.GetFirstChild())
			elif (iFocus % 2) == 0:
				pOrdersPane.SetFocus(pOrdersPane.GetNextChild(pOrdersPane.GetFocus()))
		elif iMove == 1:
			# Down.
			if iFocus == -1:
				pOrdersPane.SetFocus(pOrdersPane.GetFirstChild())
			elif iFocus < 2:
				pOrdersPane.SetFocus(pOrdersPane.GetNthChild(iFocus + 2))
		elif iMove == -1:
			# Up.
			if iFocus == -1:
				pOrdersPane.SetFocus(pOrdersPane.GetFirstChild())
			elif iFocus > 1:
				pOrdersPane.SetFocus(pOrdersPane.GetNthChild(iFocus - 2))
	elif pEvent.GetEventType() == App.ET_INPUT_CLOSE_MENU:
		# Left.
		if iFocus == -1:
			pOrdersPane.SetFocus(pOrdersPane.GetFirstChild())
		elif (iFocus % 2) == 1:
			pOrdersPane.SetFocus(pOrdersPane.GetNthChild(iFocus - 1))

	pOrdersPane.CallNextHandler(pEvent)
