###############################################################################
#	Filename:	TacticalControlWindow.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script to resize and reposition the stuff in the tactical control window.
#	
#	Created:	5/14/2001 -	Erik Novales
###############################################################################

import App
import ShipDisplay
import DamageDisplay
import WeaponsDisplay
import RadarDisplay
import Bridge.TacticalMenuHandlers

INTERFACE_PANE	= 0
BACKGROUND_PANE = 1

# Interface pane
TACTICAL_MENU		= 0
ENEMY_SHIP_DISPLAY	= 1
TARGET_LIST			= 2
RADAR_TOGGLE		= 3
RADAR_DISPLAY		= 4
SHIP_DISPLAY		= 5
ORDERS_STATUS		= 6
WEAPONS_DISPLAY		= 7
WEAPONS_CONTROL		= 8

# Background pane

# Used to provide hints for layout of the interface.
g_idMenuIsUp = 0
g_bIsInTacticalEngineering = 0
g_bIsInBridgeTactical = 0

# Used to ensure that, in the handler for refreshing after a menu
# size change, that we don't keep calling Refresh().
g_bIsInRefresh = 0

# List of windows that were already minimized when a menu was opened.
g_lMinimizedWindows = []

# Dictionary containing the functions to be used for setting up the
# tactical control window.
kSetupFunctions = {"Bridge": {
							  "Helm":		("SetupBridgeHelm", "ResizeBridgeHelm"),
							  "Tactical":	("SetupBridgeTactical", "ResizeBridgeTactical"),
							  "XO":			("SetupBridgeXO", "ResizeBridgeXO"),
							  "Science":	("SetupBridgeScience", "ResizeBridgeScience"), 
							  "Engineer":	("SetupBridgeEngineer", "ResizeBridgeEngineer"), 
							  "Picard":		("SetupBridgeGuest", "ResizeBridgeGuest"),
							  "Data":		("SetupBridgeGuest", "ResizeBridgeGuest"),
							  "Saalek":		("SetupBridgeGuest", "ResizeBridgeGuest"),
							  "None":		("SetupBridgeNone", "ResizeBridgeNone")
							 }, 
				   "Tactical": {
								"Helm":		("SetupTacticalHelm", "ResizeTacticalHelm"),
								"Tactical": ("SetupTacticalTactical", "ResizeTacticalTactical"), 
								"XO":		("SetupTacticalXO", "ResizeTacticalXO"), 
								"Science":	("SetupTacticalScience", "ResizeTacticalScience"), 
								"Engineer":	("SetupTacticalEngineer", "ResizeTacticalEngineer"),
								"Picard":	("SetupTacticalGuest", "ResizeTacticalGuest"),
								"Data":		("SetupTacticalGuest", "ResizeTacticalGuest"),
								"Saalek":	("SetupTacticalGuest", "ResizeTacticalGuest"),
								"None":		("SetupTacticalNone", "ResizeTacticalNone")
							   }}

# Cached.. name of the last setup function called.
g_sLastSetupFunc = ""

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

###############################################################################
#	HandleSwitchIconGroups(pWindow, pEvent)
#	
#	Event handler for one of the resolution-switching events.
#	
#	Args:	pWindow	- the tactical control window
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def HandleSwitchIconGroups(pWindow, pEvent):
	pass

###############################################################################
#	HandleResizeUI(pWindow, pEvent)
#	
#	Event handler for one of the resolution-switching events.
#	
#	Args:	pWindow	- the tactical control window
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def HandleResizeUI(pWindow, pEvent):
	# Save and restore the correct font, in case the menu was used to switch
	# resolutions.
	pFontGroup = App.g_kFontManager.GetDefaultFont()
	pMode = App.GraphicsModeInfo_GetCurrentMode()

	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[pMode.GetCurrentResolution()])

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	if pTCW:
		pShipDisplay = pTCW.GetShipDisplay()
		pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
		pWeaponsDisplay = pTCW.GetWeaponsDisplay()
		pRadarDisplay = pTCW.GetRadarDisplay()

		ShipDisplay.ResizeUI(pShipDisplay)
		ShipDisplay.ResizeUI(pEnemyShipDisplay)
		WeaponsDisplay.ResizeUI(pWeaponsDisplay)
		RadarDisplay.ResizeUI(pRadarDisplay)

		pTCW.Layout()

	ResizeUI()

	App.g_kFontManager.SetDefaultFont(pFontGroup.GetFontName(), pFontGroup.GetFontSize())

###############################################################################
#	HandleRepositionUI(pWindow, pEvent)
#	
#	Event handler for one of the resolution-switching events.
#	
#	Args:	pWindow	- the tactical control window
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def HandleRepositionUI(pWindow, pEvent):
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacWeaponsCtrl = App.TacWeaponsCtrl_GetTacWeaponsCtrl()
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Save and restore the correct font, in case the menu was used to switch
	# resolutions.
	pFontGroup = App.g_kFontManager.GetDefaultFont()
	pMode = App.GraphicsModeInfo_GetCurrentMode()

	import MainMenu.mainmenu
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[pMode.GetCurrentResolution()])

	# Rebuild the tactical weapons control.
	if pTacWeaponsCtrl:
		pTacWeaponsCtrl.Init()
		pTacWeaponsCtrl.SetFixedSize(LCARS.WEAPONS_CTRL_PANE_WIDTH + pTacWeaponsCtrl.GetBorderWidth(),
									 LCARS.WEAPONS_CTRL_PANE_HEIGHT + pTacWeaponsCtrl.GetBorderHeight())
		pTacWeaponsCtrl.RefreshPhaserSettings()
		pTacWeaponsCtrl.RefreshTorpedoSettings()
		pTacWeaponsCtrl.RefreshTractorToggle()
		pTacWeaponsCtrl.RefreshCloakToggle()
		pTacWeaponsCtrl.InteriorChangedSize()

	# Reposition other UI elements in this window.
	RepositionUI()

	if (pTCW != None):
		pShipDisplay = pTCW.GetShipDisplay()
		pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
		pWeaponsDisplay = pTCW.GetWeaponsDisplay()
		pRadarDisplay = pTCW.GetRadarDisplay()

		ShipDisplay.RepositionUI(pShipDisplay)
		ShipDisplay.RepositionUI(pEnemyShipDisplay)
		WeaponsDisplay.RepositionUI(pWeaponsDisplay)
		RadarDisplay.RepositionUI(pRadarDisplay)

		import Bridge.TacticalMenuHandlers
		pTacticalMenu = pTCW.GetTacticalMenu()
		pTMW = App.STStylizedWindow_Cast(pTacticalMenu.GetConceptualParent())

		pTMW.SetMaximumSize(LCARS.TACTICAL_MENU_WIDTH + pTMW.GetBorderWidth(), LCARS.TACTICAL_MENU_HEIGHT + pTMW.GetBorderHeight())
		pTacticalMenu.Resize(pTMW.GetMaximumInteriorWidth(), pTMW.GetMaximumInteriorHeight(), 0)

		# This will reattach all the appropriate stuff.
		Bridge.TacticalMenuHandlers.CreateOrdersStatusDisplay(1.0 - pTacticalMenu.GetWidth() - pTMW.GetBorderWidth(), pTacticalMenu)
		Bridge.TacticalMenuHandlers.UpdateOrderMenus()

		# Now, deal with the engineering power display.
		import Bridge.PowerDisplay
		Bridge.PowerDisplay.UIFixPowerDisplay()

		pTCW.Layout()

	Refresh()

	App.g_kFontManager.SetDefaultFont(pFontGroup.GetFontName(), pFontGroup.GetFontSize())

###############################################################################
#	HandleMinimized(pObject, pEvent)
#	
#	Handles minimization/maximization of a UI element by resizing and
#	repositioning the tactical control window's UI.
#	
#	Args:	pObject	- the object
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def HandleMinimized(pObject, pEvent):
	if (g_bIsInRefresh == 1):
		return

	pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalMenu = pTacCtrlWindow.GetTacticalMenu()
	pTop = App.TopWindow_GetTopWindow()
	if (pTacCtrlWindow.GetOpenMenu()):
		bNoMenu = 0
	else:
		bNoMenu = 1

	pcCharacterName = GetTacticalControlWindowCharacterName ()

	pFunc = None
	pcType = "Tactical"

	if (pTacCtrlWindow.GetParent()):
		pTacCtrlWindow.GetParent().RemoveChild(pTacCtrlWindow, 0)

	if pTop.IsBridgeVisible():
		if (bNoMenu == 0):
			pBridgeWindow = pTop.FindMainWindow(App.MWT_BRIDGE)
			pBridgeWindow.AddChild(pTacCtrlWindow, 0.0, 0.0, 0)
		else:
			pTacCtrlWindow.SetNotVisible(0)
		pcType = "Bridge"
	elif pTop.IsTacticalVisible():
		pTacticalWindow = pTop.FindMainWindow(App.MWT_TACTICAL)
		pTacticalWindow.AddChild(pTacCtrlWindow, 0.0, 0.0, 0)
		pcType = "Tactical"

		# Update the status of manual aim.
		import Bridge.TacticalMenuHandlers
		Bridge.TacticalMenuHandlers.UpdateManualAim()

	if (not kSetupFunctions[pcType].has_key(pcCharacterName)):
		pcCharacterName = "None"

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()

	# Update the list of minimized windows.
	global g_lMinimizedWindows
	g_lMinimizedWindows = []

	if pEnemyShipDisplay.IsMinimized() and pEnemyShipDisplay.IsMinimizable():
		g_lMinimizedWindows.append(pEnemyShipDisplay.GetObjID())
	if pRadarDisplay.IsMinimized() and pRadarDisplay.IsMinimizable():
		g_lMinimizedWindows.append(pRadarDisplay.GetObjID())

	eval(kSetupFunctions[pcType][pcCharacterName][1] + "()")

	# Handle the case if we're in bridge tactical mode.
	if (g_bIsInBridgeTactical == 1) or ((pTacticalMenu != None) and (pTacticalMenu.IsCompletelyVisible())):
		pMode = App.GraphicsModeInfo_GetCurrentMode()
		pEnemyShipDisplay.SetMinimizable(1)
		pRadarDisplay.SetMinimizable(1)

		# If we're in 640x480, depending on the state of the windows, enable or disable 
		# minimization.
		if pMode.GetWidth() == 640:
			if pRadarDisplay.IsMinimized() == 0:
				# Enemy ship display must be set not minimizable.
				pEnemyShipDisplay.SetMinimized(0)
				pEnemyShipDisplay.SetMinimizable(0)
			else:
				pEnemyShipDisplay.SetMinimizable(1)

				if pEnemyShipDisplay.IsMinimized() == 0:
					pRadarDisplay.SetMinimized(0)
					pRadarDisplay.SetMinimizable(0)
				else:
					pRadarDisplay.SetMinimizable(1)

	ResizeUI()
	RepositionUI()


###############################################################################
#	Refresh()
#	
#	Updates the UI based on whether or not the bridge or tactical is visible,
#	and depending on which character's menu is up.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def Refresh():
## 	# How did we get here?  Print the stack.
## 	import traceback
## 	import StringIO
## 	pOutput = StringIO.StringIO()
## 	traceback.print_stack(None, None, pOutput)
## 	debug("Refresh stack:\n" + pOutput.getvalue())

	kProfiling = App.TGProfilingInfo("TacticalControlWindow.Refresh")

	global g_bIsInRefresh

	if (g_bIsInRefresh == 1):
		return

	pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	if (pTacCtrlWindow == None):
		return

	g_bIsInRefresh = 1

	pTacticalMenu = pTacCtrlWindow.GetTacticalMenu()
	pTop = App.TopWindow_GetTopWindow()
	if (pTacCtrlWindow.GetOpenMenu()):
		bNoMenu = 0
	else:
		if (not pTacticalMenu.IsVisible()):
			bNoMenu = 1

	pcCharacterName = GetTacticalControlWindowCharacterName ()

	pFunc = None
	pcType = "Tactical"

	if (pTacCtrlWindow.GetParent()):
		pTacCtrlWindow.GetParent().RemoveChild(pTacCtrlWindow, 0)

	if pTop.IsBridgeVisible():
		if (bNoMenu == 0):
			pBridgeWindow = pTop.FindMainWindow(App.MWT_BRIDGE)
			pBridgeWindow.AddChild(pTacCtrlWindow, 0.0, 0.0, 0)
			pTacCtrlWindow.SetVisible(0)
		else:
			pTacCtrlWindow.SetNotVisible(0)
		pcType = "Bridge"
	elif pTop.IsTacticalVisible():
		pTacticalWindow = pTop.FindMainWindow(App.MWT_TACTICAL)
		pTacticalWindow.AddChild(pTacCtrlWindow, 0.0, 0.0, 0)
		pTacCtrlWindow.SetVisible(0)
		pcType = "Tactical"

	if (not kSetupFunctions[pcType].has_key(pcCharacterName)):
		pcCharacterName = "None"

	#debug("Refresh(): type is " + pcType + ", character is " + pcCharacterName)

	global g_sLastSetupFunc
	sSetupFunc = kSetupFunctions[pcType][pcCharacterName][0]

	#if sSetupFunc != g_sLastSetupFunc:
	g_sLastSetupFunc = sSetupFunc
	pSetupFunc = globals()[sSetupFunc]
	pSetupFunc()

	g_bIsInRefresh = 0

###############################################################################
#	ResizeUI()
#	
#	Resizes the items in the tactical control window.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def ResizeUI():
	kProfiling = App.TGProfilingInfo("TacticalControlWindow.ResizeUI")
	# Get resolution-dependant LCARS module.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pTacWeaponsCtrl = pTacCtrlWindow.GetWeaponsControl()
	pTacticalMenu = pTacCtrlWindow.GetTacticalMenu()
	pShipDisplay = pTacCtrlWindow.GetShipDisplay()
	pEnemyShipDisplay = pTacCtrlWindow.GetEnemyShipDisplay()
	pWeaponsDisplay = pTacCtrlWindow.GetWeaponsDisplay()
	pTargetMenu = pTacCtrlWindow.GetTargetMenu()
	pRadarDisplay = pTacCtrlWindow.GetRadarDisplay()
	pRadarToggle = pTacCtrlWindow.GetRadarToggle()

	kInterfacePane = App.TGPane_Cast(pTacCtrlWindow.GetNthChild(INTERFACE_PANE))
	kBackgroundPane = App.TGPane_Cast(pTacCtrlWindow.GetNthChild(BACKGROUND_PANE))

	# Get children to be resized.
	pTacticalMenuPane = App.STStylizedWindow_Cast(kInterfacePane.GetNthChild(TACTICAL_MENU))
	pTargetListPane = App.STStylizedWindow_Cast(kInterfacePane.GetNthChild(TARGET_LIST))
	pRadarTogglePane = App.TGPane_Cast(kInterfacePane.GetNthChild(RADAR_TOGGLE))

	# Resize everything.
	if (g_bIsInTacticalEngineering == 0):
		pTargetListPane.SetNotMinimized(0)
		fHeight = LCARS.TACTICAL_MENU_HEIGHT
	else:
		fHeight = LCARS.SCREEN_HEIGHT - pRadarDisplay.GetHeight() - pTargetListPane.GetHeight() - pEnemyShipDisplay.GetHeight() - (3.0 * App.globals.DEFAULT_ST_INDENT_VERT)

	global g_idMenuIsUp
	if (g_idMenuIsUp == App.NULL_ID):
		pMenu = pTacticalMenu
		fHeight = LCARS.TACTICAL_MENU_HEIGHT
		if pMenu and pMenu.GetContainingWindow():
			pTacMenuWindow = pMenu.GetContainingWindow()
			pTacMenuWindow.SetMaximumSize(LCARS.TACTICAL_MENU_WIDTH + pTacMenuWindow.GetBorderWidth(), pTacMenuWindow.GetMaximumHeight())
	else:
		pMenu = App.STMenu_Cast(App.TGObject_GetTGObjectPtr(g_idMenuIsUp))
		if (pMenu == None):
			pMenu = pTacticalMenu
			fHeight = LCARS.TACTICAL_MENU_HEIGHT
			if pMenu and pMenu.GetContainingWindow():
				pTacMenuWindow = pMenu.GetContainingWindow()
				pTacMenuWindow.SetMaximumSize(LCARS.TACTICAL_MENU_WIDTH + pTacMenuWindow.GetBorderWidth(), pTacMenuWindow.GetMaximumHeight())
		else:
			pMenuWindow = App.STStylizedWindow_Cast(pMenu.GetConceptualParent())
			pTop = App.TopWindow_GetTopWindow()

			if (pMenu.GetObjID() == pTacticalMenu.GetObjID()):
				pMenuWindow.SetMaximumSize(LCARS.TACTICAL_MENU_WIDTH + pMenuWindow.GetBorderWidth(), pMenuWindow.GetMaximumHeight())

			pMenu.ResizeToContents()
			fHeight = pMenuWindow.GetHeight()

			if (g_bIsInTacticalEngineering == 1):
				fHeight = pMenuWindow.GetMaximumHeight()

	# Resize target list
	TARGET_LIST_WIDTH = LCARS.TACTICAL_MENU_WIDTH + pTacticalMenuPane.GetBorderWidth()
	TARGET_LIST_HEIGHT = (LCARS.SCREEN_HEIGHT - fHeight - 
						pRadarDisplay.GetHeight() - pEnemyShipDisplay.GetHeight() - 
						(3.0 * App.globals.DEFAULT_ST_INDENT_VERT))

	pTargetList = App.STTargetMenu_GetTargetMenu()

	if (g_bIsInTacticalEngineering == 0):
		pEnemyShipDisplay.SetVisible(0)

	global g_idMenuIsUp
	if (g_idMenuIsUp == App.NULL_ID):
		TARGET_LIST_HEIGHT = TARGET_LIST_HEIGHT + LCARS.TACTICAL_MENU_HEIGHT

	pTargetListPane.SetMaximumSize(TARGET_LIST_WIDTH, TARGET_LIST_HEIGHT)
	pTargetList.Resize(pTargetListPane.GetMaximumInteriorWidth(), pTargetList.GetHeight())
	
	pRadarTogglePane.Resize(LCARS.RADAR_TOGGLE_WIDTH, LCARS.RADAR_TOGGLE_HEIGHT, 0)

###############################################################################
#	RepositionUI()
#	
#	Repositions the items in the tactical control window.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def RepositionUI():
	kProfiling = App.TGProfilingInfo("TacticalControlWindow.RepositionUI")
	# Get resolution-dependant LCARS module.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pTacWeaponsCtrl = pTacCtrlWindow.GetWeaponsControl()
	pTacticalMenu = pTacCtrlWindow.GetTacticalMenu()
	pShipDisplay = pTacCtrlWindow.GetShipDisplay()
	pEnemyShipDisplay = pTacCtrlWindow.GetEnemyShipDisplay()
	pWeaponsDisplay = pTacCtrlWindow.GetWeaponsDisplay()
	pTargetMenu = pTacCtrlWindow.GetTargetMenu()
	pRadarDisplay = pTacCtrlWindow.GetRadarDisplay()
	pRadarToggle = pTacCtrlWindow.GetRadarToggle()

	kInterfacePane = App.TGPane_Cast(pTacCtrlWindow.GetNthChild(INTERFACE_PANE))
	kBackgroundPane = App.TGPane_Cast(pTacCtrlWindow.GetNthChild(BACKGROUND_PANE))

	# Get children to be resized.
	pTacticalMenuPane = App.TGPane_Cast(kInterfacePane.GetNthChild(TACTICAL_MENU))
	pTargetListPane = App.TGPane_Cast(kInterfacePane.GetNthChild(TARGET_LIST))
	pRadarTogglePane = App.TGPane_Cast(kInterfacePane.GetNthChild(RADAR_TOGGLE))
	pOrdersStatusPane = App.TGPane_Cast(kInterfacePane.GetNthChild(ORDERS_STATUS))
	pWeaponsDisplayPane = App.TGPane_Cast(kInterfacePane.GetNthChild(WEAPONS_DISPLAY))
	pWeaponsControlPane = App.TGPane_Cast(kInterfacePane.GetNthChild(WEAPONS_CONTROL))

	# Reposition tactical menu.
	pTacticalMenuPane.SetPosition(0.0, 0.0, 0)
		
	# Reposition enemy ship display.
	global g_idMenuIsUp
	if (g_idMenuIsUp != App.NULL_ID):
		pMenu = App.STMenu_Cast(App.TGObject_GetTGObjectPtr(g_idMenuIsUp))

		if (pMenu):
			pWindow = App.STStylizedWindow_Cast(pMenu.GetConceptualParent())

			if (g_bIsInTacticalEngineering == 0):
				pEnemyShipDisplay.AlignTo(pMenu.GetConceptualParent(), App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL, 0)
			else:
				# Move the enemy ship display below the maximum size of the menu.
				pEnemyShipDisplay.SetPosition(pWindow.GetLeft(),
											  pWindow.GetTop() + pWindow.GetMaximumHeight(), 0)
		else:
			pEnemyShipDisplay.AlignTo(pTacticalMenuPane, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL, 0)

		pEnemyShipDisplay.Move(0.0, App.globals.DEFAULT_ST_INDENT_VERT, 0)
	else:
		pEnemyShipDisplay.SetPosition(0.0, 0.0, 0)

	# Reposition Radar Display.
	pRadarDisplay.SetPosition(0.0, LCARS.SCREEN_HEIGHT - pRadarDisplay.GetHeight(), 0)

	# Reposition target list
	pTargetListPane.AlignTo(pEnemyShipDisplay, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_UL, 0)

	pTargetListPane.Move(0.0, App.globals.DEFAULT_ST_INDENT_VERT, 0)

	# Reposition radar/enemy ship display toggle.
	pRadarTogglePane.AlignTo(pRadarDisplay, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UR, 0)

	# Reposition weapons display.
	pWeaponsDisplay.SetPosition(LCARS.SCREEN_WIDTH - pWeaponsDisplay.GetWidth(),
							LCARS.SCREEN_HEIGHT - pWeaponsDisplay.GetHeight(), 0)
	
	# Reposition weapons control.
	#pTacWeaponsCtrl.AlignTo(pWeaponsDisplay, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_BR, 0)
	pTacWeaponsCtrl.SetPosition(pWeaponsDisplay.GetLeft() - pTacWeaponsCtrl.GetWidth(), 1.0 - pTacWeaponsCtrl.GetHeight(), 0)

	# Reposition player's ship display
	#pShipDisplay.AlignTo(pTacWeaponsCtrl, App.TGUIObject.ALIGN_BL, App.TGUIObject.ALIGN_BR, 0)
	pShipDisplay.SetPosition(pTacWeaponsCtrl.GetLeft() - pShipDisplay.GetWidth(), 1.0 - pShipDisplay.GetHeight(), 0)

	# Reposition the orders status display.
	pOrdersStatusPane.SetPosition(LCARS.SCREEN_WIDTH - pOrdersStatusPane.GetWidth(), 0.0, 0)
	#pOrdersStatusPane.AlignTo(pShipDisplayPane, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_BL, 0)

	pTacCtrlWindow.Layout()

###############################################################################
#	SetupBridgeHelm()
#	
#	Sets up the control window for having the helm menu open on the bridge.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupBridgeHelm():
	HideTacticalMenu()
	ResizeBridgeHelm()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Helm"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(0)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()
	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0
	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	ResizeUI()
	RepositionUI()

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
	pEnemyShipDisplay.SetMinimizable(1)
	pRadarDisplay.SetMinimizable(1)

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)

###############################################################################
#	SetupBridgeTactical()
#	
#	Sets up the control window for having the tactical menu open on the bridge.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupBridgeTactical():
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMode = App.GraphicsModeInfo_GetCurrentMode()

	# Update the status of mouse pick fire (manual aim).
	import Bridge.TacticalMenuHandlers
	Bridge.TacticalMenuHandlers.UpdateManualAim()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Tactical"))
	pPane = pTCW.GetMenuParentPane(pDatabase.GetString("Tactical"))
	if (pPane != None):
		pPane.SetVisible(0)
		pMenu.ForceUpdate(0)
#	else:
#		debug("couldn't find tactical pane")

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 122
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(1)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()
	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0
	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 1

	pOrders = App.STStylizedWindow_Cast(Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetConceptualParent())
	pTactics = App.STStylizedWindow_Cast(Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.GetConceptualParent())
	pManeuvers = App.STStylizedWindow_Cast(Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.GetConceptualParent())
	pOrders.SetVisible(0)
	pTactics.SetVisible(0)
	pManeuvers.SetVisible(0)

	pOrders.SetUseFocusGlass(1)
	pTactics.SetUseFocusGlass(1)
	pManeuvers.SetUseFocusGlass(1)

	App.STStylizedWindow_Cast(pTCW.GetTargetMenu().GetConceptualParent()).SetUseFocusGlass(1)

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
	pEnemyShipDisplay.SetMinimizable(1)
	pRadarDisplay.SetMinimizable(1)

	# If we're in 640x480, depending on the state of the windows, enable or disable 
	# minimization.
	if pMode.GetWidth() == 640:
		if pRadarDisplay.IsMinimized() == 0:
			# Enemy ship display must be set not minimizable.
			pEnemyShipDisplay.SetMinimized(0)
			pEnemyShipDisplay.SetMinimizable(0)
		else:
			pEnemyShipDisplay.SetMinimizable(1)

			if pEnemyShipDisplay.IsMinimized() == 0:
				pRadarDisplay.SetMinimized(0)
				pRadarDisplay.SetMinimizable(0)
			else:
				pRadarDisplay.SetMinimizable(1)

	ResizeBridgeTactical()

	ResizeUI()
	RepositionUI()

	App.g_kLocalizationManager.Unload(pDatabase)

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)
	App.g_kFocusManager.AddObjectToTabOrder(Bridge.TacticalMenuHandlers.g_pOrdersStatusUI)
	App.g_kFocusManager.AddObjectToTabOrder(Bridge.TacticalMenuHandlers.g_pManeuversStatusUIMenu)
	App.g_kFocusManager.AddObjectToTabOrder(Bridge.TacticalMenuHandlers.g_pTacticsStatusUIMenu)
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetTargetMenu())
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetWeaponsControl())

###############################################################################
#	SetupBridgeXO()
#	
#	Sets up the control window for having the XO's menu open on the bridge.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupBridgeXO():
	HideTacticalMenu()
	ResizeBridgeXO()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Commander"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(0)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()
	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0
	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	ResizeUI()
	RepositionUI()

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
	pEnemyShipDisplay.SetMinimizable(1)
	pRadarDisplay.SetMinimizable(1)

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)

###############################################################################
#	SetupBridgeScience()
#	
#	Sets up the control window for having the science menu open on the bridge.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupBridgeScience():
	HideTacticalMenu()
	ResizeBridgeScience()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Science"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(0)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()
	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0
	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	ResizeUI()
	RepositionUI()

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
	pEnemyShipDisplay.SetMinimizable(1)
	pRadarDisplay.SetMinimizable(1)

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)

###############################################################################
#	SetupBridgeEngineer()
#	
#	Sets up the control window for having the engineering menu open on the 
#	bridge.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupBridgeEngineer():
	HideTacticalMenu()
	ResizeBridgeEngineer()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Engineer"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 123
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(1)

	pPower = App.STStylizedWindow_Cast(pWindow.GetParent().GetNextChild(pWindow))
	if pPower:
		pPower.SetUseFocusGlass(1)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()
	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0
	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	ResizeUI()
	RepositionUI()

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
	pEnemyShipDisplay.SetMinimizable(1)
	pRadarDisplay.SetMinimizable(1)

	# Need to explicitly call Layout() on this so it will resize to its
	# newly resized parents.
	App.EngRepairPane_GetRepairPane().Layout()

	# Force an update of the power display, to avoid flashing.
	import Bridge.PowerDisplay
	Bridge.PowerDisplay.Update(1)

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)
	App.g_kFocusManager.AddObjectToTabOrder(App.EngPowerCtrl_GetPowerCtrl())

###############################################################################
#	SetupBridgeGuest()
#	
#	Sets up the control window for having the guest menu open on the bridge.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupBridgeGuest():
	HideTacticalMenu()
	ResizeBridgeGuest()

	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")

	# Find one of our guests
	pCharacter = App.CharacterClass_GetObject(pBridge, "Picard")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Data")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Saalek")

	if pCharacter:
		pMenu = pCharacter.GetMenu()
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

		import StylizedWindow
		StylizedWindow.g_iAlternateGlass = 121
		pWindow = pMenu.GetContainingWindow()
		pWindow.SetUseFocusGlass(0)

		global g_idMenuIsUp
		g_idMenuIsUp = pMenu.GetObjID()
		global g_bIsInTacticalEngineering
		g_bIsInTacticalEngineering = 0
		global g_bIsInBridgeTactical
		g_bIsInBridgeTactical = 0
	else:
		global g_idMenuIsUp
		g_idMenuIsUp = App.NULL_ID
		global g_bIsInTacticalEngineering
		g_bIsInTacticalEngineering = 0
		global g_bIsInBridgeTactical
		g_bIsInBridgeTactical = 0

	ResizeUI()
	RepositionUI()

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
	pEnemyShipDisplay.SetMinimizable(1)
	pRadarDisplay.SetMinimizable(1)

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)

###############################################################################
#	SetupBridgeNone()
#	
#	Sets up the control window for having nobody's menu open on the bridge.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupBridgeNone():
	HideTacticalMenu()
	ResizeBridgeNone()

	global g_idMenuIsUp
	g_idMenuIsUp = App.NULL_ID
	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0
	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121

	ResizeUI()
	RepositionUI()

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	if pTCW:
		pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
		pRadarDisplay = pTCW.GetRadarDisplay()
		pEnemyShipDisplay.SetMinimizable(1)
		pRadarDisplay.SetMinimizable(1)

		App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)

###############################################################################
#	SetupTacticalHelm()
#	
#	Sets up the control window for having the helm menu open in tactical.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupTacticalHelm():
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()

	ResizeTacticalHelm()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Helm"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(1)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()

	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0

	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.GetConceptualParent().SetNotVisible(0)

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()

	# We need to minimize windows here if we're in a low resolution.
	global g_lMinimizedWindows
	if (pEnemyShipDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pEnemyShipDisplay.GetObjID())
	if (pRadarDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pRadarDisplay.GetObjID())

	if (pGraphicsMode.GetWidth() < 1024):
		global g_lMinimizedWindows
		if (pEnemyShipDisplay.IsMinimized() == 0):
			pEnemyShipDisplay.SetMinimized(0)

		if (pRadarDisplay.IsMinimized() == 0) and (pGraphicsMode.GetWidth() == 640):
			pRadarDisplay.SetMinimized(0)

		pEnemyShipDisplay.SetMinimizable(0)
		if (pGraphicsMode.GetWidth() == 640):
			pRadarDisplay.SetMinimizable(0)
		else:
			pRadarDisplay.SetMinimizable(1)
	else:
		pEnemyShipDisplay.SetMinimizable(1)
		pRadarDisplay.SetMinimizable(1)

	ResizeUI()
	RepositionUI()

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetTargetMenu())
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetWeaponsControl())

###############################################################################
#	SetupTacticalTactical()
#	
#	Sets up the control window for having the tactical menu open in tactical.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupTacticalTactical():
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Tactical"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(1)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()

	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0

	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	pOrders = App.STStylizedWindow_Cast(Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetConceptualParent())
	pTactics = App.STStylizedWindow_Cast(Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.GetConceptualParent())
	pManeuvers = App.STStylizedWindow_Cast(Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.GetConceptualParent())
	pOrders.SetVisible(0)
	pTactics.SetVisible(0)
	pManeuvers.SetVisible(0)

	pOrders.SetUseFocusGlass(1)
	pTactics.SetUseFocusGlass(1)
	pManeuvers.SetUseFocusGlass(1)

	App.STStylizedWindow_Cast(pTCW.GetTargetMenu().GetConceptualParent()).SetUseFocusGlass(1)

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()

	# We need to minimize windows here if we're in a low resolution.
	global g_lMinimizedWindows

	if (pEnemyShipDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pEnemyShipDisplay.GetObjID())
	if (pRadarDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pRadarDisplay.GetObjID())

	# If we're in 640x480, depending on the state of the windows, enable or disable 
	# minimization.
	if pGraphicsMode.GetWidth() == 640:
		if pRadarDisplay.IsMinimized() == 0:
			# Enemy ship display must be set not minimizable.
			pEnemyShipDisplay.SetMinimized(0)
			pEnemyShipDisplay.SetMinimizable(0)
		else:
			pEnemyShipDisplay.SetMinimizable(1)

			if pEnemyShipDisplay.IsMinimized() == 0:
				pRadarDisplay.SetMinimized(0)
				pRadarDisplay.SetMinimizable(0)
			else:
				pRadarDisplay.SetMinimizable(1)

	ResizeUI()
	RepositionUI()

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)
	App.g_kFocusManager.AddObjectToTabOrder(Bridge.TacticalMenuHandlers.g_pOrdersStatusUI)
	App.g_kFocusManager.AddObjectToTabOrder(Bridge.TacticalMenuHandlers.g_pManeuversStatusUIMenu)
	App.g_kFocusManager.AddObjectToTabOrder(Bridge.TacticalMenuHandlers.g_pTacticsStatusUIMenu)
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetTargetMenu())
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetWeaponsControl())

###############################################################################
#	SetupTacticalXO()
#	
#	Sets up the control window for having the XO's menu open in tactical.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupTacticalXO():
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	ResizeTacticalXO()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Commander"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(1)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()

	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0

	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.GetConceptualParent().SetNotVisible(0)

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
		
	# We need to minimize windows here if we're in a low resolution.
	global g_lMinimizedWindows
	if (pEnemyShipDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pEnemyShipDisplay.GetObjID())
	if (pRadarDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pRadarDisplay.GetObjID())

	if (pGraphicsMode.GetWidth() < 1024):
		if (pEnemyShipDisplay.IsMinimized() == 0):
			pEnemyShipDisplay.SetMinimized(0)

		if (pRadarDisplay.IsMinimized() == 0) and (pGraphicsMode.GetWidth() == 640):
			pRadarDisplay.SetMinimized(0)

		pEnemyShipDisplay.SetMinimizable(0)
		if (pGraphicsMode.GetWidth() == 640):
			pRadarDisplay.SetMinimizable(0)
		else:
			pRadarDisplay.SetMinimizable(1)
	else:
		pEnemyShipDisplay.SetMinimizable(1)
		pRadarDisplay.SetMinimizable(1)

	ResizeUI()
	RepositionUI()

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetTargetMenu())
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetWeaponsControl())

###############################################################################
#	SetupTacticalScience()
#	
#	Sets up the control window for having the science menu open in tactical.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupTacticalScience():
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	ResizeTacticalScience()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Science"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(1)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()

	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0

	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.GetConceptualParent().SetNotVisible(0)

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()

	# We need to minimize windows here if we're in a low resolution.
	global g_lMinimizedWindows
	if (pEnemyShipDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pEnemyShipDisplay.GetObjID())
	if (pRadarDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pRadarDisplay.GetObjID())

	if (pGraphicsMode.GetWidth() < 1024):
		if (pEnemyShipDisplay.IsMinimized() == 0):
			pEnemyShipDisplay.SetMinimized(0)

		if (pRadarDisplay.IsMinimized() == 0) and (pGraphicsMode.GetWidth() == 640):
			pRadarDisplay.SetMinimized(0)

		pEnemyShipDisplay.SetMinimizable(0)
		if (pGraphicsMode.GetWidth() == 640):
			pRadarDisplay.SetMinimizable(0)
		else:
			pRadarDisplay.SetMinimizable(1)
	else:
		pEnemyShipDisplay.SetMinimizable(1)
		pRadarDisplay.SetMinimizable(1)

	ResizeUI()
	RepositionUI()

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetTargetMenu())
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetWeaponsControl())

###############################################################################
#	SetupTacticalEngineer()
#	
#	Sets up the control window for having the engineering menu open in tactical.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupTacticalEngineer():
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTCW.FindMenu(pDatabase.GetString("Engineer"))
	App.g_kLocalizationManager.Unload(pDatabase)

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121
	pWindow = pMenu.GetContainingWindow()
	pWindow.SetUseFocusGlass(1)

	pPower = App.STStylizedWindow_Cast(pWindow.GetParent().GetNextChild(pWindow))
	if pPower:
		pPower.SetUseFocusGlass(1)

	global g_idMenuIsUp
	g_idMenuIsUp = pMenu.GetObjID()

	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 1

	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	import Bridge.TacticalMenuHandlers

	Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.GetConceptualParent().SetNotVisible(0)

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
	pTargetMenu = pTCW.GetTacticalMenu()
	pTargetWindow = App.STStylizedWindow_Cast(pTargetMenu.GetConceptualParent())

	# We need to minimize windows here if we're in a low resolution.
	global g_lMinimizedWindows
	if (pEnemyShipDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pEnemyShipDisplay.GetObjID())
	if (pRadarDisplay.IsMinimized() == 1):
		g_lMinimizedWindows.append(pRadarDisplay.GetObjID())

	if (pGraphicsMode.GetWidth() < 1024):
		if (pEnemyShipDisplay.IsMinimized() == 0):
			pEnemyShipDisplay.SetMinimized(0)

		if (pRadarDisplay.IsMinimized() == 0):
			pRadarDisplay.SetMinimized(0)

		pEnemyShipDisplay.SetMinimizable(0)
		pRadarDisplay.SetMinimizable(0)
	else:
		pEnemyShipDisplay.SetMinimizable(1)
		pRadarDisplay.SetMinimizable(1)

	ResizeTacticalEngineer()

	ResizeUI()
	RepositionUI()

	# Need to explicitly call Layout() on this so it will resize to its
	# newly resized parents.
	App.EngRepairPane_GetRepairPane().Layout()

	# Force an update of the power display, to avoid flashing.
	import Bridge.PowerDisplay
	Bridge.PowerDisplay.Update(1)

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pMenu)
	App.g_kFocusManager.AddObjectToTabOrder(App.EngPowerCtrl_GetPowerCtrl())
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetTargetMenu())
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetWeaponsControl())

###############################################################################
#	SetupTacticalGuest()
#	
#	Sets up the control window for having the guest menu open in tactical.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupTacticalGuest():
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	ResizeTacticalGuest()

	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")
	if not pBridge:
		return

	# Find one of our guests
	pCharacter = App.CharacterClass_GetObject(pBridge, "Picard")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Data")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Saalek")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Guest")

	if pCharacter:
		pMenu = pCharacter.GetMenu()

		import StylizedWindow
		StylizedWindow.g_iAlternateGlass = 121
		pWindow = pMenu.GetContainingWindow()
		pWindow.SetUseFocusGlass(1)

		global g_idMenuIsUp
		g_idMenuIsUp = pMenu.GetObjID()

		global g_bIsInTacticalEngineering
		g_bIsInTacticalEngineering = 0

		global g_bIsInBridgeTactical
		g_bIsInBridgeTactical = 0

		Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetConceptualParent().SetNotVisible(0)
		Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.GetConceptualParent().SetNotVisible(0)
		Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.GetConceptualParent().SetNotVisible(0)

		pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
		pRadarDisplay = pTCW.GetRadarDisplay()

		# We need to minimize windows here if we're in a low resolution.
		global g_lMinimizedWindows
		if (pEnemyShipDisplay.IsMinimized() == 1):
			g_lMinimizedWindows.append(pEnemyShipDisplay.GetObjID())
		if (pRadarDisplay.IsMinimized() == 1):
			g_lMinimizedWindows.append(pRadarDisplay.GetObjID())

		if (pGraphicsMode.GetWidth() < 1024):
			if (pEnemyShipDisplay.IsMinimized() == 0):
				pEnemyShipDisplay.SetMinimized(0)

			if (pRadarDisplay.IsMinimized() == 0) and (pGraphicsMode.GetWidth() == 640):
				pRadarDisplay.SetMinimized(0)

			pEnemyShipDisplay.SetMinimizable(0)
			if (pGraphicsMode.GetWidth() == 640):
				pRadarDisplay.SetMinimizable(0)
			else:
				pRadarDisplay.SetMinimizable(1)
		else:
			pEnemyShipDisplay.SetMinimizable(1)
			pRadarDisplay.SetMinimizable(1)

		ResizeUI()
		RepositionUI()

		App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
		App.g_kFocusManager.AddObjectToTabOrder(pMenu)
		App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetTargetMenu())
		App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetWeaponsControl())

###############################################################################
#	SetupTacticalNone()
#	
#	Sets up the control window for having nobody's menu open in tactical.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupTacticalNone():
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()

	ResizeTacticalNone()

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalMenu = pTCW.GetTacticalMenu()
	pTacticalMenu.SetNotVisible(0)
	pTacticalMenu.GetConceptualParent().SetNotVisible()

	global g_idMenuIsUp
	g_idMenuIsUp = App.NULL_ID

	global g_bIsInTacticalEngineering
	g_bIsInTacticalEngineering = 0

	global g_bIsInBridgeTactical
	g_bIsInBridgeTactical = 0

	import StylizedWindow
	StylizedWindow.g_iAlternateGlass = 121

	Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.GetConceptualParent().SetNotVisible(0)
	Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.GetConceptualParent().SetNotVisible(0)

	pEnemyShipDisplay = pTCW.GetEnemyShipDisplay()
	pRadarDisplay = pTCW.GetRadarDisplay()
		
	# We need to unminimize windows here if we're in a low resolution.
	if (pGraphicsMode.GetWidth() < 1024):
		pEnemyShipDisplay.SetMinimizable(1)
		pRadarDisplay.SetMinimizable(1)

		if pEnemyShipDisplay.GetObjID() not in g_lMinimizedWindows:
			pEnemyShipDisplay.SetNotMinimized(0)
		if pRadarDisplay.GetObjID() not in g_lMinimizedWindows:
			pRadarDisplay.SetNotMinimized(0)
	else:
		pEnemyShipDisplay.SetMinimizable(1)
		pRadarDisplay.SetMinimizable(1)

	ResizeUI()
	RepositionUI()

	App.g_kFocusManager.RemoveAllObjectsUnder(pTCW)
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetTargetMenu())
	App.g_kFocusManager.AddObjectToTabOrder(pTCW.GetWeaponsControl())

###############################################################################
#	HideTacticalMenu()
#	
#	Hides the tactical menu.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def HideTacticalMenu():
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Tactical"))
	pPane = pTCW.GetMenuParentPane(pDatabase.GetString("Tactical"))
	if (pPane != None):
		pPane.SetNotVisible(0)
		pMenu.SetNotVisible(0)
	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	Resize*()
#	
#	Functions that resize the menus for the various modes.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def ResizeBridgeHelm():
	# Resize the helm menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Helm"))
	pPane = App.STStylizedWindow_Cast(pTCW.GetMenuParentPane(pDatabase.GetString("Helm")))
	if (pPane != None):
		# Undo fixed size setting.
		pPane.SetFixedSize(0.0, 0.0, 0)
		pPane.SetMaximumSize(0.3, 1.0 - pPane.GetTop())
		#pPane.Resize(0.3, pPane.GetMaximumHeight(), 0)
		pMenu.Resize(pPane.GetMaximumInteriorWidth(), pMenu.GetDesiredHeight(), 0)
		pMenu.ForceUpdate(0)
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find helm pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeBridgeTactical():
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Resize the tactical menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.GetTacticalMenu()
	pPane = App.STStylizedWindow_Cast(pMenu.GetConceptualParent())
	if (pPane != None):
		# Undo fixed size setting.
		pPane.SetFixedSize(0.0, 0.0, 0)
		pPane.SetMaximumSize(LCARS.TACTICAL_MENU_WIDTH + pPane.GetBorderWidth(), LCARS.TACTICAL_MENU_HEIGHT + pPane.GetBorderHeight())
		pMenu.ForceUpdate(0)
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find tactical pane")

	App.g_kLocalizationManager.Unload(pDatabase)


def ResizeBridgeXO():
	# Resize the XO menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Commander"))
	pPane = App.STStylizedWindow_Cast(pTCW.GetMenuParentPane(pDatabase.GetString("Commander")))
	if (pPane != None):
		# Undo fixed size setting.
		pPane.SetFixedSize(0.0, 0.0, 0)
		pPane.SetMaximumSize(0.3, 0.6)
		pPane.Resize(0.3, pPane.GetMaximumHeight(), 0)
		pMenu.Resize(pPane.GetMaximumWidth(), pMenu.GetDesiredHeight(), 0)
		pMenu.ForceUpdate(0)
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find XO pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeBridgeScience():
	# Resize the science menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Science"))
	pPane = App.STStylizedWindow_Cast(pTCW.GetMenuParentPane(pDatabase.GetString("Science")))
	if (pPane != None):
		# Undo fixed size setting.
		pPane.SetFixedSize(0.0, 0.0, 0)
		pPane.SetMaximumSize(0.3, 1.0 - pPane.GetTop())
		pMenu.Resize(pPane.GetMaximumInteriorWidth(), pMenu.GetDesiredHeight(), 0)
		pMenu.ForceUpdate(0)
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find science pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeBridgeEngineer():
	# Resize the engineering menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Engineering"))
	pPane = App.STStylizedWindow_Cast(App.TGPane_Cast(pMenu.GetConceptualParent()))
	pDisplayPane = pPane.GetParent()
	if (pPane != None):
		# Undo fixed size setting in tactical engineering.
		pPane.SetFixedSize(0.0, 0.0, 0)
		pPane.SetMaximumSize(0.3, 1.0 - pPane.GetTop())
		pDisplayPane.Resize(pDisplayPane.GetWidth(), 1.0, 0)
		pMenu.Resize(pPane.GetMaximumWidth(), pMenu.GetHeight())
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find engineer pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeBridgeGuest():
	# Resize the guest menu.
	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	if not pBridge:
		return

	# Find one of our guests
	pCharacter = App.CharacterClass_GetObject(pBridge, "Picard")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Data")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Saalek")

	if pCharacter:
		pMenu = pCharacter.GetMenu()

		if not pMenu:
			return

		pPane = pMenu.GetContainingWindow()
		if (pPane != None):
			# Undo fixed size setting.
			pPane.SetFixedSize(0.0, 0.0, 0)
			pPane.SetMaximumSize(0.3, 1.0 - pPane.GetTop())
			pMenu.Resize(pPane.GetMaximumInteriorWidth(), pMenu.GetDesiredHeight(), 0)
			pMenu.ForceUpdate(0)
			pPane.InteriorChangedSize()
#		else:
#			debug("couldn't find guest pane")

def ResizeBridgeNone():
	pass

def ResizeTacticalHelm():
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Resize the helm menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Helm"))
	pPane = App.STStylizedWindow_Cast(pTCW.GetMenuParentPane(pDatabase.GetString("Helm")))
	if (pPane != None):
		pPane.SetFixedSize(LCARS.TACTICAL_MENU_WIDTH + pPane.GetBorderWidth(), LCARS.TACTICAL_MENU_HEIGHT)
		pMenu.ResizeToContents()
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find helm pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeTacticalTactical():
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Resize the tactical menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.GetTacticalMenu()
	pPane = App.STStylizedWindow_Cast(pMenu.GetConceptualParent())
	if (pPane != None):
		pPane.SetMaximumSize(LCARS.TACTICAL_MENU_WIDTH + pPane.GetBorderWidth(), LCARS.TACTICAL_MENU_HEIGHT + pPane.GetBorderHeight())
		pMenu.ForceUpdate(0)
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find tactical pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeTacticalXO():
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Resize the XO menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Commander"))
	pPane = App.STStylizedWindow_Cast(pTCW.GetMenuParentPane(pDatabase.GetString("Commander")))
	if (pPane != None):
		pPane.SetFixedSize(LCARS.TACTICAL_MENU_WIDTH + pPane.GetBorderWidth(), LCARS.TACTICAL_MENU_HEIGHT)
		pMenu.ResizeToContents()
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find XO pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeTacticalScience():
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Resize the science menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTCW.FindMenu(pDatabase.GetString("Science"))
	pPane = App.STStylizedWindow_Cast(pTCW.GetMenuParentPane(pDatabase.GetString("Science")))
	if (pPane != None):
		pPane.SetFixedSize(LCARS.TACTICAL_MENU_WIDTH + pPane.GetBorderWidth(), LCARS.TACTICAL_MENU_HEIGHT)
		pMenu.ResizeToContents()
		pPane.InteriorChangedSize()
#	else:
#		debug("couldn't find science pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeTacticalEngineer():
	# Get string for LCARS icon group.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Resize the engineering menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTop = App.TopWindow_GetTopWindow()
	pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	kInterfacePane = App.TGPane_Cast(pTacCtrlWindow.GetNthChild(INTERFACE_PANE))
	kBackgroundPane = App.TGPane_Cast(pTacCtrlWindow.GetNthChild(BACKGROUND_PANE))

	# Get children to be resized.
	pESDisplayPane = App.TGPane_Cast(kInterfacePane.GetNthChild(ENEMY_SHIP_DISPLAY))
	pRadarDisplayPane = App.STStylizedWindow_Cast(kInterfacePane.GetNthChild(RADAR_DISPLAY))

	pEnemyShipDisplay = pTacCtrlWindow.GetEnemyShipDisplay()
	pRadarDisplay = pTacCtrlWindow.GetRadarDisplay()
	pTargetMenu = pTacCtrlWindow.GetTargetMenu()
	pTargetWindow = App.STStylizedWindow_Cast(pTargetMenu.GetConceptualParent())

	pMenu = pTacCtrlWindow.FindMenu(pDatabase.GetString("Engineering"))
	pPane = App.STStylizedWindow_Cast(pMenu.GetConceptualParent())
	pDisplayPane = pPane.GetParent()		# contains power/menu panes
	if (pPane != None):
		fHeight = (LCARS.SCREEN_HEIGHT - pRadarDisplayPane.GetHeight() - 
				   pEnemyShipDisplay.GetHeight() - pTargetWindow.GetHeight() - 
				   (3.0 * App.globals.DEFAULT_ST_INDENT_VERT))

		fHeight = max(fHeight, 0.35)

		pPane.SetFixedSize(LCARS.TACTICAL_MENU_WIDTH + pPane.GetBorderWidth(), fHeight, 0)
		pMenu.Resize(LCARS.TACTICAL_MENU_WIDTH, pMenu.GetHeight(), 0)
		pMenu.ResizeToContents()
		pPane.InteriorChangedSize()
		pDisplayPane.Resize(pDisplayPane.GetWidth(), 1.0, 0)
#	else:
#		debug("couldn't find engineer pane")

	App.g_kLocalizationManager.Unload(pDatabase)

def ResizeTacticalGuest():
	# Resize the guest menu.
	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	if not pBridge:
		return

	# Find one of our guests
	pCharacter = App.CharacterClass_GetObject(pBridge, "Picard")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Data")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Saalek")

	if pCharacter:
		pMenu = pCharacter.GetMenu()

		if not pMenu:
			return

		# Get string for LCARS icon group.
		LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

		# Resize the guest menu.
		pPane = pMenu.GetContainingWindow()
		if (pPane != None):
			pPane.SetFixedSize(LCARS.TACTICAL_MENU_WIDTH + pPane.GetBorderWidth(), LCARS.TACTICAL_MENU_HEIGHT)
			pMenu.ResizeToContents()
			pPane.InteriorChangedSize()
#		else:
#			debug("couldn't find guest pane")

def ResizeTacticalNone():
	pass

	# Get the character name from the character, or in the case of multiplayer
	# from the menu.
def GetTacticalControlWindowCharacterName ():
	pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalMenu = pTacCtrlWindow.GetTacticalMenu()
	pTop = App.TopWindow_GetTopWindow()
	pMenu = pTacCtrlWindow.GetOpenMenu()

	if (pMenu == None):
		if (pTacticalMenu.IsVisible()):
			pMenu = App.STTopLevelMenu_Cast(pTacticalMenu)

	pCharacter = App.CharacterClass_GetCharacterFromMenu(pMenu)

	pcCharacterName = "None"

	if (pCharacter != None):
		pcCharacterName = pCharacter.GetName()
	else:
		# get the name from the menu
		if (pMenu):
			kMenuTitle = pMenu.GetText ()
			kMenuString = App.TGString ()
			kMenuTitle.GetString (kMenuString)

			pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

			kEngineer = pDatabase.GetString ("Engineering")
			if (kEngineer.Compare (kMenuString) == 0):	# Match found
				pcCharacterName = "Engineer"		
			else:
				kTactical = pDatabase.GetString ("Tactical")
				if (kTactical.Compare (kMenuString) == 0):	# Match found
					pcCharacterName = "Tactical"		
				else:
					kHelm = pDatabase.GetString ("Helm")
					if (kHelm.Compare (kMenuString) == 0):	# Match found
						pcCharacterName = "Helm"		
					else:
						kXO = pDatabase.GetString ("Commander")
						if (kXO.Compare (kMenuString) == 0):	# Match found
							pcCharacterName = "XO"		
						else:
							kScience = pDatabase.GetString ("Science")
							if (kScience.Compare (kMenuString) == 0):	# Match found
								pcCharacterName = "Science"		

			App.g_kLocalizationManager.Unload(pDatabase)


	return pcCharacterName
