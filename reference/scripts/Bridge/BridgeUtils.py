###############################################################################
#	Filename:	BridgeUtils.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Utility functions for bridge scripts.
#	
#	Created:	12/18/2000 -	Erik Novales
###############################################################################

import App
import MissionLib

# Get LCARS string.
pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()

g_bInterceptEnabled = 1
g_bAutoManageProbeButton = 1
g_iScanDisabledCount = 0
g_iScanAreaDisabledCount = 0
g_iScanTargetDisabledCount = 0
g_iScanObjectDisabledCount = 0

###############################################################################
#	CreateBridgeMenuButton(pName, eType, iSubType, pCharacter)
#	
#	Create bridge menu button given name, event type, subtype, and character
#	to send this event to.
#
#	Args:	pName - name of the button
#			eType - event type for button press
#			iSubType - subtype for the event
#			pDest - destination to which we'll send the event
#	
#	Return:	BridgeMenuButton - the newly-created button
###############################################################################
def CreateBridgeMenuButton(pName, eType, iSubType, pDest):
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pDest)
	pEvent.SetInt(iSubType)
	BridgeMenuButton = App.STButton_CreateW(pName, pEvent)
	return BridgeMenuButton

###############################################################################
#	CreateMenuToggleButton()
#
#	Create menu toggle button.
#
#	Args:	pName		- Text for button.
#			pNameOn		- Text for button ON state.
#			pNameOff 	- Text for button OFF state.
#			eType 		- Event type button will trigger.
#			iDefault 	- Default button state.
#			pCharacter 	- Character, destination for button event.
#
#	Return:	none
###############################################################################
def CreateMenuToggleButton(pName, pNameOn, pNameOff, eType, iDefault, pCharacter):
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pOnEvent = None
	pOffEvent = None
	if eType is not None:
		pOnEvent = App.TGBoolEvent_Create()
		pOnEvent.SetEventType(eType)
		pOnEvent.SetDestination(pCharacter)
		pOnEvent.SetBool(1)

		pOffEvent = App.TGBoolEvent_Create()
		pOffEvent.SetEventType(eType)
		pOffEvent.SetDestination(pCharacter)
		pOffEvent.SetBool(0)

	pMenuButton = App.STToggle_CreateW(pName, iDefault, pNameOn, pOnEvent,
										pNameOff, pOffEvent)
	if pOnEvent and pOffEvent:
		pOnEvent.SetSource(pMenuButton)
		pOffEvent.SetSource(pMenuButton)

	return pMenuButton

###############################################################################
#	CreateCommandButton()
#
# 	Create command button given icon ID and event type.
#
#	Args:	IconID 		- ID of icon to use for button.
#			EventType 	- Event type button will trigger.
#
#	Return:	none
###############################################################################
def CreateCommandButton(IconID, EventType):
	pTopWindow = App.TopWindow_GetTopWindow()
	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(EventType)
	pEvent.SetDestination(pTopWindow)

	CommandButton = App.TGButton_Create(pcLCARS, IconID)
	CommandButton.SetActivationEvent(pEvent)
	return CommandButton

###############################################################################
#	CreateToggleButtonEvent()
#
# 	Create toggle button event given event type.
#
#	Args:	EventType - Event type to assign to event.
#
#	Return:	none
###############################################################################
def CreateToggleButtonEvent(EventType):
	pTopWindow = App.TopWindow_GetTopWindow()
	pMainTacticalWindow = pTopWindow.FindMainWindow(App.MWT_TACTICAL)
	pTacticalWindow = App.TacticalWindow_Cast(pMainTacticalWindow)
	pWeaponsControlParent = pTacticalWindow.GetWeaponsControlParent()
	pWeaponsControl = pWeaponsControlParent.GetFirstChild()
	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(EventType)
	pEvent.SetDestination(pWeaponsControl)
	return pEvent

###############################################################################
#	CreateTripleToggle(pName, pNameOne, pNameTwo, pNameThree, eType, 
#					   iDefault, pCharacter)
#	
#	Creates a three-state toggle for use in bridge menus.
#	
#	Args:	pName		- name of the toggle
#			pNameOne	- first state's name
#			pNameTwo	- second state's name
#			pNameThree	- third state's name
#			eType		- event type to send
#			iDefault	- default state
#			pCharacter	- character to which we'll send the event
#	
#	Return:	STToggle * - the new toggle
###############################################################################
def CreateTripleToggle(pName, pNameOne, pNameTwo, pNameThree, eType, iDefault, pCharacter):
	pOneEvent = App.TGIntEvent_Create()
	pOneEvent.SetEventType(eType)
	pOneEvent.SetDestination(pCharacter)
	pOneEvent.SetInt(0)

	pTwoEvent = App.TGIntEvent_Create()
	pTwoEvent.SetEventType(eType)
	pTwoEvent.SetDestination(pCharacter)
	pTwoEvent.SetInt(1)

	pThreeEvent = App.TGIntEvent_Create()
	pThreeEvent.SetEventType(eType)
	pThreeEvent.SetDestination(pCharacter)
	pThreeEvent.SetInt(2)

	pMenuButton = App.STToggle_CreateW(pName, iDefault, pNameOne, pOneEvent,
										pNameTwo, pTwoEvent,
										pNameThree, pThreeEvent)

	pOneEvent.SetSource(pMenuButton)
	pTwoEvent.SetSource(pMenuButton)
	pThreeEvent.SetSource(pMenuButton)

	return pMenuButton

###############################################################################
#	GetDockButton()
#	
#	Get "Dock" button from Helm's menu. 
#	
#	Args:	none
#	
#	Return:	pButton, dock button, None if not found.
###############################################################################
def GetDockButton():
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return None

	# Get Helm.
	pHelm = GetBridgeCharacter("Helm")
	if(pHelm is None):
		return

	# Get Helm menu.
	pHelmMenu = pHelm.GetMenu()
	if(pHelmMenu is None):
		return
	
	# Try to get button, returns None if not found.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pButton = pHelmMenu.GetButtonW(pDatabase.GetString("Dock"))
	if(pButton):
		App.g_kLocalizationManager.Unload(pDatabase)
		return pButton
	else:
		pButton =  pHelmMenu.GetButtonW(pDatabase.GetString("Undock"))
		App.g_kLocalizationManager.Unload(pDatabase)
		return pButton

###############################################################################
#	UpdateDockButton()
#	
#	Update "Dock"/"Undock" button in Helm's menu based on Player's docked state.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def UpdateDockButton():
	# Get Player
	pPlayer = MissionLib.GetPlayer()
	if(pPlayer is None):
		return

	# Get bridge.
	pBridge = GetBridge()
	if(pBridge is None):
		return

	# Get Helm.
	pHelm = GetBridgeCharacter("Helm")
	if(pHelm is None):
		return

	# Get Helm menu.
	pHelmMenu = pHelm.GetMenu()
	if(pHelmMenu is None):
		return

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Get dock/undock button.
	pButton = GetDockButton()
	if(pButton is None):
		App.g_kLocalizationManager.Unload(pDatabase)
#		print "BridgeUtils.py, UpdateDockButton() unable to get Dock button.\n"
		return

	# Toggle button text, get old button and change it based on new state. 
	if(pPlayer.IsDocked()):
		pButton.SetName(pDatabase.GetString("Undock"))
	else:
		pButton.SetName(pDatabase.GetString("Dock"))

	pButton.SetEnabled()
	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	GetBridge()
#	
#	Get the bridge set.
#	
#	Args:	None
#	
#	Return:	pBridge, BridgeSet object.
###############################################################################
def GetBridge():
	pBridgeSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	return pBridgeSet

###############################################################################
#	GetBridgeCharacter(pcStationName)
#	
#	Get a bridge character given station name string.
#	
#	Args:	pcCharacter
#	
#	Return:	pCharacter, character object if found, otherwise None.
###############################################################################
def GetBridgeCharacter(pcStationName):
	pBridge = GetBridge()

	# Get character from bridge.
	pCharacter = App.CharacterClass_GetObject(pBridge, pcStationName)
	return pCharacter

################################################################################
#	GetBridgeMenu(pcStationName)
#
#	Get a bridge characters menu given the station name string.
#
#	Args:	pcStationName	- String for the station to find.
#
#	Return:	pMenu	- Menu object for station name if found.
################################################################################
def GetBridgeMenu(pcStationName):
	# Get the character
	pCharacter = GetBridgeCharacter(pcStationName)
	
	# Get the menu for the character
	if (pCharacter != None):
		pMenu = pCharacter.GetMenu()
		if (pMenu != None):
			return pMenu
			
	# Return none if we came up empty handed.
	return None

################################################################################
#	GetBridgeMenuID(pcStationName)
#
#	Get the ID of a characters menu given the station name string.
#
#	Args:	pcStationName	- String name of the station we want the ID for.
#
#	Return:	idMenu	- the ID of the menu
################################################################################
def GetBridgeMenuID(pcStationName):
	# Get the characters menu
	pMenu = GetBridgeMenu(pcStationName)
	
	# Get the ID and return it
	if (pMenu != None):
		idMenu = pMenu.GetObjID()
		if (idMenu != None):
			return idMenu
			
	# Return none if we failed to get anything
	return None
	
###############################################################################
#	MakeCharacterLine(pChar, pcID, pDatabase, iTurnBack = 1, pcTo = "Captain")
#	
#	Create a say line character action. This line comes from the mission database.
#	
#	Args:	pChar, bridge character object.
#			pcID, string ID of line to play.
#			pDatabase, TGL database to use.
#			iTurnBack, flag for wether to turn back when done.(optional)
#			pcTo, string name of who to turn to(optional)
#	
#	Return:	pAction, character action.
###############################################################################
def MakeCharacterLine(pChar, pcID, pDatabase, iTurnBack = 1, pcTo = "Captain"):
	assert pChar
	assert pcID
	assert pDatabase
	
	pAction = App.CharacterAction_Create(pChar, App.CharacterAction.AT_SAY_LINE, 
										pcID, pcTo, iTurnBack, pDatabase)
	return pAction

###############################################################################
#	GetMainCamera()
#	
#	Get the main camera of the bridge set.
#	
#	Args:	None
#	
#	Return:	pBridgeCamera, ZoomCamera object.
###############################################################################
def GetMainCamera():
	pBridgeSet = GetBridge()
	pMainCamera = App.ZoomCameraObjectClass_GetObject(pBridgeSet, "maincamera")
	return pMainCamera

###############################################################################
#	GetWarpButton()
#	
#	Get the warp button in Helm Menu.
#	
#	Args:	none
#	
#	Return:	pWarpButton, the warp button.
###############################################################################
def GetWarpButton():
	# Get warp button.
	return App.SortedRegionMenu_GetWarpButton()

###############################################################################
#	DisableWarpButton()
#	
#	Disable warp button in Helm Menu.
#	
#	Args:	pAction
#	
#	Return:	none
###############################################################################
def DisableWarpButton(pAction = None):
	pWarpButton = GetWarpButton()
	if(pWarpButton is None):
		return 0
	
	pWarpButton.SetDisabled()

	return 0

###############################################################################
#	RestoreWarpButton(pAction)
#	
#	Checks if warp button should be enabled and enables it if so.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def RestoreWarpButton(pAction = None):
	pWarpButton = GetWarpButton()
	if(pWarpButton is None):
		return 0
	
	# Enable warp button if it has a destination.
	if(pWarpButton.GetDestination()):
		pWarpButton.SetEnabled()

	return 0

################################################################################
#	EnableScanAreaButton(pAction = None)
#
#	Enables the "Scan Area" button in Miguel's menu.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def EnableScanAreaButton(pAction = None):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	if(pDatabase is None):
		return 0

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))

	# Get the button.
	pScanArea = pScienceMenu.GetButtonW(pDatabase.GetString("Scan Area"))
	App.g_kLocalizationManager.Unload(pDatabase)
	if(pScanArea is None):
		return 0

	global g_iScanAreaDisabledCount

	if (g_iScanAreaDisabledCount > 0):
		g_iScanAreaDisabledCount = g_iScanAreaDisabledCount - 1

	# Set the button to "Enabled"
	if (g_iScanAreaDisabledCount == 0) and (g_iScanDisabledCount == 0):
		pScanArea.SetEnabled()

	return 0

################################################################################
#	DisableScanAreaButton(pAction = None)
#
#	Disables the "Scan Area" button in Miguel's menu
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def DisableScanAreaButton(pAction = None):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	if(pDatabase is None):
		return 0

	# Get the Science menu
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))

	# Get the button.
	pScanArea = pScienceMenu.GetButtonW(pDatabase.GetString("Scan Area"))
	App.g_kLocalizationManager.Unload(pDatabase)
	if(pScanArea is None):
		return 0

	global g_iScanAreaDisabledCount
	g_iScanAreaDisabledCount = g_iScanAreaDisabledCount + 1

	# Set the button to "Disabled"
	pScanArea.SetDisabled()

	return 0

################################################################################
#	EnableScanTargetButton(pAction = None)
#
#	Enables the "Scan Target" button in Miguel's menu.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def EnableScanTargetButton(pAction = None):
	global g_iScanTargetDisabledCount
	if (g_iScanTargetDisabledCount > 0):
		g_iScanTargetDisabledCount = g_iScanTargetDisabledCount - 1

	# Update the ScanTarget button based on your target
	import ScienceMenuHandlers
	ScienceMenuHandlers.TargetChanged(None, None)

	return 0

################################################################################
#	DisableScanTargetButton(pAction = None)
#
#	Disables the "Scan Target" button in Miguel's menu
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def DisableScanTargetButton(pAction = None):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	if(pDatabase is None):
		return 0

	# Get the Science menu
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))

	pScanTarget = pScienceMenu.GetButtonW(pDatabase.GetString("Scan Target"))
	App.g_kLocalizationManager.Unload(pDatabase)
	if(pScanTarget is None):
		return 0

	global g_iScanTargetDisabledCount
	g_iScanTargetDisabledCount = g_iScanTargetDisabledCount + 1
		
	# Set the button to "Disabled"
	pScanTarget.SetDisabled()

	return 0

################################################################################
#	EnableScanObjectMenu(pAction = None)
#
#	Enables the "Scan Object" menu in Miguel's menu.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def EnableScanObjectMenu(pAction = None):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	if(pDatabase is None):
		return 0

	# Get the Science menu
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))

	pScanObject = pScienceMenu.GetSubmenuW(pDatabase.GetString("Scan Object"))
	App.g_kLocalizationManager.Unload(pDatabase)
	if(pScanObject is None):
		return 0

	global g_iScanObjectDisabledCount
	if (g_iScanObjectDisabledCount > 0):
		g_iScanObjectDisabledCount = g_iScanObjectDisabledCount - 1

	# Set the button to "Enabled"
	if (g_iScanObjectDisabledCount == 0) and (g_iScanDisabledCount == 0):
		pScanObject.SetEnabled()

	return 0

################################################################################
#	DisableScanObjectMenu(pAction = None)
#
#	Disables the "Scan Object" menu in Miguel's menu
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def DisableScanObjectMenu(pAction = None):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	if(pDatabase is None):
		return 0

	# Get the Science menu
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pScienceMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))

	pScanObject = pScienceMenu.GetSubmenuW(pDatabase.GetString("Scan Object"))
	App.g_kLocalizationManager.Unload(pDatabase)
	if(pScanObject is None):
		return 0

	global g_iScanObjectDisabledCount
	g_iScanObjectDisabledCount = g_iScanObjectDisabledCount + 1

	# Set the button to "Disabled"
	pScanObject.Close()
	pScanObject.SetDisabled()

	return 0

###############################################################################
#	DisableHailMenu(pAction = None)
#	
#	Disables the Hail menu
#	
#	Args:	pAction
#	
#	Return:	none
###############################################################################
def DisableHailMenu(pAction = None):
	# Get the Helm menu
	pHelm = GetBridgeCharacter("Helm")
	if(pHelm is None):
		return 0
	pHelmMenu = pHelm.GetMenu()
	if(pHelmMenu is None):
		return 0
	
	# Get the button.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	if(pDatabase is None):
		return 0
	pHail = pHelmMenu.GetSubmenuW(pDatabase.GetString("Hail"))
	App.g_kLocalizationManager.Unload(pDatabase)
	if(pHail is None):
		return 0

	# Set the button to "Disabled"
	pHail.Close()
	pHail.SetDisabled()

	return 0

###############################################################################
#	EnableHailMenu(pAction = None)
#	
#	Enables the Hail menu
#	
#	Args:	pAction
#	
#	Return:	none
###############################################################################
def EnableHailMenu(pAction = None):
	# Get the Helm menu
	pHelm = GetBridgeCharacter("Helm")
	if(pHelm is None):
		return 0
	pHelmMenu = pHelm.GetMenu()
	if(pHelmMenu is None):
		return 0
	
	# Get the button.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	if(pDatabase is None):
		return 0
	pHail = pHelmMenu.GetSubmenuW(pDatabase.GetString("Hail"))
	App.g_kLocalizationManager.Unload(pDatabase)
	if(pHail is None):
		return 0

	# Set the button to "Enabled"
	pHail.SetEnabled()

	return 0

################################################################################
#	SetupCommunicateHandlers()
#
#	Sets up Communicate handlers for regular bridge characters.
#
#	Args:	None
#
#	Return:	None
################################################################################
def SetupCommunicateHandlers():
	pcScript = MissionLib.GetMission().GetScript()

	# Communicate with Saffi event
	pSaffi = GetBridgeCharacter("XO")
	if(pSaffi):
		pMenu = pSaffi.GetMenu()
		if(pMenu):
			pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateSaffi")

	# Communicate with Felix event
	pFelix = GetBridgeCharacter("Tactical")
	if(pFelix):
		pMenu = pFelix.GetMenu()
		if(pMenu):
			pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateFelix")

	# Communicate with Kiska event
	pKiska = GetBridgeCharacter("Helm")
	if(pKiska):
		pMenu = pKiska.GetMenu()
		if(pMenu):
			pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateKiska")

	# Communicate with Miguel event
	pMiguel = GetBridgeCharacter("Science")
	if(pMiguel):
		pMenu = pMiguel.GetMenu()
		if(pMenu):
			pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateMiguel")

	# Communicate with Brex event
	pBrex = GetBridgeCharacter("Engineer")
	if(pBrex):
		pMenu = pBrex.GetMenu()
		if(pMenu):
			pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateBrex")

################################################################################
#	RemoveCommunicateHandlers()
#
#	Removes Communicate handlers for regular bridge characters.
#
#	Args:	None
#
#	Return:	None
################################################################################
def RemoveCommunicateHandlers():
	pcScript = MissionLib.GetMission().GetScript()

	# Communicate with Saffi event
	pSaffi = GetBridgeCharacter("XO")
	if(pSaffi):
		pMenu = pSaffi.GetMenu()
		if(pMenu):
			pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateSaffi")

	# Communicate with Felix event
	pFelix = GetBridgeCharacter("Tactical")
	if(pFelix):
		pMenu = pFelix.GetMenu()
		if(pMenu):
			pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateFelix")

	# Communicate with Kiska event
	pKiska = GetBridgeCharacter("Helm")
	if(pKiska):
		pMenu = pKiska.GetMenu()
		if(pMenu):
			pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateKiska")

	# Communicate with Miguel event
	pMiguel = GetBridgeCharacter("Science")
	if(pMiguel):
		pMenu = pMiguel.GetMenu()
		if(pMenu):
			pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateMiguel")

	# Communicate with Brex event
	pBrex = GetBridgeCharacter("Engineer")
	if(pBrex):
		pMenu = pBrex.GetMenu()
		if(pMenu):
			pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
													".CommunicateBrex")

################################################################################
#	SetMenuModal(bOnOff)
#
#	Disables certain mouse/keyboard input while viewscreen character
#	menu is being shown. Prevents user from dropping menu.
#
#	Args:	bOnOff, wether it should be modal or not.
#
#	Return:	None
################################################################################
def SetMenuModal(bOnOff):
	if bOnOff:
		# Set up handler for mouse events.
		pTopWindow = App.TopWindow_GetTopWindow()
		pTopWindow.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".ModalMouseHandler")

		# Set up handler for keyboard events.
		pTopWindow.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD, __name__ + ".ModalKeyboardHandler")	
	else:
		# Remove handler for mouse events.
		pTopWindow = App.TopWindow_GetTopWindow()
		pTopWindow.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".ModalMouseHandler")

		# Remove handler for keyboard events.
		pTopWindow.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".ModalKeyboardHandler")	
	
###############################################################################
#	ModalMouseHandler()
#	
#	Intercepts mouse events when menu is up. 
#	Checks for mouse down events that are not inside the menu.
#	Passes on mouse events in menu as normal.
#
#	Args:	TGObject		pObject - TGObject
#			TGMouseEvent	pEvent	- mouse event
#	
#	Return:	none
##############################################################################
def ModalMouseHandler(pObject, pEvent):
	# If it's a button down event.
	if pEvent.IsButtonEvent() and (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
		# Get viewscreen menu.
		pViewScreen = MissionLib.GetViewScreen()
		pMenu = pViewScreen.GetMenu()
		if(pMenu is None):
			pObject.CallNextHandler(pEvent)
			return
		pMenu = pMenu.GetConceptualParent()
		if(pMenu is None):
			pObject.CallNextHandler(pEvent)
			return

		pMenu.SetAlwaysHandleEvents()

		# Get mouse click x,y.
		fXPos = pEvent.GetX()
		fYPos = pEvent.GetY()

		# Get menu's bounding rect in screen coords.
		kOffSet = App.NiPoint2(0, 0)
		pMenu.GetScreenOffset(kOffSet)
		pRect = App.TGRect(kOffSet.x, kOffSet.y, pMenu.GetWidth(), pMenu.GetHeight())

		# If mouse click within menu, pass event.
		if pRect.IsWithin(fXPos, fYPos):
			pObject.CallNextHandler(pEvent)
	# Other mouse event, pass it on.
	else:
		pObject.CallNextHandler(pEvent)

###############################################################################
#	ModalKeyboardHandler()
#	
#	Intercepts keyboard events when viewscreen menu is up. 
#	Checks for keys that would cause the menu to drop and ignores those events.
#	Passes on any other keys as normal.
#	
#	Args:	TGObject		pObject - TGObject
#			TGKeyboardEvent	pEvent	- mouse event
#	
#	Return:	none
##############################################################################
def ModalKeyboardHandler(pObject, pEvent):
	assert pEvent.GetEventType() == App.ET_KEYBOARD
	
	# Get unicode character.
	wChar = pEvent.GetUnicode()

	# If it's any key that will bring down our menu, set it as handled and don't pass it on.
	if wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TOGGLE_MAP_MODE, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TOGGLE_CINEMATIC_MODE, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_HELM, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_TACTICAL, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_XO, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_SCIENCE, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_ENGINEERING, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_GUEST, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	else:
		# Pass on any other keyboard event.
		pObject.CallNextHandler(pEvent)

################################################################################
#	GetButton(pcChar, pcButton)
#
#	Return a button from a bridge character's menu.
#
#	Args:	pcChar, the bridge character station(ex: "Tactical").
#			pcButton, string for button to grab.
#
#	Return:	pButton
################################################################################
def GetButton(pcChar, pcButton):
	if pcChar and pcButton:
		pChar = GetBridgeCharacter(pcChar)
		if pChar:
			pMenu = pChar.GetMenu()	
			if pMenu:
				pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
				if pDatabase:
					pButton = pMenu.GetButtonW(pDatabase.GetString(pcButton))
					if not pButton:
						pButton = pMenu.GetSubmenuW(pDatabase.GetString(pcButton))
					App.g_kLocalizationManager.Unload(pDatabase)
					return pButton

################################################################################
#	EnableButton(pAction, pcChar, pcButton)
#
#	Enable a button from a bridge character's menu.
#
#	Args:	pAction, the script action if any.
#			pcChar, the bridge character station(ex: "Tactical").
#			pcButton, string for button to grab.
#
#	Return:	pButton
################################################################################
def EnableButton(pAction, pcChar, pcButton):
	pButton = GetButton(pcChar, pcButton)
	if pButton:
		pButton.SetEnabled()

	return 0

################################################################################
#	DisableButton(pAction, pcChar, pcButton)
#
#	Disable a button from a bridge character's menu.
#
#	Args:	pAction, the script action if any
#			pcChar, the bridge character station(ex: "Tactical").
#			pcButton, string for button to grab.
#
#	Return:	pButton
################################################################################
def DisableButton(pAction, pcChar, pcButton):
	pButton = GetButton(pcChar, pcButton)
	if pButton:
		pButton.SetDisabled()

	return 0

################################################################################
#	EnableScanMenu(pAction = None)
#
#	Enables the scan menu in science.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def EnableScanMenu(pAction = None):
	global g_iScanDisabledCount
	if (g_iScanDisabledCount > 0):
		g_iScanDisabledCount = g_iScanDisabledCount - 1

	pMiguel = GetBridgeCharacter("Science")
	if pMiguel and (g_iScanDisabledCount == 0):
		EnableScanAreaButton()
		EnableScanTargetButton()
		EnableScanObjectMenu()

	# Set our initial tooltip status to Waiting.  This will create
	# the tooltip box if it doesn't exist.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pMiguel.SetStatus(pDatabase.GetString("Waiting"))
	App.g_kLocalizationManager.Unload(pDatabase)

	# Update the ScanTarget button based on your target
	import ScienceMenuHandlers
	ScienceMenuHandlers.TargetChanged(None, None)

	return 0

################################################################################
#	DisableScanMenu(pAction = None)
#
#	Disables the scan menu in science.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def DisableScanMenu(pAction = None):
	global g_iScanDisabledCount
	g_iScanDisabledCount = g_iScanDisabledCount + 1

	pMiguel = GetBridgeCharacter("Science")
	if pMiguel:
		DisableScanAreaButton()
		DisableScanTargetButton()
		DisableScanObjectMenu()

	return 0

###############################################################################
#	EnableLaunchProbe(pAction, bOverride)
#	
#	Enables the launch probe button in the science menu. Can be called as an
#	action or as a regular function.
#	
#	Args:	pAction		- the action, if applicable
#			bOverride	- overrides "auto manage" flag
#	
#	Return:	zero for end
###############################################################################
def EnableLaunchProbe(pAction = None, bOverride = None):
	if (g_bAutoManageProbeButton == 0) and (bOverride == None):
		return 0

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pMenu = pTCW.FindMenu(pDatabase.GetString("Science"))
	if pMenu:
		pButton = pMenu.GetButtonW(pDatabase.GetString("Launch Probe"))
		if pButton:
			pButton.SetEnabled()
			pButton.SetColorBasedOnFlags()

	App.g_kLocalizationManager.Unload(pDatabase)

	return 0

###############################################################################
#	DisableLaunchProbe(pAction, bOverride)
#	
#	Disables the launch probe button in the science menu. Can be called as an
#	action or as a regular function.
#	
#	Args:	pAction		- the action, if applicable
#			bOverride	- overrides "auto manage" flag
#	
#	Return:	zero for end
###############################################################################
def DisableLaunchProbe(pAction = None, bOverride = None):
	if (g_bAutoManageProbeButton == 0) and (bOverride == None):
		return 0

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pMenu = pTCW.FindMenu(pDatabase.GetString("Science"))
	if pMenu:
		pButton = pMenu.GetButtonW(pDatabase.GetString("Launch Probe"))
		if pButton:
			pButton.SetDisabled()
			pButton.SetColorBasedOnFlags()

	App.g_kLocalizationManager.Unload(pDatabase)

	return 0

###############################################################################
#	ResetScanCounts()
#	
#	Resets the locks on the scan buttons when the player changes.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def ResetScanCounts():
	global g_iScanDisabledCount
	global g_iScanAreaDisabledCount
	global g_iScanTargetDisabledCount
	global g_iScanObjectDisabledCount

	g_iScanDisabledCount = 0
	g_iScanAreaDisabledCount = 0
	g_iScanTargetDisabledCount = 0
	g_iScanObjectDisabledCount = 0
