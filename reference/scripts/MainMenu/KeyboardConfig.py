###############################################################################
#	KeyboardConfig.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script to set up the Keyboard Config display
#	
#	Created:	05/23/2001	-	CCarley
###############################################################################

import App
import mainmenu
import UIHelpers

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

# Major groups
ET_GENERAL_BUTTONS				= App.UtopiaModule_GetNextEventType()
ET_MENU_BUTTONS					= App.UtopiaModule_GetNextEventType()
ET_SHIP_BUTTONS					= App.UtopiaModule_GetNextEventType()
ET_CAMERA_BUTTONS				= App.UtopiaModule_GetNextEventType()

# Subgroups
# General buttons
ET_GAME_BUTTONS					= App.UtopiaModule_GetNextEventType()
ET_CREW_BUTTONS					= App.UtopiaModule_GetNextEventType()
ET_TARGETING_BUTTONS			= App.UtopiaModule_GetNextEventType()
ET_VIEWSCREEN_BUTTONS			= App.UtopiaModule_GetNextEventType()

# Ship buttons
ET_MANEUVERING_BUTTONS			= App.UtopiaModule_GetNextEventType()
ET_SPEED_BUTTONS				= App.UtopiaModule_GetNextEventType()
ET_FIRING_BUTTONS				= App.UtopiaModule_GetNextEventType()

# Just plain need these ;)
ET_SAVE_BUTTON					= App.UtopiaModule_GetNextEventType()
ET_DEFAULT_BUTTON				= App.UtopiaModule_GetNextEventType()
ET_RESTORE_BUTTON				= App.UtopiaModule_GetNextEventType()

g_idDefaultButton				= App.NULL_ID

g_fVerticalSpacing = 0.0125
g_fHorizontalSpacing = 0.008125
g_fButtonHorizontalSpacing = 0.0171875

g_pcKeyboardConfigPane			= None
g_idMainConfigOptionsPane		= App.NULL_ID

def ToggleKeyboardSelected (pTabPane, iChild):
	for i in range (0, 4):
		pButton = App.STRoundedButton_Cast (pTabPane.GetNthChild (i))
		if (i == iChild):
			pButton.SetSelected (0)
		else:
			pButton.SetNotSelected (0)

###############################################################################
#	BuildKeyboardPane()
#	
#	Builds the Keyboard pane for later use.  This actually creates a few
#	things - the buttons for the various sections of info (Bridge, Tactical,
#	Common, etc), the lists those buttons correspond to, and the Apply and
#	Cancel buttons
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def BuildKeyboardPane(pContentPane):
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pContentWindow = App.STStylizedWindow_Create("StylizedWindow", "NoMinimize", "", 0.0, 0.0, App.STSubPane_Create(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH, LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT))
	pContentWindow.SetFixedSize(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH * 0.46, LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT * 0.9)
	pContentPane.Resize(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH * 0.46, LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT * 0.9)

	pContentWindow.Resize(pContentWindow.GetMaximumWidth(), pContentWindow.GetMaximumHeight())
	pContentPane.KillChildren()
	pContentPane.AddChild(pContentWindow, 0.0, 0.0, 0)

	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Keyboard Mapping.tgl")

	# Full area pane
	pConfigurePane = App.TGPane_Create(LCARS.MAIN_MENU_MIDDLE_PANE_WIDTH, LCARS.MAIN_MENU_MIDDLE_PANE_HEIGHT)

	# Pane to hold our stuff
	pKeyboardPane = App.TGPane_Create(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH, LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT)
	pConfigurePane.AddChild(pKeyboardPane, LCARS.MAIN_MENU_MIDDLE_CONTENT_X, LCARS.MAIN_MENU_MIDDLE_CONTENT_Y, 0)

	# Attach handlers for our buttons
	pContentWindow.AddPythonFuncHandlerForInstance(ET_GENERAL_BUTTONS,		__name__ + ".ShowGeneralKeyboardControls")
	pContentWindow.AddPythonFuncHandlerForInstance(ET_GAME_BUTTONS,			__name__ + ".ShowGameControls")
	pContentWindow.AddPythonFuncHandlerForInstance(ET_CREW_BUTTONS,			__name__ + ".ShowCrewControls")
	pContentWindow.AddPythonFuncHandlerForInstance(ET_TARGETING_BUTTONS,	__name__ + ".ShowTargetingControls")
	pContentWindow.AddPythonFuncHandlerForInstance(ET_VIEWSCREEN_BUTTONS,	__name__ + ".ShowViewscreenControls")

	pContentWindow.AddPythonFuncHandlerForInstance(ET_MENU_BUTTONS,			__name__ + ".ShowMenuControls")

	pContentWindow.AddPythonFuncHandlerForInstance(ET_SHIP_BUTTONS,			__name__ + ".ShowShipControls")
	pContentWindow.AddPythonFuncHandlerForInstance(ET_MANEUVERING_BUTTONS,	__name__ + ".ShowManeuveringControls")
	pContentWindow.AddPythonFuncHandlerForInstance(ET_SPEED_BUTTONS,		__name__ + ".ShowSpeedControls")
	pContentWindow.AddPythonFuncHandlerForInstance(ET_FIRING_BUTTONS,		__name__ + ".ShowFiringControls")

	pContentWindow.AddPythonFuncHandlerForInstance(ET_CAMERA_BUTTONS,		__name__ + ".ShowCameraControls")

	pKeyboardPane.AddPythonFuncHandlerForInstance(ET_SAVE_BUTTON,			__name__ + ".SaveKeyboardConfig")
	pKeyboardPane.AddPythonFuncHandlerForInstance(ET_DEFAULT_BUTTON,		__name__ + ".DefaultKeyboardConfig")
	pKeyboardPane.AddPythonFuncHandlerForInstance(ET_RESTORE_BUTTON,		__name__ + ".RestoreKeyboardConfig")
	
	# Create the left-hand tab pane (the one with the buttons to select the major content areas)
	pMainConfigOptionsPane = App.TGPane_Create(LCARS.MAIN_MENU_CONFIGURE_TAB_WIDTH - (LCARS.MAIN_MENU_TOP_BUTTON_WIDTH + g_fButtonHorizontalSpacing),
									LCARS.MAIN_MENU_CONFIGURE_TAB_HEIGHT)
	App.g_kFocusManager.AddObjectToTabOrder(pMainConfigOptionsPane)

	pMainConfigOptionsPane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,	"MainMenu.mainmenu" + ".HandleKeyboardTabButtonArea")

	# Add the handler for when a button is clicked on the display pane
	pContentWindow.AddPythonFuncHandlerForInstance(App.ET_OKAY,				__name__ + ".ChangeKeyCommand")

#	App.g_kFocusManager.AddObjectToTabOrder(pDisplaySubPane)

	fTop = 0.0

	# Create the buttons and attach them to the KeyboardSubPane
	# Common Controls
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pContentWindow)
	pEvent.SetDestination(pContentWindow)
	pEvent.SetEventType(ET_GENERAL_BUTTONS)
	pEvent.SetObjPtr (pMainConfigOptionsPane)
	pCommonTab = App.STRoundedButton_CreateW(pDatabase.GetString("General Controls"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pCommonTab.SetNormalColor(App.g_kMainMenuButton2Color)
	pCommonTab.SetHighlightedColor(App.g_kMainMenuButton2HighlightedColor)
	pCommonTab.SetSelectedColor(App.g_kMainMenuButton2SelectedColor)
	pCommonTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pCommonTab.SetColorBasedOnFlags()
	pCommonTab.SetSelected (0)

	fHeight = pCommonTab.GetHeight()

	pMainConfigOptionsPane.AddChild(pCommonTab, 0.0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	# Menu Controls
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pContentWindow)
	pEvent.SetDestination(pContentWindow)
	pEvent.SetEventType(ET_MENU_BUTTONS)
	pEvent.SetObjPtr (pMainConfigOptionsPane)
	pBridgeTab = App.STRoundedButton_CreateW (pDatabase.GetString("Menu Controls"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pBridgeTab.SetNormalColor(App.g_kMainMenuButton2Color)
	pBridgeTab.SetHighlightedColor(App.g_kMainMenuButton2HighlightedColor)
	pBridgeTab.SetSelectedColor(App.g_kMainMenuButton2SelectedColor)
	pBridgeTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pBridgeTab.SetColorBasedOnFlags()

	pMainConfigOptionsPane.AddChild(pBridgeTab, 0.0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	# Ship Controls
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pContentWindow)
	pEvent.SetDestination(pContentWindow)
	pEvent.SetEventType(ET_SHIP_BUTTONS)
	pEvent.SetObjPtr (pMainConfigOptionsPane)
	pBridgeTab = App.STRoundedButton_CreateW (pDatabase.GetString("Ship Controls"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pBridgeTab.SetNormalColor(App.g_kMainMenuButton2Color)
	pBridgeTab.SetHighlightedColor(App.g_kMainMenuButton2HighlightedColor)
	pBridgeTab.SetSelectedColor(App.g_kMainMenuButton2SelectedColor)
	pBridgeTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pBridgeTab.SetColorBasedOnFlags()

	pMainConfigOptionsPane.AddChild(pBridgeTab, 0.0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	# Camera Controls
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pContentWindow)
	pEvent.SetDestination(pContentWindow)
	pEvent.SetEventType(ET_CAMERA_BUTTONS)
	pEvent.SetObjPtr (pMainConfigOptionsPane)
	pBridgeTab = App.STRoundedButton_CreateW (pDatabase.GetString("Camera Controls"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pBridgeTab.SetNormalColor(App.g_kMainMenuButton2Color)
	pBridgeTab.SetHighlightedColor(App.g_kMainMenuButton2HighlightedColor)
	pBridgeTab.SetSelectedColor(App.g_kMainMenuButton2SelectedColor)
	pBridgeTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pBridgeTab.SetColorBasedOnFlags()

	pMainConfigOptionsPane.AddChild(pBridgeTab, 0.0, fTop, 0)
	fTop = fTop + (fHeight * 2.0) + g_fVerticalSpacing

	# Restore Controls
	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pKeyboardPane)
	pEvent.SetDestination(pKeyboardPane)
	pEvent.SetEventType(ET_RESTORE_BUTTON)
	pRestoreTab = App.STRoundedButton_CreateW (pDatabase.GetString("Restore"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pRestoreTab.SetNormalColor(App.g_kMainMenuButton3Color)
	pRestoreTab.SetHighlightedColor(App.g_kMainMenuButton3HighlightedColor)
	pRestoreTab.SetSelectedColor(App.g_kMainMenuButton3SelectedColor)
	pRestoreTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pRestoreTab.SetColorBasedOnFlags()

	pMainConfigOptionsPane.AddChild(pRestoreTab, 0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	# Default Controls
	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pKeyboardPane)
	pEvent.SetDestination(pKeyboardPane)
	pEvent.SetEventType(ET_DEFAULT_BUTTON)
	pDefaultTab = App.STRoundedButton_CreateW (pDatabase.GetString("Default"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pDefaultTab.SetNormalColor(App.g_kMainMenuButton3Color)
	pDefaultTab.SetHighlightedColor(App.g_kMainMenuButton3HighlightedColor)
	pDefaultTab.SetSelectedColor(App.g_kMainMenuButton3SelectedColor)
	pDefaultTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pDefaultTab.SetColorBasedOnFlags()
	global g_idDefaultButton
	g_idDefaultButton = pDefaultTab.GetObjID()

	pMainConfigOptionsPane.AddChild(pDefaultTab, 0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	fBracketTabHeight = LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT * 4.0 + g_fVerticalSpacing * 3.0
	fBracketHeight = LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT * 7.0 + g_fVerticalSpacing * 5.0
	pBracket = UIHelpers.CreateBracket(0.015, fBracketHeight - LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, fBracketTabHeight - LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, App.g_kMainMenuBorderMainColor)

	pKeyboardPane.AddChild(pMainConfigOptionsPane, LCARS.MAIN_MENU_CONFIGURE_TAB_X + LCARS.MAIN_MENU_TOP_BUTTON_WIDTH + g_fButtonHorizontalSpacing, LCARS.MAIN_MENU_CONFIGURE_TAB_Y, 0)

	pKeyboardPane.AddChild (pBracket, LCARS.MAIN_MENU_CONFIGURE_TAB_X + LCARS.MAIN_MENU_TOP_BUTTON_WIDTH + 0.0025, LCARS.MAIN_MENU_CONFIGURE_TAB_Y + LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT / 2.0, 0)

	# Get LCARS string.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	pBlackRegion = App.TGIcon_Create(pcLCARS, 200, App.g_kSTMenuTextColor)
	pBlackRegion.Resize (LCARS.MAIN_MENU_CONFIGURE_TAB_WIDTH, LCARS.MAIN_MENU_CONFIGURE_TAB_HEIGHT / 2.0, 0)
	pKeyboardPane.AddChild (pBlackRegion, LCARS.MAIN_MENU_CONFIGURE_TAB_X - .04, LCARS.MAIN_MENU_CONFIGURE_TAB_Y + LCARS.MAIN_MENU_CONFIGURE_TAB_HEIGHT / 2.0, 0)

	# Unload localization database.
	App.g_kLocalizationManager.Unload(pDatabase)

	global g_idMainConfigOptionsPane
	g_idMainConfigOptionsPane = pMainConfigOptionsPane.GetObjID()

	if g_pcKeyboardConfigPane == "General":
		ShowGeneralKeyboardControls(pContentWindow, None)
	elif g_pcKeyboardConfigPane == "Menu":
		ShowMenuControls(pContentWindow, None)
	elif g_pcKeyboardConfigPane == "Ship":
		ShowShipControls(pContentWindow, None)
	elif g_pcKeyboardConfigPane == "Camera":
		ShowCameraControls(pContentWindow, None)
	else:
		ShowGeneralKeyboardControls(pContentWindow, None)

	return(pConfigurePane)


###############################################################################
#	SaveKeyboardConfig()
#	
#	Saves the current config
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def SaveKeyboardConfig(pObject, pEvent):
	App.g_kKeyboardBinding.GenerateMappingFile()
	pObject.CallNextHandler(pEvent)
	mainmenu.SwitchMiddlePane("Configure")


###############################################################################
#	DefaultKeyboardConfig()
#	
#	Re-loads the default keyboard configuration
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def DefaultKeyboardConfig(pObject, pEvent):
	App.g_kKeyboardBinding.RebuildMappingFromFile("DefaultKeyboardBinding")
	pObject.CallNextHandler(pEvent)
	mainmenu.SwitchMiddlePane("Configure")

	# Give focus to graphics tab
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pMiddleArea = App.TGPane_Cast(pOptionsWindow.GetNthChild(1))
	pConfigurePane = App.TGPane_Cast(pMiddleArea.GetNthChild(0))
	pContentPane = App.TGPane_Cast (pConfigurePane.GetNthChild (0))
	pTabPane = App.TGPane_Cast (pContentPane.GetNthChild (0))
	pOptionsPane = App.TGPane_Cast (pContentPane.GetNthChild (1))

	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pConfigurePane)
	pEvent.SetDestination(pContentPane.GetFirstChild())
	pEvent.SetEventType(mainmenu.ET_CONFIGURE_KEYBOARD)
	pEvent.SetObjPtr(pOptionsPane)
	App.g_kEventManager.AddEvent (pEvent)

	# Disable the Default button
	global g_idDefaultButton
	pDefault = App.TGObject_GetTGObjectPtr(g_idDefaultButton)
	if (pDefault):
		pDefault = App.STRoundedButton_Cast(pDefault)
		if (pDefault):
			pDefault.SetDisabled(0)


###############################################################################
#	RestoreKeyboardConfig()
#	
#	Undoes all changes to the keyboard configuration
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def RestoreKeyboardConfig(pObject, pEvent):
	App.g_kKeyboardBinding.RebuildMappingFromFile()
	pObject.CallNextHandler(pEvent)
	mainmenu.SwitchMiddlePane("Configure")


###############################################################################
#	GetKeyboardKeyText()
#	
#	Gets the text for a keyboard event
#	
#	Args:	pString	- text of the event that this button generates
#	
#	Return:	The string that belongs on the button
###############################################################################
def GetKeyboardKeyText(pString):
	kKeyString = App.TGString()

	if (pString == "ET_SET_ALERT_LEVEL_RED"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_RED)
	elif (pString == "ET_SET_ALERT_LEVEL_YELLOW"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_YELLOW)
	elif (pString == "ET_SET_ALERT_LEVEL_GREEN"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_GREEN)
	elif (pString == "ET_INPUT_ZOOM_IN"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_ZOOM, App.KeyboardBinding.GET_FLOAT_EVENT, 0.25)
	elif (pString == "ET_INPUT_ZOOM_OUT"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_ZOOM, App.KeyboardBinding.GET_FLOAT_EVENT, -0.25)
	elif (pString == "ET_INPUT_SELECT_1"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 1)
	elif (pString == "ET_INPUT_SELECT_2"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 2)
	elif (pString == "ET_INPUT_SELECT_3"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 3)
	elif (pString == "ET_INPUT_SELECT_4"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 4)
	elif (pString == "ET_INPUT_SELECT_5"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 5)
	elif (pString == "ET_INPUT_SELECT_6"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 6)
	elif (pString == "ET_INPUT_SELECT_7"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 7)
	elif (pString == "ET_INPUT_SELECT_8"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 8)
	elif (pString == "ET_INPUT_SELECT_9"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 9)
	elif (pString == "ET_INPUT_SELECT_PREV"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, -1)
	elif (pString == "ET_INPUT_SELECT_NEXT"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, 1)
	elif (pString == "ET_INPUT_CLOSE_MENU"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_CLOSE_MENU, App.KeyboardBinding.GET_INT_EVENT, 0)
	elif (pString == "ET_INPUT_SELECT_OPTION"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, 0)
	elif (pString == "ET_INPUT_SET_IMPULSE_R"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, -2.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_0"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 0)
	elif (pString == "ET_INPUT_SET_IMPULSE_1"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 1.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_2"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 2.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_3"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 3.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_4"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 4.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_5"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 5.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_6"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 6.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_7"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 7.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_8"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 8.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_9"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 9.0/9.0)
	elif (pString == "ET_INPUT_ALLOW_CAMERA_ROTATION"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_ALLOW_CAMERA_ROTATION, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_ZOOM_TARGET"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_ZOOM_TARGET, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_TURN_UP"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_TURN_UP, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_TURN_LEFT"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_TURN_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_TURN_DOWN"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_TURN_DOWN, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_TURN_RIGHT"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_TURN_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_ROLL_LEFT"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_ROLL_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_ROLL_RIGHT"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_ROLL_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_FIRE_PRIMARY"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_FIRE_PRIMARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_FIRE_SECONDARY"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_FIRE_SECONDARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_FIRE_TERTIARY"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_FIRE_TERTIARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_TOGGLE_CONSOLE"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_TOGGLE_CONSOLE, App.KeyboardBinding.GET_EVENT, 0)
	elif (pString == "ET_INPUT_TOGGLE_CHAT_WINDOW"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_TOGGLE_CHAT_WINDOW, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_TOGGLE_TEAM_CHAT_WINDOW"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_TOGGLE_CHAT_WINDOW, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	elif (pString == "ET_INPUT_PRINT_SCREEN"):
		App.g_kKeyboardBinding.FindKeyString(kKeyString, App.ET_INPUT_PRINT_SCREEN, App.KeyboardBinding.GET_EVENT, 0)
	else:
		iEventType = getattr(App, pString)
		App.g_kKeyboardBinding.FindKeyString(kKeyString, iEventType, 0, 0)

	return kKeyString

###############################################################################
#	GetKeyboardButtonText()
#	
#	Gets the text for a keyboard button
#	
#	Args:	pString	- text of the event that this button generates
#	
#	Return:	The string that belongs on the button
###############################################################################
def GetKeyboardButtonText(pString):
	kKeyString = GetKeyboardKeyText(pString)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Keyboard Mapping.TGL")

	if (kKeyString.GetLength() == 0):
		kKeyString = (pDatabase.GetString ("<NONE>"))

	kLocalizedString = pDatabase.GetString(pString)

	kKeyString = kKeyString.Append(App.TGString(" : "))
	kKeyString = kKeyString.Append(kLocalizedString)

	App.g_kLocalizationManager.Unload(pDatabase)
	return kKeyString


###############################################################################
#	CreateKeyboardConfigButton()
#	
#	Creates a keyboard configuration button
#	
#	Args:	pDestination		- who tracks the event
#			pString				- string identifier
#			kLocalizedString	- the button text
#	
#	Return:	
###############################################################################
def CreateKeyboardConfigButton(pDestination, pString, kLocalizedString):
	pEvent = App.TGStringEvent_Create()
	pEvent.SetString(pString)
	pEvent.SetDestination(pDestination)
	pEvent.SetEventType(App.ET_OKAY)
	iUnicode = 0

	kButtonText = GetKeyboardButtonText(pString)

	pButton = App.STButton_CreateW(kButtonText, pEvent)

	return pButton


###############################################################################
#	ChangeKeyCommand()
#	
#	Brings up a dialog to change the command for a keyboard control
#	
#	Args:	pObject, pEvent	- object and event that called us
#	
#	Return:	none
###############################################################################
def ChangeKeyCommand(pObject, pEvent):
	# We want a modal dialog window for this...
	pTop = App.TopWindow_GetTopWindow()
	if not (pTop):
		pObject.CallNextHandler(pEvent)
		return

	pOptions = pTop.FindMainWindow(App.MWT_OPTIONS)
	if (not pOptions) or (not pOptions.IsWindowActive()) or (not pOptions.IsCompletelyVisible()):
		pObject.CallNextHandler(pEvent)
		return

	# Make sure we don't get extras of these...
	pTop.RemoveHandlerForInstance(App.ET_CANCEL_BINDING, __name__ + ".CancelBinding")
	pTop.RemoveHandlerForInstance(App.ET_CLEAR_BINDINGS, __name__ + ".ClearBinding")

	pModalDialogWindow = App.ModalDialogWindow_Cast(pTop.FindMainWindow(App.MWT_MODAL_DIALOG))
	
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Keyboard Mapping.TGL")

	pClearEvent = None
	pText = None
	if (GetKeyboardKeyText(pEvent.GetCString()).GetLength()):
		pClearEvent = App.TGEvent_Create()
		pClearEvent.SetEventType(App.ET_CLEAR_BINDINGS)
		pClearEvent.SetDestination(pTop)
		pTop.AddPythonFuncHandlerForInstance(App.ET_CLEAR_BINDINGS, __name__ + ".ClearBinding")
		pText = pDatabase.GetString("Clear Keys")
	
	pTop.AddPythonFuncHandlerForInstance(App.ET_CANCEL_BINDING, __name__ + ".CancelBinding")
	pCancelEvent = App.TGEvent_Create()
	pCancelEvent.SetEventType(App.ET_CANCEL_BINDING)
	pCancelEvent.SetDestination(pTop)

	kSelectString = App.TGString()
	kSelectString.Append(pDatabase.GetString("Please type the new key you wish for:"))
	kSelectString.Append(pDatabase.GetString(pEvent.GetCString()))
	pModalDialogWindow.Run(pDatabase.GetString("Select a new key"), None, pText, pClearEvent, pDatabase.GetString("Cancel"), pCancelEvent)
	pModalDialogWindow.SetAsKeyboardConfig(1)

	pWindow = App.STStylizedWindow_Cast(pModalDialogWindow.GetFirstChild())

	# Add a hidden paragraph with the text of our event type, for later use
	pPara = App.TGParagraph_Create(pEvent.GetCString())
	pModalDialogWindow.InsertChild(0, pPara, 0, 0, 0)
	pPara.SetNotVisible()

	# Add the display text..
	pPara = App.TGParagraph_CreateW(pDatabase.GetString(pEvent.GetCString()))
	pWindow.AddChild(pPara, (pWindow.GetMaximumInteriorWidth() - pPara.GetWidth())/2,
							pPara.GetHeight()*1.25, 0)

	# And the title..
	pPara = App.TGParagraph_CreateW(pDatabase.GetString("Please type the new key you wish for:"))
	pWindow.AddChild(pPara, (pWindow.GetMaximumInteriorWidth() - pPara.GetWidth())/2, 0)

	App.g_kLocalizationManager.Unload(pDatabase)

	pObject.CallNextHandler(pEvent)


###############################################################################
#	CancelNewBinding()
#	
#	Cancels setting a new keyboard binding
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def CancelNewBinding(pObject, pEvent):
	pTop.RemoveHandlerForInstance(App.ET_CANCEL_BINDING, __name__ + ".CancelBinding")
	pTop.RemoveHandlerForInstance(App.ET_CLEAR_BINDINGS, __name__ + ".ClearBinding")

	pObject.CallNextHandler(pEvent)


###############################################################################
#	RefreshCurrentButtons()
#	
#	Goes through buttons for current configuration screen and updates them
#	
#	Args:	
#	
#	Return:	
###############################################################################
def RefreshCurrentButtons():
	pTop = App.TopWindow_GetTopWindow()
	if (pTop == None):
		return

	pOptionsWindow = pTop.FindMainWindow(App.MWT_OPTIONS)

	pMiddleArea = App.TGPane_Cast(pOptionsWindow.GetNthChild(1))
	if not (pMiddleArea):
		return

	pConfigurePane = App.TGPane_Cast(pMiddleArea.GetNthChild(0))
	if not (pConfigurePane):
		return

	pKeyboardPane =  App.TGPane_Cast(pConfigurePane.GetNthChild(0))
	if not (pKeyboardPane):
		return

	pDisplayPane = App.TGPane_Cast(pKeyboardPane.GetNthChild(1))
	if not (pDisplayPane):
		return

	pWindow = App.STStylizedWindow_Cast(pDisplayPane.GetFirstChild())
	if not (pWindow):
		return

	pInterior = pWindow.GetInteriorPane()
	if not (pInterior):
		return

	iNumChildren = pInterior.GetNumChildren()
	for i in range (iNumChildren):
		pChild = App.STButton_Cast(pInterior.GetNthChild(i))
		if (pChild):
			pEvent = App.TGStringEvent_Cast(pChild.GetActivationEvent())
			pString = pEvent.GetCString()
			pChild.SetName(GetKeyboardButtonText(pString))


###############################################################################
#	ClearBinding()
#	
#	Clears keyboard bindings for an event type
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ClearBinding(pObject, pEvent):
	pTop = App.TopWindow_GetTopWindow()
	if not (pTop):
		pObject.CallNextHandler(pEvent)
		return

	pTop.RemoveHandlerForInstance(App.ET_CANCEL_BINDING, __name__ + ".CancelBinding")
	pTop.RemoveHandlerForInstance(App.ET_CLEAR_BINDINGS, __name__ + ".ClearBinding")

	pModalDialogWindow = App.ModalDialogWindow_Cast(pTop.FindMainWindow(App.MWT_MODAL_DIALOG))

	# Get the hidden text, so we can bind the key
	pPara = App.TGParagraph_Cast(pModalDialogWindow.GetFirstChild())

	kString = App.TGString()
	pPara.GetString(kString)
	pString = kString.GetCString()

	# BIG NASTY IF STATEMENT GOES HERE
	# Basically, rather than some nice, pretty way of doing this, we're just
	# indexing through our list of event possibilities, and setting the
	# appropriate events based on that =)  Have a nice day.
	if (pString == "ET_INPUT_ZOOM_IN"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ZOOM, App.KeyboardBinding.GET_FLOAT_EVENT, 0.25)
	elif (pString == "ET_INPUT_ZOOM_OUT"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ZOOM, App.KeyboardBinding.GET_FLOAT_EVENT, -0.25)
	elif (pString == "ET_INPUT_SELECT_1"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 1)
	elif (pString == "ET_INPUT_SELECT_2"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 2)
	elif (pString == "ET_INPUT_SELECT_3"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 3)
	elif (pString == "ET_INPUT_SELECT_4"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 4)
	elif (pString == "ET_INPUT_SELECT_5"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 5)
	elif (pString == "ET_INPUT_SELECT_6"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 6)
	elif (pString == "ET_INPUT_SELECT_7"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 7)
	elif (pString == "ET_INPUT_SELECT_8"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 8)
	elif (pString == "ET_INPUT_SELECT_9"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 9)
	elif (pString == "ET_INPUT_SELECT_PREV"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, -1)
	elif (pString == "ET_INPUT_SELECT_NEXT"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, 1)
	elif (pString == "ET_INPUT_SELECT_OPTION"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_PRE_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, 0)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, 0)
	elif (pString == "ET_INPUT_CLOSE_MENU"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_CLOSE_MENU, App.KeyboardBinding.GET_INT_EVENT, 0)
	elif (pString == "ET_INPUT_SET_IMPULSE_R"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, -2.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_0"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 0)
	elif (pString == "ET_INPUT_SET_IMPULSE_1"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 1.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_2"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 2.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_3"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 3.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_4"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 4.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_5"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 5.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_6"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 6.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_7"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 7.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_8"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 8.0/9.0)
	elif (pString == "ET_INPUT_SET_IMPULSE_9"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 9.0/9.0)
	elif (pString == "ET_SET_ALERT_LEVEL_GREEN"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_GREEN)
	elif (pString == "ET_SET_ALERT_LEVEL_YELLOW"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_YELLOW)
	elif (pString == "ET_SET_ALERT_LEVEL_RED"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_RED)
	elif (pString == "ET_INPUT_ALLOW_CAMERA_ROTATION"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ALLOW_CAMERA_ROTATION, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ALLOW_CAMERA_ROTATION, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_ZOOM_TARGET"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ZOOM_TARGET, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ZOOM_TARGET, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_TURN_UP"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TURN_UP, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TURN_UP, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_TURN_LEFT"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TURN_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TURN_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_TURN_DOWN"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TURN_DOWN, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TURN_DOWN, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_TURN_RIGHT"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TURN_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TURN_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_ROLL_LEFT"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ROLL_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ROLL_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_ROLL_RIGHT"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ROLL_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_ROLL_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_FIRE_PRIMARY"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_FIRE_PRIMARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_FIRE_PRIMARY, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_FIRE_SECONDARY"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_FIRE_SECONDARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_FIRE_SECONDARY, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_FIRE_TERTIARY"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_FIRE_TERTIARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_FIRE_TERTIARY, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_TOGGLE_CONSOLE"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TOGGLE_CONSOLE, App.KeyboardBinding.GET_EVENT, 0)
	elif (pString == "ET_INPUT_PRINT_SCREEN"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_PRINT_SCREEN, App.KeyboardBinding.GET_EVENT, 0)
	elif (pString == "ET_INPUT_TOGGLE_CHAT_WINDOW"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TOGGLE_CHAT_WINDOW, App.KeyboardBinding.GET_BOOL_EVENT, 0)
	elif (pString == "ET_INPUT_TOGGLE_TEAM_CHAT_WINDOW"):
		App.g_kKeyboardBinding.ClearBinding(App.ET_INPUT_TOGGLE_CHAT_WINDOW, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	else:
		iEventType = getattr(App, kString.GetCString())
		App.g_kKeyboardBinding.ClearBinding(iEventType, 0, 0)

	# Change the button text to reflect our changes
	RefreshCurrentButtons()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	NewKeySelected()
#	
#	A new key has been selected for the event type - map it
#	
#	Args:	pEvent	- the event that called us
#	
#	Return:	none
###############################################################################
def NewKeySelected(pEvent):
	if (pEvent.GetUnicode() and pEvent.GetKeyState() == App.TGKeyboardEvent.KS_KEYUP):
		pTop = App.TopWindow_GetTopWindow()
		if (pTop == None):
			return

		pTop.RemoveHandlerForInstance(App.ET_CANCEL_BINDING, __name__ + ".CancelBinding")
		pTop.RemoveHandlerForInstance(App.ET_CLEAR_BINDINGS, __name__ + ".ClearBinding")

		pModalDialogWindow = App.ModalDialogWindow_Cast(pTop.FindMainWindow(App.MWT_MODAL_DIALOG))

		# Get the hidden text, so we can bind the key
		pPara = App.TGParagraph_Cast(pModalDialogWindow.GetFirstChild())

		kString = App.TGString()
		pPara.GetString(kString)
		pString = kString.GetCString()

		# BIG NASTY IF STATEMENT GOES HERE
		# Basically, rather than some nice, pretty way of doing this, we're just
		# indexing through our list of event possibilities, and setting the
		# appropriate events based on that =)  Have a nice day.
		if (pString == "ET_INPUT_ZOOM_IN"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_NORMAL, App.ET_INPUT_ZOOM, App.KeyboardBinding.GET_FLOAT_EVENT, 0.25)
		elif (pString == "ET_INPUT_ZOOM_OUT"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_NORMAL, App.ET_INPUT_ZOOM, App.KeyboardBinding.GET_FLOAT_EVENT, -0.25)
		elif (pString == "ET_INPUT_SELECT_1"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 1)
		elif (pString == "ET_INPUT_SELECT_2"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 2)
		elif (pString == "ET_INPUT_SELECT_3"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 3)
		elif (pString == "ET_INPUT_SELECT_4"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 4)
		elif (pString == "ET_INPUT_SELECT_5"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 5)
		elif (pString == "ET_INPUT_SELECT_6"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 6)
		elif (pString == "ET_INPUT_SELECT_7"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 7)
		elif (pString == "ET_INPUT_SELECT_8"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 8)
		elif (pString == "ET_INPUT_SELECT_9"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_X, App.KeyboardBinding.GET_INT_EVENT, 9)
		elif (pString == "ET_INPUT_SELECT_PREV"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, -1)
		elif (pString == "ET_INPUT_SELECT_NEXT"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, 1)
		elif (pString == "ET_INPUT_SELECT_OPTION"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_PRE_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, 0)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_SELECT_OPTION, App.KeyboardBinding.GET_INT_EVENT, 0)
		elif (pString == "ET_INPUT_CLOSE_MENU"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_CLOSE_MENU, App.KeyboardBinding.GET_INT_EVENT, 0)
		elif (pString == "ET_INPUT_SET_IMPULSE_R"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, -2.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_0"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 0)
		elif (pString == "ET_INPUT_SET_IMPULSE_1"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 1.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_2"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 2.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_3"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 3.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_4"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 4.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_5"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 5.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_6"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 6.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_7"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 7.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_8"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 8.0/9.0)
		elif (pString == "ET_INPUT_SET_IMPULSE_9"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 9.0/9.0)
		elif (pString == "ET_SET_ALERT_LEVEL_GREEN"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_GREEN)
		elif (pString == "ET_SET_ALERT_LEVEL_YELLOW"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_YELLOW)
		elif (pString == "ET_SET_ALERT_LEVEL_RED"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_SET_ALERT_LEVEL, App.KeyboardBinding.GET_INT_EVENT, App.CharacterClass.EST_ALERT_RED)
		elif (pString == "ET_INPUT_ALLOW_CAMERA_ROTATION"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_ALLOW_CAMERA_ROTATION, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_ALLOW_CAMERA_ROTATION, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_ZOOM_TARGET"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_ZOOM_TARGET, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_ZOOM_TARGET, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_TURN_UP"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_TURN_UP, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_TURN_UP, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_TURN_LEFT"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_TURN_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_TURN_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_TURN_DOWN"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_TURN_DOWN, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_TURN_DOWN, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_TURN_RIGHT"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_TURN_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_TURN_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_ROLL_LEFT"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_ROLL_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_ROLL_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_ROLL_RIGHT"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_ROLL_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_ROLL_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_FIRE_PRIMARY"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_FIRE_PRIMARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_FIRE_PRIMARY, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_FIRE_SECONDARY"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_FIRE_SECONDARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_FIRE_SECONDARY, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_FIRE_TERTIARY"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, App.ET_INPUT_FIRE_TERTIARY, App.KeyboardBinding.GET_BOOL_EVENT, 1)
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_FIRE_TERTIARY, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_TOGGLE_CONSOLE"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_NORMAL, App.ET_INPUT_TOGGLE_CONSOLE, App.KeyboardBinding.GET_EVENT, 0)
		elif (pString == "ET_INPUT_PRINT_SCREEN"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYUP, App.ET_INPUT_PRINT_SCREEN, App.KeyboardBinding.GET_EVENT, 0)
		elif (pString == "ET_INPUT_TOGGLE_CHAT_WINDOW"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_NORMAL, App.ET_INPUT_TOGGLE_CHAT_WINDOW, App.KeyboardBinding.GET_BOOL_EVENT, 0)
		elif (pString == "ET_INPUT_TOGGLE_TEAM_CHAT_WINDOW"):
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_NORMAL, App.ET_INPUT_TOGGLE_CHAT_WINDOW, App.KeyboardBinding.GET_BOOL_EVENT, 1)
		else:
			iEventType = getattr(App, kString.GetCString())
			App.g_kKeyboardBinding.BindKey(pEvent.GetUnicode(), App.TGKeyboardEvent.KS_KEYDOWN, iEventType, 0, 0)

		pEvent.SetHandled()

		# Change the button text to reflect our changes
		RefreshCurrentButtons()

		# Enable the Default button
		global g_idDefaultButton
		pDefault = App.TGObject_GetTGObjectPtr(g_idDefaultButton)
		if (pDefault):
			pDefault = App.STRoundedButton_Cast(pDefault)
			if (pDefault):
				pDefault.SetEnabled(0)

		# Close down the Modal Dialog box
		pModalDialogWindow.Cancel()

		return

###############################################################################
#	ShowGeneralKeyboardControls()
#	
#	Displays the general keyboard controls in the keyboard config pane
#	
#	Args:	pObject, pEvent	- Destination object, event calling us
#	
#	Return:	none
###############################################################################
def ShowGeneralKeyboardControls(pObject, pEvent):
	global g_pcKeyboardConfigPane
	g_pcKeyboardConfigPane = "General"

	# Delete any current children
	pDisplayWindow = App.STStylizedWindow_Cast(pObject)
	pDisplayPane = App.STSubPane_Cast(pDisplayWindow.GetInteriorPane())
	pContainingSubPane = App.STSubPane_Cast(pDisplayWindow.GetParent())
	pDisplayPane.KillChildren()

	if (pEvent):
		ToggleKeyboardSelected (App.TGPane_Cast (pEvent.GetObjPtr ()), 0)
	else:
		pMainConfigOptionsPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMainConfigOptionsPane))
		if pMainConfigOptionsPane:
			ToggleKeyboardSelected(pMainConfigOptionsPane, 0)

	# Load our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Keyboard Mapping.TGL")

	fTop = 0.0

	# Create the buttons and attach them to the Sub Config pane
	###############################
	### Game Controls
	###############################

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL",
													pDatabase.GetString("ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TOGGLE_MAP_MODE",
													pDatabase.GetString("ET_INPUT_TOGGLE_MAP_MODE")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TOGGLE_CINEMATIC_MODE", 
													pDatabase.GetString("ET_INPUT_TOGGLE_CINEMATIC_MODE")), 0, 0, 0)

	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_QUICK_SAVE", 
	#												pDatabase.GetString("ET_QUICK_SAVE")), 0, 0, 0)
	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_QUICK_LOAD", 
	#												pDatabase.GetString("ET_QUICK_LOAD")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_PRINT_SCREEN",
													pDatabase.GetString("ET_INPUT_PRINT_SCREEN")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TOGGLE_PICK_FIRE",
													pDatabase.GetString("ET_INPUT_TOGGLE_PICK_FIRE")), 0, 0, 0)

	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_DEBUG_KILL_TARGET",
	#												pDatabase.GetString("ET_INPUT_DEBUG_KILL_TARGET")), 0, 0, 0)
	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_DEBUG_QUICK_REPAIR",
	#												pDatabase.GetString("ET_INPUT_DEBUG_QUICK_REPAIR")), 0, 0, 0)
	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_DEBUG_GOD_MODE",
	#												pDatabase.GetString("ET_INPUT_DEBUG_GOD_MODE")), 0, 0, 0)
	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_DEBUG_LOAD_QUANTUMS",
	#												pDatabase.GetString("ET_INPUT_DEBUG_LOAD_QUANTUMS")), 0, 0, 0)
	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_DEBUG_TOGGLE_EDIT_MODE",
	#												pDatabase.GetString("ET_INPUT_DEBUG_TOGGLE_EDIT_MODE")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_OTHER_BEAM_TOGGLE_CLICKED",
													pDatabase.GetString("ET_OTHER_BEAM_TOGGLE_CLICKED")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_OTHER_CLOAK_TOGGLE_CLICKED",
													pDatabase.GetString("ET_OTHER_CLOAK_TOGGLE_CLICKED")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TOGGLE_SCORE_WINDOW",
													pDatabase.GetString("ET_INPUT_TOGGLE_SCORE_WINDOW")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TOGGLE_CHAT_WINDOW",
													pDatabase.GetString("ET_INPUT_TOGGLE_CHAT_WINDOW")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TOGGLE_TEAM_CHAT_WINDOW",
													pDatabase.GetString("ET_INPUT_TOGGLE_TEAM_CHAT_WINDOW")), 0, 0, 0)



	###############################
	### Crew Controls
	###############################
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TALK_TO_HELM", 
													pDatabase.GetString("ET_INPUT_TALK_TO_HELM")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TALK_TO_TACTICAL", 
													pDatabase.GetString("ET_INPUT_TALK_TO_TACTICAL")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TALK_TO_XO", 
													pDatabase.GetString("ET_INPUT_TALK_TO_XO")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TALK_TO_SCIENCE", 
													pDatabase.GetString("ET_INPUT_TALK_TO_SCIENCE")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TALK_TO_ENGINEERING", 
													pDatabase.GetString("ET_INPUT_TALK_TO_ENGINEERING")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TALK_TO_GUEST", 
													pDatabase.GetString("ET_INPUT_TALK_TO_GUEST")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SKIP_EVENTS", 
													pDatabase.GetString("ET_INPUT_SKIP_EVENTS")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_SET_ALERT_LEVEL_GREEN", 
													pDatabase.GetString("ET_SET_ALERT_LEVEL_GREEN")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_SET_ALERT_LEVEL_YELLOW", 
													pDatabase.GetString("ET_SET_ALERT_LEVEL_YELLOW")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_SET_ALERT_LEVEL_RED", 
													pDatabase.GetString("ET_SET_ALERT_LEVEL_RED")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_INTERCEPT", 
													pDatabase.GetString("ET_INPUT_INTERCEPT")), 0, 0, 0)


	###############################
	### Targeting Controls
	###############################
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_CLEAR_TARGET",
													pDatabase.GetString("ET_INPUT_CLEAR_TARGET")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TARGET_NEXT",
													pDatabase.GetString("ET_INPUT_TARGET_NEXT")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TARGET_PREV",
													pDatabase.GetString("ET_INPUT_TARGET_PREV")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TARGET_NEAREST",
													pDatabase.GetString("ET_INPUT_TARGET_NEAREST")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TARGET_NEXT_ENEMY",
													pDatabase.GetString("ET_INPUT_TARGET_NEXT_ENEMY")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TARGET_TARGETS_ATTACKER",
													pDatabase.GetString("ET_INPUT_TARGET_TARGETS_ATTACKER")), 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TARGET_NEXT_NAVPOINT",
													pDatabase.GetString("ET_INPUT_TARGET_NEXT_NAVPOINT")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TARGET_NEXT_PLANET",
													pDatabase.GetString("ET_INPUT_TARGET_NEXT_PLANET")), 0, 0, 0)


	###############################
	### Viewscreen Controls
	###############################
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_VIEWSCREEN_TARGET",
													pDatabase.GetString("ET_INPUT_VIEWSCREEN_TARGET")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_VIEWSCREEN_FORWARD",
													pDatabase.GetString("ET_INPUT_VIEWSCREEN_FORWARD")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_VIEWSCREEN_LEFT",
													pDatabase.GetString("ET_INPUT_VIEWSCREEN_LEFT")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_VIEWSCREEN_RIGHT",
													pDatabase.GetString("ET_INPUT_VIEWSCREEN_RIGHT")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_VIEWSCREEN_BACKWARD",
													pDatabase.GetString("ET_INPUT_VIEWSCREEN_BACKWARD")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_VIEWSCREEN_UP",
													pDatabase.GetString("ET_INPUT_VIEWSCREEN_UP")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_VIEWSCREEN_DOWN",
													pDatabase.GetString("ET_INPUT_VIEWSCREEN_DOWN")))

	pDisplayPane.ResizeToContents()
	pContainingSubPane.ResizeToContents()

	App.g_kLocalizationManager.Unload(pDatabase)

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	ShowMenuControls()
#	
#	Displays the game keyboard controls in the keyboard config pane
#	
#	Args:	pObject, pEvent	- Destination object, event calling us
#	
#	Return:	none
###############################################################################
def ShowMenuControls(pObject, pEvent):
	global g_pcKeyboardConfigPane
	g_pcKeyboardConfigPane = "Menu"

	if pEvent:
		ToggleKeyboardSelected (App.TGPane_Cast (pEvent.GetObjPtr ()), 1)
	else:
		pMainConfigOptionsPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMainConfigOptionsPane))
		if pMainConfigOptionsPane:
			ToggleKeyboardSelected(pMainConfigOptionsPane, 1)

	# Delete any current children
	pDisplayWindow = App.STStylizedWindow_Cast(pObject)
	pDisplayPane = App.STSubPane_Cast(pDisplayWindow.GetInteriorPane())
	pContainingSubPane = App.STSubPane_Cast(pDisplayWindow.GetParent())
	pDisplayPane.KillChildren()

	# Load our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Keyboard Mapping.TGL")

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_PREV",
													pDatabase.GetString("ET_INPUT_SELECT_PREV")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_NEXT",
													pDatabase.GetString("ET_INPUT_SELECT_NEXT")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_OPTION",
													pDatabase.GetString("ET_INPUT_SELECT_OPTION")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_CLOSE_MENU",
													pDatabase.GetString("ET_INPUT_CLOSE_MENU")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_1",
													pDatabase.GetString("ET_INPUT_SELECT_1")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_2",
													pDatabase.GetString("ET_INPUT_SELECT_2")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_3", 
													pDatabase.GetString("ET_INPUT_SELECT_3")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_4", 
													pDatabase.GetString("ET_INPUT_SELECT_4")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_5", 
													pDatabase.GetString("ET_INPUT_SELECT_5")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_6", 
													pDatabase.GetString("ET_INPUT_SELECT_6")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_7", 
													pDatabase.GetString("ET_INPUT_SELECT_7")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_8", 
													pDatabase.GetString("ET_INPUT_SELECT_8")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELECT_9", 
													pDatabase.GetString("ET_INPUT_SELECT_9")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TAB_FOCUS_CHANGE",
													pDatabase.GetString("ET_INPUT_TAB_FOCUS_CHANGE")))

	# Blank example code:
	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "",
	#												pDatabase.GetString("")), 0, 0, 0)

	pDisplayPane.ResizeToContents()
	pContainingSubPane.ResizeToContents()

	App.g_kLocalizationManager.Unload(pDatabase)

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)


###############################################################################
#	ShowShipControls()
#	
#	Displays the tactical keyboard controls in the keyboard config pane
#	
#	Args:	pObject, pEvent	- Destination object, event calling us
#	
#	Return:	none
###############################################################################
def ShowShipControls(pObject, pEvent):
	global g_pcKeyboardConfigPane
	g_pcKeyboardConfigPane = "Ship"

	if pEvent:
		ToggleKeyboardSelected(App.TGPane_Cast (pEvent.GetObjPtr ()), 2)
	else:
		pMainConfigOptionsPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMainConfigOptionsPane))
		if pMainConfigOptionsPane:
			ToggleKeyboardSelected(pMainConfigOptionsPane, 2)

	# Delete any current children
	pDisplayWindow = App.STStylizedWindow_Cast(pObject)
	pDisplayPane = App.STSubPane_Cast(pDisplayWindow.GetInteriorPane())
	pContainingSubPane = App.STSubPane_Cast(pDisplayWindow.GetParent())
	pDisplayPane.KillChildren()

	# Load our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Keyboard Mapping.TGL")

	fTop = 0.0

	# Create the buttons and attach them to the Sub Config pane
	###############################
	## Maneuvering Controls
	###############################
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TURN_UP",
													pDatabase.GetString("ET_INPUT_TURN_UP")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TURN_LEFT",
													pDatabase.GetString("ET_INPUT_TURN_LEFT")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TURN_DOWN",
													pDatabase.GetString("ET_INPUT_TURN_DOWN")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_TURN_RIGHT",
													pDatabase.GetString("ET_INPUT_TURN_RIGHT")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_ROLL_LEFT",
													pDatabase.GetString("ET_INPUT_ROLL_LEFT")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_ROLL_RIGHT",
													pDatabase.GetString("ET_INPUT_ROLL_RIGHT")), 0, 0, 0)


	###############################
	### Firing Controls
	###############################
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_FIRE_PRIMARY",
													pDatabase.GetString("ET_INPUT_FIRE_PRIMARY")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_FIRE_SECONDARY",
													pDatabase.GetString("ET_INPUT_FIRE_SECONDARY")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_FIRE_TERTIARY",
													pDatabase.GetString("ET_INPUT_FIRE_TERTIARY")), 0, 0, 0)


	###############################
	### Speed Controls
	###############################
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_R",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_R")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_0",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_0")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_1",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_1")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_2",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_2")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_3",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_3")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_4",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_4")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_5",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_5")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_6",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_6")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_7",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_7")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_8",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_8")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SET_IMPULSE_9",
													pDatabase.GetString("ET_INPUT_SET_IMPULSE_9")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_INCREASE_SPEED",
													pDatabase.GetString("ET_INPUT_INCREASE_SPEED")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_DECREASE_SPEED",
													pDatabase.GetString("ET_INPUT_DECREASE_SPEED")), 0, 0, 0)


	###############################
	### Special Controls
	###############################
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_SELF_DESTRUCT",
													pDatabase.GetString("ET_INPUT_SELF_DESTRUCT")))

	pDisplayPane.ResizeToContents()
	pContainingSubPane.ResizeToContents()

	App.g_kLocalizationManager.Unload(pDatabase)

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	ShowCameraControls()
#	
#	Displays the game keyboard controls in the keyboard config pane
#	
#	Args:	pObject, pEvent	- Destination object, event calling us
#	
#	Return:	none
###############################################################################
def ShowCameraControls(pObject, pEvent):
	global g_pcKeyboardConfigPane
	g_pcKeyboardConfigPane = "Camera"

	if pEvent:
		ToggleKeyboardSelected(App.TGPane_Cast(pEvent.GetObjPtr()), 3)
	else:
		pMainConfigOptionsPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMainConfigOptionsPane))
		if pMainConfigOptionsPane:
			ToggleKeyboardSelected(pMainConfigOptionsPane, 3)

	# Delete any current children
	pDisplayWindow = App.STStylizedWindow_Cast(pObject)
	pDisplayPane = App.STSubPane_Cast(pDisplayWindow.GetInteriorPane())
	pContainingSubPane = App.STSubPane_Cast(pDisplayWindow.GetParent())
	pDisplayPane.KillChildren()

	# Load our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Keyboard Mapping.TGL")

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_CYCLE_CAMERA",
													pDatabase.GetString("ET_INPUT_CYCLE_CAMERA")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_REVERSE_CHASE",
													pDatabase.GetString("ET_INPUT_REVERSE_CHASE")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_ALLOW_CAMERA_ROTATION",
													pDatabase.GetString("ET_INPUT_ALLOW_CAMERA_ROTATION")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_ZOOM_TARGET",
													pDatabase.GetString("ET_INPUT_ZOOM_TARGET")), 0, 0, 0)

	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_ZOOM_IN",
													pDatabase.GetString("ET_INPUT_ZOOM_IN")), 0, 0, 0)
	pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "ET_INPUT_ZOOM_OUT",
													pDatabase.GetString("ET_INPUT_ZOOM_OUT")))

	# Blank example code:
	#pDisplayPane.AddChild(CreateKeyboardConfigButton(pDisplayWindow, "",
	#												pDatabase.GetString("")), 0, 0, 0)

	pDisplayPane.ResizeToContents()
	pContainingSubPane.ResizeToContents()

	App.g_kLocalizationManager.Unload(pDatabase)

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)
