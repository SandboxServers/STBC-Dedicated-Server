###############################################################################
#	Filename:	mainmenu.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to build the options menu.
#	
#	Created:	??/??/?? -	??
###############################################################################

import App
import UIHelpers
import Multiplayer.MultiplayerMenus

import KeyboardConfig

CLIENT_START_BUTTON_X_POS				= 0.65
CLIENT_START_BUTTON_Y_POS				= 0.6933333
CLIENT_START_BUTTON_WIDTH				= 0.153125
CLIENT_START_BUTTON_HEIGHT				= 0.0416667

# Event types for mission selection.
ET_E1M1 = App.UtopiaModule_GetNextEventType()
ET_E1M2 = App.UtopiaModule_GetNextEventType()

ET_E2M0 = App.UtopiaModule_GetNextEventType()
ET_E2M1 = App.UtopiaModule_GetNextEventType()
ET_E2M2 = App.UtopiaModule_GetNextEventType()
ET_E2M3 = App.UtopiaModule_GetNextEventType()
ET_E2M6 = App.UtopiaModule_GetNextEventType()

ET_E3M1 = App.UtopiaModule_GetNextEventType()
ET_E3M2 = App.UtopiaModule_GetNextEventType()
ET_E3M4 = App.UtopiaModule_GetNextEventType()
ET_E3M5 = App.UtopiaModule_GetNextEventType()

ET_E4M1 = App.UtopiaModule_GetNextEventType()
ET_E4M3 = App.UtopiaModule_GetNextEventType()
ET_E4M4 = App.UtopiaModule_GetNextEventType()
ET_E4M5 = App.UtopiaModule_GetNextEventType()
ET_E4M6 = App.UtopiaModule_GetNextEventType()

ET_E5M1 = App.UtopiaModule_GetNextEventType()
ET_E5M2 = App.UtopiaModule_GetNextEventType()
ET_E5M3 = App.UtopiaModule_GetNextEventType()
ET_E5M4 = App.UtopiaModule_GetNextEventType()

ET_E6M1 = App.UtopiaModule_GetNextEventType()
ET_E6M2 = App.UtopiaModule_GetNextEventType()
ET_E6M3 = App.UtopiaModule_GetNextEventType()
ET_E6M4 = App.UtopiaModule_GetNextEventType()
ET_E6M5 = App.UtopiaModule_GetNextEventType()

ET_E7M1 = App.UtopiaModule_GetNextEventType()
ET_E7M2 = App.UtopiaModule_GetNextEventType()
ET_E7M3 = App.UtopiaModule_GetNextEventType()
ET_E7M4 = App.UtopiaModule_GetNextEventType()
ET_E7M5 = App.UtopiaModule_GetNextEventType()
ET_E7M6 = App.UtopiaModule_GetNextEventType()

ET_E8M1 = App.UtopiaModule_GetNextEventType()
ET_E8M2 = App.UtopiaModule_GetNextEventType()

# This is kind of evil, but I want to maintain compatibility...
ET_CUSTOM_MISSION = App.FIRST_TG_SEQUENCE_MODULE_EVENT_TYPE - 100

ET_QUICK_BATTLE = App.UtopiaModule_GetNextEventType()

ET_START_NEW_GAME = App.UtopiaModule_GetNextEventType()

ET_UPDATE_JUNK_TEXT = App.UtopiaModule_GetNextEventType()

ET_COLLISIONS_TOGGLE = App.UtopiaModule_GetNextEventType()
ET_FONT_SIZE_TOGGLE	 = App.UtopiaModule_GetNextEventType()
ET_DIFFICULTY = App.UtopiaModule_GetNextEventType()

ET_VOICE_VOLUME = App.UtopiaModule_GetNextEventType()
ET_SOUND_VOLUME = App.UtopiaModule_GetNextEventType()
ET_MUSIC_VOLUME = App.UtopiaModule_GetNextEventType()

ET_MUSIC_TOGGLE = App.UtopiaModule_GetNextEventType()
ET_SOUND_TOGGLE = App.UtopiaModule_GetNextEventType()
ET_VOICE_TOGGLE = App.UtopiaModule_GetNextEventType()

ET_3D_SOUND_PREFS = App.UtopiaModule_GetNextEventType()

ET_SUBTITLE_TOGGLE = App.UtopiaModule_GetNextEventType()
ET_TOOL_TIP_TOGGLE = App.UtopiaModule_GetNextEventType()
ET_COLLISION_ALERT_TOGGLE = App.UtopiaModule_GetNextEventType()

ET_GRAPHICS_OPTIONS_MASTER				= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_MASTER_CONFIRMED	= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_MASTER_CANCEL		= App.UtopiaModule_GetNextEventType()

ET_GRAPHICS_OPTIONS_VISIBLE_DAMAGE	= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_SPACE_DUST		= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_GLOW			= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_ENHANCED_GLOW	= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_SPECULAR		= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_MOTION_BLUR		= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_LOD				= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_TEXTURE_DETAIL	= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_TEXTURE_FILTER	= App.UtopiaModule_GetNextEventType()
ET_GRAPHICS_OPTIONS_MIPMAPS			= App.UtopiaModule_GetNextEventType()

ET_SAVE_GAME = App.UtopiaModule_GetNextEventType()

ET_NEW_GAME_DIFFICULTY = App.UtopiaModule_GetNextEventType()

# These are events sent when the appropriate "tab" button at the
# top of the main menu is pressed.
ET_MAIN_MENU_NEW_GAME_TAB		= App.UtopiaModule_GetNextEventType()
ET_MAIN_MENU_EXIT_GAME_BUTTON	= App.UtopiaModule_GetNextEventType()
ET_MAIN_MENU_CONFIGURE_TAB		= App.UtopiaModule_GetNextEventType()
ET_MAIN_MENU_LOAD_GAME_TAB		= App.UtopiaModule_GetNextEventType()
ET_MAIN_MENU_SAVE_GAME_TAB		= App.UtopiaModule_GetNextEventType()
ET_MAIN_MENU_MULTIPLAYER_TAB	= App.UtopiaModule_GetNextEventType()
ET_MAIN_MENU_QUIT_TAB			= App.UtopiaModule_GetNextEventType()
ET_MAIN_MENU_CREDITS_TAB		= App.UtopiaModule_GetNextEventType()
ET_MAIN_MENU_TEST_GAME_TAB		= App.UtopiaModule_GetNextEventType()

ET_CONFIGURE_GENERAL_TAB		= App.UtopiaModule_GetNextEventType()
ET_CONFIGURE_SOUND_TAB			= App.UtopiaModule_GetNextEventType()
ET_CONFIGURE_GRAPHICS_TAB		= App.UtopiaModule_GetNextEventType()
ET_CONFIGURE_SAVE				= App.UtopiaModule_GetNextEventType()
ET_CONFIGURE_KEYBOARD			= App.UtopiaModule_GetNextEventType()

ET_CANCEL_ENTER_NAME = App.UtopiaModule_GetNextEventType()
ET_START_GAME = App.UtopiaModule_GetNextEventType()

App.g_kVarManager.SetStringVariable("Options", "EpisodeOverride", "")
App.g_kVarManager.SetStringVariable("Options", "MissionOverride", "")


# Python globals
#NonSerializedObjects = (
#	"debug",
#)

#debug = App.CPyDebug(__name__).Print

g_kCurrentMiddlePane = 0

g_pcConfigurePaneName		= None
g_pcCurrentPaneName			= None
g_idCaptainEntry			= App.NULL_ID

g_fVerticalSpacing = 0.0125
g_fHorizontalSpacing = 0.008125
g_fButtonHorizontalSpacing = 0.0171875


g_fButtonHeight = 0.0364
g_iMovieSequenceID = [App.NULL_ID, App.NULL_ID, App.NULL_ID]
g_idMoviePane = App.NULL_ID
g_idMoviePane2 = App.NULL_ID
g_iMovieMode = 2
g_idMasterGraphicsButton = App.NULL_ID
g_idCollisionButton = App.NULL_ID
g_bListPane = 0
g_idOpeningCreditsSequence = App.NULL_ID
g_idCreditsSequence = App.NULL_ID
g_idOpeningSequence = App.NULL_ID
g_idOpeningMovieSequence = App.NULL_ID
g_eNewGameDifficulty = 1
g_idResumeButton = App.NULL_ID
g_idJunkText1 = App.NULL_ID
g_idJunkText2 = App.NULL_ID
g_idJunkText3 = App.NULL_ID
g_idJunkText4 = App.NULL_ID
g_bRecreateJunkTextTimer = 0
g_idBinkIcon = App.NULL_ID
g_idMilesIcon = App.NULL_ID
g_idGameSpyIcon = App.NULL_ID

g_bMultiplayerMenusRebuiltAfterResChange = 1

g_idJunkTextTimer = App.NULL_ID
g_iRes = 0
g_pcBigFont = "Serpentine"
g_pcSmallFont = "Crillee"
g_kBigFontSize = [7, 8, 10, 12, 16]
g_kSmallFontSize = [6, 6, 9, 12, 15]

g_pcFlightSmallFont = "Crillee"
g_pcFlightBigFont = "Crillee"
g_kFlightSmallFontSize = [5, 6, 6, 6, 6]
g_kFlightBigFontSize = [5, 6, 6, 6, 6]

g_bConfigLoaded = 0

g_fCreditDelay = 2.0
g_pCreditDatabase = None
g_idCreditPane = App.NULL_ID
g_idShadowPane = App.NULL_ID
g_fTitleLeft = 0.2
g_fNameLeft = 0.5
g_iAlignment = 0

###############################################################################
#	CreateTextEntry(pName, pDefault, fMaxWidth
#	
#	Creates a text entry thingie
#	
#	Args:	pName - the name of the title tag
#			pDefault - the default string of the text entry
#			fMaxWidth - the max width of this thingie
#			fLongestLen - spacing for the name versus the text entry box
#	Return:	the newly-created thingie
###############################################################################
def CreateTextEntry(pName, pDefault, fMaxWidth, fLongestLen, pcConfigName, iMaxChars, bBackground = 1, pcIgnoreString = None):
	# First create a pane for this.
	pPane = App.TGPane_Create (fMaxWidth, 1.0)

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Create the text tag
	if (pName == None):
		pText = App.TGPane_Create ()
		fWidth = pText.GetWidth ()
		pPane.AddChild (pText, fLongestLen - fWidth, 0)
		
		# Add some space between text tag and text entry box
		fLongestLen = 0

		# Get width for spacing the text entry box.
		fWidth = fLongestLen

		# Create the name entry button
		# Get LCARS string
		pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
		pcLCARS = pGraphicsMode.GetLcarsString()

		if (pDefault == None):
			pTextEntry = App.TGParagraph_Create ("Default")
		else:
			pTextEntry = App.TGParagraph_CreateW (pDefault)
		pTextEntry.SetMaxChars (iMaxChars)
		pTextEntry.Resize (fMaxWidth - fWidth, pTextEntry.GetHeight (), 0)
		pTextEntry.SetReadOnly (0)
		if (pcIgnoreString == None):
			pTextEntry.SetIgnoreString ("\n\r")
		else:
			pTextEntry.SetIgnoreString(pcIgnoreString + "\n\r");
#		pTextEntry.SetColor (App.g_kSTMenuTextColor)

		pPane.AddChild (pTextEntry, fWidth + 0.005, (LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT - pTextEntry.GetHeight ()) / 2.0)

		# Create a background for the text entry button
		if (bBackground):
			pBackground = App.TGIcon_Create(pcLCARS, 200, App.g_kTextEntryColor)
			pBackground.Resize (fMaxWidth - fWidth, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, 0)
			pPane.AddChild (pBackground, fWidth, 0)

		# Now resize the pane to be the height of text entry
		pPane.Resize (fMaxWidth, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, 0)

		if (pDefault == None):
			# Okay, now I have to blank out the string
			pTextEntry.SetString ("", 0)

	else:
		pText = App.TGParagraph_CreateW (pName)
		fWidth = pText.GetWidth ()
		pPane.AddChild (pText, fLongestLen - fWidth, 0)
		
		# Add some space between text tag and text entry box
		fLongestLen = fLongestLen + g_fHorizontalSpacing

		# Get width for spacing the text entry box.
		fWidth = fLongestLen

		# Create the name entry button
		# Get LCARS string
		pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
		pcLCARS = pGraphicsMode.GetLcarsString()

		if (pDefault == None):
			pTextEntry = App.TGParagraph_Create ("Default")
		else:
			pTextEntry = App.TGParagraph_CreateW (pDefault)
		pTextEntry.SetMaxChars (iMaxChars)
		pTextEntry.Resize (fMaxWidth - fWidth, pTextEntry.GetHeight (), 0)
		pTextEntry.SetReadOnly (0)
		pTextEntry.SetIgnoreString ("\n\r")
		pPane.AddChild (pTextEntry, fWidth + 0.005, 0)
#		pTextEntry.SetColor (App.g_kSTMenuTextColor)

		# Create a background for the text entry button
		if (bBackground):
			pBackground = App.TGIcon_Create(pcLCARS, 200, App.g_kTextEntryColor)
			pBackground.Resize (fMaxWidth - fWidth, pTextEntry.GetHeight (), 0)
			pPane.AddChild (pBackground, fWidth, 0)

		# Now resize the pane to be the height of text entry
		pPane.Resize (fMaxWidth, pTextEntry.GetHeight (), 0)

		if (pDefault == None):
			# Okay, now I have to blank out the string
			pTextEntry.SetString ("", 0)

	# Add a hidden child that stores the name to use in the configuration file.
	pPara = App.TGParagraph_Create (pcConfigName)
	pPane.AddChild (pPara, 0, 0)
	pPara.SetNotVisible ()

	pPane.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".TextEntryMouseHandler")

	return pPane

###############################################################################
#	HandleMouse()
#	
#	Handles mouse events. This is registered as an event handler for
#	TacticalWindow.
#	
#	Args:	TacticalWindow	pTactical	- the TacticalWindow object
#			TGMouseEvent	pEvent		- mouse event
#	
#	Return:	none
###############################################################################
def TextEntryMouseHandler (pSelf, pEvent):
	"Handle mouse events for the command interface"

	if (pEvent.EventHandled () == 0):
		if (pEvent.GetButtonNum() & App.TGMouseEvent.MEF_BUTTON_LEFT):
			if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
				# Give focus to the pane.
				
				pPara = App.TGParagraph_Cast (pSelf.GetNthChild (1))
				pPara.Resize (pSelf.GetWidth (), pSelf.GetHeight ())

	# Pass event to next handler.
	pSelf.CallNextHandler(pEvent)

def CreateVolumeButton (pName, eType, fValue, fWidth):
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pBar = App.STNumericBar_Create ()

	pBar.SetRange(0.0, 1.0)
	pBar.SetKeyInterval(0.1)
	pBar.SetMarkerValue(0.5)
	pBar.SetValue(fValue)
	pBar.SetUseMarker(0)
	pBar.SetUseAlternateColor(0)
	pBar.SetUseButtons(0)

	kNormalColor = App.g_kSTMenu3NormalBase
	kEmptyColor	= App.g_kSTMenu3Disabled

	pBar.SetNormalColor(kNormalColor)
	pBar.SetEmptyColor(kEmptyColor)
	pText = pBar.GetText();
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pText.SetStringW (pName)
	App.g_kLocalizationManager.Unload(pDatabase)

	pBar.Resize (fWidth, g_fButtonHeight, 0)

	pEvent = App.TGFloatEvent_Create ()
	pEvent.SetDestination(pOptionsWindow)
	pEvent.SetFloat (fValue)
	pEvent.SetEventType(eType)

	pBar.SetUpdateEvent(pEvent)

	return pBar


###############################################################################
#	CreateMenuToggleButton(pName, kStates, iDefault)
#	
#	Creates a toggle button for the options menu.
#	
#	Args:	pName - name of the button
#			kStates - set of tuples containing name, event type, and event
#				value (for an int event)
#			iDefault - default button state
#	
#	Return:	the newly-created button
###############################################################################
def CreateMenuToggleButton(pName, kStates, iDefault, fWidth):
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	kArgs = [pName, iDefault]

	for kStateName, eEventType, iEventValue in kStates:
		pEvent = App.TGIntEvent_Create()
		pEvent.SetEventType(eEventType)
		pEvent.SetDestination(pOptionsWindow)
		pEvent.SetInt(iEventValue)

		kArgs.append(kStateName)
		kArgs.append(pEvent)

	kMenuButton = apply(App.STToggle_CreateW, kArgs)

	return kMenuButton

###############################################################################
#	CreateMenuButton(pName, eType, iState)
#	
#	Creates a regular Star Trek button for the menu.
#	
#	Args:	pName - the name of the button
#			eType - event type to send when the button is activated
#			iState - the state of the button?
#	
#	Return:	the newly-created button
###############################################################################
def CreateMenuButton(pName, eType, iState, fWidth):
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pOptionsWindow)
	pEvent.SetInt(iState)

	MenuButton = App.STButton_CreateW(pName, pEvent)

	return MenuButton

###############################################################################
#	CreateMenuYesNoButton(pName, eType, iState)
#	
#	Creates a regular Star Trek button for the menu.
#	
#	Args:	pName - the name of the button
#			eType - event type to send when the button is activated
#			iState - the state of the button?
#	
#	Return:	the newly-created button
###############################################################################
def CreateMenuYesNoButton(pName, eType, iState, fWidth):
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pOptionsWindow)

	pMenuButton = App.STButton_CreateW(pName, pEvent)
	pEvent.SetSource (pMenuButton)

	pMenuButton.SetChoosable (1)
	pMenuButton.SetAutoChoose (1)
	if (iState):
		pMenuButton.SetChosen (1)
	else:
		pMenuButton.SetChosen (0)

	return pMenuButton

###############################################################################
#	CreateMenuButtonString(pName, eType, iState)
#	
#	Creates a regular Star Trek button for the menu.  Have
#	it send a string event.
#	
#	Args:	pName - the name of the button
#			eType - event type to send when the button is activated
#			sValue - The string value to give the event.
#	
#	Return:	the newly-created button
###############################################################################
def CreateMenuButtonString(pName, eType, sValue, fWidth):
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pEvent = App.TGStringEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pOptionsWindow)
	pEvent.SetString(sValue)

	pMenuButton = App.STButton_CreateW(pName)

	pEvent.SetSource(pMenuButton)
	pMenuButton.SetActivationEvent(pEvent)

	return pMenuButton

###############################################################################
#	Handle*Tab(pWindow, pEvent)
#	
#	Event handler for selecting the tabs at the top of the main menu. These
#	switch the appropriate pane into the middle area.
#	
#	Args:	pWindow		- the options window
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def HandleNewGameTab(pWindow, pEvent):
	SwitchMiddlePane("New Game")

def HandleTestGameTab(pWindow, pEvent):
	SwitchMiddlePane("Test Only")

def HandleConfigureTab(pWindow, pEvent):
	SwitchMiddlePane("Configure")

def HandleLoadGameTab(pWindow, pEvent):
	SwitchMiddlePane("Load Game")

def HandleSaveGameTab(pWindow, pEvent):
	SwitchMiddlePane("Save Game")

def HandleMultiplayerTab(pWindow, pEvent):
	SwitchMiddlePane("Multiplayer")

def HandleConfigureKeyboard(pWindow, pEvent):
	global g_pcConfigurePaneName
	g_pcConfigurePaneName = "keyboard"

	pConfigurePane = App.TGPane_Cast (pEvent.GetSource ())
	pSubTab = pConfigurePane.GetNthChild (1)
	if (pSubTab):
		pConfigurePane.DeleteChild (pSubTab)

	pOptionsPane = App.TGPane_Cast(pEvent.GetObjPtr())
	BuildConfigureKeyboardTab (pOptionsPane, pConfigurePane, pWindow);

	pWindow.CallNextHandler (pEvent)


def BuildConfigureKeyboardTab (pOptionsPane, pConfigurePane, pContentPane, bGameEnded = 0):
	pPane = KeyboardConfig.BuildKeyboardPane(pOptionsPane)
	pConfigurePane.AddChild (pPane)

	ToggleConfigureSelected (pContentPane, 3)

	global g_iMovieMode
	if (g_iMovieMode != 0):
		g_iMovieMode = 0
		PlayBackgroundMovie (1)


def HandleQuit (pWindow, pEvent):
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pMiddleArea = App.TGPane_Cast(pOptionsWindow.GetNthChild(1))

	if (g_kCurrentMiddlePane == 0 and pMiddleArea.GetNumChildren() > 0):
		NewGameLostFocus()

	# Before we actually quit, check to see if it's the multiplayer pane.
	# If it is, do some deinit before quitting
	Multiplayer.MultiplayerMenus.UnloadPreGameMenus ()
	# Play our Quit sound, then send an ET_QUIT event.
	pQuitEvent = App.TGIntEvent_Create()
	pQuitEvent.SetEventType(App.ET_QUIT)
	pQuitEvent.SetInt (0)
	pQuitEvent.SetDestination(pOptionsWindow)

	App.g_kEventManager.AddEvent (pQuitEvent)

	SaveConfig (None, None)

def SetHandlers ():
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	# Event types.
	lEventHandlerMap = (
		(ET_MAIN_MENU_NEW_GAME_TAB,				__name__ + ".HandleNewGameTab"),
		(ET_MAIN_MENU_EXIT_GAME_BUTTON,			__name__ + ".HandleExitGameButton"),
		(ET_MAIN_MENU_TEST_GAME_TAB,			__name__ + ".HandleTestGameTab"),
		(ET_MAIN_MENU_CONFIGURE_TAB,			__name__ + ".HandleConfigureTab"),
		(ET_MAIN_MENU_LOAD_GAME_TAB,			__name__ + ".HandleLoadGameTab"),
		(ET_MAIN_MENU_SAVE_GAME_TAB,			__name__ + ".HandleSaveGameTab"),
		(ET_MAIN_MENU_MULTIPLAYER_TAB,			__name__ + ".HandleMultiplayerTab"),
		(ET_MAIN_MENU_CREDITS_TAB,				__name__ + ".Credits"),
		(ET_MAIN_MENU_QUIT_TAB,	 				__name__ + ".HandleQuit"),
		(ET_SUBTITLE_TOGGLE,					__name__ + ".ToggleSubtitles"),
		(ET_TOOL_TIP_TOGGLE,					__name__ + ".ToggleToolTips"),
		(ET_COLLISION_ALERT_TOGGLE,				__name__ + ".ToggleCollisionAlert"),
		(ET_DIFFICULTY,							__name__ + ".SetDifficulty"),
		(ET_NEW_GAME_DIFFICULTY, 				__name__ + ".SetNewGameDifficulty"),
		(ET_SAVE_GAME,							__name__ + ".SaveGame"),
		(App.ET_ST_SAVE_DIALOG_SAVE,			__name__ + ".ReallySaveGame"),
		(ET_COLLISIONS_TOGGLE,					__name__ + ".ToggleCollisions"),
		(ET_FONT_SIZE_TOGGLE,					__name__ + ".ToggleFontSize"),
		(ET_VOICE_VOLUME,						__name__ + ".VoiceVolume"),
		(ET_SOUND_VOLUME,						__name__ + ".SoundVolume"),
		(ET_MUSIC_VOLUME,						__name__ + ".MusicVolume"),
		(ET_MUSIC_TOGGLE,						__name__ + ".MusicToggle"),
		(ET_SOUND_TOGGLE,						__name__ + ".SFXToggle"),
		(ET_VOICE_TOGGLE,						__name__ + ".VoiceToggle"),
		(ET_3D_SOUND_PREFS,						__name__ + ".SoundPrefs"),
		(ET_GRAPHICS_OPTIONS_MASTER,			__name__ + ".GraphicsMaster"),
		(ET_GRAPHICS_OPTIONS_MASTER_CONFIRMED,	__name__ + ".GraphicsMasterConfirmed"),
		(ET_GRAPHICS_OPTIONS_MASTER_CANCEL,		__name__ + ".GraphicsMasterCancel"),
		(ET_GRAPHICS_OPTIONS_VISIBLE_DAMAGE,	__name__ + ".GraphicsVisibleDamage"),
		(ET_GRAPHICS_OPTIONS_LOD,				__name__ + ".GraphicsLOD"),
		(ET_GRAPHICS_OPTIONS_SPACE_DUST,		__name__ + ".GraphicsSpaceDust"),
		(ET_GRAPHICS_OPTIONS_TEXTURE_DETAIL,	__name__ + ".GraphicsTextureDetail"),
		(ET_GRAPHICS_OPTIONS_TEXTURE_FILTER,	__name__ + ".GraphicsFilterQuality"),
		(ET_GRAPHICS_OPTIONS_GLOW,				__name__ + ".GraphicsGlow"),
		(ET_GRAPHICS_OPTIONS_ENHANCED_GLOW,		__name__ + ".GraphicsEnhancedGlow"),
		(ET_GRAPHICS_OPTIONS_SPECULAR,			__name__ + ".GraphicsSpecular"),
		(ET_GRAPHICS_OPTIONS_MOTION_BLUR,		__name__ + ".GraphicsMotionBlur"),
		(ET_GRAPHICS_OPTIONS_MIPMAPS,			__name__ + ".GraphicsMipMaps"),
		(ET_CANCEL_ENTER_NAME,					__name__ + ".CancelEnterName"),
		(ET_QUICK_BATTLE,						__name__ + ".QuickBattleHandler"),
		(ET_START_NEW_GAME,						__name__ + ".StartNewGameHandler"),
	)


	for eType, sFunc in lEventHandlerMap:
		# Add instance handlers for these events.
		pOptionsWindow.AddPythonFuncHandlerForInstance(eType, sFunc)

	# New game button handling.
	pOptionsWindow.AddPythonFuncHandlerForInstance(ET_START_GAME, "MainMenu.mainmenu.StartGame")

	# Test menu button handling.
	if App.g_kUtopiaModule.GetTestMenuState () >= 2:
		# Add event handlers for the mission buttons.
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E1M1,							"MainMenu.mainmenu.E1M1")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E1M2,							"MainMenu.mainmenu.E1M2")

		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E2M0,							"MainMenu.mainmenu.E2M0")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E2M1,							"MainMenu.mainmenu.E2M1")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E2M2,							"MainMenu.mainmenu.E2M2")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E2M3,							"MainMenu.mainmenu.E2M3")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E2M6,							"MainMenu.mainmenu.E2M6")

		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E3M1,							"MainMenu.mainmenu.E3M1")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E3M2,							"MainMenu.mainmenu.E3M2")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E3M4,							"MainMenu.mainmenu.E3M4")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E3M5,							"MainMenu.mainmenu.E3M5")

		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E4M1,							"MainMenu.mainmenu.E4M1")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E4M3,							"MainMenu.mainmenu.E4M3")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E4M4,							"MainMenu.mainmenu.E4M4")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E4M5,							"MainMenu.mainmenu.E4M5")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E4M6,							"MainMenu.mainmenu.E4M6")

		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E5M1,							"MainMenu.mainmenu.E5M1")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E5M2,							"MainMenu.mainmenu.E5M2")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E5M3,							"MainMenu.mainmenu.E5M3")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E5M4,							"MainMenu.mainmenu.E5M4")

		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E6M1,							"MainMenu.mainmenu.E6M1")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E6M2,							"MainMenu.mainmenu.E6M2")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E6M3,							"MainMenu.mainmenu.E6M3")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E6M4,							"MainMenu.mainmenu.E6M4")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E6M5,							"MainMenu.mainmenu.E6M5")

		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E7M1,							"MainMenu.mainmenu.E7M1")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E7M2,							"MainMenu.mainmenu.E7M2")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E7M3,							"MainMenu.mainmenu.E7M3")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E7M4,							"MainMenu.mainmenu.E7M4")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E7M5,							"MainMenu.mainmenu.E7M5")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E7M6,							"MainMenu.mainmenu.E7M6")

		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E8M1,							"MainMenu.mainmenu.E8M1")
		pOptionsWindow.AddPythonFuncHandlerForInstance(ET_E8M2,							"MainMenu.mainmenu.E8M2")

	pOptionsWindow.AddPythonFuncHandlerForInstance(ET_CUSTOM_MISSION,					"MainMenu.mainmenu.HandleCustomMission")

	pOptionsWindow.AddPythonFuncHandlerForInstance(ET_UPDATE_JUNK_TEXT, __name__ + ".UpdateJunkTextHandler")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_UI_SWITCH_ICON_GROUPS, 
													  pOptionsWindow, __name__ + ".HandleSwitchIconGroups")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_UI_REPOSITION, 
													  pOptionsWindow, __name__ + ".HandleSwitchRes")
	#	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ST_LOAD_DIALOG_LOAD,
	#													  pOptionsWindow, __name__ + ".HandleLoadGameButton")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_GAME_LOADED,
													  pOptionsWindow, __name__ + ".GameLoaded")


###############################################################################
#	HandleKeyboardOpening(pPane, pEvent)
#	
#	Keyboard handler for the opening movie sequence.
#	
#	Args:	pPane		- the pane
#			pEvent		- the keyboard event
#	
#	Return:	none
###############################################################################
def HandleKeyboardOpening(pPane, pEvent):
	# Get the information we need about the key so we can
	# look it up in the table..
	eKeyType = pEvent.GetKeyState()
	cCharCode = pEvent.GetUnicode()

	global g_idOpeningSequence
	global g_idOpeningMovieSequence
	global g_idOpeningCreditsSequence

	pOpeningSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idOpeningSequence))
	pOpeningMovieSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idOpeningMovieSequence))
	pOpeningCreditsSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idOpeningCreditsSequence))

	if eKeyType == App.TGKeyboardEvent.KS_KEYUP:
		if (cCharCode == App.WC_ESCAPE):
			if (pOpeningSequence):
				pOpeningSequence.Skip()
			if (pOpeningMovieSequence):
				pOpeningMovieSequence.Skip()
#				App.TGActionManager_SkipEvents()
			if (pOpeningCreditsSequence):
				pOpeningCreditsSequence.Skip()

			g_idOpeningSequence = App.NULL_ID
			g_idOpeningMovieSequence = App.NULL_ID
			g_idOpeningCreditsSequence = App.NULL_ID

			FinishOpeningMovie(None)

 			pEvent.SetHandled()
		elif (cCharCode == App.WC_SPACE or cCharCode == App.WC_BACKSPACE or cCharCode == App.WC_RETURN):
			if (pOpeningSequence):
				App.TGActionManager_SkipEvents()
			elif (pOpeningMovieSequence):
				pOpeningMovieSequence.Skip ()
				OpeningCredits (None)
			elif (pOpeningCreditsSequence):
				pOpeningCreditsSequence.Skip()
				g_idOpeningCreditsSequence = App.NULL_ID
				FinishOpeningMovie(None)

 			pEvent.SetHandled()

	if (pEvent.EventHandled() == 0):
		pPane.CallNextHandler(pEvent)


###############################################################################
#	BuildMainMenu()
#	
#	Plays opening movies and then builds the main menu interface.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def BuildMainMenu():
	SetHandlers()

###############################################################################
#	PlayOpeningMovies()
#	
#	Play our opening movies...
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def PlayOpeningMovies():
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	pTopWindow.SetNotVisible ()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	App.InterfaceModule_DoTheRightThing()

	global g_idMoviePane
	pMoviePane = App.TGPane_Create (1.0, 1.0)
	g_idMoviePane = pMoviePane.GetObjID()

	global g_idMoviePane2
	pMoviePane2 = App.TGPane_Create (1.0, 1.0)
	g_idMoviePane2 = pMoviePane2.GetObjID()

	App.g_kRootWindow.PrependChild(pMoviePane2, 0.00375, 0.005)	# stick it in front
	App.g_kRootWindow.PrependChild(pMoviePane)	# stick it in front

	pMoviePane2.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,	__name__ + ".HandleKeyboardOpening")

	StopBackgroundMovies ()

	pSequence = App.TGSequence_Create()

	# Play the titles/logos movie
	pParamount = App.TGMovieAction_Create("data/Movies/Paramount.bik", 1, 1)
	pParamount.SetSkippable(1)
	pSequence.AddAction(pParamount)

	pActivision = App.TGMovieAction_Create("data/Movies/Activision.bik", 1, 1)
	pActivision.SetSkippable(1)
	pSequence.AppendAction(pActivision)

	pTotallyGames = App.TGMovieAction_Create("data/Movies/TG.bik", 1, 1)
	pTotallyGames.SetSkippable(1)
	pSequence.AppendAction(pTotallyGames)

	pAction = App.TGMovieAction_Create("data/Movies/BCLogo.bik", 1, 1)
	pAction.SetSkippable(1)
	pSequence.AppendAction(pAction)

	# Play the opening cut scene
	pSequence.AppendAction(App.TGScriptAction_Create("MainMenu.mainmenu", "OpeningMovie"))

	global g_idOpeningSequence
	g_idOpeningSequence = pSequence.GetObjID()

	pSequence.Play()


###############################################################################
#	MovieSubtitle()
#	
#	Show a movie subtitle
#	
#	Args:	sLine		- line to display
#			fStart		- time at which to start displaying (seconds from start of pSeq)
#			fDuration	- length of time to stay up (seconds, starting from fTime)
#			pSeq		- TGSequence to which to add us
#	
#	Return:	none
###############################################################################
def MovieSubtitle(sLine, fStart, fDuration, pSeq):
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))
	if (sLine == None) or (not pCreditPane):
		return

	sString = g_pCreditDatabase.GetString(sLine)
	if (sString == None):
		return

	# makes our TGCreditAction_Create() shorter
	iCenter = App.TGCreditAction.JUSTIFY_CENTER
	iTop = App.TGCreditAction.JUSTIFY_TOP

	pAction = App.TGCreditAction_Create(sString, pCreditPane, 0.00, 0.927, fDuration, 0.25, 0.25, 6, iCenter, iTop)
	pSeq.AddFrameAction(pAction, fStart)


###############################################################################
#	OpeningMovie()
#	
#	Show the opening movie with subtitles
#	
#	Args:	pAction - the script action that may have called this function
#	
#	Return:	none
###############################################################################
def OpeningMovie(pAction):
	global g_idOpeningSequence, g_pCreditDatabase, g_idCreditPane
	g_idOpeningSequence = App.NULL_ID
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMoviePane))
	if not pCreditPane:
		return 0

	g_idCreditPane = pCreditPane.GetObjID()
	App.TGCreditAction_SetDefaultColor(1.0, 1.0, 1.0, 1.0)
	g_pCreditDatabase = App.g_kLocalizationManager.Load("data/TGL/Open.tgl")

	pSequence = App.TGSequence_Create()

	pMovieSequence = App.TGSequence_Create()
	pSequence.AddAction(pMovieSequence)

	pOpenMovie = App.TGMovieAction_Create("data/Movies/Opening.bik", 1, 1)
	pMovieSequence.AddAction(pOpenMovie)

	# Subtitles.
	MovieSubtitle("OpenCaptain01.wav",	52,   10.5, pOpenMovie)
	MovieSubtitle("OpenCaptain01a.wav",	225,  3.0, pOpenMovie)
	MovieSubtitle("OpenCaptain03.wav",  285,  7.5, pOpenMovie)
	MovieSubtitle("OpenCaptain03a.wav", 405,  7.5, pOpenMovie)
	MovieSubtitle("OpenCaptain04.wav",  525,  8.5, pOpenMovie)
	MovieSubtitle("OpenMiguel01.wav",   675,  5.5, pOpenMovie)
	MovieSubtitle("OpenKiska01.wav",    780,  4.0, pOpenMovie)
	MovieSubtitle("OpenCaptain05.wav",  870,  7.0, pOpenMovie)
	MovieSubtitle("OpenKiska02.wav",   1080,  3.5, pOpenMovie)
	MovieSubtitle("OpenKiska03.wav",   1245,  3.5, pOpenMovie)
	MovieSubtitle("OpenMiguel02.wav",  1410,  4.5, pOpenMovie)
	MovieSubtitle("OpenKiska04.wav",   1590,  5.5, pOpenMovie)

	pSequence.AppendAction(App.TGScriptAction_Create("MainMenu.mainmenu", "OpeningCredits"))
	pSequence.Play()

	global g_idOpeningMovieSequence
	g_idOpeningMovieSequence = pSequence.GetObjID()

	App.g_kLocalizationManager.Unload(g_pCreditDatabase)
	g_pCreditDatabase = None
	g_idCreditPane = App.NULL_ID

	return 0



###############################################################################
#	OpeningMovieCredit()
#	
#	Show an opening movie credit with a drop shadow
#	
#	Args:	sString		- string to display
#			pSeq		- TGSequence to which to add us
#			fPos		- float position in multi-credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Expects the globals g_iAlignment, g_idCreditPane, g_idShadowPane,
#	g_pCreditDatabase, g_fTitleLeft, g_fNameLeft and g_fCreditDelay
#	to be set correctly
#
#	Return:	none
###############################################################################
def OpeningMovieCredit(sString, pSeq, fPos = 2, iFontIndex = 2):
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))
	pShadowPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idShadowPane))
	if (sString == None) or (not pCreditPane) or (not pShadowPane):
		return

	iFontSize = GetCreditFontSize(iFontIndex)
	fHeight = fPos * 0.0375

	# Alignment
	iTop = App.TGCreditAction.JUSTIFY_TOP
	if (g_iAlignment == 0):
		iAlign = App.TGCreditAction.JUSTIFY_LEFT
		fLeft = g_fTitleLeft	
	elif (g_iAlignment == 1):
		iAlign = App.TGCreditAction.JUSTIFY_CENTER
		fLeft = 0.5
	elif (g_iAlignment == 2):
		iAlign = App.TGCreditAction.JUSTIFY_RIGHT
		fLeft = g_fNameLeft

	# Normal
	pSeq.AddAction(App.TGCreditAction_CreateSTR(sString, pCreditPane, fLeft, fHeight, g_fCreditDelay, 0.25, 0.5, iFontSize, iAlign, iTop))

	# Drop shadow version
	App.TGCreditAction_SetDefaultColor(0.00, 0.00, 0.00, 1.00)
	pSeq.AddAction(App.TGCreditAction_CreateSTR(sString, pShadowPane, fLeft, fHeight, g_fCreditDelay, 0.25, 0.5, iFontSize, iAlign, iTop))
	App.TGCreditAction_SetDefaultColor(0.65, 0.65, 1.00, 1.00)



###############################################################################
#	OpeningMovieDatabaseCredit()
#	
#	Show an opening movie credit with a drop shadow, from the database
#	
#	Args:	sStringID	- string ID in database to look up
#			pSeq		- TGSequence to which to add us
#			fPos		- float position in multi-credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Expects the globals g_iAlignment, g_idCreditPane, g_idShadowPane,
#	g_pCreditDatabase, g_fTitleLeft, g_fNameLeft and g_fCreditDelay
#	to be set correctly
#
#	Return:	none
###############################################################################
def OpeningMovieDatabaseCredit(sStringID, pSeq, fPos = 2, iFontIndex = 2):
	sString = None
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))
	pShadowPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idShadowPane))

	if (not pCreditPane) or (not pShadowPane):
		return

	if (sStringID):
		sString = g_pCreditDatabase.GetString(sStringID)
	if (sString == None):
		return

	iFontSize = GetCreditFontSize(iFontIndex)
	fHeight = fPos * 0.0375

	# Alignment
	iTop = App.TGCreditAction.JUSTIFY_TOP
	if (g_iAlignment == 0):
		iAlign = App.TGCreditAction.JUSTIFY_LEFT
		fLeft = g_fTitleLeft	
	elif (g_iAlignment == 1):
		iAlign = App.TGCreditAction.JUSTIFY_CENTER
		fLeft = 0.5
	elif (g_iAlignment == 2):
		iAlign = App.TGCreditAction.JUSTIFY_RIGHT
		fLeft = g_fNameLeft

	# Normal
	pSeq.AddAction(App.TGCreditAction_Create(sString, pCreditPane, fLeft, fHeight, g_fCreditDelay, 0.25, 0.5, iFontSize, iAlign, iTop))

	# Drop shadow version
	App.TGCreditAction_SetDefaultColor(0.00, 0.00, 0.00, 1.00)
	pSeq.AddAction(App.TGCreditAction_Create(sString, pShadowPane, fLeft, fHeight, g_fCreditDelay, 0.25, 0.5, iFontSize, iAlign, iTop))
	App.TGCreditAction_SetDefaultColor(0.65, 0.65, 1.00, 1.00)



###############################################################################
#	OpeningCredits()
#	
#	Show the opening credits with a movie under them
#	
#	Args:	pAction - the script action that may have called this function
#	
#	Return:	none
###############################################################################
def OpeningCredits(pAction):
	global g_idOpeningMovieSequence
	g_idOpeningMovieSequence = App.NULL_ID

	global g_idCreditPane, g_idShadowPane, g_pCreditDatabase, g_fCreditDelay
	global g_fTitleLeft, g_fNameLeft, g_iAlignment

	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMoviePane))
	pShadowPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMoviePane2))
	if (not pCreditPane) or (not pShadowPane):
		return 0

	g_idCreditPane = pCreditPane.GetObjID()
	g_idShadowPane = pShadowPane.GetObjID()

	pcMovieName = "data/Movies/back.bik"

	g_pCreditDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	App.TGCreditAction_SetDefaultColor(0.65, 0.65, 1.0, 1.0)
	fSpacing = 0.0375

	pMainSequence = App.TGSequence_Create()

	pSequence = App.TGSequence_Create()
	pMainSequence.AddAction(pSequence)

	pMovie = App.TGMovieAction_Create(pcMovieName, 1, 1)

	# General left and right margins
	g_fTitleLeft = 0.01
	g_fNameLeft = 0.99
	
	pSequence.AddAction(pMovie)
	g_iAlignment = 1		# Center it
	g_fCreditDelay = 3		# 3 second credit
	pSubSeq = App.TGSequence_Create()
	OpeningMovieCredit("Totally Games",				pSubSeq,  3.0, 4)
	pMovie.AddFrameAction(pSubSeq, 1)

	g_fCreditDelay = 4	# These credits stay up for 4 seconds

	# Creative director
	pSubSeq = App.TGSequence_Create()
	g_iAlignment = 0		# Left justify
	OpeningMovieDatabaseCredit("Creative Director",	pSubSeq, 22.0)
	OpeningMovieCredit("Lawrence Holland",			pSubSeq, 23.0, 3)
	pMovie.AddFrameAction(pSubSeq, 62)

	# Project lead
	pSubSeq = App.TGSequence_Create()
	g_iAlignment = 2		# Right justify
	OpeningMovieDatabaseCredit("Project Lead",		pSubSeq, 21.0)
	OpeningMovieDatabaseCredit("GSP",				pSubSeq, 22.0)
	OpeningMovieCredit("David Litwin",				pSubSeq, 23.0, 3)
	pMovie.AddFrameAction(pSubSeq, 135)

	# programming
	pSubSeq = App.TGSequence_Create()
	g_iAlignment = 0		# Left justify
	OpeningMovieDatabaseCredit("Programmers", pSubSeq, 17.5)
	OpeningMovieCredit("Albert Mack",				pSubSeq, 19.0)
	OpeningMovieCredit("Kevin Deus",				pSubSeq, 20.0)
	OpeningMovieCredit("James Therien",				pSubSeq, 21.0)
	OpeningMovieCredit("Erik Novales",				pSubSeq, 22.0)
	OpeningMovieCredit("Colin Carley",				pSubSeq, 23.0)
	pMovie.AddFrameAction(pSubSeq, 215)

	# Design lead
	pSubSeq = App.TGSequence_Create()
	OpeningMovieDatabaseCredit("Game Design Lead",	pSubSeq, 22.0)
	OpeningMovieCredit("Bill Morrison",				pSubSeq, 23.0)
	pMovie.AddFrameAction(pSubSeq, 290)

	# Game Design
	pSubSeq = App.TGSequence_Create()
	OpeningMovieDatabaseCredit("Game Design",		pSubSeq, 19.5)
	OpeningMovieCredit("Jess VanDerwalker",			pSubSeq, 21.0)
	OpeningMovieCredit("Benjamin Schulson",			pSubSeq, 22.0)
	OpeningMovieCredit("Tony Evans",				pSubSeq, 23.0)
	pMovie.AddFrameAction(pSubSeq, 365)

	# Art lead
	pSubSeq = App.TGSequence_Create()
	g_iAlignment = 2		# Right justify
	OpeningMovieDatabaseCredit("Art Lead",			pSubSeq, 22.0)
	OpeningMovieCredit("Armand Cabrera",			pSubSeq, 23.0)
	pMovie.AddFrameAction(pSubSeq, 440)

	# Artists
	pSubSeq = App.TGSequence_Create()
	g_iAlignment = 2		# Right justify
	OpeningMovieDatabaseCredit("Artists",			pSubSeq, 18.5)
	OpeningMovieCredit("Richard Green",				pSubSeq, 20.0)
	OpeningMovieCredit("Anthony Hon",				pSubSeq, 21.0)
	OpeningMovieCredit("Victor Bennett",			pSubSeq, 22.0)
	OpeningMovieCredit("Matt Bein",					pSubSeq, 23.0)
	pMovie.AddFrameAction(pSubSeq, 515)

	g_fCreditDelay = 2.75	# These credits stay up for 2.75 seconds
	
	# Production coordinator
	pSubSeq = App.TGSequence_Create()
	g_iAlignment = 0		# Left justify
	OpeningMovieDatabaseCredit("Proj Coord",		pSubSeq,  3.0)
	OpeningMovieCredit("Mike Hawkins",				pSubSeq,  4.5)
	pMovie.AddFrameAction(pSubSeq, 680)

	# QA lead
	pSubSeq = App.TGSequence_Create()
	g_iAlignment = 0		# Left justify
	OpeningMovieDatabaseCredit("QA Lead",			pSubSeq, 22.0)
	OpeningMovieCredit("Evan Birkby",				pSubSeq, 23.0)
	pMovie.AddFrameAction(pSubSeq, 770)

	# QA
	pSubSeq = App.TGSequence_Create()
	OpeningMovieDatabaseCredit("QA",				pSubSeq,  3.0)
	OpeningMovieCredit("Shawn Refoua",				pSubSeq,  4.5)
	OpeningMovieCredit("Christopher Charles",		pSubSeq,  5.5)
	pMovie.AddFrameAction(pSubSeq, 838)

	# Activision
	pSubSeq = App.TGSequence_Create()
	OpeningMovieDatabaseCredit("Sen Producer",		pSubSeq,  3.0)
	OpeningMovieCredit("Parker A. Davis",			pSubSeq,  4.0)
	OpeningMovieDatabaseCredit("Assoc Producer",	pSubSeq,  6.0)
	OpeningMovieCredit("Glenn Ige",					pSubSeq,  7.0)
	g_iAlignment = 2		# Right justify
	OpeningMovieDatabaseCredit("Prod Staff",		pSubSeq,  3.0)
	OpeningMovieCredit("Aaron Gray",				pSubSeq,  4.5)
	OpeningMovieCredit("Douglas Mirabello",			pSubSeq,  5.5)
	OpeningMovieCredit("Timothy Ogle",				pSubSeq,  6.5)
	pMovie.AddFrameAction(pSubSeq, 900)

	pMainSequence.AppendAction(App.TGScriptAction_Create("MainMenu.mainmenu", "FinishOpeningMovie"), 2.0)
	pMainSequence.Play()

	global g_idOpeningCreditsSequence
	g_idOpeningCreditsSequence = pMainSequence.GetObjID()

	App.g_kLocalizationManager.Unload(g_pCreditDatabase)
	g_pCreditDatabase = None
	g_idCreditPane = App.NULL_ID
	g_idShadowPane = App.NULL_ID

	return 0

###############################################################################
#	FinishOpeningMovie()
#	
#	Clean up after the opening movie
#	
#	Args:	pAction - the script action that may have called this function
#	
#	Return:	none
###############################################################################
def FinishOpeningMovie(pAction):
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	global g_idMoviePane
	pMoviePane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMoviePane))
	if pMoviePane:
		App.g_kRootWindow.DeleteChild(pMoviePane)

	g_idMoviePane = App.NULL_ID

	global g_idMoviePane2
	pMoviePane2 = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idMoviePane2))
	if pMoviePane2:
		App.g_kRootWindow.DeleteChild(pMoviePane2)
	
	g_idMoviePane2 = App.NULL_ID

	global g_idCreditsSequence
	g_idCreditsSequence = App.NULL_ID

	StopBackgroundMovies ()

	App.g_kMovieManager.SwitchOutOfMovieMode()
	
	pTopWindow.SetVisible ()

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	pOptionsWindow.SetVisible()

	# Ensure that the volume for movies is set, now that the opening movies are done.
	if App.g_kSoundManager.IsSFXEnabled():
		App.g_kMovieManager.SetMovieVolume( App.g_kSoundManager.GetInterfaceVolume() )

	BuildInterface()

	# Start initial music.
	StartMusic()
	
	return 0


###############################################################################
#	StartMusic()
#	
#	Start the interactive music
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def StartMusic():
	App.g_kMusicManager.LoadMusic("sfx/Music/Episode 2.mp3", "Startup Music")
	App.g_kMusicManager.StartMusic("Startup Music")

def BuildInterface():
	# Change the font size based on the new res.
	global g_iRes
	if (App.g_kIconManager.GetScreenWidth () == 640):
		g_iRes = 0
	elif (App.g_kIconManager.GetScreenWidth () == 800):
		g_iRes = 1
	elif (App.g_kIconManager.GetScreenWidth () == 1024):
		g_iRes = 2
	elif (App.g_kIconManager.GetScreenWidth () == 1280):
		g_iRes = 3
	elif (App.g_kIconManager.GetScreenWidth () == 1600):
		g_iRes = 4
	else:
		g_iRes = 0
	
	App.g_kFontManager.SetDefaultFont(g_pcSmallFont, g_kSmallFontSize [g_iRes])

	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	pOptionsWindow.KillChildren()
	pOptionsWindow.Resize(1.0, 1.0, 0)
	pOptionsWindow.SetPosition(0.0, 0.0, 0)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	pTopArea = BuildMainMenuTopSection()

	pMiddleArea = BuildMiddlePane(pDatabase.GetString("New Game"))

	pOptionsWindow.AddChild(pTopArea, 0, 0, 0)
	pOptionsWindow.AddChild(pMiddleArea, 0, 0.19 + g_fVerticalSpacing * 2.0, 0)

	SwitchMiddlePane("New Game")

	pOptionsGlass = App.TGPane_Create(pOptionsWindow.GetWidth(), pOptionsWindow.GetHeight())
	pOptionsGlass.SetAlwaysHandleEvents()
	pOptionsWindow.AddChild(pOptionsGlass)

	App.g_kLocalizationManager.Unload(pDatabase)

	BuildTabOrder(pOptionsWindow)

###############################################################################
#	CreateSubtitleWindow()
#	
#	Code to create the subtitle window
#	
#	Args:	none
#	
#	Return:	a pointer to the subtitle window
###############################################################################
def CreateSubtitleWindow():
	# Create Subtitle Window.
	pSubtitle = App.SubtitleWindow_Create()
	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.AddChild(pSubtitle)
	pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_NONFELIX)

	# Temporarily start off with Subtitles on
	pSubtitle.SetOn()

	return pSubtitle

###############################################################################
#	SwitchMiddlePane(pcNewPaneName, bGameEnded)
#	
#	Switches the middle pane to be the pane of the type you specify. Don't
#	pass a pane, rather, pass one of the following strings:
#		"New Game"		- the new game pane
#		"Load Game"		- the load game pane
#		"Save Game"		- the save game pane
#		"Configure"		- the configure pane
#		"Multiplayer"	- multiplayer pane
#		"Test Only"		- Something to access all missions, for testing purposes only
#
#	Note that the string is also used to query the TGL for the
#	text that should appear in the background.
#	
#	Args:	pcNewPaneName - a string corresponding to one of the above.
#	
#	Return:	none
###############################################################################
def SwitchMiddlePane(pcNewPaneName, bGameEnded = 0):
	global g_kCurrentMiddlePane

	global g_iRes
	if (App.g_kIconManager.GetScreenWidth () == 640):
		g_iRes = 0
	elif (App.g_kIconManager.GetScreenWidth () == 800):
		g_iRes = 1
	elif (App.g_kIconManager.GetScreenWidth () == 1024):
		g_iRes = 2
	elif (App.g_kIconManager.GetScreenWidth () == 1280):
		g_iRes = 3
	elif (App.g_kIconManager.GetScreenWidth () == 1600):
		g_iRes = 4
	else:
		g_iRes = 0
	
	App.g_kFontManager.SetDefaultFont(g_pcSmallFont, g_kSmallFontSize [g_iRes])

	# Before we actually switch, check to see if it's the multiplayer pane.
	# If it is, do some deinit before killing the children
	Multiplayer.MultiplayerMenus.UnloadPreGameMenus()

	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	if (pOptionsWindow == None):
		return
	pTopSection = App.TGPane_Cast (pOptionsWindow.GetNthChild (0))
	if (pTopSection == None):
		return
	pTopButtonPane = App.TGPane_Cast (pTopSection.GetNthChild (0))
	if (pTopButtonPane == None):
		return

	# We don't want the old pane, and we're going to rebuild the background
	# anyhow...
	pMiddleArea = App.TGPane_Cast(pOptionsWindow.GetNthChild(1))

	if (g_kCurrentMiddlePane == 0 and pMiddleArea.GetNumChildren() > 0):
		NewGameLostFocus()

	# Remove any focus entries that were there.
	App.g_kFocusManager.RemoveAllObjectsUnder(pMiddleArea)
	pMiddleArea.KillChildren()

	global g_idJunkText1
	global g_idJunkText2
	global g_idJunkText3
	global g_idJunkText4

	g_idJunkText1 = App.NULL_ID
	g_idJunkText2 = App.NULL_ID
	g_idJunkText3 = App.NULL_ID
	g_idJunkText4 = App.NULL_ID

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	# Build the pane, based on the name.
	global g_bListPane
	g_bListPane = 0

	global g_pcCurrentPaneName
	g_pcCurrentPaneName = pcNewPaneName

	iFocus = 0

	global g_iMovieMode

	if (pcNewPaneName == "New Game"):
		pPane = BuildNewGamePane()
		pButton = pTopButtonPane.GetNthChild (0)
		pTopButtonPane.SetFocus (pButton)
		g_kCurrentMiddlePane = 0
		iFocus = 0
		if (g_iMovieMode != 2):
			g_iMovieMode = 2
			PlayBackgroundMovie (1)
		pTopButtonPane.SetVisible ()

	elif (pcNewPaneName == "Test Only"):
		pcNewPaneName = "New Game"
		pPane = BuildTestGamePane()
		pButton = pTopButtonPane.GetNthChild (5)
		pTopButtonPane.SetFocus (pButton)
		iFocus = 5
		g_kCurrentMiddlePane = 6
		if (g_iMovieMode != 0):
			g_iMovieMode = 0
			PlayBackgroundMovie (1)
		pTopButtonPane.SetVisible ()

	elif (pcNewPaneName == "Multiplayer"):
		pPane = Multiplayer.MultiplayerMenus.BuildMultiplayerPreGameMenus(
									not g_bMultiplayerMenusRebuiltAfterResChange)

		global g_bMultiplayerMenusRebuiltAfterResChange
		if not g_bMultiplayerMenusRebuiltAfterResChange:
			g_bMultiplayerMenusRebuiltAfterResChange = 1
			# Move the main menu to the front
			pMain = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
			pMain.SetVisible(0)
			pTopWindow.MoveToFront(pMain, 0)

		pButton = pTopButtonPane.GetNthChild (1)
		pTopButtonPane.SetFocus (pButton)
		g_kCurrentMiddlePane = 6
		iFocus = 1
		if (g_iMovieMode != 0):
			g_iMovieMode = 0
			PlayBackgroundMovie (1)

		pTopButtonPane.SetNotVisible ()

	elif (pcNewPaneName == "Load Game"):
		pPane = App.STLoadDialog_Create(LCARS.MAIN_MENU_MIDDLE_PANE_WIDTH, 
										LCARS.MAIN_MENU_MIDDLE_PANE_HEIGHT)
		pMenu = pPane.GetFileMenu()

		pMenu.SetDir("saves\\")
		pMenu.SetFilter("*.BCS")
		pPane.RefreshFileList()

		pButton = pTopButtonPane.GetNthChild (1)
		pTopButtonPane.SetFocus (pButton)
		iFocus = 4
		g_kCurrentMiddlePane = 2
		g_bListPane = 1
		if (g_iMovieMode != 1):
			g_iMovieMode = 1
			PlayBackgroundMovie (1)
		pTopButtonPane.SetVisible ()

	elif (pcNewPaneName == "Save Game"):
		pPane = App.STSaveDialog_Create(LCARS.MAIN_MENU_MIDDLE_PANE_WIDTH,
										LCARS.MAIN_MENU_MIDDLE_PANE_HEIGHT)
		pMenu = pPane.GetFileMenu()

		pMenu.SetDir("saves\\")
		pMenu.SetFilter("*.BCS")
		pPane.RefreshFileList()

		pButton = pTopButtonPane.GetNthChild(3)
		pTopButtonPane.SetFocus (pButton)
		iFocus = 3
		g_kCurrentMiddlePane = 3
		g_bListPane = 1
		g_iMovieMode = 1
		if (g_iMovieMode != 1):
			g_iMovieMode = 1
			PlayBackgroundMovie (1)
		pTopButtonPane.SetVisible ()

	elif (pcNewPaneName == "Configure"):
		pPane = BuildConfigurePane(bGameEnded)
		pButton = pTopButtonPane.GetNthChild (2)
		pTopButtonPane.SetFocus (pButton)
		iFocus = 2
		g_kCurrentMiddlePane = 4
		g_bListPane = 1

#		g_iMovieMode = 0
#		if (g_iMovieMode != 0):
#			g_iMovieMode = 0
#			PlayBackgroundMovie (1)
		pTopButtonPane.SetVisible ()

	for i in range(8):
		pButton = App.STRoundedButton_Cast (pTopButtonPane.GetNthChild (i))
		if (i == iFocus):
			pButton.SetSelected (0)
		else:
			pButton.SetNotSelected (0)

	if pcNewPaneName == "Multiplayer":
		# If we're bringing up the multiplayer menu, we're greedy -- we want
		# the whole screen, not just the middle pane.
		if (pOptionsWindow.FindPos (pPane) != -1):
			pOptionsWindow.RemoveChild (pPane)	

		pOptionsWindow.AddChild(pPane)
		pOptionsWindow.SetFocus(pPane)
		pOptionsWindow.MoveToFront(pPane)
	else:
		# Build the background.
		pBackground = BuildMiddleBackground(pDatabase.GetString(pcNewPaneName), g_bListPane)

		pMiddleArea.AddChild(pPane)
		pMiddleArea.AddChild(pBackground)

		pOptionsWindow.SetFocus(pMiddleArea)
		pMiddleArea.SetFocus(pPane)

	App.g_kLocalizationManager.Unload(pDatabase)

###############################################################################
#	RebuildMiddleBackground(kString)
#	
#	Rebuilds the middle's background area, changing the string used for the
#	name.
#	
#	Args:	kString	- TGString of the new name
#	
#	Return:	none
###############################################################################
def RebuildMiddleBackground(kString):
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pMiddleArea = App.TGPane_Cast(pOptionsWindow.GetNthChild(1))
	pBackground = pMiddleArea.GetLastChild()
	if (pBackground != None):
		pOptionsWindow.RemoveChild(pBackground)
	pBackground = BuildMiddleBackground(kString)

	pMiddleArea.AddChild(pBackground, LCARS.MAIN_MENU_MIDDLE_PANE_X,
						 LCARS.MAIN_MENU_MIDDLE_PANE_Y)

###############################################################################
#	BuildMainMenuTopSection()
#	
#	Builds the top section of the main menu.
#	
#	Args:	none
#	
#	Return:	TGPane * - the pane for the top part of the main menu
###############################################################################
def BuildMainMenuTopSection():
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pTopPane = App.TGPane_Create (1.0, 0.1825 + g_fVerticalSpacing)

	# Create button pane.
	pButtonPane = BuildMainMenuTopButtonPane(pOptionsWindow)
	pTopPane.AddChild(pButtonPane, LCARS.MAIN_MENU_TOP_BUTTON_PANE_X,
					  LCARS.MAIN_MENU_TOP_BUTTON_PANE_Y, 0)

	pTopBackgroundPane = App.TGPane_Create(1.0 - g_fHorizontalSpacing * 2.0, 0.18541666)
	pTopBackgroundPane.SetNoFocus()
	pTopPane.AddChild(pTopBackgroundPane, g_fHorizontalSpacing, g_fVerticalSpacing, 0)

	# Create top bars
	fLeft = 0.0
	fTop = 0.0

	# Create top bar and main menu title
#	pThing = UIHelpers.CreateIcon (200, 0.145, 0.025, App.g_kMainMenuBorderBlock1Color)
#	pTopBackgroundPane.AddChild (pThing, fLeft, fTop, 0)
#	fLeft = fLeft + pThing.GetWidth () + g_fHorizontalSpacing

	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()
	pThing = App.TGIcon_Create(pcLCARS, 620)
	pTopBackgroundPane.AddChild (pThing, fLeft, fTop, 0)
	fLeft = fLeft + pThing.GetWidth () + g_fHorizontalSpacing

	pThing = UIHelpers.CreateIcon (200, 0.836875, 0.025, App.g_kMainMenuBorderBlock1Color)

	# Add version string.
	#pVersion = App.TGParagraph_Create(App.UtopiaModule_GetGameVersion())
	pVersion = App.TGParagraph_Create("")
	pVersion.SetColor(App.NiColorA_WHITE)
	pVersion.Layout()

	pTopBackgroundPane.AddChild(pVersion, fLeft + pThing.GetWidth() - pVersion.GetWidth() - (App.globals.DEFAULT_ST_INDENT_HORIZ * 8.0),
								   pThing.GetTop(), 0)

	pTopBackgroundPane.AddChild (pThing, 1.0 - pThing.GetWidth () - g_fHorizontalSpacing, fTop, 0)

	# Next row
	fTop = fTop + pThing.GetHeight () + g_fVerticalSpacing
	fLeft = 0.0

#	pCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_LEFT_CURVE, 0.145, 0.223125, 0.123333333, 0.135833333, App.g_kMainMenuBorderTopColor, 0.0425)
#	pTopBackgroundPane.AddChild (pCurve, fLeft, fTop, 0)
#	fLeft = fLeft + pCurve.GetWidth () + g_fHorizontalSpacing

	pCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_RIGHT_CURVE, 0.103125, 0.308125, 0.123333333, 0.135833333, App.g_kMainMenuBorderTopColor, 0.0425)
	pTopBackgroundPane.AddChild (pCurve, 1.0 - pCurve.GetWidth () - g_fHorizontalSpacing * 2.0, fTop, 0)
	fOuterIcon = UIHelpers.GetOuterIcon (pCurve)

	pThing = UIHelpers.CreateIcon (200, 0.223125, fOuterIcon.GetHeight (), App.g_kMainMenuBorderTopColor)
	pTopBackgroundPane.AddChild (pThing, fLeft, fTop + (pCurve.GetHeight () - fOuterIcon.GetHeight ()), 0)
	fLeft = fLeft + pThing.GetWidth () + g_fHorizontalSpacing

	pThing = UIHelpers.CreateIcon (200, 0.43625, fOuterIcon.GetHeight (), App.g_kMainMenuBorderBlock1Color)
	pTopBackgroundPane.AddChild (pThing, fLeft, fTop + (pCurve.GetHeight () - fOuterIcon.GetHeight ()), 0)
	fLeft = fLeft + pThing.GetWidth () + g_fHorizontalSpacing

	pTopPane.SetFocus(pButtonPane)

	App.g_kLocalizationManager.Unload(pDatabase)

	return(pTopPane)

###############################################################################
#	BuildMainMenuTopButtonPane(pEventHandlerObject)
#	
#	Builds the button pane for the top area of the main menu.
#	
#	Args:	pEventHandlerObject - the object to which we'll send our events
#	
#	Return:	TGPane * - the button pane
###############################################################################
def BuildMainMenuTopButtonPane(pEventHandlerObject):
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pButtonPane = App.TGPane_Create(LCARS.MAIN_MENU_TOP_BUTTON_PANE_WIDTH,
									LCARS.MAIN_MENU_TOP_BUTTON_PANE_HEIGHT)
	pButtonPane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,	__name__ + ".HandleKeyboardTopButtonArea")

	# ***FIXME: add interface handler to do proper keyboard movement

	## LAYOUT OF MENU
	##															##
	##	"NEW GAME"	"CONFIGURE"	"MULTIPLAYER"	"EXIT PROGRAM"	##
	##	"LOAD GAME"	"CREDITS"	"TEST ONLY"		"EXIT GAME"		##
	##															##

	# Child order:
	# New game, configure, multiplayer, quit, load game, credits, test only, exit game

	# Top row of buttons

	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pButtonPane)
	pEvent.SetDestination(pEventHandlerObject)
	pEvent.SetEventType(ET_MAIN_MENU_NEW_GAME_TAB)
	pNewGameButton = App.STRoundedButton_CreateW (pDatabase.GetString("New Game"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pNewGameButton.SetNormalColor(App.g_kMainMenuButtonColor)
	pNewGameButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	pNewGameButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pNewGameButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pNewGameButton.SetColorBasedOnFlags()
	pButtonPane.AddChild(pNewGameButton, 0.0, 0.0, 0)

	# multiplayer button
	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pButtonPane)
	pEvent.SetDestination(pEventHandlerObject)
	pEvent.SetEventType(ET_MAIN_MENU_MULTIPLAYER_TAB)
	pMultiplayerButton = App.STRoundedButton_CreateW (pDatabase.GetString("Multiplayer"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
													 LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pMultiplayerButton.SetNormalColor(App.g_kMainMenuButtonColor)
	pMultiplayerButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	pMultiplayerButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pMultiplayerButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pMultiplayerButton.SetColorBasedOnFlags()
	pButtonPane.AddChild(pMultiplayerButton, pNewGameButton.GetRight() + g_fButtonHorizontalSpacing, 0.0, 0)

	# Configure button.
	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pButtonPane)
	pEvent.SetDestination(pEventHandlerObject)
	pEvent.SetEventType(ET_MAIN_MENU_CONFIGURE_TAB)
	pConfigureButton = App.STRoundedButton_CreateW (pDatabase.GetString("Configure"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pConfigureButton.SetNormalColor(App.g_kMainMenuButtonColor)
	pConfigureButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	pConfigureButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pConfigureButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pConfigureButton.SetColorBasedOnFlags()
	pButtonPane.AddChild(pConfigureButton, pMultiplayerButton.GetRight() + g_fButtonHorizontalSpacing * 5, 0.0, 0)

	# Quit button.
	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(ET_MAIN_MENU_QUIT_TAB)
	pEvent.SetDestination(pEventHandlerObject)
	pQuitButton = App.STRoundedButton_CreateW (pDatabase.GetString("Quit"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pQuitButton.SetNormalColor(App.g_kMainMenuButtonColor)
	pQuitButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	pQuitButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pQuitButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pQuitButton.SetColorBasedOnFlags()
	pButtonPane.AddChild(pQuitButton, pConfigureButton.GetRight() + g_fButtonHorizontalSpacing, 0.0, 0)

	# Bottom row of buttons
	# Load game button
	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pButtonPane)
	pEvent.SetDestination(pEventHandlerObject)
	pEvent.SetEventType(ET_MAIN_MENU_LOAD_GAME_TAB)
	pLoadGameButton = App.STRoundedButton_CreateW (pDatabase.GetString("Load Game"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pLoadGameButton.SetNormalColor(App.g_kMainMenuButtonColor)
	pLoadGameButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	pLoadGameButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pLoadGameButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pLoadGameButton.SetColorBasedOnFlags()
	pButtonPane.AddChild(pLoadGameButton, 0.0, pNewGameButton.GetBottom() + g_fVerticalSpacing, 0)

	# (Test Only) New Game button
	if (App.g_kUtopiaModule.GetTestMenuState () == 0):
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(ET_QUICK_BATTLE)
		pEvent.SetDestination(pOptionsWindow)
		pTestOnlyButton = App.STRoundedButton_CreateW (pDatabase.GetString ("Quick Battle"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	else:
		pEvent = App.TGEvent_Create()
		pEvent.SetSource(pButtonPane)
		pEvent.SetDestination(pEventHandlerObject)
		pEvent.SetEventType(ET_MAIN_MENU_TEST_GAME_TAB)
		pTestOnlyButton = App.STRoundedButton_Create ("Test Only", pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pTestOnlyButton.SetNormalColor(App.g_kMainMenuButtonColor)
	pTestOnlyButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	pTestOnlyButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pTestOnlyButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pTestOnlyButton.SetColorBasedOnFlags()
	pButtonPane.AddChild(pTestOnlyButton, pLoadGameButton.GetRight() + g_fButtonHorizontalSpacing, pNewGameButton.GetBottom() + g_fVerticalSpacing, 0)

	# Credits button.
	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pButtonPane)
	pEvent.SetDestination(pEventHandlerObject)
	pEvent.SetEventType(ET_MAIN_MENU_CREDITS_TAB)
	pCreditsButton = App.STRoundedButton_CreateW (pDatabase.GetString("Credits"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pCreditsButton.SetNormalColor(App.g_kMainMenuButtonColor)
	pCreditsButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	pCreditsButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pCreditsButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pCreditsButton.SetColorBasedOnFlags()
	pButtonPane.AddChild(pCreditsButton, pTestOnlyButton.GetRight() + g_fButtonHorizontalSpacing * 5, pNewGameButton.GetBottom() + g_fVerticalSpacing, 0)

	# Resume button
	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pButtonPane)
	pEvent.SetDestination(pEventHandlerObject)
	pEvent.SetEventType(ET_MAIN_MENU_EXIT_GAME_BUTTON)
	pResumeButton = App.STRoundedButton_CreateW (pDatabase.GetString("Resume"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
													 LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pResumeButton.SetNormalColor(App.g_kMainMenuButtonColor)
	pResumeButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	pResumeButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pResumeButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pResumeButton.SetColorBasedOnFlags()
	pResumeButton.SetNotVisible()
	pButtonPane.AddChild(pResumeButton, pCreditsButton.GetRight() + g_fButtonHorizontalSpacing, pNewGameButton.GetBottom() + g_fVerticalSpacing, 0)
	global g_idResumeButton
	g_idResumeButton = pResumeButton.GetObjID()

	# Unload localization database.
	App.g_kLocalizationManager.Unload(pDatabase)

	return(pButtonPane)

###############################################################################
#	HandleExitGameButton()
#	
#	The user wises to quit their current game (but not the program)
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def HandleExitGameButton(pObject, pEvent):
#	pGame = App.Game_GetCurrentGame()
#	if (pGame):
#		pGame.Terminate()
	pTopWindow = App.TopWindow_GetTopWindow()
	if not (pTopWindow):
		return
	pTopWindow.ToggleOptionsMenu ()

	pObject.CallNextHandler (pEvent)

###############################################################################
#	GameStarted()
#	
#	A game has been started, enable the Exit Game button
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GameStarted():
	pTopWindow = App.TopWindow_GetTopWindow()
	if not (pTopWindow):
		return

	pResumeButton = App.STRoundedButton_Cast(App.TGObject_GetTGObjectPtr(g_idResumeButton))

	if pResumeButton:
		pResumeButton.SetEnabled()
		pResumeButton.SetVisible()

#	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
#	pTopPane = App.TGPane_Cast(pOptionsWindow.GetFirstChild())
#	if (pTopPane):
#		pButtonPane = App.TGPane_Cast(pTopPane.GetFirstChild())
#		if (pButtonPane):
#			pButton = App.STRoundedButton_Cast(pButtonPane.GetNthChild(7))
#			if (pButton):
#				pButton.SetVisible()


###############################################################################
#	GameEnded()
#	
#	A game has ended, disable the Exit Game button
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def GameEnded():
	pTopWindow = App.TopWindow_GetTopWindow()
	if not (pTopWindow):
		return

	pResumeButton = App.STRoundedButton_Cast(App.TGObject_GetTGObjectPtr(g_idResumeButton))

	if pResumeButton:
		pResumeButton.SetNotVisible()

	# start up main menu music.
	App.g_kMusicManager.StartMusic("Startup Music")

#	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
#	pTopPane = App.TGPane_Cast(pOptionsWindow.GetFirstChild())
#	if (pTopPane):
#		pButtonPane = App.TGPane_Cast(pTopPane.GetFirstChild())
#		if (pButtonPane):
#			pButton = App.STRoundedButton_Cast(pButtonPane.GetNthChild(7))
#			if (pButton):
#				print ("*** Setting resume button not visible")
#				pButton.SetNotVisible()

	global g_pcCurrentPaneName
	if (g_pcCurrentPaneName != None):
		SwitchMiddlePane(g_pcCurrentPaneName, 1)



###############################################################################
#	HandleKeyboardTopButtonArea(pButtonPane, pEvent)
#	
#	Keyboard handler for the top button area.
#	
#	Args:	pButtonPane - the button pane
#			pEvent		- the keyboard event
#	
#	Return:	none
###############################################################################
def HandleKeyboardTopButtonArea(pButtonPane, pEvent):
	# Get the information we need about the key so we can
	# look it up in the table..
	eKeyType = pEvent.GetKeyState()
	cCharCode = pEvent.GetUnicode()

	if eKeyType == App.TGKeyboardEvent.KS_KEYUP:
		pNewGame = pButtonPane.GetNthChild(0)
		pConfigure = pButtonPane.GetNthChild(1)
		pMultiplayer = pButtonPane.GetNthChild(2)
		pQuit = pButtonPane.GetNthChild(3)
		pLoadGame = pButtonPane.GetNthChild(4)
		pCredits = pButtonPane.GetNthChild(5)
		pQuickBattle = pButtonPane.GetNthChild(6)
		pResume = pButtonPane.GetNthChild(7)

		kButtonMapping = [ pNewGame, pConfigure, pMultiplayer, pQuit,
						   pLoadGame, pCredits, pQuickBattle, pResume ]
		kFocus = pButtonPane.GetFocus()
		iIndex = 0
		bSetIndex = 1

		for kObject in kButtonMapping:
			if (str(kObject) == str(kFocus)):
				iIndex = kButtonMapping.index(kObject)
				break

		if (cCharCode == App.WC_LEFT):
			if (iIndex == 0):
				iIndex = 3
			elif (iIndex == 4):
				if (pResume.IsVisible ()):
					iIndex = 7
				else:
					iIndex = 6
			else:
				iIndex = iIndex - 1

			pEvent.SetHandled()
		elif (cCharCode == App.WC_RIGHT):
			if (iIndex == 3):
				iIndex = 0
			elif (iIndex == 7):
				iIndex = 4
			elif (iIndex == 6 and not pResume.IsVisible ()):
				iIndex = 4
			else:
				iIndex = iIndex + 1

			pEvent.SetHandled()
		elif (cCharCode == App.WC_UP or cCharCode == App.WC_DOWN):
			if (iIndex == 0):
				iIndex = 4
			elif (iIndex == 1):
				iIndex = 5
			elif (iIndex == 2):
				iIndex = 6
			elif (iIndex == 3):
				if (pResume.IsVisible ()):
					iIndex = 7
				else:
					iIndex = 6
			elif (iIndex == 4):
				iIndex = 0
			elif (iIndex == 5):
				iIndex = 1
			elif (iIndex == 6):
				iIndex = 2
			elif (iIndex == 7):
				iIndex = 3
 			pEvent.SetHandled()
		else:
			bSetIndex = 0

		if (bSetIndex == 1):
			pButtonPane.SetFocus(kButtonMapping[iIndex])

	if (pEvent.EventHandled() == 0):
		pButtonPane.CallNextHandler(pEvent)

###############################################################################
#	HandleKeyboardTabButtonArea(pButtonPane, pEvent)
#	
#	Keyboard handler for the top button area.
#	
#	Args:	pButtonPane - the button pane
#			pEvent		- the keyboard event
#	
#	Return:	none
###############################################################################
def HandleKeyboardTabButtonArea(pButtonPane, pEvent):
	# Get the information we need about the key so we can
	# look it up in the table..
	eKeyType = pEvent.GetKeyState()
	cCharCode = pEvent.GetUnicode()

	if eKeyType == App.TGKeyboardEvent.KS_KEYUP:
		if ((cCharCode == App.WC_UP) or (cCharCode == App.WC_DOWN)):
			kFocus = pButtonPane.GetFocus()

			iIndex = 0
			for iIndex in range (0, pButtonPane.GetNumChildren ()):
				pObject = pButtonPane.GetNthChild (iIndex)
				if (str(pObject) == str(kFocus)):
					break

			iOriginalIndex = iIndex

			if (cCharCode == App.WC_UP):
				while (1):
					iIndex = iIndex - 1
					if (iIndex < 0):
						iIndex = pButtonPane.GetNumChildren () - 1

					if (iIndex == iOriginalIndex):
						break;

					pObject = pButtonPane.GetNthChild (iIndex)
					if (pObject.IsEnabled ()):
						break
			else:
				while (1):
					iIndex = iIndex + 1
					if (iIndex >= pButtonPane.GetNumChildren ()):
						iIndex = 0
				
					if (iIndex == iOriginalIndex):
						break;

					pObject = pButtonPane.GetNthChild (iIndex)
					if (pObject.IsEnabled ()):
						break

			pEvent.SetHandled()

			pButtonPane.SetFocus(pButtonPane.GetNthChild (iIndex))

	if (pEvent.EventHandled() == 0):
		pButtonPane.CallNextHandler(pEvent)

###############################################################################
#	HandleKeyboardEnterNameButtonArea(pButtonPane, pEvent)
#	
#	Keyboard handler for the top button area.
#	
#	Args:	pButtonPane - the button pane
#			pEvent		- the keyboard event
#	
#	Return:	none
###############################################################################
def HandleKeyboardEnterNameButtonArea(pButtonPane, pEvent):
	# Get the information we need about the key so we can
	# look it up in the table..
	eKeyType = pEvent.GetKeyState()
	cCharCode = pEvent.GetUnicode()

	if eKeyType == App.TGKeyboardEvent.KS_KEYUP:
		if ((cCharCode == App.WC_UP) or (cCharCode == App.WC_DOWN)):
			kFocus = pButtonPane.GetFocus()

			iIndex = 0
			for iIndex in range (0, pButtonPane.GetNumChildren ()):
				pObject = pButtonPane.GetNthChild (iIndex)
				if (str(pObject) == str(kFocus)):
					break

			iOriginalIndex = iIndex

			if (cCharCode == App.WC_UP):
				while (1):
					iIndex = iIndex - 1
					if (iIndex < 0):
						iIndex = pButtonPane.GetNumChildren () - 1

					if (iIndex == iOriginalIndex):
						break;

					pObject = pButtonPane.GetNthChild (iIndex)
					if (pObject.IsEnabled ()):
						break
			else:
				while (1):
					iIndex = iIndex + 1
					if (iIndex >= pButtonPane.GetNumChildren ()):
						iIndex = 0
				
					if (iIndex == iOriginalIndex):
						break;

					pObject = pButtonPane.GetNthChild (iIndex)
					if (pObject.IsEnabled ()):
						break

			pEvent.SetHandled()

			if (iIndex == 3):
				pObject = App.TGPane_Cast (pButtonPane.GetNthChild (iIndex))
				pPara = App.TGParagraph_Cast (pObject.GetNthChild (1))
				pPara.Resize (pObject.GetWidth (), pObject.GetHeight ())
				pObject.SetFocus (pPara)
	
			pButtonPane.SetFocus(pButtonPane.GetNthChild (iIndex))

	if (pEvent.EventHandled() == 0):
		pButtonPane.CallNextHandler(pEvent)

###############################################################################
#	HandleKeyboardCredits(pPane, pEvent)
#	
#	Keyboard handler for the top button area.
#	
#	Args:	pPane - the pane
#			pEvent		- the keyboard event
#	
#	Return:	none
###############################################################################
def HandleKeyboardCredits(pPane, pEvent):
	# Get the information we need about the key so we can
	# look it up in the table..
	eKeyType = pEvent.GetKeyState()
	cCharCode = pEvent.GetUnicode()

	global g_idCreditsSequence
	pCreditsSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idCreditsSequence))

	if eKeyType == App.TGKeyboardEvent.KS_KEYUP:
		if (cCharCode == App.WC_SPACE or cCharCode == App.WC_BACKSPACE or cCharCode == App.WC_ESCAPE):
			if (pCreditsSequence):
				pCreditsSequence.Skip ()
				g_idCreditsSequence = App.NULL_ID
				BackToOptions (None)
				global g_idBinkIcon, g_idMilesIcon
				g_idBinkIcon = App.NULL_ID
				g_idMilesIcon = App.NULL_ID

 			pEvent.SetHandled()

	if (pEvent.EventHandled() == 0):
		pPane.CallNextHandler(pEvent)

###############################################################################
#	BuildMiddlePane(kName)
#	
#	Builds the middle pane, into which its background and the foreground 
#	tab go. The background pane should ALWAYS be the last child in the 
#	middle pane.
#	
#	Args:	kName	- TGString to be used for background name
#	
#	Return:	TGPane * - the middle pane
###############################################################################
def BuildMiddlePane(kName):
	pPane = App.TGPane_Create(1.0, 1.0 - .17 - g_fVerticalSpacing * 2.0)
	pPane.AddChild(BuildMiddleBackground(kName))
	return(pPane)

###############################################################################
#	BuildMiddleBackground(kName)
#	
#	Builds the background for the middle areas, and adds the title text.
#	
#	Args:	kName	- the title text, as a TGString
#			bListPane - whether to build the list view or regular view.
#	
#	Return:	TGPane * - the middle background pane
###############################################################################
def BuildMiddleBackground(kName, bListPane = 0):
	kSizes =  [6, 9, 9, 12, 15]

	pMode = App.GraphicsModeInfo_GetCurrentMode()
	pPane = App.TGPane_Create(1.0, 1.0 - 0.18541666 + g_fVerticalSpacing)
	fVertSpacing = pMode.GetPixelHeight() * 3.0

	kColor = App.g_kMainMenuBorderOffColor
	kColor1 = App.g_kMainMenuBorderMainColor
	kColor2 = App.g_kMainMenuBorderBlock1Color

	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()
	pIconGroup = App.g_kIconManager.GetIconGroup(pcLCARS)

	fLeft = g_fHorizontalSpacing
	fTop = 0.0

	fMiddleTop = 0.18541666 + g_fVerticalSpacing
	fMiddleLeft = g_fHorizontalSpacing + 0.1453125
	fMiddleRight = 0
	fMiddleBottom = 0

	global g_idJunkText1
	global g_idJunkText2
	global g_idJunkText3
	global g_idJunkText4

	# First row
	pCurve = UIHelpers.CreateCurve(UIHelpers.UPPER_LEFT_CURVE, 0.145, 0.175, 0.083333333, 0.108333333, kColor, 0.0425)

 	pText = App.TGParagraph_Create("3945 062", 1.0, App.g_kSTMenuTextColor, "LCARSText", kSizes[pMode.GetCurrentResolution()])
	pText.SetColor (App.g_kSTMenuTextColor)
	pText.RecalcBounds()
	pPane.AddChild (pText, fLeft + 0.145 - pText.GetWidth () - g_fHorizontalSpacing * 2.0, fTop + pCurve.GetHeight () - (pText.GetHeight() * 1.25), 0)
	g_idJunkText1 = pText.GetObjID()

	pPane.AddChild(pCurve, fLeft, fTop, 0)
	fLeft = fLeft + pCurve.GetWidth () + g_fHorizontalSpacing
	pOuterIcon = UIHelpers.GetOuterIcon (pCurve)

	pText = App.TGParagraph_CreateW(kName, 1.0, App.g_kMainMenuButtonColor)
	pPane.AddChild(pText, fLeft, fTop + (pOuterIcon.GetHeight () - pText.GetHeight()) / 2.0, 0)
	fLeft = fLeft + pText.GetWidth () + g_fHorizontalSpacing
	
	pThing = UIHelpers.CreateIcon (200, 0.65 - pText.GetWidth (), pOuterIcon.GetHeight (), kColor1)
	pPane.AddChild(pThing, fLeft, fTop, 0)

	pCurve = UIHelpers.CreateCurve(UIHelpers.UPPER_RIGHT_CURVE, 0.103125, 0.134375, 0.083333333, 0.108333333, kColor, 0.0425)
	pPane.AddChild(pCurve, 1.0 - g_fHorizontalSpacing - pCurve.GetWidth (), fTop, 0)

	# Next row
	fTop = fTop + pCurve.GetHeight () + g_fVerticalSpacing
	fLeft = g_fHorizontalSpacing

	# Two side bars
	pThing1 = UIHelpers.CreateIcon (200, 0.145, 0.375, kColor1)

 	pText = App.TGParagraph_Create ("27 13847", 1.0, None, "LCARSText", kSizes[pMode.GetCurrentResolution()])
	pText.SetColor (App.g_kSTMenuTextColor)
	pPane.AddChild (pText, fLeft + 0.145 - pText.GetWidth () - g_fHorizontalSpacing * 2.0, fTop + pThing1.GetHeight () - (pText.GetHeight() * 1.25), 0)
	g_idJunkText2 = pText.GetObjID()

	pPane.AddChild(pThing1, fLeft, fTop, 0)

	pThing2 = UIHelpers.CreateIcon (200, 0.103125, 0.485, kColor1)

 	pText = App.TGParagraph_Create ("468 04", 1.0, None, "LCARSText", kSizes[pMode.GetCurrentResolution()])
	pText.SetColor (App.g_kSTMenuTextColor)
	pPane.AddChild (pText, 1.0 - g_fHorizontalSpacing - pText.GetWidth () - g_fHorizontalSpacing * 2.0, fTop + pThing2.GetHeight () - (pText.GetHeight() * 1.25), 0)
	g_idJunkText3 = pText.GetObjID()


	pPane.AddChild(pThing2, 1.0 - g_fHorizontalSpacing - pThing2.GetWidth (), fTop, 0)

	# Little box on the lower left
	fTop = fTop + pThing1.GetHeight () + g_fVerticalSpacing
	fLeft = g_fHorizontalSpacing

	pCurve = UIHelpers.CreateCurve(UIHelpers.UPPER_RIGHT_CURVE, 0.05, 0.46375, 0.076666666, 0.085833333, kColor, 0.02325)


 	pText = App.TGParagraph_Create ("190", 1.0, None, "LCARSText", kSizes[pMode.GetCurrentResolution()])
	pText.SetColor (App.g_kSTMenuTextColor)
	pPane.AddChild (pText, fLeft + pCurve.GetWidth () - pText.GetWidth () - g_fHorizontalSpacing, fTop + pCurve.GetHeight () - pText.GetHeight () - g_fVerticalSpacing / 2.0, 0)
	g_idJunkText4 = pText.GetObjID()

	pPane.AddChild(pCurve, fLeft, fTop, 0)
	pOuterIcon = UIHelpers.GetOuterIcon (pCurve)

	pThing = UIHelpers.CreateIcon (200, 0.05, 0.135, kColor1)
	pPane.AddChild(pThing, fLeft + pCurve.GetWidth () - pThing.GetWidth (), fTop + pCurve.GetHeight () + g_fVerticalSpacing, 0)

	pCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_LEFT_CURVE, 0.06875, 0.40625, 0.220833333, 0.2475, kColor, 0.0425)
	pPane.AddChild(pCurve, fLeft, fTop + pOuterIcon.GetHeight () + g_fVerticalSpacing)
	pOuterIcon2 = UIHelpers.GetOuterIcon (pCurve)

	pThing = UIHelpers.CreateIcon (200, 0.426875, pOuterIcon2.GetHeight (), kColor1)
	pPane.AddChild(pThing, fLeft + pCurve.GetWidth () + g_fHorizontalSpacing, fTop + pOuterIcon.GetHeight () + g_fVerticalSpacing + pCurve.GetHeight () - pThing.GetHeight (), 0)
	fStoredTop = fTop + pOuterIcon.GetHeight () + g_fVerticalSpacing + pCurve.GetHeight ()

	# right bottom curve
	pCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_RIGHT_CURVE, 0.103125, 0.134375, 0.1325, 0.159166666, kColor, 0.0425)
	pPane.AddChild(pCurve, 1.0 - g_fHorizontalSpacing - pCurve.GetWidth (), fStoredTop - pCurve.GetHeight (), 0)

	# Set the pane not to get focus, since it's only graphical.
	pPane.SetNoFocus()

	return(pPane)

###############################################################################
#	BuildNewGamePane()
#	
#	Builds the "new game" pane. (revealed when the user selects the
#	"new game" tab in the top area)
#	
#	Args:	none
#	
#	Return:	TGPane * - the new game pane
###############################################################################
def BuildNewGamePane():
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	global g_eNewGameDifficulty
	g_eNewGameDifficulty = App.Game_GetDifficulty()

	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	pNewGamePane = App.TGPane_Create(LCARS.MAIN_MENU_MIDDLE_PANE_WIDTH, 
									 LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT)

	pContentPane = App.TGPane_Create(LCARS.MAIN_MENU_MIDDLE_PANE_WIDTH, LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT)
	pNewGamePane.AddChild (pContentPane, LCARS.MAIN_MENU_MIDDLE_CONTENT_X, LCARS.MAIN_MENU_MIDDLE_CONTENT_Y, 0)

	pTabPane = App.TGPane_Create(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH,
								 LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT)
	App.g_kFocusManager.AddObjectToTabOrder(pTabPane)

	pContentPane.AddChild(pTabPane, LCARS.MAIN_MENU_CONFIGURE_TAB_X, LCARS.MAIN_MENU_CONFIGURE_TAB_Y)

	pTabPane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,	__name__ + ".HandleKeyboardEnterNameButtonArea")

	fYPixelOffset = 1.0 / App.g_kIconManager.GetScreenHeight ()
	fXPixelOffset = 1.0 / App.g_kIconManager.GetScreenWidth ()
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	fTop = 0.066666666
#	fHeight = pMenuButton.GetHeight () + fYPixelOffset * 2.0
	fHeight = CLIENT_START_BUTTON_HEIGHT

	# Create Player name button.
	pButton = App.STRoundedButton_CreateW (pDatabase.GetString("Captain Name"), None, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, fHeight, 1)
	pButton.SetDisabledColor(App.g_kMainMenuBorderMainColor)
	pButton.SetDisabled (0)
	pButton.SetColorBasedOnFlags()
	pTabPane.AddChild(pButton, 0.0, fTop, 0)
	fWidth = pButton.GetWidth ()

	pDefault = App.g_kUtopiaModule.GetCaptainName ()
	pTextEntry = CreateTextEntry (None, pDefault, 0.523125, 0, "Captain Name", 15, 0, "*?\t\\/.,<>\"|:")
	global g_idCaptainEntry
	g_idCaptainEntry = pTextEntry.GetObjID()
	pTabPane.AddChild (pTextEntry, fWidth + 0.02, fTop - (LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT - fHeight) / 2.0, 0)

	pPane = App.TGPane_Create (1.0, 1.0)
	pTabPane.AddChild (pPane, 0, 0, 0)

	pButton = App.TGIcon_Create(pcLCARS, 200, App.g_kSTMenuTextColor)
	pButton.Resize (0.30, fHeight - fYPixelOffset * 4.0, 0)
	pPane.AddChild(pButton, fWidth + 0.020, fTop + fYPixelOffset * 2.0, 0)

	pButton = UIHelpers.CreateRoundedButton (0.543125, fHeight, App.g_kTextEntryBackgroundColor)
	pPane.AddChild(pButton, fWidth + 0.01, fTop, 0)

	fTop = fTop + fHeight * 2.0

	# Create Difficulty buttons.
	# Create easy button
	pEvent = App.TGIntEvent_Create()
	pEvent.SetSource(pTabPane)
	pEvent.SetDestination(pOptionsWindow)
	pEvent.SetEventType(ET_NEW_GAME_DIFFICULTY)
	pEvent.SetInt (0)

	pMenuButton = App.STButton_CreateW(pDatabase.GetString("First Officer"), pEvent)
	pMenuButton.SetChoosable (1)
	pMenuButton.SetAutoChoose (0)
	fHeight = pMenuButton.GetHeight ()

	pButton = App.STRoundedButton_CreateW (pDatabase.GetString("Difficulty"), None, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, fHeight, 1)
	pButton.SetDisabledColor(App.g_kMainMenuBorderMainColor)
	pButton.SetDisabled (0)
	pButton.SetColorBasedOnFlags()
	pTabPane.AddChild(pButton, 0.0, fTop, 0)

	if (g_eNewGameDifficulty == 0):
		pMenuButton.SetChosen (1)
	pButton = App.TGPane_Create (LCARS.MAIN_MENU_TOP_BUTTON_WIDTH * 1.25, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pButton.AddChild (pMenuButton)
	pButton.SetEnabled (1)
	pMenuButton.SetNormalColor(App.g_kMainMenuButton1Color)
	pMenuButton.SetHighlightedColor(App.g_kMainMenuButton1HighlightedColor)
	pMenuButton.SetSelectedColor(App.g_kMainMenuButton1SelectedColor)
	pMenuButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pMenuButton.SetColorBasedOnFlags()

	pTabPane.AddChild (pButton, fWidth + 0.01, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	# Create medium button
	pEvent = App.TGIntEvent_Create()
	pEvent.SetSource(pTabPane)
	pEvent.SetDestination(pOptionsWindow)
	pEvent.SetEventType(ET_NEW_GAME_DIFFICULTY)
	pEvent.SetInt (1)

	pMenuButton = App.STButton_CreateW(pDatabase.GetString("Captain"), pEvent)
	pMenuButton.SetChoosable (1)
	pMenuButton.SetAutoChoose (0)
	if (g_eNewGameDifficulty == 1):
		pMenuButton.SetChosen (1)

	pButton = App.TGPane_Create (LCARS.MAIN_MENU_TOP_BUTTON_WIDTH * 1.25, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pButton.AddChild (pMenuButton)
	pButton.SetEnabled (1)

	pMenuButton.SetNormalColor(App.g_kMainMenuButton1Color)
	pMenuButton.SetHighlightedColor(App.g_kMainMenuButton1HighlightedColor)
	pMenuButton.SetSelectedColor(App.g_kMainMenuButton1SelectedColor)
	pMenuButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pMenuButton.SetColorBasedOnFlags()
	pTabPane.AddChild (pButton, fWidth + 0.01, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	# Create hard button
	pEvent = App.TGIntEvent_Create()
	pEvent.SetSource(pTabPane)
	pEvent.SetDestination(pOptionsWindow)
	pEvent.SetEventType(ET_NEW_GAME_DIFFICULTY)
	pEvent.SetInt (2)

	pMenuButton = App.STButton_CreateW(pDatabase.GetString("Admiral"), pEvent)
	pMenuButton.SetChoosable (1)
	pMenuButton.SetAutoChoose (0)
	if (g_eNewGameDifficulty == 2):
		pMenuButton.SetChosen (1)

	pButton = App.TGPane_Create (LCARS.MAIN_MENU_TOP_BUTTON_WIDTH * 1.25, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pButton.AddChild (pMenuButton)
	pButton.SetEnabled (1)

	pMenuButton.SetNormalColor(App.g_kMainMenuButton1Color)
	pMenuButton.SetHighlightedColor(App.g_kMainMenuButton1HighlightedColor)
	pMenuButton.SetSelectedColor(App.g_kMainMenuButton1SelectedColor)
	pMenuButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pMenuButton.SetColorBasedOnFlags()
	pTabPane.AddChild (pButton, fWidth + 0.01, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	App.g_kLocalizationManager.Unload(pDatabase)

	# Create start button
	pEvent = App.TGEvent_Create()
	pEvent.SetSource(pTextEntry)
	pEvent.SetDestination(pOptionsWindow)
	pEvent.SetEventType(ET_START_NEW_GAME)
	pButton = App.STButton_CreateW(pDatabase.GetString("Start"), pEvent, 0, CLIENT_START_BUTTON_WIDTH, CLIENT_START_BUTTON_HEIGHT)
	pButton.SetNormalColor(App.g_kMainMenuButton3Color)
	pButton.SetHighlightedColor(App.g_kMainMenuButton3HighlightedColor)
	pButton.SetSelectedColor(App.g_kMainMenuButton3SelectedColor)
	pButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	pButton.SetHighlightedTextColor(App.g_kMultiplayerBorderBlue)
	pButton.SetColorBasedOnFlags()

	pTabPane.AddChild (pButton, 0.70 - CLIENT_START_BUTTON_WIDTH, 0.64, 0)

	return(pNewGamePane)

###############################################################################
#	BuildTestGamePane()
#	
#	Builds the "new game" pane. (revealed when the user selects the
#	"new game" tab in the top area)
#	
#	Args:	none
#	
#	Return:	TGPane * - the new game pane
###############################################################################
def BuildTestGamePane():
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	pOldFont = App.g_kFontManager.GetDefaultFont()
	App.g_kFontManager.SetDefaultFont(g_pcFlightSmallFont, g_kFlightSmallFontSize[g_iRes])

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	pNewGamePane = App.TGPane_Create(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH / 2.0 + LCARS.MAIN_MENU_MIDDLE_CONTENT_X, 
									 LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT + LCARS.MAIN_MENU_MIDDLE_CONTENT_Y)
	pNewGameSubPane = App.STSubPane_Create(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH / 2.0, 
										   LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT)
	pNewGameStylized = App.STStylizedWindow_Create("StylizedWindow", "NoMinimize", "Missions", 0.0, 0.0)
	pNewGameStylized.AddChild(pNewGameSubPane)
	pNewGameStylized.SetMaximumSize(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH / 2.0,
									# LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT + pNewGameStylized.GetBorderHeight())
									0.4)
	App.g_kFocusManager.AddObjectToTabOrder(pNewGameSubPane)

	if App.g_kUtopiaModule.GetTestMenuState () >= 2:
		# Setup the new game menu buttons.
		pEpisode1Menu = App.STMenu_CreateW(pDatabase.GetString("Episode 1"))
		pEpisode2Menu = App.STMenu_CreateW(pDatabase.GetString("Episode 2"))
		pEpisode3Menu = App.STMenu_CreateW(pDatabase.GetString("Episode 3"))
		pEpisode4Menu = App.STMenu_CreateW(pDatabase.GetString("Episode 4"))
		pEpisode5Menu = App.STMenu_CreateW(pDatabase.GetString("Episode 5"))
		pEpisode6Menu = App.STMenu_CreateW(pDatabase.GetString("Episode 6"))
		pEpisode7Menu = App.STMenu_CreateW(pDatabase.GetString("Episode 7"))
		pEpisode8Menu = App.STMenu_CreateW(pDatabase.GetString("Episode 8"))

		fMenuWidth = pEpisode1Menu.GetWidth()

		#############################################################
		# Episode 1
		pE1M1 = CreateMenuButton(pDatabase.GetString("E1M1"), ET_E1M1, 1, fMenuWidth)
		pEpisode1Menu.AddChild(pE1M1)

		if (App.g_kUtopiaModule.GetTestMenuState() >= 2):
			pE1M2 = CreateMenuButton(pDatabase.GetString("E1M2"), ET_E1M2, 1, fMenuWidth)
			pEpisode1Menu.AddChild(pE1M2)
		
		#############################################################
		# Episode 2
		pE2M0 = CreateMenuButton(pDatabase.GetString("E2M1"), ET_E2M0, 1, fMenuWidth)
		pEpisode2Menu.AddChild(pE2M0)
		
		if (App.g_kUtopiaModule.GetTestMenuState() >= 2):
			pE2M1 = CreateMenuButton(pDatabase.GetString("E2M2"), ET_E2M1, 1, fMenuWidth)
			pEpisode2Menu.AddChild(pE2M1)

			pE2M2 = CreateMenuButton(pDatabase.GetString("E2M3"), ET_E2M2, 1, fMenuWidth)
			pEpisode2Menu.AddChild(pE2M2)

			pE2M6 = CreateMenuButton(pDatabase.GetString("E2M4"), ET_E2M6, 1, fMenuWidth)
			pEpisode2Menu.AddChild(pE2M6)

		#############################################################
		# Episode 3
		pE3M1 = CreateMenuButton(pDatabase.GetString("E3M1"), ET_E3M1, 1, fMenuWidth)
		pEpisode3Menu.AddChild(pE3M1)

		if (App.g_kUtopiaModule.GetTestMenuState() >= 2):
			pE3M2 = CreateMenuButton(pDatabase.GetString("E3M2"), ET_E3M2, 1, fMenuWidth)
			pEpisode3Menu.AddChild(pE3M2)

			pE3M4 = CreateMenuButton(pDatabase.GetString("E3M3"), ET_E3M4, 1, fMenuWidth)
			pEpisode3Menu.AddChild(pE3M4)

			pE3M5 = CreateMenuButton(pDatabase.GetString("E3M4"), ET_E3M5, 1, fMenuWidth)
			pEpisode3Menu.AddChild(pE3M5)

		#############################################################
		# Episode 4
		pE4M6 = CreateMenuButton(pDatabase.GetString("E4M1"), ET_E4M6, 1, fMenuWidth)
		pEpisode4Menu.AddChild(pE4M6)

		if (App.g_kUtopiaModule.GetTestMenuState() >= 2):
			pE4M4 = CreateMenuButton(pDatabase.GetString("E4M2"), ET_E4M4, 1, fMenuWidth)
			pEpisode4Menu.AddChild(pE4M4)

			pE4M5 = CreateMenuButton(pDatabase.GetString("E4M3"), ET_E4M5, 1, fMenuWidth)
			pEpisode4Menu.AddChild(pE4M5)
		
		#############################################################
		# Episode 5
		pE5M2 = CreateMenuButton(pDatabase.GetString("E5M1"), ET_E5M2, 1, fMenuWidth)
		pEpisode5Menu.AddChild(pE5M2)

		if (App.g_kUtopiaModule.GetTestMenuState() >= 2):
			pE5M4 = CreateMenuButton(pDatabase.GetString("E5M2"), ET_E5M4, 1, fMenuWidth)
			pEpisode5Menu.AddChild(pE5M4)
		
		#############################################################
		# Episode 6
		pE6M1 = CreateMenuButton(pDatabase.GetString("E6M1"), ET_E6M1, 1, fMenuWidth)
		pEpisode6Menu.AddChild(pE6M1)

		if (App.g_kUtopiaModule.GetTestMenuState() >= 2):
			pE6M2 = CreateMenuButton(pDatabase.GetString("E6M2"), ET_E6M2, 1, fMenuWidth)
			pEpisode6Menu.AddChild(pE6M2)

			pE6M3 = CreateMenuButton(pDatabase.GetString("E6M3"), ET_E6M3, 1, fMenuWidth)
			pEpisode6Menu.AddChild(pE6M3)

			pE6M4 = CreateMenuButton(pDatabase.GetString("E6M4"), ET_E6M4, 1, fMenuWidth) 
			pEpisode6Menu.AddChild(pE6M4)

			pE6M5 = CreateMenuButton(pDatabase.GetString("E6M5"), ET_E6M5, 1, fMenuWidth) 
			pEpisode6Menu.AddChild(pE6M5)
		
		#############################################################
		# Episode 7
		pE7M1 = CreateMenuButton(pDatabase.GetString("E7M1"), ET_E7M1, 1, fMenuWidth)
		pEpisode7Menu.AddChild(pE7M1)

		if (App.g_kUtopiaModule.GetTestMenuState() >= 2):
			pE7M2 = CreateMenuButton(pDatabase.GetString("E7M2"), ET_E7M2, 1, fMenuWidth)
			pEpisode7Menu.AddChild(pE7M2)

			pE7M3 = CreateMenuButton(pDatabase.GetString("E7M3"), ET_E7M3, 1, fMenuWidth)
			pEpisode7Menu.AddChild(pE7M3)

			pE7M6 = CreateMenuButton(pDatabase.GetString("E7M4"), ET_E7M6, 1, fMenuWidth)
			pEpisode7Menu.AddChild(pE7M6)

		#############################################################
		# Episode 8
		pE8M1 = CreateMenuButton(pDatabase.GetString("E8M1"), ET_E8M1, 1, fMenuWidth)
		pEpisode8Menu.AddChild(pE8M1)

		if (App.g_kUtopiaModule.GetTestMenuState() >= 2):
			pE8M2 = CreateMenuButton(pDatabase.GetString("E8M2"), ET_E8M2, 1, fMenuWidth)
			pEpisode8Menu.AddChild(pE8M2)

	#############################################################
	# QuickBattle
	pEvent = App.TGStringEvent_Create()
	pEvent.SetEventType(ET_QUICK_BATTLE)
	pEvent.SetString("QuickBattle.QuickBattleGame")
	pEvent.SetDestination(pOptionsWindow)
	pQuickBattleButton = App.STButton_CreateW(pDatabase.GetString("Quick Battle"), pEvent)
	#############################################################

	#############################################################
	# Custom missions
	pCustomMenu = App.STMenu_CreateW(pDatabase.GetString("Custom missions"))

	try:
		import nt
		lFiles = nt.listdir("scripts/Custom")
		# Check which of these entries are directories.
		for sCandidate in lFiles:
			if ((nt.stat("scripts/Custom/" + sCandidate)[0] & 0170000) == 0040000):
				# Directory.
				try:
					# Check if the campaign wants to create its own menu/button.
					sModuleName = "Custom." + sCandidate + "." + sCandidate
					pCampaign = __import__(sModuleName)
					pButton = pCampaign.CreateMenu()
				except:
					pButton = App.STButton_Create(sCandidate)
					pEvent = App.TGStringEvent_Create()
					pEvent.SetEventType(ET_CUSTOM_MISSION)
					pEvent.SetString(sCandidate)
					pEvent.SetDestination(pOptionsWindow)
					pButton.SetActivationEvent(pEvent)

				pCustomMenu.AddChild(pButton)
	except:
		# No custom missions to use.
		pass
	
	#############################################################

	pNewGamePane.AddChild(pNewGameStylized, LCARS.MAIN_MENU_MIDDLE_CONTENT_X, 
						  LCARS.MAIN_MENU_MIDDLE_CONTENT_Y)

	if App.g_kUtopiaModule.GetTestMenuState () >= 2:
		pNewGameSubPane.AddChild(pEpisode1Menu)
		pNewGameSubPane.AddChild(pEpisode2Menu)
		pNewGameSubPane.AddChild(pEpisode3Menu)
		pNewGameSubPane.AddChild(pEpisode4Menu)
		pNewGameSubPane.AddChild(pEpisode5Menu)
		pNewGameSubPane.AddChild(pEpisode6Menu)
		pNewGameSubPane.AddChild(pEpisode7Menu)
		pNewGameSubPane.AddChild(pEpisode8Menu)

	pNewGameSubPane.AddChild(pQuickBattleButton)
	pNewGameSubPane.AddChild(pCustomMenu)

	# hack: not sure why this menu in particular doesn't size right. weird.
	pEpisode1Menu.Open()
	pEpisode1Menu.Close()
	pNewGameSubPane.ResizeToContents()
	pNewGameStylized.InteriorChangedSize(1)

	App.g_kLocalizationManager.Unload(pDatabase)

	App.g_kFontManager.SetDefaultFont(pOldFont.GetFontName(), pOldFont.GetFontSize())

	return(pNewGamePane)

###############################################################################
#	BuildConfigurePane(bGameEnded)
#	
#	Builds the "configure" pane. (revealed when the user selects the
#	"configure" tab in the top area)
#	
#	Args:	none
#	
#	Return:	TGPane * - the configure pane
###############################################################################
def BuildConfigurePane(bGameEnded = 0):
	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Full area pane
	pConfigurePane = App.TGPane_Create(LCARS.MAIN_MENU_MIDDLE_PANE_WIDTH, LCARS.MAIN_MENU_MIDDLE_PANE_HEIGHT)

	# Pane to hold our stuff
	pContentPane = App.TGPane_Create(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH, LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT)
	pConfigurePane.AddChild (pContentPane, LCARS.MAIN_MENU_MIDDLE_CONTENT_X, LCARS.MAIN_MENU_MIDDLE_CONTENT_Y, 0)

	pContentPane.AddPythonFuncHandlerForInstance(ET_CONFIGURE_GENERAL_TAB,		"MainMenu.mainmenu.HandleConfigureGeneralTab")
	pContentPane.AddPythonFuncHandlerForInstance(ET_CONFIGURE_SOUND_TAB,		"MainMenu.mainmenu.HandleConfigureSoundTab")
	pContentPane.AddPythonFuncHandlerForInstance(ET_CONFIGURE_GRAPHICS_TAB,		"MainMenu.mainmenu.HandleConfigureGraphicsTab")
	pContentPane.AddPythonFuncHandlerForInstance(ET_CONFIGURE_SAVE,				"MainMenu.mainmenu.SaveConfig")
	pContentPane.AddPythonFuncHandlerForInstance(ET_CONFIGURE_KEYBOARD,			"MainMenu.mainmenu.HandleConfigureKeyboard")

	# Create the left-hand tab pane (the one with the buttons to select the major content areas)
	pTabPane = App.TGPane_Create(LCARS.MAIN_MENU_CONFIGURE_TAB_WIDTH,
									LCARS.MAIN_MENU_CONFIGURE_TAB_HEIGHT)
	App.g_kFocusManager.AddObjectToTabOrder(pTabPane)

	pTabPane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,	__name__ + ".HandleKeyboardTabButtonArea")

	# Create the right-hand options pane.
	pOptionsPane = App.STSubPane_Create(LCARS.MAIN_MENU_CONFIGURE_CONTENT_WIDTH,
										LCARS.MAIN_MENU_CONFIGURE_CONTENT_HEIGHT)

	App.g_kFocusManager.AddObjectToTabOrder(pOptionsPane)

	# Create and add the buttons for the tabs.
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pConfigurePane)
	pEvent.SetDestination(pContentPane)
	pEvent.SetEventType(ET_CONFIGURE_GENERAL_TAB)
	pEvent.SetObjPtr(pOptionsPane)
	pGeneralTab = App.STRoundedButton_CreateW (pDatabase.GetString("General Options"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pGeneralTab.SetNormalColor(App.g_kMainMenuButton1Color)
	pGeneralTab.SetHighlightedColor(App.g_kMainMenuButton1HighlightedColor)
	pGeneralTab.SetSelectedColor(App.g_kMainMenuButton1SelectedColor)
	pGeneralTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pGeneralTab.SetColorBasedOnFlags()
	pGeneralTab.SetSelected (0)

	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pConfigurePane)
	pEvent.SetDestination(pContentPane)
	pEvent.SetEventType(ET_CONFIGURE_SOUND_TAB)
	pEvent.SetObjPtr(pOptionsPane)
	pSoundTab = App.STRoundedButton_CreateW (pDatabase.GetString("Sound"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pSoundTab.SetNormalColor(App.g_kMainMenuButton1Color)
	pSoundTab.SetHighlightedColor(App.g_kMainMenuButton1HighlightedColor)
	pSoundTab.SetSelectedColor(App.g_kMainMenuButton1SelectedColor)
	pSoundTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pSoundTab.SetColorBasedOnFlags()

	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pConfigurePane)
	pEvent.SetDestination(pContentPane)
	pEvent.SetEventType(ET_CONFIGURE_GRAPHICS_TAB)
	pEvent.SetObjPtr(pOptionsPane)
	pGraphicsTab = App.STRoundedButton_CreateW (pDatabase.GetString("Graphics"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pGraphicsTab.SetNormalColor(App.g_kMainMenuButton1Color)
	pGraphicsTab.SetHighlightedColor(App.g_kMainMenuButton1HighlightedColor)
	pGraphicsTab.SetSelectedColor(App.g_kMainMenuButton1SelectedColor)
	pGraphicsTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pGraphicsTab.SetColorBasedOnFlags()

	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetSource(pConfigurePane)
	pEvent.SetDestination(pContentPane)
	pEvent.SetEventType(ET_CONFIGURE_KEYBOARD)
	pEvent.SetObjPtr(pOptionsPane)
	pKeyboardTab = App.STRoundedButton_CreateW (pDatabase.GetString("ControlsShort"), pEvent, LCARS.MAIN_MENU_TOP_BUTTON_WIDTH, 
				   LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	pKeyboardTab.SetNormalColor(App.g_kMainMenuButton1Color)
	pKeyboardTab.SetHighlightedColor(App.g_kMainMenuButton1HighlightedColor)
	pKeyboardTab.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	pKeyboardTab.SetDisabledColor(App.g_kSTMenu1Disabled)
	pKeyboardTab.SetColorBasedOnFlags()

	fHeight = pGeneralTab.GetHeight ()
	fTop = 0.0

	pTabPane.AddChild(pGeneralTab, 0.0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing
	pTabPane.AddChild(pSoundTab, 0.0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing
	pTabPane.AddChild(pGraphicsTab, 0.0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing
	pTabPane.AddChild(pKeyboardTab, 0.0, fTop, 0)
	fTop = fTop + fHeight + g_fVerticalSpacing

	pContentPane.AddChild(pTabPane, LCARS.MAIN_MENU_CONFIGURE_TAB_X, LCARS.MAIN_MENU_CONFIGURE_TAB_Y)
	pContentPane.AddChild(pOptionsPane, LCARS.MAIN_MENU_CONFIGURE_CONTENT_X, LCARS.MAIN_MENU_CONFIGURE_CONTENT_Y)

	# Unload localization database.
	App.g_kLocalizationManager.Unload(pDatabase)

	if (g_pcConfigurePaneName == "sound"):
		BuildConfigureSoundTab(pOptionsPane, pContentPane, bGameEnded)
		pTabPane.SetFocus(pSoundTab, 0)
		pSoundTab.SetColorBasedOnFlags()
	elif (g_pcConfigurePaneName == "graphics"):
		BuildConfigureGraphicsTab(pOptionsPane, pContentPane, bGameEnded)
		pTabPane.SetFocus(pGraphicsTab, 0)
		pGraphicsTab.SetColorBasedOnFlags()
	elif (g_pcConfigurePaneName == "keyboard"):
		BuildConfigureKeyboardTab(pOptionsPane, pConfigurePane, pContentPane, bGameEnded)
		pTabPane.SetFocus(pKeyboardTab, 0)
		pKeyboardTab.SetColorBasedOnFlags()
	else:
		BuildConfigureGeneralTab(pOptionsPane, pContentPane, bGameEnded)
		pTabPane.SetFocus(pGeneralTab, 0)
		pGeneralTab.SetColorBasedOnFlags()

	return(pConfigurePane)

###############################################################################
#	LoadConfigPart1()
#	
#	Loads font configuration information. This is called early in the startup
#	sequence, before the windows are created.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def LoadConfigPart1():
	# We want this to happen regardless of whether or not the config file was
	# loaded.
	App.g_kFontManager.SetDefaultFont("Crillee", 6.0)

	if (App.g_kConfigMapping.LoadConfigFile("Options.cfg") == 0):
		return

	if (App.g_kConfigMapping.HasValue("General Options", "Captain Name")):
		App.g_kUtopiaModule.SetCaptainName (App.g_kConfigMapping.GetTGStringValue ("General Options", "Captain Name"))		
	if (App.g_kConfigMapping.HasValue ("General Options", "Played Tutorial")):
		App.g_kVarManager.SetFloatVariable ("global", "PlayedTutorial", 1)
	else:
		App.g_kVarManager.SetFloatVariable ("global", "PlayedTutorial", 0)

	# Set default "annoyances" values:
	if not App.g_kConfigMapping.HasValue("Annoyances", "Quit Game Confirmation"):
		App.g_kConfigMapping.SetIntValue("Annoyances", "Quit Game Confirmation", 1)

###############################################################################
#	LoadConfigPart2()
#	
#	Loads the rest of the configuration information.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def LoadConfigPart2():
	global g_bConfigLoaded
	g_bConfigLoaded = 1

	# Check for the subtitle window and create it if necessary. This should
	# happen regardless of whether or not we can load a config file.
	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
	if (pSubtitle == None):
		pSubtitle = CreateSubtitleWindow()

	# Try and load the config file.
	if (App.g_kConfigMapping.LoadConfigFile("Options.cfg") == 0):
		return

	if (App.g_kConfigMapping.HasValue("General Options", "Space Dust")):
		App.SpaceCamera_SetSpaceDustInGame(App.g_kConfigMapping.GetIntValue("General Options", "Space Dust"))

	if (App.g_kConfigMapping.HasValue("General Options", "Glow Maps")):
		App.g_kLODModelManager.SetGlowMapsEnabled(App.g_kConfigMapping.GetIntValue("General Options", "Glow Maps"))

	if (App.g_kConfigMapping.HasValue("General Options", "Enhanced Glows")):
		App.SetClass_SetGlowEnabled(App.g_kConfigMapping.GetIntValue("General Options", "Enhanced Glows"))

	if (App.g_kConfigMapping.HasValue("General Options", "Specular Maps")):
		App.g_kLODModelManager.SetSpecularMapsEnabled(App.g_kConfigMapping.GetIntValue("General Options", "Specular Maps"))

	if (App.g_kConfigMapping.HasValue("General Options", "Motion Blur")):
		App.g_kLODModelManager.SetMotionBlurEnabled(App.g_kConfigMapping.GetIntValue("General Options", "Motion Blur"))

	if (App.g_kConfigMapping.HasValue("General Options", "Tool Tips")):
		App.CharacterClass_SetToolTipsEnabled(App.g_kConfigMapping.GetIntValue("General Options", "Tool Tips"))

	if (App.g_kConfigMapping.HasValue("General Options", "Collision Alert")):
		App.CharacterClass_SetCollisionAlertEnabled(App.g_kConfigMapping.GetIntValue("General Options", "Collision Alert"))

	if (App.g_kConfigMapping.HasValue("General Options", "Subtitles")):
		if (App.g_kConfigMapping.GetIntValue("General Options", "Subtitles") == 1):
			pSubtitle.SetOn()
		else:
			pSubtitle.SetOff()

	if (App.g_kConfigMapping.HasValue("Graphics Options", "Effect Detail")):
		App.EffectController_SetEffectLevel(App.g_kConfigMapping.GetIntValue("Graphics Options", "Effect Detail"))

	if (App.g_kConfigMapping.HasValue("Graphics Options", "Visible Damage")):
		iDamageSetting = App.g_kConfigMapping.GetIntValue("Graphics Options", "Visible Damage")	
		if (iDamageSetting == 0):
			App.DamageableObject_SetDamageGeometryEnabled(0)
			App.DamageableObject_SetVolumeDamageGeometryEnabled(0)
			App.DamageableObject_SetBreakableComponentsEnabled(0)
		elif (iDamageSetting == 1):
			App.DamageableObject_SetDamageGeometryEnabled(1)
			App.DamageableObject_SetVolumeDamageGeometryEnabled(0)
			App.DamageableObject_SetBreakableComponentsEnabled(0)
		elif (iDamageSetting == 2):
			App.DamageableObject_SetDamageGeometryEnabled(1)
			App.DamageableObject_SetVolumeDamageGeometryEnabled(1)
			App.DamageableObject_SetBreakableComponentsEnabled(0)
		else:
			App.DamageableObject_SetDamageGeometryEnabled(1)
			App.DamageableObject_SetVolumeDamageGeometryEnabled(1)
			App.DamageableObject_SetBreakableComponentsEnabled(1)

	if (App.g_kConfigMapping.HasValue("Graphics Options", "Number of Lights")):
		App.ObjectClass_SetMaximumNumberOfLights(App.g_kConfigMapping.GetIntValue("Graphics Options", "Number of Lights"))
		
	if (App.g_kConfigMapping.HasValue("Graphics Options", "LOD Skip")):
		App.g_kLODModelManager.SetDropLODLevel(App.g_kConfigMapping.GetIntValue("Graphics Options", "LOD Skip"))
	if (App.g_kConfigMapping.HasValue("Graphics Options", "MipMaps")):
		App.g_kImageManager.EnableMipMaps(App.g_kConfigMapping.GetIntValue("Graphics Options", "MipMaps"))
	if (App.g_kConfigMapping.HasValue("Graphics Options", "Texture Detail")):
		App.g_kImageManager.SetImageDetail(App.g_kConfigMapping.GetIntValue("Graphics Options", "Texture Detail"))

	if (App.g_kConfigMapping.HasValue("General Options", "Collisions")):
		App.ProximityManager_SetPlayerCollisionsEnabled(App.g_kConfigMapping.GetIntValue("General Options", "Collisions"))
		App.ProximityManager_SetMultiplayerPlayerCollisionsEnabled(App.g_kConfigMapping.GetIntValue("General Options", "Collisions"))

	if (App.g_kConfigMapping.HasValue("Sound", "Music")):
		App.g_kMusicManager.SetEnabled(App.g_kConfigMapping.GetIntValue("Sound", "Music"))

	if (App.g_kConfigMapping.HasValue("Sound", "Sound Enabled")):
		App.g_kSoundManager.SetSFXEnabled(App.g_kConfigMapping.GetIntValue("Sound", "Sound Enabled"))

	if (App.g_kConfigMapping.HasValue("Sound", "Voice Enabled")):
		App.g_kSoundManager.SetVoiceEnabled(App.g_kConfigMapping.GetIntValue("Sound", "Voice Enabled"))

	if (App.g_kConfigMapping.HasValue("Sound", "SFX Volume")):
		App.g_kSoundManager.SetSFXVolume(App.g_kConfigMapping.GetFloatValue("Sound", "SFX Volume"))
		App.g_kSoundManager.SetInterfaceVolume(App.g_kConfigMapping.GetFloatValue("Sound", "SFX Volume"))
		# Don't set volume here.  Wait until the main menu is created.

	# Default voice volume is 80%.
	if not App.g_kConfigMapping.HasValue("Sound", "Voice Volume"):
		App.g_kConfigMapping.SetFloatValue("Sound", "Voice Volume", 0.8)
	App.g_kSoundManager.SetVoiceVolume(App.g_kConfigMapping.GetFloatValue("Sound", "Voice Volume"))

	# Default music volume is 60%.
	if not App.g_kConfigMapping.HasValue("Sound", "Music Volume"):
		App.g_kConfigMapping.SetFloatValue("Sound", "Music Volume", 0.6)
	App.g_kMusicManager.SetVolume(App.g_kConfigMapping.GetFloatValue("Sound", "Music Volume"))

	# Default sfx damping (for voice) is 0.5.
	if not App.g_kConfigMapping.HasValue("Sound", "SFX Damping"):
		App.g_kConfigMapping.SetFloatValue("Sound", "SFX Damping", 0.5)
	App.g_kSoundManager.SetSFXAdjustmentMinimum(App.g_kConfigMapping.GetFloatValue("Sound", "SFX Damping"))

	if (App.g_kConfigMapping.HasValue("General Options", "Difficulty")):
		global g_eNewGameDifficulty
		g_eNewGameDifficulty = App.g_kConfigMapping.GetIntValue ("General Options", "Difficulty")
		App.Game_SetDifficulty (App.g_kConfigMapping.GetIntValue ("General Options", "Difficulty"))		

###############################################################################
#	SaveConfig(pPane, pEvent)
#	
#	Saves configuration information.
#	
#	Args:	pPane	- target of the event
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def SaveConfig(pPane, pEvent):
	if (g_bConfigLoaded == 0):
		if (pPane != None):
			pPane.CallNextHandler(pEvent)

		return

	#	App.g_kUtopiaModule.SaveConfigFile()
	App.g_kConfigMapping.SetIntValue("General Options", "Space Dust", App.SpaceCamera_IsSpaceDustEnabledInGame())
	App.g_kConfigMapping.SetIntValue("General Options", "Glow Maps", App.g_kLODModelManager.AreGlowMapsEnabled())
	App.g_kConfigMapping.SetIntValue("General Options", "Enhanced Glows", App.SetClass_IsGlowEnabled())
	App.g_kConfigMapping.SetIntValue("General Options", "Specular Maps", App.g_kLODModelManager.AreSpecularMapsEnabled())
	App.g_kConfigMapping.SetIntValue("General Options", "Motion Blur", App.g_kLODModelManager.IsMotionBlurEnabled())
	App.g_kConfigMapping.SetIntValue("General Options", "Tool Tips", App.CharacterClass_AreToolTipsEnabled())
	App.g_kConfigMapping.SetIntValue("General Options", "Collision Alert", App.CharacterClass_IsCollisionAlertEnabled())

	App.g_kConfigMapping.SetIntValue("Graphics Options", "Effect Detail", App.EffectController_GetEffectLevel())

	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
	if (pSubtitle == None):
		pSubtitle = CreateSubtitleWindow()
	if (pSubtitle.IsOn()):
		App.g_kConfigMapping.SetIntValue("General Options", "Subtitles", 1)
	else:
		App.g_kConfigMapping.SetIntValue("General Options", "Subtitles", 0)
	
	App.g_kConfigMapping.SetIntValue("General Options", "Collisions", App.ProximityManager_GetPlayerCollisionsEnabled())

	if (App.DamageableObject_IsDamageGeometryEnabled() and App.DamageableObject_IsVolumeDamageGeometryEnabled() and App.DamageableObject_IsBreakableComponentsEnabled()):
		App.g_kConfigMapping.SetIntValue("Graphics Options", "Visible Damage", 3)
	elif (App.DamageableObject_IsDamageGeometryEnabled() and App.DamageableObject_IsVolumeDamageGeometryEnabled() and not App.DamageableObject_IsBreakableComponentsEnabled()):
		App.g_kConfigMapping.SetIntValue("Graphics Options", "Visible Damage", 2)
	elif (App.DamageableObject_IsDamageGeometryEnabled() and not App.DamageableObject_IsVolumeDamageGeometryEnabled() and not App.DamageableObject_IsBreakableComponentsEnabled()):
		App.g_kConfigMapping.SetIntValue("Graphics Options", "Visible Damage", 1)
	else:
		App.g_kConfigMapping.SetIntValue("Graphics Options", "Visible Damage", 0)

	App.g_kConfigMapping.SetIntValue("Graphics Options", "Number of Lights", App.ObjectClass_GetMaximumNumberOfLights())

	# Check on the graphics display device and windowed/fullscreen
	App.g_kConfigMapping.SetIntValue("Graphics Options", "Fullscreen Mode", App.UtopiaApp_GetApp().IsFullscreen())

	App.g_kConfigMapping.SetIntValue("Graphics Options", "Display Width", App.g_kIconManager.GetScreenWidth())
	App.g_kConfigMapping.SetIntValue("Graphics Options", "Display Height", App.g_kIconManager.GetScreenHeight())
	App.g_kConfigMapping.SetIntValue("Graphics Options", "Display Depth", App.GraphicsModeInfo_GetCurrentMode().GetColorDepth())
	App.g_kConfigMapping.SetStringValue("Graphics Options", "Display Device", App.UtopiaApp_GetApp().GetDeviceDesc())

	App.g_kConfigMapping.SetIntValue("Graphics Options", "LOD Skip", App.g_kLODModelManager.GetDropLODLevel())
	App.g_kConfigMapping.SetIntValue("Graphics Options", "MipMaps", App.g_kImageManager.AreMipMapsEnabled())
	App.g_kConfigMapping.SetIntValue("Graphics Options", "Texture Detail", App.g_kImageManager.GetImageDetail())

	App.g_kConfigMapping.SetIntValue("Sound", "Music", App.g_kMusicManager.IsEnabled())
	App.g_kConfigMapping.SetIntValue("Sound", "Sound Enabled", App.g_kSoundManager.IsSFXEnabled())
	App.g_kConfigMapping.SetIntValue("Sound", "Voice Enabled", App.g_kSoundManager.IsVoiceEnabled())


	# Save sound volume and music volume.
	App.g_kConfigMapping.SetFloatValue("Sound", "SFX Volume", App.g_kSoundManager.GetSFXVolume())
	App.g_kConfigMapping.SetFloatValue("Sound", "Voice Volume", App.g_kSoundManager.GetVoiceVolume())
	App.g_kConfigMapping.SetFloatValue("Sound", "Music Volume", App.g_kMusicManager.GetVolume())

	App.g_kConfigMapping.SetIntValue("General Options", "Difficulty", App.Game_GetDifficulty ())

	App.g_kConfigMapping.SetTGStringValue ("General Options", "Captain Name", App.g_kUtopiaModule.GetCaptainName ())

	App.g_kConfigMapping.SetFloatValue("General Options", "Played Tutorial", App.g_kVarManager.GetFloatVariable ("global", "PlayedTutorial"))

	if (App.g_kUtopiaModule.GetGamePath()):
		App.g_kConfigMapping.SetStringValue("General Options", "Game Path", App.g_kUtopiaModule.GetGamePath())
	if (App.g_kUtopiaModule.GetDataPath()):
		App.g_kConfigMapping.SetStringValue("General Options", "Data Path", App.g_kUtopiaModule.GetDataPath())

	App.g_kConfigMapping.SaveConfigFile("Options.cfg")



	if (pPane != None):
		pPane.CallNextHandler(pEvent)

def ToggleConfigureSelected (pContentPane, iChild):
	pTabPane = App.TGPane_Cast (pContentPane.GetNthChild (0))

	for i in range (0, 4):
		pButton = App.STRoundedButton_Cast (pTabPane.GetNthChild (i))
		if (i == iChild):
			pButton.SetSelected (0)
		else:
			pButton.SetNotSelected (0)

###############################################################################
#	HandleConfigureGeneralTab(pContentPane, pEvent)
#	
#	Event handler for clicking on the "General Options" selection in the
#	configuration menu.
#	
#	Args:	pConfigurePane	- the configuration pane
#			pEvent			- the event
#	
#	Return:	none
###############################################################################
def HandleConfigureGeneralTab(pContentPane, pEvent):
	global g_pcConfigurePaneName
	g_pcConfigurePaneName = "general"

	pConfigurePane = App.TGPane_Cast (pEvent.GetSource ())
	pSubTab = pConfigurePane.GetNthChild (1)
	if (pSubTab):
		pConfigurePane.DeleteChild (pSubTab)

	pOptionsPane = App.TGPane_Cast(pEvent.GetObjPtr())
	BuildConfigureGeneralTab(pOptionsPane, pContentPane)

	pContentPane.CallNextHandler(pEvent)

###############################################################################
#	BuildConfigureGeneralTab(pOptionsPane, pContentPane, bGameEnded)
#	
#	Builds the menu that appears when the Configure->General tab is selected.
#	
#	Args:	pOptionsPane - the right-hand pane of the configure menu
#	
#	Return:	none
###############################################################################
def BuildConfigureGeneralTab(pOptionsPane, pContentPane, bGameEnded = 0):
	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	pTopWindow = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTopWindow.FindMainWindow(App.MWT_SUBTITLE))

	# Remove the old content.
	pOptionsPane.KillChildren()
	pOptionsPane.SetNotExclusive()

	fMenuWidth = pOptionsPane.GetWidth ()

	# Subtitle options
	pTopWindow = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTopWindow.FindMainWindow(App.MWT_SUBTITLE))
	pOptionsPane.AddChild (CreateMenuYesNoButton (pDatabase.GetString("Subtitles"), ET_SUBTITLE_TOGGLE, pSubtitle.IsOn (), fMenuWidth))

	# Collision options
	iCollisionsOption = App.ProximityManager_GetPlayerCollisionsEnabled()
	global g_idCollisionButton
	pCollisionButton = CreateMenuYesNoButton(pDatabase.GetString("Collisions"), ET_COLLISIONS_TOGGLE, iCollisionsOption, fMenuWidth)
	g_idCollisionButton = pCollisionButton.GetObjID()
	pOptionsPane.AddChild(pCollisionButton)
	pGame = App.MultiplayerGame_Cast (App.Game_GetCurrentGame ())
	if (pGame and not App.g_kUtopiaModule.IsHost () and not bGameEnded):
		pCollisionButton.SetDisabled (1)

	pOptionsPane.AddChild(CreateMenuYesNoButton(pDatabase.GetString("Character Tool Tips"), ET_TOOL_TIP_TOGGLE, App.CharacterClass_AreToolTipsEnabled(), fMenuWidth))
	pOptionsPane.AddChild(CreateMenuYesNoButton(pDatabase.GetString("Collision Alert"), ET_COLLISION_ALERT_TOGGLE, App.CharacterClass_IsCollisionAlertEnabled(), fMenuWidth))

	pOptionsPane.SetFocus (pOptionsPane.GetFirstChild ())

	# Unload localization database.
	App.g_kLocalizationManager.Unload(pDatabase)
	
	ToggleConfigureSelected (pContentPane, 0)

	global g_iMovieMode
	if (g_iMovieMode != 3):
		g_iMovieMode = 3
		PlayBackgroundMovie (1)

###############################################################################
#	HandleConfigureSoundTab(pContent, pEvent)
#	
#	Event handler for clicking on the "Sound" selection in the
#	configuration menu.
#	
#	Args:	pConfigurePane	- the configuration pane
#			pEvent			- the event
#	
#	Return:	none
###############################################################################
def HandleConfigureSoundTab(pContentPane, pEvent):
	global g_pcConfigurePaneName
	g_pcConfigurePaneName = "sound"

	pConfigurePane = App.TGPane_Cast (pEvent.GetSource ())
	pSubTab = pConfigurePane.GetNthChild (1)
	if (pSubTab):
		pConfigurePane.DeleteChild (pSubTab)

	pOptionsPane = App.TGPane_Cast(pEvent.GetObjPtr())
	BuildConfigureSoundTab(pOptionsPane, pContentPane)

	pContentPane.CallNextHandler(pEvent)

###############################################################################
#	BuildConfigureSoundTab(pOptionsPane, pContentPane, bGameEnded)
#	
#	Builds the menu that appears when the Configure->Sound tab is selected.
#	
#	Args:	pOptionsPane - the right-hand pane of the configure menu
#	
#	Return:	none
###############################################################################

def BuildConfigureSoundTab (pOptionsPane, pContentPane, bGameEnded = 0):
	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	# Remove the old content.
	pOptionsPane.KillChildren()
	pOptionsPane.SetNotExclusive()
	fMenuWidth = pOptionsPane.GetWidth ()

	# Sound Quality menu
	pSoundQualityMenu = App.STMenu_CreateW(pDatabase.GetString("Sound Quality"))
	pSubPane = App.STSubPane_Cast(pSoundQualityMenu.GetSubPane())
	pSubPane.SetRadioGroup(1)
	pOptionsPane.AddChild(pSoundQualityMenu, 0, 0, 0)
	BuildSoundQualityMenu(pSoundQualityMenu, pDatabase, fMenuWidth)
	pSoundQualityMenu.ForceUpdate ()

	# If the game is running, disable the sound quality menu.
	if App.Game_GetCurrentGame()  and  (not bGameEnded):
		# The game is running.
		pSoundQualityMenu.Close()
		pSoundQualityMenu.SetDisabled()

	pExtraPane = App.TGPane_Create (0.01, 0.01)
	pOptionsPane.AddChild (pExtraPane, 0, 0, 0)

	# sound enabled
	pOptionsPane.AddChild(CreateMenuYesNoButton (pDatabase.GetString("SFX"), ET_SOUND_TOGGLE, App.g_kSoundManager.IsSFXEnabled(), fMenuWidth), 0, 0, 0)

	# SFX Volume
	pSFXVolume = CreateVolumeButton (pDatabase.GetString("SFX Volume"), ET_SOUND_VOLUME, App.g_kSoundManager.GetSFXVolume (), pSoundQualityMenu.GetWidth ())
	pOptionsPane.AddChild(pSFXVolume, 0, 0, 0)

	pExtraPane = App.TGPane_Create (0.01, 0.01)
	pOptionsPane.AddChild (pExtraPane, 0, 0, 0)

	# voice enabled
	pOptionsPane.AddChild(CreateMenuYesNoButton (pDatabase.GetString("Voice"), ET_VOICE_TOGGLE, App.g_kSoundManager.IsVoiceEnabled(), fMenuWidth), 0, 0, 0)

	# voice Volume
	pVoiceVolume = CreateVolumeButton (pDatabase.GetString("Voice Volume"), ET_VOICE_VOLUME, App.g_kSoundManager.GetVoiceVolume (), pSoundQualityMenu.GetWidth ())
	pOptionsPane.AddChild(pVoiceVolume, 0, 0, 0)

	pExtraPane = App.TGPane_Create (0.01, 0.01)
	pOptionsPane.AddChild (pExtraPane, 0, 0, 0)

	# Music
	pOptionsPane.AddChild(CreateMenuYesNoButton (pDatabase.GetString("Music"), ET_MUSIC_TOGGLE, App.g_kMusicManager.IsEnabled(), fMenuWidth), 0, 0, 0)

	# Music volume
	pMusicVolume = CreateVolumeButton (pDatabase.GetString("Music Volume"), ET_MUSIC_VOLUME, App.g_kMusicManager.GetVolume (), pSoundQualityMenu.GetWidth ())
	pOptionsPane.AddChild(pMusicVolume, 0, 0, 0)

	pOptionsPane.SetFocus (pOptionsPane.GetFirstChild ())

	pOptionsPane.Layout ()

	# Unload localization database.
	App.g_kLocalizationManager.Unload(pDatabase)

	ToggleConfigureSelected (pContentPane, 1)

	global g_iMovieMode
	if (g_iMovieMode != 1):
		g_iMovieMode = 1
		PlayBackgroundMovie (1)

def GetGraphicMasterSetting():
#	print ("GM lod level" + str (App.g_kLODModelManager.GetDropLODLevel()))
#	print ("GM mip map" + str (App.g_kImageManager.AreMipMapsEnabled()))
#	print ("GM glow maps" + str (App.g_kLODModelManager.AreGlowMapsEnabled()))
#	print ("GM space dust" + str (App.SpaceCamera_IsSpaceDustEnabledInGame()))
#	print ("GM image detail" + str (App.g_kImageManager.GetImageDetail()))
#	print ("GM Geometry damage" + str (App.DamageableObject_IsDamageGeometryEnabled()))
#	print ("GM Specular maps" + str (App.g_kLODModelManager.AreSpecularMapsEnabled()))
#	print ("GM motion blur" + str (App.g_kLODModelManager.IsMotionBlurEnabled()))
#	print ("GM Volume damage" + str (App.DamageableObject_IsVolumeDamageGeometryEnabled()))
#	print ("GM Breakable components" + str (App.DamageableObject_IsBreakableComponentsEnabled()))

	if (App.g_kLODModelManager.GetDropLODLevel() == 0 
		and App.g_kImageManager.AreMipMapsEnabled() == 1 
		and App.g_kLODModelManager.AreGlowMapsEnabled() == 1 
		and App.SpaceCamera_IsSpaceDustEnabledInGame() == 1 
		and App.g_kImageManager.GetImageDetail() == 2 and App.DamageableObject_IsDamageGeometryEnabled() == 1
		and App.g_kLODModelManager.AreSpecularMapsEnabled() == 1
		and App.g_kLODModelManager.IsMotionBlurEnabled() == 1
		and App.DamageableObject_IsVolumeDamageGeometryEnabled() == 1 
		and App.DamageableObject_IsBreakableComponentsEnabled() == 1):
#		print ("GM Graphics level high")
		return 2

	elif (App.g_kLODModelManager.GetDropLODLevel() == 1 
		and App.g_kImageManager.AreMipMapsEnabled() == 1 
		and App.g_kLODModelManager.AreGlowMapsEnabled() == 1 
		and App.SpaceCamera_IsSpaceDustEnabledInGame() == 1 
		and App.g_kImageManager.GetImageDetail() == 1 and App.DamageableObject_IsDamageGeometryEnabled() == 1 
		and App.g_kLODModelManager.AreSpecularMapsEnabled() == 0
		and App.g_kLODModelManager.IsMotionBlurEnabled() == 0
		and App.DamageableObject_IsVolumeDamageGeometryEnabled() == 1 
		and App.DamageableObject_IsBreakableComponentsEnabled() == 0):
#		print ("GM Graphics level medium")
		return 1

	elif (App.g_kLODModelManager.GetDropLODLevel() == 1 and App.g_kImageManager.AreMipMapsEnabled() == 1 
		and App.g_kLODModelManager.AreGlowMapsEnabled() == 0 and App.SpaceCamera_IsSpaceDustEnabledInGame() == 0 
		and App.g_kLODModelManager.AreSpecularMapsEnabled() == 0
		and App.g_kLODModelManager.IsMotionBlurEnabled() == 0
		and App.g_kImageManager.GetImageDetail() == 0 
		and App.DamageableObject_IsDamageGeometryEnabled() == 0 and App.DamageableObject_IsVolumeDamageGeometryEnabled() == 0 
		and App.DamageableObject_IsBreakableComponentsEnabled() == 0):
#		print ("GM Graphics level low")
		return 0

	else:
#		print ("GM Graphics level custom")
		return 3


def GetTextureDetailSetting():
	return App.g_kImageManager.GetImageDetail()


###############################################################################
#	HandleConfigureGraphicsTab(pContentPane, pEvent)
#	
#	Event handler for clicking on the "Graphics" selection in the
#	configuration menu.
#	
#	Args:	pPane			- the content pane, if not None
#			pEvent			- the event
#	
#	Return:	none
###############################################################################
def HandleConfigureGraphicsTab(pPane, pEvent):
	global g_pcConfigurePaneName
	g_pcConfigurePaneName = "graphics"

	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pMiddleArea = App.TGPane_Cast(pOptionsWindow.GetNthChild(1))
	pConfigurePane = App.TGPane_Cast(pMiddleArea.GetNthChild(0))
	pContentPane = App.TGPane_Cast (pConfigurePane.GetNthChild (0))
	pTabPane = App.TGPane_Cast (pContentPane.GetNthChild (0))
	pOptionsPane = App.TGPane_Cast (pContentPane.GetNthChild (1))

	pSubTab = pConfigurePane.GetNthChild (1)
	if (pSubTab):
		pConfigurePane.DeleteChild (pSubTab)

	BuildConfigureGraphicsTab (pOptionsPane, pContentPane)

	if pEvent:
		pContentPane.CallNextHandler(pEvent)

###############################################################################
#	BuildConfigureGraphicsTab(pOptionsPane, pContentPane, bGameEnded)
#	
#	Builds the menu that appears when the Configure->Graphics tab is selected.
#	
#	Args:	pOptionsPane - the right-hand pane of the configure menu
#	
#	Return:	none
###############################################################################
def BuildConfigureGraphicsTab (pOptionsPane, pContentPane, bGameEnded = 0):
	# Load localization database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")
	pGame = App.Game_GetCurrentGame ()

	# Remove the old content.
	pOptionsPane.KillChildren()
#	pOptionsPane.SetNotExclusive()

	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pContentWindow = App.STStylizedWindow_Create("StylizedWindow", "NoMinimize", "", 0.0, 0.0, App.STSubPane_Create(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH, LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT))
	pContentWindow.SetFixedSize(LCARS.MAIN_MENU_MIDDLE_CONTENT_WIDTH * 0.46, LCARS.MAIN_MENU_MIDDLE_CONTENT_HEIGHT * 0.9)
	pContentWindow.Resize(pContentWindow.GetMaximumWidth(), pContentWindow.GetMaximumHeight())
	pOptionsPane.AddChild(pContentWindow, 0.0, 0.0, 0)

	pGraphicsMenu = App.GraphicsMenu_CreateW(pDatabase.GetString("Graphics"))
	pGraphicsMenu.SetNotVisible ()
	pGraphicsMenu.SetDisabled ()
	pContentWindow.AddChild(pGraphicsMenu, 0, 0, 0)
	fMenuWidth = pContentWindow.GetWidth ()

	pButton = pGraphicsMenu.GetDevicesMenu()
	pContentWindow.AddChild(pButton, 0, 0, 0)
	pButton = pGraphicsMenu.GetResolutionMenu()
	pContentWindow.AddChild(pButton, 0, 0, 0)

	if (App.g_kUtopiaModule.GetTestMenuState () > 0):
		pButton = pGraphicsMenu.GetSizeToggle()
		pContentWindow.AddChild(pButton, 0, 0, 0)    
		 
	pButton = pGraphicsMenu.GetColorDepthToggle()
	pContentWindow.AddChild(pButton, 0, 0, 0)
	pButton.Resize (fMenuWidth, g_fButtonHeight, 0)

	DisableResChangeButtons ()

	pGraphicsMenu.ResetToggles ()

	pExtraPane = App.TGPane_Create (0.01, 0.01)
	pContentWindow.AddChild(pExtraPane, 0, 0, 0)

	iMasterSetting = GetGraphicMasterSetting()
	kMasterToggles =  ((pDatabase.GetString("HIGH  MED [LOW] CUSTOM"), ET_GRAPHICS_OPTIONS_MASTER, 0),
					   (pDatabase.GetString("HIGH [MED] LOW  CUSTOM"), ET_GRAPHICS_OPTIONS_MASTER, 1),
					   (pDatabase.GetString("[HIGH] MED  LOW  CUSTOM"), ET_GRAPHICS_OPTIONS_MASTER, 2),
					   (pDatabase.GetString("HIGH  MED  LOW [CUSTOM]"), ET_GRAPHICS_OPTIONS_MASTER, 3))

	pButton = CreateMenuToggleButton(pDatabase.GetString("Master Graphic Quality:"), kMasterToggles, iMasterSetting, fMenuWidth)
	pButton.SetChosen (1)
	global g_idMasterGraphicsButton
	g_idMasterGraphicsButton = pButton.GetObjID()
	pMasterGraphicsButton = pButton
	pContentWindow.AddChild(pButton, 0, 0, 0)
	if (pGame and not bGameEnded):
		pMasterGraphicsButton.SetDisabled ()

	pExtraPane = App.TGPane_Create (0.01, 0.01)
	pContentWindow.AddChild(pExtraPane, 0, 0, 0)

	# LOD
	iLODSkipOption = App.g_kLODModelManager.GetDropLODLevel()
	kLODSkipToggles = ((pDatabase.GetString("[HIGH] MED  LOW"), ET_GRAPHICS_OPTIONS_LOD, 0),
					   (pDatabase.GetString("HIGH [MED] LOW"), ET_GRAPHICS_OPTIONS_LOD, 1),
					   (pDatabase.GetString("HIGH  MED [LOW]"), ET_GRAPHICS_OPTIONS_LOD, 2))
	pButton = CreateMenuToggleButton(pDatabase.GetString("Model Detail:"), kLODSkipToggles, iLODSkipOption, fMenuWidth)
	pContentWindow.AddChild(pButton, 0, 0, 0)
	if (pGame and not bGameEnded):
		pButton.SetDisabled ()


	# Texture Detail
	iTextureDetail	= GetTextureDetailSetting()
	kTextureDetailToggles = ((pDatabase.GetString("HIGH  MED [LOW]"), ET_GRAPHICS_OPTIONS_TEXTURE_DETAIL, 0),
							 (pDatabase.GetString("HIGH [MED] LOW"), ET_GRAPHICS_OPTIONS_TEXTURE_DETAIL, 1),
							 (pDatabase.GetString("[HIGH] MED  LOW"), ET_GRAPHICS_OPTIONS_TEXTURE_DETAIL, 2))

	pButton = CreateMenuToggleButton(pDatabase.GetString("Texture Detail:"), kTextureDetailToggles, iTextureDetail, fMenuWidth)
	pContentWindow.AddChild(pButton, 0, 0, 0)
	if (pGame and not bGameEnded):
		pButton.SetDisabled ()

	# Visible damage on/off
	if (App.DamageableObject_IsDamageGeometryEnabled() and App.DamageableObject_IsVolumeDamageGeometryEnabled() and App.DamageableObject_IsBreakableComponentsEnabled()):
		iVisibleDamageOption = 3
	elif (App.DamageableObject_IsDamageGeometryEnabled() and App.DamageableObject_IsVolumeDamageGeometryEnabled() and not App.DamageableObject_IsBreakableComponentsEnabled()):
		iVisibleDamageOption = 2
	elif (App.DamageableObject_IsDamageGeometryEnabled() and not App.DamageableObject_IsVolumeDamageGeometryEnabled() and not App.DamageableObject_IsBreakableComponentsEnabled()):
		iVisibleDamageOption = 1
	else:
		iVisibleDamageOption = 0

	kVisibleDamageToggles = ((pDatabase.GetString("ON [OFF]"), ET_GRAPHICS_OPTIONS_VISIBLE_DAMAGE, 0),
							(pDatabase.GetString("HIGH  MED [LOW]"), ET_GRAPHICS_OPTIONS_VISIBLE_DAMAGE, 1),
							(pDatabase.GetString("HIGH [MED] LOW"), ET_GRAPHICS_OPTIONS_VISIBLE_DAMAGE, 2),
							(pDatabase.GetString("[HIGH] MED  LOW"), ET_GRAPHICS_OPTIONS_VISIBLE_DAMAGE, 3))
	pButton = CreateMenuToggleButton(pDatabase.GetString("Visible Damage:"), kVisibleDamageToggles, iVisibleDamageOption, fMenuWidth)
	pContentWindow.AddChild(pButton, 0, 0, 0)
	if (pGame and not bGameEnded):
		pButton.SetDisabled ()

	# Mip Maps
	iMipMapsOption = App.g_kImageManager.AreMipMapsEnabled()
	pContentWindow.AddChild(CreateMenuYesNoButton (pDatabase.GetString("MipMaps"), ET_GRAPHICS_OPTIONS_MIPMAPS, iMipMapsOption, fMenuWidth), 0, 0, 0)

	# Glows (Maps only for now)
	iGlowOption = App.g_kLODModelManager.AreGlowMapsEnabled()
	pButton = CreateMenuYesNoButton (pDatabase.GetString("Glow Effects"), ET_GRAPHICS_OPTIONS_GLOW, iGlowOption, fMenuWidth)
	pContentWindow.AddChild(pButton, 0, 0, 0)
	if (pGame and not bGameEnded):
		pButton.SetDisabled ()

	iEnhancedGlowOption = App.SetClass_IsGlowEnabled()
	pButton = CreateMenuYesNoButton (pDatabase.GetString("Enhanced Glows"), ET_GRAPHICS_OPTIONS_ENHANCED_GLOW, iEnhancedGlowOption, fMenuWidth)
	pContentWindow.AddChild(pButton, 0, 0, 0)
	if (not App.g_kLODModelManager.AreGlowMapsEnabled()):
		pButton.SetDisabled ()

	iCanDoEnhancedGlows = App.SetClass_CanGlowBeEnabled()
	if (not iCanDoEnhancedGlows):
		pButton.SetDisabled ()

	# Specular Highligts
	iSpecularOption = App.g_kLODModelManager.AreSpecularMapsEnabled()
	pContentWindow.AddChild(CreateMenuYesNoButton (pDatabase.GetString("Specular Highlights"), ET_GRAPHICS_OPTIONS_SPECULAR, iSpecularOption, fMenuWidth), 0, 0, 0)

	# Motion blur
	iMotionBlurOption = App.g_kLODModelManager.IsMotionBlurEnabled()
	pContentWindow.AddChild(CreateMenuYesNoButton (pDatabase.GetString("Motion Blur"), ET_GRAPHICS_OPTIONS_MOTION_BLUR, iMotionBlurOption, fMenuWidth), 0, 0, 0)

	# Space Dust
	iDustOption = App.SpaceCamera_IsSpaceDustEnabledInGame()
	pContentWindow.AddChild(CreateMenuYesNoButton (pDatabase.GetString("Space Dust"), ET_GRAPHICS_OPTIONS_SPACE_DUST, iDustOption, fMenuWidth), 0, 0, 0)

	pContentWindow.SetFocus (pContentWindow.GetNthChild (1))
	pContentWindow.InteriorChangedSize ()

	pOptionsPane.Layout ()
	
	# Unload localization database.
	App.g_kLocalizationManager.Unload(pDatabase)

	ToggleConfigureSelected (pContentPane, 2)

	global g_iMovieMode
	if (g_iMovieMode != 1):
		g_iMovieMode = 1
		PlayBackgroundMovie (1)


###############################################################################
#	BuildSoundQualityMenu
#	
#	The Sound Quality menu needs to be built from the available
#	options in the SoundConfig file ProviderReserveLists.
#	
#	Args:	pSoundQualityMenu	- The menu to add children to.
#			pDatabase			- The Options TGL database.
#	
#	Return:	None
###############################################################################
def BuildSoundQualityMenu(pSoundQualityMenu, pDatabase, fMenuWidth):
	# Look through the SoundConfig file for the dictionary
	# of sound quality preferences..
	import SoundConfig
	lsKeys = SoundConfig.AllProviderReserveLists.keys()
	lsKeys.sort()
	sCurrent = App.g_kConfigMapping.GetStringValue("Sound", "ProviderReserveList")
	for sKey in lsKeys:
		# Add a menu item for this key.
		# First get its string from the TGL database...
		if pDatabase.HasString(sKey):
			pDBString = pDatabase.GetString(sKey)
			if (pDBString != None):
				# Got it.  Create a button for this.
				pButton = CreateMenuButtonString(pDBString, ET_3D_SOUND_PREFS, sKey, fMenuWidth)
				pSoundQualityMenu.AddChild(pButton)

				# Is this button the currently selected option?
				if sKey == sCurrent:
					# Yep.
					pSoundQualityMenu.SetFocus(pButton)
					pButton.SetChosen(1)

				# Is this button supported?
				if sKey == "EAXHardware"  and  (not App.g_kSoundManager.IsEAXSupported()):
					pButton.SetDisabled()
				elif sKey == "A3DHardware"  and  (not App.g_kSoundManager.IsA3DSupported()):
					pButton.SetDisabled()

###############################################################################
#	GraphicsVisibleDamage(TGObject, pEvent)
#	
#	Toggles whether or not damage geometry is enabled in the game.
#	
#	Args:	TGObject - ?
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsVisibleDamage(TGObject, pEvent):
	iDamageSetting = pEvent.GetInt ()
	if (iDamageSetting == 0):
		App.DamageableObject_SetDamageGeometryEnabled(0)
		App.DamageableObject_SetVolumeDamageGeometryEnabled(0)
		App.DamageableObject_SetBreakableComponentsEnabled(0)
	elif (iDamageSetting == 1):
		App.DamageableObject_SetDamageGeometryEnabled(1)
		App.DamageableObject_SetVolumeDamageGeometryEnabled(0)
		App.DamageableObject_SetBreakableComponentsEnabled(0)
	elif (iDamageSetting == 2):
		App.DamageableObject_SetDamageGeometryEnabled(1)
		App.DamageableObject_SetVolumeDamageGeometryEnabled(1)
		App.DamageableObject_SetBreakableComponentsEnabled(0)
	else:
		App.DamageableObject_SetDamageGeometryEnabled(1)
		App.DamageableObject_SetVolumeDamageGeometryEnabled(1)
		App.DamageableObject_SetBreakableComponentsEnabled(1)

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()

###############################################################################
#	GraphicsLOD(TGObject, pEvent)
#	
#	Toggles the LOD used
#	
#	Args:	TGObject - ?
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsLOD(TGObject, pEvent):
#	print ("LOD Level set to " + str (pEvent.GetInt ()))
	App.g_kLODModelManager.SetDropLODLevel(pEvent.GetInt())

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()


###############################################################################
#	GraphicsTextureDetail(TGObject, pEvent)
#	
#	Toggles the LOD used
#	
#	Args:	TGObject - ?
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsTextureDetail(TGObject, pEvent):
	if (pEvent.GetInt() == 0):
		App.g_kImageManager.SetImageDetail(App.g_kImageManager.LOW_IMAGE_DETAIL)
	else:
		if (pEvent.GetInt() == 1):
			App.g_kImageManager.SetImageDetail(App.g_kImageManager.MED_IMAGE_DETAIL)
		else:
			App.g_kImageManager.SetImageDetail(App.g_kImageManager.HIGH_IMAGE_DETAIL)

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()


###############################################################################
#	ToggleSubtitles(pObject, pEvent)
#	
#	Toggles whether or not subtitles are visible during the game.
#	
#	Args:	pObject	- The object that called us
#			pEvent	- The event that called us
#	
#	Return:	none
###############################################################################
def ToggleSubtitles(pObject, pEvent):
	# Get the STButton from the event's source
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	# Get the subtitle window, which we will toggle on and off
	pTopWindow = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTopWindow.FindMainWindow(App.MWT_SUBTITLE))

	if (bOn):
		pSubtitle.SetOn()
	else:
		pSubtitle.SetOff()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	ToggleToolTips(pObject, pEvent)
#	
#	Toggles whether or not subtitles are visible during the game.
#	
#	Args:	pObject	- The object that called us
#			pEvent	- The event that called us
#	
#	Return:	none
###############################################################################
def ToggleToolTips(pObject, pEvent):
	pButton = App.STButton_Cast(pEvent.GetSource())
	bOn = pButton.IsChosen()

	App.CharacterClass_SetToolTipsEnabled(bOn)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	ToggleCollisionAlert(pObject, pEvent)
#	
#	Toggles whether or not subtitles are visible during the game.
#	
#	Args:	pObject	- The object that called us
#			pEvent	- The event that called us
#	
#	Return:	none
###############################################################################
def ToggleCollisionAlert(pObject, pEvent):
	pButton = App.STButton_Cast(pEvent.GetSource())
	bOn = pButton.IsChosen()

	App.CharacterClass_SetCollisionAlertEnabled(bOn)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	GraphicsSpaceDust(TGObject, pEvent)
#	
#	Toggles whether or not space dust is visible in the game.
#	
#	Args:	TGObject - ?
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsSpaceDust(TGObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.SpaceCamera_SetSpaceDustInGame(bOn)

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()

###############################################################################
#	GraphicsGlow(TGObject, pEvent)
#	
#	Toggles whether or not glow maps are used in space sets.
#	
#	Args:	TGObject - ?
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsGlow(TGObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.g_kLODModelManager.SetGlowMapsEnabled(bOn)

	# Get the parent pane.
	pParent = App.GraphicsMenu_GetGraphicsMenu ().GetParent ()

	pButton = None
	if (pParent):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")
		pEnhancedGlowButton = GetButton (pParent, pDatabase.GetString ("Enhanced Glows"))
		App.g_kLocalizationManager.Unload(pDatabase)

		if (pEnhancedGlowButton):
			if (bOn and App.SetClass_CanGlowBeEnabled()):
				pEnhancedGlowButton.SetEnabled ()			
			else:
				pEnhancedGlowButton.SetDisabled ()			

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()

###############################################################################
#	GraphicsEnhancedGlow(TGObject, pEvent)
#	
#	Toggles whether or not the enhanced glowing effect is on.
#	
#	Args:	TGObject - ?
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsEnhancedGlow(TGObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.SetClass_SetGlowEnabled(bOn)

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()

###############################################################################
#	GraphicsSpecular(pObject, pEvent)
#	
#	Toggles whether or not specular highlights are used in space sets.
#	
#	Args:	pObject	- the target of the event
#			pEvent	- the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsSpecular(pObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.g_kLODModelManager.SetSpecularMapsEnabled(bOn)

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()

###############################################################################
#	GraphicsMotionBlur(pObject, pEvent)
#	
#	Toggles whether or not motion blur is used in space sets.
#	
#	Args:	pObject	- the target of the event
#			pEvent	- the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsMotionBlur(pObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.g_kLODModelManager.SetMotionBlurEnabled(bOn)

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()


###############################################################################
#	GraphicsMipMaps(pObject, pEvent)
#	
#	Toggles whether or not mip maps are used/created
#	
#	Args:	pObject	- the target of the event
#			pEvent	- the event that was sent
#	
#	Return:	none
###############################################################################
def GraphicsMipMaps(pObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.g_kImageManager.EnableMipMaps(bOn)

	# Set master graphics level to custom, since we just changed a setting
	CustomMasterGraphicsLevel ()


###############################################################################
#	GraphicsMaster
#	
#	Return:	None
###############################################################################
def GraphicsMaster (pObject, pIntEvent):
	iPrevSetting = GetGraphicMasterSetting()
	pMasterGraphicsButton = App.STToggle_Cast(App.TGObject_GetTGObjectPtr(g_idMasterGraphicsButton))
	if not pMasterGraphicsButton:
		pObject.CallNextHandler(pIntEvent)
		return

	iSetting = pIntEvent.GetInt ()
	if (iSetting == 3):
		# Can't set custom detail by clicking on button.  Go to
		# next setting.
		iSetting = 0
		pMasterGraphicsButton.SetState (iSetting)

	# Bring up modal dialog to confirm
	pTopWindow = App.TopWindow_GetTopWindow()
	pModalDialogWindow = App.ModalDialogWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MODAL_DIALOG))
	if (pModalDialogWindow):
		# Create a okay and cancel events
		pOkayEvent = App.TGIntEvent_Create ()
		pOkayEvent.SetEventType (ET_GRAPHICS_OPTIONS_MASTER_CONFIRMED)
		pOkayEvent.SetDestination (pIntEvent.GetDestination ())
		pOkayEvent.SetInt (iSetting)

		pCancelEvent = App.TGIntEvent_Create ()
		pCancelEvent.SetEventType (ET_GRAPHICS_OPTIONS_MASTER_CANCEL)
		pCancelEvent.SetDestination (pIntEvent.GetDestination ())
		pCancelEvent.SetInt (iPrevSetting)

		# Get text strings for title, okay, can cancel
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

		pTitle = pDatabase.GetString("Master Graphic Quality:")		
		pOkay = pDatabase.GetString("OK")		
		pCancel = pDatabase.GetString("Cancel")	   
		pText = None
		if (iSetting == 0):	
			pText = pDatabase.GetString("Master Warning Low")		
		elif (iSetting == 1):
			pText = pDatabase.GetString("Master Warning Med")		
		else:
			pText = pDatabase.GetString("Master Warning High")		

		App.g_kLocalizationManager.Unload(pDatabase)

		pModalDialogWindow.Run (pTitle, pText, pOkay, pOkayEvent, pCancel, pCancelEvent)

	pObject.CallNextHandler(pIntEvent)

	
# Reset toggle button to previous state
def GraphicsMasterCancel (pObject, pIntEvent):
	pMasterGraphicsButton = App.STToggle_Cast(App.TGObject_GetTGObjectPtr(g_idMasterGraphicsButton))
	if not pMasterGraphicsButton:
		pObject.CallNextHandler(pIntEvent)
		return

	pMasterGraphicsButton.SetState (pIntEvent.GetInt ())

	pObject.CallNextHandler(pIntEvent)

def GraphicsMasterConfirmed (pObject, pIntEvent):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	pParent = App.GraphicsMenu_GetGraphicsMenu ().GetParent ()

	if (pIntEvent.GetInt() == 2):
		# Lots of explosions
		App.EffectController_SetEffectLevel(App.EffectController.HIGH)

		# Number of lights
		App.ObjectClass_SetMaximumNumberOfLights(8)

		# Model Detail
		App.g_kLODModelManager.SetDropLODLevel(0)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Model Detail:")))
		if (pButton):
			pButton.SetState (0)

		# Mipmaps
		App.g_kImageManager.EnableMipMaps(1)
		pButton = GetButton (pParent, pDatabase.GetString("MipMaps"))
		if (pButton):
			pButton.SetChosen (1)

		# Specular
		App.g_kLODModelManager.SetSpecularMapsEnabled(1)
		pButton = GetButton (pParent, pDatabase.GetString("Specular Highlights"))
		if (pButton):
			pButton.SetChosen (1)

		# Motion Blur
		App.g_kLODModelManager.SetMotionBlurEnabled(1)
		pButton = GetButton (pParent, pDatabase.GetString("Motion Blur"))
		if (pButton):
			pButton.SetChosen (1)

		# Glow maps
		App.g_kLODModelManager.SetGlowMapsEnabled(1)
		pButton = GetButton (pParent, pDatabase.GetString("Glow Effects"))
		if (pButton):
			pButton.SetChosen (1)
		
		# Space dust
		App.SpaceCamera_SetSpaceDustInGame(1)
		pButton = GetButton (pParent, pDatabase.GetString("Space Dust"))
		if (pButton):
			pButton.SetChosen (1)
		
		# Texture detail
		App.g_kImageManager.SetImageDetail(App.g_kImageManager.HIGH_IMAGE_DETAIL)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Texture Detail:")))
		if (pButton):
			pButton.SetState (2)

		# Damage
		App.DamageableObject_SetDamageGeometryEnabled(1)
		App.DamageableObject_SetVolumeDamageGeometryEnabled(1)
		App.DamageableObject_SetBreakableComponentsEnabled(1)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Visible Damage:")))
		if (pButton):
			pButton.SetState (3)

		# Enhanced glows
		App.SetClass_SetGlowEnabled(1)

		if (App.SetClass_CanGlowBeEnabled()):
			pButton = GetButton (pParent, pDatabase.GetString("Enhanced Glows"))
			if (pButton):
				pButton.SetChosen (1)
				pButton.SetEnabled()

	elif (pIntEvent.GetInt() == 1):
		# Less explosions
		App.EffectController_SetEffectLevel(App.EffectController.MEDIUM)

		# Number of lights
		App.ObjectClass_SetMaximumNumberOfLights(6)

		# Model Detail
		App.g_kLODModelManager.SetDropLODLevel(1)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Model Detail:")))
		if (pButton):
			pButton.SetState (1)

		# Mipmaps
		App.g_kImageManager.EnableMipMaps(1)
		pButton = GetButton (pParent, pDatabase.GetString("MipMaps"))
		if (pButton):
			pButton.SetChosen (1)

		# Specular
		App.g_kLODModelManager.SetSpecularMapsEnabled(0)
		pButton = GetButton (pParent, pDatabase.GetString("Specular Highlights"))
		if (pButton):
			pButton.SetChosen (0)

		# Motion Blur
		App.g_kLODModelManager.SetMotionBlurEnabled(0)
		pButton = GetButton (pParent, pDatabase.GetString("Motion Blur"))
		if (pButton):
			pButton.SetChosen (0)

		# Glow maps
		App.g_kLODModelManager.SetGlowMapsEnabled(1)
		pButton = GetButton (pParent, pDatabase.GetString("Glow Effects"))
		if (pButton):
			pButton.SetChosen (1)
		
		# Space dust
		App.SpaceCamera_SetSpaceDustInGame(1)
		pButton = GetButton (pParent, pDatabase.GetString("Space Dust"))
		if (pButton):
			pButton.SetChosen (1)
		
		# Texture detail
		App.g_kImageManager.SetImageDetail(App.g_kImageManager.MED_IMAGE_DETAIL)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Texture Detail:")))
		if (pButton):
			pButton.SetState (1)

		# Damage
		App.DamageableObject_SetDamageGeometryEnabled(1)
		App.DamageableObject_SetVolumeDamageGeometryEnabled(1)
		App.DamageableObject_SetBreakableComponentsEnabled(0)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Visible Damage:")))
		if (pButton):
			pButton.SetState (2)

		# Enhanced glows
		App.SetClass_SetGlowEnabled(0)
		if (App.SetClass_CanGlowBeEnabled()):
			pButton = GetButton (pParent, pDatabase.GetString("Enhanced Glows"))
			if (pButton):
				pButton.SetChosen (0)
				pButton.SetEnabled()

	else:			
		# Less explosions
		App.EffectController_SetEffectLevel(App.EffectController.LOW)

		# Number of lights
		App.ObjectClass_SetMaximumNumberOfLights(2)

		# Model Detail
		App.g_kLODModelManager.SetDropLODLevel(1)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Model Detail:")))
		if (pButton):
			pButton.SetState (1)

		# Mipmaps
		App.g_kImageManager.EnableMipMaps(1)
		pButton = GetButton (pParent, pDatabase.GetString("MipMaps"))
		if (pButton):
			pButton.SetChosen (1)

		# Specular
		App.g_kLODModelManager.SetSpecularMapsEnabled(0)
		pButton = GetButton (pParent, pDatabase.GetString("Specular Highlights"))
		if (pButton):
			pButton.SetChosen (0)

		# Motion Blur
		App.g_kLODModelManager.SetMotionBlurEnabled(0)
		pButton = GetButton (pParent, pDatabase.GetString("Motion Blur"))
		if (pButton):
			pButton.SetChosen (0)

		# Glow maps
		App.g_kLODModelManager.SetGlowMapsEnabled(0)
		pButton = GetButton (pParent, pDatabase.GetString("Glow Effects"))
		if (pButton):
			pButton.SetChosen (0)
		
		# Space dust
		App.SpaceCamera_SetSpaceDustInGame(0)
		pButton = GetButton (pParent, pDatabase.GetString("Space Dust"))
		if (pButton):
			pButton.SetChosen (0)
		
		# Texture detail
		App.g_kImageManager.SetImageDetail(App.g_kImageManager.LOW_IMAGE_DETAIL)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Texture Detail:")))
		if (pButton):
			pButton.SetState (0)

		# Damage
		App.DamageableObject_SetDamageGeometryEnabled(0)
		App.DamageableObject_SetVolumeDamageGeometryEnabled(0)
		App.DamageableObject_SetBreakableComponentsEnabled(0)
		pButton = App.STToggle_Cast (GetButton (pParent, pDatabase.GetString("Visible Damage:")))
		if (pButton):
			pButton.SetState (0)


		# Enhanced glows
		App.SetClass_SetGlowEnabled(0)
		pButton = GetButton (pParent, pDatabase.GetString("Enhanced Glows"))
		if (pButton):
			pButton.SetChosen (0)
			pButton.SetDisabled()

	App.g_kLocalizationManager.Unload(pDatabase)

	pObject.CallNextHandler(pIntEvent)


###############################################################################
#	SaveGame(pObject, pEvent)
#	
#	Triggers a game save
#	
#	Args:	pObject - the target of the event, the options window
#			pEvent	- the event that was sent
#	
#	Return:	none
###############################################################################
def SaveGame(pObject, pEvent):
	# Create and show a save dialog.
	pDialog = App.STSaveDialog_Create(pObject.GetWidth(), pObject.GetHeight())
	pMenu = pDialog.GetFileMenu()

	pMenu.SetDir("saves\\")
	pMenu.SetFilter("*.*")
	pDialog.RefreshFileList()

	pObject.AddChild(pDialog)
	pObject.MoveToFront(pDialog)
	pObject.SetFocus(pDialog)

	pObject.CallNextHandler(pEvent)

def ReallySaveGame(pObject, pEvent):
	# Stop playing the movie. This will clear the actions, and all will be
	# well with the world.
	StopBackgroundMovies ()

	App.g_kUtopiaModule.SaveToFile(pEvent.GetCString())

	pObject.CallNextHandler(pEvent)

###############################################################################
#	GameLoaded
#	
#	Called when a game has just been loaded.
#	
#	Args:	pObject	- Ignored
#			pEvent	- The ET_GAME_LOADED event.
#	
#	Return:	None
###############################################################################
def GameLoaded(pObject, pEvent):
	# The game has just been loaded.
	# Update the volume of the movie manager...
	if App.g_kSoundManager.IsSFXEnabled():
		App.g_kMovieManager.SetMovieVolume( App.g_kSoundManager.GetInterfaceVolume() )
	else:
		App.g_kMovieManager.SetMovieVolume( 0.0 )

###############################################################################
#	ToggleCollisions
#	
#	Toggle whether object collisions are on or off.
#	
#	Args:	pObject	- Unused.
#			pEvent	- The bool event that's triggering this call.
#	
#	Return:	None
###############################################################################
def ToggleCollisions(pObject, pEvent):
	# Get the button from the event
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.ProximityManager_SetPlayerCollisionsEnabled(bOn)
	App.ProximityManager_SetMultiplayerPlayerCollisionsEnabled(bOn)
	pObject.CallNextHandler(pEvent)

###############################################################################
#	SetDifficulty(pObject, pEvent)
#	
#	Sets the difficulty level of the game from the options menu.
#	
#	Args:	pObject	- the options window
#			pEvent	- the event that was sent. The int in the event
#					  corresponds to the difficulty level desired.
#	
#	Return:	none
###############################################################################
def SetDifficulty(pObject, pEvent):
	eDifficulty = pEvent.GetInt()

	App.Game_SetDifficulty(eDifficulty)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	SetNewGameDifficulty(pObject, pEvent)
#	
#	Sets the difficulty level of the game from the new game menu.
#	
#	Args:	pObject	- the options window
#			pEvent	- the event that was sent. The int in the event
#					  corresponds to the difficulty level desired.
#	
#	Return:	none
###############################################################################
def SetNewGameDifficulty(pObject, pEvent):
	eDifficulty = pEvent.GetInt()
	
	pTabPane = App.TGPane_Cast (pEvent.GetSource ())
	
	# Check the button for the appropriate difficulty
	for i in range (0, 3):
		pChild = App.TGPane_Cast (pTabPane.GetNthChild (4 + i))
		pButton = App.STButton_Cast (pChild.GetNthChild (0))
		if (i == eDifficulty):
			pButton.SetChosen (1)
		else:
			pButton.SetChosen (0)

	global g_eNewGameDifficulty
	g_eNewGameDifficulty = eDifficulty

	pObject.CallNextHandler(pEvent)

###############################################################################
#	SoundVolume
#	
#	Set the sound volume.
#	
#	Args:	(event args)
#	
#	Return:	None
###############################################################################
def SoundVolume(pObject, pEvent):
	fVolume = pEvent.GetFloat ()
	App.g_kSoundManager.SetSFXVolume(fVolume)
	App.g_kSoundManager.SetInterfaceVolume(fVolume)
	if App.g_kSoundManager.IsSFXEnabled():
		App.g_kMovieManager.SetMovieVolume(fVolume)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	VoiceVolume
#	
#	Set the sound volume.
#	
#	Args:	(event args)
#	
#	Return:	None
###############################################################################
def VoiceVolume(pObject, pEvent):
	fVolume = pEvent.GetFloat ()
	App.g_kSoundManager.SetVoiceVolume(fVolume)
	
	pObject.CallNextHandler(pEvent)

###############################################################################
#	MusicVolume
#	
#	Increase the music volume one notch.
#	
#	Args:	(event args)
#	
#	Return:	None
###############################################################################
def MusicVolume(pObject, pEvent):
	fVolume = pEvent.GetFloat ()
	App.g_kMusicManager.SetVolume(fVolume)
	
	pObject.CallNextHandler(pEvent)

###############################################################################
#	MusicVolumeDecrease
#	
#	Decrease the music volume one notch.
#	
#	Args:	(event args)
#	
#	Return:	None
###############################################################################
def MusicVolumeDecrease(pObject, pEvent):
	fVolume = App.g_kMusicManager.GetVolume()
	fVolume = fVolume - 0.1
	if fVolume < 0.0:
		fVolume = 0.0
	App.g_kMusicManager.SetVolume(fVolume)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	MusicToggle
#	
#	Toggle music on or off.
#	
#	Args:	(event args)
#	
#	Return:	None
###############################################################################
def MusicToggle(pObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.g_kMusicManager.SetEnabled(bOn)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	SFXToggle
#	
#	Toggle SFX on or off.
#	
#	Args:	(event args)
#	
#	Return:	None
###############################################################################
def SFXToggle(pObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.g_kSoundManager.SetSFXEnabled(bOn)

	# Adjust movie volume.
	if App.g_kSoundManager.IsSFXEnabled():
		App.g_kMovieManager.SetMovieVolume( App.g_kSoundManager.GetInterfaceVolume() )
	else:
		App.g_kMovieManager.SetMovieVolume( 0.0 )

	pObject.CallNextHandler(pEvent)

###############################################################################
#	VoiceToggle
#	
#	Toggle Voice on or off.
#	
#	Args:	(event args)
#	
#	Return:	None
###############################################################################
def VoiceToggle(pObject, pEvent):
	pButton = App.STButton_Cast (pEvent.GetSource ())
	bOn = pButton.IsChosen ()

	App.g_kSoundManager.SetVoiceEnabled(bOn)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	SoundPrefs
#	
#	Change sound preferences.  This changes the way 3D sound is
#	rendered: which 3d sound providers it uses in what order.
#	The string event that triggers this function should contain the
#	string for the desired list in the AllProvidersReserveLists dictionary
#	in SoundConfig.py.
#	
#	Args:	pObject			- Ignored
#			pStringEvent	- Event with the key into the dictionary mentioned.
#	
#	Return:	None
###############################################################################
def SoundPrefs(pObject, pStringEvent):
	# Get the button corresponding to the string.
	pButton = App.STButton_Cast(pStringEvent.GetSource())

	# Get the name of the configuration to use.
	sWhichConfig = pStringEvent.GetCString()

	# Make sure the configuration exists...
	bSuccess = 0
	try:
		import SoundConfig
		pConfig = SoundConfig.AllProviderReserveLists[sWhichConfig]
		bSuccess = 1
	except:
		pass

	if bSuccess:
		# Ok, it exists.  Change the config file.  This needs to be saved
		# because TGSoundManager::Reload reads the config file.
		App.g_kConfigMapping.SetStringValue("Sound", "ProviderReserveList", sWhichConfig)
		App.g_kConfigMapping.SaveConfigFile("Options.cfg")

		# And restart the sound system...
		App.g_kSoundManager.Reload(1)

		# If we got the button, change the chosen status of the buttons.
		if pButton:
			pButton.SetChosen(1)

			# Go through the parent, and fix the chosen state of each of its
			# children.
			pParent = pButton.GetConceptualParent()
			if pParent:
				for i in range(pParent.GetNumChildren()):
					pOtherButton = App.STButton_Cast(pParent.GetNthChild(i))
					if pOtherButton and (pOtherButton.GetObjID() != pButton.GetObjID()):
						pOtherButton.SetChosen(0)

	pObject.CallNextHandler(pStringEvent)

###############################################################################
#	BuildTabOrder(pWindow)
#	
#	Rebuilds the tab order.
#	
#	Args:	pWindow	- the options window
#	
#	Return:	none
###############################################################################
def BuildTabOrder(pWindow):
	# Clear the tab order.
#	App.g_kFocusManager.RemoveAllObjects()
	# Setup the tab order.
	pTopArea = App.TGPane_Cast(pWindow.GetFirstChild())
	if (pTopArea == None):
		return

	pButtonPane = App.TGPane_Cast(pTopArea.GetFirstChild())
	if (pButtonPane == None):
		return

	App.g_kFocusManager.AddObjectToTabOrder(pButtonPane)

###############################################################################
#	SetVisible()
#	
#	Called when the Main Menu is set to visible.  We will forcibly refresh
#	the display by doing this.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetVisible(pWindow, bLayout):
	# We want the trek cursor
	import Icons.SystemIcons
	Icons.SystemIcons.PushTrekCursor()

	global g_pcCurrentPaneName
	if (g_pcCurrentPaneName != None):
		SwitchMiddlePane(g_pcCurrentPaneName)

#	pTopWindow = App.TopWindow_GetTopWindow()
#	if (pTopWindow):
#		pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
#		if (pOptionsWindow):
#			pTopSection = App.TGPane_Cast (pOptionsWindow.GetNthChild (0))
#			if (pTopSection):
#				pButtonPane = App.TGPane_Cast (pTopSection.GetNthChild (0))
#				if (pButtonPane):
#					pButton = App.STRoundedButton_Cast (pButtonPane.GetNthChild(0))
#					pButton.Resize (pButton.GetWidth (), pButton.GetHeight ())
#					pButton = App.STRoundedButton_Cast (pButtonPane.GetNthChild(1))
#					pButton.Resize (pButton.GetWidth (), pButton.GetHeight ())
#					pButton = App.STRoundedButton_Cast (pButtonPane.GetNthChild(2))
#					pButton.Resize (pButton.GetWidth (), pButton.GetHeight ())
#					pButton = App.STRoundedButton_Cast (pButtonPane.GetNthChild(3))
#					pButton.Resize (pButton.GetWidth (), pButton.GetHeight ())
#					pButton = App.STRoundedButton_Cast (pButtonPane.GetNthChild(4))
#					pButton.Resize (pButton.GetWidth (), pButton.GetHeight ())
#					pButton = App.STRoundedButton_Cast (pButtonPane.GetNthChild(5))
#					pButton.Resize (pButton.GetWidth (), pButton.GetHeight ())
#					pButton = App.STRoundedButton_Cast (pButtonPane.GetNthChild(6))
#					pButton.Resize (pButton.GetWidth (), pButton.GetHeight ())
#					pButton = App.STRoundedButton_Cast (pButtonPane.GetNthChild(7))
#					pButton.Resize (pButton.GetWidth (), pButton.GetHeight ())

	PlayBackgroundMovie ()

	CreateJunkTextTimer ()

	# If we're playing a multiplayer game, toggle the multiplayer window visible.
	pMultGame = App.MultiplayerGame_Cast (App.Game_GetCurrentGame ())
	if (pMultGame):
		pTopWindow = App.TopWindow_GetTopWindow()
		pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
		if (not pMultWindow.IsGameOver ()):		
			SwitchMiddlePane ("Multiplayer")		

	BuildTabOrder (pWindow)

###############################################################################
#	SetNotVisible()
#	
#	Called when the Main Menu is set to not visible.  We will forcibly refresh
#	the display by doing this.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetNotVisible (pWindow, bLayout):
	# Restore the previous cursor
	App.g_kRootWindow.PopCursor()

	# stop the movie
	StopBackgroundMovies ()

	# Kill the junk timer.
	KillJunkTextTimer ()

	# Reset the game font.
	SetupGameFont()


###############################################################################
#	GotFocus()
#	
#	Called when the options window gets the focus.
#	
#	Args:	pWindow	- the options window
#			bLayout	- false to avoid calling Layout()
#	
#	Return:	none
###############################################################################
def GotFocus(pWindow, bLayout):
	BuildTabOrder(pWindow)

	# Change the font size based on the res.
	global g_iRes
	if (App.g_kIconManager.GetScreenWidth () == 640):
		g_iRes = 0
	elif (App.g_kIconManager.GetScreenWidth () == 800):
		g_iRes = 1
	elif (App.g_kIconManager.GetScreenWidth () == 1024):
		g_iRes = 2
	elif (App.g_kIconManager.GetScreenWidth () == 1280):
		g_iRes = 3
	elif (App.g_kIconManager.GetScreenWidth () == 1600):
		g_iRes = 4
	else:
		g_iRes = 0
	
	App.g_kFontManager.SetDefaultFont(g_pcSmallFont, g_kSmallFontSize[g_iRes])


###############################################################################
#	LostFocus()
#	
#	Called when the options window loses focus
#	
#	Args:	pWindow - the options window
#			bLayout	- false to avoid calling Layout()
#	
#	Return:	none
###############################################################################
def LostFocus(pWindow, bLayout):
	# Clear the tab order.
	SaveConfig (None, None)
	App.g_kKeyboardBinding.GenerateMappingFile()

	# Default the font back to the small font.
	SetupGameFont()

###############################################################################
#	SetupGameFont()
#	
#	Called from Game::Initialize(), to set our default flight font
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupGameFont():
	# Change the font size based on the res.
	global g_iRes
	if (App.g_kIconManager.GetScreenWidth () == 640):
		g_iRes = 0
	elif (App.g_kIconManager.GetScreenWidth () == 800):
		g_iRes = 1
	elif (App.g_kIconManager.GetScreenWidth () == 1024):
		g_iRes = 2
	elif (App.g_kIconManager.GetScreenWidth () == 1280):
		g_iRes = 3
	elif (App.g_kIconManager.GetScreenWidth () == 1600):
		g_iRes = 4
	else:
		g_iRes = 0

	# Default the font back to the small font.
	App.g_kFontManager.SetDefaultFont(g_pcFlightSmallFont, g_kFlightSmallFontSize [g_iRes])

###############################################################################
#	SetupMenuFont()
#	
#	Called to set the menu font.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupMenuFont():
	# Change the font size based on the res.
	global g_iRes
	if (App.g_kIconManager.GetScreenWidth () == 640):
		g_iRes = 0
	elif (App.g_kIconManager.GetScreenWidth () == 800):
		g_iRes = 1
	elif (App.g_kIconManager.GetScreenWidth () == 1024):
		g_iRes = 2
	elif (App.g_kIconManager.GetScreenWidth () == 1280):
		g_iRes = 3
	elif (App.g_kIconManager.GetScreenWidth () == 1600):
		g_iRes = 4
	else:
		g_iRes = 0

	# Default the font back to the small font.
	App.g_kFontManager.SetDefaultFont(g_pcSmallFont, g_kSmallFontSize [g_iRes])

###############################################################################
#	RunOverrideMission()
#	
#	Forcibly run a mission instead of the default episode and mission
#	
#	Args:	pcEpisode	- override episode
#			pcMission	- override mission
#	
#	Return:	none
###############################################################################
def RunOverrideMission(pcEpisode, pcMission):
	pGame = App.Game_GetCurrentGame ()
	App.Game_SetDifficultyReallyIMeanIt(g_eNewGameDifficulty)

	SaveConfig (None, None)

	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	App.g_kVarManager.SetStringVariable("Options", "EpisodeOverride", pcEpisode)
	App.g_kVarManager.SetStringVariable("Options", "MissionOverride", pcMission)
	pEvent = App.TGStringEvent_Create()
	pEvent.SetEventType(App.ET_NEW_GAME)
	pEvent.SetString("Maelstrom.Maelstrom")
	pEvent.SetDestination(pOptionsWindow)
	App.g_kEventManager.AddEvent(pEvent)

	# Default the font back to the small font.
	App.g_kFontManager.SetDefaultFont(g_pcFlightSmallFont, g_kFlightSmallFontSize [g_iRes])

def E1M1(pObject, pEvent):
	RunOverrideMission("Episode1", "E1M1")

def E1M2(pObject, pEvent):
	RunOverrideMission("Episode1", "E1M2")

def E2M0(pObject, pEvent):
	RunOverrideMission("Episode2", "E2M0")
	
def E2M1(pObject, pEvent):
	RunOverrideMission("Episode2", "E2M1")

def E2M2(pObject, pEvent):
	RunOverrideMission("Episode2", "E2M2")

def E2M3(pObject, pEvent):
	RunOverrideMission("Episode2", "E2M3")

def E2M6(pObject, pEvent):
	RunOverrideMission("Episode2", "E2M6")

def E3M1(pObject, pEvent):
	RunOverrideMission("Episode3", "E3M1")

def E3M2(pObject, pEvent):
	RunOverrideMission("Episode3", "E3M2")

def E3M4(pObject, pEvent):
	RunOverrideMission("Episode3", "E3M4")

def E3M5(pObject, pEvent):
	RunOverrideMission("Episode3", "E3M5")

def E4M1(pObject, pEvent):
	RunOverrideMission("Episode4", "E4M1")

def E4M3(pObject, pEvent):
	RunOverrideMission("Episode4", "E4M3")

def E4M4(pObject, pEvent):
	RunOverrideMission("Episode4", "E4M4")

def E4M5(pObject, pEvent):
	RunOverrideMission("Episode4", "E4M5")

def E4M6(pObject, pEvent):
	RunOverrideMission("Episode4", "E4M6")

def E5M1(pObject, pEvent):
	RunOverrideMission("Episode5", "E5M1")

def E5M2(pObject, pEvent):
	RunOverrideMission("Episode5", "E5M2")

def E5M3(pObject, pEvent):
	RunOverrideMission("Episode5", "E5M3")

def E5M4(pObject, pEvent):
	RunOverrideMission("Episode5", "E5M4")

def E6M1(pObject, pEvent):
	RunOverrideMission("Episode6", "E6M1")

def E6M2(pObject, pEvent):
	RunOverrideMission("Episode6", "E6M2")

def E6M3(pObject, pEvent):
	RunOverrideMission("Episode6", "E6M3")

def E6M4(pObject, pEvent):
	RunOverrideMission("Episode6", "E6M4")

def E6M5(pObject, pEvent):
	RunOverrideMission("Episode6", "E6M5")

def E7M1(pObject, pEvent):
	RunOverrideMission("Episode7", "E7M1")

def E7M2(pObject, pEvent):
	RunOverrideMission("Episode7", "E7M2")

def E7M3(pObject, pEvent):
	RunOverrideMission("Episode7", "E7M3")

def E7M4(pObject, pEvent):
	RunOverrideMission("Episode7", "E7M4")

def E7M5(pObject, pEvent):
	RunOverrideMission("Episode7", "E7M5")

def E7M6(pObject, pEvent):
	RunOverrideMission("Episode7", "E7M6")

def E8M1(pObject, pEvent):
	RunOverrideMission("Episode8", "E8M1")

def E8M2(pObject, pEvent):
	RunOverrideMission("Episode8", "E8M2")

def HandleCustomMission(pObject, pEvent):
	pGame = App.Game_GetCurrentGame ()
	App.Game_SetDifficultyReallyIMeanIt(g_eNewGameDifficulty)

	SaveConfig (None, None)

	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	pNewEvent = App.TGStringEvent_Create()
	pNewEvent.SetEventType(App.ET_NEW_GAME)
	kString = App.TGString()
	pEvent.GetString(kString)
	pNewEvent.SetString("Custom." + kString.GetCString() + "." + kString.GetCString())
	pNewEvent.SetDestination(pOptionsWindow)
	App.g_kEventManager.AddEvent(pNewEvent)

	# Default the font back to the small font.
	App.g_kFontManager.SetDefaultFont(g_pcFlightSmallFont, g_kFlightSmallFontSize [g_iRes])

def BackToOptions(pAction):
	global g_idCreditsSequence
	g_idCreditsSequence = App.NULL_ID

	App.g_kMovieManager.SwitchOutOfMovieMode()

	ShowWarpBackground (None, 0)

	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	pPane = App.g_kRootWindow.GetNthChild (0)
	App.g_kRootWindow.DeleteChild (pPane)

	pTopWindow.SetVisible ()

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	SetVisible (pOptionsWindow, 1)
	pTopWindow.DisableOptionsMenu (0)

	App.InterfaceModule_DoTheRightThing()

	return 0

###############################################################################
#	Credits()
#	
#	Run the main menu credits
#	
#	Args:	pObject	- override missionstandard event handler args
#			pEvent	- override missionstandard event handler args
#	
#	Return:	none
###############################################################################
def Credits(pObject, pEvent):
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	if (not pOptionsWindow) or (not pOptionsWindow.IsWindowActive()) or (not pOptionsWindow.IsCompletelyVisible()):
		pObject.CallNextHandler(pEvent)
		return

	pTopWindow.SetNotVisible()

	pTopWindow.DisableOptionsMenu(1)

	pPane = App.TGPane_Create(1.0, 1.0)
	App.g_kRootWindow.PrependChild(pPane)	# stick it in front

	pPane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,	__name__ + ".HandleKeyboardCredits")

	StopBackgroundMovies()

	pSequence = App.TGSequence_Create()
	pSequence.SetUseRealTime (1)
	pSequence.AddAction(App.TGScriptAction_Create(__name__, "ShowWarpBackground", 1))
	pSequence.AppendAction(CreateCreditsSequence(pPane))
	pAction = App.TGScriptAction_Create("MainMenu.mainmenu", "BackToOptions")
	pAction.SetUseRealTime (1)
	pSequence.AppendAction(pAction, 1.0)
	pSequence.Play()

	global g_idCreditsSequence
	g_idCreditsSequence = pSequence.GetObjID()



###############################################################################
#	GetCreditFontSize()
#	
#	Gets the appropriate font size, as best we can.
#	
#	Args:	iFontIndex	- index into the g_kSmallFontSize table
#			sTitle		- string identifier for localized title
#			pSequence	- TGSequence to which to add the credit
#			fPos		- float position in multi-credit
#			fDelay		- delay before starting next credit
#			iFontIndex	- 
#	
#	Return:	int			- font size
###############################################################################
def GetCreditFontSize(iFontIndex):
	iScreenWidth = App.g_kIconManager.GetScreenWidth()

	# Bump up one level at 1024 and 1280
	if (iScreenWidth >= 1024):
		iFontIndex = iFontIndex + 1

	# Bump up again at 1600
	if (iScreenWidth == 1600):
		iFontIndex = iFontIndex + 1

	# Now cap at 4
	if (iFontIndex > 4):
		iFontIndex = 4

	return (g_kSmallFontSize[iFontIndex])


###############################################################################
#	CreateNameTitleCredit()
#	
#	Helper function to make credit creation easier.  This form takes a title
#	and a name and puts the name above the title
#	
#	Args:	sName		- string name of person (non-localized)
#			sTitle		- string identifier for localized title
#			pSequence	- TGSequence to which to add the credit
#			fPos		- float position in multi-credit
#			fDelay		- delay before starting next credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Return:	none
###############################################################################
def CreateNameTitleCredit(sName, sTitle, pSequence, fPos = 15, fDelay = 0.0, iFontIndex = 2):
	if (sName):
		CreateSingleCredit(sName, pSequence, fPos, fDelay, iFontIndex)
	if (sTitle):
		CreateSingleDatabaseCredit(sTitle, pSequence, fPos + 1, fDelay, iFontIndex)


###############################################################################
#	CreateTitleNameCredit()
#	
#	Helper function to make credit creation easier.  This form takes a name and
#	a title and puts the title above the name.
#	
#	Args:	sTitle		- string identifier for localized title
#			sName		- string name of person (non-localized)
#			pSequence	- TGSequence to which to add the credit
#			fPos		- float position in multi-credit
#			fDelay		- delay before starting next credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Return:	none
###############################################################################
def CreateTitleNameCredit(sTitle, sName, pSequence, fPos = 15, fDelay = 0.0, iFontIndex = 2):
	if (sTitle):
		CreateSingleDatabaseCredit(sTitle, pSequence, fPos, fDelay, iFontIndex)
	if (sName):
		CreateSingleCredit(sName, pSequence, fPos + 1, fDelay, iFontIndex)


###############################################################################
#	CreateTitleNameHorizCredit()
#	
#	Helper function to make credit creation easier.  This form takes a name and
#	a title and puts the title to the left of the name.
#	Uses globals for the horizontal guidelines of the title and name, so they
#	don't have to be passed multiple times for aligned credits
#	
#	Args:	sTitle		- string identifier for localized title
#			sName		- string name of person (non-localized)
#			pSequence	- TGSequence to which to add the credit
#			fPos		- float position in multi-credit
#			fDelay		- delay before starting next credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Return:	none
###############################################################################
def CreateTitleNameHorizCredit(sTitle, sName, pSequence, fPos = 15, fDelay = 0.0, iFontIndex = 2):
	fHeight = fPos * 0.0375
	iFontSize = GetCreditFontSize(iFontIndex)
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))
	if not pCreditPane:
		return

	if (sTitle):
		sTitleString = g_pCreditDatabase.GetString(sTitle)
	else:
		sTitleString = None

	if (sTitleString):
		pAction = App.TGCreditAction_Create(sTitleString, pCreditPane, g_fTitleLeft, fHeight, g_fCreditDelay - fDelay, 0.25, 0.5, iFontSize, App.TGCreditAction.JUSTIFY_LEFT, App.TGCreditAction.JUSTIFY_TOP)
		pSequence.AddAction(pAction, None, fDelay)

	if (sName):
		pAction = App.TGCreditAction_CreateSTR(sName, pCreditPane, g_fNameLeft, fHeight, g_fCreditDelay - fDelay, 0.25, 0.5, iFontSize, App.TGCreditAction.JUSTIFY_LEFT, App.TGCreditAction.JUSTIFY_TOP)
		pSequence.AddAction(pAction, None, fDelay)


###############################################################################
#	CreateNameNameHorizCredit()
#	
#	Helper function to make credit creation easier.  This form takes two names
#	Uses globals for the horizontal guidelines of the title and name, so they
#	don't have to be passed multiple times for aligned credits
#	
#	Args:	sName1		- string name of person (non-localized)
#			sName2		- string name of person (non-localized)
#			pSequence	- TGSequence to which to add the credit
#			fPos		- float position in multi-credit
#			fDelay		- delay before starting next credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Return:	none
###############################################################################
def CreateNameNameHorizCredit(sName1, sName2, pSequence, fPos = 15, fDelay = 0.0, iFontIndex = 2):
	fHeight = fPos * 0.0375
	iFontSize = GetCreditFontSize(iFontIndex)
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))
	if not pCreditPane:
		return

	if (sName1):
		pAction = App.TGCreditAction_CreateSTR(sName1, pCreditPane, g_fTitleLeft, fHeight, g_fCreditDelay - fDelay, 0.25, 0.5, iFontSize, App.TGCreditAction.JUSTIFY_LEFT, App.TGCreditAction.JUSTIFY_TOP)
		pSequence.AddAction(pAction, None, fDelay)

	if (sName2):
		pAction = App.TGCreditAction_CreateSTR(sName2, pCreditPane, g_fNameLeft, fHeight, g_fCreditDelay - fDelay, 0.25, 0.5, iFontSize, App.TGCreditAction.JUSTIFY_LEFT, App.TGCreditAction.JUSTIFY_TOP)
		pSequence.AddAction(pAction, None, fDelay)


###############################################################################
#	CreateVoiceoverCredit()
#	
#	Helper function to make credit creation easier.  This form takes an actor
#	and their character and lays them out left to right, justifying to both
#	sides
#	
#	Args:	sActor		- string name of actor
#			sCharacterID- string ID of character they portray
#			pSequence	- TGSequence to which to add the credit
#			fPos		- float position in multi-credit
#			fDelay		- delay before starting next credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Return:	none
###############################################################################
def CreateVoiceoverCredit(sActor, sCharacterID, pSequence, fPos = 15, fDelay = 0.0, iFontIndex = 2):
	fHeight = fPos * 0.0375
	iFontSize = GetCreditFontSize(iFontIndex)
	sCharacter = g_pCreditDatabase.GetString(sCharacterID)
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))

	if not pCreditPane:
		return

	if (sActor):
		pAction = App.TGCreditAction_CreateSTR(sActor, pCreditPane, g_fTitleLeft, fHeight, g_fCreditDelay - fDelay, 0.25, 0.5, iFontSize, App.TGCreditAction.JUSTIFY_LEFT, App.TGCreditAction.JUSTIFY_TOP)
		pSequence.AddAction(pAction, None, fDelay)

	if (sCharacter):
		pAction = App.TGCreditAction_Create(sCharacter, pCreditPane, g_fNameLeft, fHeight, g_fCreditDelay - fDelay, 0.25, 0.5, iFontSize, App.TGCreditAction.JUSTIFY_RIGHT, App.TGCreditAction.JUSTIFY_TOP)
		pSequence.AddAction(pAction, None, fDelay)


###############################################################################
#	CreateSingleDatabaseCredit()
#	
#	Helper function to make credit creation easier.  This form makes a single
#	line credit from our global g_pCreditDatabase.  This is a global not an arg
#	because this is called a bunch with the same Options.tgl and it's a real
#	pain to pass it through many routines.
#	Used primarily by CreateNameTitleCredit()
#	
#	Args:	sStringID	- string ID
#			pSequence	- TGSequence to which to add the credit
#			fPos		- float position in multi-credit
#			fDelay		- delay before starting next credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Return:	none
###############################################################################
def CreateSingleDatabaseCredit(sStringID, pSequence, fPos = 15, fDelay = 0.0, iFontIndex = 2):
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))

	if ((sStringID == None) or (g_pCreditDatabase == None) or (not pCreditPane)):
		return

	sString = g_pCreditDatabase.GetString(sStringID)
	if (sString == None):
		return

	#
	# I'd like to use CreateSingleCredit() here, passing in the sString, but
	# a normal string and TGString require different TGCreditAction_Create()
	# calls.  So we have to duplicate the code a tiny.  Oh well.
	#
	fHeight = fPos * 0.0375
	iFontSize = GetCreditFontSize(iFontIndex)

	pAction = App.TGCreditAction_Create(sString, pCreditPane, 0.0, fHeight, g_fCreditDelay - fDelay, 0.25, 0.5, iFontSize)
	pSequence.AddAction(pAction, None, fDelay)
	


###############################################################################
#	CreateSingleCredit()
#	
#	Helper function to make credit creation easier
#	Use our global g_idCreditPane for the credit action. This is a global because
#	it really doesn't make sense to pass it for the hundreds of calls to this
#	and functions that call us when it never changes.
#	
#	Args:	sString	- string for the top line
#			pSequence	- TGSequence to which to add the credit
#			fPos		- float position in multi-credit
#			fDelay		- delay before starting next credit
#			iFontIndex	- index into the g_kSmallFontSize table
#	
#	Return:	none
###############################################################################
def CreateSingleCredit(sString, pSequence, fPos = 15, fDelay = 0.0, iFontIndex = 2):
	fHeight = fPos * 0.0375
	iFontSize = GetCreditFontSize(iFontIndex)
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))

	if (sString) and pCreditPane:
		pAction = App.TGCreditAction_CreateSTR(sString, pCreditPane, 0.0, fHeight, g_fCreditDelay - fDelay, 0.25, 0.5, iFontSize)
		pSequence.AddAction(pAction, None, fDelay)



###############################################################################
#	CreateCreditsSequence()
#	
#	Create the credits sequence to play for the Main Menu credits
#	
#	Args:	pPane	- pane in which to add credits
#	
#	Return:	none
###############################################################################
def CreateCreditsSequence(pPane):
	global g_fCreditDelay, g_pCreditDatabase, g_idCreditPane, g_fTitleLeft, g_fNameLeft

	g_idCreditPane = pPane.GetObjID()

	# This will fix the mouse cursor.
	App.InterfaceModule_DoTheRightThing()

	# Set up our credit color and Options TGL database in our global
	App.TGCreditAction_SetDefaultColor(0.65, 0.65, 1.0, 1.0)
	g_pCreditDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

	#
	# Create the master credits sequence, and make sure it is skippable
	#
	pSequence = App.TGSequence_Create()
	pSequence.SetUseRealTime (1)
	pSequence.SetSkippable(1)

	# Now add all of our Credit subsequences to our master sequence
	AddTGCredits(pSequence)
	AddNonTGProductionCredits(pSequence)
	AddActivisionCredits(pSequence)
	AddViacomCredits(pSequence)
	Add3rdPartyCredits(pSequence)

	# Add our Very Special Thanks
	g_fCreditDelay = 6.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Very Special Thanks",	pSubSeq, 11, 1.0, 3)
	CreateSingleCredit("Gene Roddenberry",				pSubSeq, 13, 1.0, 2)
	pSequence.AppendAction(pSubSeq)

	# Cleanup our global database and pointers as the last thing we do
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "UnloadCreditsDatabase"))

	return (pSequence)



###############################################################################
#	UnloadCreditsDatabase()
#	
#	Unload our credits database and clear our globals
#	
#	Args:	pAction	- TGScriptAction that called us
#	
#	Return:	none
###############################################################################
def UnloadCreditsDatabase(pAction):
	global g_pCreditDatabase, g_idCreditPane
	App.g_kLocalizationManager.Unload(g_pCreditDatabase)
	g_pCreditDatabase = None
	g_idCreditPane = App.NULL_ID
	return 0


###############################################################################
#	AddTGCredits()
#	
#	Add our TG Credits to the master credit sequence.  Expects a few globals
#	to be set by CreateCreditsSequence() which calls us:
#	g_pCreditDatabase	- set to the Options.tgl
#	g_idCreditPane		- pane passed into CreateCreditsSequence()
#	
#	Args:	pSequence	- Master sequence of credits
#	
#	Return:	none
###############################################################################
def AddTGCredits(pSequence):
	global g_fCreditDelay, g_pCreditDatabase, g_idCreditPane, g_fTitleLeft, g_fNameLeft

	g_fCreditDelay = 93.5
	pTGSeq = App.TGSequence_Create()
	pTGSeq.SetUseRealTime(1)
	CreateSingleCredit("Totally Games",									pTGSeq,   2, 1.00, 4)

	# Creative director
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	g_fCreditDelay = 5.0
	CreateSingleCredit("Lawrence Holland",								pSubSeq, 11, 0.00, 4)
	CreateSingleDatabaseCredit("Creative Director",						pSubSeq, 13, 0.10)
	pTGSeq.AddAction(pSubSeq, None, 1.0)

	# Project lead
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	g_fCreditDelay = 6.0
	CreateSingleCredit("David Litwin",									pSubSeq, 11, 0.00, 4)
	CreateSingleDatabaseCredit("Project Lead",							pSubSeq, 13, 0.10)
	CreateSingleDatabaseCredit("GSP",									pSubSeq, 14, 0.15)
	pTGSeq.AppendAction(pSubSeq, 1.0)

	# Programmers
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	g_fCreditDelay = 10.0
	CreateSingleDatabaseCredit("Programmers",							pSubSeq,  5, 0.00, 3)
	CreateNameTitleCredit("Albert Mack",		"NI",					pSubSeq,  8, 0.50)
	CreateNameTitleCredit("Kevin Deus",			"AI",					pSubSeq, 11, 0.55)
 	CreateNameTitleCredit("James Therien",		"3D Graphics",			pSubSeq, 14, 0.60)
	CreateNameTitleCredit("Erik Novales",		"IGS",					pSubSeq, 17, 0.65)
	CreateNameTitleCredit("Colin Carley",		"ASL",					pSubSeq, 20, 0.70)
	pTGSeq.AppendAction(pSubSeq, 0.5)

	# Design lead
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Game Design",							pSubSeq,  5, 0.00, 3)
	CreateNameTitleCredit("Bill Morrison",		"GDLGD",				pSubSeq,  8, 0.50)
 	CreateNameTitleCredit("Jess VanDerwalker",	"GD",					pSubSeq, 12, 1.50)
	CreateNameTitleCredit("Tony Evans",			"GD",					pSubSeq, 15, 1.55)
	CreateNameTitleCredit("Benjamin Schulson",	"GD",					pSubSeq, 18, 1.60)
	pTGSeq.AppendAction(pSubSeq, 0.5)

	# Art
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Artists",								pSubSeq,  5, 0.00, 3)
	CreateNameTitleCredit("Armand Cabrera",		"Art Lead",				pSubSeq,  8, 0.50)
 	CreateNameTitleCredit("Richard Green",		"CBA",					pSubSeq, 12, 1.50)
	CreateNameTitleCredit("Anthony Hon",		"CAA",					pSubSeq, 15, 1.55)
	CreateNameTitleCredit("Victor Bennett",		"CA",					pSubSeq, 18, 1.60)
	CreateNameTitleCredit("Matt Bein",			"SA AT",				pSubSeq, 21, 1.65)
	pTGSeq.AppendAction(pSubSeq, 0.5)

	# Quality Assurance
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	g_fCreditDelay = 8.0
	CreateSingleDatabaseCredit("QA",									pSubSeq,  7, 0.00, 3)
	CreateNameTitleCredit("Evan Birkby",		"QA Lead",				pSubSeq, 10, 0.50)
	CreateSingleDatabaseCredit("SSB",									pSubSeq, 12, 0.55)
 	CreateNameTitleCredit("Shawn Refoua",		"QA",					pSubSeq, 15, 1.50)
	CreateNameTitleCredit("Christopher Charles","QA",					pSubSeq, 18, 1.55)
	pTGSeq.AppendAction(pSubSeq, 0.5)

	# Administration
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateNameTitleCredit("Mike Hawkins",		"Proj Coord",			pSubSeq,  7, 0.00)
 	CreateNameTitleCredit("Robin Holland",		"DBD",					pSubSeq, 10, 0.05)
	CreateSingleDatabaseCredit("Admin",									pSubSeq, 15, 0.50, 3)
	CreateSingleCredit("Peter Leahy",									pSubSeq, 17, 0.55)
	CreateSingleCredit("Terry Gillespie",								pSubSeq, 18, 0.60)
	CreateSingleCredit("Penny Rosen",									pSubSeq, 19, 0.65)
	pTGSeq.AppendAction(pSubSeq, 0.5)

	# Additional Game Mission Design / Story
	g_fCreditDelay = 6.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Additional Design",						pSubSeq,  7, 0.00, 3)
	CreateNameTitleCredit("Alberto Fonseca",	"AGD AF",				pSubSeq, 10, 0.50)
 	CreateNameTitleCredit("Morgan Gray",		"AGD MG",				pSubSeq, 13, 0.55)
	CreateNameTitleCredit("Matthew Kagle",		"AGD MK",				pSubSeq, 16, 0.60)
	pTGSeq.AppendAction(pSubSeq, 0.5)

	# Additional Programming, Additional Art
	g_fCreditDelay = 8.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Additional Programming",				pSubSeq,  7, 0.00, 3)
	CreateSingleCredit("Sam Fortiner",									pSubSeq,  9, 0.50)
	CreateSingleCredit("Yossi Horowitz",								pSubSeq, 10, 0.55)
	CreateSingleCredit("Michael Zyracki",								pSubSeq, 11, 0.60)
	CreateSingleCredit("Samir Sinha",									pSubSeq, 12, 0.65)
	CreateSingleDatabaseCredit("Additional Art",						pSubSeq, 15, 1.00, 3)
	CreateSingleCredit("David Wright",									pSubSeq, 17, 1.50)
	CreateSingleCredit("Christian Bradley",								pSubSeq, 18, 1.55)
	CreateSingleCredit("Jesse Hayes",									pSubSeq, 19, 1.60)
	CreateSingleCredit("Mike Cicchi",									pSubSeq, 20, 1.65)
	CreateSingleCredit("Jim McLeod",									pSubSeq, 21, 1.70)
	pTGSeq.AppendAction(pSubSeq, 0.5)

	# TG Special Thanks
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Special Thanks",						pSubSeq,  5, 0.00, 3)
	CreateSingleCredit("Beth Gatchalian-Litwin",						pSubSeq,  7, 0.50)
	CreateSingleCredit("Cindy F. Wong",									pSubSeq,  8, 0.55)
	CreateSingleCredit("Amy Laurent Morrison",							pSubSeq,  9, 0.60)
	CreateSingleCredit("Diane Burket",									pSubSeq, 10, 0.65)
	CreateSingleCredit("K.L. Woys",										pSubSeq, 11, 0.70)
	CreateSingleCredit("Miranda L. Paugh",								pSubSeq, 12, 0.75)
	CreateSingleCredit("Lee Strom",										pSubSeq, 13, 0.80)
	CreateSingleCredit("Miye Nakahara",									pSubSeq, 14, 0.85)
	CreateSingleCredit("Arianna Huffington",							pSubSeq, 15, 0.90)
	CreateSingleCredit("Rosemary Bennett",								pSubSeq, 16, 0.95)
	CreateSingleCredit("Shuyu L. Birkby",								pSubSeq, 17, 1.00)
	CreateSingleDatabaseCredit("Morale Engineers",						pSubSeq, 20, 1.50)
	CreateSingleCredit("Lakota, Minnie and Walter",						pSubSeq, 21, 1.55)
	pTGSeq.AppendAction(pSubSeq, 0.5)

	pSequence.AddAction(pTGSeq)


###############################################################################
#	AddNonTGProductionCredits()
#	
#	Add the Non-TG credits to the master credit sequence.  Expects a few
#	globals to be set by CreateCreditsSequence() which calls us:
#	g_pCreditDatabase	- set to the Options.tgl
#	g_idCreditPane		- pane passed into CreateCreditsSequence()
#	
#	Args:	pSequence	- Master sequence of credits
#	
#	Return:	none
###############################################################################
def AddNonTGProductionCredits(pSequence):
	global g_fCreditDelay, g_pCreditDatabase, g_idCreditPane, g_fTitleLeft, g_fNameLeft

	g_fCreditDelay = 6.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Story Editing",							pSubSeq,  5, 0.00, 3)
	CreateSingleCredit("D.C. Fontana",									pSubSeq,  7, 0.05)
	CreateSingleCredit("Derek Chester",									pSubSeq,  8, 0.10)
	CreateSingleDatabaseCredit("Sound Production",						pSubSeq, 11, 0.15, 3)
	CreateSingleCredit("CB Studios",									pSubSeq, 13, 0.20)
	CreateSingleCredit("Clint Bajakian",								pSubSeq, 14, 0.25)
	CreateSingleCredit("Julian Kwasneski",								pSubSeq, 15, 0.30)
	CreateSingleDatabaseCredit("Music",									pSubSeq, 18, 0.35, 3)
	CreateSingleDatabaseCredit("Theme & OS",							pSubSeq, 20, 0.40)
	CreateSingleCredit("Danny Pelfrey",									pSubSeq, 21, 0.45)
	pSequence.AppendAction(pSubSeq, 0.5)

	#
	# Voiceover
	#
	g_fCreditDelay = 32
	pVOSeq = App.TGSequence_Create()
	pVOSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Voice-over",							pVOSeq,   2, 0.00, 4)

	# Cast, page 1
	g_fCreditDelay = 7.0
	g_fTitleLeft = 0.15
	g_fNameLeft = 0.85
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateVoiceoverCredit("Patrick Stewart",	"Picard",				pSubSeq,  7, 0.00)
	CreateVoiceoverCredit("Brent Spiner",		"Data",					pSubSeq,  9, 0.05)
	CreateVoiceoverCredit("Martha Hackett",		"Saffi",				pSubSeq, 13, 0.10)
	CreateVoiceoverCredit("Jonathan Del Arco",	"Miguel",				pSubSeq, 15, 0.15)
	CreateVoiceoverCredit("Andy Milder",		"Brex",					pSubSeq, 17, 0.20)
	CreateVoiceoverCredit("Nicholas Guest",		"Felix",				pSubSeq, 19, 0.25)
	CreateVoiceoverCredit("Lisa LoCicero",		"Kiska",				pSubSeq, 21, 0.30)
	pVOSeq.AddAction(pSubSeq, None, 0.5)

	# Cast, page 2
	g_fCreditDelay = 6.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateVoiceoverCredit("Freda Foh Shen",		"Liu",					pSubSeq,  6, 0.00)
	CreateVoiceoverCredit("Vaughn Armstrong",	"Korbus",				pSubSeq,  8, 0.05)
	CreateVoiceoverCredit(None,					"Krell",				pSubSeq,  9, 0.10)
	CreateVoiceoverCredit("Barry Dennen",		"Terrik",				pSubSeq, 11, 0.15)
	CreateVoiceoverCredit(None,					"Galor Cpt",			pSubSeq, 12, 0.20)
	CreateVoiceoverCredit("Carolyn Hennesy",	"Zeiss",				pSubSeq, 14, 0.25)
	CreateVoiceoverCredit(None,					"Haley",				pSubSeq, 15, 0.30)
	CreateVoiceoverCredit(None,					"Torenn",				pSubSeq, 16, 0.35)
	CreateVoiceoverCredit("Charles Chun",		"Takahara",				pSubSeq, 18, 0.40)
	CreateVoiceoverCredit(None,					"Yi",					pSubSeq, 19, 0.45)
	CreateVoiceoverCredit("Dennis Cockrum",		"MacCray",				pSubSeq, 21, 0.50)
	CreateVoiceoverCredit(None,					"Willis",				pSubSeq, 22, 0.55)
	CreateVoiceoverCredit(None,					"Soto",					pSubSeq, 23, 0.60)
	pVOSeq.AppendAction(pSubSeq, 0.5)

	# Cast, page 3
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	pVOSeq.AppendAction(pSubSeq, 0.5)
	CreateVoiceoverCredit("Earl Boen",			"Matan",				pSubSeq,  5, 0.00)
	CreateVoiceoverCredit(None,					"Draxon",				pSubSeq,  6, 0.05)
	CreateVoiceoverCredit(None,					"Soams",				pSubSeq,  7, 0.10)
	CreateVoiceoverCredit("Max Grodenchik",		"Dawson",				pSubSeq,  9, 0.15)
	CreateVoiceoverCredit(None,					"Praag",				pSubSeq, 10, 0.20)
	CreateVoiceoverCredit(None,					"Neb-lus",				pSubSeq, 11, 0.25)
	CreateVoiceoverCredit("Michael Reisz",		"Graff",				pSubSeq, 13, 0.30)
	CreateVoiceoverCredit(None,					"Jadeja",				pSubSeq, 14, 0.35)
	CreateVoiceoverCredit(None,					"Havar",				pSubSeq, 15, 0.40)
	CreateVoiceoverCredit("Paul Boehmer",		"Martin",				pSubSeq, 17, 0.45)
	CreateVoiceoverCredit(None,					"Sek",					pSubSeq, 18, 0.50)
	CreateVoiceoverCredit(None,					"Saalek",				pSubSeq, 19, 0.55)
	CreateVoiceoverCredit("Sean Griffin",		"Wright",				pSubSeq, 21, 0.60)
	CreateVoiceoverCredit(None,					"Verata",				pSubSeq, 22, 0.70)
	CreateVoiceoverCredit(None,					"Card Captain",			pSubSeq, 23, 0.75)
	pVOSeq.AppendAction(pSubSeq, 0.5)

	# Casting
	g_fCreditDelay = 6.0
	g_fTitleLeft = 0.20
	g_fNameLeft = 0.55
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Casting",								pSubSeq,  5, 0.00, 3)
	CreateTitleNameHorizCredit("Casting Director","Ron Surma",			pSubSeq,  7, 0.05)
	CreateTitleNameHorizCredit("Casting Assistant","Chadwick Struck",	pSubSeq,  8, 0.20)
	CreateSingleDatabaseCredit("VO Prod",								pSubSeq, 10, 0.30, 3)
	CreateTitleNameHorizCredit("Direction",		"Kris Zimmerman",		pSubSeq, 12, 0.35)
	CreateNameNameHorizCredit("SALAMI STUDIOS, LLC.",	"Devon Bowman",	pSubSeq, 14, 0.40)
	CreateNameNameHorizCredit(None,				"Mark Mercado",			pSubSeq, 15, 0.50)
	CreateNameNameHorizCredit(None,				"Gregory Cathcart",		pSubSeq, 16, 0.55)
	CreateSingleCredit("POP SOUND, Santa Monica",						pSubSeq, 18, 0.55)
	CreateNameNameHorizCredit("Stephen Dickson","Jeff Britt",			pSubSeq, 19, 0.55)
	pVOSeq.AppendAction(pSubSeq, 0.5)

	pSequence.AppendAction(pVOSeq, 2.0)


###############################################################################
#	AddActivisionCredits()
#	
#	Add the Activision credits to the master credit sequence.  Expects a few
#	globals to be set by CreateCreditsSequence() which calls us:
#	g_pCreditDatabase	- set to the Options.tgl
#	g_idCreditPane		- pane passed into CreateCreditsSequence()
#	
#	Args:	pSequence	- Master sequence of credits
#	
#	Return:	none
###############################################################################
def AddActivisionCredits(pSequence):
	global g_fCreditDelay, g_pCreditDatabase, g_idCreditPane, g_fTitleLeft, g_fNameLeft

	g_fCreditDelay = 71.0
	pActSeq = App.TGSequence_Create()
	pActSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Activision",							pActSeq,  2, 0.50, 4)

	# Production
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	g_fCreditDelay = 5.0
	g_fTitleLeft = 0.20
	g_fNameLeft = 0.55
	CreateSingleDatabaseCredit("Production",							pSubSeq,  7, 0.00, 3)
	CreateTitleNameHorizCredit("Sen Producer",		"Parker A. Davis",	pSubSeq, 10, 0.50)
 	CreateTitleNameHorizCredit("Assoc Producer",	"Glenn Ige",		pSubSeq, 13, 1.50)
	CreateTitleNameHorizCredit("Prod Coord",		"Aaron Gray",		pSubSeq, 14, 1.55)
	CreateTitleNameHorizCredit("Prod Tester",		"Douglas Mirabello",pSubSeq, 15, 1.60)
	CreateTitleNameHorizCredit("Prod Tester",		"Timothy Ogle",		pSubSeq, 16, 1.65)
	pActSeq.AddAction(pSubSeq, None, 1.0)

	# Studios
	g_fTitleLeft = 0.15
	g_fNameLeft = 0.65
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Studios",								pSubSeq,  7, 0.00, 3)
	CreateTitleNameHorizCredit("Exec Producer",		"Marc Struhl",		pSubSeq, 10, 0.50)
 	CreateTitleNameHorizCredit("VP, LAS",			"Mark Lamia",		pSubSeq, 11, 0.55)
	CreateTitleNameHorizCredit("EVP, WS",			"Larry Goldberg",	pSubSeq, 12, 0.60)
	CreateTitleNameHorizCredit("GBM",				"Jennifer Stornetta",pSubSeq,13, 0.65)
	CreateTitleNameHorizCredit("ABM",				"Elizabeth Dunn",	pSubSeq, 14, 0.70)
	CreateTitleNameHorizCredit("VP, GBM",			"Tricia Bertero",	pSubSeq, 15, 0.75)
	CreateTitleNameHorizCredit("EVP, GBM",			"Kathy Vrabeck",	pSubSeq, 16, 0.80)
	pActSeq.AppendAction(pSubSeq, 0.5)

	# Public Relations
	g_fCreditDelay = 4.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Public Relations",						pSubSeq,  7, 0.00, 3)
	CreateTitleNameHorizCredit("VP CC",				"Maryanne Lataif",	pSubSeq, 10, 0.50)
 	CreateTitleNameHorizCredit("DCC",				"Michelle Nino",	pSubSeq, 12, 0.55)
	CreateTitleNameHorizCredit("SPCC",				"Michael J. Larson",pSubSeq, 15, 0.60)
	pActSeq.AppendAction(pSubSeq, 0.5)

	# International Marketing
	g_fCreditDelay = 5.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Intl. Marketing",						pSubSeq,  7, 0.00, 3)
	CreateTitleNameHorizCredit("MM, UK & ROE",		"Carolyn London",	pSubSeq, 10, 0.50)
 	CreateTitleNameHorizCredit("PR Manager, UK",	"Guy Cunis",		pSubSeq, 11, 0.55)
	CreateTitleNameHorizCredit("PR Manager, ROE",	"Suzanne Panter",	pSubSeq, 12, 0.60)
	CreateTitleNameHorizCredit("PR Manager, Ger",	"Bernd Reinartz",	pSubSeq, 13, 0.65)
	CreateTitleNameHorizCredit("BM, UK/ROE",		"Daleep Chhabria",	pSubSeq, 14, 0.70)
	CreateTitleNameHorizCredit("MM, Germany",		"Stefan Luludes",	pSubSeq, 15, 0.75)
	CreateTitleNameHorizCredit("BM, Germany",		"Stephan Seidel",	pSubSeq, 16, 0.80)
	CreateTitleNameHorizCredit("JBM, Germany",		"Thomas Schmitt",	pSubSeq, 17, 0.85)
	CreateTitleNameHorizCredit("MD, Asia",			"Paul Butcher",		pSubSeq, 18, 0.90)
	CreateTitleNameHorizCredit("BM, Asia",		"Leigh Glover White",	pSubSeq, 19, 0.95)
	pActSeq.AppendAction(pSubSeq, 0.5)

	# Legal, Central Technology
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	g_fTitleLeft = 0.3
	g_fNameLeft = 0.55
	CreateSingleDatabaseCredit("Legal",									pSubSeq,  7, 0.00, 3)
	CreateNameNameHorizCredit("Rob Pfau",			"Michael Walker",	pSubSeq,  9, 0.25)
	CreateNameNameHorizCredit("George Rose",		"Michael Hand",		pSubSeq, 10, 0.30)
	CreateNameNameHorizCredit("Michael Larson",		None,				pSubSeq, 11, 0.35)
	g_fTitleLeft = 0.15
	g_fNameLeft = 0.65
	CreateSingleDatabaseCredit("Central Technology",					pSubSeq, 14, 0.60, 3)
	CreateTitleNameHorizCredit("Manager",			"Ed Clune",			pSubSeq, 16, 0.65)
 	CreateTitleNameHorizCredit("Inst DC",			"John Fritts",		pSubSeq, 17, 0.70)
	CreateTitleNameHorizCredit("Installer",			"Andrew Petterson",	pSubSeq, 18, 0.75)
	CreateTitleNameHorizCredit("Inst Tools",		"Alexander Rohra",	pSubSeq, 19, 0.80)
	pActSeq.AppendAction(pSubSeq, 0.5)

	# Quality Assurance
	g_fCreditDelay = 12.0
	g_fTitleLeft = 0.2
	g_fNameLeft = 0.55
	pQASeq = App.TGSequence_Create()
	pQASeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("QA",									pQASeq,   5, 0.00, 3)
	g_fCreditDelay = 5.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateTitleNameHorizCredit("QA PL",		"Siôn Rodriguez Y Gibson",	pSubSeq,  8, 0.00)
	CreateTitleNameHorizCredit("QA SPL",			"Juan Valdes",		pSubSeq, 10, 0.05)
	CreateTitleNameHorizCredit("QA FL",				"Paul Kennedy",		pSubSeq, 11, 0.15)
	CreateSingleDatabaseCredit("QA Testers",							pSubSeq, 14, 0.50, 3)
	CreateNameNameHorizCredit("Bryan Jury",			"Daniel Ko",		pSubSeq, 16, 0.55)
	CreateNameNameHorizCredit("Jay Sosnicki",	"Niles Livingston III",	pSubSeq, 17, 0.60)
	CreateNameNameHorizCredit("Paul Godilla",		"Peter Beal",		pSubSeq, 18, 0.65)
	CreateNameNameHorizCredit("William Kus",		"Dan Siskin",		pSubSeq, 19, 0.70)
	pQASeq.AddAction(pSubSeq, None, 0.5)

	# Localization QA
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateTitleNameHorizCredit("Loc PL",			"Mihai Pohontu",	pSubSeq,  8, 0.00)
	CreateTitleNameHorizCredit("Loc FL",			"Frank So",			pSubSeq,  9, 0.05)
	CreateSingleDatabaseCredit("Loc Test",								pSubSeq, 12, 0.50, 3)
	CreateNameNameHorizCredit("Kenneth Hartman",	"Mishelle Moross",	pSubSeq, 14, 0.55)
	CreateNameNameHorizCredit("Sami Tanamly",		"Jessie Rutowski",	pSubSeq, 15, 0.60)
	g_fTitleLeft = 0.1
	g_fNameLeft = 0.65
	CreateTitleNameHorizCredit("MPCT",				"Sam Nouriani",		pSubSeq, 18, 1.00)
	CreateTitleNameHorizCredit("MNTG",				"Adam Hartsfield",	pSubSeq, 19, 1.05)
	CreateTitleNameHorizCredit("MCRG",				"Tim Vanlaw",		pSubSeq, 20, 1.10)
	pQASeq.AppendAction(pSubSeq, 0.5)
	pActSeq.AppendAction(pQASeq, 0.5)

	# Visioneers
 	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Visioneers",							pSubSeq,  5, 0.00, 3)
	CreateTitleNameHorizCredit("Ext Coord",			"Chad Siedhoff",	pSubSeq,  8, 0.50)
	CreateTitleNameHorizCredit("Vis MVPs",			"Brant Clabaugh",	pSubSeq,  9, 0.60)
	CreateTitleNameHorizCredit(None,				"Ian Hill",			pSubSeq, 10, 0.70)
	CreateSingleDatabaseCredit("Vis Testers",							pSubSeq, 13, 1.00, 3)
	CreateNameNameHorizCredit("CJ Biro",			"Derek Lung",		pSubSeq, 15, 1.50)
	CreateNameNameHorizCredit("Joseph Bott",		"Karim Nouri",		pSubSeq, 16, 1.55)
	CreateNameNameHorizCredit("Wayne Chang",		"Travis Prebble",	pSubSeq, 17, 1.60)
	CreateNameNameHorizCredit("Clay Culver",		"Ken Rumsey",		pSubSeq, 18, 1.65)
	CreateNameNameHorizCredit("Bob Dudley",			"Steve Tobin",		pSubSeq, 19, 1.70)
	CreateNameNameHorizCredit("Michael Dwiel",		"John Vernon",		pSubSeq, 20, 1.75)
	CreateNameNameHorizCredit("Gary Gray",			"Henry Wang",		pSubSeq, 21, 1.80)
	CreateNameNameHorizCredit("Tom Hepner",			"Timothy Wilson",	pSubSeq, 22, 1.85)
	CreateNameNameHorizCredit("Warren Johnson",	"Dominick Ziccarelli",	pSubSeq, 23, 1.90)
	CreateNameNameHorizCredit("Scott Kasai",		None,				pSubSeq, 24, 1.95)
	pActSeq.AppendAction(pSubSeq, 0.5)

	# CS/QA Special Thanks
	g_fCreditDelay = 5.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("CS/QA ST",								pSubSeq,  7, 0.00, 3)
	CreateNameNameHorizCredit("Jim Summers",		"Neil Barizo",		pSubSeq, 10, 0.50)
	CreateNameNameHorizCredit("Jason Wong",			"Jason Kim",		pSubSeq, 11, 0.55)
	CreateNameNameHorizCredit("Nadine Theuzillot",	"Rob Lim",			pSubSeq, 12, 0.60)
	CreateNameNameHorizCredit("Joe Favazza",		"Gary Bolduc",		pSubSeq, 13, 0.65)
	CreateNameNameHorizCredit("Jeremy Gage",		"Michael Hill",		pSubSeq, 14, 0.70)
	CreateNameNameHorizCredit("Brad Saavedra",		"Willie Bolton",	pSubSeq, 15, 0.75)
	CreateNameNameHorizCredit("Bob McPherson",		"Jennifer Vitiello",pSubSeq, 16, 0.80)
	CreateNameNameHorizCredit("Indra Gunawan",		"James Hamblin",	pSubSeq, 17, 0.85)
	CreateNameNameHorizCredit("Marco Scataglini",	"Ken Love",			pSubSeq, 18, 0.90)
	CreateNameNameHorizCredit("Chris Keim",			None,				pSubSeq, 19, 0.95)
	pActSeq.AppendAction(pSubSeq, 0.5)

	# International / Creative Services
	g_fTitleLeft = 0.15
	g_fNameLeft = 0.65
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("International",							pSubSeq,  7, 0.00, 3)
	CreateTitleNameHorizCredit("SVP EP",			"Scott Dodkins",	pSubSeq,  9, 0.05)
 	CreateTitleNameHorizCredit("H PS",				"Nathalie Dove",	pSubSeq, 10, 0.10)
	CreateTitleNameHorizCredit("S LPM",				"Tamsin Lucas",		pSubSeq, 11, 0.15)
	CreateTitleNameHorizCredit("DSM E",				"Roger Walkden",	pSubSeq, 12, 0.20)
	CreateSingleDatabaseCredit("Creative Services",						pSubSeq, 16, 0.25, 3)
	CreateTitleNameHorizCredit("VP CS",				"Denise Walsh",		pSubSeq, 18, 0.30)
 	CreateTitleNameHorizCredit("MCS",				"Jill Barry",		pSubSeq, 19, 0.35)
	pActSeq.AppendAction(pSubSeq, 0.5)

	# Activision Management / Special Thanks
	g_fTitleLeft = 0.40
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Act. Management",						pSubSeq,  5, 0.00, 3)
	CreateNameNameHorizCredit("Ron Doornink",		None,				pSubSeq,  7, 0.05)
 	CreateNameNameHorizCredit("Brian Kelly",		None,				pSubSeq,  8, 0.10)
	CreateNameNameHorizCredit("Bobby Kotick",		None,				pSubSeq,  9, 0.15)
	CreateSingleDatabaseCredit("Special Thanks",						pSubSeq, 13, 0.50, 3)
	CreateNameNameHorizCredit("Mike Webster",		None,				pSubSeq, 15, 0.55)
	CreateNameNameHorizCredit("Dave Dalzell",		None,				pSubSeq, 16, 0.60)
 	CreateNameNameHorizCredit("James Mayeda",		None,				pSubSeq, 17, 0.65)
 	CreateNameNameHorizCredit("Franz Boehm",		None,				pSubSeq, 18, 0.70)
	CreateNameNameHorizCredit("Jonathan Knight",	None,				pSubSeq, 19, 0.75)
	CreateNameNameHorizCredit("Jeff Holzhauer",		None,				pSubSeq, 20, 0.80)
 	CreateNameNameHorizCredit("Jim Black",			None,				pSubSeq, 21, 0.85)
	pActSeq.AppendAction(pSubSeq, 0.5)

	pSequence.AppendAction(pActSeq, 1.0)


###############################################################################
#	AddViacomCredits()
#	
#	Add the Viacom credits to the master credit sequence.  Expects a few
#	globals to be set by CreateCreditsSequence() which calls us:
#	g_pCreditDatabase	- set to the Options.tgl
#	g_idCreditPane		- pane passed into CreateCreditsSequence()
#	
#	Args:	pSequence	- Master sequence of credits
#	
#	Return:	none
###############################################################################
def AddViacomCredits(pSequence):
	global g_fCreditDelay, g_pCreditDatabase, g_idCreditPane, g_fTitleLeft, g_fNameLeft

	g_fCreditDelay = 7.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	g_fTitleLeft = 0.25
	g_fNameLeft = 0.60
	CreateSingleDatabaseCredit("VCP",									pSubSeq,  4, 0.0, 3)
	CreateSingleDatabaseCredit("PPL",									pSubSeq,5.5, 0.1, 3)
	CreateSingleDatabaseCredit("DPD",									pSubSeq,  8, 0.2)
	CreateSingleDatabaseCredit("I&T",									pSubSeq,  9, 0.3)
 	CreateSingleCredit("Harry Lang",									pSubSeq, 10, 0.4)
	CreateSingleDatabaseCredit("SPD",									pSubSeq, 12, 0.5)
	CreateSingleDatabaseCredit("I&T",									pSubSeq, 13, 0.6)
 	CreateSingleCredit("Daniel Felts",									pSubSeq, 14, 0.7)

	CreateSingleDatabaseCredit("Paramount",								pSubSeq,16.5,1.1, 3)
 	CreateNameNameHorizCredit("Rick Berman",		"Dave Rossi",		pSubSeq, 18, 1.2)
	CreateNameNameHorizCredit("Andrea Hein",		"Terri Helton",		pSubSeq, 19, 1.3)
	CreateNameNameHorizCredit("Pam Newton",			"Sandi Isaacs",		pSubSeq, 20, 1.4)
	CreateNameNameHorizCredit("Christina Burbank",	None,				pSubSeq, 21, 1.5)

	pSequence.AppendAction(pSubSeq, 1.0)


###############################################################################
#	Add3rdPartyCredits()
#	
#	Add the 3rd Party credits to the master credit sequence.  Expects a few
#	globals to be set by CreateCreditsSequence() which calls us:
#	g_pCreditDatabase	- set to the Options.tgl
#	g_idCreditPane		- pane passed into CreateCreditsSequence()
#	
#	Args:	pSequence	- Master sequence of credits
#	
#	Return:	none
###############################################################################
def Add3rdPartyCredits(pSequence):
	global g_fCreditDelay, g_pCreditDatabase, g_idCreditPane, g_fTitleLeft, g_fNameLeft

	p3rdSeq = App.TGSequence_Create()
	p3rdSeq.SetUseRealTime(1)

	g_fCreditDelay = 7.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
 	CreateSingleCredit("Numerical Design Ltd.",							pSubSeq,4.5, 0.00, 3)
 	CreateSingleCredit("Herman Kaiser",									pSubSeq,  6, 0.05)
 	CreateSingleCredit("Rad Game Tools",								pSubSeq,8.5, 0.10, 3)
 	CreateSingleCredit("Mitch Soule",									pSubSeq, 10, 0.15)
 	CreateSingleCredit("Jeff Roberts",									pSubSeq, 11, 0.20)
 	CreateSingleCredit("GameSpy",										pSubSeq,13.5,0.25, 3)
 	CreateSingleCredit("Joost Schuur",									pSubSeq, 15, 0.30)
 	CreateSingleCredit("Travis Hogue",									pSubSeq, 16, 0.35)
 	CreateSingleCredit("Orlando Rojas",									pSubSeq, 17, 0.40)
 	CreateSingleCredit("Rich Rice",										pSubSeq, 18, 0.45)
 	CreateSingleCredit("David Wright",									pSubSeq, 19, 0.50)
	p3rdSeq.AddAction(pSubSeq, None, 0.5)

	g_fCreditDelay = 4.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("PMP",									pSubSeq,  7, 0.00, 3)
	CreateSingleCredit("Ignited Minds, LLC",							pSubSeq,  9, 0.05)
	CreateSingleDatabaseCredit("Special Thanks",						pSubSeq,12.5,0.50)
	CreateSingleCredit("Erik Jensen",									pSubSeq, 14, 0.55)
	CreateSingleCredit("Josh Lieber",									pSubSeq, 15, 0.60)
	CreateSingleCredit("Magnus Morgan",									pSubSeq, 16, 0.65)
	CreateSingleCredit("Mike Rivera",									pSubSeq, 17, 0.70)
	CreateSingleCredit("Belinda M. Van Sickle",							pSubSeq, 18, 0.75)
	CreateSingleCredit("Sylvia Orzel",									pSubSeq, 19, 0.80)
	p3rdSeq.AppendAction(pSubSeq, 0.5)

	# License icon prep work, as we need to set these realtime
	pShowBinkAndMiles = App.TGScriptAction_Create(__name__, "ShowBinkAndMiles")
	pShowGameSpy = App.TGScriptAction_Create(__name__, "ShowGameSpy")
	pRemoveBinkAndMiles = App.TGScriptAction_Create(__name__, "RemoveBinkAndMiles")
	pRemoveGameSpy = App.TGScriptAction_Create(__name__, "RemoveGameSpy")
	pShowBinkAndMiles.SetUseRealTime(1)
	pShowGameSpy.SetUseRealTime(1)
	pRemoveBinkAndMiles.SetUseRealTime(1)
	pRemoveGameSpy.SetUseRealTime(1)

	# Licenses
	g_fCreditDelay = 8.0
	pSubSeq = App.TGSequence_Create()
	pSubSeq.SetUseRealTime(1)
	CreateSingleDatabaseCredit("Licenses",								pSubSeq,  1.5, 0.0, 4)
	g_fTitleLeft = 0.2
	CreateTitleNameHorizCredit("NDL License",			None,			pSubSeq,  4, 0.0)
	g_fTitleLeft = 0.35
	CreateTitleNameHorizCredit("Bink License",			None,			pSubSeq, 10, 0.0)
	CreateTitleNameHorizCredit("Miles License",			None,			pSubSeq, 18, 0.0)
	CreateTitleNameHorizCredit("Powered by GameSpy",	None,			pSubSeq, 24, 0.0)
	pSubSeq.AddAction(pShowBinkAndMiles, None, 0.1)
	pSubSeq.AddAction(pShowGameSpy, None, 0.1)
	pSubSeq.AddAction(pRemoveBinkAndMiles, pShowBinkAndMiles, 8.25)
	pSubSeq.AddAction(pRemoveGameSpy, pShowGameSpy, 8.25)
	p3rdSeq.AppendAction(pSubSeq, 1.0)

	pSequence.AppendAction(p3rdSeq, 1.0)


###############################################################################
#	ShowBinkAndMiles()
#	
#	Show the Bink and Miles icons for the credits
#	
#	Args:	pAction		- script action that called us
#	
#	Return:	none
###############################################################################
def ShowBinkAndMiles(pAction):
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))

	if not pCreditPane:
		return 0

	pBink = App.TGIcon_Create(pcLCARS, 622)
	pBink.SizeToArtwork()
	pCreditPane.AddChild(pBink, 0.1, 0.30)

	pMiles = App.TGIcon_Create(pcLCARS, 623)
	pMiles.SizeToArtwork()
	pCreditPane.AddChild(pMiles, 0.1, 0.60)

	global g_idBinkIcon, g_idMilesIcon
	g_idBinkIcon = pBink.GetObjID()
	g_idMilesIcon = pMiles.GetObjID()

	return 0

###############################################################################
#	RemoveBinkAndMiles()
#	
#	Remove the Bink and Miles credits
#	
#	Args:	pAction		- TGScriptAction that called us
#	
#	Return:	none
###############################################################################
def RemoveBinkAndMiles(pAction):
	pBinkIcon = App.TGIcon_Cast(App.TGObject_GetTGObjectPtr(g_idBinkIcon))
	pMilesIcon = App.TGIcon_Cast(App.TGObject_GetTGObjectPtr(g_idMilesIcon))

	if (pBinkIcon):
		pBinkIcon.GetParent().DeleteChild(pBinkIcon)
	if (pMilesIcon):
		pMilesIcon.GetParent().DeleteChild(pMilesIcon)

	global g_idBinkIcon, g_idMilesIcon
	g_idBinkIcon = App.NULL_ID
	g_idMilesIcon = App.NULL_ID

	return 0


###############################################################################
#	ShowGameSpy()
#	
#	Show the GameSpy icon for the credits
#	
#	Args:	pAction		- script action that called us
#	
#	Return:	none
###############################################################################
def ShowGameSpy(pAction):
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	pCreditPane = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCreditPane))

	if not pCreditPane:
		return 0

	pGameSpy = App.TGIcon_Create(pcLCARS, 621)
	pGameSpy.SizeToArtwork()

	pCreditPane.AddChild(pGameSpy, 0.1, 0.89)
	global g_idGameSpyIcon
	g_idGameSpyIcon = pGameSpy.GetObjID()

	return 0


###############################################################################
#	RemoveGameSpy()
#	
#	Remove the GameSpy icon
#	
#	Args:	pAction		- TGScriptAction that called us
#	
#	Return:	none
###############################################################################
def RemoveGameSpy(pAction):
	pGameSpyIcon = App.TGIcon_Cast(App.TGObject_GetTGObjectPtr(g_idGameSpyIcon))

	if (pGameSpyIcon):
		pGameSpyIcon.GetParent().DeleteChild(pGameSpyIcon)

	global g_idGameSpyIcon
	g_idGameSpyIcon = App.NULL_ID

	return 0



def ShowWarpBackground(pAction, iDoShow):
	pWarpSet = App.WarpSet_Cast(App.WarpSequence_GetWarpSet())

	global g_idOldRenderedSet
	global g_idOldActiveCamera

	if (iDoShow):
		pCamera = pWarpSet.GetCamera("CreditsCam")
		if not (pCamera):
			pCamera = App.SpaceCamera_Create("CreditsCam")
			pCamera.SetAngleAxisRotation(-1.57, 0, 0, 1)
			pWarpSet.AddCameraToSet(pCamera, "CreditsCam")
			pWarpSet.SetForceUpdate(1)
			pOldActiveCamera = pWarpSet.GetActiveCamera()
			if pOldActiveCamera:
				g_idOldActiveCamera = pOldActiveCamera.GetObjID()
			else:
				g_idOldActiveCamera = App.NULL_ID
			pWarpSet.SetActiveCamera("CreditsCam")

		pOldRenderedSet = App.g_kSetManager.GetRenderedSet()
		if pOldRenderedSet:
			g_idOldRenderedSet = pOldRenderedSet.GetObjID()
		else:
			g_idOldRenderedSet = App.NULL_ID

		App.g_kSetManager.MakeRenderedSet("warp")
	else:
		App.g_kSetManager.ClearRenderedSet()
		pWarpSet.DeleteCameraFromSet("CreditsCam")
		pWarpSet.SetForceUpdate(0)

		pOldActiveCamera = App.CameraObjectClass_Cast(App.TGObject_GetTGObjectPtr(g_idOldActiveCamera))
		pOldRenderedSet = App.SetClass_Cast(App.TGObject_GetTGObjectPtr(g_idOldRenderedSet))
		if (pOldActiveCamera):
			pWarpSet.SetActiveCamera(pOldActiveCamera.GetName())
		if (pOldRenderedSet):
			App.g_kSetManager.MakeRenderedSet(pOldRenderedSet.GetName())

	return 0
	
def GetButton (pPane, pTargetName):
	pcTargetName = pTargetName.GetCString ()
	iLen = len (pcTargetName)

	for i in range (0, pPane.GetNumChildren ()):
		pButton = App.STButton_Cast (pPane.GetNthChild (i))
		if (pButton):
			pName = App.TGString ()
			pButton.GetName (pName)
			pcName = pName.GetCString ()
			if (pcName [:iLen] == pcTargetName):
				return pButton

	return None

def CustomMasterGraphicsLevel ():
	pMasterGraphicsButton = App.STToggle_Cast(App.TGObject_GetTGObjectPtr(g_idMasterGraphicsButton))
	if not pMasterGraphicsButton:
		return

	pMasterGraphicsButton.SetState (3)	

def UpdateJunkTextHandler (pObject, pEvent):
	# Toggle the junk text as well.
	i = App.g_kSystemWrapper.GetRandomNumber (4)
	if (i == 0):
		pText = App.TGParagraph_Cast(App.TGObject_GetTGObjectPtr(g_idJunkText1))
		if (pText):
			# random string
			pcString = str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pcString = pcString + " "

			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pText.SetString (pcString)
	elif (i == 1):
		pText = App.TGParagraph_Cast(App.TGObject_GetTGObjectPtr(g_idJunkText2))

		if (pText):
			# random string
			pcString = str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pcString = pcString + " "

			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pText.SetString (pcString)
	elif (i == 2):
		pText = App.TGParagraph_Cast(App.TGObject_GetTGObjectPtr(g_idJunkText3))

		if (pText):
			# random string
			pcString = str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pcString = pcString + " "

			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pText.SetString (pcString)
	else:
		pText = App.TGParagraph_Cast(App.TGObject_GetTGObjectPtr(g_idJunkText4))

		if (pText):
			# random string
			pcString = str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pText.SetString (pcString)
	
	Multiplayer.MultiplayerMenus.UpdateJunkText ()

	if (pObject):
		pObject.CallNextHandler (pEvent)		

def HandleSwitchIconGroups(pObject, pEvent):
	# Change the font size based on the new res.
	global g_iRes
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	if (pMode.GetCurrentResolution() == App.GraphicsModeInfo.RES_640x480):
		g_iRes = 0
	elif (pMode.GetCurrentResolution() == App.GraphicsModeInfo.RES_800x600):
		g_iRes = 1
	elif (pMode.GetCurrentResolution() == App.GraphicsModeInfo.RES_1024x768):
		g_iRes = 2
	elif (pMode.GetCurrentResolution() == App.GraphicsModeInfo.RES_1280x1024):
		g_iRes = 3
	elif (pMode.GetCurrentResolution() == App.GraphicsModeInfo.RES_1600x1200):
		g_iRes = 4
	else:
		g_iRes = 0
	
	# Switch old flight font for new flight font.
	if pEvent:
		App.InterfaceModule_SwitchFonts(App.g_kFontManager.GetFontGroup(g_pcSmallFont, g_kFlightSmallFontSize[pEvent.GetInt()]), 
										App.g_kFontManager.GetFontGroup(g_pcSmallFont, g_kFlightSmallFontSize[g_iRes]))

	App.g_kFontManager.SetDefaultFont(g_pcSmallFont, g_kFlightSmallFontSize[g_iRes])

def HandleSwitchRes(pObject, pEvent):
	if App.g_kUtopiaModule.IsLoading() == 0:
#		debug("In HandleSwitchRes(), not loading")
		# Store off any relevant state information that we must reset after
		# rebuilding the interface
		pResumeButton = App.STRoundedButton_Cast(App.TGObject_GetTGObjectPtr(g_idResumeButton))

		if pResumeButton:
			bResumeVisible = pResumeButton.IsVisible()
		else:
			bResumeVisible = 1

		# Rebuild the interface
		BuildInterface ()

		# Switch middle pane to the configure pane.
		SwitchMiddlePane("Configure")

		# Restore any states after the rebuilding of the interface
		pResumeButton = App.STRoundedButton_Cast(App.TGObject_GetTGObjectPtr(g_idResumeButton))
		if (bResumeVisible) and pResumeButton:
			pResumeButton.SetEnabled()
			pResumeButton.SetVisible()

		# Give focus to graphics tab
		pTopWindow = App.TopWindow_GetTopWindow()
		pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

		pMiddleArea = App.TGPane_Cast(pOptionsWindow.GetNthChild(1))
		pConfigurePane = App.TGPane_Cast(pMiddleArea.GetNthChild(0))
		pContentPane = App.TGPane_Cast (pConfigurePane.GetNthChild (0))
		pTabPane = App.TGPane_Cast (pContentPane.GetNthChild (0))
		pOptionsPane = App.TGPane_Cast (pContentPane.GetNthChild (1))

		# Go to the graphics tab.
		HandleConfigureGraphicsTab(None, None)

		# Give the graphics button the focus
		pButton = App.STRoundedButton_Cast (pOptionsPane.GetNthChild (2))
		pOptionsPane.SetFocus (pButton)

		# If there's a game of QuickBattle going, update its dialog box
		import QuickBattle.QuickBattle
		if QuickBattle.QuickBattle.g_pPane:
			QuickBattle.QuickBattle.BuildDialog(1)
			QuickBattle.QuickBattle.RebuildEnemyMenu()
			QuickBattle.QuickBattle.RebuildFriendMenu()

		# Make sure the Multiplayer UI gets rebuilt the next time it's shown
		global g_bMultiplayerMenusRebuiltAfterResChange
		g_bMultiplayerMenusRebuiltAfterResChange = 0

		# Restart the movie at the new res.
		PlayBackgroundMovie ()

		Multiplayer.MultiplayerMenus.UnloadPreGameMenus()
		pPane = Multiplayer.MultiplayerMenus.BuildMultiplayerPreGameMenus(not g_bMultiplayerMenusRebuiltAfterResChange)

		global g_bMultiplayerMenusRebuiltAfterResChange
		g_bMultiplayerMenusRebuiltAfterResChange = 1
	else:
#		debug("In HandleSwitchRes(), during loading")
		BuildInterface()
		SwitchMiddlePane("New Game")

		HandleSwitchIconGroups(None, None)

def StartGame(pObject, pEvent):
	# New game sfx.
	App.g_kSoundManager.PlaySound("UIStart")

	# First get the name of the captain.
	pTextEntry = App.TGPane_Cast (pEvent.GetSource ())

	# Get the paragraph
	pPara = App.TGParagraph_Cast (pTextEntry.GetNthChild (1))

	# Get the captain's name
	pName = App.TGString ()
	pPara.GetString (pName)

	if (pName.GetCString() == ""):
		pName.SetString("Player")
		pPara.SetStringW(pName)

	# Set the utopia module name
	App.g_kUtopiaModule.SetCaptainName (pName)

	# Set the difficulty
	App.Game_SetDifficulty(g_eNewGameDifficulty)

	# Start the mission.
	RunOverrideMission("Episode1", "E1M1")

	# Switch middle pane back to new game
	SwitchMiddlePane ("New Game")

def NewGameLostFocus():
	# Store off the current Captain Name and Difficulty settings
	# First get the name of the captain.
	# Get the paragraph
	global g_idCaptainEntry
	if (g_idCaptainEntry != App.NULL_ID):
		pCaptainEntry = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCaptainEntry))
		if (pCaptainEntry):
			pPara = App.TGParagraph_Cast(pCaptainEntry.GetNthChild(1))
			if not (pPara):
				return

			# Get the captain's name
			pName = App.TGString()
			pPara.GetString(pName)

			# Set the utopia module name
			App.g_kUtopiaModule.SetCaptainName(pName)

	# Set the difficulty
	App.Game_SetDifficulty(g_eNewGameDifficulty)

def CancelEnterName(pObject, pEvent):
	# First get the name of the captain.
	pTextEntry = App.TGPane_Cast (pEvent.GetSource ())

	# Get the paragraph
	pPara = App.TGParagraph_Cast (pTextEntry.GetNthChild (1))

	# Get the captain's name
	pName = App.TGString ()
	pPara.GetString (pName)

	# Set the utopia module name
	App.g_kUtopiaModule.SetCaptainName (pName)

	# Now abort and switch back to the new game pane
	SwitchMiddlePane ("New Game")

def PlayBackgroundMovie (bUseMovieMode = 0):
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	pOpeningSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idOpeningSequence))
	pOpeningMovieSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idOpeningMovieSequence))

	if (pOpeningSequence or pOpeningMovieSequence) or App.g_kUtopiaModule.IsLoading():
#		if (pOpeningSequence):
#			debug("Can't play movies right now - opening sequence")
#		if (pOpeningMovieSequence):
#			debug("Can't play movies right now - opening movie sequence")
#		if (App.g_kUtopiaModule.IsLoading()):
#			debug("Can't play movies right now - loading a saved game")
		return

	StopBackgroundMovies (bUseMovieMode)

	iWidth = int (App.g_kIconManager.GetScreenWidth ())
	iHeight = int (App.g_kIconManager.GetScreenHeight ())
	
	global g_iMovieSequenceID

	# Only do this if we aren't loading the game already.
	if (g_iMovieMode == 2 or g_iMovieMode == 3):
		if (g_iMovieSequenceID [2] == App.NULL_ID):
			pSequence = App.TGSequence_Create()
			pSequence.SetSurviveGlobalAbort(1)

			pcMovieName = "data/Movies/IF_starmap" + str (iWidth) + str (iHeight) + ".bik"
			pMovie = App.TGMovieAction_Create(pcMovieName, 0, 1, 1, 0)
			pMovie.SetSurviveGlobalAbort(1)
			pMovie.SetOffset (0.5125, 0.521666666)
			pSequence.AppendAction(pMovie)

			pSequence.Play ()

			g_iMovieSequenceID [2] = pSequence.GetObjID ()

	if (g_iMovieMode == 1 or g_iMovieMode == 3):
		if (g_iMovieSequenceID [1] == App.NULL_ID):
			pSequence = App.TGSequence_Create()
			pSequence.SetSurviveGlobalAbort(1)

			pcMovieName = "data/Movies/IF_Graph" + str (iWidth) + str (iHeight) + ".bik"
			pMovie = App.TGMovieAction_Create(pcMovieName, 0, 1, 1, 0)
			pMovie.SetSurviveGlobalAbort(1)
			pMovie.SetOffset (0.17, 0.5125)
			pSequence.AppendAction(pMovie)

			pSequence.Play ()

			g_iMovieSequenceID [1] = pSequence.GetObjID ()

	# Always play this movie
	if (g_iMovieSequenceID [0] == App.NULL_ID):
		pSequence = App.TGSequence_Create()
		pSequence.SetSurviveGlobalAbort(1)

		pcMovieName = "data/Movies/IF_Sov" + str (iWidth) + str (iHeight) + ".bik"
		pMovie = App.TGMovieAction_Create(pcMovieName, 0, 1, 1, 0)
		pMovie.SetSurviveGlobalAbort(1)
		pMovie.SetOffset (0.09875, 0.74)
		pSequence.AppendAction(pMovie)

		pSequence.Play ()
	
		g_iMovieSequenceID [0] = pSequence.GetObjID ()

	return

def StopBackgroundMovies (bUseMovieMode = 0):
	global g_iMovieSequenceID

	if (bUseMovieMode):
		if (g_iMovieMode == 0):
			for i in range (1, 3):
				if (g_iMovieSequenceID [i] != App.NULL_ID):
					pMovieSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr (g_iMovieSequenceID [i]))
					if (pMovieSequence):
						pMovieSequence.Skip()
						pMovieSequence = None
					g_iMovieSequenceID [i] = App.NULL_ID
		elif (g_iMovieMode == 1):
			if (g_iMovieSequenceID [2] != App.NULL_ID):
				pMovieSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr (g_iMovieSequenceID [2]))
				if (pMovieSequence):
					pMovieSequence.Skip()
					pMovieSequence = None
				g_iMovieSequenceID [2] = App.NULL_ID
		elif (g_iMovieMode == 2):
			if (g_iMovieSequenceID [1] != App.NULL_ID):
				pMovieSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr (g_iMovieSequenceID [1]))
				if (pMovieSequence):
					pMovieSequence.Skip()
					pMovieSequence = None
				g_iMovieSequenceID [1] = App.NULL_ID
		elif (g_iMovieMode == 3):
			if (g_iMovieSequenceID [1] != App.NULL_ID):
				pMovieSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr (g_iMovieSequenceID [1]))
				if (pMovieSequence):
					pMovieSequence.Skip()
					pMovieSequence = None
				g_iMovieSequenceID [1] = App.NULL_ID

			if (g_iMovieSequenceID [2] != App.NULL_ID):
				pMovieSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr (g_iMovieSequenceID [2]))
				if (pMovieSequence):
					pMovieSequence.Skip()
					pMovieSequence = None
				g_iMovieSequenceID [2] = App.NULL_ID
	else:
		for i in range (0, 3):
			if (g_iMovieSequenceID [i] != App.NULL_ID):
				pMovieSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr (g_iMovieSequenceID [i]))
				if (pMovieSequence):
					pMovieSequence.Skip()
					pMovieSequence = None
				g_iMovieSequenceID [i] = App.NULL_ID

	return

def PreSave ():
	# Kill the junk timer.
	global g_bRecreateJunkTextTimer

	if (g_idJunkTextTimer != App.NULL_ID):
		g_bRecreateJunkTextTimer = 1
	else:
		g_bRecreateJunkTextTimer = 0

	KillJunkTextTimer ()

	# Kill multiplayer things as well.
	import Multiplayer.MultiplayerMenus
	Multiplayer.MultiplayerMenus.DeleteMenus ()

def PostSave ():	
	if (g_bRecreateJunkTextTimer):
		CreateJunkTextTimer ()

def PostLoad ():	
	# reenable resume button.
	pResumeButton = App.STRoundedButton_Cast(App.TGObject_GetTGObjectPtr(g_idResumeButton))

	if pResumeButton:
		pResumeButton.SetEnabled()
		pResumeButton.SetVisible()


def KillJunkTextTimer ():
	global g_idJunkTextTimer
	App.g_kRealtimeTimerManager.DeleteTimer (g_idJunkTextTimer)
	g_idJunkTextTimer = App.NULL_ID

def CreateJunkTextTimer ():
	# Make sure to kill any old ones first before creating a new one
	KillJunkTextTimer ()
	pTopWindow = App.TopWindow_GetTopWindow()
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)

	# Create the junk text timer.
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(ET_UPDATE_JUNK_TEXT)
	pEvent.SetDestination(pOptionsWindow)

	pTimer = App.TGTimer_Create()
	pTimer.SetEvent(pEvent)
	pTimer.SetTimerStart(App.g_kUtopiaModule.GetRealTime ())
	pTimer.SetDelay (1.0)
	pTimer.SetDuration (-1.0)

	global g_idJunkTextTimer
	g_idJunkTextTimer = pTimer.GetObjID ()

	App.g_kRealtimeTimerManager.AddTimer (pTimer)

def QuickBattleHandler (pOptionsWindow, pEvent):
	pGame = App.Game_GetCurrentGame ()
	if (pGame and not App.g_kUtopiaModule.IsMultiplayer ()):
		pTopWindow = App.TopWindow_GetTopWindow()
		pModalDialogWindow = App.ModalDialogWindow_Cast (pTopWindow.FindMainWindow (App.MWT_MODAL_DIALOG))

		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

		pOkEvent = App.TGStringEvent_Create()
		pOkEvent.SetEventType(App.ET_NEW_GAME)
		pOkEvent.SetString("QuickBattle.QuickBattleGame")
		pOkEvent.SetDestination(pOptionsWindow)

		pModalDialogWindow.Run(None, pDatabase.GetString("Are you sure you want to quit"), pDatabase.GetString("OK"), pOkEvent, pDatabase.GetString("Cancel"), None)

		App.g_kLocalizationManager.Unload(pDatabase)
	else:
		# Set the difficulty to medium for quick battle.
		App.Game_SetDifficulty(1)

		pOkEvent = App.TGStringEvent_Create()
		pOkEvent.SetEventType(App.ET_NEW_GAME)
		pOkEvent.SetString("QuickBattle.QuickBattleGame")
		pOkEvent.SetDestination(pOptionsWindow)

		App.g_kEventManager.AddEvent (pOkEvent)

def StartNewGameHandler (pOptionsWindow, pEvent):
	pGame = App.Game_GetCurrentGame ()
	pTextEntry = pEvent.GetSource ()

	if (pGame and not App.g_kUtopiaModule.IsMultiplayer ()):
		pTopWindow = App.TopWindow_GetTopWindow()
		pModalDialogWindow = App.ModalDialogWindow_Cast (pTopWindow.FindMainWindow (App.MWT_MODAL_DIALOG))

		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")

		pOkEvent = App.TGIntEvent_Create()
		pOkEvent.SetSource(pTextEntry)
		pOkEvent.SetDestination(pOptionsWindow)
		pOkEvent.SetEventType(ET_START_GAME)
		pOkEvent.SetInt (0)

		pModalDialogWindow.Run(None, pDatabase.GetString("Are you sure you want to quit"), pDatabase.GetString("OK"), pOkEvent, pDatabase.GetString("Cancel"), None)

		App.g_kLocalizationManager.Unload(pDatabase)
	else:
		pOkEvent = App.TGIntEvent_Create()
		pOkEvent.SetSource(pTextEntry)
		pOkEvent.SetDestination(pOptionsWindow)
		pOkEvent.SetEventType(ET_START_GAME)
		pOkEvent.SetInt (0)
		App.g_kEventManager.AddEvent (pOkEvent)



def DisableResChangeButtons ():
	pMultGame = App.MultiplayerGame_Cast (App.Game_GetCurrentGame ())
	if (pMultGame == None):
		# only do the disabling if in multiplayer.
		return

	import Multiplayer.MissionShared
	if (Multiplayer.MissionShared.g_bGameOver == 0):
		# Not game over, don't disable.
		return		

	# Get the parent pane.
	pGraphicsMenu = App.GraphicsMenu_GetGraphicsMenu ()
	if (pGraphicsMenu == None):
		return

	pParent = App.TGPane_Cast (pGraphicsMenu.GetParent ())

	if (pParent):
		for i in range (1, pParent.GetNumChildren ()):
			pButton = App.STButton_Cast (pParent.GetNthChild (i))
			pMenu = App.STMenu_Cast (pParent.GetNthChild (i))

			if (pButton):
				pButton.SetDisabled ()
			elif (pMenu):
				pMenu.Close ()
				pMenu.SetDisabled ()
			else:
				break

def EnableResChangeButtons ():
	# Get the parent pane.
	pGraphicsMenu = App.GraphicsMenu_GetGraphicsMenu ()
	if (pGraphicsMenu == None):
		return

	pParent = App.TGPane_Cast (pGraphicsMenu.GetParent ())

	if (pParent):
		for i in range (1, pParent.GetNumChildren ()):
			pButton = App.STButton_Cast (pParent.GetNthChild (i))
			pMenu = App.STMenu_Cast (pParent.GetNthChild (i))

			if (pButton):
				pButton.SetEnabled ()
			elif (pMenu):
				pMenu.SetEnabled ()
			else:
				break

	# Make sure buttons that should be disabled are.
	pGraphicsMenu.ResetToggles ()




