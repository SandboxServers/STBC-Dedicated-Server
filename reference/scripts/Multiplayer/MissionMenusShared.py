###############################################################################
#	Filename:	MissionSharedMenus.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to build the options menu.
#	
#	Created:	12/07/00 -	Alby
###############################################################################


import App	


###############################################################################
# UI Object sizes and positions

TITLE_X_POS							= 0.089375
#TITLE_Y_POS is determined by title bar's height and position

SUBTITLE_X_POS						= 0.089375
SUBTITLE_Y_POS						= 0.0541667

#TOP_BAR_X_POS determined by the title text's width
TOP_BAR_X_DISTANCE					= 0.009375
TOP_BAR_Y_POS						= 0.0141667
TOP_BAR_RIGHT_EDGE					= 0.990625
TOP_BAR_HEIGHT						= 0.025

LEFT_BAR_1_X_POS					= 0.009375
LEFT_BAR_1_Y_POS					= 0.0141667
LEFT_BAR_1_WIDTH					= 0.06875
LEFT_BAR_1_HEIGHT					= 0.025

LEFT_BAR_2_X_POS					= 0.009375
LEFT_BAR_2_Y_POS					= 0.0516667
LEFT_BAR_2_WIDTH					= 0.06875
LEFT_BAR_2_HEIGHT					= 0.225

LEFT_BAR_3_X_POS					= 0.009375
LEFT_BAR_3_Y_POS					= 0.2891667
LEFT_BAR_3_WIDTH					= 0.06875
LEFT_BAR_3_HEIGHT					= 0.4108333

LOWER_LEFT_CURVE_X_POS				= 0.009375
LOWER_LEFT_CURVE_Y_POS				= 0.7125
LOWER_LEFT_CURVE_WIDTH				= 0.54
LOWER_LEFT_CURVE_HEIGHT				= 0.276667
LOWER_LEFT_CURVE_IN_WIDTH			= 0.06875
LOWER_LEFT_CURVE_IN_HEIGHT			= 0.264167
LOWER_LEFT_CURVE_OI_WIDTH			= 0.039375

RIGHT_BAR_1_X_POS					= 0.951875
RIGHT_BAR_1_Y_POS					= 0.0516667
RIGHT_BAR_1_WIDTH					= 0.03875
RIGHT_BAR_1_HEIGHT					= 0.4333333

RIGHT_BAR_2_X_POS					= 0.951875
RIGHT_BAR_2_Y_POS					= 0.4975
RIGHT_BAR_2_WIDTH					= 0.03875
RIGHT_BAR_2_HEIGHT					= 0.3083333

LOWER_RIGHT_CURVE_X_POS				= 0.864375
LOWER_RIGHT_CURVE_Y_POS				= 0.8183333
LOWER_RIGHT_CURVE_WIDTH				= 0.12625
LOWER_RIGHT_CURVE_HEIGHT			= 0.1708333
LOWER_RIGHT_CURVE_IN_WIDTH			= 0.03875
LOWER_RIGHT_CURVE_IN_HEIGHT			= 0.1583333
LOWER_RIGHT_CURVE_OI_WIDTH			= 0.039375

BOTTOM_BAR_1_X_POS					= 0.558125
BOTTOM_BAR_1_Y_POS					= 0.9766667
BOTTOM_BAR_1_WIDTH					= 0.07625
BOTTOM_BAR_1_HEIGHT					= 0.0125

BOTTOM_BAR_2_X_POS					= 0.640625
BOTTOM_BAR_2_Y_POS					= 0.9766667
BOTTOM_BAR_2_WIDTH					= 0.215625
BOTTOM_BAR_2_HEIGHT					= 0.0125

SHIPS_WINDOW_X_POS					= 0.0925
SHIPS_WINDOW_Y_POS					= 0.1
SHIPS_WINDOW_WIDTH					= 0.504375
SHIPS_WINDOW_HEIGHT					= 0.4533333
SHIPS_WINDOW_BAR_THICKNESS			= 0.0291667

SHIPS_SUBPANE_WIDTH					= 0.22

SHIPS_IMAGE_Y_POS					= 0.2875

SHIPS_DESC_WINDOW_X_POS				= 0.0925
SHIPS_DESC_WINDOW_Y_POS				= 0.5675
SHIPS_DESC_WINDOW_WIDTH				= 0.504375
SHIPS_DESC_WINDOW_HEIGHT			= 0.2866667
SHIPS_DESC_WINDOW_BAR_THICKNESS		= 0.0291667

SYSTEM_WINDOW_X_POS					= 0.608125
SYSTEM_WINDOW_Y_POS					= 0.1
SYSTEM_WINDOW_WIDTH					= 0.328125
SYSTEM_WINDOW_HEIGHT				= 0.4533333
SYSTEM_WINDOW_BAR_THICKNESS			= 0.0291667

SYSTEM_SUBPANE_WIDTH				= 0.16375

SYSTEM_IMAGE_X_POS					= 0.7925
SYSTEM_IMAGE_Y_POS					= 0.2051667
SYSTEM_IMAGE_WIDTH					= 0.145
SYSTEM_IMAGE_HEIGHT					= 0.273

SYSTEM_DESC_WINDOW_X_POS			= 0.608125
SYSTEM_DESC_WINDOW_Y_POS			= 0.5675
SYSTEM_DESC_WINDOW_WIDTH			= 0.328125
SYSTEM_DESC_WINDOW_HEIGHT			= 0.2866667
SYSTEM_DESC_WINDOW_BAR_THICKNESS	= 0.0291667

TIME_LIMIT_PARA_X_POS				= 0.0925

TIME_LIMIT_TOGGLE_Y_POS				= 0.9183333
TIME_LIMIT_TOGGLE_WIDTH				= 0.140625
TIME_LIMIT_TOGGLE_HEIGHT			= 0.0416667

FRAG_LIMIT_PARA_X_POS				= 0.463125

FRAG_LIMIT_TOGGLE_Y_POS				= 0.9183333
FRAG_LIMIT_TOGGLE_WIDTH				= 0.140625
FRAG_LIMIT_TOGGLE_HEIGHT			= 0.0416667

PLAYER_LIMIT_TOGGLE_Y_POS			= 0.8666666
PLAYER_LIMIT_TOGGLE_WIDTH			= 0.140625
PLAYER_LIMIT_TOGGLE_HEIGHT			= 0.0416667

START_BUTTON_X_POS					= 0.7875
START_BUTTON_Y_POS					= 0.9183333
START_BUTTON_WIDTH					= 0.153125
START_BUTTON_HEIGHT					= 0.0416667

NUMBER_190_X_POS					= 0.014375
NUMBER_190_Y_POS					= 0.7083333

NUMBER_945_X_POS					= 0.958125
NUMBER_945_Y_POS					= 0.05

NUMBER_04_X_POS						= 0.9625
NUMBER_04_Y_POS						= 0.7825

###############################################################################
# Other helpful constants

MAX_TIME_LIMIT						= 45
TIME_LIMIT_INCRIMENT				= 5
MAX_FRAG_LIMIT						= 10
FRAG_LIMIT_INCRIMENT				= 1
MIN_PLAYER_LIMIT					= 2
MAX_PLAYER_LIMIT					= 8
PLAYER_LIMIT_INCRIMENT				= 1

###############################################################################
#global variables
NonSerializedObjects = (
"g_pShipIcon",
"g_pShipSideText",
"g_pShipDescText",
"g_pShipNameText",
"g_pSystemDescText",
"g_pTimeLimitText",
"g_pTimeLimitButton",
"g_pFragLimitText",
"g_pFragLimitButton",
"g_pStartButton",
"g_pInfoPane",
"g_pSystemPane",
"g_pSystemDescPane",
"g_pSystemDescWindow",
"g_pSystemIcon"
"g_pShipSelectWindow",
"g_pEndOkayButton",
"g_pEndRestartButton",
"g_pEndTimePane",
"g_pEndFragPane",
"g_pEndGlass",
"g_pEndGameOverText",
"g_pEndReasonText",
"g_pEndWinnerText",
"g_pEndInstructionText",
"g_pEndPlayerListPane",
"g_pEndPlayerListWindow",
"g_pEndPlayerListMenu",
"g_pEndChatWindow",
"g_pEndChatSubPane",
"g_pPlayerLimitText",
"g_pPlayerLimitButton",
"g_pBackButton",
"g_pChosenSpecies",
"g_pChosenSystem",
)


g_iUseScoreLimit = 0
g_iSpecies = 0
g_iSystem = 0
g_iTimeLimit = -1
g_iFragLimit = -1
g_iPlayerLimit = MAX_PLAYER_LIMIT

g_bShipSelectState = 0

g_bAllowNoTimeLimit = 1
g_bGameStarted = 0

#global pointers to user interface items
g_pShipIcon = None
g_pShipSideText = None
g_pShipDescText = None
g_pShipNameText = None
g_pSystemDescText = None
g_pTimeLimitButton = None
g_pTimeLimitText = None
g_pFragLimitButton = None
g_pFragLimitText = None
g_pPlayerLimitText = None
g_pPlayerLimitButton = None
g_pStartButton = None
g_pInfoPane = None
g_pSystemPane = None
g_pSystemDescPane = None
g_pSystemIcon = None
g_pShipSelectWindow = None
g_pEndOkayButton = None
g_pEndRestartButton = None
g_pEndTimePane = None
g_pEndFragPane = None
g_pEndGlass = None
g_pEndGameOverText = None
g_pEndReasonText = None
g_pEndInstructionText = None
g_pEndWinnerText = None
g_pEndPlayerListWindow = None
g_pEndPlayerListMenu = None
g_pEndPlayerListPane = None
g_pEndChatWindow = None
g_pEndChatSubPane = None
g_pBackButton = None
g_pChosenSpecies = None
g_pChosenSystem = None
g_pSystemDescWindow = None

g_fYPixelOffset = 0.0
g_fXPixelOffset = 0.0

#define event types.  For multiplayer mission menus, start at 100.
ET_SELECT_SHIP_SPECIES	= App.g_kVarManager.MakeEpisodeEventType(100)
ET_SELECT_SYSTEM		= App.g_kVarManager.MakeEpisodeEventType(101)
ET_FINISHED_SELECT		= App.g_kVarManager.MakeEpisodeEventType(102)
ET_TIME_LIMIT_CLICKED	= App.g_kVarManager.MakeEpisodeEventType(103)
ET_FRAG_LIMIT_CLICKED	= App.g_kVarManager.MakeEpisodeEventType(104)
ET_PLAYER_LIMIT_CLICKED	= App.g_kVarManager.MakeEpisodeEventType(105)

def DeleteMissionMenus ():
	import MainMenu.mainmenu

	# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
	
	pMissionPane = pMultWindow.GetMissionPane ()
	if (pMissionPane):
		# Delete broadcast handlers
		App.g_kEventManager.RemoveAllBroadcastHandlersForObject (pMissionPane)
		pParent = pMissionPane.GetParent()
		if pParent:
			pParent.DeleteChild(pMissionPane)
		pMultWindow.SetMissionPane(None)
	
	pEndPane = pMultWindow.GetEndWindow ()
	if (pEndPane):
		# Delete broadcast handlers
		App.g_kEventManager.RemoveAllBroadcastHandlersForObject (pEndPane)
		pParent = pEndPane.GetParent()
		if pParent:
			pParent.DeleteChild(pEndPane)
		pMultWindow.SetEndWindow(None)

	global g_pEndTimePane
	pTopWindow.DeleteChild (g_pEndTimePane)
	g_pEndTimePane = None

	global g_pChosenSystem
	g_pChosenSystem = None
	global g_pChosenSpecies
	g_pChosenSpecies = None

	# Enable options toggling.
	pTopWindow.DisableOptionsMenu (0)	

	pResumeButton = App.STRoundedButton_Cast(App.TGObject_GetTGObjectPtr(MainMenu.mainmenu.g_idResumeButton))
	if (pResumeButton):
		pResumeButton.SetEnabled ()

	global g_pEndChatWindow
	global g_pEndChatSubPane
	g_pEndChatWindow = None
	g_pEndChatSubPane = None

	import MainMenu.mainmenu

	MainMenu.mainmenu.EnableResChangeButtons ()



###############################################################################
#	BuildEndWindow()
#	
#	Build the window that comes up at game over
#	
#	Args:	pMultWindow		- the multiplayer window
#			pDatabase		- the localization database
#			bBuildCaptions	- should we build the captions at the top?
#	
#	Return:	the end pane
###############################################################################
def BuildEndWindow (pMultWindow, pDatabase, bBuildCaptions):
	import MainMenu.mainmenu
	import Multiplayer.MissionMenusShared
	import Multiplayer.MissionShared
	import MissionLib

	pEndPane = App.TGPane_Create (1.0, 1.0)

	# Create menu of players and their scores
	fTop = 0.0
	fMaxWidth = 0.40
	fLeft = (1.0 - fMaxWidth) / 2.0

	global g_pEndPlayerListWindow
	global g_pEndPlayerListMenu
	global g_pEndPlayerListPane
	
	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	g_pEndPlayerListWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Score Board"), 0.0, 0.0)
	g_pEndPlayerListWindow.SetMaximumSize(1.0, 0.5)

	# Set the font back to normal
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	g_pEndPlayerListMenu = App.STSubPane_Create(g_pEndPlayerListWindow.GetMaximumInteriorWidth(),
								g_pEndPlayerListWindow.GetMaximumInteriorHeight(), 0)
	# g_pEndPlayerListMenu = App.STTopLevelMenu_CreateW(pDatabase.GetString ("Score Board"))
	g_pEndPlayerListMenu.SetHighlighted(0)
	g_pEndPlayerListWindow.AddChild(g_pEndPlayerListMenu, 0, 0, 0)

	g_pEndPlayerListPane = App.TGPane_Create(fMaxWidth, 1.0)
	g_pEndPlayerListPane.AddChild(g_pEndPlayerListWindow, 0, 0, 0)

	pEndPane.AddChild(g_pEndPlayerListPane, fLeft, fTop, 0)

	fTitleBarHeight = 0.01

	if bBuildCaptions == 1:
		# Create Kills and deaths and score text
		pPane = App.TGPane_Create (0.8, 0.1)
		pText = App.TGParagraph_CreateW (pDatabase.GetString ("Score"))
		pText.SetColor (App.g_kSTMenuTextColor)
		pPane.AddChild (pText, 0, 0, 0)
		pPane.Resize (0.14, pText.GetHeight (), 0)
		g_pEndPlayerListPane.PrependChild (pPane, 0.21, fTop, 0)

		pPane = App.TGPane_Create (0.065, 0.1)
		pText = App.TGParagraph_CreateW (pDatabase.GetString ("Kills"))
		pText.SetColor (App.g_kSTMenuTextColor)
		pPane.AddChild (pText, 0, 0, 0)
		pPane.Resize (0.08, pText.GetHeight (), 0)
		g_pEndPlayerListPane.PrependChild (pPane, 0.295, fTop, 0)
		
		pPane = App.TGPane_Create (0.065, 0.1)
		pText = App.TGParagraph_CreateW (pDatabase.GetString ("Deaths"))
		pText.SetColor (App.g_kSTMenuTextColor)
		pPane.AddChild (pText, 0, 0, 0)
		pPane.Resize (0.08, pText.GetHeight (), 0)
		g_pEndPlayerListPane.PrependChild (pPane, 0.345, fTop, 0)
	elif bBuildCaptions == 2:
		# Create Kills and deaths and score text
		pPane = App.TGPane_Create (0.065, 0.1)
		pText = App.TGParagraph_CreateW (pDatabase.GetString ("Kills"))
		pText.SetColor (App.g_kSTMenuTextColor)
		pPane.AddChild (pText, 0, 0, 0)
		pPane.Resize (0.08, pText.GetHeight (), 0)
		g_pEndPlayerListPane.PrependChild (pPane, 0.2, fTop, 0)
		
		pPane = App.TGPane_Create (0.065, 0.1)
		pText = App.TGParagraph_CreateW (pDatabase.GetString ("Deaths"))
		pText.SetColor (App.g_kSTMenuTextColor)
		pPane.AddChild (pText, 0, 0, 0)
		pPane.Resize (0.08, pText.GetHeight (), 0)
		g_pEndPlayerListPane.PrependChild (pPane, 0.265, fTop, 0)

	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create okay button
	# This event is handled in MultplayerMenus.py, not in this script.
	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType (App.ET_END_GAME_OKAY)
	pEvent.SetDestination (pMultWindow)

	global g_pEndOkayButton
	g_pEndOkayButton = App.STButton_CreateW(pDatabase.GetString("Okay"), pEvent, 0,
											START_BUTTON_WIDTH, START_BUTTON_HEIGHT)
	g_pEndOkayButton.SetJustification(App.STButton.CENTER)
	g_pEndOkayButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pEndOkayButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pEndOkayButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pEndOkayButton.SetColorBasedOnFlags()
	pEndPane.AddChild(g_pEndOkayButton, 1.0 - g_pEndOkayButton.GetWidth() - 0.01, 1.0 - g_pEndOkayButton.GetHeight () - 0.02, 0)
	App.g_kFocusManager.AddObjectToTabOrder(g_pEndOkayButton)

	# Create restart button
	# This event is handled in MultplayerMenus.py, not in this script.
	pEvent = App.TGEvent_Create ()
	pMission = MissionLib.GetMission ()
	pEvent.SetEventType (Multiplayer.MissionShared.ET_RESTART_GAME)
	pEvent.SetDestination (pMission)

	global g_pEndRestartButton
	g_pEndRestartButton = App.STButton_CreateW(pDatabase.GetString("Restart"),
							pEvent, 0,	START_BUTTON_WIDTH, START_BUTTON_HEIGHT)
	g_pEndRestartButton.SetJustification(App.STButton.CENTER)
	g_pEndRestartButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pEndRestartButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pEndRestartButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pEndRestartButton.SetColorBasedOnFlags()
	pEndPane.AddChild(g_pEndRestartButton, 1.0 - (g_pEndRestartButton.GetWidth () + 0.01) * 2.0, 1.0 - g_pEndRestartButton.GetHeight () - 0.02)
	App.g_kFocusManager.AddObjectToTabOrder(g_pEndRestartButton)

	# Create the stylized window in which chat messages will go at the game over screen
	global g_pEndChatWindow
	g_pEndChatWindow = App.STStylizedWindow_CreateW("StylizedWindow", "RightBorder",
						pDatabase.GetString("Chat"), 0.0, 0.0, None, 0,
						0.0, 0.0, App.g_kMultiplayerStylizedPurple)
	g_pEndChatWindow.SetNotVisible(0)
	g_pEndChatWindow.SetFixedSize(1.0, 0.0, 0)
	
	pEndPane.AddChild(g_pEndChatWindow, 0.0, 0.0, 0)

	global g_pEndChatSubPane
	g_pEndChatSubPane = App.STSubPane_Create(g_pEndChatWindow.GetMaximumInteriorWidth(), 1.0)
	g_pEndChatWindow.AddChild(g_pEndChatSubPane)
		
	# Set the font back to normal
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create the instruction text
	pInstructionTextPane = App.TGPane_Create(	g_pEndRestartButton.GetLeft() - 0.02,
												g_pEndRestartButton.GetHeight() + 0.02)
	global g_pEndInstructionText
	g_pEndInstructionText = App.TGParagraph_Create("", pInstructionTextPane.GetWidth(),
							None, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | 
							App.TGParagraph.TGPF_WORD_WRAP)
	pInstructionTextPane.AddChild(g_pEndInstructionText, 0.0, 0.0, 0)
	pEndPane.AddChild(pInstructionTextPane, 0.01, g_pEndRestartButton.GetTop())

	# Create the big "Game Over" text
	global g_pEndGameOverText
	g_pEndGameOverText = App.TGParagraph_CreateW(pDatabase.GetString("Game Over"), 1.0,
							None, "Serpentine", 16.0)
	pEndPane.AddChild(g_pEndGameOverText, (1.0 - g_pEndGameOverText.GetWidth()) / 2.0,
							0.0, 0)

	# Create the text that will explain why the game has ended
	# (We're going to want to center it when it changes, so just position it anywhere
	# along the x axis for now.)
	global g_pEndReasonText
	g_pEndReasonText = App.TGParagraph_Create("", 0.85,
							None, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | 
							App.TGParagraph.TGPF_WORD_WRAP)
	pEndPane.AddChild(g_pEndReasonText, 0.0, g_pEndGameOverText.GetBottom() + 0.02)

	# Create the text that will say who won
	global g_pEndWinnerText
	g_pEndWinnerText = App.TGParagraph_Create("", 0.85,
							None, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | 
							App.TGParagraph.TGPF_WORD_WRAP)
	pEndPane.AddChild(g_pEndWinnerText, 0.0, g_pEndReasonText.GetBottom() + 0.02)
	
							
	# If there's a time limit or frag limit, display it.
	global g_pEndTimePane
	g_pEndTimePane = Multiplayer.MissionMenusShared.ConstructTime ()
	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.AddChild (g_pEndTimePane, 1.0 - g_pEndTimePane.GetWidth (), 0.01, 0)

	global g_pEndFragPane
	g_pEndFragPane = App.TGPane_Create (0.1, 0.1)

	pString = None
	pcSubString = None
	if (g_iUseScoreLimit):
		pString = Multiplayer.MissionShared.g_pDatabase.GetString("Score Limit:")
		pcString = pString.GetCString()
		pcSubString = pcString % str(Multiplayer.MissionMenusShared.g_iFragLimit * 10000)
	else:
		pString = Multiplayer.MissionShared.g_pDatabase.GetString("Frag Limit:")
		pcString = pString.GetCString()
		pcSubString = pcString % str(Multiplayer.MissionMenusShared.g_iFragLimit)

	pText = App.TGParagraph_Create(pcSubString)
	g_pEndFragPane.AddChild(pText, 0, 0, 0)
	g_pEndFragPane.Resize(pText.GetWidth(), pText.GetHeight(), 0)
	pEndPane.AddChild(g_pEndFragPane, fLeft, g_pEndPlayerListMenu.GetHeight() + 0.01, 0)

	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	global g_pEndGlass
	g_pEndGlass = App.TGIcon_Create(pcLCARS, 120)
	g_pEndGlass.Resize(1.0, 1.0, 0)
	g_pEndGlass.AddPythonFuncHandlerForInstance(App.ET_MOUSE, "Multiplayer.MissionMenusShared.HandleMouseEventsForGlass")
	pEndPane.AddChild(g_pEndGlass, 0, 0, 0)
	g_pEndGlass.SetNotVisible(0)

	# Set pointer in multWindow for easy access.
	pMultWindow.SetEndWindow(pEndPane)

	pEndPane.AddPythonFuncHandlerForInstance(App.ET_MOUSE, "Multiplayer.MissionMenusShared.HandleMouseEventsForEndPane")

	return pEndPane
	
###############################################################################
#	BuildMissionMenu()
#	
#	Build the menu for this mission
#	
#	Args:	TGWindow				pMultWindow		- the mission menu's future
#													parent window
#			TGLocalizationDatabase	pDatabase		- the database that contains
#													our strings
#			char*					pcHostIdString	- the ID string for the
#													string in the TGL for the
#													title of this menu if we're
#													the host
#			char*					pcClientIdString- the ID string for the
#													string in the TGL for the
#													title of this menu if we're
#													the client
#			char*					pcDHostIdString- the ID string for the
#													string in the TGL for the
#													title of this menu if we're
#													the client
#			bool					bAllowNoTimeLimit
#	
#	Return:	A TGPane containing the menu for this mission
###############################################################################
def BuildMissionMenu(pMultWindow, pDatabase, pcHostIdString, pcClientIdString,
										pcDHostIdString, bAllowNoTimeLimit = 1):
	import Multiplayer.SpeciesToShip
	import MainMenu.mainmenu
	import UIHelpers

	# Create the main mission menu pane.
	pMissionPane = App.TGPane_Create (1.0, 1.0)

	global g_fYPixelOffset
	global g_fXPixelOffset

	pEyeCandyPane = App.TGPane_Create (1.0, 1.0)

	#########################################
	# Create eye candy
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	# Set the font small
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create the little "190" that's in the lower-left curve
	p190 = App.TGParagraph_Create("190", 1.0, App.g_kSTMenuTextColor)
	pEyeCandyPane.AddChild(p190, NUMBER_190_X_POS, NUMBER_190_Y_POS, 0)
	
	# Create the little "945" that's in RightBar1
	p945 = App.TGParagraph_Create("945", 1.0, App.g_kSTMenuTextColor)
	pEyeCandyPane.AddChild(p945, NUMBER_945_X_POS, NUMBER_945_Y_POS, 0)

	# Create the little "04" that's in RightBar2
	p04 = App.TGParagraph_Create("04", 1.0, App.g_kSTMenuTextColor)
	pEyeCandyPane.AddChild(p04, NUMBER_04_X_POS, NUMBER_04_Y_POS, 0)

	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes] + 1)

	# Create the title
	pTitle = App.TGParagraph_CreateW(pDatabase.GetString("Multiplayer"), 1.0, App.globals.g_kTitleColor)
	fPosDelta = (pTitle.GetHeight() - TOP_BAR_HEIGHT) / 2.0
	pEyeCandyPane.AddChild(pTitle, TITLE_X_POS, TOP_BAR_Y_POS - fPosDelta, 0)
	
	# Create the subtitle
	if App.g_kUtopiaModule.IsHost() and App.g_kUtopiaModule.IsClient():
		pSubtitle = App.TGParagraph_CreateW(pDatabase.GetString(pcHostIdString), 1.0, App.globals.g_kTitleColor)
	elif App.g_kUtopiaModule.IsClient():
		pSubtitle = App.TGParagraph_CreateW(pDatabase.GetString(pcClientIdString), 1.0, App.globals.g_kTitleColor)
	else:
		pSubtitle = App.TGParagraph_CreateW(pDatabase.GetString(pcDHostIdString), 1.0, App.globals.g_kTitleColor)
	pEyeCandyPane.AddChild(pSubtitle, SUBTITLE_X_POS, SUBTITLE_Y_POS, 0)

	# Set the font smaller but still large
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create the top bar
	fTopXPos = TITLE_X_POS + pTitle.GetWidth() + TOP_BAR_X_DISTANCE
	fTopWidth = TOP_BAR_RIGHT_EDGE - fTopXPos
	pTopBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kInterfaceBorderColor)
	pTopBar.Resize(fTopWidth, TOP_BAR_HEIGHT, 0)
	pEyeCandyPane.AddChild(pTopBar, fTopXPos, TOP_BAR_Y_POS, 0)  

	# Create the first left bar
	pLeftBar1 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kInterfaceBorderColor)
	pLeftBar1.Resize(LEFT_BAR_1_WIDTH, LEFT_BAR_1_HEIGHT, 0)
	pEyeCandyPane.AddChild(pLeftBar1, LEFT_BAR_1_X_POS, LEFT_BAR_1_Y_POS, 0)  

	# Create the second left bar
	pLeftBar2 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderBlue)
	pLeftBar2.Resize(LEFT_BAR_2_WIDTH, LEFT_BAR_2_HEIGHT, 0)
	pEyeCandyPane.AddChild(pLeftBar2, LEFT_BAR_2_X_POS, LEFT_BAR_2_Y_POS, 0)  

	# Create the third left bar
	pLeftBar3 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pLeftBar3.Resize(LEFT_BAR_3_WIDTH, LEFT_BAR_3_HEIGHT, 0)
	pEyeCandyPane.AddChild(pLeftBar3, LEFT_BAR_3_X_POS, LEFT_BAR_3_Y_POS, 0)  

	# Create the lower-left curve
	pLLCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_LEFT_CURVE, LOWER_LEFT_CURVE_IN_WIDTH,
							 LOWER_LEFT_CURVE_WIDTH, LOWER_LEFT_CURVE_IN_HEIGHT,
							 LOWER_LEFT_CURVE_HEIGHT, App.globals.g_kMultiplayerBorderBlue,
							 LOWER_LEFT_CURVE_OI_WIDTH)
	pEyeCandyPane.AddChild(pLLCurve, LOWER_LEFT_CURVE_X_POS, LOWER_LEFT_CURVE_Y_POS, 0)

	# Create the first right bar
	pRightBar1 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderBlue)
	pRightBar1.Resize(RIGHT_BAR_1_WIDTH, RIGHT_BAR_1_HEIGHT, 0)
	pEyeCandyPane.AddChild(pRightBar1, RIGHT_BAR_1_X_POS, RIGHT_BAR_1_Y_POS, 0)  
	
	# Create the second right bar
	pRightBar2 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pRightBar2.Resize(RIGHT_BAR_2_WIDTH, RIGHT_BAR_2_HEIGHT, 0)
	pEyeCandyPane.AddChild(pRightBar2, RIGHT_BAR_2_X_POS, RIGHT_BAR_2_Y_POS, 0)  
	 
	# Create the lower-right curve
	pLRCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_RIGHT_CURVE, LOWER_RIGHT_CURVE_IN_WIDTH,
							 LOWER_RIGHT_CURVE_WIDTH, LOWER_RIGHT_CURVE_IN_HEIGHT,
							 LOWER_RIGHT_CURVE_HEIGHT, App.globals.g_kMultiplayerBorderBlue,
							 LOWER_RIGHT_CURVE_OI_WIDTH)
	pEyeCandyPane.AddChild(pLRCurve, LOWER_RIGHT_CURVE_X_POS, LOWER_RIGHT_CURVE_Y_POS, 0)

	# Create the first bottom bar
	pBottomBar1 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pBottomBar1.Resize(BOTTOM_BAR_1_WIDTH, BOTTOM_BAR_1_HEIGHT, 0)
	pEyeCandyPane.AddChild(pBottomBar1, BOTTOM_BAR_1_X_POS, BOTTOM_BAR_1_Y_POS, 0)  

	# Create the second bottom bar
	pBottomBar2 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pBottomBar2.Resize(BOTTOM_BAR_2_WIDTH, BOTTOM_BAR_2_HEIGHT, 0)
	pEyeCandyPane.AddChild(pBottomBar2, BOTTOM_BAR_2_X_POS, BOTTOM_BAR_2_Y_POS, 0)

	#########################################
	# Create the icon of the currently selected ship
	global g_pShipIcon
	g_pShipIcon = App.TGIcon_Create("ShipIcons", Multiplayer.SpeciesToShip.GetIconNum(1));
	g_pShipIcon.SizeToArtwork(0)
	g_pShipIcon.SetNotVisible()
	pEyeCandyPane.AddChild(g_pShipIcon, 0.0, SHIPS_IMAGE_Y_POS, 0)

	# Create side description
	global g_pShipSideText
	g_pShipSideText = App.TGTextButton_Create("blah")
	g_pShipSideText.SetNotVisible()
	g_pShipSideText.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0);
	pEyeCandyPane.AddChild(g_pShipSideText, 0.0, 0.0, 0)

	# Create ship name
	global g_pShipNameText
	g_pShipNameText = App.TGTextButton_Create("blah")
	g_pShipNameText.SetNotVisible()
	g_pShipNameText.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0);
	pEyeCandyPane.AddChild(g_pShipNameText, 0.0, 0.0, 0)

	#########################################
	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes] + 1)

	#########################################
	# Create start button
	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType (ET_FINISHED_SELECT)
	pEvent.SetDestination (pMissionPane)

	global g_pStartButton
	g_pStartButton = App.STButton_CreateW(pDatabase.GetString ("Start"), pEvent, 0,
									START_BUTTON_WIDTH, START_BUTTON_HEIGHT)
	g_pStartButton.SetDisabled()
	g_pStartButton.SetNormalColor(App.g_kMultiplayerButtonOrange)
	g_pStartButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pStartButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pStartButton.SetHighlightedTextColor(App.g_kTextHighlightColor)
	g_pStartButton.SetColorBasedOnFlags()
	pMissionPane.AddChild(g_pStartButton, START_BUTTON_X_POS, START_BUTTON_Y_POS, 0)

	#########################################
	# Create back button
	# This event is handled in MultplayerMenus.py, not in this script.
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType (Multiplayer.MultiplayerMenus.ET_EXIT_MULTIPLAYER)
	pEvent.SetDestination (pMultWindow)

	global g_pBackButton
	g_pBackButton = App.STButton_CreateW(pDatabase.GetString("Back"),
							pEvent, 0,	START_BUTTON_WIDTH, START_BUTTON_HEIGHT)
	g_pBackButton.SetJustification(App.STButton.CENTER)
	g_pBackButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pBackButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pBackButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pBackButton.SetHighlightedTextColor(App.g_kTextHighlightColor)
	g_pBackButton.SetColorBasedOnFlags()
	pMissionPane.AddChild(g_pBackButton, START_BUTTON_X_POS, PLAYER_LIMIT_TOGGLE_Y_POS)
	
	#########################################
	# Create Time Limit, Frag Limit, and Player Limit buttons

	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType(ET_TIME_LIMIT_CLICKED)
	pEvent.SetDestination(pMissionPane)

	# The time limit caption
	global g_pTimeLimitText
	pText = App.TGParagraph_CreateW(pDatabase.GetString("Time Limit"))
	pText.SetColor(App.g_kTitleColor)
	g_pTimeLimitText = pText

	# The time limit button
	global g_pTimeLimitButton
	global g_bAllowNoTimeLimit
	g_bAllowNoTimeLimit = bAllowNoTimeLimit
	if bAllowNoTimeLimit:
		g_pTimeLimitButton = App.STRoundedButton_CreateW(pDatabase.GetString("None"),
						 pEvent, TIME_LIMIT_TOGGLE_WIDTH, TIME_LIMIT_TOGGLE_HEIGHT, 1)
	else:
		if (App.g_kUtopiaModule.IsHost ()):
			global g_iTimeLimit
			g_iTimeLimit = 20

		import MissionShared
		pString = MissionShared.g_pDatabase.GetString("Num Minutes")
		pcString = pString.GetCString ()
		pcSubString = pcString % str (g_iTimeLimit)
		g_pTimeLimitButton = App.STRoundedButton_Create(pcSubString, pEvent,
						TIME_LIMIT_TOGGLE_WIDTH, TIME_LIMIT_TOGGLE_HEIGHT, 1)
	g_pTimeLimitButton.SetColor(App.g_kTextEntryColor)
	g_pTimeLimitButton.SetNormalColor(App.g_kSTMenu2NormalBase)
	g_pTimeLimitButton.SetHighlightedColor(App.g_kSTMenu2HighlightedBase)
	g_pTimeLimitButton.SetSelectedColor(App.g_kSTMenu2Selected)
	g_pTimeLimitButton.SetTextColor(App.g_kSTMenuTextHighlightColor)
	g_pTimeLimitButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pTimeLimitButton.SetColorBasedOnFlags()
	pMissionPane.AddChild(g_pTimeLimitButton, TIME_LIMIT_PARA_X_POS + pText.GetWidth () + 0.005, TIME_LIMIT_TOGGLE_Y_POS, 0)
	App.g_kFocusManager.AddObjectToTabOrder(g_pTimeLimitButton)


	fPosDelta = (pText.GetHeight() - g_pTimeLimitButton.GetHeight()) / 2.0
	pMissionPane.AddChild(pText, TIME_LIMIT_PARA_X_POS, TIME_LIMIT_TOGGLE_Y_POS - fPosDelta, 0) 
	if (not App.g_kUtopiaModule.IsHost ()):
		g_pTimeLimitButton.SetDisabled ()

	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType(ET_FRAG_LIMIT_CLICKED)
	pEvent.SetDestination(pMissionPane)

	# The frag limit caption
	global g_pFragLimitText
	pText = None
	if (g_iUseScoreLimit):
		pText = App.TGParagraph_CreateW(pDatabase.GetString("Score Limit"))
	else:
		pText = App.TGParagraph_CreateW(pDatabase.GetString("Frag Limit"))
	pText.SetColor(App.g_kTitleColor)
	g_pFragLimitText = pText

	# The frag limit button
	global g_pFragLimitButton
	g_pFragLimitButton = App.STRoundedButton_CreateW(pDatabase.GetString("None"),
					 pEvent, FRAG_LIMIT_TOGGLE_WIDTH, FRAG_LIMIT_TOGGLE_HEIGHT, 1)
	g_pFragLimitButton.SetNormalColor(App.g_kSTMenu2NormalBase)          
	g_pFragLimitButton.SetHighlightedColor(App.g_kSTMenu2HighlightedBase)
	g_pFragLimitButton.SetSelectedColor(App.g_kSTMenu2Selected)          
	g_pFragLimitButton.SetTextColor(App.g_kSTMenuTextHighlightColor)
	g_pFragLimitButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pFragLimitButton.SetColorBasedOnFlags()
	pMissionPane.AddChild(g_pFragLimitButton, FRAG_LIMIT_PARA_X_POS + pText.GetWidth () + 0.005, FRAG_LIMIT_TOGGLE_Y_POS, 0)

	fPosDelta = (pText.GetHeight() - g_pFragLimitButton.GetHeight()) / 2.0
	pMissionPane.AddChild(pText, FRAG_LIMIT_PARA_X_POS, FRAG_LIMIT_TOGGLE_Y_POS - fPosDelta, 0) 

	if (not App.g_kUtopiaModule.IsHost ()):
		g_pFragLimitButton.SetDisabled ()

	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType(ET_PLAYER_LIMIT_CLICKED)
	pEvent.SetDestination(pMissionPane)

	# The player limit caption
	global g_pPlayerLimitText
	pText = App.TGParagraph_CreateW(pDatabase.GetString("Player Limit"))
	pText.SetColor(App.g_kTitleColor)
	g_pPlayerLimitText = pText

	# The player limit button
	import MissionShared
	pString = MissionShared.g_pDatabase.GetString("Num Players")
	pcString = pString.GetCString ()
	pcSubString = pcString % str(g_iPlayerLimit)
	global g_pPlayerLimitButton
	g_pPlayerLimitButton = App.STRoundedButton_Create(pcSubString,
					 pEvent, PLAYER_LIMIT_TOGGLE_WIDTH, PLAYER_LIMIT_TOGGLE_HEIGHT, 1)
	g_pPlayerLimitButton.SetNormalColor(App.g_kSTMenu2NormalBase)          
	g_pPlayerLimitButton.SetHighlightedColor(App.g_kSTMenu2HighlightedBase)
	g_pPlayerLimitButton.SetSelectedColor(App.g_kSTMenu2Selected)          
	g_pPlayerLimitButton.SetTextColor(App.g_kSTMenuTextHighlightColor)
	g_pPlayerLimitButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pPlayerLimitButton.SetColorBasedOnFlags()
	pMissionPane.AddChild(g_pPlayerLimitButton, g_pFragLimitButton.GetLeft(), PLAYER_LIMIT_TOGGLE_Y_POS, 0)
	App.g_kFocusManager.AddObjectToTabOrder(g_pPlayerLimitButton)
	App.g_kFocusManager.AddObjectToTabOrder(g_pFragLimitButton)

	fPosDelta = (pText.GetHeight() - g_pPlayerLimitButton.GetHeight()) / 2.0
	fXPos = g_pPlayerLimitButton.GetLeft() - (pText.GetWidth() + 0.005)
	pMissionPane.AddChild(pText, fXPos, PLAYER_LIMIT_TOGGLE_Y_POS - fPosDelta, 0) 
	
	if not App.g_kUtopiaModule.IsHost():
		g_pPlayerLimitButton.SetDisabled()

	# Set the font smaller but still large
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])
	##########################################
	# Create the instruction text.
	if (App.g_kUtopiaModule.IsClient ()):
		if (App.g_kUtopiaModule.IsHost ()):
			pString = pDatabase.GetString ("Select Region and Ship")
		else:
			pString = pDatabase.GetString ("Select Ship")
	else:
		pString = pDatabase.GetString ("Select Region")
	
	pText = App.TGTextButton_CreateW(pString)
	pText.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0);
	pText.Resize (0.0, 0.0, 0)

	pMissionPane.AddChild (pText, 0.0, 0.95, 0)


	#########################################
	# Add eye candy pane
	pMissionPane.AddChild (pEyeCandyPane, 0, 0, 0)


	#########################################
	# Create ship select window
	pPane = BuildShipSelectWindow (pMissionPane, pDatabase)
	global g_pShipSelectWindow
	g_pShipSelectWindow = pPane

	pDescPane = BuildShipDescWindow(pDatabase)

	# If we're a direct host, we can't pick a ship, so we cover these with glass
	if not App.g_kUtopiaModule.IsClient():
		pPane.SetDisabled()
		pDescPane.SetDisabled()
		pGlass = App.TGIcon_Create(pcLCARS, 120)
		pGlass.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".HandleMouseEventsForGlass")
		pMissionPane.AddChild(pGlass, SHIPS_WINDOW_X_POS, SHIPS_WINDOW_Y_POS, 0)

	# Add ship select pane 
	pMissionPane.AddChild(pPane, SHIPS_WINDOW_X_POS, SHIPS_WINDOW_Y_POS, 0)
	pMissionPane.AddChild(pDescPane, SHIPS_DESC_WINDOW_X_POS, SHIPS_DESC_WINDOW_Y_POS, 0)

	# Resize the glass to fit nicely
	if not App.g_kUtopiaModule.IsClient():
		pGlass.Resize(SHIPS_WINDOW_WIDTH, pDescPane.GetBottom() - pPane.GetTop())
	
	#########################################
	# Create region select window
	if (App.g_kUtopiaModule.IsHost()):
		pWindow = BuildRegionSelectWindow(pMissionPane, pDatabase)
		pDescPane = BuildRegionDescWindow(pDatabase)
	else:
		# create an empty pane, we do this just to keep child
		# ordering the same.
		# FIXME: This should eventually become the player-list window for the client,
		# with perhaps some information about in what system the deathmatch will take place
		pWindow = App.TGPane_Create(1.0, 1.0)
		pDescPane = App.TGPane_Create(1.0, 1.0)
		if g_pSystemIcon:
			g_pSystemIcon.SetNotVisible ()

	global g_pSystemPane
	global g_pSystemDescPane
	g_pSystemPane = pWindow
	g_pSystemDescPane = pDescPane

	# Add region pane and description.
	pMissionPane.AddChild(pWindow, SYSTEM_WINDOW_X_POS, SYSTEM_WINDOW_Y_POS, 0)
	pMissionPane.AddChild(pDescPane, SYSTEM_DESC_WINDOW_X_POS, SYSTEM_DESC_WINDOW_Y_POS, 0)

	if (App.g_kUtopiaModule.IsHost()):
		# Add the pretty picture to the System menu
		pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
		pcLCARS = pGraphicsMode.GetLcarsString()
		global g_pSystemIcon
		g_pSystemIcon = App.TGIcon_Create(pcLCARS, 800)
		g_pSystemIcon.SizeToArtwork()
		fXPos = (pWindow.GetRight() - (pWindow.GetMaximumInteriorWidth() - SYSTEM_SUBPANE_WIDTH -
				 g_pSystemIcon.GetWidth()) / 2.0) - g_pSystemIcon.GetWidth()
		fYPos = (pWindow.GetMaximumInteriorHeight() - g_pSystemIcon.GetHeight()) / 2.0 + SYSTEM_WINDOW_BAR_THICKNESS + pWindow.GetTop()
		pMissionPane.AddChild(g_pSystemIcon, fXPos, fYPos, 0)
		pMissionPane.MoveToFront(g_pSystemIcon)

	#########################################
	# Create the info window
	# For now, create a empty pane.  We'll fill
	# it later.
	global g_pInfoPane
	g_pInfoPane = App.TGPane_Create (1.0, 1.0)
	pMissionPane.AddChild (g_pInfoPane)

	if (App.g_kUtopiaModule.IsHost () or not App.g_kUtopiaModule.IsClient ()):
		# hide the info pane unless we're the client and not the host.
		g_pInfoPane.SetNotVisible ()		

	

	#########################################
	# Add event handlers for the mission pane
	pMissionPane.AddPythonFuncHandlerForInstance(ET_TIME_LIMIT_CLICKED, __name__ + ".HandleTimeLimitClicked")
	pMissionPane.AddPythonFuncHandlerForInstance(ET_FRAG_LIMIT_CLICKED, __name__ + ".HandleFragLimitClicked")
	pMissionPane.AddPythonFuncHandlerForInstance(ET_PLAYER_LIMIT_CLICKED, __name__ + ".HandlePlayerLimitClicked")
	pMissionPane.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".MouseHandler")

	#########################################
	pMultWindow.SetMissionPane (pMissionPane)

	pMissionPane.Layout ()

	# Set the font back to normal small size
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Don't allow the Options Window to come up
#	pOptionsWindow = App.TopWindow_GetTopWindow().FindMainWindow(App.MWT_OPTIONS);
#	if pOptionsWindow.IsVisible():
#		App.TopWindow_GetTopWindow().ToggleOptionsMenu()
#	App.TopWindow_GetTopWindow().AllowShowOptionsWindow(0)

	# Initialize player limit
	pGame = App.MultiplayerGame_Cast(App.Game_GetCurrentGame())
	pGame.SetMaxPlayers(g_iPlayerLimit)	

	App.g_kFocusManager.AddObjectToTabOrder(g_pStartButton)
	App.g_kFocusManager.AddObjectToTabOrder(g_pBackButton)

	return pMissionPane


###############################################################################
#	HandleMouseEventsForGlass()
#	
#	If we're a direct host, we want to cover up our ship stuff with a glass
#	pane to keep the user from getting at it. We have to make sure the user
#	can't click on it, so we make the glass handle mouse events before letting
#	them pass underneath
#	
#	Args:	TGObject*	pObject	- the glass
#			TGEvent*	pEvent	- the ET_MOUSE_EVENT
#	
#	Return:	
###############################################################################
def HandleMouseEventsForGlass(pObject, pEvent):
	pEvent.SetHandled()
	pObject.CallNextHandler(pEvent)
	

###############################################################################
#	HandleMouseEventsForEndPane()
#	
#	If the game over screen is up and the chat window is visible, we must make
#	sure that focus is returned to the input pane after other things have been
#	taken care of
#	
#	Args:	TGObject*	pObject	- the end pane
#			TGEvent*	pEvent	- the ET_MOUSE_EVENT
#	
#	Return:	
###############################################################################
def HandleMouseEventsForEndPane(pObject, pEvent):
	pObject.CallNextHandler(pEvent)
	
	import MissionShared
	if MissionShared.g_bGameOver:
		# Find the chat window
		pTopWindow = App.TopWindow_GetTopWindow()
		pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
		pChatWindow = pMultWindow.GetChatWindow()
		
		if pChatWindow.IsVisible():
			pPane = App.TGPane_Cast(pChatWindow.GetNthChild(0))
			pPara = App.TGParagraph_Cast(pPane.GetNthChild(0))
	
			# Give the focus to the chat paragraph
			pMultWindow.MoveToFront(pChatWindow)
			pTopWindow.SetFocus(pMultWindow)
			pMultWindow.SetFocus(pChatWindow)
			pChatWindow.SetFocus(pPane)
			pPane.SetFocus(pPara)


###############################################################################
#	BuildShipSelectWindow()	
#	
#	Build the stylized window from which the system can be selected
#	
#	Args:	TGPane					pMissionPane	- The pane to which our
#													events should be sent
#			TGLocalizationDatabase	pDatabase		- the database with our
#													text in it		
#	
#	Return:	A TGStylized window with a SubPane inside of it serving as a menu
###############################################################################
def BuildShipSelectWindow (pMissionPane, pDatabase):
	import MissionShared
	import Multiplayer.SpeciesToShip
	# Create the window
	pWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Select Your Ship"), 
						0.0, 0.0, None, 1, SHIPS_WINDOW_WIDTH, SHIPS_WINDOW_HEIGHT)
	pWindow.SetTitleBarThickness(SHIPS_WINDOW_BAR_THICKNESS)
	App.g_kFocusManager.AddObjectToTabOrder(pWindow)

	pSubPane = App.STSubPane_Create (SHIPS_SUBPANE_WIDTH, 500.0, 0)
	pWindow.AddChild (pSubPane, 0, 0, 0)

	
	#########################################
	# Create the buttons
	for iIndex in range(1, Multiplayer.SpeciesToShip.MAX_FLYABLE_SHIPS):
		# Setup the event for when this button is clicked
		pEvent = App.TGIntEvent_Create ()
		pEvent.SetEventType(ET_SELECT_SHIP_SPECIES)
		pEvent.SetInt(iIndex)		# store the index so we know which button was clicked.
		pEvent.SetDestination(pMissionPane)
	
		# Create the button.	
		pButton = App.STButton_CreateW (MissionShared.g_pShipDatabase.GetString (Multiplayer.SpeciesToShip.GetScriptFromSpecies (iIndex)), pEvent)
		if (iIndex == g_iSpecies):
			pButton.SetChosen (1)
			global g_pChosenSpecies
			g_pChosenSpecies = pButton
		pEvent.SetSource (pButton)
		pSubPane.AddChild(pButton, 0, 0, 0)		

	pSubPane.ResizeToContents ()

	return pWindow


###############################################################################
#	BuildShipDescWindow()
#	
#	Builds the stylized window containing the ship description
#	
#	Args:	TGLocalizationDatabase pDatabase - the database with our text in it
#	
#	Return:	The STStylizedWindow containing the ship description paragraph
###############################################################################
def BuildShipDescWindow(pDatabase):
	import MainMenu.mainmenu
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "RightBorder", pDatabase.GetString("Ship Description"), 
						0.0, 0.0, None, 1, SHIPS_DESC_WINDOW_WIDTH, SHIPS_DESC_WINDOW_HEIGHT, App.g_kMultiplayerStylizedPurple)
	pStylizedWindow.SetTitleBarThickness(SHIPS_DESC_WINDOW_BAR_THICKNESS)

	# Go to small font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create the region description paragraph.
	pText = App.TGParagraph_Create("", 
						SHIPS_DESC_WINDOW_WIDTH - 0.05, None, "", 0.0,
						App.TGParagraph.TGPF_WORD_WRAP | App.TGParagraph.TGPF_READ_ONLY)
	pStylizedWindow.AddChild(pText, 0, 0, 0)
	pStylizedWindow.InteriorChangedSize()

	global g_pShipDescWindow
	g_pShipDescWindow = pStylizedWindow

	# Go back to larger font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])


	return pStylizedWindow


###############################################################################
#	BuildRegionSelectWindow()	
#	
#	Build the stylized window from which the system can be selected
#	
#	Args:	TGPane					pMissionPane	- The pane to which our
#													events should be sent
#			TGLocalizationDatabase	pDatabase		- the database with our
#													text in it		
#	
#	Return:	A TGStylized window with a SubPane inside of it serving as a menu
###############################################################################
def BuildRegionSelectWindow (pMissionPane, pDatabase):
	import MissionShared
	import Multiplayer.SpeciesToSystem
	# Create the window
	pWindow = App.STStylizedWindow_CreateW("StylizedWindow", "NoMinimize", pDatabase.GetString("Select Region"), 
						0.0, 0.0, None, 1, SYSTEM_WINDOW_WIDTH, SYSTEM_WINDOW_HEIGHT)
	pWindow.SetTitleBarThickness(SYSTEM_WINDOW_BAR_THICKNESS)
	App.g_kFocusManager.AddObjectToTabOrder(pWindow)

	pSubPane = App.STSubPane_Create (SYSTEM_SUBPANE_WIDTH, 500.0, 0)
	pWindow.AddChild (pSubPane, 0.0, 0.0, 0)

	
	#########################################
	# Create the buttons
	for iIndex in range(1, Multiplayer.SpeciesToSystem.MAX_SYSTEMS):
		# Setup the event for when this button is clicked
		pEvent = App.TGIntEvent_Create ()
		pEvent.SetEventType(ET_SELECT_SYSTEM)
		pEvent.SetInt(iIndex)		# store the index so we know which button was clicked.
		pEvent.SetDestination(pMissionPane)
	
		# Create the button.	
		pButton = App.STButton_CreateW(MissionShared.g_pSystemDatabase.GetString (Multiplayer.SpeciesToSystem.GetScriptFromSpecies (iIndex)), pEvent)
		if (iIndex == g_iSystem):
			pButton.SetChosen (1)
			global g_pChosenSystem
			g_pChosenSystem = pButton
		pEvent.SetSource (pButton)
		InsertChildSorted (pSubPane, pButton)

	pSubPane.ResizeToContents ()

	return pWindow

def InsertChildSorted (pSubPane, pNewButton):
	pName = App.TGString ()
	pNewButton.GetName (pName)
	pcNewName = pName.GetCString ()

	iNumChildren = pSubPane.GetNumChildren ()
	i = 0
	while (i < iNumChildren):
		pButton = App.STButton_Cast (pSubPane.GetNthChild (i))
		if (pButton):
			pButton.GetName (pName)
			pcName = pName.GetCString ()
	
			if (pcNewName < pcName):
				break
		i = i + 1
				
	if (i >= iNumChildren):
		pSubPane.AddChild(pNewButton, 0.0, 0.0, 0)		
	else:
		pSubPane.InsertChild (i, pNewButton, 0, 0, 0)


###############################################################################
#	BuildRegionDescWindow()
#	
#	Builds the stylized window containing the system description
#	
#	Args:	TGLocalizationDatabase pDatabase - the database with our text in it
#	
#	Return:	The STStylizedWindow containing the system description paragraph
###############################################################################
def BuildRegionDescWindow(pDatabase):
	import MainMenu.mainmenu
	pStylizedWindow = App.STStylizedWindow_CreateW("StylizedWindow", "RightBorder", pDatabase.GetString("System Description"), 
						0.0, 0.0, None, 1, SYSTEM_DESC_WINDOW_WIDTH, SYSTEM_DESC_WINDOW_HEIGHT, App.g_kMultiplayerStylizedPurple)
	pStylizedWindow.SetTitleBarThickness(SYSTEM_DESC_WINDOW_BAR_THICKNESS)

	# Go to small font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create the region description paragraph.
	pText = App.TGParagraph_Create("", 
						SYSTEM_DESC_WINDOW_WIDTH - 0.05, None, "", 0.0,
						App.TGParagraph.TGPF_WORD_WRAP | App.TGParagraph.TGPF_READ_ONLY)
	pStylizedWindow.AddChild(pText, 0, 0, 0)
	pStylizedWindow.InteriorChangedSize()

	global g_pSystemDescWindow
	g_pSystemDescWindow = pStylizedWindow

	# Go back to larger font
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])


	return pStylizedWindow


def ConstructTime ():
	import MissionShared
	# Convert float time to hour:min:sec formation
	iSeconds = MissionShared.g_iTimeLeft
	iMinutes = iSeconds / 60
	iSeconds = iSeconds - iMinutes * 60
	iHours = iMinutes / 60
	iMinutes = iMinutes - iHours * 60

	pString = MissionShared.g_pDatabase.GetString("Time Left")
	pcString = pString.GetCString ()
	pcSubString = pcString % (str (iHours), str (iMinutes), str (iSeconds))

	pPane = App.TGPane_Create (0.135, 0.1)
	pText = App.TGParagraph_Create (pcSubString)
#	pText.SetColor (App.g_kSTMenuTextColor)
	pPane.Resize (pPane.GetWidth (), pText.GetHeight (), 0)
	pPane.AddChild (pText, 0, 0, 0)
	return pPane

def UpdateTimeLeftDisplay(pTimePane = None, bLayout = 0):
	import MissionShared
	if (pTimePane == None):
		pTimePane = g_pEndTimePane

	pText = App.TGParagraph_Cast (pTimePane.GetNthChild (0))

	# Convert float time to hour:min:sec formation
	iSeconds = MissionShared.g_iTimeLeft
	iMinutes = iSeconds / 60
	iSeconds = iSeconds - iMinutes * 60
	iHours = iMinutes / 60
	iMinutes = iMinutes - iHours * 60
	
	if (iHours < 10):
		pcHours = "0" + str (iHours)
	else:
		pcHours = str (iHours)

	if (iMinutes < 10):
		pcMinutes = "0" + str (iMinutes)
	else:
		pcMinutes = str (iMinutes)

	if (iSeconds < 10):
		pcSeconds = "0" + str (iSeconds)
	else:
		pcSeconds = str (iSeconds)

	pString = MissionShared.g_pDatabase.GetString("Time Left")
	pcString = pString.GetCString ()
	pcSubString = pcString % (pcHours, pcMinutes, pcSeconds)

	pText.SetString (pcSubString, bLayout)

def UpdateFragLimit (pFragPane, bLayout = 0):
	import MissionShared
	if (pFragPane == None):
		pFragPane = g_pEndFragPane

	pText = App.TGParagraph_Cast (pFragPane.GetNthChild (0))

	pString = None
	pcSubString = None
	if (g_iUseScoreLimit):
		pString = MissionShared.g_pDatabase.GetString("Score Limit:")
		pcString = pString.GetCString ()
		pcSubString = pcString % str (g_iFragLimit * 10000)
	else:
		pString = MissionShared.g_pDatabase.GetString("Frag Limit:")
		pcString = pString.GetCString ()
		pcSubString = pcString % str (g_iFragLimit)
	pText.SetString (pcSubString, bLayout)


def DoScoreWindow ():
	import MissionShared
	# Bring up the score display if it's not alreay up.  Otherwise, hide it.
	# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
	# Move multiplayer window to front.
	pMultWindow.SetVisible ()

	pEndPane = App.TGPane_Cast (pMultWindow.GetEndWindow ())
	if (pEndPane):
		if (pEndPane.IsVisible ()):
			# Hide it since it was showing.
#			print ("Hiding score pane")
			pEndPane.SetNotVisible ()
		else:
			# If there are no other multiplayer panes showing, then
			# show the score display.
			if (not pMultWindow.IsAnyChildVisible ()):
				# Show it since it wasn't visible.
#				print ("Showing score pane")

				# Reposition the player list pane.
				pPane = g_pEndPlayerListPane
				pStyleWindow = g_pEndPlayerListWindow
				if (App.g_kUtopiaModule.IsHost () and (not App.g_kUtopiaModule.IsClient ())):
					pPane.SetPosition (0.30, (1.0 - pStyleWindow.GetHeight ()) / 2.0, 0)
				else:
					pPane.SetPosition (0.59, 0.15, 0)

				# Position frag and time limit
				if (g_iTimeLimit != -1):
					UpdateTimeLeftDisplay(g_pEndTimePane)
					g_pEndTimePane.SetVisible (0)
				else:
					g_pEndTimePane.SetNotVisible (0)

				if (g_iFragLimit != -1):
					UpdateFragLimit(g_pEndFragPane)
					g_pEndFragPane.SetVisible (0)
					g_pEndFragPane.SetPosition(pPane.GetLeft() + 0.05, pPane.GetTop () + pStyleWindow.GetHeight () + 0.005, 0)
				else:
					g_pEndFragPane.SetNotVisible(0)

				# Hide the okay button.
				g_pEndOkayButton.SetNotVisible(0)

				# Hide the restart button.
				g_pEndRestartButton.SetNotVisible(0)

				# Hide the glass
				g_pEndGlass.SetNotVisible(0)

				# Hide the game over text
				g_pEndGameOverText.SetNotVisible(0)

				# Hide the reason text
				g_pEndReasonText.SetNotVisible(0)

				# Hide the instruction text
				g_pEndInstructionText.SetNotVisible(0)

				# Hide the winner text
				g_pEndWinnerText.SetNotVisible(0)
				
				# Hide the end-game chat window
				g_pEndChatSubPane.KillChildren()
				g_pEndChatWindow.SetNotVisible()

				pEndPane.SetVisible(0)
				pEndPane.Layout()
	return 1

###############################################################################
#	DoEndGameDialog()
#	
#	Show the "Game Over" screen
#	
#	Args:	bRestartable	- can the game be restarted?
#			pReasonString	- the string that explains why the game has ended
#			bDoChat			- should we show the chat window?
#	
#	Return:	None
###############################################################################
def DoEndGameDialog(bRestartable = 0, pReasonString = None, bDoChat = 0):
	import MissionShared
	import MissionLib
	import MainMenu.mainmenu
	import BridgeHandlers

	global g_bShipSelectState
	g_bShipSelectState = 0

	global g_bResChangeRestartable
	global g_pResChangeReasonString
	global g_bResChangeDoChat

	g_bResChangeRestartable	= bRestartable
	g_pResChangeReasonString = pReasonString
	g_bResChangeDoChat = bDoChat

	# set game over flag so scoring and everything else stops.
	MissionShared.g_bGameOver = 1

	MainMenu.mainmenu.DisableResChangeButtons ()

	# If we we're in the process of exiting the game, don't show the end game window
	import Multiplayer.MultiplayerMenus
	if Multiplayer.MultiplayerMenus.g_bExitPressed:
		Multiplayer.MultiplayerMenus.g_bExitPressed = 0
		return 1

	# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	# Move the mult window to front so that it can receive input.
	pTopWindow.MoveToFront (pMultWindow)

	# enable mouse and keyboard, just in case it was disabled.
	pTopWindow.AllowMouseInput (1)
	pTopWindow.AllowKeyboardInput (1)

	# Make sure we leave manual targetting mode.
	DropOutOfManualFireModeMultiplayer()	

	# Enable options toggling.
	pTopWindow.DisableOptionsMenu (0)	
	pResumeButton = App.STRoundedButton_Cast(App.TGObject_GetTGObjectPtr(MainMenu.mainmenu.g_idResumeButton))
	if (pResumeButton):
		pResumeButton.SetEnabled ()

	pEndPane = App.TGPane_Cast (pMultWindow.GetEndWindow ())
	if pEndPane:
		# Don't allow the Options Window to come up
		pOptionsWindow = App.OptionsWindow_Cast (App.TopWindow_GetTopWindow().FindMainWindow(App.MWT_OPTIONS))
		if (pOptionsWindow):
			if pOptionsWindow.IsVisible():
				# make multiplayer window visible when user toggles out of options window.
				# but don't actually toggle options menu, since that would be disruptive.

				# first remove all windows that would be made visible when options window is toggled off.
				# this is so things like tactical window doesn't show up underneat the game over screen.
				pOptionsWindow.RemoveAllPreviouslyVisible ()

				# Add multiplayer window to the list of windows that will be made visible when
				# options window is toggled off, and also give the focus to the multiplayer window
				# at that time.
				pOptionsWindow.AddToPreviouslyVisible (pMultWindow)
				pOptionsWindow.SetHasFocusObject (pMultWindow)
#			App.TopWindow_GetTopWindow().ToggleOptionsMenu()
#		App.TopWindow_GetTopWindow().AllowShowOptionsWindow(0)
		
		# Hide the tactical window.
		pTactWindow = App.TacticalWindow_Cast (pTopWindow.FindMainWindow(App.MWT_TACTICAL))
		pTactWindow.SetNotVisible(0)

		# Hide frag and time limit
		g_pEndTimePane.SetNotVisible(0)

		g_pEndFragPane.SetNotVisible(0)

		# Get the string that says who won
		pMissionScript = __import__(MissionLib.GetMission().GetScript())
		pcWinnerString = pMissionScript.GetWinString()

		# Show the reason text and center it
		g_pEndReasonText.SetVisible(0)
		if not pReasonString:
			# If we weren't given a reason, assume the host has been disconnected from us
			pReasonString = MissionShared.g_pDatabase.GetString("Disconnect")
		g_pEndReasonText.SetStringW(pReasonString)
		g_pEndReasonText.SetPosition((1.0 - g_pEndReasonText.GetWidth()) / 2.0,
									g_pEndGameOverText.GetBottom() + 0.02, 0)
		
		# Show the winner text and center it
		g_pEndWinnerText.SetVisible(0)
		g_pEndWinnerText.SetString(pcWinnerString)
		g_pEndWinnerText.SetPosition((1.0 - g_pEndWinnerText.GetWidth()) / 2.0,
									g_pEndReasonText.GetBottom() + 0.02, 0)

		if not bDoChat:
			# Reposition the player list pane.
			g_pEndPlayerListPane.SetPosition(0.30, (pEndPane.GetHeight() - g_pEndPlayerListWindow.GetHeight()) / 2.0, 0)
			pMultWindow.GetChatWindow().SetNotVisible(0)
			g_pEndChatWindow.SetNotVisible(0)
		else:
			# Reposition the player list pane.
			g_pEndPlayerListPane.SetPosition(0.30, g_pEndWinnerText.GetBottom() + 0.02)

			# Reposition the chat window
			# and change the text in case we were in team chat
			pChatWindow = pMultWindow.GetChatWindow()
			pPane = App.TGPane_Cast(pChatWindow.GetNthChild(0))
			pPara = App.TGParagraph_Cast(pPane.GetNthChild(0))
			pText = App.TGParagraph_Cast(pPane.GetNthChild(1))
			pText.SetStringW(MissionShared.g_pDatabase.GetString("Chat"))
			pPara.SetPosition(pText.GetRight() + 0.01, pPara.GetTop(), 0)
			pMultWindow.SetTeamChat(0)
			pChatWindow.SetPosition(0.0 - pPane.GetLeft(), (0.0 - pPane.GetTop()) + (g_pEndOkayButton.GetTop() - (0.02 + pPane.GetHeight())), 0)

			# Set up the end game chat window
			g_pEndChatWindow.SetVisible(0)
			g_pEndChatSubPane.KillChildren()
			g_pEndChatWindow.SetPosition(0.0, g_pEndPlayerListPane.GetTop() + g_pEndPlayerListWindow.GetBottom() + 0.02)
			g_pEndChatWindow.SetFixedSize(1.0,
				pChatWindow.GetTop() + pPane.GetBottom() - 0.02 - g_pEndChatWindow.GetTop())
			g_pEndChatWindow.InteriorChangedSize(1)

		# Show the restart button
		g_pEndRestartButton.SetVisible(0)
		if (bRestartable and App.g_kUtopiaModule.IsHost()):
			g_pEndRestartButton.SetEnabled(0)
		else:
			g_pEndRestartButton.SetDisabled(0)

		# Show the okay button.
		g_pEndOkayButton.SetVisible(0)

		# Show the game over text
		g_pEndGameOverText.SetVisible(0)

		# Set and show the instruction text
		g_pEndInstructionText.SetVisible(0)
		if App.g_kUtopiaModule.IsHost():
			g_pEndInstructionText.SetStringW(MissionShared.g_pDatabase.GetString(
											"Host End Game Instructions"))
		elif bRestartable:
			g_pEndInstructionText.SetStringW(MissionShared.g_pDatabase.GetString(
											"Client End Game Instructions"))
		else:
			g_pEndInstructionText.SetStringW(MissionShared.g_pDatabase.GetString(
											"Client Disconnect Instructions"))

		# Hide all other children
		pMultWindow.HideAllChildren()

		# Show the glass
		g_pEndGlass.SetVisible(0)

		# Show the end pane and lay it out
		pEndPane.SetVisible(0)
		pEndPane.Layout()

		if bDoChat:
			# Give the focus to the chat paragraph
			pChatWindow.SetVisible()
			pMultWindow.MoveToFront(pChatWindow)
			pTopWindow.SetFocus(pMultWindow)
			pMultWindow.SetFocus(pChatWindow)
			pChatWindow.SetFocus(pPane)
			pPane.SetFocus(pPara)
			pPara.SetString("")

		if (App.g_kUtopiaModule.IsHost () and not App.g_kUtopiaModule.IsClient ()):
			# dedicated server.  Hide the options window.
			pMain = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
			if (pMain.IsVisible ()):
				pTopWindow.ToggleOptionsMenu ()	

	pMultWindow.SetVisible ()

	return 1

def MouseHandler (TGObject, pEvent):
	TGObject.CallNextHandler(pEvent)
	pEvent.SetHandled ()
	

###############################################################################
#	HandleTimeLimitClicked()
#	
#	Handle events for selection of a new system
#	
#	Args:	TGObject	pObject - Destination object for the event
#			TGEvent		pEvent  - Our event
#	
#	Return:	None
###############################################################################
def HandleTimeLimitClicked(pObject, pEvent):
	import MissionShared
	global g_iTimeLimit
	if g_iTimeLimit >= MAX_TIME_LIMIT:
		if g_bAllowNoTimeLimit:
			g_iTimeLimit = -1
			g_pTimeLimitButton.SetName(MissionShared.g_pDatabase.GetString("None"))
			pObject.CallNextHandler(pEvent)
			return
		else:
			g_iTimeLimit = 5
	elif g_iTimeLimit == -1:
		g_iTimeLimit = 5
	else:
		g_iTimeLimit = g_iTimeLimit + TIME_LIMIT_INCRIMENT

	# Construct string.
	pString = MissionShared.g_pDatabase.GetString("Num Minutes")
	pcString = pString.GetCString ()

	pcSubString = pcString % str (g_iTimeLimit)

	pString = App.TGString ()
	pString.SetString (pcSubString)

	g_pTimeLimitButton.SetName(pString)
	

###############################################################################
#	HandleFragLimitClicked()
#	
#	Handle events for selection of a new system
#	
#	Args:	TGObject	pObject - Destination object for the event
#			TGEvent		pEvent  - Our event
#	
#	Return:	None
###############################################################################
def HandleFragLimitClicked(pObject, pEvent):
	import MissionShared
	global g_iFragLimit
	if g_iFragLimit >= MAX_FRAG_LIMIT:
		g_iFragLimit = -1
		g_pFragLimitButton.SetName(MissionShared.g_pDatabase.GetString("None"))
		pObject.CallNextHandler(pEvent)
		return
	elif g_iFragLimit == -1:
		g_iFragLimit = 1
	else:
		g_iFragLimit = g_iFragLimit + FRAG_LIMIT_INCRIMENT

	pString = None
	pcSubString = None
	if (g_iUseScoreLimit):
		pString = MissionShared.g_pDatabase.GetString("Num Points")
		pcString = pString.GetCString ()
		pcSubString = pcString % str (g_iFragLimit * 10000)
	else:
		pString = MissionShared.g_pDatabase.GetString("Num Frags")
		pcString = pString.GetCString ()
		pcSubString = pcString % str (g_iFragLimit)

	pString = App.TGString ()
	pString.SetString (pcSubString)

	g_pFragLimitButton.SetName(pString)


###############################################################################
#	HandlePlayerLimitClicked()
#	
#	Handle events for selection of the maximum number of players
#	
#	Args:	TGObject	pObject - Destination object for the event
#			TGEvent		pEvent  - Our event
#	
#	Return:	None
###############################################################################
def HandlePlayerLimitClicked(pObject, pEvent):
	import MissionShared
	global g_iPlayerLimit
	if g_iPlayerLimit >= MAX_PLAYER_LIMIT:
		g_iPlayerLimit = MIN_PLAYER_LIMIT
	else:
		g_iPlayerLimit = g_iPlayerLimit + PLAYER_LIMIT_INCRIMENT

	pGame = App.MultiplayerGame_Cast(App.Game_GetCurrentGame())
	pGame.SetMaxPlayers(g_iPlayerLimit)	
	
	pString = MissionShared.g_pDatabase.GetString("Num Players")
	pcString = pString.GetCString()
	pcSubString = pcString % str(g_iPlayerLimit)

	pString = App.TGString()
	pString.SetString(pcSubString)

	g_pPlayerLimitButton.SetName(pString)


def ResetLimitInfo ():
	import MissionShared

	# player limit
	pcString = MissionShared.g_pDatabase.GetString("Num Players").GetCString()
	pcString = pcString % str(g_iPlayerLimit)
	pString = App.TGString(pcString)
	g_pPlayerLimitButton.SetName(pString)

	# time limit
	if (g_iTimeLimit == -1):
		g_pTimeLimitButton.SetName(MissionShared.g_pDatabase.GetString("None"))
	else:
		pString = MissionShared.g_pDatabase.GetString("Num Minutes")
		pcString = pString.GetCString ()

		pcSubString = pcString % str (g_iTimeLimit)

		pNewString = App.TGString ()
		pNewString.SetString (pcSubString)

		g_pTimeLimitButton.SetName(pNewString)

	# Frag limit
	if (g_iFragLimit == -1):
		g_pFragLimitButton.SetName(MissionShared.g_pDatabase.GetString("None"))
	else:
		pString = None
		pcSubString = None
		if (g_iUseScoreLimit):
			pString = MissionShared.g_pDatabase.GetString("Num Points")
			pcString = pString.GetCString ()
			pcSubString = pcString % str (g_iFragLimit * 10000)
		else:
			pString = MissionShared.g_pDatabase.GetString("Num Frags")
			pcString = pString.GetCString ()
			pcSubString = pcString % str (g_iFragLimit)

		pNewString.SetString (pcSubString)

		g_pFragLimitButton.SetName(pNewString)


###############################################################################
#	SelectSpecies()
#	
#	Handle events for selection of a new system
#	
#	Args:	TGObject	pObject - destination object for the event
#			TGIntEvent	pEvent  - The Int in this event is the index of our new
#									species
#	
#	Return:	None
###############################################################################
def SelectSpecies (iSpecies):
	import MissionShared
	import Multiplayer.SpeciesToShip
	# Set the global species selected number.
	global g_iSpecies
	g_iSpecies = iSpecies

	# Change the icon.
	g_pShipIcon.SetIconNum(Multiplayer.SpeciesToShip.GetIconNum (g_iSpecies), 0)
	g_pShipIcon.SizeToArtwork()
	g_pShipIcon.SetVisible()
	
	# Position the icon at the center of the space available to it
	fXPos = SHIPS_WINDOW_X_POS + SHIPS_SUBPANE_WIDTH + 0.01 + ((SHIPS_WINDOW_WIDTH - (SHIPS_SUBPANE_WIDTH + 0.01) - g_pShipIcon.GetWidth()) / 2.0)
	fYPos = SHIPS_WINDOW_Y_POS + ((SHIPS_WINDOW_HEIGHT - g_pShipIcon.GetHeight()) / 2.0)
	g_pShipIcon.SetPosition(fXPos, fYPos, 0)

	# Get the size of the icon so we can position the text around the icon.
	fLeft = g_pShipIcon.GetLeft()
	fTop = g_pShipIcon.GetTop()
	fWidth = g_pShipIcon.GetWidth()
	fHeight = g_pShipIcon.GetHeight()

	# Change the side
	fPosLeft = fLeft - 0.05
	fPosTop = fTop - g_pShipSideText.GetHeight() - 0.005
	g_pShipSideText.Resize(fWidth + 0.1, g_pShipSideText.GetHeight(), 0)
	g_pShipSideText.SetPosition(fPosLeft, fPosTop)
	g_pShipSideText.SetVisible(0)
	g_pShipSideText.SetTextW(MissionShared.g_pDatabase.GetString(Multiplayer.SpeciesToShip.GetSideFromSpecies (g_iSpecies)))

	# Change the ship name
	fPosLeft = fLeft - 0.05
	fPosBottom = fTop + fHeight + 0.005
	g_pShipNameText.Resize(fWidth + 0.1, g_pShipNameText.GetHeight (), 0)
	g_pShipNameText.SetPosition(fPosLeft, fPosBottom)
	g_pShipNameText.SetVisible(0)
	g_pShipNameText.SetTextW(MissionShared.g_pShipDatabase.GetString (Multiplayer.SpeciesToShip.GetScriptFromSpecies (g_iSpecies)))

	# Change the description paragraph
	pText = App.TGParagraph_Cast (g_pShipDescWindow.GetNthChild (0))

	pText.SetStringW (MissionShared.g_pShipDatabase.GetString (Multiplayer.SpeciesToShip.GetScriptFromSpecies (g_iSpecies) + " Description"))

	g_pShipDescWindow.InteriorChangedSize()

	# Now call layout on the entire menu.
		# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
		# Get the mission pane.
	pMissionPane = pMultWindow.GetMissionPane ()
	pMissionPane.Layout ()


###############################################################################
#	SelectSystem()
#	
#	Handle events for selection of a new system
#	
#	Args:	TGObject	pObject - destination object for the event
#			TGIntEvent	pEvent  - The Int in this event is the index of our new
#									system
#	
#	Return:	None
###############################################################################
def SelectSystem(iSystem):
	import MissionShared
	import Multiplayer.SpeciesToSystem
	# Set the global species selected number.
	global g_iSystem
	g_iSystem = iSystem

	# Change the description paragraph
	if (g_pSystemDescWindow):
		pText = App.TGParagraph_Cast (g_pSystemDescWindow.GetNthChild (0))
		pText.SetStringW(MissionShared.g_pSystemDatabase.GetString (Multiplayer.SpeciesToSystem.GetScriptFromSpecies (g_iSystem) + " Description"))

		g_pSystemDescWindow.InteriorChangedSize()
	
	# Now call layout on the entire menu.
	# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	# Get the mission pane.
	pMissionPane = pMultWindow.GetMissionPane ()
	pMissionPane.Layout ()


def ObjectDestroyedHandler (TGObject, pEvent):
	import MissionShared
#	print ("Delete object handler called\n")
	if (MissionShared.g_bGameOver == 0):
		ShowShipSelectScreen ()

def ShowShipSelectScreen ():
	import MissionLib
	import BridgeHandlers
	import MainMenu.mainmenu

	MainMenu.mainmenu.EnableResChangeButtons ()

	global g_bShipSelectState
	g_bShipSelectState = 1

	# Determine if game is over.  If not, bring up ship select again.
	# Get the current game.  We use this in various places below.
	pGame = App.Game_GetCurrentGame ()
	pMultGame = App.MultiplayerGame_Cast (pGame)

	# Get the top window.
	pTopWindow = App.TopWindow_GetTopWindow()

	# enable mouse and keyboard, just in case it was disabled.
	pTopWindow.AllowMouseInput (1)
	pTopWindow.AllowKeyboardInput (1)

	# Make sure we leave manual targetting mode.
	DropOutOfManualFireModeMultiplayer()	

	# Find the Multiplayer window
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	if (not pMultWindow.IsGameOver ()):
		# Don't allow the Options Window to come up
		pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
		if pOptionsWindow.IsVisible():
			pTopWindow.ToggleOptionsMenu()

		pMapWindow = pTopWindow.FindMainWindow(App.MWT_TACTICAL_MAP)
		if (pMapWindow.HasFocus ()):
			pTopWindow.ToggleMapWindow ()

		# Hide the tactical window.
		pTactWindow = App.TacticalWindow_Cast (pTopWindow.FindMainWindow(App.MWT_TACTICAL))
		pTactWindow.SetNotVisible ()

		# Move multiplayer window to front.
		pTopWindow.MoveToFront (pMultWindow)

		# Hide all children so only mission pane will be visible.
		pMultWindow.HideAllChildren ()

		# Rebuild the info pane
		pMissionScript = __import__(MissionLib.GetMission().GetScript() + "Menus")
		pMissionScript.RebuildInfoPane()

		# Get the mission pane.
		pMissionPane = pMultWindow.GetMissionPane ()
		pMissionPane.SetVisible ()

		# Set the info pane visible
		g_pInfoPane.SetVisible ()

#		App.TopWindow_GetTopWindow().AllowShowOptionsWindow(0)

		# Hide the tactical window.
#		pTactWindow = App.TacticalWindow_Cast (pTopWindow.FindMainWindow(App.MWT_TACTICAL))
#		pTactWindow.SetNotVisible(0)

		# disable time, frag, and player limit buttons, since we can only
		# choose these when we first start the game.
		g_pTimeLimitButton.SetDisabled()
		g_pFragLimitButton.SetDisabled()
		g_pPlayerLimitButton.SetDisabled()

		# Hide back button.  This button is only available the very first time.
		g_pBackButton.SetNotVisible ()

		# if we're here, reset the warp button.
		pWarpButton = App.SortedRegionMenu_GetWarpButton()
		if (pWarpButton):
			pWarpButton.SetLocation (None)


def CreateShip (iType):
	import Multiplayer.SpeciesToShip
	# call script to creat a ship of correct species.
	pShip = Multiplayer.SpeciesToShip.CreateShip (iType)

	return pShip

def PreRebuildAfterResChange ():
	return

def PostRebuildAfterResChange ():
#	print ("Post rebuild after res change called");
	if (g_bShipSelectState):
#		print ("Ship select state is true");
		g_pTimeLimitButton.SetDisabled()
		g_pFragLimitButton.SetDisabled()
		g_pPlayerLimitButton.SetDisabled()

		g_pBackButton.SetNotVisible ()

		g_pSystemPane.SetNotVisible ()
		global g_pSystemIcon
		if (g_pSystemIcon):
			g_pSystemIcon.SetNotVisible ()
		g_pSystemDescPane.SetNotVisible ()

		g_pInfoPane.SetVisible ()
#	else:
#		print ("Ship select state is false");

	ResetLimitInfo ()
	if (g_iSpecies != 0):
		SelectSpecies (g_iSpecies)
	if (g_iSystem != 0):
		SelectSystem (g_iSystem)

	return

def FindGoodLocation (pSet, fRadius):
	kPos = App.TGPoint3 ()
	# first try to find a location that's centered around (0,0,0)
	iCount = 0
	while (iCount < 50):
		x = App.g_kSystemWrapper.GetRandomNumber (200)
		x = x - 100;
		y = App.g_kSystemWrapper.GetRandomNumber (200)
		y = y - 100;
		z = App.g_kSystemWrapper.GetRandomNumber (200)
		z = z - 100;

		kPos.SetXYZ (x, y, z)

		if (pSet.IsLocationEmptyTG (kPos, fRadius, 1)):
			# Okay, found a good location.  Place it here.
			return kPos

		iCount = iCount + 1
	
	# if we're here, we failed to find a good location.  Do the offset method instead.

	# generate random offset direction.
	kOffset = App.TGPoint3 ()
	while (1):
		x = App.g_kSystemWrapper.GetRandomNumber (200) - 100
		y = App.g_kSystemWrapper.GetRandomNumber (200) - 100
		z = App.g_kSystemWrapper.GetRandomNumber (200) - 100
		x = float(x) / 10.0
		y = float(y) / 10.0
		z = float(z) / 10.0

		kOffset.SetXYZ (x, y, z)

		# make sure offset is not zero length
		if (kOffset.Length () > 1.0):
			# good.
			break

	# now add offset to kPos until we find an empty spot
	while pSet.IsLocationEmptyTG(kPos, fRadius, 1) == 0:
		kPos.Add (kOffset)

	# okay, now we've found an empty spot.
	return kPos


###############################################################################
#	DropOutOfManualFireModeMultiplayer()
#	
#	Drops the mouse out of manual fire mode
#	This is different from the Single player version, which checks for you to
#	be on the bridge.. oops, we don't have a bridge in Multiplayer.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def DropOutOfManualFireModeMultiplayer():
	# Make sure we're no longer in mouse pick fire mode (manual aim).
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacWindow.SetMousePickFire(0)

	# Make sure the Pick Fire button matches the state of Pick Fire
	import Bridge.TacticalMenuHandlers
	Bridge.TacticalMenuHandlers.ResetPickFireButton()

# def BuildEndGamePlayerList ():
# 	global g_kEndGamePlayerList
# 	del g_kEndGamePlayerList [0:]
# 
# 	pNetwork = App.g_kUtopiaModule.GetNetwork()
# 	if (pNetwork):
# 		pPlayerList = pNetwork.GetPlayerList()
# 		iNumPlayers = pPlayerList.GetNumPlayers()
# 		
# 		for i in range(0, iNumPlayers):
# 			pPlayer = pPlayerList.GetPlayerAtIndex(i)
# 
# 			# this player exists.  Create a new item for him.
# 			if (pPlayer.IsDisconnected () == 0):
# 				pNewPlayer = App.TGNetPlayer ()
# 				pNewPlayer.SetName (pPlayer.GetName ())
# 
# 				pNewPlayer.SetNetID (pPlayer.GetNetID ())
# 				g_kEndGamePlayerList.append (pNewPlayer)

	