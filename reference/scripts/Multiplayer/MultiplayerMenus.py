###############################################################################
#	Filename:	MultiplayerMenus.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script to build the main menu for multi-player.
#	
#	Created:	10/25/00 -	Alby
###############################################################################

import App
import Tactical.Tactical
import UIHelpers
import MainMenu.mainmenu
import MissionLib

###############################################################################
# Upper buttons and eye candy

TITLE_X_POS								= 0.089375
#TITLE_Y_POS is determined by title bar's height and position

#TITLE_BAR_X_POS determined by the title text's width
TITLE_BAR_X_DISTANCE					= 0.009375
TITLE_BAR_Y_POS							= 0.0141667
TITLE_BAR_RIGHT_EDGE					= 0.990625
TITLE_BAR_HEIGHT						= 0.025

TOP_LEFT_BAR_X_POS						= 0.009375
TOP_LEFT_BAR_Y_POS						= 0.0141667
TOP_LEFT_BAR_WIDTH						= 0.06875
TOP_LEFT_BAR_HEIGHT						= 0.025

TOP_LOWER_LEFT_CURVE_X_POS				= 0.009375
TOP_LOWER_LEFT_CURVE_Y_POS				= 0.0516667
TOP_LOWER_LEFT_CURVE_WIDTH				= 0.146875
TOP_LOWER_LEFT_CURVE_HEIGHT				= 0.13583333
TOP_LOWER_LEFT_CURVE_IN_WIDTH			= 0.06875
TOP_LOWER_LEFT_CURVE_IN_HEIGHT			= 0.12333333
TOP_LOWER_LEFT_CURVE_OI_WIDTH			= 0.03875

TOP_LOWER_BAR_X_POS						= 0.164375
TOP_LOWER_BAR_Y_POS						= 0.175
TOP_LOWER_BAR_WIDTH						= 0.510625
TOP_LOWER_BAR_HEIGHT					= 0.0125

TOP_LOWER_RIGHT_CURVE_X_POS				= 0.683125
TOP_LOWER_RIGHT_CURVE_Y_POS				= 0.0516667
TOP_LOWER_RIGHT_CURVE_WIDTH				= 0.3075
TOP_LOWER_RIGHT_CURVE_HEIGHT			= 0.13583333
TOP_LOWER_RIGHT_CURVE_IN_WIDTH			= 0.095
TOP_LOWER_RIGHT_CURVE_IN_HEIGHT			= 0.12333333
TOP_LOWER_RIGHT_CURVE_OI_WIDTH			= 0.041875

HOST_BUTTON_X_POS						= 0.0925
HOST_BUTTON_Y_POS						= 0.058333333
HOST_BUTTON_WIDTH						= 0.153125
HOST_BUTTON_HEIGHT						= 0.041666667

JOIN_BUTTON_X_POS						= 0.0925
JOIN_BUTTON_Y_POS						= 0.1125
JOIN_BUTTON_WIDTH						= 0.153125
JOIN_BUTTON_HEIGHT						= 0.041666667

EXIT_BUTTON_X_POS						= 0.26125
EXIT_BUTTON_Y_POS						= 0.058333333
EXIT_BUTTON_WIDTH						= 0.2
EXIT_BUTTON_HEIGHT						= 0.041666667

MAIN_MENU_BUTTON_X_POS					= 0.728125
MAIN_MENU_BUTTON_Y_POS					= 0.1125
MAIN_MENU_BUTTON_WIDTH					= 0.153125
MAIN_MENU_BUTTON_HEIGHT					= 0.041666667

NUMBER_3945_X_POS						= 0.94625
NUMBER_3945_Y_POS						= 0.0516667

################################################################################
# Lower eye candy
SUBTITLE_X_POS							= 0.125
#SUBTITLE_Y_POS is determined by subtitle bar's height and position

#SUBTITLE_BAR_X_POS determined by the title text's width
SUBTITLE_BAR_X_DISTANCE					= 0.003125
SUBTITLE_BAR_Y_POS						= 0.2
SUBTITLE_BAR_RIGHT_EDGE					= 0.85625
SUBTITLE_BAR_HEIGHT						= 0.025

BOTTOM_UPPER_LEFT_CURVE_X_POS			= 0.009375
BOTTOM_UPPER_LEFT_CURVE_Y_POS			= 0.2
BOTTOM_UPPER_LEFT_CURVE_WIDTH			= 0.11125
BOTTOM_UPPER_LEFT_CURVE_HEIGHT			= 0.0766667
BOTTOM_UPPER_LEFT_CURVE_IN_WIDTH		= 0.06875
BOTTOM_UPPER_LEFT_CURVE_IN_HEIGHT		= 0.0516667
BOTTOM_UPPER_LEFT_CURVE_OI_WIDTH		= 0.04125

BOTTOM_LEFT_BAR_X_POS					= 0.009375
BOTTOM_LEFT_BAR_Y_POS					= 0.2891667
BOTTOM_LEFT_BAR_WIDTH					= 0.06875
BOTTOM_LEFT_BAR_HEIGHT					= 0.4108333

BOTTOM_LOWER_LEFT_CURVE_X_POS			= 0.009375
BOTTOM_LOWER_LEFT_CURVE_Y_POS			= 0.7125
BOTTOM_LOWER_LEFT_CURVE_WIDTH			= 0.54
BOTTOM_LOWER_LEFT_CURVE_HEIGHT			= 0.276667
BOTTOM_LOWER_LEFT_CURVE_IN_WIDTH		= 0.06875
BOTTOM_LOWER_LEFT_CURVE_IN_HEIGHT		= 0.264167
BOTTOM_LOWER_LEFT_CURVE_OI_WIDTH		= 0.039375

NUMBER_190_X_POS						= 0.014375
NUMBER_190_Y_POS						= 0.7083333

BOTTOM_UPPER_RIGHT_CURVE_X_POS			= 0.864375
BOTTOM_UPPER_RIGHT_CURVE_Y_POS			= 0.2
BOTTOM_UPPER_RIGHT_CURVE_WIDTH			= 0.12625
BOTTOM_UPPER_RIGHT_CURVE_HEIGHT			= 0.285
BOTTOM_UPPER_RIGHT_CURVE_IN_WIDTH		= 0.095
BOTTOM_UPPER_RIGHT_CURVE_IN_HEIGHT		= 0.26
BOTTOM_UPPER_RIGHT_CURVE_OI_WIDTH		= 0.040625

BOTTOM_RIGHT_BAR_X_POS					= 0.895625
BOTTOM_RIGHT_BAR_Y_POS					= 0.4975
BOTTOM_RIGHT_BAR_WIDTH					= 0.095
BOTTOM_RIGHT_BAR_HEIGHT					= 0.3083333

BOTTOM_LOWER_RIGHT_CURVE_X_POS			= 0.864375
BOTTOM_LOWER_RIGHT_CURVE_Y_POS			= 0.8183333
BOTTOM_LOWER_RIGHT_CURVE_WIDTH			= 0.12625
BOTTOM_LOWER_RIGHT_CURVE_HEIGHT			= 0.1708333
BOTTOM_LOWER_RIGHT_CURVE_IN_WIDTH		= 0.095
BOTTOM_LOWER_RIGHT_CURVE_IN_HEIGHT		= 0.1583333
#BOTTOM_LOWER_RIGHT_CURVE_OI_WIDTH		= 0.040625
BOTTOM_LOWER_RIGHT_CURVE_OI_WIDTH		= 0.04

NUMBER_46804_X_POS						= 0.928125
NUMBER_46804_Y_POS						= 0.7805

BOTTOM_LOWER_BAR_1_X_POS				= 0.558125
BOTTOM_LOWER_BAR_1_Y_POS				= 0.9766667
BOTTOM_LOWER_BAR_1_WIDTH				= 0.07625
BOTTOM_LOWER_BAR_1_HEIGHT				= 0.0125

BOTTOM_LOWER_BAR_2_X_POS				= 0.640625
BOTTOM_LOWER_BAR_2_Y_POS				= 0.9766667
BOTTOM_LOWER_BAR_2_WIDTH				= 0.215625
BOTTOM_LOWER_BAR_2_HEIGHT				= 0.0125

################################################################################
# The sub panes in which the Client and Host UIs will go

SUB_PANE_X_POS							= 0.0775
SUB_PANE_Y_POS							= 0.225
SUB_PANE_WIDTH							= 0.8175
SUB_PANE_HEIGHT							= 0.75166667

################################################################################
# The Host UI

HOST_PLAYER_NAME_PARA_X_POS				= 0.015

HOST_PLAYER_NAME_INPUT_X_POS			= 0.138125
HOST_PLAYER_NAME_INPUT_Y_POS			= 0.0641667
HOST_PLAYER_NAME_INPUT_WIDTH			= 0.31875
HOST_PLAYER_NAME_INPUT_HEIGHT			= 0.0316667


HOST_GAME_NAME_PARA_X_POS				= 0.015

HOST_GAME_NAME_INPUT_X_POS				= 0.138125
HOST_GAME_NAME_INPUT_Y_POS				= 0.1166667
HOST_GAME_NAME_INPUT_WIDTH				= 0.31875
HOST_GAME_NAME_INPUT_HEIGHT				= 0.0316667


HOST_PASSWORD_PARA_X_POS				= 0.015

HOST_PASSWORD_INPUT_X_POS				= 0.138125
HOST_PASSWORD_INPUT_Y_POS				= 0.1691667
HOST_PASSWORD_INPUT_WIDTH				= 0.31875
HOST_PASSWORD_INPUT_HEIGHT				= 0.0316667


HOST_INTERNET_BUTTON_X_POS				= 0.1375
HOST_INTERNET_BUTTON_Y_POS				= 0.2275
HOST_INTERNET_BUTTON_WIDTH				= 0.153125
HOST_INTERNET_BUTTON_HEIGHT				= 0.0416667

HOST_LAN_BUTTON_X_POS					= 0.303125
HOST_LAN_BUTTON_Y_POS					= 0.2275
HOST_LAN_BUTTON_WIDTH					= 0.153125
HOST_LAN_BUTTON_HEIGHT					= 0.0416667

HOST_DEDICATED_BUTTON_X_POS				= 0.1375
HOST_DEDICATED_BUTTON_Y_POS				= 0.2866667
HOST_DEDICATED_BUTTON_WIDTH				= 0.2125
HOST_DEDICATED_BUTTON_HEIGHT			= 0.0416667

HOST_TEXT_AREA_X_POS					= 0.1375
HOST_TEXT_AREA_Y_POS					= 0.3525
HOST_TEXT_AREA_WIDTH					= 0.321875

HOST_GAME_MENU_X_POS					= 0.475625
HOST_GAME_MENU_Y_POS					= 0.0225
HOST_GAME_MENU_WIDTH					= 0.32875
HOST_GAME_MENU_HEIGHT					= 0.6525
HOST_GAME_MENU_BAR_THICKNESS				= 0.0291667
HOST_START_BUTTON_X_POS					= 0.65
HOST_START_BUTTON_Y_POS					= 0.6933333
HOST_START_BUTTON_WIDTH					= 0.153125
HOST_START_BUTTON_HEIGHT				= 0.0416667


################################################################################
# The client UI

CLIENT_PLAYER_NAME_PARA_X_POS			= 0.045625

CLIENT_PLAYER_NAME_INPUT_X_POS			= 0.170625
CLIENT_PLAYER_NAME_INPUT_Y_POS			= 0.0148333
CLIENT_PLAYER_NAME_INPUT_WIDTH			= 0.296875
CLIENT_PLAYER_NAME_INPUT_HEIGHT			= 0.0316667


CLIENT_PASSWORD_PARA_X_POS				= 0.045625

CLIENT_PASSWORD_INPUT_X_POS				= 0.170625
CLIENT_PASSWORD_INPUT_Y_POS				= 0.0673333
CLIENT_PASSWORD_INPUT_WIDTH				= 0.296875
CLIENT_PASSWORD_INPUT_HEIGHT			= 0.0316667


CLIENT_DIRECT_JOIN_BUTTON_X_POS			= 0.014375
CLIENT_DIRECT_JOIN_BUTTON_Y_POS			= 0.1198333
CLIENT_DIRECT_JOIN_BUTTON_WIDTH			= 0.148125
CLIENT_DIRECT_JOIN_BUTTON_HEIGHT		= 0.0316667

CLIENT_DIRECT_JOIN_INPUT_X_POS			= 0.170625
CLIENT_DIRECT_JOIN_INPUT_Y_POS			= 0.1198333
CLIENT_DIRECT_JOIN_INPUT_WIDTH			= 0.626875
CLIENT_DIRECT_JOIN_INPUT_HEIGHT			= 0.0316667

CLIENT_INTERNET_BUTTON_X_POS			= 0.483125
CLIENT_INTERNET_BUTTON_Y_POS			= 0.0148333
CLIENT_INTERNET_BUTTON_WIDTH			= 0.153125
CLIENT_INTERNET_BUTTON_HEIGHT			= 0.0416667

CLIENT_LAN_BUTTON_X_POS					= 0.483125
CLIENT_LAN_BUTTON_Y_POS					= 0.0673333
CLIENT_LAN_BUTTON_WIDTH					= 0.153125
CLIENT_LAN_BUTTON_HEIGHT				= 0.0416667

CLIENT_START_QUERY_BUTTON_X_POS			= 0.65
CLIENT_START_QUERY_BUTTON_Y_POS			= 0.0148333
CLIENT_START_QUERY_BUTTON_WIDTH			= 0.153125
CLIENT_START_QUERY_BUTTON_HEIGHT		= 0.0416667

CLIENT_STOP_QUERY_BUTTON_X_POS			= 0.65
CLIENT_STOP_QUERY_BUTTON_Y_POS			= 0.0673333
CLIENT_STOP_QUERY_BUTTON_WIDTH			= 0.153125
CLIENT_STOP_QUERY_BUTTON_HEIGHT			= 0.0416667

CLIENT_GLASS_X_POS						= 0.0
CLIENT_GLASS_Y_POS						= 0.1708333
CLIENT_GLASS_WIDTH						= 0.8175
CLIENT_GLASS_HEIGHT						= 0.5041667

CLIENT_GAMES_MENU_X_POS					= 0.014375
CLIENT_GAMES_MENU_Y_POS					= 0.1708333
CLIENT_GAMES_MENU_WIDTH					= 0.573125
CLIENT_GAMES_MENU_HEIGHT				= 0.5041667
CLIENT_GAMES_MENU_BAR_THICKNESS			= 0.0291667
CLIENT_GAMES_MENU_DIV_BAR_THICKNESS		= 0.003125
CLIENT_GAMES_MENU_BG_DIV_BAR_THICKNESS	= 0.009375
CLIENT_GAMES_MENU_DIV_BAR_HEIGHT		= 0.4708333
CLIENT_GAMES_MENU_HEADER_COVER_X_POS	= 0.021875
CLIENT_GAMES_MENU_HEADER_COVER_Y_POS	= 0.2083333
CLIENT_GAMES_MENU_HEADER_COVER_WIDTH	= 0.565625
CLIENT_GAMES_MENU_HEADER_COVER_HEIGHT	= 0.055

CLIENT_GAMES_NAMES_MENU_X_POS			= 0.0
CLIENT_NAMES_BUTTON_X_POS				= 0.026875
CLIENT_NAMES_BUTTON_Y_POS				= 0.2083333
CLIENT_NAMES_BUTTON_WIDTH				= 0.26625
CLIENT_NAMES_BUTTON_HEIGHT				= 0.0308333

CLIENT_GAMES_MENU_BG_DIV_BAR_1_X_POS	= 0.293125
CLIENT_GAMES_MENU_DIV_BAR_1_X_POS		= 0.29625

CLIENT_GAMES_TYPE_MENU_X_POS			= 0.275625
CLIENT_TYPE_BUTTON_X_POS				= 0.3025
CLIENT_TYPE_BUTTON_Y_POS				= 0.2083333
CLIENT_TYPE_BUTTON_WIDTH				= 0.0925
CLIENT_TYPE_BUTTON_HEIGHT				= 0.0308333

CLIENT_GAMES_MENU_BG_DIV_BAR_2_X_POS	= 0.395
CLIENT_GAMES_MENU_DIV_BAR_2_X_POS		= 0.398125

CLIENT_GAMES_PING_MENU_X_POS			= 0.3775
CLIENT_PING_BUTTON_X_POS				= 0.404375
CLIENT_PING_BUTTON_Y_POS				= 0.2083333
CLIENT_PING_BUTTON_WIDTH				= 0.086875
CLIENT_PING_BUTTON_HEIGHT				= 0.0308333

CLIENT_GAMES_MENU_BG_DIV_BAR_3_X_POS	= 0.49125
CLIENT_GAMES_MENU_DIV_BAR_3_X_POS		= 0.494375

CLIENT_GAMES_PLAYERS_MENU_X_POS			= 0.47375
CLIENT_PLAYERS_BUTTON_X_POS				= 0.500625
CLIENT_PLAYERS_BUTTON_Y_POS				= 0.2083333
CLIENT_PLAYERS_BUTTON_WIDTH				= 0.086875
CLIENT_PLAYERS_BUTTON_HEIGHT			= 0.0308333

CLIENT_COMPLETION_BUTTON_X_POS			= 0.014375
CLIENT_COMPLETION_BUTTON_Y_POS			= 0.6933333
CLIENT_COMPLETION_BUTTON_WIDTH			= 0.573125
CLIENT_COMPLETION_BUTTON_HEIGHT			= 0.0416667

CLIENT_PLAYERS_LIST_X_POS				= 0.60625
CLIENT_PLAYERS_LIST_Y_POS				= 0.1708333
CLIENT_PLAYERS_LIST_WIDTH				= 0.196875
CLIENT_PLAYERS_LIST_HEIGHT				= 0.295
CLIENT_PLAYERS_LIST_BAR_THICKNESS		= 0.0291667

CLIENT_INFO_WINDOW_X_POS				= 0.60625
CLIENT_INFO_WINDOW_Y_POS				= 0.475
CLIENT_INFO_WINDOW_WIDTH				= 0.196875
CLIENT_INFO_WINDOW_HEIGHT				= 0.2
CLIENT_INFO_WINDOW_BAR_THICKNESS		= 0.0291667

CLIENT_COMPLETION_PARA_X_POS			= 0.028125

CLIENT_COMPLETION_BAR_X_POS				= 0.158125
CLIENT_COMPLETION_BAR_Y_POS				= 0.6975
CLIENT_COMPLETION_BAR_WIDTH				= 0.35
CLIENT_COMPLETION_BAR_HEIGHT			= 0.0333333

CLIENT_COMPLETION_NUMBER_X_POS			= 0.52375

CLIENT_START_BUTTON_X_POS				= 0.65
CLIENT_START_BUTTON_Y_POS				= 0.6933333
CLIENT_START_BUTTON_WIDTH				= 0.153125
CLIENT_START_BUTTON_HEIGHT				= 0.0416667

################################################################################
# event types.
ET_SHOW_CLIENT_UI					= 0
ET_SHOW_HOST_UI						= 0
ET_EXIT_MULTIPLAYER					= 0
ET_RETURN_TO_MAIN_MENU				= 0
ET_DEDICATED_CLICKED				= 0
ET_CLIENT_START_BUTTON_CLICKED 		= 0
ET_HOST_START_BUTTON_CLICKED   		= 0
ET_TOGGLE_DIRECT_JOIN				= 0

################################################################################
# global vars 
g_fYPixelOffset = 0.0
g_fXPixelOffset = 0.0

g_bGame = 0 # Is there currently a game in progress?
g_bPreGameUIBuilt = 0 # Has our pre-game UI been constructed?
g_bClientUI = 1 # Were we last looking at the host or client UI?
g_bExitPressed = 0 # Was the exit button just pressed?
g_bEventHandlersAdded = 0

# Make sure none of our global pointers are serialized
NonSerializedObjects = (
"g_pMultiplayerPane",
"g_pPreGamePane",
"g_pClientButton",
"g_pHostButton",
"g_pExitButton",
"g_pClientPane",
"g_pHostPane",
"g_pSubtitle",
"g_pSubtitleBar",
"g_pClientNameInput",
"g_pClientPasswordInput",
"g_pClientDirectButton",
"g_pClientDirectInput",
"g_pClientInternetButton",
"g_pClientLanButton",
"g_pClientStartQueryButton",
"g_pClientStopQueryButton",
"g_pClientCompletionText",
"g_pClientCompletionNumber",
"g_pClientCompletionIcon",
"g_pClientGameInfoPara",
"g_pClientGameInfoWindow",
"g_pClientPlayersWindow",
"g_pClientPlayersMenu",
"g_pClientGamesWindow",
"g_pClientGamesNameMenu",
"g_pClientGamesTypeMenu",
"g_pClientGamesPingMenu",
"g_pClientGamesPlayersMenu",
"g_pClientStartButton",
"g_pClientGlass",
"g_pClientGlass2",
"g_pHostGameNameInput",
"g_pHostPlayerNameCaption",
"g_pHostPlayerNameInput",
"g_pHostPasswordInput",
"g_pHostDedicatedButton",
"g_pHostInternetButton",
"g_pHostLanButton",
"g_pHostTextArea",
"g_pHostGamesMenu",
"g_pHostStartButton",
"g_pMissionPane",
"g_pJunkText5",
"g_pJunkText6",
"g_pJunkText7",
"g_pMainMenuButton",)


# General Pre-game UI
g_pMultiplayerPane			= None
g_pPreGamePane				= None
g_pClientButton				= None
g_pHostButton				= None
g_pExitButton				= None
g_pClientPane				= None
g_pHostPane					= None
g_pMissionPane				= None
g_pSubtitle					= None
g_pSubtitleBar				= None

# Client Pre-game UI
g_pClientNameInput			= None
g_pClientPasswordInput		= None
g_pClientDirectButton		= None
g_pClientDirectInput		= None
g_pClientInternetButton		= None
g_pClientLanButton			= None
g_pClientStartQueryButton	= None
g_pClientStopQueryButton	= None
g_pClientCompletionText		= None
g_pClientCompletionNumber	= None
g_pClientCompletionIcon		= None
g_pClientGameInfoPara		= None
g_pClientGameInfoWindow		= None
g_pClientPlayersWindow		= None
g_pClientPlayersMenu		= None
g_pClientGamesWindow		= None
g_pClientGamesNameMenu		= None
g_pClientGamesTypeMenu		= None
g_pClientGamesPingMenu		= None
g_pClientGamesPlayersMenu	= None
g_pClientStartButton		= None
g_pClientGlass				= None
g_pClientGlass2				= None

# Host Pre-game UI
g_pHostGameNameInput		= None
g_pHostPlayerNameCaption	= None
g_pHostPlayerNameInput		= None
g_pHostPasswordInput		= None
g_pHostDedicatedButton		= None
g_pHostInternetButton		= None
g_pHostLanButton			= None
g_pHostTextArea				= None
g_pHostGamesMenu			= None
g_pHostStartButton			= None
g_pMainMenuButton			= None

g_pJunkText5 = None
g_pJunkText6 = None
g_pJunkText7 = None



################################################################################
# Message types
CHAT_MESSAGE = App.MAX_MESSAGE_TYPES + 1
TEAM_CHAT_MESSAGE = App.MAX_MESSAGE_TYPES + 2


###############################################################################
#	AddEventHandlers()
#	
#	Adds events to the manager	
#	
#	Args:	pMultWindow		- Window that events are added for.
#	
#	Return:	none
###############################################################################
def AddEventHandlers (pMultWindow):
	if g_bEventHandlersAdded:
		return

#	print ("*** MultiplayerMenus adding handlers")

	global g_bEventHandlersAdded
	g_bEventHandlersAdded = 1
	
	global ET_SHOW_CLIENT_UI
	global ET_SHOW_HOST_UI
	global ET_EXIT_MULTIPLAYER
	global ET_RETURN_TO_MAIN_MENU
	global ET_DEDICATED_CLICKED
	global ET_CLIENT_START_BUTTON_CLICKED
	global ET_HOST_START_BUTTON_CLICKED
	global ET_TOGGLE_DIRECT_JOIN

	ET_SHOW_CLIENT_UI					= App.UtopiaModule_GetNextEventType()
	ET_SHOW_HOST_UI						= App.UtopiaModule_GetNextEventType()
	ET_EXIT_MULTIPLAYER					= App.UtopiaModule_GetNextEventType()
	ET_RETURN_TO_MAIN_MENU				= App.UtopiaModule_GetNextEventType()
	ET_DEDICATED_CLICKED				= App.UtopiaModule_GetNextEventType()
	ET_CLIENT_START_BUTTON_CLICKED 		= App.UtopiaModule_GetNextEventType()
	ET_HOST_START_BUTTON_CLICKED   		= App.UtopiaModule_GetNextEventType()
	ET_TOGGLE_DIRECT_JOIN				= App.UtopiaModule_GetNextEventType()
	
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_LOCAL_INTERNET_HOST,			__name__ + ".ToggleLocalInternetHost")
#	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_CREATE_CLIENT_AND_SERVER,	__name__ + ".HandleClientServer")
#	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_CREATE_SERVER,				__name__ + ".HandleServer")
#	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_CREATE_CLIENT, 				__name__ + ".HandleClient")
#	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_CREATE_DIRECT_CLIENT,		__name__ + ".HandleDirectClient")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_CANCEL,						__name__ + ".HandleCancel")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_CANCEL_CONNECT, 			 	__name__ + ".HandleCancelConnect")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_END_GAME_OKAY, 			 	__name__ + ".ExitMultiplayer")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_SET_MISSION_NAME,  		 	__name__ + ".HandleSetMissionName")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_SERVER_LIST_PERCENTAGE, 		__name__ + ".HandleServerListPercentage")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_SERVER_LIST_STATE,  		 	__name__ + ".HandleServerListState")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_SERVER_ENTRY_EVENT,  	 	__name__ + ".HandleServerEntry")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_SERVER_PLAYER_EVENT,  	 	__name__ + ".HandleServerPlayer")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_REFRESH_SERVER_LIST_DONE, 	__name__ + ".HandleRefreshServerListDone")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,					__name__ + ".KeyboardHandler")
	pMultWindow.AddPythonFuncHandlerForInstance(ET_TOGGLE_DIRECT_JOIN,				__name__ + ".ToggleDirectJoin")
	pMultWindow.AddPythonFuncHandlerForInstance(ET_SHOW_CLIENT_UI,					__name__ + ".ShowClientUI")
	pMultWindow.AddPythonFuncHandlerForInstance(ET_SHOW_HOST_UI,					__name__ + ".ShowHostUI")
	pMultWindow.AddPythonFuncHandlerForInstance(ET_EXIT_MULTIPLAYER,				__name__ + ".ExitMultiplayer")
	pMultWindow.AddPythonFuncHandlerForInstance(ET_RETURN_TO_MAIN_MENU,				__name__ + ".ReturnToMainMenu")
	pMultWindow.AddPythonFuncHandlerForInstance(ET_DEDICATED_CLICKED,				__name__ + ".HandleDedicatedClicked")
	pMultWindow.AddPythonFuncHandlerForInstance(ET_CLIENT_START_BUTTON_CLICKED,		__name__ + ".HandleClientStartClicked")
	pMultWindow.AddPythonFuncHandlerForInstance(ET_HOST_START_BUTTON_CLICKED,		__name__ + ".HandleHostStartClicked")
	pMultWindow.AddPythonFuncHandlerForInstance(App.ET_START,						__name__ + ".HandleStartGame")

###############################################################################
#	CreateMenuToggleButton(pName, pNameOn, pNameOff, eType, iDefault)
#	
#	Creates a toggle button (two-way) for the options menu.
#	
#	Args:	pName - name of the button
#			pNameOn - name when activated
#			pNameOff - name when deactivated
#			eType - event type to send when triggered
#			iDefault - default button state
#	
#	Return:	the newly-created button
###############################################################################
def CreateMenuToggleButton(pName, pNameOn, pNameOff, eType, iDefault):
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER)

	pOnEvent = App.TGBoolEvent_Create()
	pOnEvent.SetEventType(eType)
	pOnEvent.SetDestination(pMultWindow)
	pOnEvent.SetBool(1)

	pOffEvent = App.TGBoolEvent_Create()
	pOffEvent.SetEventType(eType)
	pOffEvent.SetDestination(pMultWindow)
	pOffEvent.SetBool(0)

	MenuButton = App.STToggle_CreateW(pName, iDefault, pNameOn, pOnEvent, pNameOff, pOffEvent)
	return MenuButton


###############################################################################
#	CreateBoolButton()
#	
#	Creates a regular Star Trek button with a TGBoolEvent
#	
#	Args:	pName - the name of the button
#			eType - event type to send when the button is activated
#			pDestination - the destination for the event
#			bState - the state of the button?
#			fWidth - the width of the button
#			fHeight - the height of the button
#	
#	Return:	the newly-created button
###############################################################################
def CreateBoolButton(pName, eType, pDestination, bState = 0, fWidth = 0.0, fHeight = 0.0):
	pEvent = App.TGBoolEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pDestination)
	pEvent.SetBool(bState)

	if fWidth == 0.0 and fHeight == 0.0:
		pMenuButton = App.STButton_CreateW(pName, pEvent)
	else:
		pMenuButton = App.STButton_CreateW(pName, pEvent, 0, fWidth, fHeight)

	pMenuButton.SetJustification(App.STButton.CENTER)
	return pMenuButton

###############################################################################
#	CreateButton()
#	
#	Creates a regular Star Trek button
#	
#	Args:	pName - the name of the button
#			eType - event type to send when the button is activated
#			pDestination - the destination for the event
#			iState - the state of the button?
#			fWidth - the width of the button
#			fHeight - the height of the button
#	
#	Return:	the newly-created button
###############################################################################
def CreateButton(pName, eType, pDestination, iState = 0, fWidth = 0.0, fHeight = 0.0):
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pDestination)
	pEvent.SetInt(iState)

	if fWidth == 0.0 and fHeight == 0.0:
		pMenuButton = App.STButton_CreateW(pName, pEvent)
	else:
		pMenuButton = App.STButton_CreateW(pName, pEvent, 0, fWidth, fHeight)

	pMenuButton.SetJustification(App.STButton.CENTER)
	return pMenuButton


###############################################################################
#	CreateRoundedTextEntry()
#	
#	Creates a rounded text entry thingie
#	
#	Args:	pDefault	 - the default string of the text entry
#			pcConfigName - the name of this box's data in the config file
#			kColor		 - the color of this thingie
#			fWidth		 - the width of this thingie
#			fHeight		 - the height of this thingie
#	Return:	the newly-created thingie
###############################################################################
def CreateRoundedTextEntry(pDefault, pcConfigName, kColor, fWidth, fHeight, iMaxChars):
	global g_fYPixelOffset
	global g_fXPixelOffset

	# Icon numbers in LCARS group for curve icons. Inner curve icon number is
	# first.
	kUpperRightCurveIcons		= [142, 143]
	kLowerRightCurveIcons		= [146, 147]
	
	# First create a pane for this.
	pPane = App.TGPane_Create(fWidth, fHeight)

	# Get LCARS string.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()

	# Calculate the size of the curves based on the height
	fScreenRatio = App.g_kIconManager.GetScreenWidth () / App.g_kIconManager.GetScreenHeight ()
	fCurveHeight = fHeight * 2.0 / 5.0
	fBetweenHeight = fHeight / 5.0
	fCurveWidth = fCurveHeight / fScreenRatio

	# Calculate the size of the square region
	fRectWidth = fWidth - fCurveWidth
	if (fRectWidth < 0):
		fRectWidth = 0

	# Create the text entry button
	pTextEntry = App.TGParagraph_Create("")
	if (pDefault):
		pTextEntry.SetStringW(pDefault)
	pTextEntry.SetMaxChars (iMaxChars)
	pTextEntry.Resize (fRectWidth - 0.01, pTextEntry.GetHeight(), 0)
	pTextEntry.SetReadOnly(0)
	pTextEntry.SetIgnoreString("\n\r\t")
	pTextPane = App.TGPane_Create (fRectWidth - 0.01, pTextEntry.GetHeight ())
	pTextPane.AddChild(pTextEntry, 0.0, 0.0, 0)
	pPane.AddChild (pTextPane, 0.006, 0.005, 0)

	# Add a hidden child that stores the name to use in the configuration file.
	pPara = App.TGParagraph_Create(pcConfigName)
	pPane.AddChild(pPara, 0, 0)
	pPara.SetNotVisible()

	# Create the icons
	pBlackRegion = App.TGIcon_Create(pcLCARS, 200, App.g_kSTMenuTextColor)
	pBlackRegion.Resize(fRectWidth - g_fXPixelOffset * 4.0, fHeight - g_fYPixelOffset * 4.0, 0)
	pPane.AddChild(pBlackRegion, g_fXPixelOffset * 2.0, g_fYPixelOffset * 2.0, 0)

	pRectRegion = App.TGIcon_Create(pcLCARS, 200, kColor)
	pRectRegion.Resize(fRectWidth, fHeight, 0)
	pPane.AddChild (pRectRegion, 0.0, 0.0, 0)

	pCurve = App.TGIcon_Create(pcLCARS, kUpperRightCurveIcons[1], kColor)
	pCurve.Resize(fCurveWidth, fCurveHeight, 0)
	pPane.AddChild(pCurve, fRectWidth, 0, 0)
	pCurve.AlignTo(pRectRegion, App.TGUIObject.ALIGN_UR, App.TGUIObject.ALIGN_UL)

	pBetweenCurveRegion = App.TGIcon_Create(pcLCARS, 200, kColor)
	pBetweenCurveRegion.Resize(fCurveWidth, fBetweenHeight + 0.00208, 0)
	pPane.AddChild(pBetweenCurveRegion, fRectWidth, fCurveHeight, 0)

	pCurve = App.TGIcon_Create(pcLCARS, kLowerRightCurveIcons[1], kColor)
	pCurve.Resize(fCurveWidth, fCurveHeight, 0)
	pPane.AddChild(pCurve, fRectWidth, fCurveHeight * 2, 0)
	pCurve.AlignTo(pRectRegion, App.TGUIObject.ALIGN_BR, App.TGUIObject.ALIGN_BL)
	pBetweenCurveRegion.AlignTo(pCurve, App.TGUIObject.ALIGN_UL, App.TGUIObject.ALIGN_BL)

	# Resize the pane based on curve and rect size.  Note it is not using the width
	# directly, since it may be different than the calculated widths.
	pPane.Resize(fCurveWidth + fRectWidth, fHeight)

	pPane.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".RoundedTextEntryMouseHandler")

	return pPane

###############################################################################
#	BuildMultiplayerMenus()
#	
#	Builds the options menu.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def BuildMultiplayerMenus():
	# Find the Multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	# Kill children at start so we can reload this script in game.
	pMultWindow.KillChildren()

	#Load localization database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")

	# setup the top and left of the position of the pane.
	fLeft = 0.156
	fTop = 0.167

	# Calculate one pixel offset
	global g_fYPixelOffset
	global g_fXPixelOffset

	g_fYPixelOffset = 1.0 / App.g_kIconManager.GetScreenHeight ()
	g_fXPixelOffset = 1.0 / App.g_kIconManager.GetScreenWidth ()


	########################################################
	# Build status window
	############################################################
	pPane = BuildStatusWindow(pMultWindow, pDatabase)
	pMultWindow.AddChild (pPane)
	pMultWindow.SetStatusWindow (pPane)
	pPane.SetNotVisible ()


	########################################################
	# Build chat window
	############################################################
	pPane = BuildChatWindow (pMultWindow, pDatabase)
	pMultWindow.AddChild (pPane)
	pMultWindow.SetChatWindow (pPane)
	pPane.SetNotVisible ()


	########################################################
	# Unload database
	############################################################
	App.g_kLocalizationManager.Unload(pDatabase)


	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NETWORK_MESSAGE_EVENT, pMultWindow, __name__ + ".ProcessMessageHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_UI_REPOSITION, pMultWindow, __name__ + ".HandleSwitchRes")


###############################################################################
#	BuildMultiplayerPreGameMenus()
#	
#	Builds the multiplayer menus used for starting up a multiplayer game
#	
#	Args:	bForceDoItAgain		- should we rebuild it even if it's already
#								in existance
#	
#	Return:	a TGPane* containing the multiplayer pre-game menus
###############################################################################
def BuildMultiplayerPreGameMenus(bForceDoItAgain = 1):
	global g_pMultiplayerPane
	global g_pPreGamePane
	global g_bPreGameUIBuilt

	bMissionPaneVisible = 1

	pTopWindow = App.TopWindow_GetTopWindow()

	if g_bPreGameUIBuilt:
		if bForceDoItAgain:
			# before we delete store off some info
			# Find the Multiplayer window
			# Store off some state info prior to doing the rebuild
			pMissionPane = g_pMultiplayerPane.GetMissionPane()
			if (pMissionPane):
				bMissionPaneVisible = pMissionPane.IsVisible ()

			import MissionMenusShared

			MissionMenusShared.PreRebuildAfterResChange ()

			MissionMenusShared.DeleteMissionMenus()
			
#			BuildMultiplayerMenus()
			
			App.g_kFocusManager.RemoveAllObjectsUnder (g_pPreGamePane)

#			print ("*** Killing pre game pane's children")
			g_pPreGamePane.KillChildren()
		else:
			g_pPreGamePane.SetVisible()
			return g_pPreGamePane
	else:
		g_pPreGamePane = App.TGPane_Create(1.0, 1.0)

	# Get LCARS string.
	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()

	# Find the Multiplayer window
	g_pMultiplayerPane = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	# Initialize events for the multiplayer window.
	AddEventHandlers(g_pMultiplayerPane)

	#Load localization database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")

	########################################################
	# build the eye candy
	############################################################
	pEyeCandy = BuildEyeCandyPane(pDatabase)
	g_pPreGamePane.AddChild(pEyeCandy)

	########################################################
	# build the client, host, and mission panes
	############################################################
	BuildClientPane(g_pMultiplayerPane, pDatabase)
	g_pPreGamePane.AddChild(g_pClientPane, SUB_PANE_X_POS, SUB_PANE_Y_POS)
	BuildHostPane(g_pMultiplayerPane, pDatabase)
	g_pHostPane.SetNotVisible() # Default to the client pane; that one will be used more often
	g_pPreGamePane.AddChild(g_pHostPane, SUB_PANE_X_POS, SUB_PANE_Y_POS)
	global g_pMissionPane
	g_pMissionPane = App.TGPane_Create(SUB_PANE_WIDTH, SUB_PANE_HEIGHT)
	g_pMissionPane.SetNotVisible() # Hide it 'til we need it
	g_pPreGamePane.AddChild(g_pMissionPane, SUB_PANE_X_POS, SUB_PANE_Y_POS)

	########################################################
	# build the upper buttons
	############################################################
	BuildTopButtons(g_pPreGamePane, pDatabase)

	# select the client button by default.
	g_pHostButton.SetNotSelected ()
	g_pClientButton.SetSelected ()
	
	# Unload localization database
	App.g_kLocalizationManager.Unload(pDatabase)

	# Create a black background so that the main menu won't be visible behind us
	# Set it to handle mouse events so that the now-hidden buttons behind it
	# won't get clicked
	pBGIcon = App.TGIcon_Create(pcLCARS, 200)
	pBGIcon.SetColor(App.NiColorA_BLACK)
	pBGIcon.Resize(g_pMultiplayerPane.GetWidth(), g_pMultiplayerPane.GetHeight())
	pBGIcon.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".HandleMouseEventsForGlass")
	g_pPreGamePane.AddChild(pBGIcon)
	
	# If we're already in the game, we must rebuild the mission-specific UI
	if App.g_kUtopiaModule.IsMultiplayer() and bForceDoItAgain:
		pGame = App.Game_GetCurrentGame ()
		if (pGame):
			import MissionMenusShared

			# Find the Multiplayer window
			pTopWindow = App.TopWindow_GetTopWindow()
			pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

			sName = App.g_kVarManager.GetStringVariable("Multiplayer", "Mission")
			pModule = __import__(sName + "Menus")
			pModule.__dict__["BuildMission" + sName[-1] + "Menus"](1)

			MissionMenusShared.PostRebuildAfterResChange ()

			# Allow the Options Window to come up
	#		App.TopWindow_GetTopWindow().AllowShowOptionsWindow(1)

			# Get the mission pane and hide it.
			pMissionPane = pMultWindow.GetMissionPane()
			if (pMissionPane):
				if (not bMissionPaneVisible):
					pMissionPane.SetNotVisible()

			# Allow the ship selection screen to come up upon player's death
			import MissionLib
			pPlayer = MissionLib.GetPlayer()
			App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_DELETE_OBJECT_PUBLIC, pMissionPane, "Multiplayer.MissionMenusShared.ObjectDestroyedHandler", pPlayer)

			# If the chat window is visible, toggle it off
			#if pMultWindow.IsChatWindowActive():
#			if (bChatActive):
#				pMultWindow.ToggleChatWindow()

			# If we're dedicated server, bring up the options window
			if App.g_kUtopiaModule.IsHost() and (not App.g_kUtopiaModule.IsClient()):
				# Bring up options again.
				# Find the multiplayer window
				pTopWindow = App.TopWindow_GetTopWindow()
				pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

				# Hide all panes, make MultiplayerPane visible.
				pMultWindow.HideAllChildren()


			pModule.RebuildPlayerList()
			pModule.UpdateStartButton()

			g_pClientButton.SetDisabled(0)
			g_pHostButton.SetDisabled(0)
			g_pExitButton.SetEnabled(1)

			# Move the multiplayer window to the back
#			if (bChatActive):
#				pTopWindow.MoveToBack(pMultWindow, 0)


	g_bPreGameUIBuilt = 1
	
	g_pPreGamePane.SetVisible()
	g_pPreGamePane.Layout()
	
	return g_pPreGamePane

###############################################################################
#	BuildTopButtons()
#	
#	Build the buttons at the top of the screen
#	
#	Args:	TGPane*					pPane		- the window in which the
#												buttons go
#			TGLocalizationDatabase*	pDatabase	- the TGL containing our
#												strings
#	
#	Return:	None
###############################################################################
def BuildTopButtons(pPane, pDatabase):
	global g_pMultiplayerPane

	# Build a special pane to put the top buttons in so that they won't make
	# annoying noises on mouse over
	pTopButtonPane = App.TGPane_Create(pPane.GetWidth(), pPane.GetHeight())
	pTopButtonPane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,	__name__ + ".HandleKeyboardTopButtonArea")
	App.g_kFocusManager.AddObjectToTabOrder(pTopButtonPane)

	pPane.AddChild(pTopButtonPane, 0.0, 0.0, 0)
		
	# build the "host game" button
	global g_pHostButton
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(g_pMultiplayerPane)
	pEvent.SetEventType(ET_SHOW_HOST_UI)
	g_pHostButton = App.STRoundedButton_CreateW (pDatabase.GetString("Host Game"), pEvent, HOST_BUTTON_WIDTH, HOST_BUTTON_HEIGHT)
	g_pHostButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pHostButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pHostButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pHostButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pHostButton.SetColorBasedOnFlags()
	pTopButtonPane.AddChild(g_pHostButton, HOST_BUTTON_X_POS, HOST_BUTTON_Y_POS)

	# build the "join game" button
	global g_pClientButton
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(g_pMultiplayerPane)
	pEvent.SetEventType(ET_SHOW_CLIENT_UI)
	g_pClientButton = App.STRoundedButton_CreateW (pDatabase.GetString("Join Game"), pEvent, JOIN_BUTTON_WIDTH, JOIN_BUTTON_HEIGHT)
	g_pClientButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pClientButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pClientButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pClientButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pClientButton.SetColorBasedOnFlags()
	pTopButtonPane.AddChild(g_pClientButton, JOIN_BUTTON_X_POS, JOIN_BUTTON_Y_POS)

	# build the "exit multiplayer" button
	global g_pExitButton
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(g_pMultiplayerPane)
	pEvent.SetEventType(ET_EXIT_MULTIPLAYER)
	g_pExitButton = App.STRoundedButton_CreateW (pDatabase.GetString("Exit Multiplayer"), pEvent, EXIT_BUTTON_WIDTH, EXIT_BUTTON_HEIGHT)
	g_pExitButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pExitButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pExitButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pExitButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pExitButton.SetColorBasedOnFlags()
	g_pExitButton.SetDisabled() # Until a game has been started that can be exited
	pTopButtonPane.AddChild(g_pExitButton, EXIT_BUTTON_X_POS, EXIT_BUTTON_Y_POS)

	# build the "main menu" button
	global g_pMainMenuButton
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(g_pMultiplayerPane)
	pEvent.SetEventType(ET_RETURN_TO_MAIN_MENU)
	g_pMainMenuButton = App.STRoundedButton_CreateW (pDatabase.GetString("Main Menu"), pEvent, MAIN_MENU_BUTTON_WIDTH, MAIN_MENU_BUTTON_HEIGHT)
	g_pMainMenuButton.SetNormalColor(App.g_kMainMenuButtonColor)
	g_pMainMenuButton.SetHighlightedColor(App.g_kMainMenuButtonHighlightedColor)
	g_pMainMenuButton.SetSelectedColor(App.g_kMainMenuButtonSelectedColor)
	g_pMainMenuButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pMainMenuButton.SetColorBasedOnFlags()
	pTopButtonPane.AddChild(g_pMainMenuButton, MAIN_MENU_BUTTON_X_POS,
								MAIN_MENU_BUTTON_Y_POS)

	# Build gamespy logo
	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()
	pThing = App.TGIcon_Create(pcLCARS, 621)
	pTopButtonPane.AddChild (pThing, 0.5, 0.058, 0)

###############################################################################
#	CreateSortButton()
#	
#	Creates a button for sorting the server list by one of various possible
#	fields
#	
#	Args:	pName			- the name of the button
#			pDestination	- the destination for the event
#			pSortBy			- which field are we sorting by?
#			bStringField	- is this field a string field?
#			fWidth			- the width of the button
#			fHeight			- the height of the button
#	
#	Return:	the newly-created button
###############################################################################
def CreateSortButton(pName, pDestination, pSortBy, bStringField, fWidth = 0.0, fHeight = 0.0):
	pEvent = App.SortServerListEvent_Create()
	pEvent.SetEventType(App.ET_SORT_SERVER_LIST)
	pEvent.SetDestination(pDestination)
	pEvent.SetSortBy(pSortBy)
	pEvent.SetStringField(bStringField)

	if fWidth == 0.0 and fHeight == 0.0:
		pButton = App.STButton_CreateW(pName, pEvent)
	else:
		pButton = App.STButton_CreateW(pName, pEvent, 0, fWidth, fHeight)

	pButton.SetNormalColor(App.g_kMultiplayerDividerPurple)
	pButton.SetColorBasedOnFlags()
	pButton.SetJustification(App.STButton.CENTER)
	return pButton

###############################################################################
#	BuildServerMenu()
#	
#	Builds the menu for the client from which available servers can be selected
#	
#	Args:	
#			TGPane*					pPane		- the multiplayer window	
#			TGLocalizationDatabase*	pDatabase	- the TGL containing our
#												strings
#	
#	Return:	a TGPane* containing the menu
###############################################################################
def BuildServerMenu(pPane, pDatabase):
	# Get LCARS string.
	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()

	######
	# Build the buttons that are going to act as menu labels for each category.
	# Each button will also serve to sort the server menu by its category.
	# Create the game name button.
	######
	# Create the Name button
	pButton1 = CreateSortButton(pDatabase.GetString("Name"), pPane, "hostname", 1, CLIENT_NAMES_BUTTON_WIDTH, CLIENT_NAMES_BUTTON_HEIGHT)
	g_pClientPane.AddChild(pButton1,	CLIENT_NAMES_BUTTON_X_POS, CLIENT_NAMES_BUTTON_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(pButton1)
	
	# Create the game type button
	pButton2 = CreateSortButton(pDatabase.GetString("Type"), pPane, "mapname", 1, CLIENT_TYPE_BUTTON_WIDTH, CLIENT_TYPE_BUTTON_HEIGHT)
	g_pClientPane.AddChild(pButton2, CLIENT_TYPE_BUTTON_X_POS, CLIENT_TYPE_BUTTON_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(pButton2)

	# Create the ping button.
	pButton3 = CreateSortButton(pDatabase.GetString("Ping"), pPane, "ping", 0, CLIENT_PING_BUTTON_WIDTH, CLIENT_PING_BUTTON_HEIGHT)
	g_pClientPane.AddChild(pButton3, CLIENT_PING_BUTTON_X_POS, CLIENT_PING_BUTTON_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(pButton3)

	# Create the min/max players button.
	pButton4 = CreateSortButton(pDatabase.GetString("P/M"), pPane, "numplayers", 0, CLIENT_PLAYERS_BUTTON_WIDTH, CLIENT_PLAYERS_BUTTON_HEIGHT)
	g_pClientPane.AddChild(pButton4, CLIENT_PLAYERS_BUTTON_X_POS, CLIENT_PLAYERS_BUTTON_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(pButton4)

	######
	# Build the barriers that go between each listing in the menu
	######
	# Divider number 1 Foreground
	pDiv1 = App.TGIcon_Create(pcLCARS, 200)
	pDiv1.SetColor(App.g_kMultiplayerDividerPurple)
	pDiv1.Resize(	CLIENT_GAMES_MENU_DIV_BAR_THICKNESS,
					CLIENT_GAMES_MENU_DIV_BAR_HEIGHT, 0)
	g_pClientPane.AddChild(pDiv1,	CLIENT_GAMES_MENU_DIV_BAR_1_X_POS,
									CLIENT_GAMES_MENU_Y_POS)
					
	# Divider number 1 Background
	pBGDiv1 = App.TGIcon_Create(pcLCARS, 200)
	pBGDiv1.SetColor(App.NiColorA_BLACK)
	pBGDiv1.Resize(	CLIENT_GAMES_MENU_BG_DIV_BAR_THICKNESS,
					CLIENT_GAMES_MENU_DIV_BAR_HEIGHT, 0)
	g_pClientPane.AddChild(pBGDiv1,	CLIENT_GAMES_MENU_BG_DIV_BAR_1_X_POS,
									CLIENT_GAMES_MENU_Y_POS)
	
	# Divider number 2 Foreground
	pDiv2 = App.TGIcon_Create(pcLCARS, 200)
	pDiv2.SetColor(App.g_kMultiplayerDividerPurple)
	pDiv2.Resize(	CLIENT_GAMES_MENU_DIV_BAR_THICKNESS,
					CLIENT_GAMES_MENU_DIV_BAR_HEIGHT, 0)
	g_pClientPane.AddChild(pDiv2,	CLIENT_GAMES_MENU_DIV_BAR_2_X_POS,
									CLIENT_GAMES_MENU_Y_POS)
					
	# Divider number 2 Background
	pBGDiv2 = App.TGIcon_Create(pcLCARS, 200)
	pBGDiv2.SetColor(App.NiColorA_BLACK)
	pBGDiv2.Resize(	CLIENT_GAMES_MENU_BG_DIV_BAR_THICKNESS,
					CLIENT_GAMES_MENU_DIV_BAR_HEIGHT, 0)
	g_pClientPane.AddChild(pBGDiv2,	CLIENT_GAMES_MENU_BG_DIV_BAR_2_X_POS,
									CLIENT_GAMES_MENU_Y_POS)
	
	# Divider number 3 Foreground
	pDiv3 = App.TGIcon_Create(pcLCARS, 200)
	pDiv3.SetColor(App.g_kMultiplayerDividerPurple)
	pDiv3.Resize(	CLIENT_GAMES_MENU_DIV_BAR_THICKNESS,
					CLIENT_GAMES_MENU_DIV_BAR_HEIGHT, 0)
	g_pClientPane.AddChild(pDiv3,	CLIENT_GAMES_MENU_DIV_BAR_3_X_POS,
									CLIENT_GAMES_MENU_Y_POS)
					
	# Divider number 3 Background
	pBGDiv3 = App.TGIcon_Create(pcLCARS, 200)
	pBGDiv3.SetColor(App.NiColorA_BLACK)
	pBGDiv3.Resize(	CLIENT_GAMES_MENU_BG_DIV_BAR_THICKNESS,
					CLIENT_GAMES_MENU_DIV_BAR_HEIGHT, 0)
	g_pClientPane.AddChild(pBGDiv3,	CLIENT_GAMES_MENU_BG_DIV_BAR_3_X_POS,
									CLIENT_GAMES_MENU_Y_POS)
	
	######
	# Build the black header the goes behind the sort buttons.
	# Its purpose is to cover up menu items that scroll up behind it.
	# It handles events so that they won't reach any buttons that it's
	# covering up.
	######
	pHeader = App.TGIcon_Create(pcLCARS, 200)
	pHeader.SetColor(App.NiColorA_BLACK)
	pHeader.Resize(	CLIENT_GAMES_MENU_HEADER_COVER_WIDTH,
					CLIENT_GAMES_MENU_HEADER_COVER_HEIGHT, 0)
	pHeader.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".HandleMouseEventsForGlass")
	g_pClientPane.AddChild(pHeader,	CLIENT_GAMES_MENU_HEADER_COVER_X_POS,
									CLIENT_GAMES_MENU_HEADER_COVER_Y_POS)

	######
	# Create the stylized window inside of which our menu will go
	######
	global g_pClientGamesWindow
	g_pClientGamesWindow = App.STStylizedWindow_CreateW("StylizedWindow",
							"NoMinimize", pDatabase.GetString("All Games"),
							0.0, 0.0, None, 1, CLIENT_GAMES_MENU_WIDTH,
							CLIENT_GAMES_MENU_HEIGHT, App.g_kInterfaceBorderColor)
	g_pClientGamesWindow.SetTitleBarThickness(CLIENT_GAMES_MENU_BAR_THICKNESS)
	g_pClientPane.AddChild(g_pClientGamesWindow, CLIENT_GAMES_MENU_X_POS,
												 CLIENT_GAMES_MENU_Y_POS, 0)
	g_pClientGamesWindow.SetNotBatchChildPolys()
	
	App.g_kFocusManager.AddObjectToTabOrder(g_pClientGamesWindow)

	######
	# Okay, now we get to work on the menu itself. We need to create a
	# bunch of subpanes - one for each field in the menu.
	# We must position each sufficiently low that the header won't be blocking
	# any menu items when the user has scrolled all the way up.
	######
	
	# The Player's subpane is leftmost, but we have it as our last child
	# because we need it to Layout() first to add the button background icons
	# before the text (all other children are text only).

	# the ping subpane:
	global g_pClientGamesPingMenu
	g_pClientGamesPingMenu = App.STSubPane_Create(CLIENT_PING_BUTTON_WIDTH, 0.0, 0)
	g_pClientGamesWindow.AddChild(g_pClientGamesPingMenu,
			CLIENT_GAMES_PING_MENU_X_POS, CLIENT_GAMES_MENU_HEADER_COVER_HEIGHT, 0)

	# the type subpane:
	global g_pClientGamesTypeMenu
	g_pClientGamesTypeMenu = App.STSubPane_Create(CLIENT_TYPE_BUTTON_WIDTH, 0.0, 0)
	g_pClientGamesWindow.AddChild(g_pClientGamesTypeMenu,
			CLIENT_GAMES_TYPE_MENU_X_POS, CLIENT_GAMES_MENU_HEADER_COVER_HEIGHT, 0)

	# and finally, the name subpane:
	global g_pClientGamesNameMenu
	g_pClientGamesNameMenu = App.STSubPane_Create(CLIENT_NAMES_BUTTON_WIDTH, 0.0, 0)
	g_pClientGamesWindow.AddChild(g_pClientGamesNameMenu,
			CLIENT_GAMES_NAMES_MENU_X_POS, CLIENT_GAMES_MENU_HEADER_COVER_HEIGHT, 0)

	# the players subpane, added last for the reasons stated above
	global g_pClientGamesPlayersMenu
	g_pClientGamesPlayersMenu = App.STSubPane_Create(CLIENT_PLAYERS_BUTTON_WIDTH, 0.0, 0)
	g_pClientGamesWindow.AddChild(g_pClientGamesPlayersMenu,
			CLIENT_GAMES_PLAYERS_MENU_X_POS, CLIENT_GAMES_MENU_HEADER_COVER_HEIGHT)


###############################################################################
#	BuildClientPane()
#	
#	Builds the pane with the UI for the client
#	
#	Args:	TGPane*					pPane		- the multiplayer window	
#			TGLocalizationDatabase*	pDatabase	- the TGL containing our
#												strings
#	
#	Return:	a TGPane* containing the client UI
###############################################################################
def BuildClientPane(pPane, pDatabase):
	global g_pClientPane
	g_pClientPane = App.TGPane_Create(SUB_PANE_WIDTH, SUB_PANE_HEIGHT)

	# Get LCARS string.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	pcLCARS = App.GraphicsModeInfo_GetCurrentMode().GetLcarsString()
	
	############################################################
	# Create player name text entry
	############################################################
	global g_pClientNameInput
	pDefault = pDatabase.GetString("Default Name")
	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Player Name")):
		pDefault = App.g_kConfigMapping.GetTGStringValue ("Multiplayer Options", "Player Name")
	else:
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Player Name", pDefault)
	g_pClientNameInput = CreateRoundedTextEntry(pDefault, "Player Name", App.g_kTextEntryBackgroundColor,
								CLIENT_PLAYER_NAME_INPUT_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, 15)
	g_pClientPane.AddChild(g_pClientNameInput, CLIENT_PLAYER_NAME_INPUT_X_POS, CLIENT_PLAYER_NAME_INPUT_Y_POS)

	g_pClientPlayerNameCaption = App.TGParagraph_CreateW(pDatabase.GetString("Player Name"))
	fPosDelta = (g_pClientPlayerNameCaption.GetHeight() - g_pClientNameInput.GetHeight()) / 2.0
	g_pClientPane.AddChild(g_pClientPlayerNameCaption, CLIENT_PLAYER_NAME_PARA_X_POS, CLIENT_PLAYER_NAME_INPUT_Y_POS - fPosDelta)

	App.g_kFocusManager.AddObjectToTabOrder(g_pClientNameInput)
	############################################################
	# Create password text entry
	############################################################
	global g_pClientPasswordInput
	pDefault = App.TGString("")

	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Password")):
		pDefault = App.g_kConfigMapping.GetTGStringValue("Multiplayer Options", "Password")
	g_pClientPasswordInput = CreateRoundedTextEntry(pDefault, "Password", App.g_kTextEntryBackgroundColor,
								CLIENT_PASSWORD_INPUT_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, 15)
	g_pClientPane.AddChild(g_pClientPasswordInput, CLIENT_PASSWORD_INPUT_X_POS, CLIENT_PASSWORD_INPUT_Y_POS)

	pPasswordCaption = App.TGParagraph_CreateW(pDatabase.GetString("Password"))
	fPosDelta = (pPasswordCaption.GetHeight() - g_pClientPasswordInput.GetHeight()) / 2.0
	g_pClientPane.AddChild(pPasswordCaption, CLIENT_PASSWORD_PARA_X_POS, CLIENT_PASSWORD_INPUT_Y_POS - fPosDelta)
	
	App.g_kFocusManager.AddObjectToTabOrder(g_pClientPasswordInput)
	############################################################
	# Create Direct Join button and text entry
	############################################################
	global g_pClientDirectButton
	global g_pClientDirectInput
	
	g_pClientDirectButton = CreateButton(pDatabase.GetString("Direct Join"),
			ET_TOGGLE_DIRECT_JOIN, pPane, 1, CLIENT_DIRECT_JOIN_BUTTON_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT)
	g_pClientDirectButton.SetChoosable(1)
	g_pClientDirectButton.SetChosen(0)
	g_pClientDirectButton.SetNormalColor(App.g_kTextEntryColor)
	g_pClientDirectButton.SetSelectedColor(App.g_kMultiplayerBorderBlue)
	g_pClientDirectButton.SetHighlightedColor(App.g_kMultiplayerBorderBlue)
	g_pClientDirectButton.SetColorBasedOnFlags()
	g_pClientPane.AddChild(g_pClientDirectButton, CLIENT_DIRECT_JOIN_BUTTON_X_POS,
													CLIENT_DIRECT_JOIN_BUTTON_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pClientDirectButton)

	pDefault = App.TGString("")
	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Direct Join Address")):
		pDefault = App.g_kConfigMapping.GetTGStringValue("Multiplayer Options", "Direct Join Address")
	else:
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Direct Join Address", pDefault)
	g_pClientDirectInput = CreateRoundedTextEntry(pDefault, "Direct Join Address",
		App.g_kTextEntryBackgroundColor, CLIENT_DIRECT_JOIN_INPUT_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, 60)
	g_pClientPane.AddChild(g_pClientDirectInput, CLIENT_DIRECT_JOIN_INPUT_X_POS,
													CLIENT_DIRECT_JOIN_INPUT_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pClientDirectInput)

	############################################################
	# Create Internet/LAN toggle
	############################################################
	global g_pClientInternetButton
	global g_pClientLanButton
	bInternet = 1
	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Internet Host")):
		bInternet = App.g_kConfigMapping.GetIntValue ("Multiplayer Options", "Internet Host")
	else:
		App.g_kConfigMapping.SetIntValue("Multiplayer Options", "Internet Host", bInternet)
	g_pClientInternetButton = CreateButton(pDatabase.GetString("Internet"),
			App.ET_LOCAL_INTERNET_HOST, pPane, 1, CLIENT_INTERNET_BUTTON_WIDTH,
			CLIENT_INTERNET_BUTTON_HEIGHT)
	g_pClientInternetButton.SetChoosable(1)
	g_pClientInternetButton.SetChosen(bInternet)
	g_pClientPane.AddChild(g_pClientInternetButton, CLIENT_INTERNET_BUTTON_X_POS,
												 CLIENT_INTERNET_BUTTON_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pClientInternetButton)

	g_pClientLanButton = CreateButton(pDatabase.GetString("LAN"),
			App.ET_LOCAL_INTERNET_HOST, pPane, 0, CLIENT_LAN_BUTTON_WIDTH,
			CLIENT_LAN_BUTTON_HEIGHT)
	g_pClientLanButton.SetChoosable(1)
	g_pClientLanButton.SetChosen(not bInternet)
	g_pClientPane.AddChild(g_pClientLanButton, CLIENT_LAN_BUTTON_X_POS,
										   CLIENT_LAN_BUTTON_Y_POS)
	App.g_kFocusManager.AddObjectToTabOrder(g_pClientLanButton)

	# Use determine instead of IsModemConnection, since IsModemConnection requires
	# that the network be initialized to be accurate.
	bModem = App.g_kUtopiaModule.DetermineModemConnection ()
	if (bModem):
		g_pClientLanButton.SetDisabled ()


	############################################################
	# Create refresh list buttons
	############################################################
	# Start Query button
	global g_pClientStartQueryButton
	g_pClientStartQueryButton = CreateBoolButton(pDatabase.GetString("Start Query"),
			App.ET_REFRESH_SERVER_LIST, pPane, 0, CLIENT_START_QUERY_BUTTON_WIDTH,
			CLIENT_START_QUERY_BUTTON_HEIGHT)
	g_pClientStartQueryButton.SetNormalColor(App.g_kTextEntryColor)
	g_pClientStartQueryButton.SetSelectedColor(App.g_kMultiplayerBorderBlue)
	g_pClientStartQueryButton.SetHighlightedColor(App.g_kMultiplayerBorderBlue)
	g_pClientStartQueryButton.SetTextColor(App.g_kSTMenuTextHighlightColor)
	g_pClientStartQueryButton.SetColorBasedOnFlags()
	g_pClientPane.AddChild(g_pClientStartQueryButton, CLIENT_START_QUERY_BUTTON_X_POS,
												 CLIENT_START_QUERY_BUTTON_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pClientStartQueryButton)

	# Stop query button
	global g_pClientStopQueryButton
	g_pClientStopQueryButton = CreateBoolButton(pDatabase.GetString("Stop Query"),
			App.ET_REFRESH_SERVER_LIST, pPane, 1, CLIENT_STOP_QUERY_BUTTON_WIDTH,
			CLIENT_STOP_QUERY_BUTTON_HEIGHT)
	g_pClientStopQueryButton.SetNormalColor(App.g_kTextEntryColor)
	g_pClientStopQueryButton.SetSelectedColor(App.g_kMultiplayerBorderBlue)
	g_pClientStopQueryButton.SetHighlightedColor(App.g_kMultiplayerBorderBlue)
	g_pClientStopQueryButton.SetTextColor(App.g_kSTMenuTextHighlightColor)
	g_pClientStopQueryButton.SetColorBasedOnFlags()
	g_pClientStopQueryButton.SetDisabled() # You can't stop a query 'til it starts
	g_pClientPane.AddChild(g_pClientStopQueryButton, CLIENT_STOP_QUERY_BUTTON_X_POS,
										   CLIENT_STOP_QUERY_BUTTON_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pClientStopQueryButton)

	############################################################
	# Create the server menu
	############################################################
	# We cover it with invisible glass, to be made visible when Direct Join
	# is enabled
	global g_pClientGlass
	g_pClientGlass = App.TGIcon_Create(pcLCARS, 120)
	g_pClientGlass.Resize(CLIENT_GLASS_WIDTH, CLIENT_GLASS_HEIGHT)
	g_pClientGlass.SetNotVisible()
	g_pClientGlass.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".HandleMouseEventsForGlass")
	g_pClientPane.AddChild(g_pClientGlass, CLIENT_GLASS_X_POS, CLIENT_GLASS_Y_POS)

	global g_pClientGlass2
	g_pClientGlass2 = App.TGIcon_Create(pcLCARS, 120)
	g_pClientGlass2.Resize(CLIENT_COMPLETION_BUTTON_WIDTH, CLIENT_COMPLETION_BUTTON_HEIGHT)
	g_pClientGlass2.SetNotVisible()
	g_pClientGlass2.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".HandleMouseEventsForGlass")
	g_pClientPane.AddChild(g_pClientGlass2, CLIENT_COMPLETION_BUTTON_X_POS, CLIENT_COMPLETION_BUTTON_Y_POS)

	BuildServerMenu(pPane, pDatabase)

	############################################################
	# Create the player list
	############################################################
	global g_pClientPlayersMenu

	# First off, a subpane that will actually store the list of players
	g_pClientPlayersMenu = App.STSubPane_Create(CLIENT_PLAYERS_LIST_WIDTH, 0.0)

	# Then a nice stylized window to stick it in
	global g_pClientPlayersWindow
	g_pClientPlayersWindow = App.STStylizedWindow_CreateW("StylizedWindow",
							"NoMinimize", pDatabase.GetString("Players"),
							0.0, 0.0, None, 1, CLIENT_PLAYERS_LIST_WIDTH,
							CLIENT_PLAYERS_LIST_HEIGHT, App.g_kInterfaceBorderColor)
	g_pClientPlayersWindow.SetTitleBarThickness(CLIENT_PLAYERS_LIST_BAR_THICKNESS)
	g_pClientPlayersWindow.AddChild(g_pClientPlayersMenu)
	g_pClientPlayersWindow.InteriorChangedSize ()
	g_pClientPane.AddChild(g_pClientPlayersWindow, CLIENT_PLAYERS_LIST_X_POS,
										   CLIENT_PLAYERS_LIST_Y_POS)

	############################################################
	# Create game info window
	############################################################
	# Set the font small
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	global g_pClientGameInfoPara
	# First off, a paragraph that will actually store the list of players
	g_pClientGameInfoPara = App.TGParagraph_Create("", CLIENT_INFO_WINDOW_WIDTH - 0.0125,
							None, "", 0.0,	App.TGParagraph.TGPF_WORD_WRAP |
											App.TGParagraph.TGPF_READ_ONLY)

	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Then a nice stylized window to stick it in
	global g_pClientGameInfoWindow
	g_pClientGameInfoWindow = App.STStylizedWindow_CreateW("StylizedWindow",
							"NoMinimize", pDatabase.GetString("Game Info"),
							0.0, 0.0, None, 1, CLIENT_INFO_WINDOW_WIDTH,
							CLIENT_INFO_WINDOW_HEIGHT, App.g_kInterfaceBorderColor)
	g_pClientGameInfoWindow.SetTitleBarThickness(CLIENT_INFO_WINDOW_BAR_THICKNESS)
	g_pClientGameInfoWindow.AddChild(g_pClientGameInfoPara)
	g_pClientGameInfoWindow.InteriorChangedSize ()
	g_pClientPane.AddChild(g_pClientGameInfoWindow, CLIENT_INFO_WINDOW_X_POS,
										   CLIENT_INFO_WINDOW_Y_POS)


	############################################################
	# Create completion area
	############################################################
	global g_pClientCompletionText
	global g_pClientCompletionNumber
	global g_pClientCompletionIcon
	
	# Create the pane in which the text string describing the current state of
	# the connection attempt will go. This pane will also fill up with a progress
	# bar behind the text, which will graphically complement the percentage
	# complete information that is also displayed numercially
	pCompletionPane = App.TGPane_Create(CLIENT_COMPLETION_BAR_WIDTH,
										CLIENT_COMPLETION_BAR_HEIGHT)
	# Set the font small
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	g_pClientCompletionText = App.TGParagraph_Create()

	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	pCompletionPane.AddChild(g_pClientCompletionText)

	# Add the progress-bar icon
	g_pClientCompletionIcon = App.TGIcon_Create(pcLCARS, 200)
	g_pClientCompletionIcon.SetColor(App.g_kMainMenuButtonColor)
	g_pClientCompletionIcon.Resize(0.0, pCompletionPane.GetHeight(), 0)
	pCompletionPane.AddChild(g_pClientCompletionIcon)
	
	# Give the pane a black background
	pBGIcon = App.TGIcon_Create(pcLCARS, 200)
	pBGIcon.SetColor(App.NiColorA_BLACK)
	pBGIcon.Resize(pCompletionPane.GetWidth(), pCompletionPane.GetHeight(), 0)
	pCompletionPane.AddChild(pBGIcon)
	
	g_pClientPane.AddChild(pCompletionPane,	CLIENT_COMPLETION_BAR_X_POS,
											CLIENT_COMPLETION_BAR_Y_POS)

	# Add the percentage complete paragraph
	g_pClientCompletionNumber = App.TGParagraph_Create("")
	fPosDelta = (g_pClientCompletionNumber.GetHeight() - pCompletionPane.GetHeight()) / 2.0
	g_pClientPane.AddChild(g_pClientCompletionNumber, CLIENT_COMPLETION_NUMBER_X_POS,
													  CLIENT_COMPLETION_BAR_Y_POS - fPosDelta)

	# Add the caption
	pCompletionCaption = App.TGParagraph_CreateW(pDatabase.GetString("Completion"))
	fPosDelta = (pCompletionCaption.GetHeight() - pCompletionPane.GetHeight()) / 2.0
	g_pClientPane.AddChild(pCompletionCaption, CLIENT_COMPLETION_PARA_X_POS,
													  CLIENT_COMPLETION_BAR_Y_POS - fPosDelta)

	# We create a button for use only as an eye-candy background to put behind
	# the actual useful UI stuff
	pCompletionButton = App.STRoundedButton_Create("", None,
				CLIENT_COMPLETION_BUTTON_WIDTH, CLIENT_COMPLETION_BUTTON_HEIGHT)
	pCompletionButton.SetDisabledColor(App.g_kTextEntryColor)
	pCompletionButton.SetDisabled()
	g_pClientPane.AddChild(pCompletionButton,	CLIENT_COMPLETION_BUTTON_X_POS,
												CLIENT_COMPLETION_BUTTON_Y_POS)

	############################################################
	# Create Start button
	############################################################
	global g_pClientStartButton
	g_pClientStartButton = CreateButton(pDatabase.GetString("Start"), ET_CLIENT_START_BUTTON_CLICKED,
					 pPane, 0, CLIENT_START_BUTTON_WIDTH, CLIENT_START_BUTTON_HEIGHT)
	g_pClientStartButton.SetNormalColor(App.g_kMainMenuButton3Color)
	g_pClientStartButton.SetHighlightedColor(App.g_kMainMenuButton3HighlightedColor)
	g_pClientStartButton.SetSelectedColor(App.g_kMainMenuButton3SelectedColor)
	g_pClientStartButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pClientStartButton.SetHighlightedTextColor(App.g_kMultiplayerBorderBlue)
	g_pClientStartButton.SetColorBasedOnFlags()
	g_pClientStartButton.SetDisabled()
	g_pClientPane.AddChild(g_pClientStartButton, CLIENT_START_BUTTON_X_POS,
								CLIENT_START_BUTTON_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pClientStartButton)

	return g_pClientPane

###############################################################################
#	BuildHostPane()
#	
#	Builds the pane with the UI for the host
#	
#	Args:	TGPane*					pPane		- the multiplayer window	
#			TGLocalizationDatabase*	pDatabase	- the TGL containing our
#	
#	Return:	a TGPane* containing the host UI
###############################################################################
def BuildHostPane(pPane, pDatabase):
	global g_pHostPane
	g_pHostPane = App.TGPane_Create(SUB_PANE_WIDTH, SUB_PANE_HEIGHT)
	
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	############################################################
	# Create player name text entry
	############################################################
	global g_pHostPlayerNameInput
	global g_pHostPlayerNameCaption
	pDefault = pDatabase.GetString("Default Name")
	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Player Name")):
		pDefault = App.g_kConfigMapping.GetTGStringValue ("Multiplayer Options", "Player Name")
	else:
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Player Name", pDefault)
#	g_pHostPlayerNameInput = CreateRoundedTextEntry(pDefault, "Player Name", App.g_kTextEntryBackgroundColor,
	g_pHostPlayerNameInput = CreateRoundedTextEntry(pDefault, "Cancel", App.g_kTextEntryBackgroundColor,
								HOST_PLAYER_NAME_INPUT_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, 15)
	g_pHostPane.AddChild(g_pHostPlayerNameInput, HOST_PLAYER_NAME_INPUT_X_POS, HOST_PLAYER_NAME_INPUT_Y_POS)

	g_pHostPlayerNameCaption = App.TGParagraph_CreateW(pDatabase.GetString("Player Name"))
	fPosDelta = (g_pHostPlayerNameCaption.GetHeight() - g_pHostPlayerNameInput.GetHeight()) / 2.0
	g_pHostPane.AddChild(g_pHostPlayerNameCaption, HOST_PLAYER_NAME_PARA_X_POS, HOST_PLAYER_NAME_INPUT_Y_POS - fPosDelta)

	App.g_kFocusManager.AddObjectToTabOrder(g_pHostPlayerNameInput)

	############################################################
	# Create game name text entry
	############################################################
	global g_pHostGameNameInput
	pDefault = pDatabase.GetString("My Game")
	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Game Name")):
		pDefault = App.g_kConfigMapping.GetTGStringValue ("Multiplayer Options", "Game Name")
	else:
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Game Name", pDefault)
	g_pHostGameNameInput = CreateRoundedTextEntry(pDefault, "Game Name", App.g_kTextEntryBackgroundColor,
								HOST_GAME_NAME_INPUT_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, 30)
	g_pHostPane.AddChild(g_pHostGameNameInput, HOST_GAME_NAME_INPUT_X_POS, HOST_GAME_NAME_INPUT_Y_POS)

	pGameNameCaption = App.TGParagraph_CreateW(pDatabase.GetString("Game Name"))
	fPosDelta = (pGameNameCaption.GetHeight() - g_pHostGameNameInput.GetHeight()) / 2.0
	g_pHostPane.AddChild(pGameNameCaption, HOST_GAME_NAME_PARA_X_POS, HOST_GAME_NAME_INPUT_Y_POS - fPosDelta)

	App.g_kFocusManager.AddObjectToTabOrder(g_pHostGameNameInput)

	############################################################
	# Create password text entry
	############################################################
	global g_pHostPasswordInput
	pDefault = App.TGString("")
	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Password")):
		pDefault = App.g_kConfigMapping.GetTGStringValue("Multiplayer Options", "Password")
	g_pHostPasswordInput = CreateRoundedTextEntry(pDefault, "Password", App.g_kTextEntryBackgroundColor,
								HOST_PASSWORD_INPUT_WIDTH, LCARS.MAIN_MENU_TOP_BUTTON_HEIGHT, 15)
	g_pHostPane.AddChild(g_pHostPasswordInput, HOST_PASSWORD_INPUT_X_POS, HOST_PASSWORD_INPUT_Y_POS)

	pPasswordCaption = App.TGParagraph_CreateW(pDatabase.GetString("Password"))
	fPosDelta = (pPasswordCaption.GetHeight() - g_pHostPasswordInput.GetHeight()) / 2.0
	g_pHostPane.AddChild(pPasswordCaption, HOST_PASSWORD_PARA_X_POS, HOST_PASSWORD_INPUT_Y_POS - fPosDelta)
	
	App.g_kFocusManager.AddObjectToTabOrder(g_pHostPasswordInput)

	############################################################
	# Create Internet/LAN toggle
	############################################################
	global g_pHostInternetButton
	global g_pHostLanButton
	bInternet = 1
	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Internet Host")):
		bInternet = App.g_kConfigMapping.GetIntValue ("Multiplayer Options", "Internet Host")
	else:
		App.g_kConfigMapping.SetIntValue("Multiplayer Options", "Internet Host", bInternet)
	g_pHostInternetButton = CreateButton(pDatabase.GetString("Internet"),
			App.ET_LOCAL_INTERNET_HOST, pPane, 1, HOST_INTERNET_BUTTON_WIDTH,
			HOST_INTERNET_BUTTON_HEIGHT)
	g_pHostInternetButton.SetChoosable(1)
	g_pHostInternetButton.SetChosen(bInternet)
	g_pHostPane.AddChild(g_pHostInternetButton, HOST_INTERNET_BUTTON_X_POS,
												 HOST_INTERNET_BUTTON_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pHostInternetButton)

	g_pHostLanButton = CreateButton(pDatabase.GetString("LAN"),
			App.ET_LOCAL_INTERNET_HOST, pPane, 0, HOST_LAN_BUTTON_WIDTH,
			HOST_LAN_BUTTON_HEIGHT)
	g_pHostLanButton.SetChoosable(1)
	g_pHostLanButton.SetChosen(not bInternet)
	g_pHostPane.AddChild(g_pHostLanButton, HOST_LAN_BUTTON_X_POS,
										   HOST_LAN_BUTTON_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pHostLanButton)

	# Use determine instead of IsModemConnection, since IsModemConnection requires
	# that the network be initialized to be accurate.
	bModem = App.g_kUtopiaModule.DetermineModemConnection ()
	if (bModem):
		g_pHostLanButton.SetDisabled ()

	############################################################
	# Create dedicated server toggle
	############################################################
	global g_pHostDedicatedButton
	bDefault = 0
	if (App.g_kConfigMapping.HasValue("Multiplayer Options", "Dedicated Server")):
		bDefault = App.g_kConfigMapping.GetIntValue ("Multiplayer Options", "Dedicated Server")
	else:
		App.g_kConfigMapping.SetIntValue("Multiplayer Options", "Dedicated Server", bDefault)
	g_pHostDedicatedButton = CreateButton(pDatabase.GetString("Dedicated Server"),
			ET_DEDICATED_CLICKED, pPane, 0, HOST_DEDICATED_BUTTON_WIDTH,
			HOST_DEDICATED_BUTTON_HEIGHT)
	g_pHostDedicatedButton.SetChoosable(1)
	g_pHostDedicatedButton.SetChosen(bDefault)
	g_pHostDedicatedButton.SetNormalColor(App.g_kTextEntryColor)
	g_pHostDedicatedButton.SetSelectedColor(App.g_kMultiplayerBorderBlue)
	g_pHostDedicatedButton.SetHighlightedColor(App.g_kMultiplayerBorderBlue)
	g_pHostDedicatedButton.SetColorBasedOnFlags()
	g_pHostPane.AddChild(g_pHostDedicatedButton, HOST_DEDICATED_BUTTON_X_POS,
												 HOST_DEDICATED_BUTTON_Y_POS)

	App.g_kFocusManager.AddObjectToTabOrder(g_pHostDedicatedButton)

	# If we're a dedicated server, we don't have a player, and we therefore also don't have
	# a player name...
	if bDefault:
		g_pHostPlayerNameInput.SetNotVisible()
		g_pHostPlayerNameCaption.SetNotVisible()

	############################################################
	# Create menu for selecting game.  We do this from code
	# 'cause we don't want to expose file access to the scripts.
	############################################################
	global g_pHostGamesMenu
	pMissionMenu = App.STSubPane_Create (HOST_GAME_MENU_WIDTH, HOST_GAME_MENU_HEIGHT)
	g_pHostGamesMenu = App.STStylizedWindow_CreateW("StylizedWindow",
							"NoMinimize", pDatabase.GetString("Game"),
							0.0, 0.0, pMissionMenu, 1, HOST_GAME_MENU_WIDTH,
							HOST_GAME_MENU_HEIGHT, App.g_kInterfaceBorderColor)
	App.MultiplayerWindow_Cast(pPane).BuildMissionMenu(g_pHostGamesMenu)
	g_pHostGamesMenu.SetTitleBarThickness(HOST_GAME_MENU_BAR_THICKNESS)
	pMenu = App.STSubPane_Cast (g_pHostGamesMenu.GetInteriorPane ())
	pMenu.ResizeToContents ()
	g_pHostGamesMenu.InteriorChangedSize()
	g_pHostGamesMenu.ScrollToTop()
	g_pHostPane.AddChild(g_pHostGamesMenu, HOST_GAME_MENU_X_POS, HOST_GAME_MENU_Y_POS)
	
	App.g_kFocusManager.AddObjectToTabOrder(pMissionMenu)

	############################################################
	# Create Mission Paragraph
	############################################################
	global g_pHostTextArea
	# Set the font small
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	g_pHostTextArea = App.TGParagraph_Create("blah", HOST_TEXT_AREA_WIDTH, None,
											"", 0.0, App.TGParagraph.TGPF_WORD_WRAP |
												App.TGParagraph.TGPF_READ_ONLY)
	g_pHostPane.AddChild(g_pHostTextArea, HOST_TEXT_AREA_X_POS, HOST_TEXT_AREA_Y_POS)

	# Set default mission and description
	pcString = App.g_kVarManager.GetStringVariable("Multiplayer", "Mission")

	# update mission description
	pModule = __import__(pcString + "Name")
	pDesc = pModule.GetMissionDescription ()
	g_pHostTextArea.SetStringW(pDesc)
	
	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	############################################################
	# Create Start button
	############################################################
	global g_pHostStartButton
	g_pHostStartButton = CreateButton(pDatabase.GetString("Start"), ET_HOST_START_BUTTON_CLICKED,
				pPane, 0, HOST_START_BUTTON_WIDTH, HOST_START_BUTTON_HEIGHT)
	g_pHostStartButton.SetNormalColor(App.g_kMainMenuButton3Color)
	g_pHostStartButton.SetHighlightedColor(App.g_kMainMenuButton3HighlightedColor)
	g_pHostStartButton.SetSelectedColor(App.g_kMainMenuButton3SelectedColor)
	g_pHostStartButton.SetDisabledColor(App.g_kSTMenu1Disabled)
	g_pHostStartButton.SetHighlightedTextColor(App.g_kMultiplayerBorderBlue)
	g_pHostStartButton.SetColorBasedOnFlags()
	g_pHostPane.AddChild(g_pHostStartButton, HOST_START_BUTTON_X_POS,
								HOST_START_BUTTON_Y_POS)
	
	App.g_kFocusManager.AddObjectToTabOrder(g_pHostStartButton)

	return g_pHostPane


###############################################################################
#	BuildEyeCandyPane()
#	
#	Builds the eye candy pane and puts eye candy in it
#	
#	Args:	TGLocalizationDatabase*	pDatabase	- the TGL containing our
#												strings
#	
#	Return:	a TGPane* containing eye candy
###############################################################################
def BuildEyeCandyPane(pDatabase):
	kSizes =  [6, 9, 9, 12, 15]
	pMode = App.GraphicsModeInfo_GetCurrentMode()

	pEyeCandyPane = App.TGPane_Create(1.0, 1.0)
	
	
	# Set the font small
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	global g_pJunkText5
	global g_pJunkText6
	global g_pJunkText7


	# Create the little "190" that's in the bottom lower-left curve
	p190 = App.TGParagraph_Create("190", 1.0, App.g_kSTMenuTextColor, "LCARSText", kSizes[pMode.GetCurrentResolution()])
	p190.RecalcBounds()
	pEyeCandyPane.AddChild(p190, NUMBER_190_X_POS, NUMBER_190_Y_POS + (p190.GetHeight() * 0.25))
	g_pJunkText5 = p190	
	
	# Create the little "3945" that's in the upper lower-right curve
	p3945 = App.TGParagraph_Create("3945", 1.0, App.g_kSTMenuTextColor, "LCARSText", kSizes[pMode.GetCurrentResolution()])
	p3945.RecalcBounds()
	pEyeCandyPane.AddChild(p3945, NUMBER_3945_X_POS, NUMBER_3945_Y_POS + (p3945.GetHeight() * 0.25))
	g_pJunkText6 = p3945

	# Create the little "468 04" that's in the lower right bar
	p46804 = App.TGParagraph_Create("468 04", 1.0, App.g_kSTMenuTextColor, "LCARSText", kSizes[pMode.GetCurrentResolution()])
	p46804.RecalcBounds()
	pEyeCandyPane.AddChild(p46804, NUMBER_46804_X_POS, NUMBER_46804_Y_POS - (p46804.GetHeight() * 0.25))
	g_pJunkText7 = p46804

	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes] + 1)

	# Create the title
	pTitle = App.TGParagraph_CreateW(pDatabase.GetString("Multiplayer"), 1.0, App.globals.g_kTitleColor)
	fPosDelta = (pTitle.GetHeight() - TITLE_BAR_HEIGHT) / 2.0
	pEyeCandyPane.AddChild(pTitle, TITLE_X_POS, TITLE_BAR_Y_POS - fPosDelta)
	
	# Create the subtitle
	global g_pSubtitle
	g_pSubtitle = App.TGParagraph_CreateW(pDatabase.GetString("Join Game"), 1.0, App.globals.g_kTitleColor)
	fPosDelta = (g_pSubtitle.GetHeight() - SUBTITLE_BAR_HEIGHT) / 2.0
	pEyeCandyPane.AddChild(g_pSubtitle, SUBTITLE_X_POS, SUBTITLE_BAR_Y_POS - fPosDelta)

	# Set the font smaller but still large
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create the top left bar
	pTopLeftBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kInterfaceBorderColor)
	pTopLeftBar.Resize(TOP_LEFT_BAR_WIDTH, TOP_LEFT_BAR_HEIGHT)
	pEyeCandyPane.AddChild(pTopLeftBar, TOP_LEFT_BAR_X_POS, TOP_LEFT_BAR_Y_POS)  

	# Create the title bar
	fTitleBarXPos = TITLE_X_POS + pTitle.GetWidth() + TITLE_BAR_X_DISTANCE
	fTitleBarWidth = TITLE_BAR_RIGHT_EDGE - fTitleBarXPos
	pTitleBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kInterfaceBorderColor)
	pTitleBar.Resize(fTitleBarWidth, TITLE_BAR_HEIGHT)
	pEyeCandyPane.AddChild(pTitleBar, fTitleBarXPos, TITLE_BAR_Y_POS)  

	# Create the top lower-left curve
	import UIHelpers
	pTopLLCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_LEFT_CURVE,
										TOP_LOWER_LEFT_CURVE_IN_WIDTH,
										TOP_LOWER_LEFT_CURVE_WIDTH,
										TOP_LOWER_LEFT_CURVE_IN_HEIGHT,
										TOP_LOWER_LEFT_CURVE_HEIGHT,
										App.globals.g_kMultiplayerBorderBlue,
										TOP_LOWER_LEFT_CURVE_OI_WIDTH)
	pEyeCandyPane.AddChild(pTopLLCurve, TOP_LOWER_LEFT_CURVE_X_POS,
										TOP_LOWER_LEFT_CURVE_Y_POS)
	
	# Create the top lower bar
	pTopLowerBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pTopLowerBar.Resize(TOP_LOWER_BAR_WIDTH, TOP_LOWER_BAR_HEIGHT)
	pEyeCandyPane.AddChild(pTopLowerBar, TOP_LOWER_BAR_X_POS, TOP_LOWER_BAR_Y_POS)  
	
	# Create the top lower-right curve
	pTopLRCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_RIGHT_CURVE,
										TOP_LOWER_RIGHT_CURVE_IN_WIDTH,
										TOP_LOWER_RIGHT_CURVE_WIDTH,
										TOP_LOWER_RIGHT_CURVE_IN_HEIGHT,
										TOP_LOWER_RIGHT_CURVE_HEIGHT,
										App.globals.g_kMultiplayerBorderBlue,
										TOP_LOWER_RIGHT_CURVE_OI_WIDTH)
	pEyeCandyPane.AddChild(pTopLRCurve, TOP_LOWER_RIGHT_CURVE_X_POS,
										TOP_LOWER_RIGHT_CURVE_Y_POS)
	
	
	# Create the subtitle bar
	global g_pSubtitleBar
	fSubtitleBarXPos = SUBTITLE_X_POS + g_pSubtitle.GetWidth() + SUBTITLE_BAR_X_DISTANCE
	fSubtitleBarWidth = SUBTITLE_BAR_RIGHT_EDGE - fSubtitleBarXPos
	g_pSubtitleBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	g_pSubtitleBar.Resize(fSubtitleBarWidth, SUBTITLE_BAR_HEIGHT)
	pEyeCandyPane.AddChild(g_pSubtitleBar, fSubtitleBarXPos, SUBTITLE_BAR_Y_POS)  
	
	
	# Create the bottom upper-left curve
	pBottomULCurve = UIHelpers.CreateCurve(UIHelpers.UPPER_LEFT_CURVE,
										BOTTOM_UPPER_LEFT_CURVE_IN_WIDTH,
										BOTTOM_UPPER_LEFT_CURVE_WIDTH,
										BOTTOM_UPPER_LEFT_CURVE_IN_HEIGHT,
										BOTTOM_UPPER_LEFT_CURVE_HEIGHT,
										App.globals.g_kMultiplayerBorderBlue,
										BOTTOM_UPPER_LEFT_CURVE_OI_WIDTH)
	pEyeCandyPane.AddChild(pBottomULCurve, BOTTOM_UPPER_LEFT_CURVE_X_POS,
										BOTTOM_UPPER_LEFT_CURVE_Y_POS)
	
	# Create the bottom upper-right curve
	pBottomURCurve = UIHelpers.CreateCurve(UIHelpers.UPPER_RIGHT_CURVE,
										BOTTOM_UPPER_RIGHT_CURVE_IN_WIDTH,
										BOTTOM_UPPER_RIGHT_CURVE_WIDTH,
										BOTTOM_UPPER_RIGHT_CURVE_IN_HEIGHT,
										BOTTOM_UPPER_RIGHT_CURVE_HEIGHT,
										App.globals.g_kMultiplayerBorderBlue,
										BOTTOM_UPPER_RIGHT_CURVE_OI_WIDTH)
	pEyeCandyPane.AddChild(pBottomURCurve, BOTTOM_UPPER_RIGHT_CURVE_X_POS,
										BOTTOM_UPPER_RIGHT_CURVE_Y_POS)

	# Create the bottom left bar
	pBottomLeftBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pBottomLeftBar.Resize(BOTTOM_LEFT_BAR_WIDTH, BOTTOM_LEFT_BAR_HEIGHT)
	pEyeCandyPane.AddChild(pBottomLeftBar, BOTTOM_LEFT_BAR_X_POS, BOTTOM_LEFT_BAR_Y_POS)  

	# Create the bottom lower-left curve
	pBottomLLCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_LEFT_CURVE,
										BOTTOM_LOWER_LEFT_CURVE_IN_WIDTH,
										BOTTOM_LOWER_LEFT_CURVE_WIDTH,
										BOTTOM_LOWER_LEFT_CURVE_IN_HEIGHT,
										BOTTOM_LOWER_LEFT_CURVE_HEIGHT,
										App.globals.g_kMultiplayerBorderBlue,
										BOTTOM_LOWER_LEFT_CURVE_OI_WIDTH)
	pEyeCandyPane.AddChild(pBottomLLCurve, BOTTOM_LOWER_LEFT_CURVE_X_POS,
										BOTTOM_LOWER_LEFT_CURVE_Y_POS)

	# Create the bottom right bar
	pBottomRightBar = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pBottomRightBar.Resize(BOTTOM_RIGHT_BAR_WIDTH, BOTTOM_RIGHT_BAR_HEIGHT)
	pEyeCandyPane.AddChild(pBottomRightBar, BOTTOM_RIGHT_BAR_X_POS, BOTTOM_RIGHT_BAR_Y_POS)  
	 
	# Create the bottom lower-right curve
	pBottomLRCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_RIGHT_CURVE,
										BOTTOM_LOWER_RIGHT_CURVE_IN_WIDTH,
										BOTTOM_LOWER_RIGHT_CURVE_WIDTH,
										BOTTOM_LOWER_RIGHT_CURVE_IN_HEIGHT,
										BOTTOM_LOWER_RIGHT_CURVE_HEIGHT,
										App.globals.g_kMultiplayerBorderBlue,
										BOTTOM_LOWER_RIGHT_CURVE_OI_WIDTH)
	pEyeCandyPane.AddChild(pBottomLRCurve, BOTTOM_LOWER_RIGHT_CURVE_X_POS,
										BOTTOM_LOWER_RIGHT_CURVE_Y_POS)

	# Create the first bottom lower bar
	pBottomBar1 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pBottomBar1.Resize(BOTTOM_LOWER_BAR_1_WIDTH, BOTTOM_LOWER_BAR_1_HEIGHT)
	pEyeCandyPane.AddChild(pBottomBar1, BOTTOM_LOWER_BAR_1_X_POS, BOTTOM_LOWER_BAR_1_Y_POS)  

	# Create the second bottom lower bar
	pBottomBar2 = App.TGIcon_Create("NormalStyleFrame", 5, App.globals.g_kMultiplayerBorderPurple)
	pBottomBar2.Resize(BOTTOM_LOWER_BAR_2_WIDTH, BOTTOM_LOWER_BAR_2_HEIGHT)
	pEyeCandyPane.AddChild(pBottomBar2, BOTTOM_LOWER_BAR_2_X_POS, BOTTOM_LOWER_BAR_2_Y_POS)

	return pEyeCandyPane

###############################################################################
#	BuildStatusWindow()
#	
#	Builds the status window
#	
#	Args:	TGPane*					pMultWindow	- the multiplayer window
#			TGLocalizationDatabase*	pDatabase	- the TGL containing our
#												strings
#	
#	Return:	a TGPane* -- the status window
###############################################################################
def BuildStatusWindow(pMultWindow, pDatabase):
	pStatusPane = App.TGPane_Create (1.0, 1.0)

	global g_fYPixelOffset
	global g_fXPixelOffset

	# Create the status message.
	pPane = App.TGPane_Create (0.64, 0.2)
	pText = App.TGParagraph_CreateW (pDatabase.GetString ("Connecting"), 0.64, None, "", 0.0, App.TGParagraph.TGPF_WORD_WRAP | App.TGParagraph.TGPF_READ_ONLY )
#	pText = App.TGParagraph_CreateW (pDatabase.GetString ("Connecting"))
	pPane.AddChild (pText)
	pStatusPane.AddChild (pPane, 0.23, 0.27)

	# cancel button
	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType (App.ET_CANCEL_CONNECT)
	pEvent.SetDestination (pMultWindow)

	pButton = App.STButton_CreateW (pDatabase.GetString ("Cancel"), pEvent)
	pPane = App.TGPane_Create (0.64, 1.0)
	pPane.AddChild (pButton)
	pStatusPane.AddChild (pPane, 0.23, 0.40)
	App.g_kFocusManager.AddObjectToTabOrder (pButton)

	# Create a background
	# Get LCARS string.
	pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
	pcLCARS = pGraphicsMode.GetLcarsString()
	pBackground = App.TGIcon_Create(pcLCARS, 200, App.g_kMainMenuBorderMainColor)
	pBackground.Resize (0.65, 0.2)
	pStatusPane.AddChild (pBackground, 0.225, 0.25)

	# Create some eye candy.
	pStuff = UIHelpers.CreateCurve(UIHelpers.UPPER_LEFT_CURVE, 
											0.1 - g_fXPixelOffset * 3.0,
											0.15,
											0.015,
											0.04,											
											App.g_kMainMenuBorderMainColor,
											0.03)

	pStatusPane.AddChild (pStuff, 0.125, 0.21 - g_fYPixelOffset * 3.0)

	pStuff = App.TGIcon_Create(pcLCARS, 200, App.g_kMainMenuBorderOffColor)
	pStuff.Resize (0.60 - g_fXPixelOffset * 3.0, 0.025)
	pStatusPane.AddChild (pStuff, 0.275 + g_fXPixelOffset * 3.0, 0.21 - g_fYPixelOffset * 3.0)

	pStuff = App.TGIcon_Create(pcLCARS, 200, App.g_kMainMenuBorderOffColor)
	pStuff.Resize (0.1 - g_fXPixelOffset * 3.0, 0.2)
	pStatusPane.AddChild (pStuff, 0.125, 0.25)

	pLowerCurve = UIHelpers.CreateCurve(UIHelpers.LOWER_LEFT_CURVE, 
											0.1 - g_fXPixelOffset * 3.0,
											0.15,
											0.015,
											0.04,											
											App.g_kMainMenuBorderMainColor,
											0.03)
	pStatusPane.AddChild (pLowerCurve, 0.125, 0.45 + g_fYPixelOffset * 3.0)

	pStuff = App.TGIcon_Create(pcLCARS, 200, App.g_kMainMenuBorderOffColor)
	pStuff.Resize (0.60 - g_fXPixelOffset * 3.0, 0.025)
	pStatusPane.AddChild (pStuff, 0.275 + g_fXPixelOffset * 3.0, pLowerCurve.GetBottom() - pStuff.GetHeight())

	return pStatusPane
	
	
###############################################################################
#	BuildChatWindow()
#	
#	Builds the pane for inputting to the chat box.
#	
#	Args:	none
#	
#	Return:	Pane
###############################################################################
def BuildChatWindow (pMultWindow, pDatabase):
	pChatParentPane = App.TGPane_Create (1.0, 1.0)

	# Create text label
	pText = App.TGParagraph_Create ("Chat:")
	fWidth = pText.GetWidth ()

	# Create tgparagraph object.
	pTextEntry = App.TGParagraph_Create ("")
	pTextEntry.Resize (1.0 - Tactical.Tactical.GetEmptyAreaLeft () - fWidth - 0.01, pTextEntry.GetHeight (), 0)
	pTextEntry.SetReadOnly (0)
	pTextEntry.SetMaxChars (80)
	pPane = App.TGPane_Create (1.0 - Tactical.Tactical.GetEmptyAreaLeft (), pTextEntry.GetHeight ())
	pPane.AddChild (pTextEntry, fWidth + 0.01, 0, 0)
	pPane.AddChild (pText, 0, 0, 0)
	pTextEntry.SetString ("", 0)		# Clear out the text entry so it starts off blank.
	pTextEntry.SetIgnoreString ("\t")
	App.g_kFocusManager.AddObjectToTabOrder (pTextEntry)

	pChatParentPane.AddChild (pPane, Tactical.Tactical.GetEmptyAreaLeft (), Tactical.Tactical.GetEmptyAreaBottom () - pTextEntry.GetHeight (), 0)	
	return pChatParentPane

def HandleCancelConnect (TGObject, pEvent):
	# This differs from handleCancel, which just cancels out of
	# screens prior to connecting.  This one actually
	# has to disconnect.

	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	if (not App.IsNull (pNetwork)):
		pNetwork.Disconnect ()	

	# Bring up options again.
	# Find the multiplayer window
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	# Hide all panes, make MultiplayerPane visible.
	pMultWindow.HideAllChildren ()

#	print ("Handle cancel connect")

	# Hide the entire window and make options window visible.
	pMain = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	pMain.SetVisible()
	pTopWindow.MoveToFront(pMain)

	TGObject.CallNextHandler(pEvent)

###############################################################################
#	HandleServerEntry()
#	
#	Update the server list
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_SERVER_ENTRY_EVENT event
#	
#	Return:	None
###############################################################################
def HandleServerEntry (TGObject, pEvent):
	# Check if the entry is the right version.
	if (pEvent.GetVersion() != App.UtopiaModule_GetGameVersion()):
		# Not the right version. Don't create any buttons.
		TGObject.CallNextHandler(pEvent)
		return

	# Initialize some globals
	# Copy the message and change its type so we can use it for the button press
	pNewEvent = App.ServerListEvent_Create()
	pNewEvent.Copy(pEvent)
	pNewEvent.SetEventType(App.ET_SELECT_SERVER_ENTRY)

	# Create button for Name menu
	pButton  = App.STButton_Create(pEvent.GetServerName(), pNewEvent)
	pButton.SetJustification(App.STButton.CENTER)
	g_pClientGamesNameMenu.AddChild(pButton, 0, 0, 0)
#	g_pClientGamesNameMenu.ResizeToContents ()
	
	# Create button for Type menu
	pTextButton  = App.TGTextButton_Create(pEvent.GetMissionName())
	pTextButton.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0)
	pTextButton.AlignTextVertical(App.TGTextButton.ALIGN_MIDDLE)
	g_pClientGamesTypeMenu.AddChild(pTextButton, 0, 0, 0)
	pTextButton.Resize(pTextButton.GetWidth(), pButton.GetHeight(), 0)
#	g_pClientGamesTypeMenu.ResizeToContents ()

	# Create button for Ping menu
	pTextButton  = App.TGTextButton_Create(str(pEvent.GetPing()))
	pTextButton.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0)
	pTextButton.AlignTextVertical(App.TGTextButton.ALIGN_MIDDLE)
	g_pClientGamesPingMenu.AddChild(pTextButton, 0, 0, 0)
	pTextButton.Resize(pTextButton.GetWidth(), pButton.GetHeight(), 0)
#	g_pClientGamesPingMenu.ResizeToContents ()


	# Create button for Players menu
	pTextButton  = App.TGTextButton_Create(str(pEvent.GetNumPlayers()) + '/'
									+ str(pEvent.GetMaxPlayers()))
	pTextButton.AlignTextHorizontal(App.TGTextButton.ALIGN_CENTER, 0)
	pTextButton.AlignTextVertical(App.TGTextButton.ALIGN_MIDDLE)
	g_pClientGamesPlayersMenu.AddChild(pTextButton, 0, 0, 0)
	pTextButton.Resize(pTextButton.GetWidth(), pButton.GetHeight(), 0)
#	g_pClientGamesPlayersMenu.ResizeToContents ()

	# Lay out everything
#	g_pClientGamesWindow.ScrollToBottom()
	g_pClientGamesWindow.InteriorChangedSize()
	g_pClientGamesWindow.Layout()
	
	TGObject.CallNextHandler(pEvent)

###############################################################################
#	HandleServerPlayer()
#	
#	Update the player list
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_SERVER_PLAYER_EVENT event
#	
#	Return:	None
###############################################################################
def HandleServerPlayer (TGObject, pEvent):

	# Set the font small
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont,
				MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Create text object of the player and add it to the list
	pcPlayerName = pEvent.GetCString()
	pText = App.TGParagraph_Create(pcPlayerName)
	g_pClientPlayersMenu.AddChild(pText)
	g_pClientPlayersMenu.ResizeToContents ()

	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Lay out everything
	g_pClientPlayersWindow.Layout ()

	TGObject.CallNextHandler(pEvent)


###############################################################################
#	HandleRefreshServerListDone()
#	
#	The server list is done refreshing.
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_REFRESH_SERVER_LIST_DONE event
#	
#	Return:	None
###############################################################################
def HandleRefreshServerListDone (TGObject, pEvent):

	# If the Direct Join toggle isn't enabled...
	if not g_pClientDirectButton.IsChosen():
		# Enable the start query button and disable the stop query button
		g_pClientStartQueryButton.SetEnabled(0)
		g_pClientStopQueryButton.SetDisabled(0)

		# Enable the Internet/LAN buttons
		g_pClientInternetButton.SetEnabled(0)
		g_pClientLanButton.SetEnabled(0)
		# Use determine instead of IsModemConnection, since IsModemConnection requires
		# that the network be initialized to be accurate.
		bModem = App.g_kUtopiaModule.DetermineModemConnection ()
		if (bModem):
			g_pClientLanButton.SetDisabled ()


	TGObject.CallNextHandler(pEvent)

###############################################################################
#	KeyboardHandler()
#	
#	Handles keyboard events.
#	
#	Args:	pObject	- The object the event was sent to (probably
#			  the tactical window or the bridge window).
#			pEvent	- The keyboard event.
#	
#	Return:	none
###############################################################################
def KeyboardHandler(pObject, pEvent):
	"Handle our special keys for the chat interface."
	eKeyType = pEvent.GetKeyState()
	cCharCode = pEvent.GetUnicode()

	if eKeyType == App.TGKeyboardEvent.KS_NORMAL:
		if (cCharCode == App.WC_RETURN):
			iRet = SendChat ()
			if (iRet == 1):
				pEvent.SetHandled ()

	if (pEvent.EventHandled() == 0):
		pObject.CallNextHandler(pEvent)

def SendChat ():
	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	if (not pNetwork):
		return

	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

	# See if chat window is up.  If not, ignore.
	if (pMultWindow.IsChatWindowActive () == 0):
		return 0

	pChatWindow = pMultWindow.GetChatWindow ()

	# Get the paragraph
	pPane = App.TGPane_Cast(pChatWindow.GetFirstChild())
	pPara = App.TGParagraph_Cast(pPane.GetFirstChild())

	# Get the string from the paragraph.  This is what will be sent.
	pcString = pPara.GetCString ()

	###############################################################
	# Send the chat message.
	# 
	pMessage = App.TGMessage_Create ()
	pMessage.SetGuaranteed (1)		# Yes, this is a guaranteed packet
	
	# Setup the stream.
	kStream = App.TGBufferStream ()		# Allocate a local buffer stream.
	kStream.OpenBuffer (256)			# Open the buffer stream with a 256 byte buffer.
	
	# Write relevant data to the stream.
	# First write message type.
	if (pMultWindow.IsTeamChat ()):
		kStream.WriteChar (chr (TEAM_CHAT_MESSAGE))
	else:
		kStream.WriteChar (chr (CHAT_MESSAGE))

	kStream.WriteLong (pNetwork.GetLocalID ())

	iLen = len (pcString)
	kStream.WriteShort (iLen)
	kStream.Write (pcString, iLen)

	# Okay, now set the data from the buffer stream to the message
	pMessage.SetDataFromStream (kStream)

	# Send the message to the host.
	pNetwork.SendTGMessage (pNetwork.GetHostID (), pMessage)

	# We're done.  Close the buffer.
	kStream.CloseBuffer ()

	import MissionShared
	# Okay, now hide chat window.
	pMultWindow.ToggleChatWindow(MissionShared.g_bGameOver)
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	if pTCW:
		pTCW.Layout()

	if MissionShared.g_bGameOver:
		# Bring it back again
		pChatWindow.SetVisible(0)
		pMultWindow.SetVisible()
		pTopWindow.MoveToFront(pMultWindow)

		# We've got to clear out the entry box for the next message to be sent
		# We need to give focus to the paragraph itself.
		pPara.SetString("", 0)
		pChatWindow.Layout()
	
		pTopWindow.SetFocus(pMultWindow)
		pMultWindow.SetFocus(pChatWindow)
		pChatWindow.SetFocus(pPane)
		pPane.SetFocus(pPara)

	return 1

def ProcessMessageHandler (self, pEvent):
	pMessage = pEvent.GetMessage()
	if (pMessage):
		# Get the data from the message
		# Open a buffer stream to read the data
		kStream = pMessage.GetBufferStream ();

		cType = kStream.ReadChar ();

		cType = ord (cType)

		if (cType == CHAT_MESSAGE):
			pNetwork = App.g_kUtopiaModule.GetNetwork ()
			if (pNetwork):
				if (App.g_kUtopiaModule.IsHost ()):
					# I'm the host, forward this message to everybody else.
					pNewMessage = pMessage.Copy ()
					pNetwork.SendTGMessageToGroup ("NoMe", pNewMessage)

				# Okay, get who the message is from.
				iFromID = kStream.ReadLong ()
				
				# Get the player name from the network.
				pPlayerList = pNetwork.GetPlayerList ()

				pNetPlayer = pPlayerList.GetPlayer (iFromID)
				if (pNetPlayer):
					pString = pNetPlayer.GetName ()
					pcName = pString.GetCString ()

					# Get string from buffer
					pcMessage = ""
					iLen = kStream.ReadShort ()
					for i in range (iLen):
						pcMessage = pcMessage + kStream.ReadChar ()

					# Create string to display based on name and the string from the buffer
					pcFullString = "%s: %s" % (pcName, pcMessage)

					import MissionShared
					if MissionShared.g_bGameOver:
						# Send the string to the StylizedWindow in the gameover screen
						
						from Multiplayer import MissionMenusShared
						pEndChatSubPane = MissionMenusShared.g_pEndChatSubPane
						pEndChatWindow = MissionMenusShared.g_pEndChatWindow
						if pEndChatWindow:
							pEndChatSubPane.AddChild(App.TGParagraph_Create(
								pcFullString, pEndChatSubPane.GetWidth(), None, "",
								0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)) 
							pEndChatSubPane.ResizeToContents ()
							pEndChatWindow.InteriorChangedSize(1)
							pEndChatWindow.Layout()
					else:
						# Create a subtitle action to display the string.
						pSequence = App.TGSequence_Create ()
						pSubtitleAction = App.SubtitleAction_CreateC (pcFullString)
						pSubtitleAction.SetDuration (5.0)
						pSequence.AddAction (pSubtitleAction)
						pSequence.Play ()
		elif (cType == TEAM_CHAT_MESSAGE):
			pNetwork = App.g_kUtopiaModule.GetNetwork ()
			if (pNetwork):
				# Okay, get who the message is from.
				iFromID = kStream.ReadLong ()

				# Get the group that the player whose message this is from
				pPlayerList = pNetwork.GetPlayerList ()

				pNetPlayer = pPlayerList.GetPlayer (iFromID)
				if (pNetPlayer):
					bShowChat = 1
					if (App.g_kUtopiaModule.IsHost ()):
						pGame = App.MultiplayerGame_Cast (App.Game_GetCurrentGame ())

						# Get the mission so we can get the friendly group
						pMission = MissionLib.GetMission ()
						pFriendlyGroup = pMission.GetFriendlyGroup ()
						pEnemyGroup = pMission.GetEnemyGroup ()

						pShip = pGame.GetShipFromPlayerID (pNetPlayer.GetNetID ())

						pGroup = None
						if (pShip):
							pcName = pShip.GetName ()
								
							if (pFriendlyGroup.IsNameInGroup (pcName)):
								# Friendly group chat.  Send to friendly group.
								pGroup = pFriendlyGroup
							else:
								# Enemy group chat.  Send to enemy group.
								pGroup = pEnemyGroup

						iNumPlayers = pPlayerList.GetNumPlayers ()
						i = 0
						while (i < iNumPlayers):
							# Get each player's ship and determine if that ship
							# belongs in the group
							pPlayer = pPlayerList.GetPlayerAtIndex (i)
							pShip = pGame.GetShipFromPlayerID (pPlayer.GetNetID ())

							if (pShip):
								pcName = pShip.GetName ()
									
								if (pGroup == None):
									# Okay, no group so send to everybody.
									if (pPlayer.GetNetID () != pNetwork.GetHostID ()):
										pNewMessage = pMessage.Copy ()
										pNetwork.SendTGMessage (pPlayer.GetNetID (), pNewMessage)
								else:
									if (pGroup.IsNameInGroup (pcName)):
										# Okay, this player is in the group.  Send him the message
										if (pPlayer.GetNetID () != pNetwork.GetHostID ()):
											pNewMessage = pMessage.Copy ()
											pNetwork.SendTGMessage (pPlayer.GetNetID (), pNewMessage)
									else:
										if (pPlayer.GetNetID () == pNetwork.GetHostID ()):
											# Host is not part of the group, don't show him the message
											bShowChat = 0
							
							i = i + 1
								 
					if (bShowChat):	
						pString = pNetPlayer.GetName ()
						pcName = pString.GetCString ()

						# Get string from buffer
						pcMessage = ""
						iLen = kStream.ReadShort ()
						for i in range (iLen):
							pcMessage = pcMessage + kStream.ReadChar ()

						# Create string to display based on name and the string from the buffer
						pcFullString = "%s: %s" % (pcName, pcMessage)

						# Create a subtitle action to display the string.
						pSequence = App.TGSequence_Create ()
						pSubtitleAction = App.SubtitleAction_CreateC (pcFullString)
						pSubtitleAction.SetDuration (5.0)
						pSequence.AddAction (pSubtitleAction)
						pSequence.Play ()

		kStream.Close ()


# Call this function to stop anything the interface might be doing, such as GameSpy.
def UnloadPreGameMenus():
	# Call this to stop gamespy
	if (not App.g_kUtopiaModule.GetNetwork ()):
		App.g_kUtopiaModule.TerminateGameSpy ()

	# Store off all configuration stuff.
	if (MainMenu.mainmenu.g_kCurrentMiddlePane == 7):
		pTopWindow = App.TopWindow_GetTopWindow()
		pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

		kString = App.TGString ()

		if (pMultWindow):
			if (App.g_kUtopiaModule.IsHost ()):
				pMenu = None
				if (App.g_kUtopiaModule.IsClient ()):
					pMenu = pMultWindow.GetHostMenu ()
				else:
					pMenu = pMultWindow.GetDedicatedServerMenu ()
			else:
				pMenu = None
				if (pMultWindow.IsDirectJoin ()):
					pMenu = pMultWindow.GetDirectJoinMenu () 

					# Set address from the direct join menu.
					pPane = App.TGPane_Cast (pMenu.GetNthChild (0))
					pPara = App.TGParagraph_Cast (pPane.GetNthChild (1))
					pPara.GetString (kString)
					App.g_kConfigMapping.SetTGStringValue ("Multiplayer Options", "IP Address", kString)
				else:
					pMenu = pMultWindow.GetJoinMenu ()

	# Remove us from the top of the mainmenu so that child order will be restored
	global g_pPreGamePane
	if g_pPreGamePane:
		if g_pPreGamePane.GetParent():
			g_pPreGamePane.GetParent().RemoveChild(g_pPreGamePane)


###############################################################################
#	HandleServerListState()
#	
#	Updates the text describing the status of the list of available multiplayer
#	servers being refreshed
#	
#	Args:	TGObject*		pObject		- the MultiplayerWindow object
#			TGEvent*		pEvent		- ET_SERVER_LIST_STATE event
#	
#	Return:	none
###############################################################################
def HandleServerListState(pObject, pEvent):
	# Get the string from the event and update the completion paragraph with
	# it
	pString = App.TGString()
	pEvent.GetString(pString)
	g_pClientCompletionText.SetStringW(pString)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	HandleServerListPercentage()
#	
#	Updates the text describing the status of the list of available multiplayer
#	servers being refreshed
#	
#	Args:	TGObject*		pObject		- the MultiplayerWindow object
#			TGEvent*		pEvent		- ET_SERVER_LIST_PERCENTAGE event
#	
#	Return:	none
###############################################################################
def HandleServerListPercentage(pObject, pEvent):
	iPercent = pEvent.GetInt()

	# Resize the progress bar to reflect the percentage complete
	fWidth = (float(iPercent) / 100.0) * CLIENT_COMPLETION_BAR_WIDTH
	g_pClientCompletionIcon.Resize(fWidth, g_pClientCompletionIcon.GetHeight())

	# Update the displayed number to accomplish same
	g_pClientCompletionNumber.SetString(str(iPercent) + '%')

	pObject.CallNextHandler(pEvent)


###############################################################################
#	RoundedTextEntryMouseHandler()
#	
#	Handles mouse events. This is registered as an event handler for
#	TacticalWindow.
#	
#	Args:	TacticalWindow	pTactical	- the TacticalWindow object
#			TGMouseEvent	pEvent		- mouse event
#	
#	Return:	none
###############################################################################
def RoundedTextEntryMouseHandler (pSelf, pEvent):
	"Handle mouse events for the command interface"

	if (pEvent.EventHandled () == 0):
		if (pEvent.GetButtonNum() & App.TGMouseEvent.MEF_BUTTON_LEFT):
			if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
				# Give focus to the pane.
				
				pPara = App.TGParagraph_Cast (App.TGPane_Cast (pSelf.GetNthChild(0)).GetNthChild (0))
				pPara.Resize (pSelf.GetWidth (), pSelf.GetHeight ())

	# Pass event to next handler.
	pSelf.CallNextHandler(pEvent)


###############################################################################
#	HandleMouseEventsForGlass()
#	
#	There are times that we want to cover up some UI elements with glass.
#	We have to make sure the user can't click on them, so we make the glass
#	handle mouse events before letting them pass underneath
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
#	ShowClientUI()
#	
#	Show the user interface for starting a multiplayer game as a client
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_SHOW_CLIENT_UI event
#	
#	Return:	None
###############################################################################
def ShowClientUI(pObject, pEvent):
	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes] + 1)

	#Load localization database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")

	# Update the subtitle
	SetSubtitle(pDatabase.GetString("Join Game"), MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Unload localization database
	App.g_kLocalizationManager.Unload(pDatabase)

	# Update the configuration manager and the client UI with the latest info
	if g_pHostPane.IsVisible():
		pGameName = App.TGString()
		pPlayerName = App.TGString()
		pPassword = App.TGString()
		App.TGParagraph_Cast(App.TGPane_Cast (g_pHostGameNameInput.GetNthChild(0)).GetNthChild(0)).GetString(pGameName)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pHostPlayerNameInput.GetNthChild(0)).GetNthChild(0)).GetString(pPlayerName)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pHostPasswordInput.GetNthChild(0)).GetNthChild(0)).GetString(pPassword)
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Game Name", pGameName)
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Player Name", pPlayerName)
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Password", pPassword)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientNameInput.GetNthChild(0)).GetNthChild(0)).GetString(pPlayerName)

		if (pPlayerName.GetCString() == ""):
			pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")
			pPlayerName = pDatabase.GetString("Default Name")
			App.g_kLocalizationManager.Unload(pDatabase)
			App.TGParagraph_Cast(App.TGPane_Cast(g_pClientNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPlayerName)
			App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Player Name", pPlayerName)

		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPlayerName)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientPasswordInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPassword)

		g_pHostPane.SetNotVisible()

	g_pClientPane.SetVisible()
	
	global g_bClientUI
	g_bClientUI = 1
	
	g_pHostButton.SetNotSelected ()
	g_pClientButton.SetSelected ()
	
	# Use determine instead of IsModemConnection, since IsModemConnection requires
	# that the network be initialized to be accurate.
	bModem = App.g_kUtopiaModule.DetermineModemConnection ()
	if (bModem):
		g_pClientLanButton.SetDisabled ()
	else:
		g_pClientLanButton.SetEnabled ()

	if pObject and pEvent: # In case this wasn't called to handle an event
		pObject.CallNextHandler(pEvent)


###############################################################################
#	ShowHostUI()
#	
#	Show the user interface for starting a multiplayer game as a server
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_SHOW_HOST_UI event
#	
#	Return:	
###############################################################################
def ShowHostUI(pObject, pEvent):
	# Call this to stop gamespy.  This will stop pending queries and the like.
	if (not App.g_kUtopiaModule.GetNetwork ()):
		App.g_kUtopiaModule.TerminateGameSpy ()

	#Load localization database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")

	# Update the subtitle
	SetSubtitle(pDatabase.GetString("Host Game"), MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes])

	# Make sure we're don't have any GameSpy queries running
	pEvent = App.TGBoolEvent_Create()
	pEvent.SetEventType(App.ET_REFRESH_SERVER_LIST)
	pEvent.SetDestination(g_pMultiplayerPane)
	pEvent.SetBool(1)
	App.g_kEventManager.AddEvent(pEvent)

	# Update the configuration manager and the host UI with the latest info
	# (We want the host pane to keep the game name that it had, though.)
	if g_pClientPane.IsVisible():
		pGameName = App.TGString()
		pPlayerName = App.TGString()
		pPassword = App.TGString()
		pAddress = App.TGString()
		App.TGParagraph_Cast(App.TGPane_Cast (g_pHostGameNameInput.GetNthChild(0)).GetNthChild(0)).GetString(pGameName)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientNameInput.GetNthChild(0)).GetNthChild(0)).GetString(pPlayerName)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientPasswordInput.GetNthChild(0)).GetNthChild(0)).GetString(pPassword)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientDirectInput.GetNthChild(0)).GetNthChild(0)).GetString(pAddress)
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Game Name", pGameName)
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Player Name", pPlayerName)
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Password", pPassword)
		App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Direct Join Address", pAddress)

		if (pPlayerName.GetCString() == ""):
			pPlayerName = pDatabase.GetString("Default Name")
			App.TGParagraph_Cast(App.TGPane_Cast(g_pClientNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPlayerName)
			App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Player Name", pPlayerName)

		if (pGameName.GetCString() == ""):
			pGameName = pDatabase.GetString("My Game")
			App.TGParagraph_Cast(App.TGPane_Cast(g_pHostGameNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pGameName)

		App.TGParagraph_Cast(App.TGPane_Cast (g_pHostPlayerNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPlayerName)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pHostPasswordInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPassword)

		g_pClientPane.SetNotVisible()

	# Unload localization database
	App.g_kLocalizationManager.Unload(pDatabase)

	g_pHostPane.SetVisible()

	global g_bClientUI
	g_bClientUI = 0

	g_pHostButton.SetSelected ()
	g_pClientButton.SetNotSelected ()
	
	# Use determine instead of IsModemConnection, since IsModemConnection requires
	# that the network be initialized to be accurate.
	bModem = App.g_kUtopiaModule.DetermineModemConnection ()
	if (bModem):
		g_pHostLanButton.SetDisabled ()
	else:
		g_pHostLanButton.SetEnabled ()

	if pObject and pEvent: # In case this wasn't called to handle an event
		pObject.CallNextHandler(pEvent)


###############################################################################
#	ExitMultiplayer()
#	
#	Stop the multiplayer game currently in progress
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_EXIT_MULTIPLAYER event
#	
#	Return:	
###############################################################################
def ExitMultiplayer(pObject, pEvent):
	global g_bExitPressed
	g_bExitPressed = 1
	
	g_bGame = 0

	# Determine if there is a game.
	pGame = App.Game_GetCurrentGame()
	if not App.IsNull(pGame):
		# Terminate the game
		pGame.Terminate()

	# Find the multiplayer window and hide it
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
	pMultWindow.HideAllChildren ()

	# Give the focus back to the main menu
	pOptionsWindow = pTopWindow.FindMainWindow(App.MWT_OPTIONS)
	pTopWindow.SetVisible()
	pTopWindow.SetFocus(pOptionsWindow)
	pTopWindow.MoveToFront(pOptionsWindow)
	pOptionsWindow.SetVisible()
	pOptionsWindow.SetFocus(g_pPreGamePane)
	pOptionsWindow.MoveToFront(g_pPreGamePane)
	g_pPreGamePane.SetVisible()

	if pObject:
		pObject.CallNextHandler(pEvent)


###############################################################################
#	ReturnToMainMenu()
#	
#	End the multiplayer game and go back to the main menu
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_EXIT_MULTIPLAYER event
#	
#	Return:	
###############################################################################
def ReturnToMainMenu(pObject, pEvent):

	# Make sure we're don't have any GameSpy queries running
	pEvent = App.TGBoolEvent_Create()
	pEvent.SetEventType(App.ET_REFRESH_SERVER_LIST)
	pEvent.SetDestination(g_pMultiplayerPane)
	pEvent.SetBool(1)
	App.g_kEventManager.AddEvent(pEvent)

	# We have to update the configuration manager with the latest data
	UpdateConfigManager()
	
	g_pPreGamePane.SetNotVisible()	

	# Bring up default options window thing.
	MainMenu.mainmenu.SwitchMiddlePane("New Game")
	
	pObject.CallNextHandler(pEvent)


###############################################################################
#	UpdateConfigManager()
#	
#	Updates the configuration manager with the latest data
#	from the multiplayer pre-game menus
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def UpdateConfigManager():
	# If neither the host nor client panes are visible, there's nothing to do here.
	if not g_pClientPane.IsVisible() and not g_pHostPane.IsVisible():
		return
	
	pGameName = App.TGString()
	pPlayerName = App.TGString()
	pPassword = App.TGString()
	pAddress = App.TGString()
	App.TGParagraph_Cast(App.TGPane_Cast (g_pHostGameNameInput.GetNthChild(0)).GetNthChild(0)).GetString(pGameName)
	if (pGameName.GetCString() == ""):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")
		pGameName = pDatabase.GetString("My Game")
		App.g_kLocalizationManager.Unload(pDatabase)
		App.TGParagraph_Cast(App.TGPane_Cast(g_pHostGameNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pGameName)

	if g_pClientPane.IsVisible(): # get the data from the client pane
		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientNameInput.GetNthChild(0)).GetNthChild(0)).GetString(pPlayerName)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientPasswordInput.GetNthChild(0)).GetNthChild(0)).GetString(pPassword)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pClientDirectInput.GetNthChild(0)).GetNthChild(0)).GetString(pAddress)
	elif g_pHostPane.IsVisible(): # get the data from the host pane
		App.TGParagraph_Cast(App.TGPane_Cast (g_pHostPlayerNameInput.GetNthChild(0)).GetNthChild(0)).GetString(pPlayerName)
		App.TGParagraph_Cast(App.TGPane_Cast (g_pHostPasswordInput.GetNthChild(0)).GetNthChild(0)).GetString(pPassword)

	if (pPlayerName.GetCString() == ""):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")
		pPlayerName = pDatabase.GetString("Default Name")
		App.g_kLocalizationManager.Unload(pDatabase)
		App.TGParagraph_Cast(App.TGPane_Cast(g_pClientNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPlayerName)

	App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Game Name", pGameName)
	App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Player Name", pPlayerName)
	App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Password", pPassword)
	App.g_kConfigMapping.SetTGStringValue("Multiplayer Options", "Direct Join Address", pAddress)

	App.TGParagraph_Cast(App.TGPane_Cast (g_pClientNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPlayerName, 0)
	App.TGParagraph_Cast(App.TGPane_Cast (g_pClientPasswordInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPassword, 0)

	App.TGParagraph_Cast(App.TGPane_Cast (g_pHostPlayerNameInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPlayerName, 0)
	App.TGParagraph_Cast(App.TGPane_Cast (g_pHostPasswordInput.GetNthChild(0)).GetNthChild(0)).SetStringW(pPassword, 0)

	if g_pClientDirectButton.IsChosen():
		g_pMultiplayerPane.SetDirectJoin(1)
	else:
		g_pMultiplayerPane.SetDirectJoin(0)

###############################################################################
#	HandleDedicatedClicked()
#	
#	The dedicated host toggle has been clicked
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_DEDICATED_CLICKED event
#	
#	Return:	None
###############################################################################
def HandleDedicatedClicked(pObject, pEvent):
	if not g_pHostDedicatedButton.IsChosen():
		g_pHostDedicatedButton.SetChosen(1)
		g_pHostPlayerNameInput.SetNotVisible()
		g_pHostPlayerNameCaption.SetNotVisible()
	else:
		g_pHostDedicatedButton.SetChosen(0)
		g_pHostPlayerNameInput.SetVisible()
		g_pHostPlayerNameCaption.SetVisible()

	App.g_kConfigMapping.SetIntValue("Multiplayer Options", "Dedicated Server",
									g_pHostDedicatedButton.IsChosen())

	pObject.CallNextHandler(pEvent)


###############################################################################
#	ToggleDirectJoin()
#	
#	Switch direct join on and off
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_TOGGLE_DIRECT_JOIN event
#	
#	Return: None	
###############################################################################
def ToggleDirectJoin(pObject, pEvent):
	# If the button was on, turn it off, and enable and disable that
	# which is appropriate. Otherwise, do the opposite.
	if g_pClientDirectButton.IsChosen():
		g_pClientDirectButton.SetChosen(0, 0)
		g_pClientGlass.SetNotVisible(0)
		g_pClientGlass2.SetNotVisible(0)
		g_pClientInternetButton.SetEnabled(0)
		g_pClientLanButton.SetEnabled(0)
		g_pClientStartQueryButton.SetEnabled(0)
		g_pClientGamesWindow.SetEnabled(0)
		g_pClientStartButton.SetDisabled(0)
		g_pMultiplayerPane.SetDirectJoin(0)

		# Use determine instead of IsModemConnection, since IsModemConnection requires
		# that the network be initialized to be accurate.
		bModem = App.g_kUtopiaModule.DetermineModemConnection ()
		if (bModem):
			g_pClientLanButton.SetDisabled ()
	else:
		# Make sure we're don't have any GameSpy queries running
		pEvent = App.TGBoolEvent_Create()
		pEvent.SetEventType(App.ET_REFRESH_SERVER_LIST)
		pEvent.SetDestination(g_pMultiplayerPane)
		pEvent.SetBool(1)
		App.g_kEventManager.AddEvent(pEvent)

		g_pClientInternetButton.SetDisabled(0)
		g_pClientLanButton.SetDisabled(0)
		g_pClientStartQueryButton.SetDisabled(0)
		g_pClientDirectButton.SetChosen(1, 0)
		g_pClientGlass.SetVisible(0)
		g_pClientGlass2.SetVisible(0)
		g_pClientPlayersMenu.KillChildren()
		g_pClientGameInfoPara.SetString("", 0)
		g_pClientGamesWindow.SetDisabled(0)
		g_pClientGamesWindow.InteriorChangedSize ()
		g_pClientStartButton.SetEnabled(0)
		g_pMultiplayerPane.SetDirectJoin(1)

		g_pClientGamesNameMenu.KillChildren ()
		g_pClientGamesTypeMenu.KillChildren ()
		g_pClientGamesPingMenu.KillChildren ()
		g_pClientGamesPlayersMenu.KillChildren ()



	# Now layout the whole pre-game pane
	g_pClientPane.Layout()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	ToggleLocalInternetHost()
#	
#	Switch between Internet and LAN play
#	
#	Args:	TGObject*	pObject	- the multiplayer pane
#			TGEvent*	pEvent	- the ET_LOCAL_INTERNET_HOST event
#	
#	Return: None	
###############################################################################
def ToggleLocalInternetHost(pObject, pEvent):
	
	bInternet = pEvent.GetInt()
	if bInternet:
		g_pHostInternetButton.SetChosen(1)
		g_pClientInternetButton.SetChosen(1)
		g_pHostLanButton.SetChosen(0)
		g_pClientLanButton.SetChosen(0)
	else:
		g_pHostInternetButton.SetChosen(0)
		g_pClientInternetButton.SetChosen(0)
		g_pHostLanButton.SetChosen(1)
		g_pClientLanButton.SetChosen(1)

	App.g_kConfigMapping.SetIntValue("Multiplayer Options", "Internet Host", bInternet)

	pObject.CallNextHandler(pEvent)


###############################################################################
#	HandleSetMissionName()
#	
#	When a mission is selected from the menu, the appropriate text description
#	must be brought up
#	
#	Args:	TGObject*	pObject	- the object that handles us
#			TGEvent*	pEvent	- the ET_SET_MISSION_NAME event
#	
#	Return:	None
###############################################################################
def HandleSetMissionName(TGObject, pEvent):
	# Set mission name based on event
	pcString = pEvent.GetCString()
	App.g_kVarManager.SetStringVariable("Multiplayer", "Mission", "Multiplayer.Episode." + pcString + "." + pcString)

	pModule = __import__("Multiplayer.Episode." + pcString + "." + pcString + "Name")
	pDesc = pModule.GetMissionDescription ()
	g_pHostTextArea.SetStringW(pDesc)
		
	TGObject.CallNextHandler(pEvent)

###############################################################################
#	HandleClientStartClicked()	
#	
#	The start button has been clicked.
#	
#	Args:	TGObject*	pObject	- the object that handles us
#			TGEvent*	pEvent	- the ET_START_BUTTON_CLICKED event
#	
#	Return:	None
###############################################################################
def HandleClientStartClicked(TGObject, pEvent):
	# We have to update the configuration manager with the latest data
	UpdateConfigManager()
	
	# Set multiplayer again just to be redundant.
	App.g_kUtopiaModule.SetMultiplayer (1)
	App.g_kUtopiaModule.SetIsClient (1)
	App.g_kUtopiaModule.SetIsHost (0)

	pNewEvent = App.TGEvent_Create()
	pNewEvent.SetEventType(App.ET_START)
	pNewEvent.SetDestination(TGObject)
	App.g_kEventManager.AddEvent(pNewEvent)

	TGObject.CallNextHandler(pEvent)

###############################################################################
#	HandleHostStartClicked()	
#	
#	The start button has been clicked.
#	
#	Args:	TGObject*	pObject	- the object that handles us
#			TGEvent*	pEvent	- the ET_START_BUTTON_CLICKED event
#	
#	Return:	None
###############################################################################
def HandleHostStartClicked(TGObject, pEvent):
	# We have to update the configuration manager with the latest data
	UpdateConfigManager()
	
	# Set multiplayer again just to be redundant.
	App.g_kUtopiaModule.SetMultiplayer (1)
	App.g_kUtopiaModule.SetIsHost (1)
	if g_pHostDedicatedButton.IsChosen():
		App.g_kUtopiaModule.SetIsClient(0)
	else:
		App.g_kUtopiaModule.SetIsClient(1)

	pNewEvent = App.TGEvent_Create()
	pNewEvent.SetEventType(App.ET_START)
	pNewEvent.SetDestination(TGObject)
	App.g_kEventManager.AddEvent(pNewEvent)

	TGObject.CallNextHandler(pEvent)

###############################################################################
#	HandleStartGame
#	
#	Add our own handling for the ET_START event, 
#	
#	Args:	pMultWindow	- The MultiplayerWindow
#			pEvent		- The ET_START event.
#	
#	Return:	None
###############################################################################
def HandleStartGame(pMultWindow, pEvent):
	# Let the normal handler handle it first.
	pMultWindow.CallNextHandler(pEvent)

	# Clear out the list of games from the gamespy window, and all associated
	# information
	g_pClientGamesNameMenu.KillChildren()

	if (not pMultWindow.IsDirectJoin ()):
		global g_pClientStartButton
		g_pClientStartButton.SetDisabled()

	g_pClientGamesTypeMenu.KillChildren()
	g_pClientGamesPingMenu.KillChildren()
	g_pClientGamesPlayersMenu.KillChildren()
	g_pClientGameInfoPara.SetString("")
	g_pClientGameInfoWindow.InteriorChangedSize ()
	g_pClientPlayersMenu.KillChildren()

	g_pClientCompletionText.SetString("")

	# Resize the progress bar to reflect the percentage complete
	g_pClientCompletionIcon.Resize(0.0, g_pClientCompletionIcon.GetHeight())

	# Update the displayed number to accomplish same
	g_pClientCompletionNumber.SetString("")

	
	# Once other handlers have had a chance to go, the network should be
	# setup.  Set the amount of time to wait before disconnecting, if
	# we don't hear a heartbeat.
	pNetwork = App.g_kUtopiaModule.GetNetwork()
	if pNetwork:
		if App.g_kUtopiaModule.IsHost():
			pNetwork.SetConnectionTimeout(45.0)	# 45 seconds before dropping an unresponsive player.
		else:
			pNetwork.SetConnectionTimeout(45.0)	# 45 seconds before leaving an unresponsive server.

###############################################################################
#	SetSubtitle()
#	
#	Sets the title of the lower portion of the pre-game UI and fixes up the
#	UI accordingly
#	
#	Args:	TGString*	pString		- the new subtitle
#			char*		pcFontName	- the name of the font to set as default
#									after the update
#			int			iFontSize	- the font size to set as default after
#									the update
#	
#	Return:	None
###############################################################################
def SetSubtitle(pString, pcFontName, iFontSize):
	
	# Set the font larger
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont,
				MainMenu.mainmenu.g_kSmallFontSize[MainMenu.mainmenu.g_iRes] + 1)

	# Update the subtitle
	g_pSubtitle.SetStringW(pString)
	fPosDelta = (g_pSubtitle.GetHeight() - SUBTITLE_BAR_HEIGHT) / 2.0
	g_pSubtitle.SetPosition(SUBTITLE_X_POS, SUBTITLE_BAR_Y_POS - fPosDelta)

	# Update the subtitle bar
	fSubtitleBarXPos = SUBTITLE_X_POS + g_pSubtitle.GetWidth() + SUBTITLE_BAR_X_DISTANCE
	fSubtitleBarWidth = SUBTITLE_BAR_RIGHT_EDGE - fSubtitleBarXPos
	g_pSubtitleBar.Resize(fSubtitleBarWidth, SUBTITLE_BAR_HEIGHT)
	g_pSubtitleBar.SetPosition(fSubtitleBarXPos, SUBTITLE_BAR_Y_POS)

	# Set the font smaller but still large
	App.g_kFontManager.SetDefaultFont(pcFontName, iFontSize)


###############################################################################
#	GetMissionPane()
#	
#	We have a special pane for mission-specific UI stuff to replace the Host
#	and Join panes that are available before the game begins. And the end of
#	the game it will automatically be emptied and the Host or Join pane
#	restored to visibility. Calling this function brings it up and sets
#	its title
#	
#	Args:	TGString*	pString - The subtitle; should be the name of the
#						mission
#	
#	Return:	TGPane*
###############################################################################
def GetMissionPane(pString):
	g_pClientPane.SetNotVisible(0)
	g_pHostPane.SetNotVisible(0)
	g_pMissionPane.SetVisible(0)

	SetSubtitle(pString, MainMenu.mainmenu.g_pcFlightSmallFont,
		MainMenu.mainmenu.g_kFlightSmallFontSize[MainMenu.mainmenu.g_iRes])
	
	return g_pMissionPane

###############################################################################
#	HideMissionPane()	
#	
#	Kill everything inside the mission pane, make it go away, and bring back
#	whatever was there before
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def HideMissionPane():
	g_pMissionPane.KillChildren()
	g_pMissionPane.SetNotVisible(0)

	if g_bClientUI:
		ShowClientUI(None, None)
	else:
		ShowHostUI(None, None)

	# Allow the Options Window to come up
#	App.TopWindow_GetTopWindow().AllowShowOptionsWindow(1)


def HandleSwitchRes (pObject, pEvent):
#	print ("*** switching res in multiplayermenus.py")
	# We have to rebuild the chat and status windows.

	pMultWindow = App.MultiplayerWindow_Cast (pObject)
	if (pMultWindow == None):
		return

#	print ("*** switching res in multiplayermenus.py rebuild status window")

	#Load localization database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")

	# first determine the child ordering of the status window.
	pStatusWindow = pMultWindow.GetStatusWindow ()
	iPos = pMultWindow.FindPos (pStatusWindow)

	# kill the old status window.
	pMultWindow.DeleteChild (pStatusWindow, 0)

	# Rebuild the status window.
	pPane = BuildStatusWindow(pMultWindow, pDatabase)
	pMultWindow.InsertChild (iPos, pPane, 0, 0, 0)
	pMultWindow.SetStatusWindow (pPane)
	pPane.SetNotVisible ()

	# determine the child position and state of the chat window.
	pChatWindow = pMultWindow.GetChatWindow ()
	iPos = pMultWindow.FindPos (pChatWindow)
	bVisible = pChatWindow.IsVisible ()
	bHasFocus = 0
	if (pMultWindow.GetFocus () != None):
		if (pMultWindow.GetFocus ().GetObjID () == pChatWindow.GetObjID ()):
			bHasFocus = 1

	# kill the old Chat window.
	pMultWindow.DeleteChild (pChatWindow, 0)

	# Rebuild the chat window
	pPane = BuildChatWindow (pMultWindow, pDatabase)
	pMultWindow.InsertChild (iPos, pPane, 0, 0, 0)
	pMultWindow.SetChatWindow (pPane)
	# restore status
	if (bVisible):
		pPane.SetVisible (0)
	else:
		pPane.SetNotVisible (0)

	if (bHasFocus):
		pMultWindow.SetFocus (pPane, 0)

	pMultWindow.Layout ()

	App.g_kLocalizationManager.Unload(pDatabase)

	# rebuild game over menu if necessary.
#	import Multiplayer.MissionShared
#	import Multiplayer.MissionMenusShared
#	if (Multiplayer.MissionShared.g_bGameOver == 1):
#		Multiplayer.MissionMenusShared.DoEndGameDialog (Multiplayer.MissionMenusShared.g_bResChangeRestartable, Multiplayer.MissionMenusShared.g_pResChangeReasonString, Multiplayer.MissionMenusShared.g_bResChangeDoChat)


def UpdateJunkText ():
	# Toggle the junk text as well.
	i = App.g_kSystemWrapper.GetRandomNumber (3)
	if (i == 0):
		pText = g_pJunkText5
		if (pText):
			# random string
			pcString = str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pText.SetString (pcString)
	elif (i == 1):
		pText = g_pJunkText6

		if (pText):
			# random string
			pcString = str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pText.SetString (pcString)
	else:
		pText = g_pJunkText7

		if (pText):
			# random string
			pcString = str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pcString = pcString + " "

			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))
			pcString = pcString + str (App.g_kSystemWrapper.GetRandomNumber (10))

			pText.SetString (pcString)


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
		pHostGame = pButtonPane.GetNthChild(0)
		pJoinGame = pButtonPane.GetNthChild(1)
		pExit = pButtonPane.GetNthChild(2)
		pMainMenu = pButtonPane.GetNthChild(3)

		kButtonMapping = [ pHostGame, pJoinGame, pExit, pMainMenu]
		kFocus = pButtonPane.GetFocus()
		iIndex = 0
		bSetIndex = 1

		for kObject in kButtonMapping:
			if (str(kObject) == str(kFocus)):
				iIndex = kButtonMapping.index(kObject)
				break

		if (cCharCode == App.WC_LEFT):
			if (iIndex == 0 or iIndex == 1):
				iIndex = 3
			elif (iIndex == 3):
				iIndex = 2
			else:
				iIndex = 0
			pEvent.SetHandled()
		elif (cCharCode == App.WC_RIGHT):
			if (iIndex == 0 or iIndex == 1):
				iIndex = 2
			elif (iIndex == 2):
				iIndex = 3
			else:
				iIndex = 0
			pEvent.SetHandled()
		elif (cCharCode == App.WC_UP or cCharCode == App.WC_DOWN):
			if (iIndex == 0):
				iIndex = 1
			elif (iIndex == 1):
				iIndex = 0
 			pEvent.SetHandled()
		else:
			bSetIndex = 0

		if (bSetIndex == 1):
			pButtonPane.SetFocus(kButtonMapping[iIndex])

	if (pEvent.EventHandled() == 0):
		pButtonPane.CallNextHandler(pEvent)

def DeleteMenus ():
	global g_bPreGameUIBuilt

	g_bPreGameUIBuilt = 0
	if (g_pPreGamePane):
		pParent = g_pPreGamePane.GetParent ()
		if (pParent):
			pParent.DeleteChild (g_pPreGamePane, 0)
		else:
			App.g_kRootWindow.AddChild (g_pPreGamePane, 0, 0, 0)
			App.g_kRootWindow.DeleteChild (g_pPreGamePane, 0)


		# General Pre-game UI
		global g_pMultiplayerPane
		global g_pPreGamePane 
		global g_pClientButton
		global g_pHostButton  
		global g_pExitButton  
		global g_pClientPane  
		global g_pHostPane	   
		global g_pMissionPane 
		global g_pSubtitle	   
		global g_pSubtitleBar

		# Client Pre-game UI
		global g_pClientNameInput	  
		global g_pClientPasswordInput
		global g_pClientDirectButton 
		global g_pClientDirectInput  
		global g_pClientInternetButton	 
		global g_pClientLanButton		 
		global g_pClientStartQueryButton
		global g_pClientStopQueryButton 
		global g_pClientCompletionText	 
		global g_pClientCompletionNumber
		global g_pClientCompletionIcon	 
		global g_pClientGameInfoPara	 
		global g_pClientGameInfoWindow	 
		global g_pClientPlayersWindow	 
		global g_pClientPlayersMenu	 
		global g_pClientGamesWindow	 
		global g_pClientGamesNameMenu	 
		global g_pClientGamesTypeMenu	 
		global g_pClientGamesPingMenu	 
		global g_pClientGamesPlayersMenu
		global g_pClientStartButton	 
		global g_pClientGlass			 
		global g_pClientGlass2			 

		# Host Pre-game UI
		global g_pHostGameNameInput	 
		global g_pHostPlayerNameCaption 
		global g_pHostPlayerNameInput	 
		global g_pHostPasswordInput	 
		global g_pHostDedicatedButton	 
		global g_pHostInternetButton	 
		global g_pHostLanButton		 
		global g_pHostTextArea			 
		global g_pHostGamesMenu		 
		global g_pHostStartButton		 
		global g_pMainMenuButton		 

		global g_pJunkText5
		global g_pJunkText6
		global g_pJunkText7

		# General Pre-game UI
		g_pMultiplayerPane			= None
		g_pPreGamePane				= None
		g_pClientButton				= None
		g_pHostButton				= None
		g_pExitButton				= None
		g_pClientPane				= None
		g_pHostPane					= None
		g_pMissionPane				= None
		g_pSubtitle					= None
		g_pSubtitleBar				= None

		# Client Pre-game UI
		g_pClientNameInput			= None
		g_pClientPasswordInput		= None
		g_pClientDirectButton		= None
		g_pClientDirectInput		= None
		g_pClientInternetButton		= None
		g_pClientLanButton			= None
		g_pClientStartQueryButton	= None
		g_pClientStopQueryButton	= None
		g_pClientCompletionText		= None
		g_pClientCompletionNumber	= None
		g_pClientCompletionIcon		= None
		g_pClientGameInfoPara		= None
		g_pClientGameInfoWindow		= None
		g_pClientPlayersWindow		= None
		g_pClientPlayersMenu		= None
		g_pClientGamesWindow		= None
		g_pClientGamesNameMenu		= None
		g_pClientGamesTypeMenu		= None
		g_pClientGamesPingMenu		= None
		g_pClientGamesPlayersMenu	= None
		g_pClientStartButton		= None
		g_pClientGlass				= None
		g_pClientGlass2				= None

		# Host Pre-game UI
		g_pHostGameNameInput		= None
		g_pHostPlayerNameCaption	= None
		g_pHostPlayerNameInput		= None
		g_pHostPasswordInput		= None
		g_pHostDedicatedButton		= None
		g_pHostInternetButton		= None
		g_pHostLanButton			= None
		g_pHostTextArea				= None
		g_pHostGamesMenu			= None
		g_pHostStartButton			= None
		g_pMainMenuButton			= None

		g_pJunkText5 = None
		g_pJunkText6 = None
		g_pJunkText7 = None

def ResetFlags ():
	global g_bClientUI
	g_bClientUI = 1 # Were we last looking at the host or client UI?

	global g_bEventHandlersAdded
	g_bEventHandlersAdded = 0

