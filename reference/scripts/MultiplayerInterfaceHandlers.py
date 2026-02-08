###############################################################################
#	Filename:	MultiplayerInterfaceHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	User interface handlers for the Multiplayer interface.
#	
#	Created:	1/25/00		- Alby
###############################################################################
import App
#kDebugObj = App.CPyDebug()

###############################################################################
#	Initialize()
#	
#	Setup all the event handlers we'll need to handle
#	the events we need to handle.  :P
#	
#	Args:	pWindow	- The MapWindow whose interface we're handling.
#	
#	Return:	none
###############################################################################
def Initialize(pWindow):
#	print ("Multiplayer interface initialize...")
	# Setup our event handlers.
	# A lot of our handling can be done by functions that
	# already exist in the tactical interface handlers.
	lEventHandlerMap = (
		(App.ET_INPUT_TOGGLE_SCORE_WINDOW,	__name__ + ".ToggleScoreWindow"),
		(App.ET_INPUT_TOGGLE_CHAT_WINDOW,	__name__ + ".ToggleChatWindow"),
		)

	for eType, sFunc in lEventHandlerMap:
		# Add instance handlers for these events.
		pWindow.AddPythonFuncHandlerForInstance(eType, sFunc)
	# Done

	
###############################################################################
#	HandleMouse()
#	
#	Handles mouse events.
#	
#	Args:	pWindow		- the window object that received this message
#			TGMouseEvent	pEvent		- mouse event
#	
#	Return:	none
###############################################################################
def HandleMouse(pWindow, pEvent):
	# If it's a button event, we have another function for that..
	if pEvent.IsButtonEvent():
		HandleMouseButtons(pEvent)
	else:
		# Not a button event.  Just a movement one.
		HandleMouseMovement(pEvent)

	if not pEvent.EventHandled():
		pWindow.CallNextHandler(pEvent)

###############################################################################
#	HandleKeyboard()
#	
#	Handles keyboard events.
#	
#	Args:	pWindow		- The window that received this event.
#			pEvent	- the TGKeyboardEvent
#	
#	Return:	none
###############################################################################
def HandleKeyboard(pWindow, pEvent):
	"Handle keyboard input for this game mode."

	if (not pEvent.EventHandled()):
		if (App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pWindow)):
			pEvent.SetHandled()

	# If the key wasn't caught by anything above, pass it on like normal
	# by calling our superclass method
	if (not pEvent.EventHandled()):
		pWindow.CallNextHandler(pEvent)



#	# Trigger events from the input..
#	App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pWindow)
#
#	if not pEvent.EventHandled():
#		pWindow.CallNextHandler(pEvent)

###############################################################################
#	HandleMouseButtons()
#	
#	Handles mouse buttons.
#	
#	Args:	TGMouseEvent	pEvent		- the mouse event
#	
#	Return:	none
###############################################################################
def HandleMouseButtons(pEvent):
	# We'll do something once we decide what to do..
#	pEvent.SetHandled()
	return

###############################################################################
#	HandleMouseMovement()
#	
#	Handles mouse movement.
#	
#	Args:	TGMouseEvent	pEvent		- the mouse event
#	
#	Return:	none
###############################################################################
def HandleMouseMovement(pEvent):
	# We'll do something once we decide what to do..
#	pEvent.SetHandled()
	return

def ToggleScoreWindow(pObject, pEvent):
	# Make sure there's a game and it's started.
	pGame = App.Game_GetCurrentGame ()
	import Multiplayer.MissionShared
	if (pGame and not Multiplayer.MissionShared.g_bGameOver):
		if (pGame.IsTypeOf (App.CT_MULTIPLAYER_GAME)):
			# Okay, we've got a multiplayer game

			# Get the mission name
			pcMissionName = App.g_kVarManager.GetStringVariable ("Multiplayer", "Mission")

			# Call the function in the mission script to bring up the score window.
			pModule = __import__(pcMissionName + "Menus")

			pModule.DoScoreWindow ()
	
	pObject.CallNextHandler(pEvent)



def ToggleChatWindow (pObject, pEvent):
	# Make sure there's a game and it's started.
	pGame = App.Game_GetCurrentGame ()
	import Multiplayer.MissionShared
	if (pGame and not Multiplayer.MissionShared.g_bGameOver):
		if (pGame.IsTypeOf (App.CT_MULTIPLAYER_GAME)):
			# Okay, we've got a multiplayer game
			# Get the multiplayer window and toggle the chat window.
			pTopWindow = App.TopWindow_GetTopWindow()
			pMultWindow = App.MultiplayerWindow_Cast (pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))

			pChatWindow = pMultWindow.GetChatWindow ()
			if (pChatWindow):
				pPane = App.TGPane_Cast (pChatWindow.GetNthChild (0))
				pText = App.TGParagraph_Cast (pPane.GetNthChild (1))

				# change the text depending on regular chat or team chat.
				pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")

				if (pEvent.GetBool () == 0):
					pText.SetStringW (pDatabase.GetString ("Chat"))
					pMultWindow.SetTeamChat (0)
				else:
					pText.SetStringW (pDatabase.GetString ("Team Chat"))
					pMultWindow.SetTeamChat (1)

				App.g_kLocalizationManager.Unload (pDatabase)

				pText.Layout ()

			pMultWindow.ToggleChatWindow ()

			pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
			if pTCW:
				pTCW.Layout()

			pEvent.SetDestination (None)
			return

	pObject.CallNextHandler(pEvent)

