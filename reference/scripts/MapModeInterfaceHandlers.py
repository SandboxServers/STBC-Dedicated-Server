###############################################################################
#	Filename:	TacticalInterfaceHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	User interface handlers for the Tactical interface.
#	
#	Created:	3/21/00 -	Erik Novales
###############################################################################
import App
import MissionLib
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
	# Setup our event handlers.
	# A lot of our handling can be done by functions that
	# already exist in the tactical interface handlers.
	lEventHandlerMap = (
		(App.ET_INPUT_TARGET_NEXT,				"TacticalInterfaceHandlers.TargetNext"),
		(App.ET_INPUT_TARGET_PREV,				"TacticalInterfaceHandlers.TargetPrev"),
		(App.ET_INPUT_TARGET_NEAREST,			"TacticalInterfaceHandlers.TargetNearest"),
		(App.ET_INPUT_TARGET_NEXT_ENEMY,		"TacticalInterfaceHandlers.TargetNextEnemy"),
		(App.ET_INPUT_TARGET_TARGETS_ATTACKER,	"TacticalInterfaceHandlers.TargetTargetsAttacker"),
		(App.ET_INPUT_TARGET_NEXT_NAVPOINT,		"TacticalInterfaceHandlers.TargetNextNavPoint"),
		(App.ET_INPUT_TARGET_NEXT_PLANET,		"TacticalInterfaceHandlers.TargetNextPlanet"),

		(App.ET_INPUT_ZOOM,						"TacticalInterfaceHandlers.Zoom"),
		(App.ET_INPUT_TOGGLE_MAP_MODE,			"TacticalInterfaceHandlers.ToggleMapMode"),
		(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	"TacticalInterfaceHandlers.ToggleCinematicMode"),
		(App.ET_INPUT_SET_IMPULSE,				"TacticalInterfaceHandlers.SetImpulse"),
		(App.ET_INPUT_FIRE_TERTIARY,			"TacticalInterfaceHandlers.FireTertiaryWeapons"),
		(App.ET_INPUT_FIRE_SECONDARY,			"TacticalInterfaceHandlers.FireSecondaryWeapons"),
		(App.ET_INPUT_FIRE_PRIMARY,				"TacticalInterfaceHandlers.FirePrimaryWeapons"),
		(App.ET_INPUT_TURN_LEFT,				"TacticalInterfaceHandlers.TurnLeft"),
		(App.ET_INPUT_TURN_RIGHT,				"TacticalInterfaceHandlers.TurnRight"),
		(App.ET_INPUT_TURN_UP,					"TacticalInterfaceHandlers.TurnUp"),
		(App.ET_INPUT_TURN_DOWN,				"TacticalInterfaceHandlers.TurnDown"),
		(App.ET_INPUT_ROLL_LEFT,				"TacticalInterfaceHandlers.RollLeft"),
		(App.ET_INPUT_ROLL_RIGHT,				"TacticalInterfaceHandlers.RollRight"),
		(App.ET_INPUT_SKIP_EVENTS,				"TacticalInterfaceHandlers.SkipEvents"),
		(App.ET_INPUT_DEBUG_KILL_TARGET,		"TacticalInterfaceHandlers.KillTarget"),
		(App.ET_INPUT_DEBUG_QUICK_REPAIR,		"TacticalInterfaceHandlers.RepairShip"),
		(App.ET_INPUT_DEBUG_GOD_MODE,			"TacticalInterfaceHandlers.ToggleGodMode"),

		(App.ET_INPUT_TALK_TO_TACTICAL,			"BridgeHandlers.TalkToTactical"),
		(App.ET_INPUT_TALK_TO_HELM,				"BridgeHandlers.TalkToHelm"), 
		(App.ET_INPUT_TALK_TO_XO,				"BridgeHandlers.TalkToXO"), 
		(App.ET_INPUT_TALK_TO_SCIENCE,			"BridgeHandlers.TalkToScience"), 
		(App.ET_INPUT_TALK_TO_ENGINEERING,		"BridgeHandlers.TalkToEngineering"), 
		(App.ET_INPUT_TALK_TO_GUEST,			"BridgeHandlers.TalkToGuest"), 
		(App.ET_SET_ALERT_LEVEL,				"BridgeHandlers.SetAlertLevel"),
		(App.ET_QUICK_SAVE,						"BridgeHandlers.QuickSave"),
		(App.ET_QUICK_LOAD,						"BridgeHandlers.QuickLoad"),

		(App.ET_INPUT_TOGGLE_SCORE_WINDOW,		"MultiplayerInterfaceHandlers.ToggleScoreWindow"),
		(App.ET_INPUT_TOGGLE_CHAT_WINDOW,		"MultiplayerInterfaceHandlers.ToggleChatWindow"),
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
		if (HandleMouseButtons(pEvent)):
			pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
			pTCW.SetIgnoreNextMouseKeyEvent(1)
			pEvent.SetHandled()

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

	if (pEvent.GetUnicode() == App.WC_LBUTTON or pEvent.GetUnicode() == App.WC_RBUTTON):
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if (pTCW.IgnoreNextMouseKeyEvent()):
	#		pTCW.SetIgnoreNextMouseKeyEvent(0)
			pEvent.SetHandled()

	# Trigger events from the input..
	App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pWindow)

	if not pEvent.EventHandled():
		pWindow.CallNextHandler(pEvent)

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
	# Left-click fires primary weapons, 
	# right-click fires secondary weapons, middle-click fires tertiary.
	if (pEvent.GetButtonNum() == App.TGMouseEvent.MEF_BUTTON_LEFT):
		pOutgoingEvent = App.TGBoolEvent_Create()
		pOutgoingEvent.SetDestination(pEvent.GetDestination())
		pOutgoingEvent.SetEventType(App.ET_INPUT_FIRE_PRIMARY)

		if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
			pOutgoingEvent.SetBool(1)
		else:
			pOutgoingEvent.SetBool(0)

		App.g_kEventManager.AddEvent(pOutgoingEvent)

	elif (pEvent.GetButtonNum() == App.TGMouseEvent.MEF_BUTTON_RIGHT):
		pOutgoingEvent = App.TGBoolEvent_Create()
		pOutgoingEvent.SetDestination(pEvent.GetDestination())
		pOutgoingEvent.SetEventType(App.ET_INPUT_FIRE_SECONDARY)

		if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
			pOutgoingEvent.SetBool(1)
		else:
			pOutgoingEvent.SetBool(0)

		App.g_kEventManager.AddEvent(pOutgoingEvent)

	elif (pEvent.GetButtonNum() == App.TGMouseEvent.MEF_BUTTON_MIDDLE):
		pOutgoingEvent = App.TGBoolEvent_Create()
		pOutgoingEvent.SetDestination(pEvent.GetDestination())
		pOutgoingEvent.SetEventType(App.ET_INPUT_FIRE_TERTIARY)

		if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
			pOutgoingEvent.SetBool(1)
		else:
			pOutgoingEvent.SetBool(0)

		App.g_kEventManager.AddEvent(pOutgoingEvent)

	pEvent.SetHandled()

	return 1
