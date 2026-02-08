###############################################################################
#	Filename:	CharacterMenuInterfaceHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	User interface handlers for CharacterMenuWindow.
#	
#	Created:	5/16/01 -	KDeus
###############################################################################
import App
import TacticalInterfaceHandlers
import Camera
import MissionLib

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " module...")

###############################################################################
#	Initialize()
#	
#	Setup all the event handlers we'll need to handle
#	the events we need to handle.  :P
#	
#	Args:	pWindow	- The TacticalWindow whose interface we're handling.
#	
#	Return:	none
###############################################################################
def Initialize(pWindow):
	# Setup our event handlers.
	# Some of our handling can be done by functions that
	# already exist in the tactical interface handlers.
	lEventHandlerMap = (
		(App.ET_INPUT_ZOOM,						"BridgeHandlers.ZoomViewscreen"),
		(App.ET_SET_ALERT_LEVEL,				"BridgeHandlers.SetAlertLevel"),
		(App.ET_INPUT_TALK_TO_HELM,				"BridgeHandlers.TalkToHelm"), 
		(App.ET_INPUT_TALK_TO_TACTICAL,			"BridgeHandlers.TalkToTactical"), 
		(App.ET_INPUT_TALK_TO_XO,				"BridgeHandlers.TalkToXO"), 
		(App.ET_INPUT_TALK_TO_SCIENCE,			"BridgeHandlers.TalkToScience"), 
		(App.ET_INPUT_TALK_TO_ENGINEERING,		"BridgeHandlers.TalkToEngineering"), 
		(App.ET_INPUT_TALK_TO_GUEST,			"BridgeHandlers.TalkToGuest"), 

		(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	"TacticalInterfaceHandlers.ToggleCinematicMode"), 
		(App.ET_INPUT_TOGGLE_MAP_MODE,			"TacticalInterfaceHandlers.ToggleMapMode"), 
		(App.ET_INPUT_SKIP_EVENTS,				"TacticalInterfaceHandlers.SkipEvents"),
		(App.ET_INPUT_FIRE_PRIMARY,				"TacticalInterfaceHandlers.FirePrimaryWeapons"),
		(App.ET_INPUT_FIRE_SECONDARY,			"TacticalInterfaceHandlers.FireSecondaryWeapons"),
		(App.ET_INPUT_TARGET_NEXT,				"TacticalInterfaceHandlers.TargetNext"),
		(App.ET_INPUT_TARGET_PREV,				"TacticalInterfaceHandlers.TargetPrev"),
		)

	for eType, sFunc in lEventHandlerMap:
		# Add instance handlers for these events.
		pWindow.AddPythonFuncHandlerForInstance(eType, sFunc)
	# Done
#	debug("Finished init on character menu handlers")

###############################################################################
#	HandleMouse()
#	
#	Handles mouse events. This is registered as an event handler for the
#	BridgeWindow class.
#	
#	Args:	BridgeWindow	pBridge	- the bridge object
#			TGMouseEvent	pEvent	- mouse event
#	
#	Return:	none
##############################################################################
def HandleMouse(pBridge, pEvent):
	"Handle mouse events for the command interface"

	# Pass event to next handler.
	pBridge.CallNextHandler(pEvent)

	if (pEvent.EventHandled () == 0):
		# Check if it's a button event..
		if pEvent.IsButtonEvent():
			# Yep, it's a button event.
			if (HandleMouseButtons(pBridge, pEvent) == 1):
				pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
				pTCW.SetIgnoreNextMouseKeyEvent(1)
				pEvent.SetHandled()

###############################################################################
#	HandleKeyboard()
#	
#	Handles keyboard events. This is registered as an event handler for
#	the BridgeWindow class.
#	
#	Args:	pMenu	- the CharacterMenuWindow object
#			pEvent	- keyboard event
#	
#	Return:	none
###############################################################################
def HandleKeyboard(pMenu, pEvent):
	"Handle keyboard events for the command interface"

	# Check to make sure instance handler didn't handle the key already
	if (pEvent.EventHandled() == 0):
		# Take care of the keyboard input..
		App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pMenu)

	# Check to make sure instance handler didn't handle the key already
	if (pEvent.EventHandled() == 0):
		# Special handling: pass to either tactical or bridge windows if either
		# is visible.
		pWindow = None
		pTop = App.TopWindow_GetTopWindow()

		if (pTop.IsBridgeVisible()):
			pWindow = App.BridgeWindow_Cast(pTop.FindMainWindow(App.MWT_BRIDGE))
		elif (pTop.IsTacticalVisible()):
			pWindow = App.TacticalWindow_Cast(pTop.FindMainWindow(App.MWT_TACTICAL))
		
		#if (pWindow != None):
		#	debug("sending off event again to " + str(pWindow))
		#	pEvent2 = pEvent.Duplicate()
		#	pEvent2.SetDestination(pWindow)
		#	App.g_kEventManager.AddEvent(pEvent2)

		# Check to see if children can handle the event
		pMenu.CallNextHandler(pEvent)

###############################################################################
#	HandleMouseButtons()
#	
#	Handles mouse buttons in the command interface.
#	
#	Args:	BridgeWindow	pBridge	- the bridge object
#			TGMouseEvent	pEvent	- mouse event
#	
#	Return:	none
###############################################################################
def HandleMouseButtons(pBridge, pEvent):
	"Handles mouse buttons for the Bridge"
	fCurrentTime = App.g_kUtopiaModule.GetGameTime()
	fXPos = pEvent.GetX()
	fYPos = pEvent.GetY()

	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalMenu = pTacticalControlWindow.GetTacticalMenu()
	pTopWindow = App.TopWindow_GetTopWindow()

	# Don't handle mouse clicks while in tactical mode.
	if (pTopWindow.IsTacticalVisible()):
		return 0

	if (pEvent.GetButtonNum() & App.TGMouseEvent.MEF_BUTTON_LEFT):
		if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
			# If the mouse cursor is visible, it means character menus
			# are visible and a character is turned.  Drop the menu and
			# turn the character back.
			if (App.STTopLevelMenu_GetOpenMenu()):
				DropMenusTurnBack()
				return 1

			# Mouse cursor isn't visible.
			pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet ("bridge"))
			if (pSet):
				if not (App.STTopLevelMenu_GetOpenMenu()):		# Nobody selected state
					if (pSet != None):
						# go through objects to see if any picked.  Middle of the screen is where
						# the pick is done.
						pSet.StartPick (.5, .5)

						bContinue = 1
						fDotProd = -1
						pBestCharacter = App.CharacterClass_CreateNull()
						pViewscreen = App.ViewScreenObject_CreateNull()
						
						while (bContinue):
							pObject = pSet.GetPickedObject()
							if (pObject == None):
								bContinue = 0
							else:
								pCharacter = App.CharacterClass_Cast(pObject)
								if (pCharacter != None):
									fNextProd = pSet.GetDotProductToObject(pCharacter)
									if (fNextProd >= fDotProd):
										fDotProd = fNextProd
										pBestCharacter = pCharacter
										pViewscreen = App.ViewScreenObject_CreateNull()

								pTempViewscreen = App.ViewScreenObject_Cast(pObject)
								if (pTempViewscreen != None):
									fNextProd = pSet.GetDotProductToObject(pTempViewscreen)
									if (fNextProd >= fDotProd):
										fDotProd = fNextProd
										pViewscreen = pTempViewscreen
										fBestCharacter = App.CharacterClass_CreateNull()


						if (pBestCharacter != None):
							pCharacter = pBestCharacter
							if (pCharacter != None):
								# If they don't have a menu, just say nothing to add
								if (pCharacter.GetMenu() == None):
									pass
									#pCharacter.SpeakLine(pCharacter.GetDatabase(), pCharacter.GetCharacterName() + "NothingToAdd")
								# If they are able to bring up their menu, zoom and turn on mouse
								if (pCharacter.MenuUp()):
									if (pCharacter.GetCharacterName()):
										pDatabase = pCharacter.GetDatabase()

										pCharacterAction = App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, pCharacter.GetCharacterName() + "Sir" + str(App.g_kSystemWrapper.GetRandomNumber(5)+1), "Captain", 0, pDatabase, App.CSP_SPONTANEOUS)
										pCharacterAction.Play()

										pTopWindow = App.TopWindow_GetTopWindow()
										pSubtitle = App.SubtitleWindow_Cast(pTopWindow.FindMainWindow(App.MWT_SUBTITLE))

										if (pTopWindow.IsBridgeVisible()):
											if (pCharacter.GetName() == "Tactical"):
													pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_FELIX)
											else:
													pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_NONFELIX)
										else:
											pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_TACTICAL)

				# This will tell our caller that we handled this mouse event.
				return 1
		
	if (pEvent.GetButtonNum() & App.TGMouseEvent.MEF_BUTTON_RIGHT):
		if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
			DropMenusTurnBack()

			return 1

	# Event not handled
	return 0


###############################################################################
#	DropMenusTurnBack()
#	
#	Drops the character menus and turns the characters to face front.
#	This will also drop the viewscreen menu and set the viewscreen back to
#	space if a menu is currently up.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def DropMenusTurnBack():
	pTop = App.TopWindow_GetTopWindow()
	pTacticalControls = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalMenu = pTacticalControls.GetTacticalMenu()

	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet ("bridge"))
	if (pSet):
		# Index through ALL objects on bridge set, if they're characters, drop their menus
		pObject = pSet.GetFirstObject()
		pFirstObject = pObject
		while not (App.IsNull(pObject)):
			pCharacter = App.CharacterClass_Cast(pObject)
			pObject = pSet.GetNextObject(pObject.GetObjID())

			if (pObject.GetObjID() == pFirstObject.GetObjID()):
				pObject = App.CharacterClass_CreateNull()

			if (pCharacter):
				if (pCharacter.IsMenuUp()):
					# If it's the tactical character, and the
					# player is in the tactical view, then don't drop the menu.
					if (str(pCharacter.GetMenu()) == str(pTacticalMenu)) and (pTop.IsTacticalVisible()):
						pass
					else:
						pCharacter.MenuDown()
						if (pCharacter.IsTurned()):
							pCharacter.TurnBack()

		pViewScreen = pSet.GetViewScreen()
		if(pViewScreen):
			if(pViewScreen.IsMenuUp()):
				pViewScreen.MenuDown()

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacticalControlWindow.GetOpenMenu()
	if (pMenu):
		pMenu.SetNotVisible()

	fCurrentTime = App.g_kUtopiaModule.GetGameTime()
	pCamera = App.ZoomCameraObjectClass_GetObject (pSet, "maincamera")
	if (pCamera):
		if (pCamera.IsZoomed()):
			pCamera.ToggleZoom (fCurrentTime)

	#Move subtitle window back to its bridge position
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))

	if (pTop.IsBridgeVisible()):
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_NONFELIX)
	else:
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_TACTICAL)


###############################################################################
#	Viewscreen angle functions.
#	
#	Set the viewscreen to face the target or whatever direction
#	is requested...  If the viewscreen is facing the target, its
#	backup mode (in case the target disappears) is set to the last
#	directional mode.
#	
#	Args:	pObject	- Unused
#			pEvent	- Unused
#	
#	Return:	None
###############################################################################
def ViewscreenTarget(pObject, pEvent):
#	debug("Viewscreen Target")
	# Get the viewscreen camera.
	import MissionLib
	pCamera = MissionLib.GetViewScreenCamera()
	if pCamera:
		# Got the camera.
		# First, if we're currently in a directional mode, set this
		# directional mode as the backup mode to the target view.
		pCurrentMode = pCamera.GetCurrentCameraMode(0)

		if pCurrentMode.GetName() in [
			"ViewscreenForward", "ViewscreenLeft", "ViewscreenRight", 
			"ViewscreenBack", "ViewscreenUp", "ViewscreenDown" ]:

			# It's one of the directional cameras.
			pCamera.AddModeHierarchy("ViewscreenZoomTarget", pCurrentMode.GetName())

		# Change the current mode to be the ViewscreenZoomTarget mode.
		if pCurrentMode.GetName() != "ViewscreenZoomTarget":
			pTargetMode = pCamera.GetNamedCameraMode("ViewscreenZoomTarget")
			if pTargetMode:
				pCamera.AddModeHierarchy("InvalidViewscreen", "ViewscreenZoomTarget")

	pObject.CallNextHandler(pEvent)

def ViewscreenForward(pObject, pEvent):
	ViewscreenDirection("Forward")
	pObject.CallNextHandler(pEvent)

def ViewscreenBackward(pObject, pEvent):
	ViewscreenDirection("Back")
	pObject.CallNextHandler(pEvent)

def ViewscreenLeft(pObject, pEvent):
	ViewscreenDirection("Left")
	pObject.CallNextHandler(pEvent)

def ViewscreenRight(pObject, pEvent):
	ViewscreenDirection("Right")
	pObject.CallNextHandler(pEvent)

def ViewscreenUp(pObject, pEvent):
	ViewscreenDirection("Up")
	pObject.CallNextHandler(pEvent)

def ViewscreenDown(pObject, pEvent):
	ViewscreenDirection("Down")
	pObject.CallNextHandler(pEvent)

def ViewscreenDirection(sDirection):
	sCamera = "Viewscreen%s" % sDirection
	import MissionLib
	pPlayer = App.Game_GetCurrentPlayer()
	pCamera = MissionLib.GetViewScreenCamera()
	if pCamera and pPlayer:
		pCamera.AddModeHierarchy("InvalidViewscreen", sCamera)

