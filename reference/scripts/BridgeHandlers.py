###############################################################################
#	Filename:	BridgeHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	User interface handlers for the command interface.
#	
#	Created:	3/21/00 -	Erik Novales
###############################################################################
import App
import TacticalInterfaceHandlers
import Camera
import MissionLib
import Tactical.Interface.TacticalControlWindow

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
		(App.ET_INPUT_ALLOW_CAMERA_ROTATION,	__name__ + ".ToggleCameraRotation"),
		(App.ET_INPUT_VIEWSCREEN_TARGET,		__name__ + ".ViewscreenTarget"),
		(App.ET_INPUT_VIEWSCREEN_FORWARD,		__name__ + ".ViewscreenForward"),
		(App.ET_INPUT_VIEWSCREEN_LEFT,			__name__ + ".ViewscreenLeft"),
		(App.ET_INPUT_VIEWSCREEN_RIGHT,			__name__ + ".ViewscreenRight"),
		(App.ET_INPUT_VIEWSCREEN_BACKWARD,		__name__ + ".ViewscreenBackward"),
		(App.ET_INPUT_VIEWSCREEN_UP,			__name__ + ".ViewscreenUp"),
		(App.ET_INPUT_VIEWSCREEN_DOWN,			__name__ + ".ViewscreenDown"),
		(App.ET_INPUT_ZOOM,						__name__ + ".ZoomViewscreen"),
		(App.ET_SET_ALERT_LEVEL,				__name__ + ".SetAlertLevel"),
		(App.ET_INPUT_INTERCEPT,				__name__ + ".InterceptTarget"),
		(App.ET_QUICK_SAVE,						__name__ + ".QuickSave"),
		(App.ET_QUICK_LOAD,						__name__ + ".QuickLoad"),
		(App.ET_INPUT_TALK_TO_HELM,				__name__ + ".TalkToHelm"), 
		(App.ET_INPUT_TALK_TO_TACTICAL,			__name__ + ".TalkToTactical"), 
		(App.ET_INPUT_TALK_TO_XO,				__name__ + ".TalkToXO"), 
		(App.ET_INPUT_TALK_TO_SCIENCE,			__name__ + ".TalkToScience"), 
		(App.ET_INPUT_TALK_TO_ENGINEERING,		__name__ + ".TalkToEngineering"), 
		(App.ET_INPUT_TALK_TO_GUEST,			__name__ + ".TalkToGuest"), 

		(App.ET_INPUT_DEBUG_LOAD_QUANTUMS,		"TacticalInterfaceHandlers.LoadQuantums"),

		(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	"TacticalInterfaceHandlers.ToggleCinematicMode"), 
		(App.ET_INPUT_TOGGLE_MAP_MODE,			"TacticalInterfaceHandlers.ToggleMapMode"), 
		(App.ET_INPUT_SKIP_EVENTS,				"TacticalInterfaceHandlers.SkipEvents"),
		(App.ET_INPUT_FIRE_PRIMARY,				"TacticalInterfaceHandlers.FirePrimaryWeapons"),
		(App.ET_INPUT_FIRE_SECONDARY,			"TacticalInterfaceHandlers.FireSecondaryWeapons"),
		(App.ET_INPUT_TARGET_NEXT,				"TacticalInterfaceHandlers.TargetNext"),
		(App.ET_INPUT_TARGET_PREV,				"TacticalInterfaceHandlers.TargetPrev"),
		(App.ET_INPUT_TARGET_NEAREST,			"TacticalInterfaceHandlers.TargetNearest"),
		(App.ET_INPUT_TARGET_NEXT_ENEMY,		"TacticalInterfaceHandlers.TargetNextEnemy"),
		(App.ET_INPUT_TARGET_TARGETS_ATTACKER,	"TacticalInterfaceHandlers.TargetTargetsAttacker"),
		(App.ET_INPUT_TARGET_NEXT_NAVPOINT,		"TacticalInterfaceHandlers.TargetNextNavPoint"),
		(App.ET_INPUT_TARGET_NEXT_PLANET,		"TacticalInterfaceHandlers.TargetNextPlanet"),

		(App.ET_OTHER_BEAM_TOGGLE_CLICKED,		__name__ + ".ToggleTractorBeam"),
		(App.ET_OTHER_CLOAK_TOGGLE_CLICKED,		__name__ + ".ToggleCloak")
		)

	for eType, sFunc in lEventHandlerMap:
		# Add instance handlers for these events.
		pWindow.AddPythonFuncHandlerForInstance(eType, sFunc)

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_GAME_SAVED, pWindow, __name__ + ".ShowSaved")

	pTop = App.TopWindow_GetTopWindow()

	# Debugging ONLY
	App.g_kKeyboardBinding.BindKey(App.WC_CTRL_F7, App.TGKeyboardEvent.KS_KEYDOWN, App.ET_QUICK_SAVE, 0, 0)
	App.g_kKeyboardBinding.BindKey(App.WC_CTRL_F8, App.TGKeyboardEvent.KS_KEYDOWN, App.ET_QUICK_LOAD, 0, 0)

	pTop.AddPythonFuncHandlerForInstance(App.ET_INPUT_TOGGLE_CURSOR, __name__ + ".ShowMouse")

	# Done
#	debug("Finished init on Bridge window handlers")

def ShowMouse(pObject, pEvent):
	if not (pEvent):
		return

	if (pEvent.GetInt() == -1):
		pObject.CallNextHandler(pEvent)
		return

	if (pEvent.GetInt() == 0):
		pObject.CallNextHandler(pEvent)
		return

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = None
	if (pEvent.GetInt() == 1):
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))
	if (pEvent.GetInt() == 2):
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Tactical"))
	if (pEvent.GetInt() == 3):
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Commander"))
	if (pEvent.GetInt() == 4):
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))
	if (pEvent.GetInt() == 5):
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Engineering"))
	
	App.g_kLocalizationManager.Unload(pDatabase)
	if (pMenu):
		pMenu.SetEnabled()
		pMenu.SetVisible()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	ToggleTractorBeam()
#	
#	Toggles the tractor beam
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ToggleTractorBeam(pObject, pEvent):
	pObject.CallNextHandler(pEvent)

	pWeapons = App.TacWeaponsCtrl_GetTacWeaponsCtrl()

	pToggle = pWeapons.GetBeamToggle()
	# Not all ships have Tractor beam, I suppose...
	if (pToggle == None):
		return

	if (pToggle.GetState() == 0):
		pToggle.SetState(1)
	else:
		pToggle.SetState(0)

	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(App.ET_OTHER_BEAM_TOGGLE_CLICKED)
	pEvent.SetDestination(pWeapons)
	App.g_kEventManager.AddEvent(pEvent)

###############################################################################
#	ToggleCloak()
#	
#	Toggles the cloaking device
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ToggleCloak(pObject, pEvent):
	pObject.CallNextHandler(pEvent)

	pWeapons = App.TacWeaponsCtrl_GetTacWeaponsCtrl()

	pToggle = pWeapons.GetCloakToggle()
	# Not all ships can cloak...
	if (pToggle == None):
		return

	if (pToggle.GetState() == 0):
		pToggle.SetState(1)
	else:
		pToggle.SetState(0)

	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(App.ET_OTHER_CLOAK_TOGGLE_CLICKED)
	pEvent.SetDestination(pWeapons)
	App.g_kEventManager.AddEvent(pEvent)

###############################################################################
#	SetAlertLevel()
#	
#	Forward our alert level event on to Saffi's menu
#	
#	Args:	TGObject	pObject	- our bridge window
#			TGIntEvent	pEvent	- int is EST_ALERT_RED, EST_ALERT_YELLOW or
#									EST_ALERT_GREEN
#	
#	Return:	none
###############################################################################
def SetAlertLevel(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	pSaffi = App.CharacterClass_GetObject(pSet, "XO")
	
	pMenu = None

	if (pSaffi):
		pMenu = pSaffi.GetMenu()
	else:
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("XO"))
		App.g_kLocalizationManager.Unload(pDatabase)

	pEvent.SetDestination(pMenu)
	pMenu.ProcessEvent(pEvent)	# forward this on to Saffi's menu

	pObject.CallNextHandler(pEvent)

###############################################################################
#	InterceptTarget
#	
#	Shortcut for pressing Helm's "Intercept" button.
#	
#	Args:	pObject	- The window receiving this event.
#			pEvent	- The ET_INPUT_INTERCEPT event.
#	
#	Return:	None
###############################################################################
def InterceptTarget(pObject, pEvent):
	# Get the helm menu...
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))
	if pHelmMenu:
		# Get the Intercept button.  If it's enabled, send an event
		# to the helm menu.
		pIntercept = pHelmMenu.GetButtonW(pDatabase.GetString("Intercept"))
		if pIntercept and pIntercept.IsEnabled():
			# Intercept button is available.  Create the event that would be
			# created if the user clicked on the button.
			pIntercept.SendActivationEvent()
	App.g_kLocalizationManager.Unload(pDatabase)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	QuickSave()
#	
#	Save your current game to "QuickSav.BCS"
#	
#	Args:	pObject, pEvent	- event destination and object
#	
#	Return:	none
###############################################################################
def QuickSave(pObject, pEvent):
	if (App.g_kUtopiaModule.IsMultiplayer()):
		pObject.CallNextHandler(pEvent)
		return

	if (App.g_kUtopiaModule.GetTestMenuState () < 2):
		return

	App.g_kUtopiaModule.SaveToFile("saves\\QuickSav.BCS")
	pObject.CallNextHandler(pEvent)

###############################################################################
#	QuickLoad()
#	
#	Load a game from "QuickSav.BCS"
#	
#	Args:	pObject, pEvent	- event destination and object
#	
#	Return:	none
###############################################################################
def QuickLoad(pObject, pEvent):
	if (App.g_kUtopiaModule.IsMultiplayer()):
		pObject.CallNextHandler(pEvent)
		return

	if (App.g_kUtopiaModule.GetTestMenuState () < 2):
		return

	App.g_kUtopiaModule.LoadFromFile("saves\\QuickSav.BCS")
	pObject.CallNextHandler(pEvent)

###############################################################################
#	GotFocus()
#	
#	The bridge has the focus again (after something else took it away).
#	Check if any of the stations were busy controlling the ship with AI.
#	If so, make sure they resume their AI.
#	
#	Args:	pBridgeWindow	- The bridge window.  Unused.
#			bLayout			- false to avoid calling Layout()
#	
#	Return:	None
###############################################################################
def GotFocus(pBridgeWindow, bLayout):
	pPlayer = App.Game_GetCurrentPlayer()
	if not (pPlayer):
		return

	Tactical.Interface.TacticalControlWindow.Refresh()

	# The player is releasing control of the ship.  If they
	# were in control before, then nobody has direct control
	# (so anyone can choose to step in and take control).
	if MissionLib.GetPlayerShipController() == "Captain":
		MissionLib.SetPlayerAI(None, None)

	# ***CHECKME: Is this a good idea?
	# If our ship already has AI, don't do anything.  It's probably
	# already doing the right thing.
	if pPlayer.GetAI():
		return

	# Have Helm check its orders.
	import Bridge.HelmMenuHandlers
	Bridge.HelmMenuHandlers.UpdateOrders(0)
	# Have Tactical check its orders.
	import Bridge.TacticalMenuHandlers
	Bridge.TacticalMenuHandlers.UpdateOrders(0)

	# If nobody is controlling the ship, set it to fly forward
	# at our current speed, avoiding obstacles.
	if MissionLib.GetPlayerShipController() == None:
		import AI.Player.FlyForward
		MissionLib.SetPlayerAI("Autopilot", AI.Player.FlyForward.CreateAI(pPlayer))

		# Stop firing, if we were firing.
		pTop = App.TopWindow_GetTopWindow()
		pTacticalWindow = pTop.FindMainWindow( App.MWT_TACTICAL )
		for eType in (	App.ET_INPUT_FIRE_PRIMARY,
						App.ET_INPUT_FIRE_SECONDARY,
						App.ET_INPUT_FIRE_TERTIARY ):
			pEvent = App.TGBoolEvent_Create()
			pEvent.SetEventType(eType)
			pEvent.SetDestination(pTacticalWindow)
			pEvent.SetBool(0)
			App.g_kEventManager.AddEvent(pEvent)

	DropOutOfManualFireMode()

###############################################################################
#	LostFocus()
#	
#	The bridge window lost the focus.  Do any special handling...
#	
#	Args:	pBridgeWindow	- The bridge window.  Unused.
#			bLayout			- false to avoid calling Layout()
#	
#	Return:	None
###############################################################################
def LostFocus(pBridgeWindow, bLayout):
	pass

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
				if (pTCW):
					pTCW.SetIgnoreNextMouseKeyEvent(1)

				pEvent.SetHandled()
		else:
			# Not a button event.  Handle mouse movement.
			# Should movement rotate the captain's head or the
			# viewscreen camera?
			if not pEvent.EventHandled():
				# Check if we're in a state where we can rotate
				# the captain's head:
				if (not App.STTopLevelMenu_GetOpenMenu()) and (not App.g_kVarManager.GetFloatVariable("global", "fLockMouse")):
					# Rotate the captain's head.
					RotateHead(pEvent)

###############################################################################
#	RotateViewscreen
#	
#	Rotate the viewscreen based on current mouse movement.
#	
#	Args:	pMouseEvent	- The mouse movement event.
#	
#	Return:	none
##############################################################################
def RotateViewscreen(pMouseEvent):
	iMouseDX = App.g_kInputManager.GetMouseDeltaX()
	iMouseDY = App.g_kInputManager.GetMouseDeltaY()

	if iMouseDX  or  iMouseDY:
		pCamera = MissionLib.GetViewScreenCamera()
		if pCamera:
			kRot = App.TGMatrix3()

			if iMouseDX:
				kAxis = pCamera.GetWorldUpTG()
				kRot.MakeRotation(iMouseDX * 0.005, kAxis)
				pCamera.Rotate(kRot)

			if iMouseDY:
				kAxis = pCamera.GetWorldRightTG()
				kRot.MakeRotation(iMouseDY * 0.005, kAxis)
				pCamera.Rotate(kRot)

###############################################################################
#	RotateHead
#	
#	Rotate the captain's head based on current mouse movement.
#	
#	Args:	pMouseEvent	- The mouse movement event.
#	
#	Return:	none
##############################################################################
def RotateHead(pMouseEvent):
	iMouseDX = App.g_kInputManager.GetMouseDeltaX()
	iMouseDY = App.g_kInputManager.GetMouseDeltaY()

	if iMouseDX  or  iMouseDY:
		pSet = App.g_kSetManager.GetSet("bridge")
		if (pSet):
			pCamera = pSet.GetCamera("maincamera")
			if pCamera:
				# Get the current rotation.
				mRotation = pCamera.GetWorldRotation()

				# Change coordinate systems so it's easy
				# to restrict the rotation.
				import math
				vFwd = App.TGPoint3()
				vFwd.SetXYZ(0, -1, 0)
				vUp = App.TGPoint3()
				vUp.SetXYZ(0, 0, 1)
				vRight = App.TGPoint3()
				vRight.SetXYZ(-1, 0, 0)

				vCameraForward = pCamera.GetWorldForwardTG()
				fDotUp = vCameraForward.Dot( vUp )
				try:
					fUpAngle = math.acos(fDotUp)
				except MathError:
					fUpAngle = 0

				vFlat = vCameraForward.GetPerpendicularComponent( vUp )
				vFlat.Unitize()
				fDotFwd = vFlat.Dot(vFwd)
				fDotRight = vFlat.Dot(vRight)
				try:
					fFlatAngle = math.acos(fDotFwd)
				except MathError:
					fFlatAngle = 0

				if fDotRight < 0:
					fFlatAngle = -fFlatAngle

				# Restrict the angles.
				fOldUp = fUpAngle
				fUpAngle = fUpAngle + (iMouseDY * 0.005)
				if fUpAngle < 0.7:
					fUpAngle = 0.7
				elif fUpAngle > 2.15:
					fUpAngle = 2.15

				fOldFlat = fFlatAngle
				fFlatAngle = fFlatAngle + (iMouseDX * 0.005)
				# No more horizontal angle restrictions.  Player can do the
				# exorcist thing anytime they want.
				#if fFlatAngle < -2.5:
				#	fFlatAngle = -2.5
				#elif fFlatAngle > 2.5:
				#	fFlatAngle = 2.5

#				#debug("Angles: Up(%f), Flat(%f)" % (fUpAngle, fFlatAngle))

				# Find the new rotation matrix with these angles..
				kStart = App.TGMatrix3()
				vFwd.Scale(-1)
				kStart.SetCol(1, vFwd)
				kStart.SetCol(0, vUp)
				kStart.SetCol(2, vRight)

				kRot = App.TGMatrix3()

				kRot.MakeZRotation(fUpAngle)
				kStart = kStart.MultMatrix(kRot)

				kRot.MakeZRotation(fFlatAngle)
				kStart = kRot.MultMatrix(kStart)

				pCamera.SetMatrixRotation(kStart)

###############################################################################
#	HandleKeyboard()
#	
#	Handles keyboard events. This is registered as an event handler for
#	the BridgeWindow class.
#	
#	Args:	BridgeWindow	pBridge	- the bridge object
#			TGKeyboardEvent	pEvent	- keyboard event
#	
#	Return:	none
###############################################################################
def HandleKeyboard(pBridge, pEvent):
	"Handle keyboard events for the command interface"

	if (pEvent.GetUnicode() == App.WC_LBUTTON or pEvent.GetUnicode() == App.WC_RBUTTON):
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if (pTCW.IgnoreNextMouseKeyEvent()):
			pTCW.SetIgnoreNextMouseKeyEvent(0)
			pEvent.SetHandled()

	# Check to make sure instance handler didn't handle the key already
	if (pEvent.EventHandled() == 0):
		# Take care of the keyboard input..
		App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pBridge)

	# Check to make sure instance handler didn't handle the key already
	if (pEvent.EventHandled() == 0):
		# Check to see if children can handle the event
		pBridge.CallNextHandler(pEvent)

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
	if (pEvent.GetButtonNum() & App.TGMouseEvent.MEF_BUTTON_LEFT):
		if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
			# Get a pointer to the open menu, if any
			pOpenMenu = App.STTopLevelMenu_GetOpenMenu()
			idOpenMenu = App.NULL_ID
			if (pOpenMenu):
				idOpenMenu = pOpenMenu.GetObjID()
#				debug("There is an open menu, dropping it..")
				DropMenusTurnBack()

			# No open menu, look to see who we should talk to
			pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet ("bridge"))
			if (pSet):
				if (pSet != None):
					# go through objects to see if any picked.  Middle of the screen is where
					# the pick is done.
					if (pOpenMenu):
						pCursor = App.g_kRootWindow.GetMouseCursor()
						pSet.StartPick(pCursor.GetLeft(), pCursor.GetTop())
					else:
						pSet.StartPick(.5, .5)

					bContinue = 1
					fDotProd = -1
					pBestCharacter = None
					pViewscreen = None
					
					while (bContinue):
						pObject = pSet.GetPickedObject()
						if (pObject == None):
							bContinue = 0
						else:
							pCharacter = App.CharacterClass_Cast(pObject)

							if (pCharacter != None):
								if not (pCharacter.IsHidden()):
									fNextProd = pSet.GetDotProductToObject(pCharacter)
									if (pCharacter.GetName() == "Science" or pCharacter.GetName() == "Engineer"):
										fNextProd = fNextProd*0.94
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
									fBestCharacter = None


					if (pBestCharacter != None):
						pCharacter = pBestCharacter
						if (pCharacter.GetMenu() and pCharacter.GetMenu().GetObjID() != idOpenMenu):
#							debug("Talking to " + pCharacter.GetCharacterName())

							pTactical = App.CharacterClass_GetObject(pSet, "Tactical")

							pTop = App.TopWindow_GetTopWindow()
							pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
							if pTactical and (str(pTactical) == str(pCharacter)):
								pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_FELIX)
							else:
								pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_NONFELIX)
								
								
							if (pCharacter.MenuUp()):
								CharacterInteraction(pCharacter)
					else:
						if (pViewscreen != None):
							if (pViewscreen.GetMenu() != None and pViewscreen.GetMenu().GetObjID() != idOpenMenu):
								pViewscreen.MenuUp()

			# This will tell our caller that we handled this mouse event.
			return 1
		
	if (pEvent.GetButtonNum() & App.TGMouseEvent.MEF_BUTTON_RIGHT):
		if (pEvent.GetFlags() & App.TGMouseEvent.MEF_BUTTON_DOWN):
			DropMenusTurnBack()

			return 1

	# Event not handled
	return 0

###############################################################################
#	CharacterInteraction()
#	
#	Have the character say their "Yes, Sir?" line when you talk to them
#	
#	Args:	pCharacter	- the character that is speaking
#	
#	Return:	none
###############################################################################
def CharacterInteraction(pCharacter):
	pCharacter = App.CharacterClass_Cast(pCharacter)
	if not (pCharacter):
		return

	pDatabase = pCharacter.GetDatabase()

	if (pDatabase):
		if (pCharacter.GetYesSir()):
			pDatabase = MissionLib.GetMissionDatabase()
			pCharacterAction = App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, pCharacter.GetYesSir(), "Captain", 0, pDatabase, App.CSP_NORMAL)
		else:
			pCharacterAction = App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, pCharacter.GetCharacterName() + "Sir" + str(App.g_kSystemWrapper.GetRandomNumber(5)+1), "Captain", 0, pDatabase, App.CSP_NORMAL)
		pCharacterAction.Play()


###############################################################################
#	ToggleOutOfMapMode()
#	
#	Toggles you out of map mode so you can talk to your crewmen
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def ToggleOutOfMapMode():
	pTop = App.TopWindow_GetTopWindow()
	pMap = pTop.FindMainWindow(App.MWT_TACTICAL_MAP)
	if (pMap.IsVisible()):
		pTop.ToggleMapWindow()


###############################################################################
#	
#	TalkToXYZ()
#	
#	Talks to the various bridge officers (result of the F1-F6 keys)
#	
#	Args:	TGObject - the destination for the event
#			pEvent- the Event generated
#	
#	Return:	none
###############################################################################
def TalkToHelm(TGObject = None, pEvent = None):
	ToggleOutOfMapMode()

	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pBridge, "Helm")
	if (pCharacter):
		if not (pCharacter.IsMenuUp()):
			DropMenusTurnBack()
			if (pCharacter.MenuUp()):
				pMenu = pCharacter.GetMenu()
				if pMenu:
					pWindow = pMenu.GetContainingWindow()
					if pWindow:
						pWindow.EnsureFocusIsVisible()

				if (pTop.IsBridgeVisible()):
					CharacterInteraction(pCharacter)
		else:
			DropMenusTurnBack()
	else:
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))
		App.g_kLocalizationManager.Unload(pDatabase)

		bOpened = 0
		if (App.STTopLevelMenu_GetOpenMenu () and pMenu):
			if (App.STTopLevelMenu_GetOpenMenu ().GetObjID () == pMenu.GetObjID ()):
				bOpened = 1

		if (bOpened):
			DropMenusTurnBack()
		else:
			DropMenusTurnBack()
			pMenu.SetVisible ()

			pWindow = pMenu.GetContainingWindow()
			if pWindow:
				pWindow.EnsureFocusIsVisible()

	if pTop.IsTacticalVisible():
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if pTCW:
			pTCW.Layout()

def TalkToScience(TGObject = None, pEvent = None):
	ToggleOutOfMapMode()

	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pBridge, "Science")
	if (pCharacter):
		if not (pCharacter.IsMenuUp()):
			DropMenusTurnBack()
			if (pCharacter.MenuUp()):
				pMenu = pCharacter.GetMenu()
				if pMenu:
					pWindow = pMenu.GetContainingWindow()
					if pWindow:
						pWindow.EnsureFocusIsVisible()

				if (pTop.IsBridgeVisible()):
					CharacterInteraction(pCharacter)
		else:
			DropMenusTurnBack()
	else:
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Science"))
		App.g_kLocalizationManager.Unload(pDatabase)

		bOpened = 0
		if (App.STTopLevelMenu_GetOpenMenu () and pMenu):
			if (App.STTopLevelMenu_GetOpenMenu ().GetObjID () == pMenu.GetObjID ()):
				bOpened = 1

		if (bOpened):
			DropMenusTurnBack()
		else:
			DropMenusTurnBack()
			pMenu.SetVisible ()

			pWindow = pMenu.GetContainingWindow()
			if pWindow:
				pWindow.EnsureFocusIsVisible()

	if pTop.IsTacticalVisible():
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if pTCW:
			pTCW.Layout()

def TalkToXO(TGObject = None, pEvent = None):
	ToggleOutOfMapMode()

	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pBridge, "XO")
	if (pCharacter):
		if not (pCharacter.IsMenuUp()):
			DropMenusTurnBack()
			if (pCharacter.MenuUp()):
				pMenu = pCharacter.GetMenu()
				if pMenu:
					pWindow = pMenu.GetContainingWindow()
					if pWindow:
						pWindow.EnsureFocusIsVisible()

				if (pTop.IsBridgeVisible()):
					CharacterInteraction(pCharacter)
		else:
			DropMenusTurnBack()
	else:
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("XO"))
		App.g_kLocalizationManager.Unload(pDatabase)

		bOpened = 0
		if (App.STTopLevelMenu_GetOpenMenu () and pMenu):
			if (App.STTopLevelMenu_GetOpenMenu ().GetObjID () == pMenu.GetObjID ()):
				bOpened = 1

		if (bOpened):
			DropMenusTurnBack()
		else:
			DropMenusTurnBack()
			pMenu.SetVisible ()

			pWindow = pMenu.GetContainingWindow()
			if pWindow:
				pWindow.EnsureFocusIsVisible()

	if pTop.IsTacticalVisible():
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if pTCW:
			pTCW.Layout()

def TalkToEngineering(TGObject = None, pEvent = None):
	ToggleOutOfMapMode()

	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pBridge, "Engineer")
	pEngCharacter = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("Engineering"), "Engineer")
	if (pCharacter):
		if not (pCharacter.IsMenuUp()):
			DropMenusTurnBack()
			if (pCharacter.MenuUp()):
				pMenu = pCharacter.GetMenu()
				if pMenu:
					pWindow = pMenu.GetContainingWindow()
					if pWindow:
						pWindow.EnsureFocusIsVisible()

				if (pTop.IsBridgeVisible()):
					CharacterInteraction(pCharacter)
		else:
			DropMenusTurnBack()
	elif (pEngCharacter and pTop.IsBridgeVisible()):
		pViewscreen = MissionLib.GetViewScreen()
		if (pViewscreen and pViewscreen.IsMenuUp()):
			pViewscreen.MenuDown()
		else:
			import Bridge.EngineerCharacterHandlers
			Bridge.EngineerCharacterHandlers.ContactEngineering()
	else:
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Engineering"))
		App.g_kLocalizationManager.Unload(pDatabase)

		bOpened = 0
		if (App.STTopLevelMenu_GetOpenMenu () and pMenu):
			if (App.STTopLevelMenu_GetOpenMenu ().GetObjID () == pMenu.GetObjID ()):
				bOpened = 1

		if (bOpened):
			DropMenusTurnBack()
		else:
			DropMenusTurnBack()
			pMenu.SetVisible ()

			pWindow = pMenu.GetContainingWindow()
			if pWindow:
				pWindow.EnsureFocusIsVisible()

	if pTop.IsTacticalVisible():
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if pTCW:
			pTCW.Layout()

def TalkToTactical(TGObject = None, pEvent = None):
	ToggleOutOfMapMode()

	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pBridge, "Tactical")
	if (pCharacter):
		if not (pCharacter.IsMenuUp()):
			DropMenusTurnBack()
			if (pCharacter.MenuUp()):
				pMenu = pCharacter.GetMenu()
				if pMenu:
					pWindow = pMenu.GetContainingWindow()
					if pWindow:
						pWindow.EnsureFocusIsVisible()

				if (pTop.IsBridgeVisible()):
					CharacterInteraction(pCharacter)

					# Move subtitles to their correct location.
					pTop = App.TopWindow_GetTopWindow()
					pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
					pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_TACTICAL)
		else:
			DropMenusTurnBack()
	else:
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Tactical"))
		App.g_kLocalizationManager.Unload(pDatabase)

		bOpened = 0
		if (App.STTopLevelMenu_GetOpenMenu () and pMenu):
			if (App.STTopLevelMenu_GetOpenMenu ().GetObjID () == pMenu.GetObjID ()):
				bOpened = 1

		if (bOpened):
			DropMenusTurnBack()
		else:
			DropMenusTurnBack()
			pMenu.SetVisible()

			pWindow = pMenu.GetContainingWindow()
			if pWindow:
				pWindow.EnsureFocusIsVisible()

	if pTop.IsTacticalVisible():
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if pTCW:
			pTCW.Layout()

def TalkToGuest(TGObject, pEvent):
	ToggleOutOfMapMode()

	pTop = App.TopWindow_GetTopWindow()
	pBridge = App.g_kSetManager.GetSet("bridge")

	# Find one of our guests
	pCharacter = App.CharacterClass_GetObject(pBridge, "Picard")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Data")
	if not (pCharacter):
		pCharacter = App.CharacterClass_GetObject(pBridge, "Saalek")

	if (pCharacter):
		if not (pCharacter.IsMenuUp()):
			DropMenusTurnBack()
			if (pCharacter.MenuUp()):
				pMenu = pCharacter.GetMenu()
				if pMenu:
					pWindow = pMenu.GetContainingWindow()
					if pWindow:
						pWindow.EnsureFocusIsVisible()

				if (pTop.IsBridgeVisible()):
					CharacterInteraction(pCharacter)
		else:
			DropMenusTurnBack()
	else:
		# Can't have guests in Multiplayer ;)
		DropMenusTurnBack()

	if pTop.IsTacticalVisible():
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if pTCW:
			pTCW.Layout()

def TalkToGeneric(pCharacter):
	ToggleOutOfMapMode()

	pCharacter = App.CharacterClass_Cast(pCharacter)
	if not (pCharacter):
		return

	pTop = App.TopWindow_GetTopWindow()

	if not (pCharacter.IsMenuUp()):
		DropMenusTurnBack()
		if (pCharacter.MenuUp()):
			pMenu = pCharacter.GetMenu()
			if pMenu:
				pWindow = pMenu.GetContainingWindow()
				if pWindow:
					pWindow.EnsureFocusIsVisible()

			if (pTop.IsBridgeVisible()):
				CharacterInteraction(pCharacter)
	else:
		DropMenusTurnBack()

	if pTop.IsTacticalVisible():
		pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
		if pTCW:
			pTCW.Layout()

###############################################################################
#	DropCharacterToolTips()
#	
#	Drop any open tool-tips...
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def DropCharacterToolTips():
	pCharacter = App.CharacterClass_GetCurrentToolTipOwner()
	if (pCharacter):
		pCharacter.GetStatusBox().SetNotVisible()
		App.CharacterClass_SetCurrentToolTipOwner(None)

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
	DropCharacterToolTips()

	pOpenMenu = App.STTopLevelMenu_GetOpenMenu()
	if (pOpenMenu):
		pOwner = pOpenMenu.GetOwner()
		bMenuDown = 0
		if (pOwner):
			pCharacter = App.CharacterClass_Cast(pOwner)
			pViewscreen = App.ViewScreenObject_Cast(pOwner)
			if (pCharacter):
				bMenuDown = 1
				pCharacter.MenuDown()
			elif (pViewscreen):
				bMenuDown = 1
				pViewscreen.MenuDown()

		if (bMenuDown == 0):
			pOpenMenu.SetNotVisible()

	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet ("bridge"))
	if pSet:
		# Loop through all the characters in this set.
		for pCharacter in pSet.GetClassObjectList(App.CT_CHARACTER):
			if (pCharacter.IsTurned()):
				pCharacter.TurnBack()

	# Move subtitle window back to its bridge position
	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))

	if (pTop.IsBridgeVisible()):
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_NONFELIX)
	else:
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_TACTICAL)

	DropOutOfManualFireMode()

	# Make sure our camera zooms out
	if (pSet):
		pCamera = App.ZoomCameraObjectClass_Cast(pSet.GetCamera("maincamera"))
		if (pCamera):
			if (pCamera.IsZoomed()):
				pCamera.ToggleZoom(App.g_kUtopiaModule.GetGameTime())

def DropOutOfManualFireMode():
	# Make sure we're no longer in mouse pick fire mode (manual aim).
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTopWindow = App.TopWindow_GetTopWindow()

	if pTopWindow.IsBridgeVisible():
		pTacWindow.SetMousePickFire(0)

		# Make sure the Pick Fire button matches the state of Pick Fire
		import Bridge.TacticalMenuHandlers
		Bridge.TacticalMenuHandlers.ResetPickFireButton()

###############################################################################
#	PlacementHandleChar (cCharCode, iKeyData, fCurrentTime)
#	
#	Handles characters in placement mode.
#	
#	Args:	cCharCode - the character
#			iKeyData - extra key data
#			fCurrentTime - the time of the event
#	
#	Return:	none
###############################################################################
def PlacementHandleChar(cCharCode, iKeyData, fCurrentTime):
	"Handle ascii characters in placement mode"

	# Get the bridge set
	pSet = App.g_kSetManager.GetRenderedSet ()

	if (cCharCode == '+'):
#		debug("+.")

		# Get the ambient light named "ambientlight1" from the set
		pLightObject = pSet.GetLight ("ambientlight1")

		# Get the current light intensity
		fDim = pLightObject.GetIntensity ()

		# Increase the intensity by .1
		fDim = fDim + .1 

		# Set the new intensity
		pLightObject.SetIntensity (fDim)
	elif (cCharCode == '-'):
		# Get the ambient light named "ambientlight1" from the set
		pLightObject = pSet.GetLight ("ambientlight1")

		# Get the current light intensity
		fDim = pLightObject.GetIntensity ()

		# if the intensity is > 0.1
		if (fDim > 0.1):
			# decrease the intensity by .1
			fDim = fDim - .1
		else:
			# otherwise, the intensity is now zero
			fDim = 0.0

		# set the new intensity
		pLightObject.SetIntensity (fDim)
	elif ((cCharCode == 'a') or (cCharCode == 'z')):
#		debug("a.")

		# Get the camera of the set		
		pCameraObject = pSet.GetActiveCamera ()

		# Get the up direction of the camera
		kTrn = pCameraObject.GetWorldUpTG()

		# Get the current location of the camera
		kTrn2 = pCameraObject.GetTranslate ()

		# Calculate new location moving in the up direction by 6 units.
		x = kTrn.GetX ()
		y = kTrn.GetY ()
		z = kTrn.GetZ ()
		
		x = x * 6.0
		y = y * 6.0
		z = z * 6.0

		if (cCharCode == 'a'):
			# Add the movement to the current location of the camera.
			# This moves the camera up in the world.
			x = kTrn2.GetX () + x 
			y = kTrn2.GetY () + y 
			z = kTrn2.GetZ () + z 
		else:
			# Subtract the movement from the current location of the camera.
			# This moves the camera down in the world.
			x = kTrn2.GetX () - x 
			y = kTrn2.GetY () - y 
			z = kTrn2.GetZ () - z 

		# Set the new location of the camera.
		pCameraObject.SetTranslateXYZ (x, y, z)
	elif (cCharCode == '9' or cCharCode == '7'):
		# Get the currently picked object.
		iCurObj = App.g_kVarManager.GetFloatVariable ("global", "fCurObject")

		if (iCurObj > 0):
			if (pSet != None):
				# Get the object
				pCurObject = pSet.GetObject (iCurObj)
				
				if (pCurObject != None):
					kTrn = pCurObject.GetTranslate ()
					z = kTrn.GetZ ()
					if (cCharCode == '9'):
						z = z + 0.5
					else:
						z = z - 0.5

					kTrn.SetZ (z)
					pCurObject.SetTranslate (kTrn)							
	elif (cCharCode == '8' or cCharCode == '2' or cCharCode == '1' or cCharCode == '3'):
		# Get the currently picked object.
		iCurObj = App.g_kVarManager.GetFloatVariable ("global", "fCurObject")

		if (iCurObj > 0):
			if (pSet != None):
				# Get the object
				pCurObject = pSet.GetObject (iCurObj)
				
				if (pCurObject != None):
					kTrn2 = App.TGPoint3 ()
					if (cCharCode == '8'):
						kTrn2.SetXYZ (0, 1.0, 0)
					elif (cCharCode == '2'):
						kTrn2.SetXYZ (0, -1.0, 0)
					elif (cCharCode == '1'):
						kTrn2.SetXYZ (1.0, 0.0, 0)
					elif (cCharCode == '3'):
						kTrn2.SetXYZ (-1.0, 0.0, 0)
					
					kTrn = pCurObject.GetTranslate ()
					kRot = pCurObject.GetRotation ()

					kTrn2.MultMatrix (kRot)

					x = kTrn.GetX ()
					y = kTrn.GetY ()
					z = kTrn.GetZ ()

					x = x + kTrn2.GetX () * 2.0
					y = y - kTrn2.GetY () * 2.0
					z = z + kTrn2.GetZ () * 2.0

					kTrn.SetXYZ (x, y, z)

					pCurObject.SetTranslate (kTrn)
	elif (cCharCode == '4' or cCharCode == '6'):
		# Get the currently picked object.
		iCurObj = App.g_kVarManager.GetFloatVariable ("global", "fCurObject")

		if (iCurObj > 0):
			if (pSet != None):
				# Get the object
				pCurObject = pSet.GetObject (iCurObj)
				
				if (pCurObject != None):
					kRot = App.TGMatrix3 ()
					
					if (cCharCode == '4'):
						kRot.MakeZRotation (-0.02)
					else:
						kRot.MakeZRotation (0.02)

					pCurObject.Rotate (kRot)
	elif (cCharCode == 's'):
#		debug("s.")
		pSet = App.g_kSetManager.GetSet ("space")
#		debug("s1.")
		pObj = pSet.GetObject (100002)
#		debug("s2.")
		pObj.SetHidden (1)
#		debug("s3.")
	elif (cCharCode == ']'):
		pSet = App.g_kSetManager.GetRenderedSet()
		pCamera = App.ZoomCameraObjectClass_GetObject(pSet, "maincamera")
		fMaxZoomLevel = pCamera.GetMaxZoom()
		fMinZoomLevel = pCamera.GetMinZoom()
		fZoomTime = pCamera.GetZoomTime()
#		debug("Min zoom level: %f\nMax zoom level: %f\nZoom time:%f" % (fMinZoomLevel, fMaxZoomLevel, fZoomTime))

###############################################################################
#	ZoomViewscreen()
#	
#	Zoom the viewscreen's camera in or out.
#	
#	Args:	pObject	- Unused
#			pEvent	- TGFloat event with zoom amount.
#	
#	Return:	none
###############################################################################
def ZoomViewscreen(pObject, pEvent):
	fZoomFactor = pEvent.GetFloat()

	pCamera = MissionLib.GetViewScreenCamera()
	if pCamera:
		# Zoom it.
		pCamera.Zoom(fZoomFactor)

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

	# Turn off the viewscreen if we want to see our target
	pViewScreen = MissionLib.GetViewScreen()
	if (pViewScreen.RenderingRemoteCam()):
		pViewScreen.ToggleRemoteCam(0)
	else:
		pViewScreen.ToggleRemoteCam(1)

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
	pPlayer = App.Game_GetCurrentPlayer()
	pCamera = MissionLib.GetViewScreenCamera()
	if pCamera and pPlayer:
		pCamera.AddModeHierarchy("InvalidViewscreen", sCamera)


###############################################################################
#	FindCourseButton()
#	
#	Finds the SetCourse button for this name
#	
#	Args:	pcLocation	- the location this button will bring us to
#	
#	Return:	pChild		- the button that brings us there
###############################################################################
def FindCourseButton(pcLocation, pMenu = None):
	if not (pMenu):
		pMenu = App.SortedRegionMenu_GetRoot()

	iNumChildren = pMenu.GetNumChildren()
	for i in range (iNumChildren):
		pChild = pMenu.GetNthChild(i)
		if (pChild.IsTypeOf(App.CT_SORTED_REGION_MENU)):
			pChild = App.SortedRegionMenu_Cast(pChild)
			if (pChild.GetNumChildren() > 0):
				pDest = FindCourseButton(pcLocation, pChild)
				if (pDest):
					return pDest
			else:
				if (pChild.GetRegionName() == pcLocation):
					return pChild

	return None


###############################################################################
#	XYZUpdateToolTip()
#	
#	Functions for the characters to update their tool-tips
#	
#	Args:	pCharacter	- the character who called us
#	
#	Return:	none
###############################################################################
def HelmUpdateToolTip(pCharacter):
	# Grab the speed of the ship
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pHelm = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")
	if not (pHelm):
		return

	fVel = App.UtopiaModule_ConvertGameUnitsToKilometers(pShip.GetVelocity().Length()) * 3600.0
	fImp = pShip.GetImpulse() * 9 + 0.1

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.TGL")

	pcLine = str(int(fImp)) + " : " + str(int(fVel)) + " "
	kString = App.TGString(pcLine)
	kString = kString.Append(pDatabase.GetString("kph"))
	pHelm.SetStatus(kString, 1)

	pSet = pShip.GetContainingSet()
	if (pSet):
		kName = App.TGString()
		kString = pDatabase.GetString("Current Location :")
		pSet.GetDisplayName(kName)
		pHelm.SetStatus(kString.Append(kName), 2)

	App.g_kLocalizationManager.Unload(pDatabase)

	pWarpButton = App.SortedRegionMenu_GetWarpButton()
	if (pWarpButton.GetDestination()):
		# Go through the Set Course buttons until we find the one with this destination
		pButton = FindCourseButton(pWarpButton.GetDestination())
		if (pButton):
			kName = App.TGString()
			pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.TGL")
			kString = pDatabase.GetString("Destination :")
			pButton.GetName(kName)
			pHelm.SetStatus(kString.Append(kName), 3)
			App.g_kLocalizationManager.Unload(pDatabase)
	else:
		pHelm.ClearStatus(3)

def TacticalUpdateToolTip(pCharacter):
	# Grab the speed of the ship
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pTactical = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if not (pTactical):
		return

def XOUpdateToolTip(pCharacter):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	if not (pXO):
		return

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.TGL")
	if (pShip.GetAlertLevel() == pShip.RED_ALERT):
		pXO.SetStatus(pDatabase.GetString("Red Alert"), 1)
	if (pShip.GetAlertLevel() == pShip.YELLOW_ALERT):
		pXO.SetStatus(pDatabase.GetString("Yellow Alert"), 1)
	if (pShip.GetAlertLevel() == pShip.GREEN_ALERT):
		pXO.SetStatus(pDatabase.GetString("Green Alert"), 1)
	App.g_kLocalizationManager.Unload(pDatabase)

def ScienceUpdateToolTip(pCharacter):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pScience = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Science")
	if not (pScience):
		return


def EngineerUpdateToolTip(pCharacter):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pEngineer = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
	if not (pEngineer):
		return

def PicardUpdateToolTip(pCharacter):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if not (pPicard):
		return

def DataUpdateToolTip(pCharacter):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pData = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Data")
	if not (pData):
		return

def SaalekUpdateToolTip(pCharacter):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pSaalek = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Saalek")
	if not (pSaalek):
		return

def KorbusUpdateToolTip(pCharacter):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return

	pKorbus = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Korbus")
	if not (pKorbus):
		return

###############################################################################
#	ShowSaved()
#	
#	Notify the player that we just saved the game
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ShowSaved(pObject = None, pEvent = None):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	MissionLib.TextBanner(None, pDatabase.GetString("Saving"), 0.05, 0.25, 3.0, 12, 1, 0)
	App.g_kLocalizationManager.Unload(pDatabase)
	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)
