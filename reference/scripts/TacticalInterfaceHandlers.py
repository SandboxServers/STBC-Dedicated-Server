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
import Camera
import MissionLib
import Tactical.Interface.TacticalControlWindow

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

pGODModeLabel = None

TIHLeft = 0
TIHRight = 0
TIHUp = 0
TIHDown = 0
TIHRLeft = 0
TIHRRight = 0
g_bCameraRotationEnabled = 0
g_bZooming = 0

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
	# A lot of our handling can be done by functions that
	# already exist in the tactical interface handlers.
	lEventHandlerMap = (
		(App.ET_INPUT_ZOOM,						__name__ + ".Zoom"),
		(App.ET_INPUT_TOGGLE_MAP_MODE,			__name__ + ".ToggleMapMode"),
		(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	__name__ + ".ToggleCinematicMode"),
		(App.ET_INPUT_CYCLE_CAMERA,				__name__ + ".CycleCameraMode"),
		(App.ET_INPUT_CHASE_PLAYER,				__name__ + ".ChasePlayer"),
		(App.ET_INPUT_REVERSE_CHASE,			__name__ + ".ReverseChase"),
		(App.ET_INPUT_ZOOM_TARGET,				__name__ + ".ZoomTarget"),
		(App.ET_INPUT_CLEAR_TARGET,				__name__ + ".ClearTarget"),
		(App.ET_INPUT_TARGET_NEXT,				__name__ + ".TargetNext"),
		(App.ET_INPUT_TARGET_PREV,				__name__ + ".TargetPrev"),
		(App.ET_INPUT_TARGET_NEAREST,			__name__ + ".TargetNearest"),
		(App.ET_INPUT_TARGET_NEXT_ENEMY,		__name__ + ".TargetNextEnemy"),
		(App.ET_INPUT_TARGET_TARGETS_ATTACKER,	__name__ + ".TargetTargetsAttacker"),
		(App.ET_INPUT_TARGET_NEXT_NAVPOINT,		__name__ + ".TargetNextNavPoint"),
		(App.ET_INPUT_TARGET_NEXT_PLANET,		__name__ + ".TargetNextPlanet"),		
		(App.ET_INPUT_ALLOW_CAMERA_ROTATION,	__name__ + ".ToggleCameraRotation"),
		(App.ET_INPUT_SET_IMPULSE,				__name__ + ".SetImpulse"),
		(App.ET_INPUT_INCREASE_SPEED,			__name__ + ".IncreaseSpeed"),
		(App.ET_INPUT_DECREASE_SPEED,			__name__ + ".DecreaseSpeed"),
		(App.ET_INPUT_FIRE_TERTIARY,			__name__ + ".FireTertiaryWeapons"),
		(App.ET_INPUT_FIRE_SECONDARY,			__name__ + ".FireSecondaryWeapons"),
		(App.ET_INPUT_FIRE_PRIMARY,				__name__ + ".FirePrimaryWeapons"),
		(App.ET_INPUT_TURN_LEFT,				__name__ + ".TurnLeft"),
		(App.ET_INPUT_TURN_RIGHT,				__name__ + ".TurnRight"),
		(App.ET_INPUT_TURN_UP,					__name__ + ".TurnUp"),
		(App.ET_INPUT_TURN_DOWN,				__name__ + ".TurnDown"),
		(App.ET_INPUT_ROLL_LEFT,				__name__ + ".RollLeft"),
		(App.ET_INPUT_ROLL_RIGHT,				__name__ + ".RollRight"),
		(App.ET_INPUT_SKIP_EVENTS,				__name__ + ".SkipEvents"),

		# Debug/cheat
		(App.ET_INPUT_DEBUG_KILL_TARGET,		__name__ + ".KillTarget"),
		(App.ET_INPUT_DEBUG_QUICK_REPAIR,		__name__ + ".RepairShip"),
		(App.ET_INPUT_DEBUG_GOD_MODE,			__name__ + ".ToggleGodMode"),
		(App.ET_INPUT_DEBUG_LOAD_QUANTUMS,		__name__ + ".LoadQuantums"),

		(App.ET_INPUT_TALK_TO_TACTICAL,			"BridgeHandlers.TalkToTactical"),
		(App.ET_INPUT_TALK_TO_HELM,				"BridgeHandlers.TalkToHelm"), 
		(App.ET_INPUT_TALK_TO_XO,				"BridgeHandlers.TalkToXO"), 
		(App.ET_INPUT_TALK_TO_SCIENCE,			"BridgeHandlers.TalkToScience"), 
		(App.ET_INPUT_TALK_TO_ENGINEERING,		"BridgeHandlers.TalkToEngineering"), 
		(App.ET_INPUT_TALK_TO_GUEST,			"BridgeHandlers.TalkToGuest"), 
		(App.ET_SET_ALERT_LEVEL,				"BridgeHandlers.SetAlertLevel"),
		(App.ET_INPUT_INTERCEPT,				"BridgeHandlers.InterceptTarget"),
		(App.ET_QUICK_SAVE,						"BridgeHandlers.QuickSave"),
		(App.ET_QUICK_LOAD,						"BridgeHandlers.QuickLoad"),

		(App.ET_INPUT_TOGGLE_SCORE_WINDOW,		"MultiplayerInterfaceHandlers.ToggleScoreWindow"),
		(App.ET_INPUT_TOGGLE_CHAT_WINDOW,		"MultiplayerInterfaceHandlers.ToggleChatWindow"),

#		(App.ET_INPUT_SELF_DESTRUCT,			__name__ + ".PlayerSelfDestruct"),

		(App.ET_OTHER_BEAM_TOGGLE_CLICKED,		"BridgeHandlers.ToggleTractorBeam"),
		(App.ET_OTHER_CLOAK_TOGGLE_CLICKED,		"BridgeHandlers.ToggleCloak")
		)

	for eType, sFunc in lEventHandlerMap:
		# Add instance handlers for these events.
		pWindow.AddPythonFuncHandlerForInstance(eType, sFunc)

	# Done

###############################################################################
#	PlayerSelfDestruct()
#	
#	Kills the player ;)
#	
#	Args:	pObject, pEvent	- object and event that call us
#	
#	Return:	none
###############################################################################
#def PlayerSelfDestruct(pObject, pEvent):
#	pShip = MissionLib.GetPlayer()
#	if (pShip):
#		pShip.DamageSystem(pShip.GetHull(), pShip.GetHull().GetMaxCondition())
#
#	pObject.CallNextHandler(pEvent)

###############################################################################
#	GotFocus()
#	
#	Called when the tactical window gets the focus.
#	
#	Args:	pTacticalWindow	- The tactical window.
#			bLayout			- false to avoid calling Layout()
#	
#	Return:	None
###############################################################################
def GotFocus(pTacticalWindow, bLayout):
	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pCinematic = pTop.FindMainWindow(App.MWT_CINEMATIC)
	if ((pTop.IsCutsceneMode()) or (pCinematic and pCinematic.IsWindowActive()) or
	    (not pTacticalWindow.IsWindowActive())):
		if (pTCW):
			pTCW.SetNotVisible(0)
	else:
		if (pTCW):
			pTCW.SetVisible(0)
		Tactical.Interface.TacticalControlWindow.Refresh()

	# If the ship is on autopilot, put it back in the captain's control.
	if MissionLib.GetPlayerShipController() == "Autopilot":
		pShip = App.Game_GetCurrentPlayer()
		if (pShip):
			fImpulse = pShip.GetImpulse()

			# Back to Captain's control...
			MissionLib.SetPlayerAI("Captain", None)

			# Send an event to set our speed to whatever the ship is at right now.
			pSetImpulse = App.TGFloatEvent_Create()
			pSetImpulse.SetEventType(App.ET_INPUT_SET_IMPULSE)
			pSetImpulse.SetDestination(pTacticalWindow)
			pSetImpulse.SetFloat(fImpulse)
			App.g_kEventManager.AddEvent(pSetImpulse)

###############################################################################
#	LostFocus()
#	
#	Called when the tactical window loses the focus.
#	
#	Args:	pTacticalWindow	- The tactical window.  It's losing focus.
#			bLayout			- false to avoid calling Layout()
#	
#	Return:	None
###############################################################################
def LostFocus(pTacticalWindow, bLayout):
	# If the ship is on autopilot, put it back in the captain's control.
	if MissionLib.GetPlayerShipController() == "Captain":
		StopShip()

	global g_bZooming, g_bCameraRotationEnabled
	if g_bZooming:
		# Disable zoom mode.
		Camera.Pop(None, "ZoomTarget")
		g_bZooming = 0

	g_bCameraRotationEnabled = 0

###############################################################################
#	StopShip()
#	
#	Stops your ship from turning and firing
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def StopShip():
	# If any of the left/right/up/down/rollleft/rollright keys are
	# down, make them go up.
	global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

	TIHLeft = 0
	TIHRight = 0
	TIHUp = 0
	TIHDown = 0
	TIHRLeft = 0
	TIHRRight = 0

	# If the ship isn't AI-controlled, stop it.
	pShip = MissionLib.GetPlayer()
	if pShip  and  (pShip.GetAI() is None):
		TurnShip(pShip, TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight)

		# If we're firing weapons, send events to stop.
		pTop = App.TopWindow_GetTopWindow()
		pTacticalWindow = pTop.FindMainWindow(App.MWT_TACTICAL)

		for eType in (	App.ET_INPUT_FIRE_PRIMARY,
						App.ET_INPUT_FIRE_SECONDARY,
						App.ET_INPUT_FIRE_TERTIARY ):
			pEvent = App.TGBoolEvent_Create()
			pEvent.SetEventType(eType)
			pEvent.SetDestination(pTacticalWindow)
			pEvent.SetBool(0)
			App.g_kEventManager.AddEvent(pEvent)

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
def HandleMouse(pTactical, pEvent):
	# We want to call our next handler to pass the input to our children in
	# most cases but not all of them.  For any mouse move events we do, and
	# for button events when the cursor is visible as well.  The case where
	# we don't want to send input on is if the mouse isn't visible and we
	# get a button event.  In this case we handle that as weapon firing.
	if (pEvent.IsButtonEvent()):
		# Only call next handler if we don't have the mouse grab.
		if ((App.g_kRootWindow.GetMouseGrabOwner() == None) or
		    (App.g_kRootWindow.GetMouseGrabOwner().GetObjID() != pTactical.GetObjID())):
			pTactical.CallNextHandler(pEvent)

		# No need to do special mouse button handling, this is dealt with by
		# the binding code now
		if (pEvent.EventHandled()):
			pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
			#pTCW.SetIgnoreNextMouseKeyEvent(1)
		pEvent.SetHandled()
		return

	# pass on other mouse events to our children by calling our next handler
	pTactical.CallNextHandler(pEvent)

	# Only pass camera movement input through if camera movement is enabled.
	if g_bCameraRotationEnabled:
		App.TacticalWindow_SpaceCameraRotation()


###############################################################################
#	HandleKeyboard()
#	
#	Handles keyboard events. This is registered as an event handler for
#	TacticalWindow.
#	
#	Args:	pWindow, the TacticalWindow
#			pEvent, the TGKeyboardEvent
#	
#	Return:	none
###############################################################################
def HandleKeyboard(pWindow, pEvent):
	"Handle keyboard events for the Tactical interface"
	global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

	pObject = App.TacticalWindow_Cast(pWindow)
	if (pObject == None):
#		debug("tactical window null in TH.HandleKeyboard")
		return

	if (pEvent.EventHandled() == 0):
		if (pEvent.GetUnicode() == App.WC_LBUTTON or pEvent.GetUnicode() == App.WC_RBUTTON):
			pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
			if (pTCW.IgnoreNextMouseKeyEvent()):
				pTCW.SetIgnoreNextMouseKeyEvent(0)
				pEvent.SetHandled()

		if (pEvent.EventHandled() == 0):
			if (App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pObject)):
				pEvent.SetHandled()

		if (not pEvent.EventHandled()):
			pWindow.CallNextHandler(pEvent)

###############################################################################
#	TurnShip()
#	
#	A helper function for the event handlers below.  Turn the
#	given ship, based on the direction flags given.
#	
#	Args:	pShip	- The ship to turn
#		bLeft	- Flag for turning left
#		bRight	- Flag for turning right
#		...
#	
#	Return:	none
###############################################################################
def TurnShip(pShip, bLeft, bRight, bUp, bDown, bRLeft, bRRight):
	# This clears the player's AI.  The Captain is in control.
	if MissionLib.GetPlayerShipController() != "Captain":
		# Ignore the next AI_DONE event, so that this command isn't overridden
		# by the code that stops the ship when AI is done...
		if pShip.GetAI():
			pShip.IncrementAIDoneIgnore()

		MissionLib.SetPlayerAI("Captain", None)

	pMdlRight = App.TGPoint3_GetModelRight()
	pMdlUp = App.TGPoint3_GetModelUp()
	pMdlFwd = App.TGPoint3_GetModelForward()
	
	# Right axis affects up/down
	pMdlRight.Scale(bDown - bUp)
	# Up axis affects left/right
	pMdlUp.Scale(bRight - bLeft)
	# Fwd axis affects roll
	pMdlFwd.Scale(bRLeft - bRRight)

	pAxis = App.TGPoint3()
	pAxis.Set(pMdlRight)
	pAxis.Add(pMdlUp)
	pAxis.Add(pMdlFwd)
	pAxis.Unitize()

	pShip.SetAngularDirectionType(App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
	pShip.SetTargetAngularVelocityFraction(pAxis)

###############################################################################
#	FireWeapons(pShip, eGroup)
#	
#	Fires the specified weapon system group. (primary, secondary, tertiary)
#	
#	Args:	pShip		- the ship that is firing
#			bFiring		- whether we are starting or stopping firing
#			eGroup		- the weapon system group to look for
#						  (i.e. App.ShipClass.WG_PRIMARY, WG_SECONDARY,
#						  WG_TERTIARY)
#	
#	Return:	none
###############################################################################
def FireWeapons(pShip, bFiring, eGroup):
	if (pShip != None):
		# Check if we're starting or stopping...
		if (bFiring == 1):
			# Starting.  Check if we have a target..
			pSystem = pShip.GetWeaponSystemGroup(eGroup)
			if (pSystem != None):
				pSystem.StartFiring(pShip.GetTarget(), pShip.GetTargetOffsetTG())
				pSystem.SetForceUpdate(1) # update and fire immediately
		else:
			# Stopping.
			pSystem = pShip.GetWeaponSystemGroup(eGroup)
			if (pSystem != None):
				pSystem.StopFiring()

	return

###############################################################################
###############################################################################
##	Event handlers for input-generated events.
##	
##	Handlers for events that were (probably) generated from
##	user input.  Simple little functions that perform a single
##	task based on the event given to them..
##	
##	Args:	pObject		- The destination for the event (probably the
##						  tactical window)
##			pEvent		- The event generated.
##	
##	Return:	none
###############################################################################
###############################################################################
def FirePrimaryWeapons(pObject, pEvent):
	# Get the player's ship...
	pShip = App.Game_GetCurrentPlayer()

	FireWeapons(pShip, pEvent.GetBool(), App.ShipClass.WG_PRIMARY)
	pObject.CallNextHandler(pEvent)

def FireSecondaryWeapons(pObject, pEvent):
	# Get the player's ship...
	pShip = App.Game_GetCurrentPlayer()

	FireWeapons(pShip, pEvent.GetBool(), App.ShipClass.WG_SECONDARY)
	pObject.CallNextHandler(pEvent)

def FireTertiaryWeapons(pObject, pEvent):
	# Get the player's ship...
	pShip = App.Game_GetCurrentPlayer()

	FireWeapons(pShip, pEvent.GetBool(), App.ShipClass.WG_TERTIARY)
	pObject.CallNextHandler(pEvent)

def TurnLeft(pObject, pEvent):
	global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

	bDoTurn = pEvent.GetBool()
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		if TIHLeft != bDoTurn:
			TIHLeft = bDoTurn
			TurnShip(pShip, TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight)

	pObject.CallNextHandler(pEvent)

def TurnRight(pObject, pEvent):
	global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

	bDoTurn = pEvent.GetBool()
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		if TIHRight != bDoTurn:
			TIHRight = bDoTurn
			TurnShip(pShip, TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight)

	pObject.CallNextHandler(pEvent)

def TurnUp(pObject, pEvent):
	global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

	bDoTurn = pEvent.GetBool()
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		if TIHUp != bDoTurn:
			TIHUp = bDoTurn
			TurnShip(pShip, TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight)

	pObject.CallNextHandler(pEvent)

def TurnDown(pObject, pEvent):
	global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

	bDoTurn = pEvent.GetBool()
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		if TIHDown != bDoTurn:
			TIHDown = bDoTurn
			TurnShip(pShip, TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight)

	pObject.CallNextHandler(pEvent)

def RollLeft(pObject, pEvent):
	global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

	bDoTurn = pEvent.GetBool()
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		if TIHRLeft != bDoTurn:
			TIHRLeft = bDoTurn
			TurnShip(pShip, TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight)

	pObject.CallNextHandler(pEvent)

def RollRight(pObject, pEvent):
	global TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight

	bDoTurn = pEvent.GetBool()
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		if TIHRRight != bDoTurn:
			TIHRRight = bDoTurn
			TurnShip(pShip, TIHLeft, TIHRight, TIHUp, TIHDown, TIHRLeft, TIHRRight)

	pObject.CallNextHandler(pEvent)

def Zoom(pObject, pEvent):
	fChange = pEvent.GetFloat()

	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	pCamera = pGame.GetPlayerCamera()
	if pCamera  and  pPlayer:
		pCamera.Zoom(fChange)

	pObject.CallNextHandler(pEvent)

def SetImpulse(pObject, pEvent):
	fImpulse = pEvent.GetFloat()
	if fImpulse >= 0.0:
		vDirection = App.TGPoint3_GetModelForward()
	else:
		vDirection = App.TGPoint3_GetModelBackward()
		fImpulse = -fImpulse

	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		# This clears the player's AI.  The Captain is in control.
		if MissionLib.GetPlayerShipController() != "Captain":
			# Ignore the next AI_DONE event, so that this command isn't overridden
			# by the code that stops the ship when AI is done...
			if pShip.GetAI():
				pShip.IncrementAIDoneIgnore()

			MissionLib.SetPlayerAI("Captain", None)

		pShip.SetImpulse(fImpulse, vDirection, App.ShipClass.DIRECTION_MODEL_SPACE)

	pObject.CallNextHandler(pEvent)

def IncreaseSpeed(pObject, pEvent):
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		if (pShip.IsReverse ()):
			fNewImpulse = 0.0
		else:
			fImpulse = pShip.GetImpulse()
			fNewImpulse = fImpulse + 1.0/9.0
			if (fNewImpulse > 1.0):
				fNewImpulse = 1.0

		# This clears the player's AI.  The Captain is in control.
		if MissionLib.GetPlayerShipController() != "Captain":
			# Ignore the next AI_DONE event, so that this command isn't overridden
			# by the code that stops the ship when AI is done...
			if pShip.GetAI():
				pShip.IncrementAIDoneIgnore()

			MissionLib.SetPlayerAI("Captain", None)

		if fNewImpulse >= 0.0:
			vDirection = App.TGPoint3_GetModelForward()
		else:
			vDirection = App.TGPoint3_GetModelBackward()
			fNewImpulse = -fNewImpulse
		pShip.SetImpulse(fNewImpulse, vDirection, App.ShipClass.DIRECTION_MODEL_SPACE)

def DecreaseSpeed(pObject, pEvent):
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		fImpulse = pShip.GetImpulse()
		if (pShip.IsReverse ()):
			fImpulse = -fImpulse
		fNewImpulse = fImpulse - 1.0/9.0
		if (fNewImpulse < -2.0/9.0):
			fNewImpulse = -2.0/9.0

		# This clears the player's AI.  The Captain is in control.
		if MissionLib.GetPlayerShipController() != "Captain":
			# Ignore the next AI_DONE event, so that this command isn't overridden
			# by the code that stops the ship when AI is done...
			if pShip.GetAI():
				pShip.IncrementAIDoneIgnore()

			MissionLib.SetPlayerAI("Captain", None)

		if fNewImpulse >= 0.0:
			vDirection = App.TGPoint3_GetModelForward()
		else:
			vDirection = App.TGPoint3_GetModelBackward()
			fNewImpulse = -fNewImpulse
		pShip.SetImpulse(fNewImpulse, vDirection, App.ShipClass.DIRECTION_MODEL_SPACE)

def CycleCameraMode(pObject, pEvent):
	# Cycle primary camera modes.  If we're not in
	# one of the primary modes, switch to one of them.
	# If we are, loop through them.
	lsPrimaryModes = ( "Chase", "Target" )

	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	pCamera = pGame.GetPlayerCamera()
	if not (pCamera  and  pPlayer):
		return
	
	pMode = pCamera.GetCurrentCameraMode()

	# Check the current camera mode against each of the primary modes..
	if pMode:
		for iIndex in range( len(lsPrimaryModes) ):
			sPrimaryMode = lsPrimaryModes[iIndex]

			pPrimaryMode = pCamera.GetNamedCameraMode(sPrimaryMode)
			if pMode.GetObjID() == pPrimaryMode.GetObjID():
				# The current camera mode is this primary mode.  Cycle
				# it to the next primary mode.
				break
	else:
		iIndex = -1

	for iAttemptCount in range( len(lsPrimaryModes) ):
		iIndex = (iIndex + 1) % len(lsPrimaryModes)
		sPrimaryMode = lsPrimaryModes[iIndex]
		pPrimaryMode = pCamera.GetNamedCameraMode( sPrimaryMode )
		if pPrimaryMode.IsValid():
			# Set the space view to use this camera mode.
			pCamera.AddModeHierarchy("InvalidSpace", sPrimaryMode)
			pPrimaryMode.Reset()
			return

#	debug("No valid primary camera modes.  Can't switch camera mode.")

def ChasePlayer(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	pCamera = pGame.GetPlayerCamera()
	if pCamera  and  pPlayer:
		pCamera.AddModeHierarchy("InvalidSpace", "Chase")

	pObject.CallNextHandler(pEvent)

def ReverseChase(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	pCamera = pGame.GetPlayerCamera()
	if pCamera  and  pPlayer:
		pCamera.AddModeHierarchy("InvalidSpace", "ReverseChase")

	pObject.CallNextHandler(pEvent)

def ZoomTarget(pObject, pBoolEvent):
	global g_bZooming

	pShip = App.Game_GetCurrentPlayer()
	if not pShip:
		return

	# Enable or disable the Zoom To Target mode.
	if pBoolEvent.GetBool():
		# Enable zoom mode.  Need to have a target to do this.
		pTarget = pShip.GetTarget()
		if not pTarget:
			return

		Camera.ZoomTarget(pShip.GetName(), pTarget.GetName(), None, 1, 0)
		g_bZooming = 1
	else:
		# Disable zoom mode.
		pGame = App.Game_GetCurrentGame()
		Camera.Pop(None, "ZoomTarget")
		g_bZooming = 0

	pObject.CallNextHandler(pBoolEvent)

def ClearTarget(pObject, pEvent):
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pPlayer.SetTarget(None)

		# Get the target menu, and clear its persistent target information.
		pTargetMenu = App.STTargetMenu_GetTargetMenu()
		if pTargetMenu:
			pTargetMenu.ClearPersistentTarget()

		# If Felix is attacking, cear Felix's Target At Will setting.
		# If we're clearing the target, we don't want Felix to jump
		# in and override our settings. Get the Tactical station's menu.
		pTopWindow = App.TopWindow_GetTopWindow()
		pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pMenu = pTacWindow.GetTacticalMenu()

		# Get the "Target At Will" button
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pTargetingButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Target At Will")))
		App.g_kLocalizationManager.Unload(pDatabase)

		pTargetingButton.SetChosen(0)

		import Bridge.TacticalMenuHandlers
		Bridge.TacticalMenuHandlers.UpdateOrders(0)

def TargetNext(pObject, pEvent):
	CycleTarget(1)
	pObject.CallNextHandler(pEvent)

def TargetPrev(pObject, pEvent):
	CycleTarget(0)
	pObject.CallNextHandler(pEvent)

def CycleTarget(bNext):
	# Get the player.
	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		return

	# Find the player's target in the target menu, and go to the next or
	# previous entry.
	pTarget = pPlayer.GetTarget()
	pTargetMenu = App.STTargetMenu_GetTargetMenu()

	if (pTargetMenu == None):
		return

	if (pTarget == None):
		# No target. Get the first or last entry in the menu.
		if (bNext == 1):
			pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetFirstChild())
			while pMenu  and  (not pMenu.IsVisible()):
				pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetNextChild(pMenu))
		else:
			pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetLastChild())
			while pMenu  and  (not pMenu.IsVisible()):
				pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetPrevChild(pMenu))

		if (pMenu != None) and (pMenu.GetShip() != None):
			pPlayer.SetTarget(pMenu.GetShip().GetName())
	else:
		pMenu = pTargetMenu.GetObjectEntry(pTarget)

		if (bNext == 1):
			pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetNextChild(pMenu))
			while pMenu  and  (not pMenu.IsVisible()):
				pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetNextChild(pMenu))

			if (pMenu == None):
				pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetFirstChild())
				while pMenu  and  (not pMenu.IsVisible()):
					pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetNextChild(pMenu))
		else:
			pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetPrevChild(pMenu))
			while pMenu  and  (not pMenu.IsVisible()):
				pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetPrevChild(pMenu))

			if (pMenu == None):
				pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetLastChild())
				while pMenu  and  (not pMenu.IsVisible()):
					pMenu = App.STSubsystemMenu_Cast(pTargetMenu.GetPrevChild(pMenu))

		if (pMenu != None) and (pMenu.GetShip() != None):
			pPlayer.SetTarget(pMenu.GetShip().GetName())

###############################################################################
#	TargetNearest
#	
#	Target the nearest attacker.  If the player has no attackers,
#	target the nearest enemy.
#	
#	Args:	pObject	- The tactical interface window (unused)
#			pEvent	- The ET_INPUT_TARGET_NEAREST event.
#	
#	Return:	None
###############################################################################
def TargetNearest(pObject, pEvent):
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		TargetAttacker(pPlayer, 0)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	TargetAttacker
#	
#	Set the player's target to be the nearest attacker of the
#	given object.
#	
#	Args:	pAttackedObject		- The object being attacked.
#			bAttackersOnly		- If true, only targets an attacker, and doesn't
#								  change the target if there are no attackers.  If
#								  false, this will target an enemy if there are no
#								  attackers.
#	
#	Return:	None
###############################################################################
def TargetAttacker(pAttackedObject, bAttackersOnly):
	# Get the list of enemies in this set.
	lEnemies = None
	pPlayer = None
	pGame = App.Game_GetCurrentGame()
	if not pGame:
		return

	pPlayer = pGame.GetPlayer()
	if not pPlayer:
		return

	pEpisode = pGame.GetCurrentEpisode()
	if pEpisode:
		pMission = pEpisode.GetCurrentMission()
		if pMission:
			pEnemyGroup = pMission.GetEnemyGroup()
			# If the attacked object is in the enemy group, use the
			# friendly group instead.
			if pEnemyGroup.IsNameInGroup(pAttackedObject.GetName()):
				pEnemyGroup = pMission.GetFriendlyGroup()

			pSet = pGame.GetPlayerSet()
			if pSet:
				lEnemies = pEnemyGroup.GetActiveObjectTupleInSet(pSet)

	# Remove enemies that cannot be seen on the player's sensors.
	pSensors = pPlayer.GetSensorSubsystem()
	lNewEnemies = []
	for pEnemy in lEnemies:
		if pSensors.IsObjectVisible(pEnemy):
			lNewEnemies.append(pEnemy)
	lEnemies = lNewEnemies

	# Look for attackers in the list of enemies.  If any attackers
	# exist, trim the list to include only the attackers.
	lAttackers = []
	for pObject in lEnemies:
		try:
			pShip = App.ShipClass_Cast(pObject)
			if pShip.GetTarget().GetObjID() == pAttackedObject.GetObjID():
				# Found an attacker.
				lAttackers.append(pObject)
		except AttributeError: pass

	if lAttackers  or  bAttackersOnly:
		lEnemies = lAttackers

	# Look through the list of enemies for the nearest target..
	if lEnemies:
		# Calculate the distance to each enemy.  Find the one that's
		# nearest.
		pNearest = None
		fNearest = 1.0e20
		for pEnemy in lEnemies:
			if pPlayer.CanTargetObject(pEnemy):
				vDiff = pEnemy.GetWorldLocation()
				vDiff.Subtract(pAttackedObject.GetWorldLocation())
				fSqrDistance = vDiff.SqrLength()

				if fSqrDistance < fNearest:
					# This enemy is closer than the last one we tried...
					pNearest = pEnemy
					fNearest = fSqrDistance

		if pNearest:
			# Got a new target.  Target it.
			pPlayer.SetTarget(pNearest.GetName())

###############################################################################
#	TargetNextEnemy
#	
#	Target the next enemy.
#	
#	Args:	pObject	- The tactical interface window (unused)
#			pEvent	- The ET_INPUT_TARGET_NEXT_ENEMY event.
#	
#	Return:	None
###############################################################################
def TargetNextEnemy(pObject, pEvent):
	# Get the list of enemies in this set.
	lEnemies = None
	pPlayer = None
	pGame = App.Game_GetCurrentGame()
	if pGame:
		pPlayer = pGame.GetPlayer()
		pEpisode = pGame.GetCurrentEpisode()
		if pEpisode:
			pMission = pEpisode.GetCurrentMission()
			if pMission:
				pEnemyGroup = pMission.GetEnemyGroup()

				pSet = pGame.GetPlayerSet()
				if pSet:
					lEnemies = pEnemyGroup.GetActiveObjectTupleInSet(pSet)

	# Remove enemies that cannot be seen on the player's sensors.
	pSensors = pPlayer.GetSensorSubsystem()
	lNewEnemies = []
	for pEnemy in lEnemies:
		if pSensors.IsObjectVisible(pEnemy):
			lNewEnemies.append(pEnemy)
	lEnemies = lNewEnemies


	if lEnemies and pPlayer:
		pTarget = pPlayer.GetTarget()
		pTargetMenu = App.STTargetMenu_GetTargetMenu()

		if (pTarget != None):
			# Iterate over the target list, and the next ship that is in
			# the enemy list will become our target.
			pItem = pTargetMenu.GetObjectEntry(pTarget)
			pNewItem = pTargetMenu.GetObjectEntry(pTarget)

			# Only loop through the target menu once.  It's possible, otherwise, for
			# the checks inside to loop forever.
			for iTarget in range( pTargetMenu.GetNumChildren() ):
				pNewItem = App.STSubsystemMenu_Cast(pTargetMenu.GetNextChild(pNewItem))

				if (pNewItem == None):
					pNewItem = App.STSubsystemMenu_Cast(pTargetMenu.GetFirstChild())

				if (str(pNewItem) == str(pItem)):
					# Cycled all the way through without finding the target.
					break

				# Check to see if this object is in the enemy list.
				pNewTarget = pNewItem.GetShip()

				if (pNewTarget == None):
					continue

				for pEnemy in lEnemies:
					if (pEnemy.GetObjID() == pNewTarget.GetObjID()):
						pPlayer.SetTarget(pNewTarget.GetName())
						pObject.CallNextHandler(pEvent)
						return
		else:
			# Find the first enemy target.
			pItem = App.STSubsystemMenu_Cast(pTargetMenu.GetFirstChild())

			while (pItem != None):
				pNewTarget = pItem.GetShip()

				if (pNewTarget != None):
					for pEnemy in lEnemies:
						if (pEnemy.GetObjID() == pNewTarget.GetObjID()):
							pPlayer.SetTarget(pNewTarget.GetName())
							pObject.CallNextHandler(pEvent)
							return

				pItem = App.STSubsystemMenu_Cast(pTargetMenu.GetNextChild(pItem))

	pObject.CallNextHandler(pEvent)

###############################################################################
#	TargetTargetsAttacker
#	
#	Target the nearest attacker of our current target.
#	
#	Args:	pObject	- Probably the tactical interface window.
#			pEvent	- The ET_INPUT_TARGET_TARGETS_ATTACKER event.
#	
#	Return:	None
###############################################################################
def TargetTargetsAttacker(pObject, pEvent):
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pTarget = pPlayer.GetTarget()
		if pTarget:
			TargetAttacker(pTarget, 1)

	pObject.CallNextHandler(pEvent)

###############################################################################
#	TargetNextNavPoint
#	
#	Target the next nav point.
#	
#	Args:	pObject	- The tactical interface window (unused)
#			pEvent	- The ET_INPUT_TARGET_NEXT_NAVPOINT event.
#	
#	Return:	None
###############################################################################
def TargetNextNavPoint(pObject, pEvent):
	# Get the player, and the player's set.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		if pSet:
			# Get the list of navpoints in this set.
			lNavPoints = pSet.GetNavPoints()
			if lNavPoints:
				iIndex = -1
				# Check if the player's current target is
				# a navpoint in this list.
				pTarget = App.PlacementObject_Cast(pPlayer.GetTarget())
				if pTarget:
					iOldNavIndex = 0
					for pNavPoint in lNavPoints:
						if pTarget.GetObjID() == pNavPoint.GetObjID():
							iIndex = iOldNavIndex
							break
						iOldNavIndex = iOldNavIndex + 1

				# Target the next navpoint
				iIndex = (iIndex + 1) % len(lNavPoints)
				pNavPoint = lNavPoints[iIndex]
				pPlayer.SetTarget(pNavPoint.GetName())

	pObject.CallNextHandler(pEvent)

###############################################################################
#	TargetNextPlanet
#	
#	Target the next planet.
#	
#	Args:	pObject	- The tactical interface window (unused)
#			pEvent	- The ET_INPUT_TARGET_NEXT_PLANET event.
#	
#	Return:	None
###############################################################################
def TargetNextPlanet(pObject, pEvent):
	# Get the player, and the player's set.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		if pSet:
			# Get the list of planets.
			lPlanets = list(pSet.GetClassObjectList(App.CT_PLANET))

			# Remove any suns from the list.  Don't want
			# to target suns, only planets.
			for pPlanet in lPlanets[:]:
				if pPlanet.IsTypeOf(App.CT_SUN):
					lPlanets.remove(pPlanet)

			if lPlanets:
				iIndex = -1
				# Check if the player's current target is
				# a planet in this list.
				pTarget = App.Planet_Cast(pPlayer.GetTarget())
				if pTarget:
					iOldIndex = 0
					for pPlanet in lPlanets:
						if pTarget.GetObjID() == pPlanet.GetObjID():
							iIndex = iOldIndex
							break
						iOldIndex = iOldIndex + 1

				# Target the next planet
				iIndex = (iIndex + 1) % len(lPlanets)
				pPlayer.SetTarget(lPlanets[iIndex].GetName())

	pObject.CallNextHandler(pEvent)

def ToggleCameraRotation(pObject, pEvent):
	# Enable or disable rotation of the camera.
	global g_bCameraRotationEnabled
	g_bCameraRotationEnabled = pEvent.GetBool()

def ToggleMapMode(pObject, pEvent):
	pTopWindow = App.TopWindow_GetTopWindow()
	pTopWindow.ToggleMapWindow()

	pObject.CallNextHandler(pEvent)

def ToggleCinematicMode(pObject, pEvent):
	# Change into cinematic mode..
	pTopWindow = App.TopWindow_GetTopWindow()
	pCinematic = App.CinematicWindow_Cast(pTopWindow.FindMainWindow(App.MWT_CINEMATIC))

	if (App.g_kUtopiaModule.IsMultiplayer() == 0) or (not pCinematic) or (pCinematic.IsInteractive() == 1):
		pTopWindow.ToggleCinematicWindow()

	pObject.CallNextHandler(pEvent)

def SkipEvents(pObject, pEvent):
	"Skips events."
	App.TGActionManager_SkipEvents()

def KillTarget(pObject, pEvent):
	if (App.g_kUtopiaModule.GetTestMenuState () < 2):
		return

	"Damages the targeted subsystem by 25%."
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		# Player exists.  Get its target.
		pTarget = pPlayer.GetTarget()
		if pTarget:
			pShipTarget = App.ShipClass_Cast(pTarget)
			if pShipTarget:
				# pHull = pShipTarget.GetHull()
				pSubsystem = pPlayer.GetTargetSubsystem()

				if (pSubsystem == None):
					pSubsystem = pShipTarget.GetHull()

				if pSubsystem:
					# Damage it by 25% of its maximum condition.
					pShipTarget.DamageSystem(pSubsystem, pSubsystem.GetMaxCondition() / 4.0)

	pObject.CallNextHandler(pEvent)

################################################################################
##	RepairShip(pObject, pEvent)
##
##	Repair Player's target completely.
##
##	Args:	pObject
##			pEvent
##
##	Return:	None
################################################################################
def RepairShip(pObject, pEvent):
	if (App.g_kUtopiaModule.GetTestMenuState () < 2):
		return

	# Get player's ship.
	pGame = App.Game_GetCurrentGame()
	if(pGame is None):
		return
	pShip = App.ShipClass_Cast(pGame.GetPlayer())
	if(pShip is None):
		return

	# Get player's target.
	pTarget = pShip.GetTarget()
	if(pTarget is None):
		return

	# Repair target completely.
	pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", 
										"RepairShipFully", pTarget.GetObjID())
	pAction.Play()

	pObject.CallNextHandler(pEvent)

################################################################################
##	ToggleGodMode(pObject, pEvent)
##
##	Toggle GOD mode.
##
##	Args:	pObject
##			pEvent
##
##	Return:	None
################################################################################
def ToggleGodMode(pObject, pEvent):
	if (App.g_kUtopiaModule.GetTestMenuState () < 2):
		return

	global pGODModeLabel
	pGame = App.Game_GetCurrentGame()
	if(pGame is None):
		return

	# Toggle flag.
	pGame.SetGodMode(not pGame.InGodMode())

	if(pGame.InGodMode()):
		# Get Player's ship.
		pPlayer = pGame.GetPlayer()

		if(pPlayer):
			# Repair ship completely.
			pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", 
												"RepairShipFully", 
												pPlayer.GetObjID())
			pAction.Play()

		# Turn on GOD Mode text label.
		pTopWindow = App.TopWindow_GetTopWindow()
		if(pTopWindow == None):
			return
		if(pGODModeLabel is None):
			pText = App.TGParagraph_Create("GOD MODE", 1.0, None, "Serpentine", 12.0)
			assert pText
			if(pText is None):
				return
			pText.SetColor(App.globals.g_kSTMenuTextColor)
			pText.Layout()
			pGODModeLabel = App.TGPane_Create(pText.GetWidth() + pText.GetWidth() / 8.0,
											pText.GetHeight() + pText.GetHeight() / 8.0)
			pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
			assert pGraphicsMode
			if(pGraphicsMode is None):
				return
			pcLCARS = pGraphicsMode.GetLcarsString()
			pBackground = App.TGIcon_Create(pcLCARS, 200, App.globals.g_kSTRadarBorderHighlighted)
			assert pBackground
			if(pBackground is None):
				return
			pBackground.Resize(pGODModeLabel.GetWidth(), pGODModeLabel.GetHeight())
			pGODModeLabel.AddChild(pText, pGODModeLabel.GetWidth() / 2.0 - pText.GetWidth() / 2.0,
									0.0)
			pGODModeLabel.AddChild(pBackground)
			pTopWindow.AddChild(pGODModeLabel, pTopWindow.GetWidth() - pGODModeLabel.GetWidth() -
								pGODModeLabel.GetHeight() / 5.0, pGODModeLabel.GetHeight() / 5.0)
		else:
			pGODModeLabel.SetVisible()
	else:
		# Turn off GOD Mode text label.
		pTopWindow = App.TopWindow_GetTopWindow()
		if(pTopWindow == None):
			return
		if(pGODModeLabel):
			pGODModeLabel.SetNotVisible()
	
	pObject.CallNextHandler(pEvent)

###############################################################################
#	LoadQuantums()
#	
#	Debug function that loads the player's ship with 10 quantum torpedoes
#	
#	Args:	pObject, pEvent	- object and event that called us
#	
#	Return:	none
###############################################################################
def LoadQuantums(pObject = None, pEvent = None):
	if (App.g_kUtopiaModule.GetTestMenuState () < 2):
		return

	MissionLib.LoadTorpedoes(None, "Quantum", 10)

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)
