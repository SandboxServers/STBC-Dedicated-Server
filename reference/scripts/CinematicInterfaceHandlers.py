###############################################################################
#	Filename:	CinematicInterfaceHandlers.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	User interface handlers for the Cinematic interface.
#	
#	Created:	10/5/00 -	KDeus
###############################################################################
import App
import Camera
#kDebugObj = App.CPyDebug()

# Event types only used in this file.  Initialized in Initialize().
ET_REMOVE_CAMERA_MODE_TEXT	= App.ET_INVALID

# our dictionary of key mappings.  We call InitKeyToEventMapping
g_dKeyToEventMapping = None

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
	# Initialize event types only used in this file.
	global ET_REMOVE_CAMERA_MODE_TEXT
	ET_REMOVE_CAMERA_MODE_TEXT	= App.Game_GetNextEventType()

	# Setup our event handlers.
	# A lot of our handling can be done by functions that
	# already exist in the tactical interface handlers.
	lEventHandlerMap = (
		(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	__name__ + ".ToggleCinematicMode"), 
		(App.ET_INPUT_CINEMATIC_DROPANDWATCH,	__name__ + ".CameraDropAndWatch"),
		(App.ET_INPUT_CINEMATIC_CHASE,			__name__ + ".CameraChase"),
		(App.ET_INPUT_CINEMATIC_TARGET,			__name__ + ".CameraTarget"),
		(App.ET_INPUT_CINEMATIC_TORPCAM,		__name__ + ".CameraTorpCam"),
		(App.ET_INPUT_CINEMATIC_WIDETARGET,		__name__ + ".CameraWideTarget"),
		(App.ET_INPUT_CINEMATIC_FREEORBIT,		__name__ + ".CameraFreeOrbit"),

		(App.ET_INPUT_SKIP_EVENTS,				"TacticalInterfaceHandlers.SkipEvents"),
		(App.ET_INPUT_ZOOM,						"TacticalInterfaceHandlers.Zoom"),

		(App.ET_QUICK_SAVE,						"BridgeHandlers.QuickSave"),
		(App.ET_QUICK_LOAD,						"BridgeHandlers.QuickLoad"),
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
	# If we're not in interactive mode, ignore all input.
	if not pWindow.IsInteractive():
		pWindow.CallNextHandler(pEvent)
		return

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
	# If we're not in interactive mode, ignore all input.
	if not pWindow.IsInteractive():
		# Except the "Skip Events" key, so the user can skip dialogue.
		if pEvent.GetUnicode() == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SKIP_EVENTS, App.KeyboardBinding.GET_EVENT, 0.0):
			# It's the Skip Events key.  Launch its event.
			if App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pWindow):
				pEvent.SetHandled()
				return

		pWindow.CallNextHandler(pEvent)
		return

	kState = pEvent.GetKeyState()
	kChar = pEvent.GetUnicode()

	import InterfaceHandlers
	InterfaceHandlers.TriggerKeyboardEvents(g_dKeyToEventMapping, pEvent, pWindow)

	# Trigger events from the input..
	if (pEvent.EventHandled() == 0):
		# Take care of the keyboard input..
		App.g_kKeyboardBinding.LaunchEvent(pEvent.GetUnicode(), pEvent.GetKeyState(), pWindow)

	if not pEvent.EventHandled():
		pWindow.CallNextHandler(pEvent)

###############################################################################
#	InitKeyToEventMapping()
#	
#	Define a table mapping keyboard events to event
#	types.
#	***REMOVE ME:  Once a good way to do this is being
#	handled in code, this stuff can go away.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def InitKeyToEventMapping():
	# A table to map keys to event types.  This also specifies
	# which type of event to create, and what extra function calls
	# need to be made to setup that event.
	#
	# As an example, to have a normal keypress of the '1' key send
	# an App.ET_HI float event, with a float value of 0.1, the
	# entry would look like this:
	# ('1', NORM):	( App.ET_HI, "TGFloatEvent", ( ("SetFloat", (1, )), ) )

	# Setup some abbreviations:
	NORM = App.TGKeyboardEvent.KS_NORMAL
	DOWN = App.TGKeyboardEvent.KS_KEYDOWN
	UP   = App.TGKeyboardEvent.KS_KEYUP

	# Build the table:
	global g_dKeyToEventMapping
	g_dKeyToEventMapping = {
		(App.WC_F1, DOWN):	(App.ET_INPUT_CINEMATIC_DROPANDWATCH,	"TGEvent", None),
		(App.WC_F2, DOWN):	(App.ET_INPUT_CINEMATIC_CHASE,			"TGEvent", None),
		(App.WC_F3, DOWN):	(App.ET_INPUT_CINEMATIC_TARGET,			"TGEvent", None),
		(App.WC_F4, DOWN):	(App.ET_INPUT_CINEMATIC_TORPCAM,		"TGEvent", None),
		(App.WC_F5, DOWN):	(App.ET_INPUT_CINEMATIC_WIDETARGET,		"TGEvent", None),
		(App.WC_F6, DOWN):	(App.ET_INPUT_CINEMATIC_FREEORBIT,		"TGEvent", None),
		}

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
	pEvent.SetHandled()

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
	# Rotate the camera (if applicable) based on the mouse movement.
	iMouseDX = App.g_kInputManager.GetMouseDeltaX()
	iMouseDY = App.g_kInputManager.GetMouseDeltaY()

	if iMouseDX  or  iMouseDY:
		pSet = App.g_kSetManager.GetRenderedSet()
		if pSet:
			pCamera = pSet.GetActiveCamera()
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

	# We'll do something once we decide what to do..
	pEvent.SetHandled()

###############################################################################
#	UpdateCameraModeText
#	
#	Update the display of which camera mode is currently active.
#	
#	Args:	sNewText	- Text for the new camera mode.
#	
#	Return:	None
###############################################################################
g_idCameraModeText = App.NULL_ID
g_idCameraModeTextTimer = App.NULL_ID
def UpdateCameraModeText(sNewText):
	global g_idCameraModeText, g_idCameraModeTextTimer

	pCameraModeText = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idCameraModeText))

	if pCameraModeText is None:
		# Text doesn't exist yet.  Create a pane for it.
		pCameraModeText = App.TGPane_Create()
		g_idCameraModeText = pCameraModeText.GetObjID()
		pCameraModeText.AddPythonFuncHandlerForInstance(ET_REMOVE_CAMERA_MODE_TEXT, __name__ + ".RemoveCameraModeText")

		# Make the text itself.
		pText = App.TGParagraph_Create(sNewText, 1.0, App.NiColorA_WHITE, "Serpentine", 12.0)
		pText.RecalcBounds()
		pCameraModeText.AddChild(pText, pText.GetWidth() * 0.1, pText.GetHeight() * 0.1)
		pCameraModeText.Resize(pText.GetWidth() * 1.2, pText.GetHeight() * 1.2)

		# Glass background.
		pGraphicsMode = App.GraphicsModeInfo_GetCurrentMode()
		if pGraphicsMode:
			pcLCARS = pGraphicsMode.GetLcarsString()

			pGlass = App.TGIcon_Create(pcLCARS, 120)
			pGlass.Resize(pCameraModeText.GetWidth(), pCameraModeText.GetHeight())

			pCameraModeText.AddChild(pGlass)

		pTopWindow = App.TopWindow_GetTopWindow()
		pCinematic = pTopWindow.FindMainWindow(App.MWT_CINEMATIC)
		pCinematic.AddChild(pCameraModeText, 1.0 - pCameraModeText.GetWidth(), 0)
	else:
		# Text exists.  Change the text...
		#print "Changing text."
		pText = App.TGParagraph_Cast(pCameraModeText.GetNthChild(0))
		if pText:
			pText.SetString(sNewText)
			pText.RecalcBounds()
			pText.SetPosition(pText.GetWidth() * 0.1, pText.GetHeight() * 0.1)

		# Resize and reposition the pane...
		pCameraModeText.Resize(pText.GetWidth() * 1.2, pText.GetHeight() * 1.2)
		pCameraModeText.SetPosition(1.0 - pCameraModeText.GetWidth(), 0)

		# Resize the glass...
		pGlass = pCameraModeText.GetNthChild(1)
		if pGlass:
			pGlass.Resize(pCameraModeText.GetWidth(), pCameraModeText.GetHeight())

		# Reset the timer.
		App.g_kTimerManager.DeleteTimer(g_idCameraModeTextTimer)
		# no need to set to App.NULL_ID, it is reset just below...


	# Start a timer to remove the text.
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(ET_REMOVE_CAMERA_MODE_TEXT)
	pEvent.SetDestination(pCameraModeText)

	pTimer = App.TGTimer_Create()
	pTimer.SetEvent(pEvent)
	pTimer.SetTimerStart( App.g_kUtopiaModule.GetGameTime() + 2.0 )

	g_idCameraModeTextTimer = pTimer.GetObjID()
	pEvent.SetInt(g_idCameraModeTextTimer)

	App.g_kTimerManager.AddTimer(pTimer)

###############################################################################
#	RemoveCameraModeText
#	
#	Event handler to remove the camera mode text that's displayed for
#	a little while.
#	
#	Args:	pText	- The text (UI object) to remove.
#			pEvent	- The event that triggered us.
#	
#	Return:	None
###############################################################################
def RemoveCameraModeText(pText, pEvent):
	global g_idCameraModeText, g_idCameraModeTextTimer
	#print __name__ + ": Remove camera mode text."

	idTimer = pEvent.GetInt()
	if idTimer == g_idCameraModeTextTimer:
		#print __name__ + ": Correct timer."
		# It's the right event.  Remove the text.
		pTopWindow = App.TopWindow_GetTopWindow()
		pCinematic = pTopWindow.FindMainWindow(App.MWT_CINEMATIC)
		pCinematic.DeleteChild(pText)

		g_idCameraModeTextTimer = App.NULL_ID
		g_idCameraModeText = App.NULL_ID

def ToggleCinematicMode(pObject, pEvent):
	# Change out of cinematic mode..
	pTopWindow = App.TopWindow_GetTopWindow()
	pCinematic = App.CinematicWindow_Cast(pTopWindow.FindMainWindow(App.MWT_CINEMATIC))

	if (App.g_kUtopiaModule.IsMultiplayer() == 0) or (not pCinematic) or (pCinematic.IsInteractive() == 1):
		pTopWindow.ToggleCinematicWindow()

	# Make sure the game is progressing at normal speed.
	App.g_kUtopiaModule.SetTimeScale(1.0)

	pObject.CallNextHandler(pEvent)

def CameraDropAndWatch(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayerCam = pGame.GetPlayerCamera()
	if pPlayerCam:
		pPlayerCam.AddModeHierarchy("InvalidCinematic", "DropAndWatch")
		UpdateCameraModeText("Flyby View")

	pObject.CallNextHandler(pEvent)

def CameraChase(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayerCam = pGame.GetPlayerCamera()
	if pPlayerCam:
		pPlayerCam.AddModeHierarchy("InvalidCinematic", "Chase")
		UpdateCameraModeText("Chase View")

	pObject.CallNextHandler(pEvent)

def CameraTarget(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayer = App.Game_GetCurrentPlayer()
	pSet = pGame.GetPlayerSet()
	pPlayerCam = pGame.GetPlayerCamera()

	if pPlayer and pPlayerCam and pSet:
		# Make sure the Reverse Target is setup with a valid source.
		pMode = pPlayerCam.GetNamedCameraMode("CinematicReverseTarget")
		if pMode:
			# Get the list of possible sources.
			# Sources don't need to be alive...
			lSources = pSet.GetTargetableObjects(pPlayer, 0)
			if lSources:
				iStartIndex = -1
				pCurrentSource = pMode.GetAttrIDObject("Source")
				if pCurrentSource:
					# Need to cycle to the next source.  Find where this
					# source is in the list of sources.
					idCurrent = pCurrentSource.GetObjID()
					for iIndex in range(len(lSources)):
						if idCurrent == lSources[iIndex].GetObjID():
							# Found it.
							iStartIndex = iIndex
							break

				# Cycle to the first available source.
				for iCount in range(len(lSources)):
					iStartIndex = (iStartIndex + 1) % len(lSources)
					pSource = lSources[iStartIndex];

					pMode.SetAttrIDObject("Source", pSource)
					break

			pPlayerCam.AddModeHierarchy("InvalidCinematic", "CinematicReverseTarget")
			UpdateCameraModeText("Reverse Cyclable View")

	pObject.CallNextHandler(pEvent)

def CameraTorpCam(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayerCam = pGame.GetPlayerCamera()
	if pPlayerCam:
		pPlayerCam.AddModeHierarchy("InvalidCinematic", "TorpCam")
		UpdateCameraModeText("Torpedo View")

	pObject.CallNextHandler(pEvent)

def CameraWideTarget(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayerCam = pGame.GetPlayerCamera()
	if pPlayerCam:
		pPlayerCam.AddModeHierarchy("InvalidCinematic", "WideTarget")
		UpdateCameraModeText("Wide Target View")

	pObject.CallNextHandler(pEvent)

def CameraFreeOrbit(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayerCam = pGame.GetPlayerCamera()
	if pPlayerCam:
		pPlayerCam.AddModeHierarchy("InvalidCinematic", "FreeOrbit")
		UpdateCameraModeText("Free Orbit View")

	pObject.CallNextHandler(pEvent)


#
# This has to be after the definition of this function, and we want
# to call it at module scope to set this variable only once.
#
InitKeyToEventMapping()
