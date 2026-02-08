###############################################################################
#	Filename:	Ep2Cutscene.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Cutscene for beginning of Episode 2.
#	
#	Created:	03/10/01 -	Jess VanDerwalker
#	Modified:	01/15/02 - 	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib

# Declare globals
g_pDatabase = None
g_pSaffi	= None

################################################################################
##	Initialize()
##
##	Does the setup that we need for the cutscene.  Cutscene is then played by a
##	script action call to PlayCutscene()
##
##	Args:	None
##
##	Return:	None
################################################################################
def Initialize():
	# Set the TGL database for the cutscene
	pMission = MissionLib.GetMission()
	if (pMission == None):
		return
		
	global g_pDatabase
	g_pDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 2/Ep2Cutscene.tgl")
	
	# Set a global pointer to Saffi so we can have her
	# speak the lines
	global g_pSaffi
	g_pSaffi	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")

	# Put Saffi in the turbo lift so I can have her walk out.
	g_pSaffi.SetStanding(1)
	g_pSaffi.SetRandomAnimationEnabled(0)
	g_pSaffi.SetHidden(0)
	g_pSaffi.SetLocation("DBL1M")

	# Load the regions that we'll need and their
	# placements.
	LoadPlacements()
	
	# Create the starting placements for objects
	CreateStartingObjects()
	
################################################################################
##	LoadPlacements()
##
##	Loads the placement files for the cutscene stuff.
##	Also loads the camera placements we'll be using on the bridge.
##	*** FIXME: Currently, this only loads the placements that are not loaded
##	by E2M1.py
##
##	Args:	None
##
##	Return:	None
################################################################################
def LoadPlacements():
	# Create Tevron 2 if it doesn't exist
	pTevron2Set =App.g_kSetManager.GetSet("Tevron2")
	if (pTevron2Set == None):
		pTevron2Set	= MissionLib.SetupSpaceSet("Systems.Tevron.Tevron2")
		
	# Get the bridge set so we can load placements into it.
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	
	import Ep2Cut_Tevron2_P
	Ep2Cut_Tevron2_P.LoadPlacements(pTevron2Set.GetName())
	
	import DBridge_P
	DBridge_P.LoadPlacements(pBridgeSet.GetName())

################################################################################
##	CreateStartingObjects()
##
##	Create the objects the exist at the beginning of the cutscene.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateStartingObjects():
	# Get the set we need
	pTevron2Set	= App.g_kSetManager.GetSet("Tevron2")	
	
	# Remove all the existing ships in the set
	for pShip in pTevron2Set.GetClassObjectList( App.CT_SHIP ):
		pTevron2Set.DeleteObjectFromSet( pShip.GetName() )
	
	# Get the set we need
	pTevron2Set	= App.g_kSetManager.GetSet("Tevron2")	
	# Place our starting objects
	pSovereign		= loadspacehelper.CreateShip("Sovereign", pTevron2Set, "Sov", "SovStart")
	pSovereign.ReplaceTexture("Data/Models/Ships/Sovereign/Sovereign.tga", "ID")
	pAmbassador		= loadspacehelper.CreateShip("Ambassador", pTevron2Set, "Ambassador", "ZhukovStart")
	pAmbassador.ReplaceTexture("Data/Models/Ships/Ambassador/Zhukov.tga", "ID")
	pGalaxy1		= loadspacehelper.CreateShip("Galaxy", pTevron2Set, "Galaxy1", "GalaxyStart")
	pGalaxy1.ReplaceTexture("data/Models/SharedTextures/FedShips/Dauntless.tga", "ID")
		
################################################################################
##	PlayCutscene()
##
##	Starts the top level sequence that calls other script functions to play
##	parts of the cutscene.  Called as script action
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def PlayCutscene(pTGAction):
	# Initialize the cutscene
	Initialize()
	
	# Give the galaxy it's AI
	pGalaxy	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Tevron2"), "Galaxy1")
	if (pGalaxy != None):
		import Cut_AI_Galaxy_Tevron
		pGalaxy.SetAI(Cut_AI_Galaxy_Tevron.CreateAI(pGalaxy))
	
	pSequence = App.TGSequence_Create()
	# Pre-load audio
	pPreLoad	= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	# Start the cutscene mode
	pCutsceneStart	= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	# Set all our cameras
	pStartCameraBridge	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pStartCameraTevron	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Tevron2")
	# Call our Tevron sequence and play it
	pTevronSequence	= App.TGScriptAction_Create(__name__, "TevronSequence")

	# Call our Galaxy sequence and play it
	pGalaxySequence	= App.TGScriptAction_Create(__name__, "GalaxySequence")
	
	# Call the bridge sequence and play it
	pBridgeSequence	= App.TGScriptAction_Create(__name__, "BridgeSequence")
	
	# End the cutscene
	pCutsceneEnd	= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	
	# Remove control from the player again
	pRemoveControl	= App.TGScriptAction_Create(__name__, "RemoveControl")
	
	# Clean up all our cameras and sundry stuff
	pCleanUp	= App.TGScriptAction_Create(__name__, "CleanUp")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCutsceneStart)	
	pSequence.AppendAction(pStartCameraBridge)
	pSequence.AppendAction(pStartCameraTevron)
	pSequence.AppendAction(pTevronSequence)
	pSequence.AppendAction(pGalaxySequence)
	pSequence.AppendAction(pBridgeSequence)
	pSequence.AppendAction(pCutsceneEnd, 1)
	pSequence.AppendAction(pRemoveControl)
	pSequence.AppendAction(pCleanUp)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)
	
	pSequence.Play()
	
	return 1

################################################################################
##	TevronSequence()
##
##	The part of the sequence that takes place in the Tevron2 set.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep the calling sequence paused
################################################################################
def TevronSequence(pTGAction):
	# Get the ships so we can warp them out
	pSet = App.g_kSetManager.GetSet("Tevron2")
	pSov = App.ShipClass_GetObject(pSet, "Sov")
	pAmb = App.ShipClass_GetObject(pSet, "Ambassador")
	
	# Bail if the ships don't exist
	if (pSov == None) or (pAmb == None):
		return 0
		
	pSequence = App.TGSequence_Create()
	
	# Move the camera to the outside view in Tevron.
	pChangeToTevron		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Tevron2")
	pPlaceCameraStart	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "Tevron2", "Sov", "SovCamStart")
	# Do the lines for Saffi
	pEp2Cut1		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut1", None, 0, g_pDatabase)
	pEp2Cut2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut2", None, 0, g_pDatabase)
	pEp2Cut3		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut3", None, 0, g_pDatabase)
	pWarpAmbassador	= App.WarpSequence_Create(pAmb, None, 0.1)
	pWarpSov		= App.WarpSequence_Create(pSov, None, 0.1)
	
	pSequence.AddAction(pChangeToTevron)
	pSequence.AppendAction(pPlaceCameraStart)

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeOut", 0))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeIn", 2))

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EpisodeTitleAction", "Ep2Title"))

	pSequence.AppendAction(pEp2Cut1)
	pSequence.AppendAction(pEp2Cut2)
	pSequence.AppendAction(pEp2Cut3, 0.5)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.AddAction(pWarpAmbassador, pEp2Cut2, 7)
	pSequence.AddAction(pWarpSov, pEp2Cut2, 7.3) 
	
	pSequence.Play()
	
	return 1

################################################################################
##	GalaxySequence()
##
##	The part of the sequence that does cinematic of Galaxy in Tevron set.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused
################################################################################
def GalaxySequence(pTGAction):
	pSequence = App.TGSequence_Create()
	
	# Watch the Galaxy from our placement
	pWatchGalaxy1	= App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Tevron2", "Galaxy1")
	# Do the lines for Saffi
	pEp2Cut4 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut4", None, 0, g_pDatabase)
	pEp2Cut5 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut5", None, 0, g_pDatabase)
	pEp2Cut6 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut6", None, 0, g_pDatabase)
	pEp2Cut7 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut7", None, 0, g_pDatabase)
	pEp2Cut8 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut8", None, 0, g_pDatabase)
	
	pSequence.AppendAction(pWatchGalaxy1)
	pSequence.AppendAction(pEp2Cut4)
	pSequence.AppendAction(pEp2Cut5, 0.5)
	pSequence.AppendAction(pEp2Cut6)
	pSequence.AppendAction(pEp2Cut7, 0.5)
	pSequence.AppendAction(pEp2Cut8, 0.5)
	
	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)
	
	pSequence.Play()
	
	return 1

################################################################################
##	BridgeSequence()
##
##	The part of the sequence that takes place on the bridge.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep the calling sequence paused.
################################################################################
def BridgeSequence(pTGAction):
	pSequence = App.TGSequence_Create()
	
	# Switch back to the bridge and place the Camera
	pChangeToBridge		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pCameraWatchSaffi	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementOffsetWatch", "bridge", "XO", "SaffiCamStatic", 0, 0, 25)
	# Saffi's walk to her seat
	pSaffiWalkToC	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
	# Switch to dolly cam
	pSaffiHeadCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementOffsetWatch", "bridge", "XO", "SaffiPanStart", 0, 0, 25)
	# Do Saffi's lines
	pEp2Cut9	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut9", None, 0, g_pDatabase)
	pEp2Cut10	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "Ep2Cut10", None, 0, g_pDatabase)
	
	pSequence.AddAction(pChangeToBridge)
	pSequence.AddAction(pCameraWatchSaffi,	pChangeToBridge)
	pSequence.AddAction(pSaffiWalkToC,		pCameraWatchSaffi, 1)
	pSequence.AddAction(pEp2Cut9,			pCameraWatchSaffi, 1)
	pSequence.AddAction(pSaffiHeadCam,		pCameraWatchSaffi, 7)
	pSequence.AddAction(pEp2Cut10,			pEp2Cut9)
	
	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)
	
	pSequence.Play()
	
	return 1

################################################################################
##	CleanUp()
##
##	Cleans up everything left over by the cutscene, including cameras and
##	TGL stuff.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def CleanUp(pTGAction):
	pSequence = App.TGSequence_Create()

	# Remove all our cameras
	pEndCameraBridge	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pEndCameraSpace		= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Tevron2")
	
	pSequence.AppendAction(pEndCameraBridge)
	pSequence.AppendAction(pEndCameraSpace)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)
	
	pSequence.Play()
	
	# Delete the spare Galaxy we created.
	pSet = App.g_kSetManager.GetSet("Tevron2")
	if (pSet != None):
		pSet.DeleteObjectFromSet("Galaxy1")
	
	# Change the mission database back to the correct TGL
	pMission = App.Game_GetCurrentGame().GetCurrentEpisode().GetCurrentMission()
	pMission.SetDatabase("data/TGL/Maelstrom/Episode 2/E2M1.tgl")
	
	return 1

################################################################################
##	RemoveControl()
##
##	Script action that calls itself over and over until cutscene mode ends, and
##	then removes control from the player.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def RemoveControl(pTGAction):
	if (App.TopWindow_GetTopWindow().IsCutsceneMode() == 0):
		# No longer in cutscene, remove control and look forward
		MissionLib.RemoveControl()
		MissionLib.LookForward(None)
		return 0
		
	else:
		# Call this again.
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "RemoveControl"), 0.1)
		pSequence.Play()
		return 0
		
