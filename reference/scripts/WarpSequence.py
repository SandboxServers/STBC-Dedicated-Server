###############################################################################
#	Filename:	WarpSequence.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Contains most of the interesting stuff with regards to the warp sequence.
#	
#	Created:	8/22/2001 -	Erik Novales
###############################################################################

import App
import string
import MissionLib

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

###############################################################################
#	SetupSequence
#	
#	Setup the warp sequence.
#	
#	Args:	pWS	- The WarpSequence object we're setting up.
#	
#	Return:	none
###############################################################################
def SetupSequence(pWS):
	fEntryDelayTime = 1.0
	pShip = pWS.GetShip()
	pPlayer = App.Game_GetCurrentPlayer()

	if (pShip == None):
		return

	# Get the destination set name from the module name, if applicable.
	pcDest = None
	pcDestModule = pWS.GetDestination()
	if (pcDestModule != None):
		pcDest = pcDestModule[string.rfind(pcDestModule, ".") + 1:]
		if (pcDest == None):
			pcDest = pcDestModule

	pWarpSet = App.WarpSequence_GetWarpSet()

	pPreWarp = App.TGSequence_Cast(pWS.GetWarpSequencePiece(pWS.PRE_WARP_SEQUENCE))
	pDuringWarp = App.TGSequence_Cast(pWS.GetWarpSequencePiece(pWS.DURING_WARP_SEQUENCE))
	pPostDuringWarp = App.TGSequence_Cast(pWS.GetWarpSequencePiece(pWS.POST_DURING_WARP_SEQUENCE))
	pPostWarp = App.TGSequence_Cast(pWS.GetWarpSequencePiece(pWS.POST_WARP_SEQUENCE))
	pWarpBeginAction = pWS.GetWarpSequencePiece(pWS.WARP_BEGIN_ACTION)
	pWarpEndAction = pWS.GetWarpSequencePiece(pWS.WARP_END_ACTION)
	pDewarpBeginAction = pWS.GetWarpSequencePiece(pWS.DEWARP_BEGIN_ACTION)
	pDewarpEndAction = pWS.GetWarpSequencePiece(pWS.DEWARP_END_ACTION)
	pWarpEnterAction = pWS.GetWarpSequencePiece(pWS.WARP_ENTER_ACTION)
	pDewarpFinishAction = pWS.GetWarpSequencePiece(pWS.DEWARP_FINISH_ACTION)
	pMoveAction1 = pWS.GetWarpSequencePiece(pWS.MOVE_ACTION_1)
	pMoveAction2 = pWS.GetWarpSequencePiece(pWS.MOVE_ACTION_2)

	# Keep track of which action is the final action in the warp sequence,
	# so we can attach the m_pPostWarp sequence to the end.  By default,
	# pMoveAction2 is the final action...
	pFinalAction = pMoveAction2
	pWarpSoundAction1 = None

	if (pPlayer != None) and (pShip.GetObjID() == pPlayer.GetObjID()):
		# Clear the player's target when they go into warp.
		import TacticalInterfaceHandlers
		TacticalInterfaceHandlers.ClearTarget(None, None)

		fEntryDelayTime = fEntryDelayTime + 1.0

		# Force a noninteractive cinematic view in space..
		pCinematicStart = App.TGScriptAction_Create("Actions.CameraScriptActions", "StartCinematicMode", 0)
		pWS.AddAction(pCinematicStart, pPreWarp)

		pDisallowInput = App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pWS.AddAction(pDisallowInput, pCinematicStart)

		if pWS.GetOrigin() != None:
			pWarpSoundAction1 = App.TGSoundAction_Create("Enter Warp", App.TGSAF_DEFAULTS, pWS.GetOrigin().GetName())
		else:
			pWarpSoundAction1 = App.TGSoundAction_Create("Enter Warp")

		pWarpSoundAction1.SetNode(pShip.GetNode())
		pWS.AddAction(pWarpSoundAction1, pPreWarp, max(0.0, fEntryDelayTime - 1.5))
	elif (pWS.GetOrigin() != None):
		pWarpSoundAction1 = App.TGSoundAction_Create("Enter Warp", App.TGSAF_DEFAULTS, pWS.GetOrigin().GetName())
		pWarpSoundAction1.SetNode(pShip.GetNode())
		pWS.AddAction(pWarpSoundAction1, pPreWarp, max(0.0, fEntryDelayTime - 1.5))

	# Finish assembling the sequence here.
	pWS.AddAction(pWarpBeginAction, pPreWarp, fEntryDelayTime)

	# Move the ship (the second part of the warping effect).
	pWS.AddAction(pWarpEndAction, pWarpBeginAction, App.WarpEngineSubsystem_GetWarpEffectTime() / 2.0)

	# Create the warp flash.
	pFlashAction1 = App.TGScriptAction_Create("Actions.EffectScriptActions", "WarpFlash", pShip.GetObjID())
	pWS.AddAction(pFlashAction1, pWarpEndAction, App.WarpEngineSubsystem_GetWarpEffectTime() / 2.0)

	# Hide the ship.
	pWS.AppendAction(App.TGScriptAction_Create(__name__, "HideShip", pShip.GetObjID()))

	# Place the ship in the warp set, shortly after the warp flash is created (don't
	# want the two to land on the same frame).
	pWS.AddAction(pMoveAction1, pFlashAction1, 0.5)

	pPreDuringWarpAction = pMoveAction1

	# If it's the player, change the rendered set after a couple of seconds.
	if (pPlayer != None) and (pShip.GetObjID() == pPlayer.GetObjID()):
		if (App.g_kUtopiaModule.IsMultiplayer()):
			pCRSA1 = App.ChangeRenderedSetAction_CreateFromSet(pWarpSet)
		else:
			pCRSA1 = App.ChangeRenderedSetAction_CreateFromSet(App.g_kSetManager.GetSet("bridge"))
		

		pWS.AddAction(pCRSA1, pMoveAction1, 2.0)

		# Set the bridge camera to look forward.
		if not App.g_kUtopiaModule.IsMultiplayer():
			pWS.AddAction( App.TGScriptAction_Create(__name__, "BridgeCameraForward"), pCRSA1 )

		# Setup a cutscene camera for the warp set.
		pCutsceneCameraBegin = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", 
														 pWarpSet.GetName(), "WarpCutsceneCamera")
		pWS.AddAction(pCutsceneCameraBegin, pCRSA1)

		# Change the viewscreen to use this camera, if we're not in cutscene mode.
		pChangeViewscreenAction = App.TGScriptAction_Create(__name__, "CheckForBeginningCameraChange")
		pWS.AddAction(pChangeViewscreenAction, pCutsceneCameraBegin)

		pOrientCameraAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "SetCameraPositionAndFacing",
														pWarpSet.GetName(), "WarpCutsceneCamera",
														0.0, 0.0, 0.0,
														0.0, 1.0, 0.0,
														0.0, 0.0, 1.0)
		pWS.AddAction(pOrientCameraAction, pChangeViewscreenAction)

		# During-warp actions will be delayed, in this case, until the camera
		# has a chance to move to the player's set and get set up.
		pPreDuringWarpAction = pOrientCameraAction
	
	# Tell the warp engine subsystem that we've entered warp.
	pWS.AddAction(pWarpEnterAction, pMoveAction1)

	# If this is the player, add the action that will wait until queued sequences are done.
	pPrevious = pPreDuringWarpAction
	if pPlayer and (pShip.GetObjID() == pPlayer.GetObjID()):
		pWaitForQueued = App.TGScriptAction_Create(__name__, "WaitForQueued")
		pWS.AddAction(pWaitForQueued, pPreDuringWarpAction)
		pPrevious = pWaitForQueued

	# Trigger during-warp actions.
	pWS.AddAction(pDuringWarp, pPrevious)

	# Add sequence for post-during warp actions.
	pWS.AddAction(pPostDuringWarp, pDuringWarp)

	if (App.g_kUtopiaModule.IsMultiplayer() == 0):
		# Add the action for setting the destination placement in the warp subsystem. This
		# has to go after the during-warp action, since mission changing may load new systems.
		pSetPlacementAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "SetWarpPlacement", 
														pShip.GetObjID(), pcDest, pWS.GetPlacementName())
		pPostDuringWarp.AddAction(pSetPlacementAction)
	else:	
		pSet = pWS.GetDestinationSet()
		fRadius = pShip.GetRadius() * 1.25

		while (1):
			# Set an exit point instead.  Randomly generate an exit point.
			kExitPoint = App.TGPoint3()
			kExitPoint.x = App.g_kSystemWrapper.GetRandomNumber(200)
			kExitPoint.x = kExitPoint.x - 100.0
			kExitPoint.y = App.g_kSystemWrapper.GetRandomNumber(200)
			kExitPoint.y = kExitPoint.y - 100.0
			kExitPoint.z = App.g_kSystemWrapper.GetRandomNumber(200)
			kExitPoint.z = kExitPoint.z - 100.0

			if (pSet == None):
				break
			elif (pSet.IsLocationEmptyTG (kExitPoint, fRadius)):
				pWS.SetExitPoint(kExitPoint)
				break
		
		pSetExitPointAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "SetWarpExitPoint", 
														pShip.GetObjID(), pcDest, 
														kExitPoint.x, kExitPoint.y, kExitPoint.z)
		pPostDuringWarp.AddAction(pSetExitPointAction)
	
	# Move the ship from the warp set to the destination set 
	# after the warp delay.  If the new set is None, this just
	# deletes the object.
	pPostDuringWarp.AddAction( App.TGScriptAction_Create(__name__, "CheckWarpInPath", pWS, pShip.GetObjID()), None, pWS.GetTimeToWarp() )
	pPostDuringWarp.AppendAction(pDewarpBeginAction)
	pPostDuringWarp.AppendAction(pMoveAction2)

	# Add the actions for exiting warp only if the destination set exists.
	if(pWS.GetDestinationSet() != None):
		fFlashDelay = pWS.GetTimeToWarp() - 0.5
		if(fFlashDelay < 0.0):
			fFlashDelay = 0.0
		fSwitchSetsDelay = fFlashDelay - 0.1
		if(fSwitchSetsDelay < 0.0):
			fSwitchSetsDelay = 0.0

		# If the player is the one warping, change the rendered set to the
		# player's new set.  Do this before the warp flash is created, so
		# the warp flash sound plays.  Also do it before the warp exit sound,
		# for the same reason.
		if (pPlayer != None) and (pShip.GetObjID() == pPlayer.GetObjID()):
			pCRSA2 = App.ChangeRenderedSetAction_Create(pcDestModule)
			pPostDuringWarp.AddAction(pCRSA2, App.TGAction_CreateNull(), fSwitchSetsDelay)

			# Get rid of the cutscene camera in the warp set.
			pCutsceneCameraEnd = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", 
														   pWarpSet.GetName(), "WarpCutsceneCamera")
			pPostDuringWarp.AddAction(pCutsceneCameraEnd, pCRSA2)

			# Setup a cutscene camera for the destination set.
			pCutsceneCameraBegin = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin",
															 pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera")
			pPostDuringWarp.AddAction(pCutsceneCameraBegin, pCutsceneCameraEnd)

			# Add actions to move the camera in the destination set to watch the placement,
			# so we can watch the ship come in.
			# Initial position is reverse chasing the placement the ship arrives at.
			if (App.g_kUtopiaModule.IsMultiplayer()):
				# Multiplayer watches the exit point rather than the exit placement
				# Create a placement object at the exit point.
				pMPPlacement = App.PlacementObject_Create(pShip.GetName() + "MPWarp1" + str(App.g_kUtopiaModule.GetGameTime()), pcDest, None)
				pMPPlacement2 = App.PlacementObject_Create(pShip.GetName() + "MPWarp2" + str(App.g_kUtopiaModule.GetGameTime()), pcDest, None)

				kPlayerFwd = pPlayer.GetWorldForwardTG()
				pMPPlacement.SetTranslateXYZ(kExitPoint.x, kExitPoint.y + (kPlayerFwd.y * 700.0), kExitPoint.z)
				pMPPlacement2.SetTranslateXYZ(kExitPoint.x, kExitPoint.y, kExitPoint.z)

				# look at where the player will come in
				pCameraAction3 = App.TGScriptAction_Create("Actions.CameraScriptActions", "TargetWatch", pcDest, pMPPlacement.GetName(), pMPPlacement2.GetName())
				pPostDuringWarp.AddAction(pCameraAction3, pCutsceneCameraBegin)
				# then, look at the player
				pCameraAction4 = App.TGScriptAction_Create("Actions.CameraScriptActions", "TargetWatch", pcDest, pMPPlacement.GetName(), pPlayer.GetName(), 0)
				pPostDuringWarp.AddAction(pCameraAction4, pMoveAction2)
			else:
				if(pWS.GetPlacementName() != None):
					fSideOffset = (App.g_kSystemWrapper.GetRandomNumber(1400) - 700) / 100.0

					pCameraAction4 = App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch",
															   pcDest, pWS.GetPlacementName())
					pPostDuringWarp.AddAction(pCameraAction4, pCutsceneCameraBegin)
					pPostDuringWarp.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
																		   pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera", "DropAndWatch",
																		   "SetAttrFloat", "AwayDistance", 100000.0))
					pPostDuringWarp.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
																		   pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera", "DropAndWatch",
																		   "SetAttrFloat", "ForwardOffset", 10.0))
					pPostDuringWarp.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
																		   pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera", "DropAndWatch",
																		   "SetAttrFloat", "SideOffset", fSideOffset))
					pPostDuringWarp.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
																		   pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera", "DropAndWatch",
																		   "SetAttrFloat", "RangeAngle1", 70.0))
					pPostDuringWarp.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
																		   pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera", "DropAndWatch",
																		   "SetAttrFloat", "RangeAngle2", 110.0))
					pPostDuringWarp.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
																		   pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera", "DropAndWatch",
																		   "SetAttrFloat", "RangeAngle3", -10.0))
					pPostDuringWarp.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetModeAttribute",
																		   pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera", "DropAndWatch",
																		   "SetAttrFloat", "RangeAngle4", 10.0))
					pPostDuringWarp.AppendAction(App.TGScriptAction_Create(__name__, "FixCamera", pWS.GetDestinationSet().GetName(), "WarpCutsceneCamera"))
			

		# Create the second warp flash, slightly before the ship gets there.
		pFlashAction2 = App.TGScriptAction_Create("Actions.EffectScriptActions", "WarpFlashEnterSet", 
												  pcDestModule, pShip.GetObjID())
		pPostDuringWarp.AddAction(pFlashAction2, App.TGAction_CreateNull(), fFlashDelay)

		# Actions for the de-warping effect. The initiate action happens earlier.
		pPostDuringWarp.AddAction(pDewarpEndAction, pDewarpBeginAction, App.WarpEngineSubsystem_GetWarpEffectTime() / 2.0)
		pPostDuringWarp.AddAction(pDewarpFinishAction, pDewarpEndAction, App.WarpEngineSubsystem_GetWarpEffectTime() / 2.0)

		# Start the warp exit sound
		pWarpSoundAction2 = None
		if pPlayer and (pShip.GetObjID() == pPlayer.GetObjID()):
			if pWS.GetDestinationSet() != None:
				pWarpSoundAction2 = App.TGSoundAction_Create("Exit Warp", App.TGSAF_DEFAULTS, pWS.GetDestinationSet().GetName())
			else:
				pWarpSoundAction2 = App.TGSoundAction_Create("Exit Warp")
		else:
			if pWS.GetDestinationSet() != None:
				pWarpSoundAction2 = App.TGSoundAction_Create("Exit Warp", App.TGSAF_DEFAULTS, pWS.GetDestinationSet().GetName())
			else:
				pWarpSoundAction2 = App.TGSoundAction_Create("Exit Warp")

		pWarpSoundAction2.SetNode(pShip.GetNode())
		pPostDuringWarp.AddAction(pWarpSoundAction2, App.TGAction_CreateNull(), pWS.GetTimeToWarp() + 0.1)

		# This ship will be coming out of warp.  Update the Final Action so it
		# points to the last action after the ship comes out of warp...
		pFinalAction = pDewarpFinishAction

		# Make the ship move a little bit after warping, by default.
		pCoastAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "SetImpulse", 
												 pShip.GetObjID(), 0.2)
		pPostDuringWarp.AddAction(pCoastAction, pDewarpFinishAction)
	

	# Drop out of cinematic mode, if we were in cinematic mode.
	if pPlayer and (pShip.GetObjID() == pPlayer.GetObjID()):
		pCheckAction = App.TGScriptAction_Create(__name__, "CheckForCameraChange")
		pPostDuringWarp.AddAction(pCheckAction, pFinalAction, 2.0)
		pAllowInput = App.TGScriptAction_Create(__name__, "CheckForReturnControl")
		pPostDuringWarp.AddAction(pAllowInput, pCheckAction)

		pFinalAction = pAllowInput
	

	# Do post-warp actions.
	pWS.AddAction(pPostWarp, pPostDuringWarp)

	if pPlayer and (pShip.GetObjID() == pPlayer.GetObjID()):
		pWS.AddAction(App.TGScriptAction_Create("Bridge.HelmMenuHandlers", "PostWarpEnableMenu"), pPostWarp)

###############################################################################
#	BridgeCameraForward
#	
#	Helper function for the warp sequence.  Get tbe main bridge
#	camera, and set it to look forward.
#	
#	Args:	pAction - the action
#	
#	Return:	zero for end
###############################################################################
def BridgeCameraForward(pAction):
	# Get the bridge...
	pSet = App.g_kSetManager.GetSet("bridge")
	if pSet:
		# Get the main camera for the captain's view.
		pCamera = App.ZoomCameraObjectClass_Cast( pSet.GetCamera("maincamera") )
		if pCamera:
			# Tell the camera to look forward.
			pCamera.LookForward()

	return 0

###############################################################################
#	HideShip(pAction, iShipID)
#	
#	Hides a ship. Used to mask the ship during the warp flash.
#	
#	Args:	pAction	- the action
#			iShipID	- the ID of the ship
#	
#	Return:	zero for end
###############################################################################
def HideShip(pAction, iShipID):
	pShip = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), iShipID)
	if pShip:
		pShip.SetHidden(1)

	return 0

###############################################################################
#	CheckForBeginningCameraChange(pAction)
#	
#	If somebody else is on the viewscreen, don't change the viewscreen camera 
#	(but do change the player camera so when the viewscreen is switched, the
#	view looks right).
#	
#	Args:	pAction	- the action
#	
#	Return:	zero for end
###############################################################################
def CheckForBeginningCameraChange(pAction):
	pGame = App.Game_GetCurrentGame()
	pBridge = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pWarpSet = App.WarpSequence_GetWarpSet()

	if not pBridge or not pGame or not pWarpSet:
		return 0

	pVS = pBridge.GetViewScreen()
	pPlayerCamera = pGame.GetPlayerCamera()
	if not pVS or not pPlayerCamera:
		return 0

	pCamera = pVS.GetRemoteCam()
	if not pCamera:
		return 0

	if str(pCamera) == str(pPlayerCamera):
		pChangeViewscreenAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "SetViewscreenCamera", 
															pWarpSet.GetName(), "WarpCutsceneCamera")
		pChangeViewscreenAction.Play()
	else:
		pOrientCameraAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "SetCameraPositionAndFacing",
														pWarpSet.GetName(), pPlayerCamera.GetName(),
														0.0, 0.0, 0.0,
														0.0, 1.0, 0.0,
														0.0, 0.0, 1.0)
		pOrientCameraAction.Play()

	return 0

###############################################################################
#	CheckForCameraChange(pAction)
#	
#	Checks if the viewscreen camera should be changed at the end of the warp
#	sequence.
#	
#	Args:	pAction	- the action
#	
#	Return:	zero for end
###############################################################################
def CheckForCameraChange(pAction):
	pTop = App.TopWindow_GetTopWindow()
	pGame = App.Game_GetCurrentGame()

	if not pGame:
		return 0

	pPlayer = App.Game_GetCurrentPlayer()
	pcDest = pPlayer.GetContainingSet().GetName()
	pPlayerCamera = pGame.GetPlayerCamera()
	pcPlayerCameraName = None
	if pPlayerCamera:
		pcPlayerCameraName = pPlayerCamera.GetName()

#	debug("Player camera: " + str(pcPlayerCameraName))

	pBridge = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	if pBridge:
		pViewscreen = pBridge.GetViewScreen()

		if pViewscreen:
			pViewscreenCamera = pViewscreen.GetRemoteCam()

			if pViewscreenCamera and (pViewscreenCamera.GetName() == "WarpCutsceneCamera"):
#				debug("Was using warp cutscene camera on the viewscreen, changing...")
				# Switch to something reasonable.
				pViewscreen.SetRemoteCam(pPlayerCamera)

	# Get rid of the cutscene camera in the destination set.
	pCutsceneCameraEnd = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd",
												   pcDest, "WarpCutsceneCamera")
	pCutsceneCameraEnd.Play()

	# Don't touch the viewscreen camera if we're in a cutscene, apart from
	# changing from the warp camera above.
	if pTop.IsCutsceneMode():
#		debug("Was in cutscene mode, not resetting viewscreen camera")
		return 0

#	debug("Was not in cutscene mode, resetting viewscreen camera")

	# Change the viewscreen to use the active camera in the new set.
	pChangeViewscreenAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "SetViewscreenCamera",
														pcDest, pcPlayerCameraName)
	pChangeViewscreenAction.Play()

	if App.g_kUtopiaModule.IsMultiplayer():
		# set options window flag, just in case we're in options.
		pOptions = App.OptionsWindow_Cast(pTop.FindMainWindow(App.MWT_OPTIONS))
		pTactical = pTop.FindMainWindow(App.MWT_TACTICAL)

		pOptions.RemoveAllPreviouslyVisible()
		pOptions.AddToPreviouslyVisible(pTactical)
		pOptions.AddToPreviouslyVisible(pTop.FindMainWindow(App.MWT_MULTIPLAYER))
		pOptions.AddToPreviouslyVisible(pTop.FindMainWindow(App.MWT_SUBTITLE))
		pOptions.SetHasFocusObject(pTactical)

		pTop.MoveToFront(pTactical, 0)
		pTop.MoveTowardsBack(pTactical, 0)

		pCinematic = pTop.FindMainWindow(App.MWT_CINEMATIC)
		pTop.MoveToBack(pCinematic, 0)

	return 0

###############################################################################
#	CheckForReturnControl(pAction)
#	
#	Used at the end of the warp sequence. If we're in cutscene mode (i.e. a
#	cutscene started when the player entered the set), we don't do anything.
#	Otherwise, we re-enable input.
#	
#	Args:	pAction	- the action
#	
#	Return:	zero for end
###############################################################################
def CheckForReturnControl(pAction):
	pTop = App.TopWindow_GetTopWindow()

	if pTop.IsCutsceneMode():
		return 0

	# Drop out of cinematic view...
	pCinematicStop = App.TGScriptAction_Create("Actions.CameraScriptActions", "StopCinematicMode")
	pCinematicStop.Play()

	# Ensure that we're in interactive mode.
	pCinematic = App.CinematicWindow_Cast(pTop.FindMainWindow(App.MWT_CINEMATIC))
	pCinematic.SetInteractive(1)

	pAllowInput = App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pAllowInput.Play()

	return 0

###############################################################################
#	FixCamera(pAction, sSetName, sCameraName)
#	
#	Fixes the warp camera -- forces an update so that the new camera
#	settings are taken into account.
#	
#	Args:	pAction		- the action
#			sSetName	- the set name
#			sCameraName	- the camera name
#	
#	Return:	zero for end
###############################################################################
def FixCamera(pAction, sSetName, sCameraName):
	pSet = App.g_kSetManager.GetSet(sSetName)

	if pSet == None:
		return 0

	pCamera = App.CameraObjectClass_GetObject(pSet, sCameraName)

	if pCamera == None:
		return 0

	# Force an update of the camera that will reposition the camera.
	pMode = pCamera.GetCurrentCameraMode()
	if pMode == None:
		return 0

	pMode.SetAttrFloat("AwayDistance", -1.0)
	pMode.Update()
	pMode.SetAttrFloat("AwayDistance", 100000.0)

	return 0

###############################################################################
#	WaitForQueued(pAction, pEvent)
#	
#	Action that will wait for queued actions to finish playing before
#	continuing with the warp sequence.
#	
#	Args:	pAction	- the action
#			pEvent	- the event, if any
#	
#	Return:	zero for end, one for wait
###############################################################################
def WaitForQueued(pAction, pEvent = None):
	pPlayer = App.Game_GetCurrentPlayer()

	if not pPlayer:
		return 0

#	debug = App.CPyDebug(__name__).Print
	
	if not pEvent:
		# This is the first time we are being called. Set up the "sequence
		# completed" event with the MissionLib queue.
		pQueue = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(MissionLib.g_idMasterSequenceObj))

		if pQueue:
#			debug("WaitForQueued(): there is a queued sequence")	
			# Add the "completed" event.
			pCompletedEvent = App.TGEvent_Create()
			pCompletedEvent.SetSource(pAction)
			pCompletedEvent.SetDestination(pPlayer)
			pCompletedEvent.SetEventType(App.ET_OKAY)		# This will never be sent to us otherwise.
			pQueue.AddCompletedEvent(pCompletedEvent)

			pPlayer.AddPythonFuncHandlerForInstance(App.ET_OKAY, __name__ + ".WaitForQueued")

			# And now we wait.
			return 1
		else:
			# No queue. We can go right ahead.
			return 0

#	debug("WaitForQueued(): queued sequence is done")
	pPlayer.RemoveHandlerForInstance(App.ET_OKAY, __name__ + ".WaitForQueued")

	# Add an event to end this action when the sound finishes, so the sequence
	# acts properly
	pCompletedEvent = App.TGObjPtrEvent_Create()
	pCompletedEvent.SetDestination(App.g_kTGActionManager)
	pCompletedEvent.SetObjPtr(pEvent.GetSource())	# in this case, pAction is not the action...
	pCompletedEvent.SetEventType(App.ET_ACTION_COMPLETED)
	App.g_kEventManager.AddEvent(pCompletedEvent)

	# If we had an event, it was the queue telling us that we were done.
	return 0

###############################################################################
#	CheckWarpInPath
#	
#	Check the path that this ship is going to be warping in along.
#	If it's not clear of obstacles, change it.
#	
#	Args:	pAction			- The TGScriptAction calling us.
#			pWarpSequence	- The warp sequence controlling the script action
#							  (and controlling the ship)
#			idShip			- The ship that's warping.
#	
#	Return:	0
###############################################################################
def CheckWarpInPath(pAction, pWarpSequence, idShip):
	if App.g_kUtopiaModule.IsMultiplayer():	# don't want to worry about multiplayer.
		return 0

	# Get various things we'll need...
	try:
		pShip = App.ShipClass_GetObjectByID(None, idShip)
		pSet = pWarpSequence.GetDestinationSet()
		if not pSet:
			return 0
		pWarpEngines = pShip.GetWarpEngineSubsystem()

		vStart = pWarpEngines.GetWarpExitLocation()
		pEndPlacement = App.PlacementObject_GetObject(pSet, pWarpSequence.GetPlacementName())
		vEnd = pEndPlacement.GetWorldLocation()
		fShipRadius = pShip.GetRadius()
	except AttributeError:
		return 0

	# Search through all ships warping in the set right now...
	lpShips = []
	for pSetShip in pSet.GetClassObjectList( App.CT_SHIP ):
		try:
			pWarpSystem = pSetShip.GetWarpEngineSubsystem()
			if pWarpSystem.GetWarpState() != App.WarpEngineSubsystem.WES_NOT_WARPING:
				# Make sure this is the set it's arriving at, not the set it's departing.
				pWS = App.WarpSequence_Cast( pWarpSystem.GetWarpSequence() )
				pDestinationSet = pWS.GetDestinationSet()
				if pDestinationSet and pDestinationSet.GetObjID() == pSet.GetObjID():
					# This ship is warping into this set.  Add it...
					lpShips.append((pSetShip, pWarpSystem))
			else:
				# It's in the set but it's not warping.  Just add the ship, not
				# the warp system.
				lpShips.append((pSetShip, None))
		except AttributeError:
			# No warp engine subsystem.  That's ok.
			pass

	# Check the path that that these ships are warping in along...
	iIndex = 0
	fRandomMax = 15.0
	bChanged = 0
	while iIndex < len(lpShips):
		pWarpingShip, pWarpingSubsystem = lpShips[iIndex]
		iIndex = iIndex + 1

		if pWarpingSubsystem:
			vWarpStart = pWarpingSubsystem.GetWarpExitLocation()
			pEndPlacement = pWarpingSubsystem.GetPlacement()

			if pEndPlacement:
				vWarpEnd = pWarpingSubsystem.GetPlacement().GetWorldLocation()
			else:
				vWarpEnd = pWarpingShip.GetWorldLocation()
		else:
			# If the ship's not warping, we still don't want to warp in near it.
			vWarpStart = pWarpingShip.GetWorldLocation()
			vWarpEnd = pWarpingShip.GetWorldLocation()
			vWarpEnd.Add( pWarpingShip.GetWorldForwardTG() )

		# If our line is ever too close to their line, adjust our line.
		# Find the distance between the two line segments...
		vClosestStart, vClosestEnd = FindSegmentBetweenSegments( vStart, vEnd, vWarpStart, vWarpEnd )
		vDiff = App.TGPoint3()
		vDiff.Set(vClosestEnd)
		vDiff.Subtract( vClosestStart )
		fDistance = vDiff.Unitize()
		#debug("Distance between segments is %f" % fDistance)

		# Just in case...
		if fDistance == 0:
			vDiff.SetXYZ(1.0, 0, 0)

		# Got the distance.  Are we too close?
		if fDistance < (fShipRadius * 4.0):
			# Yeah, it's probably too close.  Push our line away.  Far away...
			bChanged = 1
			vDiff.Scale( fShipRadius * (App.g_kSystemWrapper.GetRandomNumber(fRandomMax) + 2.0) )
			vStart.Add(vDiff)
			vEnd.Add(vDiff)
			# And reset our checks, so we check from the beginning again.
			iIndex = 0
			# And bump up the random max, in case we keep looping...  We'll eventually break out.
			fRandomMax = fRandomMax + 8.0

	if bChanged:
		# Our warp-in point has changed.  We need to make a new placement to warp into,
		# at the new location.
		iAttempt = 0
		while 1:
			sPlacement = "WarpAdjusted %d" % iAttempt
			if not App.PlacementObject_GetObject(pSet, sPlacement):
				break
			iAttempt = iAttempt + 1

		pPlacement = App.PlacementObject_Create(sPlacement, pSet.GetName(), None)

		pPlacement.SetTranslate(vEnd)
		pPlacement.SetMatrixRotation( pEndPlacement.GetRotation() )
		pPlacement.UpdateNodeOnly()

		pWarpSequence.SetPlacement(sPlacement)
		pWarpEngines.SetPlacement(pPlacement)
#		debug("Adjusted warp-in point for %s (to %s)" % (pShip.GetName(), sPlacement))
		#App.Breakpoint()

	return 0

###############################################################################
#	FindSegmentBetweenSegments
#	
#	Find the shortest line segment between the two given line segments.
#	
#	Args:	vStart1, vEnd1	- The first line segment..
#			vStart2, vEnd2	- The second line segment.
#			bThorough		- Due to the way the calculation is done,
#							  it's possible for parallel lines to give
#							  inaccurate results.  This should be set to 1
#							  by any external callers, and leads to another
#							  call (with it set to 0), to fix the problem.
#	
#	Return:	Start and end points for the shortest segment between them.
###############################################################################
def FindSegmentBetweenSegments(vStart1, vEnd1, vStart2, vEnd2, bThorough = 1):
	bCheckAgain = 0

	# Find the direction vectors for the two segments.
	vDir1 = App.TGPoint3()
	vDir1.Set(vEnd1)
	vDir1.Subtract(vStart1)

	vDir2 = App.TGPoint3()
	vDir2.Set(vEnd2)
	vDir2.Subtract(vStart2)

	# Calculations to find the nearest point on segment 1.
	fPart1 = vDir2.SqrLength() * (vStart2.Dot( vDir1 ) - vStart1.Dot( vDir1 ))
	fPart2 = vDir1.Dot( vDir2 ) * (vStart1.Dot( vDir2 ) - vStart2.Dot( vDir2 ))
	fBot = vDir1.SqrLength() * vDir2.SqrLength() - (vDir1.Dot( vDir2 ) * vDir1.Dot( vDir2 ))

	try:
		# Calculate how far along the first segment to go...
		fFrac1 = (fPart1 + fPart2) / fBot
	except ZeroDivisionError:
		fFrac1 = 0.0
		bCheckAgain = bThorough

	# Find the nearest point on segment 2.
	fPart1 = vStart1.Dot( vDir2 ) + vDir1.Dot( vDir2 ) * fFrac1 - vStart2.Dot( vDir2 )
	fBot = vDir2.SqrLength()
	try:
		# Calculate how far along the second segment to go...
		fFrac2 = fPart1 / fBot
	except ZeroDivisionError:
		fFrac2 = 0.0
		bCheckAgain = bThorough

	# Cap frac1 and frac2 to the [0,1] range.
	fFrac1 = max(0.0, min(1.0, fFrac1))
	fFrac2 = max(0.0, min(1.0, fFrac2))

	# Set the start/end points for our returned segment.
	vSegmentStart = vDir1
	vSegmentStart.Scale(fFrac1)
	vSegmentStart.Add( vStart1 )

	vSegmentEnd = vDir2
	vSegmentEnd.Scale( fFrac2 )
	vSegmentEnd.Add( vStart2 )

	if bCheckAgain:
		vSeg2Start, vSeg2End = FindSegmentBetweenSegments(vStart2, vEnd2, vStart1, vEnd1, 0)
		vDiff1 = App.TGPoint3()
		vDiff1.Set(vSegmentEnd)
		vDiff1.Subtract(vSegmentStart)

		vDiff2 = App.TGPoint3()
		vDiff2.Set(vSeg2End)
		vDiff2.Subtract(vSeg2Start)

		if vDiff2.SqrLength() < vDiff1.SqrLength():
			return (vSeg2Start, vSeg2End)

	return (vSegmentStart, vSegmentEnd)
