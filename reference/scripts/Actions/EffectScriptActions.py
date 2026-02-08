###############################################################################
#	Filename:	EffectScriptActions.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Some useful actions for effects.
#	
#	Created:	10/30/00 -	Erik Novales
###############################################################################

import App

#kDebugObj = App.CPyDebug()

###############################################################################
#	WarpFlash(pAction, iShipID, fTime)
#	
#	Creates the warp flash. Should be called before the ship leaves its
#	current set.
#	
#	Args:	pAction			- the action, passed in automatically
#			iShipID			- the ID of the ship being affected
#			fTime			- the amount of time the flash should take
#	
#	Return:	zero for end.
###############################################################################
def WarpFlash(pAction, iShipID, fTime = None):
	"Creates a warp flash."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	if (pShip == None):
		return(0)

	# fixes problem where ships get orphaned if the mission is terminated
	# while they're warping.
	if (pShip.GetContainingSet() == None):
		return(0)

	if (fTime != None):
		pFlash = App.WarpFlash_Create(pShip, fTime)
	else:
		pFlash = App.WarpFlash_Create(pShip)

	return(0)

###############################################################################
#	WarpFlashEnterSet(pAction, pcSetName, iShipID, fTime = None)
#	
#	Creates a warp flash for a ship entering a set. Queries the ship as to
#	where it will be exiting warp, and the rotation, etc. so we know where
#	to place the flash.
#	
#	Args:	pAction			- the action, passed in automatically
#			pcSetName		- the name of the module for the destination set
#			iShipID			- the ID of the ship being affected
#			fTime			- the amount of time the flash should take
#	
#	Return:	zero for end.
###############################################################################
def WarpFlashEnterSet(pAction, pcSetName, iShipID, fTime = None):
	"Creates a warp flash for a ship entering a set."

#	kDebugObj.Print("WarpFlashEnterSet(): " + pcSetName)

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	if (pShip == None):
		return(0)

	pSetModule = __import__(pcSetName)
	pSet = pSetModule.GetSet()

	if (pSet == None):
#		kDebugObj.Print("WarpFlashEnterSet(): no set")
		return(0)

	pWarp = pShip.GetWarpEngineSubsystem()

	if (pWarp == None):
#		print "In WarpFlashEnterSet(): no warp engine subsystem for use"
		return(0)

	pLocation = pWarp.GetWarpExitLocation()
	pRotation = pWarp.GetWarpExitRotation()
	fRadius = pShip.GetRadius()

	if (fTime == None):
		pFlash = App.WarpFlash_CreateWithoutShip(pSet, pLocation, pRotation, fRadius)
	else:
		pFlash = App.WarpFlash_CreateWithoutShip(pSet, pLocation, pRotation, fRadius, fTime)

	return(0)

###############################################################################
#	SetWarpStage(pAction, iShipID, eStage)
#	
#	Sets the stage that the warp subsystem of a ship is in. Affects stuff like
#	the stretching of the ship, etc.
#	
#	Args:	pAction			- the action, passed in automatically
#			iShipID			- the ID of the ship that is being affected
#			eStage			- the enum (from WarpEngineSubsystem) of the
#							  stage that you wish to go to
#	
#	Return:	zero for end.
###############################################################################
def SetWarpStage(pAction, iShipID, eStage):
	"Sets the stage that the warp subsystem of a ship is in."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	if not pShip:
#		print "In SetWarpStage(): ship is null"
		return(0)

	# If the ship is dead or dying, stop the sequence.
	if pShip.IsDead()  or  pShip.IsDying():
		pAction.Skip()
		return 1

	pWarp = pShip.GetWarpEngineSubsystem()
	if not pWarp:
#		print "In SetWarpStage(): warp subsystem is null"
		return(0)

	pWarp.TransitionToState(eStage)
	return(0)

###############################################################################
#	LiftDoorAction(pAction, pSetObject, pcDoorOpen, pcSoundName, 
#				   pcDoorClose, fTimeOpen)
#	
#	Handles opening and closing a lift door.
#	
#	Args:	pAction		- the action, passed in automatically
#			pSetObject	- the set's object
#			pcDoorOpen	- the door to open
#			pcSoundName - the sound to use
#			pcDoorClose - the door to close
#			fTimeOpen	- the amount of time the door remains open
#	
#	Return:	zero for end
###############################################################################
def LiftDoorAction(pAction, pSetObject, pcDoorOpen, pcSoundName, pcDoorClose = None, fTimeOpen = 1.0):
	pSeq = App.TGSequence_Create()

	pOpenAction = App.TGAnimAction_Create(pSetObject.GetAnimNode(), pcDoorOpen, 0, 0)
	pSeq.AddAction(pOpenAction)

	if (pcSoundName != None):
		pOpenSound = App.TGSoundAction_Create(pcSoundName)
		pSeq.AddAction(pOpenSound)

	if (pcDoorClose != None):
		pCloseAction = App.TGAnimAction_Create(pSetObject.GetAnimNode(), pcDoorClose, 0, 0)
		pSeq.AddAction(pCloseAction, pOpenAction, fTimeOpen);

		if (pcSoundName):
			pCloseSound = App.TGSoundAction_Create(pcSoundName);
			pSeq.AddAction(pCloseSound, pOpenAction, fTimeOpen);

	pSeq.Play()
	return(0)

###############################################################################
#	CreateEndWarpSequence(iShipID, pcPlacementName)
#	
#	Creates the end half of a warp sequence. To be used when creating ships
#	that are supposed to warp in.
#	
#	Args:	iShipID			- the ID of the ship to be affected
#			pcPlacementName	- the name of the placement to which the ship
#							  will go
#	
#	Return:	TGSequence * - the sequence
###############################################################################
def CreateEndWarpSequence(iShipID, pcPlacementName):
	pSequence = App.TGSequence_Create()

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))
	if (pShip == None):
		return(0)

	pInitiateDewarpAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "InitiateDewarp", iShipID, pcPlacementName)
	pDewarpEndAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "SetWarpStage", iShipID, App.WarpEngineSubsystem.WES_DEWARP_ENDING)
	pDewarpFinishAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "SetWarpStage", iShipID, App.WarpEngineSubsystem.WES_NOT_WARPING)
	pCoastAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "SetImpulse", iShipID, 0.2)
	pSoundAction = App.TGSoundAction_Create("Exit Warp", App.TGSAF_DEFAULTS, pShip.GetContainingSet().GetName())
	pSoundAction.SetNode(pShip.GetNode())

	pSequence.AddAction(pInitiateDewarpAction)
	pSequence.AppendAction(pSoundAction)
	pSequence.AddAction(pDewarpEndAction, pInitiateDewarpAction, App.WarpEngineSubsystem_GetWarpEffectTime() / 2.0)
	pSequence.AddAction(pDewarpFinishAction, pDewarpEndAction, App.WarpEngineSubsystem_GetWarpEffectTime() / 2.0)
	pSequence.AppendAction(pCoastAction)

	return(pSequence)

###############################################################################
#	InitiateDewarp(pAction, iShipID, pcPlacementName)
#	
#	Sets up dewarping for CreateEndWarpSequence() above.
#	
#	Args:	pAction			- the action
#			iShipID			- the ID of the ship we're affecting
#			pcPlacementName	- the name of the placement to which the ship is
#							  travelling
#	
#	Return:	zero for end
###############################################################################
def InitiateDewarp(pAction, iShipID, pcPlacementName):
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))
	if (pShip == None):
		return(0)

	pWarp = pShip.GetWarpEngineSubsystem()
	pSet = pShip.GetContainingSet()
	pPlacement = App.PlacementObject_GetObject(pSet, pcPlacementName)
	if (pWarp == None) or (pSet == None) or (pPlacement == None):
		return(0)

	pWarp.SetPlacement(pPlacement)
	# The transition is important.
	pWarp.SetWarpState(App.WarpEngineSubsystem.WES_WARPING)
	pWarp.TransitionToState(App.WarpEngineSubsystem.WES_DEWARP_INITIATED)

	pSequence = App.TGSequence_Create()
	pFlashAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "WarpFlashEnterSet", pSet.GetRegionModule(), iShipID)
	pSequence.AddAction(pFlashAction)
	pSequence.Play()

	return(0)
