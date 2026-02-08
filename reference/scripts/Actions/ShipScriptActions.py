###############################################################################
#	Filename:	ShipScriptActions.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Useful script actions for ships.
#	
#	Created:	10/26/00 -	Erik Novales
###############################################################################

import App
import Bridge.EngineerMenuHandlers
import MissionLib

#kDebugObj = App.CPyDebug()

###############################################################################
#	MoveBetweenSetsAction(pAction, iShipID, pcSet)
#	
#	Moves a ship between two sets.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship being affected
#			pcSet			- the name of the set the ship is moving to
#	
#	Return:	zero for end
###############################################################################
def MoveBetweenSetsAction(pAction, iShipID, pcSet):
	"Moves a ship between two sets."

	# Get the ship we're acting on.
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	if (pShip != None):
		# Move the ship between the two sets.
		pOriginSet = pShip.GetContainingSet()

		# If the destination set is null, we're deleting the object...
		if ((pcSet == "") or (pcSet == None)):
			# No destination set.  We're deleting the ship.
			if (pOriginSet != None):
				pOriginSet.DeleteObjectFromSet(pShip.GetName())
			else:
				# Hmm. They don't have a set. This is a problem.
				# As a stopgap solution, we'll move them to the warp
				# set, and delete them.
				pWarpSet = App.WarpSequence_GetWarpSet()
				if (pWarpSet != None):
					pcNewName = pShip.GetName() + str(iShipID)
					pWarpSet.AddObjectToSet(pShip, pcNewName)
					pWarpSet.DeleteObjectFromSet(pcNewName)
		else:
			# We're moving the ship..
			if (pOriginSet != None):
				# Remove it from the origin set.
				pOriginSet.RemoveObjectFromSet(pShip.GetName())

			# Add it to the destination set.
			pDestSet = App.g_kSetManager.GetSet(pcSet);
			if (pDestSet != None):
				pDestSet.AddObjectToSet(pShip, pShip.GetName())
			else:
				# Hmm, the set has gone away or doesn't exist. This is a 
				# problem similar to the one above, so we'll deal with it in
				# the same way.
				pWarpSet = App.WarpSequence_GetWarpSet()
				if (pWarpSet != None):
					pcNewName = pShip.GetName() + str(iShipID)
					pWarpSet.AddObjectToSet(pShip, pcNewName)
					pWarpSet.DeleteObjectFromSet(pcNewName)

	return(0)

###############################################################################
#	ScanObject(pAction, iScanningShipID, iTargetID)
#	
#	Initiates a scan of the given object.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iScanningShipID	- the ID of the ship doing the scanning
#			iTargetID		- the ID of the target to be scanned
#	
#	Return:	zero for end
###############################################################################
def ScanObject(pAction, iScanningShipID, iTargetID):
	"Initiates a scan of the given object."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iScanningShipID))
	pTarget = App.ObjectClass_Cast(App.TGObject_GetTGObjectPtr(iTargetID))

	if (pShip == None) or (pTarget == None):
		return(0)

	pSensors = pShip.GetSensorSubsystem()
	if (pSensors == None):
		return(0)

	pSensors.IdentifyObject(pTarget)

	return(0)

###############################################################################
#	BoostSubsystemAction(pAction, iShipID, iSubsystemID)
#	
#	Boosts the specified subsystem.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship being affected
#			iSubsystemID	- the ID of the subsystem being affected
#			fAmount			- value to which we set the system's power.
#	
#	Return:	zero for end
###############################################################################
def BoostSubsystemAction(pAction, iShipID, iSubsystemID, fAmount = 1.25):
	"Boosts the specified subsystem."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))
	pSubsystem = App.PoweredSubsystem_Cast(App.TGObject_GetTGObjectPtr(iSubsystemID))

	if (pShip == None):
		return(0)

	if (pSubsystem != None):
		pSubsystem.SetPowerPercentageWanted(fAmount)
	else:
		# Reset all subsystems to normal power for the ship's alert
		# status.
		pShip.SetAlertLevel(pShip.GetAlertLevel())

	return(0)


###############################################################################
#	SetWarpPlacement(pAction, iShipID, pcSetName, pcPlacementName)
#	
#	Sets the destination placement for the warp subsystem. Called after the
#	during-warp actions, because the placements may not exist when the ship
#	goes into warp.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship being affected
#			pcSet			- the destination set's name, which will
#							  exist at this point.
#			pcPlacement		- the destination placement's name
#	
#	Return:	zero for end.
###############################################################################
def SetWarpPlacement(pAction, iShipID, pcSetName, pcPlacementName):
	"Sets the destination placement for the warp subsystem."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	# check to see if the ship is warping to the null set.
	if ((pcSetName == None) or (pcSetName == "")):
		return(0)

	pSet = App.g_kSetManager.GetSet(pcSetName)

	if (pShip == None) or (pSet == None):
#		kDebugObj.Print("SetWarpPlacement(): couldn't find player or set")
		return(0)

	pWarp = pShip.GetWarpEngineSubsystem()

	if (pWarp == None):
#		kDebugObj.Print("SetWarpPlacement(): ship didn't have warp system...weird")
		return(0)

	pPlacement = App.PlacementObject_GetObject(pSet, pcPlacementName)
	
	# Even if the placement is null, we still want to set the placement in
	# the warp engine subsystem.
	pWarp.SetPlacement(pPlacement)

	return(0)

###############################################################################
#	SetWarpExitPoint(pAction, iShipID, pcSetName, pcPlacementName)
#	
#	Sets the destination ppoint for the warp subsystem. Called after the
#	during-warp actions, because the placements may not exist when the ship
#	goes into warp.  Used only by multiplayer.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship being affected
#			pcSet			- the destination set's name, which will
#							  exist at this point.
#			x, y, z			- the destination point
#	
#	Return:	zero for end.
###############################################################################
def SetWarpExitPoint(pAction, iShipID, pcSetName, x, y, z):
	"Sets the destination placement for the warp subsystem."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	# check to see if the ship is warping to the null set.
	if ((pcSetName == None) or (pcSetName == "")):
		return(0)

	pSet = App.g_kSetManager.GetSet(pcSetName)

	if (pShip == None) or (pSet == None):
#		kDebugObj.Print("SetWarpPlacement(): couldn't find player or set")
		return(0)

	pWarp = pShip.GetWarpEngineSubsystem()

	if (pWarp == None):
#		kDebugObj.Print("SetWarpPlacement(): ship didn't have warp system...weird")
		return(0)

	kPoint = App.TGPoint3 ()
	kPoint.SetX (x)
	kPoint.SetY (y)
	kPoint.SetZ (z)

	# Even if the placement is null, we still want to set the placement in
	# the warp engine subsystem.
	pWarp.SetPlacement (None)
	pWarp.SetExitPoint(kPoint)

	return(0)

###############################################################################
#	Warp(pAction, iShipID, pcSet, pcPlacement, fTime)
#	
#	This action sets up a warp sequence for the given ship, sending it to
#	the specified set.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship being affected
#			pcSet			- the destination set's name
#			pcPlacement		- the name of the destination placement
#			fTime			- the time it takes for the ship to get to its
#							  destination once in warp.
#	
#	Return:	zero for end.
###############################################################################
def Warp(pAction, iShipID, pcSet, pcPlacement = None, fTime = 10.0):
	"Sets up a warp sequence to warp the ship to the desired set."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	if (pShip == None):
		return(0)

	if (pcPlacement == None):
		pcPlacement = "Player Start"

	pSequence = App.WarpSequence_Create(pShip, pcSet, fTime, pcPlacement)
	pSequence.Play()

	return(0)

###############################################################################
#	RepairShipFully(pAction, iShipID)
#	
#	Repairs a ship fully. All subsystems are restored to full health.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship being affected
#	
#	Return:	zero for end.
###############################################################################
def RepairShipFully(pAction, iShipID):
	"Repairs a ship fully. Every subsystem is restored to full health."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	if(pShip is None):
		return 0

	# Iterate over all the subsystems of the ship.
	pIterator = pShip.StartGetSubsystemMatch(App.CT_SHIP_SUBSYSTEM)
	pSubsystem = pShip.GetNextSubsystemMatch(pIterator)

	while (pSubsystem != None):
		RepairSubsystemFully(pAction, pSubsystem.GetObjID())
		pSubsystem = pShip.GetNextSubsystemMatch(pIterator)

	pShip.EndGetSubsystemMatch(pIterator)

	# Set all of ship's shields to max.
	pShields = pShip.GetShields()

	if (pShields != None):
		for ShieldDir in range(App.ShieldClass.NUM_SHIELDS):
			pShields.SetCurShields(ShieldDir, pShields.GetMaxShields(ShieldDir))

	# Set the power of the ship to max.
	pPower = pShip.GetPowerSubsystem()
	if (pPower != None):
		pPower.SetMainBatteryPower(pPower.GetMainBatteryLimit())
		pPower.SetBackupBatteryPower(pPower.GetBackupBatteryLimit())

	# Fix visible damage.
	pShip.RemoveVisibleDamage()

	# Replenish probe supply.
	pSensors = pShip.GetSensorSubsystem()
	if pSensors:
		pProp = pSensors.GetProperty()
		if pProp:
			pSensors.SetNumProbes(pProp.GetMaxProbes())

	return(0)


###############################################################################
#	RepairSubsystemFully(pAction, iSubsystemID)
#	
#	Repairs a subsystem, and all of its children, fully.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iSubsystemID	- the ID of the subsystem being affected
#	
#	Return:	zero for end.
###############################################################################
def RepairSubsystemFully(pAction, iSubsystemID):
	"Repairs a single subsystem and its children fully."

	pSubsystem = App.ShipSubsystem_Cast(App.TGObject_GetTGObjectPtr(iSubsystemID))

	if (pSubsystem == None):
		return(0)

	pSubsystem.SetCondition(pSubsystem.GetMaxCondition())
	iChildren = pSubsystem.GetNumChildSubsystems()

	if (iChildren > 0):
		# Fix all child subsystems.
		for iIndex in range(iChildren):
			pChild = pSubsystem.GetChildSubsystem(iIndex)
			RepairSubsystemFully(pAction, pChild.GetObjID())
	return(0)

###############################################################################
#	ReloadShip(pAction, iShipID)
#	
#	Reloads a ship fully. All weapons systems are reset to max.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship being affected
#	
#	Return:	zero for end.
###############################################################################
def ReloadShip(pAction, iShipID):
	"Reloads a ship fully. Every weapon system is restored to max."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))
	assert pShip

	if(pShip is None):
		return 0

	# Charge ship's phasers.
	pPhaserSys = pShip.GetPhaserSystem()
	if(pPhaserSys):
		for iPhaserNum in range(pPhaserSys.GetNumChildSubsystems()):
			pPhaserBank = App.EnergyWeapon_Cast(pPhaserSys.GetChildSubsystem(iPhaserNum))
			pPhaserBank.SetChargeLevel(pPhaserBank.GetMaxCharge())

	# Charge ship's pulse weapons.
	pPulseSys = pShip.GetPulseWeaponSystem()
	if(pPulseSys):
		for iPulseNum in range(pPulseSys.GetNumChildSubsystems()):
			pPulseWeapon = App.EnergyWeapon_Cast(pPulseSys.GetChildSubsystem(iPulseNum))
			pPulseWeapon.SetChargeLevel(pPulseWeapon.GetMaxCharge())

	# Reload torpedo ammo and fill tubes.
	pTorpSys = pShip.GetTorpedoSystem()
	if(pTorpSys):
		# Load each ammo type.
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			pTorpType = pTorpSys.GetAmmoType(iType)
			bSpecialLoad = 0

			pPlayer = MissionLib.GetPlayer()
			if (pPlayer.GetObjID() == iShipID):
				iLoadAtStarbase = App.g_kUtopiaModule.GetCurrentStarbaseTorpedoLoad(iType)
				iMaxPlayerLoad = App.g_kUtopiaModule.GetMaxTorpedoLoad(iType)
				iTorpsToLoad = iLoadAtStarbase

				if (iLoadAtStarbase != -1):
					bSpecialLoad = 1
					iMaxTorps = pTorpType.GetMaxTorpedoes()
					if (iMaxPlayerLoad == -1):
						iMaxPlayerLoad = iMaxTorps
					if (iMaxTorps < iLoadAtStarbase):
						iTorpsToLoad = iMaxTorps
					iLoadAtStarbase = iLoadAtStarbase - iTorpsToLoad
					iLoadLeftover = pTorpSys.LoadAmmoType(iType, iTorpsToLoad)
					App.g_kUtopiaModule.SetCurrentStarbaseTorpedoLoad(iType, iLoadLeftover + iLoadAtStarbase)

			if (bSpecialLoad == 0):
				pTorpSys.FillAmmoType(iType)
		# Fill torpedo tubes.
		pTorpSys.SetAmmoType(pTorpSys.GetAmmoTypeNumber(), 0)

	return(0)

###############################################################################
#	SetImpulse(pAction, iShipID, fImpulse)
#	
#	Sets the desired impulse of the ship.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship being affected
#			fImpulse		- the new impulse (0 <= fImpulse <= 1)
#	
#	Return:	zero for end.
###############################################################################
def SetImpulse(pAction, iShipID, fImpulse):
	"Sets the ship accelerating towards the desired impulse speed."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	if (pShip == None):
		return(0)

	pShip.SetImpulse(fImpulse, pShip.GetWorldForwardTG(), App.PhysicsObjectClass.DIRECTION_WORLD_SPACE)
	return(0)

###############################################################################
#	LaunchObject(pAction, pShip, pcName, iType)
#	
#	Launches an object from the given ship.
#	
#	Args:	pAction			- the script action, passed in automatically
#			iShipID			- the ID of the ship from which the object will 
#							  be launched
#			pcName			- the name of the object
#			iType			- the type of object -- use the enums from
#							  ObjectEmitterProperty or look below for 
#							  OEP_SHUTTLE, etc.
#	
#	Return:	zero for end
###############################################################################
def LaunchObject(pAction, iShipID, pcName, iType):
	"Launches an object from the given ship."

	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(iShipID))

	if (pShip == None):
		return(0)

	# Find any object emitter properties on the ship.
	pPropSet = pShip.GetPropertySet()
	pEmitterInstanceList = pPropSet.GetPropertiesByType(App.CT_OBJECT_EMITTER_PROPERTY)

	pEmitterInstanceList.TGBeginIteration()
	iNumItems = pEmitterInstanceList.TGGetNumItems()

	pLaunchProperty = None

	for i in range(iNumItems):
		pInstance = pEmitterInstanceList.TGGetNext()

		# Check to see if the property for this instance is a shuttle
		# emitter point.
		pProperty = App.ObjectEmitterProperty_Cast(pInstance.GetProperty())
		if (pProperty != None):
			if (pProperty.GetEmittedObjectType() == iType):
				pLaunchProperty = pProperty
				break

	pEmitterInstanceList.TGDoneIterating()
	pEmitterInstanceList.TGDestroy()

	if (pLaunchProperty != None):
		# We found a valid launch bay. Create the object, and point it facing out
		# of the shuttle bay.
		import LoadSpaceHelper

		pSet = pShip.GetContainingSet()
		pcScript = None

		# Create the object.
		if (iType == App.ObjectEmitterProperty.OEP_SHUTTLE):
			pcScript = "Shuttle"
		if (iType == App.ObjectEmitterProperty.OEP_PROBE):
			pcScript = "Probe"
		if (iType == App.ObjectEmitterProperty.OEP_DECOY):
			pcScript = "Decoy"

		if (pcScript == None):
			# We can't create anything.
			return(0)

		# Create the object.
		pObject = LoadSpaceHelper.CreateShip(pcScript, pSet, pcName, None)

		if (pObject != None):
			# If it was a probe, add it to the ship's probe list.
			if (iType == App.ObjectEmitterProperty.OEP_PROBE):
				pSensors = pShip.GetSensorSubsystem()
				if (pSensors != None):
					pSensors.AddProbe(pObject.GetObjID())

			# Now change the position and facing of the object to match the emitter.
			pFwd = pLaunchProperty.GetForward()
			pUp = pLaunchProperty.GetUp()

			pRotation = pShip.GetWorldRotation()

			pPosition = pLaunchProperty.GetPosition()
			pPosition.MultMatrixLeft(pRotation)
			pPosition.Add(pShip.GetWorldLocation())
			pObject.SetTranslate(pPosition)

			pFwd.MultMatrixLeft(pRotation)
			pUp.MultMatrixLeft(pRotation)
			pObject.AlignToVectors(pFwd, pUp)
			pObject.UpdateNodeOnly()

			# Don't collide with the ship that created us.
			pObject.EnableCollisionsWith(pShip, 0)

	# Woohoo, we're done.
	return(0)

###############################################################################
#	PushObject(pAction, pSetName, pObjName, fSpeed)
#	
#	Pushes the specified object in the specified set.
#	
#	Args:	pAction			- the script action, passed in automatically
#			pSetName		- the name of the set for the object
#			pObjName		- the name of the object
#			fSpeed			- the kick forward to give the object
#	
#	Return:	zero for end
###############################################################################
def PushObject(pAction, pSetName, pObjName, fSpeed):
	"Used to push an object who may not be created when a sequence is created. Namely, a probe."

	pSet = App.g_kSetManager.GetSet(pSetName)
	if (pSet == None):
		return(0)

	pObject = App.ShipClass_GetObject(pSet, pObjName)
	if (pObject != None):
		# Give it some velocity.
		kVel = pObject.GetWorldForwardTG()
		kVel.Scale(10.0)
		kVel.Add(pObject.GetVelocityTG())
		pObject.SetVelocity(kVel)

	return(0)

###############################################################################
#	FlickerShields(pAction, bOn = 0, fTime = 1)
#	
#	Hides/shows shields on the player's shield display. Useful for instances
#	where someone has to beam away/back, but you don't want to actually force
#	the player's shield state to change.
#	
#	Args:	pAction		- the script action, passed in automatically
#			bOn			- flicker on, or off. If off, this will trigger
#						  another action after a second has passed, to turn
#						  the shields back on.
#			fTime		- amount of time to flicker if bOn = 0
#	
#	Return:	zero for end
###############################################################################
def FlickerShields(pAction, bOn = 0, fTime = 1):
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	if (pTCW == None):
		return 0

	pPlayerDisplay = pTCW.GetShipDisplay()
	if (pPlayerDisplay == None):
		return 0

	pShieldsDisplay = pPlayerDisplay.GetShieldsDisplay()
	if (pShieldsDisplay == None):
		return 0

	pDisplayPane = App.TGPane_Cast(pShieldsDisplay.GetNthChild(pShieldsDisplay.DISPLAY_PANE))
	pTopPane = pDisplayPane.GetNthChild(pShieldsDisplay.TOP_PANE)
	pBottomPane = pDisplayPane.GetNthChild(pShieldsDisplay.BOTTOM_PANE)

	if (bOn == 0):
		pTopPane.SetNotVisible()
		pBottomPane.SetNotVisible()

		pSequence = App.TGSequence_Create()
		pAction = App.TGScriptAction_Create(__name__, "FlickerShields", 1)
		pSequence.AppendAction(pAction, fTime)
		pSequence.Play()
	else:
		pTopPane.SetVisible()
		pBottomPane.SetVisible()

	return 0
