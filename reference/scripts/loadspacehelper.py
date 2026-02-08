import App
import imp
import Actions.EffectScriptActions

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

###############################################################################
#	PreloadShip
#	
#	Mark a ship model for preloading.  If a number of ships is specified,
#	those ships are created ahead of time, so they don't hitch the framerate
#	when they're created within the mission.
#	
#	Args:	sModelName	- Name of the ships.* file with info on this ship.
#	
#	Return:	None
###############################################################################
def PreloadShip(sModelName, iNumToLoad = 0):
	# Mark the model for preloading.
	pMod = __import__("ships.%s" % sModelName)
	pMod.PreLoadModel()

	# Before the mission is initialized, we'll want to create a
	# bunch of these ships.
	if iNumToLoad > 0:
		import MissionLib
		pMission = MissionLib.GetMission()
		if not pMission:
#			debug("No mission in PreloadShip.  Can't precreate ships (but models will be preloaded)")
			return

		pMission.AddPrecreatedShip(sModelName, iNumToLoad)

###############################################################################
#	CreateShip
#	
#	Creates a new ship.
#	
#	Args:	pcScript		- the ship's script file
#			pSet			- the set in which to place this ship.  If NULL, it's not placed in a set.  Careful with this..
#			pcIdentifier	- the name for this ship
#			pcLocationName	- the name of the initial location for this ship
#			iWarpFlash		- whether or not to create a warp flash for this
#							  ship.
#			bGrabPreloaded	- True if this should grab ships from the mission's
#							  cache of precreated ships (if possible).  False if not.
#							  Only the mission should pass 0 for this, when it's
#							  first creating its precreated ships.
#	
#	Return:	ShipClass * - the newly-created ship
###############################################################################
def CreateShip(pcScript, pSet, pcIdentifier, pcLocationName, iWarpFlash = 0, bGrabPreloaded = 1):
	# Creates a new ship

	# Check if a ship of this type has been pre-created for us.
	pShip = None
	if bGrabPreloaded:
		import MissionLib
		pMission = MissionLib.GetMission()
		if pMission:
			pShip = pMission.GetPrecreatedShip(pcScript)

	if not pShip:
		# FIX ME:  This is back-arsewards in that the ship script is gotten from kStats
		# which was gotten from the ship script in the first place.  But this is the
		# least intrusive fix I can think of
		sModule = "ships." + pcScript
		pModule = __import__ (sModule)

		pModule.LoadModel ()
		kStats = pModule.GetShipStats ()

		pShip = App.ShipClass_Create( kStats['Name'] )
		pShip.SetScript(sModule)

		if (kStats.has_key('DamageRadMod')):
			pShip.SetVisibleDamageRadiusModifier( kStats['DamageRadMod'] )

		if (kStats.has_key('DamageStrMod')):
			pShip.SetVisibleDamageStrengthModifier( kStats['DamageStrMod'] )

		if (kStats.has_key('SpecularCoef')):
			pShip.SetSpecularKs( kStats['SpecularCoef'] )

		pPropertySet = pShip.GetPropertySet()
		# Load hardpoints.
		mod = __import__('ships.Hardpoints.' + kStats['HardpointFile'])
		App.g_kModelPropertyManager.ClearLocalTemplates()
		reload(mod)
		mod.LoadPropertySet(pPropertySet)

		pShip.SetupProperties()

		# Set the default splash damage based on the size of the ship
		# and the strength of its hull.
		pHull = pShip.GetHull()
		if pHull:
			pShip.SetSplashDamage(pHull.GetMaxCondition() * 0.1, pShip.GetRadius() * 2.0)
			#debug("Setting splash damage for %s to (%f, %f)" % (pShip.GetName(), pShip.GetSplashDamage(), pShip.GetSplashDamageRadius()))

		pShip.SetNetType (kStats['Species'])

	if pSet:
		if not pSet.AddObjectToSet( pShip, pcIdentifier ):
#			debug("Unable to add ship %s to set %s" % (pcIdentifier, pSet.GetName()))

			# Delete the ship.
			pDeletionEvent = App.TGEvent_Create()
			pDeletionEvent.SetEventType(App.ET_DELETE_OBJECT_PUBLIC)
			pDeletionEvent.SetDestination(pShip)
			App.g_kEventManager.AddEvent(pDeletionEvent)

			return None

		# Place the object at the specified location.
		if pcLocationName:
			pShip.PlaceObjectByName( pcLocationName )

		pShip.UpdateNodeOnly()

		if (iWarpFlash != 0):
			pWarp = pShip.GetWarpEngineSubsystem()
			if (pWarp != None) and (pcLocationName != None) and (pcLocationName != ""):
				pSequence = Actions.EffectScriptActions.CreateEndWarpSequence(pShip.GetObjID(), pcLocationName)
				pSequence.Play()
			else:
				# Just create a warp flash wherever the thing appears.
				pAction = App.TGScriptAction_Create("Actions.EffectScriptActions", "WarpFlash", pShip.GetObjID())
				pSequence = App.TGSequence_Create()
				pSequence.AddAction(pAction)
				pSequence.Play()
		
	return pShip

###############################################################################
#	AdjustShipForDifficulty(pShip, pcHardpointFile)
#	
#	Adjusts a ship for the game's difficulty level, using the given hardpoint
#	file as a template.
#	
#	Args:	pShip			- the ship
#			pcHardpointFile	- the hardpoint file to use
#	
#	Return:	none
###############################################################################
def AdjustShipForDifficulty(pShip, pcHardpointFile):
	if (pShip == None):
		return
	if (pcHardpointFile == None):
		return

	fOFactor = App.Game_GetOffensiveDifficultyMultiplier()
	fDFactor = App.Game_GetDefensiveDifficultyMultiplier()
#	debug("Adjusting ship, o factor: " + str(fOFactor) + ", d factor: " + str(fDFactor))

	pShipSet = pShip.GetPropertySet()
	pNewSet = App.TGModelPropertySet()
	# Load hardpoints.
	try:
		mod = __import__("ships.Hardpoints." + pcHardpointFile)
	except ImportError:
#		debug("Tried to load hardpoint file ships.Hardpoints." + pcHardpointFile + " and failed miserably")
		return

	reload (mod)
	mod.LoadPropertySet(pNewSet)

	# Modify all subsystem strengths.
	pShipList = pShipSet.GetPropertiesByType(App.CT_SUBSYSTEM_PROPERTY)
	pNewList = pNewSet.GetPropertiesByType(App.CT_SUBSYSTEM_PROPERTY)

	pShipList.TGBeginIteration()
	pNewList.TGBeginIteration()

	for i in range(pShipList.TGGetNumItems()):
		pShipProperty = App.SubsystemProperty_Cast(pShipList.TGGetNext().GetProperty())
		pNewProperty = App.SubsystemProperty_Cast(pNewList.TGGetNext().GetProperty())

		pSubsystem = pShip.GetSubsystemByProperty(pShipProperty)

		if (pSubsystem != None):
			ProcessSubsystemForDifficulty(pSubsystem, pShipProperty, pNewProperty)

	pShipList.TGDoneIterating()
	pNewList.TGDoneIterating()
	pShipList.TGDestroy()
	pNewList.TGDestroy()

###############################################################################
#	ProcessSubsystemForDifficulty(pSubsystem, pShipProperty, pNewProperty)
#	
#	Processes a subsystem in order to apply difficulty settings.
#	
#	Args:	pSubsystem		- the subsystem
#			pShipProperty	- the active ship property
#			pNewProperty	- the property on which to base the subsystem
#	
#	Return:	none
###############################################################################
def ProcessSubsystemForDifficulty(pSubsystem, pShipProperty, pNewProperty):
	eDifficulty = App.Game_GetDifficulty()

	fOFactor = App.Game_GetOffensiveDifficultyMultiplier()
	fDFactor = App.Game_GetDefensiveDifficultyMultiplier()

	#kString = "Subsystem " + pSubsystem.GetName() + ":"
	#debug(kString)

	#kString = "Was: " + str(pSubsystem.GetCondition()) + "/" + str(pSubsystem.GetMaxCondition())
	#debug(kString)

	# Modify the subsystem's strength based on the difficulty
	# level.
	fNewMax = pNewProperty.GetMaxCondition() * fDFactor
	fPct = pSubsystem.GetCondition() / pSubsystem.GetMaxCondition()

	#kString = "Norm: " + str(fPct * pNewProperty.GetMaxCondition()) + "/" + str(pNewProperty.GetMaxCondition())
	#debug(kString)

	pShipProperty.SetMaxCondition(fNewMax)
	pSubsystem.SetCondition(fNewMax * fPct)

	#kString = "Now: " + str(pSubsystem.GetCondition()) + "/" + str(pSubsystem.GetMaxCondition())
	#debug(kString)

	# If it's a weapon, we may want to adjust its damage.
	if (pSubsystem.IsTypeOf(App.CT_ENERGY_WEAPON)):
		pWeapon = App.EnergyWeapon_Cast(pSubsystem)
		pEWProperty = App.EnergyWeaponProperty_Cast(pNewProperty)

		pCurrentProperty = pWeapon.GetProperty()
		pCurrentProperty.SetMaxDamage(pEWProperty.GetMaxDamage() * fOFactor)
		fPct = pWeapon.GetChargeLevel() / pWeapon.GetMaxCharge()
		pCurrentProperty.SetMaxCharge(pEWProperty.GetMaxCharge() * fOFactor)
		pWeapon.SetChargeLevel(pCurrentProperty.GetMaxCharge() * fPct)
		pCurrentProperty.SetMinFiringCharge(pEWProperty.GetMinFiringCharge() * fOFactor)
		pCurrentProperty.SetRechargeRate(pEWProperty.GetRechargeRate() * fOFactor)

	# If it's a shield, we should adjust the shield values.
	if (pSubsystem.IsTypeOf(App.CT_SHIELD_SUBSYSTEM)):
		pShields = App.ShieldClass_Cast(pSubsystem)
		pShieldProperty = App.ShieldProperty_Cast(pNewProperty)

		pCurrentProperty = pShields.GetProperty()
		kShieldFacings = [App.ShieldProperty.FRONT_SHIELDS, 
						  App.ShieldProperty.REAR_SHIELDS,
						  App.ShieldProperty.TOP_SHIELDS,
						  App.ShieldProperty.BOTTOM_SHIELDS,
						  App.ShieldProperty.LEFT_SHIELDS,
						  App.ShieldProperty.RIGHT_SHIELDS]

		for kFacing in kShieldFacings:
			fPct = pShields.GetSingleShieldPercentage(kFacing)
			pCurrentProperty.SetMaxShields(kFacing, pShieldProperty.GetMaxShields(kFacing) * fDFactor)
			pShields.SetCurShields(kFacing, pShields.GetMaxShields(kFacing) * fPct)
			pCurrentProperty.SetShieldChargePerSecond(kFacing, pShieldProperty.GetShieldChargePerSecond(kFacing) * fDFactor)
