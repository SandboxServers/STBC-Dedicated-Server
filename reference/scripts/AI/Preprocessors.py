#############################################################
# Preprocessors
#
# This file contains a collection of scripts and classes
# intended for use with PreprocessingAI objects.
#############################################################
import App
import math

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Preprocessing module...")


# There's no point in unloading this module as missions, episodes,
# or games away.  Make it persistent at the game level.
# During serialization/unserialization, the current game will
# be None, and we don't want to call AddPersistentModule then anyways.
pGame = App.Game_GetCurrentGame()
if pGame:
	pGame.AddPersistentModule(__name__)
del pGame
# del's are there because I don't want pEpisode and pGame global variables sticking around.

#
# FireScript
#
# Use this with any AI to have our ship always try to
# fire its weapons at our target (if we have a good shot).
#
# ***NOTE: The script for this preprocess is only used
# for setup.  Once the AI containing it is created, it's
# replaced with an optimized version in the code.
#
class FireScript:
	# Arguments to the constructor:
	# pOurShip	- The ship object we're controlling
	# sTarget	- The object we're trying to shoot
	def __init__(self, sTarget, **kw):
		self.sTarget = sTarget

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		self.fMaxFiringRange = 1.0e20
		if kw.has_key("MaxFiringRange"):
			self.fMaxFiringRange = kw["MaxFiringRange"]

		self.bHighPower = 1
		if kw.has_key("HighPower"):
			self.bHighPower = kw["HighPower"]

		self.bChangePowerSetting = 1
		self.bHullSelectedChooseAlternate = 0

		self.lTargetSubsystems = []
		self.bChooseSubsystemTargets = 0
		if kw.has_key("TargetSubsystems"):
			# Target subsystems have been specified explicitly.
			lSubsystems = kw["TargetSubsystems"]
			for eSubsystem, iPriority in lSubsystems:
				self.AddTargetSubsystem(eSubsystem, iPriority)
		elif kw.has_key("ChooseSubsystemTargets")  and  kw["ChooseSubsystemTargets"]:
			self.bChooseSubsystemTargets = 1

		self.bChooseTorpsWisely = 0
		if kw.has_key("SmartTorpSelection")  and  kw["SmartTorpSelection"]:
			self.bChooseTorpsWisely = 1

		self.bSmartPhasers = 0
		if kw.has_key("SmartPhasers")  and  kw["SmartPhasers"]:
			self.bSmartPhasers = 1

		self.lWeapons = []
		self.idTargetedSubsystem = None
		self.iLastUpdate = -1

		self.dTargetSubsystemRating = {}
		self.iTargetSubsystemUpdateNum = 0
		self.iNumTargetSubsystemsToUpdate = 4

		self.bEnabled = 1
		self.bAttackDisabledSubsystems = 1
		self.bAttackIfNoSubsystemsLeft = 1

		self.bCallUsingWeaponTypeFunc = 1

		# Angle of accuracy we need to fire.  We'll
		# go with 10 degrees if we should be accurate, 50 degrees
		# if not.
		if kw.has_key("InaccurateTorps")  and  kw["InaccurateTorps"]:
			# Inaccurate.
			self.fFireDotThreshold = math.cos((50.0) * (App.PI / 180.0))
		else:
			# Accurate.
			self.fFireDotThreshold = math.cos((10.0) * (App.PI / 180.0))

		self.bDumbFireTorps = 0
		if kw.has_key("DumbFireTorps"):
			self.bDumbFireTorps = kw["DumbFireTorps"]

		self.bDisableFirst = 0
		if kw.has_key("DisableBeforeDestroy"):
			self.bDisableFirst = kw["DisableBeforeDestroy"]

		# Check if we're only trying to disable the target, and not
		# destroy it.
		if kw.has_key("DisableOnly"):
			bDisableOnly = kw["DisableOnly"]
			self.SetAttackDisabled(not bDisableOnly)
			self.SetAttackWithoutValidSubsystems(not bDisableOnly)
			if not kw.has_key("HighPower"):
				self.bHighPower = not bDisableOnly

		# Whether or not our target is currently visible to us.		
		self.bTargetVisible = 0

		# Tractor beam mode, if we're firing a tractor beam.
		self.eTractorBeamMode = None
		
		# The radius around the line between us and our target
		# that we consider an object to be obstructing our view.
		self.fObstructionRadius = 0.5

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)


	def CodeAISet(self):
		# Further initialization we can do once our self.pCodeAI
		# member has been set.
		# Register external functions.
		self.pCodeAI.RegisterExternalFunction("SetTarget",
			{ "Name" : "SetTarget" } )

	# Add the weapon systems that you want
	# to fire.
	def AddWeaponSystem(self, pSystem):
		# If this is a weapon system type we didn't
		# previously have, set a flag to call the
		# "UsingWeaponSystem" external AI function
		# during the next update.
		bAlreadyThere = 0
		for pExistingSystem in self.lWeapons:
			if pSystem.IsTypeOf( pExistingSystem.GetObjType() ):
				# Already got one of these.
				bAlreadyThere = 1
				break

		if not bAlreadyThere:
			# Not there.  Gotta call the function.
			self.bCallUsingWeaponTypeFunc = 1

		# Add the weapon system to our list.
		self.lWeapons.append(pSystem)

	# Tractor beams are a special case.
	def AddTractorBeam(self, pShip, eTractorBeamMode):
		pTractorBeam = pShip.GetTractorBeamSystem()
		if pTractorBeam:
			self.AddWeaponSystem(pTractorBeam)
			self.eTractorBeamMode = eTractorBeamMode

	def RemoveAllWeaponSystems(self):
		self.StopFiring()

		if self.lWeapons:
			self.bCallUsingWeaponTypeFunc = 1

		self.lWeapons = []

	def GetWeapons(self):
		return self.lWeapons

	# Enable or disable firing from this AI.
	def SetEnabled(self, bEnabled):
		if self.bEnabled != bEnabled:
			if self.bEnabled:
				self.StopFiring()

			self.bEnabled = bEnabled

	# Whether or not this AI will attack disabled subsystems.
	def SetAttackDisabled(self, bAttack):
		self.bAttackDisabledSubsystems = bAttack

	# Whether or not this AI continues to attack if it has
	# a list of subsystems to target but none of those
	# subsystems are valid targets anymore.
	def SetAttackWithoutValidSubsystems(self, bAttack):
		self.bAttackIfNoSubsystemsLeft = bAttack

	# Add the subsystems we want the ship to target, with
	# a given priority.  Higher priority systems are targeted
	# first.  Once those are no longer worth firing at (eg.
	# destroyed), we target the next priorities.
	# Subsystems are specified by TGObjectType (for example,
	# CT_TORPEDO_SYSTEM).
	def AddTargetSubsystem(self, eSubsystem, iPriority):
		iIndex = 0
		while iIndex < len(self.lTargetSubsystems):
			if self.lTargetSubsystems[iIndex][1] < iPriority:
				# Insert it here.
				break
			iIndex = iIndex + 1
		self.lTargetSubsystems.insert(iIndex, (eSubsystem, iPriority))

	def HasSubsystemTargets(self):
		return len(self.lTargetSubsystems) > 0

	def IgnoreSubsystemTargets(self):
		if self.HasSubsystemTargets():
			self.lIgnoredSubsystemTargets = self.lTargetSubsystems
			self.lTargetSubsystems = []

	def RestoreSubsystemTargets(self):
		if not self.HasSubsystemTargets():
			try:
				self.lTargetSubsystems = self.lIgnoredSubsystemTargets
				del self.lIgnoredSubsystemTargets
			except AttributeError:
				pass

	# Convenience function, for player AI's.
	def UsePlayerSettings(self, bDisableOnly = 0):
		self.SetAttackDisabled(not bDisableOnly)
		self.SetAttackWithoutValidSubsystems(not bDisableOnly)
		self.bHighPower = not bDisableOnly
		self.bChangePowerSetting = 0
		self.bHullSelectedChooseAlternate = bDisableOnly

	def SetTarget(self, sName):
		"Change to a new target."
		self.StopFiring()

		self.sTarget = sName
		self.idTargetedSubsystem = None

	def GetTarget(self):
		"Get our target object, if we can."
		pOurShip = self.pCodeAI.GetShip()
		if (pOurShip == None):
			return None

		pSet = pOurShip.GetContainingSet()
		if (pSet == None):
			# We're not in a set.  What do we do?
			return None

		pTarget = App.ObjectClass_GetObject(pSet, self.sTarget)
		if (pTarget == None):
			# Our target is gone.
			return None
		
		return pTarget

	# We're being deactivated.  Stop firing our weapons.
	def LostFocus(self):
		self.StopFiring()
	
	def StopFiring(self):
		pTarget = self.GetTarget()

		if pTarget:
			for pWeaponSystem in self.lWeapons:
				pWeaponSystem.StopFiringAtTarget(pTarget)

	def GetNextUpdateTime(self):
		# We want to be updated every 0.2 seconds
		return 0.2

	# Our update function.
	def Update(self, dEndTime):
		pTarget = self.GetTarget()
		if not pTarget:
			return App.PreprocessingAI.PS_DONE

		# If we're supposed to call the UsingWeaponType external
		# AI function, do that...
		if self.bCallUsingWeaponTypeFunc:
			for pAI in self.pCodeAI.GetAllAIsInTree()[1:]:
				pAI.CallExternalFunction("UsingWeaponType", self.lWeapons)
			self.bCallUsingWeaponTypeFunc = 0

		if len(self.lWeapons) == 0:
			# No weapons to fire, but we're normal...
			return App.PreprocessingAI.PS_NORMAL

		if not self.bEnabled:
			# Firing has been temporarily disabled.
			return App.PreprocessingAI.PS_NORMAL

		# If we can't see our target, just keep checking until we can, and
		# don't do anything else in here.  Or if iLastUpdate is -2, check
		# TargetVisible.
		# If iLastUpdate is -1, we're choosing a subsystem to target.
		# If iLastUpdate is >= 0, we're firing one of the weapon systems.
		if (not self.bTargetVisible)  or  (self.iLastUpdate == -2)  or  (not self.TargetInRange(pTarget)):
			self.TargetVisible(pTarget)
			# If the target isn't visible, make sure iLastUpdate stays at -2.
			if not self.bTargetVisible:
				# Make sure we're not firing.
				self.StopFiring()

				self.iLastUpdate = -2
				return App.PreprocessingAI.PS_NORMAL
		elif self.iLastUpdate == -1:
			# Choose a subsystem to target.  This will save the ID of the
			# subsystem for the next update.
			idTiming = App.TGProfilingInfo_StartTiming("FireScript Update->ChooseTargetSubsystem")
			self.ChooseTargetSubsystem(pTarget)
			App.TGProfilingInfo_StopTiming(idTiming)
		else:
			# It's a weapon firing frame.  Get the subsystem we're supposed to be firing at...
			# Subsystem we're targeting is the same as last frame.
			pSubsystem = None
			if self.idTargetedSubsystem is not None:
				pSubsystem = App.ShipSubsystem_Cast( App.TGObject_GetTGObjectPtr( self.idTargetedSubsystem ) )

			# Based on the subsystem we're targeting, determine whether we should fire at all or not.
			if (pSubsystem is None)  and  (not self.bAttackIfNoSubsystemsLeft):
				# We have a list of target subsystems, but none of the
				# subsystems are valid targets.  And we're not supposed
				# to fire if we don't have a valid target subsystem.
				self.StopFiring()
				return App.PreprocessingAI.PS_NORMAL

			# Fire the weapon system we're supposed to fire this update.
			self.FireSystemAtTarget(self.lWeapons[ self.iLastUpdate % len(self.lWeapons) ], pTarget, pSubsystem)

		# Cycle the iLastUpdate counter..
		self.iLastUpdate = ((self.iLastUpdate + 3) % (len( self.lWeapons ) + 2)) - 2

		return App.PreprocessingAI.PS_NORMAL

	def TargetVisible(self, pTarget):
		# For now, skip this check.
		self.bTargetVisible = 1
		return self.bTargetVisible

		# Check if we're supposed to wait before doing
		# another visibility check...
		fCurrentTime = App.g_kUtopiaModule.GetGameTime()
		if fCurrentTime < self.fNextVisibilityCheck:
			# It's not yet time to check.  Return the
			# same result we did last time.
			return self.bTargetVisible

		# Time to do a check.
		pOurShip = self.pCodeAI.GetShip()
		if (pOurShip == None):
			return 0

		pFrom = pOurShip.GetWorldLocation()
		pTo = pTarget.GetWorldLocation()
		
		pSet = pOurShip.GetContainingSet()
		pProxManager = pSet.GetProximityManager()
		if (pProxManager == None):
			# No proximity manager in this set...  we can't test
			# to see if we have a clear line of sight to our target.
			# By default, we'll say our target is not visible.
			return 0

		pIterator = pProxManager.GetLineIntersectObjects(pFrom, pTo, self.fObstructionRadius)

		iOccludingObjects = 0
		while 1:
			pObject = pProxManager.GetNextObject(pIterator)
			if (pObject == None):
				# We're done.
				break
			
			# There's an object along the line.  If it's
			# us or our target, we don't care.  Otherwise,
			# increment the Occluding Objects count.
			if pObject.GetObjID() != pOurShip.GetObjID() and pObject.GetObjID() != pTarget.GetObjID():
				# It's not one of our two objects.  It must
				# be something else, occluding the two.

				# If it's a weapon projectile, ignore it.
				bOccludes = 1
				for eType in ( App.CT_TORPEDO ):
					if pObject.IsTypeOf(eType):
						bOccludes = 0
				if not bOccludes:
					continue

				iOccludingObjects = iOccludingObjects + 1

				# We only need to check for the existence of
				# an occluding object, not the number of them.
				# We're done...
				break

		pProxManager.EndObjectIteration(pIterator)
		
		if iOccludingObjects:
			# No, our target isn't visible.
			self.bTargetVisible = 0
		else:
			self.bTargetVisible = 1

		fAddTime = self.fVisibilityCheckDelay + (self.fVisibilityCheckRandomness * ((App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0))		
		self.fNextVisibilityCheck = fCurrentTime + fAddTime
		
		return self.bTargetVisible

	def TargetInRange(self, pTarget):
		pShip = self.pCodeAI.GetShip()
		if pShip:
			vDiff = pTarget.GetWorldLocation()
			vDiff.Subtract(pShip.GetWorldLocation())
			fSqrLength = vDiff.SqrLength()
			if fSqrLength <= (self.fMaxFiringRange * self.fMaxFiringRange):
				return 1
		return 0

	def FireSystemAtTarget(self, pWeaponSystem, pTarget, pSubsystem):
		# Make sure this system is configured correctly for
		# its attack on this target.
		if not self.ConfigureWeaponSystem(pWeaponSystem, pTarget, pSubsystem):
			# Some sort of problem configuring it.  This system isn't
			# ready to fire right now.
			return

		# Check if we have a good shot.  If so, we
		# should start firing this weapon system.
		if self.CheckGoodShot(pWeaponSystem, pTarget, pSubsystem):
			# We have a good shot.
			# Fire.  If we're already firing, this just updates the
			# targeted subsystem.
			vSubsystemOffset = App.TGPoint3()

			# If this is a torp system, only specify a target if
			# we're not dumb-firing.
			if self.bDumbFireTorps  and  App.TorpedoSystem_Cast(pWeaponSystem):
				if pSubsystem:
					vToTarget = pSubsystem.GetWorldLocation()
				else:
					vToTarget = pTarget.GetWorldLocation()
				vToTarget.Subtract(pWeaponSystem.GetWorldLocation())
				# Make sure we only fire torpedo tubes that are facing the
				# correct direction (dumb firing will fire any torp tube, not
				# just ones pointed toward a target).
				for iChild in range(pWeaponSystem.GetNumChildSubsystems()):
					pTube = App.TorpedoTube_Cast( pWeaponSystem.GetChildSubsystem(iChild) )
					if vToTarget.Dot( pTube.CalculateRoughDirection() ) > 0:
						# It's within 90 degrees of the correct direction.  Fire it.
						pTube.FireDumb(0, 1)
			else:
				if pSubsystem:
					vSubsystemOffset.Set( pSubsystem.GetPositionTG() )
				else:
					vSubsystemOffset.SetXYZ(0, 0, 0)

				pWeaponSystem.StartFiring(pTarget, vSubsystemOffset)
		else:
			# We don't have a good shot.  We should stop firing
			# this system.
			pWeaponSystem.StopFiringAtTarget(pTarget)

	def ConfigureWeaponSystem(self, pWeaponSystem, pTarget, pSubsystem):
		# If this weapon system will do too much damage, and we're just
		# trying to disable subsystems, don't fire this weapon.
		if self.WeaponTooDangerous(pWeaponSystem, pTarget, pSubsystem):
			return 0

		# If this system is a tractor beam, make sure its
		# tractor beam mode is set appropriately.
		pTractor = App.TractorBeamSystem_Cast(pWeaponSystem)
		if pTractor:
			if (self.eTractorBeamMode is not None)  and  (pTractor.GetMode() != self.eTractorBeamMode):
				# Set the mode..  -The only exception to
				# this is if our mode is Docking Stage 1,
				# the tractor beam is firing, and the
				# tractor beam is in Docking Stage 2.
				if not (pTractor.IsFiring()  and  pTractor.GetMode() == App.TractorBeamSystem.TBS_DOCK_STAGE_2 and self.eTractorBeamMode == App.TractorBeamSystem.TBS_DOCK_STAGE_1):
					pTractor.SetMode(self.eTractorBeamMode)
			# Tractor beam has been configured.
			return 1

		# If it's a phaser system, make sure its power level
		# is set appropriately.
		pPhaserSystem = App.PhaserSystem_Cast(pWeaponSystem)
		if pPhaserSystem:
			if not self.bHighPower:
				# Always use low power:
				pPhaserSystem.SetPowerLevel(App.PhaserSystem.PP_LOW)
			else:
				# Conditions are good.  High power.
				pPhaserSystem.SetPowerLevel(App.PhaserSystem.PP_HIGH)
			# Phaser system has been configured.
			return 1

		# If it's a torpedo system, make sure its torp type is
		# set correctly.
		pTorpSystem = App.TorpedoSystem_Cast(pWeaponSystem)
		if pTorpSystem:
			if self.bChooseTorpsWisely:
				# You have chosen to choose wisely.
				# Pick a torp type based on whether torps are already loaded,
				# distance to the target, and overall favorability of the
				# various torpedo types available.
				if pSubsystem:
					vTargetLocation = pSubsystem.GetWorldLocation()
				else:
					vTargetLocation = pTarget.GetWorldLocation()

				fSpeed = 0.0
				pShipTarget = App.ShipClass_Cast(pTarget)
				if pShipTarget:
					pImpulseEngines = pShipTarget.GetImpulseEngineSubsystem()
					if pImpulseEngines:
						fSpeed = pImpulseEngines.GetCurMaxSpeed()

				self.ChooseTorpType(pTorpSystem, vTargetLocation, fSpeed)

			# Torp system has been configured
			return 1

		# No special configuration.  It's ready.
		return 1

	def ChooseTorpType(self, pTorpSystem, vTargetLocation, fTargetSpeed):
		# Get the torp types that have ammo left...
		lTorpTypes = []
		for iType in range( pTorpSystem.GetNumAmmoTypes() ):
			if pTorpSystem.GetNumAvailableTorpsToType(iType) > 0:
				# This type has ammo available.
				lTorpTypes.append( (iType, pTorpSystem.GetAmmoType(iType)) )

		if len(lTorpTypes) == 0:
			return
		if len(lTorpTypes) == 1:
			# Only one choice available.  Make sure this type
			# is selected.
			if pTorpSystem.GetAmmoTypeNumber() != lTorpTypes[0][0]:
				# It's a different one.  Switch to the available one.
				pTorpSystem.SetAmmoType(lTorpTypes[0][0])
			return

		# Find the range to the target.
		vDiff = pTorpSystem.GetWorldLocation()
		vDiff.Subtract(vTargetLocation)
		fDistance = vDiff.Length()

		# Rate the various torpedo types available to us
		# based on range and on target speed...
		# ***FIXME: These calculations only need to be done once.
		lTorpAmmoRatings = []
		for iAmmoIndex, pAmmo in lTorpTypes:
			# Grab information about this ammo type.
			fLaunchSpeed = pAmmo.GetLaunchSpeed()
			fPowerCost = pAmmo.GetPowerCost()

			try:
				pScript = __import__(pAmmo.GetTorpedoScript())
				fTorpDamage = pScript.GetDamage()
				fGuidanceLifetime = pScript.GetGuidanceLifetime()
				fTurnRate = pScript.GetMaxAngularAccel()
			except:
				fTorpDamage = 0.0
				fGuidanceLifetime = 0.0
				fTurnRate = pScript.GetMaxAngularAccel()

			# From this information, try to determine what its ideal
			# distance is...
			fIdealDistMin = 0.0
			fIdealDistMax = 0.0
			if fGuidanceLifetime > 0:
				fIdealDistMax = fGuidanceLifetime * fLaunchSpeed

			# And what the ideal speed of its target is (this ends
			# up just being a rating of how likely it is to hit a
			# fast-moving target).
			fIdealTargetSpeedMin = 0.0
			fIdealTargetSpeedMax = 0.0
			if (fGuidanceLifetime > 0)  or  (fLaunchSpeed > 0):
				# It's slightly guided or it moves a little.  Max speed
				# rating is based on turn rate and launch speed.
				fIdealTargetSpeedMax = (fTurnRate * 4.0) + fLaunchSpeed

			# And what its overall rating is at its ideals...
			fRating = fTorpDamage - fPowerCost

			#debug("Rating ammo type %s(%d).  Dists(%f,%f), Speed(%f,%f), Ideal %f" % (
			#	pAmmo.GetAmmoName(), iAmmoIndex,
			#	fIdealDistMin, fIdealDistMax,
			#	fIdealTargetSpeedMin, fIdealTargetSpeedMax,
			#	fRating))
			lTorpAmmoRatings.append(
				( iAmmoIndex, fIdealDistMin, fIdealDistMax, fIdealTargetSpeedMin, fIdealTargetSpeedMax, fRating ))

		# Find the torp type with the best rating for our current situation.
		fBestScore = -1.0e20
		iChosenAmmo = 0
		for iAmmo, fMinDist, fMaxDist, fMinSpeed, fMaxSpeed, fRating in lTorpAmmoRatings:
			if fMinDist > 0:
				fUnderMin, fLowIdeal, fHighIdeal, fFar = App.FuzzyLogic_BreakIntoSets(fDistance, ( 0.0, fMinDist, fMaxDist, (fMaxDist - fMinDist) * 1.5 ))
			else:
				fLowIdeal, fHighIdeal, fFar = App.FuzzyLogic_BreakIntoSets(fDistance, ( fMinDist, fMaxDist, fMaxDist * 1.5 ))

			# Rate the distance score...
			fDistScore = fRating * (fLowIdeal + fHighIdeal)

			if fMinSpeed > 0:
				fUnderMin, fLowIdeal, fHighIdeal, fFar = App.FuzzyLogic_BreakIntoSets(fTargetSpeed, ( 0.0, fMinSpeed, fMaxSpeed, (fMaxSpeed - fMinSpeed) * 1.5 ))
			else:
				#App.Breakpoint()
				fLowIdeal, fHighIdeal, fFar = App.FuzzyLogic_BreakIntoSets(fTargetSpeed, ( fMinSpeed, fMaxSpeed, fMaxSpeed * 1.5 ))

			# Rate the speed score...
			fSpeedScore = fRating * (fLowIdeal + fHighIdeal)

			# Overall score of this torp type:
			fScore = (0.25 * fDistScore) + fSpeedScore

			#debug("Ammo type %d from (d%f, s%f) gets a score of (d%f, s%f):%f" % (
			#	iAmmo,
			#	fDistance, fTargetSpeed,
			#	fDistScore, fSpeedScore,
			#	fScore))

			if fScore > fBestScore:
				iChosenAmmo = iAmmo
				fBestScore = fScore

		# Switch to the new ammo type, if it's not the current one.
		if pTorpSystem.GetAmmoTypeNumber() != iChosenAmmo:
			#debug("Switching to ammo type %d" % iChosenAmmo)
			pTorpSystem.SetAmmoType(iChosenAmmo)

	def CheckGoodShot(self, pWeaponSystem, pTarget, pSubsystem):
		# Check if this is a weapon system that needs to be aimed...
		if not pWeaponSystem.ShouldBeAimed():
			# Nope.  It can be fired from any direction.  We
			# have a good shot anytime.
			return 1
		
		# Get our ship...
		pOurShip = self.pCodeAI.GetShip()
		if (pOurShip == None):
			return 1

		# This system needs to be aimed.  Check which direction
		# it's facing (if applicable), and see if it's good enough
		# to hit our target.
		# Alas, there is no easy way to get the facing if this weapon
		# system, because not all weapon systems have this information.
		# Figure out what kind of weapon system it is and get the info
		# we need...
		lDirections, fSpeed = self.GetWeaponInfo(pWeaponSystem)

		if len(lDirections):
			# Predict the location of our target.
			vTargetLocation = self.PredictTargetLocation(pTarget, pSubsystem, fSpeed)

			# Move the target location into our model space...
			vTargetLocation.Subtract( pOurShip.GetWorldLocation() )
			vTargetLocation.MultMatrixLeft( pOurShip.GetWorldRotation().Transpose() )
			fTargetDistance = vTargetLocation.Unitize()

			for vDirection in lDirections:
				# What's the angle between this direction
				# and the predicted target position.
				fDot = vTargetLocation.Dot( vDirection )

				# If the angle is within our angle threshold,
				# we have a good shot.
				if fDot >= self.fFireDotThreshold:
					return 1
			
			# No good shot.
			return 0

		# No direction information.  Might as well shoot.
#		debug("Aimed weapon system has no direction info.")
		return 1

	def WeaponTooDangerous(self, pWeaponSystem, pTarget, pSubsystem):
		# This is only relevant if we're just trying to disable systems.
		if self.bAttackDisabledSubsystems:
			# We'll attack even the disabled subsystems.  Nothing's
			# too dangerous.
			return 0

		# So far this is only a problem with torpedo systems.  Check
		# if this is a torp system.
		pTorpSystem = App.TorpedoSystem_Cast(pWeaponSystem)
		if pTorpSystem:
			# Check if there are other torps in the air right now.
			pSet = pTarget.GetContainingSet()
			idTarget = pTarget.GetObjID()
			if pSet:
				fIncomingDamage = 0.0
				lTorps = pSet.GetClassObjectList(App.CT_TORPEDO)
				for pTorp in lTorps:
					if pTorp.GetTargetID() == idTarget:
						fIncomingDamage = fIncomingDamage + pTorp.GetDamage()

				# Add the damage from one of our torps, so we know
				# what the damage will be if we choose to fire.
				fTorpDamage = 0.0
				pAmmoType = pTorpSystem.GetCurrentAmmoType()
				pScript = __import__(pAmmoType.GetTorpedoScript())
				if pScript:
					fTorpDamage = pScript.GetDamage()
					#debug("Got torp damage %f" % fTorpDamage)
				fIncomingDamage = fIncomingDamage + fTorpDamage
				fResultingCondition = pSubsystem.GetCondition() - fIncomingDamage

				if (fResultingCondition / pSubsystem.GetMaxCondition()) < pSubsystem.GetDisabledPercentage():
					# There's already enough stuff incoming to disable the
					# system.  Or it's within 1 torp of being disabled, in which
					# case we'll just hold our fire anyways, and let another weapon
					# system do the job.
					return 1

		return 0

	def PredictTargetLocation(self, pTarget, pSubsystem, fSpeed):
		# Find how far we are to our target.
		vDiff = pTarget.GetWorldLocation()
		pOurShip = self.pCodeAI.GetShip()
		if (pOurShip == None):
			return vDiff

		vDiff.Subtract( pOurShip.GetWorldLocation() )
		fDistance = vDiff.Unitize()
		
		# Get a rough estimate of how long it'll take our weapon
		# to hit the target.
		fTime = fDistance / fSpeed
		
		# Predict the target's position in that amount of time.
		vPredicted = pTarget.GetWorldLocation()
		pPhysicsTarget = App.PhysicsObjectClass_Cast(pTarget)
		if (pPhysicsTarget != None):
			vPredicted.Set(pPhysicsTarget.GetPredictedPosition( pTarget.GetWorldLocation(), pPhysicsTarget.GetVelocityTG(), pPhysicsTarget.GetAccelerationTG(), fTime ))

		# Now find the subsystem's predicted position...
		if pSubsystem:
			vSubsystemPos = pSubsystem.GetPositionTG()
			vSubsystemPos.MultMatrixLeft( pTarget.GetWorldRotation() )
			vPredicted.Add(vSubsystemPos)
		
		return vPredicted

	def GetWeaponInfo(self, pWeaponSystem):
		lDirections = []
		fSpeed = 1.0
		
		# Figure out which kind of weapon system it is.
		pTorp = App.TorpedoSystem_Cast(pWeaponSystem)
		if (pTorp != None):
			for iWeapNum in range( pTorp.GetNumChildSubsystems() ):
				pWeapon = App.TorpedoTube_Cast( pTorp.GetChildSubsystem(iWeapNum) )
				lDirections.append( pWeapon.GetDirection() )
			fSpeed = pTorp.GetCurrentAmmoType().GetLaunchSpeed()
		else:
			# Check to see if it's a pulse weapon.
			pPulseSystem = App.PulseWeaponSystem_Cast(pWeaponSystem)

			if (pPulseSystem != None):
				for iWeapNum in range(pPulseSystem.GetNumChildSubsystems()):
					pWeapon = App.PulseWeapon_Cast(pPulseSystem.GetChildSubsystem(iWeapNum))
					if (pWeapon != None):
						lDirections.append(pWeapon.GetProperty().GetOrientationForward())
						if (pWeapon.GetLaunchSpeed() > fSpeed):
							fSpeed = pWeapon.GetLaunchSpeed()
		
		# Ummm...   If it's not one of the above systems,
		# we have no idea what it is.  Somebody added a weapon
		# system.  -And because this code is inflexible (because
		# there's no other way to get the info we need), it can't
		# get the information we need.

		return (lDirections, fSpeed)
	
	def ChooseTargetSubsystem(self, pTarget):
		pShipTarget = App.ShipClass_Cast(pTarget)
		if not pShipTarget:
			return None

		pOurShip = self.pCodeAI.GetShip()
		if not pOurShip:
			return None

		pTargetSubsystem = None
		if len(self.lTargetSubsystems):
			iCurrentPriority = self.lTargetSubsystems[0][1]
			lpPossibleTargets = []
			iNumDisabled = 0
			
			# Find the best priority level that still
			# has systems we can target, and get all the
			# subsystems at that priority level.
			for eSystemType, iPriority in self.lTargetSubsystems:
				if len(lpPossibleTargets) and iPriority > iCurrentPriority:
					# This subsystem is too low on the priority list.
					# Keep building the list only if we're supposed to
					# disable all systems before destroying any, and
					# all the systems in the list are disabled.
					if (not self.bDisableFirst)  or  (iNumDisabled < len(lpPossibleTargets)):
						# We can stop.
						break

				iCurrentPriority = iPriority
				pIter = pShipTarget.StartGetSubsystemMatch(eSystemType)
				pSubsystem = pShipTarget.GetNextSubsystemMatch(pIter)
				while pSubsystem:
					if pSubsystem.GetCondition() > 0:
						# We can still destroy this system.
						# If it's disabled, should we still target it?
						if self.bAttackDisabledSubsystems or (not pSubsystem.IsDisabled()):
							# Can this subsystem actually be hit?  LOS
							# check to subsystem...
							#if pSubsystem.IsHittableFromLocation(pOurShip.GetWorldLocation()):

							# If this subsystem isn't targetable but has
							# targetable children, add the children.
							if not pSubsystem.IsTargetable():
								lTargets = self.GetChildTargets(pSubsystem)
								for pTarget in lTargets:
									if pSubsystem.IsDisabled():
										iNumDisabled = iNumDisabled + 1
									lpPossibleTargets.append(pSubsystem)
							else:
								if pSubsystem.IsDisabled():
									iNumDisabled = iNumDisabled + 1
								lpPossibleTargets.append(pSubsystem)
					pSubsystem = pShipTarget.GetNextSubsystemMatch(pIter)
			
			if len(lpPossibleTargets):
				# We have some subsystems we can target...
				# If we're supposed to disable all systems before
				# destroying any, look at the list of all non-disabled
				# systems first.
				lNonDisabled = []
				for pTargetSystem in lpPossibleTargets:
					if not pTargetSystem.IsDisabled():
						lNonDisabled.append( pTargetSystem )
				if lNonDisabled:
					# There are some systems that haven't been disabled
					# yet.  Choose from those systems.
					lpPossibleTargets = lNonDisabled

				# Pick one.
				pTargetSubsystem = self.PickTargetSubsystemFromList(lpPossibleTargets)
				#debug("Targeting subsystem %s" % pTargetSubsystem.GetName())
		elif self.bChooseSubsystemTargets:
			# There's no set list of subsystems we should target, but we
			# should choose our target subsystem intelligently.
			# Check out all our choices, rating each of them...
			lTargetSubsystems = []
			for pSubsystem in pShipTarget.GetSubsystems():
				# Build up a list of all targetable subsystems.
				lTargetSubsystems.extend( self.GetTargetableSubsystems(pSubsystem) )

			# Remove keys from self.dTargetSubsystemRating that don't appear
			# in lTargetSubsystems.
			for idKey in self.dTargetSubsystemRating.keys():
				# Check if this key is in lTargetSubsystems.
				bExists = 0
				for pSubsystem in lTargetSubsystems:
					if pSubsystem.GetObjID() == idKey:
						bExists = 1
						break
				if not bExists:
					del self.dTargetSubsystemRating[idKey]

			# In any 1 update, we only want to look through a small number of the
			# systems, so we don't take too long.  The systems that have been looked
			# at in the past are stored in self.dTargetSubsystemRating.
			# Pull out the systems that need to be updated...
			lNeedUpdates = []
			while (not lNeedUpdates)  and  lTargetSubsystems:
				for pSubsystem in lTargetSubsystems:
					if not self.dTargetSubsystemRating.has_key(pSubsystem.GetObjID()):
						# This subsystem doesn't have a rating yet.  It needs an update.
						lNeedUpdates.append(pSubsystem)
					else:
						# This subsystem is in self.dTargetSubsystemRating.  Check its
						# update sequence number, to see if it needs to be updated.
						if self.dTargetSubsystemRating[pSubsystem.GetObjID()][0] < self.iTargetSubsystemUpdateNum:
							lNeedUpdates.append(pSubsystem)

				if not lNeedUpdates:
					# The subsystems must have all been updated on this sequence num.  Increment to the next.
					self.iTargetSubsystemUpdateNum = self.iTargetSubsystemUpdateNum + 1

			# Got a list of subsystems whose ratings need to be updated.  Pick some of
			# them at random.
			if len(lNeedUpdates) <= self.iNumTargetSubsystemsToUpdate:
				lTargetSubsystems = lNeedUpdates
			else:
				lTargetSubsystems = []
				for iSys in range(self.iNumTargetSubsystemsToUpdate):
					iIndex = App.g_kSystemWrapper.GetRandomNumber(len(lNeedUpdates))
					lTargetSubsystems.append( lNeedUpdates[iIndex] )
					lNeedUpdates.remove( lNeedUpdates[iIndex] )

			# Update the randomly chosen ones.
			#debug("Rating %d systems (%d already done)." % (len(lTargetSubsystems), len(self.dTargetSubsystemRating.keys())))
			for pSubsystem in lTargetSubsystems:
				self.dTargetSubsystemRating[pSubsystem.GetObjID()] = (self.iTargetSubsystemUpdateNum,
																	  self.RateSubsystemForTargeting(pOurShip, pShipTarget, pSubsystem))

			# Now choose a subsystem, from the history of ratings we've been
			# gathering.
			fHighestRating = -1.0e20
			for idSubsystem, lData in self.dTargetSubsystemRating.items():
				iSeqNum, fRating = lData
				if fRating > fHighestRating:
					fHighestRating = fRating
					pTargetSubsystem = App.ShipSubsystem_Cast( App.TGObject_GetTGObjectPtr( idSubsystem ) )

			#if pTargetSubsystem:
				#debug("Choose subsystem targets chose subsystem %s." % pTargetSubsystem.GetName())
		else:
			# No subsystems in our list.  If our ship has
			# a target subsystem set already, use that one.
			# This should only be the case for the player's
			# ship.
			pShip = self.pCodeAI.GetShip()
			pTargetSubsystem = pShip.GetTargetSubsystem()

			# If it's disabled and we won't fire on disabled subsystems,
			# return None.
			if pTargetSubsystem  and  (pTargetSubsystem.IsDisabled()  and  (not self.bAttackDisabledSubsystems)):
				pTargetSubsystem = None

		if pTargetSubsystem:
			self.idTargetedSubsystem = pTargetSubsystem.GetObjID()
		else:
			self.idTargetedSubsystem = None

		return pTargetSubsystem

	def GetTargetableSubsystems(self, pSubsystem):
		lTargetable = []
		if pSubsystem.GetCondition() > 0.0:
			# This system or its children may be targetable.
			if pSubsystem.IsTargetable():
				lTargetable.append(pSubsystem)
			else:
				# This one isn't targetable, but its children may be.
				for iChild in range(pSubsystem.GetNumChildSubsystems()):
					pChild = pSubsystem.GetChildSubsystem(iChild)
					lTargetable.extend( self.GetTargetableSubsystems(pChild) )

		return lTargetable

	def RateSubsystemForTargeting(self, pOurShip, pTargetShip, pSubsystem):
		# Whether or not the system is critical is important...
		fCritical = float( pSubsystem.IsCritical() )

		# How many points of damage it'll take to disable it has a factor...
		fDamageToDisable = 0.0
		fMaxCondition = pSubsystem.GetMaxCondition()
		fDisabledCondition = pSubsystem.GetDisabledPercentage() * fMaxCondition
		fCondition = pSubsystem.GetCondition()
		if fCondition > fDisabledCondition:
			fDamageToDisable = fCondition - fDisabledCondition

		fIsDisabled = float( pSubsystem.IsDisabled() )

		# How many points to destroy has a factor...
		fDamageToDestroy = fCondition

		# Whether or not it's easy to hit from here has some influence.
		fHittable = pSubsystem.IsHittableFromLocation( pOurShip.GetWorldLocation() )

		# Certain types of systems have different overall ratings...
		fSystemRating = 0.0
		for eType, fRating in (
			(App.CT_WEAPON_SYSTEM,				5.0),
			(App.CT_WEAPON,						5.0),
			(App.CT_SHIELD_SUBSYSTEM,			5.0),
			(App.CT_CLOAKING_SUBSYSTEM,			4.0),
			(App.CT_IMPULSE_ENGINE_SUBSYSTEM,	3.0),
			(App.CT_HULL_SUBSYSTEM,				-200.0),
			):
			if pSubsystem.IsTypeOf(eType):
				fSystemRating = fRating
				break

		# Combine all these factors...
		fRating = 0.0
		for fFactor, fImportance in (
			(fCritical,			6.0),
			(fDamageToDisable,	-0.0005),
			(fIsDisabled,		-3.0 * self.bDisableFirst),
			(fDamageToDestroy,	-0.0005),
			(fHittable,			1.0),
			(fSystemRating,		1.0),
			):
			fRating = fRating + (fFactor * fImportance)

		#debug("Subsystem target %s rated at %f" % (pSubsystem.GetName(), fRating))
		return fRating

	def PickTargetSubsystemFromList(self, lSubsystems):
		if len(lSubsystems) == 1:
			return lSubsystems[0]

		# Loop through and rate the subsystems, and choose the one
		# with the highest rating.
		pTarget = None
		fTargetRating = None
		for pSubsystem in lSubsystems:
			# If it's already our target, that affects our decision.
			fIsTargetRating = 0.0
			if self.idTargetedSubsystem == pSubsystem.GetObjID():
				fIsTargetRating = 1.0

			# If it's healthy/unhealthy, that affects our decision.
			fHealthyRating = pSubsystem.GetConditionPercentage()

			# If it's disabled, that affects our decision.
			fDisabledRating = pSubsystem.IsDisabled()

			# Find this subsystem's overall rating...
			fRating = 0.0
			for fValue, fScale in (
				( fIsTargetRating,	1.0 ),
				( fHealthyRating,	-1.0 ),
				( fDisabledRating,	-1.0 )
				):
				fRating = fRating + (fValue * fScale)

			if (pTarget is None)  or  (fRating > fTargetRating):
				pTarget = pSubsystem
				fTargetRating = fRating

		return pTarget

#
# SelectTarget
#
# Use this with any AI to have our ship automatically
# select a good target from a group.  This tries not to switch
# targets too often...
#
# ***NOTE: The script for this preprocess is only used
# for setup.  Once the AI containing it is created, it's
# replaced with an optimized version in the code.
#
class SelectTarget:
	def __init__(self, *pTargetGroup):
		self.pTargetGroup = App.ObjectGroup_ForceToGroup( pTargetGroup )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		self.sCurrentTarget = None
		self.pOldHandlerInfo = None
		self.lAdditionalSetTargetAITrees = []

		self.fNormalUpdateTime = 5.0
		self.fUpdatingTargetInfoUpdateTime = 0.0
		self.fUpdateTime = self.fNormalUpdateTime

		# Whether or not we call our ship's SetTarget function
		# when we get a new target.
		self.bSetShipTarget = 1

		# Whether or not a target needs to be visible to the sensors to be chosen...
		self.bIgnoreSensors = 1

		# Whether or not we call all the SetTarget functions if
		# our chosen target is None.
		self.bCallSetTargetFuncsWithNoTarget = 0
		self.bCallSetTargetFunctions = 1
		self.bUpdateInfoOnCodeAISet = 0

		self.bUpdatingTargetInfo = 0

		# The preprocessing status of this AI if there are
		# no available targets, in case something wants to
		# override this for some special reason.
		self.eNoTargetPreprocessStatus = App.PreprocessingAI.PS_SKIP_DORMANT
		self.eNoTargetNoShipTargetPreprocessStatus = App.PreprocessingAI.PS_SKIP_DORMANT

##
##		Commented out because this is work that would need to be undone by
##		the optimized version of this preprocess.
##
## 		# We need an event handler so we can be notified when
## 		# our target leaves our set, or if our target group is
## 		# changed.
## 		self.pEventHandler = App.TGPythonInstanceWrapper()
## 		self.pEventHandler.SetPyWrapper(self)
##
## 		# Add a handler if our target group is changed...
## 		self.pTargetGroup.SetEventFlag( App.ObjectGroup.GROUP_CHANGED )
## 		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_OBJECT_GROUP_CHANGED, self.pEventHandler, "TargetListChanged", self.pTargetGroup)
## 		# Or if one of these objects enters the set...
## 		self.pTargetGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
## 		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "TargetEnteredSet", self.pTargetGroup)
##
## 		# Listen for ships decloaking, since they may create new targets.
## 		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_DECLOAK_BEGINNING, self.pEventHandler, "ObjectDecloaked" )

		# Numbers for choosing what a good target is:
		self.SetRelativeImportance()

		# More specific numbers, that determine how we judge
		# the different properties of how good a target is.
		self.fMinimumFullGoodDistance = 30.0	# Max distance at which DistGood is 1.0

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

##	Commented out CodeAISet because it would end up doing work that
##	the optimized version of this AI would have to undo.
##
## 	def CodeAISet(self):
## 		return
##
## 		# Further initialization we can do once our self.pCodeAI
## 		# member has been set.
## 		# We need to add a handler for when our ship enters
## 		# a new set.
## 		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_ENTERED_SET, self.pEventHandler, "OurShipEnteredSet", self.pCodeAI.GetShip())
##
## 		# We need to listen in on damage events, so we know when
## 		# ships in our target list are damaging us.
## 		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_WEAPON_HIT, self.pEventHandler, "DamageEvent", self.pCodeAI.GetShip())
## 		self.dDamageReceived = {}
##
## 		if self.bUpdateInfoOnCodeAISet:
## 			# Gotta call UpdateTargetInfo, but it shouldn't call
## 			# all its SetTarget functions.
## 			bOldCall = self.bCallSetTargetFunctions
## 			self.bCallSetTargetFunctions = 0
## 			self.UpdateTargetInfo(App.g_kSystemWrapper.GetTimeSinceFrameStart() + 1.0)
## 			self.bCallSetTargetFunctions = bOldCall
## 			self.bUpdateInfoOnCodeAISet = 0

	def SetRelativeImportance(self,
	  fDistance = 1.0,	# How close is it?
	  fInFront = 0.2,	# Is it in front of us?
	  fIsTarget = 1.0,	# Is it currently our target?
	  fShield = -0.2,	# Shield status
	  fWeapons = -0.2,	# Weapon status
	  fHull = -0.1,		# Hull status
	  fDamage = 1.0,	# Damage dealt to us from the target
	  fPriority = 1.0,	# Priority of the target
	  fPopularity = -1.1): # Popularity of the target as a target for others
		# Let the SelectTarget preprocessor know how important
		# certain factors are in determining which target to
		# attack.
		self.fDistanceFactor	= fDistance
		self.fInFrontFactor	= fInFront
		self.fIsTargetFactor	= fIsTarget
		self.fShieldFactor	= fShield
		self.fWeaponsFactor	= fWeapons
		self.fHullFactor	= fHull
		self.fDamageFactor	= fDamage
		self.fPriorityFactor	= fPriority
		self.fPopularityFactor = fPopularity

	# Add an AI tree to the set of AI's on which the external "SetTarget"
	# function is called, whenever the target changes...
	def AddSetTargetTree(self, pAI):
		self.lAdditionalSetTargetAITrees.append( pAI.GetID() )

	# Call this if this AI shouldn't set the ship's Target member.
	# This may be needed in cases where this AI is placed on the
	# player's ship.
	def DontSetShipTarget(self):
		self.bSetShipTarget = 0

	# In case something special wants to override the preprocess
	# status of this AI when the AI has no targets:
	def SetNoTargetPreprocessStatus(self, eStatus, eNoShipTargetStatus):
		self.eNoTargetPreprocessStatus = eStatus
		self.eNoTargetNoShipTargetPreprocessStatus = eNoShipTargetStatus

	# Use this with caution.  It doesn't call all the target
	# setup functions.  It should probably only be used for the
	# player's unusual AI.
	def ForceCurrentTargetString(self, sTarget):
		self.bUpdateInfoOnCodeAISet = 1
		self.sCurrentTarget = sTarget

	# If this preprocess determines that there are no good
	# targets, this flag determines whether or not it calls
	# all its Set Target functions with None as the target.
	def SetCallFuncsWithNoTargetFlag(self, bCall):
		self.bCallSetTargetFuncsWithNoTarget = bCall

	# If this should call a function somewhere instead of calling
	# all the externally registered SetTarget functions in the AI
	# tree beneath us, call this function with the module and
	# function names.
	def CallFunctionInsteadOfSetTargets(self, sModule, sFunction):
		self.sReplacementSetTargetModule = sModule
		self.sReplacementSetTargetFunction = sFunction

	# Convenience function, for player AI's.
	def UsePlayerSettings(self):
		self.DontSetShipTarget()
		# If we have no target but the player's ship has a target, fall through to our contained AI.  If
		# neither of us has AI, lay dormant.
		self.SetNoTargetPreprocessStatus( App.PreprocessingAI.PS_NORMAL, App.PreprocessingAI.PS_SKIP_DORMANT )
		self.SetCallFuncsWithNoTargetFlag(1)
		self.CallFunctionInsteadOfSetTargets("Bridge.TacticalMenuHandlers", "AutoTargetChange")
		self.bIgnoreSensors = 0

	def GetNextUpdateTime(self):
		# We want to be updated every 5 seconds, under
		# normal circumstances.
		return self.fUpdateTime

	def GetStatusInfo(self):
		return "Target(%s)" % (self.sCurrentTarget)

	def Update(self, dEndTime):
		#debug("SelectTarget Update, End Time %f gives %f seconds." % (dEndTime, dEndTime - App.g_kSystemWrapper.GetTimeSinceFrameStart()))

		# If we're still updating target info, just update that and then exit.
		if self.bUpdatingTargetInfo:
			self.UpdateTargetInfo(dEndTime)
			return App.PreprocessingAI.PS_SKIP_ACTIVE

		# Back to a normal update.  Set our next update delay to
		# the normal update time.
		self.fUpdateTime = self.fNormalUpdateTime

		# Determine what our best target is right now.
		sTarget = self.FindGoodTarget()

		# If our target changed, we need to update all
		# the things we need to update...  =P
		if sTarget != self.sCurrentTarget:
			self.sCurrentTarget = sTarget
			if self.bSetShipTarget and self.pCodeAI.HasFocus():
				pOurShip = self.pCodeAI.GetShip()
				if pOurShip:
					pOurShip.SetTarget(self.sCurrentTarget)

			self.UpdateTargetInfo(dEndTime)

			# Updating target info may take more than 1 frame.  If
			# it's going to, 
			if self.bUpdatingTargetInfo:
				return App.PreprocessingAI.PS_SKIP_ACTIVE

		# Figure out what our status should be...
		eStatus = App.PreprocessingAI.PS_NORMAL
		if self.sCurrentTarget == None:
			eStatus = self.eNoTargetPreprocessStatus

		# We're done.
		return eStatus

	def TargetListChanged(self, pEvent):
		# If we're active (but not necessarily in focus), force
		# an update.
		if self.pCodeAI.IsActive():
			self.pCodeAI.ForceUpdate()

	def TargetEnteredSet(self, pEvent):
		# Update our target info, even if we aren't in focus.
		# This may change us from being Dormant to being Active...
		self.pCodeAI.ForceUpdate()

	def OurShipEnteredSet(self, pEvent):
		# Update our target info, even if we aren't in focus.
		# This may change us from being Dormant to being Active...
		self.pCodeAI.ForceUpdate()

	def TargetGone(self, pEvent):
		# Our current target is gone, one way or another.  Make sure we
		# update next time around, so we can choose a better target.
		self.pCodeAI.ForceUpdate()

	def ObjectDecloaked(self, pEvent):
		pObject = App.ObjectClass_Cast(pEvent.GetDestination())
		if pObject and (self.pTargetGroup.IsNameInGroup( pObject.GetName() )):
			# One of our targets is decloaking.  Reevaluate our targets.
			self.pCodeAI.ForceUpdate()

	def DamageEvent(self, pEvent):
		# This is a broadcast handler, so it doesn't need
		# to call CallNextHandler.

		# Our ship has received a damage event.
		pOurShip = self.pCodeAI.GetShip()

		# Our ship is taking damage.  Log
		# who we're taking damage from, and
		# how much damage we're taking.
		pSource = pEvent.GetFiringObject()
		if pSource:
			idSource = pSource.GetObjID()
			fOldValue = 0.0
			if self.dDamageReceived.has_key(idSource):
				fOldValue = self.dDamageReceived[idSource]

			# Calculate the damage we're taking
			# as a fraction of our total hull
			# strength.  (It's just an arbitrary
			# number...)
			pHull = pOurShip.GetHull()
			fDamage = pEvent.GetDamage() / pHull.GetMaxCondition()

			# Record this damage for future reference.
			self.dDamageReceived[idSource] = fOldValue + fDamage

	def UpdateTargetInfo(self, dEndTime):
		idProfiling = App.TGProfilingInfo_StartTiming("SelectTarget::UpdateTargetInfo")

		# Only update function handlers if we haven't done that yet
		if not self.bUpdatingTargetInfo:
			# Get rid of our handler for when the old target
			# exited the set.
			self.RemoveOldTargetHandlers()

			# If we have a new target, add an event handler for when
			# this target exits the set.
			if self.sCurrentTarget is not None:
				pOurShip = self.pCodeAI.GetShip()
				if pOurShip:
					pSet = pOurShip.GetContainingSet()
					pNewTarget = App.ObjectClass_GetObject(pSet, self.sCurrentTarget)
					if pNewTarget:
						self.pOldHandlerInfo = (
							( App.ET_EXITED_SET, self.pEventHandler, "TargetGone", pNewTarget ),
							( App.ET_OBJECT_DESTROYED, self.pEventHandler, "TargetGone", pNewTarget ),
							( App.ET_CLOAK_COMPLETED, self.pEventHandler, "TargetGone", pNewTarget ) )

						for pInfo in self.pOldHandlerInfo:
							apply(App.g_kEventManager.AddBroadcastPythonMethodHandler, pInfo)

		# And call all the functions we're supposed to call,
		# telling them who the new target is.
		if self.bCallSetTargetFunctions  and  ((self.sCurrentTarget is not None)  or  (self.bCallSetTargetFuncsWithNoTarget)):
			self.CallSetTargetFunctions(dEndTime)

		App.TGProfilingInfo_StopTiming(idProfiling)

	def RemoveOldTargetHandlers(self):
		if self.pOldHandlerInfo:
			for pInfo in self.pOldHandlerInfo:
				apply(App.g_kEventManager.RemoveBroadcastHandler, pInfo)
		self.pOldHandlerInfo = None

	def CallSetTargetFunctions(self, dEndTime):
		# If we're supposed to be calling a funciton in another module
		# instead of calling externally registered AI SetTarget functions,
		# do that...
		if hasattr(self, "sReplacementSetTargetModule")  and  hasattr(self, "sReplacementSetTargetFunction"):
			pScript = __import__(self.sReplacementSetTargetModule)
			pFunc = getattr(pScript, self.sReplacementSetTargetFunction)
			pFunc(self.sCurrentTarget)
			return

		idProfiling = App.TGProfilingInfo_StartTiming("SelectTarget::CallSetTargetFunctions external")

		# We'll call the externally registered SetTarget functions
		# on all AI's beneath us in the AI tree, and all AI's in any
		# additional trees we've been given.
		lAIs = self.pCodeAI.GetAllAIsInTree()[1:]
		for idRoot in self.lAdditionalSetTargetAITrees:
			pRoot = App.ArtificialIntelligence_GetAIByID(idRoot)
			lAIs = lAIs + pRoot.GetAllAIsInTree()

		# Set flags so we know we're in the middle of updating.
		if not self.bUpdatingTargetInfo:
			self.bUpdatingTargetInfo = 1
			self.pCodeAI.ForceDormantStatus(App.PreprocessingAI.FDS_FALSE)
			self.fUpdateTime = self.fUpdatingTargetInfoUpdateTime

			self.lAIUpdateIDs = []
			for pAI in lAIs:
				self.lAIUpdateIDs.append( pAI.GetID() )

		#debug("Updating %d of %d remaining AI SetTarget functions" % (self.iSetTargetFunctionsPerFrame, len(self.lAIUpdateIDs)))
		iOriginalLength = len(self.lAIUpdateIDs)
		while len(self.lAIUpdateIDs):
			idAI = self.lAIUpdateIDs[0]
			self.lAIUpdateIDs.remove(idAI)

			pAI = App.ArtificialIntelligence_GetAIByID(idAI)
			if pAI:
				pAI.CallExternalFunction("SetTarget", self.sCurrentTarget)

			# Check if we should stop.
			if App.g_kSystemWrapper.GetTimeSinceFrameStart() > dEndTime:
				break

#		debug("Updated %d AI's before endtime." % (iOriginalLength - len(self.lAIUpdateIDs)))

		if len(self.lAIUpdateIDs) == 0:
			# Done updating the tree beneath us.
			del self.lAIUpdateIDs
			self.bUpdatingTargetInfo = 0
			self.pCodeAI.ForceDormantStatus(App.PreprocessingAI.FDS_NORMAL)

		App.TGProfilingInfo_StopTiming(idProfiling)

	def FindGoodTarget(self):
		# Look through our list of valid targets and see which
		# one is the 'best' target at the moment.
		pOurShip = self.pCodeAI.GetShip()
		if (pOurShip == None):
			return None
		pSet = pOurShip.GetContainingSet()

		# Get the objects that exist in our target list...
		lTargets = self.pTargetGroup.GetActiveObjectTupleInSet(pSet)

		# Remove dead, dying, and cloaked objects.
		lOldTargets = lTargets
		lTargets = []
		for pOldTarget in lOldTargets:
			pDam = App.DamageableObject_Cast(pOldTarget)
			if pDam:
				# If the target is dead or dying, skip it.
				if pDam.IsDead() or pDam.IsDying():
					continue

			pShip = App.ShipClass_Cast(pOldTarget)
			if pShip:
				pCloakSystem = pShip.GetCloakingSubsystem()
				if pCloakSystem:
					if pCloakSystem.IsCloaked():
						# This ship is cloaked.  Skip it.
						continue

			# Skip ourselves, too.
			if pOldTarget.GetObjID() == pOurShip.GetObjID():
				continue

			# This target is alive, valid, and well.  Put it in the target list.
			lTargets.append(pOldTarget)

		if len(lTargets) == 0:
			# No targets available..
			return None
		elif len(lTargets) == 1:
			# Only 1 target.  Choose that one.
			return lTargets[0].GetName()

		# Give a "good target" rating to each of the
		# objects in our list...  Choose the target with the highest
		# rating.
		fHighestRating = -1.0e20
		pHighestTarget = lTargets[0]

		for pTarget in lTargets:
			fRating = self.GetTargetRating( pTarget )
			
			if fRating > fHighestRating:
				fHighestRating = fRating
				pHighestTarget = pTarget
		
		return pHighestTarget.GetName()	

	def GetTargetRating(self, pTarget):
		pOurShip = self.pCodeAI.GetShip()
		if (pOurShip == None):
			return -1

		vDifference = pTarget.GetWorldLocation()
		vDifference.Subtract(pOurShip.GetWorldLocation())

		# Distance to target has some effect...
		# We'll choose a minimum distance, beneath which
		# everything is 1.0, above which the value falls
		# off as the inverse of the distance.
		fDistanceGood = 0.0
		fDistance = vDifference.Length()
		if fDistance > 0:
			fDistanceGood = self.fMinimumFullGoodDistance / fDistance
			if fDistanceGood > 1.0:
				fDistanceGood = 1.0

		# Whether or not a target is in front of us has
		# some effect on whether or not it's a good target...
		fAngleGood = 0.0
		if fDistance > 0:
			vOurForward = pOurShip.GetWorldForwardTG()
			fAngle = vOurForward.Dot(vDifference) / fDistance

			if fAngle > 1.0:
				fAngle = 1.0
			if fAngle < -1.0:
				fAngle = -1.0
			fAngle = math.acos(fAngle)

			fAngleGood = (1.0 - (fAngle / math.pi))

		# If the ship is currently our target, that will
		# affect our decision.
		fIsTargetGood = 0.0
		if self.bSetShipTarget:
			pOurTarget = pOurShip.GetTarget()
			if pOurTarget and (pOurTarget.GetName() == pTarget.GetName()):
				fIsTargetGood = 1.0
		elif pTarget.GetName() == self.sCurrentTarget:
			fIsTargetGood = 1.0

		# Status of the target's shields and subsystems
		# has some effect.
		fShieldGood = 0.0
		fWeaponsGood = 0.0
		fHullGood = 0.0
		pShip = App.ShipClass_Cast(pTarget)
		if (pShip != None):
			# Shields...
			pShieldSystem = pShip.GetShields()
			fShieldGood = pShieldSystem.GetShieldPercentage()

			# Weapons...
			fTotal = 0
			pWeapIter = pShip.StartGetSubsystemMatch( App.CT_WEAPON_SYSTEM )
			pSystem = pShip.GetNextSubsystemMatch( pWeapIter )
			while (pSystem != None):
				fTotal = fTotal + 1
				fWeaponsGood = fWeaponsGood + pSystem.GetCombinedConditionPercentage()
				pSystem = pShip.GetNextSubsystemMatch( pWeapIter )
			pShip.EndGetSubsystemMatch( pWeapIter )

			# fWeaponsGood needs to be from 0.0 to 1.0
			if fTotal > 0:
				fWeaponsGood = fWeaponsGood / fTotal

			# Hull...
			pHull = pShip.GetHull()
			fHullGood = pHull.GetCombinedConditionPercentage()

		# Check the amount of damage dealt to us by this
		# target.
		fDamageDealt = 0.0
		sTarget = pTarget.GetName()
		if self.dDamageReceived.has_key(pTarget.GetObjID()):
			fDamageDealt = self.dDamageReceived[pTarget.GetObjID()]
			#debug("Deciding targets (%s to %s), target has inflicted %f damage." % (pOurShip.GetName(), sTarget, fDamageDealt))

		# If we have priority information for this target,
		# factor in its priority.
		fPriority = 0.0
		pGroupWithInfo = App.ObjectGroupWithInfo_Cast(self.pTargetGroup)
		if pGroupWithInfo:
			dInfo = pGroupWithInfo[sTarget]
			if dInfo.has_key("Priority"):
				fPriority = dInfo["Priority"]
				#debug("Found priority %f for target %s" % (fPriority, sTarget))

		# Count the number of other ships targeting this target.
		fPopularity = 0.0
		pSet = pOurShip.GetContainingSet()
		if pSet:
			idOurID = pOurShip.GetObjID()
			idTargetID = pTarget.GetObjID()
			lpShips = pSet.GetClassObjectList(App.CT_SHIP)
			for pShip in lpShips:
				# Make sure it's not us.
				if pShip.GetObjID() == idOurID:
					continue

				# Is this ship targeting this target?
				pShipTarget = pShip.GetTarget()
				if pShipTarget and (pShipTarget.GetObjID() == idTargetID):
					# Yep, it is.  The target's popularity
					# just went up by 1.0.
					fPopularity = fPopularity + 1.0

		# Those are all the factors we're taking into account.
		# Take these values, scale them, and add them together
		# for a single rating.
		fRating = 0.0
		for fSubRating, fSubImportance in [
				(fDistanceGood,	self.fDistanceFactor),
				(fAngleGood,	self.fInFrontFactor),
				(fIsTargetGood,	self.fIsTargetFactor),
				(fShieldGood,	self.fShieldFactor),
				(fWeaponsGood,	self.fWeaponsFactor),
				(fHullGood,	self.fHullFactor),
				(fDamageDealt,	self.fDamageFactor),
				(fPriority,	self.fPriorityFactor),
				(fPopularity, self.fPopularityFactor) ]:
			fRating = fRating + (fSubRating * fSubImportance)

		# We're done.
		return fRating

#
# AvoidObstacles
#
# If this detects that a collision is imminent (or our
# personal space is a little cramped), it changes course
# and moves to fix the situation.
#
# ***NOTE: The script for this preprocess is only used
# for setup.  Once the AI containing it is created, it's
# replaced with an optimized version in the code.
#
class AvoidObstacles:
	def __init__(self):
		# Setup how often we'll do our check...
		self.fMinimumUpdateDelay = 0.0 # 0.25
		self.fMaximumUpdateDelay = 0.25 # 1.25
		self.fUpdateDelay = self.fMaximumUpdateDelay

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# If we're overriding the ship's course, we need
		# to know what direction to head toward, and what
		# speed to go.
		self.vOverrideDirection = None
		self.fOverrideSpeed = None
		
		# How long into the future we'll anticipate
		# collisions...
		self.fPredictionTime = 15.0

		# Minimum radius around which to look for incoming
		# objects.
		self.fMinimumRadius = 225.0 # 225 is about 40km.

		# Set how much space we want around ourselves, as
		# a multiple of our radius.
		self.fPersonalSpace = 2.5

		# Angles that determine how we maneuver...
		self.fFrontAngle = 20.0 / 180.0 * App.PI
		self.fSideAngle = App.HALF_PI
		self.fBackAngle = 170.0 / 180.0 * App.PI
		
		self.fFrontSpeed = 0.0
		self.fSideSpeed = 1.0
		self.fBackSpeed = 1.0

		# Types of objects that we won't bother avoiding:
		self.lDontAvoidTypes = [
			App.CT_PROXIMITY_CHECK,
			App.CT_DEBRIS,
			App.CT_TORPEDO,
			App.CT_ASTEROID_FIELD,
			App.CT_NEBULA ]

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)

	def GetNextUpdateTime(self):
		# Update time varies...
		return self.fUpdateDelay

	def Update(self, dEndTime):
		# Under normal circumstances, we'll pass through
		# and let our contained AI do its stuff.
		eRet = App.PreprocessingAI.PS_NORMAL
		self.fUpdateDelay = self.fMaximumUpdateDelay

		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			return App.PreprocessingAI.PS_DONE

		# If we're in-system warping, don't check for collisions, because
		# the in-system warp check already does that.
		if pShip.IsDoingInSystemWarp():
			return App.PreprocessingAI.PS_NORMAL

		# Update whether or not we should be overriding
		# the ship's course.
		self.vOverrideDirection, self.fOverrideSpeed = self.TestCourseOverride()

		if self.vOverrideDirection:
			# We're overriding the ship's course.
			# Don't let our contained AI do anything.
			eRet = App.PreprocessingAI.PS_SKIP_ACTIVE

			# Set the ship's course and speed.
			pShip.TurnTowardDirection( self.vOverrideDirection )
			pShip.SetImpulse( self.fOverrideSpeed, App.TGPoint3_GetModelForward(), App.ShipClass.DIRECTION_MODEL_SPACE)

			self.fUpdateDelay = self.fMinimumUpdateDelay

		# Done.
		return eRet

	def TestCourseOverride(self):
		# Get our ship...
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			return (None, None)

		pSet = pShip.GetContainingSet()
		if (pSet == None):
			# Not in a set.  Guess we can't collide with
			# anything.  :)
			return (None, None)

		# Predict our location in the near future...
		vPredictedLocation = pShip.GetPredictedPosition(
			pShip.GetWorldLocation(),
			pShip.GetVelocityTG(),
			pShip.GetAccelerationTG(),
			self.fPredictionTime)

		# Figure out how far that is from us...
		vDiff = App.TGPoint3()
		vDiff.Set( vPredictedLocation )
		vDiff.Subtract( pShip.GetWorldLocation() )
		fDistance = vDiff.Length()

		# Find any objects within the sphere centered at
		# our predicted location, with a radius of fDistance
		# plus our personal space.
		fPersonalSpaceRadius = pShip.GetRadius() * self.fPersonalSpace
		fCheckRadius = fDistance + fPersonalSpaceRadius
		if fCheckRadius < self.fMinimumRadius:
			fCheckRadius = self.fMinimumRadius

		pProxManager = pSet.GetProximityManager()
		lAvoidObjects = []
		if (pProxManager != None):
			pObjectIter = pProxManager.GetNearObjects( vPredictedLocation, fCheckRadius )
			pObject = pProxManager.GetNextObject( pObjectIter )
			while (pObject != None):
				# This object is inside the radius...
				# Is it our ship?
				if pObject.GetObjID() != pShip.GetObjID():
					# Nope.  It's something else.  Test whether
					# or not we need to avoid this object.
					if self.NeedToAvoid( pShip, fPersonalSpaceRadius, pObject ):
						# Probably going to collide, if we
						# don't do something.  Add this to
						# the list of objects we should avoid.
						lAvoidObjects.append( pObject )
				pObject = pProxManager.GetNextObject( pObjectIter )
			pProxManager.EndObjectIteration( pObjectIter )

		# Determine what our avoidance direction and speed
		# should be, based on the objects we need to avoid.
		return self.AvoidObjects( pShip, lAvoidObjects )

	def NeedToAvoid(self, pShip, fPersonalSpaceRadius, pObject):
		# Don't bother evading certain objects
		for eType in self.lDontAvoidTypes:
			if pObject.IsTypeOf(eType):
				return 0

		# If the object is already within our personal space,
		# we need to avoid it.
		vDiff = pObject.GetWorldLocation()
		vDiff.Subtract(pShip.GetWorldLocation())
		fDist = vDiff.Length()
		if fDist < (fPersonalSpaceRadius + pObject.GetRadius()):
			return 1

		# Get the object's velocity.		
		vOtherVelocity = App.TGPoint3()
		pPhysObj = App.PhysicsObjectClass_Cast(pObject)
		if (pPhysObj != None):
			# This is a physics object.  It has a velocity..
			vOtherVelocity.Set(pPhysObj.GetVelocityTG())
		else:
			vOtherVelocity.SetXYZ(0,0,0)

		# Find our relative velocity...
		vVelDiff = App.TGPoint3()
		vVelDiff.Set( pShip.GetVelocityTG() )
		vVelDiff.Subtract(vOtherVelocity)
		
		# This thing is an incoming hazard if the distance between us
		# will drop below our personal space + their radius anytime
		# in the near future.
		# Setup vars for quadratic formula:
		# a = (Vsx - Vtx)^2 + (Vsy - Vty)^2 + (Vsz - Vtz)^2
		a = vVelDiff.SqrLength()
		if a > 0:
			# b = 2((Psx - Ptx)(Vsx - Vtx) + (Psy - Pty)(Vsy - Vty) + (Psz - Ptz)(Vsz - Vtz))
			vPosDiff = App.TGPoint3()
			vPosDiff.Set( pShip.GetWorldLocation() )
			vPosDiff.Subtract( pObject.GetWorldLocation() )
			b = 2 * vPosDiff.Dot(vVelDiff)

			# c = (Rs + Rt)^2  +  (Psx - Ptx)^2 + (Psy - Pty)^2 + (Psz - Ptz)^2
			fRadiusSum = (fPersonalSpaceRadius  +  pObject.GetRadius())
			c = -(fRadiusSum * fRadiusSum)  +  vPosDiff.SqrLength()

			# Find the soonest collision time:
			fHitTime = -1.0

			fSqrtPart = b*b - 4.0*a*c
			if fSqrtPart >= 0:
				fSqrt = math.sqrt(fSqrtPart)
				t1 = (-b + fSqrt) / (2*a)
				t2 = (-b - fSqrt) / (2*a)
			
				if t1 < t2:
					if t1 >= 0:
						fHitTime = t1
					else:
						fHitTime = t2
				else:
					if t2 >= 0:
						fHitTime = t2
					else:
						fHitTime = t1

			if fHitTime >= 0:
				# We found a collision sometime in the future.
				# If it's within our "incoming time" threshold, then
				# this object is a hazard.
				if fHitTime < self.fPredictionTime:
					return 1

		# Nope, not a hazard.
		return 0

	def AvoidObjects(self, pShip, lAvoidObjects):
		"""Determine what our direction and speed should be to
		avoid the given list of objects."""
		# If the list is empty, we do nothing.
		if len( lAvoidObjects ) == 0:
			return None, None

		# Build a list of directions, angles around those
		# directions, and favorability values for each direction.
		lpDirectionInfo = []
		for pObject in lAvoidObjects:
			# ***FIXME: If this object is HUGE (like
			# a starbase is), break up its main spheres
			# into smaller ones that are more representative
			# of the actual obstacle).
			vDirection = pObject.GetWorldLocation()
			vDirection.Subtract(pShip.GetWorldLocation())
			fDistance = vDirection.Unitize()

			pPhys = App.PhysicsObjectClass_Cast(pObject)
			if pPhys:
				vObstacleVelocity = pPhys.GetVelocityTG()
			else:
				vObstacleVelocity = App.TGPoint3()
				vObstacleVelocity.SetXYZ(0,0,0)

			# If there's no distance between the
			# two, how can we possibly avoid the other object?
			# Just ignore it, if that's the case.
			if fDistance > 0.0:
				# Change this so it just does multiplies and
				# a sqrt, rather than 2 trig functions..
				fBlockedAngle = math.atan((pObject.GetRadius() + pShip.GetRadius()) / fDistance)
				fBlockedDot = math.cos(fBlockedAngle)

				fFavorability = -self.fMinimumRadius / fDistance

				lpDirectionInfo.append((pObject.GetWorldLocation(), vDirection, vObstacleVelocity, fBlockedDot, fFavorability))

		# Next, we need to find a good direction to flee.
		# First, test the opposites of the directions in
		# the direction info...
		vFleeDir = None
		fFleeDirAppeal = -1.0e20
		for vPosition, vDirection, vObstacleVelocity, fBlockedAngle, fFavorability in lpDirectionInfo:
			# Get the opposite of the direction..
			vFleeTestDir = App.TGPoint3()
			vFleeTestDir.Set(vDirection)
			vFleeTestDir.Scale(-1.0)

			# Calculate its appeal.
			fTestDirAppeal = self.CalculateDirectionAppeal(pShip, vFleeTestDir, lpDirectionInfo)

			# Better than our last test?
			if fTestDirAppeal > fFleeDirAppeal:
				fFleeDirAppeal = fTestDirAppeal
				vFleeDir = vFleeTestDir

		# Then test a few random directions to see if there's a better one.
		for iAttempt in range(8):
			vFleeTestDir = App.TGPoint3_GetRandomUnitVector()

			# Calculate its appeal.
			fTestDirAppeal = self.CalculateDirectionAppeal(pShip, vFleeTestDir, lpDirectionInfo)

			# Better than our last test?
			if fTestDirAppeal > fFleeDirAppeal:
				fFleeDirAppeal = fTestDirAppeal
				vFleeDir = vFleeTestDir

		vNewHeading = vFleeDir

		# Our speed depends on whether we're currently facing
		# a safe direction or not.
		bFacingSafe = self.IsDirectionSafe(pShip.GetWorldForwardTG(), lpDirectionInfo)

		fSpeed = 0.0
		if bFacingSafe:
			fSpeed = 1.0

		return (vNewHeading, fSpeed)

	def CalculateDirectionAppeal(self, pShip, vTestDirection, lpDirectionInfo):
		# Compare this direction against the various
		# directions in the direction info.
		fOverallAppeal = 0.0
		for vPosition, vDirection, vVelocity, fBlockedDot, fFavorability in lpDirectionInfo:
			# Find the dot product to this direction.
			fDot = vTestDirection.Dot(vDirection)

			# If our dot is inside fBlockedDot, we get the
			# full favorability value for this direction.
			if fDot >= fBlockedDot:
				fAppeal = fFavorability
				continue
			else:
				# Otherwise, the value of this direction
				# goes to the negative of the favorability
				# value, as the dot approaches 0, and
				# half the negative of the favorability
				# at -1.
				if fDot >= 0:
					try:
						fAppeal = fFavorability - (2.0 * fFavorability * (fBlockedDot - fDot) / fBlockedDot)
					except ZeroDivisionError:
						fAppeal = -fFavorability
				else:
					fAppeal = (fFavorability * fDot * 0.5)  +  (fFavorability * (1.0 + fDot))

			fOverallAppeal = fOverallAppeal + (fAppeal * 2.0)

			# Similar calculations against the velocity.
			vVelDir = App.TGPoint3()
			vVelDir.Set(vVelocity)
			vVelDir.Unitize()
			if vVelDir.SqrLength() > 0.0625:
				# Not a zero vector...
				fDot = vVelDir.Dot(vTestDirection)

				# Appeal goes from fFavorability at 1 to
				# -fFavorability at 0 to fFavorability at -1
				fAppeal = (abs(fDot) - 0.5) * 2.0 * fFavorability

				fOverallAppeal = fOverallAppeal + fAppeal

				# More calculations, to ensure that we aren't moving
				# in front of the other object.
				fDot = vDirection.Dot(vVelocity)
				if 1: #fDot < (0.125 / vVelocity.Length()):
					# We're roughly in front of the other object.  If
					# the direction is toward their front (the direction
					# they're moving), that's bad.
					vTestPerpendicular = vTestDirection.GetPerpendicularComponent( vVelocity )
					vDirectionPerpendicular = vDirection.GetPerpendicularComponent( vVelocity )

					vTestPerpendicular.Unitize()
					vDirectionPerpendicular.Unitize()

					fDot = vTestPerpendicular.Dot( vDirectionPerpendicular )
					fAppeal = fDot * fFavorability
				else:
					fAppeal = -fFavorability
				fOverallAppeal = fOverallAppeal + fAppeal

			# Finally, a little bit of goodness if this direction is
			# near our forward vector.
			fAppeal = pShip.GetWorldForwardTG().Dot(vDirection) * 0.1
			fOverallAppeal = fOverallAppeal + fAppeal

		return fOverallAppeal

	def IsDirectionSafe(self, vTestDirection, lpDirectionInfo):
		# Compare this direction against the various
		# directions in the direction info.
		for vPosition, vDirection, vVelocity, fBlockedDot, fFavorability in lpDirectionInfo:
			# Find the dot product to this direction.
			fDot = vTestDirection.Dot(vDirection)

			# If our dot is inside fBlockedDot, this
			# direction is not safe.
			if fDot >= fBlockedDot:
				return 0

		# This direction should be safe (ignoring our
		# own radius...).
		return 1

#
# AlertLevel
#
# Use this with any AI to have our ship stay in a
# specified Alert Level (green/yellow/red) while it
# performs the AI's attached to it.
#
class AlertLevel:
	# Arguments to the constructor:
	# eAlertLevel	- The alert level to maintain.
	def __init__(self, eAlertLevel, bRestoreOldLevelWhenDone = 1):
		self.eAlertLevel = eAlertLevel
		self.eOldAlertLevel = None
		self.bRestoreOld = bRestoreOldLevelWhenDone

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)

	def GetNextUpdateTime(self):
		# We don't really need to be updated.  Our update
		# doesn't really do anything.
		return 60

	def Update(self, dEndTime):
		return App.PreprocessingAI.PS_NORMAL

	def GotFocus(self):
		pOurShip = self.pCodeAI.GetShip()
		if pOurShip:
			self.eOldAlertLevel = pOurShip.GetAlertLevel()
			if self.eOldAlertLevel != self.eAlertLevel:
				pOurShip.SetAlertLevel(self.eAlertLevel)

	def LostFocus(self):
		if self.bRestoreOld:
			if self.eOldAlertLevel is not None:
				pOurShip = self.pCodeAI.GetShip()
				if pOurShip:
					if pOurShip.GetAlertLevel() != self.eOldAlertLevel:
						pOurShip.SetAlertLevel(self.eOldAlertLevel)

#
# CloakShip
#
# Use this AI to cloak a ship with
# a cloaking system.
#
class CloakShip:
	def __init__(self, bCloakOn):
		# If bCloakOn is true, this will cloak our ship.  If it's
		# false it will uncloak the ship.
		self.bCloakOn = bCloakOn

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)

	def GetNextUpdateTime(self):
		return 5.0
		
	def Update(self, dEndTime):
		self.CheckCloak()
		
		return App.PreprocessingAI.PS_NORMAL

	def GotFocus(self):
		self.CheckCloak()

	def LostFocus(self):
		# Losing focus.  Make sure we uncloak.
		pOurShip = self.pCodeAI.GetShip()
		if pOurShip:
			pCloak = pOurShip.GetCloakingSubsystem()
			if pCloak:
				pCloak.StopCloaking()

	def CheckCloak(self):
		# Check and see if the ship is cloaked
		# if not, try and cloak it.
		pOurShip = self.pCodeAI.GetShip()
		if pOurShip:
			pCloak = pOurShip.GetCloakingSubsystem()
			if pCloak:
				if self.bCloakOn:
					if (not pCloak.IsCloaked()) and (not pCloak.IsCloaking()):
						pCloak.StartCloaking()
				else:
					if pCloak.IsCloaked():
						pCloak.StopCloaking()

#
# ManagePower
#
# Manage the power levels of a ship, to try to give
# more power to the things that are being used, and
# less power to the things that don't need them.  And
# do anything possible to prevent from running out
# of power.
#
class ManagePower:
	def __init__(self, bConservePower):
		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)
		self.bConservePower = bConservePower

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)

	def GetNextUpdateTime(self):
		return 3.0

	def Update(self, dEndTime):
		# Unused.
		return App.PreprocessingAI.PS_DONE

#
# UpdateAIStatus
#
# This AI is used to set information about what an
# AI is currently doing.  Something can query the
# focus path in an AI tree and get responses from
# these preprocesses as to what the AI is trying to
# do.
#
class UpdateAIStatus:
	def __init__(self, sStatus):
		# sStatus is returned as the status if the AI if
		# this AI is queried.
		self.sStatus = sStatus

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	def CodeAISet(self):
		# Further initialization we can do once our self.pCodeAI
		# member has been set.
		# Register external functions.
		self.pCodeAI.RegisterExternalFunction("QueryAIStatus",
			{ "Name" : "QueryAIStatus" } )

	def QueryAIStatus(self, lInfo):
		# lInfo is a list that we'll add our status to.
		lInfo.append( self.sStatus )

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)

	def GetNextUpdateTime(self):
		# This AI never really needs to be updated.
		return 360.0
		
	def Update(self, dEndTime):
		return App.PreprocessingAI.PS_NORMAL

#
# FelixReportStatus
#
# Have Felix report on his current AI status.  This works together
# with UpdateAIStatus preprocesses to determine what Felix should
# report.
#
class FelixReportStatus:
	def __init__(self):
		self.sLastStatus = None
		self.sLastReportedStatus = None

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	def GetNextUpdateTime(self):
		# Update often enough that Felix can report in a timely manner.
		return 0.5

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)

	def Update(self, dEndTime):
		# Determine what the current status of the AI tree beneath us is.
		lStatus = []
		for pAI in self.pCodeAI.GetFocusAIs():
			pAI.CallExternalFunction("QueryAIStatus", lStatus)

		# Only use the most recent entry..
		sStatus = None
		if lStatus:
			sStatus = lStatus[len(lStatus) - 1]

		# If the status now is the same as it was last update, Felix can say
		# what he's doing, because he's been doing it long enough that he'll
		# probably keep doing it for a little while.
		if sStatus  and  (sStatus == self.sLastStatus):
			self.Report(sStatus)

		self.sLastStatus = sStatus

		return App.PreprocessingAI.PS_NORMAL

	def Report(self, sStatus):
		# If we've already reported this status, don't report it again.
		if sStatus == self.sLastReportedStatus:
			return

		# Get Felix.
		pBridgeSet = App.g_kSetManager.GetSet("bridge")
		if not pBridgeSet:
			return

		pFelix = App.CharacterClass_GetObject(pBridgeSet, "Tactical")
		if not pFelix:
			return

		# If he's said something recently, don't make him too talkative...
		fTalkDelay = App.g_kUtopiaModule.GetGameTime() - pFelix.GetLastTalkTime()
		if fTalkDelay < 15.0:
			return

		# If he's talking right now, don't add another line.
		if pFelix.IsSpeaking():
			return

		#
		# Ok, we're going to say the line.
		# Record the fact that we're reporting this status.
		self.sLastReportedStatus = sStatus

		# There may be multiple lines available for this status.  Check the character's
		# database to see what lines are available.
		lLines = []
		pDatabase = pFelix.GetDatabase()
		iNum = 1
		while 1:
			sTestString = sStatus + str(iNum)
			if not pDatabase.HasString(sTestString):
				break

			lLines.append(sTestString)
			iNum = iNum + 1

		# Choose a string at random.
		if lLines:
			sStatus = lLines[App.g_kSystemWrapper.GetRandomNumber( len(lLines) )]

		# Report the current status.
		#debug("Felix reporting status: " + str(sStatus))

		### HACK BY COLIN ###
		###
		# I don't understand how the AI is calling this, but if the line is 'lining up rear torpedo tubes' and we
		# have used up our rear torps, don't call out
		###
		if (sStatus == "AttackStatus_RearTorpRun1"):
			import MissionLib
			pShip = MissionLib.GetPlayer()
			pTorpedoSystem = pShip.GetTorpedoSystem()

			# Check rear torpedo tubes
			if (not pTorpedoSystem.IsTubeReady(4) and not pTorpedoSystem.IsTubeReady(4)):
				# No tubes are ready, fail
				return
		### END HACK BY COLIN ###

		App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, sStatus, None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()

#
# UseShipTarget
#
# A little preprocessing AI that calls the external
# SetTarget function on its AI's any time its ship
# changes target (using ShipClass::SetTarget).  If it
# has no valid target, the preprocess's tree is dormant.
#
class UseShipTarget:
	def __init__(self):
		self.sTargetName = None

		# Add event handlers...
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def CodeAISet(self):
		# Listen for when our ship changes target, or when our ship exits a set.
		pShip = self.pCodeAI.GetShip()
		if pShip:
			App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_TARGET_WAS_CHANGED, self.pEventHandler, "TargetChanged", pShip)

			# Grab our initial target.
			pTarget = pShip.GetTarget()
			if pTarget:
				self.sTargetName = pTarget.GetName()

	def TargetChanged(self, pEvent):
		pShip = self.pCodeAI.GetShip()
		if pShip:
			# Get the new target...
			sNewName = None
			try:
				pTarget = pShip.GetTarget()
				sNewName = pTarget.GetName()
			except AttributeError:
				pass

			if sNewName != self.sTargetName:
				# Our target has changed.  If our old target was None,
				# we need to make sure we're updated.
				if self.sTargetName is None:
					self.pCodeAI.ForceUpdate()

				self.sTargetName = sNewName

				# Update all AI's underneath us in the AI tree.
				for pAI in self.pCodeAI.GetAllAIsInTree()[1:]:
					pAI.CallExternalFunction("SetTarget", self.sTargetName)

	def GetNextUpdateTime(self):
		# Call update every time our tree is updated, so
		# we're accurate every frame (in case the target
		# changed event doesn't happen exactly on the right
		# frame).  If we're dormant, we won't be updated
		# unless we force it, so the update time doesn't matter.
		return 0.0

	def Update(self, dEndTime):
		# If we have a target, return normal.  If not, return dormant.
		if self.sTargetName:
			pObject = self.pCodeAI.GetObject()
			pSet = pObject.GetContainingSet()
			if pSet:
				if App.ObjectClass_GetObject(pSet, self.sTargetName):
					# Our target exists.  Return normal.
					return App.PreprocessingAI.PS_NORMAL

		# Target must not exist.  We're dormant.
		return App.PreprocessingAI.PS_SKIP_DORMANT
