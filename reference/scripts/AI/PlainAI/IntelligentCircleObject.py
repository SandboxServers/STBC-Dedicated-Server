#
# IntelligentCircleObject
#
# An AI based on the CircleObject script AI.  Rather than always keeping a set vector toward
# our target, however, this AI will constantly reevaluate which side would be best to keep facing
# the target, and will change the vector appropriately.
# Whatever sets up the ICO AI needs to set its internal priorities, so it knows whether shields
# or weapons are more important.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

REFRESH_SHIELDS	= 0
REFRESH_WEAPONS	= 1
REFRESH_FACING	= 2
TOTAL_REFRESHES	= 3

import CircleObject

class IntelligentCircleObject(CircleObject.CircleObject):
	def __init__(self, pCodeAI):
		# Parent class init first.
		CircleObject.CircleObject.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(
			self.SetRoughDistances,
			self.SetCircleSpeed,
			self.SetShieldAndWeaponImportance,
			self.SetForwardBias)
		self.SetRequiredParams(	# These will override CircleObject's versions.
			( "pcFollowObjectName", "SetFollowObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetFollowObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		self.iAngleRefresh = REFRESH_SHIELDS

		# Cache a list of the weapons we care about...
		self.lWeapons = []
		pShip = self.pCodeAI.GetShip()
		if pShip:
			kIter = pShip.StartGetSubsystemMatch(App.CT_WEAPON_SYSTEM)
			while 1:
				pSystem = pShip.GetNextSubsystemMatch(kIter)
				if not pSystem:
					break

				# Ignore tractor beams..
				if pSystem.IsTypeOf(App.CT_TRACTOR_BEAM_SYSTEM):
					continue

				# Look through all the weapons this system contains:
				for iWeapon in range( pSystem.GetNumChildSubsystems() ):
					pWeapon = App.Weapon_Cast(pSystem.GetChildSubsystem(iWeapon))
					if pWeapon:
						self.lWeapons.append(pWeapon)
			pShip.EndGetSubsystemMatch(kIter)

		self.lCachedShieldAngles = []
		self.lCachedWeaponAngles = []
		self.lCachedFacingAngles = []

	# Somewhat pointless function definitions that just
	# call our parent class.  These are here so the AI Editor
	# can see them.
	def SetFollowObjectName(self, sName): #AISetup
		CircleObject.CircleObject.SetFollowObjectName(self, sName)
	def SetRoughDistances(self, fNearDistance = 0, fFarDistance = 0): #AISetup
		CircleObject.CircleObject.SetRoughDistances(self, fNearDistance, fFarDistance)
	def SetCircleSpeed(self, fSpeed = 1.0): #AISetup
		CircleObject.CircleObject.SetCircleSpeed(self, fSpeed)
	def UseFixedCode(self, bUseFixed = 0): #AISetup
		CircleObject.CircleObject.UseFixedCode(self, bUseFixed)

	def SetShieldAndWeaponImportance(self, fShieldImportance = 0.56, fWeaponImportance = 0.34, fFacingImportance = 0.1): #AISetup
		self.fShieldImportance = fShieldImportance
		self.fWeaponImportance = fWeaponImportance
		self.fFacingImportance = fFacingImportance

	def SetForwardBias(self, fForwardBias = 0.0): #AISetup
		self.fForwardBias = fForwardBias




	fSmallResultThreshold = 0.1

	iNumUpdatesToSkip = 1
	iNumUpdatesSkipped = iNumUpdatesToSkip

	iNumAnglesToCheck = 8

	def GetStatusInfo(self):
		return "Target(%s), distances(%d, %f, %f), speed(%f), Importances(s%f, w%f, f%f)" % (
			self.pcFollowObjectName,
			self.bUseRoughDistances, self.fNearDistance, self.fFarDistance,
			self.fFastSpeed,
			self.fShieldImportance, self.fWeaponImportance, self.fFacingImportance)

	def Reset(self):
		# Reset any state info
		self.iNumUpdatesSkipped = self.iNumUpdatesToSkip
		self.fNextFiringArcUpdate = 0.0

	def Update(self):
		"The update AI script"
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# We skip most of our updates, because we don't need to do
		# our work very often.  But CircleObject does, so we'll
		# call it.
		self.iNumUpdatesSkipped = self.iNumUpdatesSkipped + 1
		if self.iNumUpdatesSkipped > self.iNumUpdatesToSkip:
			self.iNumUpdatesSkipped = 0
			
			self.AdjustFacing(pShip)
					
		# Call our base class (CircleObject) function.
		# (module).(class).(function)(args)
		return CircleObject.CircleObject.Update(self)
		
	def AdjustFacing(self, pShip):
		# Adjust our vModelSide vector

		# Build a list of angles, and values for each angle.
		# As we sweep through different angles, the value of that angle
		# is the sum of the value of each of these vectors times
		# some factor based on the difference in angle.
		lAngles = []

		# Build the list of angle/value pairs.
		if self.fShieldImportance:
			self.AddShieldAngles(lAngles, pShip)
		elif self.fWeaponImportance:
			self.AddWeaponAngles(lAngles, pShip)
		elif self.fFacingImportance:
			self.AddFacingAngle(lAngles, pShip)
		self.iAngleRefresh = (self.iAngleRefresh + 1) % TOTAL_REFRESHES

		# Find a good facing vector..
		self.vModelSide = self.FindGoodFacingVector(lAngles)

	def AddShieldAngles(self, lAngles, pShip):
		# Add angle/value pairs to the angle list for
		# each of our shields.
		if self.iAngleRefresh != REFRESH_SHIELDS:
			lAngles.extend( self.lCachedShieldAngles )
			return

		kProfiling = App.TGProfilingInfo("ICO.AddShieldAngles")
		pShields = pShip.GetShields()

		fHighestMax		= 0.01
		# Find the highest MaxShields value, among these 4 shields...
		for eShield in (App.ShieldClass.TOP_SHIELDS,
				App.ShieldClass.LEFT_SHIELDS,
				App.ShieldClass.RIGHT_SHIELDS,
				App.ShieldClass.BOTTOM_SHIELDS ):
			fMax = pShields.GetMaxShields(eShield)
			if fMax > fHighestMax:
				fHighestMax = fMax

		# Find the current value of each shield.
		fShieldTop		= pShields.GetCurShields(App.ShieldClass.TOP_SHIELDS)
		fShieldLeft		= pShields.GetCurShields(App.ShieldClass.LEFT_SHIELDS)
		fShieldRight	= pShields.GetCurShields(App.ShieldClass.RIGHT_SHIELDS)
		fShieldBottom	= pShields.GetCurShields(App.ShieldClass.BOTTOM_SHIELDS)

		# Add angle/value pairs for each shield.  The value
		# is the fraction of the highest max times the
		# importance we place on the shields...
		self.lCachedShieldAngles = [
			(0.0,		fShieldTop / fHighestMax * self.fShieldImportance),
			(App.PI * 1.5,	fShieldLeft / fHighestMax * self.fShieldImportance),
			(App.HALF_PI,	fShieldRight / fHighestMax * self.fShieldImportance),
			(App.PI,	fShieldBottom / fHighestMax * self.fShieldImportance)
			]
		lAngles.extend( self.lCachedShieldAngles )

	def AddWeaponAngles(self, lAngles, pShip):
		# Add angle/value pairs to the angle list for
		# each of our relevant weapon systems.
		if self.iAngleRefresh != REFRESH_WEAPONS:
			lAngles.extend( self.lCachedWeaponAngles )
			return

		kProfiling = App.TGProfilingInfo("ICO.AddWeaponAngles")

		# Look through all our weapon systems...
		import math

		self.lCachedWeaponAngles = []
		mWorldToModel = pShip.GetWorldRotation().Transpose()
		for pWeapon in self.lWeapons:
			# Got a weapon system.  Figure out what direction it's
			# facing, and its appeal.
			vDirection, fWeaponValue = self.GetWeaponDirectionAndValue(pWeapon, mWorldToModel)

			# If Fwd is significantly greater than Right or Up,
			# we'll ignore this system.
			fSysFwd = App.TGPoint3_GetModelForward().Dot(vDirection)
			fSysUp = App.TGPoint3_GetModelUp().Dot(vDirection)
			fSysRight = App.TGPoint3_GetModelRight().Dot(vDirection)

			if abs(fSysFwd) < 0.9:
				# Don't ignore this system.  Determine what
				# angle it's roughly aligned with.
				fAngle = math.acos(fSysUp)
				if fSysRight < 0:
					fAngle = -fAngle

				# Scale it by the importance we give
				# to weapons, and add the angle/value
				# pair.
				self.lCachedWeaponAngles.append( (fAngle, self.fWeaponImportance * fWeaponValue) )

		lAngles.extend( self.lCachedWeaponAngles )

	def GetWeaponDirectionAndValue(self, pWeapon, mWorldToModel):
		# Get this weapon's direction...  Change it
		# to model space.
		vDirection = pWeapon.CalculateRoughDirection()
		vDirection.MultMatrixLeft( mWorldToModel )

		# The weapon value is the appeal of this weapon...
		fValue = pWeapon.CalculateWeaponAppeal()

		return vDirection, fValue

	def AddFacingAngle(self, lAngles, pShip):
		if self.iAngleRefresh != REFRESH_FACING:
			lAngles.extend( self.lCachedFacingAngles )
			return

		kProfiling = App.TGProfilingInfo("ICO.AddFacingAngle")
		self.lCachedFacingAngles = []

		pSet = pShip.GetContainingSet()
		if (pSet == None):
			return

		pOther = App.ObjectClass_GetObject(pSet, self.pcFollowObjectName)
		if (pOther == None):
			return

		# Find the direction vector between our ship
		# and the other object..
		vDirection = pOther.GetWorldLocation()
		vDirection.Subtract(pShip.GetWorldLocation())
		#vDirection.Unitize()

		# Find the components of this difference that are aligned
		# with our orientation vectors.
		fUp	= pShip.GetWorldUpTG().Dot(vDirection)
		fRight	= pShip.GetWorldRightTG().Dot(vDirection)

		# Find the angle these correspond to..
		if fUp and fRight:
			import math
			fLength	= math.sqrt(fUp * fUp  +  fRight * fRight)
			fUp	= fUp / fLength
			fRight	= fRight / fLength

			fAngle = math.acos(fUp)
			if fRight < 0:
				fAngle = -fAngle

			self.lCachedFacingAngles.append( (fAngle, self.fFacingImportance) )

		lAngles.extend( self.lCachedFacingAngles )

	def FindGoodFacingVector(self, lAngles):
		# Sweep through angles from 0 to 2PI, with a little
		# bit of randomness.
		fStepSize = App.TWO_PI / self.iNumAnglesToCheck
		fRandomThreshold = fStepSize / 4.0

		#for fAngle, fValue in lAngles:
		#	debug("List angle %f\tValue %f" % (fAngle, fValue))

		fBestAngle = None
		fMaxValue = -1.0e20
		for iAngleNum in range(self.iNumAnglesToCheck):
			fRandom = (App.g_kSystemWrapper.GetRandomNumber(2001) - 1000) / 1000.0
			fChosenAngle = (iAngleNum * App.TWO_PI / self.iNumAnglesToCheck)
			fChosenAngle = fChosenAngle + (fRandom * fRandomThreshold)

			# Got an angle now.  Determine the value of this
			# angle.  This is the sum of the values of all
			# the angles we've been given times our distance
			# to those angles.
			fChosenAngleValue = self.CalcAngleValue(fChosenAngle, lAngles)

			#debug("Angle %f value: %f" % (fChosenAngle, fChosenAngleValue))
			
			# Got a value for this vector.  If it's
			# better than our max, save this vector..
			if fChosenAngleValue > fMaxValue:
				fMaxValue = fChosenAngleValue
				fBestAngle = fChosenAngle

				if fChosenAngle is None:
#					debug("Chosen angle is None!??  Find Kevin.")
#					App.Breakpoint()
					raise ValueError

		#debug("Chose angle %f" % fBestAngle)

		if fBestAngle is None:
#			debug("Best angle is None??  Find Kevin.      Best(%s), Max(%s), Checks(%s)" % (fBestAngle, fMaxValue, self.iNumAnglesToCheck))
#			App.Breakpoint()
			raise ValueError

		# Convert fBestAngle into a modelspace vector.
		return self.AngleToModelspaceVector(fBestAngle)

	def AngleToModelspaceVector(self, fBestAngle):
		vResult = App.TGPoint3()
		vUp = App.TGPoint3_GetModelUp()
		vRight = App.TGPoint3_GetModelRight()
		import math
		try:
			fSin = math.sin(fBestAngle)
			fCos = math.cos(fBestAngle)
		except:
#			debug("Unable to get sin or cos of (%s)" % fBestAngle)
#			App.Breakpoint()
			raise

		vUp.Scale(fCos)
		vRight.Scale(fSin)

		vResult.Set(vUp)
		vResult.Add(vRight)

		if self.fForwardBias:
			vForward = App.TGPoint3_GetModelForward()
			vForward.Scale(self.fForwardBias)
			vResult.Add(vForward)
			vResult.Unitize()

		return vResult

	def CalcAngleValue(self, fChosenAngle, lAngles):
		import math
		fChosenAngleValue = 0
		for fAngle, fValue in lAngles:
			# Find the difference between this angle
			# and our chosen angle.
			fAngleDiff = abs(fAngle - fChosenAngle)
			while fAngleDiff > App.TWO_PI:
				fAngleDiff = fAngleDiff - App.TWO_PI
			if fAngleDiff > App.PI:
				fAngleDiff = App.TWO_PI - fAngleDiff

			# Got the difference.  Scale this from
			# 1 to -1, instead of 0 to PI.
			fAngleDiff = 1.0 - (fAngleDiff * 2.0 / App.PI)

			# Value with respect to this angle is the
			# fAngleDiff factor times the value of this
			# angle.
			fPartialValue = fAngleDiff * fValue

			fChosenAngleValue = fChosenAngleValue + fPartialValue

		if fChosenAngleValue is None:
#			debug("Chosen angle value in CalcAngleValue is None!??  Find Kevin.  Chosen(%s), lAngles:\n%s" % (fChosenAngle, lAngles))
#			App.Breakpoint()
			raise ValueError
		return fChosenAngleValue








	
