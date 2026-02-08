import App
import BaseAI

# Fuzzy sets we're using:
FS_FAR_FACING_AWAY		= 0
FS_FAR_FACING_TOWARD	= 1
FS_NEAR_FACING_GOOD		= 2
FS_NEAR_FACING_BAD		= 3

FS_STOP_AND_TURN_TOWARD		= 4
FS_FAST_AND_TURN_TOWARD		= 5
FS_STOP_AND_TURN_SIDE		= 6
FS_FAST_AND_TURN_SIDE		= 7


#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class CircleObject(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class init first.
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(self.SetRoughDistances, self.SetCircleSpeed, self.UseFixedCode)
		self.SetRequiredParams(
			( "pcFollowObjectName", "SetFollowObjectName" ),
			( "vModelSide", "SetNearFacingVector" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetFollowObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# The name of the object we're circling
	def SetFollowObjectName(self, sName): #AISetup
		self.pcFollowObjectName = sName
		
	# The model-space vector we want to keep pointing toward the
	# object we're circling.
	def SetNearFacingVector(self, vFacing): #AISetup
		self.vModelSide = App.TGPoint3()
		self.vModelSide.Set(vFacing)

	# The rough distances at which we'll circle.  If these
	# are never set, the ship tries to circle at the current
	# distance.
	def SetRoughDistances(self, fNearDistance = 0, fFarDistance = 0): #AISetup
		self.bUseRoughDistances = not self.iSetup
		self.fNearDistance = fNearDistance
		self.fFarDistance = fFarDistance

	# Set the speed at which we circle.
	def SetCircleSpeed(self, fSpeed = 1.0): #AISetup
		self.fFastSpeed = fSpeed
		self.fNearFastSpeed = fSpeed * 0.8
		self.fStopSpeed = 0.0

	# There's a bug that needs to remain active for
	# ships to behave as they've been behaving.  But if you'd
	# rather they behave as they _should_, pass a
	# 1 to this function.
	def UseFixedCode(self, bUseFixed = 0): #AISetup
		self.bUseFixedCode = bUseFixed



	# Setup the fuzzy logic system that will guide the FollowObject module.
	pFuzzy = App.FuzzyLogic()
	pFuzzy.SetMaxRules(4)
	
	pFuzzy.AddRule(FS_FAR_FACING_AWAY,		FS_STOP_AND_TURN_TOWARD)
	pFuzzy.AddRule(FS_FAR_FACING_TOWARD,	FS_FAST_AND_TURN_TOWARD)
	pFuzzy.AddRule(FS_NEAR_FACING_GOOD,		FS_FAST_AND_TURN_SIDE)
	pFuzzy.AddRule(FS_NEAR_FACING_BAD,		FS_STOP_AND_TURN_SIDE)

	def GetNextUpdateTime(self):
		# We want to be updated every 0.5 seconds
		return 0.5

	def GetStatusInfo(self):
		return "Target(%s), side<%.2f,%.2f,%.2f>, distances(%d, %f, %f), speed(%f)" % (
			self.pcFollowObjectName,
			self.vModelSide.GetX(), self.vModelSide.GetY(), self.vModelSide.GetZ(),
			self.bUseRoughDistances, self.fNearDistance, self.fFarDistance,
			self.fFastSpeed)

	def Update(self):
		"Do our stuff."
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		pSet = pShip.GetContainingSet()
		pObject = App.ObjectClass_GetObject(pSet, self.pcFollowObjectName)

		if (pObject != None):
			# Determine how far we are from our destination object.
			vDifference = pObject.GetWorldLocation()
			vDifference.Subtract(pShip.GetWorldLocation())
			
			fDistance = vDifference.Length()
			
			# Determine if we're facing toward or away from our target
			fTowardSet = 0
			fAwaySet = 0
			
			vFacing = pShip.GetWorldForwardTG()
			fCosAngle = vFacing.Dot(vDifference)
			fScale = vFacing.Length() + fDistance
			if fScale:
				fCosAngle = fCosAngle / fScale
				
			fTowardSet = (fCosAngle + 1) / 2.0
			fAwaySet = 1.0 - fTowardSet

			# Determine if our side vector is pointing toward or away from
			# our target
			fSideTowardSet = 0
			fSideAwaySet = 0
			vFacing.Set(self.vModelSide)
			vFacing.MultMatrixLeft(pShip.GetWorldRotation())
			fCosAngle = vFacing.Dot(vDifference)
			fScale = vFacing.Length() + fDistance
			if fScale:
				fCosAngle = fCosAngle / fScale
				
			fSideTowardSet = (fCosAngle + 1.0) / 2.0

			# This was buggy code..  If you want to use the
			# fixed version of it, call UseFixedCode(1) in
			# setup.
			if self.bUseFixedCode:
				# Fixed code:
				fSideAwaySet = 1.0 - fSideTowardSet
			else:
				# Buggy code:
				fSideAwaySet = 1.0 - fTowardSet

			# Now determine which fuzzy set the distance is in...
			if not self.bUseRoughDistances:
				fNearSet = 1.0
				fFarSet = 0.0
			else:
				fNearSet, fFarSet = App.FuzzyLogic_BreakIntoSets(fDistance, (self.fNearDistance, self.fFarDistance))
				
			# Set these values in our fuzzy set.
			self.SetFuzzySetValues(fNearSet, fFarSet, fAwaySet, fTowardSet, fSideTowardSet, fSideAwaySet)
			
			self.ActOnFuzzyResults(pShip, pObject)
			
		else:
			# We no longer have a destination object.  Stop this AI.
#			debug("Scripted CircleObject AI done (no \"%s\" object)" % self.pcFollowObjectName)
			return App.ArtificialIntelligence.US_DONE

		return App.ArtificialIntelligence.US_ACTIVE

	def SetFuzzySetValues(self, fNearSet, fFarSet, fAwaySet, fTowardSet, fSideTowardSet, fSideAwaySet):
		self.pFuzzy.SetPercentageInSet(FS_FAR_FACING_AWAY,	fFarSet * fAwaySet)
		self.pFuzzy.SetPercentageInSet(FS_FAR_FACING_TOWARD,	fFarSet * fTowardSet)
		self.pFuzzy.SetPercentageInSet(FS_NEAR_FACING_GOOD,	fNearSet * fSideTowardSet)
		self.pFuzzy.SetPercentageInSet(FS_NEAR_FACING_BAD,	fNearSet * fSideAwaySet)

	def ActOnFuzzyResults(self, pShip, pObject):
		# We want to turn so either our front or our side faces pObject.  Determine
		# how much of each we want to face it..
		fFaceFront = self.pFuzzy.GetResultBySet(FS_STOP_AND_TURN_TOWARD) + self.pFuzzy.GetResultBySet(FS_FAST_AND_TURN_TOWARD)
		fFaceSide = self.pFuzzy.GetResultBySet(FS_STOP_AND_TURN_SIDE) + self.pFuzzy.GetResultBySet(FS_FAST_AND_TURN_SIDE)
		fTotal = fFaceFront + fFaceSide
		if fTotal:
			fFaceFront = fFaceFront / fTotal
			fFaceSide = fFaceSide / fTotal

		self.DoTurn(pShip, pObject, fFaceFront, fFaceSide)

		# Determine our speed forward from our fuzzy results
		fGoSlow = self.pFuzzy.GetResultBySet(FS_STOP_AND_TURN_TOWARD) + self.pFuzzy.GetResultBySet(FS_STOP_AND_TURN_SIDE)
		fGoFast = self.pFuzzy.GetResultBySet(FS_FAST_AND_TURN_TOWARD)
		fGoFastNear = self.pFuzzy.GetResultBySet(FS_FAST_AND_TURN_SIDE)
		fTotal = fGoSlow + fGoFast + fGoFastNear
		if fTotal:
			fGoSlow = fGoSlow / fTotal
			fGoFast = fGoFast / fTotal
			fGoFastNear = fGoFastNear / fTotal
		
		fVel = self.fStopSpeed * fGoSlow + self.fFastSpeed * fGoFast + self.fNearFastSpeed * fGoFastNear
		#debug("Face toward " + str(fFaceFront) + " Face side " + str(fFaceSide) + " Velocity " + str(fVel))

		# Set our speed..
		pShip.SetImpulse(fVel, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

	def DoTurn(self, pShip, pObject, fFaceFront, fFaceSide):
		# If we're ignoring the rough distances, just set
		# fFaceSide to 1.0, and fFaceFront to 0.
		if not self.bUseRoughDistances:
			fFaceFront = 0.0
			fFaceSide = 1.0
		# From the combination of these two, determine which orientation we
		# want to face...
		vFacingVector = pShip.GetWorldForwardTG()
		vFacingVector.Scale(fFaceFront)
		vTempSide = App.TGPoint3()
		vTempSide.Set(self.vModelSide)
		vTempSide.Scale(fFaceSide)
		# Rotate the side vector so it's in world space
		vTempSide.MultMatrixLeft(pShip.GetWorldRotation())
		
		vFacingVector.Add(vTempSide)
		
		#debug("Facing is <" + str(vFacingVector.GetX()) + ", " + str(vFacingVector.GetY()) + ", " + str(vFacingVector.GetZ()) + ">")
		
		# vFacingVector now contains the vector (in world space) that we want
		# to align to point to pObject.  ...Find the vector we're aligning to.
		vAlign = pObject.GetWorldLocation()
		vAlign.Subtract(pShip.GetWorldLocation())
		vAlign.Unitize()
		vFacingVector.Unitize()

		# Turn vFacingVector to point to vAlign.
		pShip.TurnDirectionsToDirections(
			vFacingVector,
			vAlign)






























	
