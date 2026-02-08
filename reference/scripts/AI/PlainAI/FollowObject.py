import App
import BaseAI

# Fuzzy sets we're using:
FS_NEAR_WAYPOINT_FACING		= 0
FS_NEAR_WAYPOINT_LEAVING	= 2
FS_MID_WAYPOINT_FACING		= 3
FS_MID_WAYPOINT_LEAVING		= 5
FS_FAR_WAYPOINT_FACING		= 6
FS_FAR_WAYPOINT_LEAVING		= 8

FS_STOP_AND_TURN_TOWARD		= 9
FS_MED_AND_TURN_TOWARD		= 10
FS_FAST_AND_TURN_TOWARD		= 11

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class FollowObject(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class init first.
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(self.SetRoughDistances)
		self.SetRequiredParams(
			( "pcFollowObjectName", "SetFollowObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetFollowObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# The name of the object we're following
	def SetFollowObjectName(self, pcName): #AISetup
		self.pcFollowObjectName = pcName
	
	# The rough distances around which we follow it.
	# The near distance is as close as we ever want to be.
	# If our target is moving, we'll be somewhere between the
	# near and far distances depending on how fast our target goes.
	def SetRoughDistances(self, fNear = 30, fMid = 60, fFar = 100): #AISetup
		self.fNearDistance = fNear
		self.fMidDistance = fMid
		self.fFarDistance = fFar




	# Setup the fuzzy logic system that will guide the FollowObject module.
	pFuzzy = App.FuzzyLogic()
	pFuzzy.SetMaxRules(6)
	
	pFuzzy.AddRule(FS_NEAR_WAYPOINT_FACING,		FS_STOP_AND_TURN_TOWARD)
	pFuzzy.AddRule(FS_NEAR_WAYPOINT_LEAVING,	FS_STOP_AND_TURN_TOWARD)
	pFuzzy.AddRule(FS_MID_WAYPOINT_FACING,		FS_FAST_AND_TURN_TOWARD)
	pFuzzy.AddRule(FS_MID_WAYPOINT_LEAVING,		FS_STOP_AND_TURN_TOWARD)
	pFuzzy.AddRule(FS_FAR_WAYPOINT_FACING,		FS_FAST_AND_TURN_TOWARD)
	pFuzzy.AddRule(FS_FAR_WAYPOINT_LEAVING,		FS_STOP_AND_TURN_TOWARD)

	
	fGoSlowSpeed = 0.0
	fGoMedSpeed  = 0.4
	fGoFastSpeed = 1.0

	def GetStatusInfo(self):
		return "Target(%s), Distances(%f, %f, %f)" % (
			self.pcFollowObjectName,
			self.fNearDistance, self.fMidDistance, self.fFarDistance)
		
	def GetNextUpdateTime(self):
		# We want to be updated every 0.2 seconds
		return 0.2

	def Update(self):
		"Do our stuff"
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		pSet = pShip.GetContainingSet()
		pObject = App.ObjectClass_GetObject(pSet, self.pcFollowObjectName)
		#debug("Running FollowObject AI")
		if pObject:
			# Determine how far we are from our destination object.
			vDifference = pObject.GetWorldLocation()
			vDifference.Subtract(pShip.GetWorldLocation())

			fDistance = vDifference.Length()

			# Determine if we're facing toward or away from our target
			fTowardSet = 0
			fAwaySet = 0

			vFacing = pShip.GetWorldForwardTG()
			fCosAngle = vFacing.Dot(vDifference)
			fScale = vFacing.Length() + vDifference.Length()
			if fScale:
				fCosAngle = fCosAngle / fScale

			fTowardSet = (fCosAngle + 1) / 2.0
			fAwaySet = 1.0 - fTowardSet

			# Now determine which fuzzy set the distance is in...
			fNearSet, fMidSet, fFarSet = App.FuzzyLogic_BreakIntoSets(fDistance, (self.fNearDistance, self.fMidDistance, self.fFarDistance))
				
			# Set these values in our fuzzy set.
			self.SetFuzzySetValues(fNearSet, fMidSet, fFarSet, fAwaySet, fTowardSet)
			
			# Get our reaction set values.
			fGoSlow = self.pFuzzy.GetResultBySet(FS_STOP_AND_TURN_TOWARD)
			fGoMed  = self.pFuzzy.GetResultBySet(FS_MED_AND_TURN_TOWARD)
			fGoFast = self.pFuzzy.GetResultBySet(FS_FAST_AND_TURN_TOWARD)
			
			# We always want to turn toward our destination:
			self.TurnToward(pShip, pObject)
			
			# Determine our speed forward from our fuzzy results
			self.GoForward(pShip, fGoSlow, fGoMed, fGoFast)
			#debug("Got follow values from t("+str(fTowardSet)+") a("+str(fAwaySet)+") of s("+str(fGoSlow)+") m("+str(fGoMed)+") f("+str(fGoFast)+")")
			
		else:
			# We no longer have a destination object.  Stop this AI.
#			debug("Scripted FollowObject AI done (no object)")
			return App.ArtificialIntelligence.US_DONE

		return App.ArtificialIntelligence.US_ACTIVE

	def SetFuzzySetValues(self, fNearSet, fMidSet, fFarSet, fAwaySet, fTowardSet):
		self.pFuzzy.SetPercentageInSet(FS_NEAR_WAYPOINT_FACING,		fNearSet * fTowardSet)
		self.pFuzzy.SetPercentageInSet(FS_NEAR_WAYPOINT_LEAVING,	fNearSet * fAwaySet)
		self.pFuzzy.SetPercentageInSet(FS_MID_WAYPOINT_FACING,		fMidSet * fTowardSet)
		self.pFuzzy.SetPercentageInSet(FS_MID_WAYPOINT_LEAVING,		fMidSet * fAwaySet)
		self.pFuzzy.SetPercentageInSet(FS_FAR_WAYPOINT_FACING,		fFarSet * fTowardSet)
		self.pFuzzy.SetPercentageInSet(FS_FAR_WAYPOINT_LEAVING,		fFarSet * fAwaySet)

	def TurnToward(self, pShip, pObject):
		"Turn toward the given object"
		vPositionDiff = pObject.GetWorldLocation()
		vPositionDiff.Subtract(pShip.GetWorldLocation())
		vPositionDiff.Unitize()
		
		pShip.TurnTowardDirection(vPositionDiff)

	def GoForward(self, pShip, fGoSlow, fGoMed, fGoFast):
		"Set our forward velocity"
		fVel = self.fGoSlowSpeed * fGoSlow  +  self.fGoMedSpeed * fGoMed  +  self.fGoFastSpeed * fGoFast

		pShip.SetImpulse(fVel, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)



























	
