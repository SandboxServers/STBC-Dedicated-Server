#
# FollowWaypoints
#
# Follow a series of waypoints.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

# Fuzzy sets we use:
FS_NEAR_FACING		= 0
FS_NEAR_TOWARD		= 1
FS_NEAR_SIDE		= 2
FS_NEAR_AWAY		= 3
FS_MID_FACING		= 4
FS_MID_TOWARD		= 5
FS_MID_SIDE		= 6
FS_MID_AWAY		= 7
FS_FAR_FACING		= 8
FS_FAR_TOWARD		= 9
FS_FAR_SIDE		= 10
FS_FAR_AWAY		= 11

FS_STOP			= 20
FS_SLOW			= 21
FS_MED			= 22
FS_FAST			= 23
FS_MATCH		= 24

class FollowWaypoints(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class init first.
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams()
		self.SetRequiredParams(
			( "pcTargetWaypoint", "SetTargetWaypointName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetTargetWaypointName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	def SetTargetWaypointName(self, pcWaypoint): #AISetup
		self.pcTargetWaypoint = pcWaypoint
		self.sOriginalWaypoint = pcWaypoint




	# How close we need to be to the waypoint, as a factor of
	# the distance from the waypoint to its pre position, to
	# head toward the waypoint, rather than toward the pre position
	fToWaypointDistanceFactor = 0.15
	# The distance, as a factor of the distance from the waypoint to
	# its pre position, beyond which we only fly toward the
	# Pre position, not the waypoint.  This should be > 1.0
	fToPrePositionDistanceFactor = 2.0

	# Angles for facing...
	fFacingAngle = 2.5 * App.HALF_PI / 180.0
	fTowardAngle = 10.0 * App.HALF_PI / 180.0
	fSideAngle = 70.0 * App.HALF_PI / 180.0
	fAwayAngle = 130.0 * App.HALF_PI / 180.0

	# The factor we multiply a waypoint's speed by to get the
	# distance between the Pre position and the waypoint.
	fSpeedToStepFactor = 7.0
	
	# How close we can be to our waypoint to be "close enough" to go to the next one.
	fCloseEnough = 8.0
	fNearDistance = 22.5
	fMidDistance = 80.0
	fFarDistance = 150.0

	# Speeds
	fStopSpeed = 0
	fSlowSpeed = 0.25
	fMedSpeed  = 0.6
	fFastSpeed = 1.0

	# Update-related variables.
	fFastUpdateDistance = 30.0	
	fUpdateTime = 0.35
	fMinUpdateTime = 0.05
	fMaxUpdateTime = 0.35
	
	pFuzzy = App.FuzzyLogic()
	pFuzzy.SetMaxRules(12)

	pFuzzy.AddRule(FS_NEAR_FACING,		FS_MATCH)
	pFuzzy.AddRule(FS_NEAR_TOWARD,		FS_SLOW)
	pFuzzy.AddRule(FS_NEAR_SIDE,		FS_STOP)
	pFuzzy.AddRule(FS_NEAR_AWAY,		FS_STOP)
	pFuzzy.AddRule(FS_MID_FACING,		FS_MED)
	pFuzzy.AddRule(FS_MID_TOWARD,		FS_MED)
	pFuzzy.AddRule(FS_MID_SIDE,		FS_STOP)
	pFuzzy.AddRule(FS_MID_AWAY,		FS_STOP)
	pFuzzy.AddRule(FS_FAR_FACING,		FS_FAST)
	pFuzzy.AddRule(FS_FAR_TOWARD,		FS_FAST)
	pFuzzy.AddRule(FS_FAR_SIDE,		FS_SLOW)
	pFuzzy.AddRule(FS_FAR_AWAY,		FS_STOP)

	def GetStatusInfo(self):
		return "Current(%s), Original(%s)" % (self.pcTargetWaypoint, self.sOriginalWaypoint)

	def Reset(self):
		#debug("Reset at " + str(App.g_kUtopiaModule.GetGameTime()))

		# Reset any state info
		self.pcTargetWaypoint = self.sOriginalWaypoint
		self.fUpdateTime = 0.25

	def GetNextUpdateTime(self):
		return self.fUpdateTime

	def Update(self):
		"Do our stuff"
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		pSet = pShip.GetContainingSet()
		pObject = App.PhysicsObjectClass_GetObject(pSet, self.pcTargetWaypoint)

		if (pObject == None):
			# We couldn't find the object in this set.  If it's a placement object,
			# search for it in the special list of placement objects.
			pObject = App.PlacementObject_GetObject(pSet, self.pcTargetWaypoint)

		if (pObject != None):
			# Determine how far we are from our destination object.
			vDifference = pObject.GetWorldLocation()
			vDifference.Subtract(pShip.GetWorldLocation())

			fDistance = vDifference.Length()

			if fDistance < self.fFastUpdateDistance:
				fUpdateTime = self.fMinUpdateTime
			else:
				fUpdateTime = self.fMaxUpdateTime

			# If we're close enough to our target, stop trying to go to it.
			if fDistance < self.fCloseEnough:
				# If we have a next waypoint, set that as our new target.
				pWaypoint = App.Waypoint_Cast(pObject)
				if (pWaypoint != None):
					# Send the event letting the world
					# know that we've reached our waypoint.
					self.ReachedWaypoint(pWaypoint, pShip)

					pNextWaypoint = pWaypoint.GetNext()
					if (pNextWaypoint != None):
						self.pcTargetWaypoint = pNextWaypoint.GetName()
						return self.Update()
					else:
						# No next waypoint.  We're done.
						#debug("Scripted FollowWaypoints AI done (reached last waypoint)")
						#debug("Finished at %f (Accel %f, MaxSpd %f)" % (App.g_kUtopiaModule.GetGameTime(), pShip.GetImpulseEngineSubsystem().GetMaxAccel(), pShip.GetImpulseEngineSubsystem().GetMaxSpeed()))
						#debug("Speeds %f, %f, %f" % (self.fSlowSpeed, self.fMedSpeed, self.fFastSpeed))
						return App.ArtificialIntelligence.US_DONE
				else:
					# No next waypoint.  We're done.
					#debug("Scripted FollowWaypoints AI done (reached non-path target)")
					#debug("Finished at %f (Accel %f, MaxSpd %f)" % (App.g_kUtopiaModule.GetGameTime(), pShip.GetImpulseEngineSubsystem().GetMaxAccel(), pShip.GetImpulseEngineSubsystem().GetMaxSpeed()))
					#debug("Speeds %f, %f, %f" % (self.fSlowSpeed, self.fMedSpeed, self.fFastSpeed))
					return App.ArtificialIntelligence.US_DONE

			# Find the location of our Pre-Waypoint position.  This is a point
			# behind the waypoint by some factor based on the speed we want to
			# match at the waypoint.
			vPrePoint = pObject.GetWorldLocation()
			vStepBack = pObject.GetWorldForwardTG()
			fStepDistance = 0
			fMatchSpeed = pShip.GetImpulseEngineSubsystem().GetMaxSpeed()
			
			pWaypoint = App.Waypoint_Cast(pObject)
			if (pWaypoint != None):
				fMatchSpeed = pWaypoint.GetSpeed()
				if fMatchSpeed == 0:
					# We'll need at least a little speed to get to the waypoint.
					fMatchSpeed = fDistance * 0.125
				fStepDistance = fMatchSpeed * self.fSpeedToStepFactor
			
			vStepBack.Scale(fStepDistance)
			vPrePoint.Subtract(vStepBack)
			
			# Determine which fuzzy set the distance is in...
			fWaypointMinDist = self.fToWaypointDistanceFactor * fStepDistance
			fWaypointMaxDist = self.fToPrePositionDistanceFactor * fStepDistance
			fFlyToWaySet, fFlyToPreSet = App.FuzzyLogic_BreakIntoSets(fDistance, (fWaypointMinDist, fWaypointMaxDist))
			
			# And between the distance sets:
			fNearSet, fMidSet, fFarSet = App.FuzzyLogic_BreakIntoSets(fDistance, (self.fNearDistance, self.fMidDistance, self.fFarDistance))

			# Our current destination position is a combination of the Pre position and
			# the Waypoint's position, based on our % in set...
			vDestination = pObject.GetWorldLocation()
			vDestination.Scale(fFlyToWaySet)
			vPrePoint.Scale(fFlyToPreSet)
			vDestination.Add(vPrePoint)

			#pDebugWay = App.PlacementObject_GetObject(pSet, "FolWayDebug")
			#if (pDebugWay == None):
			#	pDebugWay = App.PlacementObject_Create("FolWayDebug", pSet.GetName(), None)
			#	pSet.AddObjectToSet(pDebugWay, "FolWayDebug")
			#pDebugWay.SetTranslate(vDestination)
			#pDebugWay.SetMatrixRotation(pObject.GetWorldRotation())

			# Determine if we're facing toward or away from our destination
			vUnused1, fUnused2, vUnused3, fAngle = pShip.GetRelativePositionInfo( vDestination )

			# Split the info into fuzzy sets...
			fFacingSet, fTowardSet, fSideSet, fAwaySet = App.FuzzyLogic_BreakIntoSets(fAngle, (self.fFacingAngle, self.fTowardAngle, self.fSideAngle, self.fAwayAngle))

			# Set our fuzzy rules.
			self.SetFuzzySetValues(fFacingSet, fTowardSet, fSideSet, fAwaySet, fNearSet, fMidSet, fFarSet)

			# Set our speed forward
			fSpeed = self.GetSpeedFromFuzzyResults(fMatchSpeed, pShip.GetImpulseEngineSubsystem().GetMaxSpeed())
			pShip.SetSpeed(fSpeed, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

			# We always want to turn toward our destination:
			self.TurnToward(pShip, vDestination, pObject.GetWorldUpTG())
			
		else:
			# We no longer have a destination object.  Stop this AI.
#			debug("Scripted FollowWaypoints AI done (no \"" + self.pcTargetWaypoint + "\"object)")
			return App.ArtificialIntelligence.US_DONE

		return App.ArtificialIntelligence.US_ACTIVE

	def SetFuzzySetValues(self, fFacingSet, fTowardSet, fSideSet, fAwaySet, fNearSet, fMidSet, fFarSet):
		self.pFuzzy.SetPercentageInSet(FS_NEAR_FACING,	fNearSet * fFacingSet)
		self.pFuzzy.SetPercentageInSet(FS_NEAR_TOWARD,	fNearSet * fTowardSet)
		self.pFuzzy.SetPercentageInSet(FS_NEAR_SIDE,	fNearSet * fSideSet)
		self.pFuzzy.SetPercentageInSet(FS_NEAR_AWAY,	fNearSet * fAwaySet)
		self.pFuzzy.SetPercentageInSet(FS_MID_FACING,	fMidSet * fFacingSet)
		self.pFuzzy.SetPercentageInSet(FS_MID_TOWARD,	fMidSet * fTowardSet)
		self.pFuzzy.SetPercentageInSet(FS_MID_SIDE,	fMidSet * fSideSet)
		self.pFuzzy.SetPercentageInSet(FS_MID_AWAY,	fMidSet * fAwaySet)
		self.pFuzzy.SetPercentageInSet(FS_FAR_FACING,	fFarSet * fFacingSet)
		self.pFuzzy.SetPercentageInSet(FS_FAR_TOWARD,	fFarSet * fTowardSet)
		self.pFuzzy.SetPercentageInSet(FS_FAR_SIDE,	fFarSet * fSideSet)
		self.pFuzzy.SetPercentageInSet(FS_FAR_AWAY,	fFarSet * fAwaySet)
		
	def GetSpeedFromFuzzyResults(self, fMatchSpeed, fMaxSpeed):
		fStop = self.pFuzzy.GetResultBySet(FS_STOP)
		fSlow = self.pFuzzy.GetResultBySet(FS_SLOW)
		fMed = self.pFuzzy.GetResultBySet(FS_MED)
		fMatch = self.pFuzzy.GetResultBySet(FS_MATCH)
		fFast = self.pFuzzy.GetResultBySet(FS_FAST)

		fSpeed = fMaxSpeed * (self.fStopSpeed * fStop  +  self.fSlowSpeed * fSlow  +  self.fMedSpeed * fMed  +  self.fFastSpeed * fFast)  +  fMatchSpeed * fMatch
		return fSpeed

	def TurnToward(self, pShip, vDestination, vDestinationUp):
		"Turn toward the given location"
		vPositionDiff = App.TGPoint3()
		vPositionDiff.Set(vDestination)
		vPositionDiff.Subtract(pShip.GetWorldLocation())
		vPositionDiff.Unitize()
		
		vRight = vPositionDiff.Cross(vDestinationUp)
		vUp = vRight.Cross(vPositionDiff)
		vUp.Unitize()
		
		pShip.TurnTowardOrientation(vPositionDiff, vUp)

	def ReachedWaypoint(self, pWaypoint, pShip):
		"Trigger a Reached Waypoint message"
		pEvent = App.WaypointEvent_Create()
		pEvent.SetDestination(pShip)
		pEvent.SetEventType(App.ET_AI_REACHED_WAYPOINT)
		pEvent.SetPlacement(pWaypoint)
		App.g_kEventManager.AddEvent(pEvent)
		

























	
