#
# Ram
#
# Fly toward the target, and ram it.  And ram it again.  And again.
# And again and again and again, until one of us is dead.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class Ram(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams( self.SetMaximumSpeed )
		self.SetRequiredParams(
			( "sTargetName", "SetTargetObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetTargetObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# The name of our target.
	def SetTargetObjectName(self, sName): #AISetup
		self.sTargetName = sName

	def SetMaximumSpeed(self, fSpeed = 1.0e20): #AISetup
		self.fMaximumSpeed = fSpeed




	fTowardAngle	= 15.0 * App.PI / 180.0
	fNearAngle	= 30.0 * App.PI / 180.0
	fFarAngle	= 45.0 * App.PI / 180.0

	fTowardSpeed	= 1.0
	fNearSpeed	= 0.9
	fFarSpeed	= 0.7

	def GetStatusInfo(self):
		return "Target(%s), MaxSpeed(%f)" % (
			self.sTargetName, self.fMaximumSpeed)

	def GetNextUpdateTime(self):
		# We want to be updated every 0.4 seconds (+/- 0.2)
		fRandomFraction = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
		return 0.4 + (fRandomFraction * 0.2)

	def Update(self):
		"Do our stuff"
		eRet = App.ArtificialIntelligence.US_DONE

		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# Get the set we're in, if any.
		pSet = pShip.GetContainingSet()
		if (pSet == None):
#			debug("Ram update done: no set")
			return eRet

		# Get our target object.
		pObject = App.ObjectClass_GetObject(pSet, self.sTargetName)
		if (pObject != None):
			eRet = App.ArtificialIntelligence.US_ACTIVE

			# Determine the anticipated position of the target,
			# if we fly at them at maximum acceleration right now.
			vDifference = pObject.GetWorldLocation()
			vDifference.Subtract(pShip.GetWorldLocation())
			fDistance = vDifference.Length()

			fMaxSpeed = pShip.GetImpulseEngineSubsystem().GetMaxSpeed()
			if fMaxSpeed > 0:
				# Not particularly accurate (but not horribly
				# bad):
				fTime = fDistance / fMaxSpeed

				# Predict the target's location in that
				# amount of time.
				pPhysicsObject = App.PhysicsObjectClass_Cast( pObject )
				if (pPhysicsObject == None):
					# It's not a physics object.  Predicted
					# position is just its current position.
					vDestination = pObject.GetWorldLocation()
				else:
					vDestination = pPhysicsObject.GetPredictedPosition( pPhysicsObject.GetWorldLocation(), pPhysicsObject.GetVelocityTG(), pPhysicsObject.GetAccelerationTG(), fTime )

				# If the destination is much too far from the original
				# position, go with something closer.
				vPredictDiff = App.TGPoint3()
				vPredictDiff.Set(vDestination)
				vPredictDiff.Subtract(pObject.GetWorldLocation())
				fPredictDist = vPredictDiff.Unitize()
				if fPredictDist > 100.0:
					# Too far.  Shorten the prediction.
					vPredictDiff.Scale(125.0)
					vDestination = vPredictDiff
					vDestination.Add( pObject.GetWorldLocation() )

				# Turn toward the destination..
				pShip.TurnTowardLocation( vDestination )

				vDifference, fDistance, vDirection, fAngle = pShip.GetRelativePositionInfo( vDestination )

				# And fly fast, if we're reasonably accurate.
				fTowardSet, fNearSet, fFarSet = App.FuzzyLogic_BreakIntoSets(fAngle, (self.fTowardAngle, self.fNearAngle, self.fFarAngle))

				fSpeed = fTowardSet * self.fTowardSpeed  +  fNearSet * self.fNearSpeed  +  fFarSet * self.fFarSpeed
				# Change speed to an absolute speed (not an
				# impulse fraction), and make sure it's no
				# higher than the max specified speed.
				fSpeed = fSpeed * fMaxSpeed
				if fSpeed > self.fMaximumSpeed:
					fSpeed = self.fMaximumSpeed
				#debug("Setting speed to %f/%f(/%f)" % (fSpeed, fMaxSpeed, self.fMaximumSpeed))
				pShip.SetSpeed(fSpeed, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

		return eRet







