#
# StationaryAttack
#
# Sit where we are and adjust our facing so we can fire at
# our target.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class StationaryAttack(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams()
		self.SetRequiredParams(
			( "sTargetName", "SetTargetObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetTargetObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# The name of our target.
	sTargetName = None
	def SetTargetObjectName(self, sName): #AISetup
		self.sTargetName = sName




	fMaxPredictionDistance = 100.0

	def GetStatusInfo(self):
		return "Target(%s)" % self.sTargetName

	def GetNextUpdateTime(self):
		# We want to be updated every 0.5 seconds (+/- 0.2)
		fRandomFraction = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
		return 0.5 + (fRandomFraction * 0.2)

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
#			debug("StationaryAttack update done: no set")
			return eRet

		# Get our target object.
		pObject = App.ObjectClass_GetObject(pSet, self.sTargetName)
		if (pObject != None):
			# Set our speed to 0.
			pShip.SetSpeed(0, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

			# Determine the anticipated position of the target,
			# if we fired a torpedo at it right now.  This is just
			# a rough estimate.
			vDifference = pObject.GetWorldLocation()
			vDifference.Subtract(pShip.GetWorldLocation())
			fDistance = vDifference.Length()
			
			fTorpedoSpeed = pShip.GetTorpedoSystem().GetCurrentAmmoType().GetLaunchSpeed()
			fTimeToTarget = fDistance / fTorpedoSpeed
			
			pPhysicsObject = App.PhysicsObjectClass_Cast( pObject )
			if (pPhysicsObject == None):
				# It's not a physics object.  Predicted
				# position is just its current position.
				vDestination = pObject.GetWorldLocation()
			else:
				vDestination = pPhysicsObject.GetPredictedPosition( pPhysicsObject.GetWorldLocation(), pPhysicsObject.GetVelocityTG(), pPhysicsObject.GetAccelerationTG(), fTimeToTarget )

				# If the destination is too far from
				# the target's current location, don't
				# anticipate that far ahead..
				vDestDiff = App.TGPoint3()
				vDestDiff.Set(vDestination)
				vDestDiff.Subtract(pObject.GetWorldLocation())
				fDestDiff = vDestDiff.Unitize()
				if fDestDiff > self.fMaxPredictionDistance:
					# It's too far.  Put it at the
					# max distance we'll allow.
					vDestDiff.Scale(self.fMaxPredictionDistance)
					vDestDiff.Add(pObject.GetWorldLocation())
					# And change the Destination vector...
					vDestination.Set(vDestDiff)

			# Turn to face our target's predicted position.
			pShip.TurnTowardLocation( vDestination )
			
			eRet = App.ArtificialIntelligence.US_ACTIVE
#		else:
#			debug("StationaryAttack update done: no object")

		return eRet































	
