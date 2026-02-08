#
# EvilShuttleDocking
#
# Do something similar to what a tractor beam would do.  Grab
# the shuttle that's controlled by this AI and move it in to dock
# with another object.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class EvilShuttleDocking(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams( self.SetSpeed )
		self.SetRequiredParams(
			( "sTarget", "SetObjectToDockWith" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetObjectToDockWith" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# The name of our target.
	def SetObjectToDockWith(self, sName): #AISetup
		self.sTarget = sName

	# Speed to float toward the docking bay.
	def SetSpeed(self, fSpeed = 1.2): #AISetup
		if fSpeed <= 0.0:
			fSpeed = 1.2
		self.fSpeed = fSpeed



	def GetStatusInfo(self):
		return "Target(%s), Speed(%f)" % (self.sTarget, self.fSpeed)

	def GetNextUpdateTime(self):
		# We want to be updated every 0.1 seconds
		return 0.1

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
#			kDebugObj.Print(__name__ + ": Update done: no set")
			return App.ArtificialIntelligence.US_DONE

		# Get our target object.
		pObject = App.ObjectClass_GetObject(pSet, self.sTarget)
		if pObject:
			eRet = App.ArtificialIntelligence.US_ACTIVE

			# Determine the anticipated position of the target,
			# if we fly at them at our given speed right now.
			vDifference = pObject.GetWorldLocation()
			vDifference.Subtract(pShip.GetWorldLocation())
			fDistance = vDifference.Length()

			# Not particularly accurate (but not horribly
			# bad):
			fTime = fDistance / self.fSpeed

			# If we'll hit the hardpoint before our next 2 updates,
			# remove ourselves from the world.
			if fTime < (2.0 * self.GetNextUpdateTime()):
				self.Dock(pShip, pObject)
				return App.ArtificialIntelligence.US_DONE

			# Predict the target's location in that
			# amount of time.
			pPhysicsObject = App.PhysicsObjectClass_Cast( pObject )
			if (pPhysicsObject == None):
				# It's not a physics object.  Predicted
				# position is just its current position.
				vDestination = pObject.GetWorldLocation()
			else:
				vDestination = pPhysicsObject.GetPredictedPosition( pPhysicsObject.GetWorldLocation(), pPhysicsObject.GetVelocityTG(), pPhysicsObject.GetAccelerationTG(), fTime )

			# Turn toward the destination..
			pShip.TurnTowardLocation( vDestination )

			vDifference, fDistance, vDirection, fAngle = pShip.GetRelativePositionInfo( vDestination )

			# And slide toward the destination, ignoring our facing.
			# This is why this AI is "evil."
			vZero = App.TGPoint3()
			vZero.SetXYZ(0, 0, 0)
			vDirection.Scale( self.fSpeed )
			pShip.SetVelocity( vDirection )
			pShip.SetAcceleration(vZero)

		return eRet

	def Dock(self, pShip, pObject):
		# Change our velocity to match pObject.  This won't keep
		# the ship docked with the object, but it'll look right
		# long enough for external things to do what they need to.
		vZero = App.TGPoint3()
		vZero.SetXYZ(0, 0, 0)
		vVelocity = App.TGPoint3()
		vVelocity.Set(vZero)
		pPhysicsObject = App.PhysicsObjectClass_Cast(pObject)
		if pPhysicsObject:
			vVelocity = pPhysicsObject.GetVelocityTG()

		pShip.SetVelocity(vVelocity)
		pShip.SetAcceleration(vZero)

		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(pObject) # The object we docked into.
		pEvent.SetObjPtr(pShip) # The ship that docked.
		pEvent.SetEventType(App.ET_TRACTOR_TARGET_DOCKED)
		App.g_kEventManager.AddEvent(pEvent)





