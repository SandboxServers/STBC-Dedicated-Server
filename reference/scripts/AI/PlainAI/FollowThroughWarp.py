#
# FollowThroughWarp
#
# Follow a given object between sets.  If at any time the other
# object moves to a different set, our object will warp after it.
# When we warp to a new set, this creates a temporary placement
# near the object we're following, so we warp into a good position.
#
# AIEditor flags: NOTINLIST
import App
import Warp

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class FollowThroughWarp(Warp.Warp):
	def __init__(self, pCodeAI):
		# Base class init, first..
		Warp.Warp.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams()
		self.SetRequiredParams(
			( "sObjectName", "SetFollowObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetFollowObjectName" ) )

		# Override the default warp duration.
		self.SetWarpDuration(13.0)

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		self.fWarpInBackDistance = 40.0
		self.fWarpInPerpendicularDistance = 15.0

	def SetFollowObjectName(self, sName): #AISetup
		# Set the name of the object we're following...
		self.sObjectName = sName




	def GetStatusInfo(self):
		return "Target(%s)" % self.sObjectName

	def GetNextUpdateTime(self):
		# We want to be updated every 10.0 seconds (+/- 2.0)
		fRandomFraction = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
		return 10.0 + (fRandomFraction * 2.0)

	def Update(self):
		"Do our stuff"
		# Because of the compound AI we're in, we should only be
		# updated if we're not in the same set as our target, or
		# we just warped into its set.  If we're in the same set
		# and we're done warping, return DONE.  Otherwise,
		# we're ACTIVE.

		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# Are we in the same set as our target?
		bNeedToWarp = 1
		pSet = pShip.GetContainingSet()
		if (pSet != None):
			pOther = App.ObjectClass_GetObject(pSet, self.sObjectName)
			if (pOther != None):
				# We're in the same set.  We don't need to warp.
				bNeedToWarp = 0

		# If we're not in the same set as our target and
		# we're not already warping, we need to warp.
		if bNeedToWarp  and  not self.bWarping:
			# We need to warp, and we're not yet.
			# Setup the parameters for the warp..
			bWarp = self.SetupWarpParameters(pShip)

			if bWarp:
				# We're ready to warp.  Fall through
				# to our parent class, to do the actual
				# warp sequence...
				return Warp.Warp.Update(self)
		elif self.bWarping:
			# We're busy warping.  Fall through to our
			# base class and let it do whaever it needs to..
			eRet = Warp.Warp.Update(self)
			
			if eRet == App.ArtificialIntelligence.US_DONE:
				# We're done warping.  Return DONE
				self.bWarping = 0
				return App.ArtificialIntelligence.US_DONE

		# We're still active, we just can't quite do what we
		# need to yet.
		return App.ArtificialIntelligence.US_ACTIVE

	def SetupWarpParameters(self, pShip):
		# Find the set that our target object is in...
		pObject = App.ObjectClass_GetObject(None, self.sObjectName)
		if not pObject:
			return 0

		pSet = pObject.GetContainingSet()
		if not pSet:
			return 0

		# It's in a valid set.  That set needs to be
		# our destination set.  If it's in the
		# warp set, it should have a warp sequence controlling
		# it.  We can get the ship's destination set from that
		# warp sequence.
		if pSet.GetName() == "warp":
			try:
				pTargetShip = App.ShipClass_Cast(pObject)
				pWarpSystem = pTargetShip.GetWarpEngineSubsystem()
				pWarpSequence = App.WarpSequence_Cast( pWarpSystem.GetWarpSequence() )

				pSet = pWarpSequence.GetDestinationSet()
				if not pSet:
					return 0

				# Save the set name..
				self.SetDestinationSetName( pWarpSequence.GetDestination() )
			except AttributeError:
				# No target ship, or no warp subsystem, no warp sequence, or no set.
				return 0
		else:
			# It's a set we can warp to..  Set it as our
			# destination.
			self.SetDestinationSetName(pSet.GetRegionModule())

		# Get info about where the ship is coming in.  If it still has a warp sequence
		# playing, get the info from the destination placement in the destination set.
		# If it doesn't, get the info from the current location of the ship.
		pTargetShip = App.ShipClass_Cast(pObject)
		pWarpSystem = pTargetShip.GetWarpEngineSubsystem()
		pWarpSequence = App.WarpSequence_Cast( pWarpSystem.GetWarpSequence() )
		NoPlacementException = "No destination placement info"
		try:
			if not pWarpSequence:
				raise NoPlacementException

			# Get info from the warp sequence.
			pSet = pWarpSequence.GetDestinationSet()
			pPlacement = App.PlacementObject_GetObject( pSet, pWarpSequence.GetPlacementName() )
			if not pPlacement:
				raise NoPlacementException

			vPosition = pPlacement.GetWorldLocation()
			vForward = pPlacement.GetWorldForwardTG()
			vUp = pPlacement.GetWorldUpTG()
			vRight = pPlacement.GetWorldRightTG()

		except NoPlacementException:
			# Get info from the current location of the ship.
			vPosition = pObject.GetWorldLocation()
			vForward = pObject.GetWorldForwardTG()
			vUp = pObject.GetWorldUpTG()
			vRight = pObject.GetWorldRightTG()

		# Create a temporary placement in the new
		# set so we have someplace to warp to.
		sName = "WarpIn(%s,%s)" % (pShip.GetName(), self.sObjectName)
		pPlacement = App.PlacementObject_GetObject(pSet, sName)
		if not pPlacement:
			pPlacement = App.PlacementObject_Create(sName, pSet.GetName(), None)

		# Position needs to be back a bit from the
		# object we're following...
		vObjectPosition = App.TGPoint3()
		vObjectPosition.Set( vPosition )

		vOffset = App.TGPoint3()
		vOffset.Set( vForward )
		vOffset.Scale(-self.fWarpInBackDistance - (pObject.GetRadius() + pShip.GetRadius()))
		vPosition.Add(vOffset)

		# And off to the side somewhere..
		import math
		vOldPosition = App.TGPoint3 ()
		vOldPosition.Set (vPosition)
		bValidPosition = 0
		for iCount in range(8):
			vPosition.Set (vOldPosition)
			fAngle = App.g_kSystemWrapper.GetRandomNumber(50000) * App.TWO_PI / 50000.0
			vOffsetRight = App.TGPoint3()
			vOffsetRight.Set( vRight )
			vOffsetUp = App.TGPoint3()
			vOffsetUp.Set( vUp )
			vOffset = App.TGPoint3()
			vOffsetRight.Scale( math.cos(fAngle) )
			vOffsetUp.Scale( math.sin(fAngle) )
			vOffset.Set(vOffsetRight)
			vOffset.Add(vOffsetUp)
			vOffset.Scale(self.fWarpInPerpendicularDistance + (pObject.GetRadius() + pShip.GetRadius()))
			vPosition.Add(vOffset)

			# check if warping to this placement will cause the ship to warp through something.  If so,
			# pick a new path.
			if (self.SafeDirection (vPosition, vForward, pShip.GetRadius ())):
				bValidPosition = 1
				break

			# Not a valid direction.  Rotate the placement slightly..
			vObjectDirection = App.TGPoint3()
			vObjectDirection.Set( vObjectPosition )
			vObjectDirection.Subtract( vPosition )
			vObjectDirection.Unitize()
			vAxis = vForward.UnitCross( vObjectDirection )
			mRotation = App.TGMatrix3()
			fAngle = App.g_kSystemWrapper.GetRandomNumber(50000) * App.PI / 2.0 / 50000.0 # Rotate by up to 90 degrees...
			mRotation.MakeRotation(fAngle, vAxis) 

			vNewForward = App.TGPoint3()
			vNewForward.Set(vForward)
			vNewForward.MultMatrixLeft( mRotation )
			if self.SafeDirection(vPosition, vNewForward, pShip.GetRadius()):
				bValidPosition = 1
				vForward = vNewForward
				vUp.MultMatrixLeft( mRotation )
				break

		if not bValidPosition:
			# No good position found.  For now, just bail.  We'll let the user's ship move
			# around a bit first and maybe there'll be a good position for us to warp into next
			# AI update.
#			debug("Can't find a safe path for \"%s\" to warp in (chasing %s)..." % (pShip.GetName(), self.sObjectName))
			return 0

		pPlacement.SetTranslate(vPosition)
		pPlacement.AlignToVectors(vForward, vUp)
		pPlacement.UpdateNodeOnly()

		# Setup the info in the warp sequence so it
		# knows to warp to this placement...
		self.SetDestinationPlacementName(sName)

		# Reset the update state of the warp AI, so
		# it actually does stuff in case we warp
		# multiple times.
		self.eUpdateReturn = App.ArtificialIntelligence.US_ACTIVE

		# Ok, we're good to go.
		return 1

	def SafeDirection(self, vPosition, vForward, fRadius):
		# Get all the objects along the line that we'll
		# be warping through.
		fRayLength = 4000.0
		vOrigin = App.TGPoint3 ()
		vOrigin.Set (vPosition)
		vEnd = App.TGPoint3 ()
		vEnd.Set (vForward)
		vEnd.Scale(-fRayLength)
		vEnd.Add(vOrigin)

		# Get the set we'll be warping to.
		pSetModule = __import__(self.sToSetName)
		if pSetModule:
			pSet = pSetModule.GetSet()

		if (not pSetModule)  or  (not pSet):
#			debug("No set (%s) in SafeDirection" % (self.sToSetName))
			# Huh?	Return true so we can break out of the loop since
			# we didn't manage to get our set.
			return 1

		import MissionLib
		lsObstacles = MissionLib.GrabWarpObstaclesFromSet(vOrigin, vEnd, pSet, fRadius, 0, App.NULL_ID)
		# If we have no obstacles in the way, we're good.
		if len(lsObstacles) == 0:
			return 1
		else:
			return 0
