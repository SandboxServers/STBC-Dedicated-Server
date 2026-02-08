#
# TorpedoRun
#
# Make a single full-sped torpedo run on our target.  The run will abort
# when we are too close to reasonably fire torpedoes.
# Note: This AI no longer fires directly.  It just flies through the
#   maneuvers required to line-up for a torpedo pass.  A Preprocessing AI
#   should be added to contain this AI, to control the weapon systems.
#
import App
import BaseAI
import math

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class TorpedoRun(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(
			self.SetPerpendicularMovementAdjustment,
			self.SetTorpDirection)
		self.SetRequiredParams(
			( "sTarget", "SetTargetObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetTargetObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# The name of our target.
	def SetTargetObjectName(self, sName): #AISetup
		self.sTarget = sName

	#
	# SetPerpendicularMovementAdjustment
	#
	# If the target object is moving mostly perpendicular
	# to us, we may want to adjust our speed (since we may
	# not be able to line up a shot if we're moving closer,
	# and they're moving off to the side).  This function
	# allows the user to specify how much this should affect
	# the speed...
	#
	# Arguments:
	#	fSpeedFactor	- Our speed is multiplied by this
	#			  factor when our target is moving
	#			  mostly perpendicular.  So if, for
	#			  example, this is 0.0, then we will
	#			  stop when the other ship is moving
	#			  perpendicular.  1.0 means no change.
	#
	def SetPerpendicularMovementAdjustment(self, fSpeedFactor = 1.0): #AISetup
		self.fPerpendicularSpeedFactor = fSpeedFactor

	def SetTorpDirection(self, vDirection = App.TGPoint3_GetModelForward()): #AISetup
		self.vTorpDirection = App.TGPoint3()
		self.vTorpDirection.Set(vDirection)


	# Angles that help determine our speed.  Angles, not dots.
	fIdealFacingThreshold	= App.PI / 16.0
	fTowardFacingThreshold	= App.HALF_PI

	fSlowSpeed = 0.2
	fMedSpeed = 0.75
	fFastSpeed  = 1.0

	fMinDistance = 25
	fIdealDistance = 200
	fMaxDistance = 250

	# Minimum speed for us to care about perpendicular velocity
	# of the target.
	fPerpendicularSpeedThreshold = 1.0

	# Angles that determine how perpendicular our target's
	# velocity is.  Between fPerpAway and fPerpAwayPerp, the
	# perpendicular set ramps from 0.0 to 1.0.  And between
	# fPerpTowardPerp and fPerpToward, it ramps back down
	# from 1.0 to 0.0.  (Between fPerpAWayPerp and fPerpTowardPerp
	# it's 1.0).
	fPerpAway		= math.cos(60.0 * App.PI / 180.0)
	fPerpAwayPerp	= math.cos(85.0 * App.PI / 180.0)
	fPerpTowardPerp	= math.cos(95.0 * App.PI / 180.0)
	fPerpToward		= math.cos(120.0 * App.PI / 180.0)

	def GetStatusInfo(self):
		return "Target(%s), PerpSpeedFactor(%f), TorpDir<%.2f,%.2f,%.2f>" % (
			self.sTarget,
			self.fPerpendicularSpeedFactor,
			self.vTorpDirection.GetX(), self.vTorpDirection.GetY(), self.vTorpDirection.GetZ())

	def GetNextUpdateTime(self):
		# We want to be updated every 0.25 seconds
		return 0.25

	def Update(self):
		"Do our stuff"
		pShip = self.pCodeAI.GetShip()
		if not pShip:
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		pSet = pShip.GetContainingSet()
		pObject = App.ObjectClass_GetObject(pSet, self.sTarget)

		eRet = App.ArtificialIntelligence.US_DONE

		if pObject:
			idTiming = App.TGProfilingInfo_StartTiming("TorpedoRun, Setup Calcs")

			# Determine how far we are from our destination object.
			vDifference, fDistance, vDirection, fAngle = pShip.GetRelativePositionInfo( pObject.GetWorldLocation() )

			# Anticipate the location of our target if we fired a
			# torpedo at it right now.  This is just a rough estimate.
			vDestination = pObject.GetWorldLocation()
			pTorpSystem = pShip.GetTorpedoSystem()
			if pTorpSystem:
				pPhysicsTarget = App.PhysicsObjectClass_Cast(pObject)
				if pPhysicsTarget:
					fTorpedoSpeed = pTorpSystem.GetCurrentAmmoType().GetLaunchSpeed()

					# ***CHECKME: Is this significant?
					# Add in our speed relative to the target.
					vRelativeVelocity = pPhysicsTarget.GetVelocityTG()
					vRelativeVelocity.Subtract( pShip.GetVelocityTG() )

					fRelativeSpeed = -vDirection.Dot( vRelativeVelocity )

					# Calculate a rough estimate of the amount of time it'll take for
					# the torpedo to hit the target.
					fTimeToTarget = fDistance / (fTorpedoSpeed + fRelativeSpeed)
					if fTimeToTarget > 0:
						vDestination = pPhysicsTarget.GetPredictedPosition( pPhysicsTarget.GetWorldLocation(), pPhysicsTarget.GetVelocityTG(), pPhysicsTarget.GetAccelerationTG(), fTimeToTarget )

						# Fix our position info for the predicted location...
						vDifference, fDistance, vDirection, fAngle = pShip.GetRelativePositionInfo( vDestination )

			# The angle we care about is the angle to our torpedo direction,
			# which may not be forward...
			vTorpDirectionWorld = App.TGPoint3()
			vTorpDirectionWorld.Set( self.vTorpDirection )
			vTorpDirectionWorld.MultMatrixLeft( pShip.GetWorldRotation() )

			# Determine if we're facing toward or away from our target.
			# We have an angle.  Determine our fuzzy sets.
			fIdealSet, fTowardSet, fAwaySet = App.FuzzyLogic_BreakIntoSets(fAngle, (0.0, self.fIdealFacingThreshold, self.fTowardFacingThreshold))

			# Now determine which fuzzy set the distance is in...
			fCloseSet, fTorpedoSet, fFarSet = App.FuzzyLogic_BreakIntoSets(fDistance, (self.fMinDistance, self.fIdealDistance, self.fMaxDistance))

			# Get fuzzy speed values from the fuzzy sets.
			fSlow = (fFarSet * fAwaySet +
					 fTorpedoSet * fTowardSet +
					 fCloseSet * fAwaySet +
					 fCloseSet * fTowardSet)
			fMed = (fTorpedoSet * fAwaySet +
					fCloseSet * fIdealSet)
			fFast = (fFarSet * fTowardSet +
					 fFarSet * fIdealSet +
					 fTorpedoSet * fIdealSet)

			App.TGProfilingInfo_StopTiming(idTiming)

			# And do stuff, based on what our fuzzy logic tells
			# us to do.
			eRet = self.ActOnFuzzyResults(pShip, pObject, vDestination, fSlow, fMed, fFast)

		return eRet

	def ActOnFuzzyResults(self, pShip, pObject, vDestination, fSlow, fMed, fFast):
		kTiming = App.TGProfilingInfo("TorpedoRun::ActOnFuzzyResults")

		# Determine our speed from the fuzzy sets.
		fSpeed = fSlow * self.fSlowSpeed  +  fMed * self.fMedSpeed  +  fFast * self.fFastSpeed

		# Our speed is also affected by whether the object is moving
		# mostly perpendicular to us or not.
		fSpeed = self.AdjustSpeedForPerpendicularMovement(pShip, pObject, fSpeed)

		pShip.SetImpulse(fSpeed, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

		# Adjust our heading..
		self.AdjustHeading(pShip, vDestination)
		
		return App.ArtificialIntelligence.US_ACTIVE

	def AdjustHeading(self, pShip, vDestination):
		vTorpDirectionWorld = App.TGPoint3()
		vTorpDirectionWorld.Set( self.vTorpDirection )
		vTorpDirectionWorld.MultMatrixLeft( pShip.GetWorldRotation() )

		vDirection = App.TGPoint3()
		vDirection.Set( vDestination )
		vDirection.Subtract( pShip.GetWorldLocation() )
		vDirection.Unitize()

		pShip.TurnDirectionsToDirections( vTorpDirectionWorld, vDirection )

	def AdjustSpeedForPerpendicularMovement(self, pShip, pObject, fNormalSpeed):
		# Speed remains unchanged by default.
		fSpeedFactor = 1.0

		# Only physics objects will have velocity...
		pPhysicsObject = App.PhysicsObjectClass_Cast(pObject)
		if pPhysicsObject:
			# Get its velocity...
			vVelocity = pPhysicsObject.GetVelocityTG()

			# Its velocity needs to be over a certain
			# threshold for us to care..
			fSpeed = vVelocity.Unitize()
			if fSpeed > self.fPerpendicularSpeedThreshold:
				# We care.  Check the angle their velocity
				# vector and the vector between the 2 ships.
				vDiff = pObject.GetWorldLocation()
				vDiff.Subtract(pShip.GetWorldLocation())
				vDiff.Unitize()

				fDot = vDiff.Dot( vVelocity )

				# Determine how perpendicular it is,
				# based on fuzzy sets.
				fAway, fAwayPerp, fTowardPerp, fToward = App.FuzzyLogic_BreakIntoSets(fDot, (self.fPerpAway, self.fPerpAwayPerp, self.fPerpTowardPerp, self.fPerpToward))
				fPerpendicular = fAwayPerp + fTowardPerp

				# ...This determines how much our speed is affected.
				fSpeedFactor = fPerpendicular * self.fPerpendicularSpeedFactor  +  (1.0 - fPerpendicular)  # * 1.0

		return fNormalSpeed * fSpeedFactor
