#
# Flee
#
# Fly away from an object.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class Flee(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class init first.
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(self.SetSpeed)
		self.SetRequiredParams(
			( "pFleeObjectGroup", "SetFleeFromGroup" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetFleeFromGroup" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# Set the name of the object we're fleeing from
	def SetFleeFromGroup(self, *lpObjectGroup): #AISetup
		# Make sure pObjectGroup is a group.
		pObjectGroup = App.ObjectGroup_ForceToGroup( lpObjectGroup )

		self.pFleeObjectGroup = pObjectGroup

	# Set the fraction of our full speed that we'll move at.
	def SetSpeed(self, fSpeedFraction = 1.0): #AISetup
		self.fSpeedFraction = fSpeedFraction




	# Number of random vectors to generate, when choosing a direction.
	iNumRandomVectors = 8

	# Turn time thresholds that determine our speed...
	fFastTimeThreshold = 7.0
	fStopTimeThreshold = 10.0

	def GetStatusInfo(self):
		return "TargetGroup(%s), SpeedFrac(%f)" % (
			self.pFleeObjectGroup.GetNameTuple(),
			self.fSpeedFraction)

	def GetNextUpdateTime(self):
		# We want to be updated every 0.5 seconds
		return 0.5

	def Update(self):
		"Do our stuff"
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		pSet = pShip.GetContainingSet()
		if (pSet == None):
			# We're not in a set.  I guess we're done fleeing.
			return App.ArtificialIntelligence.US_DONE

		lpObjects = self.pFleeObjectGroup.GetActiveObjectTupleInSet(pSet)
		if len(lpObjects) == 0:
			# No objects to flee from.  We're done.
			return App.ArtificialIntelligence.US_DONE

		# Ok, we have objects that we need to flee from.  Pick
		# a few random vectors, and rate those vectors on their
		# angles to each of the objects..  Choose the vector with
		# the best rating...
		
		# First, we need to build a list of directions to each of
		# the objects...
		lvDirections = []
		for pObject in lpObjects:
			vDirection = pObject.GetWorldLocation()
			vDirection.Subtract( pShip.GetWorldLocation() )
			vDirection.Unitize()
			if vDirection.SqrLength() > 0.5:
				# It's not a zero vector..  Add it to our
				# list.
				lvDirections.append( vDirection )
		
		if len(lvDirections) == 0:
			# Couldn't build a list of useful directions..  But
			# we know we need to flee.  Don't do anything for now,
			# but remain active.  Hopefully the situation will
			# resolve itself by the next update.
			return App.ArtificialIntelligence.US_ACTIVE

		# Ok, got the list of object directions.  Pick some random
		# directions, rate them, and choose the best one..
		# First, as a special case, if there's only 1 direction
		# we're fleeing from, just go the opposite way:
		if len(lvDirections) == 1:
			vBestDirection = App.TGPoint3()
			vBestDirection.Set(lvDirections[0])
			vBestDirection.Scale(-1)
		else:
			vBestDirection = None
			fBestScore = -1.0e20
			for iVectorNum in range(self.iNumRandomVectors):
				# Create the random vector...
				vRandom = App.TGPoint3_GetRandomUnitVector()
				fScore = 0
			
				# Rate it based on its dot products to the
				# other vectors..
				for vDirection in lvDirections:
					# Find the dot product, and squish it into
					# the 0 to 1 range (from its -1 to 1 range).
					fScaledDot = (vDirection.Dot( vRandom ) + 1.0) * 0.5
					# 1 is bad, so we'll subtract.
					fScore = fScore - fScaledDot

				# Add a bit of a rating for the dot product
				# to our forward vector.
				fScaledDot = (pShip.GetWorldForwardTG().Dot( vRandom ) + 1.0) * 0.5
				# This isn't quite as important as the other ratings...
				# And 1 is good, so we'll add.
				fScore = fScore + (fScaledDot * fScaledDot)

				# Does this vector have the highest score so far?
				if fScore > fBestScore:
					# Yep.  Save this vector.
					fBestScore = fScore
					vBestDirection = vRandom

		# Okee, we've got our random direction.  Turn toward that
		# direction.
		fTurnTime = pShip.TurnTowardDirection(vBestDirection)

		# Our current speed needs to be based on our facing,
		# relative to all of the objects we're fleeing from.
		# If we're facing away from them, go fast.  Otherwise,
		# we might need to stop or go slow (so we don't hit them).
		# We'll base this judgement on whether or not our facing
		# is (roughly) aligned with vBestDirection.
		# And this can be determined by how low fTurnTime is...
		#debug("Turn time is " + str(fTurnTime))
		fFast, fStop = App.FuzzyLogic_BreakIntoSets(fTurnTime, (self.fFastTimeThreshold, self.fStopTimeThreshold))
		fSpeed = 1.0 * fFast  +  0.0 * fStop

		# Scale fSpeed by the fSpeedFraction factor...
		fSpeed = fSpeed * self.fSpeedFraction
		
		# Set our speed.
		pShip.SetImpulse(fSpeed, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

		# Done doing stuff.  We're still an Active AI.
		return App.ArtificialIntelligence.US_ACTIVE



























	
