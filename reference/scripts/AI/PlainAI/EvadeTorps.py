#
# EvadeTorps
#
# Maneuver out of the way of any torpedoes in the world.  This
# will even evade torpedoes that are waay off in the middle of
# nowhere that have no chance of hitting us, so this should probably
# only be used in combination with a conditional AI to check
# if there are nearby torps.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class EvadeTorps(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams()
		self.SetRequiredParams()
		self.SetExternalFunctions()

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		self.lUpdatedTorpIDs = []
		self.dTorpInfo = {}

		self.iUpdateNum = 0



	# Number of random vectors to generate, when choosing a direction.
	iNumRandomVectors = 6
	iNumTorpInfoUpdates = 4
	fFastTimeThreshold = 2.0
	fStopTimeThreshold = 6.0
	fDangerDot = 0.9

	# What self.iUpdateNum means.
	UPDATE_TORP_INFO	= 0
	UPDATE_HEADING		= 1
	NUM_UPDATE_NUMS		= 2

	# Torps are dangerous if they'll hit in this amount of time.
	# This needs to be a very generous estimate.  VERY generous.
	fDangerTimeThreshold = 3600.0

	def GetNextUpdateTime(self):
		# We want to be updated every 0.15 seconds
		return 0.15

	def Update(self):
		"Do our stuff"
		pShip = self.pCodeAI.GetShip()
		if not pShip:
			return App.ArtificialIntelligence.US_DONE

		if self.iUpdateNum == self.UPDATE_TORP_INFO:
			eRet = self.UpdateTorpInfo(pShip)
		elif self.iUpdateNum == self.UPDATE_HEADING:
			eRet = self.UpdateHeading(pShip)

		self.iUpdateNum = (self.iUpdateNum + 1) % self.NUM_UPDATE_NUMS

		return eRet

	def UpdateTorpInfo(self, pShip):
		pSet = pShip.GetContainingSet()
		if not pSet:
			return App.ArtificialIntelligence.US_DONE

		# First, we need to build a list of directions to each of
		# the objects...
		# Get a list of all the torps that are incoming...
		lIncomingTorpIDs = App.AIScriptAssist_GetIncomingTorpIDsInSet(pShip, pSet, self.fDangerTimeThreshold, App.NULL_ID, 0)
		if not lIncomingTorpIDs:
			# No incoming torps.  We're done.
			return App.ArtificialIntelligence.US_ACTIVE

		# Remove info on torps that are no longer in this list...
		for idTorp in self.dTorpInfo.keys():
			if idTorp not in lIncomingTorpIDs:
				del self.dTorpInfo[idTorp]

		# Make a list of the torps whose info needs to be updated.
		lNeedsUpdate = []
		for idTorp in lIncomingTorpIDs:
			if idTorp not in self.lUpdatedTorpIDs:
				lNeedsUpdate.append(idTorp)

		if not lNeedsUpdate:
			# Nobody needs an update.  Time to wrap around and
			# start updating from the beginning again.
			self.lUpdatedTorpIDs = []
			lNeedsUpdate = lIncomingTorpIDs

		# Update at most a certain number per update.
		if len(lNeedsUpdate) > self.iNumTorpInfoUpdates:
			lNeedsUpdate = lNeedsUpdate[:self.iNumTorpInfoUpdates]

		for idTorp in lNeedsUpdate:
			# Get the torp.
			pTorp = App.Torpedo_GetObjectByID(pSet, idTorp)
			if pTorp:
				# Get info about where this torp is relative to us.
				vDifference, fDistance, vDirection, fAngle = pShip.GetRelativePositionInfo( pTorp.GetWorldLocation() )
				vVelocity = pTorp.GetVelocityTG()
				vVelocity.Subtract( pShip.GetVelocityTG() )
				fIncomingSpeed = -vVelocity.Dot( vDirection )
				if fIncomingSpeed > 0:
					# It's coming toward us.  Add its info.
					vVelocity.Unitize()
					self.dTorpInfo[idTorp] = (vDirection, vVelocity, fDistance / fIncomingSpeed)

		# Done updating torp info
		return App.ArtificialIntelligence.US_ACTIVE

	def UpdateHeading(self, pShip):
		if not self.dTorpInfo:
			# No torp info is available, but we know we need to
			# move.  Don't do anything for now,
			# but remain active.  Hopefully the situation will
			# resolve itself by the next update.
			return App.ArtificialIntelligence.US_ACTIVE

		# Pick a good direction.
		lDirectionInfo = self.dTorpInfo.values()
		vBestDirection = self.PickRandomVector(pShip, lDirectionInfo)

		pShip.TurnTowardDirection(vBestDirection)

		# Our current speed needs to be based on our facing,
		# relative to all of the objects we're fleeing from.
		# If we're not facing directly toward any nearby ones,
		# go fast.  Otherwise, go slow.
		fSpeed = 1.0
		vForward = pShip.GetWorldForwardTG()
		for vDirection, vVelocity, fTime in lDirectionInfo:
			if vDirection.Dot( vForward ) > self.fDangerDot:
				fSpeed = 0.2
				break

		# Set our speed.
		pShip.SetImpulse(fSpeed, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

		# Done doing stuff.  We're still an Active AI.
		return App.ArtificialIntelligence.US_ACTIVE

	def PickRandomVector(self, pShip, lDirectionInfo):
		App.TGProfilingInfo_SetTimingData("EvadeTorps, numtorps", len(lDirectionInfo))
		kProfiling = App.TGProfilingInfo("EvadeTorps, PickRandomVector")
		# Ok, got the list of object directions.  Pick some random
		# directions, rate them, and choose the best one..
		# First, as a special case, if there's only 1 direction
		# we're fleeing from, just go the opposite way:
		if len(lDirectionInfo) == 1:
			vBestDirection = App.TGPoint3()
			vBestDirection.Set( lDirectionInfo[0][0] )
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
				for vDirection, vVelocity, fTime in lDirectionInfo:
					# Find the dot product, and scale it so that
					# values near 0 are good.
					fScaledDot = 1.0 - abs(vVelocity.Dot( vRandom ))
					# 1 is good, so we'll add.
					fScore = fScore + fScaledDot

					# Values toward the direction are bad...
					fScaledDot = -0.25 * vDirection.Dot(vRandom)
					fScore = fScore + fScaledDot

					# The longer it'll take to hit us, the less dangerous
					# this direction is.
					fScore = fScore - (fTime / 20.0)

				# Add a bit of a negative rating for the dot product
				# to our forward vector.
				# This isn't quite as important as the other ratings...
				fScaledDot = (pShip.GetWorldForwardTG().Dot( vRandom ) + 1.0) * 0.5
				fScore = fScore - (fScaledDot * 0.1)

				# Does this vector have the highest score so far?
				if fScore > fBestScore:
					# Yep.  Save this vector.
					fBestScore = fScore
					vBestDirection = vRandom

		return vBestDirection
























	
