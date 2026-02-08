#
# ManeuverLoop
#
# Perform a loop (or fraction of a loop) maneuver, around a specified
# model axis (default is the Left axis, which does an upward loop).
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class ManeuverLoop(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class init first.
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(
			self.SetLoopFraction,
			self.SetTurnAxis,
			self.SetSpeeds)
		self.SetRequiredParams()
		self.SetExternalFunctions()

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# Set the fraction of a circle that we actually want to turn
	# through.
	def SetLoopFraction(self, fFraction = 1.0): #AISetup
		self.fDestinationAngle = App.TWO_PI * fFraction

	# Set the axis around which we'll turn.  Default is the
	# model Left axis, which means we'll turn upward.
	def SetTurnAxis(self, vAxis = App.TGPoint3_GetModelLeft()): #AISetup
		self.vTurnAxis = App.TGPoint3()
		self.vTurnAxis.Set(vAxis)
		# We need to find a perpendicular axis to what's been
		# given.
		self.vPerpendicularAxis = self.vTurnAxis.Cross(App.TGPoint3_GetModelUp())
		if self.vPerpendicularAxis.SqrLength() < 0.1:
			self.vPerpendicularAxis = self.vTurnAxis.Cross(App.TGPoint3_GetModelLeft())
		
		self.vPerpendicularAxis.Unitize()
	
	# Set the speed we'll be moving at during the loop (as
	# a fraction of full speed; 1.0 is full speed).
	def SetSpeeds(self, fStartSpeed = 1.0, fEndSpeed = 1.0): #AISetup
		self.fStartSpeed = fStartSpeed
		self.fEndSpeed = fEndSpeed




	fRadiansSoFar = 0
	fNextUpdate = 0.1
	vLastPerpendicular = None
	fFinishAngleThreshold = 0.015625	# About 1 degree

	def Reset(self):
		# Reset any state info
		self.fRadiansSoFar = 0
		self.fNextUpdate = 0.1
		self.vLastPerpendicular = None

	def GetStatusInfo(self):
		return "Angle(%f/%f), Axis<%.2f,%.2f,%.2f>, Speeds(%.2f,%.2f)" % (
			self.fRadiansSoFar, self.fDestinationAngle,
			self.vTurnAxis.GetX(), self.vTurnAxis.GetY(), self.vTurnAxis.GetZ(),
			self.fStartSpeed, self.fEndSpeed)

	def GetNextUpdateTime(self):
		# Our update time varies...
		return self.fNextUpdate

	def Update(self):
		"The update AI script"
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# First check how far we've turned since our last update:
		mRotation = pShip.GetWorldRotation()

		vPerpendicular = App.TGPoint3()
		vPerpendicular.Set(self.vPerpendicularAxis)
		vPerpendicular.MultMatrixLeft(mRotation)
		if self.vLastPerpendicular != None:
			vDiff = vPerpendicular.Dot(self.vLastPerpendicular)
			if vDiff > 1.0:
				vDiff = 1.0
			elif vDiff < -1.0:
				vDiff = -1.0
			from math import acos
			vDiff = acos(vDiff)
			self.fRadiansSoFar = self.fRadiansSoFar + vDiff
		
		self.vLastPerpendicular = vPerpendicular
		
		# Now see how much further we need to turn, and turn toward
		# that amount.  At most, we'll aim for a turn that's 90 degrees
		# farther each update, to ensure that we're turning in the
		# right direction.
		fTurnLeft = self.fDestinationAngle - self.fRadiansSoFar
		if fTurnLeft < self.fFinishAngleThreshold:
			# We've turned far enough.  We're done.
			return App.ArtificialIntelligence.US_DONE

		# Check if we're trying to turn too far
		if fTurnLeft > App.HALF_PI:
			fTurnLeft = App.HALF_PI
		
		# Setup the turn vector (axis we're turning around * angle
		# we're turning through).
		vTurnVector = App.TGPoint3()
		vTurnVector.Set(self.vTurnAxis)
		vTurnVector.MultMatrixLeft(mRotation)
		vTurnVector.Scale(fTurnLeft)
		
		fTime = pShip.TurnTowardDifference(vTurnVector)
		
		# Update halfway through this turn, so we don't
		# decelerate partway through the turn.
		self.fNextUpdate = fTime / 2.0

		# Set our speed.
		fTurnFraction = self.fRadiansSoFar / self.fDestinationAngle
		fSpeed = (self.fStartSpeed * (1.0 - fTurnFraction)) + (self.fEndSpeed * fTurnFraction)
		pShip.SetImpulse(fSpeed, App.TGPoint3_GetModelForward(), App.ShipClass.DIRECTION_MODEL_SPACE)

		return App.ArtificialIntelligence.US_ACTIVE















