#
# MoveToObjectSide
#
# Move our ship to a specific side of another object.  ...Or any
# direction relative to the object, not necessarily a side.
# Once we're on that side, face the object.  If it's moving away,
# try to keep at the same distance to it.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

# Fuzzy sets we're using:
FS_ANGLE_GOOD		= 1
FS_ANGLE_FAR		= 2

FS_FACE_AND_FOLLOW	= 10
FS_MOVE_TO_DIRECTION	= 11

class MoveToObjectSide(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class init first.
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(
			self.SetMaxDistance,
			self.SetCenterOffset,
			self.SetDoneOnLineup)
		self.SetRequiredParams(
			( "vObjectSide", "SetObjectSide" ),
			( "sObject", "SetObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# Set the vector pointing to the side (in model space) that
	# we want to move to, based on our target object..
	def SetObjectSide(self, vSide): #AISetup
		self.vObjectSide = App.TGPoint3()
		self.vObjectSide.Set(vSide)
	
	# Set the object that we're trying to move around.
	def SetObjectName(self, sObject): #AISetup
		self.sObject = sObject

	# Set the maximum distance we're willing to move around the
	# object at.  If we're farther than this distance, we'll move
	# toward the object to cut down the distance we have to travel.
	def SetMaxDistance(self, fDist = 300.0): #AISetup
		self.fMaxDist = fDist

	# If we want the Object Side direction to have its origin
	# offset by some amount (in model space), set that here:
	def SetCenterOffset(self, vModelSpaceOffset = None): #AISetup
		if vModelSpaceOffset:
			self.vCenterOffset = App.TGPoint3()
			self.vCenterOffset.Set(vModelSpaceOffset)
		else:
			self.vCenterOffset = None

	# Whether or not our status changes to Done when we
	# reach the side we're going for.  By default, we
	# remain Active.
	def SetDoneOnLineup(self, bDone = 0): #AISetup
		self.bDoneOnLineup = bDone




	# Setup the fuzzy logic system.
	pFuzzy = App.FuzzyLogic()
	pFuzzy.SetMaxRules(2)
	
	pFuzzy.AddRule(FS_ANGLE_GOOD,	FS_FACE_AND_FOLLOW)
	pFuzzy.AddRule(FS_ANGLE_FAR,	FS_MOVE_TO_DIRECTION)


	# Thresholds at which our angle is good, or starts to become
	# good. 20/25
	fGoodAngleThreshold = (0.5) * (App.PI / 180.0)
	fNearAngleThreshold = (7.5) * (App.PI / 180.0)

	fMoveSpeedMin = 0.4
	fMoveSpeedMax = 1.0
	fMoveAngleFast = (30.0) * (App.PI / 180.0)
	fMoveAngleSlow = (90.0) * (App.PI / 180.0)

	def GetStatusInfo(self):
		sCenterOffset = "None"
		if self.vCenterOffset:
			sCenterOffset = "%.2f,%.2f,%.2f" % (self.vCenterOffset.GetX(), self.vCenterOffset.GetY(), self.vCenterOffset.GetZ())

		return "Target(%s), Side<%.2f,%.2f,%.2f>, MaxDist(%f), CenterOffset<%s>" % (
			self.sObject,
			self.vObjectSide.GetX(), self.vObjectSide.GetY(), self.vObjectSide.GetZ(),
			self.fMaxDist,
			sCenterOffset)

	def GetNextUpdateTime(self):
		return 0.4

	def Update(self):
		"Do our stuff"
		eRet = App.ArtificialIntelligence.US_DONE
		
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# Get the object we're moving around...
		pSet = pShip.GetContainingSet()
		pObject = App.ObjectClass_GetObject(pSet, self.sObject)
		if (pObject != None):
			# The object exists.
			# Get the ObjectSide vector in worldspace.
			vWorldDir = App.TGPoint3()
			vWorldDir.Set(self.vObjectSide)
			vWorldDir.MultMatrixLeft( pObject.GetWorldRotation() )
			vWorldDir.Scale(-1.0)

			# Find the center of the other object.  This
			# may be offset...
			vObjectCenter = App.TGPoint3()
			vObjectCenter.SetXYZ(0, 0, 0)
			if self.vCenterOffset:
				vObjectCenter.Add(self.vCenterOffset)
				vObjectCenter.MultMatrixLeft(pObject.GetWorldRotation())
			vObjectCenter.Add(pObject.GetWorldLocation())
			
			#debug(__name__ + ": Object center is <%f, %f, %f>" % (vObjectCenter.GetX(), vObjectCenter.GetY(), vObjectCenter.GetZ()))

			# Determine the angle between our current
			# relative location and the direction we're
			# moving toward.
			vDiff, fDistance, vDirection, fUnused = pShip.GetRelativePositionInfo( vObjectCenter )

			# Calculate the angle between the direction vector
			# and the direction to the origin of that vector.			
			import math
			fAngle = vDirection.Dot(vWorldDir)
			if fAngle > 1.0:
				fAngle = 1.0
			elif fAngle < -1.0:
				fAngle = -1.0
			fAngle = math.acos(fAngle)
			
			# Determine membership in our fuzzy sets, based
			# on our angle.
			fAngleGood = 0.0
			fAngleFar = 0.0
			if fAngle < self.fGoodAngleThreshold:
				fAngleGood = 1.0
			elif fAngle < self.fNearAngleThreshold:
				fAngleFar = (fAngle - self.fGoodAngleThreshold) / (self.fNearAngleThreshold / self.fGoodAngleThreshold)
				fAngleGood = 1.0 - fAngleFar
			else:
				fAngleFar = 1.0
			
			# Plug in the fuzzy set values..
			self.pFuzzy.SetPercentageInSet(FS_ANGLE_GOOD,	fAngleGood)
			self.pFuzzy.SetPercentageInSet(FS_ANGLE_FAR,	fAngleFar)
			
			# Get and act on the fuzzy results.
			eRet = self.ActOnFuzzyResults(pShip, fDistance, fAngle, vWorldDir, vDirection)

		return eRet

	def ActOnFuzzyResults(self, pShip, fDistance, fSideAngle, vWorldDir, vDirection):
		if fDistance > self.fMaxDist:
			# We're too far away.  Just move toward our target,
			# full speed.
			pShip.TurnTowardDirection(vDirection)
			pShip.SetImpulse(1.0, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

			return App.ArtificialIntelligence.US_ACTIVE
			
		# Get the fuzzy resuts...
		fFaceAndFollow	= self.pFuzzy.GetResultBySet(FS_FACE_AND_FOLLOW)
		fMoveTo		= self.pFuzzy.GetResultBySet(FS_MOVE_TO_DIRECTION)

		# If we're moving to the direction, find a good axis,
		# based on the object we're circling, around which to
		# circle the ship, to arrive at that direction.
		vAxis = vWorldDir.Cross(vDirection)
		vAxis.Unitize()
		if vAxis.SqrLength() < 0.5:
			# It's zero.  Just pick a vector.  As long
			# as it's perpendicular to either vDirection or
			# vWorldDir, it'll be perpendicular to both.
			vAxis = vDirection.Cross(App.TGPoint3_GetModelForward())
			vAxis.Unitize()
			if vAxis.SqrLength() < 0.5:
				vAxis = vDirection.Cross(App.TGPoint3_GetModelUp())
				vAxis.Unitize()
		
		# We want to face perpendicular to vAxis and vDirection.
		vFacing = vAxis.Cross(vDirection)
		
		# Find how far we are from this facing, and let that
		# determine our speed.
		import math
		fAngle = vFacing.Dot(pShip.GetWorldForwardTG())
		if fAngle > 1.0:
			fAngle = 1.0
		elif fAngle < -1.0:
			fAngle = -1.0
		fAngle = math.acos(fAngle)

		fSpeed = self.fMoveSpeedMin
		if fAngle < self.fMoveAngleFast:
			fSpeed = self.fMoveSpeedMax
		elif fAngle < self.fMoveAngleSlow:
			fSpeed = (self.fMoveSpeedMax - self.fMoveSpeedMin) * (fAngle - self.fMoveAngleFast) / (self.fMoveAngleSlow - self.fMoveAngleFast) + self.fMoveSpeedMin

		# If we want to be facing our target, instead of moving
		# around, we'll want our facing to be vDirection, and our
		# speed to be 0.
		vFaceTarget = App.TGPoint3()
		vFaceTarget.Set(vDirection)
		vFaceTarget.Scale(fFaceAndFollow)
		vFacing.Scale(fMoveTo)
		vFacing.Add(vFaceTarget)
		vFacing.Unitize()
		
		fSpeed = fSpeed * fMoveTo

		# Speed also depends on how close we are to our
		# destination angle, based on our distance from the
		# target ship.
		fArcLen = fSideAngle * fDistance

		fMaxSpeed = pShip.GetImpulseEngineSubsystem().GetMaxSpeed()
		fMaxAccel = pShip.GetImpulseEngineSubsystem().GetMaxAccel()
		fStopDist = 0
		if fMaxAccel > 0:
			fStopDist = fMaxSpeed * fMaxSpeed / (fMaxAccel * 2.0)

		# The ship needs to be able to stop within the
		# calculated arc length.  If we're within the distance
		# we need to start stopping.
		if fArcLen < fStopDist:
			# We need to stop.  Make sure our velocity
			# is low enough that we can stop in time.
			fMaxVel = math.sqrt(2 * fMaxAccel * fStopDist)
			if fSpeed > fMaxVel:
				fSpeed = fMaxVel

		#debug("Angle %f, Arclen %f, MaxStop %f, Speed %f" % (fAngle, fArcLen, fStopDist, fSpeed))

		# Turn toward our desired facing...
		pShip.TurnTowardDirection(vFacing)

		# Set our speed...
		pShip.SetImpulse(fSpeed, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

		# If we're lined up and we're supposed to return Done
		# once lined up, return Done.
		if fFaceAndFollow >= 0.5  and  self.bDoneOnLineup:
			return App.ArtificialIntelligence.US_DONE

		return App.ArtificialIntelligence.US_ACTIVE






































