#
# Defensive
#
# Keep our strongest shields towards our target, and try to
# stay out of firing arcs.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class Defensive(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class init first.
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams()
		self.SetRequiredParams(
			( "sObject", "SetEnemyName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetEnemyName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	# Set the object that we're trying to defend ourselves against.
	def SetEnemyName(self, sObject): #AISetup
		self.sObject = sObject





	# Angle thresholds for determining our speed.
	fTowardAngle	= 10.0 * (App.PI / 180.0)
	fMidTowardAngle	= 60.0 * (App.PI / 180.0)
	fMidAwayAngle	= 120.0 * (App.PI / 180.0)
	fAwayAngle		= 170.0 * (App.PI / 180.0)

	# Distance thresholds for determining our speed.
	fTooCloseDist = 10
	fCloseDist    = 50
	fMidDist      = 80

	# Speed settings...
	fStopped = 0.0
	fKindaFast = 0.8
	fFast = 1.0

	def GetStatusInfo(self):
		return "Target(%s)" % self.sObject

	def GetNextUpdateTime(self):
		fRandom = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
		return 1.0 + (0.15 * fRandom)

	def Update(self):
		"Do our stuff"
		eRet = App.ArtificialIntelligence.US_DONE

		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# Get the object we're defending against..
		pSet = pShip.GetContainingSet()
		pObject = App.ObjectClass_GetObject(pSet, self.sObject)
		if (pObject != None):
			# The object exists.
			# Find the direction to it.
			vDiff = pObject.GetWorldLocation()
			vDiff.Subtract(pShip.GetWorldLocation())
			fDistance = vDiff.Unitize()

			# Find the direction of our strongest shield.
			vShieldDir = self.GetStrongestShieldDirection(pShip)

			# Turn so that shield is facing our enemy..
			self.TurnToward(pShip, vShieldDir, vDiff)
			
			# Check our current facing to decide our speed
			# right now.
			self.SetGoodSpeed(pShip, vDiff, fDistance)
			
			eRet = App.ArtificialIntelligence.US_ACTIVE

		return eRet

	def GetStrongestShieldDirection(self, pShip):
		# Get our shields...
		pShields = pShip.GetShields()
		fHighestShieldStrength = -1.0
		vHighestShieldDir = App.TGPoint3()

		for eShield, vDir in ( ( App.ShieldClass.FRONT_SHIELDS,  App.TGPoint3_GetModelForward() ),
                                       ( App.ShieldClass.TOP_SHIELDS,    App.TGPoint3_GetModelUp() ),
                                       ( App.ShieldClass.LEFT_SHIELDS,   App.TGPoint3_GetModelLeft() ),
                                       ( App.ShieldClass.BOTTOM_SHIELDS, App.TGPoint3_GetModelDown() ),
                                       ( App.ShieldClass.RIGHT_SHIELDS,  App.TGPoint3_GetModelRight() ),
		                       ( App.ShieldClass.REAR_SHIELDS,   App.TGPoint3_GetModelBackward() ) ):
			# Check if the strength of this shield is higher than
			# our stored max...
			fShieldStrength = pShields.GetCurShields(eShield)
			if fShieldStrength > fHighestShieldStrength:
				fHighestShieldStrength = fShieldStrength
				vHighestShieldDir.Set( vDir )
		
		# Done..
		return vHighestShieldDir

	def TurnToward(self, pShip, vShieldDir, vDiff):
		"Turn the ship's vShieldDir toward the vDiff vector."
		"vShieldDir is in model space, vDiff is in world space."
		# Change vShieldDir into world space...
		vShieldDir.MultMatrixLeft( pShip.GetWorldRotation() )

		# Turn this shield direction toward vDiff.
		pShip.TurnDirectionsToDirections(vShieldDir, vDiff)

	def SetGoodSpeed(self, pShip, vDiff, fDistance):
		"Choose and set a good speed for our ship, based"
		"our our facing relative to vDiff."
		# Find the angle between vDiff and our world forward vector.
		fAngle = vDiff.Dot( pShip.GetWorldForwardTG() )
		import math
		try:
			fAngle = math.acos(fAngle)
		except ValueError:
			fAngle = 0.0

		# Decide our speed based on that angle.
		# If we're facing toward vDiff, we don't want to move.
		# If we're facing perpendicular, we want to go fast.
		# If we're facing away, go kind of fast.
		fStopped = 0.0
		fKindaFast = 0.0
		fFast = 0.0
		
		if fAngle < self.fTowardAngle:
			fStopped = 1.0
		elif fAngle < self.fMidTowardAngle:
			fFast = (fAngle - self.fTowardAngle) / (self.fMidTowardAngle - self.fTowardAngle)
			fStopped = 1.0 - fFast
		elif fAngle < self.fMidAwayAngle:
			fFast = 1.0
		elif fAngle < self.fAwayAngle:
			fKindaFast = (fAngle - self.fMidAwayAngle) / (self.fAwayAngle - self.fMidAwayAngle)
			fFast = 1.0 - fKindaFast
		else:
			fKindaFast = 1.0

		# Also factor distance in.  If we're really close, don't
		# go as fast.
		fDistanceFactor = 1.0
		if fDistance < self.fTooCloseDist:
			fDistanceFactor = 0.1
		elif fDistance < self.fCloseDist:
			fFactor = (fDistance - self.fTooCloseDist) / (self.fCloseDist - self.fTooCloseDist)
			fDistanceFactor = fFactor * 0.3
		elif fDistance < self.fMidDist:
			fFactor = (fDistance - self.fCloseDist) / (self.fMidDist - self.fCloseDist)
			fDistanceFactor = fFactor * 0.7
		else:
			fDistanceFactor = 1.0

		# Set our speed.
		fSpeed = (fStopped * self.fStopped) + (fKindaFast * self.fKindaFast) + (fFast * self.fFast)
		fSpeed = fSpeed * fDistanceFactor
		pShip.SetImpulse(fSpeed, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)






























