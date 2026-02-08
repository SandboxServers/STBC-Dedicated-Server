#
# PhaserSweep
#
# Turn and rotate around to bring our phasers to bear with our target.
# If there's no good way to do that, just face the target.  This can
# be given a speed, so the ship is either moving or stationary as
# it does this.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class PhaserSweep(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams(
			self.SetSweepPhasersDuringRun,
			self.SetSpeedFraction,
			self.SetPrimaryDirection)
		self.SetRequiredParams(
			( "sTargetName", "SetTargetObjectName" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetTargetObjectName" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# We need to save some information about the firing arcs
		# on our ship...  ...specifically the phaser banks.
		# A good way to do this seems to be just saving off the
		# relevant phaser banks, so we can grab all the information
		# we need, later on.
		# As long as the ship exists, the phaser system and its
		# banks should exist.
		self.lpPhaserBanks = []
		pShip = pCodeAI.GetShip()
		if (pShip != None):
			# Cycle through the phaser systems:
			kIter = pShip.StartGetSubsystemMatch( App.CT_PHASER_SYSTEM )
			pSystem = pShip.GetNextSubsystemMatch(kIter)
			while (pSystem != None):
				# Got a phaser system.  Grab its individual phaser banks.
				for iChild in range(pSystem.GetNumChildSubsystems()):
					pBank = App.PhaserBank_Cast( pSystem.GetChildSubsystem(iChild) )
					if (pBank != None):
						# Got the phaser bank..  Save it.
						self.lpPhaserBanks.append( pBank )
						
				pSystem = pShip.GetNextSubsystemMatch(kIter)

			pShip.EndGetSubsystemMatch(kIter)

	# The name of our target.
	def SetTargetObjectName(self, sName): #AISetup
		self.sTargetName = sName

	#
	# SetSweepPhasersDuringRun
	#
	# If this is set > 0, the ship will turn up to this angle
	# to try to sweep through nearby phaser arcs as it flies
	# along its torpedo run. This will lengthen the time the
	# run takes, and may send the ship flying all around the
	# target ship as it turns through its arcs.
	#
	# Arguments:
	#	fSweepAngle	- The maximum angle to turn to to
	#			  bring the target into a phaser arc.
	#
	def SetSweepPhasersDuringRun(self, fSweepAngle = 80.0): #AISetup
		import math
		self.fSweepPhaserDot = math.cos(fSweepAngle * App.PI / 180.0)

	#
	# SetSpeedFraction
	#
	# Set the fraction of our ship's full speed that we'll
	# try to move at, as we're doing the phaser sweeps.
	#
	# Arguments:
	#	fSpeedFraction	- Fraction of the ship's full
	#			  speed that we'll try to move at.
	#
	def SetSpeedFraction(self, fSpeedFraction = 1.0): #AISetup
		self.fSpeedFraction = fSpeedFraction

	#
	# SetPrimaryDirection
	#
	# If this is set, this is the direction around which the
	# phaser sweep angle is centered (if it's not set, the phaser
	# sweep angle is centered around the "current" direction).
	#
	# Arguments:
	#	vDirection	- Modelspace direction around which
	#			  the sweep angle is centered.
	#
	def SetPrimaryDirection(self, vDirection = None): #AISetup
		if vDirection:
			self.vPrimaryDirection = App.TGPoint3()
			self.vPrimaryDirection.Set(vDirection)
		else:
			self.vPrimaryDirection = None




	def GetStatusInfo(self):
		sDir = "None"
		if self.vPrimaryDirection:
			sDir = "%.2f,%.2f,%.2f" % (self.vPrimaryDirection.GetX(), self.vPrimaryDirection.GetY(), self.vPrimaryDirection.GetZ())

		return "Target(%s), SweepDot(%f), SpeedFraction(%f), PrimaryDir<%s>" % (
			self.sTargetName, self.fSweepPhaserDot, self.fSpeedFraction,
			sDir)

	def GetNextUpdateTime(self):
		# We want to be updated every 0.3 +/- 0.1 seconds
		fRandomness = (App.g_kSystemWrapper.GetRandomNumber(2001) - 1000) / 1000.0
		return 0.3 + (0.1 * fRandomness)

	def Update(self):
		"Do our stuff"
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		pSet = pShip.GetContainingSet()
		pObject = App.ObjectClass_GetObject(pSet, self.sTargetName)

		eRet = App.ArtificialIntelligence.US_DONE

		if (pObject != None):
			# Adjust our heading.
			self.AdjustHeading(pShip, pObject)

			# Set our speed.
			pShip.SetImpulse(self.fSpeedFraction, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

			# Done doing stuff.  We're Active.
			eRet = App.ArtificialIntelligence.US_ACTIVE

		return eRet

	def AdjustHeading(self, pShip, pObject):
		# Need relative position information...
		vDifference, fDistance, vDirectionToTarget, fAngle = pShip.GetRelativePositionInfo( pObject.GetWorldLocation() )
		vPhaserCenterDirection = App.TGPoint3()
		vPhaserCenterDirection.Set(vDirectionToTarget)

		# If we have a Primary Direction set, use that
		# to override our Phaser Center direction.
		if self.vPrimaryDirection:
			vPhaserCenterDirection.Set(self.vPrimaryDirection)
			vPhaserCenterDirection.MultMatrixLeft( pShip.GetWorldRotation() )

		# Look for the nearest phaser arc with the most
		# power left.  If we're near that arc, turn
		# so it can fire.
		fMaxCharge = 0.0
		pMaxPhaser = None
		#debug("Testing phaser dots for %d phasers (%f or above)" % (len(self.lpPhaserBanks), self.fSweepPhaserDot))
		for pBank in self.lpPhaserBanks:
			# Does this phaser bank have enough charge to fire?
			if not pBank.CanFire():
				# Not enough charge.
				continue

			fBankCharge = pBank.GetChargeLevel()

			# Is this phaser bank close enough?
			fPhaserDot = pBank.CalculateRoughDirection().Dot(vPhaserCenterDirection)
			
			#debug("Phaser dot is %f" % fPhaserDot)
			if fPhaserDot > self.fSweepPhaserDot:
				# Sure, it's close enough.
				# Does it have the most charge, so far, of all the
				# close phasers?
				if fBankCharge > fMaxCharge:
					fMaxCharge = fBankCharge
					pMaxPhaser = pBank

		# Check if we found a good phaser to move to..
		if pMaxPhaser:
			# Yep.  Turn to align that phaser's direction with
			# the target.
			pShip.TurnDirectionsToDirections(
				pMaxPhaser.CalculateRoughDirection(),
				vDirectionToTarget)
		else:
			# No good phaser.  Just turn our primary direction
			# (or our forward vector, if no primary direction is set)
			# toward the target.
			if self.vPrimaryDirection:
				#debug("Turning primary direction toward target (%s, %s)" % (pShip.GetName(), pObject.GetName()))
				pShip.TurnDirectionsToDirections(
					vPhaserCenterDirection,
					vDirectionToTarget)
			else:
				pShip.TurnTowardLocation(pObject.GetWorldLocation())





























	
