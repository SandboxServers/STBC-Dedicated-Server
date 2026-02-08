#
# StarbaseAttack AI
#
# An AI specific to starbases.  With this AI, they'll attack all
# available targets, with whatever weapon systems they can.
#
# AIEditor flags: NOTINLIST
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class StarbaseAttack(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams()
		self.SetRequiredParams( ( "pTargetGroup", "SetTargets" ) )
		self.SetExternalFunctions(
			( "SetTarget", "SetTargets" ) )

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	#
	# SetTargets
	#
	# Set the names of all the targets the starbase will
	# fire at.
	#
	# Arguments:
	#  - lsTargets : The names of all the targets to
	#                attack.
	#
	def SetTargets(self, lsTargets): #AISetup
		self.pTargetGroup = App.ObjectGroup_ForceToGroup(lsTargets)




	def GetStatusInfo(self):
		return "Targets(%s)" % (self.pTargetGroup.GetNameTuple(), )

	def GetNextUpdateTime(self):
		# We want to be updated every 3 seconds
		return 3.0

	def GotFocus(self):
		# Start firing if we should be firing.
		self.Update()

	def LostFocus(self):
		pShip = self.pCodeAI.GetShip()
		if pShip:
			self.StopFiring(pShip)

	def Update(self):
		"Do our stuff"
		#
		# ***FIXME: We're polling.  This AI can be done with events.
		#
		
		
		eRet = App.ArtificialIntelligence.US_ACTIVE

		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# Check if we have any targets...
		lTargets = self.GetTargets(pShip)
		if lTargets:
			# We have some targets to choose from.
			# Cycle through our weapon systems and
			# fire them at the best available targets.
			self.FireWeapons(pShip, lTargets)
		else:
#			debug("StarbaseAttack done: no targets left")
			eRet = App.ArtificialIntelligence.US_DONE

		return eRet

	def GetTargets(self, pShip):
		# Get the set we're in..
		pSet = pShip.GetContainingSet()
		if (pSet == None):
			return ()
		
		# Get all our targets that are in this set.
		lTargets = self.pTargetGroup.GetActiveObjectTupleInSet(pSet)

		# Hmm..  Guess that's it.
		return lTargets

	def FireWeapons(self, pShip, lTargets):
		# Cycle through anything in the ship that can
		# be considered a weapon (phasers, torpedoes,
		# pulse weapons, bodies, food rations, etc.)
		pMatch = pShip.StartGetSubsystemMatch(App.CT_WEAPON_SYSTEM)
		pSystem = pShip.GetNextSubsystemMatch(pMatch)
		while (pSystem != None):
			# Ok, we've got a weapon system.  Figure out
			# what its best target is, and shoot at it.
			pWeapSystem = App.WeaponSystem_Cast(pSystem)
			for pTarget in lTargets:
				if not pWeapSystem.IsInTargetList(pTarget):
					pWeapSystem.StartFiring(pTarget)

			# Get the next weapon system...
			pSystem = pShip.GetNextSubsystemMatch(pMatch)

		pShip.EndGetSubsystemMatch(pMatch)

	def StopFiring(self, pShip):
		# Cycle through anything in the ship that can
		# be considered a weapon (phasers, torpedoes,
		# pulse weapons, bodies, food rations, etc.)
		pMatch = pShip.StartGetSubsystemMatch(App.CT_WEAPON_SYSTEM)
		pSystem = pShip.GetNextSubsystemMatch(pMatch)
		while (pSystem != None):
			pWeapSystem = App.WeaponSystem_Cast(pSystem)
			if pWeapSystem:
				# Ok, we've got a weapon system.  Stop it from firing.
				pWeapSystem.StopFiring()

			# Get the next weapon system...
			pSystem = pShip.GetNextSubsystemMatch(pMatch)

		pShip.EndGetSubsystemMatch(pMatch)
































	
