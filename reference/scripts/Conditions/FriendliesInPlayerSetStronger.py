#
# FriendliesInPlayerSetStronger
#
# A condition that's true when the Friendly objects in the
# player's set are significantly stronger than the Enemy objects.
# Just what "significantly stronger" means can be adjusted
# with variables that are passed in.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

class FriendliesInPlayerSetStronger:
	# Arguments to the contstructor:
	# pCodeCondition	- the ConditionScript this will
	#			  be attached to
	# fThresholdMultiple	- Multiple of the Enemy group's strength
	#			  that the Friendly group must be above,
	#			  in order for the condition to be true.
	# fShieldImportance	- How important shields are to the strength
	#			  calculation.
	# fHullImportance	- How important hull strength is to the
	#			  overall strength calculation.
	# fWeaponImportance	- How important weapons are to the overall
	#			  strength calculation.
	def __init__(self, pCodeCondition, fThresholdMultiple, fShieldImportance = 1.0, fHullImportance = 1.0, fWeaponImportance = 1.0):
		# Store variables...
		self.pCodeCondition = pCodeCondition
		self.fThresholdMultiple = fThresholdMultiple
		self.fShieldImportance = fShieldImportance
		self.fHullImportance = fHullImportance
		self.fWeaponImportance = fWeaponImportance

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup a process to update us..
		self.pTimerProcess = None
		self.SetupTimer()

		# Set our initial state...
		self.EvaluateState()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pTimerProcess"] = (self.pTimerProcess is not None)
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)

		if self.pTimerProcess:
			self.pTimerProcess = None
			self.SetupTimer()
		else:
			self.pTimerProcess = None

	def SetupTimer(self):
		if self.pTimerProcess is not None:
			# We already have a timer.
			return

		self.pTimerProcess = App.PythonMethodProcess()
		self.pTimerProcess.SetInstance(self)
		self.pTimerProcess.SetFunction("EvaluateState")
		self.pTimerProcess.SetDelay( 15.0 )
		self.pTimerProcess.SetPriority( App.TimeSliceProcess.LOW )

	def EvaluateState(self, dEndTime = 0.0):
		# Get the Game/Episode/Mission objects.
		pGame = App.Game_GetCurrentGame()
		if (pGame == None):
			return

		pEpisode = pGame.GetCurrentEpisode()
		if (pEpisode == None):
			return

		pMission = pEpisode.GetCurrentMission()
		if (pMission == None):
			return

		# Find the player's set.
		pSet = pGame.GetPlayerSet()
		if (pSet == None):
			return

		# Got the set.  Get the friendly and enemy objects
		# that are inside that set.
		pFriendlyGroup = pMission.GetFriendlyGroup()
		pEnemyGroup = pMission.GetEnemyGroup()

		lpFriendlies = pFriendlyGroup.GetActiveObjectTupleInSet(pSet)
		lpEnemies = pEnemyGroup.GetActiveObjectTupleInSet(pSet)

		fFriendlyStrength = self.CalculateStrength(lpFriendlies)
		fEnemyStrength = self.CalculateStrength(lpEnemies)

		bCondition = 0
		if fFriendlyStrength > fEnemyStrength * self.fThresholdMultiple:
			# We should be true.
			bCondition = 1

		#kDebugObj.Print("Friendly %f, Enemy %f, Condition %d" % (fFriendlyStrength, fEnemyStrength, bCondition))

		if self.pCodeCondition.GetStatus() != bCondition:
			self.pCodeCondition.SetStatus(bCondition)

	def CalculateStrength(self, lpObjects):
		# Total shield and hull values affect side strength..
		fShieldStrength = 0.0
		fHullStrength = 0.0
		fWeaponStrength = 0.0
		for pObject in lpObjects:
			pShip = App.ShipClass_Cast(pObject)
			if (pShip != None):
				# Add shield strength..
				pShields = pShip.GetShields()
				if pShields:
					for eSide in ( App.ShieldClass.FRONT_SHIELDS,
							App.ShieldClass.REAR_SHIELDS,
							App.ShieldClass.TOP_SHIELDS,
							App.ShieldClass.BOTTOM_SHIELDS,
							App.ShieldClass.LEFT_SHIELDS,
							App.ShieldClass.RIGHT_SHIELDS ):
						# Add the strength from this shield
						# to the total...
						fShieldStrength = fShieldStrength + pShields.GetCurShields(eSide)

				# Add hull strength..
				pHull = pShip.GetHull()
				if pHull:
					fHullStrength = fHullStrength + pHull.GetCondition()

				# ***FIXME: Calculate weapon strength.

		fTotalStrength = 0.0
		for fImportance, fStat in (
			(self.fShieldImportance, fShieldStrength),
			(self.fHullImportance, fHullStrength),
			(self.fWeaponImportance, fWeaponStrength)):
			fTotalStrength = fTotalStrength + fImportance * fStat

		return fTotalStrength
