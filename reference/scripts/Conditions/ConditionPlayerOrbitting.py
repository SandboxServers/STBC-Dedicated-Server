#
# ConditionPlayerOrbitting
#
# A condition that's true if the player's ship is in orbit
# around a specified planet.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

class ConditionPlayerOrbitting:
	def __init__(self, pCodeCondition, sPlanetName = None):
		self.pCodeCondition = pCodeCondition
		self.sPlanet = sPlanetName

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		self.iOrbitAI = None

		# Assume our initial state is false.
		self.pCodeCondition.SetStatus(0)

		# Setup our event handler checking for when the
		# player enters orbit.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_AI_ORBITTING, self.pEventHandler, "StartedOrbit")

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def StartedOrbit(self, pEvent):
		# Make sure this is for the player.
		pPlayer = App.Game_GetCurrentPlayer()
		pShip = App.ShipClass_Cast(pEvent.GetSource())
		if (pPlayer and pShip) and  (pPlayer.GetObjID() == pShip.GetObjID()):
			# It's for the player.  Is the player orbitting the planet
			# we care about?
			pPlanet = App.Planet_Cast(pEvent.GetDestination())
			if pPlanet and ((self.sPlanet is None)  or  (pPlanet.GetName() == self.sPlanet)):
				# Yep.
				# We need to listen for when the player's
				# current (orbit) AI is done.
				pAI = pPlayer.GetAI()
				if pAI:
					self.iOrbitAI = pAI.GetID()
					App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_AI_DONE, self.pEventHandler, "OrbitDone", pPlayer)

					# We're true.
					self.pCodeCondition.SetStatus(1)
#					kDebugObj.Print(__name__ + ": Player in orbit around %s" % self.sPlanet)


	def OrbitDone(self, pEvent):
		# Make sure the AI ID is right..
		if self.iOrbitAI == pEvent.GetInt():
			# It is.  The player is no longer in orbit.
			self.pCodeCondition.SetStatus(0)
			self.iOrbitAI = None

#			kDebugObj.Print(__name__ + ": Player no longer in orbit around %s" % self.sPlanet)
		
		
		
		
		
		
		
		
		
		
		
