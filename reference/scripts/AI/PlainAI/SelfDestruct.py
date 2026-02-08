#
# SelfDestruct
#
# Self destruct the ship.  Boom.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class SelfDestruct(BaseAI.BaseAI):
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



	def GetNextUpdateTime(self):
		# Update time doesn't really matter, since, as soon
		# as we're hit, we start self-destructing.
		return 1.0

	def Update(self):
		"Do our stuff"
		pObject = self.pCodeAI.GetObject()
		if (pObject == None):
			# Something's wrong.  Our object is gone.  :(
			return App.ArtificialIntelligence.US_DONE

		# If we're a ship, apply a bunch of damage to our
		# hull.  This will blow us up..
		bDead = 0
		pShip = App.ShipClass_Cast(pObject)
		if pShip:
			# We're a ship.  Get our hull.
			pHull = pShip.GetHull()
			if pHull:
				# Do 100% damage to it.
				pShip.DestroySystem(pHull)
				bDead = 1

		# If the above didn't work, just delete us from the
		# world.
		if not bDead:
			pObject.SetDeleteMe(1)

		#debug("Object " + pObject.GetName() + " self destructed.  Boom.")

		# We're busy self-destructing.  Always active
		# (until we die).
		return App.ArtificialIntelligence.US_ACTIVE







