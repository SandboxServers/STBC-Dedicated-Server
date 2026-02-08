#
# GoForward
#
# Tell the ship to keep moving forward.  Just fly off to the middle of nowhere.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class GoForward(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams()
		self.SetRequiredParams( ("fImpulse", "SetImpulse") )
		self.SetExternalFunctions()

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

	def SetImpulse(self, fImpulse): #AISetup
		self.fImpulse = fImpulse


		
	def GetNextUpdateTime(self):
		# We want to be updated every 5 seconds
		return 5.0

	def Update(self):
		"Do our stuff"
		pShip = self.pCodeAI.GetShip()
		if (pShip == None):
			# ***FIXME: For now, this AI only works on ShipClass
			# and below...
			return App.ArtificialIntelligence.US_DONE

		# Set our speed to fImpulse.
		pShip.SetImpulse(self.fImpulse, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
		
		# Set our turning to 0.
		vZero = App.TGPoint3()
		vZero.SetXYZ(0, 0, 0)
		pShip.SetTargetAngularVelocityDirect( vZero )
		
		# This AI never finishes.  Always continue:
		return App.ArtificialIntelligence.US_ACTIVE



























	
