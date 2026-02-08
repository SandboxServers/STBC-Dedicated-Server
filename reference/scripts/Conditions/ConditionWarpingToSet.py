#
# ConditionWarpingToSet
#
# A condition that tests to see if an object is warping
# to a specified set.  If so, it's true.  If not, it's false.
# If no set is specified, this is true when the ship is
# warping, false when it's not warping.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionWarpingToSet:
	def __init__(self, pCodeCondition, sObjectName, sLongSetName = None):
		# Save our parameters.
		self.pCodeCondition = pCodeCondition
		self.sObject = sObjectName
		self.sSet = sLongSetName

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our event handlers, for checking when the warp
		# sequence is set for our object.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# We need to listen for ET_SET_WARP_SEQUENCE events.
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_SET_WARP_SEQUENCE, self.pEventHandler, "SequenceSet" )

		# Check if we're true right now..  Might be, of our target is already warping.
		self.CheckState()

	def RegisterExternalFunctions(self, pAI):
		pAI.RegisterExternalFunction("SetTarget", { "CodeID" : self.pCodeCondition.GetObjID(), "FunctionName" : "SetTarget" })

	def SetTarget(self, sTarget):
		# Change the target we're watching.
		self.sObject = sTarget

		# Check if we're true right now..  Might be, of our target is already warping.
		self.CheckState()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def CheckState(self):
		# Get our ship.
		pShip = App.ShipClass_GetObject(None, self.sObject)
		if pShip:
			pWarpSystem = pShip.GetWarpEngineSubsystem()
			if pWarpSystem:
				pSequence = App.WarpSequence_Cast( pWarpSystem.GetWarpSequence() )

				self.SetStateFromSequence( pSequence )

	def SequenceSet(self, pEvent):
		# Get the ship that this event is going to..
		pWarpSystem = App.WarpEngineSubsystem_Cast( pEvent.GetDestination() )
		pShip = pWarpSystem.GetParentShip()

		# Is it the ship we care about?
		if pShip.GetName() == self.sObject:
			# Yep..  Get the warp sequence.
			pSequence = App.WarpSequence_Cast( pWarpSystem.GetWarpSequence() )

			self.SetStateFromSequence(pSequence)

	def SetStateFromSequence(self, pWarpSequence):
		# Set our state based on which region the ship is warping into.
		if pWarpSequence and ((not self.sSet)  or  (pWarpSequence.GetDestination() == self.sSet)):
			self.pCodeCondition.SetStatus(1)
		else:
			self.pCodeCondition.SetStatus(0)
