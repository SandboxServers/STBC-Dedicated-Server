#
# ConditionShipDisabled
#
# True when the specified ship is disabled.  A ship is
# disabled if:
#	- Its impulse, warp, and weapon systems are disabled.
#	- It's dead.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

# Event types used only in this file.
ET_CONTAINED_CONDITION_CHANGED			= App.UtopiaModule_GetNextEventType()

#
# ConditionShipDisabled
#
class ConditionShipDisabled:
	lDisableSystems = (
		("pImpulseDisabled",	App.CT_IMPULSE_ENGINE_SUBSYSTEM),
		("pWarpDisabled",		App.CT_WARP_ENGINE_SUBSYSTEM),
		("pWeaponsDisabled",	App.CT_WEAPON_SYSTEM),
		("pCloakDisabled",		App.CT_CLOAKING_SUBSYSTEM)
		)

	def __init__(self, pCodeCondition, sShip):
		# Set our parameters...
		self.pCodeCondition = pCodeCondition
		self.sShip = sShip

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our event handler wrapper.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Our condition handler.
		self.pConditionHandler = App.ConditionEventCreator()
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(ET_CONTAINED_CONDITION_CHANGED)
		pEvent.SetDestination(self.pEventHandler)
		self.pConditionHandler.SetEvent(pEvent)

		# Add conditions for the various subsystems we're watching.
		for sAttr, eSystemType in self.lDisableSystems:
			# Create this condition...
			pCondition = App.ConditionScript_Create(
				"Conditions.ConditionSystemDisabled", "ConditionSystemDisabled",
				self.sShip, eSystemType, 1)

			# Store a reference to it..
			setattr(self, sAttr, pCondition)

			# Add it to the condition handler.
			self.pConditionHandler.AddCondition( pCondition )

		# Set our initial state..
		self.CheckState()

		# Set an event handler listening for when our conditions change.
		self.pEventHandler.AddPythonMethodHandlerForInstance(ET_CONTAINED_CONDITION_CHANGED, "CheckState")

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def CheckState(self, pEvent = None):
		# Check our conditions.  If they're all true, we're true.
		for sAttr, eSystemType in self.lDisableSystems:
			if not getattr(self, sAttr).GetStatus():
				# One of the systems isn't disabled.
				self.pCodeCondition.SetStatus(0)
				return

		# All relevant systems are disabled.
		self.pCodeCondition.SetStatus(1)
