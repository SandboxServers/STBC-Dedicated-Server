#
# ConditionCriticalSystemBelow
#
# True if any of the critical systems on the specified ship
# are below the given percentage (0.0 is dead, 1.0 is full health).
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionCriticalSystemBelow:
	def __init__(self, pCodeCondition, sShip, fFraction):
		# Set our parameters...
		self.pCodeCondition = pCodeCondition
		self.sShip = sShip
		self.fFraction = fFraction
		self.lConditions = []

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Event handler...
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Create the ConditionEventCreator we'll use to
		# monitor a series of ConditionSystemBelow conditions.
		self.pConditionEventCreator = App.ConditionEventCreator()
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(App.ET_AI_CONDITION_CHANGED)
		pEvent.SetDestination(self.pEventHandler)
		self.pConditionEventCreator.SetEvent(pEvent)

		# Need a handler to handle that event.
		self.pEventHandler.AddPythonMethodHandlerForInstance(App.ET_AI_CONDITION_CHANGED, "SystemBelowChanged")

		# If the ship exists right now, we can
		# do our setup right now.
		pShip = App.ShipClass_GetObject(None, self.sShip)
		if pShip:
			self.SetupFromShip(pShip)
		else:
			# Ship doesn't exist yet.  We need a handler
			# for ET_ENTERED_SET, so we can grab the ship
			# when it first enters a set.
			self.pGroup = App.ObjectGroup()
			self.pGroup.AddName(self.sShip)
			self.pGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pGroup )

		# Set our initial state.
		self.SystemBelowChanged()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def SetupFromShip(self, pShip):
		# Look through all the subsystems on the ship and
		# watch any systems that are marked as Critical.
		for pSubsystem in pShip.GetSubsystems():
			if pSubsystem.IsCritical():
				# Found a critical subsystem.  Watch when its
				# condition falls below self.fFraction.
				pCondition = App.ConditionScript_Create("Conditions.ConditionSystemBelow", "ConditionSystemBelow", self.sShip, pSubsystem.GetObjType(), self.fFraction)
				self.pConditionEventCreator.AddCondition(pCondition)
				self.lConditions.append(pCondition)

	def SystemBelowChanged(self, pEvent = None):
		# Check our conditions.  If any of them are true,
		# we're true.
		bState = 0
		for pCondition in self.lConditions:
			if pCondition.GetStatus():
				bState = 1
				break

		if self.pCodeCondition.GetStatus() != bState:
				self.pCodeCondition.SetStatus(bState)

	def EnteredSet(self, pEvent):
		# Our object has entered a set.  Get the object, and
		# setup our condition handler from it.
		pShip = App.ShipClass_Cast( pEvent.GetObjPtr() )
		if pShip:
			self.SetupFromShip(pShip)
			self.SystemBelowChanged()

			# Don't need this handler or the objectgroup anymore.
			App.g_kEventManager.RemoveBroadcastHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pGroup)
			del self.pGroup








