#
# ConditionMissionEvent
#
# A condition that's false until an event type is triggered,
# after which it remains true.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

class ConditionMissionEvent:
	def __init__(self, pCodeCondition, eEventType):
		# Set the time we wait..
		self.eEventType = eEventType
		self.pCodeCondition = pCodeCondition

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Our initial state is false.
		self.pCodeCondition.SetStatus(0)

		# Setup our interrupt handler, triggered when the mission
		# event goes off.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		App.g_kEventManager.AddBroadcastPythonMethodHandler( self.eEventType, self.pEventHandler, "EventTriggered")

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def EventTriggered(self, pEvent):
		self.pCodeCondition.SetStatus(1)














