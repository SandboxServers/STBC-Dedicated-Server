#
# ConditionDestroyed
#
# A condition that's false until the specified object is destroyed.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

class ConditionDestroyed:
	def __init__(self, pCodeCondition, sObjectName):
		# Setup members..
		self.pCodeCondition = pCodeCondition
		self.sObject = sObjectName

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Our initial state is false.
		self.pCodeCondition.SetStatus(0)

		# Setup our event handler..
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		self.SetupEventHandlers()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def SetupEventHandlers(self):
		# If our object exists, all we need to do is listen for
		# its deletion event.  If it doesn't exist yet, though,
		# we need to listen for an ET_ENTERED_SET event.
		pObject = App.ObjectClass_GetObject(App.SetClass_GetNull(), self.sObject)
		if (pObject == None):
			# Object doesn't exist yet.  We need to listen for
			# when it enters the set.
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet")
		else:
			# Object exists.  Just listen for an
			# ET_OBJECT_DESTROYED event on this object.
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_OBJECT_DESTROYED, self.pEventHandler, "Destroyed", pObject)

	def EnteredSet(self, pEvent):
		# Check if the destination matches the object we're watching.
		pObject = App.ObjectClass_Cast(pEvent.GetDestination())
		if (pObject != None):
			if pObject.GetName() == self.sObject:
				# Matched the object.
				# We can remove our EnteredSet handler now.
				App.g_kEventManager.RemoveBroadcastHandler(App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet")
				# And we need to add the handler for the
				# destroyed event.
				App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_OBJECT_DESTROYED, self.pEventHandler, "Destroyed", pObject)

		self.pEventHandler.CallNextHandler(pEvent)

	def Destroyed(self, pEvent):
		# The object has been destroyed.
		self.pCodeCondition.SetStatus(1)

		self.pEventHandler.CallNextHandler(pEvent)








