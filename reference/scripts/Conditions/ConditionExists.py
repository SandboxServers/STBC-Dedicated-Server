#
# ConditionExists
#
# A condition that's true as long as the object it's watching exists.  If
# it hasn't been created yet or it's been deleted, it doesn't exist.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionExists:
	def __init__(self, pCodeCondition, sObject):
		self.pCodeCondition = pCodeCondition
		self.sObject = sObject

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our event handler..
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Setup an object group with this one object.
		self.pObjectGroup = App.ObjectGroup()
		self.pObjectGroup.AddName(self.sObject)

		self.InitFromGroup()

	def InitFromGroup(self):
		# Check if our object exists yet.
		lObjects = self.pObjectGroup.GetActiveObjectTuple()
		if lObjects:
			# It exists.  Listen for its deletion event.
			pObject = lObjects[0]
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_DELETE_OBJECT_PUBLIC, self.pEventHandler, "Deleted", pObject)

			self.pCodeCondition.SetStatus(1)
		else:
			# Doesn't exist yet.  Listen for entered set events.
			self.pObjectGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pObjectGroup)
			self.pCodeCondition.SetStatus(0)

	def RegisterExternalFunctions(self, pAI):
		pAI.RegisterExternalFunction("SetTarget", { "CodeID" : self.pCodeCondition.GetObjID(), "FunctionName" : "SetTarget" })

	def SetTarget(self, sTarget):
		# Change our object group.  If we have an object, remove our handler for its deletion event.
		lObjects = self.pObjectGroup.GetActiveObjectTuple()
		if lObjects:
			# Our object exists.  Remove the handler...
			pObject = lObjects[0]
			App.g_kEventManager.RemoveBroadcastHandler( App.ET_DELETE_OBJECT_PUBLIC, self.pEventHandler, "Deleted", pObject)
		else:
			# Doesn't exist.  We should have an entered set handler; remove that.
			App.g_kEventManager.RemoveBroadcastHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pObjectGroup)

		# Change the object group so it just has the new name.
		self.pObjectGroup.RemoveAllNames()
		self.pObjectGroup.AddName(sTarget)

		# Reinitialize ourselves...
		self.InitFromGroup()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def EnteredSet(self, pEvent):
		# Our object has entered a set.  We're true.
		self.pCodeCondition.SetStatus(1)

		# We no longer need this handler...
		App.g_kEventManager.RemoveBroadcastHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pObjectGroup)

		# But we do need a handler for the object's deletion event.
		pObject = App.ObjectClass_Cast( pEvent.GetObjPtr() )
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_DELETE_OBJECT_PUBLIC, self.pEventHandler, "Deleted", pObject)

	def Deleted(self, pEvent):
		# The object has been deleted.  We're false.
		self.pCodeCondition.SetStatus(0)
