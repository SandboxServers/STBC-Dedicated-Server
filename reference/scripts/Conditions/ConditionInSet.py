#
# ConditionInSet
#
# A condition that's true iff a given object is in a given set.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionInSet:
	def __init__(self, pCodeCondition, sObjectName, sSetName, bAllowSetTargetChanges = 0):
		# Set our object and set names...
		self.sObjectName = sObjectName
		self.sSetName = sSetName
		self.pCodeCondition = pCodeCondition
		self.bAllowSetTargetChanges = bAllowSetTargetChanges

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our state.
		self.SetInitialState()

		# Setup our interrupt handlers, for checking of the object
		# enters or leaves the set.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet")
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_EXITED_SET, self.pEventHandler, "ExitedSet")

	def RegisterExternalFunctions(self, pAI):
		if self.bAllowSetTargetChanges:
			pAI.RegisterExternalFunction("SetTarget", { "CodeID" : self.pCodeCondition.GetObjID(), "FunctionName" : "SetTarget" })

	def SetTarget(self, sTarget):
		self.sObjectName = sTarget
		self.SetInitialState()

	def GetStatusInfo(self):
		return "ConditionInSet(%s, %s) is %s" % (self.sObjectName, self.sSetName, ("False", "True")[self.pCodeCondition.GetStatus()])

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def SetInitialState(self):
		# Get our initial value from the state of the world right
		# now.  
		pSet = App.g_kSetManager.GetSet(self.sSetName)
		if not pSet:
			# The set doesn't exist.  We're false.
			self.pCodeCondition.SetStatus(0)
			return

		if pSet.GetObject(self.sObjectName):
			# The object exists in the set.  Our
			# initial state is true.
			self.pCodeCondition.SetStatus(1)
			return

		# Doesn't exist.  Our initial state is false.
		self.pCodeCondition.SetStatus(0)

	def EnteredSet(self, pEvent):
		if self.pCodeCondition.GetStatus() != 1:
			# Check if it's the ship we're looking for, in the
			# set we're watching.
			pObj = App.ObjectClass_Cast(pEvent.GetDestination())
			if (pObj == None):
				return

			if pObj.GetName() != self.sObjectName:
				return
			
			pSet = pObj.GetContainingSet()
			if pSet.GetName() == self.sSetName:
				# It's a match.
				self.pCodeCondition.SetStatus(1)

	def ExitedSet(self, pEvent):
		if self.pCodeCondition.GetStatus() != 0:
			# Check if it's the ship we're looking for, leaving
			# the set we're watching.
			pObj = App.ObjectClass_Cast(pEvent.GetDestination())
			if (pObj == None):
				return

			if pObj.GetName() != self.sObjectName:
				return
			
			if pEvent.GetCString() == self.sSetName:
				# It's a match.
				self.pCodeCondition.SetStatus(0)
