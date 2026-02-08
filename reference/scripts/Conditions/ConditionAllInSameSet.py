#
# ConditionAllInSameSet
#
# A condition that tests if a list of objects are all
# in the same set.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

class ConditionAllInSameSet:
	def __init__(self, pCodeCondition, *lsObjectNames):
		# Set our object names...
		self.pCodeCondition = pCodeCondition

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our interrupt handlers, for checking of the object
		# enters or leaves the set.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)
		
		# Setup our object list and set our initial state.
		pGroup = App.ObjectGroup()
		for sName in lsObjectNames:
			if sName:
				pGroup.AddName(sName)
		self.SetObjects(pGroup)

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def SetObjects(self, pObjectGroup):
		# Set our object group...
		self.pObjectGroup = pObjectGroup

		# We need event handlers for when objects in our object
		# group enter or exit a set.
		self.pObjectGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pObjectGroup)
		self.pObjectGroup.SetEventFlag( App.ObjectGroup.EXITED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_EXITED_SET, self.pEventHandler, "ExitedSet", self.pObjectGroup)

		# SetInitialState will setup the rest.
		self.SetInitialState()

	def SetInitialState(self):
		# We need to get the names of the sets that our objects
		# are in.
		self.dSetNames = {}
		lsObjectNames = self.pObjectGroup.GetNameTuple()
		sFirstObject = lsObjectNames[0]
		bAllSame = 1
		for sObjectName in lsObjectNames:
			# Get the object and save the name of the set it's currently in.
			pObject = App.ObjectClass_GetObject(App.SetClass_GetNull(), sObjectName)
			if (pObject != None):
				self.dSetNames[sObjectName] = pObject.GetContainingSet().GetName()
			else:
				self.dSetNames[sObjectName] = ""
				# The objects aren't in the same set if any of them
				# isn't in a set.
				bAllSame = 0
			
			# Check if all the set names are the same, while we're going through them.
			# If not, set bAllSame to false.
			if self.dSetNames[sObjectName] != self.dSetNames[sFirstObject]:
				bAllSame = 0

		self.pCodeCondition.SetStatus(bAllSame)

	def EnteredSet(self, pObjEvent):
		# If we're true, we don't care about ships entering sets.
		if self.pCodeCondition.GetStatus() != 1:
			# It's one of the ships in our list.  Set its
			# new set name.
			pObj = App.ObjectClass_Cast(pObjEvent.GetObjPtr())
			self.dSetNames[pObj.GetName()] = pObj.GetContainingSet().GetName()

			# And check if this set name is the same as all our
			# other set names.  If so, our condition becomes true.
			lsSets = self.dSetNames.values()
			sFirstSet = lsSets[0]
			for sSet in lsSets[1:]:
				if sSet != sFirstSet:
					# Mismatch.  We're not true.
					return

			# We got this far.  We must be true.
			self.pCodeCondition.SetStatus(1)

	def ExitedSet(self, pObjEvent):
		# Clear the ship's set name.
		pObj = App.ObjectClass_Cast(pObjEvent.GetObjPtr())
		self.dSetNames[pObj.GetName()] = ""

		# If we were true before, since one of the ships we
		# were watching exited our set, we must be false now.
		if self.pCodeCondition.GetStatus() == 1:
			self.pCodeCondition.SetStatus(0)












