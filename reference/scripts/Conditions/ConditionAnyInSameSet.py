#
# ConditionAllInSameSet
#
# A condition that tests if a list of objects are in the
# same set as another object.  If any of them are in the
# same set, the condition is true.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionAnyInSameSet:
	def __init__(self, pCodeCondition, sObjectName, *lsOtherObjectNames):
		self.pCodeCondition = pCodeCondition
		# Set our primary object's name..
		self.sObjectName = sObjectName

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our interrupt handlers, for checking of the object
		# enters or leaves the set.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)
		
		# Setup our object list and set our initial state.
		self.SetObjects(lsOtherObjectNames)

	def RegisterExternalFunctions(self, pAI):
		pAI.RegisterExternalFunction("SetTarget", { "CodeID" : self.pCodeCondition.GetObjID(), "FunctionName" : "SetTarget" })

	def SetTarget(self, sTarget):
		# Change the contents of self.pObjectGroup so they
		# just contain sTarget.
		#debug("SetTarget from %s to (%s)" % (self.pObjectGroup.GetNameTuple(), sTarget))
		self.SetObjects(sTarget)

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
		# If we had an object group before, scrap our old info.
		if hasattr(self, "pObjectGroup")  and  hasattr(self, "pEverythingGroup"):
			# Remove our old event handlers.
			App.g_kEventManager.RemoveBroadcastHandler(
				App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pEverythingGroup)
			App.g_kEventManager.RemoveBroadcastHandler(
				App.ET_OBJECT_GROUP_OBJECT_EXITED_SET, self.pEventHandler, "ExitedSet", self.pEverythingGroup)

		# Set our object group...
		self.pObjectGroup = App.ObjectGroup_ForceToGroup( pObjectGroup )
		
		# We need another group including our primary object..
		self.pEverythingGroup = App.ObjectGroup()
		for sName in ((self.sObjectName, ) + self.pObjectGroup.GetNameTuple()):
			self.pEverythingGroup.AddName(sName)

		# We need event handlers for when any of our objects
		# enter or exit a set.  We'll base this off of the
		# pEverythingGroup object group.
		self.pEverythingGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pEverythingGroup)
		self.pEverythingGroup.SetEventFlag( App.ObjectGroup.EXITED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_EXITED_SET, self.pEventHandler, "ExitedSet", self.pEverythingGroup)

		# SetInitialState will setup the rest.
		self.SetInitialState()

	def SetInitialState(self):
		# Get our primary object, and the set it's in.
		self.sPrimarySet = ""
		pPrimary = App.ObjectClass_GetObject( None, self.sObjectName )
		if pPrimary:
			pSet = pPrimary.GetContainingSet()
			if pSet:
				self.sPrimarySet = pSet.GetName()

		# Now get the names of the sets that our other objects
		# are in.  If any of them matches the primary set (and
		# the primary set isn't ""), we're true.
		self.dSetNames = {}
		lsObjectNames = self.pObjectGroup.GetNameTuple()
		sFirstObject = lsObjectNames[0]
		bMatch = 0
		for sObjectName in lsObjectNames:
			# Get the object and save the name of the set it's currently in.
			pObject = App.ObjectClass_GetObject(App.SetClass_GetNull(), sObjectName)
			if (pObject != None):
				sSetName = pObject.GetContainingSet().GetName()
				self.dSetNames[sObjectName] = sSetName
				# Check if this set is the same as our primary
				# set.
				if sSetName == self.sPrimarySet:
					# Yep.
					bMatch = 1
			else:
				self.dSetNames[sObjectName] = ""

		self.pCodeCondition.SetStatus(bMatch)

	def EnteredSet(self, pObjEvent):
		# Get the object...
		pObj = App.ObjectClass_Cast(pObjEvent.GetObjPtr())
		sSetName = pObj.GetContainingSet().GetName()
		
		# Is this our primary ship?
		if pObj.GetName() == self.sObjectName:
			# Yep.  Update our primary setname.
			self.sPrimarySet = sSetName
			
			# And check if any other objects are in
			# this set.
			bMatch = 0
			for sName in self.dSetNames.values():
				if sName == self.sPrimarySet:
					# Yep, found a match.
					bMatch = 1
					break
			
			# If we found a match, we should be true.
			# Otherwise, we should be false:
			if self.pCodeCondition.GetStatus() != bMatch:
				self.pCodeCondition.SetStatus(bMatch)

		else:
			# Not our primary ship.
			# It's one of the ships in our list.  Set its
			# new set name.
			self.dSetNames[pObj.GetName()] = sSetName

			# And check if this set name is the same as our
			# primary set name.  If so, our condition should
			# be true.
			if sSetName == self.sPrimarySet:
				if self.pCodeCondition.GetStatus() != 1:
					self.pCodeCondition.SetStatus(1)

		# Call the next handler for this event...
		self.pEventHandler.CallNextHandler(pObjEvent)

	def ExitedSet(self, pObjEvent):
		# Get the object...
		pObj = App.ObjectClass_Cast(pObjEvent.GetObjPtr())

		# Is this our primary ship?
		if pObj.GetName() == self.sObjectName:
			# Yep.  Update our primary setname.
			self.sPrimarySet = ""

			# And make sure we're false now.
			if self.pCodeCondition.GetStatus() != 0:
				self.pCodeCondition.SetStatus(0)
		else:
			# Nope.  It's one of the ships from our list.
			# Clear the ship's set name.
			sOldSet = self.dSetNames[pObj.GetName()]
			self.dSetNames[pObj.GetName()] = ""

			# If this ship used to be in the primary ship's
			# set, we may need to trigger ourselves false.
			if sOldSet == self.sPrimarySet:
				# Check if there are any more matches
				# in the list of sets...
				bMatch = 0
				for sSet in self.dSetNames.values():
					if sSet != ""  and  sSet == self.sPrimarySet:
						# Found a match.
						bMatch = 1
						break

				# If we found a match, we should be true.
				# Otherwise, we should be false:
				if self.pCodeCondition.GetStatus() != bMatch:
					self.pCodeCondition.SetStatus(bMatch)

		# Call the next handler for this event...
		self.pEventHandler.CallNextHandler(pObjEvent)












