#
# ConditionInRange
#
# A condition that's true when one of a group of objects
# is in range of another object.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionInRange:
	# Arguments to the contstructor:
	# pCodeCondition	- the ConditionScript this will
	#			  be attached to
	# fDistance		- The distance under which we'll trigger
	#			  true, for our objects
	# sObject1		- Name of the object that we want to
	#			  check range against.
	# lsObjects		- A list of names or an ObjectGroup
	#			  to check against.  The condition is
	#			  true as long as any of these objects
	#			  are in range
	def __init__(self, pCodeCondition, fDistance, sObject1, *lsObjectNames):
		# Set our object and set names...
		self.fDistance = fDistance
		self.pCodeCondition = pCodeCondition

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		#debug("Created ConditionInRange(%f) %s" % (self.fDistance, str(self)))

		# Set our initial state...
		# We always start false.  We'll let our proximity check
		# trigger us true.
		self.pCodeCondition.SetStatus(0)

		# We need to be notified if either of our objects enters
		# a new set.  If object 1 enters a new set, we'll need to
		# create the proximity sphere again.  We need to track
		# object 2 in case multiple ships (over time) are created
		# with object 2's name.  Then we can add them to the proximity
		# check.
		# And we need to check for these objects exiting the set,
		# in case we need to trigger our condition false.
		# Setup our interrupt handlers.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		self.pProx = None
		apply(self.SetObjects, (sObject1,) + lsObjectNames)

		# Our event handler for handling proximity events...
		self.pEventHandler.AddPythonMethodHandlerForInstance(App.ET_AI_INTERNAL_PROX_EVENT, "ProximityEvent")

	def __del__(self):
		# Get rid of the proximity sphere we were using.
		#debug("Deleting ConditionInRange " + str(self))
		if self.pProx:
			#debug("ConditionInRange.__del__ deleting prox for %s" % str(self))
			self.pProx.RemoveAndDelete()
			self.pProx = None

	def RegisterExternalFunctions(self, pAI):
		#debug("RegisterExternalFunctions for " + str(self))
		pAI.RegisterExternalFunction("SetTarget", { "CodeID" : self.pCodeCondition.GetObjID(), "FunctionName" : "SetTarget" })

	def SetTarget(self, sTarget):
		#debug("SetTarget for " + str(self))
		# Change self.sObject1.
		if self.sObject1 != sTarget:
			#debug("Changing target from %s to %s" % (self.sObject1, sTarget))
			apply(self.SetObjects, (sTarget, self.pObjects))

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def SetDistance(self, fDistance):
		#debug("SetDistance for " + str(self))
		# Update our internal variable..
		self.fDistance = fDistance

		# If our proximity check exists, update its distance.
		if self.pProx:
			# If pProx exists, our object1 should exist.  Get its
			# radius, to add to the distance.
			pObjectTuple = self.pSingleObjectGroup.GetActiveObjectTuple()
			if pObjectTuple:
				pObject1 = pObjectTuple[0]
				self.pProx.SetRadius(self.fDistance + pObject1.GetRadius())

	def SetObjects(self, sObject1, *lsObjectNames):
		# SetupProximitySphere will do a lot of our work for us.
		# We need to change the names of the objects we're looking
		# for, and clear any old state information, though.
		# Set the new name and ObjectGroup.
		self.sObject1 = sObject1
		self.pObjects = App.ObjectGroup_ForceToGroup(lsObjectNames)

		#debug("SetObjects(%s, %s) for %s" % (sObject1, self.pObjects.GetNameTuple(), self))
		#debug(__name__ + " setting new objects (%s, %s)" % (self.sObject1, self.pObjects.GetNameTuple()))

		# Our implementation is a little easier if the
		# single object (sObject1) is in an ObjectGroup...
		self.pSingleObjectGroup = App.ObjectGroup()
		self.pSingleObjectGroup.AddName(self.sObject1)

		# Clear our count of how many objects are inside...
		self.iNumInside = 0
		self.lsInsideObjects = []
		self.pCodeCondition.SetStatus(0)

		# Add handlers for the objects in our ObjectGroups
		# (self.pObjects).  We need to know when they enter
		# or exit a set.
		self.pObjects.SetEventFlag( App.ObjectGroup.ENTERED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pObjects)
		self.pObjects.SetEventFlag( App.ObjectGroup.EXITED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_EXITED_SET, self.pEventHandler, "ExitedSet", self.pObjects)
		self.pObjects.SetEventFlag( App.ObjectGroup.GROUP_CHANGED )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_CHANGED, self.pEventHandler, "GroupChanged", self.pObjects)

		# And for the single...
		self.pSingleObjectGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pSingleObjectGroup)
		self.pSingleObjectGroup.SetEventFlag( App.ObjectGroup.EXITED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_EXITED_SET, self.pEventHandler, "ExitedSet", self.pSingleObjectGroup)

		# Setup the proximity sphere.
		self.SetupProximitySphere()

	def GetStatusInfo(self):
		return "ConditionInRange(%.2f, %s, %s) is %s" % (self.fDistance, self.sObject1, self.pObjects.GetNameTuple(), ("False", "True")[self.pCodeCondition.GetStatus()])

	def SetupProximitySphere(self, pObject1 = None):
		#debug("SetupProximitySphere for %s" % self)
		# If we already have a proximity sphere, scrap it.
		if self.pProx:
			# Remove our event handler for this prox's deletion,
			# so we don't get confused by it.
			App.g_kEventManager.RemoveBroadcastHandler(App.ET_DELETE_OBJECT_PUBLIC, self.pEventHandler, "ProxDeleted", self.pProx)
			
			# Scrap the prox check.
			self.pProx.RemoveAndDelete()
			self.pProx = None

		# Clear our count of how many objects are inside...
		self.iNumInside = 0
		self.lsInsideObjects = []

		# Check if object 1 exists (if it wasn't passed in),
		# and get the set that it's in.
		if pObject1:
			pSet = pObject1.GetContainingSet()
		else:
			pObject1 = App.ObjectClass_GetObject(App.SetClass_GetNull(), self.sObject1)
			if (pObject1 == None):
				# Nope, object 1 doesn't exist.
				# It could be a placement object...
				pObject1 = App.PlacementObject_GetObject(App.SetClass_GetNull(), self.sObject1)
				if (pObject1 == None):
					# Nope, it's still NULL.
					# We can't setup our sphere.
					# We'll have to wait until
					# object 1 enters a set somewhere..
					return
				else:
					pSet = pObject1.FindContainingSet()
			else:
				pSet = pObject1.GetContainingSet()

		# Get the set that our primary object is in...
		if not pSet:
			return

		pProximityManager = pSet.GetProximityManager()
		if (pProximityManager == None):
			# This set has no proximity manager, so it can't
			# manage any proximity checks.  We can't create our
			# proximity check...
			return

		# Setup the proximity check itself
		self.pProx = App.ProximityCheck_Create(
			App.ET_AI_INTERNAL_PROX_EVENT,
			self.pEventHandler)
		#debug("Created new prox (%s) for %s" % (str(self.pProx.this), str(self)))

		# If pObject1 is warping in, its radius is going to be messed up.
		fObject1Radius = pObject1.GetRadius()
		try:
			pShip1 = App.ShipClass_Cast(pObject1)
			pWarpSystem = pShip1.GetWarpEngineSubsystem()
		except AttributeError:
			pWarpSystem = None
		if pWarpSystem:
			if pWarpSystem.GetWarpState() != App.WarpEngineSubsystem.WES_NOT_WARPING:
				# It appears to be warping.  Get its unstretched radius.
				if pShip1.HasClonedModel():
					fObject1Radius = pShip1.GetClonedModelRadius()
				
		self.pProx.SetRadius(self.fDistance + pObject1.GetRadius())
		self.pProx.SetIgnoreObjectSize(1)

		# Add an event handler for the deletion of our proximity
		# check object.
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_DELETE_OBJECT_PUBLIC, self.pEventHandler, "ProxDeleted", self.pProx)

		pProximityManager.AddObject(self.pProx)

		# Attach the proximity check to our object 1.
		pObject1.AttachObject(self.pProx)
		# Need to update it...  :/
		self.pProx.UpdateNodeOnly()

		# Cycle through all the objects in our
		# self.pObjects list that are in pObject1's set,
		# and add them to the prox check.
		for pObject in self.pObjects.GetActiveObjectTupleInSet(pSet):
			# Is this object inside the radius right now?
			vDiff = pObject1.GetWorldLocation()
			vDiff.Subtract(pObject.GetWorldLocation())
			fDistance = vDiff.Length()

			if fDistance < self.fDistance:
				# Yep, it's in range.  Add it to our list
				# of objects that are in range..
				self.AddInside(pObject.GetName())

				# Add it to the prox check, checking for when it goes
				# outside.
				self.pProx.AddObjectToCheckList(pObject, App.ProximityCheck.TT_OUTSIDE)
			else:
				# It's not currently inside.  Add it to the
				# prox check, for when it goes inside.
				self.pProx.AddObjectToCheckList(pObject, App.ProximityCheck.TT_INSIDE)

			# Force an immediate check.
			self.pProx.CheckProximity(pObject)

	def ProxDeleted(self, pEvent):
		#debug("ProxDeleted for %s" % self)
		# Our proximity object is now invalid...
		# This will probably only happen if the proximity manager
		# is being deleted, because the set is being deleted.  If
		# this is the case, we don't want to create another proximity
		# object.  And if we ever need to create another prox object,
		# it'll be because the object we're watching has been added
		# to another set, and we already have a handler for that.
		# So, in short, we don't need to setup a new proximity sphere.
		#debug("ConditionInRange.ProxDeleted(%s)" % str(self))
		self.pProx = None

		self.pEventHandler.CallNextHandler(pEvent)
	
	def ProximityEvent(self, pEvent):
		# Our proximity event was triggered.
		# Note: No need to CallNextHandler here, since we're the only
		# handler for this particular event.
		pObject = pEvent.GetObject()
		pCheck = pEvent.GetProximityCheck()

		# Make sure this proximity event is for the right proximity object...
		try:
			if pCheck.GetObjID() != self.pProx.GetObjID():
				return
		except AttributeError:
			return

		#debug("ProximityEvent(%s, %d) for %s" % (pObject.GetName(), pCheck.GetTriggerType(pObject), self))

		# Make sure this object is actually in our list.
		# There are some unusual circumstances where we could
		# get an event for an object that's no longer in our list.
		if not self.pObjects.IsNameInGroup(pObject.GetName()):
			return

		eType = pCheck.GetTriggerType(pObject)
		if eType == App.ProximityCheck.TT_INSIDE:
			# It's inside the sphere now.
			#debug("Proxcheck found %s inside. (%s)" % (pObject.GetName(), self.sObject1))
			self.AddInside(pObject.GetName())

			# Trigger again if this goes outside
			pCheck.SetTriggerType(pObject, App.ProximityCheck.TT_OUTSIDE)

		elif eType == App.ProximityCheck.TT_OUTSIDE:
			# It's outside the sphere now.
			#debug("Proxcheck found %s outside. (%s)" % (pObject.GetName(), self.sObject1))
			self.RemoveInside(pObject.GetName())

			# Trigger again if this goes inside
			pCheck.SetTriggerType(pObject, App.ProximityCheck.TT_INSIDE)

	def EnteredSet(self, pObjectEvent):
		#debug("ConditionInRange(%s)::EnteredSet" % str(self))
		# One of our objects has entered the set.
		pObject = App.ObjectClass_Cast(pObjectEvent.GetObjPtr())

		#debug("EnteredSet(%s) for %s" % (pObject.GetName(), self))

		# Is it our Object1?
		if pObject.GetName() == self.sObject1:
			# Yes, it's object 1.
			# We need to recreate our proximity check...
			self.SetupProximitySphere(pObject)
		else:
			# Nope.  It's one of our other objects.
			# Check if it's in the same set as our sObject1.
			pSet = pObject.GetContainingSet()
			pObject1 = App.ObjectClass_GetObject(pSet, self.sObject1)
			if (pObject1 != None):
				# Yep, same set.  If it's not already in
				# the prox check, add it.
				if self.pProx:
					if not self.pProx.IsObjectInCheckList( pObject ):
						#debug("Added %s to check." % pObject.GetName())
						self.pProx.AddObjectToCheckList(pObject, App.ProximityCheck.TT_INSIDE)
					else:
						# It's in the checklist.  Make sure it's set for TT_INSIDE
						self.pProx.SetTriggerType(pObject, App.ProximityCheck.TT_INSIDE)

		# Call the next handler for this event...
		self.pEventHandler.CallNextHandler(pObjectEvent)

	def ExitedSet(self, pObjectEvent):
		#debug("ConditionInRange::Exited")
		# One of our objects has exited the set.
		pObject = App.ObjectClass_Cast(pObjectEvent.GetObjPtr())

		#debug("ExitedSet(%s) for %s" % (pObject.GetName(), self))

		# Is it our Object1?
		if pObject.GetName() == self.sObject1:
			# Yes, it's object 1.
			# Scrap our proximity object, since it's been
			# deleted by the app.
			self.pProx = None
			
			# And clear our count of the number of objects
			# in range.
			self.iNumInside = 0
			
			# And make sure we're false.
			if self.pCodeCondition.GetStatus() != 0:
				self.pCodeCondition.SetStatus(0)

		else:
			# Nope.  Must be one of our other objects.
			# Check if it's in our proximity check,
			# and if we're triggering when it goes
			# outside the radius.
			if self.pProx:
				eTrigger = self.pProx.GetTriggerType(pObject)
				if eTrigger == App.ProximityCheck.TT_OUTSIDE:
					# Yep.
					# This object must be inside right now.
					# Decrement our Inside count.
					self.RemoveInside(pObject.GetName())

		# Call the next handler for this event...
		self.pEventHandler.CallNextHandler(pObjectEvent)

	def GroupChanged(self, pEvent):
		#debug("GroupChanged for %s" % self)
		# An object has been added to or removed from our self.pObjects group.
		# We'll need to update the proximity sphere for the changed group.
		# Hopefully this won't be too painfully slow:
		apply(self.SetObjects, (self.sObject1, self.pObjects))

	def AddInside(self, sObject):
		#debug("AddInside(%s) for %s" % (sObject, self))
		# Increment our count of how many objects are in range.
		# And set ourselves true, if we're not already.
		if not (sObject in self.lsInsideObjects):
			self.lsInsideObjects.append(sObject)

			self.iNumInside = self.iNumInside + 1
			if self.pCodeCondition.GetStatus() != 1:
				self.pCodeCondition.SetStatus(1)

			# Just a sanity check, for debugging:
#			if self.iNumInside > len(self.pObjects.GetNameTuple()):
#				debug("ERROR: Too many objects in range (%d/%d) for (%s, %s)!" % (self.iNumInside, len(self.pObjects.GetNameTuple()), self.sObject1, self.pObjects.GetNameTuple()))

	def RemoveInside(self, sObject):
		#debug("RemoveInside(%s) for %s" % (sObject, self))
		# Decrement our count of how many objects are in range.
		# Set ourselves false if no more objects are in range.
		if sObject in self.lsInsideObjects:
			self.lsInsideObjects.remove(sObject)

			self.iNumInside = self.iNumInside - 1
			if self.iNumInside < 1:
				self.pCodeCondition.SetStatus(0)

			# Just a sanity check, for debugging:
#			if self.iNumInside < 0:
#				debug("ERROR: Too few objects in range (%d)!" % (self.iNumInside))

















