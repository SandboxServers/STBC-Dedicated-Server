#
# ConditionInLineOfSight
#
# A condition that's true if one object is between the line of
# sight of 2 other objects.
# Be careful using this condition, as it is inefficient, and should
# not be used often.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionInLineOfSight:
	def __init__(self, pCodeCondition, sObject1Name, sObject2Name, sBlockingObjectName):
		# Keep track of our parameters...
		self.sObject1Name = sObject1Name
		self.sObject2Name = sObject2Name
		self.sBlockingObjectName = sBlockingObjectName
		self.fTimeDelay = 2.0 # Check every 2 seconds.

		self.pCodeCondition = pCodeCondition

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Check our initial state.
		self.CheckState()

		# Setup our event handler..
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)
		self.pEventHandler.AddPythonMethodHandlerForInstance( App.ET_AI_TIMER, "TimerTriggered" )

		# Setup our timer.
		self.SetupTimer()

		# Setup handlers when either of our two objects enter a set, since that may
		# change the state of the condition.
		self.pBothObjects = App.ObjectGroup()
		self.pBothObjects.AddName( self.sObject1Name )
		self.pBothObjects.AddName( self.sObject2Name )
		self.pBothObjects.SetEventFlag( App.ObjectGroup.ENTERED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnterSet", self.pBothObjects )

	def __del__(self):
		# Stop our timer.
		self.StopTimer()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def Activate(self):
		self.SetupTimer()

	def SetupTimer(self):
		# If we had a timer running before, stop it.
		self.StopTimer()

		# Setup our timer so we check our condition every once in a while...
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(App.ET_AI_TIMER)
		pEvent.SetDestination(self.pEventHandler)
		
		pTimer = App.TGTimer_Create()
		pTimer.SetEvent(pEvent)
		pTimer.SetTimerStart( App.g_kUtopiaModule.GetGameTime() + self.fTimeDelay )
		pTimer.SetDelay(self.fTimeDelay)
		pTimer.SetDuration(-1)	# Infinite
		self.iTimerID = pTimer.GetObjID()

		App.g_kTimerManager.AddTimer(pTimer)

	def StopTimer(self):
		# Stop our timer.  If we didn't have one running, do nothing.
		try:
			App.g_kTimerManager.DeleteTimer( self.iTimerID )
			del self.iTimerID
		except AttributeError: pass

	def TimerTriggered(self, pEvent):
		if self.pCodeCondition.IsActive():
			# We're active.  Time to do the check.
			self.CheckState()
		else:
			# Not active.  Stop our timer.  It'll be started
			# again when we're activated.
			self.StopTimer()

		self.pEventHandler.CallNextHandler(pEvent)

	def EnterSet(self, pEvent):
		# One of our two objects has just entered a set.  Check our state.
		self.CheckState()

	def CheckState(self):
		# Get the two main objects.
		pObject1 = App.ObjectClass_GetObject(None, self.sObject1Name)
		if pObject1:
			pSet = pObject1.GetContainingSet()
			if pSet:
				pObject2 = App.ObjectClass_GetObject(pSet, self.sObject2Name)

				if pObject2:
					# They both exist in the same set.
					# Check for objects between them.
					self.CheckLOS(pObject1, pObject2, pSet)

	def CheckLOS(self, pObject1, pObject2, pSet):
		bBlockedLOS = 0

		# Get the proximity manager...
		pProxManager = pSet.GetProximityManager()

		if pProxManager:
			# Get a list of objects between pObject1 and pObject2
			kIter = pProxManager.GetLineIntersectObjects(pObject1.GetWorldLocation(), pObject2.GetWorldLocation(), 0)
			pObject = pProxManager.GetNextObject(kIter)
			while (pObject != None):
				# Is this object the object we're looking for?
				if pObject.GetName() == self.sBlockingObjectName:
					# Yep.  We're now true.
					bBlockedLOS = 1

				pObject = pProxManager.GetNextObject(kIter)
			pProxManager.EndObjectIteration(kIter)

		# If our status has changed, update the code condition..
		if self.pCodeCondition.GetStatus() != bBlockedLOS:
#			debug("Changing status to " + str(bBlockedLOS))
			self.pCodeCondition.SetStatus(bBlockedLOS)









