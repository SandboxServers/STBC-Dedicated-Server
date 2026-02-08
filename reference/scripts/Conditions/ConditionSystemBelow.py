#
# ConditionSystemBelow
#
# A condition that's true when a specific system on a given object
# is below a certain percentage.
# Since systems are specified by type, if the ship we're watching
# has multiple systems of the same type... ...this will be true if
# any of the systems are below the given fraction.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

class ConditionSystemBelow:
	def __init__(self, pCodeCondition, sObject, eSystem, fSystemFraction):
		# Set our parameters...
		self.pCodeCondition = pCodeCondition
		self.sObject = sObject  # The object that contains the system.
		self.eSystem = eSystem  # The type of system to watch.
		self.fFraction = fSystemFraction
		self.dWatchInfo = {}	# Info about our watchers...

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# We use an ObjectGroup to track our object...
		self.pGroup = App.ObjectGroup()
		self.pGroup.AddName(self.sObject)

		# Setup our event handler wrapper.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Set our initial state..
		self.pCodeCondition.SetStatus(0)

		# Get the object, if it exists:
		try:
			pObject = self.pGroup.GetActiveObjectTuple()[0]
		except IndexError:
			# Doesn't exist yet.
			pObject = None
			
			# We need to add event handlers for when our
			# object enters a set, so we can start tracking.
			self.pGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pGroup )

		pShip = App.ShipClass_Cast(pObject)
		if (pShip != None):
			self.AddWatchersAndCheckStatus(pShip)

		# Since the events for the watchers are being sent
		# to us, we just need an instance handler.			
		self.pEventHandler.AddPythonMethodHandlerForInstance( App.ET_AI_SYSTEM_STATUS_WATCHER, "SystemEvent" )

	def __del__(self):
		# Make sure the watchers watching our systems don't
		# give us any more events.
		self.RemoveWatchers()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def AddWatchersAndCheckStatus(self, pShip):
		bStatus = 0

		# Cycle through all the subsystems that match the
		# specified type.
		pSystemIter = pShip.StartGetSubsystemMatch( self.eSystem )
		pSystem = pShip.GetNextSubsystemMatch( pSystemIter )
		while (pSystem != None):
			# Add a watcher for the condition of this
			# system.
			# We need an event...  The event needs to contain
			# information about the value of the system at the
			# time (that part is filled in by the range watcher)
			# and the system it came from (we'll fill that in here).
			pEvent = App.TGFloatEvent_Create()
			pEvent.SetEventType( App.ET_AI_SYSTEM_STATUS_WATCHER )
			pEvent.SetDestination( self.pEventHandler )
			pEvent.SetSource( pSystem )

			pWatcher = pSystem.GetConditionWatcher()
			iRangeID = pWatcher.AddRangeCheck( self.fFraction, App.FloatRangeWatcher.FRW_BOTH, pEvent )
			self.dWatchInfo[pSystem.GetObjID()] = iRangeID

			# Check the current status of this system.
			fFraction = pWatcher.GetWatchedVariable()
			if fFraction < self.fFraction:
				bStatus = 1

			pSystem = pShip.GetNextSubsystemMatch( pSystemIter )

		pShip.EndGetSubsystemMatch(pSystemIter)

		# Check our status...
		if self.pCodeCondition.GetStatus() != bStatus:
			self.pCodeCondition.SetStatus(bStatus)

	def RemoveWatchers(self):
		# Check if the object still exists...
		lObjects = self.pGroup.GetActiveObjectTuple()
		if len(lObjects) == 0:
			# Nope, doesn't exist.  Nothing to do.
			return

		pShip = App.ShipClass_Cast(lObjects[0])
		if (pShip != None):
			# Ok, cycle through the systems of this ship that
			# have our watchers...
			pSystemIter = pShip.StartGetSubsystemMatch( self.eSystem )
			pSystem = pShip.GetNextSubsystemMatch( pSystemIter )
			while (pSystem != None):
				# Retrieve our info about this watcher, if
				# we added a check to it.

				# Standard dictionary lookup isn't working, because
				# they keys are different items...
				iInfo = None
				try:
					iInfo = self.dWatchInfo[pSystem.GetObjID()]
				except:
					iInfo = None

				if iInfo is not None:
					# Remove the watcher for the
					# condition of this system.
					pWatcher = pSystem.GetConditionWatcher()
					pWatcher.RemoveRangeCheck( iInfo )

				pSystem = pShip.GetNextSubsystemMatch( pSystemIter )

			pShip.EndGetSubsystemMatch(pSystemIter)

	def EnteredSet(self, pObjEvent):
		# Our object has entered a set.  Get it, and add its
		# system watchers.
		pShip = App.ShipClass_Cast( pObjEvent.GetObjPtr() )
		if (pShip != None):
			self.AddWatchersAndCheckStatus( pShip )

		# We no longer need this event handler.
		App.g_kEventManager.RemoveBroadcastHandler( App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pGroup )

	def SystemEvent(self, pFloatEvent):
		# Check if our system is now above or below the fraction...
		fFraction = pFloatEvent.GetFloat()

		if fFraction < self.fFraction:
			# It's below.  Make sure our status is true.
			if self.pCodeCondition.GetStatus() != 1:
				self.pCodeCondition.SetStatus(1)
		else:
			# It's at or above.  Make sure our status is false.
			if self.pCodeCondition.GetStatus() != 0:
				self.pCodeCondition.SetStatus(0)

		self.pEventHandler.CallNextHandler(pFloatEvent)

			
		
		
		
		
		
		
		
		
		
		
		
