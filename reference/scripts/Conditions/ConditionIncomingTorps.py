#
# ConditionIncomingTorps
#
# True if a given object has incoming torps from the specified
# firing object.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

# Global dictionary of all ConditionIncomingTorpsInternal instances, and
# a refcount of those instances.
g_dInternalInstances = {}

#
# ConditionIncomingTorps
#
# This is just a wrapper class for the ConditionIncomingTorpsInternal class.
# It checks if an appropriate internal class exists.  If so, it just uses that
# one.  If not, it makes a new one.
#
class ConditionIncomingTorps:
	def __init__(self, pCodeCondition, sTarget, sFiringObject = None, bSetTargetChangesTarget = 0):
		# Set params...
		self.sTarget = sTarget
		self.sFiringObject = sFiringObject
		self.bSetTargetChangesTarget = bSetTargetChangesTarget
		self.pCodeCondition = pCodeCondition

		self.pInternal = self.GetInternalInstance(pCodeCondition, sTarget, sFiringObject)

	def __del__(self):
		self.pInternal.RemoveReference(self, self.pCodeCondition)

	def RegisterExternalFunctions(self, pAI):
		pAI.RegisterExternalFunction("SetTarget", { "CodeID" : self.pCodeCondition.GetObjID(), "FunctionName" : "SetTarget" })

	def SetTarget(self, sTarget):
		if self.bSetTargetChangesTarget  and  (self.sTarget != sTarget):
			# Changing self.sTarget.
			self.pInternal.RemoveReference(self, self.pCodeCondition)
			self.pInternal = self.GetInternalInstance(self.pCodeCondition, sTarget, self.sFiringObject)

			self.sTarget = sTarget
		elif (not self.bSetTargetChangesTarget)  and  (self.sFiringObject is not None)  and  (self.sFiringObject != sTarget):
			# Changing self.sFiringObject from its current object to a new one.
			self.pInternal.RemoveReference(self, self.pCodeCondition)
			self.pInternal = self.GetInternalInstance(self.pCodeCondition, self.sTarget, sTarget)

			#debug("Changing target from %s to %s" % (self.sFiringObject, sTarget))
			self.sFiringObject = sTarget
		else:
			# No change.
			return

	def GetInternalInstance(self, pCodeCondition, *lArgs):
		# Get an instance of the ConditionIncomingTorpsInternal class
		# with arguments that match the ones we were given.
		global g_dInternalInstances
		try:
			iReferences, pInstance = g_dInternalInstances[lArgs]
			g_dInternalInstances[lArgs] = ( iReferences + 1, pInstance )

			# Add the new pCodeCondition to this instance's list.
			pInstance.lCodeConditions.append( pCodeCondition )
			return pInstance
		except KeyError:
			# No such instance exists yet.
			pInstance = apply(ConditionIncomingTorpsInternal, (pCodeCondition,) + lArgs)
			g_dInternalInstances[lArgs] = (1, pInstance)
			return pInstance

class ConditionIncomingTorpsInternal:
	def __init__(self, pCodeCondition, sTarget, sFiringObject):
		# Set params...
		self.lCodeConditions = [pCodeCondition]

		self.sTarget = sTarget
		self.sFiringObject = sFiringObject
		self.iTargetID = None
		self.iFiringObjectID = App.NULL_ID
		self.liIncoming = []

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# If a torp is within this amount of time of hitting us,
		# we should start worrying about it:
		self.fDangerTimeThreshold = 18.0

		# Timer info for our periodic check.
		self.pTimerProcess = None
		self.fTimeDelay = 1.0

		# Determine our initial state.
		self.SetupInitialState()

		# Setup our event handlers.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)
		self.SetupEventHandlers()

	def RemoveReference(self, pInstance, pCodeCondition):
		assert( pCodeCondition in self.lCodeConditions )
		self.lCodeConditions.remove( pCodeCondition )

		# Remove a reference to us from g_dInternalInstances
		global g_dInternalInstances
		lArgs = (self.sTarget, self.sFiringObject)
		iReferences, pSelfInstance = g_dInternalInstances[lArgs]

		# If there will be no references left, delete the global reference to us.
		# Otherwise, just decrement it.
		if iReferences <= 1:
			del g_dInternalInstances[lArgs]
		else:
			g_dInternalInstances[lArgs] = (iReferences - 1, pSelfInstance)

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		dState["pTimerProcess"] = (self.pTimerProcess is not None)
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

		if self.pTimerProcess:
			self.pTimerProcess = None
			self.SetupTimer()
		else:
			self.pTimerProcess = None

	def SetupInitialState(self):
		# By default we're false.
		for pCodeCondition in self.lCodeConditions:
			pCodeCondition.SetStatus(0)

		# Does the firing object exist yet?
		if self.sFiringObject:
			pSource = App.ObjectClass_GetObject(None, self.sFiringObject)
			if pSource:
				# Yep.  Save its ID.
				self.iFiringObjectID = pSource.GetObjID()
		else:
			pSource = None

		# Check if the target exists yet.
		pObject = App.ObjectClass_GetObject(None, self.sTarget)
		if pObject:
			# Yup, it exists.  Save its ID for later...
			self.iTargetID = pObject.GetObjID()
			pSet = pObject.GetContainingSet()

			if pSource  or  (not self.sFiringObject):
				self.CheckTorpsInSet(pObject, pSet)

	def CheckTorpsInSet(self, pTarget, pSet):
		self.liIncoming = App.AIScriptAssist_GetIncomingTorpIDsInSet(pTarget, pSet, self.fDangerTimeThreshold, self.iFiringObjectID, (self.sFiringObject is not None))
		#debug("liIncoming is " + str(self.liIncoming))
		for pCodeCondition in self.lCodeConditions:
			pCodeCondition.SetStatus( len(self.liIncoming) != 0 )

	def CheckTorpedo(self, pTorpedo):
		pTarget = App.ObjectClass_GetObjectByID(None, self.iTargetID)
		if pTarget:
			return App.AIScriptAssist_TorpIsIncoming(pTarget, pTorpedo, self.fDangerTimeThreshold, self.iFiringObjectID, (self.sFiringObject is not None))
		return 0

	def SetupEventHandlers(self):
		# We need a general Entered Set handler, and another
		# for Exited Set.
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_TORPEDO_ENTERED_SET, self.pEventHandler, "EnteredSet" )
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet" )
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_TORPEDO_EXITED_SET, self.pEventHandler, "ExitedSet" )
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_EXITED_SET, self.pEventHandler, "ExitedSet" )

	def SetupTimer(self):
		if self.pTimerProcess is not None:
			# We already have a timer.
			return

		self.pTimerProcess = App.PythonMethodProcess()
		self.pTimerProcess.SetInstance(self)
		self.pTimerProcess.SetFunction("PeriodicCheck")
		self.pTimerProcess.SetDelay( self.fTimeDelay )
		self.pTimerProcess.SetPriority( App.TimeSliceProcess.LOW )

	def Activate(self):
		self.SetupTimer()

	def PeriodicCheck(self, dTimeLeft):
		kProfiling = App.TGProfilingInfo("ConditionIncomingTorps.PeriodicCheck")
		
		bTriggerAgain = 0

		# If we're not active, abort.
		bActive = 0
		for pCodeCondition in self.lCodeConditions:
			if pCodeCondition.IsActive():
				bActive = 1
				break
		if bActive:
			# Get the target object.
			if self.iTargetID:
				pTarget = App.ObjectClass_GetObject(None, self.sTarget)
				if pTarget:
					pSet = pTarget.GetContainingSet()
					if pSet:
						self.CheckTorpsInSet(pTarget, pSet)

						# If there are any torps in the set that could be
						# a threat, start up the timer again.
						if pSet.GetClassObjectList(App.CT_TORPEDO):
							# Keep the timer running.
							bTriggerAgain = 1

		if not bTriggerAgain:
			self.pTimerProcess = None

	def EnteredSet(self, pEvent):
		# An object has entered the set.

		# We're interested in this object if it's a torpedo...
		pObject = App.ObjectClass_Cast(pEvent.GetDestination())
		pTorp = App.Torpedo_Cast(pObject)
		if pTorp:
			# It's a torpedo.  Check if it's incoming..
			if self.CheckTorpedo(pTorp):
				self.AddIncoming(pTorp)

			# Start our periodic checks, if they
			# aren't already running.
			self.SetupTimer()
		else:
			# We're also interested in this object if we
			# don't have our Target or FiringObject ID's yet,
			# and this is either our target or the firing object.
			if self.iTargetID is None:
				if pObject.GetName() == self.sTarget:
					# It's the target.  Save its ID.
					self.iTargetID = pObject.GetObjID()
			if (self.iFiringObjectID == App.NULL_ID)  and  self.sFiringObject:
				if pObject.GetName() == self.sFiringObject:
					# It's the firing object.  Save its ID.
					self.iFiringObjectID = pObject.GetObjID()

		self.pEventHandler.CallNextHandler(pEvent)

	def ExitedSet(self, pEvent):
		# An object is exiting a set.
		# Is it a torpedo?
		pTorp = App.Torpedo_Cast(pEvent.GetDestination())
		if pTorp:
			# Yes, it's a torp.  If it was in our
			# incoming list, remove it.
			self.RemoveIncoming(pTorp)

		self.pEventHandler.CallNextHandler(pEvent)

	def AddIncoming(self, pTorpedo):
		if not (pTorpedo.GetObjID() in self.liIncoming):
			self.liIncoming.append(pTorpedo.GetObjID())

		for pCodeCondition in self.lCodeConditions:
			if pCodeCondition.GetStatus() != 1:
				pCodeCondition.SetStatus(1)

	def RemoveIncoming(self, pTorpedo):
		if pTorpedo.GetObjID() in self.liIncoming:
			self.liIncoming.remove(pTorpedo.GetObjID())

			if len(self.liIncoming) == 0:
				# We are now false.
				for pCodeCondition in self.lCodeConditions:
					if pCodeCondition.GetStatus() != 0:
						pCodeCondition.SetStatus(0)













