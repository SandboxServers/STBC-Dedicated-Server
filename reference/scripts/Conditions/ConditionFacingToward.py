#
# ConditionFacingToward
#
# A condition that's true if a specified side (or front, or
# whatever model-space vector is specified) of one object
# is facing toward another object.
#
import App
import math

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionFacingToward:
	def __init__(self, pCodeCondition, sObject1Name, sObject2Name, fAngleThreshold, vDirection, bSetTargetReplacesObject2 = 0):
		# Keep track of our parameters...
		self.pCodeCondition = pCodeCondition
		self.sObject1Name = sObject1Name
		self.sObject2Name = sObject2Name
		self.fDotThreshold = math.cos(fAngleThreshold * App.PI / 180.0)
		self.vDirection = App.TGPoint3()
		self.vDirection.Set(vDirection)

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# By default, calls to SetTarget will replace object 1.  If you want them
		# to replace object 2, this needs to be true.
		self.bSetTargetReplacesObject2 = bSetTargetReplacesObject2

		self.fTimeDelay = 0.5
		self.pGroup = App.ObjectGroup()
		self.pGroup.AddName(self.sObject1Name)
		self.pGroup.AddName(self.sObject2Name)

		# Check our initial state.
		pObj1, pObj2 = self.GetObjectsIfSameSet()
		if pObj1 and pObj2:
			self.CheckState(pObj1, pObj2)

		# Setup our event handler..
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Also listen for Entered Set messages for
		# our object group.  We need these so we can
		# start running the timer at an appropriate time.
		self.pGroup.SetEventFlag( App.ObjectGroup.ENTERED_SET )
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET, self.pEventHandler, "EnteredSet", self.pGroup)

		# Setup our timer.
		self.pTimerProcess = None
		self.SetupTimer(0)

	def RegisterExternalFunctions(self, pAI):
		pAI.RegisterExternalFunction("SetTarget", { "CodeID" : self.pCodeCondition.GetObjID(), "FunctionName" : "SetTarget" })

	def SetTarget(self, sTarget):
		# Change one of the objects we're watching.  Which one?
		if self.bSetTargetReplacesObject2  and  (self.sObject2Name != sTarget):
			# Change object 2
			#debug("Changing target from %s to %s" % (self.sObject2Name, sTarget))
			self.pGroup.RemoveName( self.sObject2Name )
			self.sObject2Name = sTarget
			self.pGroup.AddName( self.sObject2Name )
		elif self.sObject1Name != sTarget:
			# Change object 1
			#debug("Changing target from %s to %s" % (self.sObject1Name, sTarget))
			self.pGroup.RemoveName( self.sObject1Name )
			self.sObject1Name = sTarget
			self.pGroup.AddName( self.sObject1Name )
		else:
			# Nothing's changing.
			return

		# Check our new state, and setup a timer if appropriate.
		pObj1, pObj2 = self.GetObjectsIfSameSet()
		if pObj1 and pObj2:
			self.CheckState(pObj1, pObj2)
			self.SetupTimer(1)

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
			self.SetupTimer(1)
		else:
			self.pTimerProcess = None

	def SetupTimer(self, bForce):
		# Don't run multiple timers...
		if self.pTimerProcess is not None:
			return

		# Should the timer be running?  Check if both
		# objects exist, and if they're in the same set.
		bRun = bForce
		if not bForce:
			pObj1, pObj2 = self.GetObjectsIfSameSet()
			if pObj1 and pObj2:
				bRun = 1

		if bRun:
			# Yep, start the timer.
			self.pTimerProcess = App.PythonMethodProcess()
			self.pTimerProcess.SetInstance(self)
			self.pTimerProcess.SetFunction("PeriodicCheck")
			self.pTimerProcess.SetDelay( self.fTimeDelay )

	def Activate(self):
		pObj1, pObj2 = self.GetObjectsIfSameSet()
		if pObj1 and pObj2:
			self.CheckState(pObj1, pObj2)
			self.SetupTimer(1)

	def GetObjectsIfSameSet(self):
		# Get the objects that exist...
		lpObjects = self.pGroup.GetActiveObjectTuple()
		if len(lpObjects) == 2:
			# Both objects exist.  Are they in the same set?
			pSet1 = lpObjects[0].GetContainingSet()
			pSet2 = lpObjects[1].GetContainingSet()
			if pSet1 and pSet2 and pSet1.GetName() == pSet2.GetName():
				# Yep, same set.  Return the objects.
				# Object 1 first.
				if lpObjects[0].GetName() == self.sObject1Name:
					return (lpObjects[0], lpObjects[1])
				else:
					return (lpObjects[1], lpObjects[0])
		return None, None

	def PeriodicCheck(self, dTimeLeft):
		kProfiling = App.TGProfilingInfo("ConditionFacingToward.PeriodicCheck")

		bKeepTimer = 0
		if self.pCodeCondition.IsActive():
			# We're active.  Time to do the check.
			pObj1, pObj2 = self.GetObjectsIfSameSet()
			if pObj1 and pObj2:
				self.CheckState(pObj1, pObj2)

				# If both objects are in the same
				# set, we want to trigger the timer
				# again.
				bKeepTimer = 1

		if not bKeepTimer:
			self.pTimerProcess = None

	def EnteredSet(self, pEvent):
		self.SetupTimer(0)

		self.pEventHandler.CallNextHandler(pEvent)

	def CheckState(self, pObj1, pObj2):
		# Move object 1's direction vector into worldspace.
		vWorldDir = App.TGPoint3()
		vWorldDir.Set(self.vDirection)
		vWorldDir.MultMatrixLeft(pObj1.GetWorldRotation())

		# Find the location direction from object 1 to object 2.
		vDiffDir = pObj2.GetWorldLocation()
		vDiffDir.Subtract(pObj1.GetWorldLocation())
		vDiffDir.Unitize()

		# Dot product of the 2 directions...
		fDot = vWorldDir.Dot(vDiffDir)

		bState = 0
		if fDot >= self.fDotThreshold:
			# Angle is good.  We're true.
			bState = 1

		#debug(__name__ + ": CheckState(%s, %s) dot (%f/%f) (State %d)" %
		#	(pObj1.GetName(), pObj2.GetName(), fDot, self.fDotThreshold, bState))

		if self.pCodeCondition.GetStatus() != bState:
			self.pCodeCondition.SetStatus(bState)









