#
# ConditionInPhaserFiringArc
#
# A condition that's true if a specified object is within
# a phaser firing arc of another object.
#
import App
import math

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionInPhaserFiringArc:
	def __init__(self, pCodeCondition, sTargetName, sPhaserObjectName, bOnlyDangerousArcs, bSetTargetChangesTarget = 0):
		# Keep track of our parameters...
		self.pCodeCondition = pCodeCondition
		self.sTarget = sTargetName
		self.sPhaserObject = sPhaserObjectName
		self.bDangerousOnly = bOnlyDangerousArcs
		# By default, external SetTarget function calls change sPhaserObjectName.  Set this to 1
		# to have it change sTarget instead.
		self.bSetTargetChangesTarget = bSetTargetChangesTarget

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		self.fTimeDelay = 0.5
		self.pGroup = App.ObjectGroup()
		self.pGroup.AddName(self.sTarget)
		self.pGroup.AddName(self.sPhaserObject)

		# Check our initial state.
		pTarget, pPhaserObject = self.GetObjectsIfSameSet()
		if pTarget and pPhaserObject:
			self.CheckState(pTarget, pPhaserObject)

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
		if self.bSetTargetChangesTarget  and  (self.sTarget != sTarget):
			# Change self.sTarget
			#debug("Changing target from %s to %s" % (self.sTarget, sTarget))
			self.pGroup.RemoveName(self.sTarget)
			self.sTarget = sTarget
			self.pGroup.AddName(self.sTarget)
		elif (not self.bSetTargetChangesTarget)  and  (self.sPhaserObject != sTarget):
			# Change self.sPhaserObject.
			#debug("Changing target from %s to %s" % (self.sPhaserObject, sTarget))
			self.pGroup.RemoveName(self.sPhaserObject)
			self.sPhaserObject = sTarget
			self.pGroup.AddName(self.sPhaserObject)
		else:
			# No change.
			return

		# Check our new state, and setup a timer if appropriate.
		pTarget, pPhaserObject = self.GetObjectsIfSameSet()
		if pTarget and pPhaserObject:
			self.CheckState(pTarget, pPhaserObject)
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
			pTarget, pPhaserObject = self.GetObjectsIfSameSet()
			if pTarget and pPhaserObject:
				bRun = 1

		if bRun:
			# Yep, start the timer.
			self.pTimerProcess = App.PythonMethodProcess()
			self.pTimerProcess.SetInstance(self)
			self.pTimerProcess.SetFunction("PeriodicCheck")
			self.pTimerProcess.SetDelay( self.fTimeDelay )

	def Activate(self):
		pTarget, pPhaserObject = self.GetObjectsIfSameSet()
		if pTarget and pPhaserObject:
			self.CheckState(pTarget, pPhaserObject)
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
				if lpObjects[0].GetName() == self.sTarget:
					return (lpObjects[0], lpObjects[1])
				else:
					return (lpObjects[1], lpObjects[0])
		return None, None

	def PeriodicCheck(self, dTimeLeft):
		kProfiling = App.TGProfilingInfo("ConditionInPhaserFiringArc.PeriodicCheck")
		
		bKeepTimer = 0
		if self.pCodeCondition.IsActive():
			# We're active.  Time to do the check.
			pTarget, pPhaserObject = self.GetObjectsIfSameSet()
			if pTarget and pPhaserObject:
				self.CheckState(pTarget, pPhaserObject)

				# If both objects are in the same
				# set, we want to trigger the timer
				# again.
				bKeepTimer = 1

		if not bKeepTimer:
			self.pTimerProcess = None

	def EnteredSet(self, pEvent):
		self.SetupTimer(0)

		self.pEventHandler.CallNextHandler(pEvent)

	def CheckState(self, pTarget, pPhaserObject):
		bState = 0
		# Check which firing arcs the target is in, and
		# whether or not those firing arcs can fire.
		pShip = App.ShipClass_Cast(pPhaserObject)
		if pShip:
			vTargetLocation = pTarget.GetWorldLocation()
			pPhaserSystem = pShip.GetPhaserSystem()
			if pPhaserSystem:
				for iBank in range(pPhaserSystem.GetNumChildSubsystems()):
					pBank = App.PhaserBank_Cast(pPhaserSystem.GetChildSubsystem(iBank))
					# Is the target in this phaser bank?
					if ((not self.bDangerousOnly) or pBank.CanFire())  and  pBank.CanHit(vTargetLocation):
						# Yep.  We're True.
						bState = 1
						break

		if self.pCodeCondition.GetStatus() != bState:
			self.pCodeCondition.SetStatus(bState)









