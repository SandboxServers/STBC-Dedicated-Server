#
# ConditionSystemDestroyed
#
# A condition that's true when a specific system on a given object
# is destroyed.
# Since systems are specified by type, if the ship we're watching
# has multiple systems of the same type... ...this will be true only
# ALL of the systems are destroyed.
# The optional bDestroyedIfChildrenDestroyed flag, if true, will force
# this condition to check all child subsystems, and consider a subsystem
# to be destroyed if all its children have been destroyed.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionSystemDestroyed:
	def __init__(self, pCodeCondition, sObject, eSystem, bDestroyedIfChildrenDestroyed = 0):
		# Set our parameters...
		self.pCodeCondition = pCodeCondition
		self.sObject = sObject  # The object that contains the system.
		self.idObject = None	# ID of the object we're watching.
		self.eSystem = eSystem  # The type of system to watch.
		# Whether or not we're True if all children of this subsystem
		# are disabled.
		self.bDestroyedIfChildrenDestroyed = bDestroyedIfChildrenDestroyed
		self.lpWatchedSubsystems = []
		self.dSubsystemInfoMap = {}

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our event handler wrapper.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Set our initial state..
		self.pCodeCondition.SetStatus(0)

		# Get the object.  If it has subsystems, it needs
		# to be a ShipClass...
		pShip = App.ShipClass_GetObject(None, self.sObject)
		if pShip:
			self.SetupShipHandlers(pShip)
		else:
			# No object yet.  Add a broadcast handler on
			# the Entered Set event so we know when the
			# object is created.
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet" )

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def SetupShipHandlers(self, pShip):
		# Check if we're already setup.
		if self.idObject is not None:
			return

		# Save the ship's ID for quick lookups later..
		self.idObject = pShip.GetObjID()

		# Get the root systems we're watching..
		pPos = pShip.StartGetSubsystemMatch(self.eSystem)
		pSubsystem = pShip.GetNextSubsystemMatch(pPos)
		while pSubsystem:
			# Add this subsystem to the list of subsystems
			# we're watching.
			pInfo = SubsystemInfo(pSubsystem, None, self.dSubsystemInfoMap)
			self.lpWatchedSubsystems.append(pInfo)

			# If our flag is set, have this subsystem
			# store information about its children.
			if self.bDestroyedIfChildrenDestroyed:
				pInfo.FillChildInfo()

			# Cycle to the next subsystem...
			pSubsystem = pShip.GetNextSubsystemMatch(pPos)
		pShip.EndGetSubsystemMatch(pPos)

		self.CheckRootState()

		if len(self.lpWatchedSubsystems):
			# Add our event handler for Subsystem Disabled and
			# Subsystem Operational events for this ship.
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_SUBSYSTEM_DESTROYED, self.pEventHandler, "SystemDestroyed", pShip )

	def EnteredSet(self, pObjEvent):
		# An object has entered a set.  Is it our object?
		pShip = App.ShipClass_Cast(pObjEvent.GetDestination())
		if pShip:
			if pShip.GetName() == self.sObject:
				# This is the object we need to watch.
				self.SetupShipHandlers(pShip)

				# Remove the EnteredSet handler.
				App.g_kEventManager.RemoveBroadcastHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet" )

		self.pEventHandler.CallNextHandler( pObjEvent )

	def SystemDestroyed(self, pEvent):
		# A system on the ship has been disabled.  Is it a
		# system we care about?
		pSubsystem = App.ShipSubsystem_Cast(pEvent.GetSource())
		if pSubsystem:
			if self.dSubsystemInfoMap.has_key(pSubsystem.GetObjID()):
				# Yep, we care about this one.  Find
				# this subsystem's root subsystem, in
				# the tree of subsystems we watch, and
				# check whether or not that system is
				# disabled (destroyed).
				pSubsystemInfo = self.dSubsystemInfoMap[pSubsystem.GetObjID()]
				pSubsystemInfo.bDisabled = 1
				pRoot = pSubsystemInfo.GetRoot()

				if pRoot.IsDisabled():
					# A root is now disabled.
					# Check all our roots, to see
					# if our condition should be true.
					self.CheckRootState()

	def CheckRootState(self):
		# Check all our root subsystems.  If they're
		# all disabled, we're True.  Otherwise we're false.
		bState = 1
		for pInfo in self.lpWatchedSubsystems:
			if not pInfo.IsDisabled():
				bState = 0
				break

		if self.pCodeCondition.GetStatus() != bState:
			self.pCodeCondition.SetStatus(bState)


class SubsystemInfo:
	def __init__(self, pSubsystem, pParentInfo, dInfoMap):
		self.idSubsystem = pSubsystem.GetObjID()
		self.pParentSubsystem = pParentInfo
		self.lpChildInfo = []
		self.bDisabled = 0
		self.dInfoMap = dInfoMap

		# Add ourselves to the map of This pointers to Info.
		self.dInfoMap[self.idSubsystem] = self

	def GetRoot(self):
		if self.pParentSubsystem:
			return self.pParentSubsystem.GetRoot()
		return self

	def IsDisabled(self):
		# We're disabled if:
		#  - Our flag says we're diabled.   OR
		#  - We have children, and all our children are disabled.
		if self.bDisabled:
			return 1

		if len(self.lpChildInfo):
			# Check all our children to see if they're
			# disabled.
			bAllChildrenDisabled = 1
			for pChildInfo in self.lpChildInfo:
				if not pChildInfo.IsDisabled():
					bAllChildrenDisabled = 0
					break
			return bAllChildrenDisabled

		# Not disabled.
		return 0

	def FillChildInfo(self):
		pSubsystem = App.ShipSubsystem_Cast( App.TGObject_GetTGObjectPtr(self.idSubsystem) )
		if not pSubsystem:
			return

		for iChild in range(pSubsystem.GetNumChildSubsystems()):
			pChild = pSubsystem.GetChildSubsystem(iChild)

			# Add info for this child, and have it
			# recursively get its child info.
			pInfo = SubsystemInfo(pChild, self, self.dInfoMap)
			pInfo.FillChildInfo()
			self.lpChildInfo.append(pInfo)












