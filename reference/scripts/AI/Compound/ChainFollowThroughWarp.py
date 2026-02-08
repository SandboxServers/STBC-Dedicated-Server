import App

#NonSerializedObjects = ( "debug", )
#debug = App.CPyDebug(__name__).Print

ET_CHAIN_FOLLOW_CONDITION_CHANGED = App.UtopiaModule_GetNextEventType()

class ChooseFollowTarget:
	def __init__(self, lShipNames, sOurName):
		# Save the list of ship names..
		self.lShipNames = list(lShipNames)
		self.sOurName = sOurName
		self.sTarget = None
		self.bUpdateTargets = 0

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup event handling...
 		self.pEventHandler = App.TGPythonInstanceWrapper()
 		self.pEventHandler.SetPyWrapper(self)
		self.SetupEventHandlers()

	def CodeAISet(self):
		# Determine which ship we need to try to follow.
		self.SetFollowTarget()

	def SetupEventHandlers(self):
		self.lConditionEventCreators = []

		# Add a handler for our ET_CHAIN_FOLLOW_CONDITION_CHANGED event.
		self.pEventHandler.AddPythonMethodHandlerForInstance(ET_CHAIN_FOLLOW_CONDITION_CHANGED, "ConditionChanged")

		# We need an event handler listening on a ConditionExists and a ConditionSystemDisabled(CT_WARP)
		# on each of the ships that we may need to follow.
		for sShip in self.lShipNames:
			# We can stop adding handlers once we hit our ship.
			if sShip == self.sOurName:
				break

			# Add conditions watching this ship.
			pExists = App.ConditionScript_Create("Conditions.ConditionExists", "ConditionExists", sShip)
			pWarpDisabled = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", sShip, App.CT_WARP_ENGINE_SUBSYSTEM)

			# Can't have too many conditions on any 1 condition handler, so split this into
			# 1 condition event creator per ship we're watching.  There's no significant speed difference.
			pConditionEventCreator = self.CreateConditionEventCreator()
			pConditionEventCreator.AddCondition(pExists)
			pConditionEventCreator.AddCondition(pWarpDisabled)

			self.lConditionEventCreators.append(pConditionEventCreator)

	def CreateConditionEventCreator(self):
		# Add an object to send us an event whenever one of our conditions changes...
		pConditionEventCreator = App.ConditionEventCreator()

		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(ET_CHAIN_FOLLOW_CONDITION_CHANGED)
		pEvent.SetDestination(self.pEventHandler)
		pConditionEventCreator.SetEvent(pEvent)

		return pConditionEventCreator

	def ConditionChanged(self, pEvent):
		# One of our conditions has changed.  We may need to update our target...
		self.SetFollowTarget()
		if self.bUpdateTargets:
			# Need to update the AI.
			self.pCodeAI.ForceUpdate()
		# No need to call next handler.  We're the only handler for this event.

	def GetNextUpdateTime(self):
		# Rarely updated unless events update us..
		return 3600.0

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def Update(self, dEndTime):
		self.pCodeAI.ForceDormantStatus(App.PreprocessingAI.FDS_NORMAL)

		self.SetFollowTarget()
		if self.sTarget is None:
			# No available targets.  Sit dormant.
			return App.PreprocessingAI.PS_SKIP_DORMANT

		if self.bUpdateTargets:
			#debug("Changed ChainFollowThroughWarp target for (%s) to (%s)" % (self.sOurName, self.sTarget))
			self.UpdateTargets()

		return App.PreprocessingAI.PS_NORMAL

	def SetFollowTarget(self):
		# Look through our list, starting at our name and moving toward the beginning,
		# trying to find the first ship that's alive and capable of warping.  If it's
		# not already our target, switch our target so it is.
		sTarget = None
		try:
			iIndex = self.lShipNames.index(self.sOurName)
		except ValueError:
			iIndex = len(self.lShipNames)

		# Look down through the list...
		while iIndex > 0:
			# Get the next ship name...
			iIndex = iIndex - 1
			sShip = self.lShipNames[iIndex]

			# Get this ship, if it still exists.
			pShip = App.ShipClass_GetObject(None, sShip)
			if not pShip:
				continue

			# Got the ship.  Is the ship warp-capable?
			pWarpEngines = pShip.GetWarpEngineSubsystem()
			if (not pWarpEngines)  or  (pWarpEngines.IsDisabled()):
				continue

			# Yep, it's warp-capable.  This should be our target.
			sTarget = sShip
			break

		#debug("Chose Follow target (%s) from %s for (%s)" % (sTarget, self.lShipNames, self.sOurName))

		# Check if our target changed...
		if sTarget != self.sTarget:
			# Yeap, the target has changed.  Next update, we'll need
			# to update the AI's we contain.
			self.sTarget = sTarget
			self.bUpdateTargets = 1
			self.pCodeAI.ForceDormantStatus(App.PreprocessingAI.FDS_FALSE)

	def UpdateTargets(self):
		# Get the AI's we contain, and need to update...
		lAIs = self.pCodeAI.GetAllAIsInTree()[1:]
		for pAI in lAIs:
			pAI.CallExternalFunction("SetTarget", self.sTarget)

		# Done.  Targets have been updated.
		self.bUpdateTargets = 0

def CreateAI(pShip, lShipNames):
	#########################################
	# Creating CompoundAI FollowThroughWarp at (171, 132)
	import AI.Compound.FollowThroughWarp
	pFollowThroughWarp = AI.Compound.FollowThroughWarp.CreateAI(pShip, pShip.GetName())
	# Done creating CompoundAI FollowThroughWarp
	#########################################
	#########################################
	# Creating PreprocessingAI SelectFollowTarget at (130, 188)
	## Setup:
	pPreprocess = ChooseFollowTarget( lShipNames, pShip.GetName() )
	## The PreprocessingAI:
	pSelectFollowTarget = App.PreprocessingAI_Create(pShip, "SelectFollowTarget")
	pSelectFollowTarget.SetInterruptable(1)
	pSelectFollowTarget.SetPreprocessingMethod(pPreprocess, "Update")
	pSelectFollowTarget.SetContainedAI(pFollowThroughWarp)
	# Done creating PreprocessingAI SelectFollowTarget
	#########################################
	return pSelectFollowTarget
