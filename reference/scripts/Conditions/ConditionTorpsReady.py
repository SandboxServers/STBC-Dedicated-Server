#
# ConditionTorpsReady
#
# A condition that's true as long as the specified object
# has at least one torpedo ready.  This can be restricted so
# it only pays attention to torpedoes that fire in a certain
# direction (such as Forward), or it can count all torpedoes.
#
# ***NOTE: This class is never used.  There is an optimized
#          version of this class that is created in place of
#          this, any time ConditionScript_Create is called.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading Condition module (%s)...\n" % __name__)

class ConditionTorpsReady:
	def __init__(self, pCodeCondition, sObjectName, vDirectionRestriction = None):
		# Set params...
		self.sObjectName = sObjectName
		self.iObjectID = App.NULL_ID
		self.vDirectionRestriction = vDirectionRestriction
		self.pCodeCondition = pCodeCondition
		self.lpCachedTubes = None

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Determine our initial state.
		self.SetupInitialState()

		# Setup our event handlers.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)
		self.SetupEventHandlers()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def SetupInitialState(self):
		# By default we're false.
		self.pCodeCondition.SetStatus(0)

		# Check if our object exists yet.
		pObject = App.ObjectClass_GetObject(None, self.sObjectName)
		if (pObject != None):
			# Yup, it exists.  Save its ID for later...
			self.iObjectID = pObject.GetObjID()

			# If this is a ship, we can check the number
			# of active torps...
			pShip = App.ShipClass_Cast(pObject)
			if (pShip != None):
				# It's a ship.  Check number of torps,
				# so we can set our state.
				self.SetStateFromTorpCount(pShip)

	def SetupEventHandlers(self):
		# Does our object exist?
		if self.iObjectID != App.NULL_ID:
			# Yep, it does.  We need a broadcast handler listening
			# for when any of this object's torpedo tubes gets a
			# Torpedo Reload event.
			pShip = App.ShipClass_GetObjectByID(None, self.iObjectID)
			if pShip:
				# Add a broadcast handler so we know when one of the ship's systems is disabled.
				# If it's a torpedo system or tube, we'll do some special handling.
				App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_SUBSYSTEM_DISABLED, self.pEventHandler, "ShipSystemDisabled", pShip )
				App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_SUBSYSTEM_OPERATIONAL, self.pEventHandler, "ShipSystemEnabled", pShip )

				lpTubes = self.GetTorpedoTubes(pShip)
				if lpTubes:
					for pTube in lpTubes:
						# Add event handlers for this tube.
						self.AddHandlersToTube(pTube)
		else:
			# The object doesn't exist yet.  We need a handler
			# to listen for when the object enters the set.
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet" )

	def EnteredSet(self, pEvent):
		# An object has entered the set.  Is it the object
		# we're looking for?
		pObject = App.ShipClass_Cast(pEvent.GetDestination())
		if pObject:
			if pObject.GetName() == self.sObjectName:
				# Yep, it's our object.  Save its ID.
				self.iObjectID = pObject.GetObjID()

				# Update our current state...
				self.SetStateFromTorpCount(pObject)
				
				# Remove our Entered Set event handler.
				App.g_kEventManager.RemoveBroadcastHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet" )

				# And add the new handlers that we need...
				self.SetupEventHandlers()

		self.pEventHandler.CallNextHandler(pEvent)

	def GetTorpedoTubes(self, pShip):
		if self.lpCachedTubes is None:
			self.lpCachedTubes = []

			# Get the torpedo system...
			pTorpSystem = pShip.GetTorpedoSystem()
			if (pTorpSystem != None):
				for iChild in range( pTorpSystem.GetNumChildSubsystems() ):
					pTube = pTorpSystem.GetChildSubsystem(iChild)
					pTube = App.TorpedoTube_Cast(pTube)
					if pTube:
						# Got a torpedo tube.  If we're using
						# direction restrictions, is this tube
						# pointing in a good direction?
						if self.vDirectionRestriction:
							fDot = self.vDirectionRestriction.Dot( pTube.GetDirection() )
							if fDot >= 0.66:
								# It's facing the right
								# direction.  Add it.
								self.lpCachedTubes.append(pTube)
						else:
							self.lpCachedTubes.append(pTube)

		return self.lpCachedTubes

	def AddHandlersToTube(self, pTube):
		# Add all the handlers we need for this torpedo tube.
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_TORPEDO_RELOAD, self.pEventHandler, "TorpReloaded", pTube )
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_TORPEDO_FIRED, self.pEventHandler, "TorpFired", pTube )

	def SetStateFromTorpCount(self, pShip):
		bState = 0

		# Get the torpedo tubes...
		lpTubes = self.GetTorpedoTubes(pShip)
		for pTube in lpTubes:
			# We need to count the number of torps ready in
			# this tube. If there's at least one ready, our
			# state needs to be True.
			if (not pTube.IsDisabled())  and  (pTube.GetNumReady() > 0):
				# Make sure its parent system isn't disabled...
				pSystem = pTube.GetParentSubsystem()
				if (not pSystem)  or  (not pSystem.IsDisabled()):
					# Parent system isn't disabled.
					bState = 1
					break

		# Update our status..
		if self.pCodeCondition.GetStatus() != bState:
			self.pCodeCondition.SetStatus(bState)

	def TorpReloaded(self, pEvent):
		# One of our torps was reloaded.  As long as
		# this tube isn't disabled (and the overall system
		# isn't disabled), we should
		# be true now.
		pTube = App.TorpedoTube_Cast(pEvent.GetDestination())
		if pTube  and  (not pTube.IsDisabled()):
			pSystem = pTube.GetParentSubsystem()
			if (not pSystem)  or  (not pSystem.IsDisabled()):
				if self.pCodeCondition.GetStatus() != 1:
					self.pCodeCondition.SetStatus(1)

		self.pEventHandler.CallNextHandler(pEvent)

	def TorpFired(self, pEvent):
		# One of our torps was fired.  Check the number
		# of torps remaining to see what our current
		# state is.
		pTube = App.TorpedoTube_Cast(pEvent.GetDestination())
		if pTube:
			pShip = pTube.GetParentShip()
			if pShip:
				# Got the ship.  Check our state.
				self.SetStateFromTorpCount(pShip)

		self.pEventHandler.CallNextHandler(pEvent)

	def ShipSystemDisabled(self, pEvent):
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		pSystem = pEvent.GetSource()

		# If this system is the ship's torpedo system, call TorpSystemDisabled.
		pTorpSystem = pShip.GetTorpedoSystem()
		if pTorpSystem  and  (pSystem.GetObjID() == pTorpSystem.GetObjID()):
			# It's the ship's torpedo system.
			self.TorpSystemDisabled()
			return

	def ShipSystemEnabled(self, pEvent):
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		pSystem = pEvent.GetSource()

		# If this system is the ship's torpedo system, call TorpSystemEnabled.
		pTorpSystem = pShip.GetTorpedoSystem()
		if pTorpSystem  and  (pSystem.GetObjID() == pTorpSystem.GetObjID()):
			# It's the ship's torpedo system.
			self.TorpSystemEnabled(pShip)
			return

	def TorpTubeDisabled(self, pEvent):
		# One of our torp tubes has been disabled.  Doh.
		# Check our state.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		if pShip:
			# Got the ship.  Check our state.
			self.SetStateFromTorpCount(pShip)
			
	def TorpTubeEnabled(self, pEvent):
		# One of our torp tubes has been re-enabled.  Yaaay.
		# Check our state.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		if pShip:
			# Got the ship.  Check our state.
			self.SetStateFromTorpCount(pShip)

	def TorpSystemDisabled(self):
		# The torpedo system has been disabled.  Set our condition to false.
		self.pCodeCondition.SetStatus(0)

	def TorpSystemEnabled(self, pShip):
		# The torpedo system has been re-enabled.  Yaay.
		# Check our state.
		self.SetStateFromTorpCount(pShip)












