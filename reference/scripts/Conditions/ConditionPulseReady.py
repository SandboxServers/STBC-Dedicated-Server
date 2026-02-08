#
# ConditionPulseReady
#
# A condition that's true as long as the specified object
# has at least one pulse weapon ready.  This can be restricted so
# it only pays attention to pulse weapons that fire in a certain
# direction (such as Forward), or it can count all pulse weapons.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading Condition module (%s)...\n" % __name__)

# Event types only used in this file.
ET_CHARGE_TOGGLE = App.UtopiaModule_GetNextEventType()

class ConditionPulseReady:
	def __init__(self, pCodeCondition, sObjectName, vDirectionRestriction = None):
		# Set params...
		self.sObjectName = sObjectName
		self.iObjectID = App.NULL_ID
		self.vDirectionRestriction = vDirectionRestriction
		self.pCodeCondition = pCodeCondition

		self.dRangeCheckIDs = {}
		self.lpCachedWeapons = None

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Determine our initial state.
		self.SetupInitialState()

		# Setup our event handlers.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)
		self.SetupEventHandlers()

	def __del__(self):
		# Remove our range checks..
		if self.dRangeCheckIDs:
			if self.iObjectID != App.NULL_ID:
				pShip = App.ShipClass_GetObjectByID(None, self.iObjectID)
				if pShip:
					for pWeapon in self.GetWeapons(pShip):
						idCheck = self.dRangeCheckIDs[ pWeapon.GetObjID() ]
						pWatcher = pWeapon.GetChargeWatcher()
						pWatcher.RemoveRangeCheck( idCheck )

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
		if pObject:
			# Yup, it exists.  Save its ID for later...
			self.iObjectID = pObject.GetObjID()

			# Check the current state of our object.
			pShip = App.ShipClass_Cast(pObject)
			if pShip:
				# It's a ship.  Check number of torps,
				# so we can set our state.
				self.SetStateFromWeapons(pShip)

	def SetupEventHandlers(self):
		# Does our object exist?
		if self.iObjectID != App.NULL_ID:
			# Yep, it should.
			pShip = App.ShipClass_GetObjectByID(None, self.iObjectID)
			if pShip:
				# We need a broadcast handler listening
				# for when any of this object's pulse weapons are ready
				# to fire, or not ready.  Get all the weapons...
				lpWeapons = self.GetWeapons(pShip)
				if lpWeapons:
					for pWeapon in lpWeapons:
						# Add event handlers for this pulse weapon.
						self.AddHandlersToPulseWeapon(pWeapon)

					# Keep track of the disabled status of the overall
					# pulse weapon system.
					pPulseSystem = pShip.GetPulseWeaponSystem()
					if pPulseSystem:
						App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_SUBSYSTEM_DISABLED, self.pEventHandler, "WeaponSystemDisabled", pPulseSystem )
						App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_SUBSYSTEM_OPERATIONAL, self.pEventHandler, "WeaponSystemEnabled", pPulseSystem )
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
				self.SetStateFromWeapons(pObject)
				
				# Remove our Entered Set event handler.
				App.g_kEventManager.RemoveBroadcastHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet" )

				# And add the new handlers that we need...
				self.SetupEventHandlers()

	def GetWeapons(self, pShip):
		if self.lpCachedWeapons is None:
			self.lpCachedWeapons = []

			# Get the torpedo system...
			pPulseSystem = pShip.GetPulseWeaponSystem()
			if pPulseSystem:
				for iChild in range( pPulseSystem.GetNumChildSubsystems() ):
					pWeapon = App.PulseWeapon_Cast(pPulseSystem.GetChildSubsystem(iChild))
					if pWeapon:
						# Got a pulse weapon.  If we're using
						# direction restrictions, check if this
						# tube is pointing in a good direction.
						if self.vDirectionRestriction:
							vDirection = App.PulseWeaponProperty_Cast( pWeapon.GetProperty() ).GetOrientationForward()
							fDot = self.vDirectionRestriction.Dot( vDirection )
							if fDot >= 0.66:
								# It's facing the right
								# direction.  Add it.
								self.lpCachedWeapons.append(pWeapon)
						else:
							self.lpCachedWeapons.append(pWeapon)

		return self.lpCachedWeapons

	def AddHandlersToPulseWeapon(self, pWeapon):
		# Add all the handlers we need for this pulse weapon.
		self.pEventHandler.AddPythonMethodHandlerForInstance( ET_CHARGE_TOGGLE, "ChargeToggled" )
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_SUBSYSTEM_DISABLED, self.pEventHandler, "WeaponDisabled", pWeapon )
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_SUBSYSTEM_OPERATIONAL, self.pEventHandler, "WeaponEnabled", pWeapon )

		# Add a float range watcher event to this weapon, so we
		# know when it has enough of a charge to fire.
		pEvent = App.TGFloatEvent_Create()
		pEvent.SetDestination( self.pEventHandler )
		pEvent.SetEventType( ET_CHARGE_TOGGLE )
		pEvent.SetSource( pWeapon.GetParentShip() )

		pWatcher = pWeapon.GetChargeWatcher()
		# The watcher watches the charge percentage.  Find the percentage
		# needed to fire the weapon...
		fChargePercent = pWeapon.GetMinFiringCharge() / pWeapon.GetMaxCharge()
		self.dRangeCheckIDs[pWeapon.GetObjID()] = pWatcher.AddRangeCheck( fChargePercent, App.FloatRangeWatcher.FRW_BOTH, pEvent )

	def ChargeToggled(self, pEvent):
		# Our float range watcher on one of the pulse weapons' charge values
		# has been toggled.  Check our current state.
		self.SetStateFromWeapons(App.ShipClass_Cast( pEvent.GetSource() ) )
		self.pEventHandler.CallNextHandler(pEvent)

	def SetStateFromWeapons(self, pShip):
		bState = 0

		# Check if the overall system is disabled.
		pSystem = pShip.GetPulseWeaponSystem()
		if pSystem and (not pSystem.IsDisabled()):
			# Get the pulse weapons..
			lpWeapons = self.GetWeapons(pShip)
			for pWeapon in lpWeapons:
				# We need to check whether or not this weapon is ready to fire.
				if (not pWeapon.IsDisabled())  and  (pWeapon.GetChargeLevel() > pWeapon.GetMinFiringCharge()):
					# Make sure its parent system isn't disabled...
					pSystem = pWeapon.GetParentSubsystem()
					if (not pSystem)  or  (not pSystem.IsDisabled()):
						# Parent system isn't disabled.
						bState = 1
						break

		# Update our status..
		if self.pCodeCondition.GetStatus() != bState:
			self.pCodeCondition.SetStatus(bState)

	def WeaponDisabled(self, pEvent):
		# One of our pulse weapons has been disabled.  Doh.
		# Check our state.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		if pShip:
			# Got the ship.  Check our state.
			self.SetStateFromWeapons(pShip)
			
	def WeaponEnabled(self, pEvent):
		# One of our weapons has been re-enabled.  Yaaay.
		# Check our state.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		if pShip:
			# Got the ship.  Check our state.
			self.SetStateFromWeapons(pShip)

	def WeaponSystemDisabled(self, pEvent):
		# The pulse weapon system has been disabled.  Set our condition to false.
		if self.pCodeCondition.GetStatus() != 0:
			self.pCodeCondition.SetStatus(0)

	def WeaponSystemEnabled(self, pEvent):
		# The pulse weapon system has been re-enabled.  Yaay.
		# Check our state.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		if pShip:
			# Got the ship.  Check our state.
			self.SetStateFromWeapons(pShip)












