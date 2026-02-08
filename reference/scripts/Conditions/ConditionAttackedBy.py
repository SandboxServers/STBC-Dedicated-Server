#
# ConditionAttackedBy
#
# A condition that's false until the specified target
# ship takes enough damage (in a short enough time) from
# the specified firing ship.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

class ConditionAttackedBy:
	#
	# ConditionAttackedBy init
	#
	# Args:
	#	sTargetShipName	- Name of the target.  If the target is
	#			  attacked enough by the firing ship (next
	#			  arg), the condition will go true.
	#	sFiringShipName	- Name of the ship that can trigger the
	#			  condition.  It can go True if this ship
	#			  attacks the target ship enough.
	#	fShieldThreshold- Fraction of the shields that the firing
	#			  ship needs to take down for the condition
	#			  to become true.
	#	fDamageThreshold- Fraction of the ship hull (shots that
	#			  go through the shields) that can be damaged
	#			  before the condition becomes true.
	#	fForgivenessTime- If the condition is not yet true, and this
	#			  amount of time passes between shots, all
	#			  previous damage is ignored.
	#	fMemoryTime		- The condition only remembers damage that was
	#			  applied within this time.  If this is greater than zero,
	#			  it's possible for this condition to become true and then
	#			  go false again, as it forgets about damage.
	def __init__(self, pCodeCondition, sTargetShipName, sFiringShipName, fShieldThreshold, fDamageThreshold, fForgivenessTime = 0.0, fMemoryTime = 0.0):
		# Set the time we wait..
		self.pCodeCondition = pCodeCondition
		self.sTargetShip = sTargetShipName
		self.sFiringShip = sFiringShipName
		self.fShieldThreshold = fShieldThreshold
		self.fShieldDamage = 0.0
		self.dShieldDamageRecords = {}
		self.fDamageThreshold = fDamageThreshold
		self.fDamageDamage = 0.0
		self.dDamageDamageRecords = {}
		self.fForgivenessTime = fForgivenessTime
		self.idForgivenessTimer = App.NULL_ID
		self.fMemoryTime = fMemoryTime

		self.iRecordID = 0

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Our initial state is false.
		self.pCodeCondition.SetStatus(0)

		# Setup our event handler...
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# We need to listen in on damage events.
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_WEAPON_HIT, self.pEventHandler, "DamageEvent" )

		# And we need to listen for our timer event.
		self.pEventHandler.AddPythonMethodHandlerForInstance( App.ET_CONDITION_ATK_FORGIVE, "Forgive" )

		# And the damage removal event.
		self.pEventHandler.AddPythonMethodHandlerForInstance( App.ET_CONDITION_ATK_REMOVE_DAMAGE, "RemoveDamage" )

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def DamageEvent(self, pEvent):
		# Check if the destination matches the target ship.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		if (pShip != None):
			if pShip.GetName() == self.sTargetShip:
				# Matched the ship.  Is the source of
				# the shot the ship we're watching for?
				pSource = pEvent.GetFiringObject()

				if (pSource != None) and pSource.GetName() == self.sFiringShip:
					# Yep, this is the ship we're
					# looking for.  Add its damage..
					# Need to figure out which function
					# to call..
					if (pEvent.IsHullHit() == 1):
						pDamageFunc = self.AddShipDamage
					else:
						pDamageFunc = self.AddShieldDamage

					pDamageFunc(pEvent, pShip)

		self.pEventHandler.CallNextHandler(pEvent)

	def Forgive(self, pEvent):
		# Forgive the firing ship all the damage it's done
		# up until now.
		self.fShieldDamage = 0.0
		self.dShieldDamageRecords = {}
		self.fDamageDamage = 0.0
		self.dDamageDamageRecords = {}

		#debug("Damage forgiven.")

	def RemoveDamage(self, pEvent):
		# Remove a damage record from our memory.
		idRecord = pEvent.GetInt()
		#debug("Removing damage %d" % idRecord)

		try:
			# Try removing it from the shield damage records.
			fTime, fDamage = self.dShieldDamageRecords[idRecord]
			del self.dShieldDamageRecords[idRecord]

			# Successful removal.  Recalculate total shield damage (can't just
			# subtract fDamage, due to floating point error).
			self.fShieldDamage = 0.0
			for fTime, fDamage in self.dShieldDamageRecords.values():
				self.fShieldDamage = self.fShieldDamage + fDamage

			#debug("Removed %f shield damage (now %f)" % (fDamage, self.fShieldDamage))
		except KeyError:
			pass

		try:
			# Try removing it from the hull damage records.
			fTime, fDamage = self.dDamageDamageRecords[idRecord]
			del self.dDamageDamageRecords[idRecord]

			# Successful removal.  Recalculate total hull damage (can't just
			# subtract fDamage, due to floating point error).
			self.fDamageDamage = 0.0
			for fTime, fDamage in self.dDamageDamageRecords.values():
				self.fDamageDamage = self.fDamageDamage + fDamage

			#debug("Removed %f hull damage (now %f)" % (fDamage, self.fDamageDamage))
		except KeyError:
			pass

		# Check the value of our condition again.
		if ((self.fShieldDamage < self.fShieldThreshold)  or  (self.fShieldDamage == 0.0))  and  ((self.fDamageDamage < self.fDamageThreshold)  or  (self.fDamageDamage == 0.0)):
			# The condition should now be false.
			if self.pCodeCondition.GetStatus() != 0:
				#debug("Changing condition back to false.")
				self.pCodeCondition.SetStatus(0)

	def AddShieldDamage(self, pEvent, pShip):
		# Add the specified amount of damage to the shield
		# damage we're tracking, and restart the forgiveness
		# timer.

		# Find out how much damage was caused, from the
		# information in the event.  And apply the damage..
		# This needs to be a percentage (or a fraction of 1.0).
		pShields = pShip.GetShields()
		fMaxShield = pShields.GetMaxShields( App.ShieldClass.FRONT_SHIELDS )
		if fMaxShield <= 0:	# Just in case.
			fMaxShield = 1.0
		fDamage = pEvent.GetDamage() / fMaxShield

		self.fShieldDamage = self.fShieldDamage + fDamage

		# Log this damage and the time it occurred.
		self.dShieldDamageRecords[self.iRecordID] = ( App.g_kUtopiaModule.GetGameTime(), fDamage )

		# Add a timer to remove this damage after fMemoryTime time passes.
		if self.fMemoryTime > 0.0:
			self.AddDamageRemovalTimer(self.iRecordID)
		self.iRecordID = self.iRecordID + 1
		
		# Stop the forgiveness timer.
		self.StopForgivenessTimer()

		# Check if the shield damage has passed its threshold..
		if self.fShieldDamage >= self.fShieldThreshold:
			# Yep.  This condition is now True.
			if self.pCodeCondition.GetStatus() != 1:
				self.pCodeCondition.SetStatus(1)
		else:
			# Nope, it's still under the threshold.
			# Start the forgiveness timer again.
			self.StartForgivenessTimer()

	def AddShipDamage(self, pEvent, pShip):
		"Add the specified amount of damage to the ship"
		"damage we're tracking, and restart the forgiveness"
		"timer."
		# Find out how much damage was caused, from the
		# information in the event.  And apply the damage..
		# This is calculated as a percentage of the maximum
		# hull value (even if the damage isn't done to the hull).
		pHull = pShip.GetHull()
		fMaxHull = pHull.GetMaxCondition()
		if fMaxHull <= 0:	# Just in case
			fMaxHull = 1.0
		fDamage = pEvent.GetDamage() / fMaxHull
		self.fDamageDamage = self.fDamageDamage + fDamage

		# Log this damage and the time it occurred.
		self.dDamageDamageRecords[self.iRecordID] = ( App.g_kUtopiaModule.GetGameTime(), fDamage )

		# Add a timer to remove this damage after fMemoryTime time passes.
		if self.fMemoryTime > 0.0:
			self.AddDamageRemovalTimer(self.iRecordID)
		self.iRecordID = self.iRecordID + 1

		#debug("Ship damage at %f/%f" % (self.fDamageDamage, self.fDamageThreshold))
		
		# Stop the forgiveness timer.
		self.StopForgivenessTimer()

		# Check if the shield damage has passed its threshold..
		if self.fDamageDamage >= self.fDamageThreshold:
			# Yep.  This condition is now True.
			if self.pCodeCondition.GetStatus() != 1:
				self.pCodeCondition.SetStatus(1)
		else:
			# Nope, it's still under the threshold.
			# Start the forgiveness timer again.
			self.StartForgivenessTimer()

	def StartForgivenessTimer(self):
		if self.fForgivenessTime <= 0.0:
			return

		# Create the event for the timer.
		pEvent = App.TGEvent_Create()
		pEvent.SetDestination( self.pEventHandler )
		pEvent.SetEventType( App.ET_CONDITION_ATK_FORGIVE )

		# Figure out what time it is...
		fTime = App.g_kUtopiaModule.GetGameTime()
		fStartTime = fTime + self.fForgivenessTime

		#debug("Start time is %f (from %f)" % (fStartTime, fTime))


		# Create the timer.
		pTimer = App.TGTimer_Create()
		pTimer.SetTimerStart( fStartTime )
		pTimer.SetEvent( pEvent )

		# Add the timer to the queue..
		if App.g_kTimerManager.AddTimer( pTimer ):
			# Added the timer successfully.
			self.idForgivenessTimer = pTimer.GetObjID()
#		else:
			# Unable to add the timer..  :(
#			debug(__name__ + ": Error, couldn't add timer.")

	def StopForgivenessTimer(self):
		if (self.idForgivenessTimer != App.NULL_ID):
			App.g_kTimerManager.DeleteTimer(self.idForgivenessTimer)
			self.idForgivenessTimer = App.NULL_ID

	def AddDamageRemovalTimer(self, iRecordID):
		# Add a timer that says to remove a certain damage record from our memory.
		pEvent = App.TGIntEvent_Create()
		pEvent.SetDestination(self.pEventHandler)
		pEvent.SetEventType( App.ET_CONDITION_ATK_REMOVE_DAMAGE )
		pEvent.SetInt(iRecordID)

		pTimer = App.TGTimer_Create()
		pTimer.SetTimerStart( App.g_kUtopiaModule.GetGameTime() + self.fMemoryTime )
		pTimer.SetEvent(pEvent)

		App.g_kTimerManager.AddTimer(pTimer)























