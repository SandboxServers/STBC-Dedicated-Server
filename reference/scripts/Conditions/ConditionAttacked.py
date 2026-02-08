#
# ConditionAttacked
#
# A condition that's false until the specified target
# ship takes enough damage (in a short enough time) from
# any other ship.  Use the GetTargetList function to get
# a list of ships that have attacked the target.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

class ConditionAttacked:
	#
	# ConditionAttackedBy init
	#
	# Args:
	#	sTargetShipName	- Name of the target.  If the target is
	#			  attacked enough by the firing ship (next
	#			  arg), the condition will go true.
	#	fShieldThreshold- Fraction of the shields that the firing
	#			  ship needs to take down for the condition
	#			  to become true.
	#	fDamageThreshold- Fraction of the ship hull (shots that
	#			  go through the shields) that can be damaged
	#			  before the condition becomes true.
	#	fForgivenessTime- If the condition is not yet true, and this
	#			  amount of time passes between shots, all
	#			  previous damage is ignored.
	def __init__(self, pCodeCondition, sTargetShipName, fShieldThreshold, fDamageThreshold, fForgivenessTime):
		# Set the time we wait..
		self.pCodeCondition = pCodeCondition
		self.sTargetShip = sTargetShipName
		self.fShieldThreshold = fShieldThreshold
		self.dfShieldDamage = {}
		self.fDamageThreshold = fDamageThreshold
		self.dfDamageDamage = {}
		self.fForgivenessTime = fForgivenessTime
		self.idForgivenessTimer = {}

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Our initial state is false.
		self.pCodeCondition.SetStatus(0)

		# Setup our event handler...
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# We need to listen in on damage events.
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_WEAPON_HIT, self.pEventHandler, "DamageEvent")

		# And we need to listen for our timer event.
		self.pEventHandler.AddPythonMethodHandlerForInstance( App.ET_CONDITION_ATK_FORGIVE, "Forgive" )

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def GetTargetList(self):
		# Look through the ships that have attacked us and
		# find the ships that have done enough damage to
		# have triggered the condition True.
		lsTargets = []
		# Add objects that have taken down enough of our shields...
		for sObject, fShieldDamage in self.dfShieldDamage.items():
			if fShieldDamage > self.fShieldThreshold:
				lsTargets.append(sObject)

		# Add objects that have destroyed enough of our ship...
		for sObject, fDamage in self.dfDamageDamage.items():
			if fDamage > self.fDamageThreshold:
				if not sObject in lsTargets:
					lsTargets.append(sObject)

		return lsTargets

	def DamageEvent(self, pEvent):
		# Check if the destination matches the target ship.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		if not App.IsNull(pShip):
			if pShip.GetName() == self.sTargetShip:
				# Matched the ship.  Record the damage..
				# Apply damage from this source.
				if (pEvent.IsHullHit() == 1):
					pDamageFunc = self.AddShipDamage
				else:
					pDamageFunc = self.AddShieldDamage

				pDamageFunc(pEvent, pShip)

		self.pEventHandler.CallNextHandler(pEvent)

	def Forgive(self, pEvent):
		# Forgive the firing ship all the damage it's done
		# up until now.
		sObject = pEvent.GetCString()

		self.dfShieldDamage[sObject] = 0.0
		self.dfDamageDamage[sObject] = 0.0

		#kDebugObj.Print("Damage for %s forgiven." % sObject)

	def AddShieldDamage(self, pEvent, pShip):
		"Add the specified amount of damage to the shield"
		"damage we're tracking, and restart the forgiveness"
		"timer for this source."
		# Get the name of the firing object.
		pSource = pEvent.GetFiringObject()
		if pSource:
			sName = pSource.GetName()

			# Find out how much damage was caused, from the
			# information in the event.  And record the damage..
			pShields = pShip.GetShields()
			fMaxShield = pShields.GetMaxShields( App.ShieldClass.FRONT_SHIELDS )
			if fMaxShield <= 0:	# Just in case.
				fMaxShield = 1.0
			fDamage = pEvent.GetDamage() / fMaxShield

			# Add the damage to the damage that's already been
			# caused by this ship.
			fOldDamage = 0.0
			if self.dfShieldDamage.has_key(sName):
				fOldDamage = self.dfShieldDamage[sName]

			self.dfShieldDamage[sName] = fOldDamage + fDamage

			#kDebugObj.Print("Shield damage from %s at %f/%f" % (sName, self.dfShieldDamage[sName], self.fShieldThreshold))

			# Stop the forgiveness timer for this source.
			self.StopForgivenessTimer(sName)

			# Check if the shield damage has passed its threshold..
			if self.dfShieldDamage[sName] >= self.fShieldThreshold:
				# Yep.  This condition is now True.
				if self.pCodeCondition.GetStatus() != 1:
					self.pCodeCondition.SetStatus(1)
			else:
				# Nope, it's still under the threshold.
				# Start the forgiveness timer again.
				self.StartForgivenessTimer(sName)

	def AddShipDamage(self, pEvent, pShip):
		"Add the specified amount of damage to the ship"
		"damage we're tracking, and restart the forgiveness"
		"timer."
		# Get the name of the firing object.
		pSource = pEvent.GetFiringObject()
		if pSource:
			sName = pSource.GetName()

			# Find out how much damage was caused, from the
			# information in the event.  And record the damage..
			pHull = pShip.GetHull()
			fMaxHull = pHull.GetMaxCondition()
			if fMaxHull <= 0:	# Just in case
				fMaxHull = 1.0
			fDamage = pEvent.GetDamage() / fMaxHull

			# Add the damage to the damage that's already been
			# caused by this ship
			fOldDamage = 0.0
			if self.dfDamageDamage.has_key(sName):
				fOldDamage = self.dfDamageDamage[sName]
			self.dfDamageDamage[sName] = fOldDamage + fDamage

			#kDebugObj.Print("Ship damage for %s at %f/%f" % (sName, self.dfDamageDamage[sName], self.fDamageThreshold))
		
			# Stop the forgiveness timer for this source.
			self.StopForgivenessTimer(sName)

			# Check if the shield damage has passed its threshold..
			if self.dfDamageDamage[sName] >= self.fDamageThreshold:
				# Yep.  This condition is now True.
				if self.pCodeCondition.GetStatus() != 1:
					self.pCodeCondition.SetStatus(1)
			else:
				# Nope, it's still under the threshold.
				# Start the forgiveness timer again.
				self.StartForgivenessTimer(sName)

	def StartForgivenessTimer(self, sSource):
		# Create the event for the timer.
		pEvent = App.TGStringEvent_Create()
		pEvent.SetDestination( self.pEventHandler )
		pEvent.SetEventType( App.ET_CONDITION_ATK_FORGIVE )
		pEvent.SetString(sSource)

		# Figure out what time it is...
		fTime = App.g_kUtopiaModule.GetGameTime()
		fStartTime = fTime + self.fForgivenessTime

		# Create the timer.
		pTimer = App.TGTimer_Create()
		pTimer.SetTimerStart( fStartTime )
		pTimer.SetEvent( pEvent )

		# Add the timer to the queue..
		if App.g_kTimerManager.AddTimer( pTimer ):
			# Added the timer successfully.
			self.idForgivenessTimer[sSource] = pTimer.GetObjID()
#		else:
			# Unable to add the timer..  :(
#			kDebugObj.Print(__name__ + ": Error, couldn't add timer.")

	def StopForgivenessTimer(self, sName):
		iTimer = None
		try:
			iTimer = self.idForgivenessTimer[sName]
		except KeyError:
			pass

		if iTimer is not None:
			App.g_kTimerManager.DeleteTimer(iTimer)
			self.idForgivenessTimer[sName] = None

























