#
# ConditionSingleShieldBelow
#
# A condition that's true when a given object's overall shield level
# is below a certain amount.
#
import App

#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading ' + __name__ + ' Condition module...')

class ConditionSingleShieldBelow:
	def __init__(self, pCodeCondition, sObjectName, fShieldFraction, eWhichShield):
		# Set our object name and parameters...
		self.sObjectName = sObjectName
		self.fShieldFraction = fShieldFraction
		self.eShieldSide = eWhichShield
		self.pCodeCondition = pCodeCondition
		self.iRangeID = None

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our event handlers.  We need to trigger (and handle)
		# an event when the object's shields reach a certain level.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)
		
		# Set our initial state..
		self.SetInitialState()

		# Since the event is being sent to us, we just need
		# an instance handler.			
		self.pEventHandler.AddPythonMethodHandlerForInstance( App.ET_AI_SHIELD_WATCHER, "ShieldEvent" )

	# Need to call this explicitly, if you want SetTarget to affect this.
	def RegisterSetTarget(self, pAI):
		pAI.RegisterExternalFunction("SetTarget", { "CodeID" : self.pCodeCondition.GetObjID(), "FunctionName" : "SetTarget" })

	def SetTarget(self, sTarget):
		# Change self.sObjectName.
		if self.sObjectName != sTarget:
			self.SetObjectName(sTarget)

	def __del__(self):
		# We need to remove our shield watcher, if the object
		# it's attached to is still around, so it doesn't send
		# us any more events.
		self.RemoveShieldWatcher()

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def RemoveShieldWatcher(self):
		"Remove the shield watcher from our target..."
		pObject = App.ShipClass_GetObject(App.SetClass_GetNull(), self.sObjectName)
		if pObject:
			# The object still exists.  Get the shields...
			pShields = pObject.GetShields()

			# And remove our range watcher...
			pRange = pShields.GetShieldWatcher( self.eShieldSide )
			pRange.RemoveRangeCheck( self.iRangeID )
			self.iRangeID = None

	def SetObjectName(self, sName):
		# Remove our old shield watcher, if we had one...
		self.RemoveShieldWatcher()

		# Set our new target name.
		self.sObjectName = sName
		# And setup the watcher again...
		self.SetInitialState()

	def SetInitialState(self):
		# Default status is false.
		self.pCodeCondition.SetStatus(0)

		# See if we can find the object anywhere.
		pObject = App.ShipClass_GetObject(App.SetClass_GetNull(), self.sObjectName)

		if not pObject:
			# If our object doesn't exist at the time we're
			# created, we need to listen to the ET_ENTERED_SET event...
			App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet" )
		else:
			# The object exists.
			self.SetupFromShip( pObject )

	def SetupFromShip(self, pObject):
		# Check its shields.
		pShields = pObject.GetShields()
		if not pShields:
			# No shields.  They must be below whatever our
			# threshold is...
			self.pCodeCondition.SetStatus(1)
			return

		# Setup a watcher for the shield side we're
		# interested in.
		pWatcher = pShields.GetShieldWatcher( self.eShieldSide )

		# Need an event for the watcher..
		pEvent = App.TGFloatEvent_Create()
		pEvent.SetSource(pShields)
		pEvent.SetDestination(self.pEventHandler)
		pEvent.SetEventType(App.ET_AI_SHIELD_WATCHER)

		self.iRangeID = pWatcher.AddRangeCheck( self.fShieldFraction, App.FloatRangeWatcher.FRW_BOTH, pEvent)

		# And get the current value, so we know if we start
		# out true or false..
		fFraction = pWatcher.GetWatchedVariable()
		if fFraction < self.fShieldFraction:
			self.pCodeCondition.SetStatus(1)

	def ShieldEvent(self, pEvent):
		# Our shield may have crossed the boundary we gave it.
		fShieldValue = pEvent.GetFloat()
		if fShieldValue < self.fShieldFraction:
			if self.pCodeCondition.GetStatus() != 1:
				self.pCodeCondition.SetStatus(1)
			else:
				#kDebugObj.Print(__name__ + ": WARNING, received unnecessary shield frac event for %s (%f/%f while %d)" % (self.sObjectName, fShieldValue, self.fShieldFraction, self.pCodeCondition.GetStatus()))
				pass
		else:
			if self.pCodeCondition.GetStatus() != 0:
				self.pCodeCondition.SetStatus(0)
			else:
				#kDebugObj.Print(__name__ + ": WARNING, received unnecessary shield frac event for %s (%f/%f while %d)" % (self.sObjectName, fShieldValue, self.fShieldFraction, self.pCodeCondition.GetStatus()))
				pass

		self.pEventHandler.CallNextHandler(pEvent)

	def EnteredSet(self, pEvent):
		# An object has entered a set.  Check if it's our object.
		pObject = App.ShipClass_Cast( pEvent.GetDestination() )
		if pObject:
			if pObject.GetName() == self.sObjectName:
				# It's a match.  We can get rid of our
				# broadcast handler for this event...
				App.g_kEventManager.RemoveBroadcastHandler( App.ET_ENTERED_SET, self.pEventHandler, "EnteredSet" )

				# Set ourselves up, since we couldn't before...
				self.SetupFromShip( pObject )

		# Done.  Pass the event to the next handler...
		self.pEventHandler.CallNextHandler(pEvent)
















