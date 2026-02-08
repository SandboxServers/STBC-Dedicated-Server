#
# ConditionPowerBelow
#
# Check if the power levels on one of the ship's batteries are below a certain
# level.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " Condition module...")

ET_POWER_FRACTION_CHANGED = None

class ConditionPowerBelow:
	def __init__(self, pCodeCondition, pObject, bReserveOnly, fPowerFraction):
		# Setup globals..
		global ET_POWER_FRACTION_CHANGED
		if ET_POWER_FRACTION_CHANGED is None:
			ET_POWER_FRACTION_CHANGED = App.UtopiaModule_GetNextEventType()
		
		# Set our parameters...
		self.pCodeCondition = pCodeCondition
		self.idPower = App.NULL_ID
		self.bReserveOnly = bReserveOnly
		self.fFraction = fPowerFraction

		# If the fraction is invalid, just set our condition.
		if fPowerFraction > 1.0:
#			debug("Warning: Power fraction %f is too big (> 1.0)" % fPowerFraction)
			self.pCodeCondition.SetStatus(1)
			return
		elif fPowerFraction <= 0.0:
#			debug("Warning: Power fraction %f is too small (<= 0.0)" % fPowerFraction)
			self.pCodeCondition.SetStatus(0)
			return

		# Get the object's power system...
		try:
			pShip = App.ShipClass_Cast(pObject)
			pPower = pShip.GetPowerSubsystem()
			if self.bReserveOnly:
				pWatcher = pPower.GetBackupBatteryWatcher()
			else:
				pWatcher = pPower.GetMainBatteryWatcher()
		except AttributeError:
			# Something was NULL.  Pretend the power level is below the set fraction.
			self.pCodeCondition.SetStatus(1)
			return

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Setup our event handler wrapper.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Have the power watcher send us an event whenever
		# the power level crosses the given power boundary.
		pEvent = App.TGFloatEvent_Create()
		pEvent.SetEventType( ET_POWER_FRACTION_CHANGED )
		pEvent.SetSource( pPower )
		pEvent.SetDestination( self.pEventHandler )

		self.idWatcher = pWatcher.AddRangeCheck(self.fFraction, App.FloatRangeWatcher.FRW_BOTH, pEvent)
		self.idPower = pPower.GetObjID()

		# Since the events for the watchers are being sent
		# to us, we just need an instance handler.
		self.pEventHandler.AddPythonMethodHandlerForInstance( ET_POWER_FRACTION_CHANGED, "PowerChanged" )

		# Set the initial state.
		try:
			if self.bReserveOnly:
				fCurrentFraction = pPower.GetBackupBatteryPower() / pPower.GetBackupBatteryLimit()
			else:
				fCurrentFraction = pPower.GetMainBatteryPower() / pPower.GetMainBatteryLimit()
		except ZeroDivisionError:
			fCurrentFraction = 0.0

		if fCurrentFraction < self.fFraction:
			self.pCodeCondition.SetStatus(1)
		else:
			self.pCodeCondition.SetStatus(0)

	def __del__(self):
		# Make sure the watchers watching our systems don't
		# give us any more events.
		pPower = App.PowerSubsystem_Cast( App.TGObject_GetTGObjectPtr( self.idPower ) )
		if pPower:
			if self.bReserveOnly:
				pWatcher = pPower.GetBackupBatteryWatcher()
			else:
				pWatcher = pPower.GetMainBatteryWatcher()

			pWatcher.RemoveRangeCheck(self.idWatcher)

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def PowerChanged(self, pFloatEvent):
		# Check if the system is above or below our fraction.
		fFraction = pFloatEvent.GetFloat()
		if fFraction < self.fFraction:
			self.pCodeCondition.SetStatus(1)
		else:
			self.pCodeCondition.SetStatus(0)
		# No need to call next handler; we're the only handler for this event.
