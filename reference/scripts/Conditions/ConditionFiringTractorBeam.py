#
# ConditionFiringTractorBeam
#
# A condition that's true if its ship is firing one of
# its tractor beams, false if not.
#
import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug('Loading ' + __name__ + ' Condition module...')

class ConditionFiringTractorBeam:
	def __init__(self, pCodeCondition, pShip):
		self.pCodeCondition = pCodeCondition
		self.idShip = pShip.GetObjID()

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Listen to tractor beam firing/stopped events sent to the ship.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_TRACTOR_BEAM_STARTED_FIRING, self.pEventHandler, "StartedFiring", pShip)
		App.g_kEventManager.AddBroadcastPythonMethodHandler( App.ET_TRACTOR_BEAM_STOPPED_FIRING, self.pEventHandler, "StoppedFiring", pShip)

		# Check our current state.
		self.CheckState(pShip)

	def __getstate__(self):
		dState = self.__dict__.copy()
		dState["pModule"] = self.pModule.__name__
		dState["pEventHandler"].pContainingInstance = self
		return dState

	def __setstate__(self, dict):
		self.__dict__ = dict
		self.pModule = __import__(self.pModule)
		del self.pEventHandler.pContainingInstance

	def CheckState(self, pShip):
		bState = 0

		# Get the ship's tractor beam system.
		pTractorSystem = pShip.GetTractorBeamSystem()
		if pTractorSystem:
			# Loop through all the tractor beam projectors...
			for iChild in range( pTractorSystem.GetNumChildSubsystems() ):
				pProjector = App.TractorBeamProjector_Cast( pTractorSystem.GetChildSubsystem(iChild) )
				if pProjector  and  pProjector.IsFiring():
					# This tractor beam projector is firing.  We're True.
					bState = 1

		self.pCodeCondition.SetStatus(bState)

	def StartedFiring(self, pEvent):
		# The ship has started firing a tractor beam.  We're True.
		self.pCodeCondition.SetStatus(1)

	def StoppedFiring(self, pEvent):
		# The ship has stopped firing one of its tractor beams.  Check
		# if any others are firing, and set our state.
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		self.CheckState(pShip)
