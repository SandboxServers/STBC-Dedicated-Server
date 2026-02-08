#
# RunAction
#
# Play a TGAction.  This waits for the action to finish, then says it's Done.
#
import App
import BaseAI

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " AI module...")

class RunAction(BaseAI.BaseAI):
	def __init__(self, pCodeAI):
		# Parent class constructor first...
		BaseAI.BaseAI.__init__(self, pCodeAI)

		# Set default values for parameters that have them.
		self.SetupDefaultParams()
		self.SetRequiredParams( ( "idAction", "SetAction" ) )
		self.SetExternalFunctions()

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# We need an event handler...
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		self.pEventHandler.AddPythonMethodHandlerForInstance( App.ET_ACTION_COMPLETED, "ActionDone" )

		self.bPlayed = 0

	def SetAction(self, pAction): #AISetup
		self.idAction = pAction.GetObjID()






	def GetStatusInfo(self):
		return "Action ID:%s" % (self.idAction)

	def GetNextUpdateTime(self):
		return 0.0

	def LostFocus(self):
		# We're being forced to stop.  If the action is running, abort it.
		pAction = App.TGAction_Cast( App.TGObject_GetTGObjectPtr( self.idAction ) )
		if pAction  and  pAction.IsPlaying():
			pAction.Abort()

	def ActionDone(self, pEvent):
		self.idAction = App.NULL_ID
		self.pEventHandler.CallNextHandler(pEvent)

	def Update(self):
		# Get the action.
		pAction = App.TGAction_Cast( App.TGObject_GetTGObjectPtr( self.idAction ) )
		if not pAction:
			return App.ArtificialIntelligence.US_DONE

		# If it's not playing yet, play it.
		if not self.bPlayed:
			# We want to receive an event when it's done playing.
			pEvent = App.TGEvent_Create()
			pEvent.SetEventType( App.ET_ACTION_COMPLETED )
			pEvent.SetDestination( self.pEventHandler )

			pAction.AddCompletedEvent(pEvent)
			pAction.Play()
			self.bPlayed = 1

		return App.ArtificialIntelligence.US_ACTIVE










	
