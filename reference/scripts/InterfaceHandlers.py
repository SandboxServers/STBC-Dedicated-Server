import App

###############################################################################
#	TriggerKeyboardEvents()
#	
#	Trigger input events based on the given keyboard
#	event.
#	
#	Args:	dKeyToEventMapping	- A dictionary mapping keypress information
#					  to event types to trigger.
#		pEvent			- The keyboard event
#		pDestination		- The destination for the events.
#	
#	Return:	None
###############################################################################
def TriggerKeyboardEvents(dKeyToEventMapping, pEvent, pDestination):
	# Get the information we need about the key so we can
	# look it up in the table..
	eKeyType = pEvent.GetKeyState()
	cCharCode = pEvent.GetUnicode()
	# KS_NORMAL keys need their key code converted to a character.
	#if eKeyType == App.TGKeyboardEvent.KS_NORMAL:
	#	cCharCode = chr(cCharCode)

	# Look up the key combo in the table.
	try:
		eEventType, sEventClass, pExtraSetupArgs = dKeyToEventMapping[(cCharCode, eKeyType)]
	except KeyError:
		# Not in the table.
		eEventType = App.ET_INVALID

	# If we found the key combo in the table, send an event for it.
	if eEventType != App.ET_INVALID:
		# Figure out which type of event to create...
		sCreateFunc = sEventClass + "_Create"
		pCreateFunc = App.__dict__[sCreateFunc]

		# Create an event for this keypress.
		pOutgoingEvent = pCreateFunc()
		pOutgoingEvent.SetEventType(eEventType)
		pOutgoingEvent.SetDestination(pDestination)

		# Extra setup for the event:
		if pExtraSetupArgs:
			dSetupFuncs = {
				"TGEvent": None,
				"TGIntEvent": App.TGIntEvent.SetInt,
				"TGBoolEvent": App.TGBoolEvent.SetBool,
				"TGFloatEvent": App.TGFloatEvent.SetFloat
				}
			pSetupFunc = dSetupFuncs[sEventClass]
			if pSetupFunc:
				pSetupFunc(pOutgoingEvent, pExtraSetupArgs)

		App.g_kEventManager.AddEvent(pOutgoingEvent)
		
		# We've handled the key.
		pEvent.SetHandled()
