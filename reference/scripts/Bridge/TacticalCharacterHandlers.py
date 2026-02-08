###############################################################################
#	Filename:	TacticalCharacterHandlers.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Script to create the Tactical menu and handle some of its events.
#
#	Created:	12/26/2000 -	CCarley
###############################################################################

import App
import Bridge.BridgeUtils
import MissionLib

#NonSerializedObjects = ( "debug", )

# Create debug function
#debug = App.CPyDebug(__name__).Print

###############################################################################
#	AttachMenuToTactical(pTactical)
#
#	Attaches the Tactical menu to the character. This code must be called AFTER the
#	Tactical officer is created.  Also sets up python handlers for events
#
#	Args:	pTactical		- the Tactical character
#
#	Return:	none
###############################################################################
def AttachMenuToTactical(pTactical):
	pTactical = App.CharacterClass_Cast(pTactical)
	if (pTactical.GetMenu()):
		DetachMenuFromTactical(pTactical)

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Set our initial tooltip status to Waiting.  This will create
	# the tooltip box if it doesn't exist.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pTactical.SetStatus( pDatabase.GetString("Waiting") )
	App.g_kLocalizationManager.Unload(pDatabase)

	import Bridge.BridgeMenus
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalMenu = App.STTopLevelMenu_Cast(pTacWindow.GetTacticalMenu())
	pTactical.SetMenu(pTacticalMenu)
	App.g_kLocalizationManager.Unload(pDatabase)

	# Add handlers for our buttons
	pTacticalMenu.AddPythonFuncHandlerForInstance(App.ET_REPORT, __name__ + ".Report")

	pPlayer = MissionLib.GetPlayer()
	if (pPlayer):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_AI_DONE,						__name__ + ".AIDone")
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_CANT_FIRE,					__name__ + ".PlayerCantFire")
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_PLAYER_TORPEDO_TYPE_CHANGED,	__name__ + ".PlayerTorpChanged")
#	else:
#		debug("Can't get player..")


###############################################################################
#	DetachMenuFromTactical(pTactical)
#	
#	Removes the Tactical menu, and removes any watches, handlers, etc.
#	
#	Args:	pTactical	- the Tactical character
#	
#	Return:	none
###############################################################################
def DetachMenuFromTactical(pTactical):
	# This doesn't destroy the menu, just removes the character's pointer to it
	pMenu = pTactical.GetMenu()
	pTactical.SetMenu(App.STTopLevelMenu_CreateNull())

	pMenu.RemoveHandlerForInstance(App.ET_REPORT,				__name__ + ".Report")

	import MissionLib
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer):
		pPlayer.RemoveHandlerForInstance(App.ET_AI_DONE,						__name__ + ".AIDone")
		pPlayer.RemoveHandlerForInstance(App.ET_CANT_FIRE,						__name__ + ".PlayerCantFire")
		pPlayer.RemoveHandlerForInstance(App.ET_PLAYER_TORPEDO_TYPE_CHANGED,	__name__ + ".PlayerTorpChanged")

###############################################################################
#	AIDone()
#	
#	Function to tell Felix to stop being active
#	
#	Args:	pObject, pEvent
#	
#	Return:	none
###############################################################################
def AIDone(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	
	import TacticalMenuHandlers
	pTactical = App.CharacterClass_GetObject(pSet, "Tactical")
	if (pTactical and TacticalMenuHandlers.g_bIgnoreNextAIDone == 0):
		pTactical.SetActive(0)
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
		pTactical.SetStatus(pDatabase.GetString("Waiting"))
		App.g_kLocalizationManager.Unload(pDatabase)

	TacticalMenuHandlers.g_bIgnoreNextAIDone = 0

	pObject.CallNextHandler(pEvent)


###############################################################################
#	Report(pObject, pEvent)
#	
#	Reports on the state of the ship or various subsystems.
#	
#	Args:	pObject - the target of the event
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def Report(pObject = None, pEvent = None):
	pSet = App.g_kSetManager.GetSet("bridge")
	pTactical = App.CharacterClass_GetObject(pSet, "Tactical")
	pDatabase = pTactical.GetDatabase()

	pGame = App.Game_GetCurrentGame()
	pShip = App.ShipClass_Cast(pGame.GetPlayer())

	pSequence = App.TGSequence_Create()
	# Talk about weapon status
	# Phasers
	pPhaserSystem = pShip.GetPhaserSystem()
	fCondition = pPhaserSystem.GetCombinedConditionPercentage()
	if (fCondition >= 0.95):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "PhaserFunctional", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (not pPhaserSystem.IsDisabled()):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "PhaserDamaged", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fCondition > 0.0):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "PhaserDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "PhaserDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))

	# Torpedoes
	pTorpedoSystem = pShip.GetTorpedoSystem()
	fCondition = pTorpedoSystem.GetCombinedConditionPercentage()
	if (fCondition >= 0.95):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "TorpedoFunctional", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (not pTorpedoSystem.IsDisabled()):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "TorpedoDamaged", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fCondition > 0.0):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "TorpedoDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "TorpedoDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))

	# Tractor
	pTractorSystem = pShip.GetTractorBeamSystem()
	fCondition = pTractorSystem.GetCombinedConditionPercentage()
	if (fCondition >= 0.95):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "TractorBeamFunctional", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (not pTractorSystem.IsDisabled()):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "TractorBeamDamaged", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fCondition > 0.0):
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "TractorBeamDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SPEAK_LINE, "TractorBeamDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))


	if (pObject):
		if (pEvent):
#			debug("This is an event handled call")
			pObject.CallNextHandler(pEvent)
			pSequence.Play()
			return

		# This might be called as a script action, so return after the sequence if it is
#		debug("An action called us..")
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pObject)
		pSequence.AddCompletedEvent(pEvent)

		pSequence.Play()

	return 1

###############################################################################
#	PlayerCantFire()
#	
#	The player just attempted to fire, but can't.  Find out why, and report
#	the condition if necessary
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def PlayerCantFire(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	pTactical = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if not (pTactical):
		pObject.CallNextHandler(pEvent)
		return

	fLastTime = App.g_kUtopiaModule.GetGameTime() - pTactical.GetLastTalkTime()
	if (fLastTime < 10.0):
		pObject.CallNextHandler(pEvent)
		return
	
	# Get the tactical database
	pDatabase = pTactical.GetDatabase()
	
	# Figure out what just fired...
	pTorps = App.TorpedoSystem_Cast(pEvent.GetSource())
	pPhasers = App.PhaserSystem_Cast(pEvent.GetSource())
	pTractors = App.TractorBeamSystem_Cast(pEvent.GetSource())

	if (pTorps):
		if (pTorps.GetNumReady() > 0):
			# They're out of range - check to see if they're within a reasonable firing arc
			pTarget = App.ShipClass_Cast(pPlayer.GetTarget())
			if (pTarget):
				kLocation = pPlayer.GetWorldLocation()
				kTheirLocation = pTarget.GetWorldLocation()
				kToShip = kTheirLocation
				kToShip.Subtract(kLocation)

				# Make sure they're outside our range..
				if (kToShip.Length() > 1000.0):
					App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "gt030", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()				

			pObject.CallNextHandler(pEvent)
			return

		if (pTorps.GetNumAvailableTorpsToType(pTorps.GetAmmoTypeNumber()) <= 0):
			# We're out of torps of that type
			if (pTorps.GetAmmoTypeNumber() == 0):
				App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "OutOfPhotons", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
			elif (pTorps.GetAmmoTypeNumber() == 1):
				App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "OutOfQuantums", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
			else:
				App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "OutOfType", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
		else:
			# We haven't reloaded yet
			App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "gt037", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	PlayerTorpChanged()
#	
#	The player just changed the type of torpedo they're using
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def PlayerTorpChanged(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	pTactical = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if not (pTactical):
		pObject.CallNextHandler(pEvent)
		return

	pTorps = App.TorpedoSystem_Cast(pEvent.GetSource())

	#global g_fLastWarnTime
	#if (App.g_kUtopiaModule.GetGameTime() - g_fLastWarnTime < 2):
	#	pObject.CallNextHandler(pEvent)
	#	return

	if not (pTorps):
		pObject.CallNextHandler(pEvent)
		return

	#g_fLastWarnTime = App.g_kUtopiaModule.GetGameTime()
	
	# Get Felix's database
	pDatabase = pTactical.GetDatabase()
	pShipProp = pPlayer.GetShipProperty()
	
	if (pTorps.GetNumAmmoTypes() == 1) and (pShipProp.GetSpecies() == App.SPECIES_GALAXY):
		App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "PhotonsOnlyDaunt", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
	else:
		pAmmo = pTorps.GetCurrentAmmoType()
		if not pAmmo:
			pObject.CallNextHandler(pEvent)
			return

		if (pAmmo.GetAmmoName() == "Photon"):
			App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "LoadingPhoton", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
		elif (pAmmo.GetAmmoName() == "Quantum"):
			App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "LoadingQuantum", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
		else:
			App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "LoadingTorps", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
		
	pObject.CallNextHandler(pEvent)
