###############################################################################
#	Filename:	HelmCharacterHandlers.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Script to create the helm menu and handle some of its events.
#
#	Created:	12/26/2000 -	CCarley
###############################################################################

import App
import Bridge.BridgeUtils
import MissionLib
import HelmMenuHandlers

#NonSerializedObjects = ( "debug", )

# Create debug function
#debug = App.CPyDebug(__name__).Print

###############################################################################
#	AttachMenuToHelm(pHelm)
#
#	Attaches the helm menu to the character. This code must be called AFTER the
#	helm officer is created.  Also sets up python handlers for events
#
#	Args:	pHelm		- the helm character
#
#	Return:	none
###############################################################################
def AttachMenuToHelm(pHelm):
	pHelm = App.CharacterClass_Cast(pHelm)

	if (pHelm.GetMenu()):
		DetachMenuFromHelm(pHelm)

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Set our initial tooltip status to Waiting.  This will create
	# the tooltip box if it doesn't exist.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pHelm.SetStatus( pDatabase.GetString("Waiting") )
	App.g_kLocalizationManager.Unload(pDatabase)

	import Bridge.BridgeMenus
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pHelm.SetMenu(pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm")))

	pMenu = pHelm.GetMenu()
	pOrbitMenu = pMenu.GetSubmenuW(pDatabase.GetString("Orbit Planet"))

	App.g_kLocalizationManager.Unload(pDatabase)

	pMenu.AddPythonFuncHandlerForInstance(App.ET_REPORT,				__name__ + ".Report")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SET_COURSE,			__name__ + ".SetCourse")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_DOCK,					__name__ + ".HelmDock")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_ALL_STOP,				__name__ + ".AllStop")
	pOrbitMenu.AddPythonFuncHandlerForInstance(App.ET_ORBIT_PLANET,		__name__ + ".OrbitPlanet")

	import MissionLib
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_AI_DONE,	"Bridge.HelmCharacterHandlers.AIDone")

###############################################################################
#	DetachMenuFromHelm(pHelm)
#	
#	Removes the Helm menu, and removes any watches, handlers, etc.
#	
#	Args:	pHelm	- the helm character
#	
#	Return:	none
###############################################################################
def DetachMenuFromHelm(pHelm):
	# This doesn't destroy the menu, just removes the character's pointer to it
	pMenu = pHelm.GetMenu()
	pHelm.SetMenu(App.STTopLevelMenu_CreateNull())

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pOrbitMenu = pMenu.GetSubmenuW(pDatabase.GetString("Orbit Planet"))
	App.g_kLocalizationManager.Unload(pDatabase)

	pMenu.RemoveHandlerForInstance(App.ET_REPORT,				__name__ + ".Report")
	pMenu.RemoveHandlerForInstance(App.ET_SET_COURSE,			__name__ + ".SetCourse")
	pMenu.RemoveHandlerForInstance(App.ET_DOCK,					__name__ + ".HelmDock")
	pMenu.RemoveHandlerForInstance(App.ET_ALL_STOP,				__name__ + ".AllStop")
	pOrbitMenu.RemoveHandlerForInstance(App.ET_ORBIT_PLANET,	__name__ + ".OrbitPlanet")

###############################################################################
#	Report(pObject, pEvent)
#
#	Handles the "report" button in the menu.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def Report(pObject = None, pEvent = None):
	pSet = App.g_kSetManager.GetSet("bridge")
	pHelm = App.CharacterClass_GetObject(pSet, "Helm")
	pDatabase = pHelm.GetDatabase()

	pGame = App.Game_GetCurrentGame()
	pShip = App.ShipClass_Cast(pGame.GetPlayer())

	pSequence = App.TGSequence_Create()
	# Talk about Impulse and Warp engine status
	# Impulse Engines
	pImpulseSystem = pShip.GetImpulseEngineSubsystem()
	fCondition = pImpulseSystem.GetCombinedConditionPercentage()
	if (fCondition >= 0.95):
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "ImpulseEnginesFunctional", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (not pImpulseSystem.IsDisabled()):
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "ImpulseEnginesDamaged", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fCondition > 0.0):
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "ImpulseEnginesDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "ImpulseEnginesDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))

	# Warp Engines
	pWarpSystem = pShip.GetWarpEngineSubsystem()
	fCondition = pWarpSystem.GetCombinedConditionPercentage()
	if (fCondition >= 0.95):
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "WarpEnginesFunctional", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (not pWarpSystem.IsDisabled()):
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "WarpEnginesDamaged", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fCondition > 0.0):
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "WarpEnginesDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SPEAK_LINE, "WarpEnginesDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))

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
#	SetCourse(pObject, pEvent)
#
#	Handles the "set course" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def SetCourse(pObject, pEvent):
#	debug("Helm Set Course - Character handler\n")

	iType = pEvent.GetInt()

	pSet = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pSet, "Helm")

	if (iType == App.CharacterClass.EST_SET_COURSE_INTERCEPT):
#		debug("intercepting")

		pGame = App.Game_GetCurrentGame()
		pPlayer = pGame.GetPlayer()

		if not pPlayer:
			return

		pTarget = pPlayer.GetTarget()
		
		if (pTarget == None):
			return

		pEngines = pPlayer.GetImpulseEngineSubsystem()
		if not pEngines:
			pObject.CallNextHandler(pEvent)
			return

		if (pEngines.GetPowerPercentageWanted() == 0.0):
			# Player is trying to intercept with their engines off.
			pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
			MissionLib.QueueActionToPlay(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "EngineeringNeedPowerToEngines", None, 1))
			pObject.CallNextHandler(pEvent)
			return

		pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
		pCharacter.SetStatus(pDatabase.GetString("Intercepting"))
		App.g_kLocalizationManager.Unload(pDatabase)

		pCharacter.SetActive(1)

		App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, "gh081", None, 1).Play()
	else:
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
		pCharacter.SetStatus(pDatabase.GetString("ReadyToWarp"))
		App.g_kLocalizationManager.Unload(pDatabase)

		pCharacter.SetActive(1)

		App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, "gh075", None, 1).Play()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	HelmFollow(pObject, pEvent)
#
#	Handles the "follow" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def HelmFollow(pObject, pEvent):
#	debug("Helm Menu Follow")

	pGame = App.Game_GetCurrentGame()
	pPlayer = App.ShipClass_Cast( pGame.GetPlayer() )

	if not pPlayer:
		pObject.CallNextHandler(pEvent)
		return

	# Get the player's Target
	pTarget = pPlayer.GetTarget()
	
	if (pTarget == None):
#		debug("No Target")
		return

	pEngines = pPlayer.GetImpulseEngineSubsystem()
	if not pEngines:
		pObject.CallNextHandler(pEvent)
		return

	if (pEngines.GetPowerPercentageWanted() == 0.0):
		# Player is trying to intercept with their engines off.
		pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
		MissionLib.QueueActionToPlay(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "EngineeringNeedPowerToEngines", None, 1))
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pSet, "Helm")
	pCharacter.SetActive(1)

	pCharacterAction = App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, pCharacter.GetCharacterName() + "Yes" + str(App.g_kSystemWrapper.GetRandomNumber(4)+1), None, 1, pDatabase, App.CSP_NORMAL)
	pCharacterAction.Play()

	App.g_kLocalizationManager.Unload(pDatabase)
	pObject.CallNextHandler(pEvent)

###############################################################################
#	HelmDock(pObject, pEvent)
#
#	Handles the "dock" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def HelmDock(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pSet, "Helm")

	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		pObject.CallNextHandler(pEvent)
		return

	pEngines = pPlayer.GetImpulseEngineSubsystem()

	if not pEngines:
		pObject.CallNextHandler(pEvent)
		return

	if (pEngines.GetPowerPercentageWanted() == 0.0) and (pEngines.GetCombinedConditionPercentage() > pEngines.GetDisabledPercentage()):
		# Player is trying to dock with their engines off, but not disabled.
		pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
		MissionLib.QueueActionToPlay(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "EngineeringNeedPowerToEngines", None, 1))
		#pObject.CallNextHandler(pEvent)
		return

	pDatabase = pCharacter.GetDatabase()
	App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, "gh086", None, 1, pDatabase).Play()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	AllStop()
#	
#	Have the Helmsman respond to this order
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def AllStop(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pSet, "Helm")

	pDatabase = pCharacter.GetDatabase()
	App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, pCharacter.GetCharacterName() + "Yes" + str(App.g_kSystemWrapper.GetRandomNumber(4)+1), None, 1, pDatabase).Play()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	OrbitPlanet()
#	
#	Have the Helmsman respond to this order
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def OrbitPlanet(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	pCharacter = App.CharacterClass_GetObject(pSet, "Helm")

	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		pObject.CallNextHandler(pEvent)
		return

	pEngines = pPlayer.GetImpulseEngineSubsystem()

	if not pEngines:
		pObject.CallNextHandler(pEvent)
		return

	if (pEngines.GetPowerPercentageWanted() == 0.0):
		# Player is trying to orbit with their engines off.
		pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
		MissionLib.QueueActionToPlay(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "EngineeringNeedPowerToEngines", None, 1))
		pObject.CallNextHandler(pEvent)
		return

	App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SAY_LINE, "StandardOrbit", None, 1).Play()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	AIDone()
#	
#	Function to tell Helm to stop being active
#	
#	Args:	pObject, pEvent
#	
#	Return:	none
###############################################################################
def AIDone(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	
	pHelm = App.CharacterClass_GetObject(pSet, "Helm")
	if (pHelm and HelmMenuHandlers.g_bIgnoreNextAIDone == 0):
		pHelm.SetActive(0)

		pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
		pHelm.SetStatus(pDatabase.GetString("Waiting"))
		App.g_kLocalizationManager.Unload(pDatabase)
		
	HelmMenuHandlers.g_bIgnoreNextAIDone = 0

	pObject.CallNextHandler(pEvent)
