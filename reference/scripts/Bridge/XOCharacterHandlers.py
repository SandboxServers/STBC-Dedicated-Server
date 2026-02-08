###############################################################################
#	Filename:	XOCharacterHandlers.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Script to attach the XO's menu to a character, as well as set up handlers
#	to take care of the menu events.
#
#	Created:	12/26/2000 -	CCarley
###############################################################################
import App
import Bridge.BridgeUtils

#NonSerializedObjects = ( "debug", )

# Create debug function
#debug = App.CPyDebug(__name__).Print

###############################################################################
#	AttachMenuToXO(pXO, pMenu)
#
#	Attaches the menu to the XO.  Loads all required sounds, as well as setting
#	up the event handlers.
#
#	Args:	pXO		- the character to attach the menu to
#
#	Return:	none
###############################################################################
def AttachMenuToXO(pXO):
	pXO = App.CharacterClass_Cast(pXO)

	if (pXO.GetMenu()):
		DetachMenuFromXO(pXO)

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Set our initial tooltip status to Waiting.  This will create
	# the tooltip box if it doesn't exist.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pXO.SetStatus( pDatabase.GetString("Waiting") )
	App.g_kLocalizationManager.Unload(pDatabase)

	import Bridge.BridgeMenus
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pXO.SetMenu(pTacticalControlWindow.FindMenu(pDatabase.GetString("Commander")))
	App.g_kLocalizationManager.Unload(pDatabase)

	# Add Python function handlers.
	pMenu = pXO.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_REPORT,				__name__ + ".Report")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SET_ALERT_LEVEL,		__name__ + ".SetAlertLevel")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_OBJECTIVES,			__name__ + ".Objectives")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET,		__name__ + ".ContactStarfleet")

	# Add a handler for weapons hits, so we know when someone is attacking, and can go to red alert
	import MissionLib
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT,	__name__ + ".PlayerHit")
#	else:
#		debug("Can't get the player yet...")


###############################################################################
#	DetachMenuFromXO(pXO)
#	
#	Removes the menu from the character, also gets rid of any handlers
#	
#	Args:	pXO	- the character
#	
#	Return:	none
###############################################################################
def DetachMenuFromXO(pXO):
	# We don't destroy the menu here, just get rid of the character's pointer to it
	pMenu = pXO.GetMenu()
	pXO.SetMenu(App.STTopLevelMenu_CreateNull())

	pMenu.RemoveHandlerForInstance(App.ET_REPORT,				__name__ + ".Report")
	pMenu.RemoveHandlerForInstance(App.ET_SET_ALERT_LEVEL,		__name__ + ".SetAlertLevel")
	pMenu.RemoveHandlerForInstance(App.ET_OBJECTIVES,			__name__ + ".Objectives")
	pMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET,	__name__ + ".ContactStarfleet")

	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	if (pPlayer):
		pPlayer.RemoveHandlerForInstance(App.ET_WEAPON_HIT,		"XOCharacterHandlers.PlayerHit")


# XO Functions
# Report, Alert Level, Damage Report, Objectives

###############################################################################
#	Report(pObject, pEvent)
#
#	Handles the "report" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def Report(pObject = None, pEvent = None):
	pSet = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pSet, "XO")
	pDatabase = pXO.GetDatabase()

	pSequence = App.TGSequence_Create()
	# Tell all other characters to call out their status
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetDamageReportEnabled", 0))
	pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "gf020", None, 0, pDatabase, App.CSP_NORMAL))
	pSequence.AppendAction(App.TGScriptAction_Create("Bridge.HelmCharacterHandlers", "Report"))
	pSequence.AppendAction(App.TGScriptAction_Create("Bridge.TacticalCharacterHandlers", "Report"))
	pSequence.AppendAction(App.TGScriptAction_Create("Bridge.ScienceCharacterHandlers", "Report"))
	pSequence.AppendAction(App.TGScriptAction_Create("Bridge.EngineerCharacterHandlers", "Report"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetDamageReportEnabled", 1))

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

def SetDamageReportEnabled(pAction, bEnabled):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()

	pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Commander"))
	pButton = pMenu.GetButtonW(pDatabase.GetString("Damage Report"))

	if (bEnabled):
		pButton.SetEnabled(0)
	else:
		pButton.SetDisabled(0)

	App.g_kLocalizationManager.Unload(pDatabase)

	return 0
	

###############################################################################
#	SetAlertLevel(pObject, pEvent)
#
#	Handles the "set alert level" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def SetAlertLevel(pObject, pEvent):
	iType = pEvent.GetInt()

	pSet = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pSet, "XO")

	pGame = App.Game_GetCurrentGame()
	pPlayer = App.ShipClass_Cast(pGame.GetPlayer())

	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	###Load localization database
	pDatabase = pXO.GetDatabase()

	iLevel = 0
	if (iType == App.CharacterClass.EST_ALERT_GREEN):
		iLevel = pPlayer.GREEN_ALERT
	if (iType == App.CharacterClass.EST_ALERT_YELLOW):
		iLevel = pPlayer.YELLOW_ALERT
	if (iType == App.CharacterClass.EST_ALERT_RED):
		iLevel = pPlayer.RED_ALERT

	iOldAlert = pPlayer.GetAlertLevel()

	pShields = pPlayer.GetShields()
	pPhasers = pPlayer.GetPhaserSystem()
	pPulse = pPlayer.GetPulseWeaponSystem()

	if (iLevel != pPlayer.GetAlertLevel()):
		if (iType == App.CharacterClass.EST_ALERT_GREEN):
			if (iOldAlert == pPlayer.YELLOW_ALERT):
				App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "GreenAlert2", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
			elif (iOldAlert == pPlayer.RED_ALERT):
				App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "GreenAlert3", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
			else:
				App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "GreenAlert", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()

			# If the player is hurting, remind them that it might be a good idea to go to Starbase 12
			pHull = pPlayer.GetHull()
			if (pHull.GetConditionPercentage() < 0.5):
				pSequence = App.TGSequence_Create()
				pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "gf019", None, 0, pDatabase, App.CSP_SPONTANEOUS), 7.0)
				pSequence.Play()

		if (iType == App.CharacterClass.EST_ALERT_YELLOW):
			if not (pShields.IsOn()):
				App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "YellowAlert", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
			else:
				bWeaponsOn = 0
				if (pPhasers):
					if (pPhasers.IsOn ()):
						bWeaponsOn = 1
				elif (pPulse):
					if (pPulse.IsOn ()):
						bWeaponsOn = 1

				if (bWeaponsOn):
					App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "YellowAlert3", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
				else:
					App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "YellowAlert2", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
		if (iType == App.CharacterClass.EST_ALERT_RED):
			if not (pShields.IsOn()):
				App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "RedAlert", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()
			else:
				App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "RedAlert2", None, 0, pDatabase, App.CSP_SPONTANEOUS).Play()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	Objectives(pObject, pEvent)
#
#	Handles the "objectives" menu item.
#
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#
#	Return:	none
###############################################################################
def Objectives(pObject, pEvent):
#	debug("XO Objectives - Character handler")

	pObject.CallNextHandler(pEvent)

###############################################################################
#	PlayerHit() and PlayerHitAction()
#	
#	The player has been hit - go to red alert
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def PlayerHit(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()

	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	if (not (pSet == None)):
		pXO = App.CharacterClass_GetObject(pSet, "XO")

		if not (pPlayer.GetAlertLevel() == pPlayer.RED_ALERT):
			if (pXO.IsInitiativeOn()):
				pSequence = App.TGSequence_Create()
				pSequence.AddAction(App.TGScriptAction_Create(__name__, "PlayerHitAction"), None, 2.0)
				pSequence.Play()

	pObject.CallNextHandler(pEvent)

def PlayerHitAction(pAction):
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()

	pShields = pPlayer.GetShields()
	if not (pShields):
#		debug("Ack, we don't have a shield system??!?")
		return 0

	pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	pXOMenu = pXO.GetMenu()

	if not (pShields.IsOn()):
		pEvent = App.TGIntEvent_Create()
		pEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
		pEvent.SetInt(App.CharacterClass.EST_ALERT_RED)		
		pEvent.SetDestination(pXOMenu)
		pAction.AddCompletedEvent(pEvent)
		
	return 0

###############################################################################
#	ContactStarfleet()
#	
#	Default handler for the Contact Starfleet button, should set up a brief
#	sequence telling the player that there is no need to contact the Starbase
#	at this time.  Missions will override this with mission-specific handlers
#	
#	Args:	pObject, pEvent	- object and event that called us
#	
#	Return:	none
###############################################################################
def ContactStarfleet(pObject, pEvent):
	import MissionLib

	pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")

	pContactSequence = App.TGSequence_Create()
	pContactSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", 1))
	pContactSequence.AppendAction(MissionLib.ContactStarfleet())

	# Now grab Liu and her set (or create them if they don't yet exist..)
	pLiuSet = MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")
	if not (pLiu):
		pLiu = MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet", 0, 0, 5)

	iLine = App.g_kSystemWrapper.GetRandomNumber(2) + 4
	pContactSequence.AppendAction(App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "gl00" + str(iLine)), 0.5)

	pContactSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"), 0.5)
	pContactSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", 0))

	MissionLib.QueueActionToPlay(pContactSequence)
