###############################################################################
#	Filename:	EngineerCharacterHandlers.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Script to create the engineer's menu and handle some of its events.
#
#	Created:	12/26/2000 -	CCarley
###############################################################################

import App
import Bridge.BridgeUtils
import MissionLib
import Bridge.Characters.Brex
import Bridge.BridgeMenus
import BridgeHandlers

#NonSerializedObjects = ( "debug", )

# Create debug function
#debug = App.CPyDebug(__name__).Print

lCurrentRangeChecks				= [ ]
g_fLastAnnounceHull				= 0.0
g_fLastAnnounceShields			= 0.0
g_fLastAnnounceSpecificShield	= 0.0
g_fLastPowerAnnounce			= 0.0
g_fCommunicate					= 0.0
g_fLastCommunicate				= 0.0

ANNOUNCE_HULL_DELAY				= 3.0
ANNOUNCE_SHIELDS_DELAY			= 3.0
ANNOUNCE_SPECIFIC_SHIELD_DELAY	= 3.0

###############################################################################
#	AttachMenuToEngineer(pEngineer, pMenu)
#
#	Attaches the menu to the engineer officer.  Must be called AFTER engineer
#	officer is created.
#
#	Args:	pEngineer	- the science character
#
#	Return:	none
###############################################################################
def AttachMenuToEngineer(pEngineer):
	pEngineer = App.CharacterClass_Cast(pEngineer)

	if (pEngineer.GetMenu()):
		DetachMenuFromEngineer(pEngineer)

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Set our initial tooltip status to Waiting.  This will create
	# the tooltip box if it doesn't exist.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pEngineer.SetStatus( pDatabase.GetString("Waiting") )
	App.g_kLocalizationManager.Unload(pDatabase)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pEngineer.SetMenu(pTacticalControlWindow.FindMenu(pDatabase.GetString("Engineering")))
	App.g_kLocalizationManager.Unload(pDatabase)

	pMenu = pEngineer.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_REPORT,		__name__ + ".Report")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".Communicate")

	# Your ship status reports
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TACTICAL_SHIELD_LEVEL_CHANGE,		pMenu,	__name__ + ".ShieldLevelChange")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TACTICAL_HULL_LEVEL_CHANGE,		pMenu,	__name__ + ".HullLevelChange")

	# Some reports on specific shields
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")

	# Reports on when subsystems are disabled/destroyed
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SUBSYSTEM_DISABLED,				pMenu,	__name__ + ".SubsystemDisabled")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SUBSYSTEM_DESTROYED,				pMenu,	__name__ + ".SubsystemDestroyed")

	# Repairing events
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_REPAIR_COMPLETED,					pMenu,	__name__ + ".RepairCompleted")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_REPAIR_CANNOT_BE_COMPLETED,		pMenu,	__name__ + ".RepairCannotBeCompleted")

	# Power events
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_MAIN_BATTERY_LEVEL_CHANGE,			pMenu,	__name__ + ".MainBatteryLevelChange")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_BACKUP_BATTERY_LEVEL_CHANGE,		pMenu,	__name__ + ".BackupBatteryLevelChange")

	# Pre-load our common sounds
	pGame = App.Game_GetCurrentGame()
	pDatabase = pEngineer.GetDatabase()

	if (pGame and pDatabase):
		# Overall Shields
		if not (App.g_kSoundManager.GetSound("ShieldsFailed")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "ShieldsFailed", "Bridge")
		if not (App.g_kSoundManager.GetSound("Shields05")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "Shields05", "Bridge")
		if not (App.g_kSoundManager.GetSound("Shields10")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "Shields10", "Bridge")
		if not (App.g_kSoundManager.GetSound("Shields15")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "Shields15", "Bridge")
		if not (App.g_kSoundManager.GetSound("Shields20")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "Shields20", "Bridge")
		if not (App.g_kSoundManager.GetSound("Shields25")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "Shields25", "Bridge")
		if not (App.g_kSoundManager.GetSound("Shields50")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "Shields50", "Bridge")
		if not (App.g_kSoundManager.GetSound("Shields75")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "Shields75", "Bridge")

		# Specific Shields
		if not (App.g_kSoundManager.GetSound("FrontShieldDraining")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "FrontShieldDraining", "Bridge")
		if not (App.g_kSoundManager.GetSound("FrontShieldFailed")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "FrontShieldFailed", "Bridge")
		if not (App.g_kSoundManager.GetSound("RearShieldDraining")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "RearShieldDraining", "Bridge")
		if not (App.g_kSoundManager.GetSound("RearShieldFailed")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "RearShieldFailed", "Bridge")
		if not (App.g_kSoundManager.GetSound("TopShieldDraining")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "TopShieldDraining", "Bridge")
		if not (App.g_kSoundManager.GetSound("TopShieldFailed")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "TopShieldFailed", "Bridge")
		if not (App.g_kSoundManager.GetSound("BottomShieldDraining")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "BottomShieldDraining", "Bridge")
		if not (App.g_kSoundManager.GetSound("BottomShieldFailed")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "BottomShieldFailed", "Bridge")
		if not (App.g_kSoundManager.GetSound("LeftShieldDraining")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "LeftShieldDraining", "Bridge")
		if not (App.g_kSoundManager.GetSound("LeftShieldFailed")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "LeftShieldFailed", "Bridge")
		if not (App.g_kSoundManager.GetSound("RightShieldDraining")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "RightShieldDraining", "Bridge")
		if not (App.g_kSoundManager.GetSound("RightShieldFailed")):
			pGame.LoadDatabaseSoundInGroup(pDatabase, "RightShieldFailed", "Bridge")

	pShip = MissionLib.GetPlayer()
	if (pShip):
		# Setup our watchers...
		# Set up the status events that we need - Shield and Hull
		# Other events (repairs, subsystem reports) are generated elsewhere
		pShieldWatcher = pShip.GetShields().GetShieldWatcher(6)
		pHullWatcher = pShip.GetHull().GetCombinedPercentageWatcher()
		pMainWatcher = pShip.GetPowerSubsystem().GetMainBatteryWatcher()
		pBackupWatcher = pShip.GetPowerSubsystem().GetBackupBatteryWatcher()

		lWatchers = (
			( pShieldWatcher,	App.ET_TACTICAL_SHIELD_LEVEL_CHANGE ),
			( pHullWatcher,		App.ET_TACTICAL_HULL_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 0.75 )

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
				# Need an event for this range check..
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetEventType(eEventType)
				pEvent.SetDestination(pShip)

				lCurrentRangeChecks.append(pWatcher.AddRangeCheck(fRange, App.FloatRangeWatcher.FRW_BELOW, pEvent))

		lWatchers = (
			( pMainWatcher,		App.ET_MAIN_BATTERY_LEVEL_CHANGE ),
			( pBackupWatcher,	App.ET_BACKUP_BATTERY_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.1, 0.5 )

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
				# Need an event for this range check..
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetEventType(eEventType)
				pEvent.SetDestination(pShip)

				lCurrentRangeChecks.append(pWatcher.AddRangeCheck(fRange, App.FloatRangeWatcher.FRW_BELOW, pEvent))

		lWatchers = (
			( pShip.GetShields().GetShieldWatcher(0), App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(1), App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(2), App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(3), App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(4), App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(5), App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.5)

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
				# Need an event for this range check..
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetEventType(eEventType)
				pEvent.SetDestination(pShip)

				lCurrentRangeChecks.append(pWatcher.AddRangeCheck(fRange, App.FloatRangeWatcher.FRW_BELOW, pEvent))


###############################################################################
#	DetachMenuFromEngineer(pEngineer)
#	
#	Removes character's pointer to menu, also removes handlers, etc.
#	
#	Args:	pEngineer	- character to remove menu from
#	
#	Return:	
###############################################################################
def DetachMenuFromEngineer(pEngineer):
	# We don't destroy the menu here, just get rid of the character's pointer to it
	pMenu = pEngineer.GetMenu()
	pEngineer.SetMenu(App.STTopLevelMenu_CreateNull())

	pMenu.RemoveHandlerForInstance(App.ET_REPORT,		"EngineerCharacterHandlers.Report")
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	"EngineerCharacterHandlers.Communicate")

	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")

	# Reports on when subsystems are disabled/destroyed
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_SUBSYSTEM_DISABLED,				pMenu,	__name__ + ".SubsystemDisabled")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_SUBSYSTEM_DESTROYED,				pMenu,	__name__ + ".SubsystemDestroyed")

	# Repairing events
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_REPAIR_COMPLETED,					pMenu,	__name__ + ".RepairCompleted")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_REPAIR_CANNOT_BE_COMPLETED,		pMenu,	__name__ + ".RepairCannotBeCompleted")

	return

	pShip = MissionLib.GetPlayer()
	if (pShip):
		# Remove our watchers
		pShieldWatcher = pShip.GetShields().GetShieldWatcher(6)
		pHullWatcher = pShip.GetHull().GetCombinedPercentageWatcher()
		pMainWatcher = pShip.GetPowerSubsystem().GetMainBatteryWatcher()
		pBackupWatcher = pShip.GetPowerSubsystem().GetBackupBatteryWatcher()

		lWatchers = (
			( pShieldWatcher,	App.ET_TACTICAL_SHIELD_LEVEL_CHANGE ),
			( pHullWatcher,		App.ET_TACTICAL_HULL_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 0.75 )

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
					idRange = lCurrentRangeChecks[0]
					lCurrentRangeChecks.pop(0)
					pWatcher.RemoveRangeCheck(idRange)

		lWatchers = (
			( pMainWatcher,		App.ET_MAIN_BATTERY_LEVEL_CHANGE ),
			( pBackupWatcher,	App.ET_BACKUP_BATTERY_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.5 )

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
					idRange = lCurrentRangeChecks[0]
					lCurrentRangeChecks.pop(0)
					pWatcher.RemoveRangeCheck(idRange)

		lWatchers = (
			( pShip.GetShields().GetShieldWatcher(0), App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(1), App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(2), App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(3), App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(4), App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE ),
			( pShip.GetShields().GetShieldWatcher(5), App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.5)

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
					idRange = lCurrentRangeChecks[0]
					lCurrentRangeChecks.pop(0)
					pWatcher.RemoveRangeCheck(idRange)

###############################################################################
#	RepairCompleted(pObject, pEvent)
#	
#	Handles 'repair completed' events for the player's ship.
#	
#	Args:	pObject - the target of the event
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def RepairCompleted(pObject, pEvent):
	pObject.CallNextHandler(pEvent)
	return

	"Handles 'repair completed' events for the player's ship."
	pPlayer = MissionLib.GetPlayer()
	pSender = App.ShipSubsystem_Cast(pEvent.GetSource())

	# Only do talking, etc. for these events on the player's ship.
	if (pSender.GetParentShip() != pPlayer):
		return

	pSet = App.g_kSetManager.GetSet ("bridge")
	pEngineer = App.CharacterClass_GetObject (pSet, "Engineer")

	pSystem = pEvent.GetObjPtr()
	pSystem = App.ShipSubsystem_Cast(pSystem)

	###Load localization database
	pDatabase = pEngineer.GetDatabase()

	if (pSystem.IsTypeOf(App.CT_TORPEDO_SYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge119", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_PHASER_SYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge115", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_TRACTOR_BEAM_SYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge135", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_WARP_ENGINE_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge131", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_IMPULSE_ENGINE_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge127", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_SENSOR_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge123", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_HULL_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge111", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_SHIELD_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge111", App.CSP_SPONTANEOUS)
	if (pSystem.IsTypeOf(App.CT_REPAIR_SUBSYSTEM)):
		pEngineer.SpeakLine(pDatabase, "ge139", App.CSP_SPONTANEOUS)
	
#	debug("Repair on subsystem complete")

	pObject.CallNextHandler(pEvent)


###############################################################################
#	Communicate()
#	
#	Put here for some Easter Eggs
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def Communicate(pObject, pEvent):
	global g_fCommunicate,g_fLastCommunicate
	fTime = App.g_kUtopiaModule.GetGameTime() - g_fLastCommunicate - 10
	g_fLastCommunicate = App.g_kUtopiaModule.GetGameTime()
	if (fTime < 0):
		g_fCommunicate = g_fCommunicate + 1
		if (g_fCommunicate > 8):
			g_fCommunicate = 0

		if (g_fCommunicate > 3):
			iLine = int(g_fCommunicate)
			pEngineer = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
			if (pEngineer):
				App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "BrexNothingToAdd" + str(iLine)).Play()
				return
			else:
				g_fCommunicate = g_fCommunicate - 1

	pObject.CallNextHandler(pEvent)

###############################################################################
#	RepairCannotBeCompleted(pObject, pEvent)
#	
#	Handles 'repair cannot be completed' events for the player's ship.
#	
#	Args:	pObject - the target of the event
#			pEvent - the event that was sent
#	
#	Return:	none
###############################################################################
def RepairCannotBeCompleted(pObject, pEvent):
	pObject.CallNextHandler(pEvent)
	return

	"Handles 'repair cannot be completed' events for the player's ship."
	pPlayer = MissionLib.GetPlayer()
	pSender = App.ShipSubsystem_Cast(pEvent.GetSource())

	# Only do talking, etc. for these events on the player's ship.
	if (pSender.GetParentShip() != pPlayer) or (pPlayer == None):
		return

	pSet = App.g_kSetManager.GetSet ("bridge")
	pEngineer = App.CharacterClass_GetObject (pSet, "Engineer")

#	debug("Repair on subsystem cannot be completed")

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
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	pDatabase = pEngineer.GetDatabase()

	pGame = App.Game_GetCurrentGame()
	pShip = App.ShipClass_Cast(pGame.GetPlayer())

	pSequence = App.TGSequence_Create()

	pSequence = App.TGSequence_Create()

	fHull = pShip.GetHull().GetConditionPercentage()

	if (fHull <= 0.05):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Hull05", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fHull <= 0.1):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Hull10", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fHull <= 0.15):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Hull15", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fHull <= 0.2):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Hull20", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fHull <= 0.25):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Hull25", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fHull <= 0.5):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Hull50", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fHull <= 0.75):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Hull75", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Hull100", None, 0, pDatabase, App.CSP_SPONTANEOUS))

	iNumShields = pShip.GetShields().NUM_SHIELDS
	fShields = 0
	for i in range (iNumShields):
		fShields = fShields + (pShip.GetShields().GetCurShields(i)/pShip.GetShields().GetMaxShields(i))
	fShields = fShields / iNumShields

	if (fShields <= 0.0):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "ShieldsFailed", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fShields <= 0.05):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Shields05", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fShields <= 0.1):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Shields10", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fShields <= 0.15):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Shields15", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fShields <= 0.2):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Shields20", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fShields <= 0.25):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Shields25", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fShields <= 0.5):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Shields50", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fShields <= 0.75):
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Shields75", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, "Shields100", None, 0, pDatabase, App.CSP_SPONTANEOUS))

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
#	ShieldLevelChange(pObject, pEvent)
#
#	Handler function for shield level change event.
#
#	Args:	pObject 	- target for this event.
#			pEvent		- Event we are handling.
#
#	Return:	none
###############################################################################
def ShieldLevelChange(pObject, pEvent):
	pShip = App.Game_GetCurrentPlayer()
	if (pShip == None):
		return

	if (pShip.IsDying()):
		pObject.CallNextHandler(pEvent)
		return

	# If this isn't for the player, ignore it.
	if pShip.GetObjID() != pEvent.GetDestination().GetObjID():
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")

	if not (pEngineer):
		pObject.CallNextHandler(pEvent)
		return

	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
		pObject.CallNextHandler(pEvent)
		return

	# If we've setup a sequence for AnnounceShields too recently, don't do so again.
	global g_fLastAnnounceShields
	fCurrent = App.g_kUtopiaModule.GetGameTime()
	if fCurrent - g_fLastAnnounceShields < ANNOUNCE_SHIELDS_DELAY:
		# We've setup a sequence too recently.
		pObject.CallNextHandler(pEvent)
		return

	# Update "last updated" time for AnnounceShields.
	g_fLastAnnounceShields = fCurrent

	# Create a sequence to make engineer "look active" then call out the new shield status
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceShields"), 0.5)
	pSequence.Play()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	AnnounceShields(pAction)
#	
#	Announces general shield status.
#	
#	Args:	pAction	- the action
#	
#	Return:	zero for end
###############################################################################
def AnnounceShields(pAction):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return 0

	if (pShip.IsDying()):
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking() or pShip.GetAlertLevel() == pShip.GREEN_ALERT):
		return 0

	iNumShields = pShip.GetShields().NUM_SHIELDS
	fShields = 0
	for i in range (iNumShields):
		fShields = fShields + (pShip.GetShields().GetCurShields(i)/pShip.GetShields().GetMaxShields(i))
	fShields = fShields / iNumShields

	pDatabase = pEngineer.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()

	if (fShields <= 0.0 and fLastTime > 1.0):
		pEngineer.SayLine(pDatabase, "ShieldsFailed", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Shields Failed!")
	elif (fShields <= 0.05 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Shields05", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Shields 05")
	elif (fShields <= 0.1 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Shields10", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Shields 10")
	elif (fShields <= 0.15 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Shields15", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Shields 15")
	elif (fShields <= 0.2 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Shields20", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Shields 20")
	elif (fShields <= 0.25 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Shields25", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Shields 25")
	elif (fShields <= 0.5 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Shields50", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Shields 50")
	elif (fShields <= 0.75 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Shields75", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Shields 75")

	return 0

###############################################################################
#	SpecificShieldLevelChange(pObject, pEvent)
#
#	Handler function for shield level change event.
#
#	Args:	pObject 	- target for this event.
#			pEvent		- Event we are handling.
#
#	Return:	none
###############################################################################
def SpecificShieldLevelChange(pObject, pEvent):
	pShip = App.Game_GetCurrentPlayer()
	if (pShip == None):
		pObject.CallNextHandler(pEvent)
		return

	if (pShip.IsDying()):
		pObject.CallNextHandler(pEvent)
		return

	# If this isn't for the player, ignore it.
	if pShip.GetObjID() != pEvent.GetDestination().GetObjID():
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")

	if not (pEngineer):
		pObject.CallNextHandler(pEvent)
		return

	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
		pObject.CallNextHandler(pEvent)
		return

	# If we've setup a sequence for AnnounceSpecificShield too recently, don't do so again.
	global g_fLastAnnounceSpecificShield
	fCurrent = App.g_kUtopiaModule.GetGameTime()
	if fCurrent - g_fLastAnnounceSpecificShield < ANNOUNCE_SPECIFIC_SHIELD_DELAY:
		# We've setup a sequence too recently.
		pObject.CallNextHandler(pEvent)
		return

	# Update "last updated" time for AnnounceSpecificShield.
	g_fLastAnnounceSpecificShield = fCurrent

	# Create a sequence to make engineer "look active" then call out the new shield status
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceSpecificShield", pEvent.GetEventType()), 0.5)
	pSequence.Play()

	pObject.CallNextHandler(pEvent)


###############################################################################
#	AnnounceSpecificShield(pAction, iEventType)
#	
#	Announces a shield's condition.
#	
#	Args:	pAction		- the action
#			iEventType	- event type
#	
#	Return:	zero for end
###############################################################################
def AnnounceSpecificShield(pAction, iEventType):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return 0

	if (pShip.IsDying()):
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking() or pShip.GetAlertLevel() == pShip.GREEN_ALERT):
		return 0

	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()
	if (fLastTime < 1.0):
		return 0

	if (iEventType == App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE):
		fShields = (pShip.GetShields().GetCurShields(App.ShieldClass.FRONT_SHIELDS)/pShip.GetShields().GetMaxShields(App.ShieldClass.FRONT_SHIELDS))
		pString = "Front"
	elif (iEventType == App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE):
		fShields = (pShip.GetShields().GetCurShields(App.ShieldClass.REAR_SHIELDS)/pShip.GetShields().GetMaxShields(App.ShieldClass.REAR_SHIELDS))
		pString = "Rear"
	elif (iEventType == App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE):
		fShields = (pShip.GetShields().GetCurShields(App.ShieldClass.TOP_SHIELDS)/pShip.GetShields().GetMaxShields(App.ShieldClass.TOP_SHIELDS))
		pString = "Top"
	elif (iEventType == App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE):
		fShields = (pShip.GetShields().GetCurShields(App.ShieldClass.BOTTOM_SHIELDS)/pShip.GetShields().GetMaxShields(App.ShieldClass.BOTTOM_SHIELDS))
		pString = "Bottom"
	elif (iEventType == App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE):
		fShields = (pShip.GetShields().GetCurShields(App.ShieldClass.LEFT_SHIELDS)/pShip.GetShields().GetMaxShields(App.ShieldClass.LEFT_SHIELDS))
		pString = "Left"
	elif (iEventType == App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE):
		fShields = (pShip.GetShields().GetCurShields(App.ShieldClass.RIGHT_SHIELDS)/pShip.GetShields().GetMaxShields(App.ShieldClass.RIGHT_SHIELDS))
		pString = "Right"
	else:
#		debug("Uh oh, we don't know what shield we just got hit on (number " + str(iEventType) + ")?")
		return 0

	pString = pString + "Shield"

	if (fShields < 0.1):
		pString = pString + "Failed"
	elif (fShields < 0.5):
		pString = pString + "Draining"
	else:
		return 0

	pDatabase = pEngineer.GetDatabase()
#	debug(pString)
	pEngineer.SayLine(pDatabase, pString, "Captain", 1, App.CSP_SPONTANEOUS)

	return 0

###############################################################################
#	HullLevelChange(pObject, pEvent)
#
#	Handler function for hull level change event.
#	Note: This is a broadcast handler.  It doesn't need CallNextHandler's.
#
#	Args:	pObject 	- target for this event.
#			pEvent		- Event we are handling.
#
#	Return:	none
###############################################################################
def HullLevelChange(pObject, pEvent):
	pShip = App.Game_GetCurrentPlayer()
	if (pShip == None):
		pObject.CallNextHandler(pEvent)
		return

	if (pShip.IsDying()):
		pObject.CallNextHandler(pEvent)
		return

	# If this isn't for the player, ignore it.
	if pShip.GetObjID() != pEvent.GetDestination().GetObjID():
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")

	if not (pEngineer):
		pObject.CallNextHandler(pEvent)
		return

	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
		pObject.CallNextHandler(pEvent)
		return

	# If we've setup a sequence for AnnounceHull too recently, don't do so again.
	global g_fLastAnnounceHull
	fCurrent = App.g_kUtopiaModule.GetGameTime()
	if fCurrent - g_fLastAnnounceHull < ANNOUNCE_HULL_DELAY:
		# We've setup a sequence too recently.
		pObject.CallNextHandler(pEvent)
		return

	# Update "last updated" time for AnnounceHull.
	g_fLastAnnounceHull = fCurrent

	# Create a sequence to make engineer "look active" then call out the new shield status
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceHull"), 0.5)
	pSequence.Play()


###############################################################################
#	AnnounceHull(pAction)
#	
#	Announces hull condition.
#	
#	Args:	pAction	- the action
#	
#	Return:	zero for end
###############################################################################
def AnnounceHull(pAction):
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return 0

	if (pShip.IsDying()):
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
		return 0

	fHull = pShip.GetHull().GetConditionPercentage()

	pDatabase = pEngineer.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()

	if (fHull <= 0.05 and fLastTime > 1.0):
		pEngineer.SayLine(pDatabase, "Hull05", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Hull 05")
	elif (fHull <= 0.1 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Hull10", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Hull 10")
	elif (fHull <= 0.15 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Hull15", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Hull 15")
	elif (fHull <= 0.2 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Hull20", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Hull 20")
	elif (fHull <= 0.25 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Hull25", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Hull 25")
	elif (fHull <= 0.5 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Hull50", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Hull 50")
	elif (fHull <= 0.75 and fLastTime > 2.0):
		pEngineer.SayLine(pDatabase, "Hull75", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("Hull 75")

	return 0

###############################################################################
#	SubsystemDisabled()
#	
#	Called when a subsystem becomes disabled
#	
#	Args:	pObject, pEvent
#	
#	Return:	none
###############################################################################
def SubsystemDisabled(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()

	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	if (pPlayer.IsDying()):
		pObject.CallNextHandler(pEvent)
		return

	if not (pEvent.GetSource()):
		pObject.CallNextHandler(pEvent)
		return

	if not (pEvent.GetDestination()):
		pObject.CallNextHandler(pEvent)
		return

	if (pEvent.GetDestination().GetObjID() != pPlayer.GetObjID()):
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")

	if not (pEngineer):
		pObject.CallNextHandler(pEvent)
		return

	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
		pObject.CallNextHandler(pEvent)
		return 

	pDatabase = pEngineer.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()

	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))

	idSource = pEvent.GetSource().GetObjID()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceSystemDisabled", idSource), 0.5)

	pSequence.Play()

#	debug("A system has become disabled")

	pObject.CallNextHandler(pEvent)

###############################################################################
#	AnnounceSystemDisabled(pAction, pSource)
#	
#	Announces when a system has been disabled.
#	
#	Args:	pAction		- the action
#			idSource	- the ID of the source of the disabled event
#	
#	Return:	zero for end
###############################################################################
def AnnounceSystemDisabled(pAction, idSource):
	pGame = App.Game_GetCurrentGame()
	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		return 0

	if (pPlayer.IsDying()):
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	if not (pSet):
		return 0

	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if not (pEngineer):
		return 0

	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
		return 0

	pDatabase = pEngineer.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()

	if (fLastTime < 1.5):
		return 0

	pSource = App.TGObject_GetTGObjectPtr(idSource)
	if (App.PhaserSystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "PhasersDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.ShieldClass_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "ShieldsDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.SensorSubsystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "SensorsDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.TorpedoSystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "TorpedoesDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.TractorBeamProjector_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "TractorDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.ImpulseEngineSubsystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "ImpulseDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.WarpEngineSubsystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "WarpDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.PowerSubsystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "PowerDisabled", "Captain", 1, App.CSP_SPONTANEOUS)

	return 0

###############################################################################
#	SubsystemDestroyed()
#	
#	Called when a subsystem becomes destroyed
#	
#	Args:	pObject, pEvent
#	
#	Return:	none
###############################################################################
def SubsystemDestroyed(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayer = MissionLib.GetPlayer()

	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	if (pPlayer.IsDying()):
		pObject.CallNextHandler(pEvent)
		return

	if not (pEvent.GetDestination()):
		pObject.CallNextHandler(pEvent)
		return

	if (pEvent.GetDestination().GetObjID() != pPlayer.GetObjID()):
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")

	if not (pEngineer):
		pObject.CallNextHandler(pEvent)
		return
				
	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
		pObject.CallNextHandler(pEvent)
		return 

	pDatabase = pEngineer.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()

	pSystem = pEvent.GetSource()
	if pSystem:
		idSystem = pSystem.GetObjID()

		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceSystemDestroyed", idSystem), 0.5)
		pSequence.Play()

	#debug("A system has become destroyed")

	pObject.CallNextHandler(pEvent)

def AnnounceSystemDestroyed(pAction, idSource):
	pGame = App.Game_GetCurrentGame()
	pPlayer = MissionLib.GetPlayer()

	if not (pPlayer):
		return 0

	if (pPlayer.IsDying()):
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	if not (pSet):
		return 0

	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if not (pEngineer):
		return 0

	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
		return 0

	# Get the subsystem that was destroyed.
	pSource = App.ShipSubsystem_Cast(App.TGObject_GetTGObjectPtr(idSource))
	if not pSource:
		# The subsystem doesn't exist anymore.  Ship was probably destroyed.
		return 0

	pDatabase = pEngineer.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()

	if (fLastTime < 1.25):
		return 0

	if (App.PhaserSystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "PhasersDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.ShieldClass_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "ShieldsDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.SensorSubsystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "SensorsDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.TorpedoSystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "TorpedoesDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.TractorBeamSystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "TractorDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.ImpulseEngineSubsystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "ImpulseDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.WarpEngineSubsystem_Cast(pSource)):
		pEngineer.SayLine(pDatabase, "WarpDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)

	return 0

###############################################################################
#	MainBatteryLevelChange()
#	
#	Announces when a system has been disabled.
#	
#	Args:	pObject		- the object that called us
#			pEvent		- the event that called us
#	
#	Return:	none
###############################################################################
def MainBatteryLevelChange(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	if not (pSet):
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		return 0

	if (pPlayer.IsDying()):
		return 0

	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if not (pEngineer):
		pObject.CallNextHandler(pEvent)
		return

	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
#		debug("Engineering can't talk now, sorry")
		pObject.CallNextHandler(pEvent)
		return

	global g_fLastPowerAnnounce
	if (App.g_kUtopiaModule.GetGameTime() - g_fLastPowerAnnounce < 10.0):
		pObject.CallNextHandler(pEvent)
		return

	pDatabase = pEngineer.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()

	if (fLastTime < 1.5 or pEngineer.IsSpeaking()):
#		debug("Engineering talks to much")
		pObject.CallNextHandler(pEvent)
		return

	# If power is rising, rather than draining, don't issue this warning.
	if not IsPowerDraining(pPlayer):
		return

	g_fLastPowerAnnounce = App.g_kUtopiaModule.GetGameTime()

	if (pEvent.GetFloat() < 0.05):
		pEngineer.SayLine(pDatabase, "MainPowerDepleted", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (pEvent.GetFloat() < 0.4):
		pEngineer.SayLine(pDatabase, "MainPowerDraining", "Captain", 1, App.CSP_SPONTANEOUS)
	else:
		pEngineer.SayLine(pDatabase, "MainPower50", "Captain", 1, App.CSP_SPONTANEOUS)

	return

###############################################################################
#	IsPowerDraining
#	
#	Check if the main/backup batteries are draining, with the
#	current power settings on the specified ship.
#	
#	Args:	pShip	- The ship to check.
#	
#	Return:	True if they're draining, false if not.
###############################################################################
def IsPowerDraining(pShip):
	# Check if power is still draining right now.  If power is no longer
	# draining, there's no point in issuing a warning.
	pPower = pShip.GetPowerSubsystem()
	if pPower:
		fAvailable = min(pPower.GetPowerOutput(), (pPower.GetMainConduitCapacity() + pPower.GetBackupConduitCapacity()))
		fTotalPower = 0.0
		for pSystem in (pShip.GetImpulseEngineSubsystem(), pShip.GetWarpEngineSubsystem(),
						pShip.GetShields(), pShip.GetPhaserSystem(), pShip.GetTorpedoSystem(),
						pShip.GetPulseWeaponSystem(), pShip.GetSensorSubsystem()):
			if pSystem:
				fTotalPower = fTotalPower + (pSystem.GetNormalPowerWanted() * pSystem.GetPowerPercentageWanted())

		if fTotalPower <= fAvailable:
			# Power consumption is below power output.  Not draining.
			#debug("Power is NOT draining (%f/%f)." % (fTotalPower, fAvailable))
			return 0
		#debug("Power IS draining (%f/%f)." % (fTotalPower, fAvailable))
	# Power is draining.
	return 1

###############################################################################
#	BackupBatteryLevelChange()
#	
#	Announces when a system has been disabled.
#	
#	Args:	pObject		- the object that called us
#			pEvent		- the event that called us
#	
#	Return:	none
###############################################################################
def BackupBatteryLevelChange(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("bridge")
	if not (pSet):
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		return 0

	if (pPlayer.IsDying()):
		return 0

	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if not (pEngineer):
		pObject.CallNextHandler(pEvent)
		return

	if (pEngineer.IsHidden() or pEngineer.IsAnimatingNonInterruptable() or pEngineer.IsSpeaking()):
#		debug("Engineering can't talk now, sorry")
		pObject.CallNextHandler(pEvent)
		return

	global g_fLastPowerAnnounce
	if (App.g_kUtopiaModule.GetGameTime() - g_fLastPowerAnnounce < 10.0):
		pObject.CallNextHandler(pEvent)
		return

	pDatabase = pEngineer.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pEngineer.GetLastTalkTime()

	if (fLastTime < 1.5 or pEngineer.IsSpeaking()):
#		debug("Engineering talks to much")
		pObject.CallNextHandler(pEvent)
		return

	# If power is rising, rather than draining, don't issue this warning.
	if not IsPowerDraining(pPlayer):
		return

	g_fLastPowerAnnounce = App.g_kUtopiaModule.GetGameTime()

	if (pEvent.GetFloat() < 0.05):
		pEngineer.SayLine(pDatabase, "BackupPowerDepleted", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (pEvent.GetFloat() < 0.4):
		pEngineer.SayLine(pDatabase, "BackupPowerDraining", "Captain", 1, App.CSP_SPONTANEOUS)
	else:
		pEngineer.SayLine(pDatabase, "BackupPower50", "Captain", 1, App.CSP_SPONTANEOUS)

	return

###############################################################################
#	GetEngineeringSet()
#	
#	Gets (or creates, if it doesn't exist) the Engineering set
#	
#	Args:	pcSetName		- Galaxy or Sovereign
#	
#	Return:	pEngineeringSet	- the newly created (or gotten) set
###############################################################################
def GetEngineeringSet(pcSetName = "Sovereign"):
#	debug("Getting Engineering set")
	pSet = App.g_kSetManager.GetSet("Engineering")
	if (pSet):
		return pSet

#	debug("Correction, CREATING engineering set")

	# OK, the set wasn't created yet, create it!
	pcSetName = "data/Models/Sets/" + pcSetName + "Eng/" + pcSetName + "Eng.nif"
	pEngineeringSet = MissionLib.SetupBridgeSet("Engineering", pcSetName)

	return pEngineeringSet


###############################################################################
#	ShowEngineering(pAction)
#	
#	Shows the Engineer on the Engineering set (can be part of a sequence)
#	
#	Args:	pAction	- Action which called this
#	
#	Return:	0 to indicate finished
###############################################################################
def ShowEngineering(pAction):
	# First, see if the engineer is still on the bridge
	pBridge = App.g_kSetManager.GetSet("bridge")
	if not (pBridge):
		return 0

	pBridgeEngineer = App.CharacterClass_GetObject(pBridge, "Engineer")
	if (pBridgeEngineer):
		if not (pBridgeEngineer.IsHidden()):
			pBridgeEngineer.LookAtMe()
			return 0

	pEngineeringSet = GetEngineeringSet()

	MissionLib.ViewscreenOn(None, "Engineering", "Engineer")

	return 0

###############################################################################
#	ContactEngineering()
#	
#	Contacts the Engineer on the Engineering set
#	
#	Args:	pObject	- object that called the event
#			pEvent	- event that was created
#	
#	Return:	none
###############################################################################
def ContactEngineering(pObject = None, pEvent = None):
	ShowEngineering(None)

	pBridge = App.g_kSetManager.GetSet("bridge")
	if not (pBridge):
		if (pObject):
			pObject.CallNextHandler(pEvent)

		return

	pBridgeEngineer = App.CharacterClass_GetObject(pBridge, "Engineer")
	if (pBridgeEngineer):
		if not (pBridgeEngineer.IsHidden()):
			BridgeHandlers.TalkToEngineering(None, None)
#			debug("Engineer is on bridge, don't bother")
			if (pObject):
				pObject.CallNextHandler(pEvent)

			return 

	pEngineeringSet = GetEngineeringSet()
	pEngineer = App.CharacterClass_GetObject(pEngineeringSet, "Engineer")

	pDatabase = pEngineer.GetDatabase()

	pCharacterAction = App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SPEAK_LINE, pEngineer.GetCharacterName() + "Sir" + str(App.g_kSystemWrapper.GetRandomNumber(4)+1), None, 0, pDatabase, App.CSP_NORMAL)
	pCharacterAction.Play()


	pViewscreen = MissionLib.GetViewScreen()
	pViewscreen.SetMenu(pEngineer.GetMenu())
	pViewscreen.MenuUp()

	if (pObject):
		pObject.CallNextHandler(pEvent)
