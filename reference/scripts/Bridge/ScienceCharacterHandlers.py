###############################################################################
#	Filename:	ScienceCharacterHandlers.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Script to create the science menu and handle some of its events.
#
#	Created:	12/26/2000 -	CCarley
###############################################################################

import App
import Bridge.BridgeUtils
import Bridge.EngineerMenuHandlers
import Bridge.ScienceMenuHandlers
import MissionLib

#NonSerializedObjects = ( "debug", )

# Create debug function
#debug = App.CPyDebug(__name__).Print

g_lCurrentRangeChecks	= [ ]
g_idTarget				= App.NULL_ID
g_fLastCallOutTime		= 0.0
g_fTargetSet			= 0.0

###############################################################################
#	AttachMenuToScience(pScience, pMenu)
#
#	Attaches the menu to the science officer.  Must be called AFTER science
#	officer is created.
#
#	Args:	pScience	- the science character
#
#	Return:	none
###############################################################################
def AttachMenuToScience(pScience):
	pScience = App.CharacterClass_Cast(pScience)

	if (pScience.GetMenu()):
		DetachMenuFromScience(pScience)

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Set our initial tooltip status to Waiting.  This will create
	# the tooltip box if it doesn't exist.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pScience.SetStatus( pDatabase.GetString("Waiting") )
	App.g_kLocalizationManager.Unload(pDatabase)

	import Bridge.BridgeMenus
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pScience.SetMenu(pTacticalControlWindow.FindMenu(pDatabase.GetString("Science")))
	App.g_kLocalizationManager.Unload(pDatabase)

	pMenu = pScience.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_REPORT,		__name__ + ".Report")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN,			__name__ + ".Scan")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_LAUNCH_PROBE,	__name__ + ".LaunchProbe")

	# Get rid of the normal handlers, we do it here now
	pMenu.RemoveHandlerForInstance(App.ET_SCAN,					"Bridge.ScienceMenuHandlers.Scan")
	pMenu.RemoveHandlerForInstance(App.ET_LAUNCH_PROBE,			"Bridge.ScienceMenuHandlers.LaunchProbe")

	# Target ship status reports
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


	import MissionLib
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_TARGET_WAS_CHANGED,	__name__ + ".TargetChanged")
#	else:
#		debug("Can't get player..")


###############################################################################
#	DetachMenuFromScience()
#	
#	Detaches the menu, removes extra handlers
#	
#	Args:	pScience	- Science officer
#	
#	Return:	none
###############################################################################
def DetachMenuFromScience(pScience):
	pMenu = pScience.GetMenu()
	if (pMenu):
		pScience.SetMenu(App.STTopLevelMenu_CreateNull())

		# Put back the normal handlers
		pMenu.RemoveHandlerForInstance(App.ET_SCAN,					"Bridge.ScienceMenuHandlers.Scan")
		pMenu.RemoveHandlerForInstance(App.ET_LAUNCH_PROBE,			"Bridge.ScienceMenuHandlers.LaunchProbe")

		pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN,			"Bridge.ScienceMenuHandlers.Scan")
		pMenu.AddPythonFuncHandlerForInstance(App.ET_LAUNCH_PROBE,	"Bridge.ScienceMenuHandlers.LaunchProbe")

		pScience.RemoveHandlerForInstance(App.ET_REPORT,			__name__ + ".Report")
		pMenu.RemoveHandlerForInstance(App.ET_SCAN,					__name__ + ".Scan")
		pMenu.RemoveHandlerForInstance(App.ET_LAUNCH_PROBE,			__name__ + ".LaunchProbe")

	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_HULL_LEVEL_CHANGE,		pMenu,	__name__ + ".HullLevelChange")

	# Some reports on specific shields
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE,	pMenu,	__name__ + ".SpecificShieldLevelChange")

	# Reports on when subsystems are disabled/destroyed
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_SUBSYSTEM_DISABLED,				pMenu,	__name__ + ".SubsystemDisabled")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_SUBSYSTEM_DESTROYED,				pMenu,	__name__ + ".SubsystemDestroyed")

	import MissionLib
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer):
		pPlayer.RemoveHandlerForInstance(App.ET_TARGET_WAS_CHANGED,								__name__ + ".TargetChanged")
		RemoveTargetWatchers()
#	else:
#		debug("Can't get player..")

###############################################################################
#	TargetChanged()
#	
#	We should set up watchers on our target for specific shields
#	
#	Args:	
#	
#	Return:	
###############################################################################
def TargetChanged(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pShip = App.ShipClass_Cast(pGame.GetPlayer())

	pTarget = None
	if (pShip):
		pTarget = App.ShipClass_Cast(pShip.GetTarget())

	idTarget = App.NULL_ID
	if (pTarget):
		idTarget = pTarget.GetObjID()

	# Only do this if we've really changed targets (NULL to NULL doesn't count)
	global g_idTarget
	if (g_idTarget != idTarget):
		# Remove the old watchers
		RemoveTargetWatchers()

		# Add the new watchers
		AddTargetWatchers()


###############################################################################
#	AddTargetWatchers()
#	
#	Adds target shield and hull watchers
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def AddTargetWatchers():
	global g_lCurrentRangeChecks
	global g_idTarget

	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
#		debug("ScienceCharacterHandlers.AddTargetWatchers() failed - player doesn't exist")

		g_lCurrentRangeChecks = [ ]
		g_idTarget = App.NULL_ID

		return

	# Remove old watches, if they're around
	RemoveTargetWatchers()

	pTarget = App.ShipClass_Cast(pPlayer.GetTarget())

	if (pTarget):
		g_idTarget = pTarget.GetObjID()
		g_fTargetSet = App.g_kUtopiaModule.GetGameTime()

		# Add new watches
		pShieldWatcher = pTarget.GetShields().GetShieldWatcher(6)
		pHullWatcher = pTarget.GetHull().GetCombinedPercentageWatcher()

		lWatchers = (
			( pShieldWatcher,	App.ET_TACTICAL_SHIELD_LEVEL_CHANGE ),
			( pHullWatcher,		App.ET_TACTICAL_HULL_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 0.75 )

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
				# Need an event for this range check..
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetEventType(eEventType)
				pEvent.SetDestination(pTarget)

				g_lCurrentRangeChecks.append(pWatcher.AddRangeCheck(fRange, App.FloatRangeWatcher.FRW_BELOW, pEvent))

		lWatchers = (
			( pTarget.GetShields().GetShieldWatcher(0), App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(1), App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(2), App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(3), App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(4), App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(5), App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.5)

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
				# Need an event for this range check..
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetEventType(eEventType)
				pEvent.SetDestination(pTarget)

				g_lCurrentRangeChecks.append(pWatcher.AddRangeCheck(fRange, App.FloatRangeWatcher.FRW_BELOW, pEvent))


###############################################################################
#	RemoveTargetWatchers()
#	
#	Removes target shield and hull watchers
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def RemoveTargetWatchers():
	global g_lCurrentRangeChecks
	global g_idTarget

	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
#		debug("ScienceCharacterHandlers.RemoveTargetWatchers() failed - player doesn't exist")

		g_lCurrentRangeChecks = [ ]
		g_idTarget = App.NULL_ID

		return

	if (len(g_lCurrentRangeChecks) <= 0):
#		if (g_idTarget != App.NULL_ID):
#			debug("ScienceCharacterHandlers.RemoveTargetWatchers() failed - we still had a target (ID " + str(g_idTarget) + "), but no checks to remove")

		g_lCurrentRangeChecks = [ ]
		g_idTarget = App.NULL_ID

		return

	# Remove watchers from target
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if (pTarget):
		pShieldWatcher = pTarget.GetShields().GetShieldWatcher(6)
		pHullWatcher = pTarget.GetHull().GetCombinedPercentageWatcher()

		lWatchers = (
			( pShieldWatcher,	App.ET_TACTICAL_SHIELD_LEVEL_CHANGE ),
			( pHullWatcher,		App.ET_TACTICAL_HULL_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 0.75 )

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
				idRange = g_lCurrentRangeChecks[0]
				g_lCurrentRangeChecks.pop(0)
				pWatcher.RemoveRangeCheck(idRange)

		lWatchers = (
			( pTarget.GetShields().GetShieldWatcher(0), App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(1), App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(2), App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(3), App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(4), App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE ),
			( pTarget.GetShields().GetShieldWatcher(5), App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE ) )

		lRanges = ( 0.05, 0.5)

		for pWatcher, eEventType in lWatchers:
			for fRange in lRanges:
				idRange = g_lCurrentRangeChecks[0]
				g_lCurrentRangeChecks.pop(0)
				pWatcher.RemoveRangeCheck(idRange)

	# Now forcibly empty the list and remove our target ID
	g_idTarget = App.NULL_ID
	g_lCurrentRangeChecks = [ ]

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
	pScience = App.CharacterClass_GetObject(pSet, "Science")
	pDatabase = pScience.GetDatabase()

	pGame = App.Game_GetCurrentGame()
	pShip = App.ShipClass_Cast(pGame.GetPlayer())

	pSequence = App.TGSequence_Create()
	# Talk about sensor status
	pSensorSystem = pShip.GetSensorSubsystem()
	fCondition = pSensorSystem.GetCombinedConditionPercentage()
	if (fCondition >= 0.95):
		pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SPEAK_LINE, "SensorSystemFunctional", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (not pSensorSystem.IsDisabled()):
		pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SPEAK_LINE, "SensorSystemDamaged", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	elif (fCondition > 0.0):
		pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SPEAK_LINE, "SensorSystemDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SPEAK_LINE, "SensorSystemDestroyed", None, 0, pDatabase, App.CSP_SPONTANEOUS))

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
#	GetScanActionSequence(fDelay)
#	
#	Returns a sequence to make the Science officer 'look busy' during a scan
#	NOTICE
#	fDelay is no longer used - it was causing more trouble than it was worth,
#	and no one was using it anyway =P
#	Therefore, I am leaving the argument there, so that scripts that do pass 0
#	don't break, but the arg itself is not used anywhere in the function
#	
#	Args:	fDelay, amount of time to "look busy" for.
#	
#	Return:	pSequence	- sequence of animations to play
###############################################################################
def GetScanSequence(fDelay = 3.0, sScanSound = "UIScanObject", pcScanLine = None, pDatabase = None):
	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")

	# Check to see if we have power to sensors.  If not, say we need some before we can continue
	pShip = MissionLib.GetPlayer()
	if not (pShip):
		return None

	pSensors = pShip.GetSensorSubsystem()
	if not (pSensors):
		return None

	if not (pSensors.IsOn()):
		App.CharacterAction_Create(pScience, App.CharacterAction.AT_SPEAK_LINE, "SensorPowerLow").Play()
		return None
		
	App.TGScriptAction_Create("Bridge.BridgeUtils", "DisableScanMenu").Play()

	pSequence = App.TGSequence_Create()

	# Look around, push some buttons, look around some more, then 'look like you're busy' until the scan is finished
	pStatusDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
	pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SET_STATUS, "Scanning", None, 0, pStatusDatabase))
	App.g_kLocalizationManager.Unload(pStatusDatabase)
	if not (pDatabase):
		pDatabase = pScience.GetDatabase()

	if (pcScanLine):
		pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, pcScanLine, None, 1, pDatabase))
	else:
		pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "MiguelScan", None, 1, pDatabase))
	if sScanSound:
		pSequence.AppendAction( App.TGSoundAction_Create(sScanSound) )
	pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
	return pSequence

#def DebugOutput(pAction, pcString):
#	debug(pcString)
#	return 0

###############################################################################
#	Scan(pObject, pEvent)
#	
#	Handles the "scan" menu item.
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def Scan(pObject, pEvent):
	try:
#		debug("Science Scan (Character version)\n")

		iType = pEvent.GetInt()

		pSet = App.g_kSetManager.GetSet("bridge")
		pScience = App.CharacterClass_GetObject(pSet, "Science")

		pGame = App.Game_GetCurrentGame()
		pShip = App.ShipClass_Cast(pGame.GetPlayer())
		pSensors = pShip.GetSensorSubsystem()
		if (App.ObjectClass_Cast(pEvent.GetSource())):
			pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		else:
			pTarget = App.ObjectClass_Cast(pShip.GetTarget())

		###Load localization database
		pDatabase = pScience.GetDatabase()

		if (iType == App.CharacterClass.EST_SCAN_OBJECT):
			if (pTarget):
				pScanSequence = GetScanSequence(sScanSound = "UIScanObject")
				if not (pScanSequence):
					pObject.CallNextHandler(pEvent)
					return

				pSequence = App.TGSequence_Create() 
				pSequence.AppendAction(pScanSequence)
				pSequence.AppendAction(App.TGScriptAction_Create("Actions.ShipScriptActions", "ScanObject", pShip.GetObjID(), pTarget.GetObjID()), 0.5)
				pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "gs0" + str(38 + App.g_kSystemWrapper.GetRandomNumber(4)), "Captain", 1, pDatabase), pSensors.GetIdentificationTime() + 0.5)
				pDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")
				pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SET_STATUS, "Waiting", None, 0, pDatabase))
				App.g_kLocalizationManager.Unload(pDatabase)
#				pSequence.AppendAction(App.TGScriptAction_Create(__name__, "DebugOutput", "Before Enable"))
				pSequence.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
#				pSequence.AppendAction(App.TGScriptAction_Create(__name__, "DebugOutput", "After Enable"))
				pSequence.Play()

		if (iType == App.CharacterClass.EST_SCAN_AREA):
			# Setup a sequence to scan each ship in the area.
#			debug("Setting up sequence")
			pScanSequence = GetScanSequence(sScanSound = "UIScanArea")
			if not (pScanSequence):
				pObject.CallNextHandler(pEvent)
				return

			pSequence = pSensors.ScanAllObjects()
			if (pSequence != None):
#				debug("Adding character actions")

				pStatDatabase = App.g_kLocalizationManager.Load("data/TGL/CharacterStatus.tgl")

				pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "gs0" + str(38 + App.g_kSystemWrapper.GetRandomNumber(4)), "Captain", 1, pDatabase), pSensors.GetIdentificationTime() + 0.5)
#				pSequence.AppendAction(App.TGScriptAction_Create(__name__, "DebugOutput", "Before enable"))
				pSequence.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
#				pSequence.AppendAction(App.TGScriptAction_Create(__name__, "DebugOutput", "After enable"))
				pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SET_STATUS, "Waiting", None, 0, pStatDatabase))

				pSequence2 = App.TGSequence_Create()
				pSequence2.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SET_STATUS, "Scanning", None, 0, pStatDatabase))
				pSequence2.AppendAction(pScanSequence)
				pSequence2.AppendAction(pSequence)

				App.g_kLocalizationManager.Unload(pStatDatabase)

				pSequence2.Play()
			else:
				pScanSequence.Completed()
	except:
		pass
#		debug("Exception raised in Bridge.ScienceMenuHandlers.Scan()")

	import BridgeHandlers
	BridgeHandlers.TalkToScience()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	LaunchProbe(pObject, pEvent)
#	
#	Launches a probe from the player's ship.
#	
#	Args:	pObject		- the target of the event
#			pEvent		- the event that was sent
#	
#	Return:	none
###############################################################################
def LaunchProbe(pObject, pEvent):
	# Launch one of them probe thingies from the player's ship.
	pGame = App.Game_GetCurrentGame()
	pShip = MissionLib.GetPlayer()

	if (pGame == None) or (pShip == None):
		pObject.CallNextHandler(pEvent)
		return

	pSet = pShip.GetContainingSet()
	pSensors = pShip.GetSensorSubsystem()
	if (not pSet) or (not pSensors):
		pObject.CallNextHandler(pEvent)
		return

	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pBridgeSet, "Science")

	if (not pBridgeSet) or (not pScience):
		pObject.CallNextHandler(pEvent)
		return

	###Load localization database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	# Check the number of probes remaining.
	if pSensors.GetNumProbes() <= 0:
		# No probes remaining.
		pAction1 = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "gs036", "Captain", 1, pDatabase)
		pAction1.Play()
		pObject.CallNextHandler(pEvent)

		App.g_kLocalizationManager.Unload(pDatabase)
		return

	# Decrement the number of probes available by one.
	pSensors.SetNumProbes(pSensors.GetNumProbes() - 1)
	pSequence = App.TGSequence_Create()

	pAction1 = App.TGScriptAction_Create("Bridge.BridgeUtils", "DisableLaunchProbe")
	pSequence.AddAction(pAction1)
	pAction2 = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, pScience.GetCharacterName() + "Yes1", "Captain", 1, pDatabase)
	pSequence.AddAction(pAction2)
	pAction3 = App.CharacterAction_Create(pScience, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons")
	pSequence.AddAction(pAction3, pAction2, 0.7)
	pAction4 = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "gs030", "Captain", 1, pDatabase)
	pSequence.AddAction(pAction4, pAction3, 0.5)
	pAction5 = App.TGScriptAction_Create("Bridge.ScienceMenuHandlers", "MakeLaunchProbeAction", pShip.GetObjID())
	pSequence.AddAction(pAction5, pAction4)
	pAction6 = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableLaunchProbe")
	pSequence.AddAction(pAction6, pAction5)

	pSequence.Play()

	###Unload database
	App.g_kLocalizationManager.Unload(pDatabase)

	pObject.CallNextHandler(pEvent)

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
	if (g_fTargetSet + 10 > App.g_kUtopiaModule.GetGameTime()):
		# No need to talk about it so soon
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	pShip = MissionLib.GetPlayer()

	if (pShip == None):
		pObject.CallNextHandler(pEvent)
		return

	global g_idTarget
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if not (pTarget):
		RemoveTargetWatchers()
		pObject.CallNextHandler(pEvent)
		return 

	if (pTarget.IsDying()):
		RemoveTargetWatchers()
		pObject.CallNextHandler(pEvent)
		return 

	# Make sure they have shield systems, and that those systems are powered
	pShields = pTarget.GetShields()
	if not (pShields):
		pObject.CallNextHandler(pEvent)
		return 

	if not (pShields.IsOn()):
		pObject.CallNextHandler(pEvent)
		return 

	pProp = pTarget.GetShipProperty()
	if (pProp.GetGenus() == App.GENUS_ASTEROID):
		# This is an asteroid, don't talk about it
		pObject.CallNextHandler(pEvent)
		return 

	if (pShields.IsDisabled()):
		pObject.CallNextHandler(pEvent)
		return 

	if not (pEvent.GetDestination()):
		pObject.CallNextHandler(pEvent)
		return

	if not (pTarget.GetObjID() == pEvent.GetDestination().GetObjID()):
		pObject.CallNextHandler(pEvent)
		return

	# Make sure this is an enemy before continuing
	pMission = MissionLib.GetMission()
	if not (pMission):
		pObject.CallNextHandler(pEvent)
		return

	if not (pMission.GetEnemyGroup().IsNameInGroup(pTarget.GetName())):
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")

	if (pScience.IsHidden() or pScience.IsAnimatingNonInterruptable() or pScience.IsSpeaking()):
		pObject.CallNextHandler(pEvent)
		return

	# Create a sequence to make engineer "look active" then call out the new shield status
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceSpecificShield", pEvent.GetEventType()))
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
	if (g_fTargetSet + 10 > App.g_kUtopiaModule.GetGameTime()):
		# No need to talk about it so soon
		return 0

	pShip = MissionLib.GetPlayer()

	if (pShip == None):
		return(0)

	global g_idTarget
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if not (pTarget):
		RemoveTargetWatchers()
		return 0

	pProp = pTarget.GetShipProperty()
	if (pProp.GetGenus() == App.GENUS_ASTEROID):
		# This is an asteroid, don't talk about it
		return 0

	if (pProp.GetGenus() == App.GENUS_STATION):
		# This is a space station, don't talk about its shields
		return 0

	if (pTarget.IsDying()):
		RemoveTargetWatchers()
		return 0

	# Make sure they have shield systems, and that those systems are powered
	pShields = pTarget.GetShields()
	if not (pShields):
		return 0

	if not (pShields.IsOn()):
		return 0

	if (pShields.IsDisabled()):
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")
	if (pScience.IsHidden() or pScience.IsAnimatingNonInterruptable() or pScience.IsSpeaking() or pScience.IsReadyToSpeak()):
		return 0

	global g_fLastCallOutTime
	fLastTime = App.g_kUtopiaModule.GetGameTime() - g_fLastCallOutTime
	if (fLastTime < 5.0):
		return 0

	pString = "Target"
	if (iEventType == App.ET_TACTICAL_SHIELD_0_LEVEL_CHANGE):
		if (pTarget.GetShields().GetMaxShields(App.ShieldClass.FRONT_SHIELDS) <= 0.0):
			return 0
		fShields = pTarget.GetShields().GetSingleShieldPercentage(App.ShieldClass.FRONT_SHIELDS)
		pString = pString + "Front"
	elif (iEventType == App.ET_TACTICAL_SHIELD_1_LEVEL_CHANGE):
		if (pTarget.GetShields().GetMaxShields(App.ShieldClass.REAR_SHIELDS) <= 0.0):
			return 0
		fShields = pTarget.GetShields().GetSingleShieldPercentage(App.ShieldClass.REAR_SHIELDS)
		pString = pString + "Rear"
	elif (iEventType == App.ET_TACTICAL_SHIELD_2_LEVEL_CHANGE):
		if (pTarget.GetShields().GetMaxShields(App.ShieldClass.TOP_SHIELDS) <= 0.0):
			return 0
		fShields = pTarget.GetShields().GetSingleShieldPercentage(App.ShieldClass.TOP_SHIELDS)
		pString = pString + "Top"
	elif (iEventType == App.ET_TACTICAL_SHIELD_3_LEVEL_CHANGE):
		if (pTarget.GetShields().GetMaxShields(App.ShieldClass.BOTTOM_SHIELDS) <= 0.0):
			return 0
		fShields = pTarget.GetShields().GetSingleShieldPercentage(App.ShieldClass.BOTTOM_SHIELDS)
		pString = pString + "Bottom"
	elif (iEventType == App.ET_TACTICAL_SHIELD_4_LEVEL_CHANGE):
		if (pTarget.GetShields().GetMaxShields(App.ShieldClass.LEFT_SHIELDS) <= 0.0):
			return 0
		fShields = pTarget.GetShields().GetSingleShieldPercentage(App.ShieldClass.LEFT_SHIELDS)
		pString = pString + "Left"
	elif (iEventType == App.ET_TACTICAL_SHIELD_5_LEVEL_CHANGE):
		if (pTarget.GetShields().GetMaxShields(App.ShieldClass.RIGHT_SHIELDS) <= 0.0):
			return 0
		fShields = pTarget.GetShields().GetSingleShieldPercentage(App.ShieldClass.RIGHT_SHIELDS)
		pString = pString + "Right"
	else:
#		debug("Uh oh, we don't know what shield they just got hit on (number " + str(iEventType) + ")?")
		return 0

	if (fShields > 0.6):
		# We're too high, no need for the call-out
		return 0

	pString = pString + "Shield"

	if (fShields < 0.1):
		pString = pString + "Failed"
	else:
		pString = pString + "Draining"

	pDatabase = pScience.GetDatabase()
#	debug(pString)
	pScience.SayLine(pDatabase, pString, "Captain", 1, App.CSP_SPONTANEOUS)

	g_fLastCallOutTime = App.g_kUtopiaModule.GetGameTime()

	return 0

###############################################################################
#	HullLevelChange(pObject, pEvent)
#
#	Handler function for hull level change event.
#
#	Args:	pObject 	- target for this event.
#			pEvent		- Event we are handling.
#
#	Return:	none
###############################################################################
def HullLevelChange(pObject, pEvent):
	if (g_fTargetSet + 10 > App.g_kUtopiaModule.GetGameTime()):
		# No need to talk about it so soon
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	pShip = MissionLib.GetPlayer()
	if (pShip == None):
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")

	global g_idTarget
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if not (pTarget):
		RemoveTargetWatchers()
		pObject.CallNextHandler(pEvent)
		return

	if (pTarget.IsDying()):
		RemoveTargetWatchers()
		pObject.CallNextHandler(pEvent)
		return 

	if not (pEvent.GetDestination()):
		pObject.CallNextHandler(pEvent)
		return

	if not (pTarget.GetObjID() == pEvent.GetDestination().GetObjID()):
		pObject.CallNextHandler(pEvent)
		return

	# Make sure this is an enemy before continuing
	pMission = MissionLib.GetMission()
	if not (pMission):
		pObject.CallNextHandler(pEvent)
		return

	if not (pMission.GetEnemyGroup().IsNameInGroup(pTarget.GetName())):
		pObject.CallNextHandler(pEvent)
		return


	if (pScience.IsHidden() or pScience.IsAnimatingNonInterruptable() or pScience.IsSpeaking()):
		pObject.CallNextHandler(pEvent)
		return

	# Create a sequence to make engineer "look active" then call out the new shield status
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceHull"), 0.5)
	pSequence.Play()

	pObject.CallNextHandler(pEvent)


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
	if (g_fTargetSet + 10 > App.g_kUtopiaModule.GetGameTime()):
		# No need to talk about it so soon
		return 0

	pShip = App.Game_GetCurrentGame().GetPlayer()
	if (pShip == None):
		return(0)

	global g_idTarget
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if not (pTarget):
		RemoveTargetWatchers()
		return 0

	if (pTarget.IsDying()):
		RemoveTargetWatchers()
		return 0

	pProp = pTarget.GetShipProperty()
	if (pProp.GetGenus() == App.GENUS_ASTEROID):
		# This is an asteroid, don't talk about it
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")
	if (pScience.IsHidden() or pScience.IsAnimatingNonInterruptable() or pScience.IsSpeaking() or pScience.IsReadyToSpeak()):
		return 0

	if not (pTarget.GetHull()):
		return 0

	fHull = pTarget.GetHull().GetConditionPercentage()

	pDatabase = pScience.GetDatabase()

	global g_fLastCallOutTime
	fLastTime = App.g_kUtopiaModule.GetGameTime() - g_fLastCallOutTime

	if (fHull <= 0.05 and fLastTime > 4.0):
		pScience.SayLine(pDatabase, "TargetHull05", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("TargetHull 05")
	elif (fHull <= 0.1 and fLastTime > 5.0):
		pScience.SayLine(pDatabase, "TargetHull10", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("TargetHull 10")
	elif (fHull <= 0.15 and fLastTime > 5.0):
		pScience.SayLine(pDatabase, "TargetHull15", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("TargetHull 15")
	elif (fHull <= 0.2 and fLastTime > 5.0):
		pScience.SayLine(pDatabase, "TargetHull20", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("TargetHull 20")
	elif (fHull <= 0.25 and fLastTime > 5.0):
		pScience.SayLine(pDatabase, "TargetHull25", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("TargetHull 25")
	elif (fHull <= 0.5 and fLastTime > 5.0):
		pScience.SayLine(pDatabase, "TargetHull50", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("TargetHull 50")
	elif (fHull <= 0.75 and fLastTime > 6.0):
		pScience.SayLine(pDatabase, "TargetHull75", "Captain", 1, App.CSP_SPONTANEOUS)
#		debug("TargetHull 75")

	g_fLastCallOutTime = App.g_kUtopiaModule.GetGameTime()

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
	if (g_fTargetSet + 10 > App.g_kUtopiaModule.GetGameTime()):
		# No need to talk about it so soon
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
 
	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return

	if not (pEvent.GetDestination()):
		pObject.CallNextHandler(pEvent)
		return

	if not (pEvent.GetSource()):
		pObject.CallNextHandler(pEvent)
		return

	global g_idTarget
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if not (pTarget):
		RemoveTargetWatchers()
		pObject.CallNextHandler(pEvent)
		return

	if (pTarget.IsDying()):
		RemoveTargetWatchers()
		pObject.CallNextHandler(pEvent)
		return 

	if not (pEvent.GetDestination()):
		pObject.CallNextHandler(pEvent)
		return

	if not (pEvent.GetDestination().GetObjID() == pTarget.GetObjID()):
		pObject.CallNextHandler(pEvent)
		return

	# Make sure this is an enemy before continuing
	pMission = MissionLib.GetMission()
	if not (pMission):
		pObject.CallNextHandler(pEvent)
		return

	if not (pMission.GetEnemyGroup().IsNameInGroup(pTarget.GetName())):
		pObject.CallNextHandler(pEvent)
		return

	pProp = pTarget.GetShipProperty()
	if (pProp.GetGenus() == App.GENUS_ASTEROID):
		# This is an asteroid, don't talk about it
		pObject.CallNextHandler(pEvent)
		return

	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")
	if (pScience.IsHidden() or pScience.IsAnimatingNonInterruptable() or pScience.IsSpeaking()):
		pObject.CallNextHandler(pEvent)

	pDatabase = pScience.GetDatabase()
	fLastTime = App.g_kUtopiaModule.GetGameTime() - pScience.GetLastTalkTime()

	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))

	idSource = pEvent.GetSource().GetObjID()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceSystemDisabled", idSource), 0.5)
	pSequence.Play()

#	debug("A system has become disabled")

	pObject.CallNextHandler(pEvent)

###############################################################################
#	AnnounceSystemDisabled(pAction, idSource)
#	
#	Announces when a system has been disabled.
#	
#	Args:	pAction		- the action
#			idSource	- the ID of the source of the disabled event
#	
#	Return:	zero for end
###############################################################################
def AnnounceSystemDisabled(pAction, idSource):
	if (g_fTargetSet + 10 > App.g_kUtopiaModule.GetGameTime()):
		# No need to talk about it so soon
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")
	if (pScience.IsHidden() or pScience.IsAnimatingNonInterruptable() or pScience.IsSpeaking() or pScience.IsReadyToSpeak()):
		return 0

	global g_idTarget
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if not (pTarget):
		RemoveTargetWatchers()
		return 0

	if (pTarget.IsDying()):
		RemoveTargetWatchers()
		return 0

	pDatabase = pScience.GetDatabase()

	global g_fLastCallOutTime
	fLastTime = App.g_kUtopiaModule.GetGameTime() - g_fLastCallOutTime
	if (fLastTime < 5):
		return 0
	g_fLastCallOutTime = App.g_kUtopiaModule.GetGameTime()

	pSource = App.TGObject_GetTGObjectPtr(idSource)
	if (App.PhaserSystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetPhasersDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.ShieldClass_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetShieldsDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.SensorSubsystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetSensorsDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.TorpedoSystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetTorpedoesDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.TractorBeamSystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetTractorDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.ImpulseEngineSubsystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetImpulseDisabled", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.WarpEngineSubsystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetWarpDisabled", "Captain", 1, App.CSP_SPONTANEOUS)

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
	if (g_fTargetSet + 10 > App.g_kUtopiaModule.GetGameTime()):
		# No need to talk about it so soon
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	pGame = App.Game_GetCurrentGame()
	pPlayer = MissionLib.GetPlayer()

	if not (pPlayer):
		pObject.CallNextHandler(pEvent)
		return
	if not (pEvent.GetDestination()):
		pObject.CallNextHandler(pEvent)
		return

	global g_idTarget
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if not (pTarget):
		RemoveTargetWatchers()
		pObject.CallNextHandler(pEvent)
		return

	if (pTarget.IsDying()):
		RemoveTargetWatchers()
		pObject.CallNextHandler(pEvent)
		return 

	if not (pEvent.GetDestination()):
		pObject.CallNextHandler(pEvent)
		return

	if not (pEvent.GetDestination().GetObjID() == pTarget.GetObjID()):
		pObject.CallNextHandler(pEvent)
		return

	# Make sure this is an enemy before continuing
	pMission = MissionLib.GetMission()
	if not (pMission):
		pObject.CallNextHandler(pEvent)
		return

	if not (pMission.GetEnemyGroup().IsNameInGroup(pTarget.GetName())):
		pObject.CallNextHandler(pEvent)
		return

	pProp = pTarget.GetShipProperty()
	if (pProp.GetGenus() == App.GENUS_ASTEROID):
		# This is an asteroid, don't talk about it
		pObject.CallNextHandler(pEvent)
		return 

	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")
	if (pScience.IsHidden() or pScience.IsAnimatingNonInterruptable() or pScience.IsSpeaking()):
		pObject.CallNextHandler(pEvent)
		return

	pDatabase = pScience.GetDatabase()

	pSystem = pEvent.GetSource()
	if pSystem:
		idSystem = pSystem.GetObjID()

		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AnnounceSystemDestroyed", idSystem), 0.5)
		pSequence.Play()

	#debug("A system has become destroyed")

	pObject.CallNextHandler(pEvent)

def AnnounceSystemDestroyed(pAction, idSource):
	if (g_fTargetSet + 10 > App.g_kUtopiaModule.GetGameTime()):
		# No need to talk about it so soon
		return 0

	pSet = App.g_kSetManager.GetSet("bridge")
	pScience = App.CharacterClass_GetObject(pSet, "Science")
	if (pScience.IsHidden() or pScience.IsAnimatingNonInterruptable() or pScience.IsSpeaking() or pScience.IsReadyToSpeak()):
		return 0

	global g_idTarget
	pTarget = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idTarget))
	if not (pTarget):
		RemoveTargetWatchers()
		return 0

	if (pTarget.IsDying()):
		RemoveTargetWatchers()
		return 0

	# Get the subsystem that was destroyed.
	pSource = App.ShipSubsystem_Cast(App.TGObject_GetTGObjectPtr(idSource))
	if not pSource:
		# The subsystem doesn't exist anymore.  Ship was probably destroyed.
		return 0

	pDatabase = pScience.GetDatabase()

	global g_fLastCallOutTime
	fLastTime = App.g_kUtopiaModule.GetGameTime() - g_fLastCallOutTime
	if (fLastTime < 5):
		return 0
	g_fLastCallOutTime = App.g_kUtopiaModule.GetGameTime()

	if (App.PhaserSystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetPhasersDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.ShieldClass_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetShieldsDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.SensorSubsystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetSensorsDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.TorpedoSystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetTorpedoesDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.TractorBeamSystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetTractorDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.ImpulseEngineSubsystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetImpulseDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)
	elif (App.WarpEngineSubsystem_Cast(pSource)):
		pScience.SayLine(pDatabase, "TargetWarpDestroyed", "Captain", 1, App.CSP_SPONTANEOUS)

	return 0

