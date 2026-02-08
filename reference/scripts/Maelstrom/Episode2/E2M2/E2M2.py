###############################################################################
#	Filename:	E2M2.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 2, Mission 2
#	
#	Created:	10/19/00 -	Jess VanDerwalker
#	Revised:	1/10/01
###############################################################################
import App
import loadspacehelper
import MissionLib
import Actions.MissionScriptActions
import Actions.CameraScriptActions
import Bridge.BridgeUtils
import Bridge.ScienceCharacterHandlers
import Maelstrom.Episode2.Episode2
import Maelstrom.Episode2.AI_WarpOut

# Declare global variables
TRUE				= 1
FALSE				= 0

g_pMissionDatabase	= None
g_pGeneralDatabase	= None
g_pDatabase			= None

g_bMissionTerminate	= None

g_iProdTimer		= None
g_sProdLine			= None
g_iBackToSerrisProd	= None

g_bSequenceRunning	= None
g_bCantWarp			= None

g_iMissionState	= None
DEFAULT			= None
IN_SERRIS3		= None
IN_SERRIS2		= None
SHIPS_ID		= None
GALORS_LEAVE	= None
GALORS_RETURN	= None

g_bPlayerArriveSerris2		= None
g_bPlayerNotInSerris		= None
g_bPlayerInWarp				= None

g_bSerris3ScanDone		= None
g_bPlayerScannedSerris3	= None

g_bShipsOnSensors		= None
g_bShipsIDd				= None
g_bCheckShipIDdCalled	= None
g_bPlayerNotVisible		= None
g_bPlayerInRange		= None
g_bPlayerSneaking		= None
g_bCanHearMsg			= None
g_bPlayerDetected		= None
g_bCoversationHeard		= None
g_bCantWarp				= None
g_bGalorsLeaveOnce		= None

g_bPlayerInterceptDone	= None
g_bMarauderFiresPlayer	= None
g_bMarauderDisabled		= None
g_bMarauderDestroyed	= None
g_bMarauderEscaped		= None
g_bMissionWon			= None
g_bEndDialoguePlayed	= None
g_bMarauderRuns			= None
g_bMarauderNeedsHelp	= None
g_bPlayerFiredUpon		= None

g_iMarauderWarpRepairRate	= None

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None

g_lShipNames	= []

g_lCardShipNames	= []

g_pKeldon1Targets	= None
g_pGalor2Targets	= None

g_iWarpTimerID	= None

# Event types
ET_MARAUDER_WARP_TIMER		= App.Mission_GetNextEventType()
ET_MARAUDER_WARP_WARNING	= App.Mission_GetNextEventType()
ET_PROD_TIMER				= App.Mission_GetNextEventType()
ET_CLEAR_FLAGS				= App.Mission_GetNextEventType()

###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to load ship instances.
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Galaxy", 1)
	loadspacehelper.PreloadShip("Marauder", 1)
	loadspacehelper.PreloadShip("Galor", 1)
	loadspacehelper.PreloadShip("Keldon", 1)
	
################################################################################
##	Initialize()
##	
##  Called once when mission loads to initialize mission
##	
##	Args: pMission - the mission object
##	
##	Return: None
################################################################################
def Initialize(pMission):
	# Initialize all our global variables
	InitializeGlobals(pMission)

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")
	
	# Initialize our global pointers to the bridge crew
	InitializeCrewPointers()
	
	# Create our regions
	CreateRegions()

	# Create the viewscreen sets we'll need
	CreateSets()
	
	# Setup the friendly fire
	MissionLib.SetupFriendlyFire()
	
	# Create objects that exist at beginning of mission
	CreateStartingObjects(pMission)
	
	# Create AI target lists
	CreateTargetLists()
	
	# Setup our event handlers
	SetupEventHandlers(pMission)

	# Set the stats on the players ship
	App.Game_SetDifficultyMultipliers(1.0, 1.2, 0.9, 1.0, 0.75, 0.75)

	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)

	# Call PlayerArrivedSerris3()
	PlayerArrivedSerris3()

	# Save the game
	MissionLib.SaveGame("E2M2-")
	
################################################################################
##	InitializeGlobals(pMission)
##
##	Sets the initial values of all our global variables.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
	# Globals for used with bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0
	
	# Set g_bMissionTerminate here in case mission gets reloaded
	global g_bMissionTerminate
	g_bMissionTerminate = 1
	
	# TGL database globals
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 2/E2M2.tgl")
	g_pGeneralDatabase 	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	
	# Timer ID global used with prodding
	global g_iProdTimer
	global g_sProdLine
	global g_iBackToSerrisProd
	g_iProdTimer		= App.NULL_ID
	g_sProdLine			= "E2M2Serris2Prod"
	g_iBackToSerrisProd	= 0

	# Flag used to tell if sequence is running
	global g_bSequenceRunning
	g_bSequenceRunning	= FALSE
	
	# Flag to see if we can warp or not
	global g_bCantWarp
	g_bCantWarp = FALSE
	
	# Globals used for Communicate
	global g_iMissionState
	global DEFAULT
	global IN_SERRIS3
	global IN_SERRIS2
	global SHIPS_ID
	global GALORS_LEAVE
	global GALORS_RETURN
	g_iMissionState	= 1
	DEFAULT			= 0
	IN_SERRIS3		= 1
	IN_SERRIS2		= 2
	SHIPS_ID		= 3
	GALORS_LEAVE	= 4
	GALORS_RETURN	= 5

	# Flags for tracking player
	global g_bPlayerArriveSerris2
	global g_bPlayerNotInSerris
	global g_bPlayerInWarp
	g_bPlayerArriveSerris2		= FALSE
	g_bPlayerNotInSerris		= FALSE
	g_bPlayerInWarp				= FALSE

	# Flags for mission events
	global g_bSerris3ScanDone
	global g_bPlayerScannedSerris3
	global g_bShipsOnSensors
	global g_bShipsIDd
	global g_bCheckShipIDdCalled
	global g_bPlayerNotVisible
	global g_bPlayerSneaking
	global g_bPlayerInRange
	global g_bCanHearMsg
	global g_bPlayerDetected
	global g_bCoversationHeard
	global g_bCantWarp
	global g_bGalorsLeaveOnce
	global g_bPlayerInterceptDone
	global g_bMarauderFiresPlayer
	global g_bMarauderDisabled
	global g_bMissionWon
	global g_bEndDialoguePlayed
	global g_bMarauderRuns
	global g_bMarauderNeedsHelp
	global g_bPlayerFiredUpon
	g_bSerris3ScanDone		= FALSE
	g_bPlayerScannedSerris3	= FALSE
	g_bShipsOnSensors		= FALSE
	g_bShipsIDd				= FALSE
	g_bCheckShipIDdCalled	= FALSE
	g_bPlayerInRange		= FALSE
	g_bPlayerNotVisible		= TRUE
	g_bPlayerSneaking		= TRUE
	g_bCanHearMsg			= FALSE
	g_bPlayerDetected		= FALSE
	g_bCantWarp				= FALSE
	g_bCoversationHeard		= FALSE
	g_bGalorsLeaveOnce		= FALSE
	g_bPlayerInterceptDone	= FALSE
	g_bMarauderFiresPlayer	= FALSE
	g_bMarauderDisabled		= FALSE
	g_bMissionWon			= FALSE
	g_bEndDialoguePlayed	= FALSE
	g_bMarauderRuns			= FALSE
	g_bMarauderNeedsHelp	= FALSE
	g_bPlayerFiredUpon		= FALSE

	# Flags for tracking ships other than player
	global g_bMarauderDestroyed
	global g_bMarauderEscaped
	g_bMarauderDestroyed	= FALSE
	g_bMarauderEscaped		= FALSE

	# Global for the original repair rate of the
	# Marauder's warp engines.
	global g_iMarauderWarpRepairRate
	g_iMarauderWarpRepairRate	= None
	
	# List of ship names other than player
	global g_lShipNames
	g_lShipNames	=	[
						"Keldon 1", "Galor 2", "Marauder"
						]

	# List of Cardassian ship names
	global g_lCardShipNames
	g_lCardShipNames	=	[
							"Keldon 1", "Galor 2"
							]
							
	# Globals used for AI target lists
	global g_pKeldon1Targets
	global g_pGalor2Targets
	g_pKeldon1Targets	= None
	g_pGalor2Targets	= None

	# Global ID for the Marauder's warp timer
	global g_iWarpTimerID
	g_iWarpTimerID	= App.NULL_ID

	# Event types
	global ET_MARAUDER_WARP_TIMER
	global ET_MARAUDER_WARP_WARNING
	global ET_PROD_TIMER
	global ET_CLEAR_FLAGS
	ET_MARAUDER_WARP_TIMER		= App.Mission_GetNextEventType()
	ET_MARAUDER_WARP_WARNING	= App.Mission_GetNextEventType()
	ET_PROD_TIMER				= App.Mission_GetNextEventType()
	ET_CLEAR_FLAGS				= App.Mission_GetNextEventType()
	
################################################################################
##	InitializeCrewPointers()
##
##	Initializes the global pointers to the bridge crew members and their menus.
##	NOTE: This must be called after the bridge has been loaded.
##
##	Args:	None
##
##	Return:	None
################################################################################
def InitializeCrewPointers():	
	# Get the bridge
	pBridge = App.g_kSetManager.GetSet("bridge")
	
	# Set the globals
	global g_pKiska
	global g_pFelix
	global g_pSaffi
	global g_pMiguel
	global g_pBrex
	
	g_pKiska	= App.CharacterClass_GetObject(pBridge, "Helm")
	g_pFelix	= App.CharacterClass_GetObject(pBridge, "Tactical")
	g_pSaffi	= App.CharacterClass_GetObject(pBridge, "XO")
	g_pMiguel	= App.CharacterClass_GetObject(pBridge, "Science")
	g_pBrex		= App.CharacterClass_GetObject(pBridge, "Engineer")
	
################################################################################
##	CreateSets()
##
##	Creates the viewscreen sets that will be used in this mission and populates
##	them.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateSets():
	# Starbase set with Liu
	pStarbaseSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu			= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)

	# Marauder set with Praag
	pMarauderSet	= MissionLib.SetupBridgeSet("MarauderSet", "data/Models/Sets/Ferengi/ferengibridge.nif", -40, 65, -1.55)
	pPraag			= MissionLib.SetupCharacter("Bridge.Characters.Praag", "MarauderSet")
	
################################################################################
##	CreateRegions()
##
##	Create all the regions we'll be using and load our placements for them.
##	Also creates systems in helm.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateRegions():
	pSerris3Set		= MissionLib.SetupSpaceSet("Systems.Serris.Serris3")
	pSerris2Set		= MissionLib.SetupSpaceSet("Systems.Serris.Serris2")
	pVesuvi6Set		= MissionLib.SetupSpaceSet("Systems.Vesuvi.Vesuvi6")
	pStarbaseSet	= MissionLib.SetupSpaceSet("Systems.Starbase12.Starbase12")
	pDeepSpaceSet	= MissionLib.SetupSpaceSet("Systems.DeepSpace.DeepSpace")
	
	# Load mission specific placements into sets
	import E2M2_Serris2_P
	import E2M2_DeepSpace_P
	E2M2_Serris2_P.LoadPlacements(pSerris2Set.GetName())
	E2M2_DeepSpace_P.LoadPlacements(pDeepSpaceSet.GetName())
	
	# Setup Warp Menu Buttons for Helm
	import Systems.Starbase12.Starbase
	import Systems.Serris.Serris
	import Systems.Vesuvi.Vesuvi

	pStarbaseMenu	= Systems.Starbase12.Starbase.CreateMenus()
	pSerrisMenu		= Systems.Serris.Serris.CreateMenus()
	pVesuviMenus	= Systems.Vesuvi.Vesuvi.CreateMenus()

################################################################################
##	CreateStartingObjects()
##
##	Creates all the objects that exist at the beginning of the mission.  Also
##	assigns ship affiliations.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def CreateStartingObjects(pMission):
	# Get the sets we need
	pSerris3Set		= App.g_kSetManager.GetSet("Serris3")
	pSerris2Set		= App.g_kSetManager.GetSet("Serris2")
	pStarbaseSet	= App.g_kSetManager.GetSet("Starbase12")
	
	# Create the ships
	pPlayer 	= MissionLib.CreatePlayerShip("Galaxy", pSerris3Set, "player", "Player Start")
	pStarbase12	= loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	pMarauder	= loadspacehelper.CreateShip("Marauder", pSerris2Set, "Marauder", "MarauderStart")
	pKeldon1	= loadspacehelper.CreateShip("Keldon", pSerris2Set, "Keldon 1", "Galor1Start")
	pGalor2		= loadspacehelper.CreateShip("Galor", pSerris2Set, "Galor 2", "Galor2Start")
	
	# Give starting AIs to ships
	import E2M2_AI_Stay
	pMarauder.SetAI(E2M2_AI_Stay.CreateAI(pMarauder))
	pGalor2.SetAI(E2M2_AI_Stay.CreateAI(pGalor2))
	pKeldon1.SetAI(E2M2_AI_Stay.CreateAI(pKeldon1))
	
	# Setup the Marauder so it's easier to take down.
	PrepMarauder(pMarauder)
	
	# Setup the Cardassians so you can't take out their warp engines.
	PrepCards([pKeldon1, pGalor2])
	
	# Setup ship affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	
	pNeutral = pMission.GetNeutralGroup()
	for sName in g_lShipNames:
		pNeutral.AddName(sName)

	# Make the Marauder tractorable
	pTractorGroup = pMission.GetTractorGroup()
	pTractorGroup.AddName("Marauder")
	
	# Create the line of sight condition
	pCondition = App.ConditionScript_Create("Conditions.ConditionInLineOfSight", "ConditionInLineOfSight", "player", "Keldon 1", "Serris 2")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "PlayerVisibleChanged", pCondition)
	
	# Create the in range condition
	pCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 800, "player", "Keldon 1")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "PlayerInRangeChanged", pCondition)

################################################################################
##	PrepMarauder()
##
##	Alter the Marauder's attributes so it's  easier to take down.
##
##	Args:	pShip	- The ship object to tweak.
##
##	Return:	None
################################################################################
def PrepMarauder(pShip):
	pSystem = pShip.GetWarpEngineSubsystem()

	for i in range(pSystem.GetNumChildSubsystems()):
		pChild = pSystem.GetChildSubsystem(i)
		pProp = pChild.GetProperty()
		# Get the original value and store it to the global
		global g_iMarauderWarpRepairRate
		g_iMarauderWarpRepairRate = pProp.GetRepairComplexity()
		# If we're not on hard, change the repair complexity
		eDifficulty = App.Game_GetDifficulty()
		if (eDifficulty != App.Game.HARD):
			pProp.SetRepairComplexity(10000.0)	
			
		# Set the disabled level on the warp engines
		pProp.SetDisabledPercentage(0.50)
		# Set the number of hitpoints
		pProp.SetMaxCondition(4100)

	# Up the hull points
	pHull = pShip.GetHull()
	if (pHull != None):
		pProp = pHull.GetProperty()
		pProp.SetMaxCondition(12000.0)
		pHull.SetCondition(pProp.GetMaxCondition())
	
################################################################################
##	PrepCards()
##
##	Alter the Cardassian ships so their warp engines can't be taken down.  Turns
##	off collisions as well.
##
##	Args:	lpShips	- List of ship objects to alter.
##
##	Return:	None
################################################################################
def PrepCards(lpShips):
	for pShip in lpShips:
		if (pShip != None):
			pShip.SetCollisionsOn(FALSE)
			pSystem = pShip.GetWarpEngineSubsystem()
			if (pSystem != None):
				MissionLib.MakeSubsystemsInvincible(pSystem)

				for i in range(pSystem.GetNumChildSubsystems()):
					pChild = pSystem.GetChildSubsystem(i)
					pProp = pChild.GetProperty()

					# Set the disabled level on the warp engines
					pProp.SetDisabledPercentage(0.25)
					# Increase their hit points to 6000
					pProp.SetMaxCondition(6000.0)
					pChild.SetCondition(pProp.GetMaxCondition())

################################################################################
##	CreateTargetLists()
##
##	Create the target lists that will be used by the AI ships.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateTargetLists():
	# Get the players name so we can add it to the list
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	sPlayerName	= pPlayer.GetName()
	
	# Target list for Keldon 1
	global g_pKeldon1Targets
	g_pKeldon1Targets = App.ObjectGroupWithInfo()
	g_pKeldon1Targets[sPlayerName]	= {"Priority"	:	1.5}
	g_pKeldon1Targets["Marauder"]	= {"Priority"	:	2.0}
	
	# Target list for Galor 2
	global g_pGalor2Targets
	g_pGalor2Targets = App.ObjectGroupWithInfo()
	g_pGalor2Targets[sPlayerName]	= {"Priority"	:	1.0}
	g_pGalor2Targets["Marauder"]	= {"Priority"	:	1.5}
		
################################################################################
##	SetupEventHandlers()
##	
##  Set up handlers for broadcast events that we will want to handle
##	
##	Args:	pMission	- The mission object.
##	
##	Return:	None
################################################################################
def SetupEventHandlers(pMission):
	# Ship enters set event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__+".EnterSet")
	# Ship exits set event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__+".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__+".ObjectDestroyed")
	# Weapon fired event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_WEAPON_FIRED, pMission, __name__+".WeaponFired")
	# Target comes into range of sensors
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_FAR_PROXIMITY, pMission, __name__+".ShipInSensorRange")
	# Target is ID'd by sensors event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_IDENTIFIED, pMission, __name__+".ShipIdentified")
		
	# Instance handlers on the mission for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")
	# Instance handler on the mission for friendly fire game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".FriendlyFireGameOverHandler")

	# Weapon hit event handler attached to the players ship
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".WeaponHitPlayer")
		# Power changed handler attached to the players ship
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_POWER_CHANGED, __name__ + ".PowerLevelChanged")

	# Instance handler for Miguel's menu
	pMiguelMenu = Bridge.BridgeUtils.GetBridgeMenu("Science")
	if (pMiguelMenu != None):
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN,		__name__ + ".ScanHandler")
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Instance handler for Kiska's menu
	pKiskaMenu = Bridge.BridgeUtils.GetBridgeMenu("Helm")
	if (pKiskaMenu != None):
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL,			__name__ + ".HailHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_SET_COURSE,	__name__ + ".SetCourseHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		# Instance handler for warp button
		pWarpButton = Bridge.BridgeUtils.GetWarpButton()
		if (pWarpButton != None):
			pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")
			
	# Instance handler for Saffi's menu
	pSaffiMenu = Bridge.BridgeUtils.GetBridgeMenu("XO")
	if (pSaffiMenu != None):
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET,	__name__ + ".HailStarfleet")
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,			__name__ + ".CommunicateHandler")
		
	# Instance handlers for Felix's menu
	pFelixMenu = Bridge.BridgeUtils.GetBridgeMenu("Tactical")
	if (pFelixMenu != None):
		pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
	
	# Instance handlers for Brex's menu
	pBrexMenu = Bridge.BridgeUtils.GetBridgeMenu("Engineer")
	if (pBrexMenu != None):
		pBrexMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

################################################################################
##	EnterSet()
##	
##  Called when ET_ENTERED_SET event is broadcast
##	
##	Args: 	TGObject -
##			pEvent - pointer to object event is being sent to
##	
##	Return:	None
################################################################################
def EnterSet(TGObject, pEvent):
	# Check to see if what entered is a ship
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if (pShip == None):
		return
	
	# Make sure the ship we're check is alive
	if (pShip.IsDead()):
		return
		
	pSet		= pShip.GetContainingSet()
	sSetName	= pSet.GetName()
	sShipName	= pShip.GetName()
	
	# See if it's the players ship and call
	# TrackPlayer() if it is.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		if (pPlayer.GetName() == sShipName):
			TrackPlayer(sSetName)

	# See if the Galors are leaving for the first time
	if (sSetName == "warp") and (sShipName == "Keldon 1") and (g_bGalorsLeaveOnce == FALSE) and (g_bMarauderDestroyed == FALSE):
		global g_bGalorsLeaveOnce
		g_bGalorsLeaveOnce = TRUE
		GalorsLeave()

	# Nothing else to do.  Let any other events for this event handle it
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ExitSet()
##	
##  Called when ET_EXITED_SET event is broadcast.  Used to determine if enemy
##	ship has been destroyed.
##	
##	Args: 	TGObject -	The TGObject object
##			pEvent - pointer to object event is being sent to
##	
##	Return:	None
################################################################################
def ExitSet(TGObject, pEvent):
	# Check and see if the mission is terminating
	if (g_bMissionTerminate != 1):
		return
		
	pShip 		= App.ShipClass_Cast(pEvent.GetDestination())
	sSetName	= pEvent.GetCString()

	if (pShip == None):
		return

	sShipName = pShip.GetName()
	
	# If the player exits the set, do our tracking
	pPlayer	= MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	if (sShipName == pPlayer.GetName()):
		PlayerExitsSet()
	
	# If the player is exiting the warp set, clear our flag
	if (sShipName == pPlayer.GetName()):
		global g_bPlayerInWarp
		g_bPlayerInWarp = FALSE
		
	# See if the Marauder has escaped and set our flag
	# and call our function
	global g_bMarauderEscaped
	if (sShipName == "Marauder") and (g_bMarauderEscaped == FALSE) and (g_bMarauderDestroyed == FALSE) and (g_bGalorsLeaveOnce == TRUE):
		g_bMarauderEscaped = TRUE
		MarauderEscapes()
		
	# Check and see if the Galors have been destroyed or
	# warped out of the set after engaging the player and Marauder
	if (sShipName in g_lCardShipNames) and (sSetName == "Serris2") and (g_bGalorsLeaveOnce == TRUE) and (g_bMarauderDisabled == TRUE):
		global g_lCardShipNames
		g_lCardShipNames.remove(sShipName)
		# If all the Cards have left, call MissionWin()
		if (len(g_lCardShipNames) == 0) and (g_bMarauderDestroyed == FALSE):
			MissionWin()
			
	# Nothing else to do.  Let any other events for this event handle it
	TGObject.CallNextHandler(pEvent)			

################################################################################
##	ObjectDestroyed()
##	
##  Called when ET_OBJECT_EXPLODING event is broadcast.  Used to check if Galor
##	has been destroyed or not.
##	
##	Args: 	TGObject -	The TGObject object.
##			pEvent - pointer to object event is being sent to
##	
##	Return:	None
################################################################################
def ObjectDestroyed(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if (pShip == None):
		return	
	sShipName	= pShip.GetName()
				
	# If the Marauder was destroyed...
	global g_bMarauderDestroyed
	if (sShipName == "Marauder"):
		g_bMarauderDestroyed = TRUE
		MarauderDestroyed()
	
	# If one of the Cards was destroyed, make the other one invincible
	if (sShipName in g_lCardShipNames):
		for sName in g_lCardShipNames:
			if (sName != sShipName):
				pShip = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Serris2"), sName)
				if (pShip != None):
					pShip.SetInvincible(TRUE)
					pShip.SetCollisionsOn(FALSE)
					
	# Nothing else to do.  Let any other events for this event handle it
	TGObject.CallNextHandler(pEvent)

################################################################################
##	WeaponFired()
##
##	Handler called if a ship fires a weapon.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WeaponFired(TGObject, pEvent):
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	pTargetShip	= App.ShipClass_Cast(pEvent.GetObjPtr())
	if (pTargetShip == None):
		return
	
	sSetName	= pShip.GetContainingSet().GetName()
	sShipName 	= pShip.GetName()
	sTargetName	= pTargetShip.GetName()
	
	# Get the players ship name
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	
	# If the Cards are firing, make them enemies
	if (sShipName in g_lCardShipNames):
		pMission	= MissionLib.GetMission()
		if (pMission == None):
			return
		pNeutrals	= pMission.GetNeutralGroup()
		pEnemies	= pMission.GetEnemyGroup()
	
		for sShipName in g_lCardShipNames:
			pNeutrals.RemoveName(sShipName)
			pEnemies.AddName(sShipName)

		# Affiliation colors sometimes don't get set correctly here (by the normal mechanisms). Reset
		# them, just in case.
		pTargetMenu = App.STTargetMenu_GetTargetMenu()
		if pTargetMenu:
			pTargetMenu.ResetAffiliationColors()

	# See if the Cards are firing on the Marauder
	if (sTargetName == "Marauder") and (sShipName in g_lCardShipNames) and (g_bPlayerSneaking == FALSE) and (g_bMarauderNeedsHelp == FALSE):
		global g_bMarauderNeedsHelp
		g_bMarauderNeedsHelp = TRUE
		MarauderNeedsHelp()
		# Get the Marauder and give it a new AI
		pShip	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Serris2"), "Marauder")	
		import E2M2_AI_MarauderAttack
		if (pShip != None):
			pShip.SetAI(E2M2_AI_MarauderAttack.CreateAI(pShip))
	
	# See if the Cards are firing on the Player
	if (sTargetName == pPlayer.GetName()) and (sShipName in g_lCardShipNames) and (g_bPlayerFiredUpon == FALSE):
		global g_bPlayerFiredUpon
		g_bPlayerFiredUpon = TRUE
		PlayerFiredUpon()
		
	# Nothing else to do.  Let any other events for this event handle it
	TGObject.CallNextHandler(pEvent)

################################################################################
##	MarauderNeedsHelp()
##	
##	Called when the Cards fire on the Marauder.  Calls itself as script action
##	if another sequence is running.
##	
##	Args: 	pTGAction	- The script action object.
##	
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MarauderNeedsHelp(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# Delay sequence 1 second1.
		pSequence = App.TGSequence_Create()
		pWaitAction	= App.TGScriptAction_Create(__name__, "MarauderNeedsHelp")
		pSequence.AppendAction(pWaitAction, 1)
		pSequence.Play()

		return 0

	else:
		# Set our sequence flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE

		# Get the characters we need		
		pPraag	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("MarauderSet"), "Praag")

		pSequence = App.TGSequence_Create()

		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaIncomming1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg1", "Captain", 1, g_pGeneralDatabase)
		pMarauderViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MarauderSet", "Praag")
		pPraagHelp1			= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2CardsAttack1", None, 0, g_pMissionDatabase)
		pPraagHelp2			= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2CardsAttack1a", None, 0, g_pMissionDatabase)
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pClearFlag			= App.TGScriptAction_Create(__name__, "ClearSequenceFlag")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pKiskaIncomming1, 1)	# 1 sec delay
		pSequence.AppendAction(pMarauderViewOn, 2)
		pSequence.AppendAction(pPraagHelp1)
		pSequence.AppendAction(pPraagHelp2)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pClearFlag)

		pSequence.Play()

		# Register this sequence so we can stop it if need be
		App.TGActionManager_RegisterAction(pSequence, "PraagSequence")		

		# Add the protect Marauder goal
		MissionLib.AddGoal("E2ProtectMarauderGoal")
		
		# Remove the Marauder from the Tactor group
		pTractorGroup = MissionLib.GetTractorGroup()
		if (pTractorGroup != None):
			pTractorGroup.RemoveName("Marauder")

		return 0

################################################################################
##	PlayerFiredUpon()
##	
##	Called when the Cards fire on the Player
##	
##	Args: 	pTGAction	- The script action object.
##	
##	Return:	0	- Return 0 to keep calling sequence from crashing
################################################################################
def PlayerFiredUpon(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# Delay sequence 1 second1.
		pSequence = App.TGSequence_Create()
		pWaitAction	= App.TGScriptAction_Create(__name__, "PlayerFiredUpon")
		pSequence.AppendAction(pWaitAction, 1)
		pSequence.Play()

		return 0

	else:
		# Set our sequence flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		
		pSequence = App.TGSequence_Create()

		pFelixAttacked1		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2CardsAttack2", "Captain", 1, g_pMissionDatabase)
		pClearFlag			= App.TGScriptAction_Create(__name__, "ClearSequenceFlag")

		pSequence.AppendAction(pFelixAttacked1, 1)	# 1 sec delay
		# If we saved the Karoon, have Miguel mention it
		if (Maelstrom.Episode2.Episode2.g_bKaroonDestroyed == FALSE):
			pMiguelAttacked2 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2CardsAttack3", "Captain", 1, g_pMissionDatabase)
			pSequence.AppendAction(pMiguelAttacked2)
		
		pSequence.AppendAction(pClearFlag)

		pSequence.Play()

		# Register this to "Generic"
		App.TGActionManager_RegisterAction(pSequence, "Generic")
		
		return 0
		
################################################################################
##	ShipInSensorRange()
##
##	Handler called when a ship comes into sensor range.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ShipInSensorRange(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if (pShip == None):
		return
	sShipName = pShip.GetName()

	# See we care about the ship
	if (sShipName in g_lShipNames) and (g_bShipsOnSensors == FALSE):
		global g_bShipsOnSensors
		g_bShipsOnSensors = TRUE
		
	# All done, call our next handler
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ShipIdentified()
##
##	Handler called when a ship is ID'd on the sensors.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ShipIdentified(TGObject, pEvent):
	# See what ship was ID'd
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sShipName = pShip.GetName()

	# See if the ship is in the list
	if (sShipName in g_lShipNames):
		# Check the "ships on sensors" flag, and set it to true if necessary.
		# This case can happen if you enter with low sensors, and use scan
		# area to find the ships.
		if g_bShipsOnSensors == FALSE:
			global g_bShipsOnSensors
			g_bShipsOnSensors = TRUE

		if (g_bShipsIDd == FALSE):
			global g_bShipsIDd
			g_bShipsIDd	= TRUE
			# Make sure that they all get identified.
			pSet = App.g_kSetManager.GetSet("Serris2")
			for sName in g_lShipNames:
				pShip = App.BaseObjectClass_GetObject(pSet, sName)
				if (pShip != None):
					MissionLib.IdentifyObjects(pShip)
			
			# Set our mission state here as well
			global g_iMissionState
			g_iMissionState = SHIPS_ID
		
	# Nothing else to do.  Let any other events for this event handle it
	TGObject.CallNextHandler(pEvent)

################################################################################
##	FriendlyFireReportHandler()
##
##	Handler called if player has done enough damage to a friendly ship to get
##	Saffi to warn them.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def FriendlyFireReportHandler(TGObject, pEvent):
	# Get the ship that was hit
	pShip	= App.ShipClass_Cast(pEvent.GetSource())
	if (pShip == None):
		return
	sShipName = pShip.GetName()
	
	# If its the Marauder, do our special line from Saffi
	if (sShipName == "Marauder"):
		if (g_bMissionWon == FALSE):
			fTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - g_pSaffi.GetLastTalkTime()
			if (fTimeSinceTalk < 5.0):
				return
			else:
				pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2FireMarauder1", "Captain", 1, g_pMissionDatabase)
				pSaffiLine.Play()
				return
		else:
			# Mission is won and player is being a pain, fail the mission
			# End all our sequences
			App.TGActionManager_KillActions("PraagSequence")
			App.TGActionManager_KillActions("Generic")
			App.TGActionManager_KillActions("PraagHavar")

			# If it's the Marauder, do our mission specific loss
			if (sShipName == "Marauder"):
				# Do the line from Saffi and end the game
				pSequence = App.TGSequence_Create()
				pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME))
				pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2FireMarauder2", "Captain", 1, g_pMissionDatabase))
				# End the mission
				pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
				pGameOver.Play()

				return
			
	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	FriendlyFireGameOverHandler()
##
##	Handler called if player does enough damage to friendly ship to get game
##	over.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def FriendlyFireGameOverHandler(TGObject, pEvent):
	# Get the ship that was fired on
	pShip	= App.ShipClass_Cast(pEvent.GetSource())
	if (pShip == None):
		return
	sShipName	= pShip.GetName()

	# End all our Praag sequences
	App.TGActionManager_KillActions("PraagSequence")
	App.TGActionManager_KillActions("Generic")
	App.TGActionManager_KillActions("PraagHavar")
	
	# If it's the Marauder, do our mission specific loss
	if (sShipName == "Marauder"):
		# Do the line from Saffi and end the game
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME))
		pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2FireMarauder2", "Captain", 1, g_pMissionDatabase))
		# End the mission
		pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
		pGameOver.Play()
		
		return
		
	# All done, call the next handler for the event
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	WeaponHitPlayer()
##
##	Event handler called when a weapon hits the players ship.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WeaponHitPlayer(TGObject, pEvent):
	# See what ship hit the player
	pShip = App.ShipClass_Cast(pEvent.GetFiringObject())
	if (pShip == None):
		return

	sShipName = pShip.GetName()
	
	# See if the Marauder is firing on the player
	if (sShipName == "Marauder") and (g_bMarauderFiresPlayer == FALSE):
		# Set our flag and do our line from Miguel
		global g_bMarauderFiresPlayer
		g_bMarauderFiresPlayer = TRUE
		# Check the shields
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
		pShields = pPlayer.GetShields()
		fShieldsUp = pShields.GetShieldPercentage()
		
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderFiresPlayer1", "Captain", 1, g_pMissionDatabase))
		if (fShieldsUp != 0):
			pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderFiresPlayer1a", "Captain", 1, g_pMissionDatabase))
		pSequence.Play()
		
		# Register to Generic
		App.TGActionManager_RegisterAction(pSequence, "Generic")
		
	# All done, call the next handler for this event
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	PowerLevelChanged()
##
##	Handler called when the player changes their power levels.  Calls
##	PlayerDetected() if the player turns on weapons or shields while visible.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PowerLevelChanged(TGObject, pEvent):
	# If the player is visible and the shields or phasers are on,
	# call player detected.
	if (g_bPlayerNotVisible == FALSE) and (g_bPlayerSneaking == TRUE):
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
			
		pShields = pPlayer.GetShields()
		pPhasers = pPlayer.GetPhaserSystem()
		
		if ((pShields.IsOn() and not pShields.IsDisabled()) or (pPhasers.IsOn() and not pPhasers.IsDisabled())):
			PlayerDetected("Power")
	
	# All done, call our next handler
	if (TGObject != None):
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	ScanHandler()
##
##	Called when the "Scan" button in Miguel's menu is hit.  Performs tasks
##	based on what system we're in.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ScanHandler(TGObject, pEvent):
	# See if we're scanning the area.
	iScanType = pEvent.GetInt()
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	# If the players sensors are off, do the default thing
	pSensors = pPlayer.GetSensorSubsystem()
	if (pSensors == None):
		TGObject.CallNextHandler(pEvent)
		return
	if (pSensors.IsOn() == FALSE):
		TGObject.CallNextHandler(pEvent)
		return

	# Get the set the player is in.
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
		
	# See what type of scan we're doing.
	if (iScanType == App.CharacterClass.EST_SCAN_AREA):
		# We're scanning the area so see what set it is.
		if ((pSet.GetName() == "Serris3") or (pSet.GetName() == "Serris1")) and (g_bSerris3ScanDone == FALSE):
			global g_bSerris3ScanDone
			g_bSerris3ScanDone = TRUE
			ScanningSerris3()
			return
		
		# See if we're scanning in Serris 2 and the ships haven't
		# been ID'd.  If so, do line from Miguel and boost the sensors.
		elif (pSet.GetName() == "Serris2") and (g_bShipsIDd == FALSE):
			# Get the sensors and the scan sequence
			pSensors = pPlayer.GetSensorSubsystem()
			if (pSensors != None):
				# If the scan sequence returns None, call next handler
				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
				if (pScanSequence == None):
					return
					
				# The scan sequence is valid, so do our default stuff.
				pSequence		= App.TGSequence_Create()
				
				pSensorSequence	= pSensors.ScanAllObjects()
				pEnableScan		= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
				pSequence.AppendAction(pScanSequence)
				pSequence.AppendAction(pSensorSequence)
				pSequence.AppendAction(pEnableScan)
				
				pSequence.Play()
				
				# Register to Generic
				App.TGActionManager_RegisterAction(pSequence, "Generic")
				
				# Return so we don't call the default behavior
				return
	
	# If we're scanning target, just ID all the ships to make things easy
	if (iScanType == App.CharacterClass.EST_SCAN_OBJECT) and (g_bShipsIDd == FALSE) and (pSet.GetName() == "Serris2"):
		pShip = App.ObjectClass_Cast(pEvent.GetSource())
		if (pShip == None):
			pShip = pPlayer.GetTarget()
			if (pShip != None):
				sShipName = pShip.GetName()
				# If we're scanning any of the ships
				if (sShipName in g_lShipNames):
					# We're scanning one of the ships, so ID all of them
					# Do Miguel's scan line.
					pMiguelScan = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "MiguelScan", None, 0, g_pGeneralDatabase)
					pMiguelScan.Play()
					for sName in g_lShipNames:
						pShip = App.BaseObjectClass_GetObject(pSet, sName)
						if (pShip != None):
							MissionLib.IdentifyObjects(pShip)
					return
						
	# Nothing else to do.  Let any other events for this event handle it
	TGObject.CallNextHandler(pEvent)

################################################################################
##	HailHandler()
##
##	Event handler called when Kiska's "Hail" button is pressed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def HailHandler(TGObject, pEvent):
	# Get the hail target	
	pTarget	= App.ObjectClass_Cast(pEvent.GetSource())
	if (pTarget == None):
		return
		
	sTargetName = pTarget.GetName()
	
	# If the player tries to hail the ships, have them detect them.
	if (g_bPlayerSneaking == TRUE) and (sTargetName in g_lShipNames):
		MissionLib.CallWaiting(None, TRUE)
		PlayerDetected("Hail")
		return
		
	if (sTargetName == "Marauder") and (g_bPlayerSneaking == FALSE):
		pSequence = App.TGSequence_Create()
		
		pKiskaHail1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2HailMarauder1", "Captain", 1, g_pMissionDatabase)
		pKiskaHail2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "NotResponding2", None, 0, g_pGeneralDatabase)
				
		pSequence.AppendAction(pKiskaHail1)
		pSequence.AppendAction(pKiskaHail2, 1)
		
		pSequence.Play()
				
		# Register to Generic
		App.TGActionManager_RegisterAction(pSequence, "Generic")
		
		# call the marader runs funtion
		MarauderRuns()
		
		# Don't call the next handler
		return
		
	# Nothing else to do.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	SetCourseHandler()
##	
##	Intercept the helm's handling of the Intercept button.
##	
##	Args:	TGObject	- The TGObject object.
##			pEvent		- A Set Course event.  Maybe the Intercept one.
##	
##	Return: None
################################################################################
def SetCourseHandler(TGObject, pEvent):
	# Intercept the helm menu's Set-Course related functions, so we can
	# override the intercept button.
	if (pEvent.GetInt() == App.CharacterClass.EST_SET_COURSE_INTERCEPT):
		# If the player is intercepting the Marauder after the Galors
		# leave, play our lines from Saffi and Kiska.
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer != None):
			pTarget = pPlayer.GetTarget()
			if (pTarget == None):
				TGObject.CallNextHandler(pEvent)
				return
				
			if (pTarget.GetName() == "Marauder") and (g_bGalorsLeaveOnce == TRUE) and (g_bPlayerInterceptDone == FALSE):
				global g_bPlayerInterceptDone
				g_bPlayerInterceptDone = TRUE
				
				# Do our little sequence.
				pSequence = App.TGSequence_Create()
				pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))
				pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2InterceptMarauder1", None, 0, g_pMissionDatabase))
				pSequence.Play()
				
	# Nothing else to do.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	WarpButtonHandler()
##
##	Handler called when warp button is pressed
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WarpButtonHandler(TGObject, pEvent):
	# Get the player's set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	
	# If the player is trying to warp when he shouldn't, tell him so
	# Make sure that we only stop the player if they are in Serris 2.
	if (g_bCantWarp == TRUE) and (pSet.GetName() == "Serris2"):
		pSaffiWarpStop3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "WarpStop3", "Captain", 1, g_pGeneralDatabase)
		pSaffiWarpStop3.Play()
		# Don't call the next handler
		return
		
	# Set the for the player being in warp.
	global g_bPlayerInWarp
	g_bPlayerInWarp = TRUE
	
	# All done, send event on to the next handler
	TGObject.CallNextHandler(pEvent)
	
###############################################################################
#	HailStarfleet()
#
#	Handler for Contact Starfleet button.
#
#	Args:	TGObject	- TGObject object
#			pEvent		- TGEvent object
#
#	Return:	none
###############################################################################
def HailStarfleet(TGObject, pEvent):
	if (g_bMissionWon == TRUE) and (g_bEndDialoguePlayed == FALSE):
		HailLiu(None)
		
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	CommunicateHandler()
##
##	Handler called when one of the crews communicate buttons is hit.  Checks
##	the mission state and calls functions that play the dialogue specific to
##	that part of the mission.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	
################################################################################
def CommunicateHandler(TGObject, pEvent):
	# Get the menu that was clicked
	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())

	# Check the mission state variable and call our functions.
	if (g_iMissionState == IN_SERRIS3):
		Serris3Communicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == IN_SERRIS2):
		Serris2Communicate(pMenu.GetObjID())
		
	elif (g_iMissionState == SHIPS_ID):
		ShipsIdCommunicate(pMenu.GetObjID())
		
	elif (g_iMissionState == GALORS_LEAVE):
		GalorsLeaveCommunicate(pMenu.GetObjID())
		
	elif (g_iMissionState == GALORS_RETURN):
		# Pass in the TGObject and pEvent so we can have the
		# default behavior if we want it
		GalorsReturnCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	else:
		# Do the default behavior
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	TrackPlayer()
##
##	Called from EnterSet() if player enters a new set,
##
##	Args:	sSetName	- String name of the set entered.
##
##	Return:	None
################################################################################
def TrackPlayer(sSetName):
	# Player has arrived in Serris2, so call the arrival function
	if (sSetName == "Serris2") and (g_bPlayerArriveSerris2 == FALSE):
		global g_bPlayerArriveSerris2
		global g_iMissionState
		g_bPlayerArriveSerris2	= TRUE
		g_iMissionState			= DEFAULT

		StopProdTimer()
		PlayerArrivesSerris2()		
	
	# See if the player is leaving Serris 2 before mission
	# is over, and start prodding if they are
	if (g_bPlayerNotInSerris == FALSE) and (g_bPlayerArriveSerris2 == TRUE) and not(sSetName == "warp"):
		# Clear flag if we're heading back to Serris 2
		if (sSetName == "Serris2"):
			global g_bPlayerNotInSerris
			g_bPlayerNotInSerris = FALSE
				
		else:
			# Set the flag
			global g_bPlayerNotInSerris
			g_bPlayerNotInSerris = TRUE
			RestartProdTimer(None, 10)

################################################################################
##	PlayerExitsSet()
##
##	Called if player exits a set.  Keeps track of the player and were he's
##	going for proding needs.
##
##	Args:	None
##
##	Return: None	
################################################################################
def PlayerExitsSet():
	# Get the warp button and see where where headed.
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu == None):
		return
	pWarpButton	= Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return
	pString = pWarpButton.GetDestination()
	
	# See if we're heading to Serris 2 for the first time
	if (pString == "Systems.Serris.Serris2") and (g_bPlayerArriveSerris2 == FALSE) and (g_bMissionWon == FALSE):
		StopProdTimer()
		
	# If we left the system and are heading back, lengthen the
	# prod timer
	if (g_bPlayerNotInSerris == TRUE) and (pString == "Systems.Serris.Serris3"):
		StopProdTimer()
		RestartProdTimer(None, 30)
		
	# If we are returning to Serris 2, end the prodding
	elif (g_bPlayerNotInSerris == TRUE) and (pString ==  "Systems.Serris.Serris2"):
		StopProdTimer()
		global g_bPlayerNotInSerris
		g_bPlayerNotInSerris = FALSE
		
		# Set the back to Serris prod counter to 1
		global g_iBackToSerrisProd
		g_iBackToSerrisProd = 1
		
################################################################################
##	PlayerArrivedSerris3()
##	
##	Does the first sequence for the mission.  Let's player know they should
##	scan the system.  Waits for player to come out of warp before playing.
##	
##	Args: 	pTGAction	- The script action object.
##	
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PlayerArrivedSerris3(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check and see if the player is in warp.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
		
	pWarp = pPlayer.GetWarpEngineSubsystem()
	if (pWarp == None):
		return 0
		
	if MissionLib.IsPlayerWarping():
		# Delay sequence 1 second1.
		pSequence = App.TGSequence_Create()
		pEnterSerris3	= App.TGScriptAction_Create(__name__, "PlayerArrivedSerris3")
		pSequence.AppendAction(pEnterSerris3, 1)
		pSequence.Play()

		return 0

	else:		
		pSequence = App.TGSequence_Create()

		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaArrive1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2ArriveSerris3-1", "Captain", 1, g_pMissionDatabase)
		pMiguelScan1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2Serris3Scan1", "Captain", 0, g_pMissionDatabase)

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pKiskaArrive1)
		pSequence.AppendAction(pMiguelScan1)

		pSequence.Play()

		# Register to Generic
		App.TGActionManager_RegisterAction(pSequence, "Generic")

		# Remove the InvestigateSerris goal and SupplyCeil5Goal
		# if they still exist and add our scanning goal
		MissionLib.RemoveGoal("E2SupplyCeli5Goal")
		MissionLib.AddGoal("E2InvestigateSerrisGoal")
		MissionLib.AddGoal("E2ScanSerris3Goal")
		MissionLib.AddGoal("E2AvoidDetectionGoal")
		
		return 0

################################################################################
##	ScanningSerris3()
##
##	Called by ScanHandler() if the player hits the "Scan" button while were in
##	the Serris 3 system.  Does short sequence to lead player into system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningSerris3():
	# Check and see if the player has weapon or shield levels online
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pShields	= pPlayer.GetShields()
	pPhasers	= pPlayer.GetPhaserSystem()
	
	# Get the sensors and return if they are dead
	pSensors = pPlayer.GetSensorSubsystem()
	if (pSensors == None):
		return

	# Do the correct line from Felix.
	if (pShields.IsOn() and not pShields.IsDisabled()) or (pPhasers.IsOn()):
		pFelixScan3	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2Serris3Scan3", "Captain", 1, g_pMissionDatabase)
	else:
		pFelixScan3	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2Serris3Scan3a", "Captain", 1, g_pMissionDatabase)
		
	# Do our sequence
	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
	pSensorSequence	= pSensors.ScanAllObjects()
	pMiguelScan2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2Serris3Scan2", "Captain", 1, g_pMissionDatabase)
	pEnableScan		= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSetFlag		= App.TGScriptAction_Create(__name__, "SetPlayerScannedSerris3Flag")
	pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 15)

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pScanSequence)
	pSequence.AppendAction(pSensorSequence)
	pSequence.AppendAction(pMiguelScan2)
	pSequence.AppendAction(pSetFlag)
	pSequence.AppendAction(pEnableScan)
	pSequence.AppendAction(pFelixScan3)
	pSequence.AppendAction(pStartProdTimer)

	pSequence.Play()
	
	# Register to Generic
	App.TGActionManager_RegisterAction(pSequence, "Generic")

	# Remove our scanning goal
	MissionLib.RemoveGoal("E2ScanSerris3Goal")

################################################################################
##	SetPlayerScannedSerris3Flag()
##
##	Script action that sets our flag used in communicate.
##
##	Args:	pTGAction 	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetPlayerScannedSerris3Flag(pTGAction):
	global g_bPlayerScannedSerris3
	g_bPlayerScannedSerris3 = TRUE
	
	return 0
	
################################################################################
##	PlayerArrivesSerris2()
##
##	Called when the player first arrives in the Serris 2 system.  Plays
##	sequence.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PlayerArrivesSerris2(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check and see if the player is in warp.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
		
	if (MissionLib.IsPlayerWarping()):
		# Delay sequence 1 second.
		pSequence = App.TGSequence_Create()
		pEnterSerris2	= App.TGScriptAction_Create(__name__, "PlayerArrivesSerris2")
		pSequence.AppendAction(pEnterSerris2, 1)
		pSequence.Play()

		return 0

	else:		
		# Set our prod line and our mission state
		global g_sProdLine

		pSequence = App.TGSequence_Create()

		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaArrive1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2ArriveSerris2-1", "Captain", 1, g_pMissionDatabase)
		pCheckSensors	= App.TGScriptAction_Create(__name__, "CheckShipsOnSensors")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pKiskaArrive1)
		pSequence.AppendAction(pCheckSensors)

		pSequence.Play()

		# Register to Generic
		App.TGActionManager_RegisterAction(pSequence, "Generic")

		# Make sure to remove the ScanSerris3 goal
		MissionLib.RemoveGoal("E2ScanSerris3Goal")
		
		return 0

################################################################################
##	CheckShipsOnSensors()
##
##	Script action that plays line from Miguel if the ships are on sensors.
##	Loops until they are then calls CheckShipIDd()
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CheckShipsOnSensors(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bShipsOnSensors == FALSE):
		# Delay sequence 1 second1.
		pSequence = App.TGSequence_Create()
		pWaitAction	= App.TGScriptAction_Create(__name__, "CheckShipsOnSensors")
		pSequence.AppendAction(pWaitAction, 1)
		pSequence.Play()

		return 0

	else:
		# Set our mission state for the communicate lines
		global g_iMissionState
		g_iMissionState = IN_SERRIS2
		# Ships are on the sensors, so do the line from Miguel
		pSequence = App.TGSequence_Create()
		
		pMiguelArrive2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2ArriveSerris2-2", "Captain", 0, g_pMissionDatabase)
		pCheckSensors	= App.TGScriptAction_Create(__name__, "CheckShipIDd")
		
			
		pSequence.AppendAction(pMiguelArrive2)
		# If the ships have not been ID'd, have Miguel prod for a scan
		if (g_bShipsIDd == FALSE):
			pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 6/E6M4.TGL")
			pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrompt1", None, 0, pDatabase))
			App.g_kLocalizationManager.Unload(pDatabase)

		pSequence.AppendAction(pCheckSensors)
		
		pSequence.Play()
		
		return 0
		
################################################################################
##	CheckShipIDd()
##
##	Script action that sees if the ships have been identified.  If not, prods
## 	to boost sensors.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CheckShipIDd(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Check our flag and see what we need to do
	# If player is behind the gas giant and not detected
	if (g_bShipsIDd == TRUE) and (g_bPlayerDetected == FALSE) and (g_bPlayerNotVisible == TRUE):
		ShipsIDdBehindPlanet()
		return 0
	
	# If player is not behind the gas giant and not detected
	elif (g_bShipsIDd == TRUE) and (g_bPlayerDetected == FALSE) and (g_bPlayerNotVisible == FALSE):
		ShipsIDdNotBehindPlanet()
		return 0
		
	# If the player has been detected
	elif (g_bShipsIDd == TRUE) and (g_bPlayerDetected == TRUE) and (g_bMarauderDestroyed == FALSE):
		ShipsIDdPlayerDetected()
		return 0
		
	# If the ships have not been IDd	
	elif (g_bShipsIDd == FALSE) and (g_bMarauderDestroyed == FALSE):
		# If this is our first time through,
		# start the prod timer.
		if (g_bCheckShipIDdCalled == FALSE):
			global g_bCheckShipIDdCalled
			g_bCheckShipIDdCalled = TRUE
			
		# Call ourselves again over and over until
		# the ships are IDd
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction((App.TGScriptAction_Create(__name__, "CheckShipIDd")), 2)
		pSequence.Play()
		
		return 0
		
	return 0

################################################################################
##	ShipsIDdBehindPlanet()
##
##	Called from CheckShipIDd() if player IDs the ships while behind the gas
##	giant.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ShipsIDdBehindPlanet():
	# Do our sequence
	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelScan1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan1a", None, 0, g_pMissionDatabase)
	pMiguelScan1b	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan1b", None, 0, g_pMissionDatabase)
	pSaffiScan2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan2", None, 0, g_pMissionDatabase)
	pKiskaScan3		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan3", "Captain", 0, g_pMissionDatabase)
	pKiskaProd1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2OrbitProd1", None, 0, g_pMissionDatabase)
	pMiguelProd2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2OrbitProd2", None, 0, g_pMissionDatabase)
	pSaffiScan4		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan4", "Captain", 0, g_pMissionDatabase)
	pCheckMsg		= App.TGScriptAction_Create(__name__, "CheckForMessage")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelScan1)
	pSequence.AppendAction(pMiguelScan1b)
	pSequence.AppendAction(pSaffiScan2)
	pSequence.AppendAction(pKiskaScan3)
	pSequence.AppendAction(pKiskaProd1)
	pSequence.AppendAction(pMiguelProd2)
	pSequence.AppendAction(pSaffiScan4)
	pSequence.AppendAction(pCheckMsg)

	pSequence.Play()

	# Register to Generic
	App.TGActionManager_RegisterAction(pSequence, "Generic")

	# Make the Marauder the players target
	MakeMarauderTarget()
	
################################################################################
##	ShipsIDdNotBehindPlanet()
##
##	Called from CheckShipIDd() if player IDs the ships but is not behind the gas
##	giant.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ShipsIDdNotBehindPlanet():
	# Do our sequence.
	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelScan1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan1a", None, 0, g_pMissionDatabase)
	pMiguelScan1b	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan1b", None, 0, g_pMissionDatabase)
	pCheckMsg		= App.TGScriptAction_Create(__name__, "CheckForMessage")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelScan1)
	pSequence.AppendAction(pMiguelScan1b)
	pSequence.AppendAction(pCheckMsg)

	pSequence.Play()

	# Register to Generic
	App.TGActionManager_RegisterAction(pSequence, "Generic")

	# Make the Marauder the players target
	MakeMarauderTarget()
		
################################################################################
##	ShipsIDdPlayerDetected()
##
##	Called from CheckShipIDd() if player IDs the ships after being detected.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ShipsIDdPlayerDetected():
	# Do our sequence
	pSequence = App.TGSequence_Create()

	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelScan1		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan1a", None, 0, g_pMissionDatabase)
	pMiguelScan1b		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2Serris2Scan1b", None, 0, g_pMissionDatabase)
	pFelixDetected2		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerDetected2", "Captain", 1, g_pMissionDatabase)
	pMiguelDetected3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerDetected3", None, 0, g_pMissionDatabase)

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelScan1)
	pSequence.AppendAction(pMiguelScan1b)
	pSequence.AppendAction(pFelixDetected2)
	pSequence.AppendAction(pMiguelDetected3)

	pSequence.Play()
	
	# Register to Generic
	App.TGActionManager_RegisterAction(pSequence, "Generic")

	# Make the Marauder the players target
	MakeMarauderTarget()
	
################################################################################
##	CheckForMessage()
##
##	Script action called to see if we are somewhere where we can hear the
##	message.  Calls itself recursively until g_bCanHearMsg is TRUE.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CheckForMessage(pTGAction):
	# Check our flag
	if (g_bPlayerDetected == TRUE) or (g_bMissionTerminate != 1):
		return 0

	# See if we can hear the msg or not and if not, call this function again
	if (g_bCanHearMsg == FALSE):
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction((App.TGScriptAction_Create(__name__, "CheckForMessage")), 1)
		pSequence.Play()
		return 0
	
	else:
		# Set our warp flag
		global g_bCantWarp
		g_bCantWarp	= TRUE

		# We are in place to hear the message, so let the player know
		# and check our sensors.
		pSequence = App.TGSequence_Create()

		pKiskaOrbit2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2OrbitMoon2", "Captain", 1, g_pMissionDatabase)
		pSaffiOrbit3		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2OrbitMoon3", None, 0, g_pMissionDatabase)
		pCheckSensorBoost	= App.TGScriptAction_Create(__name__, "CheckSensorBoost")

		pSequence.AppendAction(pKiskaOrbit2)
		pSequence.AppendAction(pSaffiOrbit3)
		pSequence.AppendAction(pCheckSensorBoost)

		pSequence.Play()

		# Register to Generic
		App.TGActionManager_RegisterAction(pSequence, "Generic")
	
		return 0

################################################################################
##	CheckSensorBoost()
##
##	Script action that checks to see if the sensors are boosted.  If so, plays
##	sequence, if not starts a loop that checks when they are.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CheckSensorBoost(pTGAction):
	# Get the sensor subsystem
	pPlayer	= MissionLib.GetPlayer()
	if (pPlayer == None) or (g_bPlayerDetected == TRUE) or (g_bMissionTerminate != 1):
		return 0
		
	pSensors	= pPlayer.GetSensorSubsystem()
	bBoosted = MissionLib.IsBoosted(pSensors, 1.2)
	
	# If the sensors are boosted above 120%
	if (bBoosted == TRUE):
		# Do the sequence that lets the player hear
		pSequence = App.TGSequence_Create()
		
		pKiskaOrbit7	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2OrbitMoon7", None, 0, g_pMissionDatabase)
		pPraagHavar		= App.TGScriptAction_Create(__name__, "PraagAndHavar")
		
		pSequence.AppendAction(pKiskaOrbit7)
		pSequence.AppendAction(pPraagHavar)
		
		pSequence.Play()

		# Register to Generic
		App.TGActionManager_RegisterAction(pSequence, "Generic")
	
	# If the sensors are below 120%
	else:
		# Set our prod line
		global g_sProdLine
		g_sProdLine = "E2M2OrbitMoon5"
		
		# Play our lines and start our loop
		pSequence = App.TGSequence_Create()
		
		pKiskaOrbit5		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2OrbitMoon5", "Captain", 1, g_pMissionDatabase)
		pStartProdTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 20)
		pCheckSensorLoop	= App.TGScriptAction_Create(__name__, "CheckSensorLoop")
		
		pSequence.AppendAction(pKiskaOrbit5)
		pSequence.AppendAction(pStartProdTimer)
		pSequence.AppendAction(pCheckSensorLoop)
		
		pSequence.Play()
	
		# Register to Generic
		App.TGActionManager_RegisterAction(pSequence, "Generic")

	return 0

################################################################################
##	MakeMarauderTarget()
##
##	Makes the Marauder the players target if they are not targeting anything
##	else.
##
##	Args:	None
##
##	Return:	None
################################################################################
def MakeMarauderTarget():
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pTarget = pPlayer.GetTarget()
	if (pTarget == None):
		pPlayer.SetTarget("Marauder")
		
################################################################################
##	CheckSensorLoop()
##
##	Script action that loops itself checking to see if the sensors have been
##	boosted above 120%.  When the sensors are boosted, plays sequence that calls
##	PraagAndHavar().
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CheckSensorLoop(pTGAction):
	# Get the sensor subsystem
	pPlayer	= MissionLib.GetPlayer()
	if (pPlayer == None) or (g_bPlayerDetected == TRUE) or (g_bMissionTerminate != 1):
		return 0
		
	pSensors	= pPlayer.GetSensorSubsystem()
	bBoosted	= MissionLib.IsBoosted(pSensors, 1.2)
	
	# If the sensors are boosted above 120%.
	if (bBoosted == TRUE):
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaOrbit6	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2OrbitMoon6", None, 0, g_pMissionDatabase)
		pKiskaOrbit7	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2OrbitMoon7", None, 0, g_pMissionDatabase)
		pPraagHavar		= App.TGScriptAction_Create(__name__, "PraagAndHavar")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pKiskaOrbit6)
		pSequence.AppendAction(pKiskaOrbit7)
		pSequence.AppendAction(pPraagHavar)

		pSequence.Play()
		
		# Register to Generic
		App.TGActionManager_RegisterAction(pSequence, "Generic")

	else:
		# Call ourselves and do the check again
		pSequence = App.TGSequence_Create()
		pCheckSensorLoop	= App.TGScriptAction_Create(__name__, "CheckSensorLoop")
		pSequence.AppendAction(pCheckSensorLoop, 1)
		pSequence.Play()
		
	return 0

################################################################################
##	PlayerVisibleChanged()
##
##	Called by MissionLib.CallFunctionWhenConditionChanges() when the line of
##	sight condition changes.
##
##	Args:	bNewState	- The new state of the condition.
##
##	Return:	None
################################################################################
def PlayerVisibleChanged(bNewState):
	# Set the new state of our global 
	global g_bPlayerNotVisible
	g_bPlayerNotVisible	= bNewState
		
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	# Bail out if the player is not in Serris 2
	pSet = pPlayer.GetContainingSet()
	if (pSet == None) or (pSet.GetName() != "Serris2"):
		return
		
	# Check and see if our shields or weapons are on
	if (g_bPlayerNotVisible == FALSE):
		PowerLevelChanged(None, None)
		
	# Call PlayerDetected if the player is visible and in range
	if (g_bPlayerNotVisible == FALSE) and (g_bPlayerInRange == TRUE):
		PlayerDetected()
	# If the player is not in range and visible, set the 
	# flag that will let us hear their conversation.
	# Keep the player from going to warp as well.
	elif (g_bPlayerNotVisible == FALSE) and (g_bPlayerInRange == FALSE) and (g_bPlayerInWarp == FALSE):
		global g_bCanHearMsg
		global g_bCantWarp
		g_bCanHearMsg	= TRUE
		g_bCantWarp		= TRUE
		
################################################################################
##	PlayerInRangeChanged()
##
##	Called by MissionLib.CallFunctionWhenConditionChanges() when in range
##	condition changes.
##
##	Args:	bNewState	- The new state of the condition.
##
##	Return:	None
################################################################################
def PlayerInRangeChanged(bNewState):
	# Set the new state of our global flag
	global g_bPlayerInRange
	g_bPlayerInRange = bNewState
	
	# Call PlayerDetected() if we are in range and visible
	if (g_bPlayerNotVisible == FALSE) and (g_bPlayerInRange == TRUE):
		PlayerDetected()
	
################################################################################
##	PlayerDetected()
##
##	Called if the player is in range and in sight or if in sight with shields
##	and weapons online.
##
##	Args:	sDetectMethod	- String detailing how player detected.  Defaults to
##							  None.
##
##	Return:	None
################################################################################
def PlayerDetected(sDetectMethod = None):
	# Set our mission state
	global g_iMissionState
	g_iMissionState = DEFAULT
	
	# Check our flag to see if this matters
	if (g_bPlayerSneaking == FALSE) or (g_bPlayerDetected == TRUE) or (g_bPlayerInWarp == TRUE):
		return
	
	# Set our flag
	global g_bPlayerDetected
	g_bPlayerDetected = TRUE
	
	# Kill the Praag and Havar sequence if it's running
	App.TGActionManager_KillActions("PraagHavar")
	
	# Get the set and the ships.
	pSet		= App.g_kSetManager.GetSet("Serris2")
	pKeldon1	= App.ShipClass_GetObject(pSet, "Keldon 1")
	pGalor2		= App.ShipClass_GetObject(pSet, "Galor 2")
	
	# Set their AI to attack the Marauder
	import E2M2_AI_GalorDetect
	if (pKeldon1 != None):
		pKeldon1.SetAI(E2M2_AI_GalorDetect.CreateAI(pKeldon1))
	if (pGalor2 != None):
		pGalor2.SetAI(E2M2_AI_GalorDetect.CreateAI(pGalor2))
	
	# Check our flags and see what sequence we play
	if (g_bShipsIDd == TRUE):
		# Do the sequence that lets the player
		# know the Galors are turning on the Marauder.
		pSequence = App.TGSequence_Create()
	
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaDetect1a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerDetected1a", "Captain", 1, g_pMissionDatabase)
		pFelixDetect2	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerDetected2", "Captain", 1, g_pMissionDatabase)
		pMiguelDetect3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerDetected3", None, 0, g_pMissionDatabase)
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	
		pSequence.AppendAction(pPreLoad)
		# If the player was detected by not hailing ships
		if (sDetectMethod == "Hail"):
			pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase))
		elif (sDetectMethod == None):
			pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerDetected1", None, 0, g_pMissionDatabase))
		pSequence.AppendAction(pKiskaDetect1a)
		pSequence.AppendAction(pFelixDetect2)
		pSequence.AppendAction(pMiguelDetect3)
		pSequence.AppendAction(pEndCallWaiting)
	
		pSequence.Play()

	else:
		# Do the sequence for if the ship are still "unidentified"
		# when the player is detected
		pMiguelDetect5	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerDetected5", "Captain", 1, g_pMissionDatabase)
		pMiguelDetect5.Play()
		
		# Kill the other sequences if their running.
		App.TGActionManager_KillActions()
		
################################################################################
##	PraagAndHavar()
##
##	Script action that plays the converstation between Praag and Havar.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PraagAndHavar(pTGAction):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1) or (g_bPlayerDetected == TRUE):
		return 0
	
	# Set our flags
	global g_bCoversationHeard
	g_bCoversationHeard = TRUE
	
	# Set our mission state to the default
	global g_iMissionState
	g_iMissionState = DEFAULT
	
	# Get the characters we need
	pPraag	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("MarauderSet"), "Praag")
	pHavar	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("CardSet"), "CardCapt")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pPraagLine1		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", g_pMissionDatabase, "E2M2PraagHavar1")
	pHavarLine2		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", g_pMissionDatabase, "E2M2PraagHavar2")
	pPraagLine3		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", g_pMissionDatabase, "E2M2PraagHavar3")
	pHavarLine4		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", g_pMissionDatabase, "E2M2PraagHavar4")
	pPraagLine5		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", g_pMissionDatabase, "E2M2PraagHavar5")
	pSaffiLine6		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2PraagHavar6", None, 0, g_pMissionDatabase)
	pFelixLine7		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2PraagHavar7", "Captain", 1, g_pMissionDatabase)
	pBrexLine8		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2PraagHavar8", None, 0, g_pMissionDatabase)
	pTransferDone	= App.TGScriptAction_Create(__name__, "TransferDone")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pPraagLine1)
	pSequence.AppendAction(pHavarLine2)
	pSequence.AppendAction(pPraagLine3)
	pSequence.AppendAction(pHavarLine4)
	pSequence.AppendAction(pPraagLine5)
	pSequence.AppendAction(pSaffiLine6)
	pSequence.AppendAction(pFelixLine7)
	pSequence.AppendAction(pBrexLine8)
	pSequence.AppendAction(pTransferDone, 2)
	
	# Register this sequence so we can kill it if the player is detected
	App.TGActionManager_RegisterAction(pSequence, "PraagHavar")	
	
	pSequence.Play()
	
	return 0

################################################################################
##	TransferDone()
##
##	Script action that plays sequence letting  the player know the Cards and 
##	Marauder are done with their business.  Calls script actions to reset
##	Galor and Marauder AI.
##
##	Args:	pTGAction	- The script aciton object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def TransferDone(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1)  or (g_bPlayerDetected == TRUE):
		return 0
	
	# Set our flag so the player can't be detected
	global g_bPlayerSneaking
	g_bPlayerSneaking = FALSE
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pKiskaLeave1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2CardsLeave1", "Captain", 0, g_pMissionDatabase)
	pResetAIs		= App.TGScriptAction_Create(__name__, "ResetAIs")
	
	pSequence.AppendAction(pKiskaLeave1)
	pSequence.AppendAction(pResetAIs)

	pSequence.Play()

	# Register to Generic
	App.TGActionManager_RegisterAction(pSequence, "Generic")
	
	# Remove our Investigate goal
	MissionLib.RemoveGoal("E2InvestigateSerrisGoal")
	
	return 0

################################################################################
##	ResetAIs()
##
##	Resets the AIs for both the Galors and the Marauder.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep callling sequence from crashing.
################################################################################
def ResetAIs(pTGAction):
	# Set our flag so the Galors won't "detect" the player
	# when they go to warp and allow the player to warp.
	global g_bPlayerSneaking
	g_bPlayerSneaking	= FALSE
	
	# Get the set and the ships
	pSet		= App.g_kSetManager.GetSet("Serris2")
	pMarauder	= App.ShipClass_GetObject(pSet, "Marauder")
	pKeldon1	= App.ShipClass_GetObject(pSet, "Keldon 1")
	pGalor2		= App.ShipClass_GetObject(pSet, "Galor 2")
	
	# Import the AI for the Galors and assign
	import E2M2_AI_GalorWarp
	if (pKeldon1 != None):
		pKeldon1.SetAI(E2M2_AI_GalorWarp.CreateAI(pKeldon1, "Galor1Enter"))
	if (pGalor2 != None):
		pGalor2.SetAI(E2M2_AI_GalorWarp.CreateAI(pGalor2, "Galor2Enter"))

	# Get our difficulity level and set the speeds based on that
	eDifficulty = App.Game_GetDifficulty()
	if (eDifficulty == App.Game.EASY):
		fSpeed = 0.9
	elif (eDifficulty == App.Game.MEDIUM):
		fSpeed = 1.0
	elif (eDifficulty == App.Game.HARD):
		fSpeed = 1.0

	# Import and assign the AI for the Marauder
	import E2M2_AI_MarauderRun
	if (pMarauder != None):
		pMarauder.SetAI(E2M2_AI_MarauderRun.CreateAI(pMarauder, fSpeed))
	
	return 0

################################################################################
##	GalorsLeave()
##
##	Called from EnterSet() when the Galors leave the set for the first time.
##	Starts the timer that controls when the Marauder will warp out.  Sets flag
##	that allows player to warp.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GalorsLeave():
	# Set our mission state
	global g_iMissionState
	g_iMissionState = GALORS_LEAVE
	
	# Set the flag that will allow the player to warp if they want to
	global g_bCantWarp
	g_bCantWarp	= FALSE

	# Do our sequence to let the player know the Galors have left
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelLeave2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2CardsLeave2", None, 0, g_pMissionDatabase)
	pKiskaLeave3	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2CardsLeave3", None, 1, g_pMissionDatabase)
	pSaffiLeave4	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2CardsLeave4", "Captain", 1, g_pMissionDatabase)

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelLeave2)
	pSequence.AppendAction(pKiskaLeave3)
	pSequence.AppendAction(pSaffiLeave4)
	
	pSequence.Play()

	# Register to Generic
	App.TGActionManager_RegisterAction(pSequence, "Generic")

	# Start the Matauders warp timer
	global g_iWarpTimerID
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_MARAUDER_WARP_TIMER, __name__ + ".MarauderWarps", fStartTime + 300, 0, 0)
	g_iWarpTimerID = pTimer.GetObjID()
	MissionLib.CreateTimer(ET_MARAUDER_WARP_WARNING, __name__ + ".MarauderWarpWarning", fStartTime + 270, 0, 0)
	
	# Add our goal and remove the AvoidDetection goal
	MissionLib.AddGoal("E2DisableMarauderGoal")
	MissionLib.RemoveGoal("E2AvoidDetectionGoal")
	
################################################################################
##	MarauderRuns()
##
##	Called from E2M2_AI_MarauderRun.py when the player gets close to the
##	Marauder.  Does short sequence.  Also boosts the speed on the waypoint
##	so the Marauder speeds up. Also can be called from the hailhandler.
##
##	Args:	None
##
##	Return:	None
################################################################################
def MarauderRuns():
	#make sure this only plays once
	if (g_bMarauderRuns == TRUE):
		return
	global g_bMarauderRuns
	g_bMarauderRuns = TRUE
	
	# Set the Impulse engines on the Marauder back to 100%
	pShip = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Serris2"), "Marauder")
	if (pShip != None):
		pImpulse = pShip.GetImpulseEngineSubsystem()
		if (pImpulse != None):
			pImpulse.SetPowerPercentageWanted(1.0)
			
	# Do our sequence.
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelRun1		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderRuns1", "Captain", 1, g_pMissionDatabase)
	pMiguelRun1a	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderRuns1a", None, 0, g_pMissionDatabase)
	pBrexRun1b		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderRuns1b", None, 0, g_pMissionDatabase)
	pSaffiRun3		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderRuns3", "Captain", 0, g_pMissionDatabase)
	pKiskaSOS1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderSOS1", "Captain", 1, g_pMissionDatabase)
	pSaffiSOS2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderSOS2", None, 0, g_pMissionDatabase)

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelRun1, 5) #5 second delay in case this is called from the hail handler
	pSequence.AppendAction(pMiguelRun1a)
	pSequence.AppendAction(pBrexRun1b)
	pSequence.AppendAction(pSaffiRun3)
	pSequence.AppendAction(pKiskaSOS1, 10)
	pSequence.AppendAction(pSaffiSOS2)
	
	pSequence.Play()
	
	# Register the sequence.
	App.TGActionManager_RegisterAction(pSequence, "PraagSequence")
	
################################################################################
##	BoostMarauderEngines()
##
##	Called from E2M2_AI_MarauderRun.py.  Boosts the power to the engines if
##	we are at the hard difficulty
##
##	Args:	None
##
##	Return:	None
################################################################################
def BoostMarauderEngines():
	#Bail if the difficulity is not at hard
	eDifficulty = App.Game_GetDifficulty()
	if (eDifficulty != App.Game.HARD):
		return
	
	# Get the Marauder and the impulse system
	pShip	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Serris2"), "Marauder")
	if (pShip == None):
		return
	
	pImpulse = pShip.GetImpulseEngineSubsystem()
	# Boost the engines
	if (pImpulse != None):
		pImpulse.SetPowerPercentageWanted(1.15)
		
################################################################################
##	MarauderDisabled()
##
##	Called from E2M2_AI_MarauderRun.py when the Marauders warp engines are
##	disabled.
##
##	Args:	None
##
##	Return:	None
################################################################################
def MarauderDisabled():
	# Don't play if the Marauder has been destroyed
	if (g_bMarauderDestroyed == TRUE):
		return

	# Set our mission state
	global g_iMissionState
	g_iMissionState = DEFAULT
	
	# Set our flags
	global g_bMarauderDisabled
	global g_bCantWarp
	g_bMarauderDisabled = TRUE
	g_bCantWarp			= TRUE
	
	# Get the characters we need
	pPraag	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("MarauderSet"), "Praag")
	
	# Do the sequence.
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCutsceneStart		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pStopFelix			= App.TGScriptAction_Create("MissionLib", "StopFelix")
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pLookForward		= App.TGScriptAction_Create("MissionLib", "LookForward")
	pPlayerIntercept	= App.TGScriptAction_Create(__name__, "GivePlayerIntercept")
	pStartSerrisCam		= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Serris2")
	pMiguelDisabled1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled1a", "Captain", 1, g_pMissionDatabase)
	pSaffiDisabled2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled2", None, 0, g_pMissionDatabase)
	pKiskaDisabled3		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled3", None, 0, g_pMissionDatabase)
	pPraagDisabled4		= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled4", None, 0, g_pMissionDatabase)
	pSaffiStepUp		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
	pSaffiDisabled5		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled5", None, 0, g_pMissionDatabase)
	pMarauderViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MarauderSet", "Praag")
	pPlaceCards			= App.TGScriptAction_Create(__name__, "PlaceCards")
	pPraagDisabled6		= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled6", None, 0, g_pMissionDatabase)
	pSaffiDisabled7		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled7", None, 0, g_pMissionDatabase)
	pPraagDisabled8		= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled8", None, 0, g_pMissionDatabase)
	pSaffiDisabled9		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled9", None, 0, g_pMissionDatabase)
	pPraagDisabled12	= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled12", None, 0, g_pMissionDatabase)
	pSaffiDisabled13	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled13", None, 0, g_pMissionDatabase)
	pPraagDisabled14	= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled14", None, 0, g_pMissionDatabase)
	pSaffiDisabled15	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled15", None, 0, g_pMissionDatabase)
	pPraagDisabled16	= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled16", None, 0, g_pMissionDatabase)
	pSaffiDisabled17	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled17", None, 0, g_pMissionDatabase)
	pResetGalorAI		= App.TGScriptAction_Create(__name__, "ResetGalorAI")	
	pMiguelReturn1		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2CardsReturn1", "Captain", 0, g_pMissionDatabase)
	pSwitchToSerris		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Serris2")
	pWatchKeldon		= App.TGScriptAction_Create("Actions.CameraScriptActions", "LockedViewAnyAngle", "Serris2", "Keldon 1", 350, 10, 5, 170, -5)
	pSaffiReturn2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2CardsReturn2", None, 0, g_pMissionDatabase)
	pMiguelReturn3		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2CardsReturn3", None, 1, g_pMissionDatabase)
	pSaffiStepDown		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
	pSwitchToBridge		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSaffiReturn4		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2CardsReturn4", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndSerrisCam		= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Serris2")
	pMakeMarauderFriend	= App.TGScriptAction_Create(__name__, "MakeMarauderFriend")
	pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCutsceneStart)
	pSequence.AppendAction(pStopFelix)
	pSequence.AddAction(pForceToBridge, pCutsceneStart)
	pSequence.AddAction(pLookForward, pForceToBridge)
	pSequence.AddAction(pPlayerIntercept, pCutsceneStart)
	pSequence.AddAction(pStartSerrisCam, pForceToBridge)
	pSequence.AddAction(pMiguelDisabled1, pForceToBridge)
	pSequence.AppendAction(pSaffiDisabled2)
	pSequence.AppendAction(pKiskaDisabled3)
	pSequence.AppendAction(pPraagDisabled4)
	pSequence.AppendAction(pSaffiDisabled5)
	pSequence.AddAction(pSaffiStepUp, pPraagDisabled4)
	pSequence.AddAction(pMarauderViewOn, pSaffiStepUp)
	pSequence.AddAction(pPlaceCards, pMarauderViewOn)
	pSequence.AddAction(pPraagDisabled6, pMarauderViewOn)
	pSequence.AddAction(pSaffiDisabled7, pPraagDisabled6)
	pSequence.AddAction(pPraagDisabled8, pSaffiDisabled7)
	pSequence.AddAction(pSaffiDisabled9, pSaffiDisabled7, 5.5)
	pSequence.AppendAction(pPraagDisabled12)
	pSequence.AppendAction(pSaffiDisabled13)
	pSequence.AppendAction(pPraagDisabled14)
	pSequence.AppendAction(pSaffiDisabled15)
	pSequence.AppendAction(pPraagDisabled16)
	pSequence.AppendAction(pSaffiDisabled17)
	pSequence.AddAction(pResetGalorAI, pSaffiDisabled15)
	pSequence.AddAction(pMiguelReturn1, pSaffiDisabled17)
	pSequence.AddAction(pSwitchToSerris, pMiguelReturn1)
	pSequence.AddAction(pWatchKeldon, pSwitchToSerris)
	pSequence.AddAction(pSaffiReturn2, pMiguelReturn1)
	pSequence.AddAction(pMiguelReturn3, pSaffiReturn2)
	pSequence.AddAction(pSwitchToBridge, pMiguelReturn3)
	pSequence.AddAction(pSaffiStepDown, pMiguelReturn3)
	pSequence.AddAction(pSaffiReturn4, pMiguelReturn3)
	pSequence.AddAction(pViewOff, pSaffiReturn4)
	pSequence.AppendAction(pEndSerrisCam)
	pSequence.AppendAction(pMakeMarauderFriend)
	pSequence.AppendAction(pEndCutscene)
	
	pSequence.Play()

	# Register this sequence so we can stop it if need be
	App.TGActionManager_RegisterAction(pSequence, "PraagSequence")		
	
	# Remove the disable Marauder goal
	MissionLib.RemoveGoal("E2DisableMarauderGoal")

################################################################################
##	MakeMarauderFriend()
##
##	Script action that changes affliation of Marauder and sets the repair rate
##	on it's warp engines.  Also turns collisions back on for the Cardassians.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MakeMarauderFriend(pTGAction):
	# Bail if mission terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Set the repair complexity of the warp engines back to their original
	pShip	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Serris2"), "Marauder")

	if (pShip != None):	
		pSystem = pShip.GetWarpEngineSubsystem()

		for i in range(pSystem.GetNumChildSubsystems()):
			pChild = pSystem.GetChildSubsystem(i)
			pProp = pChild.GetProperty()
			pProp.SetRepairComplexity(g_iMarauderWarpRepairRate)	
	
		# Return the power balance on the engines
		pImpulse = pShip.GetImpulseEngineSubsystem()
		# Boost the engines
		if (pImpulse != None):
			pImpulse.SetPowerPercentageWanted(1)

	# Set the Marauder to be friendly
	pMission = MissionLib.GetMission()
	if (pMission == None):
		return 0
	pNeutrals	= pMission.GetNeutralGroup()
	pFriendlies	= pMission.GetFriendlyGroup()

	pNeutrals.RemoveName("Marauder")
	pFriendlies.AddName("Marauder")
	
	# Turn the collisions back on for the Cardassians
	for sShipName in g_lCardShipNames:
		pShip = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Serris2"), sShipName)
		if (pShip != None):
			pShip.SetCollisionsOn(TRUE)
			
	return 0

################################################################################
##	GivePlayerIntercept()
##
##	Script action that gives the players ship the intercept AI with the
##	Marauder as a target.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def GivePlayerIntercept(pTGAction):
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
	
	# Get the Marauder so we can have it be the target
	pSet		= App.g_kSetManager.GetSet("Serris2")
	pMarauder	= App.ShipClass_GetObject(pSet, "Marauder")
	if (pMarauder == None):
		return 0
		
	# Import the intercept AI and assign it to the player.
	import AI.Player.InterceptTarget
	MissionLib.SetPlayerAI("Helm", AI.Player.InterceptTarget.CreateAI(pPlayer, pMarauder))
	
	return 0

################################################################################
##	PlaceCards()
##
##	Script action that places the Cardassians in the set so we don't have to
##	wait for them to warp.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PlaceCards(pTGAction):
	# Get the Cardassians
	pDeepSpaceSet	= App.g_kSetManager.GetSet("DeepSpace")
	pSerris2Set		= App.g_kSetManager.GetSet("Serris2")
	pKeldon1		= App.ShipClass_GetObject(pDeepSpaceSet, "Keldon 1")
	pGalor2			= App.ShipClass_GetObject(pDeepSpaceSet, "Galor 2")
	
	if (pKeldon1 != None):
		pDeepSpaceSet.RemoveObjectFromSet("Keldon 1")
		pSerris2Set.AddObjectToSet(pKeldon1, pKeldon1.GetName())
		pKeldon1.PlaceObjectByName("Galor1Enter")

	if (pGalor2 != None):
		pDeepSpaceSet.RemoveObjectFromSet("Galor 2")
		pSerris2Set.AddObjectToSet(pGalor2, pGalor2.GetName())
		pGalor2.PlaceObjectByName("Galor2Enter")
		
	return 0

################################################################################
##	MarauderWarpWarning()
##
##	Called from timner event.
##	Gives the user a 20 second warning that the Marauder is going to warp
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def MarauderWarpWarning(TGObject, pEvent):
	
	# Check our flag
	if (g_bMarauderDisabled == TRUE):
		return
			
	pSequence = App.TGSequence_Create()
	
	pMiguel1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderRuns4", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AppendAction(pMiguel1)
	
	pSequence.Play()
	
################################################################################
##	MarauderWarps()
##
##	Called from timner event.  Resets the Marauder AI so the ship warps out of
##	the system.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def MarauderWarps(TGObject, pEvent):
	# Check our flag
	if (g_bMarauderDisabled == TRUE):
		return

	# Get the set and the ship
	pSet	= App.g_kSetManager.GetSet("Serris2")
	pShip	= App.ShipClass_GetObject(pSet, "Marauder")
	
	# Import and assign the AI
	if (pShip != None):
		import Maelstrom.Episode2.AI_WarpOut
		pShip.SetAI(Maelstrom.Episode2.AI_WarpOut.CreateAI(pShip))
	
################################################################################
##	MarauderEscapes()
##
##	Called from ExitSet if the Marauder warps out before the player can disable
##	them.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MarauderEscapes(pTGAction = None):
	# Don't play if we've won the mission
	if (g_bMissionWon == TRUE):
		return 0
	
	# Get the players set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return 0
	
	# Set our local flag
	bPlayerInTheSet = TRUE
	
	if (pSet.GetName() != "Serris2"):
		# Delay sequence 1 second1.
		pSequence = App.TGSequence_Create()
		pWaitAction	= App.TGScriptAction_Create(__name__, "MarauderEscapes")
		pSequence.AppendAction(pWaitAction, 1)
		pSequence.Play()
		bPlayerInTheSet = FALSE
		return 0

	else:	
		# Kill all the Sequence we can
		App.TGActionManager_KillActions("Generic")
		App.TGActionManager_KillActions("PraagSequence")
		App.TGActionManager_KillActions("PraagHavar")

		pSequence = App.TGSequence_Create()

		pLookAtSaffi	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
		pSaffiEscapes1a	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderEscapes1a", "Captain", 0, g_pMissionDatabase)
		pSaffiEscapes1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderEscapes1", None, 1, g_pMissionDatabase)

		# If the Marauder warped out, add Kiska's line to tell the player
		if (bPlayerInTheSet == TRUE):
			pKiskaWarps	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin9alt", "Captain", 0, g_pMissionDatabase)
			pSequence.AppendAction(pKiskaWarps)

		pSequence.AppendAction(pLookAtSaffi)
		pSequence.AppendAction(pSaffiEscapes1a)
		pSequence.AppendAction(pSaffiEscapes1)

		# End the mission
		pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
		pGameOver.Play()

		return 0
		
################################################################################
##	ResetGalorAI()
##
##	Called as script action.  Resets the AI of the Galors so they will warp back
##	into the system and attack the player and Marauder.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequqence from crashing.
################################################################################
def ResetGalorAI(pTGAction):
	# Get the set and the ships
	pSet		= App.g_kSetManager.GetSet("Serris2")
	pKeldon1	= App.ShipClass_GetObject(pSet, "Keldon 1")
	pGalor2		= App.ShipClass_GetObject(pSet, "Galor 2")
	
	# Import and assign the AI
	import E2M2_AI_GalorReturn
	
	if (pKeldon1 != None):
		pKeldon1.SetAI(E2M2_AI_GalorReturn.CreateAI(pKeldon1, g_pKeldon1Targets))
	if (pGalor2 != None):
		pGalor2.SetAI(E2M2_AI_GalorReturn.CreateAI(pGalor2, g_pGalor2Targets))
	
	return 0
	
################################################################################
##	MissionWin()
##
##	Called from ExitSet() when both the Galors have left the Serris 2 set.
##
##	Args:	None
##
##	Return:	None
####G############################################################################
def MissionWin():
	# Don't play if the Maruader was destroyed
	if (g_bMarauderDestroyed == TRUE):
		return
	
	# Set flag so we can't warp
	global g_bCantWarp
	g_bCantWarp = TRUE
	
	# Set the condition of the warp engines on the Marauder
	pShip	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Serris2"), "Marauder")
	if (pShip != None):
		# Get the warp subsystem
		pWarp	= pShip.GetWarpEngineSubsystem()
		# Get the warp engines one by one and fix each of them above
		# the disabled percentage
		for iCounter in range(pWarp.GetNumChildSubsystems()):
			pChild = pWarp.GetChildSubsystem(iCounter)
			pChild.SetConditionPercentage(pChild.GetDisabledPercentage() + 0.1)
	
	# Set our flag
	global g_bMissionWon
	g_bMissionWon = TRUE
	
	# Set our mission state
	global g_iMissionState
	g_iMissionState = DEFAULT
	
	# Get the characters we need		
	pPraag	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("MarauderSet"), "Praag")
	
	pSequence = App.TGSequence_Create()

	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pKiskaRetreat1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2CardsRetreat1", "Captain", 1, g_pMissionDatabase)
	pMiguelRetreat2		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2CardsRetreat2", "Captain", 0, g_pMissionDatabase)
	pMiguelRetreat3		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2CardsRetreat3", None, 1, g_pMissionDatabase)
	pKiskaWin1			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin1", "Captain", 1, g_pMissionDatabase)
	pMarauderViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MarauderSet", "Praag")
	pPraagWin2			= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin2", None, 0, g_pMissionDatabase)
	pSaffiWin3			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin3", None, 0, g_pMissionDatabase)
	pPraagWin4			= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin4", None, 0, g_pMissionDatabase)
	pPraagWin5			= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin5", None, 0, g_pMissionDatabase)
	pSaffiWin6			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin6", None, 0, g_pMissionDatabase)
	pPraagWin6a			= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin6a", None, 0, g_pMissionDatabase)
	pPraagDisabled18	= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled18", None, 0, g_pMissionDatabase)
	pSaffiDisabled19	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled19", None, 0, g_pMissionDatabase)
	pPraagDisabled20	= App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled20", None, 0, g_pMissionDatabase)
	pSaffiDisabled21	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDisabled21", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pBrexWin7			= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin7", None, 0, g_pMissionDatabase)
	pClearWarp			= App.TGScriptAction_Create(__name__, "ClearCantWarpFlag")
	pResetAI			= App.TGScriptAction_Create(__name__, "ResetMarauderAI")
	pMiguelWin8			= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin8", None, 0, g_pMissionDatabase)
	pKiskaWin9			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin9", "Captain", 1, g_pMissionDatabase)
	pSaffiWin11			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin11", None, 1, g_pMissionDatabase)
	pHailLiu			= App.TGScriptAction_Create(__name__, "HailLiu")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pKiskaRetreat1)
	pSequence.AppendAction(pMiguelRetreat2)
	pSequence.AppendAction(pMiguelRetreat3)
	pSequence.AppendAction(pKiskaWin1)
	pSequence.AppendAction(pMarauderViewOn)
	pSequence.AppendAction(pPraagWin2)
	pSequence.AppendAction(pSaffiWin3)
	pSequence.AppendAction(pPraagWin4)
	pSequence.AppendAction(pPraagWin5)
	pSequence.AppendAction(pSaffiWin6)
	pSequence.AppendAction(pPraagWin6a)
	pSequence.AppendAction(pPraagDisabled18)
	pSequence.AppendAction(pSaffiDisabled19)
	pSequence.AppendAction(pPraagDisabled20)
	pSequence.AppendAction(pSaffiDisabled21)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pBrexWin7)
	pSequence.AppendAction(pClearWarp)
	pSequence.AppendAction(pResetAI)
	pSequence.AppendAction(pMiguelWin8)
	pSequence.AppendAction(pKiskaWin9)
	pSequence.AppendAction(pSaffiWin11)
	pSequence.AppendAction(pHailLiu)
	
	pSequence.Play()
	
	# Register this sequence so we can stop it if need be
	App.TGActionManager_RegisterAction(pSequence, "PraagSequence")		

	# Remove our Protect Marauder Goal and add
	# our head home goal
	MissionLib.RemoveGoal("E2ProtectMarauderGoal")
	
################################################################################
##	ResetMarauderAI()
##
##	Resets the Maruader AI so that it will warp out of the system.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetMarauderAI(pTGAction):
	# Get the ship
	pMarauder	= App.ShipClass_GetObject(None, "Marauder")
	
	# Get and assign the AI
	if (pMarauder != None):
		import Maelstrom.Episode2.AI_WarpOut
		pMarauder.SetAI(Maelstrom.Episode2.AI_WarpOut.CreateAI(pMarauder))
	
	return 0

################################################################################
##	MarauderDestroyed()
##
##	Called from ObjectDestroyed() if the Marauder is destroyed in Serris 2.
##	Is a mission loss.
##
##	Args:	None
##
##	Return:	None
################################################################################
def MarauderDestroyed():
	# End all our sequences
	App.TGActionManager_KillActions("PraagSequence")
	App.TGActionManager_KillActions("Generic")
	App.TGActionManager_KillActions("PraagHavar")

	pSequence = App.TGSequence_Create()
	# Reset the AI of the Galors
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "WarpGalorsOut"))
	# Add action to face the camera forward
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "LookForward"))
	
	# Check our flag to see what sequence to call
	if (g_bShipsIDd == TRUE):
		# Sequence that plays if the ships were IDd before Marauder was destroyed
		pLiu = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("StarbaseSet"), "Liu")

		pFelixDestroyed1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDestroyed1", "Captain", 1, g_pMissionDatabase)
		pBrexDestroyed4		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDestroyed4", None, 0, g_pMissionDatabase)
		pSaffiLook2			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
		pSaffiPressButtons	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons", None, 1)
		pSaffiHailStarfleet	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet1", None, 0, g_pGeneralDatabase)
		pKiskaIncoming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg5", "Captain", 1, g_pGeneralDatabase)
		pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
		pLiuDestroyed5		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDestroyed5", None, 1, g_pMissionDatabase)
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

		# Create and add these if the Cards actually returned
		if (g_bMarauderDisabled == TRUE):
			pMiguelDestroyed2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDestroyed2", "Captain", 1, g_pMissionDatabase)
			pSaffiDestroyed3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderDestroyed3", "Captain", 1, g_pMissionDatabase)
			pSaffiLook			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
		
		# Build the sequence
		pSequence.AppendAction(pFelixDestroyed1)
		
		if (g_bMarauderDisabled == TRUE):
			pSequence.AppendAction(pMiguelDestroyed2)
			pSequence.AppendAction(pSaffiLook)
			pSequence.AppendAction(pSaffiDestroyed3)
			
		pSequence.AppendAction(pBrexDestroyed4)
		pSequence.AppendAction(pSaffiLook2)
		pSequence.AddAction(pSaffiPressButtons,		pSaffiLook2)
		pSequence.AddAction(pSaffiHailStarfleet,	pSaffiLook2)
		pSequence.AppendAction(pKiskaIncoming, 2)
		pSequence.AppendAction(pStarbaseViewOn)
		pSequence.AppendAction(pLiuDestroyed5)
		pSequence.AppendAction(pViewOff)
	
	else:
		# If the ships were not IDd.
		pMiguelSaved1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderSaved1", None, 0, g_pMissionDatabase)
		pSaffiScan4		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2Serris3Scan4", None, 0, g_pMissionDatabase)
		pMiguelNothing	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "gs038", None, 0, g_pGeneralDatabase)
		pSaffiEscape1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2MarauderEscapes1", "Captain", 1, g_pMissionDatabase)
		
		pSequence.AppendAction(pMiguelSaved1)
		pSequence.AppendAction(pSaffiScan4)
		pSequence.AppendAction(pMiguelNothing)
		pSequence.AppendAction(pSaffiEscape1)
		
	# End the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()

################################################################################
##	WarpGalorsOut()
##
##	Script action that warps the Galors out.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def WarpGalorsOut(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Reset the AI for the Cards
	for sShipName in g_lCardShipNames:
		pShip = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Serris2"), sShipName)
		if (pShip != None):
			import Maelstrom.Episode2.AI_WarpOut
			pShip.SetAI(Maelstrom.Episode2.AI_WarpOut.CreateAI(pShip), 0, 0)	

	return 0
	
################################################################################
##	HailLiu()
##
##	Script action that does debriefing from Liu after Saffi contacts her.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def HailLiu(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1) or (g_bEndDialoguePlayed == TRUE):
		return 0
	
	# Set our flag
	global g_bEndDialoguePlayed
	g_bEndDialoguePlayed = TRUE
	
	# Get the characters we need
	pLiu	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("StarbaseSet"), "Liu")

	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pSaffiHail1		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet1", None, 0, g_pGeneralDatabase)
	pSaffiActive	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons", None, 1)
	pSaffiHail7		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet7", None, 0, g_pGeneralDatabase)
	pKiskaIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "gf013a", None, 0, g_pGeneralDatabase)
	pViewscreenOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pHailLiu1		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin11b", None, 0, g_pMissionDatabase)
	pHailLiu2		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M2MissionWin12a", None, 0, g_pMissionDatabase)
	pStartE2M6		= App.TGScriptAction_Create(__name__, "StartMissionE2M6")
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pSaffiHail1)
	pSequence.AppendAction(pSaffiActive)
	pSequence.AppendAction(pSaffiHail7, 3)
	pSequence.AppendAction(pKiskaIncoming)
	pSequence.AppendAction(pViewscreenOn)
	pSequence.AppendAction(pHailLiu1)
	pSequence.AppendAction(pHailLiu2)
	pSequence.AppendAction(pStartE2M6)
	pSequence.AppendAction(pEndCallWaiting)

	pSequence.Play()

	# Register to Generic
	App.TGActionManager_RegisterAction(pSequence, "Generic")

	return 0
	
################################################################################
##	StartMissionE2M6()
##
##	Starts E2M6.  Does the briefing and the link.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 0 to keep calling sequence paused.
################################################################################
def StartMissionE2M6(pTGAction):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Get the Database for this audio
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 2/E2M6.TGL")
	
	# Do our sequence stuff
	pStarbase	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu		= App.CharacterClass_GetObject(pStarbase, "Liu")

	pSequence = App.TGSequence_Create()

	pLiuBriefing1		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6Briefing1", None, 0, pDatabase)
	pLiuBriefing2		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6Briefing2", None, 0, pDatabase)
	pLiuBriefing3		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6Briefing3", None, 0, pDatabase)
	pCreateBiranu		= App.TGScriptAction_Create(__name__, "CreateBiranu")
	pStarbaseViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pKiskaBriefing4		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6Briefing4", "Captain", 0, pDatabase)

	pSequence.AppendAction(pLiuBriefing1)
	pSequence.AppendAction(pLiuBriefing2)
	pSequence.AppendAction(pLiuBriefing3)
	pSequence.AppendAction(pStarbaseViewOff)
	pSequence.AppendAction(pCreateBiranu)
	pSequence.AppendAction(pKiskaBriefing4)

	# Add completed event so calling sequence continues.
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

	return 1

################################################################################
##	CreateBiranu()
##
##	Script action that creates the Biranu system in the helm menu and links it
##	to the next mission.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CreateBiranu(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	# Set our menus
	import Systems.Biranu.Biranu
	pBiranuMenu = Systems.Biranu.Biranu.CreateMenus()

	# Set the mission name for the button
	pBiranuMenu.SetMissionName("Maelstrom.Episode2.E2M6.E2M6")

	# Get the epiosde and register our Defend Station goal
	MissionLib.AddGoal("E2ResolveConflictGoal")

	return 0
	
################################################################################
##	Serris3Communicate()
##
##	Called from CommunicateHandler if the player is in Serris 3 at beginning of
##	mission.  Plays special communicate lines.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was caught by CommunicateHandler()
##
##	Return:	None
################################################################################
def Serris3Communicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose menu was clicked and play their line.
	if (iMenuID == idKiskaMenu) and (g_bPlayerScannedSerris3 == TRUE):
		pComLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2KiskaCom1", "Captain", 0, g_pMissionDatabase)
		pComLine.Play()
	
	elif (iMenuID == idFelixMenu):
		pComLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2FelixCom1", "Captain", 0, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idSaffiMenu) and (g_bPlayerScannedSerris3 == TRUE):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2SaffiCom1", "Captain", 0, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idMiguelMenu):
		# Miguel has two lines depending on if the scan was done or not.
		if (g_bSerris3ScanDone == TRUE):
			pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MiguelCom1a", "Captain", 0, g_pMissionDatabase)
			pComLine.Play()
		else:
			pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MiguelCom1", "Captain", 0, g_pMissionDatabase)
			pComLine.Play()
				
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2BrexCom1", "Captain", 0, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Just do the default
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	Serris2Communicate()
##
##	Called from CommunicateHander if the player is in Serris 2 before the ships
##	in that system are identified.  Plays communicate lines.
##
##	Args:	iMenuID	- The object ID of the menu that was clicked.
##
##	Return:	None
################################################################################
def Serris2Communicate(iMenuID):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose menu was clicked and play their line.
	if (iMenuID == idKiskaMenu):
		pComLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2KiskaCom2", "Captain", 0, g_pMissionDatabase)
	
	elif (iMenuID == idFelixMenu):
		pComLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2FelixCom2", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2SaffiCom2", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MiguelCom2", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2BrexCom2", "Captain", 0, g_pMissionDatabase)
		
	else:
		# We got a bogus object ID, so just return
		return
	
	# Play the line that we've set up
	pComLine.Play()
	
################################################################################
##	ShipsIdCommunicate()
##
##	Called from CommunicateHandler() if player has ID'd the ships.  Plays
##	special communicate lines.
##
##	Args:	iMenuID	- The object ID of the menu that was clicked.
##
##	Return:	None
################################################################################
def ShipsIdCommunicate(iMenuID):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose menu was clicked and play their line.
	if (iMenuID == idKiskaMenu):
		pComLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2KiskaCom3", "Captain", 0, g_pMissionDatabase)
	
	elif (iMenuID == idFelixMenu):
		pComLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2FelixCom3", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2SaffiCom3", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MiguelCom3", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2BrexCom3", "Captain", 0, g_pMissionDatabase)
		
	else:
		# We got a bogus object ID, so just return
		return

	# Play the line that we've set up
	pComLine.Play()

################################################################################
##	GalorsLeaveCommunicate()
##
##	Called from CommunicateHandler() if the Galors have warped out of the
##	system.  Plays special communicate lines.
##
##	Args:	iMenuID	- The object ID of the menu that was clicked.
##
##	Return:	None
################################################################################
def GalorsLeaveCommunicate(iMenuID):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose menu was clicked and play their line.
	if (iMenuID == idKiskaMenu):
		pComLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M2KiskaCom4", "Captain", 0, g_pMissionDatabase)
	
	elif (iMenuID == idFelixMenu):
		pComLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M2FelixCom4", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2SaffiCom4", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M2MiguelCom4", "Captain", 0, g_pMissionDatabase)
		
	elif (iMenuID == idBrexMenu):
		# Brex has two lines depending of if the impulse engines are boosted
		# Get the ship and the impulse subsystem and see if it's boosted
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
		pImpulse	= pPlayer.GetImpulseEngineSubsystem()
		if (MissionLib.IsBoosted(pImpulse) == TRUE):
			pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2BrexCom4a", "Captain", 0, g_pMissionDatabase)
		else:
			pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M2BrexCom4", "Captain", 0, g_pMissionDatabase)
			
	else:
		# We got a bogus object ID, so just return
		return

	# Play the line that we've set up
	pComLine.Play()

################################################################################
##	GalorsReturnCommunicate()
##
##	Called from CommunicateHandler() if the Galors have warped back into the
##	system.  Plays special communicate line for Saffi, does default for the
##	others.
##
##	Args:	iMenuID	- The object ID of the menu that was clicked.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was caught by CommunicateHandler()
##
##	Return:	None
################################################################################
def GalorsReturnCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idSaffiMenu = Bridge.BridgeUtils.GetBridgeMenuID("XO")

	# Check and see whose menu was clicked and play their line.
	if (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2SaffiCom5", "Captain", 0, g_pMissionDatabase)
		pComLine.Play()

	# Do the default for everyone else 
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	ClearSequenceFlag()
##
##	Script action that clears the sequence flag.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ClearSequenceFlag(pTGAction = None):
	global g_bSequenceRunning
	g_bSequenceRunning = FALSE
	
	return 0

################################################################################
##	ClearCantWarpFlag()
##
##	Script action that clears the flag that is keeping us from warping.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ClearCantWarpFlag(pTGAction = None):
	global g_bCantWarp
	g_bCantWarp = FALSE
	
	return 0
	
################################################################################
##	StopProdTimer()	
##
##	Removes old timer if goal is reached.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StopProdTimer():
	global g_iProdTimer
	if (g_iProdTimer != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iProdTimer)
		g_iProdTimer = App.NULL_ID

################################################################################
##	RestartProdTimer()
##
##	Starts a timer to prod the player, called as a TGScriptAction
##
##	Args:	pTGAction	- Script action object
##			iTime 		- The length of time in seconds that the timer will run for.
##
##	Return:	0	- Return 0 so sequence that calls won't choke
################################################################################
def RestartProdTimer(pTGAction, iTime):
	# Stop the old prod timer.
	StopProdTimer()

	# Start a new prod timer.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_TIMER, __name__+".ProdPlayer", fStartTime + iTime, 0, 0)
	# Save the ID of the prod timer, so we can stop it later.
	global g_iProdTimer
	g_iProdTimer = pTimer.GetObjID()
	
	return 0

################################################################################
##	ProdPlayer()
##
##	Function called when prod timer triggers.  Plays audio to prod player to
##	next goal.
##
##	Args:	pTGObject	- The TGObject object
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def ProdPlayer(pTGObject, pEvent):
	# Get the player's sensor system and see if it's boosted
	pPlayer		= MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pSensors	= pPlayer.GetSensorSubsystem()
	bBoosted	= MissionLib.IsBoosted(pSensors, 1.2)

	# Don't prod if the player has gone straight from Serris 3 to Serris 1
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	if (pSet.GetName() == "Serris1") and (g_bPlayerArriveSerris2 == FALSE):
		return
	# If the player is leaving the system, call our function
	# to prod him back and return
	elif (g_bPlayerNotInSerris == TRUE) and (g_bMissionWon == FALSE):
		BackToSerrisProd()
	
	# Check our flags and play the prod line if necessary
	elif (g_sProdLine == "E2M2Serris2Prod") and (g_bPlayerArriveSerris2 == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 60)
		
	elif (g_sProdLine == "E2M2OrbitMoon5") and (bBoosted == FALSE) and (g_bCoversationHeard == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 20)

################################################################################
##	BackToSerrisProd()
##
##	Function called to prod the player back to Serris 2.  Will warn the player
##	a couple of times, if they aren't quick enough will end the game.
##
##	Args:	None
##
##	Return:	None
################################################################################
def BackToSerrisProd():
	# Bail if we are in Serris
	if (g_bPlayerNotInSerris == FALSE) or (g_bMissionWon == TRUE):
		return
		
	# Check our counter and play the prod line based on that.
	if (g_iBackToSerrisProd == 0):
		# If player is in Serris 1 or 3, prod back to Serris 2
		pSet = MissionLib.GetPlayerSet()
		if (pSet == None):
			return
		if (pSet.GetName() == "Serris1") or (pSet.GetName() == "Serris3"):
			pSaffiProd1a	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerLeaves1a", "Captain", 1, g_pMissionDatabase)
			pSaffiProd1a.Play()
			RestartProdTimer(None, 60)
		else:
			pSaffiProd1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerLeaves1", "Captain", 1, g_pMissionDatabase)
			pSaffiProd1.Play()
			RestartProdTimer(None, 60)
		
	elif (g_iBackToSerrisProd == 1):
		pSaffiProd2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerLeaves2", "Captain", 1, g_pMissionDatabase)
		pSaffiProd2.Play()
		RestartProdTimer(None, 60)
		
	elif (g_iBackToSerrisProd == 2):
		# We've waited long enough, end the game
		pSaffiProd3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M2PlayerLeaves3", "Captain", 1, g_pMissionDatabase)
		pGameOver	= App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiProd3)
		pGameOver.Play()

	# Increase our counter
	global g_iBackToSerrisProd
	g_iBackToSerrisProd	= g_iBackToSerrisProd + 1
	
################################################################################
##	Teminate()
##	
##  Unloads mission databases
##	
##	Args:	pMission	- The mission object.
##	
##	Return:	None
################################################################################
def Terminate(pMission):
	# Remove all our mission objectives
	MissionLib.DeleteAllGoals()
	
	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()

	# Remove our instance handlers
	RemoveInstanceHandlers()
	
	# Mark our flag
	global g_bMissionTerminate
	g_bMissionTerminate = 0

	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# Unload the Bridge Menus data base
	if (g_pDatabase):
		App.g_kLocalizationManager.Unload(g_pDatabase)
	
	# Stop our prod timer if it's running
	StopProdTimer()
		
################################################################################
##	RemoveInstanceHandlers()
##
##	Removes the instance handlers we registered with the players ship and crew
##	members.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RemoveInstanceHandlers():
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".FriendlyFireGameOverHandler")
	
	# Weapon hit event handler attached to the players ship and the power change handler
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.RemoveHandlerForInstance(App.ET_WEAPON_HIT,					__name__ + ".WeaponHitPlayer")
		pPlayer.RemoveHandlerForInstance(App.ET_SUBSYSTEM_POWER_CHANGED,	__name__ + ".PowerLevelChanged")

	# Handlers attached to Miguel's menu
	pMiguel = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Science")
	if (pMiguel != None):
		pMiguelMenu = pMiguel.GetMenu()
		if (pMiguelMenu != None):
			pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN,			__name__ + ".ScanHandler")
			pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Remove instance handlers for Kiska's
	pKiska = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")
	if (pKiska != None):
		pKiskaMenu = pKiska.GetMenu()
		if (pKiskaMenu != None):
			pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL,		__name__ + ".HailHandler")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_SET_COURSE,	__name__ + ".SetCourseHandler")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			# Remove instance handler on Warp button event
			pWarpButton = Bridge.BridgeUtils.GetWarpButton()
			if (pWarpButton != None):
				pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")

	# Remove instance handlers for Saffi
	pSaffi = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	if (pSaffi != None):
		pSaffiMenu = pSaffi.GetMenu()
		if (pSaffiMenu != None):
			pSaffiMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET,	__name__ + ".HailStarfleet")
			pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,			__name__ + ".CommunicateHandler")
	
	# Remove the instance handlers for Felix
	pFelix = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if (pFelix != None):
		pFelixMenu = pFelix.GetMenu()
		if (pFelixMenu != None):
			pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Remove the instance handlers for Brex
	pBrex = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
	if (pBrex != None):
		pBrexMenu = pBrex.GetMenu()
		if (pBrexMenu != None):
			pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
	

