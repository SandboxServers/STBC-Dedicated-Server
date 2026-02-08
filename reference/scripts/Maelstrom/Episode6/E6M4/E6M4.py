###############################################################################
#	Filename:	E6M4.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 6, Mission 4
#	
#	Created:	11/6/00 -	Jess VanDerwalker
###############################################################################
import App
import loadspacehelper
import MissionLib
import Bridge.BridgeUtils #this will be used later to override erik's probe auto-disable

# For debugging
#kDebugObj = App.CPyDebug()

#kDebugObj.Print('Loading Episode 6 Mission 4 definition...\n')


# Set up global variables here
TRUE				= 1
FALSE				= 0

g_bMissionTerminated	= None

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None
g_pDatabase			= None

g_pInnerProximityCheck	= None
g_pOuterProximityCheck	= None

g_iProdTimer	= None
g_iMissionPositionCounter	=None
g_iScanPromptCounter	=None

g_bPlayerArrivePrendel	= None
g_bPlayerArriveRiha		= None
g_bPlayerArriveTezle2	= None
g_bPlayerArriveTezle1	= None
g_bPlayerArriveYiles4	= None
g_bPlayerArriveYiles2	= None
g_bPlayerNotInTezle1	= None
g_bProbeExists			= None
g_bProbeReachedPlanet	= None
g_bPlayerStuckInTezle2	= None
g_bMissionWinCalled		= None
g_bLiuHailed			= None

g_bPrendelScanned	= None
g_bTezle2Scanned	= None
g_bRihaScanned		= None
g_bYilesScanned		= None
g_bYiles4Scanned	= None
g_bYiles3Scanned	= None
g_bYiles2Scanned	= None
g_bYiles1Scanned	= None
g_bKessokScanned	= None
g_bDerelictScanned	= None
g_bKessokRetreats	= None

g_pYilesCardTargets	= None
g_pGalor2Targets	= None
g_pKeldon2Targets	= None

g_bGalor1Destroyed	= None
g_bGalor2Destroyed	= None
g_bKeldon1Destroyed	= None
g_bKeldon2Destroyed	= None
g_bIncomingCalled	= None

g_bHulkScaned		= None
g_bHulkDestroyed	= None
g_bRihaShipsCreated	= None
g_bKessokCombatPlayed	= None
g_bKessokCombat2Played	= None

g_lCardNames	= []
g_lFriendlyShips	= []
g_lProbeNames		= []

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None

# Event Types for mission
ET_PROD_TIMER			= App.Mission_GetNextEventType()
ET_ENTER_TEZLE_TIMER	= App.Mission_GetNextEventType()
ET_PROBE_TIMER			= App.Mission_GetNextEventType()
ET_PROBE_SHORT_TIMER	= App.Mission_GetNextEventType()
ET_PLANET_PROXIMITY		= App.Mission_GetNextEventType()
ET_CARDS_ON_WAY_TIMER	= App.Mission_GetNextEventType()
ET_MORE_FREAKIN_CARDS_TIMER	= App.Mission_GetNextEventType()

###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to add models to be pre loaded
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	loadspacehelper.PreloadShip("Sovereign", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Keldon", 6)
	loadspacehelper.PreloadShip("Galor", 2)
	loadspacehelper.PreloadShip("KessokLight", 1)
	loadspacehelper.PreloadShip("Transport", 1)

################################################################################
##	Initialize()
##	
##  Called once when mission loads to initialize mission
##	
##	Args: 	pMission	- the mission object
##	
##	Return: None
################################################################################
def Initialize(pMission):
	"Event handler called on episode start.  Create the episode objects here."
#	kDebugObj.Print ("Initializing Episode 6, Mission 4.\n")
	
	# Initialize our global variables
	InitializeGlobals(pMission)
	
	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	# Create the regions that we'll need
	CreateRegions()

	# Create the proximity checks around Tezle 1
	CreateProximityChecks()
	
	# Create needed viewscreen sets
	pLBridgeSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu		= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)
	
	# Initialize global pointers to the bridge crew members
	InitializeCrewPointers()

	# Create menus available at mission start
	CreateStartingMenus()
	
	# Import all the ships we'll be using and place them
	CreateStartingObjects(pMission)
	
	#set the diffucultly level - easy Offense, Defense, med O, D, Hard O, D
	App.Game_SetDifficultyMultipliers(1.15, 1.0, 0.8, 0.8, 0.65, 0.70)
	
	# Create the target lists will use with the AIs
	CreateTargetLists()
		
	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()
	
	# Setup more mission-specific events.
	SetupEventHandlers()
	
	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	
	# Call Liu's breifing
	LiuBriefing(None)
	
	# Save the Game
	MissionLib.SaveGame("E6M4-")

################################################################################
##	InitializeGlobals()
##
##	Initializes our global variables to their default state.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
#	kDebugObj.Print("Initializing global variables")
	
	# Global used with bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0

	# Set the Mission terminate flag
	global g_bMissionTerminated
	g_bMissionTerminated = FALSE

	# Globals used with the TGL database
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 6/E6M4.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Global pointers for proximity checks
	global g_pInnerProximityCheck
	global g_pOuterProximityCheck
	g_pInnerProximityCheck	= None
	g_pOuterProximityCheck	= None
	
	# Global ID for prod timer
	global g_iProdTimer
	g_iProdTimer	= 0
	
	# Global for tracking mission for communicate
	global g_iMissionPositionCounter
	g_iMissionPositionCounter	= 0
	
	global g_iScanPromptCounter
	g_iScanPromptCounter	= 0
	
	# Global used for tracking the player
	global g_bPlayerArrivePrendel
	global g_bPlayerArriveRiha
	global g_bPlayerArriveTezle2
	global g_bPlayerArriveTezle1
	global g_bPlayerArriveYiles4
	global g_bPlayerArriveYiles2
	global g_bPlayerNotInTezle1
	g_bPlayerArrivePrendel	= FALSE
	g_bPlayerArriveRiha		= FALSE
	g_bPlayerArriveTezle2	= FALSE
	g_bPlayerArriveTezle1	= FALSE
	g_bPlayerArriveYiles4	= FALSE
	g_bPlayerArriveYiles2	= FALSE
	g_bPlayerNotInTezle1	= TRUE
	
	# Globals flags for mission events
	global g_bPrendelScanned
	global g_bTezle2Scanned
	global g_bRihaScanned
	global g_bYilesScanned
	global g_bYiles4Scanned
	global g_bYiles3Scanned
	global g_bYiles2Scanned
	global g_bYiles1Scanned
	global g_bProbeExists
	global g_bProbeReachedPlanet
	global g_bPlayerStuckInTezle2
	global g_bMissionWinCalled
	global g_bLiuHailed
	global g_bKessokScanned
	global g_bDerelictScanned
	global g_bKessokRetreats
	g_bPrendelScanned		= FALSE
	g_bTezle2Scanned		= FALSE
	g_bRihaScanned			= FALSE
	g_bYilesScanned			= FALSE
	g_bYiles4Scanned		= FALSE
	g_bYiles3Scanned		= FALSE
	g_bYiles2Scanned		= FALSE
	g_bYiles1Scanned		= FALSE
	g_bProbeExists			= FALSE
	g_bProbeReachedPlanet	= FALSE
	g_bPlayerStuckInTezle2	= FALSE
	g_bMissionWinCalled		= FALSE
	g_bLiuHailed			= FALSE
	g_bKessokScanned		= FALSE
	g_bDerelictScanned		= FALSE
	g_bKessokRetreats		= FALSE
	
	# Target list globals for AIs
	global g_pYilesCardTargets
	global g_pGalor2Targets
	global g_pKeldon2Targets
	g_pYilesCardTargets	= None
	g_pGalor2Targets	= None
	g_pKeldon2Targets	= None

	# Globals used for tracking destroyed Cards
	global g_bGalor1Destroyed
	global g_bGalor2Destroyed
	global g_bKeldon1Destroyed
	global g_bKeldon2Destroyed
	global g_bIncomingCalled
	g_bGalor1Destroyed	= FALSE
	g_bGalor2Destroyed	= FALSE
	g_bKeldon1Destroyed	= FALSE
	g_bKeldon2Destroyed	= FALSE
	g_bIncomingCalled	= FALSE
	
	global g_bHulkScaned
	global g_bHulkDestroyed
	global g_bRihaShipsCreated
	global g_bKessokCombatPlayed
	global g_bKessokCombat2Played
	g_bHulkScaned		= FALSE
	g_bHulkDestroyed	= FALSE
	g_bRihaShipsCreated	= FALSE
	g_bKessokCombatPlayed	= FALSE
	g_bKessokCombat2Played	= FALSE
	
	# List of Cardassian ship names
	global g_lCardNames
	g_lCardNames	=	[
						"Galor 1", "Galor 2", "Keldon 1", "Keldon 2"
						]
						
	# Global lists of ship names
	global g_lFriendlyShips
	g_lFriendlyShips =	[
						"Starbase 12", "Khitomer", "San Francisco", "Devore", "Venture", "Nightingale", "Transport 1", "Transport 2", "Shuttle 1", "Shuttle 2", "Shuttle 3"
						]

	# Global list of all probes that exist in Tezle 1
	global g_lProbeNames
	g_lProbeNames = []
	
	# Set our limits for the friendly fire warnings and game loss
	App.g_kUtopiaModule.SetMaxFriendlyFire(3000)			# how many damage points the player can do total before losing
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(800)	# how many damage points before Saffi warns you
		
################################################################################
##	InitializeCrewPointers()
##
##	Initializes the global pointers to the bridge crew members.
##	NOTE: This must be called after the bridge is loaded.
##
##	Args:	None
##
##	Return:	None
################################################################################
def InitializeCrewPointers():
	# Get the bridge set
	pBridge = App.g_kSetManager.GetSet("bridge")
	
	# Set the pointer for the crew
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
##	CreateRegions()
##
##	Create all the regions that we will be using in this mission.
##  Do mission specific placements in this function as well.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateRegions():
	# Starbase 12
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()
	pStarbaseSet = Systems.Starbase12.Starbase12.GetSet()
	# Prendel 3
	import Systems.Prendel.Prendel3
	Systems.Prendel.Prendel3.Initialize()
	pPrendel3Set = Systems.Prendel.Prendel3.GetSet()
	# Prendel 5
	import Systems.Prendel.Prendel5
	Systems.Prendel.Prendel5.Initialize()
	pPrendel5Set = Systems.Prendel.Prendel5.GetSet()
	# Riha
	import Systems.Riha.Riha1
	Systems.Riha.Riha1.Initialize()
	pRiha1Set = Systems.Riha.Riha1.GetSet()
	# Tezle 2
	import Systems.Tezle.Tezle2
	Systems.Tezle.Tezle2.Initialize()
	pTezle2Set = Systems.Tezle.Tezle2.GetSet()
	# Tezle 1
	import Systems.Tezle.Tezle1
	Systems.Tezle.Tezle1.Initialize()
	pTezle1Set = Systems.Tezle.Tezle1.GetSet()
	# Yiles 2
	import Systems.Yiles.Yiles2
	Systems.Yiles.Yiles2.Initialize()
	pYiles2Set = Systems.Yiles.Yiles2.GetSet()
	# Yiles 1
	import Systems.Yiles.Yiles1
	Systems.Yiles.Yiles1.Initialize()
	pYiles1Set = Systems.Yiles.Yiles1.GetSet()
	
	# Get the Bridge for the cutscene
	pBridge = App.g_kSetManager.GetSet("bridge")
	
	
	# Do our mission specific placements
	# Import the files we need
	import E6M4_Riha1_P
	import E6M4_Yiles2_P
	import E6M4_Yiles1_P	
	import E6M4_Tezle1_P
	import E6M4_Tezle2_P
	import E6M4_Prendel3_P
	import E6M4_Prendel5_P
	import E6M4_EBridge_P
	
	# Load the placements
	E6M4_Riha1_P.LoadPlacements(pRiha1Set.GetName())
	E6M4_Yiles2_P.LoadPlacements(pYiles2Set.GetName())
	E6M4_Yiles1_P.LoadPlacements(pYiles1Set.GetName())
	E6M4_Tezle1_P.LoadPlacements(pTezle1Set.GetName())
	E6M4_Tezle2_P.LoadPlacements(pTezle2Set.GetName())
	E6M4_Prendel3_P.LoadPlacements(pPrendel3Set.GetName())
	E6M4_Prendel5_P.LoadPlacements(pPrendel5Set.GetName())
	E6M4_EBridge_P.LoadPlacements(pBridge.GetName())

################################################################################
##	CreateProximityChecks()
##
##	Creates proximity checks around the object given at the radius given.  Does
##	an outer and an inner check.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateProximityChecks():
	# Get the planet and the set
	pSet	= App.g_kSetManager.GetSet("Tezle1")
	pPlanet	= App.Planet_GetObject(pSet, "Tezle 1")
	
	# Get the radius of the planet and add to
	# that for our prox. check
	# For inner prox. check
	fInnerRadius = pPlanet.GetRadius() + 5
	# For outer prox check
	fOuterRadius = pPlanet.GetRadius() + 200
	
	# Create the proximity checks, well add the objects to them
	# when their created.
	global g_pInnerProximityCheck
	global g_pOuterProximityCheck
	
	g_pInnerProximityCheck = MissionLib.ProximityCheck(pPlanet, fInnerRadius, [], __name__+".InnerPlanetProximity")
	g_pOuterProximityCheck = MissionLib.ProximityCheck(pPlanet, fOuterRadius, [], __name__+".OuterPlanetProximity")
	
################################################################################
##	CreateStartingMenus()
##	
##  Creates menu items for Starbase in "Helm" at mission start.
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def CreateStartingMenus():
	import Systems.Starbase12.Starbase
	Systems.Starbase12.Starbase.CreateMenus()
	
	# pull out the systems from E6M3 out so the user doesn't go there.
	pKiskaMenu = g_pKiska.GetMenu()
	pSetCourse = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
		
	pSavoy = pSetCourse.GetSubmenu("Savoy")
	pSetCourse.DeleteChild(pSavoy)
	
################################################################################
##	CreateStartingObjects()
##
##	Create all the objects that exist when the mission starts and their
##	affliations.  Also creates AI target lists for the Cardassian ships.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def CreateStartingObjects(pMission):
	# Get the sets we need
	pStarbaseSet = App.g_kSetManager.GetSet("Starbase12")
	
	# Place the players ship
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pStarbaseSet, "player", "Player Start")
	# Place the Starbase
	pStarbase = loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")

	# Setup object affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Galor 1")
	pEnemies.AddName("Galor 2")
	pEnemies.AddName("Keldon 1")
	pEnemies.AddName("Keldon 2")
	pEnemies.AddName("Kessok")
	pEnemies.AddName("Keldon 3")
	pEnemies.AddName("Keldon 4")
	pEnemies.AddName("Keldon 5")
	pEnemies.AddName("Keldon 6")

	
################################################################################
##	CreateTargetList()
##
##	Create the target lists used with the AIs.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateTargetLists():
	# Get the players name so we can use it in the target lists
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	sPlayerName = pPlayer.GetName()

	# Create our target lists
	global g_pYilesCardTargets
	g_pYilesCardTargets = App.ObjectGroupWithInfo()
	g_pYilesCardTargets[sPlayerName]	= {"Priority" : 0.0}

	global g_pKeldon2Targets
	g_pKeldon2Targets = App.ObjectGroupWithInfo()
	g_pKeldon2Targets[sPlayerName]	= {"Priority" : 0.0}
	
	global g_pGalor2Targets
	g_pGalor2Targets = App.ObjectGroupWithInfo()
	# Add at least 2 probes to the Galors target list
	for iCounter in range(1, 3):
		sProbeName = "Probe " + str(iCounter)
		g_pGalor2Targets[sProbeName]	= {"Priority" : 2.0}
	# Add the player
	g_pGalor2Targets[sPlayerName]	= {"Priority" : 0.0}
	
################################################################################
##	SetupEventHandlers()
##	
##	Sets up the event handlers that we're going to use in this mission
##	
##	Args:	None
##	
##	Return: None
################################################################################
def SetupEventHandlers():
	"Setup any event handlers to listen for broadcast events that we'll need."
	pMission = App.Game_GetCurrentGame().GetCurrentEpisode().GetCurrentMission()

	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ +".EnterSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_WARP, pMission, __name__ +".ExitedWarp")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__+".ObjectDestroyed")
	# Probe launched event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_LAUNCH_PROBE, pMission, __name__+".ProbeLaunched")
		# Weapon fired event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_WEAPON_FIRED, pMission, __name__+".WeaponFired")	
	
	# Instance handler for Miguel's Scan Area button
	pSet	= App.g_kSetManager.GetSet("bridge")
	pSci	= App.CharacterClass_GetObject(pSet, "Science")
	pMenu	= pSci.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")
	
	# Instance handler on players ship for Weapon Fired event, for fire on firendlys
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")
	
#	kDebugObj.Print("Adding Crew Communicate Handlers")
	pBridge = App.g_kSetManager.GetSet("bridge")
	# Communicate with Saffi event
	pSaffi = App.CharacterClass_GetObject(pBridge, "XO")
	pMenu = pSaffi.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET,	__name__ + ".HailStarfleet")
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Felix event
	pFelix = App.CharacterClass_GetObject(pBridge, "Tactical")
	pMenu = pFelix.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Kiska event
	pKiska = App.CharacterClass_GetObject(pBridge, "Helm")
	pMenu = pKiska.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	# Communicate with Miguel event
	pMiguel = App.CharacterClass_GetObject(pBridge, "Science")
	pMenu = pMiguel.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Brex event
	pBrex = App.CharacterClass_GetObject(pBridge, "Engineer")
	pMenu = pBrex.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
################################################################################
##	PlayerWeaponFired()
##
##	Handler called when player fires a weapon.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PlayerWeaponFired(TGObject, pEvent):
	# Get the players target.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	pTarget = pPlayer.GetTarget()
	if(pTarget == None):
		return
		
	sTargetName = pTarget.GetName()
	
	#play felix's line the first time the user fires on the kessok.		
	if (sTargetName == "Kessok") and (g_bKessokCombat2Played == FALSE):
		global g_bKessokCombat2Played
		g_bKessokCombat2Played = TRUE
		# Do little sequence
		pFelixCombat	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate4-1", None, 0, g_pMissionDatabase)
		pFelixCombat.Play()
		
			
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
	
	# See if the Kessok is firing on the player and play a line
	if (sShipName == "Kessok") and (sTargetName == pPlayer.GetName()) and (g_bKessokCombatPlayed == FALSE):
		global g_bKessokCombatPlayed
		g_bKessokCombatPlayed = TRUE
		# Do little sequence
		pSequence = App.TGSequence_Create()
		pFelixCombat	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4EngageKessok4", None, 0, g_pMissionDatabase)		
		
		pSequence.AppendAction(pFelixCombat, 2)
		pSequence.Play()
		
		
	# Nothing else to do.  Let any other events for this event handle it
	TGObject.CallNextHandler(pEvent)

			
################################################################################
##	PlayerFiringOnFriend()
##
##	Called if the player continues to fire on Friends.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PlayerFiringOnFriend(TGObject, pEvent):
	# Get the ship that was hit
	pShip	= App.ShipClass_Cast(pEvent.GetSource())
	if (pShip == None):
		return
	sTargetName = pShip.GetName()
	
	# If we need to, do our special line
	fTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - g_pSaffi.GetLastTalkTime()
	if (fTimeSinceTalk < 10.0):
		# All done, so call our next handler
		TGObject.CallNextHandler(pEvent)
		return
	fKiskaTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - g_pKiska.GetLastTalkTime()
	if (fKiskaTimeSinceTalk < 10.0):
		# All done, so call our next handler
		TGObject.CallNextHandler(pEvent)
		return	
	else:
		# See who is being fired on and do the correct line
		if (sTargetName == "Devore"):
	
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg3", None, 0, g_pGeneralDatabase)
			pDevoreFire			= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6DontShoot2", "Martin")
					
			pSequence.AppendAction(pKiskaIncomming, 2)
			pSequence.AppendAction(pDevoreFire, 2)
			
			pSequence.Play()
			return
			
		elif (sTargetName == "Nightingale"):
	
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg3", None, 0, g_pGeneralDatabase)
			pNightingaleFire	= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6DontShoot6", "Jadeja")
					
			pSequence.AppendAction(pKiskaIncomming, 2)
			pSequence.AppendAction(pNightingaleFire, 2)
			
			pSequence.Play()
			return	
		
		elif (sTargetName == "San Francisco"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg3", None, 0, g_pGeneralDatabase)
			pSanFranciscoFire	= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6DontShoot1", "Zeiss")
					
			pSequence.AppendAction(pKiskaIncomming, 2)
			pSequence.AppendAction(pSanFranciscoFire, 2)
			
			pSequence.Play()
			return
			
		elif (sTargetName == "Venture"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg3", None, 0, g_pGeneralDatabase)
			pVentureFire	= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6DontShoot5", "Dawson")
					
			pSequence.AppendAction(pKiskaIncomming, 2)
			pSequence.AppendAction(pVentureFire, 2)
			
			pSequence.Play()
			return
			
	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)
		
################################################################################
##	PlayerStillFiringOnFriend()
##
##	Called if the player continues to fire on friend after the grace timer
##	has tripped.  Ends the game because the player is being a bastard.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PlayerStillFiringOnFriend(TGObject, pEvent):
	# Do the line from Saffi and end the game
	pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "DontShoot3", "Captain", 1, g_pGeneralDatabase)
	
	# End the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
	pGameOver.Play()

################################################################################
##	ExitedWarp()
##	
##	Event handler called whenever an Player leaves warp.
##	
##	Args: 	TGObject	-
##			pEvent		- Pointer to the event that was sent to the object
##	
##	Return: None
################################################################################
def ExitedWarp(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	# Make sure it's a ship and the player, return if not
	if (MissionLib.GetPlayer() == None):
		return
	if (pShip == None) or (pShip.GetObjID() != MissionLib.GetPlayer().GetObjID()):
		return
			
	pSet		= pShip.GetContainingSet()
	if (pSet == None):
		return
	sSetName 	= pSet.GetName()
	sShipName	= pShip.GetName()
	
#	kDebugObj.Print("Object \"%s\" entered set \"%s\"" % (sShipName, sSetName))
	
	# it's the player, lets see where he is
	TrackPlayer(sSetName)
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	EnterSet()
##	
##	Event handler called whenever an object enters a set.
##	
##	Args: 	TGObject	-
##			pEvent		- Pointer to the event that was sent to the object
##	
##	Return: None
################################################################################
def EnterSet(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	# Make sure it's a ship, return if not
	if (pShip == None):
		return
		
	pSet		= pShip.GetContainingSet()
	sSetName 	= pSet.GetName()
	sShipName	= pShip.GetName()
	
#	kDebugObj.Print("Object \"%s\" entered set \"%s\"" % (sShipName, sSetName))
	
	# If it's the player, lets see where he is
	if (sShipName == "player"):
		if (sSetName == "warp"):
			PlayerEntersWarpSet()
	
	# Get the player's  set
	pPlayerSet = MissionLib.GetPlayerSet()
	if (pPlayerSet == None):
		TGObject.CallNextHandler(pEvent)
		return
	sPlayerSetName	= pSet.GetName()
			
	#if its a Yiles card say incomming, if the player is there
	if (sSetName == "Tezle1") and (sPlayerSetName == "Tezle1"):
		if (sShipName == "Galor 1") or (sShipName == "Keldon 1"):
			if (g_bGalor1Destroyed == TRUE) or (g_bKeldon1Destroyed == TRUE):
				pSequence = App.TGSequence_Create()
				App.TGActionManager_RegisterAction(pSequence, "IncommingCards")
				pFelixLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "Incoming1", "Captain", 1, g_pGeneralDatabase)
				pSequence.AppendAction(pFelixLine, 1)
				pSequence.Play()
			elif (g_bGalor1Destroyed == FALSE) and (g_bKeldon1Destroyed == FALSE):
				# play this line only once.
				if (g_bIncomingCalled == TRUE):
					TGObject.CallNextHandler(pEvent)
					return
				global g_bIncomingCalled
				g_bIncomingCalled = TRUE
				pSequence = App.TGSequence_Create()
				App.TGActionManager_RegisterAction(pSequence, "IncommingCards")
				pFelixLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "Incoming2", "Captain", 1, g_pGeneralDatabase)
				pSequence.AppendAction(pFelixLine, 1)
				pSequence.Play()
			
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ExitSet()
##	
##	Event handler called whenever an object leaves a set.
##	
##	Args: 	TGObject	-
##			pEvent		- Pointer to the event that was sent to the object
##	
##	Return: None
################################################################################
def ExitSet(TGObject, pEvent):
	# See if our mission is terminating
	if (g_bMissionTerminated == TRUE):
		return
		
	pShip		= App.ShipClass_Cast(pEvent.GetDestination())
	sSetName	= pEvent.GetCString()

	# Make sure it's a ship, return if not
	if (pShip == None):
		return 0
	
	sShipName = pShip.GetName()
	
	if (sShipName == "player"):
		global g_iMissionPositionCounter
		g_iMissionPositionCounter = 0
		# Call our function to track the player
		PlayerExitsSet()
	
	# If its a probe remove the it from our list
	if (sShipName[:5] == "Probe") and (g_bProbeReachedPlanet == FALSE) and (sSetName == "Tezle1"):
		global g_lProbeNames
		for sName in g_lProbeNames:
			if (sName == sShipName):
				g_lProbeNames.remove(sShipName)
	
	# We're done. Let any other event handlers for this event handle it
	TGObject.CallNextHandler(pEvent)

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
	# Get Kiska's warp heading and see where were headed
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pString		= pWarpButton.GetDestination()
	
	# See if the player is leaving Tezle 1
	if (pString != "Systems.Tezle.Tezle1") and (g_bPlayerNotInTezle1 == FALSE):
		global g_bPlayerNotInTezle1
		g_bPlayerNotInTezle1 = TRUE
		# Set the probe flag
		global g_bProbeReachedPlanet
		g_bProbeReachedPlanet = FALSE
		
		# Destroy any probe that might exist
		pSet	= App.g_kSetManager.GetSet("Tezle1")
		for sName in g_lProbeNames:
			pProbe = App.ShipClass_GetObject(pSet, sName)
			if (pProbe != None):
				pSet.DeleteObjectFromSet(sName)
				
################################################################################
##	ObjectDestroyed()
##
##	Event handler called when a ship destroyed event is sent.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- Event that was sent to the object.
##
##	Return:	None
################################################################################
def ObjectDestroyed(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	# Check and see if it's a ship, if not return
	if (pShip == None):
		return
	
	sShipName	= pShip.GetName()
	sSetName	= pEvent.GetCString()
	
#	kDebugObj.Print("Object \"%s\" destroyed in set \"%s\"" % (sShipName, sSetName))
	
	# Check and see if it was Galor1 or Keldon1
	global g_bGalor1Destroyed
	global g_bKeldon1Destroyed
	if (sShipName == "Galor 1"):
		g_bGalor1Destroyed = TRUE
	elif (sShipName == "Keldon 1"):
		g_bKeldon1Destroyed = TRUE
	
	# If it was one of the Cards, remove it's name from the list
	for sName in g_lCardNames:
		if (sName == sShipName):
			global g_lCardNames
			g_lCardNames.remove(sName)
			# If the list is empty, all the Cards have
			# been destroyed, so hurry up the timer on
			# our mission win
			if (len(g_lCardNames) == 0) and (g_bProbeReachedPlanet == TRUE):
#				kDebugObj.Print("Setting the time to short time")
				fStartTime = App.g_kUtopiaModule.GetGameTime()
				MissionLib.CreateTimer(ET_PROBE_SHORT_TIMER, __name__+".MissionWin", fStartTime + 8, 0, 0)
				
	# See if it's the probe and if yes call our function.
	if (sShipName[:5] == "Probe") and (sSetName == "Tezle1") and (g_bProbeReachedPlanet == FALSE):
		ProbeDestroyed()
	
	# if it is the hulk, set the flag
	if (sShipName == "Hulk"):
		global g_bHulkDestroyed
		g_bHulkDestroyed	= TRUE
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ScanHandler()
##
##	Called when Miguels Scan Area button is pressed.  Initiates behavior based
##	on what set the player is in.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ScanHandler(TGObject, pEvent):
	
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	# If the players sensors are off, do the default thing and bail
	pSensors = pPlayer.GetSensorSubsystem()
	if (pSensors == None):
		TGObject.CallNextHandler(pEvent)
		return
	if (pSensors.IsOn() == FALSE):
		TGObject.CallNextHandler(pEvent)
		return
		
	# Get the player and the set their in	
	pSet		= pPlayer.GetContainingSet()
	sSetName	= pSet.GetName()
	iType		= pEvent.GetInt()
#	kDebugObj.Print("Scan Handler")	
	
	# Check what set it is and if we haven't scanned it
	# before, call our function, unless it is a scan target on the kessok.
	if (iType == App.CharacterClass.EST_SCAN_OBJECT):
		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
#			kDebugObj.Print("You're scanning the target")
			pTarget = pPlayer.GetTarget()
		if (pTarget): 
			if (pTarget.GetName() == "Kessok") and (g_bKessokScanned == FALSE):
#				kDebugObj.Print("You're scanning the kessok")
				ScanningKessok()
			elif (pTarget.GetName() == "Derelict") and (g_bDerelictScanned == FALSE):
#				kDebugObj.Print("You're scanning the Derelict")
				ScanningDerelict()	
			elif (pTarget.GetName() == "Hulk") and (g_bHulkScaned == FALSE):
#				kDebugObj.Print("You're scanning the hulk")
				ScanningHulk()	
			# if scaning nothing we care about do default
			else:
				TGObject.CallNextHandler(pEvent)
				return	
	# don't call any special scan handlers if the mission has been won		
	elif (g_bMissionWinCalled == TRUE):
		TGObject.CallNextHandler(pEvent)
		return
	
	elif (iType == App.CharacterClass.EST_SCAN_AREA) and (g_bMissionWinCalled == FALSE):
		# check and see if we are in a mission specific system
		if (sSetName == "Prendel5") and (g_bPrendelScanned == FALSE):
			global g_bPrendelScanned
			g_bPrendelScanned = TRUE
			ScanningPrendel()
		elif (sSetName == "Riha1") and (g_bRihaScanned == FALSE):
			ScanningRiha()
		elif (sSetName == "Tezle2") and (g_bTezle2Scanned == FALSE):
			global g_bTezle2Scanned
			g_bTezle2Scanned = TRUE
			ScanningTezle2()
		elif (sSetName == "Yiles4") and (g_bYiles4Scanned == FALSE):
			global g_bYiles4Scanned
			g_bYiles4Scanned = TRUE
			ScanningYiles4()
		elif (sSetName == "Yiles3") and (g_bYiles3Scanned == FALSE):
			global g_bYiles3Scanned
			g_bYiles3Scanned = TRUE
			ScanningYiles4()
		elif (sSetName == "Yiles2") and (g_bYiles2Scanned == FALSE):
			global g_bYiles2Scanned
			g_bYiles2Scanned = TRUE
			ScanningYiles2()
		elif (sSetName == "Yiles1") and (g_bYiles1Scanned == FALSE):
			global g_bYiles1Scanned
			g_bYiles1Scanned = TRUE
			ScanningYiles4()
		else:
			# Not in a set we need to worry about, so call the next standard line
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L004", None, 0, g_pMissionDatabase)
			pAction.Play()
	# if scaning nothing we care about do default
	else:
		TGObject.CallNextHandler(pEvent)


##################################################		
##
## WarpHandler()
##
## This funtion will handle the use of the warp button
##
##	Args:	None
##
##	Return: None
##
###################################################
def WarpHandler(pObject, pEvent):
#	kDebugObj.Print("Handling Warp")

	if (g_bPlayerStuckInTezle2 == TRUE):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "WarpStop2", None, 0, g_pGeneralDatabase)
		pAction.Play()
	
		return

	pObject.CallNextHandler(pEvent)
		
##################################################		
##
## CommunicateHandler()
##
## This funtion will handle the use of the communicate button 
##
##	Args:	None
##
##	Return: None
##
###################################################

def CommunicateHandler(pObject, pEvent):
#	kDebugObj.Print("Communicating with crew")

	# check whose menu was clicked.
	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())

	# Do a quick error check
	pPlayer 	= MissionLib.GetPlayer()
	if pPlayer == None:
		return

	# pick a communicate dialogue, or behave normally 
	if pMenu and (g_iMissionPositionCounter == 2):
		Yiles4Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Yiles4Communicate

	elif pMenu and (g_iMissionPositionCounter == 3):
		Yiles2Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Yiles2Communicate
		
	elif pMenu and (g_iMissionPositionCounter == 4):
		RihaCommunicate(pMenu.GetObjID()) #pass on whose menu was clicked to RihaCommunicate
	
	elif pMenu and (g_iMissionPositionCounter == 5):
		Tezle2Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Tezle2Communicate		
	
	elif pMenu and (g_iMissionPositionCounter == 6):
		Tezle1Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Tezle1Communicate
				
	else:
#		kDebugObj.Print("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)

	
#####################################################################
##
## Yiles4Communicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def Yiles4Communicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate3-3", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate3-1", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6ScanYiles2GoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate2-1", "Captain", 1, g_pMissionDatabase)
		
	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate2-2", None, 0, g_pMissionDatabase)
	
	pAction.Play()
	
#####################################################################
##
## Yiles2Communicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def Yiles2Communicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate3-3", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate3-1", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6FindCardBaseGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L010", "Captain", 1, g_pMissionDatabase)
		
	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate3-2", None, 0, g_pMissionDatabase)
	
	pAction.Play()
	
#####################################################################
##
## RihaCommunicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##	Return: None
##
####################################################################		
def RihaCommunicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate4-3", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate4-1", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6FindCardBaseGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L004", None, 0, g_pMissionDatabase)
	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate4-2", None, 0, g_pMissionDatabase)

	pAction.Play()
	
#####################################################################
##
## Tezle2Communicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def Tezle2Communicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate5-1", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate6-1", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate5-5", None, 0, g_pMissionDatabase)

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate5-2", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate5-3", None, 0, g_pMissionDatabase)

	pAction.Play()
		
#####################################################################
##
## Tezle1Communicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def Tezle1Communicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate6-2", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate6-1", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6FindCardBaseGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate6-3", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4Communicate6-4", None, 0, g_pMissionDatabase)

	pAction.Play()

	
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
	if (g_bMissionWinCalled == TRUE) and (g_bLiuHailed == FALSE):
		global g_bLiuHailed
		g_bLiuHailed = TRUE
		
		# Get the character we need
		pStarbase	= App.g_kSetManager.GetSet("StarbaseSet")
		pLiu		= App.CharacterClass_GetObject(pStarbase, "Liu")
		
		#add the 6.5 database
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 6/E6M5.tgl")
		
		pSequence = App.TGSequence_Create()
	
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
		pSaffiHail1		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet1", "Captain", 1, g_pGeneralDatabase)
		pSaffiActive	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
		pSaffiHail2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet7", None, 0, g_pGeneralDatabase)
		pViewscreenOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
		pHailLiu1		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "gl007", None, 0, g_pGeneralDatabase)
		pHailLiu2		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M5Liu2", None, 0, pDatabase)
		pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pCallWaiting)
		pSequence.AppendAction(pSaffiActive)
		pSequence.AppendAction(pSaffiHail1)
		pSequence.AppendAction(pSaffiHail2, 3)
		pSequence.AppendAction(pViewscreenOn)
		pSequence.AppendAction(pHailLiu1)
		pSequence.AppendAction(pHailLiu2)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pEndCallWaiting)
	
		MissionLib.QueueActionToPlay(pSequence)
		
		if(pDatabase):
			App.g_kLocalizationManager.Unload(pDatabase)
		
	else:
		TGObject.CallNextHandler(pEvent)
		
		

################################################################################
##	OuterPlanetProximity()
##
##	Called when object gets close to planet.  Plays a line from Miguel.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def OuterPlanetProximity(TGObject, pEvent):
#	kDebugObj.Print("Triggered outer planet proximity check...")
	
	pObject = App.ShipClass_Cast(pEvent.GetDestination())
	if (pObject != None):
		return

	# Remove the probe from the proximity check list
	g_pOuterProximityCheck.RemoveObjectFromCheckList(pObject)

	# Make sure the probe isn't dead
	if (not pObject.IsDead()):
#		kDebugObj.Print("Probe is at outer proximity, playing miguel's line")
		# It's a probe, play our line
		pMiguelLine028 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L028", None, 0, g_pMissionDatabase)
		pMiguelLine028.Play()
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	InnerPlanetProximity()
##
##	Called when an object gets to planet.  Calls ProbeReachedPlanet() if
##	object was a probe.
##
##	Args:	TGObject	- TGObject object
##			pEvent		- Pointer to event object	
##
##	Return:	None
################################################################################
def InnerPlanetProximity(TGObject, pEvent):
#	kDebugObj.Print("Triggered planet proximity check.  (probe)")
	
	pObject = App.ShipClass_Cast(pEvent.GetDestination())
	
	if (pObject == None):
		return

	# Remove it from the proximity check and bail
	# if the probe is dead at this point
	g_pInnerProximityCheck.RemoveObjectFromCheckList(pObject)
	if (pObject.IsDead()):
		return
		
	# It's a probe.  Call our function
	ProbeReachesPlanet(pObject)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ProbeLaunched()
##
##	Handles ET_PROBE_LAUNCHED event.  Does special mission stuff if the probe
##	was launched in Tezle1.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ProbeLaunched(TGObject, pEvent):

	# Get the player
	pShip = MissionLib.GetPlayer()
	if (pShip == None):
		TGObject.CallNextHandler(pEvent)
		return
	pSensors = pShip.GetSensorSubsystem()
	if (not pShip) or (not pSensors):
		TGObject.CallNextHandler(pEvent)
		return
	# Check the number of probes remaining.
	if pSensors.GetNumProbes() <= 0:
		# No probes remaining.
		TGObject.CallNextHandler(pEvent)
		return
		
	# Disable the probe button while the probe exists	
	DisableProbeButton()

	# Call the next handler first so the probe is actually created.
	TGObject.CallNextHandler(pEvent)

	# Make sure it's a probe and see if we're in the Tezle1 set
	pProbe = App.ShipClass_Cast(pEvent.GetSource())
	if (pProbe == None):
		return
		
	# Get the set the probe is in
	pSet = pProbe.GetContainingSet()
	# Check and see what set the probe is in and don't do it if we've already
	# been successful.
	if (pSet.GetName() == "Tezle1") and (g_bProbeReachedPlanet == FALSE):
		# Set our flag
		global g_bProbeExists
		g_bProbeExists = TRUE
		
		# Probe is in Tezle1, so add it to the two proximity checks lists...
		g_pInnerProximityCheck.AddObjectToCheckList(pProbe, App.ProximityCheck.TT_INSIDE)
		g_pOuterProximityCheck.AddObjectToCheckList(pProbe, App.ProximityCheck.TT_INSIDE)

		# Give the probe an AI
		import E6M4_AI_Probe
		pProbe.SetAI(E6M4_AI_Probe.CreateAI(pProbe))
	
#		kDebugObj.Print("Probe's impluse engines are Invincible")
		pImpulse = pProbe.GetImpulseEngineSubsystem()
		pImpulse.SetInvincible(1)
		
		# Add the name of the probe to our list
		global g_lProbeNames
		g_lProbeNames.append(pProbe.GetName())
	
	if (pSet.GetName() != "Tezle1") or (g_bProbeReachedPlanet == TRUE):
		# we're not in Tezle 1 or the mission is won, so let the user go nuts on the probe button.
		EnableProbeButton(None)
		
		
################################################################################
##	TrackPlayer()
##
##	See what set the player has just entered into and call functions based on
##	that.
##
##	Args:	sSetName	- The name of the set the player has entered.
##
##	Return:	None
################################################################################
def TrackPlayer(sSetName):
	global g_bPlayerArrivePrendel
	global g_bPlayerArriveRiha
	global g_bPlayerArriveTezle2
	global g_bPlayerArriveTezle1
	global g_bPlayerArriveYiles4
	global g_bPlayerArriveYiles2

	# Player arrives in Prendel for first time
	if (sSetName  == "Prendel5") and (g_bPlayerArrivePrendel == FALSE):
		g_bPlayerArrivePrendel = TRUE
		PlayerArrivedPrendel()

	# Player arrives Riha for first time
	elif (sSetName == "Riha1") and (g_bPlayerArriveRiha == FALSE):
		g_bPlayerArriveRiha = TRUE
		PlayerArrivedRiha()

	# Player arrives in Yiles4 for first time
	elif (sSetName == "Yiles4") and (g_bPlayerArriveYiles4 == FALSE):
		g_bPlayerArriveYiles4 = TRUE
		PlayerArrivedYiles()

	# Player arrives in Yiles2 for first time
	elif (sSetName == "Yiles2") and (g_bPlayerArriveYiles2 == FALSE):
		g_bPlayerArriveYiles2 = TRUE
		PlayerArrivedYiles2()

	# Player srrives in Tezle2 for first time
	elif (sSetName == "Tezle2") and (g_bPlayerArriveTezle2 == FALSE):
		g_bPlayerArriveTezle2 = TRUE
		PlayerArrivedTezle2()

	# Player srrives in Tezle1 for first time
	elif (sSetName == "Tezle1") and (g_bPlayerArriveTezle1 == FALSE):
		g_bPlayerArriveTezle1 = TRUE
		PlayerArrivedTezle1()
		global g_bPlayerNotInTezle1
		g_bPlayerNotInTezle1 = FALSE
	
	# If the player is returning to Tezle 1 and a probe has been launched,
	# destroy it and make them launch another
	elif (sSetName == "Tezle1") and (g_bPlayerArriveTezle1 == TRUE) and (g_bPlayerNotInTezle1 == TRUE):
		global g_bPlayerNotInTezle1
		g_bPlayerNotInTezle1 = FALSE
		if (g_bProbeExists == TRUE) and (g_bMissionWinCalled == FALSE):
			ProbeDestroyed()
			
################################################################################
##	PlayerEntersWarpSet()
##
##	Called if player enters warp set.  Keeps track of the player and were he's
##	going for proding needs and creating ships while were in warp.
##
##	Args:	None
##
##	Return: None	
################################################################################
def PlayerEntersWarpSet():
	# Get Kiska's warp heading and see where were headed
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pString 	= pWarpButton.GetDestination()
	
	# If player is arriving in Yiles4 for first time
	if (pString == "Systems.Yiles.Yiles4") and (g_bPlayerArriveYiles4 == FALSE):
		StopProdTimer()
		# Create the ships we'll need in that system
		CreateYilesShips()
	
	# If player is arriving in Tezle2 for first time
	elif (pString == "Systems.Tezle.Tezle2") and (g_bPlayerArriveTezle2 == FALSE):
		StopProdTimer()
		# Create the ship we'll need in that system
		CreateTezleShips()
	
	# If the player is heading to Riha for the first time
	elif (pString == "Systems.Riha.Riha1") and (g_bPlayerArriveRiha == FALSE):
		StopProdTimer()
		# Create the ships in that system
		CreateRihaShips()
		
	# If the player is heading to Prendel for the first time
	elif (pString == "Systems.Prendel.Prendel5") and (g_bPlayerArrivePrendel == FALSE):
		StopProdTimer()
		# Create the ships in that system
		CreatePrendelShips()
		
################################################################################
##	LiuBriefing()
##
##	Play's Liu's breifing and starts prompting timer.  Registers all our
##	starting goals.
##
##	Args:	None
##
##	Return:	None
################################################################################
def LiuBriefing(pTGAction):
	# check if the player is done warping in, if not call this function again in 2 seconds
	if MissionLib.IsPlayerWarping():
		# Delay sequence 2 seconds.
		pSequence = App.TGSequence_Create()
		pRePlayBriefing	= App.TGScriptAction_Create(__name__, "LiuBriefing")
		pSequence.AppendAction(pRePlayBriefing, 2)
		pSequence.Play()

		return 0

	pStarbase	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu		= App.CharacterClass_GetObject(pStarbase, "Liu")

	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pIncoming		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "gt029", "Captain", 1, g_pGeneralDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLine001		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M4L001", None, 0, g_pMissionDatabase)
	pLiuLine002		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M4L002", None, 0, g_pMissionDatabase)
	pLiuLine003		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M4L003", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSaffiLine004	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4Briefing4", "Captain", 1, g_pMissionDatabase)
	pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)	# 30 sec prod timer
	pAddSystems		= App.TGScriptAction_Create(__name__, "AddSystems")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pIncoming, 4)
	pSequence.AddAction(pStarbaseViewOn, pIncoming)
	pSequence.AddAction(pLiuLine001, pStarbaseViewOn)
	pSequence.AddAction(pLiuLine002, pLiuLine001)
	pSequence.AddAction(pLiuLine003, pLiuLine002)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pSaffiLine004)
	pSequence.AppendAction(pStartProdTimer)
	pSequence.AppendAction(pAddSystems)
	
	pSequence.Play()

	# Register our goals for scanning all the systems
	MissionLib.AddGoal("E6FindCardBaseGoal")
	MissionLib.AddGoal("E6ScanPrendelGoal")
	MissionLib.AddGoal("E6ScanTezleGoal")
	MissionLib.AddGoal("E6ScanRihaGoal")
	MissionLib.AddGoal("E6ScanYilesGoal")
	
	return 0
	
###############################################################################
##
## AddSystems()
##
## adds the systems to the helm menu
##
##	Args:	None
##
##	Return:	0
################################################################################
def AddSystems(pAction):

	import Systems.Prendel.Prendel
	import Systems.Riha.Riha
	import Systems.Tezle.Tezle
	import Systems.Yiles.Yiles
	
	Systems.Prendel.Prendel.CreateMenus()
	Systems.Riha.Riha.CreateMenus()
	Systems.Tezle.Tezle.CreateMenus()
	Systems.Yiles.Yiles.CreateMenus()

	# Link the Tezle1 menu item to a different placement.
	MissionLib.LinkMenuToPlacement("Tezle", "Tezle 1", "PlayerEnterTezle1")
			
	return 0
################################################################################
##	CreatePrendelShips()
##
##	Creates the transport that will be present in the Prendel system.  
##  Called when the player first heads to the Prendel system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreatePrendelShips():
	# Get the set and create the ships
	pSet	= App.g_kSetManager.GetSet("Prendel5")
	pTransport	= loadspacehelper.CreateShip("Transport", pSet, "Hulk", "HulkStart")
	
	pTransport.SetHailable(0)
		
	# Add the damage to the Hulk 
	import DamagedTransport
	DamagedTransport.AddDamage(pTransport)
			
	# Turn off the ship's repair
	pRepair = pTransport.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)

	# Damage the Hulk...
	# Turn off the shields
	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(pTransport)
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(pTransport.GREEN_ALERT)

	App.g_kEventManager.AddEvent(pAlertEvent)

	# Damage the hull - 500 pts left
	pTransport.DamageSystem(pTransport.GetHull(), 3000)
	
	# Dont allow the user to see the sub-systems
	MissionLib.HideSubsystems(pTransport)
	
	# Have the Keldon rotate
	MissionLib.SetRandomRotation(pTransport, 0.5)
		
################################################################################
##	PlayerArrivedPrendel()
##
##	Sequnece that plays when the player arrives in Prendel
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivedPrendel():
	# don't play if the mission has been won		
	if (g_bMissionWinCalled == TRUE):
		return
	#see if we've been promted twice
	if (g_iScanPromptCounter <= 1):
		
		global g_iScanPromptCounter
		g_iScanPromptCounter = g_iScanPromptCounter + 1
		
		pSequence = App.TGSequence_Create()
		
		pMiguelScanPrompt	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrompt1", "Captain", 1, g_pMissionDatabase)
		
		pSequence.AppendAction(pMiguelScanPrompt, 2)	# 5 sec delay before Miguel's line
		
		pSequence.Play()
	
################################################################################
##	ScanningPrendel()
##
##	Called from ScanHandler if player scans the Prendel4 region.  Does sequence
##	and removes goal.
##	
##
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningPrendel():
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
	pMiguelLine01	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrendel1", "Captain", 0, g_pMissionDatabase)
	if (g_bHulkScaned == FALSE) and (g_bHulkDestroyed == FALSE):
		pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrendel2", "Captain", 0, g_pMissionDatabase)
	pMiguelLine03	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrendel3", "Captain", 1, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pScanSequence)	
	pSequence.AppendAction(pMiguelLine01)
	if (g_bHulkScaned == FALSE) and (g_bHulkDestroyed == FALSE):
		pSequence.AppendAction(pMiguelLine02)
	pSequence.AppendAction(pMiguelLine03)
	pSequence.AppendAction(pEnableScanMenu)
		
	pSequence.Play()

	# We've scanned, so remove the goal
	MissionLib.RemoveGoal("E6ScanPrendelGoal")
	
################################################################################
##	ScanningHulk()
##
##	Called from ScanHandler if player scans the Prendel Hulk.  
##	
##
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningHulk():
#	kDebugObj.Print("Scanning the hulk, finding torps")
	
	#first, find out if the user has 60 quantums already.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	global g_bHulkScaned
	g_bHulkScaned = TRUE
	pTorpSys = pPlayer.GetTorpedoSystem()
	iNumQuantumsLeft = 0
	if (pTorpSys):
		# Find proper torps..
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			pTorpType = pTorpSys.GetAmmoType(iType)
			# set iNumQuantumsLeft to equal the number of quantums the user has.
			if (pTorpType.GetAmmoName() == "Quantum"):
				iNumQuantumsLeft = pTorpSys.GetNumAvailableTorpsToType(iType)

	if (iNumQuantumsLeft != 60):
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "E6M4ScanTransport1", MissionLib.GetEpisode().GetDatabase())
		pMiguelLine01	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport3", None, 1, MissionLib.GetEpisode().GetDatabase())
		pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport4", None, 1, MissionLib.GetEpisode().GetDatabase())
		pBrexLine03		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport5a", None, 1, MissionLib.GetEpisode().GetDatabase())
		pFlickerShields	= App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields")
		pBrexLine04		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport6", None, 1, MissionLib.GetEpisode().GetDatabase())
		pTransTorps		= App.TGScriptAction_Create("MissionLib", "LoadTorpedoes", "Quantum", 15)
		pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
			
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pScanSequence)
		pSequence.AppendAction(pMiguelLine01)
		pSequence.AppendAction(pMiguelLine02)
		pSequence.AppendAction(pBrexLine03)
		pSequence.AddAction(pBrexLine04, pBrexLine03)
		pSequence.AddAction(pFlickerShields, pBrexLine03, 1.5)
		pSequence.AppendAction(pTransTorps, 0.5)
		pSequence.AppendAction(pEnableScanMenu)
		
		pSequence.Play()

	elif (iNumQuantumsLeft == 60):
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "E6M4ScanTransport1", MissionLib.GetEpisode().GetDatabase())
		pMiguelLine01	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport2", None, 1, MissionLib.GetEpisode().GetDatabase())
		pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport3", None, 1, MissionLib.GetEpisode().GetDatabase())
		pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pScanSequence)			
		pSequence.AppendAction(pMiguelLine01)
		pSequence.AppendAction(pMiguelLine02)
		pSequence.AppendAction(pEnableScanMenu)
				
		pSequence.Play()

################################################################################
##	CreateRihaShips()
##
##	Creates the Kessok that will be present in the Riha system and the derelict
##	Galor.  Called when the player first heads to the Riha system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateRihaShips():
	#check that this was only called once.
	if (g_bRihaShipsCreated == FALSE):
		global g_bRihaShipsCreated
		g_bRihaShipsCreated = TRUE
	else:
		return
	
	# Get the set and create the ships
	pSet	= App.g_kSetManager.GetSet("Riha1")
	pKessok	= loadspacehelper.CreateShip("KessokLight", pSet, "Kessok", "KessokStart")
	pKeldon	= loadspacehelper.CreateShip("Keldon", pSet, "Derelict", "DerelictStart")
	
	# set these ship to not appear on the target list, we'll make them visable later
	pKessok.SetTargetable(0)
	pKeldon.SetTargetable(0)
	pKessok.SetScannable(0)
	pKeldon.SetScannable(0)
	pKessok.SetHailable(0)
	pKeldon.SetHailable(0)

	# Give the Kessok it's AI
	import E6M4_AI_Kessok
	pKessok.SetAI(E6M4_AI_Kessok.CreateAI(pKessok))
	
	# Add the damage to the Keldon
	import DamagedKeldon
	DamagedKeldon.AddDamage(pKeldon)
	
	# Turn off the Keldon's repair
	pRepair = pKeldon.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)
	
	# Damage the power Plant - 1287 pts of damage
	pKeldon.DamageSystem(pKeldon.GetPowerSubsystem(), 1287)
	# Damage the  hull - 2000 pts of damage
	pKeldon.DamageSystem(pKeldon.GetHull(), 4000)
	
	# Dont allow the user to see the sub-systems
	MissionLib.HideSubsystems(pKeldon)
	
	# Have the Keldon rotate
	MissionLib.SetRandomRotation(pKeldon, 0.8)
	
	# destroy the shields
	pShields = pKeldon.GetShields()
	pKeldon.DestroySystem(pShields)
	
################################################################################
##	PlayerArrivedRiha()
##
##	Sequence that plays when player first arrives in Riha system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivedRiha():
	# don't play if the mission has been won		
	if (g_bMissionWinCalled == TRUE):
		return
	
	pSequence = App.TGSequence_Create()
	
	pKiskaLine01		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveRiha1", "None", 0, g_pMissionDatabase)
	pSequence.AppendAction(pKiskaLine01, 1)	# 1 sec delay before Kiska's line
	#see if we've been promted twice
	if (g_iScanPromptCounter <= 1):
		global g_iScanPromptCounter
		g_iScanPromptCounter = g_iScanPromptCounter + 1
		pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrompt2", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction(pMiguelLine02)
	
	pSequence.Play()
	
################################################################################
##	ScanningRiha()
##
##	Called from ScanHandler() if player scans in the Riha1 system. Also called from Kessok_AI.py
##	when player moves within range . Plays sequence and removes goal.
##	
##
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningRiha():
	# check if the player is warping, if so stop this function
	if MissionLib.IsPlayerWarping():
		return

	#Check and set the scan flag.
	if (g_bRihaScanned == TRUE):
		return
	global g_bRihaScanned
	g_bRihaScanned = TRUE
	
	# check if kessok has been scaned, if not play this
	if (g_bKessokScanned == FALSE):
	
#		kDebugObj.Print("Playing scan riha dialogue")
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "E6M4RihaScanned2", g_pMissionDatabase)
		pSaffiLine01	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4RihaScanned1", "None", 0, g_pMissionDatabase)
		pMiguelLine03	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4RihaScanned3", "None", 0, g_pMissionDatabase)
		pMiguelLine04	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4RihaScanned4", "None", 0, g_pMissionDatabase)
		pKiskaOnScreen	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", "None", 0, g_pGeneralDatabase)
		pKessokOnScreen	= App.TGScriptAction_Create(__name__, "KessokOnScreen")
		pFelixLine05	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4RihaScanned5", "None", 0, g_pMissionDatabase)
		pBrexLine06		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4RihaScanned6", "None", 0, g_pMissionDatabase)
		pFelixLine07	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4EngageKessok1", "None", 0, g_pMissionDatabase)
		pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pScanSequence)
		pSequence.AppendAction(pSaffiLine01)	
		pSequence.AppendAction(pMiguelLine03)
		pSequence.AppendAction(pMiguelLine04)
		pSequence.AppendAction(pKiskaOnScreen)
		pSequence.AppendAction(pKessokOnScreen)
		pSequence.AppendAction(pFelixLine05)
		pSequence.AppendAction(pBrexLine06)
		pSequence.AppendAction(pFelixLine07)
		pSequence.AppendAction(pEnableScanMenu)
		
		MissionLib.QueueActionToPlay(pSequence)
		
	# check if kessok has been scaned; if so play this
	elif (g_bKessokScanned == TRUE):
#		kDebugObj.Print("Playing scan riha dialogue with out kessok")
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "E6M4RihaScanned2", g_pMissionDatabase)
		pSaffiLine01	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4RihaScanned1", "None", 0, g_pMissionDatabase)
		pFelixLine05	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4RihaScanned5", "None", 0, g_pMissionDatabase)
		pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pScanSequence)	
		pSequence.AppendAction(pSaffiLine01)
		pSequence.AppendAction(pFelixLine05)
		pSequence.AppendAction(pEnableScanMenu)
			
		MissionLib.QueueActionToPlay(pSequence)
	
	# We've scanned, so remove the goal
	MissionLib.RemoveGoal("E6ScanRihaGoal")
	
	# Set g_iMissionPositionCounter so the right communicate dialogue is played
	global g_iMissionPositionCounter
	g_iMissionPositionCounter	= 4

###############################################################################
##
## KessokOnScreen()
##
## Puts the Kessok ship on the Viewscreen
##
##	Args:	None
##
##	Return:	None
################################################################################
def KessokOnScreen(pAction):
	pSet = App.g_kSetManager.GetSet("Riha1")
	pKessok 	= App.ShipClass_GetObject(pSet, "Kessok")
	pDerelict	= App.ShipClass_GetObject(pSet, "Derelict")
		
	# set the probe to appear on the target list
	pDerelict.SetTargetable(1)
	pKessok.SetTargetable(1)
	pKessok.SetScannable(1)
	pDerelict.SetScannable(1)
	pKessok.SetHailable(1)
	
	MissionLib.ViewscreenWatchObject(pKessok)
		
	return 0

################################################################################
##	ScanningKessok()
##
##	Sequence that plays when The Kessok is scanned in Riha.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningKessok():
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pScanSequence		= Bridge.ScienceCharacterHandlers.GetScanSequence()
	pMiguelLine01		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4KessokScanned1", "Captain", 0, g_pMissionDatabase)
	pSaffiLine02		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4KessokScanned2", None, 0, g_pMissionDatabase)
	pMiguelLine03		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4KessokScanned3", "None", 1, g_pMissionDatabase)
	pEnableScanMenu		= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pScanSequence)
	pSequence.AppendAction(pMiguelLine01)
	pSequence.AppendAction(pSaffiLine02)
	pSequence.AppendAction(pMiguelLine03)
	pSequence.AppendAction(pEnableScanMenu)	

	MissionLib.QueueActionToPlay(pSequence)
	
	global g_bKessokScanned
	g_bKessokScanned	= TRUE

################################################################################
##	ScanningDerelict()
##
##	Sequence that plays when The Derelict is scanned in Riha. 
##
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningDerelict():
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pScanSequence		= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "E6M4DerelictScanned1", g_pMissionDatabase)
	pMiguelLine03		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4DerelictScanned2", "None", 1, g_pMissionDatabase)
	pEnableScanMenu		= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pScanSequence)
	pSequence.AppendAction(pMiguelLine03)
	pSequence.AppendAction(pEnableScanMenu)	

	MissionLib.QueueActionToPlay(pSequence)
	
	global g_bDerelictScanned
	g_bDerelictScanned	= TRUE

################################################################################
##	RihaKessokRetreats()
##
##	Sequence that plays when The Kessok retreats from Riha, called from E6M4_AI_Kessok.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RihaKessokRetreats():
#	kDebugObj.Print("Playing RihaKessokRetreats dialogue")
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaLine00		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4EngageKessok7", None, 0, g_pMissionDatabase)
	pFelixLine01		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4KessokFlees1", None, 0, g_pMissionDatabase)
	pSaffiLine02		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4KessokFlees2", None, 0, g_pMissionDatabase)
	pMiguelLine02		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4KessokFlees3", "Captain", 1, g_pMissionDatabase)

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaLine00, 1)
	pSequence.AppendAction(pFelixLine01, 3) # 3 sec delay on Felix's line
	pSequence.AppendAction(pSaffiLine02)
	pSequence.AppendAction(pMiguelLine02)
	
	MissionLib.QueueActionToPlay(pSequence)
	
	# Set g_iMissionPositionCounter so the right communicate dialogue is played
	global g_iMissionPositionCounter
	g_iMissionPositionCounter	= 0
	
	# set the g_bKessokRetreats to true so we know it is in tezle
	global g_bKessokRetreats
	g_bKessokRetreats = TRUE
	
################################################################################
##	CreateYilesShips()
##
##	Creates the ships for the Yiles2 set. Called  while player is in warp.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateYilesShips():
	pSet = App.g_kSetManager.GetSet("Yiles2")
	
	# Create the ships.
	pGalor1		= loadspacehelper.CreateShip("Galor", pSet, "Galor 1", "Galor1Start")
	pKeldon1	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 1", "Keldon1Start")
	
	# Now give them an AI
	import E6M4_AI_Yiles
	
	pGalor1.SetAI(E6M4_AI_Yiles.CreateAI(pGalor1, g_pYilesCardTargets))
	pKeldon1.SetAI(E6M4_AI_Yiles.CreateAI(pKeldon1, g_pYilesCardTargets))
	
################################################################################
##	PlayerArrivedYiles()
##
##	Sequence that plays when player first arrives in Yiles system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivedYiles():
	# don't play if the mission has been won		
	if (g_bMissionWinCalled == TRUE):
		return
		#see if we've been promted twice
	if (g_iScanPromptCounter <= 1):
		global g_iScanPromptCounter
		g_iScanPromptCounter = g_iScanPromptCounter + 1
		pSequence = App.TGSequence_Create()
	
		pMiguelScanPrompt	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrompt2", "Captain", 1, g_pMissionDatabase)
	
		pSequence.AppendAction(pMiguelScanPrompt, 2)	# 5 sec delay before Miguel's line
	
		pSequence.Play()

################################################################################
##	ScanningYiles4()
##
##	Called from ScanHandler() when player scans in Yiles4 region.  Plays
##	sequence and removes goal.
##	
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningYiles4():
	if (g_bYilesScanned == FALSE):
		global g_bYilesScanned
		g_bYilesScanned = TRUE
		# Do our sequence
		pSequence = App.TGSequence_Create()
	
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
		pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveYiles4-2", "None", 0, g_pMissionDatabase)
		pSaffiLine03	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveYiles4-3", "Captain", 0, g_pMissionDatabase)
		pFelixLine04	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveYiles4-5", "None", 0, g_pMissionDatabase)
		pSaffiLine05	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveYiles4-6", "Captain", 1, g_pMissionDatabase)
		pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 45) # 45 sec prod timer
		pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pScanSequence)
		pSequence.AppendAction(pMiguelLine02)
		pSequence.AppendAction(pSaffiLine03)
		pSequence.AppendAction(pFelixLine04)
		pSequence.AppendAction(pSaffiLine05)
		pSequence.AppendAction(pStartProdTimer)
		pSequence.AppendAction(pEnableScanMenu)
			
		pSequence.Play()
		
		global g_iMissionPositionCounter
		g_iMissionPositionCounter	= 2
		
	elif (g_bYilesScanned == TRUE):
		# Do our sequence
		pSequence = App.TGSequence_Create()
	
		pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
		pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveYiles4-2", "None", 0, g_pMissionDatabase)
		pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 45) # 45 sec prod timer
		pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
		pSequence.AppendAction(pScanSequence)
		pSequence.AppendAction(pMiguelLine02)
		pSequence.AppendAction(pStartProdTimer)
		pSequence.AppendAction(pEnableScanMenu)
			
		pSequence.Play()
		
		global g_iMissionPositionCounter
		g_iMissionPositionCounter	= 2

	# We've scanned, so remove our goal and
	# add the Scan Yiles 2 goal
	MissionLib.RemoveGoal("E6ScanYilesGoal")
	MissionLib.AddGoal("E6ScanYiles2Goal")
	
################################################################################
##	PlayerArrivedYiles2()
##
##	Sequence that plays when player enters Yiles2 set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivedYiles2():
	
	# don't play if the mission has been won		
	if (g_bMissionWinCalled == TRUE):
		return
		
	pSequence = App.TGSequence_Create()
	
	pFelixLine008		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4L008", "Captain", 1, g_pMissionDatabase)
	pFelixLine009		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4L009", None, 0, g_pMissionDatabase)

	pSequence.AppendAction(pFelixLine008, 1) # 1 sec delay on Felix's line
	pSequence.AppendAction(pFelixLine009)
	
	pSequence.Play()
	
	global g_iMissionPositionCounter
	g_iMissionPositionCounter	= 3

################################################################################
##	ScanningYiles2()
##
##	Called from ScanHandler() when player scans the Yiles2 region.  Plays
##	sequence and removes goal.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningYiles2():
	
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
	pMiguelLine010	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L010", "Captain", 1, g_pMissionDatabase)
	pSaffiMoveOn	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4MoveOn1", "Captain", 1, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pScanSequence)
	pSequence.AppendAction(pMiguelLine010)
	pSequence.AppendAction(pSaffiMoveOn)
	pSequence.AppendAction(pEnableScanMenu)
	
	pSequence.Play()
	
	# We've scanned, so remove our goal.  Make sure that all the
	# Scan Yiles goals have been removed in case player didn't
	# scan in Yiles4
	MissionLib.RemoveGoal("E6ScanYiles2Goal")
	MissionLib.RemoveGoal("E6ScanYilesGoal")
	
	# check if the user scaned yiles 4, if not, make it so yailes 4 scan won't happen
	if (g_bYiles4Scanned == FALSE):
		global g_bYiles4Scanned
		g_bYiles4Scanned = TRUE
	
	return 0
	
################################################################################
##	SurvivingCardRetreats()
##
##	Called if one of the Cards in Yiles is destroyed and the other warps to
##	Yiles1.  Called by E6M4_AI_Yiles
##
##	Args:	None
##
##	Return:	None
################################################################################
def SurvivingCardRetreats():
#	kDebugObj.Print("Doing SurvivingCardRetreats")
	# check if the user has scanned yet, and play approriate dialogue
	if (g_bYiles2Scanned == TRUE):
	
		pSequence = App.TGSequence_Create()
	
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pFelixLine011	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4L011", None, 0, g_pMissionDatabase)
		pMiguelLine04	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L005", "Captain", 1, g_pMissionDatabase)
		pSaffiMoveOn	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4MoveOn2", "Captain", 1, g_pMissionDatabase)
	
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pFelixLine011, 5)
		pSequence.AppendAction(pMiguelLine04)
		pSequence.AppendAction(pSaffiMoveOn)
		
		pSequence.Play()
	
	elif (g_bYiles2Scanned == FALSE):
	
		pSequence = App.TGSequence_Create()
	
		pFelixLine011	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4L011", "Captain", 1, g_pMissionDatabase)
		pMiguelLine04	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrompt1", "Captain", 1, g_pMissionDatabase)
	
		pSequence.AppendAction(pFelixLine011, 5)
		pSequence.AppendAction(pMiguelLine04)
	
		pSequence.Play()
	
	
	# set communicate to say nothing special
	global g_iMissionPositionCounter
	g_iMissionPositionCounter	= 0
	
################################################################################
##	CreateTezleShips()
##
##	Creates the ships for the Yiles2 set. Called  while player is in warp.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateTezleShips():
	pSet = App.g_kSetManager.GetSet("Tezle1")

	# Create the ships.
	pGalor2		= loadspacehelper.CreateShip("Galor", pSet, "Galor 2", "Galor2Start")
	pKeldon2	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 2", "Keldon2Start")
	
	# Now give them an AI
	import E6M4_AI_Galor2
	import E6M4_AI_Keldon2
	
	pGalor2.SetAI(E6M4_AI_Galor2.CreateAI(pGalor2, g_pGalor2Targets))
	pKeldon2.SetAI(E6M4_AI_Keldon2.CreateAI(pKeldon2, g_pKeldon2Targets))


################################################################################
##	PlayerArrivedTezle2()
##
##	Sequence that plays when player first arrives in Tezle system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivedTezle2():
	#play generic "scan?" line unless kessok is present, in which case do the dialogue and AI thang
	if (g_bKessokRetreats == FALSE):
		pSequence = App.TGSequence_Create()
		
		pKiskaLine01		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4KessokInTezle1", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pKiskaLine01)
		#see if we've been promted twice
		if (g_iScanPromptCounter <= 1):
			global g_iScanPromptCounter
			g_iScanPromptCounter = g_iScanPromptCounter + 1
			pMiguelScanPrompt	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrompt1", "Captain", 1, g_pMissionDatabase)
			pSequence.AppendAction(pMiguelScanPrompt, 2)	# 3 sec delay before Miguel's line
		
		pSequence.Play()
	
	elif (g_bKessokRetreats == TRUE):
		pSequence = App.TGSequence_Create()
		
		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaLine01		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4KessokInTezle1", None, 0, g_pMissionDatabase)
		pFelixLine02		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4KessokInTezle2", None, 0, g_pMissionDatabase)
		pMiguelLine03		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4KessokInTezle3", None, 0, g_pMissionDatabase)
		pSetKessokAI		= App.TGScriptAction_Create(__name__, "SetKessokAI")
		pMiguelLine04		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4KessokInTezle4", None, 0, g_pMissionDatabase)
		pMiguelScanPrompt	= App.TGScriptAction_Create(__name__, "MiguelScanPrompt")
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pKiskaLine01, 1)	# 1 sec delay before Kiska's line
		pSequence.AppendAction(pFelixLine02)
		pSequence.AppendAction(pMiguelLine03)
		pSequence.AppendAction(pSetKessokAI)
		pSequence.AppendAction(pMiguelLine04, 5)
		pSequence.AppendAction(pMiguelScanPrompt, 3)
		
		pSequence.Play()
		
################################################################################
##	MiguelScanPrompt()
##
##	Sequence that plays when player first arrives in Tezle system.
##
##	Args:	pAction - passed for the sequence
##
##	Return:	return 0 - to dismiss the pAction
################################################################################
def MiguelScanPrompt(pAction):
	# see if miguel should say his scan line
	if (g_bTezle2Scanned == FALSE) and (g_iScanPromptCounter <= 1):
		global g_iScanPromptCounter
		g_iScanPromptCounter = g_iScanPromptCounter + 1
		pMiguelScanPrompt	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanPrompt1", "Captain", 1, g_pMissionDatabase)
		pMiguelScanPrompt.Play()
	return 0
	
################################################################################
##	SetKessokAI()
##
##	Sequence that plays when player first arrives in Tezle system.
##
##	Args:	pAction - passed for the sequence
##
##	Return:	return 0 - to dismiss the pAction
################################################################################	
def SetKessokAI(pAction):
	# set the AI to the kessok to retreat if it came to tezle
	if (g_bKessokRetreats == TRUE):
		pKessok = App.ShipClass_GetObject(None, "Kessok")
		if (pKessok):
			import E6M4_AI_KessokWarp
			pKessok.SetAI(E6M4_AI_KessokWarp.CreateAI(pKessok))
	return 0


################################################################################
##	ScanningTezle2()
##
##	Called from ScanHandler() when player scans the Tezle2 region.  Plays
##	sequence and adds and removes goals.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ScanningTezle2():
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "E6M4ArriveYiles4-1", g_pMissionDatabase)
	pMiguelLine01	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L012", "None", 0, g_pMissionDatabase)
	pFelixLine02	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveTezle2-3", "None", 0, g_pMissionDatabase)
	pMiguelLine03	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L013", "None", 0, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pScanSequence)
	pSequence.AppendAction(pMiguelLine01)
	pSequence.AppendAction(pFelixLine02)
	pSequence.AppendAction(pMiguelLine03)
	pSequence.AppendAction(pEnableScanMenu)
	
	pSequence.Play()
	
	# Remove the Scan Tezle goal and add the
	# Scan Tezle 1 goal
	MissionLib.RemoveGoal("E6ScanTezleGoal")
	MissionLib.AddGoal("E6ScanTezle1Goal")
	
	# set the g_iMissionPositionCounter so the right communicate dialogue plays
	global g_iMissionPositionCounter
	g_iMissionPositionCounter	= 5
	
################################################################################
##	PlayerArrivedTezle1()
##
##	Sequence that plays when player first arrives in Tezle1 set.
##	
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivedTezle1():
	# Make sure "Launch Probe" button is disabled when we enter the system
	DisableProbeButton()
	
	pBridge	= App.g_kSetManager.GetSet("bridge")
		
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pLookAtMe = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_LOOK_AT_ME)
	pCutsceneStart	= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pChangeToBridge	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pStartBridgeCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	if (g_bTezle2Scanned == FALSE):
		pScienceCam0	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam2")
		pMiguelLine013	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L013", None, 0, g_pMissionDatabase)
		pFelixCam1		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam2")
		pFelixLine0		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveTezle2-3", "Captain", 1, g_pMissionDatabase)
	pScienceCam1	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1")
	pMiguelLine014	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L014", None, 0, g_pMissionDatabase)
	pBrexCam		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam2")
	pBrexLine015	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4L015", "Captain", 0, g_pMissionDatabase)
	pBrexLine016	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4L016", "Captain", 1, g_pMissionDatabase)
	pCardsOnScreen	= App.TGScriptAction_Create(__name__, "CardsOnScreen")
	pFelixCam2		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View2", "Felix Cam3")
	pFelixLine017	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4L017", "Captain", 1, g_pMissionDatabase)
	pChangeToTezle1		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Tezle1")
	pStartTezle1Camera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Tezle1")
	pCardCamera			= App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Tezle1", "Galor 2")
	pKiskaLine018	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M4L018", "Captain", 1, g_pMissionDatabase)
	pCardCamera2			= App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Tezle1", "Keldon 2")
	pMiguelLine019	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L019", None, 0, g_pMissionDatabase)
	pChangeToBridge2	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSaffiCam			= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam2")
	pSaffiLine021	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4L021", "Captain", 0, g_pMissionDatabase)
	pSaffiLine022	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4L022", "Captain", 1, g_pMissionDatabase)
	pFelixCam3		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam2")
	pFelixLine023	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4ArriveTezle1-14", None, 0, g_pMissionDatabase)
	pEnableProbe	= App.TGScriptAction_Create(__name__, "EnableProbeButton")
	pPlayerCam		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Player Cam")
	pMiguelLine027	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L027", "Captain", 1, g_pMissionDatabase)
	pEndBridgeCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pEndTezle1Camera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Tezle1")
	pCutsceneEnd	= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pBrexLine024	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4L024", "Captain", 0, g_pMissionDatabase)
	pBrexLine026	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4L026", "Captain", 1, g_pMissionDatabase)
	
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pLookAtMe)
	pSequence.AppendAction(pCutsceneStart)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pChangeToBridge)
	pSequence.AppendAction(pStartBridgeCamera)
	if (g_bTezle2Scanned == FALSE):
		pSequence.AppendAction(pScienceCam0)
		pSequence.AppendAction(pMiguelLine013)
		pSequence.AppendAction(pFelixCam1)
		pSequence.AppendAction(pFelixLine0)
	pSequence.AppendAction(pScienceCam1)
	pSequence.AppendAction(pMiguelLine014)
	pSequence.AppendAction(pBrexCam)
	pSequence.AppendAction(pBrexLine015)
	pSequence.AppendAction(pBrexLine016)
	pSequence.AppendAction(pCardsOnScreen)
	pSequence.AppendAction(pFelixCam2, 0.2)
	pSequence.AppendAction(pFelixLine017)
	pSequence.AppendAction(pChangeToTezle1)
	pSequence.AppendAction(pStartTezle1Camera)
	pSequence.AppendAction(pCardCamera)
	pSequence.AppendAction(pKiskaLine018)
	pSequence.AppendAction(pCardCamera2)
	pSequence.AppendAction(pMiguelLine019)
	pSequence.AppendAction(pChangeToBridge2)
	pSequence.AppendAction(pSaffiCam)
	pSequence.AppendAction(pSaffiLine021)
	pSequence.AppendAction(pSaffiLine022)
	pSequence.AppendAction(pFelixCam3)
	pSequence.AppendAction(pFelixLine023)
	pSequence.AppendAction(pEnableProbe)
	pSequence.AppendAction(pPlayerCam)
	pSequence.AppendAction(pMiguelLine027)
	pSequence.AppendAction(pEndBridgeCamera)
	pSequence.AppendAction(pEndTezle1Camera)
	pSequence.AppendAction(pCutsceneEnd)
	pSequence.AppendAction(pBrexLine024, 5)  
	pSequence.AppendAction(pBrexLine026, 3)


	pSequence.Play()

	# Start the timer that will have Felix say more Cards are on way
	# Will only be activated if the Cards in Yiles still exist
	if (g_bGalor1Destroyed == FALSE) or (g_bKeldon1Destroyed == FALSE):
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		# Use a 90 sec timer for now
		MissionLib.CreateTimer(ET_CARDS_ON_WAY_TIMER, __name__+".CardsOnWay", fStartTime + 105, 0, 0)

	# Add the Launch probe goal and remove the Scan Tezle goals
	# if it's still hanging around.
	MissionLib.AddGoal("E6LaunchProbeGoal")
	MissionLib.RemoveGoal("E6ScanTezleGoal")
	MissionLib.RemoveGoal("E6ScanTezle1Goal")
	
	# set the g_iMissionPositionCounter so the right communicate dialogue plays
	global g_iMissionPositionCounter
	g_iMissionPositionCounter	= 6
	
	# This disables the automatic enabling/disabling of the launch probe button
	Bridge.BridgeUtils.g_bAutoManageProbeButton = 0

###############################################################################
##
## CardsOnScreen()
##
## Puts the Cards on the Viewscreen
##
##	Args:	pAction passed on from the sequence
##
##	Return:	return 0 to dismiss the pAction
################################################################################
def CardsOnScreen(pAction):
	pSet = App.g_kSetManager.GetSet("Tezle1")
	pCards = App.ShipClass_GetObject(pSet, "Keldon 2")

	MissionLib.ViewscreenWatchObject(pCards)
		
	return 0
	
################################################################################
##	EnableProbeButton()
##
##	Enables the "Launch Probe" button in Miguel's menu.
##
##	Args:	pTGAction
##
##	Return:	0	- Return 0 to keep calling sequence from crashing
################################################################################
def EnableProbeButton(pTGAction):
	# Get the Science menu
	pBridge		= App.g_kSetManager.GetSet("bridge")
	pSci		= App.CharacterClass_GetObject(pBridge, "Science")
	pSciMenu	= pSci.GetMenu()
	# Get the "Launch Probe" button
	pLaunchProbe = pSciMenu.GetButtonW(g_pDatabase.GetString("Launch Probe"))
	# Set the button to "Enabled"
	pLaunchProbe.SetEnabled()

	return 0
	
################################################################################
##	DisableProbeButton()
##
##	Disables the "Launch Probe" button in Miguel's menu
##
##	Args:	None
##
##	Return:	None
################################################################################
def DisableProbeButton():
	# Get the Science menu
	pBridge		= App.g_kSetManager.GetSet("bridge")
	pSci		= App.CharacterClass_GetObject(pBridge, "Science")
	pSciMenu	= pSci.GetMenu()
	# Get the "Launch Probe" button
	pLaunchProbe = pSciMenu.GetButtonW(g_pDatabase.GetString("Launch Probe"))
	# Set the button to "Disabled"
	pLaunchProbe.SetDisabled()

################################################################################
##	ProbeReachesPlanet()
##
##	Called if probe reaches planet.  Deletes the probe from the set and starts
##	the probe timer.
##	
##
##	Args:	pProbe	- The probe object
##
##	Return: None	
################################################################################
def ProbeReachesPlanet(pProbe):
	# Bail if the player is not in Tezle 1
	if (g_bPlayerNotInTezle1 == TRUE):
		return
	# Mark our flag
	if (g_bProbeReachedPlanet == FALSE):
		global g_bProbeReachedPlanet
		g_bProbeReachedPlanet = TRUE
	else:
		return
		
	#make sure the player doesn't leave the system until were done
	global g_bPlayerStuckInTezle2
	g_bPlayerStuckInTezle2	= TRUE
	
	# Make sure "Launch Probe" button is disabled
	DisableProbeButton()
		
	# Delete the probe
	pProbe.SetDeleteMe(1)
	
	# Check and see how long the timer should be
	if (len(g_lCardNames) == 0):
		fTimerLength = 5
	else:
		fTimerLength = 25
		
	# Start the timer on the probe
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_PROBE_TIMER, __name__+".MissionWin", fStartTime + fTimerLength, 0, 0)
	
	# Do Miguel's line that the probe has reached the planet.
	pMiguelLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L035", "Captain", 1, g_pMissionDatabase)
	pMiguelLine.Play()
	

	
################################################################################
##	ProbeDestroyed()
##
##	Called if probe is destroyed.  Plays sequence and reactivates "Launch Probe"
##	button in Miguel's menu.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ProbeDestroyed():
	# Set our flag
	global g_bProbeExists
	g_bProbeExists = FALSE
	
	# Play the line saying probe destroyed
	pMiguelLine030	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L030", "Captain", 1, g_pMissionDatabase)
	pMiguelLine030.Play()
	
	# Reactivate the "Launch Probe" menu option
	EnableProbeButton(None)

################################################################################
##	CardsOnWay()
##
##	Called by timer.  Plays audio line for Felix and resets surviving Card's AI
##	so that they will warp to system. If the player never went to Yiles, creates
##	the two cards that would have been there and then assigns AI.
##	Timer controlling warp time is in AI.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def CardsOnWay(TGObject, pEvent):
	# Get the player's  set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	# Check and see if the player ever went to Yiles
	if (g_bPlayerArriveYiles4 == FALSE):
		# He never went to Yiles so create the Cards that were in
		# that system.
		CreateYilesShips()		
		# Set the globals for Yiles so that if the player goes back, doesn't recreate
		# the ships
		global g_bPlayerArriveYiles4
		global g_bPlayerArriveYiles2
		g_bPlayerArriveYiles4 = TRUE
		g_bPlayerArriveYiles2 = TRUE
	
	# Do Felix's audio line
	if(g_bGalor1Destroyed == FALSE) and (g_bKeldon1Destroyed == FALSE):
		# Is the player still in Tezle 1?
		if (sSetName == "Tezle1"):
			# Line given if both Cards are comming
			pSequence = App.TGSequence_Create()
			App.TGActionManager_RegisterAction(pSequence, "IncommingCards")
			pFelixLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M4L033", "Captain", 1, g_pMissionDatabase)
			pSequence.AppendAction(pFelixLine)
			pSequence.Play()
		
	# Set the AI for the surviving Cards in Yiles
	# Get the set we need
	import E6M4_AI_Yiles_Survive
	if (g_bGalor1Destroyed == FALSE):
		pGalor1 = App.ShipClass_GetObject(None, "Galor 1")
		if (pGalor1 != None):
			pGalor1.SetAI(E6M4_AI_Yiles_Survive.CreateAI(pGalor1, "Card1Enter", g_pYilesCardTargets))
	
	if (g_bKeldon1Destroyed == FALSE):
		pKeldon1 = App.ShipClass_GetObject(None, "Keldon 1")
		if (pKeldon1 != None):
			pKeldon1.SetAI(E6M4_AI_Yiles_Survive.CreateAI(pKeldon1, "Card2Enter", g_pYilesCardTargets))

################################################################################
##	ProdPlayer()
##
##	Prods player with audio if not completing mission goals
##
##	Args:	TGObject	- TGObject object
##			pEvent		- Event sent to object
##
##	Return:	None
################################################################################
def ProdPlayer(TGObject, pEvent):
	pass
	
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
#	print "Trying to stop the HurryUp timer..."
	global g_iProdTimer
	if (g_iProdTimer != App.NULL_ID):
#		print "Timer exists with ID %d.  Removing it." % g_iProdTimer
		bSuccess = App.g_kTimerManager.DeleteTimer(g_iProdTimer)
#		if bSuccess:
#			print "Successfully removed."
#		else:
#			print "Failed to remove timer.  Prod warning may trigger inappropriately.  :("
		g_iProdTimer = App.NULL_ID

################################################################################
##	RestartProdTimer()
##
##	Starts a timer to prod the player.
##
##	Args:	pTGAction	- The script action object.
##			iTime		- The length of time in seconds that the timer will run for.
##
##	Return:	None
################################################################################
def RestartProdTimer(pTGActon, iTime):
#	print "Creating prod timer for %d seconds." % iTime

	# Stop the old prod timer.
	StopProdTimer()

	# Start a new prod timer.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_TIMER, __name__+".ProdPlayer", fStartTime + iTime, 0, 0)
	# Save the ID of the prod timer, so we can stop it later.
	global g_iProdTimer
	g_iProdTimer = pTimer.GetObjID()
#	print "New prod timer ID is " + str(g_iProdTimer)
	
	return 0

################################################################################
##	MissionWin()
##	
##  Called if the probe has been on the planet for the required amount of time.
##	Plays sequence and links us to E6M5.  Removes all the scanning goals and
##	replaces them with the "Head Home" goal.
##	
##	Args: 	TGObject	- The TGObject object
##			pEvent		- The event that was sent
##	
##	Return: None
################################################################################		
def MissionWin(TGObject, pEvent):
	# Bail if the probe did not reach the planet
	if (g_bProbeReachedPlanet == FALSE):
		return
		
	# Check our flag
	if (g_bMissionWinCalled == FALSE):
		global g_bMissionWinCalled
		g_bMissionWinCalled = TRUE
	else:
		return

	# Link this mission to E6M5
	LinkToE6M5()
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelLine036	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4L036", "Captain", 1, g_pMissionDatabase)
	pPlayerCanMove	= App.TGScriptAction_Create(__name__, "PlayerCanMove")
	pSaffiLine039	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4L039", "Captain", 0, g_pMissionDatabase)
	pSaffiLine040	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4L040", "Captain", 0, g_pMissionDatabase)
	pSaffiLine037	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M4L037", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelLine036)
	pSequence.AppendAction(pPlayerCanMove)
	pSequence.AppendAction(pSaffiLine039)
	pSequence.AppendAction(pSaffiLine040)
	pSequence.AppendAction(pSaffiLine037)
	
	MissionLib.QueueActionToPlay(pSequence)
	
	# Make sure the probe button is enabled
	EnableProbeButton(None)
	
	# Make sure all other mission goals have been removed
	# and add the Head Home goal
	MissionLib.RemoveGoal("E6FindCardBaseGoal")
	MissionLib.RemoveGoal("E6ScanPrendelGoal")
	MissionLib.RemoveGoal("E6ScanRihaGoal")
	MissionLib.RemoveGoal("E6ScanYilesGoal")
	MissionLib.RemoveGoal("E6ScanYiles2Goal")
	# Remove our LaunchProbeGoal
	MissionLib.RemoveGoal("E6LaunchProbeGoal")
	
	MissionLib.AddGoal("E6HeadHomeGoal")
	
	# this timer will call Cardassian reinforcments to pound on the user if they don't link to 6.5
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_MORE_FREAKIN_CARDS_TIMER, __name__+".MoreFreakinCards", fStartTime + 30, 0, 0)
	
	#set the communicate dialogue to not play anything
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 0
	
	# This will return the automatic enable/disable of the probe button to its normal state.
	Bridge.BridgeUtils.g_bAutoManageProbeButton = 1


################################################################################
##	PlayerCanMove()
##
##	Lets the player link to e6m5
##
##	Args:	pAction
##			
##
##	Return:	None
################################################################################
def PlayerCanMove(pAction):
	# Okay, the player can leave the system
	global g_bPlayerStuckInTezle2
	g_bPlayerStuckInTezle2	= FALSE
	
	return 0
		
################################################################################
##	MoreFreakinCards()
##
##	Creates the Cardassians in Tezle 1 which beat on the user for not warping to SB12 when told to.
##	Called from timer event started in MissionWin.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def MoreFreakinCards(TGObject, pEvent):

	# Get the set
	pSet	= App.g_kSetManager.GetSet("Tezle1")
	
	# Create the ships
	pKeldon3	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 3", "Keldon2Start", 1)
	pKeldon4	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 4", "Galor2Start", 1)
	pKeldon5	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 5", "Card1Enter", 1)
	pKeldon6	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 6", "Card2Enter", 1)
	
	# Import our AIs and assign them
	import E6M4_AI_Keldon2
	pKeldon3.SetAI(E6M4_AI_Keldon2.CreateAI(pKeldon3, g_pKeldon2Targets))
	pKeldon4.SetAI(E6M4_AI_Keldon2.CreateAI(pKeldon4, g_pKeldon2Targets))
	pKeldon5.SetAI(E6M4_AI_Keldon2.CreateAI(pKeldon5, g_pKeldon2Targets))
	pKeldon6.SetAI(E6M4_AI_Keldon2.CreateAI(pKeldon6, g_pKeldon2Targets))
	
	pSequence = App.TGSequence_Create()
	pFelixMoreShips	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "Incoming5", "Captain", 1, g_pGeneralDatabase)
	pSaffiLine		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6HeadHomeGoalAudio", "Captain", 1, MissionLib.GetEpisode().GetDatabase())

	pSequence.AppendAction(pFelixMoreShips)
	pSequence.AppendAction(pSaffiLine)
	
	pSequence.Play()	

################################################################################
##	LinkToE6M5()
##
##	Links this mission to the next in the helm menu.  Called from MissionWin().
##	
##
##	Args:	None
##
##	Return:	None
################################################################################
def LinkToE6M5():
	import Systems.Starbase12.Starbase
	pStarbaseMenu = Systems.Starbase12.Starbase.CreateMenus()
	pStarbaseMenu.SetMissionName("Maelstrom.Episode6.E6M5.E6M5")


################################################################################
##	Terminate()
##	
##  Called when mission ends to free resources
##	
##	Args: pMission - the mission object
##	
##	Return: None
################################################################################
def Terminate(pMission):
#	kDebugObj.Print ("Terminating Episode 6, Mission 4.\n")
	# Mission is terminating, so lets set our flag
	global g_bMissionTerminated
	g_bMissionTerminated = TRUE
	
	#Stop registered actions
	App.TGActionManager_KillActions("IncommingCards")

	# Delete all our mission goals
	MissionLib.DeleteAllGoals()
	
	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()

	# Remove all our instance handlers
	RemoveInstanceHandlers()
	
	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# unload the database: "data/TGL/Bridge Menus.tgl"
	if(g_pDatabase):
		App.g_kLocalizationManager.Unload(g_pDatabase)
	
	# now remove any remaining ships in the warp set
	MissionLib.DeleteShipsFromWarpSetExceptForMe()
	
	# Delete remaining Cards
	DeleteCards()

################################################################################
##	DeleteCards()
##
##	Remove any Cardassians in case they are in the warp set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def DeleteCards():
	pGalor1		= App.ShipClass_GetObject(None, "Galor 1")
	pGalor2		= App.ShipClass_GetObject(None, "Galor 2")
	pKeldon1	= App.ShipClass_GetObject(None, "Keldon 1")
	pKeldon2	= App.ShipClass_GetObject(None, "Keldon 2")
	
	if (pGalor1 != None):
		pGalor1.SetDeleteMe(1)
	if (pGalor2 != None):
		pGalor2.SetDeleteMe(1)
	if (pKeldon1 != None):
		pKeldon1.SetDeleteMe(1)
	if (pKeldon2 != None):
		pKeldon2.SetDeleteMe(1)
		
################################################################################
##	RemoveInstanceHandlers()
##
##	Remove any instance handlers we've registered in this mission.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RemoveInstanceHandlers():
	pSciMenu	= g_pMiguel.GetMenu()
	pSciMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")
	
	# Remove instance handler on players ship for Weapon Fired event
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.RemoveHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")
	
	pMenu = g_pSaffi.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET,	__name__ + ".HailStarfleet")
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
	pMenu = g_pFelix.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = g_pKiska.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	pMenu = g_pMiguel.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = g_pBrex.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
