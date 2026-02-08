###############################################################################
#	Filename:	E6M5.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 6, Mission 5
#	
#	Created:	11/27/00 -	Jess VanDerwalker
#	Updated:	01/10/02 - 	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Episode6.Episode6
import Bridge.BridgeUtils

# For debugging
#kDebugObj = App.CPyDebug()

#kDebugObj.Print('Loading Episode 6 Mission 5 definition...\n')


# Set up global variables here
TRUE				= 1
FALSE				= 0

g_bMissionTerminate	= None

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None
g_pDatabase			= None
# Prod globals
g_sProdLine		= None
g_iProdTimer	= None
# Player tracking flags
g_bPlayerArrivePrendel5	= None
g_bCardsWarpPlayed		= None
g_bPlayerArriveTezle2	= None
g_bTezle2ClearCalled	= None
g_bPlayerArriveTezle1	= None
g_bPlayerArriveBeol		= None
g_iMissionPositionCounter	= None
# Strike force traking flags
g_bStrikeForceTimerStarted	= None
g_bStrikeForceInTezle2		= None
g_bStrikeForceInTezle1		= None
g_bPlayerInTezleFirst		= None
# Card tracking flags
g_bSecondWaveArriveTezle1	= None
g_bThirdWaveArriveTezle1	= None

# Fed ship destroyed flags
g_bKhitomerDestroyed	= None
g_bYiLastLineSpoken		= None
g_bZhukovDestroyed		= None
g_bDevoreDestroyed		= None
g_bVentureDestroyed		= None
g_bSFDestroyed			= None
# Fed escort name
g_sFedEscortName		= None


# Shuttle tracking vars
g_iNumberShuttlesLanded		= None
g_iNumberShuttlesEscaped	= None
g_iNumberShuttlesDestroyed	= None
g_bShuttlesInBeol			= None
# Card tracking flags
g_iNumberCardsDestroyed		= None
g_iNumberMoreCardsDestroyed	= None
g_bStartingGalorsCreated	= None
g_bGalor1Destroyed			= None
g_bGalor2Destroyed			= None

g_bKessokScanned	= None

# Ship names
g_lCardNames	= []
g_lMoreCardNames	= []		
g_lFedNames	= []
g_lShuttleNames	= []

# Target list globals
g_pFedTezle2Targets		= None
g_pFedTezle1Targets		= None
g_pFedKessokTargets		= None
g_pFedCardTargets		= None
g_pCardTargets			= None
g_pCardSecondTargets	= None
g_pCardShuttleTargets	= None

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None

# Event Types for mission
ET_PROD_TIMER						= App.Mission_GetNextEventType()
ET_PLANET_PROXIMITY					= App.Mission_GetNextEventType()
ET_FORCE_TO_TEZLE_TIMER				= App.Mission_GetNextEventType()
ET_CARD_FIRST_WAVE_TIMER			= App.Mission_GetNextEventType()
ET_CARD_SECOND_WAVE_MASTER_TIMER	= App.Mission_GetNextEventType()
ET_CARD_SECOND_WAVE_TIMER			= App.Mission_GetNextEventType()
ET_CARD_THIRD_WAVE_TIMER			= App.Mission_GetNextEventType()
ET_FIRST_KESSOK_TIMER				= App.Mission_GetNextEventType()
ET_SHUTTLES_LAUNCH_TIMER			= App.Mission_GetNextEventType()
ET_SHUTTLES_LAUNCH_TIMER_2			= App.Mission_GetNextEventType()
ET_SHUTTLES_LAUNCH_TIMER_3			= App.Mission_GetNextEventType()
ET_SHUTTLES_LAUNCH_TIMER_4			= App.Mission_GetNextEventType()
ET_LAST_WAVE_TIMER					= App.Mission_GetNextEventType() #FIXME

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
	loadspacehelper.PreloadShip("Ambassador", 1)
	loadspacehelper.PreloadShip("Nebula", 1)
	loadspacehelper.PreloadShip("Akira", 1)
	loadspacehelper.PreloadShip("Galaxy", 2)
	loadspacehelper.PreloadShip("Keldon", 4)
	loadspacehelper.PreloadShip("Galor", 5)
	loadspacehelper.PreloadShip("KessokLight", 7)
	loadspacehelper.PreloadShip("Shuttle", 4)


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
	# "Event handler called on episode start.  Create the episode objects here."
#	kDebugObj.Print ("Initializing Episode 6, Mission 5.\n")

	# Initialize globals
	InitializeGlobals(pMission)
	
	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")
	
	# Create needed viewscreen sets
	CreateViewscreenSets()
	
	# Create the regions that we'll need
	CreateRegions()
	
	# Create the proximity check around the planet the shuttles will use
	CreatePlanetProximityCheck()
	
	#set the diffucultly level - easy Offense, Defense, med O, D, Hard O, D
	App.Game_SetDifficultyMultipliers(1.2, 1.1, 1.0, 1.0, 0.9, 0.9)
	
	# Import all the ships we'll be using and place them
	CreateStartingObjects(pMission)
	
	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()
	
	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()
		
	# Setup more mission-specific events.
	SetupEventHandlers()
	
	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)

	# Create menus available at mission start
	CreateStartingMenus()

	# Call Willis' briefing
	WillisBriefing(None)
	
	# Quiet the call out volume to %80 #FIXME cut this?
	MissionLib.SetSpeakingVolume(None, App.CSP_SPONTANEOUS, 0.8)
	
	# Save the Game
	MissionLib.SaveGame("E6M5-")

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
	# Set the Mission terminate flag
	global g_bMissionTerminate
	g_bMissionTerminate = FALSE

	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 6/E6M5.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	
	# Global constants used with bools
	global FALSE
	global TRUE
	TRUE	= 1
	FALSE	= 0
	
	# Globals used with prodding
	global g_sProdLine
	global g_iProdTimer
	g_sProdLine 	= "E6M5ProdToPrendel5"
	g_iProdTimer	= 0
	
	#Player tracking flags
	global g_bPlayerArrivePrendel5
	global g_bCardsWarpPlayed
	global g_bPlayerArriveTezle2
	global g_bTezle2ClearCalled
	global g_bPlayerArriveTezle1
	global g_bPlayerArriveBeol
	global g_iMissionPositionCounter
	g_bPlayerArrivePrendel5	= FALSE
	g_bCardsWarpPlayed		= FALSE
	g_bPlayerArriveTezle2	= FALSE
	g_bTezle2ClearCalled	= FALSE
	g_bPlayerArriveTezle1	= FALSE
	g_bPlayerArriveBeol 	= FALSE
	g_iMissionPositionCounter	= 0
	
	# Strike force traking flags
	global g_bStrikeForceTimerStarted
	global g_bStrikeForceInTezle2
	global g_bStrikeForceInTezle1
	global g_bPlayerInTezleFirst
	g_bStrikeForceTimerStarted	= FALSE
	g_bStrikeForceInTezle2		= FALSE
	g_bStrikeForceInTezle1		= FALSE
	g_bPlayerInTezleFirst		= FALSE

	# Card tracking flags
	global g_bSecondWaveArriveTezle1
	global g_bThirdWaveArriveTezle1
	g_bSecondWaveArriveTezle1	= FALSE
	g_bThirdWaveArriveTezle1	= FALSE

	# Fed ship destroyed flags
	global g_bKhitomerDestroyed
	global g_bYiLastLineSpoken
	global g_bZhukovDestroyed
	g_bKhitomerDestroyed	= FALSE
	g_bYiLastLineSpoken		= FALSE
	g_bZhukovDestroyed		= FALSE
	
	# Shuttle tracking vars
	global g_iNumberShuttlesLanded
	global g_iNumberShuttlesEscaped
	global g_iNumberShuttlesDestroyed
	global g_bShuttlesInBeol
	g_iNumberShuttlesLanded		= 0
	g_iNumberShuttlesEscaped	= 0
	g_iNumberShuttlesDestroyed	= 0
	g_bShuttlesInBeol			= FALSE

	# Card tracking flags
	global g_iNumberCardsDestroyed
	global g_iNumberMoreCardsDestroyed
	global g_bStartingGalorsCreated
	global g_bGalor1Destroyed
	global g_bGalor2Destroyed
	g_iNumberCardsDestroyed		= 0
	g_iNumberMoreCardsDestroyed	= 0
	g_bStartingGalorsCreated	= FALSE
	g_bGalor1Destroyed			= FALSE
	g_bGalor2Destroyed			= FALSE
	
	global g_bKessokScanned
	g_bKessokScanned	= FALSE

	# Ship names
	global g_lCardNames
	g_lCardNames	=	[
						"Galor 1", "Galor 2", "Galor 3", "Galor 4", "Galor 5", "Keldon 1", "Keldon 2", "Keldon 3", "Keldon 4",
						"Kessok 1", "Kessok 2", "Kessok 3", "Kessok 4", "Kessok 5", "Kessok 6", "Kessok 7"
						]
	global g_lMoreCardNames
	g_lMoreCardNames	=	[
							"Keldon 4", "Kessok 6", "Kessok 7"
							]
	global g_lFedNames
	g_lFedNames	=	[
					"Starbase 12", "Khitomer", "San Francisco", "Devore", "Venture", "Zhukov", "player"
					]
	global g_lShuttleNames
	g_lShuttleNames	=	[
					"Shuttle 1", "Shuttle 2", "Shuttle 3", "Shuttle 4"
						]

	
	# Check our episode level stuff and see if these ships have been destroyed
	global g_bDevoreDestroyed
	global g_bSFDestroyed
	global g_bVentureDestroyed
	g_bDevoreDestroyed	= Maelstrom.Episode6.Episode6.IsDevoreDestroyed()
	g_bSFDestroyed		= Maelstrom.Episode6.Episode6.IsSFDestroyed()
	g_bVentureDestroyed	= Maelstrom.Episode6.Episode6.IsVentureDestroyed()
	
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
##	CreateViewscreenSets()
##
##	Creates and populates sets used on viewscreen.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateViewscreenSets():

	pStarbaseSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu			= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)
	
	pDBridgeSet	= MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -30, 65, -1.55)
	MissionLib.ReplaceBridgeTexture(None, "DBridgeSet", "Map 7.tga", "data/Models/Sets/DBridge/NebulaLCARS.tga")
	pWillis		= MissionLib.SetupCharacter("Bridge.Characters.Willis", "DBridgeSet")
	
	pYiBridgeSet	= MissionLib.SetupBridgeSet("YiBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -30, 65, -1.55)
	MissionLib.ReplaceBridgeTexture(None, "YiBridgeSet", "Map 7.tga", "data/Models/Sets/DBridge/NebulaLCARS.tga")
	pYi			= MissionLib.SetupCharacter("Bridge.Characters.Yi", "YiBridgeSet")
	
	pShuttleSet	= MissionLib.SetupBridgeSet("ShuttleSet", "data/Models/Sets/Shuttle/Shuttle2.nif", -30, 65, -1.55)
	pWillis		= MissionLib.SetupCharacter("Bridge.Characters.Willis", "ShuttleSet")

################################################################################
##	CreateRegions()
##
##	Create all the regions that we will be using in this mission.
##	Call CreatePlacements() from in this function to do all our mission specific
##	placements.
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
	# Prendel5
	import Systems.Prendel.Prendel5
	Systems.Prendel.Prendel5.Initialize()
	pPrendel5Set = Systems.Prendel.Prendel5.GetSet()
	#Prendel4
	import Systems.Prendel.Prendel4
	Systems.Prendel.Prendel4.Initialize()
	pPrendel4Set = Systems.Prendel.Prendel4.GetSet()
	# Tezle2
	import Systems.Tezle.Tezle2
	Systems.Tezle.Tezle2.Initialize()
	pTezle2Set = Systems.Tezle.Tezle2.GetSet()
	# Tezle1
	import Systems.Tezle.Tezle1
	Systems.Tezle.Tezle1.Initialize()
	pTezle1Set = Systems.Tezle.Tezle1.GetSet()
	# Beol 4
	import Systems.Beol.Beol4
	Systems.Beol.Beol4.Initialize()
	pBeol4Set = Systems.Beol.Beol4.GetSet()
	
	# Get the Bridge for the cutscene
	pBridge = App.g_kSetManager.GetSet("bridge")
	
	# Do our mission specific placements
	# Import all our placement files
	import E6M5_Starbase12_P
	import E6M5_Prendel5_P
	import E6M5_Prendel4_P
	import E6M5_Tezle2_P
	import E6M5_Tezle1_P
	import E6M5_Beol4_P
	import E6M5_EBridge_P
	
	# Assign the placements to their sets
	E6M5_Starbase12_P.LoadPlacements(pStarbaseSet.GetName())
	E6M5_Prendel5_P.LoadPlacements(pPrendel5Set.GetName())
	E6M5_Prendel4_P.LoadPlacements(pPrendel4Set.GetName())
	E6M5_Tezle2_P.LoadPlacements(pTezle2Set.GetName())
	E6M5_Tezle1_P.LoadPlacements(pTezle1Set.GetName())
	E6M5_Beol4_P.LoadPlacements(pBeol4Set.GetName())
	E6M5_EBridge_P.LoadPlacements(pBridge.GetName())
	
################################################################################
##	CreateStartingMenus()
##	
##  Creates menu items for Starbase 
##	systems in "Helm" at mission start.
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def CreateStartingMenus ():
	import Systems.Starbase12.Starbase
	
	Systems.Starbase12.Starbase.CreateMenus()
	
	# pull out the Tezle system so the user doesn't go there.
	pKiskaMenu = g_pKiska.GetMenu()
	pSetCourse = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
		
	pTezle = pSetCourse.GetSubmenu("Tezle")
	pSetCourse.DeleteChild(pTezle)
	pRiha = pSetCourse.GetSubmenu("Riha")
	pSetCourse.DeleteChild(pRiha)
	pYiles = pSetCourse.GetSubmenu("Yiles")
	pSetCourse.DeleteChild(pYiles)

################################################################################
##	CreatePlanetProximityCheck()
##
##	Creates a proximity check around the planet.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreatePlanetProximityCheck():
	# Have the proximity check be global so that we can
	# get to in other functions
	global pProximityCheck
	
	# Set the proximity check will be in
	pSet = App.g_kSetManager.GetSet("Savoy1")
	
	# Create the proximity check object that will do the check and
	# send the event if necessary:
	pProximityCheck = App.ProximityCheck_Create(ET_PLANET_PROXIMITY)
	
	
	# Get the set we need
	pSet = App.g_kSetManager.GetSet("Tezle1")
	
	# Get the planet object
	pObject = pSet.GetObject("Tezle 1")
	
	# Setup the proximity check...
	fRadius	= (pObject.GetRadius()) + 10
	pProximityCheck.SetRadius(fRadius)

	# Make sure the check is centered around the planet.
	pObject.AttachObject(pProximityCheck)
	
	# Finally, add the proximity check to the proximity manager, so it will actually work.
	pProxManager = pSet.GetProximityManager()
	pProxManager.AddObject(pProximityCheck)
			
################################################################################
##	CreateStartingObjects()
##
##	Create all the objects that exist when the mission starts and their
##	affliations
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def CreateStartingObjects(pMission):
	# Import models needed for mission

	# Setup object affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	for sShipName in g_lFedNames:
		pFriendlies.AddName(sShipName)
	for sShipName in g_lShuttleNames:
		pFriendlies.AddName(sShipName)
	
	pEnemies = pMission.GetEnemyGroup()
	for sShipName in g_lCardNames:
		pEnemies.AddName(sShipName)
	
	pEnemies.AddName("Kessok 6")
	pEnemies.AddName("Kessok 7")
	pEnemies.AddName("Keldon 4")
	
	# Create our target groups
	CreateTargetGroups(pMission)
	
	# Get the sets we need
	pStarbaseSet = App.g_kSetManager.GetSet("Starbase12")
	
	# Place the players ship
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pStarbaseSet, "player", "Player Start")
	# Place the other starting objects and ships
	pStarbase12 = loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	pZhukov		= loadspacehelper.CreateShip("Ambassador", pStarbaseSet, "Zhukov", "ZhukovStart")
	pZhukov.ReplaceTexture("Data/Models/Ships/Ambassador/Zhukov.tga", "ID")
	pKhitomer	= loadspacehelper.CreateShip("Nebula", pStarbaseSet, "Khitomer", "KhitomerStart")
	pKhitomer.ReplaceTexture("data/Models/SharedTextures/FedShips/Khitomer.tga", "ID")
	
	# Figure out who exists and bring them along
	global g_sFedEscortName
	if (g_bDevoreDestroyed == FALSE):
		g_sFedEscortName = "Devore"
		pFedShip = loadspacehelper.CreateShip("Akira", pStarbaseSet, "Devore", "FedStart")
		pFedShip.ReplaceTexture("Data/Models/Ships/Akira/Devore.tga", "ID")
	elif (g_bSFDestroyed == FALSE):
		g_sFedEscortName = "San Francisco"
		pFedShip	= loadspacehelper.CreateShip("Galaxy", pStarbaseSet, "San Francisco", "FedStart")
		pFedShip.ReplaceTexture("data/Models/SharedTextures/FedShips/SanFrancisco.tga", "ID")
	elif (g_bVentureDestroyed == FALSE):
		g_sFedEscortName = "Venture"
		pFedShip	= loadspacehelper.CreateShip("Galaxy", pStarbaseSet, "Venture", "FedStart")
		pFedShip.ReplaceTexture("data/Models/SharedTextures/FedShips/Venture.tga", "ID")
	
	# Give all the Federation ships the flee from Starbase AI
	import E6M5_AI_FleeFromStarbase
	pZhukov.SetAI(E6M5_AI_FleeFromStarbase.CreateAI(pZhukov))
	pKhitomer.SetAI(E6M5_AI_FleeFromStarbase.CreateAI(pKhitomer))
	pFedShip.SetAI(E6M5_AI_FleeFromStarbase.CreateAI(pFedShip))
	
################################################################################
##	CreateTargetGroups()
##
##	Create the global target groups that the AIs will use.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def CreateTargetGroups(pMission):
	# Federation targets in Tezle2
	global g_pFedTezle2Targets
	lTezle2Names	= ["Galor 1", "Galor 2", "Galor 3", "Galor 4", "Keldon 1"]
	g_pFedTezle2Targets = App.ObjectGroup()
	for sName in lTezle2Names:
		g_pFedTezle2Targets.AddName(sName)
		
	global g_pFedTezle1Targets
	g_pFedTezle1Targets = App.ObjectGroup()
	
	# Federation Kessok targets
	global g_pFedKessokTargets
	lKessokNames=	["Kessok 1", "Kessok 2", "Kessok 3", "Kessok 4", "Kessok 5", "Kessok 6", "Kessok 7", "Kessok 8"]
	g_pFedKessokTargets = App.ObjectGroup()
	for sName in lKessokNames:
		g_pFedKessokTargets.AddName(sName)
		g_pFedTezle1Targets.AddName(sName)
	
	# Federation Cardassian targets
	global g_pFedCardTargets
	g_pFedCardTargets = App.ObjectGroup()
	g_lCardNames	=	["Galor 4", "Galor 5", "Keldon 2", "Keldon 3", "Keldon 4"]
	for sName in g_lCardNames:
		g_pFedCardTargets.AddName(sName)
		g_pFedTezle1Targets.AddName(sName)

	# All targets for Cardassian ships
	global g_pCardTargets
	g_pCardTargets = App.ObjectGroup()
	for sName in g_lFedNames:
		g_pCardTargets.AddName(sName)
		
	# Secondary targets for Cardassians
	global g_pCardSecondTargets
	g_pCardSecondTargets = App.ObjectGroup()
	lSecondFeds	= [ "Devore", "San Francisco", "Venture" ]
	for sName in lSecondFeds:
		g_pCardSecondTargets.AddName(sName)
	
	# Shuttle targets for Cards
	global g_pCardShuttleTargets
	g_pCardShuttleTargets = App.ObjectGroup()
	lShuttleNames	= [ "Shuttle 1", "Shuttle 2", "Shuttle 3", "Shuttle 4" ]
	for sName in lShuttleNames:
		g_pCardShuttleTargets.AddName(sName)
		
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
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__+".ObjectDestroyed")
	# Object exploding event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__+".ObjectExploding")
	
	# Instance handler on players ship for Weapon Fired event, for Tractor on firendlys
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")
	
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")
	
	# Instance handler for Kiska's Hail button
	pMenu = g_pKiska.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	
	# Instance handler for Miguel's Scan button
	pSet	= App.g_kSetManager.GetSet("bridge")
	pSci	= App.CharacterClass_GetObject(pSet, "Science")
	pMenu	= pSci.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	
#	kDebugObj.Print("Adding Crew Communicate Handlers")
	pBridge = App.g_kSetManager.GetSet("bridge")
	# Communicate with Saffi event
	pSaffi = App.CharacterClass_GetObject(pBridge, "XO")
	pMenu = pSaffi.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Felix event
	pFelix = App.CharacterClass_GetObject(pBridge, "Tactical")
	pMenu = pFelix.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Kiska event
	pKiska = App.CharacterClass_GetObject(pBridge, "Helm")
	pMenu = pKiska.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Miguel event
	pMiguel = App.CharacterClass_GetObject(pBridge, "Science")
	pMenu = pMiguel.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Brex event
	pBrex = App.CharacterClass_GetObject(pBridge, "Engineer")
	pMenu = pBrex.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

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
			if (pTarget.GetName()[:6] == "Kessok") and (g_bKessokScanned == FALSE):
#				kDebugObj.Print("You're scanning a Kessok")
				ScanningKessok()
				global g_bKessokScanned
				g_bKessokScanned = TRUE
			# if scaning nothing we care about do default
			else:
				TGObject.CallNextHandler(pEvent)
	else:
		TGObject.CallNextHandler(pEvent)			
	
################################################################################
##	ScanningKessok()
##
##  Creates sequence for ScanningKessok and plays it.  
##
##	Args: 	None
##
##	Return: None
################################################################################
def ScanningKessok():
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "gs007", g_pGeneralDatabase)
	pFelixLine02	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L024", None, 0, g_pMissionDatabase)
	pMiguelLine03	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6KessokTorp", None, 0, MissionLib.GetEpisode().GetDatabase())
	pMiguelLine04	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "gs038", None, 0, g_pGeneralDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pScanSequence)		
	pSequence.AppendAction(pFelixLine02)
	pSequence.AppendAction(pMiguelLine03)
	pSequence.AppendAction(pMiguelLine04)
	pSequence.AppendAction(pEnableScanMenu)
		
	pSequence.Play()


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
	# Get the player and his target
	pPlayer = MissionLib.GetPlayer ()
	if (pPlayer == None):
		return
		
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if (pTarget):
		if (pTarget.GetName () == "Khitomer"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			
			pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pKhitomerHailed		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6HailKhitomer", "Yi")
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pPreLoad)
			pSequence.AppendAction(pCallWaiting)		
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pKhitomerHailed, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
		
		elif (pTarget.GetName () == "San Francisco"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pSFHailed			= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6HailSanFrancisco", "Zeiss")
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pCallWaiting)		
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pSFHailed, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
			
		elif (pTarget.GetName () == "Nightingale"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pNightHailed		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6HailNightingale", "Jadeja")
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pCallWaiting)		
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pNightHailed, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
			
		elif (pTarget.GetName () == "Devore"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pDevoreHailed		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6HailDevore", "Martin")
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pCallWaiting)		
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pDevoreHailed, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()

		elif (pTarget.GetName () == "Venture"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pVentureHailed		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6HailVenture", "Dawson")
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pCallWaiting)		
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pVentureHailed, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
	
		elif (pTarget.GetName () in g_lFedNames) or (pTarget.GetName () in g_lShuttleNames):	
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pKiskaNoResponse	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6HailAnyone3", None, 0, MissionLib.GetEpisode().GetDatabase())
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pCallWaiting)					
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pKiskaNoResponse, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
		
		else:
			TGObject.CallNextHandler(pEvent)

################################################################################
##	PlayerWeaponFired()
##
##	Handler called when player fires a weapon. Checks if it is a tractor on the shuttles
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
		
	# check if the user is firing a tractor beam.
	if (App.TractorBeamProjector_Cast(pEvent.GetSource())):
#		print "tractor beam was fired"
		# if they are firing a trcator on a shuttle, warn them
		if (sTargetName in g_lShuttleNames):
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "DontShoot8", None, 0, g_pGeneralDatabase)
			pAction.Play()
			pTractors = pPlayer.GetTractorBeamSystem()
			if pTractors:
				pTractors.StopFiring()
	
################################################################################
##	PlayerFiringOnFriend()
##
##	Called if the player continues to fire on Friendly ships
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
##	Called if the player continues to fire on friend. 
##	Ends the game because the player is being a bastard.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PlayerStillFiringOnFriend(TGObject, pEvent):
	App.TGActionManager_KillActions()	
	# Do the line from Saffi and end the game
	pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "DontShoot3", "Captain", 1, g_pGeneralDatabase)
	
	# End the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
	pGameOver.Play()

	
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
	if pMenu and (g_iMissionPositionCounter == 1):
		PrendelCommunicate(pMenu.GetObjID()) #pass on whose menu was clicked to PrendelCommunicate
		
	elif pMenu and (g_iMissionPositionCounter == 2):
		Tezle2Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Tezle2Communicate

	elif pMenu and (g_iMissionPositionCounter == 3):
		Tezle1Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Tezle1Communicate
				
	elif pMenu and (g_iMissionPositionCounter == 4):
		TezleBattleCommunicate(pMenu.GetObjID()) #pass on whose menu was clicked to TezleBattleCommunicate
	
	else:
#		kDebugObj.Print("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)
	
#####################################################################
##
## PrendelCommunicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def PrendelCommunicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate03", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate01", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6EngagePrendelCardsGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate04", None, 0, g_pMissionDatabase)
		
	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate02", None, 0, g_pMissionDatabase)
	
	pAction.Play()
	
#####################################################################
##
## Tezle2Communicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
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
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate03", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate05", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate07", None, 0, g_pMissionDatabase)

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate04", None, 0, g_pMissionDatabase)
	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate06", None, 0, g_pMissionDatabase)

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
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate08", None, 0, g_pMissionDatabase)

	# no special communicate dialogue for felix
	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "FelixNothingToAdd", None, 0, g_pGeneralDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate07", None, 0, g_pMissionDatabase)

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate09", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate06", None, 0, g_pMissionDatabase)

	pAction.Play()

#####################################################################
##
## TezleBattleCommunicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def TezleBattleCommunicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate13", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate10", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate12", None, 0, g_pMissionDatabase)

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate14", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M5Communicate11", None, 0, g_pMissionDatabase)

	pAction.Play()
	
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
		
	# Bail if the ship is dead
	if (pShip.IsDead()):
		return
		
	pSet		= pShip.GetContainingSet()
	sSetName 	= pSet.GetName()
	sShipName	= pShip.GetName()
	
#	kDebugObj.Print("Object \"%s\" entered set \"%s\"" % (sShipName, sSetName))
	
	# If it's the player, lets see where he is
	if (sShipName == "player"):
		if (sSetName == "warp"):
			PlayerEntersWarpSet()
		else:
			TrackPlayer(sSetName)
	
	# If it's Galor 1 in Prendel, call our function
	if (sSetName == "Prendel5") and (sShipName == "Galor 1"):
		GalorsArrivePrendel5()
		
	global g_bStrikeForceInTezle1
	# If it's the Khitomer entering Tezle2, hail the player
	if (sShipName == "Khitomer") and (sSetName == "Tezle2"):
		StrikeForceArrivesTezle2()
	# If it's the Khitomer entering Tezle1, 
	elif (sShipName == "Khitomer") and (sSetName == "Tezle1"):

		g_bStrikeForceInTezle1 = TRUE
		# check if the player went to tezle 1 first, if so call the PlayerArrivesTezle1() fuction
		if (g_bPlayerInTezleFirst == TRUE):
			PlayerArrivesTezle1()
			
	
	# See if it's a shuttle entering Beol4
	if (sSetName == "Beol4") and (sShipName[:7] == "Shuttle"):
		# It is so increase our counter
		global g_iNumberShuttlesEscaped
		g_iNumberShuttlesEscaped = g_iNumberShuttlesEscaped + 1
		# Check and see if we can call the all clear
		if (g_iNumberShuttlesEscaped + g_iNumberShuttlesDestroyed >= 4) and (g_iNumberShuttlesDestroyed != 4):
			global g_bShuttlesInBeol
			g_bShuttlesInBeol = TRUE
			ShuttlesEscape()
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ExitSet()
##	
##	Event handler called whenever an object leaves a set.
##	
##	Args: 	TGObject	- The TGObject object
##			pEvent		- Pointer to the event that was sent to the object
##	
##	Return: None
################################################################################
def ExitSet(TGObject, pEvent):
	# See if our mission is terminating
	if (g_bMissionTerminate == TRUE):
		return
		
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()

	# Make sure it's a ship, return if not
	if (pShip == None):
		return
	sShipName = pShip.GetName()	
	
	# if the player is moving, set g_iMissionPositionCounter to play no dialogue	
	if (sShipName == "player"):
		global g_iMissionPositionCounter
		g_iMissionPositionCounter = 0
		
#	kDebugObj.Print("Object \"%s\" exited set \"%s\"" % (sShipName, sSetName))
	
	# We're done. Let any other event handlers for this event handle it
	TGObject.CallNextHandler(pEvent)
	
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
	
	# See if Zhukov has been destroyed
	global g_bZhukovDestroyed
	if (sShipName == "Zhukov"):
		g_bZhukovDestroyed = TRUE
		# play a line of dialogue.
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L035", None, 0, g_pMissionDatabase)
		pAction.Play()

	# See if Devore has been destroyed
	if (sShipName == "Devore"):
		# play a line of dialogue.
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1DevoreDestroyed1", None, 0, MissionLib.GetEpisode().GetDatabase())
		pAction.Play()
		
	# See if Venture has been destroyed
	if (sShipName == "Venture"):
		# play a line of dialogue. 
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1VentureDestroyed1", None, 0, MissionLib.GetEpisode().GetDatabase())
		pAction.Play()
		
	# See if San Fransisco has been destroyed
	if (sShipName == "San Francisco"):
		# play a line of dialogue.
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1SFDamaged2", None, 0, MissionLib.GetEpisode().GetDatabase())
		pAction.Play()
		
	if (sShipName[:7] == "Shuttle"):
		global g_iNumberShuttlesDestroyed
		g_iNumberShuttlesDestroyed = g_iNumberShuttlesDestroyed + 1
		if (g_iNumberShuttlesDestroyed == 4):
			MissionLostTezle2()
		
	# Keep track of the number of Cards and Kessok destroyed
	global g_iNumberCardsDestroyed
	for sCard in g_lCardNames:
		if (sCard == sShipName):
			g_iNumberCardsDestroyed = g_iNumberCardsDestroyed + 1
			# Call our function to handle the creation of the waves
			CardWasDestroyed()
	
	# Keep track of the number of more Cards and Kessok destroyed at the end
	global g_iNumberMoreCardsDestroyed
	for sCard in g_lMoreCardNames:
		if (sCard == sShipName):
			g_iNumberMoreCardsDestroyed = g_iNumberMoreCardsDestroyed + 1
			#if they are all dead call them again
			if (g_iNumberMoreCardsDestroyed == 3):
				CreateLastWave(None, None)
				g_iNumberMoreCardsDestroyed = 0	

	# Lets see if it's the Khitomer that's been destroyed
	# an if so deal with it in another function
	if (sShipName == "Khitomer"):
		KhitomerDestroyed(sShipName, sSetName)	
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


################################################################################
##	ObjectExploding()
##
##	Event handler called when a ship exploding event is sent.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- Event that was sent to the object.
##
##	Return:	None
################################################################################
def ObjectExploding(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	# Check and see if it's a ship, if not return
	if (pShip == None):
		return
	sShipName	= pShip.GetName()
	pSet = pShip.GetContainingSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	# See if the Galors in Prendel have been destroyed
	global g_bGalor1Destroyed
	global g_bGalor2Destroyed
	if (sSetName == "Prendel5"):
		if (sShipName == "Galor 1"):
			g_bGalor1Destroyed = TRUE
		elif (sShipName == "Galor 2"):
			g_bGalor2Destroyed = TRUE
		# If both are destroyed, have the strike force warp
		if (g_bGalor1Destroyed == TRUE) and (g_bGalor2Destroyed == TRUE):
			App.TGActionManager_KillActions("Galors")
			# Extra arguments are needed for this function
			StrikeForceDeparts(None, None)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	PlanetProximity()
##
##	Called when an object gets close to planet.  Calls ShuttleReachedPlanet() if
##	object was a shuttle.
##
##	Args:	TGObject	- TGObject object
##			pEvent		- Pointer to event object	
##
##	Return:	None
################################################################################
def PlanetProximity(TGObject, pEvent):
	pObject = App.ShipClass_Cast(pEvent.GetDestination())
	if (pObject != None):
		# It's a shuttle.  Call our function
		ShuttleReachesPlanet(pObject)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

	
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
	# See if were entering Prendel5 for the first time
	global g_bPlayerArrivePrendel5
	if (sSetName == "Prendel5") and (g_bPlayerArrivePrendel5 == FALSE):
		StopProdTimer()
		g_bPlayerArrivePrendel5 = TRUE
		PlayerArrivesPrendel5()
		
	global g_bPlayerArriveTezle2
	global g_bPlayerArriveTezle1
	# See if we're entering Tezle2 for the first time
	if (sSetName == "Tezle2") and (g_bPlayerArriveTezle2 == FALSE):
		StopProdTimer()
		g_bPlayerArriveTezle2 = TRUE
		global g_iMissionPositionCounter
		g_iMissionPositionCounter = 2
		PlayerArrivesTezle2()
		
	# See if we're entering Tezle1 for the first time
	elif (sSetName == "Tezle1") and (g_bPlayerArriveTezle1 == FALSE):
		StopProdTimer()
		g_bPlayerArriveTezle1 = TRUE
		PlayerArrivesTezle1()
		# Start the timer for
		# the arrival of the Cardassians
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_CARD_FIRST_WAVE_TIMER, __name__+".CreateFirstCardWave", fStartTime + 53, 0, 0)
	
################################################################################
##	PlayerEntersWarpSet()
##
##	Called if player enters warp set.  Keeps track of were the player is headed
##	for proding needs and creating ships while were in warp.
##
##	Args:	None
##
##	Return: None	
################################################################################
def PlayerEntersWarpSet():
	# Get Kiska's warp heading and see where were headed
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pString 	= pWarpButton.GetDestination()
	
	# If were warping anywhere for the first time, create the starting Galors
	global g_bStartingGalorsCreated
	if (g_bStartingGalorsCreated == FALSE):
		g_bStartingGalorsCreated = TRUE
		CreateStartingGalors()
	
	# The first time that we warp anywhere, start our timer
	# that will cause the other FedShips to warp to Tezle2
	if (g_bStrikeForceTimerStarted == FALSE):
		global g_bStrikeForceTimerStarted
		g_bStrikeForceTimerStarted = TRUE
		
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_FORCE_TO_TEZLE_TIMER, __name__+".StrikeForceDeparts", fStartTime + 170, 0, 0)
	
	
	# See if were heading to Prendel for the first time
	if (pString == "Systems.Prendel.Prendel5") and (g_bPlayerArrivePrendel5 == FALSE):
		StopProdTimer()
	# See if were heading to Tezle2 for the first time
	elif (pString == "Systems.Tezle.Tezle2") and (g_bPlayerArriveTezle2 == FALSE):
		StopProdTimer()
	# See if we're heading to Tezle1 for the first time
	elif (pString == "Systems.Tezle.Tezle1") and (g_bPlayerArriveTezle1 == FALSE):
		StopProdTimer()
	# See if we're heading to the Beol system
	elif (pString == "Systems.Beol.Beol4") and (g_bPlayerArriveBeol == FALSE) and (g_bShuttlesInBeol == TRUE):
		StopProdTimer()
		global g_bPlayerArriveBeol
		g_bPlayerArriveBeol = TRUE
		
################################################################################
##	CardWasDestroyed()
##
##	Called when a Card or Kessok was destroyed.  Use the counter to see if it's
##	time to create another wave of enemies.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CardWasDestroyed():
	# See if it's time to call the second wave.
	# if this doesn't happen, then second wave will occur by another timer
	if (g_iNumberCardsDestroyed == 6):
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_CARD_SECOND_WAVE_TIMER, __name__+".CreateSecondCardWave", fStartTime + 45, 0, 0)
	
	# See if enough ships have been destroyed to create third wave
	if (g_iNumberCardsDestroyed == 8):
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_CARD_THIRD_WAVE_TIMER, __name__+".CreateThirdCardWave", fStartTime + 50, 0, 0)
		
	# the arrival of the last bad guys
	if (g_iNumberCardsDestroyed == 12):
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_LAST_WAVE_TIMER, __name__+".CreateLastWave", fStartTime + 10, 0, 0)
		
################################################################################
##	KhitomerDestroyed()
##
##	Function to deal with the destruction of the Khitomer.
##
##	Args:	sShipName	- The name of the ship as a string
##			sSetName	- The name of the set as a string
##
##	Return:	None
################################################################################
def KhitomerDestroyed(sShipName, sSetName):
	# Get the globals needed
	global g_bKhitomerDestroyed
	# Deal with the Khitomer destruction
	if (sShipName == "Khitomer") and (g_bYiLastLineSpoken == FALSE):
		g_bKhitomerDestroyed = TRUE
		# "Khitomer destroyed" audio line
		g_pSaffi.SpeakLine(g_pMissionDatabase, "E6M5L042", App.CSP_MISSION_CRITICAL)
		if (sSetName == "Tezle2"):
			MissionLostTezle2()
		elif (sSetName == "Tezle1"):
			MissionLostTezle1()
	# If Yi is done talking, no mission loss
	elif (sShipName == "Khitomer") and (g_bYiLastLineSpoken == TRUE):
		MissionLib.RemoveGoal("E6ProtectKhitomerGoal")		
		g_bKhitomerDestroyed = TRUE
		# "Khitomer destroyed" audio line
		g_pSaffi.SpeakLine(g_pMissionDatabase, "E6M5L042", App.CSP_MISSION_CRITICAL)
				
################################################################################
##	WillisBriefing()
##
##	Plays Willis' and Liu's briefings and starts prompting timer.
##
##	Args:	pTGAction
##
##	Return:	None
################################################################################
def WillisBriefing(pTGAction):
	# check if the player is done warping in, if not call this function again in 2 seconds
	if MissionLib.IsPlayerWarping():
		# Delay sequence 2 seconds.
		pSequence = App.TGSequence_Create()
		pRePlayBriefing	= App.TGScriptAction_Create(__name__, "WillisBriefing")
		pSequence.AppendAction(pRePlayBriefing, 2)
		pSequence.Play()

		return 0

	# Set our prod line
	global g_sProdLine
	g_sProdLine = "E6M5ProdToPrendel5"
	
	pStarbaseSet = App.g_kSetManager.GetSet("StarbaseSet")
	pLiu	= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pDBridgeSet = App.g_kSetManager.GetSet("DBridgeSet")
	pCamera = pDBridgeSet.GetCamera("maincamera")
	pCamera.SetTranslateXYZ(37.936455, 52.250359, 49.288269)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.509437, 0.859258, -0.046366)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.019864, 0.042125, 0.998915)
	pCamera.UpdateNodeOnly()
	pCamera.AlignToVectors(kForward, kUp)

	pWillis		= App.CharacterClass_GetObject(pDBridgeSet, "Willis")
		
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Willis")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pIncoming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg1", "Captain", 1, g_pGeneralDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLine041		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M5Liu1", None, 0, g_pMissionDatabase)
	pLiuLine043		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M5Liu3", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pIncoming2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesOffPlanet2", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis")
	pWillisLine001	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5L001", None, 0, g_pMissionDatabase)
	pWillisLine002	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5L002", None, 0, g_pMissionDatabase)
	pWillisLine003	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5L003", None, 0, g_pMissionDatabase)
	pWillisLine004	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5L004", None, 0, g_pMissionDatabase)
	pViewOff2		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pAddPrendel		= App.TGScriptAction_Create(__name__, "AddPrendelSystem")
	pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 60)	# 60 sec prod timer
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pIncoming, 3)	# 3 sec delay before the talking heads start
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuLine041)
	pSequence.AppendAction(pLiuLine043)
	pSequence.AppendAction(pViewOff)
	
	pSequence.AppendAction(pIncoming2, 2)	# 3 sec delay before the talking heads start
	pSequence.AppendAction(pDBridgeViewOn, 1)
	pSequence.AppendAction(pWillisLine001)
	pSequence.AppendAction(pWillisLine002)
	pSequence.AppendAction(pWillisLine003)
	pSequence.AppendAction(pWillisLine004)
	pSequence.AppendAction(pViewOff2)
	pSequence.AppendAction(pAddPrendel)
	pSequence.AppendAction(pStartProdTimer)
	
	pSequence.Play()

	return 0

################################################################################
##	AddPrendelSystem()
##
##	Adds prendel to the course list and changes the goals
##
##	Args:	pTGAction		- The script action object
##			
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def AddPrendelSystem(pTGAction):
		
	# Register our first goal
	MissionLib.AddGoal("E6GoToPrendelGoal")
	MissionLib.AddGoal("E6EngagePrendelCardsGoal")
	#add prendel to set course list.
	import Systems.Prendel.Prendel
	Systems.Prendel.Prendel.CreateMenus()
	
	return 0
	
################################################################################
##	CreateStartingGalors()
##
##	Creates Galor1 and Galor2 in the Prendel4 system and Galors 3& 4 in Tezle 2.
##	Called when the player enters warp for the first time.
##	AI for Tezle2 Galors will be done later.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateStartingGalors():
	# Import the needed scripts
	
	# Get the set
	pPrendel4Set = App.g_kSetManager.GetSet("Prendel4")
		
	# Place the Prendel ships
	pGalor1 = loadspacehelper.CreateShip("Galor", pPrendel4Set, "Galor 1", "Galor1Start")
	pGalor2 = loadspacehelper.CreateShip("Galor", pPrendel4Set, "Galor 2", "Galor2Start")
	
	MissionLib.MakeEnginesInvincible(pGalor1)
	MissionLib.MakeEnginesInvincible(pGalor2)
	
	# Give the Prendel ships their AI
	import E6M5_AI_Galor1_2
	pGalor1.SetAI(E6M5_AI_Galor1_2.CreateAI(pGalor1, "Galor1Enter", g_pCardTargets))
	pGalor2.SetAI(E6M5_AI_Galor1_2.CreateAI(pGalor2, "Galor2Enter", g_pCardTargets))
	
	# Get the set
	pTezle2Set = App.g_kSetManager.GetSet("Tezle2")
	
	# Place the Tezle ships
	pGalor3		= loadspacehelper.CreateShip("Galor", pTezle2Set, "Galor 3", "Galor3Start")
	pGalor4		= loadspacehelper.CreateShip("Galor", pTezle2Set, "Galor 4", "Galor4Start")
	pKeldon1	= loadspacehelper.CreateShip("Keldon", pTezle2Set, "Keldon 1", "Keldon1Start")
	
	#make them invincible util the user arrives
	pGalor3.SetInvincible(1)
	pGalor4.SetInvincible(1)
	pKeldon1.SetInvincible(1)
	
################################################################################
##	PlayerArrivesPrendel5()
##
##	Sequence that plays when player arrives in the Prendel5 set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesPrendel5():
	
	# Remove the GoToPrendelGoal
	MissionLib.RemoveGoal("E6GoToPrendelGoal")
	
	# set the g_iMissionPositionCounter to play the right dialogue
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 1
	
################################################################################
##	GalorsArrivePrendel5()
##
##	Line that plays when Galor 1 enters Prendel 5.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GalorsArrivePrendel5():
	pFelixLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L007", "Captain", 1, g_pMissionDatabase)
	pFelixLine.Play()
	
################################################################################
##	StrikeForceDeparts()
##
##	Assigns AI to the strike force at Starbase 12 which causes them to begin
##	mission.  First stop is Tezle2.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def StrikeForceDeparts(TGObject, pEvent):
	# Check and make sure that this hasn't been done already
	global g_bStrikeForceInTezle2
	if (g_bStrikeForceInTezle2 == TRUE):
		return
	else:
		g_bStrikeForceInTezle2 = TRUE
		
	# Import the AIs for the ships
	import E6M5_AI_Zhukov
	import E6M5_AI_Fed
	import E6M5_AI_Khit
	
	# Get the ships
	pSet		= App.g_kSetManager.GetSet("Starbase12")
	pZhukov		= App.ShipClass_GetObject(pSet, "Zhukov")
	pFed		= App.ShipClass_GetObject(pSet, g_sFedEscortName)
	pKhitomer	= App.ShipClass_GetObject(pSet, "Khitomer")
	
	# Assign the AIs to the ships
	pZhukov.SetAI(E6M5_AI_Zhukov.CreateAI(pZhukov))
	pFed.SetAI(E6M5_AI_Fed.CreateAI(pFed))
	pKhitomer.SetAI(E6M5_AI_Khit.CreateAI(pKhitomer))
	
	MissionLib.AddCommandableShip("Zhukov")
	MissionLib.AddCommandableShip(g_sFedEscortName)
	
	# Damage the shields on the Zhukov
	pShields = pZhukov.GetShields()
	# Set the front shield to 50%
	pShields.SetCurShields(pShields.FRONT_SHIELDS, pShields.GetMaxShields(pShields.FRONT_SHIELDS) / 1.5)
	# Set the left and top shields to 65%
	pShields.SetCurShields(pShields.LEFT_SHIELDS, pShields.GetMaxShields(pShields.LEFT_SHIELDS) / 1.35)
	pShields.SetCurShields(pShields.TOP_SHIELDS, pShields.GetMaxShields(pShields.TOP_SHIELDS) / 1.35)
	# Do some damage to it's hull
	pZhukov.DamageSystem(pZhukov.GetHull(), 3000)
	
	# Get the Tezle ships
	pTezleSet		= App.g_kSetManager.GetSet("Tezle2")
	pGalor3		= App.ShipClass_GetObject(pTezleSet, "Galor 3")
	pGalor4		= App.ShipClass_GetObject(pTezleSet, "Galor 4")
	pKeldon1	= App.ShipClass_GetObject(pTezleSet, "Keldon 1")
	
	# Give the Tezle 2 ships their AI
	import E6M5_AI_Tezle2
	import E6M5_AI_Galor3
	import E6M5_AI_Keldon1
	pGalor3.SetAI(E6M5_AI_Galor3.CreateAI(pGalor3, g_pCardTargets))
	pGalor4.SetAI(E6M5_AI_Tezle2.CreateAI(pGalor4))
	pKeldon1.SetAI(E6M5_AI_Keldon1.CreateAI(pKeldon1))
		
################################################################################
##	StrikeForceArrivesTezle2()
##
##	Sequence called when the strike force arrives at Tezle2
##
##	Args:	Name
##
##	Return:	Name
################################################################################
def StrikeForceArrivesTezle2():
	# Reset our prod line
	global g_sProdLine
	g_sProdLine = "E6M5ProdToTezle2"
	
	# If the player beat us to Tezle 2, do our contact with them.
	pSet = MissionLib.GetPlayerSet()
	if (pSet.GetName() == "Tezle2"):
		PlayerArrivesTezle2()
		return
		
	YiBridgeSet = App.g_kSetManager.GetSet("YiBridgeSet")

	pYi	= App.CharacterClass_GetObject(YiBridgeSet, "Yi")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Yi")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaLine008	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5L008", "Captain", 1, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "YiBridgeSet", "Yi", 0.2, 0.5)
	pYiLine009		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M5L009", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pAddGoal 		= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E6GoToTezle2Goal")
	pKiskaLine010	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5L010", "Captain", 0, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)
	pAddTezle		= App.TGScriptAction_Create(__name__, "AddTezleSystem")
	pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaLine008, 10)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pYiLine009)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pAddGoal)
	pSequence.AddAction(pKiskaLine010, pAddGoal)
	pSequence.AddAction(pAddTezle, pAddGoal, 0.3)
	pSequence.AppendAction(pStartProdTimer)
	
	pSequence.Play()
	
	# Register GoToTezle2Goal and remove the EngagePrendleCards goal
	MissionLib.RemoveGoal("E6EngagePrendelCardsGoal")
	

################################################################################
##	AddTezleSystem()
##
##	Adds Tezle to the course list
##
##	Args:	pTGAction		- The script action object
##			
##	Return:	0	- Return 0
################################################################################
def AddTezleSystem(pTGAction):
		
	import Systems.Tezle.Tezle
	Systems.Tezle.Tezle.CreateMenus()
	
	return 0
	
################################################################################
##	CardsWarpOut()
##
##	Called by E6M5_AI_Galor1_2.py when  the Cardassians in Prendel leave
##	for tezle.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CardsWarpOut():
	if (g_bCardsWarpPlayed == TRUE):
		return
	global g_bCardsWarpPlayed
	g_bCardsWarpPlayed = TRUE
	# check if the galors lived
	if (g_bGalor1Destroyed == FALSE) or (g_bGalor2Destroyed == FALSE):
		pSequence = App.TGSequence_Create()
		App.TGActionManager_RegisterAction(pSequence, "Galors")
		pKiskaLine		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5CardsWarp1", "Captain", 1, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)
		pMiguelLine		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5CardsWarp2", "Captain", 1, g_pMissionDatabase)
		
		pSequence.AppendAction(pKiskaLine)
		pSequence.AppendAction(pMiguelLine)
		
		pSequence.Play()
	
################################################################################
##	PlayerArrivesTezle2()
##
##	Sequence that plays when player first arrives in Tezle system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesTezle2():
	# set cards to not be invincible now that the player is here
	pGalor3 = App.ShipClass_GetObject(None, "Galor 3")
	if (pGalor3 != None):
		pGalor3.SetInvincible(0)
	pGalor4 = App.ShipClass_GetObject(None, "Galor 4")
	if (pGalor4 != None):
		pGalor4.SetInvincible(0)
	pKeldon1 = App.ShipClass_GetObject(None, "Keldon 1")
	if (pKeldon1 != None):
		pKeldon1.SetInvincible(0)
		
	# Check and see if the Khitomer is actually in this set.
	if (g_bStrikeForceInTezle2 == FALSE) or (g_bPlayerArriveTezle2 == FALSE):
		if (g_bPlayerArriveTezle2 == TRUE):
			# Set our flag so we won't get any dialogue
			# if we go to Prendel
			global g_bPlayerArrivePrendel5
			g_bPlayerArrivePrendel5 = TRUE
			# Make sure to remove this goal if we can here direct from Starbase 12
			MissionLib.RemoveGoal("E6EngagePrendelCardsGoal")
		
		return
	
	# Do the sequence
	pDBridge	= App.g_kSetManager.GetSet("YiBridgeSet")
	pYi			= App.CharacterClass_GetObject(pDBridge, "Yi")
	
	pSequence 		= App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Yi")
	
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "YiBridgeSet", "Yi")

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pYiLine011		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M5L011", None, 0, g_pMissionDatabase)
	pYiLine012		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M5L012", None, 0, g_pMissionDatabase)
	pSaffiHi		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5L045", None, 0, g_pMissionDatabase)
	pYiLine046		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M5L046", None, 0, g_pMissionDatabase)
	pYiLine044		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M5L044", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pDBridgeViewOn, 8)	# 8 sec delay before Yi comes up
	pSequence.AppendAction(pYiLine011)
	pSequence.AppendAction(pYiLine012)
	pSequence.AppendAction(pSaffiHi)
	pSequence.AppendAction(pYiLine046)
	pSequence.AppendAction(pYiLine044)
	pSequence.AppendAction(pViewOff)
	
	pSequence.Play()
	
	# Remove our GoToTezle2Goal add EngageCardsGoal and ProtectKhitomerGoal
	MissionLib.RemoveGoal("E6GoToTezle2Goal")
	MissionLib.AddGoal("E6EngageTezle2CardsGoal")
	MissionLib.AddGoal("E6ProtectKhitomerGoal")
	
################################################################################
##	Tezle2Clear()
##
##	Called by E6M5_AI_Fed.py when all the Cardassians in Tezle 2 have been
##	destroyed.  Lets us know we can head for Tezle 1.
##
##	Args:	None
##
##	Return:	None
################################################################################
def Tezle2Clear():
	if (g_bTezle2ClearCalled == TRUE):
		return
	global g_bTezle2ClearCalled
	g_bTezle2ClearCalled = TRUE
	
	# Change our prod line
	global g_sProdLine
	g_sProdLine = "E6M5ProdToTezle1"
	
	# Get the player's  set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	if (sSetName == "Tezle2"):
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pFelixLine013	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L013", "Captain", 1, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)
		pMiguelLine014	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5L014", "Captain", 1, g_pMissionDatabase)
		pKiskaLine015	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5L015", "Captain", 1, g_pMissionDatabase)
		pKiskaLine016	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5L016", "Captain", 1, g_pMissionDatabase)
		pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pFelixLine013)
		pSequence.AppendAction(pMiguelLine014)
		pSequence.AppendAction(pKiskaLine015)
		pSequence.AppendAction(pKiskaLine016, 1)
		pSequence.AppendAction(pStartProdTimer)
		
		pSequence.Play()
	
	else:
		pSequence = App.TGSequence_Create()
		
		pKiskaLine016	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5L016", "Captain", 1, g_pMissionDatabase)
		pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)
		
		pSequence.AppendAction(pKiskaLine016)
		pSequence.AppendAction(pStartProdTimer)
		
		pSequence.Play()

	# Remove our EngageTezle2Card goal and add GoToTezle1
	MissionLib.RemoveGoal("E6EngageTezle2CardsGoal")
	MissionLib.AddGoal("E6GoToTezle1Goal")
	
################################################################################
##	PlayerArrivesTezle1()
##
##	Called when player arrives in Tezle1 and the Strike Force is there.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesTezle1():
	# Make sure the Strike Force is here to
	if (g_bStrikeForceInTezle1 == FALSE):
		global g_bPlayerInTezleFirst
		g_bPlayerInTezleFirst = TRUE
		return
	
	# Warp event
	import Bridge.BridgeUtils
	pWarpButton = Bridge.BridgeUtils.GetWarpButton() 
	pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	pShuttleSet	= App.g_kSetManager.GetSet("ShuttleSet")
	pWillis		= App.CharacterClass_GetObject(pShuttleSet, "Willis")
	pWillis.SetLocation("ShuttleSeated2")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Willis")
	
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "ShuttleSet", "Willis")
	pWillisLine017	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5L017", None, 0, g_pMissionDatabase)
	pWillisLine018	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5L018", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pDBridgeViewOn, 7)
	pSequence.AppendAction(pWillisLine017)
	pSequence.AppendAction(pWillisLine018)
	pSequence.AppendAction(pViewOff)

	pSequence.Play()
	
	# Remove GoToTezle1Goal
	MissionLib.RemoveGoal("E6GoToTezle1Goal")
	
	# set our g_iMissionPositionCounter to play the correct dialogue
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 3
	
################################################################################
##	CreateFirstCardWave()
##
##	Creates the first wave of Cardassians and start another timer for the
##	second.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def CreateFirstCardWave(TGObject, pEvent):
	# Import the ships needed
	
	# Get the Tezle1 set
	pSet = App.g_kSetManager.GetSet("Tezle1")
	
	# Now create the ships
	pKeldon2	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 2", "Card1Enter")
	pGalor4		= loadspacehelper.CreateShip("Galor", pSet, "Galor 4", "Card3Enter")
	
	# Now give them an AI
	import E6M5_AI_FirstWave
	pKeldon2.SetAI(E6M5_AI_FirstWave.CreateAI(pKeldon2))
	pGalor4.SetAI(E6M5_AI_FirstWave.CreateAI(pGalor4))
	
	# Call our sequence that plays when these guys show up
	FirstWaveArrives()
	
	# Starts timer for the arrival of the first Kessok
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_FIRST_KESSOK_TIMER, __name__+".CreateFirstKessok", fStartTime + 60, 0, 0)

################################################################################
##	FirstWaveArrives()
##
##	Sequence that plays when the first wave of Cardassians arrive.
##
##	Args:	None
##
##	Return:	None
################################################################################
def FirstWaveArrives():
	pSequence = App.TGSequence_Create()
	
	pFelixLine020	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L020", "Captain", 1, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)
	pSaffiLine021	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5L021", "Captain", 1, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)

	pSequence.AddAction(pFelixLine020)
	pSequence.AddAction(pSaffiLine021, pFelixLine020)
	
	pSequence.Play()
	
	# set our g_iMissionPositionCounter so the correct communicate dialogue plays.
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 4

################################################################################
##	KhitLaunchingShuttles()
##
##	Called from E6M5_AI_Khit.py when Khitomer get close to planet. 
##	
##
##	Args:	None
##
##	Return:	None
################################################################################
def KhitLaunchingShuttles():
	# Get the ship
	pShip	= App.ShipClass_GetObject((App.g_kSetManager.GetSet("Tezle1")), "Khitomer")
	if (pShip == None):
		return
		
	pSequence = App.TGSequence_Create()
	
	pSaffiLine019	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5L019", "Captain", 1, g_pMissionDatabase)
	pLaunchShuttle1 = App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", pShip.GetObjID(), "Shuttle 1", App.ObjectEmitterProperty.OEP_SHUTTLE)
	pHandleShuttle1	= App.TGScriptAction_Create(__name__, "HandleShuttle", ["Shuttle 1"])
	pLaunchShuttle2	= App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", pShip.GetObjID(), "Shuttle 2", App.ObjectEmitterProperty.OEP_SHUTTLE)
	pHandleShuttle2	= App.TGScriptAction_Create(__name__, "HandleShuttle", ["Shuttle 2"])
	pLaunchShuttle3	= App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", pShip.GetObjID(), "Shuttle 3", App.ObjectEmitterProperty.OEP_SHUTTLE)
	pHandleShuttle3	= App.TGScriptAction_Create(__name__, "HandleShuttle", ["Shuttle 3"])
	pLaunchShuttle4	= App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", pShip.GetObjID(), "Shuttle 4", App.ObjectEmitterProperty.OEP_SHUTTLE)
	pHandleShuttle4	= App.TGScriptAction_Create(__name__, "HandleShuttle", ["Shuttle 4"])
	
	pSequence.AddAction(pLaunchShuttle1)
	pSequence.AddAction(pHandleShuttle1)
	pSequence.AddAction(pLaunchShuttle2, pHandleShuttle1, 3)
	pSequence.AddAction(pHandleShuttle2, pLaunchShuttle2)
	pSequence.AddAction(pLaunchShuttle3, pHandleShuttle2, 3)
	pSequence.AddAction(pHandleShuttle3, pLaunchShuttle3)
	pSequence.AddAction(pLaunchShuttle4, pHandleShuttle3, 3)
	pSequence.AddAction(pHandleShuttle4, pLaunchShuttle4)
	pSequence.AddAction(pSaffiLine019, pHandleShuttle4)
	
	pSequence.Play()

################################################################################
##	HandleShuttle()
##
##	Takes a list of shuttles and assign's the same generic AI to all of them
##	and adds them to the proximity checks list o' objects.
##
##	Args:	pTGAction		- The script action object
##			lShuttleNames	- List of shuttle names
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def HandleShuttle(pTGAction, lShuttleNames):
	# Get the set
	pSet = App.g_kSetManager.GetSet("Tezle1")
	
	import E6M5_AI_ShuttleLanding
	# Go though the list of shuttles
	for sName in lShuttleNames:
		pShuttle = App.ShipClass_GetObject(pSet, sName)
		
		# This will disable collisions between the two ships.
		pShip = App.ShipClass_GetObject(None, "Khitomer")
		pShip.EnableCollisionsWith(pShuttle, 0)
		
		# Give the shuttle an AI
		pShuttle.SetAI(E6M5_AI_ShuttleLanding.CreateAI(pShuttle))
		
		# Add all the shuttles to the list of objects the proximity
		# check is checking against.
		if (pShuttle != None):
			# Got the shuttle.  Add it to the check list...
			pProximityCheck.AddObjectToCheckList(pShuttle, App.ProximityCheck.TT_INSIDE)
			# The proximity event will now be sent to the object that triggered it (the probe),
			# so we need to add a handler to that object..
			pShuttle.AddPythonFuncHandlerForInstance(ET_PLANET_PROXIMITY, __name__ + ".PlanetProximity")

#		else:
#			kDebugObj.Print("Error: Couldn't find Shuttle (%s) that should have been there.  :(" % sName)
		
	return 0

################################################################################
##	ShuttleReachesPlanet()
##
##	Called if a shuttle triggers the proximity check.  Deletes the Shuttle and
##	increases our counter.
##
##	Args:	pShuttle	- The shuttle that triggered the proximity check.
##
##	Return:	None
################################################################################
def ShuttleReachesPlanet(pShuttle):
	global g_iNumberShuttlesLanded
	# Increase the counter for shuttles landed
	g_iNumberShuttlesLanded	= g_iNumberShuttlesLanded + 1
	
	# Delete the shuttle from the set
	pShuttle.SetDeleteMe(1)
	
	# Check and see if all the shuttles have landed
	if (g_iNumberShuttlesLanded == 4):
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesLanded", None, 0, g_pMissionDatabase)
		pSaffiLine.Play()
		
		# Get the Khit and give it battle AI
		pKhit	= App.ShipClass_GetObject(None, "Khitomer")
		if (pKhit != None):
			import E6M5_AI_Khit_2
			pKhit.SetAI(E6M5_AI_Khit_2.CreateAI(pKhit))
		
################################################################################
##	CreateFirstKessok()
##
##	Creates the first Kessok to appear and play a sequence that goes with it's
##	entrance.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def CreateFirstKessok(TGObject, pEvent):
	# Create the Kessok and give it it's AI
	# Get the Tezle1 set
	pSet = App.g_kSetManager.GetSet("Tezle1")
	# Now create the ship
	pKessok1	= loadspacehelper.CreateShip("KessokLight", pSet, "Kessok 1", "Card2Enter")
	# Now give them an AI
	import E6M5_AI_Kessok1
	pKessok1.SetAI(E6M5_AI_Kessok1.CreateAI(pKessok1))
	
	# Now do our sequence
	pDBridge	= App.g_kSetManager.GetSet("YiBridgeSet")
	pYi			= App.CharacterClass_GetObject(pDBridge, "Yi")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Yi")

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixLine022	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L022", None, 0, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)
	pFelixLine023	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L023", "Captain", 0, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)
	pSaffiLine025	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5L025", None, 0, g_pMissionDatabase, App.CSP_MISSION_CRITICAL)
	pFelixIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", "Captain", 1, g_pGeneralDatabase, App.CSP_MISSION_CRITICAL)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "YiBridgeSet", "Yi")
	pYiLine026		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M5L026", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixLine022)
	pSequence.AppendAction(pFelixLine023)
	pSequence.AppendAction(pSaffiLine025)
	pSequence.AppendAction(pFelixIncoming)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pYiLine026)
	pSequence.AppendAction(pViewOff)
	
	pSequence.Play()
	
	# Start our timer for the arrival of the Second wave of Cardassians
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_CARD_SECOND_WAVE_MASTER_TIMER, __name__+".CreateSecondCardWave", fStartTime + 240, 0, 0)
	
################################################################################
##	CreateSecondCardWave()
##
##	Create the second wave of Cards
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def CreateSecondCardWave(TGObject, pEvent):
	# Check our flag
	if (g_bSecondWaveArriveTezle1 == FALSE):
		global g_bSecondWaveArriveTezle1
		g_bSecondWaveArriveTezle1 = TRUE
	else:
		return
		
	# Import the ships we'll need
	# Get the set
	pSet = App.g_kSetManager.GetSet("Tezle1")
	# Create the ships
	pKessok2 = loadspacehelper.CreateShip("KessokLight", pSet, "Kessok 2", "Card4Enter")
	pKessok3 = loadspacehelper.CreateShip("KessokLight", pSet, "Kessok 3", "Card5Enter")
	pGalor5 = loadspacehelper.CreateShip("Galor", pSet, "Galor 5", "Card6Enter")
	# Set their AI
	import E6M5_AI_SecondWave
	import E6M5_AI_Kessok2
	pKessok2.SetAI(E6M5_AI_Kessok2.CreateAI(pKessok2))
	pKessok3.SetAI(E6M5_AI_SecondWave.CreateAI(pKessok3))
	pGalor5.SetAI(E6M5_AI_SecondWave.CreateAI(pGalor5))
	
	# Call the sequence that announces their arrival
	SecondWaveArrives()
	
################################################################################
##	SecondWaveArrives()
##
##	Sequence that plays when the second wave of Cardassians arrives.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SecondWaveArrives():
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixLine029	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L029", "Captain", 0, g_pMissionDatabase)
	pFelixLine030	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L030", "Captain", 1, g_pMissionDatabase)
	pSaffiLine031	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5L031", None, 0, g_pMissionDatabase)
	pFelixLine032	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5L032", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixLine029)
	pSequence.AppendAction(pFelixLine030)
	pSequence.AppendAction(pSaffiLine031)
	pSequence.AppendAction(pFelixLine032)

	pSequence.Play()
	
	# Remove the ProtectKhitomerGoal
	MissionLib.RemoveGoal("E6ProtectKhitomerGoal")

################################################################################
##	CreateThirdCardWave()
##
##	Creates the third wave of Cardassians
##
##	Args:	TGObject	- The TGObject object
##			pEvent 		- The event that was sent
##
##	Return:	None
################################################################################
def CreateThirdCardWave(TGObject, pEvent):
	# Mark our flag
	global g_bThirdWaveArriveTezle1
	g_bThirdWaveArriveTezle1 = TRUE
	
	# Get the ships needed
	# Get the set
	pSet = App.g_kSetManager.GetSet("Tezle1")
	# Do the placements
	pKessok4 = loadspacehelper.CreateShip("KessokLight", pSet, "Kessok 4", "Card1Enter")
	pKeldon3 = loadspacehelper.CreateShip("Keldon", pSet, "Keldon 3", "Card2Enter")
	pKessok5 = loadspacehelper.CreateShip("KessokLight", pSet, "Kessok 5", "Card3Enter")
	# Set the AI
	import E6M5_AI_Kessok45
	import E6M5_AI_Keldon3
	pKessok4.SetAI(E6M5_AI_Kessok45.CreateAI(pKessok4))
	pKeldon3.SetAI(E6M5_AI_Keldon3.CreateAI(pKeldon3))
	pKessok5.SetAI(E6M5_AI_Kessok45.CreateAI(pKessok5))
	
	# Call the retreat once the Third Wave arrives.
	CallRetreat()
	
	
################################################################################
##	CallRetreat()
##	
##  Called after Third Wave arrives.  Starts timer that needs to run to get
##	the troops of the planet.
##
##	Args: 	None
##	
##	Return: None
################################################################################		
def CallRetreat():
	global g_bYiLastLineSpoken
	g_bYiLastLineSpoken	= TRUE
	# If the Khitomer has been destroyed, don't play
	if (g_bKhitomerDestroyed == TRUE):
		return
		
	pYi = App.CharacterClass_GetObject((App.g_kSetManager.GetSet("YiBridgeSet")), "Yi")
	
	# Do the sequence
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Yi")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaLine036		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M5L036", "Captain", 1, g_pMissionDatabase)
	pViewOn 			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "YiBridgeSet", "Yi")
	pYiLine037			= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M5L037a", None, 0, g_pMissionDatabase)
	pYiLine038 			= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M5L038", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaLine036, 5)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pYiLine037, 0.5)
	pSequence.AppendAction(pYiLine038)
	pSequence.AppendAction(pViewOff)
	
	pSequence.Play()
	
	# set our g_iMissionPositionCounter to not play any communicate.
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 0
	
	# Start the timer that says the troops are off the planet
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SHUTTLES_LAUNCH_TIMER, __name__+".ShuttlesLaunchOffPlanet", fStartTime + 240, 0, 0)
	MissionLib.CreateTimer(ET_SHUTTLES_LAUNCH_TIMER_2, __name__+".ShuttlesLaunchOffPlanet", fStartTime + 245, 0, 0)
	MissionLib.CreateTimer(ET_SHUTTLES_LAUNCH_TIMER_3, __name__+".ShuttlesLaunchOffPlanet", fStartTime + 250, 0, 0)
	MissionLib.CreateTimer(ET_SHUTTLES_LAUNCH_TIMER_4, __name__+".ShuttlesLaunchOffPlanet", fStartTime + 255, 0, 0)


################################################################################
##	CreateLastWave()
##
##	Creates the Last wave of Cardassians
##
##	Args:	TGObject	- The TGObject object
##			pEvent 		- The event that was sent
##
##	Return:	None
################################################################################
def CreateLastWave(TGObject, pEvent):
	
	# Get the ships needed
	# Get the set
	pSet = App.g_kSetManager.GetSet("Tezle1")
	# Do the placements
	pKessok6 = loadspacehelper.CreateShip("KessokLight", pSet, "Kessok 6", "Card1Enter")
	pKessok7 = loadspacehelper.CreateShip("KessokLight", pSet, "Kessok 7", "Card2Enter")
	pKeldon4 = loadspacehelper.CreateShip("Keldon", pSet, "Keldon 4", "Card3Enter")
	
	# Set the AI
	import E6M5_AI_Kessok1
	if (pKessok6 != None):
		pKessok6.SetAI(E6M5_AI_Kessok1.CreateAI(pKessok6))
	if (pKessok7 != None):
		pKessok7.SetAI(E6M5_AI_Kessok1.CreateAI(pKessok7))
	if (pKeldon4 != None):
		pKeldon4.SetAI(E6M5_AI_Kessok1.CreateAI(pKeldon4))
	
	pFelixMoreShips	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "Incoming6", "Captain", 1, g_pGeneralDatabase)
	pFelixMoreShips.Play()

################################################################################
##	ShuttlesLaunchOffPlanet()
##
##	Called from timer started in CallRetreat().  Has Shuttles "take off" from
##	planet.  This function should be called 4 times by the 
##	ET_SHUTTLES_LAUNCH_TIMER.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ShuttlesLaunchOffPlanet(TGObject, pEvent):
	# Get the shuttle model and our set
	pSet	= App.g_kSetManager.GetSet("Tezle1")
	
	# If our number of shuttles landed is greater than zero, do create one
	if (g_iNumberShuttlesLanded > 0):
		# Create our shuttle using the g_iNumberShuttlesLanded global to name them
		pShuttle	= loadspacehelper.CreateShip("Shuttle", pSet, "Shuttle " + str(g_iNumberShuttlesLanded), "ShuttleLaunchPoint")
		# Get our AI and assign it
		import E6M5_AI_ShuttleEscape
		pShuttle.SetAI(E6M5_AI_ShuttleEscape.CreateAI(pShuttle, "Shuttle"+str(g_iNumberShuttlesLanded)+"Enter"))
		
		# Damage the shuttles a little
		if (g_iNumberShuttlesLanded == 4):
			pShuttle.DamageSystem(pShuttle.GetHull(), 300)
		if (g_iNumberShuttlesLanded == 3):
			pShuttle.DamageSystem(pShuttle.GetHull(), 500)
		if (g_iNumberShuttlesLanded == 2):
			pShuttle.DamageSystem(pShuttle.GetHull(), 150)
		if (g_iNumberShuttlesLanded == 1):
			pShuttle.DamageSystem(pShuttle.GetHull(), 75)
			pShuttle.DamageSystem(pShuttle.GetPowerSubsystem(), 100)
					
		# Now decrease our counter
		global g_iNumberShuttlesLanded
		g_iNumberShuttlesLanded = g_iNumberShuttlesLanded - 1
		
		# If g_iNumberShuttlesLanded equals 0, than there all off...
		if (g_iNumberShuttlesLanded == 0):
			AllShuttlesOffPlanet()
			
################################################################################
##	AllShuttlesOffPlanet()
##
##	Playes a sequence from Willis telling the player the shuttles are off the
##	planet.
##
##	Args:	None
##
##	Return:	None
################################################################################
def AllShuttlesOffPlanet():
	pShuttleSet	= App.g_kSetManager.GetSet("ShuttleSet")
	pWillis		= App.CharacterClass_GetObject(pShuttleSet, "Willis")
	pWillis.SetLocation("ShuttleSeated2")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Willis")
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelShuttlesOff1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesOffPlanet1", "Captain", 0, g_pMissionDatabase)
	pMiguelShuttlesOff2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesOffPlanet2", "Captain", 1, g_pMissionDatabase)
	pShuttleViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "ShuttleSet", "Willis", 0, 0.3)
	pWillisShuttlesOff3	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesOffPlanet3", None, 0, g_pMissionDatabase)
	pWillisShuttlesOff4	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesOffPlanet4", None, 0, g_pMissionDatabase)
	pWillisShuttlesOff5	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesOffPlanet5", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelShuttlesOff1)
	pSequence.AppendAction(pMiguelShuttlesOff2)
	pSequence.AppendAction(pShuttleViewOn)
	pSequence.AppendAction(pWillisShuttlesOff3)
	pSequence.AppendAction(pWillisShuttlesOff4)
	pSequence.AppendAction(pWillisShuttlesOff5)
	pSequence.AppendAction(pViewOff)
	
	pSequence.Play()
	
	# Add our ProtectShuttlesGoal
	MissionLib.AddGoal("E6ProtectShuttlesGoal")

################################################################################
##	ShuttlesEscape()
##
##	Called from EnterSet when 3 shuttles reach Tezle 2.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ShuttlesEscape():
#	kDebugObj.Print ("Shuttles escpaed, playing dialogue and calling ResetFedAIs")

	# Reset our prod line
	global g_sProdLine
	g_sProdLine = "E6M5ProdToBeol"

	# Remove the ProtectShuttles and add HeadToBeol
	MissionLib.RemoveGoal("E6ProtectShuttlesGoal")
	MissionLib.AddGoal("E6HeadToBeolGoal")
	
	# pull out the Prendel system
	pKiskaMenu = g_pKiska.GetMenu()
	pSetCourse = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
	pPrendel = pSetCourse.GetSubmenu("Prendel")
	pSetCourse.DeleteChild(pPrendel)
	
	# Add Beol to the set course list
	import Systems.Beol.Beol
	Systems.Beol.Beol.CreateMenus()

	pSequence = App.TGSequence_Create()
	
	pPreLoad				= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelShuttlesWarp1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesWarpOut1", "Captain", 1, g_pMissionDatabase)
	pSaffiShuttlesWarp2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5ShuttlesWarpOut2", "Captain", 1, g_pMissionDatabase)
	pResetFedAIs			= App.TGScriptAction_Create(__name__, "ResetFedAIs")
	pStartProdTimer			= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelShuttlesWarp1)
	pSequence.AppendAction(pSaffiShuttlesWarp2)
	pSequence.AppendAction(pResetFedAIs)
	pSequence.AppendAction(pStartProdTimer)
	
	MissionLib.QueueActionToPlay(pSequence)
	

#
# WarpHandler()
#
def WarpHandler(pObject, pEvent):
	pWarpButton = App.STWarpButton_Cast(pEvent.GetDestination())
	pcDest	 	= pWarpButton.GetDestination()
	# Get the player's  set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	if (pcDest != "Systems.Beol.Beol4") and (g_bShuttlesInBeol == TRUE) and (sSetName == "Tezle1"):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M5ProdToBeol", None, 0, g_pMissionDatabase)
		pAction.Play()
	
		return
	
	elif (pcDest != "Systems.Beol.Beol4") and (g_bStrikeForceInTezle1 == TRUE) and (sSetName == "Tezle1"):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "WarpStop2", None, 0, g_pGeneralDatabase)
		pAction.Play()
	
		return
	
	if (pcDest == "Systems.Beol.Beol4"):
		# Stop the prod timer.
		StopProdTimer()
		
		global g_bPlayerArriveBeol
		g_bPlayerArriveBeol = TRUE
		
		# Load lighting for warp set
		# Ensure that the warp set is created.
		App.WarpSequence_GetWarpSet()
		import Warp_P
		Warp_P.LoadPlacements("warp")

		# Redirect warp to Starbase 12 and setup load for Episode 7
		pWarpButton.SetDestination("Systems.Starbase12.Starbase12",
								   "Maelstrom.Episode7.E7M1.E7M1", 
								   "Player Start", "Maelstrom.Episode7.Episode7")

		# Play the Episode 7 cutscene in the warp set
		pSequence = Episode7Cutscene()
		pWarpButton.AddActionBeforeDuringWarp(pSequence)

	pObject.CallNextHandler(pEvent)


#
#	Episode7Cutscene() - Saffi's personal log and Liu's briefing for the start of Episode 7
#
def Episode7Cutscene():

	# Load custom placements for bridge.
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	import Maelstrom.Episode7.E7M1.EBridge_P
	Maelstrom.Episode7.E7M1.EBridge_P.LoadPlacements(pBridgeSet.GetName())

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 7/E7M1.tgl")

	pLiuSet = App.g_kSetManager.GetSet("StarbaseSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Cutscene")
	
	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "UnhidePlayer")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "warp")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "warp")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "warp", "player")
	pSequence.AppendAction(pAction)

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeOut", 0))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeIn", 3))

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EpisodeTitleAction", "Ep7Title"))

	pAction = App.TGScriptAction_Create("MissionLib", "TextBanner", pDatabase.GetString("EnrouteToBeol"), 0, .15)
	pSequence.AppendAction(pAction, 6)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E7M1SaffiLog1", "Saffi")
	pSequence.AppendAction(pAction, 3)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E7M1SaffiLog2", "Saffi")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "warp")	
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "HidePlayer")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "SaffiWatchLMed", "SaffiCamLMed", 1)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E7M1SaffiLog3", "Saffi")
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction)
	pAction3 = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E7M1SaffiLog4", "Saffi")
	pSequence.AddAction(pAction3, pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E7M1SaffiLog5", "Saffi")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E7M1SaffiLog6", "Saffi")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1BeingHailed1", "Captain", 1, pDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1BeingHailed2", "Helm", 1, pDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Briefing1", None, 0, pDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Briefing2", None, 0, pDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Briefing3", None, 0, pDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Briefing4", None, 0, pDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M1Briefing5", None, 0, pDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1ChangeCourse1", "Helm", 1, pDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1ChangeCourse2", None, 0, pDatabase)
	pSequence.AppendAction(pAction2)
	pAction3 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction3, pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)

	if(pDatabase):
		App.g_kLocalizationManager.Unload(pDatabase)

	return pSequence


#
# HidePlayer() - makes the player invisible in the warp set
#
def HidePlayer(pAction):
	pPlayer = MissionLib.GetPlayer()
	pPlayer.SetHidden(1)

	return 0

#
# UnhidePlayer() - makes the player visible in the warp set
#
def UnhidePlayer(pAction):
	pPlayer = MissionLib.GetPlayer()
	pPlayer.SetHidden(0)

	return 0

################################################################################
##	ResetFedAIs()
##
##	Called as script action.  Resets all Federation ship AIs so they warp out
##	of system to Beol 4.
##
##	Args:	pAction	- The action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetFedAIs(pAction):
#	kDebugObj.Print ("resetting the fed AIs")
	
	# Import the AI
	import E6M5_AI_Fed_WarpToBeol
	
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Tezle1")
	# Assign the AI to ships that haven't been destroyed
	if (g_bZhukovDestroyed == FALSE):
#		kDebugObj.Print ("resetting zhukov AI")
		pShip	= App.ShipClass_GetObject(pSet, "Zhukov")
		pShip.SetAI(E6M5_AI_Fed_WarpToBeol.CreateAI(pShip, "ZhukovEnter"))
		
	if (g_bKhitomerDestroyed == FALSE):
#		kDebugObj.Print ("resetting khitomer AI")
		pShip	= App.ShipClass_GetObject(pSet, "Khitomer")
		pShip.SetAI(E6M5_AI_Fed_WarpToBeol.CreateAI(pShip, "KhitEnter"))
	
	# Have to handle the escort ship a little different...
	pShip = App.ShipClass_GetObject(pSet, g_sFedEscortName)
	if (pShip != None):
#		kDebugObj.Print ("resetting fed escort AI")
		pShip.SetAI(E6M5_AI_Fed_WarpToBeol.CreateAI(pShip, "FedEnter"))
		
	return 0
	
################################################################################
##	MissionLostTezle2()
##
##	Called Khitomer haves been destroyed in Tezle2.
##	
##
##	Args:	None
##
##	Return:	None
################################################################################
def MissionLostTezle2():
	App.TGActionManager_KillActions()	
	# Do the sequence stuff
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg2", None, 0, g_pGeneralDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuTezleLoss1	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M5LiuTezleLoss1", None, 0, g_pMissionDatabase)
	pLiuTezleLoss2	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M5LiuTezleLoss2", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixIncoming, 5)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuTezleLoss1)
	pSequence.AppendAction(pLiuTezleLoss2)
	pSequence.AppendAction(pViewOff)
	
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()

################################################################################
##	MissionLostTezle1()
##
##	Called if Khitomer is destroyed in Tezle 1.
##
##	Args:	None
##
##	Return:	None
################################################################################
def MissionLostTezle1():
	App.TGActionManager_KillActions()	
	# Set up sequence stuff
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixIncoming	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "gt029", "Captain", 1, g_pGeneralDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLossLine1	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M5LiuLoss1", None, 0, g_pMissionDatabase)
	pLiuLossLine2	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M5LiuLoss2", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixIncoming, 5)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuLossLine1)
	pSequence.AppendAction(pLiuLossLine2)
	pSequence.AppendAction(pViewOff)
	
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()


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
	# Get the player and the set their in
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	# Check the prod line, see which one to play and make
	# sure we don't play it when it's not needed
	if (g_sProdLine == "E6M5ProdToPrendel5") and (g_bPlayerArrivePrendel5 == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 20)
	if (g_sProdLine == "E6M5ProdToTezle2") and (g_bPlayerArriveTezle2 == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 15)
	if (g_sProdLine == "E6M5ProdToTezle1") and (g_bPlayerArriveTezle1 == FALSE) and (sSetName != "Tezle1"):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 15)
	if (g_sProdLine == "E6M5ProdToBeol") and (g_bPlayerArriveBeol == FALSE) and (g_bShuttlesInBeol == TRUE):
#		kDebugObj.Print ("Proding player to Beol")
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 15)

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
##	Terminate()
##	
##  Called when mission ends to free resources
##	
##	Args: pMission - the mission object
##	
##	Return: None
################################################################################
def Terminate(pMission):
#	kDebugObj.Print ("Terminating Episode 6, Mission 5.\n")
	# Mission is terminating, so lets set our flag
	global g_bMissionTerminate
	g_bMissionTerminate = TRUE

	# Remove all our mission goal
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
	
	# Remove instance handler for Kiska's Hail button
	pMenu = g_pKiska.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")	
	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
			
	pSciMenu	= g_pMiguel.GetMenu()
	pSciMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	
	# Remove instance handler on players ship for Weapon Fired event
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.RemoveHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")
	
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")
	
	pMenu = g_pSaffi.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
	pMenu = g_pFelix.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = g_pKiska.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = g_pMiguel.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = g_pBrex.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
