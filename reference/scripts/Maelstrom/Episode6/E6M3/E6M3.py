###############################################################################
#	Filename:	E6M3.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 6, Mission 3
#	
#	Created:	12/20/00 -	Jess VanDerwalker (updated)
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Episode6.Episode6
import Bridge.BridgeUtils

# For debug output
#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading Episode 6 Mission 3 definition...\n')


# Global variables
TRUE	= 1
FALSE	= 0

g_bMissionTerminate	= None

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None
g_pDatabase			= None

g_pProximityCheck	= None

g_iProdTimer	= None
g_sProdLine		= None

g_bPlayerArriveSavoy3	= None
g_bPlayerArriveSavoy1	= None

g_bStrikeForceArriveSavoy3	= None
g_bTransportsArrived		= None
g_bFirstCardLinePlayed		= None
g_bKhitGoesToStation		= None
g_bAllCardsWarp				= None

g_bVentureDestroyed		= None
g_bSFDestroyed			= None
g_bDevoreDestroyed		= None
g_bStationDestroyed		= None
g_bKhitomerDestroyed	= None

g_bTransportsIdentified	= None

g_iNumberTransportsDestroyed	= None
g_iNumberCardsDestroyed			= None
g_iShuttleAtStationCounter		= None
g_iCardsWarpToSavoy				= None
g_iMissionPositionCounter		= None

g_bAllTransportsDestroyed	= None
g_bTransportsLandingTroopsCalled	= None
g_bAllOtherCardsDestroyed	= None
g_bKhitomerHailed			= None
g_bLiuFinished				= None

g_lFedShipNames		= []
g_lCardShipNames	= []
g_lSavoy3CardShipNames	= []
g_lTransportNames	= []
g_lShuttleNames		= []
g_lFriendlyShips	= []
					
# Target list globals
g_pSavoy3GalorTargets	= None
g_pSavoy3FedsTargets	= None
g_pSavoy1FedsTargets	= None
g_pSavoy1Transports		= None

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None

# Event types for mission
ET_PROD_TIMER				= App.Mission_GetNextEventType()
ET_TRANSPORT_TIMER			= App.Mission_GetNextEventType()
ET_TROOPS_TIMER				= App.Mission_GetNextEventType()
ET_RECHECK_TRANSPORT_TIMER	= App.Mission_GetNextEventType()
ET_STATION_PROXIMITY		= App.Mission_GetNextEventType()

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
	loadspacehelper.PreloadShip("Nebula", 2)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("SpaceFacility", 1)
	loadspacehelper.PreloadShip("Galaxy", 2)
	loadspacehelper.PreloadShip("Akira", 1)
	loadspacehelper.PreloadShip("Galor", 4)
	loadspacehelper.PreloadShip("Keldon", 4)
	loadspacehelper.PreloadShip("CardFreighter", 2)
	loadspacehelper.PreloadShip("Shuttle", 3)

################################################################################
##	Initialize()
##	
##  Called to initialize mission when it first loads.
##	
##	Args: 	pMission	- The mission object
##
##	Return: None
################################################################################
def Initialize(pMission):
	"Event handler called on episode start.  Create the episode objects here."
#	kDebugObj.Print ("Initializing Episode 6, Mission 3.\n")
	
	# Initialize our global variables
	InitializeGlobals(pMission)
	
	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")
	
	# Create needed viewscreen sets
	pLBridgeSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu		= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)

	pFedOutpostSet	= MissionLib.SetupBridgeSet("FedOutpostSet", "data/Models/Sets/FedOutpost/fedoutpost.nif", -30, 65, -1.55)
	pGraff			= MissionLib.SetupCharacter("Bridge.Characters.Graff", "FedOutpostSet")
	
	# Since Willis is used most (and he has a Nebula) we replace the texture right off and have Yi replace it
	# back to the Galaxy the one time he shows up.
	pDBridgeSet	= MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -30, 65, -1.55)
	MissionLib.ReplaceBridgeTexture(None, "DBridgeSet", "Map 7.tga", "data/Models/Sets/DBridge/NebulaLCARS.tga")
	pWillis		= MissionLib.SetupCharacter("Bridge.Characters.Willis", "DBridgeSet")
	
	# Martin and the E-bridge set
	pEBridgeSet	= MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif", -30, 65, -1.55)
	pMartin 	= MissionLib.SetupCharacter("Bridge.Characters.Martin", "EBridgeSet")
	
	
	#set the diffucultly level - easy Offense, Defense, med O, D, Hard O, D
	App.Game_SetDifficultyMultipliers(1.2, 1.1, 1.0, 1.0, 0.8, 0.8)
	
	# Create the regions that we'll need
	# We'll also do our placement stuff from inside this function
	CreateRegions()
	
	# Import all the ships we'll be using and place them
	# and return the "player" object.
	CreateStartingObjects(pMission)
	
	# Get the Savoy Station shuttle bay so we can create a
	# proximity check around it
	GetShuttleBayLocation()

	# Initialize global pointer to all the 5 bridge crew members
	InitializeCrewPointers()

	# Create menus available at mission start
	CreateStartingMenus()
	
	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()
	
	# Setup more mission-specific events.
	SetupEventHandlers()

	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	
	# Save the Game
	MissionLib.SaveGame("E6M3-")
	
################################################################################
##	InitializeGlobals()
##
##	Initialize our global variables to their starting defaults.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
#	kDebugObj.Print("Initializing global variables")
	
	# Globals used with bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0

	# Flag for when mission is terminating
	global g_bMissionTerminate 
	g_bMissionTerminate	= FALSE

	# Global for TGL database stuff
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 6/E6M3.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	
	# Global pointer to proximity check
	global g_pProximityCheck
	g_pProximityCheck	= None

	# Globals used in prodding
	global g_iProdTimer
	global g_sProdLine
	g_iProdTimer	= 0
	g_sProdLine		= "E6M3ProdToSavoy3"

	# Flags to track player
	global g_bPlayerArriveSavoy3
	global g_bPlayerArriveSavoy1
	g_bPlayerArriveSavoy3	= FALSE
	g_bPlayerArriveSavoy1	= FALSE

	# Flag to track strike force
	global g_bStrikeForceArriveSavoy3
	global g_bTransportsArrived
	global g_bFirstCardLinePlayed
	global g_bKhitGoesToStation
	global g_bAllCardsWarp
	g_bStrikeForceArriveSavoy3	= FALSE
	g_bTransportsArrived		= FALSE
	g_bFirstCardLinePlayed		= FALSE
	g_bKhitGoesToStation		= FALSE
	g_bAllCardsWarp				= FALSE

	# Flags for Federation ships
	global g_bStationDestroyed
	global g_bKhitomerDestroyed
	g_bStationDestroyed		= FALSE
	g_bKhitomerDestroyed	= FALSE

	# Set our values for g_bSFDestroyed, bVenturedDestroyed, and g_bDevoreDestroyed based
	# on Episode level variables
	global g_bVentureDestroyed
	global g_bSFDestroyed
	global g_bDevoreDestroyed
	g_bVentureDestroyed = Maelstrom.Episode6.Episode6.IsVentureDestroyed()
	g_bSFDestroyed		= Maelstrom.Episode6.Episode6.IsSFDestroyed()
	g_bDevoreDestroyed	= Maelstrom.Episode6.Episode6.IsDevoreDestroyed()

	# Mission event plags
	global g_bTransportsIdentified
	global g_bAllTransportsDestroyed
	global g_bTransportsLandingTroopsCalled
	global g_bAllOtherCardsDestroyed
	global g_bKhitomerHailed
	global g_bLiuFinished
	g_bTransportsIdentified		= FALSE
	g_bAllTransportsDestroyed	= FALSE
	g_bTransportsLandingTroopsCalled	= FALSE
	g_bAllOtherCardsDestroyed	= FALSE
	g_bKhitomerHailed			= FALSE
	g_bLiuFinished				= FALSE
	
	# Global counters
	global g_iNumberTransportsDestroyed
	global g_iNumberCardsDestroyed
	global g_iShuttleAtStationCounter
	global g_iCardsWarpToSavoy
	global g_iMissionPositionCounter
	g_iNumberTransportsDestroyed	= 0
	g_iNumberCardsDestroyed			= 0
	g_iShuttleAtStationCounter		= 0
	g_iCardsWarpToSavoy				= 0
	g_iMissionPositionCounter		= 0

	# Lists of ship names
	global g_lFedShipNames
	g_lFedShipNames	= 	[
						"player", "Khitomer", "San Francisco", "Devore", "Venture", "Nightingale"
						]
	
	global g_lCardShipNames
	g_lCardShipNames	=	[
							"Galor 1", "Galor 2", "Galor 3", "Galor 4", "Keldon 1", "Keldon 2",
							"Keldon 3", "Keldon 4"
							]
	
	global g_lSavoy3CardShipNames
	g_lSavoy3CardShipNames	=	[
							"Galor 1", "Galor 2", "Keldon 1", 
							]
	
	global g_lTransportNames
	g_lTransportNames	=	[
							"Transport 1", "Transport 2"
							]

	global g_lShuttleNames
	g_lShuttleNames	=	[
						"Shuttle 1", "Shuttle 2", "Shuttle 3"
						]
	# Global lists of ship names
	global g_lFriendlyShips
	g_lFriendlyShips =	[
						"Starbase 12", "Khitomer", "San Francisco", "Devore", "Venture", "Nightingale", "Shuttle 1", "Shuttle 2", "Shuttle 3"
						]
	# Target list globals
	global g_pSavoy3GalorTargets
	global g_pSavoy3FedsTargets
	global g_pSavoy1FedsTargets
	global g_pSavoy1Transports
	g_pSavoy3GalorTargets	= None
	g_pSavoy3FedsTargets	= None
	g_pSavoy1FedsTargets	= None
	g_pSavoy1Transports		= None
	
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
##	
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
	# Savoy3 system
	import Systems.Savoy.Savoy3
	Systems.Savoy.Savoy3.Initialize()
	pSavoy3Set = Systems.Savoy.Savoy3.GetSet()
	# Savoy 1 system
	import Systems.Savoy.Savoy1
	Systems.Savoy.Savoy1.Initialize()
	pSavoy1Set = Systems.Savoy.Savoy1.GetSet()
	# Deep Space (somewhere the Nightingale can warp out of)
	import Systems.DeepSpace.DeepSpace
	Systems.DeepSpace.DeepSpace.Initialize()
	pDeepSpaceSet = Systems.DeepSpace.DeepSpace.GetSet()
	
	# Get the Bridge for the cutscene
	pBridge = App.g_kSetManager.GetSet("bridge")
		
	# Load our mission specific placements
	import E6M3_Starbase_P
	import E6M3_Savoy3_P
	import E6M3_Savoy1_P
	import E6M3_EBridge_P
	
	E6M3_Starbase_P.LoadPlacements(pStarbaseSet.GetName())
	E6M3_Savoy3_P.LoadPlacements(pSavoy3Set.GetName())
	E6M3_Savoy1_P.LoadPlacements(pSavoy1Set.GetName())
	E6M3_EBridge_P.LoadPlacements(pBridge.GetName())
	
################################################################################
##	CreateStartingMenus()
##	
##  Creates menus for systems in "Helm"
##	
##	Args:	None
##	
##	Return: None
################################################################################
def CreateStartingMenus():
	import Systems.Starbase12.Starbase
	Systems.Starbase12.Starbase.CreateMenus()
	
	# pull out the systems from E6M2 out so the user doesn't go there too soon.
	pKiskaMenu = g_pKiska.GetMenu()
	pSetCourse = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
		
	pGeble = pSetCourse.GetSubmenu("Geble")
	pSetCourse.DeleteChild(pGeble)
	pSerris = pSetCourse.GetSubmenu("Serris")
	pSetCourse.DeleteChild(pSerris)

################################################################################
##	LinkMenuToPlacement()
##
##	Links one of the helm menu buttons to a placement other than the defalut
##	"Player Start".
##
##	Args:	None
##
##	Return:	None
################################################################################
def LinkMenuToPlacement():
	# Get the warp menu
	pSet	= App.g_kSetManager.GetSet("bridge")
	pKiska	= App.CharacterClass_GetObject(pSet, "Helm")
	pMenu	= pKiska.GetMenu()

	# get the System menu.
	pSetCourseMenu	= pMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
	pSavoySystem 	= pSetCourseMenu.GetSubmenu("Savoy")
	pSavoy1Menu		= App.SortedRegionMenu_Cast(pSavoySystem.GetSubmenu("Savoy 1"))
	# Set the placement that this system will be linked to.
	pSavoy1Menu.SetPlacementName("PlayerEnterSavoy1")

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
	SetUpObjectAffiliations(pMission)
	
	# Get the sets we need
	pStarbaseSet 	= App.g_kSetManager.GetSet("Starbase12")
	pDeepSpaceSet	= App.g_kSetManager.GetSet("DeepSpace")
	pSavoy3Set		= App.g_kSetManager.GetSet("Savoy3")
	pSavoy1Set		= App.g_kSetManager.GetSet("Savoy1")
	
	# Place the players ship
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pStarbaseSet, "player", "Player Start")
	# Place the Nightingale in Deep Space so it can warp in
	pNight	= loadspacehelper.CreateShip("Nebula", pDeepSpaceSet, "Nightingale", "NightStart")
	pNight.ReplaceTexture("data/Models/SharedTextures/FedShips/Nightingale.tga", "ID")
	# Place the other starting objects and ships
	pStarbase12 	= loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	pKhitomer		= loadspacehelper.CreateShip("Nebula", pStarbaseSet, "Khitomer", "KhitStart")
	pKhitomer.ReplaceTexture("data/Models/SharedTextures/FedShips/Khitomer.tga", "ID")
	pSavoyStation	= loadspacehelper.CreateShip("SpaceFacility", pSavoy1Set, "Savoy Station", "Station Location")
	
	# Import the Station AI and assign it
	import E6M3_AI_Station
	pSavoyStation.SetAI(E6M3_AI_Station.CreateAI(pSavoyStation))
	
	# Turn off the Night's shields
	pNight.SetAlertLevel(App.ShipClass.GREEN_ALERT)
	
	# Turn off the station's shields
	pSavoyStation.SetAlertLevel(App.ShipClass.GREEN_ALERT)
	
	# Check and see if SF, Venture, and Devore still exist, and if so create them
	import E6M3_AI_Stay
	if (g_bVentureDestroyed == FALSE):
		pVenture = loadspacehelper.CreateShip("Galaxy", pStarbaseSet, "Venture", "VentureStart")
		pVenture.ReplaceTexture("data/Models/SharedTextures/FedShips/Venture.tga", "ID")
		pVenture.SetAI(E6M3_AI_Stay.CreateAI(pVenture))
	if (g_bSFDestroyed == FALSE):
		pSanFrancisco = loadspacehelper.CreateShip("Galaxy", pStarbaseSet, "San Francisco", "SFStart")
		pSanFrancisco.ReplaceTexture("data/Models/SharedTextures/FedShips/SanFrancisco.tga", "ID")
		pSanFrancisco.SetAI(E6M3_AI_Stay.CreateAI(pSanFrancisco))
	if (g_bDevoreDestroyed == FALSE):
		pDevore	= loadspacehelper.CreateShip("Akira", pStarbaseSet, "Devore", "DevoreStart")
		pDevore.ReplaceTexture("Data/Models/Ships/Akira/Devore.tga", "ID")
		pDevore.SetAI(E6M3_AI_Stay.CreateAI(pDevore))

	# Create the Savoy 3 Galors
	pGalor1		= loadspacehelper.CreateShip("Galor", pSavoy3Set, "Galor 1", "Galor1Start")
	pGalor2		= loadspacehelper.CreateShip("Galor", pSavoy3Set, "Galor 2", "Galor2Start")
	pKeldon1	= loadspacehelper.CreateShip("Keldon", pSavoy3Set, "Keldon 1", "Keldon1Start")

	# Make these ship's impulse and warp engines invincibale so they can escape.
#	kDebugObj.Print ("Making Impulse and Warp Engines invincible.")
	pWarp1 = pGalor1.GetWarpEngineSubsystem()
	pImpulse1 = pGalor1.GetImpulseEngineSubsystem()
	if (pWarp1 and pImpulse1):
		MissionLib.MakeSubsystemsInvincible(pImpulse1, pWarp1)

	pWarp2 = pGalor2.GetWarpEngineSubsystem()
	pImpulse2 = pGalor2.GetImpulseEngineSubsystem()
	if (pWarp2 and pImpulse2):
		MissionLib.MakeSubsystemsInvincible(pImpulse2, pWarp2)
		
	pWarp3 = pKeldon1.GetWarpEngineSubsystem()
	pImpulse3 = pKeldon1.GetImpulseEngineSubsystem()
	if (pWarp3 and pImpulse3):
		MissionLib.MakeSubsystemsInvincible(pImpulse3, pWarp3)
		
	# Import the AIs and assign them
	import E6M3_AI_Cards_Savoy3
	pGalor1.SetAI(E6M3_AI_Cards_Savoy3.CreateAI(pGalor1, "Galor1Enter"))
	pGalor2.SetAI(E6M3_AI_Cards_Savoy3.CreateAI(pGalor2, "Galor2Enter"))
	pKeldon1.SetAI(E6M3_AI_Cards_Savoy3.CreateAI(pKeldon1, "Keldon1Enter"))

	# Give the Nightingale it's AI that will warp it into the set.
	import E6M3_AI_Night
	pNight.SetAI(E6M3_AI_Night.CreateAI(pNight))
	
################################################################################
##	SetUpObjectAffiliations()
##
##	Sets up the affiliations of objects in the enemies, neutral, and friendly
##	groups.  Also sets up groups to be used in AI's for target lists.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def SetUpObjectAffiliations(pMission):
		
		pFriendlies = pMission.GetFriendlyGroup()
		pFriendlies.AddName("player")
		pFriendlies.AddName("Starbase 12")
		pFriendlies.AddName("Khitomer")
		pFriendlies.AddName("San Francisco")
		pFriendlies.AddName("Devore")
		pFriendlies.AddName("Venture")
		pFriendlies.AddName("Savoy Station")
		pFriendlies.AddName("Nightingale")
		for sShuttleName in g_lShuttleNames:
			pFriendlies.AddName(sShuttleName)
		
		
		pEnemies = pMission.GetEnemyGroup()
		for sShipName in g_lCardShipNames:
			pEnemies.AddName(sShipName)
		for sTransName in g_lTransportNames:
			pEnemies.AddName(sTransName)
			
		# Set up the target lists
		global g_pSavoy3GalorTargets
		g_pSavoy3GalorTargets = App.ObjectGroup()
		for sShipName in g_lFedShipNames:
			g_pSavoy3GalorTargets.AddName(sShipName)
		
		global g_pSavoy3FedsTargets
		g_pSavoy3FedsTargets = App.ObjectGroup()
		g_pSavoy3FedsTargets.AddName("Galor 1")
		g_pSavoy3FedsTargets.AddName("Galor 2")
		g_pSavoy3FedsTargets.AddName("Keldon 1")
		g_pSavoy3FedsTargets.AddName("Keldon 2")
		g_pSavoy3FedsTargets.AddName("Galor 3")
		
		global g_pSavoy1FedsTargets
		g_pSavoy1FedsTargets = App.ObjectGroup()
		for sShipName in g_lCardShipNames:
			g_pSavoy1FedsTargets.AddName(sShipName)
		
		global g_pSavoy1Transports
		g_pSavoy1Transports = App.ObjectGroup()
		for sShipName in g_lTransportNames:
			g_pSavoy1Transports.AddName(sShipName)
		
################################################################################
##	GetShuttleBayLocation()
##
##	Gets the shuttle emitter on the Savoy Station and creates a proximity check
##	around it so we can have shuttles fly into it.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GetShuttleBayLocation():
	# Get the shuttle bay off the station
	pSet = App.g_kSetManager.GetSet("Savoy1")
	pStation = App.ShipClass_GetObject(pSet, "Savoy Station")
	pPropSet = pStation.GetPropertySet()
	pEmitterInstanceList = pPropSet.GetPropertiesByType(App.CT_OBJECT_EMITTER_PROPERTY)

	pEmitterInstanceList.TGBeginIteration()
	iNumItems = pEmitterInstanceList.TGGetNumItems()

	pLaunchProperty = None

	for i in range(iNumItems):
		pInstance = pEmitterInstanceList.TGGetNext()

		# Check to see if the property for this instance is a shuttle
		# emitter point.
		pProperty = App.ObjectEmitterProperty_Cast(pInstance.GetProperty())
		if (pProperty != None):
			if (pProperty.GetEmittedObjectType() == App.ObjectEmitterProperty.OEP_SHUTTLE):
				pLaunchProperty = pProperty
				break

	if (pLaunchProperty != None):
		# We found a valid launch bay. Find its location in world space.
		pRotation = pStation.GetWorldRotation()

		pPosition = pLaunchProperty.GetPosition()
		pPosition.MultMatrixLeft(pRotation)
		pPosition.Add(pStation.GetWorldLocation())
		# Feed our position into a proximity check
		CreateProximityCheck(pPosition)

	pEmitterInstanceList.TGDoneIterating()
	pEmitterInstanceList.TGDestroy()


################################################################################
##	CreateProximityCheck()
##
##	Takes the location in we got in GetShuttleBayLocation() and add the 
##	proximity check to it.
##
##	Args:	pPosition	- The world location of the shuttle emitter
##
##	Return:	None
################################################################################
def CreateProximityCheck(pPosition):
	# Have the proximity check be global so that we can
	# get to in other functions
	global g_pProximityCheck
	
	# Set the proximity check will be in
	pSet = App.g_kSetManager.GetSet("Savoy1")
	
	# Create the proximity check object that will do the check and
	# send the event if necessary:
	g_pProximityCheck = App.ProximityCheck_Create(ET_STATION_PROXIMITY)
	
	# Setup the proximity check...
	g_pProximityCheck.SetRadius(10)
	
	# Set location of proximity check in world
	g_pProximityCheck.SetTranslate(pPosition)
	g_pProximityCheck.UpdateNodeOnly()
	
	# Finally, add the proximity check to the proximity manager, so it will actually work.
	pProxManager = pSet.GetProximityManager()
	pProxManager.AddObject(g_pProximityCheck)
	
################################################################################
##	SetupEventHandlers()
##	
##  Sets up event types we want to listen for and the handlers to call
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def SetupEventHandlers():
	"Setup any event handlers to listen for broadcast events that we'll need."
	pEpisode = App.Game_GetCurrentGame().GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()

	# Object entering set event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ +".EnterSet")
	# Object exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__+".ObjectDestroyed")
	# Target ID'd by sensors
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_IDENTIFIED, pMission, __name__+".ObjectIdentified")

	# Instance handler for Kiska's Hail button
	pMenu = g_pKiska.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	
	# Instance handler for Miguel's Scan Area button
	pSet	= App.g_kSetManager.GetSet("bridge")
	pSci	= App.CharacterClass_GetObject(pSet, "Science")
	pMenu	= pSci.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")
		
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
##	PlayerFiringOnFriend()
##
##	Called if the player continues to fire on the friendlys.
##	Called from the weapon fired handler.
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
##	Called if the player continues to fire on friend 
##  Ends the game because the player is being a bastard.
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
	
	# If the Nightingale has entered the Starbase set,
	# start our E6M2End briefing
	if (sSetName == "Starbase12") and (sShipName == "Nightingale"):
		E6M2EndBriefing(None)
	
	# If it's the player, call our functions to handle it
	if (sShipName == "player"):
		if (sSetName == "warp"):
			PlayerEntersWarpSet()
		else:
			TrackPlayer(sSetName)
			
	# See if the strike force is entering Savoy 3 after the player
	global g_bStrikeForceArriveSavoy3
	if (sSetName == "Savoy3") and (sShipName == "Khitomer"):
		g_bStrikeForceArriveSavoy3 = TRUE
		if (g_bPlayerArriveSavoy3 == TRUE):
			PlayerArrivesSavoy3()
	
	# See if the Transports are entering Savoy 1
	if (sSetName == "Savoy1") and (sShipName == "Transport 1"):
		TransportsArriveSavoy1()
		pass
		
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
		
	# Bail if the ship is dead
	if (pShip.IsDead()):
		return
	
	sShipName = pShip.GetName()
	
#	kDebugObj.Print("Object \"%s\" exited set \"%s\"" % (sShipName, sSetName))
	
	# check if it is one of the savoy 3 cards warping to savoy 1.
	if (sShipName in g_lSavoy3CardShipNames) and (sSetName == "Savoy3"):
		global g_iCardsWarpToSavoy
		g_iCardsWarpToSavoy = g_iCardsWarpToSavoy + 1
		
		if (g_iCardsWarpToSavoy == 3):
			global g_bAllCardsWarp
			g_bAllCardsWarp = TRUE
		
	
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
		# We're done.  Let any other handlers for this event handle it.
		TGObject.CallNextHandler(pEvent)
		return
	
	sShipName	= pShip.GetName()
	pSet = pShip.GetContainingSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
#	kDebugObj.Print("Object \"%s\" destroyed." % (sShipName))
	if (sSetName == "Starbase12"):
		if (sShipName == "Nightingale") or (sShipName == "Venture") or (sShipName == "San Francisco"):
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "DontShoot7", None, 0, g_pGeneralDatabase)
			# End the mission
			pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pAction)
			pGameOver.Play()
			return
	# If the Station or the Khitomer have been destroyed, plays a line and calls MissionLost()
	if (sShipName == "Savoy Station"):
		global g_bStationDestroyed
		g_bStationDestroyed = TRUE
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3l030", None, 0, g_pMissionDatabase)
		pAction.Play()
		MissionLost(App.TGAction_CreateNull())
	elif (sShipName == "Khitomer"):
		global g_bKhitomerDestroyed
		g_bKhitomerDestroyed = TRUE
		App.TGActionManager_KillActions("Willis")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3KhitomerDestroyed", None, 0, g_pMissionDatabase)
		pAction.Play()
		MissionLost(App.TGAction_CreateNull())
	elif (sShipName == "Devore"):
		App.TGActionManager_KillActions("Martin")
		Maelstrom.Episode6.Episode6.SetDevoreDestroyed(TRUE)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1DevoreDestroyed1", None, 0, MissionLib.GetEpisode().GetDatabase())
		pAction.Play()
	elif (sShipName == "San Francisco"):
		App.TGActionManager_KillActions("Zeiss")
		Maelstrom.Episode6.Episode6.SetSFDestroyed(TRUE)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1SFDamaged2", None, 0, MissionLib.GetEpisode().GetDatabase())
		pAction.Play()
	elif (sShipName == "Venture"):
		App.TGActionManager_KillActions("Dawson")
		Maelstrom.Episode6.Episode6.SetVentureDestroyed(TRUE)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1VentureDestroyed1", None, 0, MissionLib.GetEpisode().GetDatabase())
		pAction.Play()
	elif (sShipName == "Nightingale"):
		App.TGActionManager_KillActions("Jadeja")
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 6/E6M2.tgl")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed1", None, 0, pDatabase)
		pAction.Play()
		if(pDatabase):
			App.g_kLocalizationManager.Unload(pDatabase)
		
	# Keep track of the Cardassians that have been destroyed
	global g_iNumberCardsDestroyed
	global g_iNumberTransportsDestroyed

	for sCardName in g_lCardShipNames:
		if (sCardName == sShipName):
			g_lCardShipNames.remove(sCardName)
			g_iNumberCardsDestroyed = g_iNumberCardsDestroyed + 1
			
	for sTransName in g_lTransportNames:
		if (sTransName == sShipName):
			g_lTransportNames.remove(sTransName)
			g_iNumberTransportsDestroyed = g_iNumberTransportsDestroyed + 1
	
	if (g_iNumberCardsDestroyed ==  5):
		FirstCardsBeaten()
	
	# Check and see if all the groups of Cardassians have been destroyed
	global g_bAllOtherCardsDestroyed
	if (g_iNumberCardsDestroyed ==  8) and (g_bAllOtherCardsDestroyed == FALSE):
		g_bAllOtherCardsDestroyed = TRUE
		# If the transports have already been destroyed, call MissonWin()
		if (g_bAllTransportsDestroyed == TRUE):
			MissionWin()
			
			
			
	global g_bAllTransportsDestroyed
	if (g_iNumberTransportsDestroyed == 2) and (g_bAllTransportsDestroyed == FALSE):
		g_bAllTransportsDestroyed = TRUE
		TransportsDestroyed()
	
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ObjectIdentified()
##
##	Event handler called when a target is identified by sensors.
##
##	Args:	TGObject	- The TGObject object
##			pEvent 		- The event that was sent to object.
##
##	Return:	None
################################################################################
def ObjectIdentified(TGObject, pEvent):
	# Get the ship that was ID'd
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sShipName = pShip.GetName()
	
	# See if the ship is one of the the transports
	global g_bTransportsIdentified
	if ((sShipName == "Transport 1") or (sShipName == "Transport 2")) and (g_bTransportsIdentified == FALSE):
		# It is so call our sequence
		g_bTransportsIdentified = TRUE
		TransportsIdentified()
	
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	StationProximity()
##
##	Event handler called when object in proximity check list triggers the
##	proximity check.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def StationProximity(TGObject, pEvent):
	# See if it's a valid shuttle
#	kDebugObj.Print("Triggered station proximity check.  (shuttle)")

	pShuttle= App.ShipClass_Cast(pEvent.GetDestination())
	if not App.IsNull(pShuttle):
		# It's a shuttle.  Increase our counter
		global g_iShuttleAtStationCounter
		g_iShuttleAtStationCounter = g_iShuttleAtStationCounter + 1
		# Delete the shuttle so we don't have to worry about it.
		pShuttle.SetDeleteMe(1)
		# If the number of shuttles at planet is 2, call our function
		if (g_iShuttleAtStationCounter == 2):
			ShuttlesLanded()

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
	global g_bPlayerArriveSavoy3
	global g_bPlayerArriveSavoy1

	# See if we're entering Savoy3 for the first time
	if (sSetName == "Savoy3") and (g_bPlayerArriveSavoy3 == FALSE):
		StopProdTimer()
		g_bPlayerArriveSavoy3 = TRUE
		if (g_bStrikeForceArriveSavoy3 == TRUE):
			PlayerArrivesSavoy3()
	# See if we're entering Savoy1 for the first time
	elif (sSetName == "Savoy1") and (g_bPlayerArriveSavoy3 == TRUE) and (g_bPlayerArriveSavoy1 == FALSE):
		StopProdTimer()
		g_bPlayerArriveSavoy1 = TRUE
		PlayerArrivesSavoy1()
		DeleteShipsAtStarbase()
		
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
	
	# Get what type of scan it is	
	iType		= pEvent.GetInt()
	
	# Check what objet it is and call our function
	if (iType == App.CharacterClass.EST_SCAN_OBJECT):
		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
			pTarget = pPlayer.GetTarget()
		if (pTarget): 
			if (pTarget.GetName() == "Savoy Station"):
				pSequence = App.TGSequence_Create()
	
				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
				pAction			= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M3ScanStation", None, 0, g_pMissionDatabase)
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
				
				pSequence.AppendAction(pScanSequence)		
				pSequence.AppendAction(pAction)
				pSequence.AppendAction(pEnableScanMenu)
					
				pSequence.Play()
				
			elif (pTarget.GetName() == "Transport 1"):
				pSequence = App.TGSequence_Create()
	
				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
				pAction 		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M3ScanTransport1", None, 0, g_pMissionDatabase)
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
				
				pSequence.AppendAction(pScanSequence)		
				pSequence.AppendAction(pAction)
				pSequence.AppendAction(pEnableScanMenu)
					
				pSequence.Play()

			elif (pTarget.GetName() == "Transport 2"):
				pSequence = App.TGSequence_Create()
	
				pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
				pAction 		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M3ScanTransport2", None, 0, g_pMissionDatabase)
				pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
				
				pSequence.AppendAction(pScanSequence)		
				pSequence.AppendAction(pAction)
				pSequence.AppendAction(pEnableScanMenu)
					
				pSequence.Play()

			else:
				TGObject.CallNextHandler(pEvent)
	# if scaning nothing we care about do default
	else:
		TGObject.CallNextHandler(pEvent)
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
	
	# If we're warping to Savoy 3 for the first time.
	if (pString == "Systems.Savoy.Savoy3") and (g_bPlayerArriveSavoy3 == FALSE):
		StopProdTimer()
		
	# If we're warping to Ona for first time, create Ona ships
	elif (pString == "Systems.Savoy.Savoy1") and (g_bPlayerArriveSavoy1 == FALSE):
		StopProdTimer()

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
	# Get the player's  set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	if (g_bKhitomerHailed == FALSE):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6HailTheKhitomerGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())
		pAction.Play()
		return
	
	if (g_bKhitGoesToStation == TRUE) and (sSetName == "Savoy1") and (g_bTransportsArrived == FALSE):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "WarpStop2", "Captain", 1, g_pGeneralDatabase)
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
	if pMenu and (g_iMissionPositionCounter == 1):
		Savoy3Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Savoy3Communicate
		
	elif pMenu and (g_iMissionPositionCounter == 2):
		Savoy1Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Savoy1Communicate

	elif pMenu and (g_iMissionPositionCounter == 3):
		Savoy1TransportsCommunicate(pMenu.GetObjID()) #pass on whose menu was clicked to Savoy1TransportsCommunicate
				
	else:
#		kDebugObj.Print("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)
	
		
#####################################################################
##
## Savoy3Communicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def Savoy3Communicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate1", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate2", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi")

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6ProtectKhitomerGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID():
#		kDebugObj.Print("Communicating with Miguel")

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate4", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")

		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate3", None, 0, g_pMissionDatabase)

	pAction.Play()
	
#####################################################################
##
## Savoy1Communicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def Savoy1Communicate(iMenuID):

	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate1", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate5", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi")

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6ProtectStationGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID():
#		kDebugObj.Print("Communicating with Miguel")

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate6", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")
		
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate3", None, 0, g_pMissionDatabase)

	pAction.Play()
#####################################################################
##
## Savoy1TransportsCommunicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def Savoy1TransportsCommunicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate7", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate8", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi")

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6DestroyTransportGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID():
#		kDebugObj.Print("Communicating with Miguel")

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate9", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")

		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M3Communicate10", None, 0, g_pMissionDatabase)

	pAction.Play()

	
################################################################################
##	E6M2EndBriefing()
##
##	Plays lines from Graff that end E6M2.  Calls LiuBriefing() as action at
##	end of sequence.
##
##	Args:	pTGAction
##
##	Return:	None
################################################################################
def E6M2EndBriefing(pTGAction):
	# check if the player is done warping in, if not call this function again in 2 seconds
	if MissionLib.IsPlayerWarping():
		# Delay sequence 2 seconds.
		pSequence = App.TGSequence_Create()
		pRePlayBriefing	= App.TGScriptAction_Create(__name__, "E6M2EndBriefing")
		pSequence.AppendAction(pRePlayBriefing, 2)
		pSequence.Play()

		return 0

	pFedOutpostSet	= App.g_kSetManager.GetSet("FedOutpostSet")
	
	pGraff	= App.CharacterClass_GetObject(pFedOutpostSet, "Graff")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
	pGraffEndLine1	= App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E6M2EndGraffLine1", None, 0, g_pMissionDatabase)
	pGraffEndLine2	= App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E6M2EndGraffLine2", None, 0, g_pMissionDatabase)
	pGraffEndLine3	= App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E6M2EndGraffLine3", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pMiguelEndLine4	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2EndGraffLine4", "Captain", 1, g_pMissionDatabase)
	pFlickerShields	= App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields")
	pLiuBriefing	= App.TGScriptAction_Create(__name__, "LiuBriefing")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pGraffEndLine1)
	pSequence.AppendAction(pGraffEndLine2)
	pSequence.AppendAction(pGraffEndLine3)
	pSequence.AppendAction(pViewOff)
	pSequence.AddAction(pMiguelEndLine4, pViewOff)
	pSequence.AddAction(pFlickerShields, pViewOff, 1)
	pSequence.AppendAction(pLiuBriefing, 2)	# 2 sec before the real briefing starts up.
	
	pSequence.Play()
	
	return 0
	
################################################################################
##	LiuBriefing()
##	
##  Creates sequence for first breifing and plays it.  Also registers our
##	first goal.  Called as a script action in E6M2EndBriefing()
##	
##	Args: 	pTGAction	- The script action object.
##	
##	Return: 0	- Return 0 to keep calling sequence from crashing.
################################################################################
def LiuBriefing(pTGAction):
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	
	pLiu 	= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaIncoming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3L034", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLine001			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3LiuBriefing1", None, 0, g_pMissionDatabase)
	pLiuLine002 		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3LiuBriefing2", None, 0, g_pMissionDatabase)
	pLiuLine003 		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3LiuBriefing3", None, 0, g_pMissionDatabase)
	pLiuLine004 		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3LiuBriefing4", None, 0, g_pMissionDatabase)
	pLiuLine005 		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3LiuBriefing5", None, 0, g_pMissionDatabase)
	pLiuLine006 		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3LiuBriefing6", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pAddKitGoal			= App.TGScriptAction_Create(__name__, "AddKitGoal")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaIncoming)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuLine001)
	pSequence.AppendAction(pLiuLine002)
	pSequence.AppendAction(pLiuLine003)
	pSequence.AppendAction(pLiuLine004)
	pSequence.AppendAction(pLiuLine005)
	pSequence.AppendAction(pLiuLine006)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pAddKitGoal)
		
	pSequence.Play()
	
	return 0

###############################################################################
##
## AddKitGoal()
##
##	Args:	TGObject	- The TGObject object.
##			
##  Return:	  return 0 to avoid crashin'
##	
##############################################################################
def AddKitGoal(pTGAction):
	# Get the Episode and register our first goal 
	MissionLib.AddGoal("E6HailTheKhitomerGoal") 	
	
	#set g_bLiuFinished to TRUE so hail will work on the khitomer
	global g_bLiuFinished
	g_bLiuFinished = TRUE
	return 0

	
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
		if (pTarget.GetName () == "Khitomer") and (g_bKhitomerHailed == FALSE) and (g_bLiuFinished == TRUE):
			# The player is hailing the Khitomer, so call our sequence.
			global g_bKhitomerHailed
			g_bKhitomerHailed = TRUE 
			HailKhitomer()

		elif (pTarget.GetName () == "Khitomer"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 0, g_pGeneralDatabase)
			pKhitomerHailed		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6HailWillis", "Willis")
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pCallWaiting)		
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pKhitomerHailed, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
		
		elif (pTarget.GetName () == "San Francisco"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase)
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
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 0, g_pGeneralDatabase)
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
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 0, g_pGeneralDatabase)
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
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase)
			pVentureHailed		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6HailVenture", "Dawson")
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pCallWaiting)		
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pVentureHailed, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
	
		elif (pTarget.GetName () in g_lFriendlyShips):	
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase)
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
##	HailKhitomer()
##	
##  Creates sequence for Khit breifing and plays it.  Also registers our
##	goals. 
##	
##	Args: 	none
##	
##	Return: 0	- Return 0 to keep calling sequence from crashing.
################################################################################
def HailKhitomer():
	pDBridgeSet = App.g_kSetManager.GetSet("DBridgeSet")
	
	pCamera = pDBridgeSet.GetCamera("maincamera")
	pCamera.SetTranslateXYZ(37.936455, 52.250359, 49.288269)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.509437, 0.859258, -0.046366)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.019864, 0.042125, 0.998915)
	pCamera.AlignToVectors(kForward, kUp)
	
	pWillis	= App.CharacterClass_GetObject(pDBridgeSet, "Willis")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaHail			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3WillisBriefing0", "Captain", 1, g_pMissionDatabase)
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis", 0, 0, 1)
	pWillisLine006		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3WillisBriefing1", None, 0, g_pMissionDatabase)
	pWillisLine007		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3WillisBriefing2", None, 0, g_pMissionDatabase)
	pWillisLine008		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3WillisBriefing3", None, 0, g_pMissionDatabase)
	pWillisLine009		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3WillisBriefing4", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pRestartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 60)	# 60 sec prod timer
	pSetFedAIs			= App.TGScriptAction_Create(__name__, "SetFedAIs")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaHail)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pDBridgeViewOn, 2)
	pSequence.AppendAction(pWillisLine006)
	pSequence.AppendAction(pWillisLine007)
	pSequence.AppendAction(pWillisLine008)
	pSequence.AppendAction(pWillisLine009)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pRestartProdTimer)
	pSequence.AppendAction(pSetFedAIs)
	
	pSequence.Play()
	
	# Get the Episode and register our next goal
	MissionLib.RemoveGoal("E6HailTheKhitomerGoal")
	MissionLib.AddGoal("E6HeadToSavoy3Goal")
	MissionLib.AddGoal("E6ProtectKhitomerGoal")
	
	return 0
			
################################################################################
##	SetFedAIs()
##
##	Set the starting AIs for the Federation ships.  Called as script action.
##	Also figures out what surviving Fed ship, if any to bring along (prefers
##	Devore)
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- return 0 to keep calling sequence from crashing.
################################################################################
def SetFedAIs(pTGAction):
	#Add Savoy to the user's helm menu	
	import Systems.Savoy.Savoy
	Systems.Savoy.Savoy.CreateMenus()
			
	# Create our link to special placement in Savoy 1 for player
	LinkMenuToPlacement()
	
	# Import the AIs
	import E6M3_AI_Khit
	import E6M3_AI_Fed
	# Get the ships and assign the AI
	pKhitomer = App.ShipClass_GetObject(None, "Khitomer")
	pKhitomer.SetAI(E6M3_AI_Khit.CreateAI(pKhitomer))
	
	# Figure out which of these ships still exist, if any and use that one
	if (g_bDevoreDestroyed == FALSE):
		pFedShip	= App.ShipClass_GetObject(None, "Devore")
		pFedShip.SetAI(E6M3_AI_Fed.CreateAI(pFedShip))
		MissionLib.AddCommandableShip("Devore")
	elif (g_bSFDestroyed == FALSE):
		pFedShip	= App.ShipClass_GetObject(None, "San Francisco")
		pFedShip.SetAI(E6M3_AI_Fed.CreateAI(pFedShip))
		MissionLib.AddCommandableShip("San Francisco")
	elif (g_bVentureDestroyed == FALSE):
		pFedShip	= App.ShipClass_GetObject(None, "Venture")
		pFedShip.SetAI(E6M3_AI_Fed.CreateAI(pFedShip))
		MissionLib.AddCommandableShip("Venture")
	
	return 0

################################################################################
##	PlayerArrivesSavoy3()
##
##	Called when player first arrives in the Savoy3 system.  Removes
##	HeadToSavoy3Goal.  
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesSavoy3():
	pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
	
	pWillis	= App.CharacterClass_GetObject(pDBridgeSet, "Willis")
	
	pSequence = App.TGSequence_Create()

	pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg2", None, 0, g_pGeneralDatabase)	
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis")
	pWillisLine010	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3WillisArriveSavoy3", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pKiskaIncomming, 1)
	pSequence.AppendAction(pDBridgeViewOn, 1)
	pSequence.AddAction(pWillisLine010, pDBridgeViewOn)
	pSequence.AddAction(pViewOff, pWillisLine010)
	
	pSequence.Play()

	# Remove the Head to Savoy3 goal
	MissionLib.RemoveGoal("E6HeadToSavoy3Goal")
	
	# set mission counter to 1 for communicate
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 1


		
################################################################################
##	WillisSayGoToSavoy1()
##
##	Sequence that plays once all the Cards in Savoy3 have either warped out or
##	been destroyed.  Registers and removes mission goals as well. 
##
##	Args:	None
##
##	Return:	None
################################################################################
def WillisSayGoToSavoy1():
	# Create the ships that will be in the Savoy system
	CreateSavoy1Ships()
	
	# Set our prodding line
	global g_sProdLine
	g_sProdLine = "E6M3ProdToSavoy1"
	
	# Do sequence stuff
	pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
		
	pWillis	= App.CharacterClass_GetObject(pDBridgeSet, "Willis")
	
	# Un-hide Willis
	pWillis.SetHidden(0)
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	if (g_bAllCardsWarp == TRUE):
		pFelixLine01	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3Savoy3Clear1a", None, 0, g_pMissionDatabase)
		pKiskaLine01	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3Savoy3Clear2a", None, 0, g_pMissionDatabase)
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-4", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis")
	pWillisLine011		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3Savoy3Clear1", None, 0, g_pMissionDatabase)
	pWillisLine012		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3Savoy3Clear2", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pRestartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 20)	# 20 sec prod timer
	
	pSequence.AppendAction(pPreLoad)
	if (g_bAllCardsWarp == TRUE):
		pSequence.AppendAction(pFelixLine01, 2)
		pSequence.AppendAction(pKiskaLine01)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pKiskaIncomming)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AddAction(pWillisLine011, pDBridgeViewOn)
	pSequence.AddAction(pWillisLine012, pWillisLine011)
	pSequence.AddAction(pViewOff, pWillisLine012)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pRestartProdTimer)
	
	MissionLib.QueueActionToPlay(pSequence)
		
	# Add add our goals
	MissionLib.AddGoal("E6HeadToSavoy1Goal")
	MissionLib.AddGoal("E6ProtectStationGoal")
	
	
################################################################################
##	CreateSavoy1Ships()
##
##	Creates the ships that will be present in Savoy1 system when player
##	arrives.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateSavoy1Ships():
	# Import the ships we'll need
	
	# Get the set
	pSet = App.g_kSetManager.GetSet("Savoy1")
	
	# Create the ships (AI will be assigned once player comes out of warp)
	pGalor3		= loadspacehelper.CreateShip("Galor", pSet, "Galor 3", "Galor3Start")
	pKeldon2	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 2", "Keldon2Start")
	
	# Import the AIs and assign them
	import E6M3_AI_Keldon2
	import E6M3_AI_Galor3
	pKeldon2.SetAI(E6M3_AI_Keldon2.CreateAI(pKeldon2))
	pGalor3.SetAI(E6M3_AI_Galor3.CreateAI(pGalor3))

################################################################################
##	PlayerArrivesSavoy1()
##
##	Sequence that playes when the player arrives in the Ona system for first
##	time.  Also removes the HeadToSavoy1Goal form Saffi's menu.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesSavoy1():
#	kDebugObj.Print("PlayerArrivesSavoy1()")
	# Remove the goal from Saffi's menu
	MissionLib.RemoveGoal("E6HeadToSavoy1Goal")
	
	# set mission counter to 2 for communicate
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 2

################################################################################
##	KeldonAttackingKhitomer()
##
##	Called from E6M3_AI_Keldon2.py when the Khitomer is close enough to attack.
##
##	Args:	None
##
##	Return:	None
################################################################################
def KeldonAttackingKhitomer():
	# Make sure the player is in the set
	pGame = App.Game_GetCurrentGame()
	if (pGame == None):
		return
	pPlayer = pGame.GetPlayer()
	if (pPlayer == None):
		return
	if (pPlayer.GetContainingSet().GetName() != "Savoy1"):
		return
	
	# Do our sequence stuff
	pSequence = App.TGSequence_Create()

	pFelixLine014	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3KeldonAttacksKhit1", "Captain", 1, g_pMissionDatabase)
	pSaffiLine015	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M3KeldonAttacksKhit2", None, 0, g_pMissionDatabase)

	pSequence.AddAction(pFelixLine014)
	pSequence.AddAction(pSaffiLine015, pFelixLine014)

	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	KhitomerGoingToStation()
##
##	Called from E6M3_AI_Khit.py when the Khitomer changes it's AI to E6M3_AI_Khit_launch.py.
##
##	Args:	None
##
##	Return:	None
################################################################################
def KhitomerGoingToStation():
	
#	kDebugObj.Print("Khit is going to the station")
	
	if (g_bKhitGoesToStation == FALSE):
		global g_bKhitGoesToStation
		g_bKhitGoesToStation = TRUE
	
#		kDebugObj.Print("Khitomer is heading to the station")
	
		pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
		pWillis		= App.CharacterClass_GetObject(pDBridge, "Willis")
	
		pSequence = App.TGSequence_Create()
	
		pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-4", "Captain", 1, g_pMissionDatabase)
		pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis")
		pWillisStation1		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3WillisStation1", None, 0, g_pMissionDatabase)
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
		pSequence.AppendAction(pKiskaIncomming, 8) # 5 second delay
		pSequence.AppendAction(pDBridgeViewOn)
		pSequence.AppendAction(pWillisStation1)
		pSequence.AppendAction(pViewOff)
	
		MissionLib.QueueActionToPlay(pSequence)
	
	return
	
################################################################################
##	FirstCardsBeaten()
##
##	Called when five cards have been destroyed if transports have not arrived yet.
##
##	Args:	None
##
##	Return:	None
################################################################################
def FirstCardsBeaten():
	if (g_bTransportsArrived == FALSE) and (g_bFirstCardLinePlayed == FALSE):
		global g_bFirstCardLinePlayed
		g_bFirstCardLinePlayed = TRUE
	
#		kDebugObj.Print("Five cards have been beaten")
		pSequence = App.TGSequence_Create()
		pAction	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3FirstWaveBeat1", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction(pAction, 3)
		pSequence.Play()
		
################################################################################
##	KhitomerLaunchesShuttles()
##
##	Called from E6M3_AI_Khit_Launch.py when the Khitomer is in position to launch the
##	the shuttles.
##
##	Args:	pTGAction
##
##	Return:	None
################################################################################
def KhitomerLaunchesShuttles(pTGAction):
	# check if the player is done warping in, if not call this function again in 2 second
	pPlayer = App.Game_GetCurrentPlayer()
	if (pPlayer != None):
		pWarp = pPlayer.GetWarpEngineSubsystem()
		if (pWarp != None):
			if (pWarp.GetWarpState() != App.WarpEngineSubsystem.WES_NOT_WARPING):
				# Delay sequence 2 seconds.
				pSequence = App.TGSequence_Create()
				pRePlayLaunch	= App.TGScriptAction_Create(__name__, "KhitomerLaunchesShuttles")
				pSequence.AppendAction(pRePlayLaunch, 2)
				pSequence.Play()
				
				return 0
	
	# Get the Khitomer
	pShip = App.ShipClass_GetObject(None, "Khitomer")
	if (pShip == None):
		return

	# Launch the shuttles, one every 10 sec
	pSequence = App.TGSequence_Create()
	
	pCutsceneStart		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pPlayerAI			= App.TGScriptAction_Create(__name__, "GivePlayerAI")
	pChangeToSavoy1		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Savoy1")
	pStartSavoyCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Savoy1")
	pKhitomerCamera		= App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Savoy1", "Khitomer", 0)
	pLaunchShuttle1		= App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", pShip.GetObjID(), "Shuttle 1", App.ObjectEmitterProperty.OEP_SHUTTLE)
	pHandleShuttle1		= App.TGScriptAction_Create(__name__, "HandleShuttle", ["Shuttle 1"])
	pShuttle1Camera		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "Savoy1", "Shuttle 1", "ShuttleWatch")
	pSaffiLaunching		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M3LaunchingShuttles", "Captain", 1, g_pMissionDatabase)
	pLaunchShuttle2		= App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", pShip.GetObjID(), "Shuttle 2", App.ObjectEmitterProperty.OEP_SHUTTLE)
	pHandleShuttle2		= App.TGScriptAction_Create(__name__, "HandleShuttle", ["Shuttle 2"])
	pShuttle2Camera		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ReverseChaseCam", "Savoy1", "Shuttle 2", 1)
	pEndSavoyCamera		= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Savoy1")
	pChangeToBridge2	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pCutsceneEnd		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pLaunchShuttle3		= App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", pShip.GetObjID(), "Shuttle 3", App.ObjectEmitterProperty.OEP_SHUTTLE)
	pHandleShuttle3		= App.TGScriptAction_Create(__name__, "HandleShuttle", ["Shuttle 3"])
	pResetKhitAI		= App.TGScriptAction_Create(__name__, "ResetKhitAI")
	
	pSequence.AppendAction(pCutsceneStart)
	pSequence.AppendAction(pPlayerAI)
	pSequence.AppendAction(pChangeToSavoy1)
	pSequence.AppendAction(pStartSavoyCamera)
	pSequence.AppendAction(pKhitomerCamera)
	pSequence.AppendAction(pLaunchShuttle1, 2)
	pSequence.AppendAction(pHandleShuttle1)
	pSequence.AppendAction(pShuttle1Camera, 2)  # 2 sec after pHandleShuttle1
	pSequence.AddAction(pSaffiLaunching, pShuttle1Camera, 2)
	pSequence.AddAction(pLaunchShuttle2, pShuttle1Camera, 8) # 10 sec after pHandleShuttle1
	pSequence.AppendAction(pHandleShuttle2)
	pSequence.AppendAction(pShuttle2Camera, 1)
	pSequence.AppendAction(pEndSavoyCamera, 6)
	pSequence.AppendAction(pChangeToBridge2)
	pSequence.AppendAction(pCutsceneEnd)
	pSequence.AppendAction(pLaunchShuttle3)
	pSequence.AppendAction(pHandleShuttle3)
	pSequence.AppendAction(pResetKhitAI, 5)
	
	pSequence.Play()
	
	return 0

################################################################################
##	GivePlayerAI()
##
##	Gives the player an AI for the cutscene 
##
##	Args:	pAction	- Because it is called as a script action
##			
##	Return:	return 0 because the action that is passed on is unused
##	
################################################################################
def GivePlayerAI(pAction):
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
	
	# assign the AI
	import AI.Player.DefenseNoTarget
	MissionLib.SetPlayerAI("Tactical", AI.Player.DefenseNoTarget.CreateAI(pPlayer))
	
	return 0	

################################################################################
##	HandleShuttle()
##
##	Takes a list of shuttles and assign's the same generic AI to all of them
##	and adds them to the proximity checks list o' objects.
##
##	Args:	TGAction		- The script action object
##			g_lShuttleNames	- List of shuttle names
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def HandleShuttle(TGAction, g_lShuttleNames):
	pShip = App.ShipClass_GetObject(None, "Khitomer")
	if (pShip == None):
		return
	import E6M3_AI_Shuttle
	# Go though the list of shuttles
	for sName in g_lShuttleNames:
#		kDebugObj.Print('Creating AI for ' + sName)
		pShuttle = App.ShipClass_GetObject(None, sName)
		# Give the shuttle an AI
		pShuttle.SetAI(E6M3_AI_Shuttle.CreateAI(pShuttle))
		
		# This will disable collisions between the two ships.
		pShip.EnableCollisionsWith(pShuttle, 0)
		
		# Add all the shuttles to the list of objects the proximity
		# check is checking against.
		pSet = pShuttle.GetContainingSet()
		if not App.IsNull(pShuttle):
			# Got the shuttle.  Add it to the check list...
			g_pProximityCheck.AddObjectToCheckList(pShuttle, App.ProximityCheck.TT_INSIDE)
			# The proximity event will now be sent to the object that triggered it,
			# so we need to add a handler to that object..
			pShuttle.AddPythonFuncHandlerForInstance(ET_STATION_PROXIMITY, __name__ + ".StationProximity")

#		else:
#			kDebugObj.Print("Error: Couldn't find Shuttle (%s) that should have been there.  :(" % sName)
		
	return 0

################################################################################
##	ResetKhitAI()
##
##	Resets the AI for the Khitomer so that it will go after the transports.
##	Called as script action.
##
##	Args:	pTGAction	- The script action.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetKhitAI(pTGAction):
	# Save the Game # FIXME fix if possible
	#MissionLib.SaveGame("E6M3-2-")
	
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Savoy1")
	
	# Get the ship
	pShip	= App.ShipClass_GetObject(pSet, "Khitomer")
	if (pShip != None):
		# Get the AI and assign it
		import E6M3_AI_Khit_Launch_Done
		pShip.SetAI(E6M3_AI_Khit_Launch_Done.CreateAI(pShip))
		
	return 0
	
################################################################################
##	ShuttlesLanded()
##
##	Called when three shuttles have docked with the station. Starts
##	timer that will create the transports.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ShuttlesLanded():
	# Start timer for the transports
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_TRANSPORT_TIMER, __name__+".CreateTransports", fStartTime + 4, 0, 0)

	
################################################################################
##	CreateTransports()
##
##	Creates the transports and the Keldon that arrive in Savoy 1.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CreateTransports(TGObject, pEvent):
	# Check and make sure that at least some of the Cards have been destroyed
	if (g_iNumberCardsDestroyed <= 2):
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		# Recheck every 20seconds
		MissionLib.CreateTimer(ET_RECHECK_TRANSPORT_TIMER, __name__+".CreateTransports", fStartTime + 20, 0, 0)
		return 
	
	# Get the set
	pSet = App.g_kSetManager.GetSet("Savoy1")
	# Get the ships and create them
	pTransport1	= loadspacehelper.CreateShip("CardFreighter", pSet, "Transport 1", "Transport1Enter")
	pTransport2	= loadspacehelper.CreateShip("CardFreighter", pSet, "Transport 2", "Transport2Enter")
	pKeldon3	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 3", "Keldon3Enter")
	pKeldon4	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 4", "Keldon4Enter")
	pGalor4		= loadspacehelper.CreateShip("Galor", pSet, "Galor 4", "Galor4Enter")
	
	# Import the AIs and assign them
	import E6M3_AI_Transport
	import E6M3_AI_Keldon3
	
	pTransport1.SetAI(E6M3_AI_Transport.CreateAI(pTransport1))
	pTransport2.SetAI(E6M3_AI_Transport.CreateAI(pTransport2))
	pKeldon3.SetAI(E6M3_AI_Keldon3.CreateAI(pKeldon3, "Transport 1"))
	pKeldon4.SetAI(E6M3_AI_Keldon3.CreateAI(pKeldon4, "Transport 2"))
	pGalor4.SetAI(E6M3_AI_Keldon3.CreateAI(pGalor4, "Transport 1"))
		
################################################################################
##	TransportsArriveSavoy1()
##
##	Plays line from Felix when the Transport group first arrives in system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def TransportsArriveSavoy1():
	# Do the single line from Felix
	pFelixTransArrive1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-1", "Captain", 1, g_pMissionDatabase)
	pFelixTransArrive1.Play()
	
	global g_bTransportsArrived
	g_bTransportsArrived = TRUE
	
################################################################################
##	TransportsIdentified()
##
##	Called when the Cardassian transports arrive in Savoy 1.
##
##	Args:	None
##
##	Return:	None
################################################################################
def TransportsIdentified():
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	pWillis		= App.CharacterClass_GetObject(pDBridge, "Willis")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelTransArrive2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-2", "Captain", 0, g_pMissionDatabase)
	pMiguelTransArrive2a	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-2a", None, 1, g_pMissionDatabase)
	pKiskaTransArrive3	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-3", None, 0, g_pMissionDatabase)
	pFelixTransArrive3a	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive3a", "Captain", 1, g_pMissionDatabase)
	pFelixTransArrive4	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-4", "Captain", 1, g_pMissionDatabase)
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis")
	pWillisTransArrive5	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-5", None, 0, g_pMissionDatabase)
	pWillisTransArrive6	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3TransArrive-6", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelTransArrive2, 7) # 7 second delay
	pSequence.AppendAction(pMiguelTransArrive2a)
	pSequence.AppendAction(pKiskaTransArrive3)
	pSequence.AppendAction(pFelixTransArrive3a)
	pSequence.AppendAction(pFelixTransArrive4)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pWillisTransArrive5)
	pSequence.AppendAction(pWillisTransArrive6)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.Play()
	
	# Add the Destroy Transports goal
	MissionLib.AddGoal("E6DestroyTransportGoal")
	
	# set mission counter to 3 for communicate
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 3

################################################################################
##	TransportsLandingTroops()
##
##	Called from E6M3_AI_Transport when one of the transports gets in range of
##	the station.  Gives the user 20 seconds to kill all transports
##
##	Args:	None
##
##	Return:	None
##	
################################################################################
def TransportsLandingTroops():
	#first check if the transports are all destroyed
	if (g_bAllTransportsDestroyed == TRUE):
		return
	
	# Set our flag
	global g_bTransportsLandingTroopsCalled
	if (g_bTransportsLandingTroopsCalled == TRUE):
		return
	else:
		g_bTransportsLandingTroopsCalled = TRUE
	
	# Start timer for the transports
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_TROOPS_TIMER, __name__+".TroopsLandingLoss", fStartTime + 30, 0, 0)
		
	pSequence = App.TGSequence_Create()
	
	pKiskaLine027	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3L027", "Captain", 1, g_pMissionDatabase)
	pSaffiLine		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M3TroopsLand", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AppendAction(pKiskaLine027)
	pSequence.AppendAction(pSaffiLine)
	
	pSequence.Play()
	
	
################################################################################
##	TroopsLandingLoss()
##
##	Called from TransportsLandingTroops when one of the transports have been in range in range of
##	the station for 20 seconds.  Causes mission lost.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
##
################################################################################
def TroopsLandingLoss(TGObject, pEvent):	
	#first check if the transports are all destroyed
	if (g_bAllTransportsDestroyed == TRUE):
		return
	
	# Do the sequence stuff
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	pWillis		= App.CharacterClass_GetObject(pDBridge, "Willis")
	
	pSequence = App.TGSequence_Create()
	
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis")
	pWillisLine028	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3L028", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pMissionLost	= App.TGScriptAction_Create(__name__, "MissionLost")
	
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pWillisLine028)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pMissionLost)
	
	pSequence.Play()

	
################################################################################
##	TransportsDestroyed()
##
##	Called when all the Cardassian transports have been destroyed.  Also calls
##	function to see if all Cardassian ships have been destroyed.  Removes the
##	goal from Saffi's menu.
##
##	Args:	None
##
##	Return:	None
################################################################################
def TransportsDestroyed():
	pSequence = App.TGSequence_Create()
	
	pFelixLine024	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3L024", "Captain", 1, g_pMissionDatabase)
	pCheckCards		= App.TGScriptAction_Create(__name__, "CheckCardStatus")
	
	pSequence.AppendAction(pFelixLine024, 3)
	pSequence.AppendAction(pCheckCards)
	
	pSequence.Play()
	
	# Get the Episode and remove the goal
	MissionLib.RemoveGoal("E6DestroyTransportGoal")

################################################################################
##	CheckCardStatus()
##
##	Called as script action.  Checks and sees if there are any other Cards 
##	left in system after Transports have been destroyed. Plays sequence based
##	on check.  Will call MissionWin() if all the Galors have been destroyed.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CheckCardStatus(pTGAction):
	# If there are still Cards in system
	if (g_bAllOtherCardsDestroyed == FALSE):
		pSequence = App.TGSequence_Create()
		
		pSaffiLine025	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M3L025", "Captain", 1, g_pMissionDatabase)
		pFelixLine026	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M3L026", "Captain", 1, g_pMissionDatabase)
		
		pSequence.AppendAction(pSaffiLine025)
		pSequence.AppendAction(pFelixLine026)
		
		pSequence.Play()
		
		# Call function to reset Card AIs
		ResetCardsToAttackStation()
	# If all the Cardassians have been destroyed
	elif (g_bAllOtherCardsDestroyed == TRUE):
		MissionWin()
		
	return 0

################################################################################
##	ResetCardsToAttackStation()
##
##	Resets surviving Cards AI so they all attack the station
##
##	Args:	None
##
##	Return:	None
################################################################################
def ResetCardsToAttackStation():
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Savoy1")
	
	# Import the AI
	import E6M3_AI_AttackStation
	# Check each Cardassian and if they exist, set AI
	for sShipName in g_lCardShipNames:
		pShip	= App.ShipClass_GetObject(pSet, sShipName)
		# Double check and make sure ship is not null
		if (pShip != None):
			pShip.SetAI(E6M3_AI_AttackStation.CreateAI(pShip))

################################################################################
##	StationTakingDamage()
##
##	Called from E6M3_AI_Station.py when Savoy station takes %50 hull damage.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationTakingDamage():
	pAction	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M3L029", None, 0, g_pMissionDatabase)
	pAction.Play()
		
################################################################################
##	KhitomerTakingDamage()
##
##	Called from E6M3_AI_Khit.py when Khitomer starts to take hull damage.
##
##	Args:	None
##
##	Return:	None
################################################################################
def KhitomerTakingDamage():
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	
	pWillis	= App.CharacterClass_GetObject(pDBridge, "Willis")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Willis")
	
	pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", None, 0, g_pGeneralDatabase)
	pDBridgeView	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis")
	pWillisLine016	= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3KhitDamaged", None, 0, g_pMissionDatabase)
	pDBridgeViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pKiskaIncomming)
	pSequence.AppendAction(pDBridgeView, 1)
	pSequence.AppendAction(pWillisLine016)
	pSequence.AppendAction(pDBridgeViewOff)
	
	pSequence.Play()

################################################################################
##	FedShipDamaged()
##
##	Called from E6M3_AI_Fed.py.  Figures out what ship called this function and
##	calls sequence for the specific ship.
##
##	Args:	sShipName	- The name of the ship that called this function.
##
##	Return:	None
################################################################################
def FedShipDamaged(sShipName):
	# Check the name of the ship and call our functions based on that
	if (sShipName == "San Francisco"):
		SFTakingDamage()
	elif (sShipName == "Venture"):
		VentureTakingDamage()
	else:
		DevoreTakingDamage()
		
################################################################################
##	SFTakingDamage()
##
##	Sequence that plays if the San Francisco is the ship that is being damaged.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SFTakingDamage():
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Zeiss")

	pSaffiSFDamaged1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M3SFDamaged-1", "Captain", 1, g_pMissionDatabase)
	pZeissSFDamaged2	= App.TGScriptAction_Create("MissionLib", "SubtitledLine", g_pMissionDatabase, "E6M3SFDamaged-2", "Zeiss")
			
	pSequence.AppendAction(pSaffiSFDamaged1)
	pSequence.AppendAction(pZeissSFDamaged2)
	
	pSequence.Play()
	
################################################################################
##	VentureTakingDamage()
##
##	Sequence that plays if the Venture is the ship that is being damaged.
##
##	Args:	None
##
##	Return:	None
################################################################################
def VentureTakingDamage():
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Dawson")
	pSaffiVentureDamaged1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M3VentureDamaged-1", "Captain", 0, g_pMissionDatabase)
	pSaffiVentureDamaged2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M3VentureDamaged-2", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AppendAction(pSaffiVentureDamaged1)
	pSequence.AppendAction(pSaffiVentureDamaged2)
	
	
	pSequence.Play()
	
################################################################################
##	DevoreTakingDamage():
##
##	Called from E6M3_AI_Devore.py when Devore's hull is ddamaged.
##
##	Args:	None
##
##	Return:	None
################################################################################
def DevoreTakingDamage():
	pEBridge	= App.g_kSetManager.GetSet("EBridgeSet")
	
	pMartin	= App.CharacterClass_GetObject(pEBridge, "Martin")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Martin")
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridge", "Martin")
	pMartinDamaged	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M3DevoreDamaged", None, 1, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AddAction(pDBridgeViewOn)
	pSequence.AddAction(pMartinDamaged, pDBridgeViewOn)
	pSequence.AddAction(pViewOff, pMartinDamaged)
	
	pSequence.Play()

################################################################################
##	MissionWin()
##
##	Called when all the Galors have been destroyed.  Plays sequence and links
##	us to E6M4.
##
##	Args:	None
##
##	Return:	None
################################################################################
def MissionWin():
	# Make sure this doesn't play if Station or Khihtomer have
	# been destroyed
	if (g_bKhitomerDestroyed == TRUE) or (g_bStationDestroyed == TRUE):
		return
	# romove all commandable ships so we dont mess up later missions.
	MissionLib.RemoveAllCommandableShips()
		
	# Set our prodding line
	global g_sProdLine
	g_sProdLine = "E6M3ProdToStarbase"
	
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	pWillis		= App.CharacterClass_GetObject(pDBridge, "Willis")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "Willis")
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Willis")
	pWillisLine031		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3L031", None, 0, g_pMissionDatabase)
	pWillisLine032		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3L032", None, 0, g_pMissionDatabase)
	pWillisLine033		= App.CharacterAction_Create(pWillis, App.CharacterAction.AT_SAY_LINE, "E6M3L033", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pRestartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 45) # 45 secs on prod timer
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pDBridgeViewOn, 3) #3 second delay
	pSequence.AppendAction(pWillisLine031)
	pSequence.AppendAction(pWillisLine032)
	pSequence.AppendAction(pWillisLine033)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pRestartProdTimer)
	
	MissionLib.QueueActionToPlay(pSequence)
	
	# Link us to E6M4
	LinkToE6M4()
	
	# set mission counter to 0 so no communicate is called
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 0

################################################################################
##	LinkToE6M4()
##
##	Links Starbase 12 in helm menu to E6M4 and put HeadHomeGoal in Saffi's menu.
##
##	Args:	None
##
##	Return:	None
################################################################################
def LinkToE6M4():
		import Systems.Starbase12.Starbase
		pStarbaseMenu = Systems.Starbase12.Starbase.CreateMenus()
		pStarbaseMenu.SetMissionName("Maelstrom.Episode6.E6M4.E6M4")
		
		MissionLib.AddGoal("E6HeadHomeGoal")
		
################################################################################
##	MissionLost()
##
##	Called from ObjectDestroyed() if station or Khitomer are destroyed and from
##	TransportsAtStation() if Cardassian transports reach the station.  Called
##	as a script action.
##
##	Args:	pTGAction	- The script action object
##
##	Return:	0 - Return 0 to keep calling sequence from crashing.
################################################################################
def MissionLost(pTGAction):
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")	
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaLine034	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M3L034", "Captain", 1, g_pMissionDatabase)
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	if (g_bKhitomerDestroyed == TRUE):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 6/E6M5.tgl")
		pKhitDestroyed = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M5LiuLoss1", None, 0, pDatabase)
	pLiuLine035		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3L035", None, 0, g_pMissionDatabase)
	pLiuLine036		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3L036", None, 0, g_pMissionDatabase)
	pLiuLine037		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M3L037", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaLine034, 1)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pStarbaseViewOn)
	if (g_bKhitomerDestroyed == TRUE):
		pSequence.AppendAction(pKhitDestroyed)
	pSequence.AppendAction(pLiuLine035)
	pSequence.AppendAction(pLiuLine036)
	pSequence.AppendAction(pLiuLine037)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	
	# Do the cutscene stuff to end the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()
	
	if (g_bKhitomerDestroyed == TRUE):
		if(pDatabase):
			App.g_kLocalizationManager.Unload(pDatabase)
	
	# set mission counter to 0 so no communicate is called
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 0
	
	return 0

################################################################################
##	DeleteShipsAtStarbase()
##
##	Gets the ships that might be left at Starbase and deletes them so that we
##	don't have them floating around taking up memory.
##
##	Args:	None
##
##	Return:	None
################################################################################
def DeleteShipsAtStarbase():
	# Get the Starbase set
	pSet	= App.g_kSetManager.GetSet("Starbase12")
	
	# Check each ship and delete it if it's there
	lShipNames = ["Venture", "San Francisco", "Nightingale"]
	for sName in lShipNames:
		pShip = App.ShipClass_GetObject(pSet, sName)
		if (pShip != None):
			pSet.DeleteObjectFromSet(sName)

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
#	kDebugObj.Print("Prodding player")
	
	# Check and see what prodding line we need to play and restart the prod.
	if (g_sProdLine == "E6M3ProdToSavoy3") and (g_bPlayerArriveSavoy3 == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 30)
	elif (g_sProdLine == "E6M3ProdToSavoy1") and (g_bPlayerArriveSavoy1 == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 30)
	elif (g_sProdLine == "E6M3ProdToStarbase"):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 30)
	
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
##	Terminate()
##	
##  Called when mission ends to free resources
##	
##	Args: pMission - the mission object
##	
##	Return: None
################################################################################
def Terminate(pMission):
#	kDebugObj.Print ("Terminating Episode 6, Mission 3.\n")
	# Mission is terminating, so lets set our flag
	global g_bMissionTerminate
	g_bMissionTerminate = TRUE
	
	#stop any sequences we have registered
	App.TGActionManager_KillActions()
	
	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()
	
	# Delete all our mission goals
	MissionLib.DeleteAllGoals()
	
	# Remove our instance handlers
	RemoveInstanceHandlers()
	
	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# unload the database: "data/TGL/Bridge Menus.tgl"
	if(g_pDatabase):
		App.g_kLocalizationManager.Unload(g_pDatabase)

	# now remove any remaining ships in the warp set
	MissionLib.DeleteShipsFromWarpSetExceptForMe()

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
	# Remove instance handler for Kiska's Hail button
	pMenu = g_pKiska.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	
	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	
	# Remove instance handler for Miguel's Scan button
	pSciMenu	= g_pMiguel.GetMenu()
	pSciMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")
		
	# Communicate handler			
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
