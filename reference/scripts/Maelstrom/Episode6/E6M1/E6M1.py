###############################################################################
#	Filename:	E6M1.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 6, Mission 1
#	
#	Created:	9/15/00 -	DLitwin (added header)
#				01/10/02 -	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Episode6.Episode6
import Bridge.BridgeUtils

# For debug output
#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading Episode 6 Mission 1 definition...\n')


# Declare global variables
TRUE	= 1
FALSE	= 0

g_bMissionTerminate	= None

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None
g_pDatabase			= None

g_iProdTimer	= None
g_sProdLine		= None

g_iOnaTimer				= None
g_bGoingToOna			= None
g_bLiuSayGoToOnaPlayed	= None
g_bGoingToSavoy			= None
g_bPlayerArriveArtrus	= None
g_bPlayerArriveOna		= None
g_bPlayerArriveSavoy3	= None
g_bPlayerStuckInSavoy3	= None
g_iPlayerTriesToWarp	= None
g_bRescueCalledForHelp	= None
g_bPlayerArriveSavoy1	= None

g_iMissionPositionCounter	= None

g_bSecondArtrusWaveCreated	= None
g_bArtrusCardsFollow		= None
g_bOnaShipsHaveAI			= None
g_bSecondOnaWaveCreated		= None
g_bOnaCardShipsCreated		= None
g_bCardsHaveWarped			= None
g_bThirdCardWaveMade		= None
g_bMoreCardsMade			= None
g_bYetMoreCardsMade			= None

g_bSFTakingDamageCalled		= None		
g_bSanFranciscoDestroyed	= None
g_bDevoreDestroyed			= None
g_bVentureDestroyed			= None

g_bShannonHitCalled	= None
g_bInverHitCalled	= None
g_bCamHitCalled		= None

g_sRescueShipName			= None

g_iNumberCardsDestroyed	= 0
g_iNumberOnaCardsDestroyed	= 0
g_iNumberSavoyCardsDestroyed	= 0
g_iEscapedTransports	= 0

g_lCardShipNames	= []
g_lMoreCardShipNames	= []
g_lOnaCardShipNames	= []
g_lArtrusCardShipNames	= []
g_lSavoy3WarpCards	= []
g_lTransportNames	= []

g_pGalor3_4Targets	= None
g_pKeldon1Targets	= None
g_pGalor5Targets	= None
g_pGalor6Targets	= None
g_pGalor7Targets	= None
g_pGalor8Targets	= None
g_pGalor9Targets	= None
g_pGalor10Targets	= None
g_pGalor11Targets	= None
g_pGalor12Targets	= None
g_pKeldon2Targets	= None
g_pKeldon4Targets	= None
g_pKeldon5Targets	= None
g_pKeldon6Targets	= None
g_pKeldon7Targets	= None
g_pRescueTargets	= None

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None

# Event types for mission
ET_PROD_TIMER				= App.Mission_GetNextEventType()
ET_SECOND_ARTRUS_WAVE_TIMER	= App.Mission_GetNextEventType()
ET_GO_TO_ONA_TIMER			= App.Mission_GetNextEventType()
ET_SECOND_SAVOY_WAVE_TIMER	= App.Mission_GetNextEventType()
ET_THIRD_SAVOY_WAVE_TIMER	= App.Mission_GetNextEventType()
ET_FIRST_TRANS_WARP			= App.Mission_GetNextEventType()
ET_SECOND_TRANS_WARP		= App.Mission_GetNextEventType()
ET_THIRD_TRANS_WARP			= App.Mission_GetNextEventType()
ET_MORE_FREAKIN_CARDS_TIMER	= App.Mission_GetNextEventType()
ET_YET_MORE_CARDS_TIMER		= App.Mission_GetNextEventType()
ET_MORE_ONA_CARDS_TIMER		= App.Mission_GetNextEventType()

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
	loadspacehelper.PreloadShip("SpaceFacility", 1)
	loadspacehelper.PreloadShip("Galaxy", 2)
	loadspacehelper.PreloadShip("Akira", 1)
	loadspacehelper.PreloadShip("Keldon", 20)
	loadspacehelper.PreloadShip("Galor", 12)
	loadspacehelper.PreloadShip("Transport", 3)

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
#	kDebugObj.Print ("Initializing Episode 6, Mission 1.\n")
	
	# Initialize our global variables
	InitializeGlobals(pMission)
	
	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	#set the diffucultly level - easy Offense, Defense, med O, D, Hard O, D
	App.Game_SetDifficultyMultipliers(1.3, 1.1, 1.0, 1.0, 0.85, 0.9)

	# Create the regions that we'll need
	# We'll also do our placement stuff from inside this function
	CreateRegions()
	
	# Create needed viewscreen sets
	CreateSets()
	
	# Create menus available at mission start
	CreateStartingMenus()
	
	# Import all the ships we'll be using and place them.
	CreateStartingObjects(pMission)

	# Create the target groups we'll be using with the AI's
	CreateTargetGroups()
	
	# Initialize global pointer to all the 5 bridge crew members
	InitializeCrewPointers()

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	# Setup more mission-specific events.
	SetupEventHandlers()
	
	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)

	# Call liu's briefing
	LiuBriefing(None)

	# Save the game
	MissionLib.SaveGame("E6M1-")
	
################################################################################
##	InitializeGlobals()
##
##	Initialize the default values of all our global variables at mission start.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
#	kDebugObj.Print("Initializing global variables")
	
	# Standard globals used with bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0
	
	# Set the Mission terminate flag
	global g_bMissionTerminate
	g_bMissionTerminate = FALSE
	
	# TGL database globals
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 6/E6M1.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 			= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Globals for prodding
	global g_iProdTimer
	global g_sProdLine
	g_iProdTimer	= 0
	g_sProdLine	= "E6M1ProdToArtrus"
	
	# Globals for tracking player location
	global g_iOnaTimer
	global g_bGoingToOna
	global g_bLiuSayGoToOnaPlayed
	global g_bGoingToSavoy
	global g_bPlayerArriveArtrus
	global g_bPlayerArriveOna 
	global g_bPlayerArriveSavoy3
	global g_bPlayerStuckInSavoy3
	global g_iPlayerTriesToWarp
	global g_bRescueCalledForHelp
	global g_bPlayerArriveSavoy1
	global g_iMissionPositionCounter
	g_iOnaTimer	= 0
	g_bGoingToOna			= FALSE
	g_bLiuSayGoToOnaPlayed	= FALSE
	g_bGoingToSavoy			= FALSE
	g_bPlayerArriveArtrus	= FALSE
	g_bPlayerArriveOna		= FALSE
	g_bPlayerArriveSavoy3	= FALSE
	g_bPlayerStuckInSavoy3	= FALSE
	g_iPlayerTriesToWarp	= 0
	g_bRescueCalledForHelp	= FALSE
	g_bPlayerArriveSavoy1	= FALSE
	g_iMissionPositionCounter	= 0
	
	# Global flags for mission events
	global g_bSecondArtrusWaveCreated
	global g_bArtrusCardsFollow
	global g_bOnaShipsHaveAI
	global g_bSecondOnaWaveCreated
	global g_bOnaCardShipsCreated
	global g_bCardsHaveWarped
	global g_bThirdCardWaveMade
	global g_bMoreCardsMade
	global g_bYetMoreCardsMade
	g_bSecondArtrusWaveCreated	= FALSE
	g_bArtrusCardsFollow		= FALSE
	g_bOnaShipsHaveAI			= FALSE
	g_bSecondOnaWaveCreated		= FALSE
	g_bOnaCardShipsCreated		= FALSE
	g_bCardsHaveWarped			= FALSE
	g_bThirdCardWaveMade		= FALSE
	g_bMoreCardsMade			= FALSE
	g_bYetMoreCardsMade			= FALSE
	
	# Flags for ship states
	global g_bSFTakingDamageCalled
	global g_bSanFranciscoDestroyed
	global g_bDevoreDestroyed
	global g_bVentureDestroyed
	g_bSFTakingDamageCalled		= FALSE	
	g_bSanFranciscoDestroyed	= FALSE
	g_bDevoreDestroyed			= FALSE
	g_bVentureDestroyed			= FALSE

	# Flags to tell if the transport hit lines were called
	global g_bShannonHitCalled
	global g_bInverHitCalled
	global g_bCamHitCalled
	g_bShannonHitCalled	= FALSE
	g_bInverHitCalled	= FALSE
	g_bCamHitCalled		= FALSE


	# The name of ship that will serve as the rescue ship
	global g_sRescueShipName
	g_sRescueShipName			= "Devore"
	
	# Counter for destroyed Cardassians
	global g_iNumberCardsDestroyed
	g_iNumberCardsDestroyed	= 0
	
	global g_iNumberOnaCardsDestroyed
	g_iNumberOnaCardsDestroyed	= 0
	
	global g_iNumberSavoyCardsDestroyed
	g_iNumberSavoyCardsDestroyed	= 0
	
	# Counter for number of transports that have escaped
	global g_iEscapedTransports
	g_iEscapedTransports	= 0
	
	# Global list of Cardassian ship names
	global g_lCardShipNames
	g_lCardShipNames	= 	[ 
						"Galor 1", "Galor 2", "Galor 3", "Galor 4", "Galor 5", "Galor 6", "Galor 7", "Galor 8",
						"Galor 9", "Galor 10", "Galor 11", "Galor 12", "Keldon 1", "Keldon 2", "Keldon 3", "Keldon 4",
						"Keldon 5", "Keldon 6", "Keldon 7"
							]
						
	# list of ships that will attack the user if they dont follow orders
	global g_lMoreCardShipNames
	g_lMoreCardShipNames	=	[
							"Keldon 8", "Keldon 9", "Keldon 10", "Keldon 11", "Keldon 12", "Keldon 13", "Keldon 14",
							"Keldon 15", "Keldon 16", "Keldon 17", "Keldon 18", "Keldon 19", "Keldon 20"
								]
	
	# Global list of Cardassian ship names in Ona
	global g_lArtrusCardShipNames
	g_lArtrusCardShipNames	= 	[ 
							"Galor 1", "Galor 2", "Galor 3", "Galor 4", "Keldon 1"
								]						
						
	# Global list of Cardassian ship names in Ona
	global g_lOnaCardShipNames
	g_lOnaCardShipNames	= 	[ 
						"Galor 5", "Galor 6", "Galor 7", "Galor 8",	"Galor 9", "Keldon 2", "Keldon 3"
							]
	
	# List of names of Cards that could warp to Savoy 1
	global g_lSavoy3WarpCards
	g_lSavoy3WarpCards	=	[
							"Galor 11", "Galor 12", "Keldon 5"
							]
							
	# List of names for the transports
	global g_lTransportNames
	g_lTransportNames	= 	[
							"Shannon", "Inverness", "Cambridge"
							]
							
	# Global lists of ship names
	global g_lFriendlyShips
	
	g_lFriendlyShips	= 	[
							"Starbase 12", "Shannon", "Inverness", "Cambridge", "Devore", "San Francisco", "Venture", "Savoy Station"
							]
							
	# Globals used in target lists for AI's
	global g_pGalor3_4Targets
	global g_pKeldon1Targets
	global g_pGalor5Targets
	global g_pGalor6Targets
	global g_pGalor7Targets
	global g_pGalor8Targets
	global g_pGalor9Targets
	global g_pGalor10Targets
	global g_pGalor11Targets
	global g_pGalor12Targets
	
	global g_pKeldon2Targets
	global g_pKeldon3Targets
	global g_pKeldon4Targets
	global g_pKeldon5Targets
	global g_pKeldon6Targets
	global g_pKeldon7Targets
	global g_pRescueTargets	
	
	g_pGalor3_4Targets	= None
	g_pKeldon1Targets	= None
	g_pGalor5Targets	= None
	g_pGalor6Targets	= None
	g_pGalor7Targets	= None
	g_pGalor8Targets	= None
	g_pGalor9Targets	= None
	g_pGalor10Targets	= None
	g_pGalor11Targets	= None
	g_pGalor12Targets	= None
	g_pKeldon2Targets	= None
	g_pKeldon3Targets	= None
	g_pKeldon4Targets	= None
	g_pKeldon5Targets	= None
	g_pKeldon6Targets	= None
	g_pKeldon7Targets	= None
	g_pRescueTargets	= None
	
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
	# Artrus system
	import Systems.Artrus.Artrus3
	Systems.Artrus.Artrus3.Initialize()
	pArtrus3Set = Systems.Artrus.Artrus3.GetSet()
	# Ona system
	import Systems.Ona.Ona3
	Systems.Ona.Ona3.Initialize()
	pOna3Set = Systems.Ona.Ona3.GetSet()
	# Savoy3 system
	import Systems.Savoy.Savoy3
	Systems.Savoy.Savoy3.Initialize()
	pSavoy3Set = Systems.Savoy.Savoy3.GetSet()
	# Savoy 1 system
	import Systems.Savoy.Savoy1
	Systems.Savoy.Savoy1.Initialize()
	pSavoy1Set = Systems.Savoy.Savoy1.GetSet()
	# DeepSpace
	import Systems.DeepSpace.DeepSpace
	Systems.DeepSpace.DeepSpace.Initialize()
	pDeepSpaceSet =Systems.DeepSpace.DeepSpace.GetSet()
	
	# Get the Bridge for the cutscene
	pBridge = App.g_kSetManager.GetSet("bridge")	
	
	# Load our mission specific placements
	import E6M1_Starbase12_P
	import E6M1_Artrus3_P
	import E6M1_Ona3_P
	import E6M1_Savoy3_P
	import E6M1_Savoy1_P
	import E6M1_DeepSpace_P
	import E6M1_EBridge_P
	
	E6M1_Starbase12_P.LoadPlacements(pStarbaseSet.GetName())
	E6M1_Artrus3_P.LoadPlacements(pArtrus3Set.GetName())
	E6M1_Ona3_P.LoadPlacements(pOna3Set.GetName())
	E6M1_Savoy3_P.LoadPlacements(pSavoy3Set.GetName())
	E6M1_Savoy1_P.LoadPlacements(pSavoy1Set.GetName())
	E6M1_DeepSpace_P.LoadPlacements(pDeepSpaceSet.GetName())
	E6M1_EBridge_P.LoadPlacements(pBridge.GetName())

################################################################################
##	CreateSets()
##
##	Create and populate the sets that we'll be using on the viewscreen.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateSets():
	# Liu and the Starbase set
	pLBridgeSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu		= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)

	# Zeiss and Dawson on the DBridgeSet
	pDBridgeSet	= MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -30, 65, -1.55)
	pZeiss		= MissionLib.SetupCharacter("Bridge.Characters.Zeiss", "DBridgeSet")
	pDawson		= MissionLib.SetupCharacter("Bridge.Characters.Dawson", "DBridgeSet")
	
	# Martin and the E-bridge set
	pEBridgeSet	= MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif", -30, 65, -1.55)
	pMartin 	= MissionLib.SetupCharacter("Bridge.Characters.Martin", "EBridgeSet")
	
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
	import Systems.Artrus.Artrus
	
	Systems.Starbase12.Starbase.CreateMenus()
	Systems.Artrus.Artrus.CreateMenus()
	
################################################################################
##	CreateStartingObjects()
##
##	Create all the objects that exist when the mission starts and their
##	affiliations
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def CreateStartingObjects(pMission):
	# Import models needed for mission

	# Setup object affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("San Francisco")
	pFriendlies.AddName("Devore")
	pFriendlies.AddName("Venture")
	pFriendlies.AddName("Savoy Station")
	for sName in g_lTransportNames:
		pFriendlies.AddName(sName)
	
	pEnemies = pMission.GetEnemyGroup()
	for sShipName in g_lCardShipNames:
		pEnemies.AddName(sShipName)
	for sShipName in g_lMoreCardShipNames:
		pEnemies.AddName(sShipName)
		
	# Get the sets we need
	pStarbaseSet 	= App.g_kSetManager.GetSet("Starbase12")
	pSavoy1Set		= App.g_kSetManager.GetSet("Savoy1")
	
	# Place the players ship
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pStarbaseSet, "player", "Player Start")
	# Place the other starting objects and ships
	pStarbase12		= loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	pSavoyStation	= loadspacehelper.CreateShip("SpaceFacility", pSavoy1Set, "Savoy Station", "Station Location")

	# Turn off the station's shields and make it invincible
	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(pSavoyStation)
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(pSavoyStation.GREEN_ALERT)

	App.g_kEventManager.AddEvent(pAlertEvent)
	
	pSavoyStation.SetInvincible(1)
	
################################################################################
##	CreateTargetGroups()
##
##	Creates the object groups that we'll be using in the AI's for attacks.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateTargetGroups():
	# Get the players name
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	sPlayerName = pPlayer.GetName()
	
	# Target list for Cardassians that might be going from
	# Artrus to Ona
	global g_pGalor3_4Targets
	g_pGalor3_4Targets = App.ObjectGroupWithInfo()
	g_pGalor3_4Targets[sPlayerName]		= {"Priority" : 1.0}
	g_pGalor3_4Targets["San Francisco"]	= {"Priority" : 2.0}
	g_pGalor3_4Targets["Devore"]		= {"Priority" : 0.0}
	g_pGalor3_4Targets["Venture"]		= {"Priority" : 0.0}
	
	global g_pKeldon1Targets
	g_pKeldon1Targets = App.ObjectGroupWithInfo()
	g_pKeldon1Targets[sPlayerName]		= {"Priority" : 2.0}
	g_pKeldon1Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pKeldon1Targets["Devore"]			= {"Priority" : 0.0}
	g_pKeldon1Targets["Venture"]		= {"Priority" : 0.0}
	
	# Target lists for first Card wave in Ona
	global g_pGalor5Targets
	g_pGalor5Targets = App.ObjectGroupWithInfo()
	g_pGalor5Targets[sPlayerName]		= {"Priority" : 0.0}
	g_pGalor5Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pGalor5Targets["Devore"]			= {"Priority" : 1.0}
	g_pGalor5Targets["Venture"]			= {"Priority" : 2.0}
	
	global g_pGalor6Targets
	g_pGalor6Targets = App.ObjectGroupWithInfo()
	g_pGalor6Targets[sPlayerName]		= {"Priority" : 2.0}
	g_pGalor6Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pGalor6Targets["Devore"]			= {"Priority" : 0.0}
	g_pGalor6Targets["Venture"]			= {"Priority" : 1.0}
	
	global g_pGalor7Targets
	g_pGalor7Targets = App.ObjectGroupWithInfo()
	g_pGalor7Targets[sPlayerName]		= {"Priority" : 0.0}
	g_pGalor7Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pGalor7Targets["Devore"]			= {"Priority" : 0.0}
	g_pGalor7Targets["Venture"]			= {"Priority" : 1.5}
	
	global g_pKeldon2Targets
	g_pKeldon2Targets = App.ObjectGroupWithInfo()
	g_pKeldon2Targets[sPlayerName]		= {"Priority" : 2.0}
	g_pKeldon2Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pKeldon2Targets["Devore"]			= {"Priority" : 0.0}
	g_pKeldon2Targets["Venture"]		= {"Priority" : 1.0}
	
	# Target lists for second Card wave in Ona
	global g_pGalor8Targets
	g_pGalor8Targets = App.ObjectGroupWithInfo()
	g_pGalor8Targets[sPlayerName]		= {"Priority" : 0.0}
	g_pGalor8Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pGalor8Targets["Devore"]			= {"Priority" : 0.5}
	g_pGalor8Targets["Venture"]			= {"Priority" : 1.5}

	global g_pGalor9Targets
	g_pGalor9Targets = App.ObjectGroupWithInfo()
	g_pGalor9Targets[sPlayerName]		= {"Priority" : 0.0}
	g_pGalor9Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pGalor9Targets["Devore"]			= {"Priority" : 0.5}
	g_pGalor9Targets["Venture"]			= {"Priority" : 1.5}

	global g_pKeldon3Targets
	g_pKeldon3Targets = App.ObjectGroupWithInfo()
	g_pKeldon3Targets[sPlayerName]		= {"Priority" : 2.0}
	g_pKeldon3Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pKeldon3Targets["Devore"]			= {"Priority" : 0.0}
	g_pKeldon3Targets["Venture"]		= {"Priority" : 0.5}
	
	# Target lists for first Savoy 3 wave
	global g_pKeldon4Targets
	g_pKeldon4Targets = App.ObjectGroupWithInfo()
	g_pKeldon4Targets[sPlayerName]		= {"Priority" : 0.0}
	g_pKeldon4Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pKeldon4Targets["Devore"]			= {"Priority" : 2.0}
	g_pKeldon4Targets["Venture"]		= {"Priority" : 0.0}
	
	global g_pGalor10Targets
	g_pGalor10Targets = App.ObjectGroupWithInfo()
	g_pGalor10Targets[sPlayerName]		= {"Priority" : 2.0}
	g_pGalor10Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pGalor10Targets["Devore"]			= {"Priority" : 0.0}
	g_pGalor10Targets["Venture"]		= {"Priority" : 1.0}

	# Target group for the rescue ship in Savoy
	global g_pRescueTargets
	g_pRescueTargets = App.ObjectGroup()
	for sName in g_lCardShipNames:
		g_pRescueTargets.AddName(sName)
		
	# Target list for second Savoy 3 wave that moves to Savoy1
	global g_pGalor11Targets
	g_pGalor11Targets = App.ObjectGroupWithInfo()
	g_pGalor11Targets[sPlayerName]		= {"Priority" : 0.5}
	g_pGalor11Targets["San Francisco"]	= {"Priority" : 1.0}
	g_pGalor11Targets["Devore"]			= {"Priority" : 1.0}
	g_pGalor11Targets["Venture"]		= {"Priority" : 1.0}
	g_pGalor11Targets["Cambridge"]		= {"Priority" : 0.5}
	
	global g_pGalor12Targets
	g_pGalor12Targets = App.ObjectGroupWithInfo()
	g_pGalor12Targets[sPlayerName]		= {"Priority" : 1.5}
	g_pGalor12Targets["San Francisco"]	= {"Priority" : 0.5}
	g_pGalor12Targets["Devore"]			= {"Priority" : 1.0}
	g_pGalor12Targets["Venture"]		= {"Priority" : 1.0}
	
	global g_pKeldon5Targets
	g_pKeldon5Targets = App.ObjectGroupWithInfo()
	g_pKeldon5Targets[sPlayerName]		= {"Priority" : 1.5}
	g_pKeldon5Targets["San Francisco"]	= {"Priority" : 0.5}
	g_pKeldon5Targets["Devore"]			= {"Priority" : 1.0}
	g_pKeldon5Targets["Venture"]		= {"Priority" : 0.0}

	# Target list for the third wave to enter the Savoy system
	global g_pKeldon6Targets
	g_pKeldon6Targets = App.ObjectGroupWithInfo()
	g_pKeldon6Targets[sPlayerName]		= {"Priority" : 1.0}
	g_pKeldon6Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pKeldon6Targets["Devore"]			= {"Priority" : 1.0}
	g_pKeldon6Targets["Venture"]		= {"Priority" : 0.0}
	g_pKeldon6Targets["Shannon"]		= {"Priority" : 0.0}
	g_pKeldon6Targets["Inverness"]		= {"Priority" : 0.0}
	g_pKeldon6Targets["Cambridge"]		= {"Priority" : 0.5}
	
	global g_pKeldon7Targets
	g_pKeldon7Targets = App.ObjectGroupWithInfo()
	g_pKeldon7Targets[sPlayerName]		= {"Priority" : 1.0}
	g_pKeldon7Targets["San Francisco"]	= {"Priority" : 0.0}
	g_pKeldon7Targets["Devore"]			= {"Priority" : 1.0}
	g_pKeldon7Targets["Venture"]		= {"Priority" : 0.0}

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
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__+".ObjectDestroyed")

	# Instance handler for Kiska's Hail button
	pMenu = g_pKiska.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	
	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton() 
	pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	
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
		if (pTarget.GetName () == "San Francisco"):
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
	
		elif (pTarget.GetName () in g_lFriendlyShips):	
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
	pWarpButton = App.STWarpButton_Cast(pEvent.GetDestination())
	pcDest	 	= pWarpButton.GetDestination()
	# Get the player's  set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
#	kDebugObj.Print("Handling Warp")

	if (g_bPlayerStuckInSavoy3 == TRUE):
		global g_iPlayerTriesToWarp
		g_iPlayerTriesToWarp = g_iPlayerTriesToWarp + 1
		
		if (g_iPlayerTriesToWarp == 1): #warn them
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1GenProd1", "Captain", 1, g_pMissionDatabase)
			pAction.Play()
		
		elif (g_iPlayerTriesToWarp == 5): #tried to warp five times, call game over
			#kill any registered sequences
			App.TGActionManager_KillActions()
			pSequence = App.TGSequence_Create()
		
			pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
			pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1GenProd3", "Captain", 1, g_pMissionDatabase)
		
			pSequence.AppendAction(pAction1)
			pSequence.AppendAction(pAction2)
		
			# End the mission
			pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
			pGameOver.Play()
						
		elif (g_iPlayerTriesToWarp >= 2):	#warn them again
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1GenProd2", "Captain", 1, g_pMissionDatabase)
			pAction.Play()
		return
				
	
	if (sSetName== "Starbase12") and (g_bGoingToSavoy == TRUE) and (pcDest != "Systems.Savoy.Savoy3"):
		pcLine = MissionLib.GetRandomLine(["E6FollowOrders1", "E6InterceptGalorsGoalAudio"])
		
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, pcLine, "Captain", 1, MissionLib.GetEpisode().GetDatabase())
		pAction.Play()
		return
	
	if (sSetName== "Ona3") and (g_bGoingToSavoy == TRUE):
		 if (pcDest != "Systems.Savoy.Savoy3") and (pcDest != "Systems.Starbase12.Starbase12"):
			pcLine = MissionLib.GetRandomLine(["E6FollowOrders1", "E6InterceptGalorsGoalAudio"])
			
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, pcLine, "Captain", 1, MissionLib.GetEpisode().GetDatabase())
			pAction.Play()
			return

	pObject.CallNextHandler(pEvent)
			
################################################################################
##	PlayerFiringOnFriend()
##
##	Called if the player continues to fire on the Marauder after it's been
##	disabled.  Called from the weapon fired handler.
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
	#kill any registered sequences
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

	# check which menu was clicked.
	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())

	# Do a quick error check
	pPlayer 	= MissionLib.GetPlayer()
	if pPlayer == None:
		return

	# pick a communicate dialogue, or behave normally
	if pMenu and (g_iMissionPositionCounter == 1):
		ArtrusCommunicate(pMenu.GetObjID()) #pass on whose menu was clicked to ArtrusCommunicate
		
	elif pMenu and (g_iMissionPositionCounter == 2):
		OnaCommunicate(pMenu.GetObjID()) #pass on whose menu was clicked to OnaCommunicate

	elif pMenu and (g_iMissionPositionCounter == 3):
		Savoy3Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Savoy3Communicate
				
	elif pMenu and (g_iMissionPositionCounter == 4):
		Savoy1Communicate(pMenu.GetObjID()) #pass on whose menu was clicked to Savoy1Communicate
	
	else:
#		kDebugObj.Print("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)
	
#####################################################################
##
## ArtrusCommunicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def ArtrusCommunicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()	
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate02", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate01", None, 0, g_pMissionDatabase)

	elif (iMenuID == pSaffiMenu.GetObjID()) and (g_bSanFranciscoDestroyed == FALSE):
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate03", None, 0, g_pMissionDatabase)
	
	elif (iMenuID == pSaffiMenu.GetObjID()) and (g_bSanFranciscoDestroyed == TRUE):
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "SaffiNothingToAdd", None, 0, g_pGeneralDatabase)
	
	elif (iMenuID == pMiguelMenu.GetObjID()) and (g_bSanFranciscoDestroyed == FALSE): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate05", None, 0, g_pMissionDatabase)
	
	elif (iMenuID == pMiguelMenu.GetObjID()) and (g_bSanFranciscoDestroyed == TRUE): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport2", None, 0, MissionLib.GetEpisode().GetDatabase())
		
	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate04", None, 0, g_pMissionDatabase)
	
	pAction.Play()
	
#####################################################################
##
## OnaCommunicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##	Return: None
##
####################################################################		
def OnaCommunicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
		
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate06", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate01", None, 0, g_pMissionDatabase)

	elif (iMenuID == pSaffiMenu.GetObjID()) and (g_sProdLine != "E6M1ProdToSavoy3"):
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6DefendOnaGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif (iMenuID == pSaffiMenu.GetObjID()) and (g_sProdLine == "E6M1ProdToSavoy3"):
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6InterceptGalorsGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate08", None, 0, g_pMissionDatabase)
	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate07", None, 0, g_pMissionDatabase)

	pAction.Play()
	
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
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate10", None, 0, g_pMissionDatabase)

	# no special communicate dialogue for felix
	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate09", None, 0, g_pMissionDatabase)

	elif (iMenuID == pSaffiMenu.GetObjID()) and (g_sProdLine != "E6M1ProdToSavoy1"):
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6InterceptGalorsGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())
	
	elif (iMenuID == pSaffiMenu.GetObjID()) and (g_sProdLine == "E6M1ProdToSavoy1"):
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6ProtectTransportsGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate12", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate11", None, 0, g_pMissionDatabase)

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
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate13", None, 0, g_pMissionDatabase)

	# no special communicate dialogue for felix
	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate09", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi") 
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6ProtectTransportsGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID(): 
#		kDebugObj.Print("Communicating with Miguel")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate14", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1Communicate11", None, 0, g_pMissionDatabase)

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
	
	# See if the Cards in Savoy 3 are warping to Savoy1
	if (sSetName == "warp") and (sShipName in g_lSavoy3WarpCards):
		SecondSavoyWaveWarps()
		
	# see if the artrus cards are folowing the user to Ona
	if (sSetName == "Ona3") and (sShipName in g_lArtrusCardShipNames):
#		kDebugObj.Print("Artrus cards followed us to Ona")
		global g_bArtrusCardsFollow
		g_bArtrusCardsFollow = TRUE
	
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


################################################################################
##	DarnArtrusCards()
##	
##	Plays a line of dialogue if the artrus cards follow the user to Ona.
##	
##	Args: 	pTGAction	
##	
##	Return: 0
################################################################################
def DarnArtrusCards(pTGAction):
	if (g_bArtrusCardsFollow == TRUE):
		pSequence = App.TGSequence_Create()
		
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveOna7", None, 0, g_pMissionDatabase)
	
		pSequence.AppendAction(pAction, 1) # 1 sec delay
	
		pSequence.Play()	
	return 0
	
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
		
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()

	# Make sure it's a ship, return if not
	if (pShip == None):
		return
		
	# Bail if ship is dead
	if (pShip.IsDead()):
		return
	
	sShipName = pShip.GetName()
		
	# if the player is moving, set g_iMissionPositionCounter to play no dialogue	
	if (sShipName == "player"):
		global g_iMissionPositionCounter
		g_iMissionPositionCounter = 0
	
#	kDebugObj.Print("Object \"%s\" exited set \"%s\"" % (sShipName, sSetName))
	
	# If one of the transports has exited the set, and
	# still exists in the list, then increase our counter
	if (sSetName == "Savoy1") and (sShipName in g_lTransportNames):
#		kDebugObj.Print("Increasing the transports escaped counter")
		global g_iEscapedTransports
		g_iEscapedTransports = g_iEscapedTransports + 1
		
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
	
	# See if one of the Fed ships has been destroyed, see if it's a mission loss
	if (sShipName == "San Francisco") or (sShipName == "Venture") or (sShipName == "Devore"):
		FedShipDestroyed(sShipName, sSetName)
		
	# If set was Artrus or Ona, call our function to handle it
	if (sSetName == "Artrus3") or (sSetName == "Ona3"):
		ObjectExitsArtrusOrOna(sShipName)

	# If the SF or Venture are destroyed in Ona, call our episode level
	# functions track it
	if (sSetName == "Ona3"):
		if (sShipName == "Venture"):
			Maelstrom.Episode6.Episode6.SetVentureDestroyedInOna(TRUE)
		elif (sShipName == "San Francisco"):
			Maelstrom.Episode6.Episode6.SetSFDestroyedInOna(TRUE)

	# If the object was one of the transports call our function
	if (sShipName in g_lTransportNames):
		TransportDestroyed(sShipName)
	
	for sSavoy1CardShip in g_lSavoy3WarpCards:
		if (sShipName == sSavoy1CardShip):
			# Yes, a Savoy 1 Cardassian has been destroyed, so increase our counter
#			kDebugObj.Print("A savoy 1 card has been destroyed")
			global g_iNumberSavoyCardsDestroyed
			g_iNumberSavoyCardsDestroyed = g_iNumberSavoyCardsDestroyed + 1
	# if they are all destroyed, call the third wave.
	if (g_iNumberSavoyCardsDestroyed == 3):
		# Make sure the player can leave savoy 3 if they are there.
		global g_bPlayerStuckInSavoy3
		g_bPlayerStuckInSavoy3 = FALSE
		
#		kDebugObj.Print("three savoy 1 cards destroyed, call last wave.")
		CreateThirdSavoyWave(None, None)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	FedShipDestroyed()
##
##	Called if one of the Federation ships has been destroyed.  Checks to see
##	if it's a mission loss.  Also calls our Episode level script and set the
##	flag for each ship there.
##
##	Args:	sShipName	- Name of ship destroyed.
##			sSetName	- Name of the set the ship was destroyed in.
##			
##	Return:	None
################################################################################
def FedShipDestroyed(sShipName, sSetName):
#	kDebugObj.Print("Federation ship destroyed")
	
	global g_bVentureDestroyed
	global g_bSanFranciscoDestroyed
	global g_bDevoreDestroyed
	
	if (sShipName == "Venture"):
		g_bVentureDestroyed = TRUE
		g_pMiguel.SpeakLine(MissionLib.GetEpisode().GetDatabase(), "E6M1VentureDestroyed1", App.CSP_MISSION_CRITICAL)
		Maelstrom.Episode6.Episode6.SetVentureDestroyed(TRUE)
	elif (sShipName == "San Francisco"):
		g_bSanFranciscoDestroyed = TRUE
		g_pFelix.SpeakLine(MissionLib.GetEpisode().GetDatabase(), "E6M1SFDamaged2", App.CSP_MISSION_CRITICAL)
		Maelstrom.Episode6.Episode6.SetSFDestroyed(TRUE)
	elif (sShipName == "Devore"):
		g_bDevoreDestroyed = TRUE
		g_pFelix.SpeakLine(MissionLib.GetEpisode().GetDatabase(), "E6M1DevoreDestroyed1", App.CSP_MISSION_CRITICAL)
		Maelstrom.Episode6.Episode6.SetDevoreDestroyed(TRUE)

	# See if it's time to call AllFedsDestroyed()
	if (g_bDevoreDestroyed == TRUE) and (g_bVentureDestroyed == TRUE) and (g_bSanFranciscoDestroyed == TRUE):
		# All the other Fed ships have been destroyed, so MissionLost
		AllFedsDestroyed()
		return
	
	# set the resuce ship too.
	if (g_bDevoreDestroyed == TRUE) and (g_bSanFranciscoDestroyed == FALSE):
		global g_sRescueShipName
		g_sRescueShipName = "SanFrancisco"
	elif (g_bDevoreDestroyed == TRUE) and (g_bSanFranciscoDestroyed == TRUE):
		global g_sRescueShipName
		g_sRescueShipName = "Venture"

################################################################################
##	TransportDestroyed()
##
##	Called from ObjectDestroyed().  Figures out which transport was destroyed
##	and plays the correct audio.
##
##	Args:	sShipName	- The name of the ship destroyed.
##
##	Return:	None
################################################################################
def TransportDestroyed(sShipName):
	# Remove the transport from the names.
	global g_lTransportNames
	g_lTransportNames.remove(sShipName)
	
	# Do a sequence with the correct line for the transport destroyed
	# and either the one transport destroyed audio, the game over, or
	# mission "won" dialogue.
	if (sShipName == "Shannon"):
		pDestroyedLine = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1ShannonDestroyed1", "Captain", 1, g_pMissionDatabase)
	elif (sShipName == "Inverness"):
		pDestroyedLine = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1InverDestroyed1", "Captain", 1, g_pMissionDatabase)
	else:
		pDestroyedLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1CamDestroyed1", "Captain", 1, g_pMissionDatabase)

	# Check and see if too many transports have died
	# call the mission loss stuff
	if (len(g_lTransportNames) == 1):
		pDestroyedFunction	= App.TGScriptAction_Create(__name__, "SecondTransportDestroyed")

	elif (len(g_lTransportNames) == 2) and (g_iEscapedTransports == 2):
		pDestroyedFunction	= App.TGScriptAction_Create(__name__, "EnoughEscaped")

	elif (len(g_lTransportNames) == 2):
		pDestroyedFunction	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1TransportDestroyed1", "Captain", 1, g_pMissionDatabase)
	else:
		#just in case all three are distroyed before the mission ends.
		pDestroyedFunction	= App.TGAction_CreateNull()

	# Build the sequence and play it
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(pDestroyedLine)
	pSequence.AppendAction(pDestroyedFunction)
	
	pSequence.Play()
	
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
	global g_bPlayerArriveArtrus
	global g_bPlayerArriveOna
	global g_bPlayerArriveSavoy3
	global g_bPlayerArriveSavoy1

	# See if were entering Artrus for the first time
	if (sSetName == "Artrus3") and (g_bPlayerArriveArtrus == FALSE):
		StopProdTimer()
		g_bPlayerArriveArtrus = TRUE
		GiveArtrusShipsAI()
		CreateOnaFedShips()
		PlayerArrivesArtrus()
		
	# See if we're entering Ona for first time after Artrus
	elif (sSetName == "Ona3") and (g_bPlayerArriveOna == FALSE) and (g_bGoingToOna == TRUE):
		StopProdTimer()
		g_bPlayerArriveOna = TRUE
		PlayerArrivesOna()
		
	# See if we're entering Savoy3 for the first time
	elif (sSetName == "Savoy3") and (g_bPlayerArriveOna == TRUE) and (g_bPlayerArriveSavoy3 == FALSE) and (g_bGoingToSavoy == TRUE):
		StopProdTimer()
		g_bPlayerArriveSavoy3 = TRUE
		global g_bPlayerStuckInSavoy3
		g_bPlayerStuckInSavoy3 = TRUE
		PlayerArrivesSavoy3()
		
	# See if we're entering Savoy1 for the first time
	elif (sSetName == "Savoy1") and (g_bPlayerArriveSavoy3 == TRUE) and (g_bPlayerArriveSavoy1 == FALSE):
		StopProdTimer()
		g_bPlayerArriveSavoy1 = TRUE
		PlayerArrivesSavoy1()
	
		
################################################################################
##	PlayerEntersWarpSet()
##
##	Called if player enters warp set.  Keeps track of were the player is headed
##	for prodding needs and creating ships while were in warp.
##
##	Args:	None
##
##	Return: None	
################################################################################
def PlayerEntersWarpSet():
	# Get Kiska's warp heading and see where were headed
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	
	pString 	= pWarpButton.GetDestination()
	
	# If we're warping to Artrus for first time, create the ships in Artrus3
	if (pString == "Systems.Artrus.Artrus3") and (g_bPlayerArriveArtrus == FALSE):
		StopProdTimer()
		CreateArtrusShips()
		
################################################################################
##	ObjectExitsArtrusOrOna()
##
##	Keeps track of ships that exit the Artrus and Ona sets by increasing the
##	g_iNumberCardsDestroyed counter.  Calls functions based on that number.
##
##	Args:	sShipName	- The name of the object tat exited.
##
##	Return:	None
################################################################################
def ObjectExitsArtrusOrOna(sShipName):
	global g_iNumberCardsDestroyed
	global g_iNumberOnaCardsDestroyed
	global g_bSecondArtrusWaveCreated
	global g_bGoingToOna
	global g_bSecondOnaWaveCreated
	global g_bGoingToSavoy

	for sCardShip in g_lCardShipNames:
		if (sCardShip == sShipName):
			# Yes, a Cardassian has been destroyed, so increase
			# our counter
			g_iNumberCardsDestroyed = g_iNumberCardsDestroyed + 1
	
	# Check and see if it's time to call any functions
	if (g_iNumberCardsDestroyed == 2) and (g_bSecondArtrusWaveCreated == FALSE):
		g_bSecondArtrusWaveCreated = TRUE
		# Start short delay for creation of Second Artrus wave
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_SECOND_ARTRUS_WAVE_TIMER, __name__+".SecondArtrusWaveArrives", fStartTime + 6, 0, 0)
		
	# All but one of the Artrus Cards have been destroyed - Create the Ona Cards.	
	elif (g_iNumberCardsDestroyed == 5) and (g_bGoingToOna == FALSE):
		CreateOnaCardShips()
		SecondArtrusWaveDone()
		
	for sOnaCardship in g_lOnaCardShipNames:
		if (sOnaCardship == sShipName):
			# Yes, a Ona Cardassian has been destroyed, so increase
			# our counter
			g_iNumberOnaCardsDestroyed = g_iNumberOnaCardsDestroyed + 1
			
	# Most of first Ona wave is destroyed, start timer for the second wave.	
	if (g_iNumberOnaCardsDestroyed == 3) and (g_bSecondOnaWaveCreated == FALSE):
		g_bSecondOnaWaveCreated = TRUE
		# Create second wave in 15 seconds
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_SECOND_ARTRUS_WAVE_TIMER, __name__+".CreateSecondOnaWave", fStartTime + 15, 0, 0)
		
	# All but one of the Ona ships have been destroyed, so call the FallBack
	elif (g_iNumberOnaCardsDestroyed == 6) and (g_bGoingToSavoy == FALSE):
		g_bGoingToSavoy = TRUE
		FallBackToSavoy()
		
################################################################################
##	LiuBriefing()
##	
##  Creates sequence for first briefing and plays it.  Also registers our
##	first goal.
##	
##	Args: 	pTGAction - in case the user was warping, and this call it self
##	
##	Return: 0
################################################################################
def LiuBriefing(pTGAction):
	# See if our mission is terminating
	if (g_bMissionTerminate == TRUE):
		return 0
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu 			= App.CharacterClass_GetObject (pStarbaseSet, "Liu")
	
	# check if the player is done warping in, if not call this function again in 2 seconds
	if MissionLib.IsPlayerWarping():
		# Delay sequence 2 seconds.
		pSequence = App.TGSequence_Create()
		pRePlayLiuBriefing	= App.TGScriptAction_Create(__name__, "LiuBriefing")
		pSequence.AppendAction(pRePlayLiuBriefing, 1)
		pSequence.Play()

		return 0
				
	pSequence = App.TGSequence_Create()

	# Add an action right at the start to stream in all the voice lines in this
	# sequence, so the game doesn't hitch in the middle.
	pSequence.AddAction( App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") )

	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pChangeToBridge		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pStartBridgeCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pChangeToSB12		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Starbase12")
	pStartSB12Camera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Starbase12")
	pSB12Camera			= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "Starbase12", "player", "CutScene0")
	pSaffiBreathe		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_FORCE_BREATHE) #make sure Saffi is neutral
	pFelixIntro1		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E6Intro1", None, 0, g_pMissionDatabase)
	pSB12Camera2		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "Starbase12", "player", "CutScene1")
	pFelixIntro2		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E6Intro2", None, 0, g_pMissionDatabase)
	pSB12Camera3		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "Starbase12", "player", "CutScene2a")
	pFelixIntro3		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E6Intro3", None, 0, g_pMissionDatabase)
	pFelixIntro4		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E6Intro4", None, 0, g_pMissionDatabase)
	pFelixCam2			= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "FelixCam2")
	pFelixIntro5		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E6Intro5", None, 0, g_pMissionDatabase)
	pGuestCam1			= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "FelixCam3", 0)
	pFelixTurn			= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_TURN, "Captain")
	pFelixIntro6		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, "E6Intro6", None, 1, g_pMissionDatabase)
	pSaffiCam			= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "SaffiCam2")
	pSaffiHail			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "gf017", None, 0, g_pGeneralDatabase)
	pViewCam1			= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu", 0, 0, 0)
	pLiuLine001			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1Briefing1", None, 0, g_pMissionDatabase)
	pFelixTurnBack		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_TURN_BACK, None)
	pKiskaLooks 		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_TURN, "T")
	pKiskaLooksBack		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_TURN_BACK)
	pLiuLine003 		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1Briefing3", None, 0, g_pMissionDatabase)
	pLiuLine004 		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1Briefing4", None, 0, g_pMissionDatabase)
	pLiuLine005 		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1Briefing5", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndSB12Camera		= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Starbase12")
	pEndBridgeCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pRestartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 60)	# 60 sec prod timer

	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pChangeToSB12)
	pSequence.AppendAction(pStartSB12Camera)
	pSequence.AppendAction(pSB12Camera)
	pSequence.AppendAction(pSaffiBreathe)

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeOut", 0))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeIn", 3))

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EpisodeTitleAction", "Ep6Title"))

	pSequence.AppendAction(pFelixIntro1, 3)
	pSequence.AppendAction(pSB12Camera2)
	pSequence.AppendAction(pFelixIntro2)
	pSequence.AppendAction(pSB12Camera3, 0.3)
	pSequence.AppendAction(pFelixIntro3)
	pSequence.AppendAction(pFelixIntro4)
	pSequence.AppendAction(pChangeToBridge)
	pSequence.AppendAction(pStartBridgeCamera)
	pSequence.AppendAction(pFelixCam2)
	pSequence.AppendAction(pFelixIntro5)
	pSequence.AppendAction(pGuestCam1)
	pSequence.AppendAction(pFelixTurn)
	pSequence.AppendAction(pFelixIntro6)
	pSequence.AppendAction(pSaffiHail, 1)
	pSequence.AddAction(pSaffiCam, pFelixIntro6, 1.5)
	pSequence.AppendAction(pViewCam1, 1.5)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AddAction(pLiuLine001, pStarbaseViewOn)
	pSequence.AddAction(pKiskaLooks, pStarbaseViewOn, 1)
	pSequence.AddAction(pFelixTurnBack, pStarbaseViewOn, 2)
	pSequence.AddAction(pKiskaLooksBack, pFelixTurnBack, 1)
	pSequence.AddAction(pLiuLine003, pLiuLine001)
	pSequence.AppendAction(pLiuLine004)
	pSequence.AppendAction(pLiuLine005)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndSB12Camera)
	pSequence.AppendAction(pEndBridgeCamera)
	pSequence.AppendAction(pEndCutscene)
	pSequence.AppendAction(pRestartProdTimer)

	pSequence.Play()
	
	# Get the Episode and register our first goal - Defend Artrus
	MissionLib.AddGoal("E6DefendArtrusGoal")
	
	return 0

################################################################################
##	CreateArtrusShips()
##
##	Create the ships that will be in Artrus when the player arrives.  AI will
##	be done once the player arrives in the set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateArtrusShips():
	# Import the ships we'll need
	# Get the set
	pSet = App.g_kSetManager.GetSet("Artrus3")
	# Create the ships
	pSanFrancisco 	= loadspacehelper.CreateShip("Galaxy", pSet, "San Francisco", "SFStart")
	pSanFrancisco.ReplaceTexture("data/Models/SharedTextures/FedShips/SanFrancisco.tga", "ID")
	pGalor1			= loadspacehelper.CreateShip("Galor", pSet, "Galor 1", "Galor1Start")
	pGalor2			= loadspacehelper.CreateShip("Galor", pSet, "Galor 2", "Galor2Start")
	
	# Damage the ships with script!
	DamageArtrusShips(pSanFrancisco, pGalor1, pGalor2)
	
################################################################################
##	DamageArtrusShips()
##
##	Damage the ships with script so it looks like they've been fighting for
##	a bit.
##
##	Args:	pSanFrancisco	- The San Francisco ship object
##			pGalor1			- The Galor 1 ship object
##			pGalor2			- The Galor 2 ship object
##
##	Return:	None
################################################################################
def DamageArtrusShips(pSanFrancisco, pGalor1, pGalor2):
	# Damage the shields on the SanFrancisco
	pShields = pSanFrancisco.GetShields()
	# Set the front shield to 90%
	pShields.SetCurShields(pShields.FRONT_SHIELDS, pShields.GetMaxShields(pShields.FRONT_SHIELDS) / 1.1)
	# Set the left and top shields to 80%
	pShields.SetCurShields(pShields.LEFT_SHIELDS, pShields.GetMaxShields(pShields.LEFT_SHIELDS) / 1.25)
	pShields.SetCurShields(pShields.TOP_SHIELDS, pShields.GetMaxShields(pShields.TOP_SHIELDS) / 1.25)
	
	# Damage the shields on Galor 1
	pShields = pGalor1.GetShields()
	# Set the front shield to 70%
	pShields.SetCurShields(pShields.FRONT_SHIELDS, pShields.GetMaxShields(pShields.FRONT_SHIELDS) / 1.43)
	# Set bottom shield to 50%
	pShields.SetCurShields(pShields.BOTTOM_SHIELDS, pShields.GetMaxShields(pShields.BOTTOM_SHIELDS) / 2.0)
	# Right shield to 80%
	pShields.SetCurShields(pShields.RIGHT_SHIELDS, pShields.GetMaxShields(pShields.RIGHT_SHIELDS) / 1.25)

################################################################################
##	GiveArtrusShipsAI()
##
##	Called when player first arrives in the Artrus system.  Gives AIs to all the
##	ship present in the system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GiveArtrusShipsAI():
	# Get the set
	pSet = App.g_kSetManager.GetSet("Artrus3")
	
	# Import the AIs
	import E6M1_AI_SanFrancisco_Artrus
	import E6M1_AI_Galor1
	
	# Get the ships
	pSanFrancisco	= App.ShipClass_GetObject(pSet, "San Francisco")
	pGalor1			= App.ShipClass_GetObject(pSet, "Galor 1")
	pGalor2			= App.ShipClass_GetObject(pSet, "Galor 2")
	
	# Assign the AIs
	pSanFrancisco.SetAI(E6M1_AI_SanFrancisco_Artrus.CreateAI(pSanFrancisco))
	pGalor1.SetAI(E6M1_AI_Galor1.CreateAI(pGalor1))
	pGalor2.SetAI(E6M1_AI_Galor1.CreateAI(pGalor2))
	
	#Make them commandable
	MissionLib.AddCommandableShip("San Francisco")

################################################################################
##	PlayerArrivesArtrus()
##
##	Called when player first arrives in the Artrus system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesArtrus():
	pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")	
	pZeiss		= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

	pSequence = App.TGSequence_Create()

	# Add an action right at the start to stream in all the voice lines in this
	# sequence, so the game doesn't hitch in the middle.
	pSequence.AddAction( App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") )

	pKiskaArriveArtrus1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveArtrus1", "Captain", 1, g_pMissionDatabase)
	pFelixArriveArtrus2		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveArtrus2", "Captain", 0, g_pMissionDatabase)
	pSFOnScreen				= App.TGScriptAction_Create(__name__, "SFOnScreen")
	pFelixArriveArtrus3		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveArtrus3", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
	pZeissArriveArtrus4		= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveArtrus4", None, 0, g_pMissionDatabase)
	pZeissArriveArtrus5		= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveArtrus5", None, 0, g_pMissionDatabase)
	pViewOff				= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pMiguelArriveArtrus6	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveArtrus6", None, 0, g_pMissionDatabase)
	pFelixArriveArtrus7		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveArtrus7", None, 0, g_pMissionDatabase)
	pResetGalor2AI			= App.TGScriptAction_Create(__name__, "ResetGalor2AI")
	
	pSequence.AppendAction(pKiskaArriveArtrus1, 5)
	pSequence.AddAction(pFelixArriveArtrus2, pKiskaArriveArtrus1)
	pSequence.AddAction(pSFOnScreen, pKiskaArriveArtrus1 ,1)
	pSequence.AppendAction(pFelixArriveArtrus3)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pZeissArriveArtrus4)
	pSequence.AppendAction(pZeissArriveArtrus5)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pMiguelArriveArtrus6)
	pSequence.AppendAction(pFelixArriveArtrus7)
	pSequence.AppendAction(pResetGalor2AI)

	pSequence.Play()
	
	# set the g_iMissionPositionCounter to play the right dialogue
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 1

###############################################################################
##
## SFOnScreen()
##
## Puts the SF on the Viewscreen
##
##	Args:	pAction passed on from the sequence
##
##	Return:	return 0 to dismiss the pAction
################################################################################
def SFOnScreen(pAction):
	pSet = App.g_kSetManager.GetSet("Artrus3")
	if (pSet == None):
		return 0
	pSF = App.ShipClass_GetObject(pSet, "San Francisco")
	if (pSF == None):
		return 0
	
	MissionLib.ViewscreenWatchObject(pSF)
		
	return 0

################################################################################
##	ResetGalor2AI()
##
##	Resets the AI of Galors 1 & 2 so that they will attack the player.  This is called
##	from the PlayerArrivesArtrus sequence after Zeiss is finished speaking.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetGalor2AI(pTGAction):
	# Get the AI and the ship
	import E6M1_AI_Galor2
	pShip	= App.ShipClass_GetObject(None, "Galor 2")
	pShip2	= App.ShipClass_GetObject(None, "Galor 1")
	if (pShip != None):
		pShip.SetAI(E6M1_AI_Galor2.CreateAI(pShip))
	if (pShip2 != None):
		pShip2.SetAI(E6M1_AI_Galor2.CreateAI(pShip2))
		
	return 0
	
################################################################################
##	SecondArtrusWaveArrives()
##
##	Calls function to create the second wave of Artrus Cards and does sequence
##	for when they arrive.  Called by timer.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def SecondArtrusWaveArrives(TGObject, pEvent):
#	kDebugObj.Print("Creating second wave of Artrus Cards")
	# Create the ships of the second wave
	CreateSecondArtrusWave()

	# Do our sequence stuff to announce their coming
	pSequence = App.TGSequence_Create()

	# Add an action right at the start to stream in all the voice lines in this
	# sequence, so the game doesn't hitch in the middle.
	pSequence.AddAction( App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") )
	
	pFelixSecondWave1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ArtrusSecondWave1", "Captain", 1, g_pMissionDatabase)
	pBrexSecondWave2	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1ArtrusSecondWave2", None, 0, g_pMissionDatabase)
	pSaffiSecondWave3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1ArtrusSecondWave3", None, 0, g_pMissionDatabase)
	if (g_bSanFranciscoDestroyed == FALSE):
		pSaffiSecondWave4	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1ArtrusSecondWave4", None, 0, g_pMissionDatabase)

	pSequence.AppendAction(pFelixSecondWave1, 0.001) # Say this starting next frame, since there's already enough happening this frame.
	pSequence.AppendAction(pBrexSecondWave2)
	pSequence.AppendAction(pSaffiSecondWave3)
	if (g_bSanFranciscoDestroyed == FALSE):
		pSequence.AppendAction(pSaffiSecondWave4, 3)
	
	pSequence.Play()

################################################################################
##	CreateSecondArtrusWave()
##
##	Creates the ships of the second wave and assigns them AIs
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateSecondArtrusWave():
	# Import needed ships
	
	# Get the set
	pSet = App.g_kSetManager.GetSet("Artrus3")
	
	# Create the ships
	pGalor3		= loadspacehelper.CreateShip("Galor", pSet, "Galor 3", "Galor3Enter", 1)
	pGalor4		= loadspacehelper.CreateShip("Galor", pSet, "Galor 4", "Galor4Enter", 1)
	pKeldon1	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 1", "Keldon1Enter", 1)
	
	# Import the AIs and assign them
	import E6M1_AI_SecondArtrusWave
	pGalor3.SetAI(E6M1_AI_SecondArtrusWave.CreateAI(pGalor3, "Galor3Enter", g_pGalor3_4Targets))
	# use keldon targets on these guys go they attack the player
	pGalor4.SetAI(E6M1_AI_SecondArtrusWave.CreateAI(pGalor4, "Galor4Enter", g_pKeldon1Targets))
	pKeldon1.SetAI(E6M1_AI_SecondArtrusWave.CreateAI(pKeldon1,"Keldon1Enter", g_pKeldon1Targets))
	
	# Create a timer to send the user to Ona after 150 seconds
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_GO_TO_ONA_TIMER, __name__+".LiuSayGoToOna", fStartTime + 210, 0, 0)
	# Save the ID of the prod timer, so we can stop it later.
	global g_iOnaTimer
	g_iOnaTimer = pTimer.GetObjID()
#	kDebugObj.Print("New prod timer ID is " + str(g_iOnaTimer))

################################################################################
##	SecondArtrusWaveDone()
##
##	Sequence that plays once all the Cards in Artrus have been destroyed.
##	Player told to go to Ona system.  Changes our goal to "Defend Ona" as well.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SecondArtrusWaveDone():
	#check that Liu hasn't spoken yet.
	if (g_bLiuSayGoToOnaPlayed == TRUE):
		return	
	#Stops the "liu says goto Ona" timer
#	kDebugObj.Print("Trying to stop the HurryUp timer...")
	global g_iOnaTimer
	if (g_iOnaTimer != App.NULL_ID):
#		kDebugObj.Print("Timer exists with ID " + str(g_iOnaTimer) + ".  Removing it.")
		bSuccess = App.g_kTimerManager.DeleteTimer(g_iOnaTimer)
#		if bSuccess:
#			kDebugObj.Print("Successfully removed.")
#		else:
#			kDebugObj.Print("Failed to remove timer.  Prod warning may trigger inappropriately.  :(")
		g_iOnaTimer = App.NULL_ID
	
	
	# Create the script action for LiuSayGoToOna()
	pGoToOna	= App.TGScriptAction_Create(__name__, "LiuSayGoToOna", None)
	
	# Make sure that the San Francisco is still around
	if (g_bSanFranciscoDestroyed == FALSE):
		# Get Zeiss
		pZeiss	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("DBridgeSet"), "Zeiss")
	
		pSequence = App.TGSequence_Create()

		# Add an action right at the start to stream in all the voice lines in this
		# sequence, so the game doesn't hitch in the middle.
		pSequence.AddAction( App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") )
	
		pFelixArtrusDone1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1SecondWaveDone1", "Captain", 1, g_pMissionDatabase)
		pKiskaArtrusDone2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1SecondWaveDone2", "Captain", 1, g_pMissionDatabase)
		pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pZeissArtrusDone3a	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1FirstWaveOver2", None, 0, g_pMissionDatabase)
		pZeissArtrusDone3	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1SecondWaveDone3", None, 0, g_pMissionDatabase)
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pFelixGoOna1		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna1", "Captain", 1, g_pMissionDatabase)
		pMiguelGoOna2		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna2", "Captain", 1, g_pMissionDatabase)
		
		pSequence.AppendAction(pFelixArtrusDone1)
		pSequence.AppendAction(pKiskaArtrusDone2)
		pSequence.AppendAction(pDBridgeViewOn)
		pSequence.AppendAction(pZeissArtrusDone3a)
		pSequence.AppendAction(pZeissArtrusDone3)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pFelixGoOna1)
		pSequence.AppendAction(pMiguelGoOna2)
		pSequence.AppendAction(pGoToOna)
		
		pSequence.Play()
		
	# If the SF has been destroyed, then just do the Go To Ona stuff
	else:
		pGoToOna.Play()
		
################################################################################
##	LiuSayGoToOna()
##
##	Called as script action from the SecondArtrusWaveDone() sequence.  Resets
##	our goals. This funtion can be called from a timer or a script action.
##
##	Args:	pTGAction	- The script action object.
##			pEvent		- The event arg passed on by the timer
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def LiuSayGoToOna(pTGAction, pEvent):
	# Set our flag
	global g_bLiuSayGoToOnaPlayed
	if (g_bLiuSayGoToOnaPlayed == FALSE):
		g_bLiuSayGoToOnaPlayed = TRUE
	else:
		return 0
	
	# Check where the player is and check our flag
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return 0
	
	if (pSet.GetName() == "Ona3"):
		# Reset the SF's AI so it heads to Ona
		ResetSFAI(None)
		return 0
	else:
		global g_bGoingToOna
		g_bGoingToOna = TRUE
		
	# Set our Prod line
	global g_sProdLine
	g_sProdLine = "E6M1ProdToOna"

	# Do sequence stuff
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")	
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")

	pSequence = App.TGSequence_Create()

	# Add an action right at the start to stream in all the voice lines in this
	# sequence, so the game doesn't hitch in the middle.
	pSequence.AddAction( App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") )
	
	pKiskaGoToOna3		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna3", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuGoOna4			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna4", None, 0, g_pMissionDatabase)
	pLiuGoOna5			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna5", None, 0, g_pMissionDatabase)
	
	# See which line Liu gives
	if (g_bSanFranciscoDestroyed == FALSE):
		pLiuGoOnaEnd	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna6", None, 0, g_pMissionDatabase)
	else:
		pLiuGoOnaEnd	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna7", None, 0, g_pMissionDatabase)
		
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pResetSFAI			= App.TGScriptAction_Create(__name__, "ResetSFAI")
	pFelixGoOna8		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna8", "Captain", 1, g_pMissionDatabase)
	pBrexGoOna9			= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna9", "Captain", 1, g_pMissionDatabase)
	pSaffiGoOna10		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1GoToOna10", "Captain", 1, g_pMissionDatabase)
	pRestartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 20)	# 20 sec prod timer
	
	pSequence.AppendAction(pKiskaGoToOna3)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuGoOna4)
	pSequence.AppendAction(pLiuGoOna5)
	pSequence.AppendAction(pLiuGoOnaEnd)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pResetSFAI)
	pSequence.AppendAction(pFelixGoOna8)
	pSequence.AppendAction(pBrexGoOna9)
	pSequence.AppendAction(pSaffiGoOna10)
	pSequence.AppendAction(pRestartProdTimer)

	pSequence.Play()
	
	# Get the Episode, remove our first goal - Defend Artrus
	# Add add our second goal - Defend Ona
	MissionLib.RemoveGoal("E6DefendArtrusGoal")
	MissionLib.AddGoal("E6DefendOnaGoal")
	
	CreateOnaCardShips()
	
	return 0
	
################################################################################
##	ResetSFAI()
##
##	Loads a new AI for the San Francisco so that it will warp to the Ona system
##	and engage the enemies.
##
##	Args:	pTGAction	- The action object
##
##	Return:	0	- Return 0 to keep calling sequence from crashing
################################################################################
def ResetSFAI(pTGAction):
	
	# Add Ona to the helm menu
	import Systems.Ona.Ona
	Systems.Ona.Ona.CreateMenus()
	
	# If the ship has been destroyed, return
	if (g_bSanFranciscoDestroyed == TRUE):
		return 0
	# Load the AI
	import E6M1_AI_SanFrancisco_Ona
	# Get the ship
	pSet	= App.g_kSetManager.GetSet("Artrus3")
	pShip	= App.ShipClass_GetObject(pSet, "San Francisco")
	# Make sure the ship still exists
	if (pShip == None):
		return 0
	# Set the AI
	pShip.SetAI(E6M1_AI_SanFrancisco_Ona.CreateAI(pShip))
	
	return 0

################################################################################
##	CreateOnaFedShips()
##
##	Creates the Devore and Venture in the Ona3 set.  Called when player first
##	warps to the Artrus system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateOnaFedShips():
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Ona3")
	# Get the models and create the ships
	pDevore		= loadspacehelper.CreateShip("Akira", pSet, "Devore", "DevoreWait")
	pDevore.ReplaceTexture("Data/Models/Ships/Akira/Devore.tga", "ID")
	pVenture	= loadspacehelper.CreateShip("Galaxy", pSet, "Venture", "VentureWait")
	pVenture.ReplaceTexture("data/Models/SharedTextures/FedShips/Venture.tga", "ID")


################################################################################
##	CreateOnaCardShips()
##
##	Creates the ships that will be present in the Ona system when player
##	arrives.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateOnaCardShips():
#	kDebugObj.Print("Creating Ona ships")
	
	# Set our flag
	global g_bOnaCardShipsCreated
	if (g_bOnaCardShipsCreated == FALSE):
		g_bOnaCardShipsCreated = TRUE
	else:
		return
	
	# Import the ships we'll need
	
	# Get the set
	pSet = App.g_kSetManager.GetSet("Ona3")
	
	# Create the ships (AI will be assigned once player comes out of warp)
	pGalor5		= loadspacehelper.CreateShip("Galor", pSet, "Galor 5", "Galor5Start", 1)
	pGalor6		= loadspacehelper.CreateShip("Galor", pSet, "Galor 6", "Galor6Start", 1)
	pGalor7		= loadspacehelper.CreateShip("Galor", pSet, "Galor 7", "Galor7Start", 1)
	pKeldon2	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 2", "Keldon2Start", 1)
		
	GiveOnaShipsAI()
	
################################################################################
##	PlayerArrivesOna()
##
##	Sequence that plays when the player arrives in the Ona system for first
##	time.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesOna():
#	kDebugObj.Print("PlayerArrivesOna()")
	# Do our sequence stuff
	pEBridgeSet	= App.g_kSetManager.GetSet("EBridgeSet")
	pMartin		= App.CharacterClass_GetObject(pEBridgeSet, "Martin")

	pSequence = App.TGSequence_Create()
	
	# Add an action right at the start to stream in all the voice lines in this
	# sequence, so the game doesn't hitch in the middle.
	pSequence.AddAction( App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") )

	pFelixArriveOna1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveOna1", "Captain", 1, g_pMissionDatabase)
	pMiguelArriveOna2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveOna2", None, 0, g_pMissionDatabase)
	pKiskaArriveOna3	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveOna3", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Martin")
	pMartinArriveOna4	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveOna4", None, 0, g_pMissionDatabase)
	pMartinArriveOna5	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveOna5", None, 0, g_pMissionDatabase)
	
	# Check and see if the SF survived
	if (g_bSanFranciscoDestroyed == FALSE):
		pMartinArriveOna6	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveOna6a", None, 0, g_pMissionDatabase)
	else:
		pMartinArriveOna6	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1ArriveOna6", None, 0, g_pMissionDatabase)
	
	pViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pCheckArtrusCards 	= App.TGScriptAction_Create(__name__, "DarnArtrusCards")
	
	pSequence.AppendAction(pFelixArriveOna1, 5)
	pSequence.AppendAction(pMiguelArriveOna2)
	pSequence.AppendAction(pKiskaArriveOna3)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pMartinArriveOna4)
	pSequence.AppendAction(pMartinArriveOna5)
	pSequence.AppendAction(pMartinArriveOna6)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pCheckArtrusCards)

	pSequence.Play()
	
	# get the Devore and Venture
	pDevore = App.ShipClass_GetObject(None, "Devore")
	pVenture = App.ShipClass_GetObject(None, "Venture")
	
	# Import the AI's we'll use	and Set the AIs
	if (pDevore != None):
		import E6M1_AI_Devore_Ona
		pDevore.SetAI(E6M1_AI_Devore_Ona.CreateAI(pDevore))
		#Make them commandable
		MissionLib.AddCommandableShip("Devore")
	if (pVenture != None):
		import E6M1_AI_Venture_Ona
		pVenture.SetAI(E6M1_AI_Venture_Ona.CreateAI(pVenture))
		MissionLib.AddCommandableShip("Venture")
		MissionLib.DamageShip("Venture", 0.2, 0.3, 1)		
	# set the g_iMissionPositionCounter to play the right dialogue
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 2
	
################################################################################
##	GiveOnaShipsAI()
##
##	Assigns the AI to the Ona ships when the player enters the set for the
##	first time.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GiveOnaShipsAI():
#	kDebugObj.Print("Giving Ona ships AI")
	
	import E6M1_AI_OnaGalor
	import E6M1_AI_OnaKeldon
	
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Ona3")
	
	# Get the ships
	pGalor5		= App.ShipClass_GetObject(pSet, "Galor 5")
	pGalor6		= App.ShipClass_GetObject(pSet, "Galor 6")
	pGalor7		= App.ShipClass_GetObject(pSet, "Galor 7")
	pKeldon2	= App.ShipClass_GetObject(pSet, "Keldon 2")
	
	# Assign the AI's
	pGalor5.SetAI(E6M1_AI_OnaGalor.CreateAI(pGalor5, g_pGalor5Targets))
	pGalor6.SetAI(E6M1_AI_OnaGalor.CreateAI(pGalor6, g_pGalor6Targets))
	pGalor7.SetAI(E6M1_AI_OnaGalor.CreateAI(pGalor7, g_pGalor7Targets))
	pKeldon2.SetAI(E6M1_AI_OnaKeldon.CreateAI(pKeldon2, g_pKeldon2Targets))

################################################################################
##	CreateSecondOnaWave()
##
##	Creates the second wave of ship to enter the Ona systems and assigns
##	their AI.  Called from timer started in ObjectExitsArtrusOrOna()
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CreateSecondOnaWave(TGObject, pEvent):
	# Call our sequence announcing their arrival
	SecondOnaWaveArrives()
	
	# Import the ships needed
	# Get the set
	pSet = App.g_kSetManager.GetSet("Ona3")
	
	pGalor8		= loadspacehelper.CreateShip("Galor", pSet, "Galor 8", "Card1Enter", 1)
	pGalor9		= loadspacehelper.CreateShip("Galor", pSet, "Galor 9", "Card3Enter", 1)
	pKeldon3	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 3", "Card2Enter", 1)
	
	# Import and assign the AIs
	import E6M1_AI_OnaGalor
	import E6M1_AI_OnaKeldon
	
	pGalor8.SetAI(E6M1_AI_OnaGalor.CreateAI(pGalor8, g_pGalor8Targets))
	pGalor9.SetAI(E6M1_AI_OnaGalor.CreateAI(pGalor9, g_pGalor9Targets))
	pKeldon3.SetAI(E6M1_AI_OnaKeldon.CreateAI(pKeldon3, g_pKeldon3Targets))

################################################################################
##	SecondOnaWaveArrives()
##
##	Sequence that plays when the second wave of Ona ships appears
##
##	Args:	None
##
##	Return:	None
################################################################################
def SecondOnaWaveArrives():
	# Call our function to create the transports around the Savoy Station
	CreateTransports()

	pSequence = App.TGSequence_Create()

	# Add an action right at the start to stream in all the voice lines in this
	# sequence, so the game doesn't hitch in the middle.
	pSequence.AddAction( App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") )
	
	pFelixSecondOnaWave1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1SecondOnaWave1", "Captain", 1, g_pMissionDatabase)
	pBrexSecondOnaWave3		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1SecondOnaWave3", None, 0, g_pMissionDatabase)
	pSaffiSecondOnaWave4	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1SecondOnaWave4", None, 0, g_pMissionDatabase)
	
	pSequence.AppendAction(pFelixSecondOnaWave1, 2)
	pSequence.AppendAction(pBrexSecondOnaWave3)
	pSequence.AppendAction(pSaffiSecondOnaWave4)
	
	pSequence.Play()

################################################################################
##	FallBackToSavoy()
##
##	Plays sequence telling player to fall back to Savoy3.  Also calls functions
##	that reset the Fed ship AI and create the Savoy Station.  Removes our old
##	goals and registers new ones. Also calls a timer for back up Ona cards
##
##	Args:	None
##
##	Return:	None
################################################################################
def FallBackToSavoy():
	# Set our prod line
	global g_sProdLine
	g_sProdLine = "E6M1ProdToSavoy3"
	
	# Do the sequence stuff
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")	
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")

	pSequence = App.TGSequence_Create()

	# Add an action right at the start to stream in all the voice lines in this
	# sequence, so the game doesn't hitch in the middle.
	pSequence.AddAction( App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") )
	
	pFelixIncoming	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "gt029", "Captain", 1, g_pGeneralDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuEvac1a		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy1a", None, 0, g_pMissionDatabase)
	pLiuEvac1		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy1", None, 0, g_pMissionDatabase)
	pLiuEvac2		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy2", None, 0, g_pMissionDatabase)
	if (g_sRescueShipName == "Devore"):
		pLiuEvac3		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy3a", None, 0, g_pMissionDatabase)
	elif (g_sRescueShipName == "SanFrancisco"):
		pLiuEvac3		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy3b", None, 0, g_pMissionDatabase)
	elif (g_sRescueShipName == "Venture"):
		pLiuEvac3		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy3c", None, 0, g_pMissionDatabase)
	pLiuEvac4		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy4", None, 0, g_pMissionDatabase)
	pLiuEvac5		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy5", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pResetFedAIs	= App.TGScriptAction_Create(__name__, "ResetFedShipAIForSavoy3")
	pRestartProd	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 20)	# 30sec on prod timer
	
	pSequence.AppendAction(pFelixIncoming)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuEvac1a)
	pSequence.AppendAction(pLiuEvac1)
	pSequence.AppendAction(pLiuEvac2)
	pSequence.AppendAction(pLiuEvac3)
	pSequence.AppendAction(pLiuEvac4)
	pSequence.AppendAction(pLiuEvac5)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pResetFedAIs)
	pSequence.AppendAction(pRestartProd)
	
	pSequence.Play()
	
	# Get the Episode, remove our second goal - Defend Ona
	# Add add our third and fourth goals - Intercept Galors & Protect Devore
	MissionLib.RemoveGoal("E6DefendOnaGoal")
	MissionLib.AddGoal("E6InterceptGalorsGoal")
	MissionLib.AddGoal("E6ProtectTransportsGoal")
	
	# this timer will call Cardassian reinforcments to pound on the user if they don't goto Savoy
#	print "starting the more_Ona_cards timer"
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_MORE_ONA_CARDS_TIMER, __name__+".MoreOnaCards", fStartTime + 65, 0, 0)

################################################################################
##	MoreOnaCards()
##
##	Creates the Cardassians in Ona which beat on the user for not warping to Savoy when told to
##	Called from timer event started in FallBackToSavoy.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def MoreOnaCards(TGObject, pEvent):
#	print "more freakin cards since you didn't warp to savoy."
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Ona3")
	
	# Create the ships
	pKeldon13	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 13", "Card1Enter", 1) 
	pKeldon14	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 14", "Card2Enter", 1)
	pKeldon15	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 15", "Card3Enter", 1)
	pKeldon16	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 16", "Galor5Start", 1)
	pKeldon17	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 17", "Galor6Start", 1)
	
	# Import our AIs and assign them
	import E6M1_AI_More_Keldon
	pKeldon13.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon13, g_pKeldon7Targets))
	pKeldon14.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon14, g_pKeldon7Targets))
	pKeldon15.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon15, g_pKeldon7Targets))
	pKeldon16.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon16, g_pKeldon7Targets))
	pKeldon17.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon17, g_pKeldon7Targets))
	
	
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	if (sSetName == "Ona3"):
		pFelixMoreShips	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "Incoming6", "Captain", 1, g_pGeneralDatabase)
		pFelixMoreShips.Play()
		

################################################################################
##	CreateTransports()
##
##	Creates the transports in the Savoy 1 set.  Called when the second Ona
##	wave is destroyed.  Creates instance handlers on the ships so we can know
##	when they come under attack
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateTransports():
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Savoy1")
	
	# Create the ships
	pTransport1	= loadspacehelper.CreateShip("Transport", pSet, "Shannon", "Transport1Start")
	pTransport2	= loadspacehelper.CreateShip("Transport", pSet, "Inverness", "Transport2Start")
	pTransport3	= loadspacehelper.CreateShip("Transport", pSet, "Cambridge", "Transport3Start")
	
	# Assign the transports their AI
	import E6M1_AI_Transport
	pTransport1.SetAI(E6M1_AI_Transport.CreateAI(pTransport1))
	pTransport2.SetAI(E6M1_AI_Transport.CreateAI(pTransport2))
	pTransport3.SetAI(E6M1_AI_Transport.CreateAI(pTransport3))
	
	# Create our instance handlers
	pTransport1.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".TransportHit")
	pTransport2.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".TransportHit")
	pTransport3.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".TransportHit")
	
	# Make the transport's impulse and warp engines invincibale so it can escape.
	# transport 1
	pWarp1 = pTransport1.GetWarpEngineSubsystem()
	pImpulse1 = pTransport1.GetImpulseEngineSubsystem()
	if (pWarp1 and pImpulse1):
		MissionLib.MakeSubsystemsInvincible(pImpulse1, pWarp1)
	# transport 2
	pWarp2 = pTransport2.GetWarpEngineSubsystem()
	pImpulse2 = pTransport2.GetImpulseEngineSubsystem()
	if (pWarp2 and pImpulse2):
		MissionLib.MakeSubsystemsInvincible(pImpulse2, pWarp2)
	# transport 3
	pWarp3 = pTransport3.GetWarpEngineSubsystem()
	pImpulse3 = pTransport3.GetImpulseEngineSubsystem()
	if (pWarp3 and pImpulse3):
		MissionLib.MakeSubsystemsInvincible(pImpulse3, pWarp3)
		
################################################################################
##	TransportHit()
##
##	Event handler called when one of the transports is hit by weapons fire.
##	Checks to make sure it came from the Cards and play line specific to each
##	transport.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def TransportHit(TGObject, pEvent):
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	if (sSetName == "Savoy1"):	
		# Get the attacker
		pAttacker	= App.ShipClass_Cast(pEvent.GetFiringObject())
		if (pAttacker == None):
			return
		sAttackerName = pAttacker.GetName()
		
		# Make sure its a Cardassian
		if (sAttackerName not in g_lCardShipNames):
			TGObject.CallNextHandler(pEvent)
			return
			
		# It is a Cardassian, let's see which transport it is
		pTarget	= App.ShipClass_Cast(pEvent.GetDestination())
		if (pTarget == None):
			return
		sTargetName = pTarget.GetName()
		
		global g_bShannonHitCalled
		global g_bInverHitCalled
		global g_bCamHitCalled
	
		if (sTargetName == "Shannon") and (g_bShannonHitCalled == FALSE):
			g_bShannonHitCalled = TRUE
			pAttackLine1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ShannonAttacked1", "Captain", 1, g_pMissionDatabase)
			pAttackLine2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1ShannonAttacked2", None, 0, g_pMissionDatabase)
			
		elif (sTargetName == "Inverness") and (g_bInverHitCalled == FALSE):
			g_bInverHitCalled = TRUE
			pAttackLine1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1InverAttacked1", "Captain", 1, g_pMissionDatabase)
			pAttackLine2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1InverAttacked2", None, 0, g_pMissionDatabase)
			
		elif (sTargetName == "Cambridge") and (g_bCamHitCalled == FALSE):
			g_bCamHitCalled = TRUE
			pAttackLine1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1CamAttacked1", None, 0, g_pMissionDatabase)
			pAttackLine2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1CamAttacked2", "Captain", 1, g_pMissionDatabase)
			
		else:
			TGObject.CallNextHandler(pEvent)
			return
			
		# Build and play our sequence
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(pAttackLine1, 15)
		pSequence.AppendAction(pAttackLine2)
		
		pSequence.Play()
	
	# All done, call the next handler for this event
	TGObject.CallNextHandler(pEvent)
		
################################################################################
##	ResetFedShipAIForSavoy3()
##
##	Resets the AIs for all surviving ship in Ona so they'll warp to Savoy 3
##	and such.  Also decides what ship will be the "Rescue" ship the Devore has
##	been destroyed.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetFedShipAIForSavoy3(pTGAction):
	
	# add savoy to the helm menu
	import Systems.Savoy.Savoy
	Systems.Savoy.Savoy.CreateMenus()
	
	# pull out the Artrus system
	pKiskaMenu = g_pKiska.GetMenu()
	pSetCourse = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
	pArtrus = pSetCourse.GetSubmenu("Artrus")
	pSetCourse.DeleteChild(pArtrus)
	
	global g_sRescueShipName
	# Import the AIs we need
	import E6M1_AI_Rescue
	import E6M1_AI_SanFrancisco_Savoy3
	import E6M1_AI_Venture_Savoy3
	
	# Get the set
	pSet = App.g_kSetManager.GetSet("Ona3")
	
	# The default stuff if the Devore exists
	if (g_bDevoreDestroyed == FALSE):
#		kDebugObj.Print("Setting Devore as rescue ship")
		g_sRescueShipName = "Devore"
		pDevore	= App.ShipClass_GetObject(pSet, "Devore")
		pDevore.SetAI(E6M1_AI_Rescue.CreateAI(pDevore, g_pRescueTargets))
		MissionLib.RemoveCommandableShip("Devore")
		# Do the San Francisco
		if (g_bSanFranciscoDestroyed == FALSE):
			pSanFrancisco = App.ShipClass_GetObject(pSet, "San Francisco")
			pSanFrancisco.SetAI(E6M1_AI_SanFrancisco_Savoy3.CreateAI(pSanFrancisco, g_pRescueTargets))
		# Do the Venture
		if (g_bVentureDestroyed == FALSE):
			pVenture	= App.ShipClass_GetObject(pSet, "Venture")
			pVenture.SetAI(E6M1_AI_Venture_Savoy3.CreateAI(pVenture, g_pRescueTargets))
	# If the Devore has been destroyed, check the others
	elif (g_bSanFranciscoDestroyed == FALSE):
		# The SF still exists, so make it the Rescue ship
		g_sRescueShipName = "SanFrancisco"
		pSanFrancisco	= App.ShipClass_GetObject(pSet, "San Francisco")
		pSanFrancisco.SetAI(E6M1_AI_Rescue.CreateAI(pSanFrancisco, g_pRescueTargets))
		MissionLib.RemoveCommandableShip("San Francisco")
		# Do the Venture
		if (g_bVentureDestroyed == FALSE):
			pVenture	= App.ShipClass_GetObject(pSet, "Venture")
			pVenture.SetAI(E6M1_AI_Venture_Savoy3.CreateAI(pVenture, g_pRescueTargets))
	elif (g_bVentureDestroyed == FALSE):
		# The Venture exists, so it becomes the rescue ship.
		g_sRescueShipName = "Venture"
		pVenture	= App.ShipClass_GetObject(pSet, "Venture")
		pVenture.SetAI(E6M1_AI_Rescue.CreateAI(pVenture, g_pRescueTargets))
		MissionLib.RemoveCommandableShip("Venture")
		
	return 0
	
################################################################################
##	PlayerArrivesSavoy3()
##
##	Called when the player enters Savoy3.  Starts timer that triggers second
##	wave.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesSavoy3():
	pSequence = App.TGSequence_Create()
	
	pSaffiSavoy31			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1Savoy3-1", "Captain", 1, g_pMissionDatabase)
	pCreateFirstSavoyWave	= App.TGScriptAction_Create(__name__, "CreateFirstSavoyWave")
	pFelixSavoy33			= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1Savoy3-3", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AppendAction(pSaffiSavoy31, 10)
	pSequence.AppendAction(pCreateFirstSavoyWave, 10)
	pSequence.AppendAction(pFelixSavoy33)
	
	pSequence.Play()
	
	# Start the timer for the second wave
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SECOND_SAVOY_WAVE_TIMER, __name__+".CreateSecondSavoyWave", fStartTime + 90, 0, 0)
	
	# set the g_iMissionPositionCounter to play the right dialogue
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 3

################################################################################
##	RescueWarping()
##
##	Called from E6M1_AI_Rescue.py when the rescue ship is about to warp from
##	Savoy 3 to Savoy 1.  Plays short line.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RescueWarping():
	# Figure out which ship is the rescue ship and
	# call the correct line.
	# If it's the SanFrancisco
	if (g_sRescueShipName == "SanFrancisco"):
		# Get Zeiss
		pZeiss	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("DBridgeset"), "Zeiss")
		
		pViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pWarpLine	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy8a", None, 0, g_pMissionDatabase)
		pViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		
	# If it's the Devore
	elif (g_sRescueShipName == "Devore"):
		# Get Martin
		pMartin	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("EBridgeset"), "Martin")
		
		pViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Martin")
		pWarpLine	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy8b", None, 0, g_pMissionDatabase)
		pViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		
	# If it's the Venture
	else:
		# Get Dawson
		pDawson	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("DBridgeSet"), "Dawson")
		
		pViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Dawson")
		pWarpLine	= App.CharacterAction_Create(pDawson, App.CharacterAction.AT_SAY_LINE, "E6M1EvacSavoy8c", None, 0, g_pMissionDatabase)
		pViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

	# Build the sequence and play it
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pWarpLine)
	pSequence.AppendAction(pViewOff)
	
	pSequence.Play()
	
################################################################################
##	CreateFirstSavoyWave()
##
##	Creates the first wave of Cards to attack Savoy 3.  Called as a script
##	action.
##
##	Args:	pTGAction	- The script action
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CreateFirstSavoyWave(pTGAction):
	# Import the ships we need
	# Get the set
	pSet = App.g_kSetManager.GetSet("Savoy3")
	# Create the ships
	pGalor10	= loadspacehelper.CreateShip("Galor", pSet, "Galor 10", "Galor10Enter", 1)
	pKeldon4	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 4", "Keldon4Enter", 1)
	
	# Get the AIs and assign them
	import E6M1_AI_Keldon
	import E6M1_AI_OnaGalor
	pGalor10.SetAI(E6M1_AI_OnaGalor.CreateAI(pGalor10, g_pGalor10Targets))
	pKeldon4.SetAI(E6M1_AI_Keldon.CreateAI(pKeldon4, g_pKeldon4Targets))
	
	return 0

################################################################################
##	CreateSecondSavoyWave()
##
##	Creates second Savoy wave which will attack the station in Savoy 1.  Called
##	by timer started in PlayerArrivesSavoy3.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event sent
##
##	Return:	None
################################################################################
def CreateSecondSavoyWave(TGObject, pEvent):
	# Get the set
	pSet = App.g_kSetManager.GetSet("Savoy3")
	# Create the ships
	pGalor11	= loadspacehelper.CreateShip("Galor", pSet, "Galor 11", "Galor11Enter", 1)
	pGalor12	= loadspacehelper.CreateShip("Galor", pSet, "Galor 12", "Galor12Enter", 1)
	pKeldon5	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 5", "Keldon5Enter", 1)
	
	# Import and assign the AIs
	import E6M1_AI_Savoy3Galor
	import E6M1_AI_Savoy3Keldon
	pGalor11.SetAI(E6M1_AI_Savoy3Galor.CreateAI(pGalor11, g_pGalor11Targets, "Galor11Enter"))
	pGalor12.SetAI(E6M1_AI_Savoy3Galor.CreateAI(pGalor12, g_pGalor12Targets, "Galor12Enter"))
	pKeldon5.SetAI(E6M1_AI_Savoy3Keldon.CreateAI(pKeldon5, g_pKeldon5Targets, "Keldon5Enter"))
	
	# Do the line that plays when the second wave arrives
	pFelixLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1SecondSavoyWave1", "Captain", 1, g_pMissionDatabase)
	pFelixLine.Play()

	# Start the timer for the third Savoy wave
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_THIRD_SAVOY_WAVE_TIMER, __name__ + ".CreateThirdSavoyWave", fStartTime + 251, 0, 0)
	
	# get Galor 10 and Kelodn 4 and give them the AI from above
	pGalor10 = App.ShipClass_GetObject(None, "Galor 10")
	pKeldon4 = App.ShipClass_GetObject(None, "Keldon 4")
	if (pGalor10 != None):
		pGalor10.SetAI(E6M1_AI_Savoy3Galor.CreateAI(pGalor10, g_pGalor10Targets, "Galor10Enter"))
	if (pKeldon4 != None):
		pKeldon4.SetAI(E6M1_AI_Savoy3Keldon.CreateAI(pKeldon4, g_pKeldon4Targets, "Keldon4Enter"))
	
	DeleteOnaCards()

################################################################################
##	DeleteOnaCards()
##
##	Remove any Cardassians in the ona set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def DeleteOnaCards():
	pSet	= App.g_kSetManager.GetSet("Ona3")
	
	for sShipName in g_lMoreCardShipNames:
		pKeldon	= App.ShipClass_GetObject(pSet, sShipName)
		if (pKeldon != None):
			pKeldon.SetDeleteMe(1)
			
################################################################################
##	SecondSavoyWaveWarps()
##
##	Sequence that plays after the second Savoy 3 wave warps to Savoy 1.  Called from
##	EnterSet() when one of the Cards enters the warp set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SecondSavoyWaveWarps():
	# let the player leave savoy 3
	global g_bPlayerStuckInSavoy3
	g_bPlayerStuckInSavoy3 = FALSE
	# Check our flag
	if (g_bCardsHaveWarped == FALSE):
		global g_bCardsHaveWarped
		g_bCardsHaveWarped = TRUE
	else:
		return
		
	pSequence = App.TGSequence_Create()
	
	pFelixSavoy3Warp1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1Savoy3Warp1", None, 0, g_pMissionDatabase)
	pKiskaSavoy3Warp2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1Savoy3Warp2", None, 0, g_pMissionDatabase)
	pSaffiSavoy3Warp3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1Savoy3Warp3", None, 0, g_pMissionDatabase)
	
	pSequence.AppendAction(pFelixSavoy3Warp1, 4)
	pSequence.AppendAction(pKiskaSavoy3Warp2)
	pSequence.AppendAction(pSaffiSavoy3Warp3)
	
	pSequence.Play()
	
################################################################################
##	PlayerArrivesSavoy1()
##
##	Plays sequence.  Called when player arrives in Savoy 1.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesSavoy1():
	# Check what ship  is the rescue ship and play that sequence
	if (g_sRescueShipName == "Devore"):
		PlayerArrivesSavoy1Devore()
	elif (g_sRescueShipName == "SanFrancisco"):
		PlayerArrivesSavoy1SF()
	else:
		# There's no audio for the Venture, so return
		return
	
	# set the g_iMissionPositionCounter to play the right dialogue
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 4
		
################################################################################
##	PlayerArrivesSavoy1Devore()
##
##	Sequence that plays if the Devore is the Rescue ship
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesSavoy1Devore():
	pEBridge	= App.g_kSetManager.GetSet("EBridgeSet")
	pMartin		= App.CharacterClass_GetObject(pEBridge, "Martin")
	
	pSequence = App.TGSequence_Create()
	
	pEBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Martin")
	pMartinSavoy1Enter	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1Savoy1Enter1a", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pEBridgeViewOn)
	pSequence.AppendAction(pMartinSavoy1Enter)
	pSequence.AppendAction(pViewOff)
	
	pSequence.Play()

################################################################################
##	PlayerArrivesSavoy1SF()
##
##	Sequence that plays if the SF is the rescue ship.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesSavoy1SF():
		pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
		pZeiss		= App.CharacterClass_GetObject(pDBridge, "Zeiss")
		
		pSequence = App.TGSequence_Create()
		
		pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pZeissSavoy1Enter	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1Savoy1Enter1b", None, 0, g_pMissionDatabase)
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		
		pSequence.AddAction(pDBridgeViewOn)
		pSequence.AddAction(pZeissSavoy1Enter, pDBridgeViewOn)
		pSequence.AddAction(pViewOff, pZeissSavoy1Enter)
		
		pSequence.Play()

################################################################################
##	RescueAtStation()
##
##	Called when the Devore reaches the station.  Starts timer for the warping of
##	the first shuttle.  Called from E6M1_AI_Rescue.py
##
##	Args:	None
##
##	Return:	None
################################################################################
def RescueAtStation():
	# Start the timer
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_FIRST_TRANS_WARP, __name__+".FirstTransportWarps", fStartTime + 210, 0, 0)
	
################################################################################
##	RescueCallsForHelp():
##
##	Called by E6M1_AI_Rescue.py when Cards enter Savoy1.  Also resets the AI
## 	of any Fed ship so they will come to "Rescue's" aid.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RescueCallsForHelp():
	#check our flag
	if (g_bRescueCalledForHelp == TRUE):
		return
	global g_bRescueCalledForHelp
	g_bRescueCalledForHelp	= TRUE
	
	# Set our prod line
	global g_sProdLine
	g_sProdLine = "E6M1ProdToSavoy1"
	
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	pSequence = App.TGSequence_Create()
	
	# If the player is not in Savoy 1, do the audio
	if (sSetName != "Savoy1"):
		# Get the correct lines for the Rescue ship
		pShipSpecific		= ShipSpecificCallForHelp()
		pSaffiSavoyHail3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M1SavoyHail3", "Captain", 1, g_pMissionDatabase)
		pRestartProd		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 20)	# 20 sec on the prod timer
		pResetFedAIs		= App.TGScriptAction_Create(__name__, "ResetFedAIToSavoy1")
	
		pSequence.AppendAction(pShipSpecific)
		pSequence.AppendAction(pSaffiSavoyHail3)
		pSequence.AppendAction(pRestartProd)
		pSequence.AppendAction(pResetFedAIs)
	
	# If the player has arrived in Savoy 1, just reset the Fed's AIs
	else:
		pResetFedAIs	= App.TGScriptAction_Create(__name__, "ResetFedAIToSavoy1")
		pSequence.AppendAction(pResetFedAIs)

	# Play the sequence.
	MissionLib.QueueActionToPlay(pSequence)
	
	# Remove the intercept galor goal
	MissionLib.RemoveGoal("E6InterceptGalorsGoal")

################################################################################
##	ResetFedAIToSavoy1()
##
##	Resets the AIs of any surviving Fed ships so they will aid the Rescue ship.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	None
################################################################################
def ResetFedAIToSavoy1(pTGAction):
	# See if the SF still exists and is not the rescue ship
	if (g_bSanFranciscoDestroyed == FALSE) and (g_sRescueShipName <> "SanFrancisco"):
		import E6M1_AI_SanFrancisco_Savoy1
		pSanFrancisco = App.ShipClass_GetObject(None, "San Francisco")
		pSanFrancisco.SetAI(E6M1_AI_SanFrancisco_Savoy1.CreateAI(pSanFrancisco, g_pRescueTargets))
	# See if the Venture is still around
	if (g_bVentureDestroyed == FALSE) and (g_sRescueShipName <> "Venture"):
		import E6M1_AI_Venture_Savoy1
		pVenture = App.ShipClass_GetObject(None, "Venture")
		pVenture.SetAI(E6M1_AI_Venture_Savoy1.CreateAI(pVenture))
		
	return 0

################################################################################
##	CreateThirdSavoyWave()
##
##	Creates the third wave of Cardassians in Savoy 3, which then warp to
##	Savoy 1.  Called from timer event started in CreateSecondSavoyWave().
##  This will also be called when the second wave is destroyed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CreateThirdSavoyWave(TGObject, pEvent):
	if (g_bThirdCardWaveMade == TRUE):
		return 0
	if (g_bThirdCardWaveMade == FALSE):
		global g_bThirdCardWaveMade
		g_bThirdCardWaveMade = TRUE
		
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Savoy3")
	
	# Create the ships
	pKeldon6	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 6", "Galor11Enter", 1)
	pKeldon7	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 7", "Keldon5Enter", 1)
	
	# Import our AIs and assign them
	import E6M1_AI_Savoy1Keldon
	pKeldon6.SetAI(E6M1_AI_Savoy1Keldon.CreateAI(pKeldon6, g_pKeldon6Targets, "Galor11Enter"))
	pKeldon7.SetAI(E6M1_AI_Savoy1Keldon.CreateAI(pKeldon7, g_pKeldon7Targets, "Keldon5Enter"))
	
	pSequence = App.TGSequence_Create()
	pMiguelMoreShips	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M1ThirdSavoyWave1", "Captain", 1, g_pMissionDatabase)
	pFelixMoreShips	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ThirdSavoyWave2", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction(pMiguelMoreShips, 5)
	pSequence.AppendAction(pFelixMoreShips)
	pSequence.Play()
		
################################################################################
##	FirstTransportWarps()
##
##	Called from timer event started when the "rescue" ship reaches the station.
##	Resets the AI on Transport 1 so it warps out.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def FirstTransportWarps(TGObject, pEvent):
	# See if our list contains the name of the first transport,
	# if it does, than it hasn't been destroyed and can warp out.
	if ("Shannon" in g_lTransportNames):
		# Get the set and the ship and assign the AI
		pSet	= App.g_kSetManager.GetSet("Savoy1")
		pShip	= App.ShipClass_GetObject(pSet, "Shannon")
		if (pShip == None):
			return
			
		import E6M1_AI_WarpToStarbase
		pShip.SetAI(E6M1_AI_WarpToStarbase.CreateAI(pShip))
		#make the ship invincible so it doesn't blow up on its way home.
		pShip.SetInvincible(1)

		# Do the lines that let is know its gone
		pSequence = App.TGSequence_Create()

		pKiskaTransClear1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1FirstTransportClear1", "Captain", 1, g_pMissionDatabase)
		if (len(g_lTransportNames) == 3):
			pBrexTransClear2	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1FirstTransportClear2", "Captain", 1, g_pMissionDatabase)

		pSequence.AppendAction(pKiskaTransClear1, 1)
		if (len(g_lTransportNames) == 3):
			pSequence.AppendAction(pBrexTransClear2)

		pSequence.Play()
	
	# Start the timer for the next transport
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SECOND_TRANS_WARP, __name__+".SecondTransportWarps", fStartTime + 90, 0, 0)
	
################################################################################
##	SecondTransportWarps()
##
##	Called from timer event.  Has the second transport warp out if it still
##	exists.  Starts the timer for the third transport.  If this was the last
##	remaining transport, and transport one survived, than call EnoughEscaped().
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def SecondTransportWarps(TGObject, pEvent):
	# See if our list contains the name of the second transport,
	# if it does, than it hasn't been destroyed and can warp out.
	if ("Inverness" in g_lTransportNames):
		# Get the set and the ship and assign the AI
		pSet	= App.g_kSetManager.GetSet("Savoy1")
		pShip	= App.ShipClass_GetObject(pSet, "Inverness")
		if (pShip == None):
			return

		import E6M1_AI_WarpToStarbase
		pShip.SetAI(E6M1_AI_WarpToStarbase.CreateAI(pShip))
		#make the ship invincible so it doesn't blow up on its way home.
		pShip.SetInvincible(1)

		# Do the lines that let is know its gone
		pSequence = App.TGSequence_Create()

		pKiskaTransClear1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1SecondTransportClear1", "Captain", 1, g_pMissionDatabase)
		pKiskaTransClear2	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M1SecondTransportClear2", "Captain", 1, g_pMissionDatabase)

		pSequence.AppendAction(pKiskaTransClear1)
		pSequence.AppendAction(pKiskaTransClear2, 3)

		MissionLib.QueueActionToPlay(pSequence)

		# Check and see if this was the last transport alive.
		# If so call our win dialogue.
		if (g_iEscapedTransports == 1) and (len(g_lTransportNames) == 2):
			EnoughEscaped(None)
	# Start the timer for the next transport
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_THIRD_TRANS_WARP, __name__+".ThirdTransportWarps", fStartTime + 90, 0, 0)
	

		
################################################################################
##	ThirdTransportWarps()
##
##	Called from timer event.  Has the third transport warp out if it still
##	exists.  If it is the last transport and one other has escaped, calls
##	StationClear().
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ThirdTransportWarps(TGObject, pEvent):
	# See if our list contains the name of the Third transport,
	# if it does, than it hasn't been destroyed and can warp out.
	if ("Cambridge" in g_lTransportNames):
		# Get the set and the ship and assign the AI
		pSet	= App.g_kSetManager.GetSet("Savoy1")
		pShip	= App.ShipClass_GetObject(pSet, "Cambridge")
		if (pShip == None):
			return

		import E6M1_AI_WarpToStarbase
		pShip.SetAI(E6M1_AI_WarpToStarbase.CreateAI(pShip))
		#make the ship invincible so it doesn't blow up on its way home.
		pShip.SetInvincible(1)

		
		# If there are more than 2 transports in the list,
		# call StationClear(), if there isn't, then we've 
		# already called mission lost.
		if (len(g_lTransportNames) >= 2):
			StationClear()

################################################################################
##	EnoughEscaped()
##
##	Called as script action from TransportDestroyed() if the final transport
##	has been destroyed and two others have escaped.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def EnoughEscaped(pTGAction):
	# Play a sequence based on the remaining Federation ships
	pSequence = App.TGSequence_Create()

	# Action to link us to the next mission
	pLinkToE6M2	= App.TGScriptAction_Create(__name__, "LinkToE6M2")

	# If the Devore exists	
	if (g_bDevoreDestroyed == FALSE):
		pMartin	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("EBridgeSet"), "Martin")
		
		pIncoming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone1a", "Captain", 1, g_pMissionDatabase)
		pViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Martin")
		pFinalTrans1	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1FinalTransDestroyed1a", None, 0, g_pMissionDatabase)
		pFinalTrans2	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1FinalTransDestroyed2a", None, 0, g_pMissionDatabase)

	# If the SF exists
	elif (g_bSanFranciscoDestroyed == FALSE):
		pZeiss	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("DBridgeSet"), "Zeiss")
		
		pIncoming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone1b", "Captain", 1, g_pMissionDatabase)
		pViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pFinalTrans1	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1FinalTransDestroyed1b", None, 0, g_pMissionDatabase)
		pFinalTrans2	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1FinalTransDestroyed2b", None, 0, g_pMissionDatabase)
		
	# If the Venture exists
	elif (g_bVentureDestroyed == FALSE):
		pDawson	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("DBridgeSet"), "Dawson")
		
		pIncoming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone1c", "Captain", 1, g_pMissionDatabase)
		pViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Dawson")
		pFinalTrans1	= App.CharacterAction_Create(pDawson, App.CharacterAction.AT_SAY_LINE, "E6M1FinalTransDestroyed1c", None, 0, g_pMissionDatabase)
		pFinalTrans2	= App.CharacterAction_Create(pDawson, App.CharacterAction.AT_SAY_LINE, "E6M1FinalTransDestroyed2c", None, 0, g_pMissionDatabase)
	
	# No Fed ships exist, so bail
	else:
		return 0
	
	# Viewscreen off action
	pViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pResetFedAI	= App.TGScriptAction_Create(__name__, "ResetFedAIToStarbase")

	# Build our sequence and play it
	pSequence.AppendAction(pLinkToE6M2)
	pSequence.AppendAction(pIncoming)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pFinalTrans1)
	pSequence.AppendAction(pFinalTrans2)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pResetFedAI)
	
	MissionLib.QueueActionToPlay(pSequence)
	
	# Change our goals
	MissionLib.RemoveGoal("E6ProtectTransportsGoal")
	MissionLib.AddGoal("E6HeadHomeGoal")
	
	return 0
	
################################################################################
##	StationClear()
##
##	Called from either SecondTransportWarps() or ThirdTransportWarps()
##	depending on how many transports were left.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationClear():
	# Check to see who's the rescue ship
	if (g_sRescueShipName == "Devore"):
		StationClearDevore()
	elif (g_sRescueShipName == "SanFrancisco"):
		StationClearSF()
	else:
		StationClearVenture()

	# Get the Episode, remove our third and fourth goals - Intercept Galors & Protect Devore
	# Add add our fifth goal - Head Home

	MissionLib.RemoveGoal("E6ProtectTransportsGoal")
	MissionLib.AddGoal("E6HeadHomeGoal")
	
	# this timer will call Cardassian reinforcments to pound on the user if they don't link to 6.2
#	print "starting the more freakin cards timer"
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_MORE_FREAKIN_CARDS_TIMER, __name__+".MoreFreakinCards", fStartTime + 35, 0, 0)
	
	# set the g_iMissionPositionCounter to play the right dialogue
	global g_iMissionPositionCounter
	g_iMissionPositionCounter = 0


################################################################################
##	MoreFreakinCards()
##
##	Creates the Cardassians in Savoy 1 which beat on the user for not warping to SB12 when told to
##	Called from timer event started in StationClear().
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def MoreFreakinCards(TGObject, pEvent):
	if (g_bMoreCardsMade == TRUE):
		return
	global g_bMoreCardsMade
	g_bMoreCardsMade = TRUE
	
#	print "more freakin cards since you didn't warp home."
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Savoy1")
	
	# Create the ships
	pKeldon8	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 8", "Galor12Enter", 1) 
	pKeldon9	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 9", "Keldon5Enter", 1)
	pKeldon10	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 10", "Galor11Enter", 1)
	pKeldon11	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 11", "SFEnter", 1)
	pKeldon12	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 12", "VentureEnter", 1)
	
	# Import our AIs and assign them
	import E6M1_AI_More_Keldon
	pKeldon8.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon8, g_pKeldon7Targets))
	pKeldon9.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon9, g_pKeldon7Targets))
	pKeldon10.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon10, g_pKeldon7Targets))
	pKeldon11.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon11, g_pKeldon7Targets))
	pKeldon12.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon12, g_pKeldon7Targets))
	
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	if (sSetName == "Savoy1"):
		pFelixMoreShips	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "Incoming5", "Captain", 1, g_pGeneralDatabase)
		pFelixMoreShips.Play()
	
	# this timer will call Cardassian reinforcments to pound on the user if they don't link to 6.2
#	print "starting the Yet more cards timer"
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_YET_MORE_CARDS_TIMER, __name__+".YetMoreCards", fStartTime + 65, 0, 0)
	
################################################################################
##	YetMoreCards()
##
##	Creates the Cardassians in Savoy 1 which beat on the user for not warping to SB12 when told to
##	Called from timer event started in MoreFreakinCards().
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def YetMoreCards(TGObject, pEvent):
	if (g_bYetMoreCardsMade == TRUE):
		return
	global g_bYetMoreCardsMade
	g_bYetMoreCardsMade = TRUE
	
#	print "more freakin cards since you didn't warp home."
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Savoy1")
	
	# Create the ships
	pKeldon18	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 18", "Galor12Enter", 1) 
	pKeldon19	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 19", "Keldon5Enter", 1)
	pKeldon20	= loadspacehelper.CreateShip("Keldon", pSet, "Keldon 20", "Galor11Enter", 1)
		
	# Import our AIs and assign them
	import E6M1_AI_More_Keldon
	pKeldon18.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon18, g_pKeldon7Targets))
	pKeldon19.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon19, g_pKeldon7Targets))
	pKeldon20.SetAI(E6M1_AI_More_Keldon.CreateAI(pKeldon20, g_pKeldon7Targets))
	
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	if (sSetName == "Savoy1"):
		pFelixMoreShips	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "Incoming6", "Captain", 1, g_pGeneralDatabase)
		pFelixMoreShips.Play()		

################################################################################
##	StationClearDevore()
##
##	Called from StationClear if Devore is the rescue ship.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationClearDevore():
	# Do the sequence
	pEBridge	= App.g_kSetManager.GetSet("EBridgeSet")
	pMartin		= App.CharacterClass_GetObject(pEBridge, "Martin")
	
	pSequence = App.TGSequence_Create()
	
	pLinkToE6M2		= App.TGScriptAction_Create(__name__, "LinkToE6M2")
	pKiskaDone1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone1a", "Captain", 1, g_pMissionDatabase)
	pEBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Martin")
	pMartinDone2	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone2a", None, 0, g_pMissionDatabase)
	pMartinDone3	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone3a", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pResetFedAI		= App.TGScriptAction_Create(__name__, "ResetFedAIToStarbase")
	
	pSequence.AppendAction(pLinkToE6M2)
	pSequence.AppendAction(pKiskaDone1)
	pSequence.AppendAction(pEBridgeViewOn)
	pSequence.AppendAction(pMartinDone2)
	pSequence.AppendAction(pMartinDone3)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pResetFedAI)
	
	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	StationClearSF()
##
##	Called from StationClear() if SF is the rescue ship.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationClearSF():
	# Do the sequence
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	pZeiss		= App.CharacterClass_GetObject(pDBridge, "Zeiss")
	
	pSequence = App.TGSequence_Create()
	
	pLinkToE6M2		= App.TGScriptAction_Create(__name__, "LinkToE6M2")
	pKiskaDone1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone1b", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
	pZeissDone2		= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone2b", None, 0, g_pMissionDatabase)
	pZeissDone3		= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone3b", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pResetFedAI		= App.TGScriptAction_Create(__name__, "ResetFedAIToStarbase")
	
	pSequence.AppendAction(pLinkToE6M2)
	pSequence.AppendAction(pKiskaDone1)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pZeissDone2)
	pSequence.AppendAction(pZeissDone3)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pResetFedAI)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	StationClearVenture()
##
##	Called from StatioinClear() if Venture is the rescue ship.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationClearVenture():
	# Do the sequence
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	pDawson		= App.CharacterClass_GetObject(pDBridge, "Dawson")

	pSequence = App.TGSequence_Create()
	
	pLinkToE6M2		= App.TGScriptAction_Create(__name__, "LinkToE6M2")
	pKiskaDone1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone1c", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Dawson")
	pDawsonDone2	= App.CharacterAction_Create(pDawson, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone2c", None, 0, g_pMissionDatabase)
	pDawsonDone3	= App.CharacterAction_Create(pDawson, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDone3c", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pResetFedAI		= App.TGScriptAction_Create(__name__, "ResetFedAIToStarbase")

	pSequence.AppendAction(pLinkToE6M2)	
	pSequence.AppendAction(pKiskaDone1)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pDawsonDone2)
	pSequence.AppendAction(pDawsonDone3)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pResetFedAI)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	TransportTakingDamage()
##
##	Called from E6M1_AI_Transport.py when the transport sufferes critical
##	damage.  Plays the line that lets the player know which one is being beat up.
##
##	Args:	sShipName	- The name of the ship that called us.
##			pTGAction	- Passsed by the sequence if this has to wait
##
##	Return:	None
################################################################################
def TransportTakingDamage(pTGAction, sShipName):
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
		
	if (sSetName == "Savoy1"):
		# Figure out which ship is damaged and do our sequence based on that.
		if (sShipName == "Inverness") and ("Inverness" in g_lTransportNames):
			pDamageLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1InverDamaged1", None, 0, g_pMissionDatabase)
			
		elif (sShipName == "Shannon") and ("Shannon" in g_lTransportNames):
			pDamageLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1ShannonDamaged1", None, 0, g_pMissionDatabase)
			
		elif (sShipName == "Cambridge") and ("Cambridge" in g_lTransportNames):
			pDamageLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1CamDamaged1", None, 0, g_pMissionDatabase)
			
		else:
			return
			
		# Play our line
		pDamageLine.Play()
		
	else:		
		# call this funtion again in 20 seconds.
		pSequence	= App.TGSequence_Create()
		pAction		= App.TGScriptAction_Create(__name__, "TransportTakingDamage", sShipName)
		pSequence.AppendAction(pAction, 20)
		pSequence.Play()
		
################################################################################
##	SFTakingDamage()
##
##	Called from San Francisco AIs if it's hull falls below 80%.  Plays line
##	from Felix.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SFTakingDamage():
	# Check our flag
	if (g_bSFTakingDamageCalled == FALSE):
		global g_bSFTakingDamageCalled
		g_bSFTakingDamageCalled = TRUE
	else:
		return
		
	g_pFelix.SpeakLine(g_pMissionDatabase, "E6M1SFDamaged1", App.CSP_MISSION_CRITICAL)

################################################################################
##	RescueTakingDamage():
##
##	Called from E6M1_AI_Rescue.  Not called if ship takes damage in other
##	systems (not Savoy 1).  Checks and see which ship is rescue and calls correct function
##	to do sequence.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RescueTakingDamage():
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	#if the player is not in savoy 1 don't call for help.
	if (sSetName != "Savoy1"):
		return
	
	# Check to see who's rescue
	if (g_sRescueShipName == "Devore"):
		RescueTakingDamageDevore()
	elif (g_sRescueShipName == "San Francisco"):
		RescueTakingDamageSF()
	else:
		VentureTakingDamage()
				
################################################################################
##	RescueTakingDamageDevore()
##
##	Sequence that plays if Devore is the rescue ship. Called by
##	RescueTakingDamage()
##
##	Args:	None
##
##	Return:	None
################################################################################
def RescueTakingDamageDevore():
	pEBridgeSet	= App.g_kSetManager.GetSet("EBridgeSet")
	pMartin		= App.CharacterClass_GetObject(pEBridgeSet, "Martin")
	
	pSequence = App.TGSequence_Create()
	
	pFelixRescueDamaged1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDamaged1a", "Captain", 1, g_pMissionDatabase)
	pEBridgeViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Martin")
	pMartinRescueDamaged2	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDamaged2a", None, 1, g_pMissionDatabase)
	pViewOff				= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pFelixRescueDamaged1)
	pSequence.AppendAction(pEBridgeViewOn)
	pSequence.AppendAction(pMartinRescueDamaged2)
	pSequence.AppendAction(pViewOff)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	RescueTakingDamageSF()
##
##	Sequence that plays if SF is rescue ship.  Called by RescueTakingDamage()
##
##	Args:	None
##
##	Return:	None
################################################################################
def RescueTakingDamageSF():
	pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
	pZeiss		= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")
	
	pSequence = App.TGSequence_Create()
	
	pFelixRescueDamaged1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDamaged1b", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
	pZeissRescueDamaged2	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1RescueDamaged2b", None, 1, g_pMissionDatabase)
	pViewOff				= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pFelixRescueDamaged1)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pZeissRescueDamaged2)
	pSequence.AppendAction(pViewOff)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	VentureTakingDamage()
##
##	Called from Venture AIs when its hull falls below 80%, or from RescueTakingDamage if
##  Venture is the resuce ship.
##
##	Args:	None
##
##	Return:	None
##	-	bVentureTakingDamageCalled is global specific to this function.
################################################################################
bVentureTakingDamageCalled = FALSE
def VentureTakingDamage():
	if (bVentureTakingDamageCalled == FALSE):
		global bVentureTakingDamageCalled
		bVentureTakingDamageCalled = TRUE
		
		# Get Dawson
		pDawson	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("DBridgeSet"), "Dawson")
		pSequence = App.TGSequence_Create()
		
		pKiskaIncoming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg2", "Captain", 1, g_pGeneralDatabase)
		pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Dawson")
		pVentureDamaged2	= App.CharacterAction_Create(pDawson, App.CharacterAction.AT_SAY_LINE, "E6M1VentureDamaged3", None, 0, g_pMissionDatabase)
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		
		pSequence.AppendAction(pKiskaIncoming)
		pSequence.AppendAction(pDBridgeViewOn)
		pSequence.AppendAction(pVentureDamaged2)
		pSequence.AppendAction(pViewOff)
		
		MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	LinkToE6M2()
##
##	Called as a script action when the Devore has been near station long
##	enough.  Links "Starbase" in helm menu to E6M2.
##
##	Args:	pTGAction	- The action object
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def LinkToE6M2(pTGAction):
		
	# Link the menu in helm to the next mission
	import Systems.Starbase12.Starbase
	pStarbaseMenu = Systems.Starbase12.Starbase.CreateMenus()
	pStarbaseMenu.SetMissionName("Maelstrom.Episode6.E6M2.E6M2")
	return 0

################################################################################
##	ResetFedAIToStarbase()
##
##	Resets surviving Fed ships AI so they all warp out of system.
##
##	Args:	pTGAction	- The action object
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetFedAIToStarbase(pTGAction):
	# Import the AI
	import E6M1_AI_WarpToStarbase
	# If San Francisco has survived
	if (g_bSanFranciscoDestroyed == FALSE):
		pSanFrancisco = App.ShipClass_GetObject(None, "San Francisco")
		pSanFrancisco.SetAI(E6M1_AI_WarpToStarbase.CreateAI(pSanFrancisco))
		if (g_sRescueShipName != "San Francisco"):
			MissionLib.RemoveCommandableShip("San Francisco")
	# If Venture has survived
	if (g_bVentureDestroyed == FALSE):
		pVenture = App.ShipClass_GetObject(None, "Venture")
		pVenture.SetAI(E6M1_AI_WarpToStarbase.CreateAI(pVenture))
		if (g_sRescueShipName != "Venture"):
			MissionLib.RemoveCommandableShip("Venture")
	# If Devore survived
	if (g_bDevoreDestroyed == FALSE):
		pDevore = App.ShipClass_GetObject(None, "Devore")
		pDevore.SetAI(E6M1_AI_WarpToStarbase.CreateAI(pDevore))
		if (g_sRescueShipName != "Devore"):
			MissionLib.RemoveCommandableShip("Devore")
	return 0	
################################################################################
##	ShipSpecificCallForHelp()
##
##	Strings together sequence with correct bridge and characters for to use
##	in RescueCallsForHelp()
##
##	Args:	None
##
##	Return:	pSequence	- The sequence with the correct actions
################################################################################
def ShipSpecificCallForHelp():
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	# Get the sets
	pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
	pEBridgeSet	= App.g_kSetManager.GetSet("EBridgeSet")
	# Get all the characters we need
	pMartin	= App.CharacterClass_GetObject(pEBridgeSet, "Martin")
	pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")
	pDawson	= App.CharacterClass_GetObject(pDBridgeSet, "Dawson")
	
	if (g_sRescueShipName == "Devore"):
		pIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1SavoyHail1", "Captain", 1, g_pMissionDatabase)
		pViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Martin")
		pSavoyHail2	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E6M1SavoyHail2a", None, 0, g_pMissionDatabase)
				
	elif (g_sRescueShipName == "SanFrancisco"):
		pIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1SavoyHail1", "Captain", 1, g_pMissionDatabase)
		pViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSavoyHail2	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E6M1SavoyHail2b", None, 0, g_pMissionDatabase)
			
	elif (g_sRescueShipName == "Venture"):
		pIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1SavoyHail1c", "Captain", 1, g_pMissionDatabase)
		pViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Dawson")
		pSavoyHail2	= App.CharacterAction_Create(pDawson, App.CharacterAction.AT_SAY_LINE, "E6M1SavoyHail2c", None, 0, g_pMissionDatabase)
	
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						
	# Build the sequence and return it
	pSequence = App.TGSequence_Create()
	
	pSequence.AppendAction(pIncoming)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pSavoyHail2)
	pSequence.AppendAction(pViewOff)
	#if the player is not in savoy 1
	if (sSetName != "Savoy1") and (sSetName != "warp"):
		pSetCourse			= App.TGScriptAction_Create(__name__, "Savoy1CourseSet")
		pKiskaSavoy3Warp4	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1Savoy3Warp4", None, 0, g_pMissionDatabase)	
		pSequence.AppendAction(pSetCourse)
		pSequence.AppendAction(pKiskaSavoy3Warp4)
				
	return pSequence

###############################################################################
#	Savoy1CourseSet()
#
#	this sets course for Savoy 1
#
#	Args:	pAction
#
#	Return:	0
###############################################################################
def Savoy1CourseSet(pAction):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	# Set the location on the warp menu
	pWarpButton.SetDestination("Systems.Savoy.Savoy1")
	pKiskaMenu.SetFocus(pWarpButton)

	return 0

################################################################################
##	AllFedsDestroyed()
##
##	Called if all the Fed warships have been destroyed.
##
##	Args:	None
##
##	Return:	None
################################################################################
def AllFedsDestroyed():
	#kill any registered sequences
	App.TGActionManager_KillActions()
			
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()

	pKiskaLossOna1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1LossOna1", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLossOna2	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1LossOna2", "Captain", 1, g_pMissionDatabase)
	pLiuLossOna3	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1LossOna3", "Captain", 1, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pKiskaLossOna1)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuLossOna2)
	pSequence.AppendAction(pLiuLossOna3)
	pSequence.AppendAction(pViewOff)
	
	# End the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()

################################################################################
##	SecondTransportDestroyed()
##
##	Called from TransportDestroyed() if two of the transports have been destroyed.
##	Plays mission loss dialogue and ends the game.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SecondTransportDestroyed(pTGAction):
	#kill any registered sequences
	App.TGActionManager_KillActions()	
	
	# Get Liu
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()

	pFelixTransLoss1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M1SecondTransportDestroyed1", "Captain", 1, g_pMissionDatabase)
	pKiskaTransLoss2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M1SecondTransportDestroyed2", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuTransLoss3		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1SecondTransportDestroyed3", None, 0, g_pMissionDatabase)
	pLiuTransLoss4		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1SecondTransportDestroyed4", None, 0, g_pMissionDatabase)
	pLiuTransLoss5		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M1SecondTransportDestroyed5", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

	pSequence.AppendAction(pFelixTransLoss1)
	pSequence.AppendAction(pKiskaTransLoss2)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuTransLoss3)
	pSequence.AppendAction(pLiuTransLoss4)
	pSequence.AppendAction(pLiuTransLoss5)
	pSequence.AppendAction(pViewOff)
	
	# Do the cutscene stuff to end the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()
	
	return 0
	
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
	
	# Get the player and the set their in	
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	
	# Check and see which prod line to use.
	if (g_sProdLine == "E6M1ProdToArtrus") and (g_bPlayerArriveArtrus == FALSE) and (sSetName != "warp"):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 20)
	elif (g_sProdLine == "E6M1ProdToOna") and (g_bPlayerArriveOna == FALSE) and (sSetName != "warp"):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 20)
	elif (g_sProdLine == "E6M1ProdToSavoy3") and (g_bPlayerArriveSavoy3 == FALSE) and (sSetName != "warp"):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 20)
	elif (g_sProdLine == "E6M1ProdToSavoy1") and (g_bPlayerArriveSavoy1 == FALSE) and (sSetName != "warp"):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 20)

	
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
def RestartProdTimer(pTGAction, iTime):
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
#	kDebugObj.Print ("Terminating Episode 6, Mission 1.\n")
	# Mission is terminating, so lets set our flag
	global g_bMissionTerminate
	g_bMissionTerminate = TRUE
	
	# Collect the surviving ships into episode level globals
	CollectSurvivingShips()
	
	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()
	
	# Delete all our mission goals
	MissionLib.DeleteAllGoals()
	
	# Remove all our instance handlers
	RemoveInstanceHandlers()
	
	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# unload the database: "data/TGL/Bridge Menus.tgl"
	if(g_pDatabase):
		App.g_kLocalizationManager.Unload(g_pDatabase)
	
	# Stop the prod timer if it's running.
	StopProdTimer()
	
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
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")

	# Remove instance handler for Kiska's Hail button
	pMenu = g_pKiska.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	
	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	
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
	
	# get the transports
	pTransport1		= App.ShipClass_GetObject(None, "Shannon")
	pTransport2		= App.ShipClass_GetObject(None, "Inverness")
	pTransport3		= App.ShipClass_GetObject(None, "Cambridge")
	if (pTransport1 != None):
		pTransport1.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".TransportHit")
	if (pTransport2 != None):
		pTransport2.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".TransportHit")
	if (pTransport3 != None):		
		pTransport3.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".TransportHit")


################################################################################
##	CollectSurvivingShips()
##
##	Checks each Fed ship by name, and if it still exists, saves it to a episode
##	level global so that we can recreate them E6M2.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CollectSurvivingShips():
	# We'll do this the long way and check each ships on its own

	# San Francisco
	pShip = App.ShipClass_GetObject(None, "San Francisco")
	if (pShip != None):
#		kDebugObj.Print("Saving SanFrancisco")
		pSet = pShip.GetContainingSet()
		pSet.RemoveObjectFromSet("San Francisco")
		Maelstrom.Episode6.Episode6.g_idSanFrancisco = pShip.GetObjID()
	else:
		Maelstrom.Episode6.Episode6.g_idSanFrancisco = App.NULL_ID
	
	# Devore	
	pShip = App.ShipClass_GetObject(None, "Devore")
	if (pShip != None):
#		kDebugObj.Print("Saving Devore")
		pSet = pShip.GetContainingSet()
		pSet.RemoveObjectFromSet("Devore")
		Maelstrom.Episode6.Episode6.g_idDevore = pShip.GetObjID()
	else:
		Maelstrom.Episode6.Episode6.g_idDevore = App.NULL_ID
	
	# Venture
	pShip = App.ShipClass_GetObject(None, "Venture")
	if (pShip != None):
#		kDebugObj.Print("Saving Venture")
		pSet = pShip.GetContainingSet()
		pSet.RemoveObjectFromSet("Venture")
		Maelstrom.Episode6.Episode6.g_idVenture = pShip.GetObjID()
	else:
		Maelstrom.Episode6.Episode6.g_idVenture = App.NULL_ID

	# Inverness
	pShip = App.ShipClass_GetObject(None, "Inverness")
	if (pShip != None):
#		kDebugObj.Print("Saving Inverness")
		pSet = pShip.GetContainingSet()
		pSet.RemoveObjectFromSet("Inverness")
		Maelstrom.Episode6.Episode6.g_idInverness = pShip.GetObjID()
	else:
		Maelstrom.Episode6.Episode6.g_idInverness = App.NULL_ID

	# Cambridge
	pShip = App.ShipClass_GetObject(None, "Cambridge")
	if (pShip != None):
#		kDebugObj.Print("Saving Cambridge")
		pSet = pShip.GetContainingSet()
		pSet.RemoveObjectFromSet("Cambridge")
		Maelstrom.Episode6.Episode6.g_idCambridge = pShip.GetObjID()
	else:
		Maelstrom.Episode6.Episode6.g_idCambridge = App.NULL_ID
		
	# Shannon
	pShip = App.ShipClass_GetObject(None, "Shannon")
	if (pShip != None):
#		kDebugObj.Print("Saving Shannon")
		pSet = pShip.GetContainingSet()
		pSet.RemoveObjectFromSet("Shannon")
		Maelstrom.Episode6.Episode6.g_idShannon = pShip.GetObjID()
	else:
		Maelstrom.Episode6.Episode6.g_idShannon = App.NULL_ID

	# now remove any remaining ships in the warp set
	MissionLib.DeleteShipsFromWarpSetExceptForMe()
