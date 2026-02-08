###############################################################################
#	Filename:	E2M6.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 2, Mission 6
#	
#	Created:	10/26/00 -	Jess VanDerwalker (added header and updated)
#	Modified:	12/14/01 -	Jess VanDerwalker
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Episode2.Episode2
import Bridge.BridgeUtils
import Actions.MissionScriptActions
import loadsplash
import DynamicMusic

# For debugging
#kDebugObj = App.CPyDebug()

# Declare global variables here
TRUE				= 1
FALSE				= 0

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None

g_bMissionTerminate	= None

g_bSequenceRunning	= None

g_iProdTimer			= None
g_bPlayerNotInBiranu	= None
g_iProdToBiranuCounter	= None

g_iMissionState		= None
DEFAULT				= None
ENTER_BIRANU		= None
KLINGON_ATTACK		= None
STATION_ATTACKED	= None
GALORS_RETREAT		= None
SECOND_WAVE			= None
SHIELDS_DOWN		= None

g_bPlayerArriveBiranu2		= None
g_bPlayerWarned				= None
g_bGracePeriod				= None
g_bStationHit				= None
g_bCardsAttackStationCalled	= None
g_bGalorOnPlayerCalled		= None
g_bBiranuHailed				= None
g_bPlayerChasingGalors		= None
g_bBiranu1ClearCalled		= None
g_bCallForHelpSent			= None
g_bStationShieldsDown		= None
g_bPlayerInRange			= None
g_bMissionWin				= None

g_bRanKufDestroyed		= None
g_bTrayorDestroyed		= None
g_bBOPsLeavingBiranu2	= None
g_bBOPsReturningBiranu2	= None

g_bGalor5And6HaveAI		= None
g_bGalorsOnSensors		= None
g_bGalorsIDd			= None

g_bStationDestroyed		= None
g_bGalors4And5Attack	= None

g_iNumberCardsGone	= None

g_lCardNames		= []
g_lKlingonNames		= []
g_lFirstWaveNames	= []

g_pBOPTargets		= None
g_pGalor1_2Targets	= None
g_pGalor5_6Targets	= None

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None
					
# For Friendly Fire warnings
g_bDraxonWarned 	= None
g_bKlingonWarned 	= None
g_bStationWarned 	= None

# Event Types for mission
ET_PROD_TIMER				= None
ET_GRACE_PERIOD_TIMER		= None
ET_CLEAR_FLAGS				= None
ET_TWO_GALORS_DESTROYED		= None
ET_RETURN_TO_BIRANU1_TIMER	= None
ET_SECOND_GALOR_TIMER		= None
ET_KLINGON_RETURN_TIMER		= None

###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to add instances of ships we'll use.
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Galaxy", 1)
	loadspacehelper.PreloadShip("BiranuStation", 1)
	loadspacehelper.PreloadShip("Galor", 6)
	loadspacehelper.PreloadShip("RanKuf", 2)
	
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
	# Check and see if we have a player, if we don't
	# we aren't linking and will have to call the initial
	# briefing "by hand" and the end of Initialize
	bHavePlayer = 0
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		bHavePlayer = 1

	# Initialize all our global variables
	InitializeGlobals(pMission)

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")

	# Create the regions for this mission
	CreateRegions()
	
	# Create sets we need
	CreateSets()
	
	# Create menus available at mission start
	CreateStartingMenus()
	
	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	# Create the starting objects
	CreateStartingObjects(pMission)
	
	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	# Create our target groups
	CreateTargetGroups()
	
	# Setup more mission-specific events.
	SetupEventHandlers()

	# Set the stats on the players ship
	App.Game_SetDifficultyMultipliers(1.25, 1.5, 1.0, 1.0, 0.75, 0.9)
	
	# Add our goal for this mission - Defend Station
	MissionLib.AddGoal("E2ResolveConflictGoal")
	
	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	
	# If the player was created from scratch, call our initial briefing
	if (bHavePlayer == 0):
		PlayerEntersBiranu()
	
	# Save the game
	MissionLib.SaveGame("E2M3-")
	
################################################################################
##	InitializeGlobals(pMission)
##
##	Initialize all the global variables used in this mission.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
	# General flags used in bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0
	
	# Set g_bMissionTerminate here in case mission gets reloaded
	global g_bMissionTerminate
	g_bMissionTerminate = 1

	# Flag to check if sequence is running
	global g_bSequenceRunning
	g_bSequenceRunning	= FALSE
	
	# TGL Database globals
	global g_pMissionDatabase
	global g_pGeneralDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 2/E2M6.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	# Globals used with player prodding
	global g_iProdTimer
	global g_bPlayerNotInBiranu
	global g_iProdToBiranuCounter
	g_iProdTimer			= App.NULL_ID
	g_bPlayerNotInBiranu	= FALSE
	g_iProdToBiranuCounter	= 0

	# Globals used with the communicate functions
	global g_iMissionState
	global DEFAULT
	global ENTER_BIRANU
	global KLINGON_ATTACK
	global STATION_ATTACKED
	global GALORS_RETREAT
	global SECOND_WAVE
	global SHIELDS_DOWN
	g_iMissionState		= 0
	DEFAULT				= 0
	ENTER_BIRANU		= 1
	KLINGON_ATTACK		= 2
	STATION_ATTACKED	= 3
	GALORS_RETREAT		= 4
	SECOND_WAVE			= 5
	SHIELDS_DOWN		= 6

	# Flags to track player and functions called
	global g_bPlayerArriveBiranu2
	global g_bPlayerWarned
	global g_bGracePeriod
	global g_bStationHit
	global g_bCardsAttackStationCalled
	global g_bGalorOnPlayerCalled
	global g_bBiranuHailed
	global g_bPlayerChasingGalors
	global g_bBiranu1ClearCalled
	global g_bCallForHelpSent
	global g_bStationShieldsDown
	global g_bPlayerInRange
	global g_bMissionWin
	g_bPlayerArriveBiranu2		= FALSE
	g_bPlayerWarned				= FALSE
	g_bGracePeriod				= FALSE
	g_bStationHit				= FALSE
	g_bCardsAttackStationCalled	= FALSE
	g_bGalorOnPlayerCalled		= FALSE
	g_bBiranuHailed				= FALSE
	g_bPlayerChasingGalors		= FALSE
	g_bBiranu1ClearCalled		= FALSE
	g_bCallForHelpSent			= FALSE
	g_bStationShieldsDown		= FALSE
	g_bPlayerInRange			= FALSE
	g_bMissionWin				= FALSE
	
	# Flags for tracking Birds of Prey
	global g_bBOPSOSAISet
	global g_bRanKufDestroyed
	global g_bTrayorDestroyed
	global g_bBOPsLeavingBiranu2
	global g_bBOPsReturningBiranu2
	g_bBOPSOSAISet			= FALSE
	g_bRanKufDestroyed		= FALSE
	g_bTrayorDestroyed		= FALSE
	g_bBOPsLeavingBiranu2	= FALSE
	g_bBOPsReturningBiranu2	= FALSE
	
	# Flags specific to second group of Galors
	global g_bGalor5And6HaveAI
	global g_bGalorsOnSensors
	global g_bGalorsIDd
	g_bGalor5And6HaveAI		= FALSE
	g_bGalorsOnSensors		= FALSE
	g_bGalorsIDd			= FALSE
	
	# Flag for attacking ships
	global g_bGalors4And5Attack
	g_bGalors4And5Attack	= FALSE
	
	# Number of Cardassian ships that have left
	# Biranu 2
	global g_iNumberCardsGone
	g_iNumberCardsGone	= 0
	
	# Global pointers to target groups used in AIs
	global g_pBOPTargets
	global g_pGalor1_2Targets
	global g_pGalor5_6Targets
	g_pBOPTargets		= None
	g_pGalor1_2Targets	= None
	g_pGalor5_6Targets	= None
	
	# For Friendly Fire warnings
	global g_bDraxonWarned, g_bKlingonWarned, g_bStationWarned
	g_bDraxonWarned 	= FALSE
	g_bKlingonWarned 	= FALSE
	g_bStationWarned 	= FALSE

	# List of Cardassian ship names
	global g_lCardNames
	g_lCardNames	=	[
						"Galor 1", "Galor 2", "Galor 3", "Galor 4", "Galor 5", "Galor 6"
						]
	
	# List of Klingon ship names
	global g_lKlingonNames
	g_lKlingonNames	=	[
						"RanKuf", "Trayor"
						]
	
	# List of names of ships in first attack wave
	global g_lFirstWaveNames
	g_lFirstWaveNames	=	[
							"Galor 1", "Galor 2", "Galor 3", "Galor 4"
							]

	# Set our limits for the friendly fire warnings and game loss
	App.g_kUtopiaModule.SetMaxFriendlyFire(2000)			# how many damage points the player can do total before losing
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(400)	# how many damage points before Saffi warns you

	# Event types for mission
	global ET_PROD_TIMER
	global ET_GRACE_PERIOD_TIMER
	global ET_CLEAR_FLAGS
	global ET_TWO_GALORS_DESTROYED
	global ET_RETURN_TO_BIRANU1_TIMER
	global ET_SECOND_GALOR_TIMER
	global ET_KLINGON_RETURN_TIMER
	ET_PROD_TIMER				= App.Mission_GetNextEventType()
	ET_GRACE_PERIOD_TIMER		= App.Mission_GetNextEventType()
	ET_CLEAR_FLAGS				= App.Mission_GetNextEventType()
	ET_TWO_GALORS_DESTROYED		= App.Mission_GetNextEventType()
	ET_RETURN_TO_BIRANU1_TIMER	= App.Mission_GetNextEventType()
	ET_SECOND_GALOR_TIMER		= App.Mission_GetNextEventType()
	ET_KLINGON_RETURN_TIMER		= App.Mission_GetNextEventType()
							
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
##	CreateRegions()
##
##	Creates the regions we'll be using in this mission.  Also loads in any
##	mission placement files we need.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateRegions():
	# Starbase 12
	pStarbaseSet = MissionLib.SetupSpaceSet("Systems.Starbase12.Starbase12")
	# Biranu 1
	pBiranu1Set = MissionLib.SetupSpaceSet("Systems.Biranu.Biranu1")
	# Biranu 2
	pBiranu2Set = MissionLib.SetupSpaceSet("Systems.Biranu.Biranu2")
	
	# Add our custom placement objects for this mission.
	import E2M6_Biranu1_P
	import E2M6_Biranu2_P
	E2M6_Biranu1_P.LoadPlacements(pBiranu1Set.GetName())
	E2M6_Biranu2_P.LoadPlacements(pBiranu2Set.GetName())

################################################################################
##	CreateSets()
##
##	Creates the sets that we'll be using for characters that appear on the
##	viewscreen.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateSets():
	# Starbase with Liu
	pStarbaseSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -30, 65, -1.55)
	pLiu			= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)

	# FedOutpost with Picard
	pFedOutpostSet	= MissionLib.SetupBridgeSet("FedOutpostSet", "data/Models/Sets/FedOutpost/fedoutpost.nif", -30, 65, -1.55)
	pPicard			= MissionLib.SetupCharacter("Bridge.Characters.Picard", "FedOutpostSet")
	pPicard.SetLocation("FederationOutpostSeated")	

	# Klingon bridge with Draxon
	pKilingonSet	= MissionLib.SetupBridgeSet("KlingonSet", "data/Models/Sets/Klingon/BOPbridge.nif", -30, 65, -1.55)
	pDraxon			= MissionLib.SetupCharacter("Bridge.Characters.Draxon", "KlingonSet", 0, 0, -5)

	# Cardassian bridge with Oben
	pCardSet		= MissionLib.SetupBridgeSet("CardSet", "data/Models/Sets/Cardassian/cardbridge.nif", -30, 65, -1.55)
	pOben			= MissionLib.SetupCharacter("Bridge.Characters.Oben", "CardSet")
	# Set Oben's name to Cardassian capt
	pOben.SetCharacterName("CardCapt")
	
################################################################################
##	CreateStartingMenus()
##	
##  Creates menu items for Starbase and Biranu systems in "Helm" at mission start.
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def CreateStartingMenus ():
	import Systems.Starbase12.Starbase
	import Systems.Biranu.Biranu
	
	pStarbaseMenu	= Systems.Starbase12.Starbase.CreateMenus()
	pBiranuMenu		= Systems.Biranu.Biranu.CreateMenus()
	
################################################################################
##	CreateStartingObjects()
##
##	Creates all the objects that exist at the beginning of the mission and sets
## 	up the affiliations for all objects that will occur in the mission.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def CreateStartingObjects(pMission):
	# Import all the ships we'll be using.
	
	# Setup ship affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("Biranu Station")

	pNeutrals = pMission.GetNeutralGroup()
	pNeutrals.AddName("RanKuf")
	pNeutrals.AddName("Trayor")
	
	for sShipName in g_lCardNames:
		pNeutrals.AddName(sShipName)

	# get the sets we need
	pBiranu2Set		= App.g_kSetManager.GetSet("Biranu2")
	pBiranu1Set		= App.g_kSetManager.GetSet("Biranu1")
	pStarbaseSet	= App.g_kSetManager.GetSet("Starbase12")
	
	# Create the ships that exist at mission start
	pPlayer			= MissionLib.CreatePlayerShip("Galaxy", pBiranu2Set, "player", "PlayerEnterBiranu2")
	pStarbase		= loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	pBiranuStation	= loadspacehelper.CreateShip("BiranuStation", pBiranu2Set, "Biranu Station", "Facility Location")
	pGalor1			= loadspacehelper.CreateShip("Galor", pBiranu2Set, "Galor 1", "Galor1Start")
	pGalor2			= loadspacehelper.CreateShip("Galor", pBiranu2Set, "Galor 2", "Galor2Start")
	pGalor3			= loadspacehelper.CreateShip("Galor", pBiranu2Set, "Galor 3", "Galor3Start")
	pGalor4			= loadspacehelper.CreateShip("Galor", pBiranu2Set, "Galor 4", "Galor4Start")
	pBird1			= loadspacehelper.CreateShip("RanKuf", pBiranu2Set, "RanKuf", "Bird1Start")
	pBird2			= loadspacehelper.CreateShip("RanKuf", pBiranu2Set, "Trayor", "Bird2Start")

	# Make RanKuf invincible and turn off collisions
	pBird1.SetInvincible(TRUE)
	pBird1.SetCollisionsOn(FALSE)
	
	# Turn collisions off on the Trayor - we'll turn these back on later
	pBird2.SetCollisionsOn(FALSE)

	# Make BOPs' Engines invincible
	for pShip in [ pBird1, pBird2 ]:
		if (pShip != None):
			pWarp = pShip.GetWarpEngineSubsystem()
			if (pWarp):
				MissionLib.MakeSubsystemsInvincible(pWarp)
			pImpulse = pShip.GetImpulseEngineSubsystem()
			if (pImpulse):
				MissionLib.MakeSubsystemsInvincible(pImpulse)
	
	# Set the default torp types for the Bird of Prey
	pTorps = pBird1.GetTorpedoSystem()
	pTorps.SetAmmoType(App.AT_TWO, 0)

	pTorps = pBird2.GetTorpedoSystem()
	pTorps.SetAmmoType(App.AT_TWO, 0)

	# Make the Warp systems invicible on the Galors
	for pShip in [pGalor1, pGalor2, pGalor3, pGalor4 ]:
		pWarp = pShip.GetWarpEngineSubsystem()
		MissionLib.MakeSubsystemsInvincible(pWarp)
	
	# Make the Warp systems invicible on the BoPs
	for pShip in [pBird1, pBird2]:
		pWarp = pShip.GetWarpEngineSubsystem()
		MissionLib.MakeSubsystemsInvincible(pWarp)
		
	# Figure out how long of a delay before the shields go down
	# Get our difficulity level and set the speeds based on that
	eDifficulty = App.Game_GetDifficulty()
	if (eDifficulty == App.Game.EASY):
		fTime = 240
	elif (eDifficulty == App.Game.MEDIUM):
		fTime = 240
	elif (eDifficulty == App.Game.HARD):
		fTime = 180
	
	# Give the station it's AI
	import E2M6_AI_Station
	pBiranuStation.SetAI(E2M6_AI_Station.CreateAI(pBiranuStation, fTime))
	
	# Set the splash damage on the Station to zero
	pBiranuStation.SetSplashDamage(0.0, pShip.GetRadius())
	
################################################################################
##	CreateTargetGroups()
##
##	Create the global target groups that we'll use in our AI's.
##	NOTE:	Call this after the players ship has been created so we can get
##			its name.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateTargetGroups():
	# Get the players ship name so we can add it
	# to the list
	pPlayer = MissionLib.GetPlayer()
	assert pPlayer
	if (pPlayer == None):
		return
	sPlayerName = pPlayer.GetName()
	
	# Target list for the Birds Of Prey
	global g_pBOPTargets
	g_pBOPTargets = App.ObjectGroupWithInfo()
	g_pBOPTargets["Galor 1"]	= {"Priority" : 1.0}
	g_pBOPTargets["Galor 2"]	= {"Priority" : 1.5}
	g_pBOPTargets["Galor 3"]	= {"Priority" : 0.0}
	g_pBOPTargets["Galor 4"]	= {"Priority" : 0.0}	
	# If the player is going for admiral, have the Klingon's
	# go after the Galors attacking the station.
	eDifficulty = App.Game_GetDifficulty()
	if (eDifficulty == App.Game.HARD):
		g_pBOPTargets["Galor 5"]	= {"Priority" : 1.5}
		g_pBOPTargets["Galor 6"]	= {"Priority" : 1.0}
	else:
		g_pBOPTargets["Galor 5"]	= {"Priority" : 0.0}
		g_pBOPTargets["Galor 6"]	= {"Priority" : 0.0}
		
	# Target list for Galors 1 & 2
	global g_pGalor1_2Targets
	g_pGalor1_2Targets = App.ObjectGroupWithInfo()
	g_pGalor1_2Targets["RanKuf"]	= {"Priority" : 0.0}
	g_pGalor1_2Targets["Trayor"]	= {"Priority" : 0.5}
	
	# Target list for Galors 4 and 5
	global g_pGalor5_6Targets
	g_pGalor5_6Targets = App.ObjectGroupWithInfo()
	g_pGalor5_6Targets["Biranu Station"]	= {"Priority" : 1.0}
	g_pGalor5_6Targets[sPlayerName]			= {"Priority" : 0.2}
	g_pGalor5_6Targets["RanKuf"]			= {"Priority" : 0.0}
	g_pGalor5_6Targets["Trayor"]			= {"Priority" : 0.0}
	
	
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

	# Player exits warp event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_WARP, pMission, __name__ + ".ExitedWarp")
	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ +".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__+".ObjectDestroyed")
	# Target is ID'd by sensors event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_IDENTIFIED, pMission, __name__+".ShipIdentified")
	# Target comes into other range of sensors event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_FAR_PROXIMITY, pMission, __name__+".ShipInSensorRange")

	# Instance handler for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")
	# Instance handler on the mission for friendly fire game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".FriendlyFireGameOverHandler")

	# Weapon hit event handler attached to the Biranu Station
	pBiranuStation	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Biranu2"), "Biranu Station")
	if (pBiranuStation != None):
		pBiranuStation.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".WeaponHitStation")

	# Instance handler on players ship for Weapon Fired event
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")

	# Instance handler for Kiska's menu
	pKiskaMenu = Bridge.BridgeUtils.GetBridgeMenu("Helm")
	if (pKiskaMenu != None):
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL,			__name__ + ".HailHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		# Instance handler for warp button
		pWarpButton = Bridge.BridgeUtils.GetWarpButton()
		if (pWarpButton != None):
			pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")

	# Instance handler for Saffi's menu
	pSaffiMenu = Bridge.BridgeUtils.GetBridgeMenu("XO")
	if (pSaffiMenu != None):
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
	
	# Instance handlers for Felix's menu
	pFelixMenu = Bridge.BridgeUtils.GetBridgeMenu("Tactical")
	if (pFelixMenu != None):
		pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Instance handler for Miguel's menu
	pMiguelMenu = Bridge.BridgeUtils.GetBridgeMenu("Science")
	if (pMiguelMenu != None):
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Instance handlers for Brex's menu
	pBrexMenu = Bridge.BridgeUtils.GetBridgeMenu("Engineer")
	if (pBrexMenu != None):
		pBrexMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

###############################################################################
##	ExitedWarp()
##	
##	Called when the players ship has finished warping.
##	
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent
##	
##	Return:	none
###############################################################################
def ExitedWarp(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	pPlayer = App.Game_GetCurrentPlayer()

	if (pShip == None) or (pPlayer == None) or (g_bMissionTerminate != 1) or (pShip.GetObjID() != pPlayer.GetObjID()):
		TGObject.CallNextHandler(pEvent)
		return
	
	pSet = pShip.GetContainingSet()
	if (pSet == None):
		TGObject.CallNextHandler(pEvent)
		return
	
	# If the player is entering Vesuvi 6 for the first time,
	# call our sequence and start the cutscene
	if (pSet.GetName() == "Biranu2") and (g_bPlayerArriveBiranu2 == FALSE):
		PlayerEntersBiranu()
		
	# All done, call our next handler
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	EnterSet()
##	
##	Event handler called whenever an object enters a set.
##	
##	Args: 	TGObject	- TGObject object.
##			pEvent		- The ScriptAction object.
##	
##	Return: None
################################################################################
def EnterSet(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	# Make sure it's a ship, return if not
	if (pShip == None):
		return
		
	pSet 		= pShip.GetContainingSet()
	sSetName 	= pSet.GetName()
	sShipName	= pShip.GetName()
	
	# See if the player is chasing the Galors to Biranu1
	global g_bPlayerChasingGalors
	if (sShipName == "player") and (sSetName == "Biranu1") and (g_bPlayerChasingGalors == FALSE) and (g_bBOPsLeavingBiranu2 == TRUE):
		g_bPlayerChasingGalors = TRUE
		PlayerFollowingKlingons()
		
	# Check and see if the Birds of Prey are returning to Biranu2
	global g_bBOPsReturningBiranu2
	if (sSetName == "Biranu2") and (g_bBOPsLeavingBiranu2 == TRUE) and (g_bBOPsReturningBiranu2 == FALSE):
		if (sShipName == "RanKuf") or (sShipName == "Trayor"):
			g_bBOPsReturningBiranu2 = TRUE
			BOPsReturnToHelp()

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ExitSet()
##	
##	Event handler called whenever an object leaves a set.
##	
##	Args: 	TGObject	- TGObject object.
##			pEvent		- The ScriptAction object.
##	
##	Return: None
################################################################################
def ExitSet(TGObject, pEvent):
	# Check and see if the mission is terminating
	if (g_bMissionTerminate != 1):
		return

	pShip		= App.ShipClass_Cast(pEvent.GetDestination())
	sSetName	= pEvent.GetCString()

	# Make sure it's a ship, return if not
	if (pShip == None):
		return
	
	sShipName	= pShip.GetName()

	# If it's the player, call our function to handle it
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	if (pPlayer.GetName() == sShipName):
		PlayerExitsSet()
		
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
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu == None):
		return
	pWarpButton	= Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return
	pString	= pWarpButton.GetDestination()
	if (pString == None):
		return

	# See if were leaving the Biranu system before the mission is over
	if (g_bPlayerArriveBiranu2 == TRUE) and (g_bPlayerNotInBiranu == FALSE) and (pString[:14] != "Systems.Biranu"):
		global g_bPlayerNotInBiranu
		g_bPlayerNotInBiranu = TRUE
		RestartProdTimer(None, 20)
		
	# See if we are returning to Biranu Station
	elif (g_bPlayerNotInBiranu == TRUE) and (pString[:14] == "Systems.Biranu"):
		global g_bPlayerNotInBiranu
		g_bPlayerNotInBiranu = TRUE
		StopProdTimer()
		# Reset our prod counter
		global g_iProdToBiranuCounter
		g_iProdToBiranuCounter = 1
		
################################################################################
##	ObjectDestroyed()
##
##	Event handler called when an object destroyed event is sent.
##
##	Args:	TGObject	- TGObject object
##			pEvent		- The ScriptAction object.
##
##	Return:	None
################################################################################
def ObjectDestroyed(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	# Check and see if it's a ship, if not return
	if (pShip == None):
		return
		
	sShipName 	= pShip.GetName()
	sSetName 	= pEvent.GetCString()

	# See if the RanKuf has been destroyed
	if (sShipName == "RanKuf"):
		global g_bRanKufDestroyed
		g_bRanKufDestroyed = TRUE

		g_pMiguel.SayLine(g_pMissionDatabase, "E2M6RankufDestroyed", "Captain", 1)

	elif (sShipName == "Trayor"):
		global g_bTrayorDestroyed
		g_bTrayorDestroyed = TRUE

		g_pMiguel.SayLine(g_pMissionDatabase, "E2M6TrayorDestroyed", "Captain", 1)
		
	# Check and see if Biranu Station was destroyed
	elif (sShipName == "Biranu Station"):
		global g_bStationDestroyed
		g_bStationDestroyed = TRUE
		StationWasDestroyed()
	
	# See if it's one of the first Galor wave ships
	elif (sShipName in g_lFirstWaveNames):
		# Remove the name from the list
		global g_lFirstWaveNames
		g_lFirstWaveNames.remove(sShipName)
		
		# If there are only two ships of the first wave left, send
		# off our event that the AIs are listening to.
		if (len(g_lFirstWaveNames) <= 2):
			# Get the mission
			pMission = MissionLib.GetMission()
			if (pMission != None):
				pEvent = App.TGEvent_Create()
				pEvent.SetEventType(ET_TWO_GALORS_DESTROYED)
				pEvent.SetDestination(pMission)
				App.g_kEventManager.AddEvent(pEvent)

	# See which Cardassians have been destroyed.
	# If they all have, call mission win
	global g_lCardNames
	for sCard in g_lCardNames:
		if (sCard == sShipName):
			# Remove the name from the list
			g_lCardNames.remove(sCard)
			if (len(g_lCardNames) == 0):
				# No names left in g_lCardNames, so they must all be gone
				MissionWin()


	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ShipIdentified()
##
##	Event handler called when a ship is identified with the sensors.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent 		- The event that was sent.
##
##	Return:	None
################################################################################
def ShipIdentified(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sShipName = pShip.GetName()
	
	# If the ship is Galor 3 or 4, call our function
	# and don't CallNextHandler
	if ((sShipName == "Galor 5") or (sShipName == "Galor 6")) and (g_bGalorsIDd == FALSE):
		global g_bGalorsIDd
		g_bGalorsIDd = TRUE
		Galors5And6IDd()
		return
	
	# We're done. Let any other event handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ShipInSensorRange()
##
##	Event handler called when a ship first appears on sensors (target list).
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
	
	# If the ship is Galor 3 or 4, call our function
	# and don't CallNextHandler
	if ((sShipName == "Galor 5") or (sShipName == "Galor 6")) and (g_bGalorsOnSensors == FALSE):
		global g_bGalorsOnSensors
		g_bGalorsOnSensors = TRUE
		Galors5And6OnSensors()
	
	# We're done. Let any other event handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	FriendlyFireReportHandler()
##
##	Handler called if player has done enough damage to a friendly ship to get a 
##  warning.
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
	sTargetName = pShip.GetName()

	# See who was shot and what line to call
	if (sTargetName == "RanKuf") and not g_bDraxonWarned:
		global g_bDraxonWarned
		g_bDraxonWarned = TRUE

		pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")

		pSequence = App.TGSequence_Create()
		
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))	
		pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp4", "Captain", 0, g_pMissionDatabase))
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KlingonSet", "Draxon"))
		pSequence.AppendAction(App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6FiresKlingon2", None, 0, g_pMissionDatabase)		)
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

		# Register and play
		App.TGActionManager_RegisterAction(pSequence, "Generic")
		pSequence.Play()

		return

	elif (sTargetName in g_lKlingonNames) and not (g_bKlingonWarned):

		global g_bKlingonWarned
		g_bKlingonWarned = TRUE

		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6FiresKlingon1", "Captain", 1, g_pMissionDatabase)
		pSaffiLine.Play()

		return

	elif (sTargetName == "Biranu Station") and not (g_bStationWarned):
		global g_bStationWarned
		g_bStationWarned = TRUE

		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6FiresStation1", "Captain", 1, g_pMissionDatabase)
		pSaffiLine.Play()

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
	sTargetName	= pShip.GetName()
	
	# See who's being shot at and call the right line.
	if (sTargetName in g_lKlingonNames):
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6FiresKlingon3", "Captain", 1, g_pMissionDatabase)
		
	else:
		# It's not the Klingon's, so it must be the station
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6FiresStation2", "Captain", 1, g_pMissionDatabase)
		
	# End the game
	pGameOver	= App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
	pGameOver.Play()

################################################################################
##	WeaponHitStation()
##
##	Handler called when a weapon hits the Biranu Station.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WeaponHitStation(TGObject, pEvent):
	# See what ship hit the Station
	pShip = App.ShipClass_Cast(pEvent.GetFiringObject())
	if (pShip == None):
		return

	sShipName = pShip.GetName()

	# Check and see if it's the first Galor firing on the station
	if (sShipName == "Galor 3") and (g_bCardsAttackStationCalled == TRUE) and (g_bStationHit == FALSE):
		global g_bStationHit
		g_bStationHit = TRUE

		# Remove instance handler on players ship for Weapon Fired event
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer != None):
			pPlayer.RemoveHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")

		# Make Cardassians Enemies and Klingons Friendlies
		pMission	= MissionLib.GetMission()
		if (pMission == None):
			return
		pNeutrals	= pMission.GetNeutralGroup()
		pEnemies	= pMission.GetEnemyGroup()
		pFriendlies	= pMission.GetFriendlyGroup()
	
		for sShipName in g_lCardNames:
			pNeutrals.RemoveName(sShipName)
			pEnemies.AddName(sShipName)

		pNeutrals.RemoveName("RanKuf")
		pNeutrals.RemoveName("Trayor")
		pFriendlies.AddName("RanKuf")
		pFriendlies.AddName("Trayor")

		# Affiliation colors sometimes don't get set correctly here (by the normal mechanisms). Reset
		# them, just in case.
		pTargetMenu = App.STTargetMenu_GetTargetMenu()
		if pTargetMenu:
			pTargetMenu.ResetAffiliationColors()

		# Change our music back to the default
		import DynamicMusic
		DynamicMusic.StopOverridingMusic()

		DamageStationHull()
		
	# Check and see if it's Galor 5 or 6
	elif ((sShipName == "Galor 5") or (sShipName == "Galor 6")) and (g_bGalors4And5Attack == FALSE):
		global g_bGalors4And5Attack
		g_bGalors4And5Attack = TRUE
		SecondGalorsFire()

	# All done with this event, call the next handler
	TGObject.CallNextHandler(pEvent)

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

	# See if the player is firing on the Klingons or Cardassians
	# before being give the order.
	if (g_bStationHit == FALSE) and (g_bGracePeriod == FALSE):
		if (sTargetName in g_lCardNames) or (sTargetName in g_lKlingonNames):
			if not g_bPlayerWarned:
				global g_bPlayerWarned
				g_bPlayerWarned = TRUE
				PlayerFiringEarly()
			else:
				# Player is still firing, so relieve them.
				RelievePlayer()

################################################################################
##	HailHandler()
##
##	Instance handler called when Kiska's hail button is hit.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent 		- The event that was sent.
##
##	Return:	None
################################################################################
def HailHandler(TGObject, pEvent):
	# Get the player and his target
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if (pTarget == None):
		return
		
	sTargetName = pTarget.GetName()
	
	# Are we hailing Draxon during the battle
	if (sTargetName == "RanKuf"):
		MissionLib.CallWaiting(None, TRUE)
		pKiskaHail	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pMissionDatabase)
		GenericRanKufHail()
		return
	# See if we can do the hail to Picard
	elif (sTargetName == "Biranu Station") and (g_bBOPsLeavingBiranu2 == TRUE) and (g_bCallForHelpSent == FALSE) and (g_bGalorsIDd == FALSE):
		PlayerHailsBiranu()
		return
	
	# Don't need to do anything special, pass on the event.
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
	#Get the players current set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName = pSet.GetName()
	
	# Keep them in place during the first part of the mission.
	if (sSetName == "Biranu2") and (g_bCardsAttackStationCalled == FALSE):
		pSaffiStayProd = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6ProdToGuard2", "Captain", 1, g_pMissionDatabase)
		pSaffiStayProd.Play()
		return
	# If the player is trying to warp when he shouldn't, tell him so
	elif (sSetName == "Biranu2") and ((g_bGalorsOnSensors == TRUE) or (g_bGalorsIDd == TRUE)):
		pSaffiGuardProd	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6ProdToGuard", "Captain", 1, g_pMissionDatabase)
		pSaffiGuardProd.Play()
		# Don't call the next handler
		return
		
	# All done, send event on to the next handler
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
##	Return:	None
################################################################################
def CommunicateHandler(TGObject, pEvent):
	# Get the menu that was clicked
	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())

	# Check the mission state variable and call our functions.
	if (g_iMissionState == ENTER_BIRANU):
		BiranuCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == KLINGON_ATTACK):
		KlingonsAttackCommunicate(pMenu.GetObjID(), TGObject, pEvent)
	
	elif (g_iMissionState == STATION_ATTACKED):
		StationAttackedCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == GALORS_RETREAT):
		GalorsRetreatCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == SECOND_WAVE):
		SecondWaveCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == SHIELDS_DOWN):
		ShieldsDownCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	else:
		# Just do the default stuff.
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	PlayerEntersBiranu()
##
##	Called when player enters Biranu2.  Plays dialog sequence.  Called from
##	exited warp when the player first enters Biranu 2.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerEntersBiranu():
	# Set our mission state and player location flag
	global g_bPlayerArriveBiranu2
	global g_iMissionState
	g_bPlayerArriveBiranu2	= TRUE
	g_iMissionState			= ENTER_BIRANU

	pKlingonSet		= App.g_kSetManager.GetSet("KlingonSet")
	pFedOutpostSet	= App.g_kSetManager.GetSet("FedOutpostSet")
	pCardSet		= App.g_kSetManager.GetSet("CardSet")

	pDraxon	= App.CharacterClass_GetObject(pKlingonSet, "Draxon")
	pPicard	= App.CharacterClass_GetObject(pFedOutpostSet, "Picard")
	pOben	= App.CharacterClass_GetObject(pCardSet, "Oben")

	pSequence = App.TGSequence_Create()

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"), 1)
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE))
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME))
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu1", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Biranu2"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Biranu2"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Biranu2", "Biranu Station"))
	pSequence.AppendAction(App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu2a", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu3", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu7", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Biranu2", "RanKuf"))
	pSequence.AppendAction(App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu8", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu9", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Biranu2", "Galor 1"))
	pSequence.AppendAction(App.CharacterAction_Create(pOben, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu10", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu11", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu12", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Biranu2")	)
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu4", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Picard"))
	pSequence.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu5", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu16", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu17", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "CardSet", "Oben"))
	pSequence.AppendAction(App.CharacterAction_Create(pOben, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu18", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetGalorAndBOPAI"))
	pSequence.AppendAction(App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu19", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu20", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(pOben, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu21", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "WatchRankuf"))
	pSequence.AppendAction(App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu22", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu23", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu24", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu25", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu26", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KlingonSet", "Draxon"))
	pSequence.AppendAction(App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu27a", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6ArriveBiranu27", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))

	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	WatchRankuf()
##
##	Watch the RanKuf on the Viewscreen. Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing
################################################################################
def WatchRankuf(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# If the player already has a target, don't do this
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
	pTarget = pPlayer.GetTarget()
	if (pTarget != None):
		return 0
		
	pSet	= App.g_kSetManager.GetSet("Biranu2")
	pBird1	= App.ShipClass_GetObject(pSet, "RanKuf")
	if (pBird1 != None):
		MissionLib.ViewscreenWatchObject(pBird1)

	return 0

################################################################################
##	PlayerFiringEarly()
##
##	Called from PlayerWeaponFired() if the player fires on the Klingons or Cardassians
##	before the station is attacked.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerFiringEarly():
	global g_bGracePeriod
	g_bGracePeriod = TRUE
	
	# Do the warning line from Saffi
	pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6EngageEarly1", "Captain", 1, g_pMissionDatabase)
	pSaffiLine.Play()

	# Start our timer to set the loss flag
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_GRACE_PERIOD_TIMER, __name__ + ".GracePeriodOver", fStartTime + 10, 0, 0)

################################################################################
##	GracePeriodOver()
##
##	Sets the grace period flag to false.  Called from timer event.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def GracePeriodOver(TGObject, pEvent):

	global g_bGracePeriod
	g_bGracePeriod = FALSE

################################################################################
##	RelievePlayer()
##
##	Called from PlayerWeaponFired() if the player attacks the Klingons or Cardassians
##	after the grace period is over.  Ends the mission.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RelievePlayer():
	# Do the loss sequence.
	pSequence = App.TGSequence_Create()
	
	pSaffiLook	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6EngageEarly2", "Captain", 0, g_pMissionDatabase)
	
	pSequence.AppendAction(pSaffiLook)
	pSequence.AppendAction(pSaffiLine)
	
	# End the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()

################################################################################
##	SetGalorAndBOPAI()
##	
##	Sets the AI's for the BOPs and the first three Galors.  Called as a script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing,
################################################################################
def SetGalorAndBOPAI(pTGAction):
	# Set mission state
	global g_iMissionState
	g_iMissionState = KLINGON_ATTACK
	
	# Change the music to netural combat
	import DynamicMusic
	DynamicMusic.OverrideMusic("Combat Neutral")

	# Get the set we need
	pSet	= App.g_kSetManager.GetSet("Biranu2")
	
	# Get the ships we need
	pGalor1	= App.ShipClass_GetObject(pSet, "Galor 1")
	pGalor2	= App.ShipClass_GetObject(pSet, "Galor 2")
	pGalor3	= App.ShipClass_GetObject(pSet, "Galor 3")
	pGalor4	= App.ShipClass_GetObject(pSet, "Galor 4")
	
	pBird1	= App.ShipClass_GetObject(pSet, "RanKuf")
	pBird2	= App.ShipClass_GetObject(pSet, "Trayor")
	
	# Assign AI to existing ships
	import E2M6_AI_Galor1_2
	import E2M6_AI_Galor3
	import E2M6_AI_Bird
	import E2M6_AI_RanKuf
	if (pGalor1 != None):
		pGalor1.SetAI(E2M6_AI_Galor1_2.CreateAI(pGalor1, "Card1Enter", g_pGalor1_2Targets, ET_TWO_GALORS_DESTROYED))
	if (pGalor2 != None):
		pGalor2.SetAI(E2M6_AI_Galor1_2.CreateAI(pGalor2, "Card2Enter", g_pGalor1_2Targets, ET_TWO_GALORS_DESTROYED))
	if (pGalor3 != None):
		pGalor3.SetAI(E2M6_AI_Galor3.CreateAI(pGalor3, "Card3Enter", ET_TWO_GALORS_DESTROYED))
	if (pGalor4 != None):
		pGalor4.SetAI(E2M6_AI_Galor3.CreateAI(pGalor4, "Card4Enter", ET_TWO_GALORS_DESTROYED))
	if (pBird1 != None):
		pBird1.SetAI(E2M6_AI_RanKuf.CreateAI(pBird1, "BOP1Enter", g_pBOPTargets))
	if (pBird2 != None):
		pBird2.SetAI(E2M6_AI_Bird.CreateAI(pBird2, "BOP2Enter", g_pBOPTargets))
	
	return 0

################################################################################
##	CardsAttackStation()
##
##	Called from E2M6_AI_Galor3.py just before Galor turns on the station.
##	Plays sequence from Picard telling the player to engage the Cardassians.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CardsAttackStation():
	# Check and see if the player is in Biranu2
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	elif (pSet.GetName() == "Biranu2"):
		# Set our mission state
		global g_iMissionState
		g_iMissionState = STATION_ATTACKED
		
		# Check our flag to see if this sequence has played
		if (g_bCardsAttackStationCalled == FALSE):
			global g_bCardsAttackStationCalled
			g_bCardsAttackStationCalled = TRUE
		else:
			return
			
		pSequence = App.TGSequence_Create()

		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")		
		pFelixAttacked1		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6StationAttacked1", None, 0, g_pMissionDatabase)
		pSaffiAttacked2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6StationAttacked2", None, 0, g_pMissionDatabase)
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pFelixAttacked1)
		pSequence.AppendAction(pSaffiAttacked2)
		
		MissionLib.QueueActionToPlay(pSequence)

		# Turn collisions back on for the Trayor
		pTrayor = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Biranu2"), "Trayor")
		if (pTrayor != None):
			pTrayor.SetCollisionsOn(TRUE)
		
################################################################################
##	DamageStationHull()
##
##	Damages the hull of the Biranu Station so the "death" of the commander
##	seems believable.  Does sequence from Picard telling the player to go after
##	the Galors.
##
##	Args:	None
##
##	Return:	None
################################################################################
def DamageStationHull():
	# Get the Station
	pStation = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Biranu2"), "Biranu Station")
	# Get the stations hull and apply damage to it.
	pStation.DamageSystem(pStation.GetHull(), pStation.GetHull().GetMaxCondition() / 7.0)
	
	# Set our flag
	global g_bSequenceRunning
	g_bSequenceRunning = TRUE
	
	# Do our sequence
	pFedOutpostSet	= App.g_kSetManager.GetSet("FedOutpostSet")
	pPicard			= App.CharacterClass_GetObject(pFedOutpostSet, "Picard")

	pSequence = App.TGSequence_Create()

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))

	# Check and see if the player is in Biranu2
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	elif (pSet.GetName() == "Biranu2"):
		pSequence.AppendAction(App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6StationAttacked3", None, 0, g_pMissionDatabase))
		pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6StationAttacked4", None, 0, g_pMissionDatabase))
		pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6StationAttacked5", "Captain", 1, g_pMissionDatabase))
		pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6StationAttacked6", None, 0, g_pMissionDatabase))

	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6StationAttacked7", None, 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Picard", 0.7, 1.0))
	pSequence.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6StationAttacked8", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetSequenceRunning"))

	MissionLib.QueueActionToPlay(pSequence)

	# Remove the resolve goal and add defend goal
	MissionLib.RemoveGoal("E2ResolveConflictGoal")
	MissionLib.AddGoal("E2DefendStationGoal")

################################################################################
##	GalorAttackingPlayer()
##
##	Called from E2M6_AI_Galor3.py when Galor starts to attack player.
##
##	Args:	pTGAction	- The script action object.	
##
##	Return:	0	- Return 0 to keep sequence from crashing.
################################################################################
def GalorAttackingPlayer(pTGAction):	
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "GalorAttackingPlayer")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:	# Set our flag
		if (g_bGalorOnPlayerCalled == FALSE):
			global g_bGalorOnPlayerCalled
			g_bGalorOnPlayerCalled = TRUE
		else:
			return 0
		
		# Set sequence flag
		global g_bSequenceRunning
		g_bSequenceRunning	= TRUE
		
		pSequence = App.TGSequence_Create()
		
		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pFelixAttacked1		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked1", "Captain", 1, g_pMissionDatabase)
		pKiskaAttacked2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked2", "Captain", 1, g_pMissionDatabase)
		pIsRanKufAlive		= App.TGScriptAction_Create(__name__, "RanKufAliveWhenPlayerAttacked")
		pFelixAttacked9		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked9", "Captain", 1, g_pMissionDatabase)
		pMiguelAttacked10	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked10", None, 0, g_pMissionDatabase)
		pSaffiAttacked11	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked11", None, 0, g_pMissionDatabase)
		pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pFelixAttacked1)
		pSequence.AppendAction(pKiskaAttacked2)
		pSequence.AppendAction(pIsRanKufAlive)
		pSequence.AppendAction(pFelixAttacked9)
		pSequence.AppendAction(pMiguelAttacked10)
		pSequence.AppendAction(pSaffiAttacked11)
		pSequence.AppendAction(pClearFlag)

		MissionLib.QueueActionToPlay(pSequence)

		# Add the player and the station to the target list of the other Galors
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer != None):
			global g_pGalor1_2Targets
			g_pGalor1_2Targets[pPlayer.GetName()]	= {"Priority" : 0.0}
			g_pGalor1_2Targets["Biranu Station"]	= {"Priority" : 0.0}
			
		return 0

################################################################################
##	RanKufAliveWhenPlayerAttacked()
##
##	Plays additional audio if the RanKuf is still alive when
##	GalorAttackingPlayer() is called.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep the calling sequence paused.
################################################################################
def RanKufAliveWhenPlayerAttacked(pTGAction):
	if (g_bRanKufDestroyed == TRUE) or (g_bMissionTerminate != 1):
		return 0
	else:
		# The ship exists so do our extra audio
		pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
		
		pSequence = App.TGSequence_Create()
		
		pKiskaAttacked5		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked5", "Captain", 1, g_pMissionDatabase)
		pDraxonAttacked6	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked6", None, 0, g_pMissionDatabase)
		pMiguelAttacked7	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked7", None, 0, g_pMissionDatabase)
		pDraxonAttacked8	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6PlayerAttacked8", None, 0, g_pMissionDatabase)
		
		pSequence.AddAction(pKiskaAttacked5)
		pSequence.AppendAction(pDraxonAttacked6)
		pSequence.AppendAction(pMiguelAttacked7)
		pSequence.AppendAction(pDraxonAttacked8)

		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pTGAction)
		pSequence.AddCompletedEvent(pEvent)
		
		pSequence.Play()
		
		return 1
		
################################################################################
##	BOPsChaseGalor()
##
##	Called from E2M6_AI_Bird.py just before the Birds of Prey warp out to
##	Biranu 1.  Does sequence and calls function to set AIs for Galors 4 & 5.
##
##	Args:	None
##
##	Return:	None
################################################################################
def BOPsChaseGalor():
	# Set our mission state
	global g_iMissionState
	g_iMissionState = GALORS_RETREAT
	
	# Check our flag
	if (g_bBOPsLeavingBiranu2 == FALSE):
		global g_bBOPsLeavingBiranu2
		g_bBOPsLeavingBiranu2 = TRUE
	else:
		return
		
	# Do our sequence
	pKlingonSet	= App.g_kSetManager.GetSet("KlingonSet")
	pDraxon		= App.CharacterClass_GetObject(pKlingonSet, "Draxon")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixGalorWarp1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp1", "Captain", 1, g_pMissionDatabase)
	pKiskaGalorWarp2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp2", None, 0, g_pMissionDatabase)
	pFelixGalorWarp3	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp3", "Captain", 1, g_pMissionDatabase)
	pCheckRanKufAlive	= App.TGScriptAction_Create(__name__, "RanKufAliveWhenGalorsWarp")	
	pKiskaGalorWarp6	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp6", "Captain", 0, g_pMissionDatabase)
	pKiskaGalorWarp7	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp7", None, 1, g_pMissionDatabase)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixGalorWarp1)
	pSequence.AppendAction(pKiskaGalorWarp2)
	pSequence.AppendAction(pFelixGalorWarp3)
	pSequence.AppendAction(pCheckRanKufAlive)
	pSequence.AppendAction(pKiskaGalorWarp6)
	pSequence.AppendAction(pKiskaGalorWarp7)
	
	MissionLib.QueueActionToPlay(pSequence)
		
	# Start timer that will start the second Galors toward the station.
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SECOND_GALOR_TIMER, __name__+".CreateGalor5And6", fStartTime + 90, 0, 0)
	
################################################################################
##	RanKufAliveWhenGalorsWarp()
##
##	Checks to see if the RanKuf is still alive and plays additional audio in
##	sequence called in BOPsChaseGalor().  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence from crashing.
################################################################################
def RanKufAliveWhenGalorsWarp(pTGAction):
	# Check and see if the RanKuf is alive
	if (g_bRanKufDestroyed == TRUE) or (g_bMissionTerminate != 1):
		return 0
	else:
		# Do the extra audio
		pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
		
		pSequence = App.TGSequence_Create()
		
		pKiskaGalorWarp4	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp4", "Captain", 0, g_pMissionDatabase)
		pKlingonViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KlingonSet", "Draxon")
		pDraxonGalorWarp3	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp5", None, 0, g_pMissionDatabase)		
		pKlingonViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		
		pSequence.AddAction(pKiskaGalorWarp4)
		pSequence.AppendAction(pKlingonViewOn)
		pSequence.AppendAction(pDraxonGalorWarp3)
		pSequence.AppendAction(pKlingonViewOff)
		
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pTGAction)
		pSequence.AddCompletedEvent(pEvent)
		
		pSequence.Play()
		
		return 1

################################################################################
##	GenericRanKufHail()
##
##	Called from HailHandler() when player hails the RanKuf.  Does generic line.
##	Calls itself as script action if another sequence is running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def GenericRanKufHail(pTGAction = None):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "GenericRanKufHail")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Set our flags
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		
		# Get Draxon
		pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
		
		pSequence = App.TGSequence_Create()
		
		pKiskaIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg3", None, 0, g_pGeneralDatabase)
		pDraxonGeneric	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6DraxonGeneric1", None, 0, g_pMissionDatabase)
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pKiskaIncoming)
		pSequence.AppendAction(pDraxonGeneric)
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AppendAction(pClearFlag)
		
		MissionLib.QueueActionToPlay(pSequence)
		
		return 0
		
################################################################################
##	PlayerHailsBiranu()
##
##	Called from HailHandler() if the player hails the Biranu Station after the
##	surviving Galor has warped out of the system.  Calls itself as script
##	action if another sequence is running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PlayerHailsBiranu(pTGAction = None):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1) or (g_bBiranuHailed == TRUE):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "PlayerHailsBiranu")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Set our flags
		global g_bSequenceRunning
		global g_bBiranuHailed
		g_bSequenceRunning	= TRUE
		g_bBiranuHailed		= TRUE

		# First time hailing, so do our sequence.
		pFedOutpostSet	= App.g_kSetManager.GetSet("FedOutpostSet")
		pPicard	= App.CharacterClass_GetObject(pFedOutpostSet, "Picard")

		pSequence = App.TGSequence_Create()

		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
		pSaffiGalorWarp8	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp8", "Captain", 1, g_pMissionDatabase)
		pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Picard")
		pPicardGalorWarp7	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp9", None, 0, g_pMissionDatabase)
		pPicardGalorWarp8	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp10", None, 0, g_pMissionDatabase)
		pPicardGalorWarp9	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsWarp11", None, 0, g_pMissionDatabase)
		pStarbaseViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
		pStayInBiranu		= App.TGScriptAction_Create(__name__, "StayInBiranu")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pCallWaiting)
		pSequence.AppendAction(pSaffiGalorWarp8)
		pSequence.AppendAction(pStarbaseViewOn)
		pSequence.AppendAction(pPicardGalorWarp7)
		pSequence.AppendAction(pPicardGalorWarp8)
		pSequence.AppendAction(pPicardGalorWarp9)
		pSequence.AppendAction(pStarbaseViewOff)
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AppendAction(pClearFlag)
		pSequence.AppendAction(pStayInBiranu, 6)	# 15 sec delay before we try this action

		MissionLib.QueueActionToPlay(pSequence)

		return 0
		
################################################################################
##	CreateGalor5And6()
##
##	Creates and sets the AI for Galor 5 & 6 so they will fly to the station 
##	and attack it.  Called by timer from BOPsChaseGalor().
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CreateGalor5And6(TGObject, pEvent):
	# Check our flag
	if (g_bGalor5And6HaveAI == FALSE):
		global g_bGalor5And6HaveAI
		g_bGalor5And6HaveAI = TRUE
	else:
		return
		
	# Get the set we need
	pSet	= App.g_kSetManager.GetSet("Biranu2")
	
	# Create the Galors that are out by the moon
	pGalor5	= loadspacehelper.CreateShip("Galor", pSet, "Galor 5", "Galor5Start")
	pGalor6	= loadspacehelper.CreateShip("Galor", pSet, "Galor 6", "Galor6Start")
 	
	# Get the AI and assign it
	import E2M6_AI_Galor5_6
	if (pGalor5 != None):
		pGalor5.SetAI(E2M6_AI_Galor5_6.CreateAI(pGalor5, g_pGalor5_6Targets))
	if (pGalor6 != None):
		pGalor6.SetAI(E2M6_AI_Galor5_6.CreateAI(pGalor6, g_pGalor5_6Targets))

################################################################################
##	StayInBiranu()
##
##	Called PlayerHailsBiranu().  Playes sequence if the player is still in
##	Biranu 2 set.
##
##	Args:	pTGAction	- The script action object.   
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def StayInBiranu(pTGAction):
	# See if the player is in Biranu 2
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None) or (g_bMissionTerminate != 1):
		return 0
	
	# Don't play if the player has already been to Biranu 1
	if (g_bPlayerChasingGalors == TRUE):
		return 0
		
	pSet = pPlayer.GetContainingSet()
	
	if (pSet.GetName() == "Biranu2"):
		# The player is in Biranu, so play the sequence.
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pMiguelStay1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6StayBiranu1", None, 0, g_pMissionDatabase)
		pBrexStay3		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M6StayBiranu3", "Captain", 1, g_pMissionDatabase)
		pKiskaStay2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6StayBiranu2", "Captain", 1, g_pMissionDatabase)
		pSaffiStay4		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6StayBiranu4", None, 0, g_pMissionDatabase)

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pMiguelStay1)
		pSequence.AppendAction(pBrexStay3)
		pSequence.AppendAction(pKiskaStay2)
		pSequence.AppendAction(pSaffiStay4)
		
		pSequence.Play()
		
		# Register this so we can kill it.
		App.TGActionManager_RegisterAction(pSequence, "StayBiranu")
		
		return 0
	
	else:
		return 0
		
################################################################################
##	PlayerFollowingKlingons()
##
##	Called if player enters Biranu 1 after the Klingons have left to chase
##	Galors.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerFollowingKlingons():
	# Set our mission state
	global g_iMissionState
	g_iMissionState = DEFAULT
	
	# Play a short sequence from Draxon if his ship is still alive
	if (g_bRanKufDestroyed == TRUE):
		return
	
	pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaFollow1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6FollowKlingons1", "Captain", 1, g_pMissionDatabase)
	pKlingonViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KlingonSet", "Draxon")
	pDraxonFollow2	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6FollowKlingons2", None, 0, g_pMissionDatabase)
	pKlingonViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaFollow1)
	pSequence.AppendAction(pKlingonViewOn)
	pSequence.AppendAction(pDraxonFollow2)
	pSequence.AppendAction(pKlingonViewOff)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	Biranu1Clear()
##
##	Called by E2M6_AI_Bird.py when there are no Cardassians in the Biranu 1 set.
##	Calls itself as script action if sequence if playing.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def Biranu1Clear(pTGAction = None):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1) or (g_bBiranu1ClearCalled == TRUE):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "Biranu1Clear")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Don't play if the player is not in Biranu 1
		pSet = MissionLib.GetPlayerSet()
		if (pSet == None):
			return 0
		if (pSet.GetName() != "Biranu1"):
			return 0
	
		# Set our flags
		global g_bSequenceRunning
		global g_bBiranu1ClearCalled
		g_bBiranu1ClearCalled	= TRUE
		g_bSequenceRunning		= TRUE
		
		# Get Draxon
		pDraxon = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
		
		# Do the lines from Draxon
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
		pKiskaFollow1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6FollowKlingons1", "Captain", 1, g_pMissionDatabase)
		pKiksaOnScreen	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, g_pGeneralDatabase)
		pViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KlingonSet", "Draxon")
		pDraxonClear1	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6Biranu1Clear1", None, 0, g_pMissionDatabase)
		pDraxonClear2	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6Biranu1Clear2", None, 0, g_pMissionDatabase)
		pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pResetBOPAI		= App.TGScriptAction_Create(__name__, "ResetBOPAI")
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pCallWaiting)
		pSequence.AppendAction(pKiskaFollow1)
		pSequence.AppendAction(pKiksaOnScreen)
		pSequence.AppendAction(pViewOn)
		pSequence.AppendAction(pDraxonClear1)
		pSequence.AppendAction(pDraxonClear2)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pResetBOPAI)
		pSequence.AppendAction(pClearFlag)
		pSequence.AppendAction(pEndCallWaiting)
		
		MissionLib.QueueActionToPlay(pSequence)
		
		return 0
		
################################################################################
##	StationCallsForHelp()
##
##	Called from E2M6_AI_Station if Galors 5 and 6 get close to station.  Calls
##	itself recursively if sequence is running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def StationCallsForHelp(pTGAction = None):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1) or (g_bCallForHelpSent == TRUE):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "StationCallsForHelp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Reset the AI's for any remaining first wave Galors
		iCounter = 0
		global g_pGalor1_2Targets
		g_pGalor1_2Targets = App.ObjectGroupWithInfo()
		g_pGalor1_2Targets["RanKuf"]	= {"Priority" : 0.0}
		g_pGalor1_2Targets["Trayor"]	= {"Priority" : 0.0}
		g_pGalor1_2Targets["player"]	= {"Priority" : 0.0}

		for sShipName in g_lFirstWaveNames:
			import E2M6_AI_GalorReturn
			pShip = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Biranu1"), sShipName)
			if (pShip != None):
				pShip.SetAI(E2M6_AI_GalorReturn.CreateAI(pShip, g_pGalor1_2Targets, ("GalorReturn" + str(iCounter))))
				iCounter = iCounter + 1

		# Check and see if the player is in Biranu2
		pSet = MissionLib.GetPlayerSet()
		if (pSet == None):
			return 0
		elif (pSet.GetName() != "Biranu2"):
			# Set our mission state
			global g_iMissionState
			g_iMissionState = SECOND_WAVE

			global g_bCallForHelpSent
			global g_bSequenceRunning
			g_bCallForHelpSent 	= TRUE
			g_bSequenceRunning	= TRUE

			# Get Picard
			pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("FedOutpostSet"), "Picard")
			# If we made it here, the player is not in Biranu 2 -
			# do our sequence.
			pSequence = App.TGSequence_Create()

			pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pKiskaCallForHelp1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6CallForHelp1", "Captain", 0, g_pMissionDatabase)
			pPicardCallForHelp2	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6CallForHelp2", None, 0, g_pMissionDatabase)
			pPicardCallForHelp3	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6CallForHelp3", None, 0, g_pMissionDatabase)
			pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

			pSequence.AppendAction(pPreLoad)
			pSequence.AppendAction(pKiskaCallForHelp1)
			pSequence.AppendAction(pPicardCallForHelp2)
			pSequence.AppendAction(pPicardCallForHelp3)
			pSequence.AppendAction(pClearFlag)

			MissionLib.QueueActionToPlay(pSequence)

			# Start a timer to play a couple of lines if the player has failed to
			# return to Biranu 2
			fStartTime	= App.g_kUtopiaModule.GetGameTime()
			MissionLib.CreateTimer(ET_RETURN_TO_BIRANU1_TIMER, __name__+".ProdBackToBiranu2", fStartTime + 60, 0, 0)

		return 0
			
################################################################################
##	ProdBackToBiranu2()
##
##	Called from timer event.  Plays prodding lines if the player has not gone
##	back to Biranu2.  Calls itself as script action sequence is running.
##
##	Args:	TGObject	- The TGObject object or script action.
##			pEvent		- The event that was sent.
##
##	Return:	0
################################################################################
def ProdBackToBiranu2(TGObject, pEvent = None):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1) or (g_bCallForHelpSent == TRUE):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ProdBackToBiranu2")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Check and see if the player is in Biranu2
		pSet = MissionLib.GetPlayerSet()
		if (pSet == None):
			return 0
		elif (pSet.GetName() == "Biranu2"):
			# We're in Biranu 2, so don't do the sequence.
			return 0

		# Set our sequence flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		
		# Get Picard
		pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("FedOutpostSet"), "Picard")

		pSequence = App.TGSequence_Create()

		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaCallForHelp4	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6CallForHelp4", "Captain", 1, g_pMissionDatabase)
		pPicardCallForHelp5	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6CallForHelp5", None, 0, g_pMissionDatabase)
		pSaffiCallForHelp6	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6CallForHelp6", "Captain", 1, g_pMissionDatabase)
		pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pKiskaCallForHelp4)
		pSequence.AppendAction(pPicardCallForHelp5)
		pSequence.AppendAction(pSaffiCallForHelp6)
		pSequence.AppendAction(pClearFlag)

		pSequence.Play()

		return 0
		
################################################################################
##	Galors5And6OnSensors()
##
##	Called when Galor 5 and 6 first appear on the sensors as "unidentified".
##	Calls SetGalor5And6AI() to make sure they've got one.
##
##	Args:	None
##
##	Return:	None
################################################################################
def Galors5And6OnSensors():
	# Check and see if the station has called for help
	if (g_bCallForHelpSent == TRUE):
		return
		
	pSequence = App.TGSequence_Create()
	
	pMiguelGalorsDetected	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6SecondGalorsDetected1", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AddAction(pMiguelGalorsDetected)
	
	pSequence.Play()
	
################################################################################
##	Galors5And6IDd()
##
##	Called from ShipIdentified() if Galor 5 or Galor 6 are identified by
##	scanning.  If the Galors have not been given their AI, do that now as well.
##
##	Args:	None
##
##	Return:	None
################################################################################
def Galors5And6IDd():
	# Set our mission state
	global g_iMissionState
	g_iMissionState = SECOND_WAVE
	
	# Check and see if station has called for help
	if (g_bCallForHelpSent == TRUE):
		return
		
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelIDd1			= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsIDd1", "Captain", 1, g_pMissionDatabase)
	pHaveGalorsFired	= App.TGScriptAction_Create(__name__, "HaveGalorsFired")
	pKiskaIDd4			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsIDd4", "Captain", 0, g_pMissionDatabase)
	pRedAlertCheck		= App.TGScriptAction_Create(__name__, "RedAlertCheck")	
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelIDd1)
	pSequence.AppendAction(pHaveGalorsFired)
	pSequence.AppendAction(pKiskaIDd4)
	pSequence.AppendAction(pRedAlertCheck)

	pSequence.Play()

	# Kill the StayBiranu sequence
	App.TGActionManager_KillActions("StayBiranu")
	
################################################################################
##	HaveGalorsFired()
##
##	Script action that plays a line from Picard if the Galors 4 and 5 have not
##	yet fired on the station.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def HaveGalorsFired(pTGAction):
	# Check and see if the Galors have fired.
	if (g_bGalors4And5Attack == TRUE) or (g_bMissionTerminate != 1):
		return 0
		
	# The Galors haven't fired so do Picard's line
	pFedOutpostSet	= App.g_kSetManager.GetSet("FedOutpostSet")
	pPicard			= App.CharacterClass_GetObject(pFedOutpostSet, "Picard")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaIDd2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsIDd2", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Picard")
	pPicardIDd3		= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsIDd3", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaIDd2)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pPicardIDd3)
	pSequence.AppendAction(pViewOff)

	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	# Register and play
	App.TGActionManager_RegisterAction(pSequence, "Generic")
	pSequence.Play()

	return 1		

################################################################################
##	RedAlertCheck()
##
##	Check and see what alert level we're at, and play audio line based on that.
##	Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def RedAlertCheck(pTGAction):
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None) or (g_bMissionTerminate != 1):
		return 0
		
	if (pPlayer.GetAlertLevel() == App.ShipClass.RED_ALERT):
		# We're at Red alert, so do Felix's line
		pFelixLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsIDd6", "Captain", 1, g_pMissionDatabase)
		pFelixLine.Play()
	else:
		# Not at Red alert, so have Saffi's line play
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsIDd5", "Captain", 0, g_pMissionDatabase)
		pSaffiLine.Play()
		
	return 0
	
################################################################################
##	SecondGalorsFire()
##
##	Called from WeaponFire() if either Galor 5 or 6 opens fire for the first
##	time.  Plays sequence letting the player know they can attack the Galors.
##	Calls itsef as script action if another sequence is running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SecondGalorsFire(pTGAction = None):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "SecondGalorsFire")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Set our flags
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		# Get Picard
		pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("FedOutpostSet"), "Picard")

		pSequence = App.TGSequence_Create()

		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))

		# Check and see if the player is in Biranu2
		pSet = MissionLib.GetPlayerSet()
		if (pSet == None):
			return 0
		elif (pSet.GetName() == "Biranu2"):
			pSequence.AppendAction(App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsFire1", "Captain", 1, g_pMissionDatabase))
			pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsFire2", "Captain", 1, g_pMissionDatabase))

		pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsFire3", "Captain", 1, g_pMissionDatabase))
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Picard"))
		pSequence.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6GalorsFire4", None, 0, g_pMissionDatabase))
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetSequenceRunning"))

		MissionLib.QueueActionToPlay(pSequence)

		# Start the timer that will bring the Klingons back.
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_KLINGON_RETURN_TIMER, __name__+".ResetBOPAI", fStartTime + 120, 0, 0)
	
		return 0
		
################################################################################
##	DisableStationShields()
##
##	Called from E2M6_AI_Station.py when one of the stations shields is taken
##	down to 0.  Disables the shield generator and does sequence telling player
##	to fix them.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def DisableStationShields(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "DisableStationShields")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Set our mission state
		global g_iMissionState
		g_iMissionState = SHIELDS_DOWN

		# Get the station and disable it's shield generator
		pSet	= App.g_kSetManager.GetSet("Biranu2")
		pStation	= App.ShipClass_GetObject(pSet, "Biranu Station")
		if (pStation == None):
			return 0

		pStation.DamageSystem(pStation.GetShields(), pStation.GetShields().GetMaxCondition() / 1.75)
		
		# Set our flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		
		# Do the sequence that let's the player know
		# the shields have been taken out.
		pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("FedOutpostSet"), "Picard")

		pSequence = App.TGSequence_Create()

		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pMiguelShieldsDown1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6ShieldsDown1", "Captain", 0, g_pMissionDatabase)
		pMiguelShieldsDown2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6ShieldsDown2", None, 1, g_pMissionDatabase)
		pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pMiguelShieldsDown1)
		pSequence.AppendAction(pMiguelShieldsDown2)
		pSequence.AppendAction(pClearFlag)

		MissionLib.QueueActionToPlay(pSequence)

		return 0
		
################################################################################
##	ResetBOPAI()
##
##	Resets the Bird of Prey's AI so that they will return to aid the station
##	after finishing with the Galors in Biranu 1.  Called from timer or
##	Biranu1Clear() as script action.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetBOPAI(TGObject, pEvent = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check and set out flag
	if (g_bBOPSOSAISet == FALSE):
		global g_bBOPSOSAISet
		g_bBOPSOSAISet = TRUE
	else:
		return 0
		
	import E2M6_AI_BirdSOS
	import E2M6_AI_RanKufSOS
	
	# Get the ships and assign the AI if they exist
	pSet	= App.g_kSetManager.GetSet("Biranu1")
	pRanKuf	= App.ShipClass_GetObject(pSet, "RanKuf")
	pTrayor = App.ShipClass_GetObject(pSet, "Trayor")
	
	if (pRanKuf != None):
		pRanKuf.SetAI(E2M6_AI_RanKufSOS.CreateAI(pRanKuf, "BOP1Enter", g_pBOPTargets))
	
	if (pTrayor != None):
		pTrayor.SetAI(E2M6_AI_BirdSOS.CreateAI(pTrayor, "BOP2Enter", g_pBOPTargets))

	# Add the player to the target list for the other Galors
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		global g_pGalor1_2Targets
		g_pGalor1_2Targets[pPlayer.GetName()]	= {"Priority" : 0.5}

	return 0
	
################################################################################
##	BOPsReturnToHelp()
##
##	Sequence that plays when Klingons arrive back in Biranu 2 if they survived
##	in Biranu 1.  Called from EnterSet().  Calls itself as script action if
##	another sequence is running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def BOPsReturnToHelp(pTGAction = None):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1) or (g_bBiranu1ClearCalled == TRUE):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "BOPsReturnToHelp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# If the player is not in Biranu 2, don't play
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return 0
		pSet = pPlayer.GetContainingSet()
		if (pSet == None):
			return 0
			
		if (pSet.GetName() == "Biranu2"):
			# Set our flags
			global g_bSequenceRunning
			g_bSequenceRunning = TRUE

			pBridge		= App.g_kSetManager.GetSet("bridge")
			pKlingonSet	= App.g_kSetManager.GetSet("KlingonSet")

			pDraxon	= App.CharacterClass_GetObject(pKlingonSet, "Draxon")

			pSequence = App.TGSequence_Create()

			# Figure out Kiska's first line bby getting the BOPs and seeing who's NULL
			pBOP1	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Biranu2"), "RanKuf")
			pBOP2	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Biranu2"), "Trayor")
			if (pBOP1 != None) and (pBOP2 != None):
				sKiskaLine = "E2M6KlingonsReturn1B"
			else:
				sKiskaLine = "E2M6KlingonsReturn1A"

			pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaReturn1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, sKiskaLine, "Captain", 1, g_pMissionDatabase)
			pRanKufReturn	= App.TGScriptAction_Create(__name__, "DidRanKufReturn")
			pFelixReturn7	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6KlingonsReturn7", None, 0, g_pMissionDatabase)
			pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

			pSequence.AppendAction(pPreLoad)
			pSequence.AppendAction(pCallWaiting)
			pSequence.AppendAction(pKiskaReturn1)
			pSequence.AppendAction(pRanKufReturn)
			pSequence.AppendAction(pFelixReturn7)
			pSequence.AppendAction(pEndCallWaiting)
			pSequence.AppendAction(pClearFlag)

			MissionLib.QueueActionToPlay(pSequence)

		return 0
		
################################################################################
##	DidRanKufReturn()
##
##	Checks to see if the RanKuf was one of the Klingon ships to return to
##	Biranu2.  If so, plays sequence from Draxon.  Called as script action.
##
##	Args:	pTGAction	- The script aciton object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def DidRanKufReturn(pTGAction):
	# Check the flag for the RanKuf
	if (g_bRanKufDestroyed == TRUE) or (g_bMissionTerminate != 1):
		return 0
	
	# Draxon lives! Do the sequence.
	pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
	
	pSequence = App.TGSequence_Create()
	
	pKiskaReturn2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6KlingonsReturn2", "Captain", 1, g_pMissionDatabase)
	pDraxonReturn3	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6KlingonsReturn3", None, 0, g_pMissionDatabase)
	pMiguelReturn4	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6KlingonsReturn4", "Captain", 1, g_pMissionDatabase)
	pDraxonReturn5	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M6KlingonsReturn5", None, 0, g_pMissionDatabase)
	
	pSequence.AddAction(pKiskaReturn2)
	pSequence.AppendAction(pDraxonReturn3)
	pSequence.AppendAction(pMiguelReturn4)
	pSequence.AppendAction(pDraxonReturn5)

		
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	return 1		

################################################################################
##	StationTakingDamage()
##
##	Called for E2M6_AI_Station when either the power plant or hull fall
##	below 50%.  Plays audio for Felix.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationTakingDamage():
	# Get Picard
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("FedOutpostSet"), "Picard")
	
	pSequence = App.TGSequence_Create()

	# Check and see if the player is in Biranu2
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	elif (pSet.GetName() == "Biranu2"):	
		pSequence.AppendAction(App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6StationDamaged1", "Captain", 1, g_pMissionDatabase))

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6StationDamaged2", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Picard", 0.2, 0.5))
	pSequence.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6StationDamaged3", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6StationDamaged4", None, 0, g_pMissionDatabase))

	# Register and play
	App.TGActionManager_RegisterAction(pSequence, "Generic")
	pSequence.Play()
	
################################################################################
##	StationWasDestroyed()
##
##	Called from ShipDestroyed if Biranu Station is destroyed.  Plays fail
##	dialog.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationWasDestroyed():
	# Delete any queued sequences
	MissionLib.DeleteQueuedActions()
	
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu 			= App.CharacterClass_GetObject (pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	pFelixLook			= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME)
	pFelixDestroyed1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6StationDestroyed1", "Captain", 1, g_pMissionDatabase)
	pSaffiLook			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSaffiDestroyed2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6StationDestroyed2", None, 0, g_pMissionDatabase)
	pSaffiDestroyed3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6StationDestroyed3", "Captain", 0, g_pMissionDatabase)
	pSaffiStarfleet1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet1", None, 1, g_pGeneralDatabase)
	pSaffiStarfleet7	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet7", None, 0, g_pGeneralDatabase)
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuDestroyed4		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6StationDestroyed4", None, 0, g_pMissionDatabase)
	pLiuDestroyed5		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6StationDestroyed5", None, 0, g_pMissionDatabase)
	pLiuDestroyed6		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6StationDestroyed6", None, 0, g_pMissionDatabase)
	pLiuDestroyed7		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6StationDestroyed7", None, 0, g_pMissionDatabase)
	pStarbaseViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pFelixLook)
	pSequence.AppendAction(pFelixDestroyed1)
	pSequence.AddAction(pSaffiLook,	pFelixDestroyed1)
	pSequence.AddAction(pSaffiDestroyed2, pFelixDestroyed1)
	pSequence.AppendAction(pSaffiDestroyed3)
	pSequence.AppendAction(pSaffiStarfleet1)
	pSequence.AppendAction(pSaffiStarfleet7)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuDestroyed4)
	pSequence.AppendAction(pLiuDestroyed5)
	pSequence.AppendAction(pLiuDestroyed6)
	pSequence.AppendAction(pLiuDestroyed7)
	pSequence.AppendAction(pStarbaseViewOff)

	# End the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()

################################################################################
##	MissionWin()
##	
##  Called if Galor is destroyed and Starbase survives
##	
##	Args: 	None
##	
##	Return: None
################################################################################		
def MissionWin():
	# Set our mission state
	global g_iMissionState
	g_iMissionState = DEFAULT
	
	# If the station has been destroyed, bail
	if (g_bStationDestroyed == TRUE):
		return
		
	# Set our flag
	global g_bMissionWin
	g_bMissionWin = TRUE
	
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pFedOutpostSet	= App.g_kSetManager.GetSet("FedOutpostSet")
	pPicard 		= App.CharacterClass_GetObject(pFedOutpostSet, "Picard")
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pFelixWin1			= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin1", "Captain", 1, g_pMissionDatabase)
	pKiskaWin2			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin2", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Picard")
	pPicardWin3			= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin3", None, 0, g_pMissionDatabase)
	pPicardWin4			= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin4", None, 0, g_pMissionDatabase)
	pPicardWin5			= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin5", None, 0, g_pMissionDatabase)
	pPicardWin6			= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin6", None, 0, g_pMissionDatabase)
	pPicardWin7			= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin7", None, 0, g_pMissionDatabase)
	pPicardWin8			= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin8", None, 0, g_pMissionDatabase)
	pPicardWin9			= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin9", None, 0, g_pMissionDatabase)
	pStarbaseViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pKiskaWin10			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin10", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn2	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuWin11			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin11", None, 0, g_pMissionDatabase)
	pLiuWin12			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin12", None, 0, g_pMissionDatabase)
	pLiuWin13			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin13", None, 0, g_pMissionDatabase)
	pStarbaseViewOff2	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pKiskaWin14			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin14", "Captain", 0, g_pMissionDatabase)
	pSaffiWin15			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin15", None, 0, g_pMissionDatabase)
	pKiskaWin16			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6MissionWin16", None, 1, g_pMissionDatabase)
	# Start the next episode
	pFadeToBlack		= App.TGScriptAction_Create("MissionLib", "FadeOut", 2.0)
	pStartEpisode3		= App.TGScriptAction_Create(__name__, "StartEpisode3")
	pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pFelixWin1)
	pSequence.AppendAction(pKiskaWin2)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pPicardWin3)
	pSequence.AppendAction(pPicardWin4)
	pSequence.AppendAction(pPicardWin5)
	pSequence.AppendAction(pPicardWin6)
	pSequence.AppendAction(pPicardWin7)
	pSequence.AppendAction(pPicardWin8)
	pSequence.AppendAction(pPicardWin9)
	pSequence.AppendAction(pStarbaseViewOff)
	pSequence.AppendAction(pKiskaWin10)
	pSequence.AppendAction(pStarbaseViewOn2)
	pSequence.AppendAction(pLiuWin11)
	pSequence.AppendAction(pLiuWin12)
	pSequence.AppendAction(pLiuWin13)
	pSequence.AppendAction(pStarbaseViewOff2)
	pSequence.AppendAction(pKiskaWin14)
	pSequence.AppendAction(pSaffiWin15)
	pSequence.AppendAction(pKiskaWin16)
	pSequence.AddAction(pFadeToBlack, pSaffiWin15, 2.5)
	pSequence.AddAction(pStartEpisode3, pFadeToBlack, 2)
	pSequence.AddAction(pEndCutscene, pFadeToBlack)

	MissionLib.QueueActionToPlay(pSequence)
	
	# Remove our Defend station goal
	MissionLib.RemoveGoal("E2DefendStationGoal")

################################################################################
##	StartEpisode3()
##
##	Script action that will load the next episode, in this case, Episode 3.
##
##	Args:	pTGAction	- The script aciton object.
##
##	Return:	0	- Return 0 so the calling sequence completes.
################################################################################
def StartEpisode3(pTGAction):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Put up the splash screen.
	App.g_kMovieManager.LoadForcedMovie("data/Movies/Loading.bik")

	# Load the next episode
	App.Game_GetCurrentGame().LoadEpisode("Maelstrom.Episode3.Episode3")
	
	return 0

################################################################################
##	BiranuCommunicate()
##
##	Called from CommunicateHandler() if the player has just entered Biranu 2.
##	Plays special dialogue, but calls next handler for event if now special line
##	exists.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was caught by CommunicateHandler()
##
##	Return:	None
################################################################################
def BiranuCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID of the menu and see who's it is
	if (iMenuID == idKiskaMenu):
		pComLine = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6KiskaCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6SaffiCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	KlingonsAttackCommunicate()
##
##	Called from CommunicateHandler() if the Klingons have engaged the Cards.
##	Plays special dialogue, but calls next handler for event if now special line
##	exists.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was caught by CommunicateHandler()
##
##	Return:	None
################################################################################
def KlingonsAttackCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID if the menu and see who it is
	if (iMenuID == idKiskaMenu):
		pComLine = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6KiskaCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6SaffiCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6MiguelCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M6BrexCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)
	
################################################################################
##	StationAttackedCommunicate()
##
##	Called from CommunicateHandler() if the Cards have attacked the station.
##	Plays special dialogue, but calls next handler for event if now special line
##	exists.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was caught by CommunicateHandler()
##
##	Return:	None
################################################################################
def StationAttackedCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID if the menu and see who it is
	if (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6SaffiCom3", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6MiguelCom3", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M6BrexCom3", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	GalorsRetreatCommunicate()
##
##	Called from CommunicateHandler() if the first wave of Galors retreats.
##	Plays special dialogue, but calls next handler for event if now special line
##	exists.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was caught by CommunicateHandler()
##
##	Return:	None
################################################################################
def GalorsRetreatCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID if the menu and see who it is
	if (iMenuID == idKiskaMenu):
		pComLine = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6KiskaCom4", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()

	# Make sure we don't do this line if the player has already hailed Biranu
	elif (iMenuID == idSaffiMenu) and (g_bBiranuHailed == FALSE):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6SaffiCom4", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6MiguelCom4", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M6BrexCom4", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)
			
################################################################################
##	SecondWaveCommunicate()
##
##	Called from CommunicateHandler() if the second Card wave has arrived.
##	Plays special dialogue, but calls next handler for event if now special line
##	exists.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was caught by CommunicateHandler()
##
##	Return:	None
################################################################################
def SecondWaveCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID if the menu and see who it is
	if (iMenuID == idKiskaMenu):
		pComLine = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M6KiskaCom5", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()

	elif (iMenuID == idFelixMenu):
		pComLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6FelixCom5", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
				
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6SaffiCom5", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M6MiguelCom5", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	ShieldsDownCommunicate()
##
##	Called from CommunicateHandler() if the player has just entered Biranu 2.
##	Plays special dialogue, but calls next handler for event if now special line
##	exists.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was caught by CommunicateHandler()
##
##	Return:	None
################################################################################
def ShieldsDownCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID if the menu and see who it is
	if (iMenuID == idFelixMenu):
		pComLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M6FelixCom6", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
				
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6SaffiCom6", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M6BrexCom6", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)

################################################################################
##	SetSequenceRunning()
##
##	Script action that sets the value of g_bSequenceRunning to FALSE.
##	g_bSequenceRunning used as flag to see if it's okay to start running another
##	sequence.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetSequenceRunning(pTGAction):
	global g_bSequenceRunning
	g_bSequenceRunning = FALSE
	
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
##	Figure out what kind of prodding the player need and call the correct
##	function.
##
##	Args:	pTGObject	- The TGObject object
##			pEvent		- The event that was sent to the object
##
##	Return:	None
##
################################################################################
def ProdPlayer(pTGObject, pEvent):
	# Prod back to Biranu if the player has left.
	if (g_bPlayerNotInBiranu == TRUE):
		ProdBackToBiranu()
		
################################################################################
##	ProdBackToBiranu()
##
##	Function called from ProdPlayer() if the player has left Biranu before the
##	mission is over.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ProdBackToBiranu():
	# Check the counter and decide what line to play.
	if (g_iProdToBiranuCounter == 0):
		pSequence = App.TGSequence_Create()
		pPreLoad	= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")	
		pSaffiLine1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6ProdToGuard2", "Captain", 0, g_pMissionDatabase)
		pSaffiLine2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6ProdToGuard2a", None, 1, g_pMissionDatabase)
		pStartTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 20)
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pSaffiLine1)
		pSequence.AppendAction(pSaffiLine2)
		pSequence.AppendAction(pStartTimer)
		
		pSequence.Play()
	
	elif (g_iProdToBiranuCounter == 1):
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6ProdToGuard3", "Captain", 1, g_pMissionDatabase)
		pSaffiLine.Play()
		RestartProdTimer(None, 20)
		
	elif (g_iProdToBiranuCounter == 2):
		# That's it, no more Ms. Nice.
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M6ProdToGuard4", "Captain", 1, g_pMissionDatabase)
		
		pGameOver	= App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
		pGameOver.Play()
		
	# Increase our counter
	global g_iProdToBiranuCounter
	g_iProdToBiranuCounter = g_iProdToBiranuCounter + 1
	
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
	# Clear out all the systems in the set course menu.
	App.SortedRegionMenu_ClearSetCourseMenu()
	
	# Delete any ships that might be in the warp set
	MissionLib.DeleteShipsFromWarpSetExceptForMe()
	
	# Delete all our goals
	MissionLib.DeleteAllGoals()

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()
	
	# Mark our flag
	global g_bMissionTerminate
	g_bMissionTerminate = 0
	
	# Remove our instance handlers
	RemoveInstanceHandlers()
	
	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# Stop the prod timer if it's running
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
	# Remove instance handler on players ship for Weapon Fired event
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.RemoveHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")

	# Remove instance handlers for Kiska
	pKiska = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")
	if (pKiska != None):
		pKiskaMenu = pKiska.GetMenu()
		if (pKiskaMenu != None):
			pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			# Remove instance handler on Warp button event
			pWarpButton = Bridge.BridgeUtils.GetWarpButton()
			if (pWarpButton != None):
				pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")
	
	# Remove instance handlers for Saffi
	pSaffi = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	if (pKiska != None):
		pSaffiMenu = pSaffi.GetMenu()
		if (pSaffiMenu != None):
			pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			
	# Remove instance handlers for Felix
	pFelix = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if (pFelix != None):
		pFelixMenu = pFelix.GetMenu()
		if (pFelixMenu != None):
			pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			
	# Remove instance handlers for Miguel
	pMiguel = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Science")
	if (pMiguel != None):
		pMiguelMenu = pMiguel.GetMenu()
		if (pMiguelMenu != None):
			pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			
	# Remove instance handlers for Brex
	pBrex = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
	if (pBrex != None):
		pBrexMenu = pBrex.GetMenu()
		if (pBrexMenu != None):
			pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")