###############################################################################
#	Filename:	E3M2.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	 
#	Episode 3 Mission 2
#	
#	Created:	05/07/01 - Alberto Fonseca
#	Modified:	01/11/02 - Tony Evans
###############################################################################

import App
import loadspacehelper
import MissionLib
import Bridge.Characters.CommonAnimations
import Maelstrom.Episode3.Episode3
import Bridge.BridgeUtils

#Start debugger
#kDebugObj = App.CPyDebug()

TRUE					= 1
FALSE					= 0

#
# Place event types here
#
ET_PROD_REENTER_EVENT	= App.Mission_GetNextEventType()
ET_HELP_BERKELEY		= App.Mission_GetNextEventType()
ET_PLAYER_HIT			= App.Mission_GetNextEventType()
ET_SUGGEST_HIDE			= App.Mission_GetNextEventType()
ET_CREATE_TAUNT_PROX	= App.Mission_GetNextEventType()
ET_VIEWSCREEN_RETRY		= App.Mission_GetNextEventType()
ET_RADIATION_WARN		= App.Mission_GetNextEventType()

#
# Global variables 
#
g_bMissionTerminated	= FALSE
g_bBriefingPlayed		= FALSE
g_bVesuvi6Arrive		= FALSE
g_pMissionDatabase		= None
g_pGeneralDatabase		= None
g_bHelpedBerkeley		= FALSE
g_bDerelictAttacked		= FALSE
g_bTerrikIntroPlayed	= FALSE
g_bTerrikOutroPlayed	= FALSE
g_bRadiationWarning		= FALSE	
g_iShieldProdCount		= 0
g_bNavPointsCreated		= FALSE
g_bInNebula				= FALSE
g_bHailedBerkeley		= FALSE
g_bAsteroidScanned		= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
g_iAsteroidsScanned		= 0
g_iMissionProgress		= 0
g_pProxBeta				= None
g_pProxBerkeley			= None
g_iProdReEnterTimerID	= App.NULL_ID
g_iPlanetFragmentCount	= 1
g_iGasShellCount		= 1
g_bTerrikTalksTactics	= FALSE
g_bTerrikTauntPlayed	= FALSE
g_pFriendlies			= None
g_pEnemies				= None
g_pNeutrals				= None
g_pProxProbe			= None
g_iNumToScan			= 0
g_bProbeFound			= FALSE
g_bProbeTriggered		= FALSE

# Constants
NUM_OBJECTS_NAV1		= 3
NUM_OBJECTS_NAV2		= 4
NUM_OBJECTS_NAV3		= 3
NUM_OBJECTS_NAV4		= 2
MIN_TO_SCAN				= 3
MAX_TO_SCAN				= 8
STELLAR_CORE			= 5		
ASTEROID_SCAN_RANGE		= 115	
NAV_PROXIMITY_DIST		= 145
PROBE_WARN_DIST			= 142
PLAYER_PROBE_DIST		= 57
NAV_BERKELEY_PROX		= -114
SUGGEST_HIDE_THRESHOLD	= 0.75

# Mission progress
FIND_CORE				= 0
AID_BERKELEY			= 1
HAIL_STARFLEET			= 2
FIND_PROBE				= 3
PROBE_DESTROYED			= 4
ROMULAN_ENCOUNTER		= 5
MET_ROMULANS			= 6
MISSION_WON				= 7

###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to add models to be pre loaded.
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	import loadspacehelper
	loadspacehelper.PreloadShip("Sovereign", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Nebula", 3)
	loadspacehelper.PreloadShip("KessokMine", 1)
	loadspacehelper.PreloadShip("Warbird", 4)
	loadspacehelper.PreloadShip("KessokHeavy", 1)

################################################################################
#	Initialize(pMission)
#
#	Called at mission start.
#
#	Args:	pMission - Current mission starting.
#
#	Return:	None
################################################################################
def Initialize(pMission):
#	kDebugObj.Print("Initializing E3M2.\n")
	
	# Initialize all global variables.
	InitGlobals(pMission)

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")
	
	# Load placements for bridge.
	import Maelstrom.Episode3.EBridge_P
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	Maelstrom.Episode3.EBridge_P.LoadPlacements(pBridgeSet.GetName())

	pLiuSet = MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu = MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet", 0, 0, 5)

	pTBridgeSet = MissionLib.SetupBridgeSet("TBridgeSet", "data/Models/Sets/Romulan/romulanbridge.nif", -40, 65, -1.55)
	pTerrik = MissionLib.SetupCharacter("Bridge.Characters.Terrik", "TBridgeSet")

	pHBridgeSet = MissionLib.SetupBridgeSet("HBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -40, 65, -1.55)
	MissionLib.ReplaceBridgeTexture(None, "HBridgeSet", "Map 7.tga", "data/Models/Sets/DBridge/NebulaLCARS.tga")
	pHaley = MissionLib.SetupCharacter("Bridge.Characters.Haley", "HBridgeSet")

	# Set random number of asteroids player must scan.
	global g_iNumToScan
	g_iNumToScan = App.g_kSystemWrapper.GetRandomNumber(MAX_TO_SCAN) + MIN_TO_SCAN

	CreateMenus()
	CreateSpaceSets()
	CreateShips()
	SetAffiliations(pMission)	
	SetupEventHandlers(pMission)
	CreateData()

	# Goals
	MissionLib.AddGoal("E3MeetWithBerkeleyGoal")

#	kDebugObj.Print("Finished loading " + __name__)

	MissionLib.SaveGame("E3M2-")

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)

	MissionLib.SetupFriendlyFire()

################################################################################
#	InitGlobals(pMission)
#
#	Initialize global variables for whole mission.
#
#	Args:	pMission, the current mission.
#
#	Return:	None
################################################################################
def InitGlobals(pMission):
	global g_bMissionTerminated
	global g_bBriefingPlayed		
	global g_bHelpedBerkeley		
	global g_bDerelictAttacked
	global g_bTerrikIntroPlayed	
	global g_bTerrikOutroPlayed	
	global g_bRadiationWarning		
	global g_iShieldProdCount
	global g_bNavPointsCreated		
	global g_bInNebula				
	global g_bHailedBerkeley		
	global g_bAsteroidScanned		
	global g_iAsteroidsScanned		
	global g_iMissionProgress		
	global g_pProxBerkeley			
	global g_pProxBeta				
	global g_iProdReEnterTimerID
	global g_iPlanetFragmentCount	
	global g_iGasShellCount		
	global g_bTerrikTalksTactics
	global g_bTerrikTauntPlayed	
	global g_pMissionDatabase		
	global g_pGeneralDatabase	
	global g_pFriendlies
	global g_pEnemies
	global g_pNeutrals	
	global g_pProxProbe
	global g_iNumToScan

	g_bMissionTerminated	= FALSE
	g_bBriefingPlayed		= FALSE
	g_bHelpedBerkeley		= FALSE
	g_bDerelictAttacked		= FALSE
	g_bTerrikIntroPlayed	= FALSE
	g_bTerrikOutroPlayed	= FALSE
	g_bRadiationWarning		= FALSE	
	g_iShieldProdCount		= 0
	g_bNavPointsCreated		= FALSE
	g_bInNebula				= FALSE
	g_bHailedBerkeley		= FALSE
	g_bAsteroidScanned		= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
	g_iAsteroidsScanned		= 0
	g_iMissionProgress		= FIND_CORE
	g_pProxBerkeley			= None
	g_pProxBeta				= None
	g_iProdReEnterTimerID	= App.NULL_ID
	g_iPlanetFragmentCount	= 1
	g_iGasShellCount		= 1
	g_bTerrikTalksTactics	= FALSE
	g_bTerrikTauntPlayed	= FALSE
	g_pFriendlies			= pMission.GetFriendlyGroup()
	g_pEnemies				= pMission.GetEnemyGroup()
	g_pNeutrals				= pMission.GetNeutralGroup()
	g_pProxProbe			= None
	g_iNumToScan			= 0
	g_pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 3/E3M2.tgl")
	g_pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

################################################################################
#	CreateMenus()
#
#	Create the menus for systems that exist at the beginning of the mission.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateMenus():
	App.SortedRegionMenu_SetPauseSorting(1)

	import Systems.Starbase12.Starbase
	pMenu = Systems.Starbase12.Starbase.CreateMenus()
	pMenu.SetMissionName()
	
	import Systems.Vesuvi.Vesuvi
	pMenu = Systems.Vesuvi.Vesuvi.CreateMenus()
	pMenu.SetMissionName(__name__)

	App.SortedRegionMenu_SetPauseSorting(0)


################################################################################
#	CreateSpaceSets()
#
#	Create space sets used in this mission. Load placements into sets.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateSpaceSets():
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()
	pStarbase = Systems.Starbase12.Starbase12.GetSet()
	
	import Systems.Vesuvi.Vesuvi4
	Systems.Vesuvi.Vesuvi4.Initialize()
	pVesuvi4 = Systems.Vesuvi.Vesuvi4.GetSet()

	import Systems.Vesuvi.Vesuvi6
	Systems.Vesuvi.Vesuvi6.Initialize()
	pVesuvi6 = Systems.Vesuvi.Vesuvi6.GetSet()

	# Add our custom placement objects for this mission.
	import Maelstrom.Episode3.E3M2.E3M2_Starbase12_P
	import Maelstrom.Episode3.E3M2.E3M2_Vesuvi4_P
	import Maelstrom.Episode3.E3M2.E3M2_Vesuvi6_P
	Maelstrom.Episode3.E3M2.E3M2_Starbase12_P.LoadPlacements(pStarbase.GetName())
	Maelstrom.Episode3.E3M2.E3M2_Vesuvi4_P.LoadPlacements(pVesuvi4.GetName())
	Maelstrom.Episode3.E3M2.E3M2_Vesuvi6_P.LoadPlacements(pVesuvi6.GetName())

	# Create a temp set.
	import Systems.DeepSpace.DeepSpace
	Systems.DeepSpace.DeepSpace.Initialize()
	pTempSet = Systems.DeepSpace.DeepSpace.GetSet()
	
	# Use Vesuvi 4 placements for temp set.
	Maelstrom.Episode3.E3M2.E3M2_Vesuvi4_P.LoadPlacements(pTempSet.GetName())

	# Make sure the asteroids aren't hailable.
	for i in range(1, 13):
		pDebris = MissionLib.GetShip("Unknown Debris " + str(i), None, TRUE)
		if pDebris:
			pDebris.SetHailable(FALSE)
#		else:
#			kDebugObj.Print("Couldn't find Unknown Debris " + str(i))

################################################################################
#	CreateShips()
#
#	Create ships used in this mission, set their initial AI.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateShips():
	import Systems.Vesuvi.Vesuvi4
	import Systems.Vesuvi.Vesuvi6
	import Systems.Starbase12.Starbase12
	import Systems.DeepSpace.DeepSpace
	pVesuvi4 = Systems.Vesuvi.Vesuvi4.GetSet()
	pVesuvi6 = Systems.Vesuvi.Vesuvi6.GetSet()
	pStarbase = Systems.Starbase12.Starbase12.GetSet()
	pTempSet = Systems.DeepSpace.DeepSpace.GetSet()

	MissionLib.CreatePlayerShip("Sovereign", pVesuvi6, "player", "Player Start")
	loadspacehelper.CreateShip("FedStarbase", pStarbase, "Starbase 12", "Starbase12 Location")
	pNebula = loadspacehelper.CreateShip("Nebula", pStarbase, "USS Prometheus", "Circling Nebula")
	pNebula.ReplaceTexture("data/Models/SharedTextures/FedShips/Prometheus.tga", "ID")
	pBerkeley = loadspacehelper.CreateShip("Nebula", pVesuvi4, "USS Berkeley", "Berkeley Start")
	pBerkeley.ReplaceTexture("data/Models/SharedTextures/FedShips/Berkeley.tga", "ID")
	
	pWarbird1 = loadspacehelper.CreateShip("Warbird", pTempSet, "Chairo", "Warbird 1 Start")
	pWarbird2 = loadspacehelper.CreateShip("Warbird", pTempSet, "T'Awsun", "Warbird 2 Start")

	MissionLib.MakeEnginesInvincible(pWarbird1)
	MissionLib.MakeEnginesInvincible(pWarbird2)

	if pNebula:
		import Maelstrom.Episode3.E3M1.E3M1NebulaAI
		pNebula.SetAI(Maelstrom.Episode3.E3M1.E3M1NebulaAI.CreateAI(pNebula))

################################################################################
#	CommunicateSaffi(pObject, pEvent)
#
#	Handler for Saffi's Communicate button press event.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def CommunicateSaffi(pObject, pEvent):
#	kDebugObj.Print("Saffi Communicating...")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	if not g_bHailedBerkeley:
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2SaffiComm4", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == FIND_CORE):
		if g_bNavPointsCreated and not g_bInNebula:
			iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	
			if (iNum == 1):
				pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2SaffiComm1", None, 0, g_pMissionDatabase)
	
			else:
				pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2SaffiComm5", None, 0, g_pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2SaffiComm6", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == AID_BERKELEY):
		iNum = App.g_kSystemWrapper.GetRandomNumber(2)

		if (iNum == 1):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2SaffiComm2", None, 0, g_pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2SaffiComm7", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == PROBE_DESTROYED):
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2SaffiComm3", None, 0, g_pMissionDatabase)

	else:
		pObject.CallNextHandler(pEvent)
		return

	pAction.Play()

################################################################################
#	CommunicateFelix(pObject, pEvent)
#
#	Handler for Felix's Communicate button press event.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def CommunicateFelix(pObject, pEvent):
#	kDebugObj.Print("Felix Communicating...")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	if (g_iMissionProgress == PROBE_DESTROYED):
		pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E3M2FelixComm1", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == ROMULAN_ENCOUNTER):
		pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E3M2FelixComm2", None, 0, g_pMissionDatabase)

	else:
		pObject.CallNextHandler(pEvent)
		return
			
	pAction.Play()

################################################################################
#	CommunicateKiska(pObject, pEvent)
#
#	Handler for Kiska's Communicate button press event.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def CommunicateKiska(pObject, pEvent):
#	kDebugObj.Print("Kiska Communicating...")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	
	pPlayerSet = MissionLib.GetPlayerSet()
	if pPlayerSet is None:
		pObject.CallNextHandler(pEvent)
		return

	if not g_bHailedBerkeley and (pPlayerSet.GetName() == "Vesuvi4"):
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2KiskaComm3", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == FIND_CORE) and g_bNavPointsCreated:
	
		if not g_bInNebula:
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2KiskaComm4", None, 0, g_pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2KiskaComm2", None, 0, g_pMissionDatabase)

	elif g_iMissionProgress == AID_BERKELEY:
		pcLine = MissionLib.GetRandomLine(["E3M2KiskaComm1", "E3M2KiskaComm5"])
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, pcLine, None, 0, g_pMissionDatabase)

	elif g_bInNebula:
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2KiskaComm2", None, 0, g_pMissionDatabase)

	else:
		pObject.CallNextHandler(pEvent)
		return

	pAction.Play()

################################################################################
#	CommunicateMiguel(pObject, pEvent)
#
#	Handler for Miguel's Communicate button press event.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def CommunicateMiguel(pObject, pEvent):
#	kDebugObj.Print("Miguel Communicating...")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return

	if (g_iMissionProgress == FIND_CORE) and g_bNavPointsCreated:
		iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	
		if (iNum == 1):
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M2MiguelComm1", None, 0, g_pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M2MiguelComm4", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == HAIL_STARFLEET):
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M2MiguelComm5", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == PROBE_DESTROYED):
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M2MiguelComm3", None, 0, g_pMissionDatabase)

	elif g_bInNebula:
		iNum = App.g_kSystemWrapper.GetRandomNumber(2)
		if (iNum == 1):
			pEng = pPlayer.GetImpulseEngineSubsystem()
			if pEng.GetPowerPercentageWanted() < 1.25:
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M2MiguelComm2", None, 0, g_pMissionDatabase)
			else:
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M2MiguelComm4", None, 0, g_pMissionDatabase)
		else:
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M2MiguelComm4", None, 0, g_pMissionDatabase)

	else:
		pObject.CallNextHandler(pEvent)
		return

	pAction.Play()

################################################################################
#	CommunicateBrex(pObject, pEvent)
#
#	Handler for Brex's Communicate button press event.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def CommunicateBrex(pObject, pEvent):
#	kDebugObj.Print("Brex Communicating...")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return

	pShields = pPlayer.GetShields()

	if (g_iMissionProgress == FIND_CORE) and g_bHailedBerkeley and pShields:
		if g_bInNebula and pShields.IsOn():
			pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E3M2BrexComm1", None, 0, g_pMissionDatabase)
		else:
			pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E3M2BrexComm2", None, 0, g_pMissionDatabase)

	elif g_iMissionProgress == AID_BERKELEY:
		pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E3M2BrexComm3", None, 0, g_pMissionDatabase)

	elif g_iMissionProgress == HAIL_STARFLEET:
		pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E3M2BrexComm5", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == ROMULAN_ENCOUNTER) and not g_bInNebula:
		pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E3M2BrexComm4", None, 0, g_pMissionDatabase)

	else:
		pObject.CallNextHandler(pEvent)
		return

	pAction.Play()

################################################################################
#	CommunicateData(pObject, pEvent)
#
#	Handler for Data's Communicate button press event.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def CommunicateData(pObject, pEvent):
#	kDebugObj.Print("Data Communicating...")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	if (g_iMissionProgress == FIND_CORE) and g_bNavPointsCreated:
		if g_iAsteroidsScanned == 0:
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2DataCommunicate", None, 0, g_pMissionDatabase)
		elif (g_iAsteroidsScanned > 0) and not g_bInNebula:
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2Prod1", None, 0, g_pMissionDatabase)
		else:
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2DataComm1", None, 0, g_pMissionDatabase)

	elif g_iMissionProgress == AID_BERKELEY:
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2DataComm3", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == PROBE_DESTROYED):
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2DataComm2", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == ROMULAN_ENCOUNTER) and not g_bInNebula:
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2DataComm4", None, 0, g_pMissionDatabase)

	elif (g_iMissionProgress == MISSION_WON) or (g_iMissionProgress == MET_ROMULANS):
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2DataComm5", None, 0, g_pMissionDatabase)

	else:
		pObject.CallNextHandler(pEvent)
		return

	pAction.Play()

###############################################################################
#	SetAffiliations(pMission)
#	
#	Creates lists of friendlies and enemies
#	
#	Args:	pMission	- the mission object
#	
#	Return:	none
###############################################################################
def SetAffiliations(pMission):
	"Sets up who is an enemy and who isn't"
	g_pFriendlies.AddName("player")
	g_pFriendlies.AddName("USS Berkeley")
	g_pFriendlies.AddName("USS Prometheus")
	g_pFriendlies.AddName("USS Nightingale")
	g_pFriendlies.AddName("Starbase 12")
	g_pFriendlies.AddName("GekiStation")
	g_pFriendlies.AddName("GekiSatellite1")
	g_pFriendlies.AddName("GekiSatellite2")
	g_pFriendlies.AddName("Facility")
	g_pFriendlies.AddName("Starbase 12")

	g_pEnemies.AddName("Chairo")
	g_pEnemies.AddName("T'Awsun")

###############################################################################
#	CreateNavProximity()
#
# 	Create proximity checks for the Nav points.
#
#	Args:	None
#
#	Return:	None
###############################################################################
def CreateNavProximity():
	pMission = MissionLib.GetMission()

	pCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", NAV_PROXIMITY_DIST, "Nav 1", "player")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "Nav1Active", pCondition)
	pCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", NAV_PROXIMITY_DIST, "Nav 2", "player")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "Nav2Active", pCondition)
	pCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", NAV_PROXIMITY_DIST, "Nav 3", "player")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "Nav3Active", pCondition)
	pCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", NAV_PROXIMITY_DIST, "Nav 4", "player")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "Nav4Active", pCondition)

###############################################################################
#	RemoveNavProximity()
#
# 	Remove proximity checks for the Nav points.
#
#	Args:	None
#
#	Return:	None
###############################################################################
def RemoveNavProximity():
	MissionLib.StopCallingFunctionWhenConditionChanges(__name__, "Nav1Active")
	MissionLib.StopCallingFunctionWhenConditionChanges(__name__, "Nav2Active")
	MissionLib.StopCallingFunctionWhenConditionChanges(__name__, "Nav3Active")
	MissionLib.StopCallingFunctionWhenConditionChanges(__name__, "Nav4Active")

################################################################################
#	SetupEventHandlers(pMission)
#
#	Set up any event handlers for this mission.
#
#	Args:	pMission - Current mission.
#
#	Return:	None
################################################################################
def SetupEventHandlers(pMission):
	# Add Communicate Handlers
	Bridge.BridgeUtils.SetupCommunicateHandlers()

	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ + ".EnterSet")

	# Ship exploding event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ShipExploding")

	# Ship destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ + ".ShipDestroyed")

	# Player destroyed event.
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_OBJECT_EXPLODING, __name__ + "PlayerDestroyed")

	# Check for environmental damage on the player.
	if pPlayer:
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, __name__ + ".CoreDamage")
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_ENTERED_NEBULA, __name__ + ".InNebula")
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_EXITED_NEBULA, __name__ + ".OutNebula")

	# Instance handler for Saffi's Contact Starfleet button
	pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pMenu = pXO.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".CallStarfleet")

	# Instance handler for Miguel's Scan Area button
	pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pScience.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Instance handler for Kiska's Hail button
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pHelm.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

################################################################################
#	CallStarfleet(pObject, pEvent)
#
#	Handle player contacting Admiral Liu. Called from button click event.
#
#	Args:	pObject, 
#			pEvent
#
#	Return:	None
################################################################################
def CallStarfleet(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	pBridge = App.g_kSetManager.GetSet("bridge")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pSci = App.CharacterClass_GetObject(pBridge, "Science")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pSeq = MissionLib.ContactStarfleet()
	if not g_bHailedBerkeley:
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M2L039", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSeq.AppendAction(pAction)
		MissionLib.QueueActionToPlay(pSeq)
	elif g_iMissionProgress == FIND_CORE:
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M2Prod3", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSeq.AppendAction(pAction)
		MissionLib.QueueActionToPlay(pSeq)
	elif g_iMissionProgress == AID_BERKELEY:
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3L003", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSeq.AppendAction(pAction)
		MissionLib.QueueActionToPlay(pSeq)
	elif g_iMissionProgress == HAIL_STARFLEET:
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", FIND_PROBE))
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3ThankYou", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3ThankYou2", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3ThankYou3", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3L013", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3L014", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3L015", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2Trail", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "AddNavAlpha")
		pSeq.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "CreateNightingale")
		pSeq.AppendAction(pAction, 10)
		MissionLib.QueueActionToPlay(pSeq)
	elif g_iMissionProgress == MET_ROMULANS:
		global g_iMissionProgress
		g_iMissionProgress = MISSION_WON

		MissionLib.RemoveGoal("E3CallStarfleetGoal")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M2Disappointed", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3L044", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M3L045", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		pAction = App.TGScriptAction_Create(__name__, "MissionWin")
		pSeq.AppendAction (pAction)
		MissionLib.QueueActionToPlay(pSeq)

	else:
		pSeq.Skip()
		pObject.CallNextHandler(pEvent)
		return

###############################################################################
#	AddNavDustCloud(pAction)
#	
#	Create Nav point to Dust Cloud.
#	
#	Args:	pAction - The script action.
#	
#	Return:	0
###############################################################################
def AddNavDustCloud(pAction):
	pSet = App.g_kSetManager.GetSet("Vesuvi4")
	pObj = App.PlacementObject_GetObject(pSet, "Dust Cloud")
	if pObj:
		pObj.SetNavPoint(TRUE)

	return 0

###############################################################################
#	AddNavAlpha(pAction)
#	
#	Create Nav Alpha and setup proximity check.
#	Create the probe the player will encounter and update mission goals.
#	
#	Args:	pAction - The script action.
#	
#	Return:	0
###############################################################################
def AddNavAlpha(pAction):
	pSet = App.g_kSetManager.GetSet("Vesuvi4")
	pObj = App.PlacementObject_GetObject(pSet, "Nav Alpha")
	if pObj:
		pObj.SetNavPoint(TRUE)

	# Create the probe
	pProbe = loadspacehelper.CreateShip("KessokMine", pSet, "Unknown Probe", "Kessok Probe")
	if pProbe:
		pProbe.SetSplashDamage(1500.0, pProbe.GetRadius() * 20.0)
		pProbe.AddPythonFuncHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, "MissionLib.IgnoreEvent")
		pProbe.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
		pProbe.AddPythonFuncHandlerForInstance(App.ET_SENSORS_SHIP_IDENTIFIED, __name__ + ".ProbeFindDialog")
		pProbe.SetDeathScript (__name__ + ".ProbeExploding")


	MissionLib.RemoveGoal("E3CallForRescueGoal")
	MissionLib.AddGoal("E3FollowNavAlphaGoal")

	return 0


#
#	ProbeExploding() - Makes a huge explosion when the Probe is destroyed
#
def ProbeExploding(TGObject):
	import Effects

	pObject = App.DamageableObject_Cast(TGObject)

	if (pObject == None):
#		debug("Unexpected NULL Ptr")
		return

	# we need a set to put it in
	# this should never be null, but you never know
	pSet = pObject.GetContainingSet()
	if (pSet == None):
#		debug("Unexpected NULL Set Ptr")
		return

	sSetName = pSet.GetName()

	# death only takes 2 seconds
	pObject.SetLifeTime (2.0)
	
	pSequence = App.TGSequence_Create()

	pEmitPos = pObject.GetRandomPointOnModel()

	pSparks = Effects.CreateDebrisSparks(1.0, pEmitPos, 0, pSet.GetEffectRoot())
	pSequence.AppendAction(pSparks)

	pExplosion = Effects.CreateDebrisExplosion(pObject.GetRadius() * 20.0, 1.5, pEmitPos, 1, pSet.GetEffectRoot())
	pSequence.AppendAction(pExplosion)

	pSound = App.TGSoundAction_Create("Big Death Explosion " + str(App.g_kSystemWrapper.GetRandomNumber(8)+1), 0, sSetName)
	pSound.SetNode(pObject.GetNode())
	pSequence.AppendAction(pSound)
	
	pSequence.Play()


###############################################################################
#	ProxBerkeley(pAction)
#	
#	Create proximity to Nav Berkeley.
#	
#	Args:	pAction - The script action.
#	
#	Return:	0
###############################################################################
def ProxBerkeley(pAction):
	# Create proximity to Nav Berkeley.
	pPlayer = MissionLib.GetPlayer()
	pVesuvi4 = App.g_kSetManager.GetSet("Vesuvi4")
	pNavBerkeley = App.PlacementObject_GetObject(pVesuvi4, "Nav Berkeley")
	global g_pProxBerkeley
	g_pProxBerkeley = MissionLib.ProximityCheck(pNavBerkeley, NAV_BERKELEY_PROX, 
								[pPlayer], __name__+ ".BerkeleyHelp", pVesuvi4)

	pBerkeley = MissionLib.GetShip("USS Berkeley", pVesuvi4)
	if pBerkeley:
		pBerkeley.AddPythonFuncHandlerForInstance(App.ET_TARGET_LIST_OBJECT_ADDED, 
													__name__ + ".DetectBerkeley")

	return 0

################################################################################
#	DetectBerkeley(pObject, pEvent)
#
#	Handle player detecting the Berkeley on sensors on route to Nav Berkeley.
#
#	Args:	pObject, pEvent
#
#	Return:	None
################################################################################
def DetectBerkeley(pObject, pEvent):
	pVesuvi4 = App.g_kSetManager.GetSet("Vesuvi4")
	pBerkeley = MissionLib.GetShip("USS Berkeley", pVesuvi4)

	MissionLib.SetTarget(None, "USS Berkeley")

	pBerkeley.RemoveHandlerForInstance(App.ET_TARGET_LIST_OBJECT_ADDED, __name__ + ".DetectBerkeley")

	pObject.CallNextHandler(pEvent)


###############################################################################
#	CreateNightingale(pAction)
#	
#	Create the Nightingale and give it AI to rescue the Berkeley.
#	
#	Args:	pAction - The script action.
#	
#	Return:	0
###############################################################################
def CreateNightingale(pAction):
	pVesuvi4 = App.g_kSetManager.GetSet("Vesuvi4")
	pNightingale = loadspacehelper.CreateShip("Nebula", pVesuvi4, "USS Nightingale", "Nightingale Arrive", TRUE)
	
	if pNightingale:
		import Maelstrom.Episode3.E3M2.TowAway
		pNightingale.SetAI(Maelstrom.Episode3.E3M2.TowAway.CreateAI(pNightingale, "USS Berkeley"))

	pBerkeley = App.ShipClass_GetObject(pVesuvi4, "USS Berkeley")
	if pBerkeley:
		pBerkeley.AddPythonFuncHandlerForInstance(App.ET_EXITED_SET, __name__ + ".BerkeleyExit")

	return 0


################################################################################
#	BerkeleyExit(pObject, pEvent)
#
#	Berkeley exits the set, so remove Nav Berkeley
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def BerkeleyExit(pObject, pEvent):
	if g_bMissionTerminated:
		return

	MissionLib.RemoveNavPoints("Vesuvi4", "Nav Berkeley")


################################################################################
#	WarpHandler(pObject, pEvent)
#
#	Called when the "Warp" button in Kiska's menu is clicked.
#	Prevent player from warping while in dust cloud or while waiting for
#	Federation releif ship to arrive and help the Berkeley.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def WarpHandler(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()
	
	import Bridge.BridgeUtils
	pWarp = Bridge.BridgeUtils.GetWarpButton()
	
	if not (pWarp):
		return
	
	if g_bInNebula:
		pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
		pAction = Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E3M2NoWarpInNebula", g_pMissionDatabase)

	# If player must contact Starfleet before proceeding.
	elif g_iMissionProgress == HAIL_STARFLEET:
		pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
		pAction = Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E3M2NoWarpCallStarfleet", g_pMissionDatabase)

	# If player is trying to leave combat with the Romulans
	elif (g_iMissionProgress == ROMULAN_ENCOUNTER) and (pWarp.GetDestination() == "Systems.Starbase12.Starbase12"):
		TauntPlayer()
		pObject.CallNextHandler(pEvent)
		return

	# If not handled:
	# Remove entry/exit nebula handlers. We don't want the messages when the player warps.
	else:
		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			pPlayer.RemoveHandlerForInstance(App.ET_ENTERED_NEBULA, __name__ + ".InNebula")
			pPlayer.RemoveHandlerForInstance(App.ET_EXITED_NEBULA, __name__ + ".OutNebula")
	
			pObject.CallNextHandler(pEvent)

			return
	
	pAction.Play()

###############################################################################
#	CreateNavPoints(pAction)
#
# 	Create Nav points which are entered by Commander Data.
#
#	Args:	pAction, the script action.
#
#	Return:	none
###############################################################################
def CreateNavPoints(pAction):
	global g_bNavPointsCreated
	g_bNavPointsCreated = TRUE

	MissionLib.AddNavPoints("Vesuvi4", "Nav 1", "Nav 2", "Nav 3", "Nav 4", "Nav Berkeley")
	CreateNavProximity()

	MissionLib.AddGoal ("E3InvestigateDustCloudGoal")

	return 0

################################################################################
#	CreateData(None)
#
#	Create Commander Data in the turbolift on the bridge.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateData():
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	import Bridge.Characters.Data
	pData = App.CharacterClass_GetObject(pBridgeSet, "Data")
	if not (pData):
		pData = Bridge.Characters.Data.CreateCharacter(pBridgeSet)
		Bridge.Characters.Data.ConfigureForSovereign(pData)
	pData.SetHidden(1)
	pData.SetLocation("EBL1M")

	# Setup event handler for communicate button.
	pMenu = pData.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateData")

################################################################################
#	BerkeleyHelp(pObject, pEvent)
#
#	If player made it in time, play dialogue from Berkeley.
#	Otherwise inform player that they are too late and end game.
#	Called from a proximity check to Nav Berkeley.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def BerkeleyHelp(pObject, pEvent):
	if g_iMissionProgress != AID_BERKELEY:
		return

	# Temporarily null the flag to avoid inconsistencies with ContactStarfleet, Report, etc
	global g_iMissionProgress
	g_iMissionProgress = -1

	global g_bHelpedBerkeley
	g_bHelpedBerkeley = TRUE

	pVesuvi4 = App.g_kSetManager.GetSet("Vesuvi4")
	pBerkeley = App.ShipClass_GetObject(pVesuvi4, "USS Berkeley")

	if pBerkeley:
		MissionLib.ViewscreenWatchObject(pBerkeley)

	# Remove the Kessok from the set
	pVesuvi4.DeleteObjectFromSet("Strange Ship")

	pHBridgeSet = App.g_kSetManager.GetSet("HBridgeSet")
	pHaley = App.CharacterClass_GetObject (pHBridgeSet, "Haley")
	pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", HAIL_STARFLEET))
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", None, 0, g_pGeneralDatabase)
	pSeq.AppendAction(pAction)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E3ReturnToBerkeleyGoal"))
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "HBridgeSet", "Haley", 1)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M3L007", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M3L009", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M3L010", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M3L008", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction(pAction)
	pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2LightlyArmed", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2FrightenAway", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E3M2WhyNot", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2DrawAway", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2ReadyHail", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3CallForRescueGoal"))
	MissionLib.QueueActionToPlay(pSeq)
	
	# Remove proximity check
	global g_pProxBerkeley
	if g_pProxBerkeley:
		g_pProxBerkeley.RemoveAndDelete()
		g_pProxBerkeley = None


###############################################################################
#	InNebula(pObject, pEvent)
#
# 	Called from event when player enters the nebula.
#
#	Args:	pObject,
#			pEvent
#
#	Return:	none
###############################################################################
def InNebula(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if g_bInNebula:
		# We're already in the nebula.  Don't play going in message.
		pObject.CallNextHandler(pEvent)
		return

	global g_bInNebula
	g_bInNebula = TRUE

	Bridge.BridgeUtils.DisableHailMenu()

	# Can't warp while in nebula.
	Bridge.BridgeUtils.DisableWarpButton()

	pBridge = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pHelm = App.CharacterClass_GetObject (pBridge, "Helm")

	# Notify the player we're inside.
	pSeq = App.TGSequence_Create ()
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M2L041", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	if g_iMissionProgress == ROMULAN_ENCOUNTER:
		if not g_bTerrikTalksTactics:
			global g_bTerrikTalksTactics
			g_bTerrikTalksTactics = TRUE

			# Try to append Terrik's dialogue to sequence.
			TerrikTalkTactics(None, None, pSeq)

	MissionLib.QueueActionToPlay(pSeq)

	# Player is in nebula.  Remove the prod move on timer if it exists.
	global g_iProdReEnterTimerID
	if g_iProdReEnterTimerID != App.NULL_ID:
		App.g_kTimerManager.DeleteTimer(g_iProdReEnterTimerID)
		g_iProdReEnterTimerID = App.NULL_ID

	pObject.CallNextHandler(pEvent)


#
# ShieldProd() - Saffi prods you to raise shields if they are down
#
def ShieldProd(pAction = None):
	# Warn player that radiation is damaging the ship
	if not g_bRadiationWarning:
		global g_bRadiationWarning
		g_bRadiationWarning = TRUE

		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			pShields = pPlayer.GetShields()
			if pShields:
				global g_iShieldProdCount
				g_iShieldProdCount = g_iShieldProdCount + 1
	
				pBridge = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	
				# if g_iShieldProdCount is an even number
				if not pShields.IsOn() and not (g_iShieldProdCount % 2) == 0:
					pXO = App.CharacterClass_GetObject (pBridge, "XO")
					pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2ProdRaiseShields", "Captain", 1, g_pMissionDatabase)
					MissionLib.QueueActionToPlay(pAction)

				else:
					pEng = App.CharacterClass_GetObject (pBridge, "Engineer")
					pAction = App.CharacterAction_Create(pEng, App.CharacterAction.AT_SAY_LINE, "E3M2L027", "Captain", 1, g_pMissionDatabase)
					MissionLib.QueueActionToPlay(pAction)

		# Start a timer to reset the radiation warning
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_RADIATION_WARN, __name__ + ".ResetRadiationWarning", fStartTime + 20, 0, 0)

	return 0


###############################################################################
#	TerrikTalkTactics(pObject, pEvent, pSeq = None)
#
#	Play Terrik's dialogue admiring player's tactics.
#	Attempt to add dialogue actions to sequence if one was passed in.
#	Otherwise create a sequence and play it.
#
#	Args:	pObject,
#			pEvent
#			pSeq, the sequence we want actions added to.
#
#	Return:	none
###############################################################################
def TerrikTalkTactics(pObject, pEvent, pSeq = None):
	if not g_bTerrikOutroPlayed:
		if not MissionLib.g_bViewscreenOn:
			pTBridgeSet = App.g_kSetManager.GetSet("TBridgeSet")
			pTerrik = App.CharacterClass_GetObject(pTBridgeSet, "Terrik")
			pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	
			if not pSeq:
				pSeq = MissionLib.NewDialogueSequence()
			
			pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2MessageFromRomulans", None, 0, g_pMissionDatabase))
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Terrik"))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pTerrik, "E3M3L038", g_pMissionDatabase))
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
			MissionLib.QueueActionToPlay(pSeq)
		else:
			# Viewscreen used, try again in a few..
			fStartTime = App.g_kUtopiaModule.GetGameTime()
			pTimer = MissionLib.CreateTimer(ET_VIEWSCREEN_RETRY, __name__ + ".TerrikTalkTactics", 
									fStartTime + 5, 0, 0)


###############################################################################
#	OutNebula(pObject, pEvent)
#
#	Set flag, enable warp button, make Berkeley targetable, and notify player.
#	Also creates a prod timer if player is still looking for core.
# 	Called from event when player exits the nebula.
#
#	Args:	pObject,
#			pEvent
#
#	Return:	none
###############################################################################
def OutNebula(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if not g_bInNebula:
		# We're not in the nebula, so we don't play the going out message.
		pObject.CallNextHandler(pEvent)
		return

	global g_bInNebula
	g_bInNebula = FALSE

	Bridge.BridgeUtils.EnableHailMenu()
	Bridge.BridgeUtils.RestoreWarpButton()

	# Allow the radiation warning again.
	global g_iShieldProdCount
	g_iShieldProdCount	= 0
	
	# Notify player we're out of nebula.
	pBridge = App.g_kSetManager.GetSet("bridge")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")

	pSeq = App.TGSequence_Create ()
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M2L042", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	if g_bHailedBerkeley:
		# Create prod timer if we're still looking for core.
		if g_iMissionProgress == FIND_CORE:
			pAction = App.TGScriptAction_Create(__name__, "AddProdReEnterTimer")
			pSeq.AppendAction(pAction)

	pSeq.Play()

	pObject.CallNextHandler(pEvent)

################################################################################
#	AddProdReEnterTimer(pAction)
#
#	Create timer to prod player into continuing with mission when they exit
#	the nebula without having found the core. 
#
#	Args:	pObject
#			pEvent
#
#	Return:	0
################################################################################
def AddProdReEnterTimer(pAction):
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_REENTER_EVENT, __name__ + ".MoveOn", fStartTime + 60.0, 0, 0)

	# Store off the timer ID so if the player warps we can get rid of it.
	global g_iProdReEnterTimerID
	g_iProdReEnterTimerID = pTimer.GetObjID ()

	return 0

################################################################################
#	MoveOn(pObject, pEvent)
#
#	Play dialogue sequence to prod the player to continue with mission.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def MoveOn(pObject, pEvent):
	global g_iProdReEnterTimerID
	g_iProdReEnterTimerID = App.NULL_ID

	if g_iMissionProgress == FIND_CORE:

		pBridge = App.g_kSetManager.GetSet("bridge")
		pData = App.CharacterClass_GetObject(pBridge, "Data")
	
		pSeq = MissionLib.NewDialogueSequence()
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L033", "Captain", 1, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	CoreDamage(pObject, pEvent)
#
#	Play line warning the player of damage from the nebula.
#	Called from event, when player's ship takes environment damage.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def CoreDamage(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	#Take no environment damage in the Stellar Core cutscene 
	if (g_iAsteroidsScanned == g_iNumToScan) and (g_iMissionProgress == FIND_CORE):
		return
 
	pShip = MissionLib.GetPlayer()
	if pShip is None:
		pObject.CallNextHandler(pEvent)
		return

	pShields = pShip.GetShields()
	if pShields is None:
		pObject.CallNextHandler(pEvent)
		return

	if not pShields.IsOn() or (pShields.GetSingleShieldPercentage(App.ShieldClass.NUM_SHIELDS) < 0.05):
		ShieldProd()

	pObject.CallNextHandler(pEvent)


#
#   ResetRadiationWarning()
#
def ResetRadiationWarning(pObject, pEvent):
	global g_bRadiationWarning
	g_bRadiationWarning = FALSE


################################################################################
#	ProbeFindDialog(pObject, pEvent)
#
#	Play sequence when player finds the alien probe.
#	Called from event sent to Probe when player sees it on sensors.
#
#	Args:	pObject,
#			pEvent
#
#	Return:	None
################################################################################
def ProbeFindDialog(pObject, pEvent):
	# Target the probe
	pPlayer = MissionLib.GetPlayer()
	if pPlayer and not g_bProbeFound:
		global g_bProbeFound
		g_bProbeFound = TRUE
		
		pPlayer.SetTarget("Unknown Probe")

		pTact = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
		pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")

		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, 
												"E3M3L021", "Captain", 1, g_pMissionDatabase))
		pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, 
												"E3M3L021a", "Captain", 1, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetupProbeProx"))
		MissionLib.QueueActionToPlay(pSeq)

	pObject.CallNextHandler(pEvent)

################################################################################
#	SetupProbeProx(pAction)
#
#	Setup proximity to probe in case player flies away.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def SetupProbeProx(pAction):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pProbe = MissionLib.GetShip("Unknown Probe")
		if pProbe:
			iDist = MissionLib.GetDistance(pPlayer, pProbe)
			pSet = pPlayer.GetContainingSet()
			global g_pProxProbe
			g_pProxProbe = MissionLib.ProximityCheck(pProbe, iDist + PLAYER_PROBE_DIST, [pPlayer], 
												__name__+ ".ProbeProxTriggered", pSet)
	return 0

################################################################################
#	ProbeProxTriggered(pObject, pEvent)
#
#	Handle player flying away from Probe.
#
#	Args:	pObject, pEvent
#
#	Return:	None
################################################################################
def ProbeProxTriggered(pObject, pEvent):
	if g_iMissionProgress != FIND_PROBE:
		return

	pProbe = MissionLib.GetShip("Unknown Probe")
	if pProbe and not pProbe.IsDead() and not pProbe.IsDying() and not g_bProbeTriggered:
		global g_bProbeTriggered
		g_bProbeTriggered = TRUE

		# Remove proximity check.
		if g_pProxProbe:
			g_pProxProbe.RemoveAndDelete()
			global g_pProxProbe
			g_pProxProbe = None

		pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, 
												"E3M3L023", "Captain", 0, g_pMissionDatabase))
		pPlayer = MissionLib.GetPlayer()
		# Play warning message to back away if player is within 25km of probe.
		if MissionLib.GetDistance(pPlayer, pProbe) < PROBE_WARN_DIST:
			pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
			pSeq.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M3L024", "Captain", 1, g_pMissionDatabase))

		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SelfDestructProbe"))
		pSeq.Play()
		
################################################################################
#	ScanProbe()
#
#	Play dialogue when scanning the probe.
#
#	Args:	None
#
#	Return:	bool, TRUE if scanned, FALSE if not.
################################################################################
def ScanProbe():
	pSci = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")

	pProbe = MissionLib.GetShip("Unknown Probe")
	if pProbe and not pProbe.IsDead() and not pProbe.IsDying() and not g_bProbeTriggered:
		global g_bProbeTriggered
		g_bProbeTriggered = TRUE

		pSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
		if pSeq is None:
			return TRUE

		# Remove proximity check.
		if g_pProxProbe:
			g_pProxProbe.RemoveAndDelete()
			global g_pProxProbe
			g_pProxProbe = None

#		pSeq.AppendAction(App.CharacterAction_Create(pSci, App.CharacterAction.AT_SAY_LINE, 
#												"E3M3L022", "Captain", 0, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ProbeCheck"))

#		pPlayer = MissionLib.GetPlayer()
#		# Play warning message to back away if player is within 25km of probe.
#		if MissionLib.GetDistance(pPlayer, pProbe) < PROBE_WARN_DIST:
#			pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
#			pSeq.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M3L024", "Captain", 1, g_pMissionDatabase))

		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SelfDestructProbe"), 6)
		pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
		MissionLib.QueueActionToPlay(pSeq)
		return TRUE

	return FALSE

################################################################################
#	ProbeCheck(pAction)
#
#	Check the status of the probe before Data's line about it self-destructing
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def ProbeCheck(pAction):
	pProbe = MissionLib.GetShip("Unknown Probe")
	if pProbe and not pProbe.IsDead() and not pProbe.IsDying():
		pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M3L023", "Captain", 0, g_pMissionDatabase)
		pAction.Play()

	return 0

################################################################################
#	SelfDestructProbe(pAction)
#
#	Set probe's AI to self-destruct. Called from ProbeFindDialog().
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def SelfDestructProbe(pAction):
	pProbe = MissionLib.GetShip("Unknown Probe")
	if pProbe and not pProbe.IsDead() and not pProbe.IsDying():

		import Maelstrom.Episode3.E3M2.ProbeDestructAI
		pProbe.SetAI(Maelstrom.Episode3.E3M2.ProbeDestructAI.CreateAI(pProbe))

	return 0

################################################################################
#	ProbeDestroyed()
#
#	Play dialogue sequence when probe is destroyed.
#
#	Args:	None
#
#	Return:	None
################################################################################
def ProbeDestroyed():
	SetMissionProgress(None, PROBE_DESTROYED)

	pSci = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.CharacterAction_Create(pSci, App.CharacterAction.AT_SAY_LINE, "E3M3L025", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M3L026", "Captain", 0, g_pMissionDatabase), 2)
	pSeq.AppendAction(App.CharacterAction_Create(pSci, App.CharacterAction.AT_SAY_LINE, "E3M3L027", None, 1, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M3L028", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M3L029", None, 1, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2NextNav", None, 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "EnableBetaNav"))
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 5/E5M2.tgl")
	pSeq.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E5M2NavPoint", "Captain", 1, pDatabase))
	App.g_kLocalizationManager.Unload(pDatabase)
	MissionLib.QueueActionToPlay(pSeq)

################################################################################
#	EnableBetaNav(pAction)
#
#	Create Nav Beta, setup proximity check and setup derelict Warbrid.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def EnableBetaNav(pAction):
	pSet = App.g_kSetManager.GetSet("Vesuvi4")

	# Remove nav alpha
	pObj = App.PlacementObject_GetObject(pSet, "Nav Alpha")
	if pObj:
		pObj.SetNavPoint(FALSE)

	# Create nav beta.
	pObj = App.PlacementObject_GetObject(pSet, "Nav Beta")
	if pObj:
		pObj.SetNavPoint(TRUE)

	MissionLib.RemoveGoal("E3FollowNavAlphaGoal")
	MissionLib.AddGoal("E3FollowNavBetaGoal")

	pPlayer = MissionLib.GetPlayer()

	global g_pProxBeta
	g_pProxBeta = MissionLib.ProximityCheck(pObj, -114, [pPlayer], __name__+ ".FindDerelict", pSet)

	# Create derelict warbird
	pWarbird = loadspacehelper.CreateShip("Warbird", pSet, "Derelict Warbird", "Dead Warbird Start")
	if pWarbird:
		pWarbird.AddPythonFuncHandlerForInstance(App.ET_TARGET_LIST_OBJECT_ADDED, __name__ + ".FindDerelict")
		pWarbird.SetInvincible(TRUE)
		pWarbird.SetTargetable(0)
		pWarbird.SetHailable(0)
		pWarbird.SetDestroyBrokenSystems(0)		# make it so that he doesn't get blown up by being broken
		MissionLib.SetupWeaponHitHandlers(["Derelict Warbird"])

		# Damage the warbird.
		import DamageWarbird
		DamageWarbird.AddDamage(pWarbird)
		vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
		vVelocity.Scale(10.0 * App.PI / 180.0)	# Scale it to 10 degrees/second (converted to radians)
		pWarbird.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
		pWarbird.SetAlertLevel(App.ShipClass.GREEN_ALERT)

		DamageShip(pWarbird, 0, 0.5)
		pSystem = pWarbird.GetHull()
		if pSystem:
			pSystem.SetConditionPercentage(0.01)

	return 0

################################################################################
#	TerrikDialogue(pAction)
#
#	Play dialogue as Terrik warps in.
#	Called from EnterSet event.
#
#	Args:	None
#
#	Return:	None
################################################################################
def TerrikDialogue(pAction):
	if not g_bTerrikIntroPlayed:
		global g_bTerrikIntroPlayed
		g_bTerrikIntroPlayed = TRUE

		pTBridgeSet = App.g_kSetManager.GetSet("TBridgeSet")
		pTerrik = App.CharacterClass_GetObject (pTBridgeSet, "Terrik")
		pBridge = App.g_kSetManager.GetSet("bridge")
		pXO = App.CharacterClass_GetObject(pBridge, "XO")
		pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
		pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

		pPlayer = MissionLib.GetPlayer()
		pChairo = App.ShipClass_GetObject(App.SetClass_GetNull(), "Chairo")
		pTawsun = App.ShipClass_GetObject(App.SetClass_GetNull(), "T'Awsun")
		MissionLib.OrientObjectTowardObject(pChairo, pPlayer)
		MissionLib.OrientObjectTowardObject(pTawsun, pPlayer)

		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
		pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
		pSeq.AppendAction(pAction)
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StopShip"))
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSeq.AppendAction(pAction)
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "WatchWarbirds"))
		pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M3L031", "Captain", 1, g_pMissionDatabase)
		pSeq.AppendAction (pAction)

		if pPlayer:
			if (pPlayer.GetAlertLevel() != pPlayer.RED_ALERT):
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RedAlert"))

		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
		pSeq.AppendAction(pAction, 2)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
		pSeq.AppendAction(pAction)
		pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2MessageFromRomulans", None, 0, g_pMissionDatabase))
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Terrik")
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E3M3L033", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E3M3L034", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		if not g_bDerelictAttacked:
			pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
			pSeq.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M3L035", None, 0, g_pMissionDatabase)
			pSeq.AppendAction (pAction)
			pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
			pSeq.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E3M3L036", None, 0, g_pMissionDatabase)
			pSeq.AppendAction (pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSeq.AppendAction (pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
		pSeq.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pSeq.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "TerrikAttack")
		pSeq.AppendAction (pAction)
		
		MissionLib.QueueActionToPlay(pSeq)

		return 0

###############################################################################
#	WatchWarbirds(pAction)
#
# 	Watch the Warbirds warping in on viewscreen.
#
#	Args:	pAction, the script action.
#
#	Return:	0
###############################################################################
def WatchWarbirds(pAction):
	pChairo = App.ShipClass_GetObject(App.SetClass_GetNull(), "Chairo")
	MissionLib.ViewscreenWatchObject(pChairo)

	return 0

###############################################################################
#	TerrikAttack(pAction)
#
# 	Have the Romulan Warbirds attack the player. Called from TerrikDialogue()
#
#	Args:	pAction, the script action.
#
#	Return:	0
###############################################################################
def TerrikAttack(pAction):
	# Increment mission progress
	global g_iMissionProgress
	g_iMissionProgress = ROMULAN_ENCOUNTER

	pWarbird1 = App.ShipClass_GetObject(App.SetClass_GetNull(), "Chairo")
	pWarbird2 = App.ShipClass_GetObject(App.SetClass_GetNull(), "T'Awsun")

	import Maelstrom.Episode3.E3M2.BasicWarbirdAI

	# Make warbirds invincible

	if pWarbird1:
		pWarbird1.SetInvincible(TRUE)

		pWarp = pWarbird1.GetWarpEngineSubsystem()
		pImpulse = pWarbird1.GetImpulseEngineSubsystem()
		if (pWarp and pImpulse):
			MissionLib.MakeSubsystemsInvincible(pImpulse, pWarp)

		pWarbird1.SetAI(Maelstrom.Episode3.E3M2.BasicWarbirdAI.CreateAI(pWarbird1))

	if pWarbird2:
		pWarbird2.SetInvincible(TRUE)

		pWarp = pWarbird2.GetWarpEngineSubsystem()
		pImpulse = pWarbird2.GetImpulseEngineSubsystem()
		if (pWarp and pImpulse):
			MissionLib.MakeSubsystemsInvincible(pImpulse, pWarp)

		pWarbird2.SetAI(Maelstrom.Episode3.E3M2.BasicWarbirdAI.CreateAI(pWarbird2))

	MissionLib.AddGoal("E3DriveOffRomulansGoal")

	# Create a Timer to suggest hiding in the dust cloud
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SUGGEST_HIDE, __name__ + ".SuggestHideInDustCloud", fStartTime + 30, 0, 0)

	return 0

###############################################################################
#	TauntPlayer()
#
# 	Event handler for player running away from Romulans.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
###############################################################################
def TauntPlayer():
	if g_bMissionTerminated:
		return

	if g_bTerrikOutroPlayed:
		return

	if g_iMissionProgress == MISSION_WON:
		return

	pTBridgeSet = App.g_kSetManager.GetSet("TBridgeSet")
	pTerrik = App.CharacterClass_GetObject(pTBridgeSet, "Terrik")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg2", None, 0, g_pGeneralDatabase), 4)
	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, g_pGeneralDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Terrik"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pTerrik, "E3M3L040", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	MissionLib.QueueActionToPlay(pSeq)


###############################################################################
#	SuggestHideInDustCloud()
#
# 	Play dialogue suggesting to the player to hide in dust cloud.
#	Called from condition created above.
#
#	Return:	None
###############################################################################
def SuggestHideInDustCloud(pObject, pEvent):
	if g_bMissionTerminated:
		return

	if not g_bInNebula:
		# If any enemies around.
		if MissionLib.IsInSameSet("Chairo") or MissionLib.IsInSameSet("T'Awsun"):
				pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")
				pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
				pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
				pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
				pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

				pSeq = MissionLib.NewDialogueSequence()

				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E3M2Brunt", 
									g_pMissionDatabase))
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E3M3L037", 
									g_pMissionDatabase))
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E3M2Difficult", 
									g_pMissionDatabase))
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E3M2WhatChoice", 
									g_pMissionDatabase))
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E3M2NavPlotted", 
									g_pMissionDatabase))
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "AddNavDustCloud"))

				MissionLib.QueueActionToPlay(pSeq)


###############################################################################
#	TerrikFleeDialog()
#
# 	Play dialogue for Terrik fleeing.
#	Called from BasicWarbirdAI.
#
#	Args:	None
#
#	Return:	None
###############################################################################
def TerrikFleeDialog():
	if not g_bTerrikOutroPlayed:
		global g_bTerrikOutroPlayed
		g_bTerrikOutroPlayed = TRUE

		MissionLib.RemoveGoal("E3DriveOffRomulansGoal")
		MissionLib.AddGoal("E3CallStarfleetGoal")

		global g_iMissionProgress
		g_iMissionProgress = MET_ROMULANS

		# Give Romulans flee AI.
		pWarbird1 = MissionLib.GetShip("Chairo")
		pWarbird2 = MissionLib.GetShip("T'Awsun")

		import Maelstrom.Episode3.E3M2.FleeAI
		assert pWarbird1
		if pWarbird1:
			pWarbird1.SetAI(Maelstrom.Episode3.E3M2.FleeAI.CreateAI(pWarbird1, "Warbird 1 Start"))
		assert pWarbird2
		if pWarbird2:
			pWarbird2.SetAI(Maelstrom.Episode3.E3M2.FleeAI.CreateAI(pWarbird2, "Warbird 2 Start"))

		# Play dialogue.
		pTBridgeSet = App.g_kSetManager.GetSet("TBridgeSet")
		pTerrik = App.CharacterClass_GetObject (pTBridgeSet, "Terrik")
		pBridge = App.g_kSetManager.GetSet("bridge")
		pXO = App.CharacterClass_GetObject(pBridge, "XO")

		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Terrik"))
		pSeq.AppendAction(App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E3M3L039", None, 0, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2CallStarfleet", "Captain", 1, g_pMissionDatabase), 5.0)
		MissionLib.QueueActionToPlay(pSeq)

	
################################################################################
#	MissionWin(pAction)
#
#	Call episode level handler when mission is complete.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def MissionWin(pAction):
	Maelstrom.Episode3.Episode3.Mission2Complete()

	return 0

################################################################################
#	EnterSet(pObject, pEvent)
#
#	Ship entered set event handler.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def EnterSet(pObject, pEvent):
	if g_bMissionTerminated:
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if pShip is None:
		pObject.CallNextHandler(pEvent)
		return
	pSet = pShip.GetContainingSet()
	if pSet is None:
		pObject.CallNextHandler(pEvent)
		return

	pcName = pShip.GetName()
	pcSetName = pSet.GetName()

	if pcName == "player":
		if (pcSetName == "Vesuvi6") and not g_bVesuvi6Arrive:
			global g_bVesuvi6Arrive
			g_bVesuvi6Arrive = TRUE
			
			pWarbird = loadspacehelper.CreateShip("Warbird", pSet, "Warbird", "Warbird Start")
			pWarbird.SetInvincible(TRUE)

			import RunAI
			pWarbird.SetAI(RunAI.CreateAI(pWarbird))

			pBridge = App.g_kSetManager.GetSet("bridge")
			pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
			pScience = App.CharacterClass_GetObject(pBridge, "Science")
			pXO = App.CharacterClass_GetObject(pBridge, "XO")

			pSeq = MissionLib.NewDialogueSequence()

			pAction1 = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M2ReadyToWarp", None, 0, g_pMissionDatabase)
			pSeq.AppendAction(pAction1)

			# Start cutscene, but don't hide the target reticle
			pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene", 1, .125, 0)
			pSeq.AppendAction(pAction)

			pAction = App.TGScriptAction_Create(__name__, "TargetWarbird")
			pSeq.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", pcSetName)
			pSeq.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", pcSetName)
			pSeq.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "TargetWatch", pcSetName, "player", "Warbird", 0, 0)
			pSeq.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M2HavenWarbird1", "Captain", 1, g_pMissionDatabase)
			pSeq.AppendAction(pAction, 1)
			pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2HavenWarbird2", "S", 1, g_pMissionDatabase)
			pSeq.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M2HavenWarbird3", None, 0, g_pMissionDatabase)
			pSeq.AppendAction(pAction, 1)
			pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2HavenWarbird4", "H", 1, g_pMissionDatabase)
			pSeq.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "PushButtons", pHelm)
			pSeq.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", pcSetName)
			pSeq.AppendAction(pAction)
			pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
			pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
			pSeq.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M2HavenWarbird5", None, 0, g_pMissionDatabase)
			pSeq.AppendAction(pAction)
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetCourseForDustCloud"))

			MissionLib.QueueActionToPlay(pSeq)

			# Remove warp to Vesuvi goal
			MissionLib.RemoveGoal("E3WarpToCeli4Goal")

		elif (pcSetName == "Vesuvi4"):

			if not g_bBriefingPlayed:
				global g_bBriefingPlayed
				g_bBriefingPlayed = TRUE

				# Set the berkeley as the player's target
				pShip.SetTarget("USS Berkeley")
	
				OrientBerkeley()
					
				# Do sequence.
				pBridge = App.g_kSetManager.GetSet("bridge")
				pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
				pScience = App.CharacterClass_GetObject(pBridge, "Science")

				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M2ShouldHail", None, 0, g_pMissionDatabase), 2)
				pSeq.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M2HavenWarbird6", "Captain", 1, g_pMissionDatabase), 1)
				pSeq.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M2ShouldHail2", "Captain", 1, g_pMissionDatabase))
				pSeq.Play()

			# We want to re-enable the entry/exit nebula messages
			# since they could have been removed if player warped.
			pShip.RemoveHandlerForInstance(App.ET_ENTERED_NEBULA, __name__ + ".InNebula")
			pShip.RemoveHandlerForInstance(App.ET_EXITED_NEBULA, __name__ + ".OutNebula")
			pShip.AddPythonFuncHandlerForInstance(App.ET_ENTERED_NEBULA, __name__ + ".InNebula")
			pShip.AddPythonFuncHandlerForInstance(App.ET_EXITED_NEBULA, __name__ + ".OutNebula")

		elif (g_iMissionProgress == ROMULAN_ENCOUNTER) and (pcSetName == "Starbase12"):	
			MissionLib.RemoveGoal("E3CallStarfleetGoal")

			global g_iMissionProgress
			g_iMissionProgress = MISSION_WON

			pBridge = App.g_kSetManager.GetSet("bridge")
			pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
			pXO = App.CharacterClass_GetObject(pBridge, "XO")
			pLiuSet = App.g_kSetManager.GetSet("LiuSet")
			pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

			pSeq = MissionLib.NewDialogueSequence()

			pAction =  App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "HailStarfleet2", None, 0, g_pGeneralDatabase)
			pSeq.AppendAction(pAction, 5)
			pAction =  App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "HailStarfleet8", None, 0, g_pGeneralDatabase)
			pSeq.AppendAction(pAction, 3)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
			pSeq.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M2Disappointed", None, 0, g_pMissionDatabase)
			pSeq.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "MissionWin")
			pSeq.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSeq)
		
	elif (pcName == "USS Nightingale"):
		if (pcSetName == "Vesuvi4"):
			if MissionLib.IsInSameSet(pcName):
				if not g_bInNebula:
					pTactical = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
					pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")
					pSeq = MissionLib.NewDialogueSequence()
					pSeq.AppendAction(App.CharacterAction_Create(pTactical, App.CharacterAction.AT_SAY_LINE, "E3M3L047", None, 0, g_pMissionDatabase))
					pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M3WeCanGo", None, 0, g_pMissionDatabase))
					MissionLib.QueueActionToPlay(pSeq)
		elif (pcSetName == "Starbase12"):
			pShip.PlaceObjectByName("Nightingale Docked")
			pShip.SetStatic(TRUE)
	elif (pcName == "USS Berkeley") and (pcSetName == "Starbase12"):
		pShip.PlaceObjectByName("Berkeley Docked")
		pShip.SetStatic(TRUE)

	elif (pcName == "Chairo"):
		if pcSetName == "Vesuvi4":
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "TerrikDialogue"), 2.0)
			MissionLib.QueueActionToPlay(pSeq)


#
# TargetWarbird()
#
def TargetWarbird(pAction):

	pSet = App.g_kSetManager.GetSet("Vesuvi6")
	pPlayerShip = MissionLib.GetPlayer()
	pPlayerShip.SetTarget("Warbird")

	pWarbird = App.ShipClass_GetObject(pSet, "Warbird")

	import WarpAI
	pWarbird.SetAI(WarpAI.CreateAI(pWarbird))

	return 0


################################################################################
#	SetCourseForDustCloud(pAction)
#
#	Set course for the Vesuvi Dust Cloud and bring up Kiska's menu.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def SetCourseForDustCloud(pAction):
#	print "E3M2.SetCourseForDustCloud() called."
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.SetDestination("Systems.Vesuvi.Vesuvi4")

	return 0

################################################################################
#	PlayerDestroyed(pObject, pEvent)
#
#	Handler for the player destroyed event.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def PlayerDestroyed(pObject, pEvent):
	# Abort currently playing sequence.
	pSeq = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(MissionLib.g_idMasterSequenceObj))
	if pSeq:
		pSeq.Abort()

	pObject.CallNextHandler(pEvent)

################################################################################
#	ShipDestroyed(pObject, pEvent)
#
#	Handler for the object destroyed event.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def ShipDestroyed(pObject, pEvent):
	if g_bMissionTerminated:
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip):
		pcName = pShip.GetName()

		if (pcName == "USS Berkeley") or (pcName == "USS Nightingale"):
			pLiuSet = App.g_kSetManager.GetSet("LiuSet")
			pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

			pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
			pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
			pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

			pSequence = MissionLib.NewDialogueSequence()
			if (pcName == "USS Berkeley"):
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_LOOK_AT_ME)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed1", "Captain", 1, g_pMissionDatabase)
				pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction2 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
			pSequence.AddAction(pAction2, pAction)
			pAction3 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed2", "Captain", 1, g_pMissionDatabase)
			pSequence.AddAction(pAction3, pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed3", "Captain", 0, g_pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed4", None, 0, g_pMissionDatabase)
			pSequence.AppendAction(pAction, 1)
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_TURN_BACK)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed5", None, 0, g_pMissionDatabase)
			pSequence.AppendAction(pAction)	
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed6", None, 0, g_pMissionDatabase)
			pSequence.AppendAction(pAction)
	
			MissionLib.GameOver(None, pSequence)


	pObject.CallNextHandler(pEvent)

################################################################################
#	ShipExploding(pObject, pEvent)
#
#	Handler for the object destroyed event.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def ShipExploding(pObject, pEvent):
	if g_bMissionTerminated:
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip):
		pcName = pShip.GetName()

		if pcName == "Unknown Probe":
			ProbeDestroyed()

	pObject.CallNextHandler(pEvent)

################################################################################
#	HailHandler(pObject, pEvent)
#
#	Called when the "Hail" button is hit
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def HailHandler(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return

	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if pTarget is None:
		pTarget = pPlayer.GetTarget()
	
	if pTarget is None:
		pObject.CallNextHandler(pEvent)
		return

	import Bridge.HelmMenuHandlers
	sTarget = pTarget.GetName()

	if sTarget == "USS Berkeley":
		if not g_bHailedBerkeley:
			global g_bHailedBerkeley
			g_bHailedBerkeley = TRUE
			
			pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
			pSeq.AppendAction(App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge"))
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "BerkeleyIntro"))
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StopShip"))
			pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
			MissionLib.QueueActionToPlay(pSeq)
		else:
			pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HailBerkeley"))
			MissionLib.QueueActionToPlay(pSeq)
	elif sTarget == "USS Nightingale":
		pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HailNightingale"))
		MissionLib.QueueActionToPlay(pSeq)
	else:
		pObject.CallNextHandler(pEvent)


#
# OrientBerkeley
#
def OrientBerkeley(pAction = 0):
	pSet = App.g_kSetManager.GetSet("Vesuvi4")
	pBerkeley = App.ShipClass_GetObject(pSet, "USS Berkeley")
	if pBerkeley:

		pPlayer = MissionLib.GetPlayer()
		if not pPlayer:
			return

		# Make the Berkeley orient to the player
		MissionLib.OrientObjectTowardObject(pBerkeley, pPlayer)

	return 0

################################################################################
#	BerkeleyIntro(pAction)
#
#	Play dialogue for meeting with the Berkeley. Commander Data comes aboard.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def BerkeleyIntro(pAction):
	if g_bMissionTerminated:
		return 0

	MissionLib.RemoveGoal ("E3MeetWithBerkeleyGoal")

	pHBridgeSet = App.g_kSetManager.GetSet("HBridgeSet")
	pHaley = App.CharacterClass_GetObject (pHBridgeSet, "Haley")
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pEng = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")
	pSci = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pTact = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "HBridgeSet", "Haley"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "LookForward"))
	pSeq.AppendAction(App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2L009", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1"))

	# Play Brex line "lowering shields" if shields are up.
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pShields = pPlayer.GetShields()
		if pShields:
			if pShields.IsOn():
				pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields")
				pSeq.AppendAction(pAction)
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pEng, "LoweringShields", g_pGeneralDatabase))

	pSeq.AppendAction(App.CharacterAction_Create(pEng, App.CharacterAction.AT_SAY_LINE, "E3M2DataAboard", "Captain", 1, g_pMissionDatabase))

	pPause = App.TGScriptAction_Create("MissionLib", "PauseExtras")
	pSeq.AppendAction(pPause)

	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pAction1 = App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2WhatHappened", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction1)
	pAction2 = App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2L010", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction2)
	pActionA = App.CharacterAction_Create(pData, App.CharacterAction.AT_MOVE, "X2")
	pSeq.AddAction(pActionA, pAction1, 5)
	pActionB = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementOffsetWatch", "bridge", "Data", "Guest Head", 0, 0, 20)
	pSeq.AddAction(pActionB, pAction1, 5)
	pActionL2 = App.CharacterAction_Create(pEng, App.CharacterAction.AT_TURN, "Captain")
	pSeq.AddAction(pActionL2, pAction1, 6)
	pActionL3 = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_TURN, "Captain")
	pSeq.AddAction(pActionL3, pAction1, 6)
	pActionL4 = App.CharacterAction_Create(pTact, App.CharacterAction.AT_TURN, "Captain")
	pSeq.AddAction(pActionL4, pAction1, 6)
	pActionL5 = App.CharacterAction_Create(pSci, App.CharacterAction.AT_TURN, "E")
	pSeq.AddAction(pActionL5, pAction1, 6)

	pActionC = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSeq.AddAction(pActionC, pActionA)
	pActionD = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSeq.AddAction(pActionD, pActionA)

	pAction = App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2L014", None, 0, g_pMissionDatabase)
	pSeq.AddAction(pAction, pAction2)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_DISABLE_RANDOM_ANIMATIONS)
	pSeq.AppendAction(pAction)

	pUnPause = App.TGScriptAction_Create("MissionLib", "PauseExtras", 1)
	pSeq.AppendAction(pUnPause)

	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L015", "Captain", 1, g_pMissionDatabase))
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_LOOK_AT_ME)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2L016", "E", 1, g_pMissionDatabase)
	pSeq.AppendAction(pAction)

	pSeq2 = MissionLib.NewDialogueSequence()
	pSeq2.AppendAction(pSeq)
	pAction1 = App.CharacterAction_Create(pData, App.CharacterAction.AT_WATCH_ME)
	pSeq2.AppendAction(pAction1)
	pAction2 = App.CharacterAction_Create(pData, App.CharacterAction.AT_MOVE, "X")
	pSeq2.AppendAction(pAction2)
	pAction3 = App.CharacterAction_Create(pData, App.CharacterAction.AT_TURN, "Captain")
	pSeq2.AddAction(pAction3, pAction2)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L017", "Captain", 1, g_pMissionDatabase)
	pSeq2.AddAction(pAction, pAction1)
	pSeq2.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_STOP_WATCHING_ME))
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_ENABLE_RANDOM_ANIMATIONS)
	pSeq2.AppendAction(pAction)
	pSeq2.AppendAction(App.TGScriptAction_Create("MissionLib", "LookForward"))
	pSeq2.AppendAction(App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2L018", None, 0, g_pMissionDatabase))
	pSeq2.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge"))
	pSeq2.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam2"))
	pSeq2.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2L019", "E", 0, g_pMissionDatabase))
	pSeq2.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1"))
	pSeq2.AppendAction(App.CharacterAction_Create(pEng, App.CharacterAction.AT_SAY_LINE, "E3M2L020", "C", 1, g_pMissionDatabase))
	pSeq2.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1))
	pSeq2.AppendAction(App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2L021", None, 0, g_pMissionDatabase))
	pSeq2.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1))
	pSeq2.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L022", None, 0, g_pMissionDatabase))
	pSeq2.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1))
	pSeq2.AppendAction(App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2L023", None, 0, g_pMissionDatabase))
	pSeq2.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_TURN_BACK))
	pSeq2.AppendAction(App.TGScriptAction_Create(__name__, "OrientBerkeley"))
	pSeq2.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	pSeq3 = MissionLib.NewDialogueSequence()
	pSeq3.AppendAction(pSeq2)
	pSeq3.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge"))
	pSeq3.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSeq3.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3FindCoreFragmentGoal"))
	pSeq3.AppendAction(App.CharacterAction_Create(pSci, App.CharacterAction.AT_TURN_BACK))
	pSeq3.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_TURN_BACK))
	pSeq3.AppendAction(App.CharacterAction_Create(pEng, App.CharacterAction.AT_TURN_BACK))
	pSeq3.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_TURN_BACK))
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2WhatToDo", "Captain", 1, g_pMissionDatabase)
	pSeq3.AppendAction(pAction)
	pActionL1 = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_TURN_BACK)
	pSeq3.AddAction(pActionL1, pAction)
	pActionL2 = App.CharacterAction_Create(pTact, App.CharacterAction.AT_TURN_BACK)
	pSeq3.AddAction(pActionL2, pAction)

	pAction1 = App.TGScriptAction_Create(__name__, "CreateNavPoints")
	pSeq3.AddAction(pAction1, pAction)
	pSeq3.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M2Confirmed", "Captain", 1, g_pMissionDatabase))
	pSeq3.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2Ready", "Captain", 1, g_pMissionDatabase))

	MissionLib.QueueActionToPlay(pSeq3)

	return 0

	
################################################################################
#	HailBerkeley(pAction)
#
#	Play dialogue response for hailing the Berkeley.
#
#	Args:	The script action.
#
#	Return:	0
################################################################################
def HailBerkeley(pAction):

	pHBridgeSet = App.g_kSetManager.GetSet("HBridgeSet")
	pHaley = App.CharacterClass_GetObject (pHBridgeSet, "Haley")
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, g_pGeneralDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "HBridgeSet", "Haley"))

	if g_iMissionProgress == FIND_CORE:
		pSeq.AppendAction(App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2L023", None, 0, g_pMissionDatabase))
	elif g_iMissionProgress == AID_BERKELEY:
		pSeq.AppendAction(App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M3L005", None, 0, g_pMissionDatabase))
	elif g_iMissionProgress == HAIL_STARFLEET:
		pSeq.AppendAction(App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M2HailBerkeley1", None, 0, g_pMissionDatabase))
	else:
		pSeq.AppendAction(App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, 
						MissionLib.GetRandomLine(["E3M3L046", "E3M2HailBerkeley2"]), None, 0, g_pMissionDatabase))

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	MissionLib.QueueActionToPlay(pSeq)
	
	return 0

################################################################################
#	HailNightingale(pAction)
#
#	Play dialogue response for hailing the Nightingale.
#
#	Args:	The script action.
#
#	Return:	0
################################################################################
def HailNightingale(pAction):
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, 
											"KiskaYes4", None, 0, g_pGeneralDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, 
											"E3M2HailNightingale", None, 0, g_pMissionDatabase), 3.0)
	MissionLib.QueueActionToPlay(pSeq)

	return 0

###############################################################################
#	Nav1Active(bInRange)
#	
#	Play dialogue informing player they've arrived at Nav 1.
#	Target first asteroid not scanned if any, otherwise tell player to move on.
#	Called from proximity check to Nav point.
#	
#	Args:	bInRange - flag for wether in/out of range.
#	
#	Return:	none
###############################################################################
def Nav1Active(bInRange):
	if g_bMissionTerminated:
		return

	if g_iMissionProgress != FIND_CORE:
		return

	if not bInRange:
		return
		
	# Count num left to scan.
	iToScan = 0
	for i in range(NUM_OBJECTS_NAV1):
		if not g_bAsteroidScanned[i]:
			iToScan = iToScan + 1

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	pSeq = MissionLib.NewDialogueSequence()
	pAction = None

	if (iToScan == NUM_OBJECTS_NAV1):
		# Say line to scan this area for the first time
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdFirst", None, 0, g_pMissionDatabase)
	elif (iToScan < NUM_OBJECTS_NAV1 and iToScan > 0):
		# Say line that there are still asteroids to scann
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdActive", None, 0, g_pMissionDatabase)
	else:
		# Say line that there are no more asteroids near this nav point left to scan
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdNoMore", None, 0, g_pMissionDatabase)

	pSeq.AppendAction(pAction)
	MissionLib.QueueActionToPlay(pSeq)

	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		# Find an asteroid to automatically target.
 		pTarget = pPlayer.GetTarget()
		if pTarget:
			if pTarget.IsTypeOf(App.CT_PLACEMENT):
				# Player currently has nav point targeted.  Switch to asteroid if any available.
				pcAsteroidToTarget = None
				pSensors = pPlayer.GetSensorSubsystem()
				if pSensors:
					k = 0
					for i in range(NUM_OBJECTS_NAV1):
						if g_bAsteroidScanned[k] == FALSE:
							pcAsteroidToTarget = "Unknown Debris " + str(k + 1)
							pObj = MissionLib.GetShip(pcAsteroidToTarget)
							if pObj:
								if pSensors.IsObjectVisible(pObj):
									pPlayer.SetTarget(pcAsteroidToTarget)
									break
						k = k + 1

###############################################################################
#	Nav2Active(bInRange)
#	
#	Play dialogue informing player they've arrived at Nav 2.
#	Target first asteroid not scanned if any, otherwise tell player to move on.
#	Called from proximity check to Nav point.
#	
#	Args:	bInRange - flag for wether in/out of range.
#	
#	Return:	none
###############################################################################
def Nav2Active(bInRange):
	if g_bMissionTerminated:
		return

	if g_iMissionProgress != FIND_CORE:
		return

	if not bInRange:
		return
		
	# Count num left to scan.
	iToScan = 0
	i = NUM_OBJECTS_NAV1
	for x in range(NUM_OBJECTS_NAV2):
		if not g_bAsteroidScanned[i]:
			iToScan = iToScan + 1
		i = i + 1

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	pSeq = MissionLib.NewDialogueSequence()
	pAction = None

	if iToScan == NUM_OBJECTS_NAV2:
		# Say line to scan this area for the first time
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdFirst", None, 0, g_pMissionDatabase)
	elif (iToScan < NUM_OBJECTS_NAV2 and iToScan > 0):
		# Say line that there are still asteroids to scann
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdActive", None, 0, g_pMissionDatabase)
	else:
		# Say line that there are no more asteroids near this nav point left to scan
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdNoMore", None, 0, g_pMissionDatabase)

	pSeq.AppendAction (pAction)
	MissionLib.QueueActionToPlay(pSeq)

	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		# Find an asteroid to automatically target.
		pTarget = pPlayer.GetTarget()
		if pTarget:
			if pTarget.IsTypeOf (App.CT_PLACEMENT):
				# Player currently has nav point targeted.  Switch to asteroid if any available.
				pcAsteroidToTarget = None
				pSensors = pPlayer.GetSensorSubsystem()
				if pSensors:
					k = NUM_OBJECTS_NAV1
					for i in range(NUM_OBJECTS_NAV2):
						if g_bAsteroidScanned[k] == FALSE:
							pcAsteroidToTarget = "Unknown Debris " + str(k + 1)
							pObj = MissionLib.GetShip(pcAsteroidToTarget)
							if pObj:
								if pSensors.IsObjectVisible(pObj):
									pPlayer.SetTarget(pcAsteroidToTarget)
									break
						k = k + 1

###############################################################################
#	Nav3Active(bInRange)
#	
#	Play dialogue informing player they've arrived at Nav 3.
#	Target first asteroid not scanned if any, otherwise tell player to move on.
#	Called from proximity check to Nav point.
#	
#	Args:	bInRange - flag for wether in/out of range.
#	
#	Return:	none
###############################################################################
def Nav3Active(bInRange):
	if g_bMissionTerminated:
		return

	if g_iMissionProgress != FIND_CORE:
		return

	if not bInRange:
		return

	# Count num left to scan.
	iToScan = 0
	i = NUM_OBJECTS_NAV1 + NUM_OBJECTS_NAV2
	for x in range(NUM_OBJECTS_NAV3):
		if not g_bAsteroidScanned[i]:
			iToScan = iToScan + 1
		i = i + 1

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	pSeq = MissionLib.NewDialogueSequence()
	pAction = None

	if (iToScan == NUM_OBJECTS_NAV3):
		# Say line to scan this area for the first time
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdFirst", None, 0, g_pMissionDatabase)
	elif (iToScan < NUM_OBJECTS_NAV3 and iToScan > 0):
		# Say line that there are still asteroids to scann
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdActive", None, 0, g_pMissionDatabase)
	else:
		# Say line that there are no more asteroids near this nav point left to scan
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdNoMore", None, 0, g_pMissionDatabase)

	pSeq.AppendAction(pAction)
	MissionLib.QueueActionToPlay(pSeq)

	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		# Find an asteroid to automatically target.
		pTarget = pPlayer.GetTarget()
		if pTarget:
			if pTarget.IsTypeOf(App.CT_PLACEMENT):
				# Player currently has nav point targeted.  Switch to asteroid if any available.
				pcAsteroidToTarget = None
				pSensors = pPlayer.GetSensorSubsystem()
				if pSensors:
					k = NUM_OBJECTS_NAV1 + NUM_OBJECTS_NAV2
					for i in range(NUM_OBJECTS_NAV3):
						if g_bAsteroidScanned[k] == FALSE:
							pcAsteroidToTarget = "Unknown Debris " + str(k + 1)
							pObj = MissionLib.GetShip(pcAsteroidToTarget)
							if pObj:
								if pSensors.IsObjectVisible(pObj):
									pPlayer.SetTarget(pcAsteroidToTarget)
									break
						k = k + 1

###############################################################################
#	Nav4Active(bInRange)
#	
#	Play dialogue informing player they've arrived at Nav 4.
#	Target first asteroid not scanned if any, otherwise tell player to move on.
#	Called from proximity check to Nav point.
#	
#	Args:	bInRange - flag for wether in/out of range.
#	
#	Return:	none
###############################################################################
def Nav4Active(bInRange):
	if g_bMissionTerminated:
		return

	if g_iMissionProgress != FIND_CORE:
		return

	if not bInRange:
		return
		
	# Count num left to scan.
	iToScan = 0
	i = NUM_OBJECTS_NAV1 + NUM_OBJECTS_NAV2 + NUM_OBJECTS_NAV3
	for x in range(NUM_OBJECTS_NAV4):
		if not g_bAsteroidScanned[i]:
			iToScan = iToScan + 1
		i = i + 1

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	pSeq = MissionLib.NewDialogueSequence()
	pAction = None

	if (iToScan == NUM_OBJECTS_NAV4):
		# Say line to scan this area for the first time
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdFirst", None, 0, g_pMissionDatabase)
	elif (iToScan < NUM_OBJECTS_NAV4 and iToScan > 0):
		# Say line that there are still asteroids to scann
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdActive", None, 0, g_pMissionDatabase)
	else:
		# Say line that there are no more asteroids near this nav point left to scan
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ProdNoMore", None, 0, g_pMissionDatabase)

	pSeq.AppendAction(pAction)
	MissionLib.QueueActionToPlay(pSeq)

	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		# Find an asteroid to automatically target.
		pTarget = pPlayer.GetTarget()
		if pTarget:
			if pTarget.IsTypeOf (App.CT_PLACEMENT):
				# Player currently has nav point targeted.  Switch to asteroid if any available.
				pcAsteroidToTarget = None
				pSensors = pPlayer.GetSensorSubsystem()
				if pSensors:
					k = NUM_OBJECTS_NAV1 + NUM_OBJECTS_NAV2 + NUM_OBJECTS_NAV3
					for i in range(NUM_OBJECTS_NAV4):
						if g_bAsteroidScanned[k] == FALSE:
							pcAsteroidToTarget = "Unknown Debris " + str(k + 1)
							pObj = MissionLib.GetShip(pcAsteroidToTarget)
							if pObj:
								if pSensors.IsObjectVisible(pObj):
									pPlayer.SetTarget(pcAsteroidToTarget)
									break
						k = k + 1

################################################################################
#	ScanHandler()
#
#	Called when the "Scan" button in Miguel's menu is hit.  
#	Performs tasks based on what system we're in.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def ScanHandler(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return
	
	iScanType = pEvent.GetInt()

	if iScanType == App.CharacterClass.EST_SCAN_OBJECT and g_bNavPointsCreated:
		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if pTarget is None:
			pTarget = pPlayer.GetTarget()
		if pTarget:
			pcName = pTarget.GetName()

			if g_iMissionProgress == FIND_CORE:
				if pcName[:len("Unknown Debris ")] == "Unknown Debris ":
					if ScanDebris(pTarget):
						return
			# Don't do default scan since probe is already being scanned.
			elif g_iMissionProgress == FIND_PROBE:
				if pcName == "Unknown Probe":
					if ScanProbe():
						return

	pObject.CallNextHandler(pEvent)

################################################################################
#	ScanDebris(pTarget)
#
#	Scan a piece of debris. Tell the player scan results if in range,
#	otherwise play message telling player their too far.
#
#	Args:	pTarget - The target being scanned.
#
#	Return:	bool, TRUE if scanned, FALSE if unable to.
################################################################################
def ScanDebris(pTarget):
	assert pTarget
	if pTarget is None:
		return FALSE

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return FALSE

	pcName = pTarget.GetName()

	pcTargetNumber = pcName[len("Unknown Debris "):]
	iTargetNumber = int(pcTargetNumber) - 1

	global g_bAsteroidScanned
	if not g_bAsteroidScanned[iTargetNumber]:
		kTargetPos = pTarget.GetWorldLocation()
		kPlayerPos = pPlayer.GetWorldLocation()

		kPlayerPos.Subtract(kTargetPos)
		fDistance = kPlayerPos.Length()

		pScanSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
		if pScanSeq is None:
			return TRUE

		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(pScanSeq)

		# If we're too far, play dialogue informing player.
		if(fDistance > ASTEROID_SCAN_RANGE):
			pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
			pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M2GetCloser", None, 1, g_pMissionDatabase)
			pSeq.AppendAction(pAction)
		else:
			pcTargetNumber = pTarget.GetName()[len("Unknown Debris "):]
			iTargetNumber = int(pcTargetNumber) - 1
		
			# Set flag that this asteroid has been scanned
			global g_bAsteroidScanned
			g_bAsteroidScanned[iTargetNumber] = TRUE
		
			# Increment count of asteroids already scanned.
			global g_iAsteroidsScanned
			g_iAsteroidsScanned = g_iAsteroidsScanned + 1
		
			pBridge = App.g_kSetManager.GetSet("bridge")
			pData = App.CharacterClass_GetObject(pBridge, "Data")
			pScience = App.CharacterClass_GetObject(pBridge, "Science")
		
			# If g_iNumToScan asteroids scanned, player finds stellar core.
			if g_iAsteroidsScanned == g_iNumToScan:
				RemoveNavProximity()

				pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
				pXO = App.CharacterClass_GetObject(pBridge, "XO")
				pHBridgeSet = App.g_kSetManager.GetSet("HBridgeSet")
				pHaley = App.CharacterClass_GetObject (pHBridgeSet, "Haley")


				pAction = App.TGScriptAction_Create("MissionLib", "SetSpeakingVolume", App.CSP_SPONTANEOUS, 0.5)
				pSeq.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "SetSpeakingVolume", App.CSP_NORMAL, 0.5)
				pSeq.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
				pSeq.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
				pSeq.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1")
				pSeq.AppendAction(pAction)
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StopShip"))
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
				pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M2L035", None, 0, g_pMissionDatabase)
				pSeq.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1")
				pSeq.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L034", None, 0, g_pMissionDatabase)
				pSeq.AppendAction(pAction)
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RenameFragment", pTarget, STELLAR_CORE))
				pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L036", None, 0, g_pMissionDatabase))
				pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L037", None, 0, g_pMissionDatabase)
				pSeq.AppendAction (pAction)
				pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Kiska Head", "Kiska Cam", 1)
				pSeq.AppendAction(pAction, 2)
				pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M2EmergencyHail", None, 0, g_pMissionDatabase)
				pSeq.AppendAction (pAction)
				pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
				pSeq.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pHaley, App.CharacterAction.AT_SAY_LINE, "E3M3L005", None, 0, g_pMissionDatabase)
				pSeq.AppendAction (pAction)
				pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2")
				pSeq.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2ReturnNow", "Captain", 1, g_pMissionDatabase)
				pSeq.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
				pSeq.AppendAction(pAction)
				pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2EverythingWeNeed", "S", 1, g_pMissionDatabase))
				pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1")
				pSeq.AppendAction(pAction)
				pSeq.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M2AllCatalogued", "Captain", 1, g_pMissionDatabase))
				pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
				pSeq.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
				pSeq.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "SetupRescueBerkeley")
				pSeq.AppendAction (pAction)
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ProxBerkeley"))
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", AID_BERKELEY))
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E3InvestigateDustCloudGoal"))
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E3FindCoreFragmentGoal"))
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3ReturnToBerkeleyGoal"))
				pAction = App.TGScriptAction_Create("MissionLib", "SetSpeakingVolume", App.CSP_SPONTANEOUS, 1)
				pSeq.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "SetSpeakingVolume", App.CSP_NORMAL, 1)
				pSeq.AppendAction(pAction)

			else:
				# Not the core.
				pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "gs029", None, 0, g_pGeneralDatabase)
		
				r = App.g_kSystemWrapper.GetRandomNumber(2)
				if (r == 0):
					pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L043", None, 0, g_pMissionDatabase)
				else:
					pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2L044", None, 0, g_pMissionDatabase)
		
				pSeq.AppendAction(pAction)
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RenameFragment", pTarget, r))
		
		pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
		MissionLib.QueueActionToPlay(pSeq)
		return TRUE
	
	return FALSE


################################################################################
#	RenameFragment(pAction, pTarget, iName)
#
#	Rename fragment being scanned and send event to identify it.
#
#	Args:	pAction, the script action.
#			pTarget, the target being scanned.
#			iName, the name to change to.
#
#	Return:	None
################################################################################
def RenameFragment(pAction, pTarget, iName):
	assert pTarget
	if pTarget:
		# Remove the object from the Scan Object menu
		import Bridge.ScienceMenuHandlers
		Bridge.ScienceMenuHandlers.ExitedSet(pTarget)

		# ***FIXME: Localize these names.
		if iName == 0:
			pTarget.SetName("Planet Fragment " + str (g_iPlanetFragmentCount))
			pTarget.SetDisplayName(g_pMissionDatabase.GetString("Planet Fragment ").Append(App.TGString(str(g_iPlanetFragmentCount))))
			global g_iPlanetFragmentCount
			g_iPlanetFragmentCount = g_iPlanetFragmentCount + 1
		elif iName == 1:
			pTarget.SetName("Inert Matter " + str (g_iGasShellCount))
			pTarget.SetDisplayName(g_pMissionDatabase.GetString("Inert Matter ").Append(App.TGString(str(g_iGasShellCount))))
			global g_iGasShellCount
			g_iGasShellCount = g_iGasShellCount + 1
		# Must be stellar core.
		else:
			# Set the name of this asteroid to stellar debris.
			pTarget.SetName("Stellar Debris")
			pTarget.SetDisplayName(g_pMissionDatabase.GetString("Stellar Debris"))

		# Send event to identify object.
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetEventType(App.ET_SENSORS_SHIP_IDENTIFIED)
		pEvent.SetSource(pTarget)
		pEvent.SetDestination(pTarget)
		pEvent.SetObjPtr(pTarget)
		App.g_kEventManager.AddEvent (pEvent)

	return 0
	
################################################################################
#	WeaponHitHandler(pObject, pEvent)
#
#	Called when a friendly ship is hit.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def WeaponHitHandler(pObject, pEvent):
	pAttacker = pEvent.GetFiringObject()
	if pAttacker:
		pSet = pAttacker.GetContainingSet()
		if pSet:
			global g_bDerelictAttacked
			g_bDerelictAttacked = TRUE

			pDerelict = MissionLib.GetShip("Derelict Warbird", None, TRUE)
			if pDerelict:
				pDerelict.SetInvincible(FALSE)
				MissionLib.RemoveWeaponHitHandlers(["Derelict Warbird"])
	pObject.CallNextHandler(pEvent)

	
###############################################################################
#	SetupRescueBerkeley(pAction)
#	
#	- Setup Kessok to attack Berkeley.  
#	- Remove Nav points in nebula. 
#	- Start prod timer for player to help Berkeley.
#	
#	Args:	pAction, the script action.
#	
#	Return:	none
###############################################################################
def SetupRescueBerkeley(pAction):

	pSet = App.g_kSetManager.GetSet("Vesuvi4")
	pKessok = loadspacehelper.CreateShip("KessokHeavy", pSet, "Strange Ship", "Nightingale Arrive")

	# Make the Kessok invisible, invincible, not hailable, not scannable and not targetable
	pKessok.SetHidden(TRUE)
	pKessok.SetInvincible(TRUE)
	pKessok.SetHailable(FALSE)
	pKessok.SetScannable(FALSE)
	pKessok.SetTargetable(FALSE)

	import AttackBerkeleyAI
	pKessok.SetAI(AttackBerkeleyAI.CreateAI(pKessok))

	pBerkeley = App.ShipClass_GetObject(pSet, "USS Berkeley")
	if pBerkeley:
		import DamageBerkeley
		DamageBerkeley.AddDamage(pBerkeley)
		DamageShip(pBerkeley, 0.25, 0.5)

		MissionLib.SetConditionPercentage(pBerkeley.GetHull(), .75)

	MissionLib.RemoveNavPoints("Vesuvi4", "Nav 1", "Nav 2", "Nav 3", "Nav 4")	

	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_HELP_BERKELEY, __name__ + ".HelpBerkeleyProd", 
							fStartTime + 60, 0, 0)

	return 0

################################################################################
#	HelpBerkeleyProd(pObject, pEvent)
#
#	Prod player to return to the Berkeley's position.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def HelpBerkeleyProd(pObject, pEvent):
	if not g_bHelpedBerkeley:

		pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2SaffiComm2", "Captain", 1, g_pMissionDatabase)
		MissionLib.QueueActionToPlay(pAction)

		# Create timer for next prod.
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_HELP_BERKELEY, __name__ + ".HelpBerkeleyProd", fStartTime + 30, 0, 0)


################################################################################
#	DamageShip(pShip, fMinPercent, fMaxPercent)
#
#	Randomly damage ship systems within Min/Max percentages.
#
#	Args:	pShip, ship to damage.
#			fMinPercent, minimum damage percentage.
#			fMaxPercent, maximum damage percentage.
#
#	Return:	None
################################################################################
def DamageShip(pShip, fMinPercent, fMaxPercent):
	assert pShip
	if pShip is None:
		return

	# Randomly damage all other systems.
	pSystem = pShip.GetHull()
	if pSystem:
		r = App.g_kSystemWrapper.GetRandomNumber(100)
		r = (1 + r) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetSensorSubsystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0)

	pSystem = pShip.GetShields()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0)

	pSystem = pShip.GetPowerSubsystem()
	if pSystem:
		r = App.g_kSystemWrapper.GetRandomNumber(100)
		r = (1 + r) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetImpulseEngineSubsystem()
	if pSystem:
		r = App.g_kSystemWrapper.GetRandomNumber(100)
		r = (1 + r) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	# Warp system is nearly destroyed
	pSystem = pShip.GetWarpEngineSubsystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, .05)

	pSystem = pShip.GetTorpedoSystem()
	if pSystem:
		r = App.g_kSystemWrapper.GetRandomNumber(100)
		r = (1 + r) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetPhaserSystem()
	if pSystem:
		r = App.g_kSystemWrapper.GetRandomNumber(100)
		r = (1 + r) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetPulseWeaponSystem()
	if pSystem:
		r = App.g_kSystemWrapper.GetRandomNumber(100)
		r = (1 + r) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetTractorBeamSystem()
	if pSystem:
		r = App.g_kSystemWrapper.GetRandomNumber(100)
		r = (1 + r) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetRepairSubsystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0)

	pSystem = pShip.GetCloakingSubsystem()
	if pSystem:
		r = App.g_kSystemWrapper.GetRandomNumber(100)
		r = (1 + r) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)


################################################################################
#	FindDerelict(pObject, pEvent)
#
#	Play dialogue when player encounters derelict Warbird.
#	Set AI for Romulans to warp in.
#
#	Args:	pMission, current mission.
#
#	Return:	None
################################################################################
def FindDerelict(pObject, pEvent):
	pWarbird = MissionLib.GetShip("Derelict Warbird")
	if pWarbird:
		pWarbird.RemoveHandlerForInstance(App.ET_TARGET_LIST_OBJECT_ADDED, 
											__name__ + ".FindDerelict")

	# Remove proximity check
	global g_pProxBeta
	if g_pProxBeta:
		g_pProxBeta.RemoveAndDelete()
		g_pProxBeta = None

	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pSci = App.CharacterClass_GetObject(pBridge, "Science")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")

	pSeq = MissionLib.NewDialogueSequence()		
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M2LastNav", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M3L030", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction(pAction, 2.0)
	pAction = App.TGScriptAction_Create(__name__, "TargetDerelict")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M2NoDoubt", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "WarpWarbirds")
	pSeq.AppendAction(pAction)
	MissionLib.QueueActionToPlay(pSeq)

	pObject.CallNextHandler(pEvent)

################################################################################
#	TargetDerelict(pAction)
#
#	Target the derelict Warbird.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def TargetDerelict (pAction):
	pSet = App.g_kSetManager.GetSet("Vesuvi4")
	pWarbird = App.ShipClass_GetObject(pSet, "Derelict Warbird")
	if pWarbird:
		pWarbird.SetTargetable(1)
		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			pPlayer.SetTarget("Derelict Warbird")

	MissionLib.RemoveGoal("E3FollowNavBetaGoal")

	return 0

################################################################################
#	WarpWarbirds(pAction)
#
#	Set AI for Warbirds to warp in.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def WarpWarbirds(pAction):
	pTempSet = App.g_kSetManager.GetSet("DeepSpace")

	pWarbird1 = App.ShipClass_GetObject(pTempSet, "Chairo")
	pWarbird2 = App.ShipClass_GetObject(pTempSet, "T'Awsun")

	import Maelstrom.Episode3.E3M2.E3M2WarpAI
	if pWarbird1:
		pWarbird1.SetAI(Maelstrom.Episode3.E3M2.E3M2WarpAI.CreateAI(pWarbird1, "Warbird 1 Start"))
	if pWarbird2:
		pWarbird2.SetAI(Maelstrom.Episode3.E3M2.E3M2WarpAI.CreateAI(pWarbird2, "Warbird 2 Start"))

	return 0

################################################################################
#	SetMissionProgress(pAction, iProgress)
#
# 	Set mission progress flag.
#
#	Args:	pAction, TGAction
#			iProgress, new mission progress value.
#
#	Return:	0
################################################################################
def SetMissionProgress(pAction, iProgress):
	global g_iMissionProgress
	g_iMissionProgress = iProgress

	return 0

################################################################################
#	Terminate(pMission)
#
#	Mission terminate.
#
#	Args:	pMission, current mission.
#
#	Return:	None
################################################################################
def Terminate(pMission):
	global g_bMissionTerminated
	g_bMissionTerminated = TRUE

	MissionLib.RemoveWeaponHitHandlers(["Derelict Warbird"])

	Bridge.BridgeUtils.RemoveCommunicateHandlers()

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	if pData:
		pMenu = pData.GetMenu()
		if pMenu:
			pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateData")

	global g_iProdReEnterTimerID
	if (g_iProdReEnterTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iProdReEnterTimerID)		
		g_iProdReEnterTimerID = App.NULL_ID

	App.SortedRegionMenu_ClearSetCourseMenu()
	
	# Remove python instance handlers
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.RemoveHandlerForInstance(App.ET_ENVIRONMENT_DAMAGE, __name__ + ".CoreDamage")
		pPlayer.RemoveHandlerForInstance(App.ET_ENTERED_NEBULA, __name__ + ".InNebula")
		pPlayer.RemoveHandlerForInstance(App.ET_EXITED_NEBULA, __name__ + ".OutNebula")
		pPlayer.RemoveHandlerForInstance(App.ET_OBJECT_EXPLODING, __name__ + "PlayerDestroyed")

	# Instance handler for Saffi's Contact Starfleet button
	pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	if pXO:
		pMenu = pXO.GetMenu()
		if pMenu:
			pMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".CallStarfleet")

	# Instance handler for Miguel's Scan Area button
	pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	if pScience:
		pMenu = pScience.GetMenu()
		if pMenu:
			pMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Instance handler for Kiska's Hail and warp buttons
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	if pHelm:
		pMenu = pHelm.GetMenu()
		if pMenu:
			pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

			pWarpButton = Bridge.BridgeUtils.GetWarpButton()
			
			if pWarpButton:
				pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	if g_pGeneralDatabase:
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	MissionLib.ShutdownFriendlyFire()