###############################################################################
#	Filename:	E7M3.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Episode 7 Mission 3
#
#	Created:	11/09/00 -	Bill Morrison (added header)
#	Modified:	01/16/02 -	Tony Evans
###############################################################################
import App
import Maelstrom.Maelstrom
import loadspacehelper
import MissionLib
import LoadBridge
import Effects
import Bridge.BridgeUtils
import Bridge.ScienceCharacterHandlers
import Systems.Starbase12.Starbase
import Systems.Starbase12.Starbase12
import Systems.Poseidon.Poseidon
import Systems.Poseidon.Poseidon2
import Systems.Geble.Geble
import Systems.Geble.Geble4
import Systems.Serris.Serris
import Systems.Serris.Serris3
import Systems.Artrus.Artrus
import Systems.Artrus.Artrus3
import Systems.Ascella.Ascella
import Systems.Ascella.Ascella5
import Systems.Ascella.Ascella3
import Systems.XiEntrades.XiEntrades
import Systems.XiEntrades.XiEntrades5
import Maelstrom.Episode7.E7M1.E7M1_P
import E7M3_P
import XiEnt5_P
import E7M5_P
import Ascella3_P
import GeronimoAI 
import EnemyAI
import AkiraAI 
import EnemyFollowAI
import FreighterAI
import DefenderAI
import BaseAI
import BaseAI2
import WarpAwayAI
import StarbaseAI
import TorpLauncherAI
import LaunchMateAI

# For debugging
#kDebugObj = App.CPyDebug()

#
# Event types
#
ET_ONE_MINUTE			= App.Mission_GetNextEventType()
ET_RESCUE_PROD			= App.Mission_GetNextEventType()
ET_CONTINUE				= App.Mission_GetNextEventType()
ET_SYSTEM_SCAN_TIMER	= App.Mission_GetNextEventType()
ET_STATION_ALERT_TIMER	= App.Mission_GetNextEventType()
ET_DISTRESS				= App.Mission_GetNextEventType()
ET_SUMMON_ZEISS			= App.Mission_GetNextEventType()
ET_CARD_ATTACK			= App.Mission_GetNextEventType()
ET_RESTORE_WARP			= App.Mission_GetNextEventType()
ET_RESET_GERONIMO		= App.Mission_GetNextEventType()
ET_MINES				= App.Mission_GetNextEventType()

#
# Global variables
#
TRUE		= 1
FALSE		= 0

pMissionDatabase	= None
pMission1Database	= None
pEpisodeDatabase	= None
pMenuDatabase		= None
pGeneralDatabase 	= None

g_pKiska			= None
g_pFelix			= None
g_pSaffi			= None
g_pMiguel			= None
g_pBrex				= None

g_pSaffiMenu		= None
g_pFelixMenu		= None
g_pKiskaMenu		= None
g_pMiguelMenu		= None
g_pBrexMenu			= None

bDebugPrint				= 1

HASNT_ARRIVED			= 0
HAS_ARRIVED				= 1

fStartTime				= 0
kStartupSoundID			= App.PSID_INVALID

g_bBriefingPlayed		= FALSE
bMissionTerminate		= FALSE
bPoseidon2Arrive		= FALSE
bArtrus3Arrive			= FALSE
bGeble4Arrive			= FALSE
bSerris3Arrive			= FALSE
bXiEnt5Arrive			= FALSE
bAscella5Arrive			= FALSE
bAscella3Arrive			= FALSE
bStopDamageDialogue		= FALSE
bOutpost1Destroyed		= FALSE
bOutpost2Destroyed		= FALSE
bOutpost3Destroyed		= FALSE
bOutpost4Destroyed		= FALSE
bDistressCallPlayed		= FALSE
bRescuedGeronimo		= FALSE
bRescueSequencePlayed	= FALSE
bThanksForRescue		= FALSE
bResupplyDestroyed		= FALSE
bPos2Defenders 			= FALSE
bArt3Defenders 			= FALSE
bSer3Defenders 			= FALSE
bGeb4Defenders 			= FALSE
bZeissLine				= FALSE
bFreighterDisabled		= FALSE
bKessokRepairGone		= FALSE
bDisruptorsGone			= FALSE
bStationAlert			= FALSE
bGeronimoAttackWait		= FALSE
bReinforcements			= FALSE
bMinesActive			= FALSE

iRescueGeronimoProd		= 0
iGeronimoAttackers		= 3
iOutposts 				= 4
iOutpostsDestroyed 		= 0
iPoseidon2Enemies		= 2
iArtrus3Enemies			= 2
iSerris3Enemies			= 3
iAttackWave				= 0
iGeronimoHit			= 0

g_bGraffWarned 		= FALSE
g_bZeissWarned 		= FALSE

pEnemies				= 0 # Enemy object group.
pFriendlies				= 0	# Friendly object group.
pHostileObjGroup		= 0 # Group of ships to destroy before engaging station.
pFreighterObjGroup		= 0 
pDisabledFreighters		= 0 # Group of freighters that are disabled
pFollowObjGroup			= 0
iNumHostilesDestroyed	= 0
iNumSurpriseHostiles	= 5		# Number of hostiles if surprising Cardassinas.
iNumAmbushHostiles		= 6		# Number of hostiles if player is ambushed by Cardassians.
iNumFreighters			= 4		# Number of freighters not destroyed.
bGalorPoweredUp			= FALSE	# Flag for "Galor powered up" dialog being played.
bFreighterPoweredUp		= FALSE	# Flag for line 1 of "Freighter powered up" dialog being played.

iEnemiesFollowing		= 0
iEnemiesStillFollowing	= 0
iMakeAStandLine			= 0
iProtectStarbase		= 0
bPosseLine				= FALSE
bDeathwishLine 			= FALSE
bFirstTimeFollowed		= FALSE
bKessokFollowed			= FALSE
bMultipleFollowers		= FALSE
bFirstTimeInXi5			= FALSE
bStarbaseCritical		= FALSE
bGeronimoDamaged		= FALSE
bGeronimoCritical		= FALSE
bSanFranciscoCritical	= FALSE


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
	loadspacehelper.PreloadShip("CardStation", 1)
	loadspacehelper.PreloadShip("CommArray", 4)
	if Maelstrom.Maelstrom.bGeronimoAlive:
		loadspacehelper.PreloadShip("Geronimo", 1)
	if Maelstrom.Maelstrom.bZeissAlive:
		loadspacehelper.PreloadShip("Galaxy", 1)
	loadspacehelper.PreloadShip("CardFreighter", 4)
	loadspacehelper.PreloadShip("KessokHeavy", 1)
	loadspacehelper.PreloadShip("KessokLight", 1)
	loadspacehelper.PreloadShip("KessokMine", 24)
	loadspacehelper.PreloadShip("Galor", 13)
	loadspacehelper.PreloadShip("Keldon", 1)


#
#	Initialize() - Called to initialize our mission
#
def Initialize(pMission):
#	DebugPrint ("Initializing Episode 7, Mission 3.\n")

	# Check and see if we have a player, if we don't
	# we aren't linking and will have to call the initial
	# briefing "by hand" and the end of Initialize
	bHavePlayer = 0
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		bHavePlayer = 1

	# Set bMissionTerminate here so it sets value correctly
	# if mission is reloaded
	global bMissionTerminate
	bMissionTerminate = FALSE

	global pMissionDatabase, pMission1Database, pEpisodeDatabase, pMenuDatabase, pGeneralDatabase
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 7/E7M3.tgl")
	pMission1Database = pMission.SetDatabase("data/TGL/Maelstrom/Episode 7/E7M1.tgl")
	pEpisodeDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 7/Episode7.tgl")
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	# Specify (and load if necessary) our bridge
	LoadBridge.Load("SovereignBridge")

	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	# Create Liu and her set
#	DebugPrint("Create Liu and her set")

	MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet")
	
	MissionLib.SetupBridgeSet("FedOutpostSet", "data/Models/Sets/FedOutpost/fedoutpost.nif", -30, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Graff", "FedOutpostSet")

	# Create and load the Space Sets we'll need for this mission
	Systems.Starbase12.Starbase12.Initialize()
	pSet = Systems.Starbase12.Starbase12.GetSet()

	Systems.Poseidon.Poseidon2.Initialize()
	pPoseidon2Set = Systems.Poseidon.Poseidon2.GetSet()

	Systems.Artrus.Artrus3.Initialize()
	pArtrus3Set = Systems.Artrus.Artrus3.GetSet()

	Systems.Serris.Serris3.Initialize()
	pSerris3Set = Systems.Serris.Serris3.GetSet()

	Systems.Geble.Geble4.Initialize()
	pGeble4Set = Systems.Geble.Geble4.GetSet()

	Systems.Ascella.Ascella5.Initialize()
	pAsc5Set = Systems.Ascella.Ascella5.GetSet()

	Systems.Ascella.Ascella3.Initialize()
	pAsc3Set = Systems.Ascella.Ascella3.GetSet()

	Systems.XiEntrades.XiEntrades5.Initialize()
	pXiEnt5Set = Systems.XiEntrades.XiEntrades5.GetSet()

	CreateMenus()

	# Load our placements into this set
	Maelstrom.Episode7.E7M1.E7M1_P.LoadPlacements(pSet.GetName())
	XiEnt5_P.LoadPlacements(pXiEnt5Set.GetName())
	E7M3_P.LoadPlacements(pPoseidon2Set.GetName())
	E7M3_P.LoadPlacements(pSerris3Set.GetName())
	E7M3_P.LoadPlacements(pGeble4Set.GetName())
	E7M3_P.LoadPlacements(pArtrus3Set.GetName())	
	E7M5_P.LoadPlacements(pAsc5Set.GetName())
	Ascella3_P.LoadPlacements(pAsc3Set.GetName())

	# Create the ships and set their stats
#	DebugPrint ("Creating ships.\n")

	# Starbase 12 ships
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pSet, "player", "Enterprise Start")
	pStarbase = loadspacehelper.CreateShip( "FedStarbase", pSet, "Starbase 12", "Starbase Location" )

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	# Outposts
	pOutpost1 = loadspacehelper.CreateShip( "CommArray", pPoseidon2Set, "Sensor Post 1", "Outpost Location", 1)
	pOutpost2 = loadspacehelper.CreateShip( "CommArray", pArtrus3Set, "Sensor Post 2", "Outpost Location" )
	pOutpost3 = loadspacehelper.CreateShip( "CommArray", pSerris3Set, "Sensor Post 3", "Outpost Location" )
	pOutpost4 = loadspacehelper.CreateShip( "CommArray", pGeble4Set, "Sensor Post 4", "Outpost Location" )

	######################
	# Setup Affiliations #
	######################

	global pFriendlies, pEnemies, pHostileObjGroup, pEnemyTargets, pFreighterObjGroup, pDisabledFreighters, pFollowObjGroup

	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("USS Geronimo")
	pFriendlies.AddName("USS San Francisco")

	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Sensor Post 1")
	pEnemies.AddName("Sensor Post 2")
	pEnemies.AddName("Sensor Post 3")
	pEnemies.AddName("Sensor Post 4")
	pEnemies.AddName("Keldon1")
	pEnemies.AddName("Galor1")
	pEnemies.AddName("Galor2")
	pEnemies.AddName("Galor3")
	pEnemies.AddName("Galor4")
	pEnemies.AddName("KessokHeavy")
	pEnemies.AddName("KessokAttacker")
	pEnemies.AddName("GalorAttacker1")
	pEnemies.AddName("GalorAttacker2")
	pEnemies.AddName("Reinforcement1")
	pEnemies.AddName("Reinforcement2")
	pEnemies.AddName("Resupply Station")
	pEnemies.AddName("Freighter1")
	pEnemies.AddName("Freighter2")
	pEnemies.AddName("Freighter3")
	pEnemies.AddName("Freighter4")
	pEnemies.AddName("Attacker1")
	pEnemies.AddName("Attacker2")
	pEnemies.AddName("Attacker3")
	pEnemies.AddName("Attacker4")
	pEnemies.AddName("Attacker5")
	pEnemies.AddName("Attacker6")
	pEnemies.AddName("Defender1")
	pEnemies.AddName("Defender2")
	pEnemies.AddName("Defender3")
	pEnemies.AddName("Launcher1")
	pEnemies.AddName("Launcher2")
	pEnemies.AddName("Launcher3")
	pEnemies.AddName("Launcher4")
	pEnemies.AddName("Launcher5")
	pEnemies.AddName("Launcher6")
	pEnemies.AddName("Launcher7")
	pEnemies.AddName("Launcher8")
	pEnemies.AddName("Launcher9")
	pEnemies.AddName("Launcher10")
	pEnemies.AddName("Launcher11")
	pEnemies.AddName("Launcher12")
	pEnemies.AddName("Launcher13")
	pEnemies.AddName("Launcher14")
	pEnemies.AddName("Launcher15")
	pEnemies.AddName("Launcher16")
	pEnemies.AddName("Launcher17")
	pEnemies.AddName("Launcher18")
	pEnemies.AddName("Launcher19")
	pEnemies.AddName("Launcher20")
	pEnemies.AddName("Launcher21")
	pEnemies.AddName("Launcher22")
	pEnemies.AddName("Launcher23")
	pEnemies.AddName("Launcher24")

	pHostileObjGroup = App.ObjectGroup()
	pHostileObjGroup.AddName("Reinforcement1")
	pHostileObjGroup.AddName("Reinforcement2")
	pHostileObjGroup.AddName("Attacker1")
	pHostileObjGroup.AddName("Attacker2")
	pHostileObjGroup.AddName("Attacker3")
	pHostileObjGroup.AddName("Attacker4")
	pHostileObjGroup.AddName("Attacker5")
	pHostileObjGroup.AddName("Attacker6")
	pHostileObjGroup.AddName("Defender1")
	pHostileObjGroup.AddName("Defender2")
	pHostileObjGroup.AddName("Defender3")

	pFreighterObjGroup = App.ObjectGroup()
	pFreighterObjGroup.AddName("Freighter1")
	pFreighterObjGroup.AddName("Freighter2")
	pFreighterObjGroup.AddName("Freighter3")
	pFreighterObjGroup.AddName("Freighter4")

	pDisabledFreighters = App.ObjectGroup()

	# Make a new group to serve as a target list for AI's..
	pEnemyTargets = App.ObjectGroup()
	pEnemyTargets.AddName("Keldon1")
	pEnemyTargets.AddName("Galor1")
	pEnemyTargets.AddName("Galor2")
	pEnemyTargets.AddName("Galor3")
	pEnemyTargets.AddName("Galor4")
	pEnemyTargets.AddName("KessokHeavy")
	pEnemyTargets.AddName("KessokAttacker")
	pEnemyTargets.AddName("GalorAttacker1")
	pEnemyTargets.AddName("GalorAttacker2")
	pEnemyTargets.AddName("Reinforcement1")
	pEnemyTargets.AddName("Reinforcement2")
	pEnemyTargets.AddName("Attacker1")
	pEnemyTargets.AddName("Attacker2")
	pEnemyTargets.AddName("Attacker3")
	pEnemyTargets.AddName("Attacker4")
	pEnemyTargets.AddName("Attacker5")
	pEnemyTargets.AddName("Attacker6")
	pEnemyTargets.AddName("Defender1")
	pEnemyTargets.AddName("Defender2")
	pEnemyTargets.AddName("Defender3")
	pEnemyTargets.AddName("Launcher1")
	pEnemyTargets.AddName("Launcher2")
	pEnemyTargets.AddName("Launcher3")
	pEnemyTargets.AddName("Launcher4")
	pEnemyTargets.AddName("Launcher5")
	pEnemyTargets.AddName("Launcher6")
	pEnemyTargets.AddName("Launcher7")
	pEnemyTargets.AddName("Launcher8")
	pEnemyTargets.AddName("Launcher9")
	pEnemyTargets.AddName("Launcher10")
	pEnemyTargets.AddName("Launcher11")
	pEnemyTargets.AddName("Launcher12")
	pEnemyTargets.AddName("Launcher13")
	pEnemyTargets.AddName("Launcher14")
	pEnemyTargets.AddName("Launcher15")
	pEnemyTargets.AddName("Launcher16")
	pEnemyTargets.AddName("Launcher17")
	pEnemyTargets.AddName("Launcher18")
	pEnemyTargets.AddName("Launcher19")
	pEnemyTargets.AddName("Launcher20")
	pEnemyTargets.AddName("Launcher21")
	pEnemyTargets.AddName("Launcher22")
	pEnemyTargets.AddName("Launcher23")
	pEnemyTargets.AddName("Launcher24")

	# This group will contain any ships that are following you
	pFollowObjGroup = App.ObjectGroup()

	# Set Starbase 12 AI
	pStarbase.SetAI(StarbaseAI.CreateAI(pStarbase))	

	# Setup more mission-specific events.
	SetupEventHandlers(pMission)

	# If the player was created from scratch, call our initial briefing
	if (bHavePlayer == 0):
		Briefing()

	MissionLib.SaveGame("E7M3-")

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetTotalTorpsAtStarbase("Quantum", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)
	MissionLib.SetMaxTorpsForPlayer("Quantum", 60)


################################################################################
#	InitializeCrewPointers()
#
#	Initializes the global pointers to the bridge crew members.
#	NOTE: This must be called after the bridge is loaded.
#
#	Args:	None
#
#	Return:	None
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
	
	global g_pSaffiMenu
	global g_pFelixMenu
	global g_pKiskaMenu
	global g_pMiguelMenu
	global g_pBrexMenu
	
	g_pSaffiMenu = g_pSaffi.GetMenu()
	g_pFelixMenu = g_pFelix.GetMenu()
	g_pKiskaMenu = g_pKiska.GetMenu()
	g_pMiguelMenu = g_pMiguel.GetMenu()
	g_pBrexMenu = g_pBrex.GetMenu()


################################################################################
#	DebugPrint(pcString)
#
#	Wrapper for print function that checks debug flag.
#
#	Args:	pcString, string to print.
#
#	Return:	None
################################################################################
def DebugPrint(pcString):
	if(bDebugPrint):
		print(pcString)


########################################
# Setup up Warp Menu Buttons for Helm  #
###############################	########

def CreateMenus():		
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
	pSBMenu.SetMissionName("Maelstrom.Episode7.E7M3.E7M3")


#
# SetupEventHandlers()
#
def SetupEventHandlers(pMission):
	#Setup any event handlers to listen for broadcast events that we'll need."

	# Exit warp event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_WARP, pMission, __name__ + ".ExitWarp")
	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ + ".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ + ".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ + ".ObjectDestroyed")
	# Ship exploding event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectExploding")

	# Instance handler for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")

	# Contact Starfleet event
	g_pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	# Instance handler for Miguel's Scan Area button
	g_pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	# Instance handler for Kiska's dock button
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_DOCK, __name__+ ".DockHandler")
	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	# Hail event
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

#	DebugPrint("Adding Crew Communicate Handlers")
	# Communicate with Saffi event
	g_pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Felix event
	g_pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Kiska event
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Miguel event
	g_pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Brex event
	g_pBrexMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

############################
#Mission Related Functions #
############################

#
# CommunicateHandler()
#
def CommunicateHandler(pObject, pEvent):
#	DebugPrint("Communicating with crew")

	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())
	pPlayer = MissionLib.GetPlayer()
	if not pPlayer or not pMenu:
		return
	pSet = pPlayer.GetContainingSet()

	pAction = 0

	if (pMenu.GetObjID() == g_pSaffiMenu.GetObjID()):
#		DebugPrint("Communicating with Saffi")

		if (pSet.GetName() == "Starbase12") and (iEnemiesFollowing > 0): 
			if bStarbaseCritical:
#				DebugPrint("The Starbase is critical")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi5", None, 0, pMissionDatabase)

			elif Maelstrom.Maelstrom.bGeronimoAlive and bGeronimoCritical and bRescuedGeronimo:
#				DebugPrint("The Geronimo is critical")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi6", None, 0, pMissionDatabase)

			elif Maelstrom.Maelstrom.bZeissAlive and bZeissPresent and bSanFranciscoCritical:
#				DebugPrint("The San Francisco is critical")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi7", None, 0, pMissionDatabase)

			else:
#				DebugPrint("Make our stand here")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi4", None, 0, pMissionDatabase)

		elif Maelstrom.Maelstrom.bGeronimoAlive and bDistressCallPlayed and not bFirstTimeInXi5 and not bRescuedGeronimo:
#			DebugPrint("We should rescue the Geronimo")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4Prod1", None, 0, pMissionDatabase)

		elif Maelstrom.Maelstrom.bGeronimoAlive and bGeronimoCritical and bXiEnt5Arrive:
#			DebugPrint("The Geronimo is critical")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi6", None, 0, pMissionDatabase)

		elif not (pSet.GetName() == "XiEntrades5"):
			if (iOutpostsDestroyed == 0):
#				DebugPrint("We should destroy the sensor posts")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi1", None, 0, pMissionDatabase)
	
			elif not (iOutpostsDestroyed == iOutposts):
#				DebugPrint("Still more sensor posts to destroy")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi2", None, 0, pMissionDatabase)
	
			elif not bResupplyDestroyed:
#				DebugPrint("We should destroy the resupply station")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi3", None, 0, pMissionDatabase)

			else:
#				DebugPrint("We should return to Starbase 12")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateSaffi8", None, 0, pMissionDatabase)

	elif (pMenu.GetObjID() == g_pKiskaMenu.GetObjID()):
#		DebugPrint("Communicating with Kiska")

		if Maelstrom.Maelstrom.bGeronimoAlive and bDistressCallPlayed and not bFirstTimeInXi5 and not bRescuedGeronimo:
#			DebugPrint("We should rescue the Geronimo")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateKiska1", None, 0, pMissionDatabase)

		elif bResupplyDestroyed and (iOutpostsDestroyed == iOutposts):
#			DebugPrint("We should return to Starbase 12")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateKiska2", None, 0, pMissionDatabase)

	elif (pMenu.GetObjID() == g_pFelixMenu.GetObjID()):
#		DebugPrint("Communicating with Felix")

		if (pSet.GetName() == "Ascella3") and not bResupplyDestroyed:
			if bStationAlert and not bDisruptorsGone:
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateFelix2", None, 0, pMissionDatabase)

			elif not bStationAlert:
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateFelix3", None, 0, pMissionDatabase)

		elif bGeb4Defenders and not bKessokRepairGone:
			# Make sure player and Kessok are in the same set
			pGame = App.Game_GetCurrentGame()
			pKessok = App.ShipClass_GetObject( App.SetClass_GetNull(), "KessokHeavy")
			pKessokSetName = pKessok.GetContainingSet().GetName()

			if (pSet.GetName() == pKessokSetName):
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateFelix1", None, 0, pMissionDatabase)

	elif (pMenu.GetObjID() == g_pMiguelMenu.GetObjID()):
#		DebugPrint("Communicating with Miguel")

		if (pSet.GetName() == "Starbase12") and (iEnemiesFollowing > 0): 
			if bStarbaseCritical:
#				DebugPrint("The Starbase is critical")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateMiguel1", None, 0, pMissionDatabase)

			elif Maelstrom.Maelstrom.bGeronimoAlive and bGeronimoCritical and bRescuedGeronimo:
#				DebugPrint("The Geronimo is critical")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateMiguel2", None, 0, pMissionDatabase)

			elif Maelstrom.Maelstrom.bZeissAlive and bZeissPresent and bSanFranciscoCritical:
#				DebugPrint("The San Francisco is critical")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateMiguel3", None, 0, pMissionDatabase)

		elif not (pSet.GetName() == "Ascella3") and not bResupplyDestroyed and not (iOutpostsDestroyed == iOutposts):
#			DebugPrint("We should destroy the sensor posts")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateMiguel4", None, 0, pMissionDatabase)

		elif (pSet.GetName() == "Ascella3") and not (iOutpostsDestroyed == iOutposts) and not bResupplyDestroyed:
#			DebugPrint("I have a bad feeling about this")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateMiguel5", None, 0, pMissionDatabase)

		elif (pSet.GetName() == "Ascella3") and (iOutpostsDestroyed == iOutposts) and not bFreighterDisabled:
#			DebugPrint("We should disable a Freighter")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateMiguel6", None, 0, pMissionDatabase)

	elif (pMenu.GetObjID() == g_pBrexMenu.GetObjID()):
#		DebugPrint("Communicating with Brex")

		if (pSet.GetName() == "Ascella3") and not bResupplyDestroyed and not (pPlayer.GetImpulseEngineSubsystem().GetNormalPowerPercentage() > 1):
			if bStationAlert and not bDisruptorsGone:
#				DebugPrint("We should boost power to Engines")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateBrex1", None, 0, pMissionDatabase)

			else:
#				DebugPrint("We should target the station's power core")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M3CommunicateBrex2", None, 0, pMissionDatabase)

	if pAction:
		pAction.Play()

	else:
#		DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)


#
# HailHandler()
#
def HailHandler(pObject, pEvent):
#	DebugPrint("Handling Hail")

	pPlayer = MissionLib.GetPlayer()
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if not (pTarget):
		pTarget = pPlayer.GetTarget()
	
	if pTarget == None:
		return
	
	sTarget = pTarget.GetName()

	pSequence = Bridge.HelmMenuHandlers.GetHailSequence()
	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (sTarget == "Starbase 12"):
		pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
		pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
		pSequence.AppendAction(pAction)

		if iEnemiesFollowing == 0:
			# Good luck on your mission
			pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M3Follow33", None, 0, pMissionDatabase)

		else:
			# Defeat the attackers
			pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M3Follow32", None, 0, pMissionDatabase)

	elif (sTarget == "USS San Francisco"):
		pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
		pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)

		if iEnemiesFollowing == 0:
			# It's been fun, but duty calls
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E7M3Follow29", None, 0, pMissionDatabase)

			global bZeissLine
			bZeissLine = TRUE

		else:
			# We can take 'em
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E7M3HailingZeiss", None, 0, pMissionDatabase)

	elif (sTarget == "USS Geronimo"):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)

		if not bRescuedGeronimo:
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4Rescue4", None, 0, pMissionDatabase)

		else:
			pSet = pPlayer.GetContainingSet()

			if (pSet.GetName() == "Poseidon2") and not (bMinesActive == FALSE):
				pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines18", None, 0, pMissionDatabase)

			else:
				iNum = App.g_kSystemWrapper.GetRandomNumber(2)

				if iNum == 1:
					pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3ArtrusMacCray1", None, 0, pMissionDatabase)

				else:
					pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3SerrisMacCray1", None, 0, pMissionDatabase)

	else:
#		DebugPrint("Nothing Special to handle")

		pSequence.Completed()
		pObject.CallNextHandler(pEvent)

		return

	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# WarpHandler()
#
def WarpHandler(pObject, pEvent):
#	DebugPrint("Handling Warp")

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	if (pPlayerSetName == "Starbase12") and (iEnemiesFollowing > 0):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3Follow18", "Captain", 1, pMissionDatabase)
		pAction.Play()

		return

	elif (pPlayerSetName == "XiEntrades5") and (bRescuedGeronimo == FALSE):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4Prod2", "Captain", 1, pMissionDatabase)
		pAction.Play()

		return

	pObject.CallNextHandler(pEvent)


#
#	DockHandler()
#
def DockHandler(pObject, pEvent):
#	DebugPrint("Docking with Starbase 12")

	if MissionLib.NumGroupInSet(pEnemies) > 0:
		pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
		pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M3Follow32b", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	else:
		pObject.CallNextHandler(pEvent)


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
	sShipName = pShip.GetName()
	
	# If its the Starbase, have Graff complain the first time
	if (sShipName == "Starbase 12") and (g_bGraffWarned == FALSE):
#		DebugPrint("Graff warns you about hitting Starbase")

		global g_bGraffWarned
		g_bGraffWarned = TRUE

		pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
		pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow27", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M3HitStarbase", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "USS Geronimo") and (bGeronimoAttackWait == FALSE) and (iGeronimoHit < 3):
#		DebugPrint("MacCray warns you about hitting the Geronimo")

		global iGeronimoHit, bGeronimoAttackWait
		iGeronimoHit = iGeronimoHit + 1
		bGeronimoAttackWait = TRUE

		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)

		if (iGeronimoHit == 1):
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3HitGeronimo1", None, 0, pMissionDatabase)

		elif (iGeronimoHit == 2):
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3HitGeronimo2", None, 0, pMissionDatabase)

		elif (iGeronimoHit == 3):
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3HitGeronimo3", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		# Create a Timer that resets Geronimo's attack handler
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_RESET_GERONIMO, __name__ + ".ResetGeronimoHit", fStartTime + 20, 0, 0)

		return

	elif (sShipName == "USS San Francisco") and (g_bZeissWarned == FALSE):
#		DebugPrint("Zeiss warns you about hitting the San Francisco")

		global g_bZeissWarned
		g_bZeissWarned = TRUE

		pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
		pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

		pSequence = App.TGSequence_Create()
	
		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow21", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E7M3HitSanFrancisco", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)


#
#	ResetGeronimoHit() 
#
def ResetGeronimoHit(pObject, pEvent):
#	DebugPrint("Resetting Geronimo Attack handler")

	global bGeronimoAttackWait
	bGeronimoAttackWait = FALSE


################################################################################
#	DistressCallDialogue()
#
#	Set station to Red Alert, give it AI.
#	Play dialogue for station sending out distress call.
#
#	Args:	None
#
#	Return:	None
################################################################################
def DistressCallDialogue():
#	DebugPrint("DistressCallDialogue() called.")

	if (bResupplyDestroyed == FALSE):
		# Get bridge characters.
	
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)	

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L028", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L029", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M5L030", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		
		MissionLib.QueueActionToPlay(pSequence)


################################################################################
#	ReinforcementsArrived()
#
#	Play dialogue for Cardassian reinforcements entering system.
################################################################################
def ReinforcementsArrived(pAction):
	if (bReinforcements == FALSE):
		global bReinforcements
		bReinforcements = TRUE

		pSet = App.g_kSetManager.GetSet("Ascella3")
		pReinforcement1 = loadspacehelper.CreateShip("Galor", pSet, "Reinforcement1", "Reinforcement 1 Start", 1)
		pReinforcement2 = loadspacehelper.CreateShip("Galor", pSet, "Reinforcement2", "Reinforcement 2 Start", 1)

		pReinforcement1.SetAI(EnemyAI.CreateAI(pReinforcement1))
		pReinforcement2.SetAI(EnemyAI.CreateAI(pReinforcement2))

		# Get bridge characters.
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L036", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L037", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pSequence.Play()

	return 0


################################################################################
#	AreAllHostilesDestroyed()
#
#	Check if all hostile ships(Cardassian warships) have been destroyed. 
#	This is evaluated differently based on mission branch, wether outposts
#	have been destroyed or not determines number of hostiles.
#
#	Args:	None
#
#	Return:	TRUE if all destroyed, FALSE otherwise.
################################################################################
def AreAllHostilesDestroyed():
	# If all outposts were destroyed.
	if (iOutpostsDestroyed == iOutposts):
		if(iNumHostilesDestroyed == iNumSurpriseHostiles):
			return TRUE
	# Not all outposts destroyed.
	else:
		if(iNumHostilesDestroyed == iNumAmbushHostiles):
			return TRUE

	return FALSE


################################################################################
#	PlayHostilesDialogue()
#
#	Play dialogue lines for all Cardassian warships being destroyed.
#
#	Args:	None
#
#	Return:	None
################################################################################
def PlayHostilesDialogue():
#	DebugPrint("Playing hostiles dialogue.")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L038", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	# If Geronimo is still alive, MacCray will talk.
	if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
#		print "MacCray Alive and saying dialogue."
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M5L039", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	MissionLib.QueueActionToPlay(pSequence)


################################################################################
#	StationRedAlert(TGObject, pEvent):
#
#	Set Station to Red Alert.
#
#	Args:	None
#
#	Return:	None
################################################################################
def StationRedAlert(TGObject, pEvent):
#	DebugPrint("Station going to Red Alert")

	if (bStationAlert == FALSE) and (bResupplyDestroyed == FALSE):
		global bStationAlert
		bStationAlert = TRUE
		
		# Get Cardassina resupply station in Ascella 3.
		pSet = App.g_kSetManager.GetSet("Ascella3")
		if pSet:
			pBase = MissionLib.GetShip("Resupply Station", pSet)
		
			# Set it to Red Alert.	
			if pBase:
				pBase.SetAlertLevel(App.ShipClass.RED_ALERT)

		# Get bridge characters.
		pSequence = App.TGSequence_Create()

		# Have Miguel say it's raised shields.	
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M5L045", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ReinforcementsArrived")
		pSequence.AppendAction(pAction, 5)
	
		MissionLib.QueueActionToPlay(pSequence)

 
################################################################################
#	Ascella3Arrive()
#
#	Called when player's ship first enters Ascella 3 Region.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Ascella3Arrive():

	# If all sensor outposts were destroyed, create ships still docked to station.
	if (iOutpostsDestroyed == iOutposts):
		pSet = App.g_kSetManager.GetSet("Ascella3")

		# Set Freighters escaped Episode global variable to zero to start
		Maelstrom.Episode7.Episode7.iNumFreightersEscaped = 0

		pFreighter1 = loadspacehelper.CreateShip("CardFreighter", pSet, "Freighter1", "Freighter 1 Start")
		pFreighter2 = loadspacehelper.CreateShip("CardFreighter", pSet, "Freighter2", "Freighter 2 Start")
		pFreighter3 = loadspacehelper.CreateShip("CardFreighter", pSet, "Freighter3", "Freighter 3 Start")
		pFreighter4 = loadspacehelper.CreateShip("CardFreighter", pSet, "Freighter4", "Freighter 4 Start")
		pDefender1 = loadspacehelper.CreateShip("Galor", pSet, "Defender1", "Defender 1 Start")
		pDefender2 = loadspacehelper.CreateShip("Galor", pSet, "Defender2", "Defender 2 Start")
		pDefender3 = loadspacehelper.CreateShip("Galor", pSet, "Defender3", "Defender 3 Start")

		# Add Instance Handlers to detect if Freighter's Warp, Impulse or shields are disabled
		pFreighter1.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".DisableSystemHandler")
		pFreighter2.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".DisableSystemHandler")
		pFreighter3.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".DisableSystemHandler")
		pFreighter4.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".DisableSystemHandler")

		# Set power up delays for Freighters.
		fFreighter1Delay = 120
		fFreighter2Delay = 150
		fFreighter3Delay = 180
		fFreighter4Delay = 210

		# Set freighter AI.
		pFreighter1.SetAI(FreighterAI.CreateAI(pFreighter1, "Freighter 1 Way", fFreighter1Delay))
		pFreighter2.SetAI(FreighterAI.CreateAI(pFreighter2, "Freighter 2 Way", fFreighter2Delay))
		pFreighter3.SetAI(FreighterAI.CreateAI(pFreighter3, "Freighter 3 Way", fFreighter3Delay))
		pFreighter4.SetAI(FreighterAI.CreateAI(pFreighter4, "Freighter 4 Way", fFreighter4Delay))

		# Disable collisions between the the Freighters and Resupply Station
		pBase = MissionLib.GetShip("Resupply Station", pSet)
		if pBase:
			pBase.EnableCollisionsWith(pFreighter1, 0)
			pBase.EnableCollisionsWith(pFreighter2, 0)
			pBase.EnableCollisionsWith(pFreighter3, 0)
			pBase.EnableCollisionsWith(pFreighter4, 0)

		# Set power up delays for Defenders.
		fDefender1Delay = 90
		fDefender2Delay = 95
		fDefender3Delay = 100

		# Set galor AI.
		pDefender1.SetAI(DefenderAI.CreateAI(pDefender1, "Defender 1 Way", fDefender1Delay))
		pDefender2.SetAI(DefenderAI.CreateAI(pDefender2, "Defender 2 Way", fDefender2Delay))
		pDefender3.SetAI(DefenderAI.CreateAI(pDefender3, "Defender 3 Way", fDefender3Delay))

		SurpriseCardassians()

	else:
		# Not all sensor outposts destroyed.  Player is detected...
		PlayerDetected()


#
#	DisableSystemHandler()
#
def DisableSystemHandler(pObject, pEvent):

	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if not pShip:
		return

	sShipName = pShip.GetName()

	bStopFollowFlag = 0

	# Make sure Event Source is valid, so the game won't crash when I do a GetObjID
	if not (pEvent.GetSource() == None): 
		# Make sure the subsystem is valid, so the game won't crash when I do a GetObjID
		if not (pShip.GetImpulseEngineSubsystem() == None):
			if (pEvent.GetSource().GetObjID() == pShip.GetImpulseEngineSubsystem().GetObjID()):
#				DebugPrint ("Ship's Impulse Engines Gone.")

				bStopFollowFlag = 1

		if not (pShip.GetWarpEngineSubsystem() == None):
			if (pEvent.GetSource().GetObjID() == pShip.GetWarpEngineSubsystem().GetObjID()):
#				DebugPrint ("Ship's Warp Engines Gone.")

				bStopFollowFlag = 1

		if (bStopFollowFlag == 1) and (sShipName[:len("Freighter")] == "Freighter") and not (pDisabledFreighters.IsNameInGroup(sShipName)):
			FreighterDisabled(sShipName)

		if (sShipName == "KessokHeavy"):
			if not (pShip.GetRepairSubsystem() == None):
				if (pEvent.GetSource().GetObjID() == pShip.GetRepairSubsystem().GetObjID()):
#					DebugPrint ("Kessok's Repair System Disabled.")
					global bKessokRepairGone
					bKessokRepairGone = TRUE

		if (sShipName == "Resupply Station"):
			if not (pShip.GetPulseWeaponSystem() == None):
				if (pEvent.GetSource().GetObjID() == pShip.GetPulseWeaponSystem().GetObjID()):
#					DebugPrint ("Station's Disruptor System Disabled.")
					global bDisruptorsGone
					bDisruptorsGone = TRUE

	if not (pShip.GetContainingSet() == None):
		if not (pShip.GetContainingSet().GetName() == "Starbase12"):
			if (bStopFollowFlag == 1) and (pFollowObjGroup.IsNameInGroup(pObject.GetName())):
				global pFriendlies, iEnemiesFollowing, iEnemiesStillFollowing
				pFollowObjGroup.RemoveName(pShip.GetName())
				iEnemiesFollowing = iEnemiesFollowing - 1
				iEnemiesStillFollowing = iEnemiesStillFollowing - 1
				if iEnemiesFollowing == 0:
					global bMultipleFollowers, iMakeAStandLine
					bMultipleFollowers = FALSE
					iMakeAStandLine = 0
	
				g_pFelix.SayLine(pMissionDatabase, "E7M3Follow41", "Captain", 1)


#
#	FreighterDisabled()
#
def FreighterDisabled(sFreighter):

	if sFreighter == None:
		return

	pFreighter = MissionLib.GetShip(sFreighter)

	if pFreighter == None:
		return

#	DebugPrint (sFreighter + " disabled.")	

	# Make Freighter stay put
	pFreighter.ClearAI()

	global pDisabledFreighters
	pDisabledFreighters.AddName(sFreighter)

	global bFreighterDisabled
	bFreighterDisabled = TRUE

	# Disable any systems that would allow the Freighter to escape
	pSystem = pFreighter.GetWarpEngineSubsystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, pSystem.GetDisabledPercentage())
	pSystem = pFreighter.GetImpulseEngineSubsystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, pSystem.GetDisabledPercentage())
	pSystem = pFreighter.GetRepairSubsystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0)

	iNum = App.g_kSystemWrapper.GetRandomNumber(2)
	if iNum == 1:
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3DisableFreighter1", None, 0, pMissionDatabase)

	else:
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3DisableFreighter2", None, 0, pMissionDatabase)

	pAction.Play()


################################################################################
#	SurpriseCardassians()
#
#	Player surprises Cardassians at Ascella 3.
#	Create Cardassian reinforcements which warp in after a few minutes.
#	Play dialogue sequence with bridge crew and MacCray if still alive.
#	Ship AI's have already been set for the docked ships.
#	Give Geronimo AI to engage enemy.
#
#	Args:	None
#
#	Return:	None
################################################################################
def SurpriseCardassians():
	# Create timer to trigger station going into Red Alert.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_STATION_ALERT_TIMER, __name__+ ".StationRedAlert", fStartTime + 180, 0, 0)

	# Get Cardassina resupply station in Ascella 3.
	pAscella3Set = App.g_kSetManager.GetSet("Ascella3")
	pBase = MissionLib.GetShip("Resupply Station", pAscella3Set)
	
	# Setup it's AI, starts off with shields down, delays defense.
	if pBase:
		pBase.SetAlertLevel(App.ShipClass.GREEN_ALERT)
		pBase.SetAI(BaseAI.CreateAI(pBase))

	# Create dialogue sequence.
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "TargetStation")
	pSequence.AddAction(pAction, None, 10.0)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L015", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L016", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L017", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M5L018", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L019", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	# If Geronimo is still alive, MacCray will join in to conversation.
	if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")
		# Get MacCray on viewscreen.
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M5L020", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		
		# Give Geronimo AI for it to engage the enemy.
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "GeronimoEngage"))

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L031", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M5L032", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M5L033", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L034", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


################################################################################
#	PlayerDetected()
#
#	Player was detected before getting to Ascella 3.
#	Play dialogue sequence with bridge crew and MacCray(if still alive).
#	Create Cardassian ships to "ambush" player.
#	Give Geronimo AI to engage enemy.
#
#	Args:	None
#
#	Return:	None
################################################################################
def PlayerDetected():
	# Add attacking ships to enemy group.
	pMission = MissionLib.GetMission()
	assert pMission
	if(pMission is None):
		return

	global bStationAlert
	bStationAlert = TRUE

	# Create dialogue sequence.
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "TargetStation")
	pSequence.AppendAction(pAction, 10)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L003", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M5L004", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L005", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M5L006", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	# If Geronimo is still alive, MacCray will join in to conversation.
	if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		# Get MacCray on viewscreen.
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M5L007", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L008", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	# Saffi's lines.
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L009", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	# If Geronimo is still alive, MacCray will join in to conversation.
	if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
		# Create dialogue sequence.
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M5L010", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

		# Give Geronimo AI for it to engage the enemy.
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "GeronimoEngage"))

	# Create Cardassian ships and begin their attack.
	pAction = App.TGScriptAction_Create(__name__, "CardassianAttackTimer")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


################################################################################
#	GeronimoEngage(pAction)
#
#	Give Geronimo AI to engage the enemy.
#	This is a generic AI that will follow waypoints during which dialogue
#	will play and immediately after will engage the enemy. The list of enemies
#	this AI chooses to attack first is in the global pEnemies group, after
#	those it will attack the resupply station.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def GeronimoEngage(pAction):
	pGeronimo = MissionLib.GetShip("USS Geronimo")
	if pGeronimo:
		pGeronimo.SetAI(GeronimoAI.CreateAI(pGeronimo))

	return 0

#
#	CardassianAttackTimer() - Starts the timer to ambush player
#
def CardassianAttackTimer(pAction):
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	# Create a Timer that triggers the KessokInfo Function
	MissionLib.CreateTimer(ET_CARD_ATTACK, __name__ + ".CardassianAttack", fStartTime + 15, 0, 0)

	return 0


#
#	CardassianAttack() - Cardassians ambush player
#
def CardassianAttack(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pSet = pGame.GetPlayerSet()
	if not pSet:
		return

	if not (pSet.GetName() == "Ascella3"):
		return

	if iAttackWave > 4:
		return

	pBase = MissionLib.GetShip("Resupply Station", pSet)

	# Setup station AI, starts off in red alert, defenses ready.
	if pBase:
		pBase.SetAlertLevel(App.ShipClass.RED_ALERT)
		pBase.SetAI(BaseAI2.CreateAI(pBase))

	global iAttackWave
	iAttackWave = iAttackWave + 1

	bFelixWarn = 0

	fStartTime = App.g_kUtopiaModule.GetGameTime()
	# Create timer for next wave of ships
	MissionLib.CreateTimer(ET_CARD_ATTACK, __name__ + ".CardassianAttack", fStartTime + 75, 0, 0)

	if iAttackWave == 1:
		pDefender1 = loadspacehelper.CreateShip("Galor", pSet, "Defender1", "Attacker 1 Start", 1)
		pDefender2 = loadspacehelper.CreateShip("Galor", pSet, "Defender2", "Attacker 2 Start", 1)
		pDefender3 = loadspacehelper.CreateShip("Galor", pSet, "Defender3", "Attacker 3 Start", 1)
	
		pDefender1.SetAI(EnemyAI.CreateAI(pDefender1))
		pDefender2.SetAI(EnemyAI.CreateAI(pDefender2))
		pDefender3.SetAI(EnemyAI.CreateAI(pDefender3))

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L011", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L012", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
	
		# If Geronimo is still alive, MacCray will join in to conversation.
		if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
			pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M5L013", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L014", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif iAttackWave == 2:
		pSet = App.g_kSetManager.GetSet("Serris3")
		if bSer3Defenders:
			pShip = App.ShipClass_GetObject(pSet, "Galor2")
			if pShip:
				bFelixWarn = 1
				FollowPlayer("Galor2")
	
			pShip = App.ShipClass_GetObject(pSet, "Galor3")
			if pShip:
				bFelixWarn = 1
				FollowPlayer("Galor3")
	
			pShip = App.ShipClass_GetObject(pSet, "Galor4")
			if pShip:
				bFelixWarn = 1
				FollowPlayer("Galor4")

		else:
			bFelixWarn = 1
			CreateSensorDefenders(pSet, 1)

		if bFelixWarn:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L046", None, 0, pMissionDatabase)
			pAction.Play()

	elif iAttackWave == 3:
		pSet = App.g_kSetManager.GetSet("Artrus3")
		if bArt3Defenders:
			pShip = App.ShipClass_GetObject(pSet, "Keldon1")
			if pShip:
				bFelixWarn = 1
				FollowPlayer("Keldon1")
	
			pShip = App.ShipClass_GetObject(pSet, "Galor1")
			if pShip:
				bFelixWarn = 1
				FollowPlayer("Galor1")
	
		else:
			bFelixWarn = 1
			CreateSensorDefenders(pSet, 1)

		if bFelixWarn:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L046", None, 0, pMissionDatabase)
			pAction.Play()

	elif iAttackWave == 4:
		pSet = App.g_kSetManager.GetSet("Geble4")
		if bGeb4Defenders:
			pShip = App.ShipClass_GetObject(pSet, "KessokHeavy")
			if pShip:
				bFelixWarn = 1
				FollowPlayer("KessokHeavy")

		else:
			bFelixWarn = 1
			CreateSensorDefenders(pSet, 1)

		if bFelixWarn:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L046", None, 0, pMissionDatabase)
			pAction.Play()


################################################################################
#	FreighterPoweredUp()
#
#	Play Felix's line saying that the first Freighter has powered up.
#
#	Args:	none
#
#	Return:	none
################################################################################
def FreighterPoweredUp(pcName):
#	DebugPrint(pcName + " PoweredUp")

	if not bResupplyDestroyed:
		global bFreighterPoweredUp
	
		pAction = None
		
		# If no freighters powered up yet, say first line.
		if(not bFreighterPoweredUp):
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M5L021", "Captain", 1, pMissionDatabase)
			bFreighterPoweredUp = TRUE
		# One has powered up, say, "another powered up" line.
		else:
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M5L022", "Captain", 1, pMissionDatabase)

		if(pAction):
			pAction.Play()


################################################################################
#	FreighterWarpedOut()
#
#	Play Felix's line saying that a Freighter has warped out.
#
#	Args:	none
#
#	Return:	none
################################################################################
def FreighterWarpedOut():
	if(Maelstrom.Episode7.Episode7.iNumFreightersEscaped == 4):
		return
		
	pFelixLine = None
	
	# If we're the first freighter warping.
	# Play the "One of the freighters warping out" line.
	if(Maelstrom.Episode7.Episode7.iNumFreightersEscaped == 0):
		pFelixLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L025", "Captain", 1, pMissionDatabase)
	# If we're not the last freighter warping.
	# Play the "Another freighter warping out" line.
	elif(Maelstrom.Episode7.Episode7.iNumFreightersEscaped < 3):
		pFelixLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L026", "Captain", 1, pMissionDatabase)
	# We're the last freighter warping.
	# Play the "The last of the freighters has warped" line.
	else:
		pFelixLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L027", "Captain", 1, pMissionDatabase)

	# Play Felix line.
	if(pFelixLine):
		pFelixLine.Play()

	# Increment Episode global Freighters escaped variable.
	Maelstrom.Episode7.Episode7.iNumFreightersEscaped = Maelstrom.Episode7.Episode7.iNumFreightersEscaped + 1


################################################################################
#	DefenderPoweredUp()
#
#	Play Felix's line saying that a Galor has powered up.
#
#	Args:	none
#
#	Return:	none
################################################################################
def DefenderPoweredUp(pcName):
#	DebugPrint("Defender " + pcName + " PoweredUp")

	if not bResupplyDestroyed and not bGalorPoweredUp:
		global bGalorPoweredUp
		bGalorPoweredUp = TRUE

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L023", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M5L024", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)
		
	
################################################################################
#	TargetStation(pAction)
#
#	Action to target the resupply station.
#
#	Args:	pAction, current action.
#
#	Return:	None
################################################################################
def TargetStation(pAction):

	pPlayer = MissionLib.GetPlayer()

	# Target the Station if the Player has no target
	if pPlayer:
		pTarget = pPlayer.GetTarget()
		if pTarget == None:
			pPlayer.SetTarget("Resupply Station")

	return 0


#
# ScanHandler()
#
def ScanHandler(pObject, pEvent):
#	DebugPrint("Scanning")

	pPlayer = MissionLib.GetPlayer()
	if pPlayer == None:
		return
	pSet = pPlayer.GetContainingSet()

	iScanType = pEvent.GetInt()

	pSequence = Bridge.ScienceCharacterHandlers.GetScanSequence()

	if not (pSequence):
		return

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (iScanType == App.CharacterClass.EST_SCAN_OBJECT):
#		DebugPrint("Scanning Target")

		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
			pTarget = pPlayer.GetTarget()
	
		if pTarget == None:
			pSequence.Completed()
			pObject.CallNextHandler(pEvent)
			return
	
		sTarget = pTarget.GetName()

		if (sTarget[:len("Freighter")] == "Freighter"):
			if (bFreighterDisabled == FALSE):
#				DebugPrint("Can't scan past dampening field")
	
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3ScanFreighter1", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif bFreighterDisabled == TRUE:
				# Look through DisabledFreighterList for our freighter

				if pDisabledFreighters.IsNameInGroup(sTarget):
#						DebugPrint("Scanning a disabled frieghter first time")
					global bFreighterDisabled
					bFreighterDisabled = -1
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3ScanFreighter2", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3ScanFreighter3", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3ScanFreighter4", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

			else:
#				DebugPrint("Nothing new detected.")
			
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanNothing", "Captain", 1, pMission1Database)
				pSequence.AppendAction(pAction)

		else:
#			DebugPrint("Nothing new detected.")
			
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanNothing", "Captain", 1, pMission1Database)
			pSequence.AppendAction(pAction)

	else:
#		DebugPrint("Nothing new detected.")
	
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1ScanNothing", "Captain", 1, pMission1Database)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# DistressCall() - You receive a distress call from the Geronimo
#
def DistressCall(pObject, pEvent):
	global bDistressCallPlayed
	bDistressCallPlayed = TRUE

	# Start a timer for Saffi's prodding
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_RESCUE_PROD, __name__ + ".RescueProd", fStartTime + 60, 0, 0)

	pSequence = App.TGSequence_Create()

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M4Distress1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E7M4Distress2", "MacCray")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddRescueGoal")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "SetupGeronimoSkirmish")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)
	
	pXiMenu = Systems.XiEntrades.XiEntrades.CreateMenus()
	pXiMenu.SetPlacementName("Akira Way1")

	return 0


# 
#	RescueProd() - Saffi Prods you to go rescue the Geronimo
#
def RescueProd(pObject, pEvent):
	if bRescuedGeronimo == FALSE:
		pPlayer = MissionLib.GetPlayer()
		if pPlayer == None:
			return

		pSet = pPlayer.GetContainingSet()
		if pSet == None:
			return

		pPlayerSetName = pSet.GetName()

		if not (pPlayerSetName == "XiEntrades5"):
#			DebugPrint ("Player is not at XiEntrades5, so increment RescueProd counter.")
			global iRescueGeronimoProd
			iRescueGeronimoProd = iRescueGeronimoProd + 1

			if iRescueGeronimoProd > 4:
				# Kill Geronimo
				pSet = App.g_kSetManager.GetSet("XiEntrades5")
				pGeronimo = App.ShipClass_GetObject(pSet, "USS Geronimo")
				if pGeronimo:
					# Die you stupid Hull!
					pGeronimo.DamageSystem(pGeronimo.GetHull(), 1000000)

			else:
				if iRescueGeronimoProd == 1:
#					DebugPrint ("Can't we get there any faster?")
					sSaffiLine = "E7M4Prod3"

					# Geronimo takes damage, disable nothing
					MissionLib.DamageShip("USS Geronimo", 0.1, 0.2, 1)
				elif iRescueGeronimoProd == 2:
#					DebugPrint ("I hope there's something left to rescue.")
					sSaffiLine = "E7M4Prod4"
	
					# Geronimo takes damage, disable nothing
					MissionLib.DamageShip("USS Geronimo", 0.2, 0.3, 1)
				elif iRescueGeronimoProd == 3:
#					DebugPrint ("Aren't we going to rescue the Geronimo?")
					sSaffiLine = "E7M4Prod1"
	
					# Geronimo takes damage, disable nothing
					MissionLib.DamageShip("USS Geronimo", 0.3, 0.4, 1)
				else:
#					DebugPrint ("Starfleet regulation requires that you rescue the Geronimo!")
					sSaffiLine = "E7M4Prod2"
	
					# Geronimo takes damage, may disable systems
					MissionLib.DamageShip("USS Geronimo", 0.4, 0.5)

				if not ((pPlayerSetName == "Starbase12") and (iEnemiesFollowing > 0)):
					# Play Saffi prod, as long as you are not tied up in a battle at Starbase 12
					g_pSaffi.SayLine(pMissionDatabase, sSaffiLine, "Captain", 1)

				# Timer to replay Prod function
				fStartTime = App.g_kUtopiaModule.GetGameTime()
				MissionLib.CreateTimer(ET_RESCUE_PROD, __name__ + ".RescueProd", fStartTime + 45, 0, 0)


#
#	AddRescueGoal()
#
def AddRescueGoal(pAction):

#	DebugPrint ("Adding E7RescueGeronimoGoal.\n")

	# Add our Objectives
	MissionLib.AddGoal("E7RescueGeronimoGoal")

	return 0



#
# SetupGeronimoSkirmish()
#
def SetupGeronimoSkirmish(pAction):
	pSet = App.g_kSetManager.GetSet("XiEntrades5")

	pKessok1 = loadspacehelper.CreateShip( "KessokLight", pSet, "KessokAttacker", "Kessok Start" )
	pGalor1 = loadspacehelper.CreateShip( "Galor", pSet, "GalorAttacker1", "Galor1 Start" )
	pGalor2 = loadspacehelper.CreateShip( "Galor", pSet, "GalorAttacker2", "Galor2 Start" )
	pGeronimo = loadspacehelper.CreateShip( "Geronimo", pSet, "USS Geronimo", "Akira Start" )
	pGeronimo.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")

	# Damage Geronimo, disable nothing
	MissionLib.DamageShip("USS Geronimo", 0.0, 0.1, 1)

	return 0


#
# StartGeronimoSkirmish()
#
def StartGeronimoSkirmish():
	pSet = App.g_kSetManager.GetSet("XiEntrades5")

	pGeronimo = App.ShipClass_GetObject(pSet, "USS Geronimo")
	if pGeronimo:
		pGeronimo.SetAI(AkiraAI.CreateAI(pGeronimo))


#		DebugPrint ("Disabling Geronimo's Warp Engines and making them invincible.")
		pWarp = pGeronimo.GetWarpEngineSubsystem()
		if (pWarp):
			MissionLib.SetConditionPercentage(pWarp, pWarp.GetDisabledPercentage() - 0.2)
			MissionLib.MakeSubsystemsInvincible(pWarp)

	pKessok1 = App.ShipClass_GetObject(pSet, "KessokAttacker")
	if pKessok1:
		pKessok1.SetAI(EnemyAI.CreateAI(pKessok1))
	pGalor1 = App.ShipClass_GetObject(pSet, "GalorAttacker1")
	if pGalor1:
		pGalor1.SetAI(EnemyAI.CreateAI(pGalor1))
	pGalor2 = App.ShipClass_GetObject(pSet, "GalorAttacker2")
	if pGalor2:
		pGalor2.SetAI(EnemyAI.CreateAI(pGalor2))


###############################################################################
#	CallDamage()
#
#	Dialogue for when ships are damaged
#
#	Args:	sShipName	- Name of the ship damaged
#			sSystemName - The System damaged
#			iPercentageLeft - The percentage of the System remaining
#
#	Return:	none
###############################################################################

def CallDamage(sShipName, sSystemName, iPercentageLeft ):
	#Make sure nothing overlaps
	if (bStopDamageDialogue == TRUE):
		return
	global bStopDamageDialogue
	bStopDamageDialogue = TRUE

	pSequence = App.TGSequence_Create()

	if (sShipName == "USS Geronimo"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if pPlayerSetName:
			if (pPlayerSetName != pGeronimoSetName):
				pSequence.Completed()
				return

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 0):
#				DebugPrint("Geronimo shields are gone!")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("Geronimo shields down to 50 percent.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 10):
#				DebugPrint("Geronimo hull down to 10 percent.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoHull10", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

				global bGeronimoCritical
				bGeronimoCritical = TRUE

			elif (iPercentageLeft == 25):
#				DebugPrint("Geronimo hull down to 25 percent.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoHull25", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

				global bGeronimoCritical
				bGeronimoCritical = TRUE

			elif (iPercentageLeft == 50):
#				DebugPrint("Geronimo hull down to 50 percent.")

				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M4Rescue2", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoHull50", None, 0, pMissionDatabase)	
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

				global bGeronimoCritical
				bGeronimoCritical = TRUE


	if (sShipName == "USS San Francisco"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		pSanFranciscoSetName = pSanFrancisco.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if pPlayerSetName:
			if (pPlayerSetName != pSanFranciscoSetName):
				pSequence.Completed()
				return

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 0):
#				DebugPrint("San Francisco shields are gone!")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3SanFranciscoShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("San Francisco shields down to 50 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3SanFranciscoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 25):
#				DebugPrint("San Francisco hull down to 25 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3SanFranciscoHull25", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

				global bSanFranciscoCritical
				bSanFranciscoCritical = TRUE

			elif (iPercentageLeft == 50):
#				DebugPrint("San Francisco hull down to 50 percent")

				pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
				pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow21", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E7M3SanFranciscoHull50", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

				global bSanFranciscoCritical
				bSanFranciscoCritical = TRUE

	elif (sShipName == "Starbase 12"):
		pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
		pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 0):
#				DebugPrint("Starbase 12 shields are gone!")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseShields0", "Captain", 1, pMission1Database)
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 25):
#				DebugPrint("Starbase 12 shields down to 25 percent")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive7", None, 0, pMission1Database)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseShields25", None, 0, pMission1Database)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("Starbase 12 shields down to 50 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseShields50", "Captain", 1, pMission1Database)
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 75):
#				DebugPrint("Starbase 12 shields down to 75 percent")

				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseAttack", "Captain", 1, pMission1Database)
				pSequence.AppendAction(pAction)

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 1):
#				DebugPrint("Starbase 12 hull down to 1 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull1", "Captain", 1, pMission1Database)
				pSequence.AppendAction(pAction)

				global bStarbaseCritical
				bStarbaseCritical = TRUE

			elif (iPercentageLeft == 10):
#				DebugPrint("Starbase 12 hull down to 10 percent")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull10", "Captain", 1, pMission1Database)
				pSequence.AppendAction(pAction)

				global bStarbaseCritical
				bStarbaseCritical = TRUE

			elif (iPercentageLeft == 40):
#				DebugPrint("Starbase 12 hull down to 40 percent")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive7", None, 0, pMission1Database)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull25", None, 0, pMission1Database)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

				global bStarbaseCritical
				bStarbaseCritical = TRUE

			if (iPercentageLeft == 75):
#				DebugPrint("Starbase 12 hull down to 75 percent")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1Arrive3", None, 0, pMission1Database)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M1StarbaseHull75", None, 0, pMission1Database)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

	pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
	pSequence.AppendAction(pReAllow)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# Reset the Call Damage global
# Called from script above
#
def ReAllowDamageDialogue(pAction):
	#Make sure nothing overlaps
	global bStopDamageDialogue
	bStopDamageDialogue = FALSE

	return 0


#
#	RestoreWarp() - Restores Warp for Geronimo
#
def RestoreWarp(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("XiEntrades5")
	pGeronimo = App.ShipClass_GetObject(pSet, "USS Geronimo")

	if pGeronimo and (bRescuedGeronimo == FALSE):
#		DebugPrint("The Geronimo has been rescued.")

		pGeronimo.SetAI(GeronimoAI.CreateAI(pGeronimo))	

		MissionLib.RemoveGoal("E7RescueGeronimoGoal")
	
		MissionLib.AddCommandableShip("USS Geronimo")

		pCommandFleetMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")
		if pCommandFleetMenu:
			pCommandFleetMenu.AddPythonFuncHandlerForInstance(Bridge.HelmMenuHandlers.ET_FLEET_COMMAND_DOCK_SB12, __name__ + ".DockHandler")
#		else:
#			DebugPrint(__name__ + " error: Unable to get Command Fleet menu.")
	
		global bRescuedGeronimo
		bRescuedGeronimo = TRUE

		pKessok1 = App.ShipClass_GetObject(pSet, "KessokAttacker")
		pGalor1 = App.ShipClass_GetObject(pSet, "GalorAttacker1")
		pGalor2 = App.ShipClass_GetObject(pSet, "GalorAttacker2")

		pWarp = pGeronimo.GetWarpEngineSubsystem()
		if (pWarp):
			r = pWarp.GetDisabledPercentage() + 0.1

			if (r > pWarp.GetConditionPercentage()):
				MissionLib.SetConditionPercentage(pWarp, r)

			if (iEnemiesFollowing > 0) or (iGeronimoAttackers > 0):
				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")
			
				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)
			
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M4Rescue2", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3Follow36", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
			
				MissionLib.QueueActionToPlay(pSequence)


#
# GeronimoRescued()
#
def GeronimoRescued(pAction):
	if not bRescueSequencePlayed:
		global bRescueSequencePlayed
		bRescueSequencePlayed = TRUE

		RestoreWarp(None, None)

		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M4Rescue2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued4", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued5", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued6", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued7", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued8", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued9", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		if bGeronimoDamaged:
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRepair1", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# GeronimoDamaged() - Called from AkiraAI when Geronimo takes a moderate amount of damage
#
def GeronimoDamaged():
	global bGeronimoDamaged
	bGeronimoDamaged = TRUE


#
# MissionWin()  - A mission is completed
#
def MissionWin(pAction):
#	DebugPrint("A mission is completed.")

	DisableContactStarfleet(None)

	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	pSequence = App.TGSequence_Create()	

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (iOutpostsDestroyed == iOutposts) and (bResupplyDestroyed == TRUE):
#		DebugPrint("Missions Completed.  Liu congratulates you and asks you to return to Starbase")

		pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
		pSBMenu.SetMissionName("Maelstrom.Episode7.E7M6.E7M6")

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L040", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 5)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7LiuHail", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7MissionsCompleted1", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7MissionsCompleted2", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

#		DebugPrint ("Adding ReturnToStarbaseGoal")
		MissionLib.AddGoal("E7ReturnToStarbaseGoal")

	elif (iOutpostsDestroyed == iOutposts):
#		DebugPrint("Good job, now destroy the resupply outpost")
		
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7LiuHail", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu4", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	elif (bResupplyDestroyed == TRUE):
#		DebugPrint("Good job, now destroy the sensor stations")

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M5L040", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 5)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7LiuHail", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu5", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "EnableContactStarfleet")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


###############################################################################
#	HailStarfleet()
#
#	Contact Starfleet
#
#	Args:	pObject	- TGObject object
#			pEvent	- TGEvent object
#
#	Return:	none
###############################################################################
def HailStarfleet(pObject, pEvent):
#	DebugPrint("Contacting Starfleet - E7M3_M4_M5")
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	pSequence = MissionLib.ContactStarfleet()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (pPlayerSetName == "Starbase12") and (iEnemiesFollowing > 0):
#		DebugPrint("Clean up your mess!")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu6", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)

	elif (iOutpostsDestroyed == iOutposts):
		if (bResupplyDestroyed == TRUE):
#			DebugPrint("Return to Starbase 12")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7MissionsCompleted2", None, 0, pEpisodeDatabase)
			pSequence.AppendAction(pAction)
		else:
#			DebugPrint("Go destroy the resupply outpost")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu4", None, 0, pEpisodeDatabase)
			pSequence.AppendAction(pAction)
	elif (bResupplyDestroyed == TRUE):
#		DebugPrint("Destroy all the sensor posts")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu5", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)
	elif (Maelstrom.Maelstrom.bGeronimoAlive == 1):
		if (bDistressCallPlayed == 1) and (bRescuedGeronimo == 0):
#			DebugPrint("Go rescue the Geronimo!")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu2", None, 0, pEpisodeDatabase)
			pSequence.AppendAction(pAction)
		elif (bRescuedGeronimo == TRUE) and (Maelstrom.Maelstrom.bGeronimoAlive == 1) and (bThanksForRescue == FALSE):
#			DebugPrint("Thanks for rescuing the Geronimo")
			global bThanksForRescue
			bThanksForRescue = TRUE
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu3", None, 0, pEpisodeDatabase)
			pSequence.AppendAction(pAction)
		else:
#			DebugPrint("Destroy sensor stations and resupply outpost")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu1", None, 0, pEpisodeDatabase)
			pSequence.AppendAction(pAction)
	else:
#		DebugPrint("Destroy sensor stations and resupply outpost")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7HailLiu1", None, 0, pEpisodeDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# DisableContactStarfleet() - Disable Contact Starfleet Button
#
def DisableContactStarfleet(pAction):
#	DebugPrint ("Disable ContactStarfleet Button")

	pContactStarfleet = g_pSaffiMenu.GetButtonW(pMenuDatabase.GetString("Contact Starfleet"))
	pContactStarfleet.SetDisabled()

	return 0


#
# EnableContactStarfleet() - Re-enable Contact Starfleet Button
#
def EnableContactStarfleet(pAction):
#	DebugPrint ("Re-enable Contact Starfleet Button")

	pContactStarfleet = g_pSaffiMenu.GetButtonW(pMenuDatabase.GetString("Contact Starfleet"))
	pContactStarfleet.SetEnabled()

	return 0


##############################################################################
#	ExitWarp(pMission, pEvent)
#	
#	Called when a ship has finished warping.
#	
#	Args:	TGObject	- The TGObject object
#			pEvent		- The event that was sent
#	
#	Return:	none
##############################################################################
def ExitWarp(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	pPlayer = App.Game_GetCurrentPlayer()

	if (pShip== None) or (pPlayer == None) or (pShip.GetObjID() != pPlayer.GetObjID()):
		TGObject.CallNextHandler(pEvent)
		return
	
	pSet = pShip.GetContainingSet()
	if (pSet == None):
		TGObject.CallNextHandler(pEvent)
		return
	
	# Arriving at Starbase at start of mission, play briefing
	if not g_bBriefingPlayed and (pSet.GetName() == "Starbase12"):
#		DebugPrint("Arrived at Starbase12")
		Briefing()
		
	# All done, call our next handler
	TGObject.CallNextHandler(pEvent)


#
# EnterSet()
#
def EnterSet(TGObject, pEvent):
	# An event triggered whenever an object enters a set.
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if not App.IsNull(pShip):
		# It's a ship.
		sShipName = pShip.GetName()

		pSet = pShip.GetContainingSet()
		if not pSet:
			return

		sSetName = pSet.GetName()

#		DebugPrint("Ship \"%s\" entered set \"%s\"" % (sShipName, sSetName))

		if (sShipName == "player") and not (sSetName == "warp"):
			pSequence = ShipsFollowing(pSet)

			# When the player arrives at Poseidon 2 the first time
			if (sSetName == "Poseidon2"):
				if (bPoseidon2Arrive == FALSE):
#					DebugPrint("First time arriving in Poseidon 2")
					global bPoseidon2Arrive
					bPoseidon2Arrive = TRUE

					pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
					pSequence.AppendAction(pAction)

					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines01", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines02", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines03", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines04", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
					if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
						pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
						pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")
	
						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail2", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines05", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)

					pAction = App.TGScriptAction_Create(__name__, "SetupCloakedLaunchers")
					pSequence.AppendAction(pAction, 2)

			# When the player arrives at Artrus 3 the first time
			elif (sSetName == "Artrus3") and (bArtrus3Arrive == FALSE):
#				DebugPrint("First time arriving in Artrus 3")
				global bArtrus3Arrive
				bArtrus3Arrive = TRUE

				if (iAttackWave < 4):
					CreateSensorDefenders(pSet)

					pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
					pSequence.AppendAction(pAction)

					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Artrus1", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
		
					if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
						pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
						pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail2", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3ArtrusMacCray1", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)
		
					pAction2 = App.TGScriptAction_Create(__name__, "SetArtrus3AI")
					pSequence.AddAction(pAction2, pAction, 5)
	
			# When the player arrives at Geble 4 the first time
			elif (sSetName == "Geble4") and (bGeble4Arrive == FALSE):
#				DebugPrint("First time arriving in Geble 4")
				global bGeble4Arrive
				bGeble4Arrive = TRUE

				if (iAttackWave < 5):
					CreateSensorDefenders(pSet)

					pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
					pSequence.AppendAction(pAction)
	
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Geble1", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Geble2", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M3Geble3", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create(__name__, "SetGeble4AI")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Geble4", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
		
					if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
						pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
						pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail1", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3GebleMacCray1", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)
	
			# When the player arrives at Serris 3 the first time
			elif (sSetName == "Serris3") and (bSerris3Arrive == FALSE):
#				DebugPrint("First time arriving in Serris 3")
				global bSerris3Arrive
				bSerris3Arrive = TRUE
	
				if (iAttackWave < 2):
					CreateSensorDefenders(pSet)

					pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
					pSequence.AppendAction(pAction)

					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Serris1", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
		
					if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
						pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
						pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail2", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3SerrisMacCray1", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)

					pAction2 = App.TGScriptAction_Create(__name__, "SetSerris3AI")
					pSequence.AddAction(pAction2, pAction, 5)

			elif (sSetName == "Ascella3"):
				if (bAscella3Arrive == FALSE):
					global bAscella3Arrive
					bAscella3Arrive = TRUE
		
					pBase = loadspacehelper.CreateShip("CardStation", pSet, "Resupply Station", "Station Start")

					# Add Instance Handler to detect if Disruptors are disabled
					pBase.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".DisableSystemHandler")

					Ascella3Arrive()

				elif not (bResupplyDestroyed):
					CardassianAttack(None, None)

			elif (sSetName == "Ascella5") and (bAscella5Arrive == FALSE):
				global bAscella5Arrive
				bAscella5Arrive = TRUE

				MissionLib.SaveGame("E7M3-Ascella-")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M5L044", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				
				# If all outposts destroyed. 
				if (iOutpostsDestroyed == iOutposts):
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L001", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
				# Not all outposts destroyed.
				else:
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M5L002", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

			elif (sSetName == "XiEntrades5") and (bXiEnt5Arrive == FALSE):
				global bXiEnt5Arrive, bFirstTimeInXi5
				bXiEnt5Arrive = TRUE
				bFirstTimeInXi5 = TRUE

				StartGeronimoSkirmish()

				if (bRescuedGeronimo == FALSE) and (iRescueGeronimoProd < 5):
					# Start a timer to restore the Geronimo's warp engines
					fStartTime = App.g_kUtopiaModule.GetGameTime()
					MissionLib.CreateTimer(ET_RESTORE_WARP, __name__ + ".RestoreWarp", fStartTime + 210, 0, 0)
			
					pEBridgeSet = MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif", -40, 65, -1.55)
					pMacCray =  MissionLib.SetupCharacter("Bridge.Characters.MacCray", "EBridgeSet")

					pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
					pSequence.AppendAction(pAction)
			
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M4Rescue2", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction, 4)
					pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
					pSequence.AppendAction(pAction)
					if iEnemiesFollowing == 1:
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3Follow35b", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
					elif iEnemiesFollowing > 1:
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3Follow35", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
					else:
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4Rescue3", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M4Rescue4", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
					pSequence.AppendAction(pAction)

			if not (pSequence == None):
				MissionLib.QueueActionToPlay(pSequence)

		elif (sShipName == "USS San Francisco") and (sSetName == "Serris2"):
			pShip.SetDeleteMe(1)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# SetupCloakedLaunchers() - Creates Cloaked Torpedo launchers and sets them up to attack
#
def SetupCloakedLaunchers(pAction):
	pSet = App.g_kSetManager.GetSet("Poseidon2")

	iLaunchers = 0

	while iLaunchers < 24:
		# Increment Launcher counter
		iLaunchers = iLaunchers + 1

		# Set Launcher's name
		sLauncher = "Launcher" + str(iLaunchers)

		# Create Launcher
		pLauncher = loadspacehelper.CreateShip("KessokMine", pSet, sLauncher, "Mine" + str(iLaunchers) + " Location")

		# Cloak the Launcher to start
		pCloak = pLauncher.GetCloakingSubsystem()
		if (not App.IsNull(pCloak)):
			pCloak.TurnOn()
			pCloak.InstantCloak()

		if iLaunchers < 13:
			# Set Launcher proximity attack
			pLauncher.SetAI(TorpLauncherAI.CreateAI(pLauncher))
#			DebugPrint(sLauncher + " AI set")

#		DebugPrint(sLauncher + " done")

	return 0


#
# LauncherAttack() - This function called from TorpLauncherAI
#
def LauncherAttack(sLauncher):
	if (sLauncher == None):
#		DebugPrint("ERROR - sLauncher is None")
		return

#	DebugPrint(sLauncher + " decloaks and attacks")

	pSet = App.g_kSetManager.GetSet("Poseidon2")

	# This name represents which other launcher will decloak and launch along with sLauncher
	sLaunchMate = None

	if (sLauncher == "Launcher1"):
		sLaunchMate = "Launcher13"
	elif (sLauncher == "Launcher2"):
		sLaunchMate = "Launcher14"
	elif (sLauncher == "Launcher3"):
		sLaunchMate = "Launcher15"
	elif (sLauncher == "Launcher4"):
		sLaunchMate = "Launcher16"
	elif (sLauncher == "Launcher5"):
		sLaunchMate = "Launcher17"
	elif (sLauncher == "Launcher6"):
		sLaunchMate = "Launcher18"
	elif (sLauncher == "Launcher7"):
		sLaunchMate = "Launcher19"
	elif (sLauncher == "Launcher8"):
		sLaunchMate = "Launcher20"
	elif (sLauncher == "Launcher9"):
		sLaunchMate = "Launcher21"
	elif (sLauncher == "Launcher10"):
		sLaunchMate = "Launcher22"
	elif (sLauncher == "Launcher11"):
		sLaunchMate = "Launcher23"
	elif (sLauncher == "Launcher12"):
		sLaunchMate = "Launcher23"

	pLaunchMate = App.ShipClass_GetObject(pSet, sLaunchMate)
	if not (pLaunchMate == None):
		# Set AI for Launchmate
		pLaunchMate.SetAI(LaunchMateAI.CreateAI(pLaunchMate))

	pPlayerSet = MissionLib.GetPlayerSet()
	if not (pPlayerSet.GetName() == "Poseidon2"):
		# Player is not in set, so skip dialogue
		return

	# Play warning dialogue
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (bMinesActive == FALSE):
		global bMinesActive
		bMinesActive = TRUE

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines05a", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines06", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 7)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines07", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	else:
		iNum = App.g_kSystemWrapper.GetRandomNumber(2)
		if iNum == 1:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines10", "Captain", 1, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines10b", "Captain", 1, pMissionDatabase)

		pSequence.AppendAction(pAction)

		if not (bMinesActive == -1):
			global bMinesActive
			bMinesActive = -1

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines11", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines12", "S", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3CloakedMines13", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN_BACK)
			pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
#	ShipsFollowing() - Deals with ships following you when you enter a set, and returns a sequence to be appended to in EnterSet
#
def ShipsFollowing(pSet):
	pSequence = App.TGSequence_Create()

	if not (iEnemiesFollowing == 0):
#		DebugPrint("Enemies are following you")
		if (iEnemiesFollowing > iEnemiesStillFollowing):
			if (bKessokFollowed == TRUE):
#				DebugPrint("The KessokHeavy is following you")
				global bKessokFollowed
				bKessokFollowed = FALSE

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow05", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction, 5)
				if (bFirstTimeFollowed == FALSE):
#					DebugPrint("First time being followed")
					global bFirstTimeFollowed
					bFirstTimeFollowed = TRUE
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow04", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

			elif (bFirstTimeFollowed == FALSE):
#				DebugPrint("First time being followed")
				global bFirstTimeFollowed
				bFirstTimeFollowed = TRUE
				if (iEnemiesFollowing > 1):
#					DebugPrint("Multiple Enemies following")
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow01", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction, 5)
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow02", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

				elif (iEnemiesFollowing == 1):
#					DebugPrint("Only one enemy following")
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow03", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction, 5)
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow04", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

			elif (iEnemiesFollowing - iEnemiesStillFollowing) == 1:
				if (iEnemiesStillFollowing > 0):
#					DebugPrint("A new enemy has joined the group following you")
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow06", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction, 5)

				else:
#					DebugPrint("A new enemy is following you")
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow07", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction, 5)

			elif not (iEnemiesFollowing == 1):
#				DebugPrint("A new group is following you")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow08", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction, 5)
				if bPosseLine == FALSE:
					global bPosseLine
					bPosseLine = TRUE
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M3Follow09", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
			else:
#				DebugPrint("One Enemy still following")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow13", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction, 5)
				if bDeathwishLine == FALSE:
					global bDeathwishLine
					bDeathwishLine = TRUE
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Follow14", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

		elif (iEnemiesFollowing == 1):
#			DebugPrint("One Enemy still following")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow13", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction, 5)
			if bDeathwishLine == FALSE:
				global bDeathwishLine
				bDeathwishLine = TRUE
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Follow14", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		else:
#			DebugPrint("Enemies still following")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow10", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction, 5)
			if not (pSet.GetName() == "Starbase12") and (iMakeAStandLine < 2):
				global iMakeAStandLine
				iMakeAStandLine = iMakeAStandLine + 1

				if (iMakeAStandLine == 1):
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Follow11", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

				elif (iMakeAStandLine == 2):
					if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
						pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
						pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail1", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3Follow37", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)

					else:
						pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3Follow12", "Captain", 1, pMissionDatabase)
						pSequence.AppendAction(pAction)

		if (pSet.GetName() == "Starbase12") and (iEnemiesFollowing > 1):
			pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
			pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

			if (iProtectStarbase == 1):
#				DebugPrint("You guys just can't stay out of trouble.")

				global iProtectStarbase
				iProtectStarbase = 3

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow27", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M3Follow31", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

		 	elif (iEnemiesFollowing > 1):
#				DebugPrint("Making a stand at Starbase 12.")
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3Follow15", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M3Follow16", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
			 	if (iEnemiesFollowing > 3) and Maelstrom.Maelstrom.bZeissAlive:
					pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M3Follow17", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create(__name__, "SummonZeiss")
					pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

			if not (iProtectStarbase == 3):
				global iProtectStarbase
				iProtectStarbase = 2

		global iEnemiesStillFollowing
		iEnemiesStillFollowing = iEnemiesFollowing

	return pSequence


#
#	SummonZeiss()
#
def SummonZeiss(pAction):
	# Setup a timer to Create Zeiss
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SUMMON_ZEISS, __name__ + ".ZeissArrive", fStartTime + 90, 0, 0)

	return 0


#
#	ZeissArrive()
#
def ZeissArrive(pObject, pEvent):
	if iEnemiesFollowing > 1:
#		DebugPrint("Zeiss Arrives")

		global bZeissPresent
		bZeissPresent = TRUE

		pDBridgeSet = MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -40, 65, -1.55)
		pZeiss = MissionLib.SetupCharacter("Bridge.Characters.Zeiss", "DBridgeSet")

		pSet = App.g_kSetManager.GetSet("Starbase12")
		pGalaxy = loadspacehelper.CreateShip("Galaxy", pSet, "USS San Francisco", "Nebula Start", 1)
		pGalaxy.ReplaceTexture("data/Models/SharedTextures/FedShips/SanFrancisco.tga", "ID")

#		DebugPrint ("Making the San Francisco's Warp and Impulse Engines invincible.")
		pWarp = pGalaxy.GetWarpEngineSubsystem()
		if (pWarp):
			MissionLib.MakeSubsystemsInvincible(pWarp)
		pImpulse = pGalaxy.GetImpulseEngineSubsystem()
		if (pImpulse):
			MissionLib.MakeSubsystemsInvincible(pImpulse)

		pGalaxy.SetAI(AkiraAI.CreateAI(pGalaxy))
	
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow19", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M3Follow20", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow21", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E7M3Follow22", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3Follow23", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E7M3Follow24", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)


#
#	CreateSensorDefenders() - Creates ships for the given set.  If iInt == 1, give ships follow AI.
#
def CreateSensorDefenders(pSet, iInt = 0):
	# Artrus 3 ships
	if (pSet.GetName() == "Artrus3"):
		global bArt3Defenders
		bArt3Defenders = TRUE

		pKeldon1 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon1", "Enemy1 Start" )
		pGalor1 = loadspacehelper.CreateShip( "Galor", pSet, "Galor1", "Enemy2 Start" )

		if iInt == 1:
			FollowPlayer("Keldon1", "Galor1")

	# Serris 3 ships
	elif (pSet.GetName() == "Serris3"):
		global bSer3Defenders
		bSer3Defenders = TRUE

		pGalor2 = loadspacehelper.CreateShip( "Galor", pSet, "Galor2", "Enemy1 Start" )
		pGalor3 = loadspacehelper.CreateShip( "Galor", pSet, "Galor3", "Enemy2 Start" )
		pGalor4 = loadspacehelper.CreateShip( "Galor", pSet, "Galor4", "Enemy3 Start" )

		if iInt == 1:
			FollowPlayer("Galor2", "Galor3", "Galor4")

	# Geble 4 ships
	elif (pSet.GetName() == "Geble4"):
		global bGeb4Defenders
		bGeb4Defenders = TRUE

		pKessokHeavy = loadspacehelper.CreateShip( "KessokHeavy", pSet, "KessokHeavy", "Enemy1 Start" )

		# Add Instance Handler to detect if Warp or Impulse or Repair is disabled
		pKessokHeavy.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".DisableSystemHandler")

		if iInt == 1:
			FollowPlayer("KessokHeavy")
			global bKessokFollowed
			bKessokFollowed = TRUE


#
#	SetArtrus3AI() - Sets the Enemy AI for Artrus3
#
def SetArtrus3AI(pAction):
#	DebugPrint("Setting Artrus3 AI")

	pSet = App.g_kSetManager.GetSet("Artrus3")

	pKeldon1 = App.ShipClass_GetObject(pSet, "Keldon1")
	pGalor1 = App.ShipClass_GetObject(pSet, "Galor1")

	pKeldon1.SetAI(EnemyAI.CreateAI(pKeldon1))
	pGalor1.SetAI(EnemyAI.CreateAI(pGalor1))

	return 0


#
#	SetSerris3AI() - Sets the Enemy AI for Serris3
#
def SetSerris3AI(pAction):
#	DebugPrint("Setting Serris3 AI")

	pSet = App.g_kSetManager.GetSet("Serris3")

	pGalor2 = App.ShipClass_GetObject(pSet, "Galor2")
	pGalor3 = App.ShipClass_GetObject(pSet, "Galor3")
	pGalor4 = App.ShipClass_GetObject(pSet, "Galor4")

	pGalor2.SetAI(EnemyAI.CreateAI(pGalor2))
	pGalor3.SetAI(EnemyAI.CreateAI(pGalor3))
	pGalor4.SetAI(EnemyAI.CreateAI(pGalor4))

	return 0


#
#	SetGeble4AI() - Sets the Enemy AI for Geble4
#
def SetGeble4AI(pAction):
#	DebugPrint("Setting Geble4 AI")

	pSet = App.g_kSetManager.GetSet("Geble4")

	pKessokHeavy = App.ShipClass_GetObject(pSet, "KessokHeavy")

	pKessokHeavy.SetAI(EnemyAI.CreateAI(pKessokHeavy))

	return 0


#
# ExitSet()
#
def ExitSet(TGObject, pEvent):
	"Triggered whenever an object leaves a set."
	# Check and see if mission is terminating, if so return
	if (bMissionTerminate == TRUE):
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()
		
	if not App.IsNull(pShip):
		# It's a ship.
#		DebugPrint("Ship \"%s\" exited set \"%s\"" % (pShip.GetName(), sSetName))

		if (pShip.GetName() == "player"):
			if ((sSetName == "Ascella3") and bResupplyDestroyed or 
				(sSetName == "Artrus3") and bOutpost2Destroyed or
				(sSetName == "Serris3") and bOutpost3Destroyed or
				(sSetName == "Geble4") and bOutpost4Destroyed):

				# Make enemies follow you if the post they were protecting is destroyed
				MakeEnemiesInSetFollow(sSetName)

			elif (sSetName == "XiEntrades5"):
	
				if (bRescuedGeronimo == TRUE) or (Maelstrom.Maelstrom.bGeronimoAlive == 0):
					global bFirstTimeInXi5
					bFirstTimeInXi5 = FALSE

				if (iGeronimoAttackers > 0):
					MakeEnemiesInSetFollow(sSetName)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# MakeEnemiesInSetFollow()
#
def MakeEnemiesInSetFollow(sSetName, bCheckPlayerSet = 0):
	pSet = App.g_kSetManager.GetSet(sSetName)
	if pSet == None:
		return

	if bCheckPlayerSet:
		if (iOutpostsDestroyed == iOutposts) and (bResupplyDestroyed == TRUE):
			# End of Mission.  Don't follow.
			return

		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			pPlayerSet = pPlayer.GetContainingSet()
			if pPlayerSet:
				sPlayerSetName = pPlayerSet.GetName()
				if (sPlayerSetName == sSetName):
					# Player hasn't left this set, so return
					return

	# Index through ALL objects in the set the player is leaving.
	# If they're enemies and not following you already, have them follow the player through warp
	pObject = pSet.GetFirstObject()
	pFirstObject = pObject
	while not (App.IsNull(pObject)):
		if (pEnemyTargets.IsNameInGroup(pObject.GetName()) and
			not (pFollowObjGroup.IsNameInGroup(pObject.GetName()))):

			pFollower = App.ShipClass_Cast(pObject)
			if pFollower:
				sName = pFollower.GetName()
				FollowPlayer(sName)

				if (sName == "KessokHeavy"):
					global bKessokFollowed
					bKessokFollowed = TRUE

		pObject = pSet.GetNextObject(pObject.GetObjID())

		if (pObject.GetObjID() == pFirstObject.GetObjID()):
#			DebugPrint("Exiting loop.")
			pObject = None


#
# ObjectDestroyed()
#
def ObjectDestroyed(TGObject, pEvent):
#	DebugPrint("Object Destroyed")
	pShip = App.ObjectClass_Cast(pEvent.GetDestination())
	sShipName = pShip.GetName()
#	DebugPrint("Ship \"%s\" was destroyed" % pShip.GetName())

	global iEnemiesFollowing, pFollowObjGroup

	if not App.IsNull(pShip):
		# Set flag if multiple ships are following you
		if (iEnemiesFollowing > 1) and not bMultipleFollowers:
			global bMultipleFollowers
			bMultipleFollowers = TRUE

		# If ship was following you
		if (iEnemiesFollowing > 0) and (pFollowObjGroup.IsNameInGroup(sShipName)):
			global iEnemiesFollowing, iEnemiesStillFollowing
			pFollowObjGroup.RemoveName(pShip.GetName())
			iEnemiesFollowing = iEnemiesFollowing - 1
			iEnemiesStillFollowing = iEnemiesStillFollowing - 1

			if iEnemiesFollowing == 0:
#				DebugPrint("Last enemy follower destroyed")

				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)

				if (iProtectStarbase > 1):
					global bStarbaseCritical
					bStarbaseCritical = FALSE

					if (iProtectStarbase == 2):
						global bSanFranciscoCritical
						bSanFranciscoCritical = FALSE

						pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
						pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

						pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Follow25", "Captain", 1, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M3Follow26", "Captain", 1, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow27", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M3Follow28", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)
						if Maelstrom.Maelstrom.bZeissAlive:
							pAction = App.TGScriptAction_Create(__name__, "ZeissLeaving")
							pSequence.AppendAction(pAction)

					global iProtectStarbase
					iProtectStarbase = 1

				elif (pEvent.GetCString() == "XiEntrades5") and not (bRescuedGeronimo == TRUE) and bFirstTimeInXi5 and (iGeronimoAttackers == 0):
					global iGeronimoAttackers
					iGeronimoAttackers = -1

					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued1", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
					if Maelstrom.Maelstrom.bGeronimoAlive == 1:
						pAction = App.TGScriptAction_Create(__name__, "GeronimoRescued")
						pSequence.AppendAction(pAction)
		
					else:
						pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDestroyed5", "Captain", 1, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4ContinueMission", "Captain", 1, pMissionDatabase)
						pSequence.AddAction(pAction2, pAction, 5)
				
				elif bMultipleFollowers:
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Follow38", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

				else:
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Follow39", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M3Follow40", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

				global bMultipleFollowers
				bMultipleFollowers = FALSE

		if(sShipName == "Keldon1") or (sShipName == "Galor1"):
#			DebugPrint("One Artrus 3 defender destroyed")
			global iArtrus3Enemies
			iArtrus3Enemies = iArtrus3Enemies - 1

			if (iArtrus3Enemies == 0) and (iEnemiesFollowing == 0) and (pEvent.GetCString() == "Artrus3"):
#				DebugPrint("All Artrus 3 defenders destroyed")

				pSequence = App.TGSequence_Create()
	
				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)
	
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Artrus2", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

				if (bOutpost2Destroyed == FALSE) and (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
					pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
					if pGeronimo:
						pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
						pGame = App.Game_GetCurrentGame()
						pPlayerSetName = pGame.GetPlayerSet().GetName()
	
						if (pPlayerSetName == pGeronimoSetName):
							pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
							pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

							pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail2", None, 0, pMissionDatabase)
							pSequence.AppendAction(pAction)
							pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
							pSequence.AppendAction(pAction)
							pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3ArtrusMacCray2", None, 0, pMissionDatabase)
							pSequence.AppendAction(pAction)
							pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
							pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

		elif(sShipName == "Galor2") or (sShipName == "Galor3") or (sShipName == "Galor4"):
#			DebugPrint("One Serris 3 defender destroyed")
			global iSerris3Enemies
			iSerris3Enemies = iSerris3Enemies - 1

			if (iSerris3Enemies == 0) and (iEnemiesFollowing == 0) and (pEvent.GetCString() == "Serris3"):
#				DebugPrint("All Serris 3 defenders destroyed")

				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)
	
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Serris2", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

				if (bOutpost3Destroyed == FALSE) and (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bRescuedGeronimo == TRUE):
					pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
					if pGeronimo:
						pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
						pGame = App.Game_GetCurrentGame()
						pPlayerSetName = pGame.GetPlayerSet().GetName()
	
						if (pPlayerSetName == pGeronimoSetName):
							pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
							pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")
		
							pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail1", None, 0, pMissionDatabase)
							pSequence.AppendAction(pAction)
							pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
							pSequence.AppendAction(pAction)
							pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3SerrisMacCray2", None, 0, pMissionDatabase)
							pSequence.AppendAction(pAction)
							pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
							pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

		elif ((sShipName == "KessokAttacker") or (sShipName == "GalorAttacker1") or (sShipName == "GalorAttacker2")):
			global iGeronimoAttackers
			iGeronimoAttackers = iGeronimoAttackers - 1
#			DebugPrint(str(iGeronimoAttackers) + " Geronimo attackers left")

			pGame = App.Game_GetCurrentGame()
			pPlayerSetName = pGame.GetPlayerSet().GetName()

			# Make sure player and ship are in the same set
			pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
			if pGeronimo:
				pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
			else: 
				pGeronimoSetName = ""
	
			if (pPlayerSetName == pGeronimoSetName) and (Maelstrom.Maelstrom.bGeronimoAlive == 1) and (iGeronimoAttackers > 1) and (sShipName == "GalorAttacker1" or sShipName == "GalorAttacker2"):
				pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E7M4Taunt1", "MacCray")
				pAction.Play()
			elif (pPlayerSetName == pGeronimoSetName) and (Maelstrom.Maelstrom.bGeronimoAlive == 1) and (iGeronimoAttackers > 0) and (sShipName == "KessokAttacker"):
				pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E7M4Taunt2", "MacCray")
				pAction.Play()
			elif (iGeronimoAttackers == 0) and (iEnemiesFollowing == 0):
				# If all enemies destroyed and Geronimo still alive, then win
#				DebugPrint("All enemy ships destroyed.")
				global iGeronimoAttackers
				iGeronimoAttackers = -1

				pSequence = App.TGSequence_Create()
				if (bRescuedGeronimo == FALSE) and (pPlayerSetName == pGeronimoSetName):
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoRescued1", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

				if Maelstrom.Maelstrom.bGeronimoAlive == 1:
					pAction = App.TGScriptAction_Create(__name__, "GeronimoRescued")
					pSequence.AppendAction(pAction)
	
				else:
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDestroyed5", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4ContinueMission", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction, 5)

				MissionLib.QueueActionToPlay(pSequence)

		elif(sShipName == "KessokHeavy"):
#			DebugPrint("Geble 4 KessokHeavy destroyed")

			global bGeb4Defenders
			bGeb4Defenders = FALSE

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)
	
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Geble5", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

			if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE):
				pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
				if pGeronimo:
					pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
					pGame = App.Game_GetCurrentGame()
					pPlayerSetName = pGame.GetPlayerSet().GetName()
	
					if (pPlayerSetName == pGeronimoSetName):
						pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
						pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3MacCrayHail2", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3GebleMacCray2", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						if (bOutpost4Destroyed == FALSE) and (pEvent.GetCString() == "Geble4"):
							pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M3GebleMacCray3", None, 0, pMissionDatabase)
							pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

		elif(sShipName == "USS Geronimo"):
#			DebugPrint("Geronimo destroyed!!!!!")

			global bGeronimoCritical
			bGeronimoCritical = FALSE

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

		 	if (bRescuedGeronimo != TRUE):
#				DebugPrint("Geronimo was not rescued")

				MissionLib.RemoveGoal("E7RescueGeronimoGoal")
		
				pLiuSet = App.g_kSetManager.GetSet("LiuSet")
				pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")
	
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDestroyed3", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDestroyed4", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDead2", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction, 5)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
				pSequence.AppendAction(pAction)

				if (bXiEnt5Arrive == FALSE):
					pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDead3", None, 0, pMissionDatabase)

				else:
					pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDead3b", None, 0, pMissionDatabase)

				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDead4", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDead5", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)	

			else:
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDestroyed1", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E7M4GeronimoDestroyed2", "MacCray")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDestroyed3", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDestroyed4", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

			global bRescuedGeronimo
			bRescuedGeronimo = -1
			Maelstrom.Maelstrom.bGeronimoAlive = 0

		# If San Francisco is destroyed
		elif (sShipName == "USS San Francisco"):
#			DebugPrint ("San Francisco destroyed dialogue")
			Maelstrom.Maelstrom.bZeissAlive = FALSE

			global bZeissPresent
			bZeissPresent = FALSE

			g_pMiguel.LookAtMe()
			g_pMiguel.SayLine(pMissionDatabase, "E7M3SanFranciscoDestroyed", "Captain", 1)

			global bSanFranciscoCritical
			bSanFranciscoCritical = FALSE

		# If Starbase12 is destroyed
		elif (sShipName == "Starbase 12"):
			global bStarbaseCritical
			bStarbaseCritical = FALSE

			MissionLib.GameOver(None)

		# If ship was in hostile object group, check if we need to play voice lines.
		elif(pHostileObjGroup.IsNameInGroup(sShipName)):
			global iNumHostilesDestroyed
			iNumHostilesDestroyed = iNumHostilesDestroyed + 1
#			DebugPrint("Number of Hostiles destroyed: " + str(iNumHostilesDestroyed))
			if AreAllHostilesDestroyed() and not bResupplyDestroyed:
				PlayHostilesDialogue()

		# If ship was one of the freighters.
		elif(pFreighterObjGroup.IsNameInGroup(sShipName)):
			# Increment Episode global Freighter counter.
			global iNumFreighters
			iNumFreighters = iNumFreighters - 1

			if (iNumFreighters == 0) and (bStationAlert == FALSE):
				# If all freighters destroyed, have Station bring up shields and attack early
				StationRedAlert(None, None)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# The handler for object exploding event.
#
def ObjectExploding(TGObject, pEvent):
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	
	sShipName = pShip.GetName()

	#  If the Geronimo was destroyed, play dialogue
	if (sShipName == "USS Geronimo"):
		pSequence = App.TGSequence_Create()

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M4GeronimoDestroyed1", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E7M4GeronimoDestroyed2", "MacCray")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	elif(sShipName == "Sensor Post 1") and not bOutpost1Destroyed:
		global iOutpostsDestroyed
		iOutpostsDestroyed = iOutpostsDestroyed + 1
#		DebugPrint("Sensor Post 1 destroyed")
#		DebugPrint("Sensor Posts destroyed = " +str(iOutpostsDestroyed))

		global bOutpost1Destroyed
		bOutpost1Destroyed = TRUE

		pPosMenu = Systems.Poseidon.Poseidon.CreateMenus()

		# Goal Completed
#		DebugPrint("E7DestroyPoseidonSensorGoal Complete!")
		MissionLib.RemoveGoal("E7DestroyPoseidonSensorGoal")

		pSequence = App.TGSequence_Create()

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Poseidon3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		if(iOutpostsDestroyed == iOutposts):
#			DebugPrint("All Outposts destroyed")
			pAction = App.TGScriptAction_Create(__name__, "MissionWin")
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	elif(sShipName == "Sensor Post 2") and not bOutpost2Destroyed:
		global iOutpostsDestroyed
		iOutpostsDestroyed = iOutpostsDestroyed + 1
#		DebugPrint("Sensor Post 2 destroyed")
#		DebugPrint("Sensor Posts destroyed = " +str(iOutpostsDestroyed))

		global bOutpost2Destroyed
		bOutpost2Destroyed = TRUE

		# If player has warped out already, make the enemies chase him
		MakeEnemiesInSetFollow("Artrus3", 1)

		pArtMenu = Systems.Artrus.Artrus.CreateMenus()

		# Goal Completed
#		DebugPrint("E7DestroyArtrusSensorGoal Complete!")
		MissionLib.RemoveGoal("E7DestroyArtrusSensorGoal")

		pSequence = App.TGSequence_Create()

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Artrus3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		if(iOutpostsDestroyed == iOutposts):
#			DebugPrint("All Outposts destroyed")
			pAction = App.TGScriptAction_Create(__name__, "MissionWin")
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	elif(sShipName == "Sensor Post 3") and not bOutpost3Destroyed:
		global iOutpostsDestroyed
		iOutpostsDestroyed = iOutpostsDestroyed + 1
#		DebugPrint("Sensor Post 3 destroyed")
#		DebugPrint("Sensor Posts destroyed = " +str(iOutpostsDestroyed))

		global bOutpost3Destroyed
		bOutpost3Destroyed = TRUE

		# If player has warped out already, make the enemies chase him
		MakeEnemiesInSetFollow("Serris3", 1)

		pSerMenu = Systems.Serris.Serris.CreateMenus()

		# Goal Completed
#		DebugPrint("E7DestroySerrisSensorGoal Complete!")
		MissionLib.RemoveGoal("E7DestroySerrisSensorGoal")

		pSequence = App.TGSequence_Create()

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Serris3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		if(iOutpostsDestroyed == iOutposts):
#			DebugPrint("All Outposts destroyed")
			pAction = App.TGScriptAction_Create(__name__, "MissionWin")
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	elif(sShipName == "Sensor Post 4") and not bOutpost4Destroyed:
		global iOutpostsDestroyed
		iOutpostsDestroyed = iOutpostsDestroyed + 1
#		DebugPrint("Sensor Post 4 destroyed")
#		DebugPrint("Sensor Posts destroyed = " +str(iOutpostsDestroyed))

		global bOutpost4Destroyed
		bOutpost4Destroyed = TRUE

		# If player has warped out already, make the enemies chase him
		MakeEnemiesInSetFollow("Geble4", 1)

		pGebMenu = Systems.Geble.Geble.CreateMenus()

		# Goal Completed
#		DebugPrint("E7DestroyGebleSensorGoal Complete!")
		MissionLib.RemoveGoal("E7DestroyGebleSensorGoal")

		pSequence = App.TGSequence_Create()

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M3Geble6", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		if(iOutpostsDestroyed == iOutposts):
#			DebugPrint("All Outposts destroyed")
			pAction = App.TGScriptAction_Create(__name__, "MissionWin")
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	# Play voice line if station is destroyed.
	elif(sShipName == "Resupply Station") and not bResupplyDestroyed:
		MissionLib.RemoveGoal("E7DestroyResupplyStationGoal")
		global bResupplyDestroyed
		bResupplyDestroyed = TRUE

		# If player has warped out already, make the enemies chase him
		MakeEnemiesInSetFollow("Ascella3", 1)

		MissionWin(None)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
#	ZeissLeaving() - Zeiss Warps out
#
def ZeissLeaving(pAction):
#	DebugPrint("Zeiss bids you adeiu")

	pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
	if pSanFrancisco:
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		if (bZeissLine == FALSE):
			pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
			pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M3Follow21", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E7M3Follow29", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create(__name__, "ZeissWarpOut")
		pSequence.AppendAction(pAction)
		pAction2 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M3Follow30", "Captain", 1, pMissionDatabase)
		pSequence.AddAction(pAction2, pAction, 5)

		MissionLib.QueueActionToPlay(pSequence)

	return 0


#
#	ZeissWarpOut() - Zeiss Warps out
#
def ZeissWarpOut(pAction):
#	DebugPrint("Zeiss warps out")
	pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")

	if pSanFrancisco:
		pSanFrancisco.SetAI(WarpAwayAI.CreateAI(pSanFrancisco))

		global bZeissPresent
		bZeissPresent = FALSE

	return 0


#
# FollowPlayer() - Set Enemy ships to follow the player
#
def FollowPlayer(*kShipNames):
	if(kShipNames is None):
		return

	for theShip in kShipNames:
		# Get this ship in any set
		pShip = MissionLib.GetShip(theShip, None, 1)

		if pShip:
			pWarp = pShip.GetWarpEngineSubsystem()
			pImpulse = pShip.GetImpulseEngineSubsystem()
		
			if pWarp and pImpulse and not (pWarp.IsDisabled()) and not (pImpulse.IsDisabled()):
				global pFollowObjGroup, iEnemiesFollowing
	
#				DebugPrint(theShip + " is following the player.")
				pFollowObjGroup.AddName(theShip)
				pShip.SetAI(EnemyFollowAI.CreateAI(pShip))

				if not (theShip == "KessokHeavy"):
					pShip.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".DisableSystemHandler")

				iEnemiesFollowing = iEnemiesFollowing + 1
		
#			else:
#				DebugPrint(theShip + "'s engines are out.  Can't following player.")


#
# Briefing() - Briefing dialogue
#
def Briefing():
	global g_bBriefingPlayed
	g_bBriefingPlayed = TRUE

	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg6", None, 0, pGeneralDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M3Briefing1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M3Briefing2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M3Briefing3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M3Briefing4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M3Briefing5", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M3Briefing6", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddMissionStuff")
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M3Hint", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction, 3)

	MissionLib.QueueActionToPlay(pSequence)


###############################################################################
#	AddMissionStuff()
#
#	Adds all the Mission 3 Goals and locations after the Briefing
#
#	Args:	none
#
#	Return:	none
###############################################################################
def AddMissionStuff(pAction):

	# Create timer to trigger Geronimo's distress call
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_DISTRESS, __name__+ ".DistressCall", fStartTime + 240, 0, 0)

	# Add E7M3 Goals
#	DebugPrint ("Adding E7M3 Goals.\n")
	MissionLib.AddGoal("E7DestroyPoseidonSensorGoal", "E7DestroyArtrusSensorGoal", "E7DestroyGebleSensorGoal", "E7DestroySerrisSensorGoal", "E7DestroyResupplyStationGoal")

#	DebugPrint ("Adding locations")

	App.SortedRegionMenu_SetPauseSorting(1)

	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()

	pPosMenu = Systems.Poseidon.Poseidon.CreateMenus()
	pPosMenu.SetMissionName("Maelstrom.Episode7.E7M3.E7M3")
	pPosMenu.SetPlacementName("Player Start")

	pGebMenu = Systems.Geble.Geble.CreateMenus()
	pGebMenu.SetMissionName("Maelstrom.Episode7.E7M3.E7M3")
	pGebMenu.SetPlacementName("Player Start")

	pSerMenu = Systems.Serris.Serris.CreateMenus()
	pSerMenu.SetMissionName("Maelstrom.Episode7.E7M3.E7M3")
	pSerMenu.SetPlacementName("Player Start")

	pArtMenu = Systems.Artrus.Artrus.CreateMenus()
	pArtMenu.SetMissionName("Maelstrom.Episode7.E7M3.E7M3")
	pArtMenu.SetPlacementName("Player Start")

	pAscMenu = Systems.Ascella.Ascella.CreateMenus()
	pAscMenu.SetMissionName("Maelstrom.Episode7.E7M3.E7M3")

	App.SortedRegionMenu_SetPauseSorting(0)

	return 0


#
# Remove all mission hooks to the menus
#
def RemoveHooks():

	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
	pPosMenu = Systems.Poseidon.Poseidon.CreateMenus()
	pGebMenu = Systems.Geble.Geble.CreateMenus()
	pSerMenu = Systems.Serris.Serris.CreateMenus()
	pArtMenu = Systems.Artrus.Artrus.CreateMenus()
	pAscMenu = Systems.Ascella.Ascella.CreateMenus()
	pXiEntMenu = Systems.XiEntrades.XiEntrades.CreateMenus()


#
# Terminate()
#
# Unload our mission database
#
def Terminate(pMission):
#	DebugPrint ("Terminating Episode 7, Mission 3.\n")

	RemoveHooks()

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()

	# Set our terminate flag to true
	global bMissionTerminate
	bMissionTerminate = TRUE

	# Remove handler for Contact Starfleet
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	# Remove Science Scan event
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	# Remove Instance handler for Kiska's dock button
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_DOCK, __name__+ ".DockHandler")
	pCommandFleetMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")
	if pCommandFleetMenu:
		pCommandFleetMenu.RemoveHandlerForInstance(Bridge.HelmMenuHandlers.ET_FLEET_COMMAND_DOCK_SB12, __name__+ ".DockHandler")
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	# Remove Communicate handlers
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	MissionLib.DeleteAllGoals()

	if (pGeneralDatabase):
		App.g_kLocalizationManager.Unload(pGeneralDatabase)

	if(pMenuDatabase):
		App.g_kLocalizationManager.Unload(pMenuDatabase)

	# Clear the set course menu
	App.SortedRegionMenu_ClearSetCourseMenu()