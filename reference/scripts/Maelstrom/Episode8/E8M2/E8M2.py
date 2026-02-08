###############################################################################
#	Filename:	E8M2.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Episode 8 Mission 2
#
#	Created:	11/09/00 -	Bill Morrison (added header)
#	Modified:	01/15/02 - 	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Maelstrom
import Maelstrom.Episode8.Episode8
import Bridge.Characters.Data
import LoadBridge
import Effects
import Bridge.Characters.CommonAnimations
import Bridge.BridgeMenus
import Bridge.BridgeUtils
import Bridge.ScienceCharacterHandlers
import Bridge.HelmMenuHandlers
import Bridge.BridgeEffects
import Systems.Starbase12.Starbase
import Systems.Starbase12.Starbase12
import Systems.OmegaDraconis.OmegaDraconis
import Systems.OmegaDraconis.OmegaDraconis1
import Systems.OmegaDraconis.OmegaDraconis3
import Systems.OmegaDraconis.OmegaDraconis5
import Systems.DeepSpace.DeepSpace
import Maelstrom.Episode7.E7M1.E7M1_P
import E8M2_P
import EBridge_P
import OrbitColonyAI
import WarpToOD3AI
import EnemyAI
import FriendlyAI
import Friendly2AI
import StayAI
import FleeAI
import WarpToOD1AI
import OrbitSolarformerAI
import AttackSolarformerAI
import AttackPlayerAI
import HybridFirstWaveAI
import HybridAI
import MainMenu.mainmenu

#
# Event types
#
ET_CHOOSE_TERRIK		= App.Mission_GetNextEventType()
ET_CHOOSE_KORBUS		= App.Mission_GetNextEventType()
ET_CHOOSE_ZEISS			= App.Mission_GetNextEventType()
ET_CHOOSE_MACCRAY		= App.Mission_GetNextEventType()
ET_LIU_TIMER			= App.Mission_GetNextEventType()
ET_WARP_WARN_RESET		= App.Mission_GetNextEventType()
ET_MATAN_TAUNT			= App.Mission_GetNextEventType()
ET_GO_SOLARFORMER		= App.Mission_GetNextEventType()
ET_ATTACK_KESSOK_RESET	= App.Mission_GetNextEventType()
ET_PICARD_TIMER			= App.Mission_GetNextEventType()
ET_COUNTDOWN			= App.Mission_GetNextEventType()
ET_NEW_HYBRID			= App.Mission_GetNextEventType()
ET_KESSOKS_DISAPPEAR	= App.Mission_GetNextEventType()
ET_SOLARFORMER_TIMER	= App.Mission_GetNextEventType()
ET_DATA_SOLARFORMER		= App.Mission_GetNextEventType()

#
# Global variables
#
g_pKiska			= None
g_pFelix			= None
g_pSaffi			= None
g_pMiguel			= None
g_pBrex				= None
g_pData				= None

g_pSaffiMenu		= None
g_pFelixMenu		= None
g_pKiskaMenu		= None
g_pMiguelMenu		= None
g_pBrexMenu			= None
g_pDataMenu			= None
g_idCreditsSequence	= App.NULL_ID
g_idWinMovieSequence	= App.NULL_ID

bDebugPrint			= 1

TRUE	= 1
FALSE	= 0

HASNT_ARRIVED		= 0
HAS_ARRIVED			= 1

pMissionDatabase	= None
pGeneralDatabase	= None
pMenuDatabase		= None

idInterruptSequence	= App.NULL_ID

iLiuTimer			= 0

bOD5Flag			= HASNT_ARRIVED
bOD3Flag			= HASNT_ARRIVED
bOD1Flag			= HASNT_ARRIVED

iOD5Keldons			= 5
iOD3Keldons			= 2
iOD3Kessoks			= 3
iOD5KeldonsToOD3	= 0

ENEMY				= 0
NEUTRAL				= 1
FRIENDLY			= 2
iKessokState		= ENEMY
iNumberChosen		= 0
iGroupGreetings		= 0

g_bMacCrayGreet		= FALSE
g_bZeissGreet		= FALSE
g_bKorbusGreet		= FALSE
g_bTerrikGreet		= FALSE
g_bPicardGreet		= FALSE

iLiuWarning			= 0
iTachyonEmitters	= 2
iCommArrayPlayed	= 0
iNumHybrids			= 0
iNewHybrids			= 0
iMatanTaunt			= 0
iMatanDisableCount	= 0
iWarpWarned			= 0

bJonkaAlive 		= -1
bChairoAlive		= -1
bKessokAlive 		= -1
bOmegaScanned		= FALSE
bWarpTried 			= FALSE
bTachyonDissipating	= FALSE
bWhyWarpSpeech		= FALSE
bDataInEngineering	= FALSE
bKessokWithYou		= FALSE
bKessokAttackWait	= FALSE
bMatanDisabled		= FALSE
bSolarformerFixed	= FALSE
bMatanCanArrive		= FALSE
bMatanArrived		= FALSE
bCountdownWarned	= FALSE
bLockOnMatan		= FALSE
bTorpedoFired		= FALSE
bMatanHit			= FALSE
bMatanScanned		= FALSE
bStopMatanScan		= FALSE
bSolarformerFlag	= FALSE
bSolarformerScanned	= FALSE
bDataAway			= FALSE
bCanDisableMatan	= FALSE
bMatanSolarformer 	= FALSE
bAlliesStay			= FALSE
bMatanDeparted		= FALSE
bCourseSet			= FALSE
bDataWantsToGo 		= FALSE
bDisableDialogue	= FALSE

g_bBriefingPlayed	= FALSE

bLiuChoose			= FALSE
bMacCrayChosen		= FALSE
bZeissChosen		= FALSE
bKorbusChosen		= FALSE
bTerrikChosen		= FALSE
bMissionTerminate	= FALSE
bAllowDmgDialogue	= FALSE		#Allows the damage dialogue to be spoken and not overlap
bImpulseOut			= FALSE
bSkipAttackWarn 	= FALSE
bMatanPunishment	= FALSE
bTractorTried		= FALSE

iAttackKessokWarn 	= 0
pMatanTorpedo		= 0
iCountdownMinutes	= 12

fStartTime			= 0
bAllowDamageDialogue = 0		#Allows the damage dialogue to be spoken and not overlap

kAllyList			= []
pKeldonGroup		= 0
pHybridGroup		= 0

g_bGraffWarned		= FALSE
g_bMacCrayWarned	= FALSE
g_bZeissWarned		= FALSE
g_bPicardWarned 	= FALSE
g_bKorbusWarned 	= FALSE
g_bTerrikWarned 	= FALSE


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
	loadspacehelper.PreloadShip("Enterprise", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	if Maelstrom.Maelstrom.bGeronimoAlive:
		loadspacehelper.PreloadShip("Geronimo", 1)
	if Maelstrom.Maelstrom.bZeissAlive:
		loadspacehelper.PreloadShip("Galaxy", 1)
	loadspacehelper.PreloadShip("Vorcha", 1)
	loadspacehelper.PreloadShip("Warbird", 1)
	if Maelstrom.Episode8.Episode8.KessoksFriendly:
		loadspacehelper.PreloadShip("KessokHeavy", 4)
	else:
		loadspacehelper.PreloadShip("KessokHeavy", 3)
	loadspacehelper.PreloadShip("CardHybrid", 8)
	loadspacehelper.PreloadShip("Keldon", 7)
	loadspacehelper.PreloadShip("MatanKeldon", 1)
	loadspacehelper.PreloadShip("CommLight", 2)
	loadspacehelper.PreloadShip("Sunbuster", 1)


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


#
# Initialize()
#
# Called to initialize our mission
#
def Initialize(pMission):
#	DebugPrint ("Initializing Episode 8, Mission 2.\n")

	# Check and see if we have a player, if we don't
	# we aren't linking and will have to call the initial
	# briefing "by hand" and the end of Initialize
	bHavePlayer = 0
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		bHavePlayer = 1

#	Uncomment the line below to test this mission with the Neb-lig
#	Maelstrom.Episode8.Episode8.KessoksFriendly = TRUE
	
	# Set bMissionTerminate here so it sets value correctly
	# if mission is reloaded
	global bMissionTerminate
	bMissionTerminate = FALSE

	# Setting Game Difficulty Multipliers
	App.Game_SetDifficultyMultipliers(1.5, 1.5, 1.0, 1.0, 0.8, 0.8)

	global pMissionDatabase, pGeneralDatabase, pMenuDatabase
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 8/E8M2.tgl")
	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Specify (and load if necessary) our bridge

	LoadBridge.Load("SovereignBridge")

	Bridge.Characters.CommonAnimations.PutGuestChairIn()

	# Add Data to the bridge
	pBridgeSet = App.g_kSetManager.GetSet("bridge")

	pData = App.CharacterClass_GetObject(pBridgeSet, "Data")
	if not (pData):
		pData = Bridge.Characters.Data.CreateCharacter(pBridgeSet)
		Bridge.Characters.Data.ConfigureForSovereign(pData)
		pData.SetLocation("EBGuest")

	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	# Create and load the Space Sets we'll need for this mission

	Systems.Starbase12.Starbase12.Initialize()
	pSet = Systems.Starbase12.Starbase12.GetSet()

	Systems.OmegaDraconis.OmegaDraconis1.Initialize()
	pOD1Set = Systems.OmegaDraconis.OmegaDraconis1.GetSet()

	Systems.OmegaDraconis.OmegaDraconis3.Initialize()
	pOD3Set = Systems.OmegaDraconis.OmegaDraconis3.GetSet()

	Systems.OmegaDraconis.OmegaDraconis5.Initialize()
	pOD5Set = Systems.OmegaDraconis.OmegaDraconis5.GetSet()

	Systems.DeepSpace.DeepSpace.Initialize()
	pSet2 = Systems.DeepSpace.DeepSpace.GetSet()

	CreateMenus()

	# Load our placements into this set
	Maelstrom.Episode7.E7M1.E7M1_P.LoadPlacements(pSet.GetName())
	E8M2_P.LoadPlacements(pOD1Set.GetName())
	E8M2_P.LoadPlacements(pOD3Set.GetName())
	E8M2_P.LoadPlacements(pOD5Set.GetName())

	# Load custom placements for bridge.
	EBridge_P.LoadPlacements(pBridgeSet.GetName())

	# Create character sets
	pLiuSet = MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	pLiu = MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet")
	
	MissionLib.SetupBridgeSet("FedOutpostSet", "data/Models/Sets/FedOutpost/fedoutpost.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Graff", "FedOutpostSet")

	if Maelstrom.Episode8.Episode8.KessoksFriendly == TRUE:
		pKessokBridgeSet = MissionLib.SetupBridgeSet("KessokSet", "data/Models/Sets/Kessok/kessokbridge.nif")
		MissionLib.SetupCharacter("Bridge.Characters.Kessok", "KessokSet")

	# Make a menu for Liu
	# if either the Geronimo or the San Francisco are alive or the Kessoks are friendly
	if (Maelstrom.Maelstrom.bZeissAlive == TRUE) or (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) or (Maelstrom.Episode8.Episode8.KessoksFriendly == TRUE):

		# Create Battle Group menu for Liu
		pLiuMenu = Bridge.BridgeMenus.CreateBlankCharacterMenu(pMissionDatabase.GetString("ChooseBattleGroup"), 0.28, 0.4, 0.7, 0.1)
		pLiu.SetMenu(pLiuMenu)
	
		# Create buttons for Liu's menu
		if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
			pLiu.AddPythonFuncHandlerForInstance(ET_CHOOSE_MACCRAY, __name__ + ".ChooseMacCray")
			pLiuMenu.AddChild(CreateBridgeMenuButton(pMissionDatabase.GetString("McCrayButton"), ET_CHOOSE_MACCRAY, 0, pLiu)) 
		if Maelstrom.Maelstrom.bZeissAlive == TRUE:
			pLiu.AddPythonFuncHandlerForInstance(ET_CHOOSE_ZEISS, __name__ + ".ChooseZeiss")
			pLiuMenu.AddChild(CreateBridgeMenuButton(pMissionDatabase.GetString("ZeissButton"), ET_CHOOSE_ZEISS, 0, pLiu)) 
		pLiu.AddPythonFuncHandlerForInstance(ET_CHOOSE_KORBUS, __name__ + ".ChooseKorbus")
		pLiuMenu.AddChild(CreateBridgeMenuButton(pMissionDatabase.GetString("KorbusButton"), ET_CHOOSE_KORBUS, 0, pLiu)) 
		pLiu.AddPythonFuncHandlerForInstance(ET_CHOOSE_TERRIK, __name__ + ".ChooseTerrik")
		pLiuMenu.AddChild(CreateBridgeMenuButton(pMissionDatabase.GetString("TerrikButton"), ET_CHOOSE_TERRIK, 0, pLiu)) 
	
	# Create the ships and set their stats
#	DebugPrint ("Creating Starbase 12 ships.\n")


	#
	# Starbase 12 ships
	#
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pSet, "player", "Player Start")
	pStarbase = loadspacehelper.CreateShip("FedStarbase", pSet, "Starbase 12", "Starbase Location")

	if Maelstrom.Episode8.Episode8.KessoksFriendly == TRUE:
#		DebugPrint ("Creating the Neb-lig")
		pKessok = loadspacehelper.CreateShip("KessokHeavy", pSet, "Neb-lig", "Nebula Way1")
		pKessok.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".KessoksAttacked")

		global bKessokWithYou, bKessokAlive
		bKessokWithYou = TRUE
		bKessokAlive = TRUE
		MissionLib.AddCommandableShip("Neb-lig")

		pCommandFleetMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")
		if pCommandFleetMenu:
			pCommandFleetMenu.AddPythonFuncHandlerForInstance(Bridge.HelmMenuHandlers.ET_FLEET_COMMAND_ATTACK_TARGET, __name__ + ".NebligAttackCommand")
			pCommandFleetMenu.AddPythonFuncHandlerForInstance(Bridge.HelmMenuHandlers.ET_FLEET_COMMAND_DISABLE_TARGET, __name__ + ".NebligAttackCommand")
#		else:
#			DebugPrint(__name__ + " error: Unable to get Command Fleet menu.")

	kAllyList.append("player")

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	######################
	# Setup Affiliations #
	######################
	global pFriendlies, pEnemies, pKeldonGroup, pHybridGroup

	pHybridGroup = App.ObjectGroup()

	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	if Maelstrom.Episode8.Episode8.KessoksFriendly == TRUE:
		pFriendlies.AddName("Neb-lig")

	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Keldon1")
	pEnemies.AddName("Keldon2")
	pEnemies.AddName("Keldon3")
	pEnemies.AddName("Keldon4")
	pEnemies.AddName("Keldon5")
	pEnemies.AddName("Keldon6")
	pEnemies.AddName("Keldon7")
	pEnemies.AddName("KessokHeavy1")
	pEnemies.AddName("KessokHeavy2")
	pEnemies.AddName("KessokHeavy3")
	pEnemies.AddName("Tachyon Emitter")
	pEnemies.AddName("Tachyon Emitter 2")
	pEnemies.AddName("Hybrid 1")
	pEnemies.AddName("Hybrid 2")
	pEnemies.AddName("Hybrid 3")
	pEnemies.AddName("Hybrid 4")
	pEnemies.AddName("Hybrid 5")
	pEnemies.AddName("Hybrid 6")
	pEnemies.AddName("Hybrid 7")
	pEnemies.AddName("Hybrid 8")
	pEnemies.AddName("Matan's Keldon")

	pKeldonGroup = App.ObjectGroup()
	pKeldonGroup.AddName("Keldon1")
	pKeldonGroup.AddName("Keldon2")
	pKeldonGroup.AddName("Keldon3")
	pKeldonGroup.AddName("Keldon4")
	pKeldonGroup.AddName("Keldon5")
	pKeldonGroup.AddName("Keldon6")
	pKeldonGroup.AddName("Keldon7")

	pHybridGroup = App.ObjectGroup()

	#####################################
	#
	#	Music Set up
	#
	#####################################
	#MissionLib.StandardMusic(pMission)

	# Setup more mission-specific events.
	SetupEventHandlers(pMission)

	# If the player was created from scratch, call our initial briefing
	if (bHavePlayer == 0):
		Briefing()

	MissionLib.SaveGame("E8M2-")

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
	global g_pData
	
	g_pKiska	= App.CharacterClass_GetObject(pBridge, "Helm")
	g_pFelix	= App.CharacterClass_GetObject(pBridge, "Tactical")
	g_pSaffi	= App.CharacterClass_GetObject(pBridge, "XO")
	g_pMiguel	= App.CharacterClass_GetObject(pBridge, "Science")
	g_pBrex		= App.CharacterClass_GetObject(pBridge, "Engineer")
	g_pData		= App.CharacterClass_GetObject(pBridge, "Data")
	
	global g_pSaffiMenu
	global g_pFelixMenu
	global g_pKiskaMenu
	global g_pMiguelMenu
	global g_pBrexMenu
	global g_pDataMenu
	
	g_pSaffiMenu = g_pSaffi.GetMenu()
	g_pFelixMenu = g_pFelix.GetMenu()
	g_pKiskaMenu = g_pKiska.GetMenu()
	g_pMiguelMenu = g_pMiguel.GetMenu()
	g_pBrexMenu = g_pBrex.GetMenu()
	g_pDataMenu = g_pData.GetMenu()

		
########################################
# Setup up Warp Menu Buttons for Helm  #
###############################	########

def CreateMenus():		
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()


#
# SetupEventHandlers()
#
def SetupEventHandlers(pMission):

	# AI Done event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_AI_DONE, pMission, __name__ +".AIDone")
	# AI Reached Waypoint event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_AI_REACHED_WAYPOINT, pMission, __name__ +".AIReachedWaypoint")
	# AI End Firing Run event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_AI_END_FIRING_RUN, pMission, __name__ +".AIEndFiringRun")
	# Exit warp event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_WARP, pMission, __name__ + ".ExitWarp")
	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ +".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ +".ObjectDestroyed")
	# Ship exploding event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectExploding")
	# Tractor Beam Handler
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STARTED_FIRING, pMission, __name__ + ".TractorHandler")

	# Instance handler for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")

	# Contact Starfleet event
	g_pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	# Scan event
	g_pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	# Hail event
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

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

	# Communicate with Data event
	g_pDataMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")


############################
#Mission Related Functions #
############################

#
#	NebligAttackCommand() - The Neb-lig is commanded to Attack a target
#
def NebligAttackCommand(pMenu, pEvent):
#	DebugPrint("Neb-lig given Fleet Command: Attack ")
	pCommandedShip = App.ShipClass_Cast(pEvent.GetSource())

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pTarget = pPlayer.GetTarget()
		if pTarget:
			sTarget = pTarget.GetName()
			if (sTarget[:len("KessokHeavy")] == "KessokHeavy"):
#				DebugPrint("Player is commanding %s to attack a KessokHeavy." % pCommandedShip.GetName())

				pKessokSet = App.g_kSetManager.GetSet("KessokSet")
				pKessok	= App.CharacterClass_GetObject(pKessokSet, "Kessok")

				pSequence = App.TGSequence_Create()

				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2OD3AttackKessoks4", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

				return

	pMenu.CallNextHandler(pEvent)


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
	sSetName = pSet.GetName()

	pAction = 0

	if pMenu.GetObjID() == g_pSaffiMenu.GetObjID():
#		DebugPrint("Communicating with Saffi")

		if bCourseSet and (sSetName == "Starbase12"):
#			DebugPrint("Let's go already!")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateSaffi1", None, 0, pMissionDatabase)

		elif ((sSetName == "OmegaDraconis5") and (iTachyonEmitters == 2)) or ((sSetName == "OmegaDraconis3") and (iTachyonEmitters == 1)):
#			DebugPrint("We should destroy the tachyon emitter")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateSaffi2", None, 0, pMissionDatabase)

		elif (sSetName == "OmegaDraconis3") and (iKessokState == ENEMY):
#			DebugPrint("Don't destroy the hostile Kessoks")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateSaffi3", None, 0, pMissionDatabase)

		elif (sSetName == "OmegaDraconis3") and bMatanDeparted:
#			DebugPrint("We should go after Matan")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateSaffi4", None, 0, pMissionDatabase)

		elif (sSetName == "OmegaDraconis1") and not bSolarformerFixed and not bDataAway:
#			DebugPrint("Forget about Matan.  Deal with the Solarformer.")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateSaffi5", None, 0, pMissionDatabase)

		elif bSolarformerFixed or bDataAway:
#			DebugPrint("Must keep Matan from destroying the Solarformer.")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateSaffi6", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pKiskaMenu.GetObjID():
#		DebugPrint("Communicating with Kiska")

		if bCourseSet and (sSetName == "Starbase12"):
#			DebugPrint("Ready to warp")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateKiska1", None, 0, pMissionDatabase)

		elif not (iKessokState == ENEMY) and (sSetName == "OmegaDraconis3") and (iOD3Kessoks > 1):
#			DebugPrint("Good thing we don't have to fight the Kessoks")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateKiska3", None, 0, pMissionDatabase)

		elif (sSetName == "OmegaDraconis1") and not bSolarformerFixed:
#			DebugPrint("Shall I take us closer to the Solarformer?")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateKiska4", None, 0, pMissionDatabase)

		elif ((iTachyonEmitters == 2) and (sSetName == "OmegaDraconis5")) or ((iTachyonEmitters == 1) and (sSetName == "OmegaDraconis3")):
			if (bWarpTried == FALSE):
#				DebugPrint("Why can't we warp?")
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Warp2", None, 0, pMissionDatabase)
			else:
#				DebugPrint("I still don't understand why we can't warp.")
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateKiska2", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pFelixMenu.GetObjID():
#		DebugPrint("Communicating with Felix")

		if (sSetName == "OmegaDraconis5"):
#			DebugPrint("The advantage of tachyon emitters")
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateFelix1", None, 0, pMissionDatabase)

		elif (sSetName == "OmegaDraconis3"):
			if (iTachyonEmitters == 1):
#				DebugPrint("Destroy the tachyon emitter ASAP")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateFelix2", None, 0, pMissionDatabase)

			elif (iNumHybrids > 1) and not bMatanDeparted:
#				DebugPrint("Destroy all the Hybrids")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateFelix3", None, 0, pMissionDatabase)

			elif bMatanDeparted:
#				DebugPrint("Aren't we going after Matan?")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateFelix4", None, 0, pMissionDatabase)

		elif (sSetName == "OmegaDraconis1"):
			if (bMatanHit == FALSE) and (bLockOnMatan == FALSE) and (bSolarformerFixed == FALSE):
#				DebugPrint("Standing by to hit Matan")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateFelix6", None, 0, pMissionDatabase)

			elif (bMatanHit == FALSE) and (bLockOnMatan == TRUE):
#				DebugPrint("I have a lock on Matan")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry1", None, 0, pMissionDatabase)

			elif not bSolarformerScanned:
#				DebugPrint("Let's blow up the Solarformer")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateFelix5", None, 0, pMissionDatabase)

			else:
#				DebugPrint("Matan is good, but we're better")
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateFelix7", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pMiguelMenu.GetObjID():
#		DebugPrint("Communicating with Miguel")

		if not bMatanDeparted and (iNumHybrids > 0) and (sSetName == "OmegaDraconis3"):
#			DebugPrint("Scan the Hybrids to find Matan")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateMiguel1", None, 0, pMissionDatabase)

		elif bMatanDeparted and (sSetName == "OmegaDraconis3"):
#			DebugPrint("More hybrids will be here soon")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateMiguel2", None, 0, pMissionDatabase)

		elif (sSetName == "OmegaDraconis1"):
			if (bMatanHit == FALSE) and (bLockOnMatan == FALSE) and (bSolarformerFixed == FALSE):
#				DebugPrint("Wait for Matan to taunt us")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateMiguel3", None, 0, pMissionDatabase)
	
			elif bMatanDisabled:
#				DebugPrint("Let's scan Matan")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateMiguel5", None, 0, pMissionDatabase)
	
			elif not bSolarformerScanned:
#				DebugPrint("Let's scan the Solarformer")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateMiguel4", None, 0, pMissionDatabase)

		elif not (sSetName == "Starbase12"):
#			DebugPrint("Scans are reading elevated radiation from the sun")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanArea4", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pBrexMenu.GetObjID():
#		DebugPrint("Communicating with Brex")

		if ((sSetName == "OmegaDraconis5") and (iTachyonEmitters == 2)) or ((sSetName == "OmegaDraconis3") and (iTachyonEmitters == 1)):
#			DebugPrint("We should destroy the tachyon emitter")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateBrex1", None, 0, pMissionDatabase)

		elif (iNumHybrids > 0) and (sSetName == "OmegaDraconis3"):
#			DebugPrint("Make every torpedo count")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateBrex2", None, 0, pMissionDatabase)

		elif (sSetName == "OmegaDraconis1"):
			if not bMatanDisabled:
#				DebugPrint("Let's scan Matan after we disable him")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateBrex3", None, 0, pMissionDatabase)

			elif not bMatanScanned:
#				DebugPrint("Let's scan Matan!")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateBrex4", None, 0, pMissionDatabase)
	
			elif not bSolarformerScanned:
#				DebugPrint("Let's scan the Solarformer")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateBrex5", None, 0, pMissionDatabase)

	else:
#		DebugPrint("Communicating with Data")

		if ((sSetName == "OmegaDraconis5") and (iTachyonEmitters == 2)) or ((sSetName == "OmegaDraconis3") and (iTachyonEmitters == 1)):
			iNum = App.g_kSystemWrapper.GetRandomNumber(2)

			if (iNum == 1) or not bKessokWithYou:
#				DebugPrint("We should destroy the tachyon emitter")
				pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateData1", None, 0, pMissionDatabase)

			else:
#				DebugPrint("Standing by to contact the Kessok colony")
				pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateData2", None, 0, pMissionDatabase)

		elif bMatanDeparted and (sSetName == "OmegaDraconis5"):
#			DebugPrint("Let's go after Matan")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateData3", None, 0, pMissionDatabase)

		elif not bSolarformerScanned and (sSetName == "OmegaDraconis1"):
#			DebugPrint("Let's scan the Solarformer")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateData4", None, 0, pMissionDatabase)

		elif bDataWantsToGo:
#			DebugPrint("I would like to beam over to the Solarformer")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateData5", None, 0, pMissionDatabase)

		elif bSolarformerFixed:
#			DebugPrint("Stop Matan")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommunicateData6", None, 0, pMissionDatabase)

	if pAction:
		pAction.Play()

	else:
#		DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")
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
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailStarbase", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E8M2HitStarbase", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "USS Geronimo") and (g_bMacCrayWarned == FALSE):
#		DebugPrint("MacCray warns you about hitting the Geronimo")

		global g_bMacCrayWarned
		g_bMacCrayWarned = TRUE

		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		iNum = App.g_kSystemWrapper.GetRandomNumber(2)
		if (iNum == 1):
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailMcCray1", None, 0, pMissionDatabase)
		else:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailMcCray2", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2HitGeronimo", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

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

		iNum = App.g_kSystemWrapper.GetRandomNumber(2)
		if iNum == 1:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailZeiss1", None, 0, pMissionDatabase)
	
		else:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailZeiss2", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2HitSanFrancisco", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "USS Enterprise") and (g_bPicardWarned == FALSE):
#		DebugPrint("Picard warns you about hitting the Enterprise")

		global g_bPicardWarned
		g_bPicardWarned = TRUE

		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pPicard = App.CharacterClass_GetObject (pEBridgeSet, "Picard")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart05", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2HitEnterprise", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "JonKa") and (g_bKorbusWarned == FALSE):
#		DebugPrint("Korbus warns you about hitting the JonKa")

		global g_bKorbusWarned
		g_bKorbusWarned = TRUE

		pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
		pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		iNum = App.g_kSystemWrapper.GetRandomNumber(2)
		if iNum == 1:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus1", None, 0, pMissionDatabase)
	
		else:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus2", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2HitJonka", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "Chairo") and (g_bTerrikWarned == FALSE):
#		DebugPrint("Terrik warns you about hitting the Chairo")

		global g_bTerrikWarned
		g_bTerrikWarned = TRUE

		pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
		pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		iNum = App.g_kSystemWrapper.GetRandomNumber(2)
		if iNum == 1:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailTerrik1", None, 0, pMissionDatabase)
	
		else:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailTerrik2", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2HitChairo", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)


#
# TractorHandler() - Keeps you from using the tractor beam in OD1
#
def TractorHandler(pObject, pEvent):
#	DebugPrint ("Checking to use tractor beam")

	# if you are in OD1
	if (bOD1Flag == HAS_ARRIVED):
		pSet = App.g_kSetManager.GetSet("OmegaDraconis1")
		pPlayer = MissionLib.GetPlayer()

		pTacCtrlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		pTacWeaponsCtrl = pTacCtrlWindow.GetWeaponsControl()

#		DebugPrint ("Can't use tractor beam in OD1")
		# Can't use tractor beam in OD1
		pPlayer.GetTractorBeamSystem().StopFiring()
		pTacWeaponsCtrl.RefreshTractorToggle()

		if bTractorTried == FALSE:
			global bTractorTried
			bTractorTried = TRUE
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated11", "Captain", 1, pMissionDatabase)
		else:
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated11b", "Captain", 1, pMissionDatabase)

		pAction.Play()


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
	if (bAllowDamageDialogue == 1):
		return
	global bAllowDamageDialogue
	bAllowDamageDialogue = 1

	if (sShipName == "USS Geronimo"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if (pPlayerSetName != pGeronimoSetName):
			return

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 50):
#				DebugPrint("Geronimo shields down to 50 percent.")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2GeronimoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 0):
#				DebugPrint("Geronimo shields are gone!")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2GeronimoShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 50):
#				DebugPrint("Geronimo hull down to 50 percent.")

				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)
		
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailMacCray1", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2GeronimoHull50", None, 0, pMissionDatabase)	
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 25):
#				DebugPrint("Geronimo hull down to 25 percent.")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2GeronimoHull25", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return
		else:
			return

	elif (sShipName == "USS San Francisco"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		pSanFranciscoSetName = pSanFrancisco.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if (pPlayerSetName != pSanFranciscoSetName):
			return

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 50):
#				DebugPrint("San Francisco shields down to 50 percent")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2SanFranciscoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 0):
#				DebugPrint("San Francisco shields are gone!")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2SanFranciscoShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 50):
#				DebugPrint("San Francisco hull down to 50 percent")

				pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
				pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailZeiss1", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2SanFranciscoHull25", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 25):
#				DebugPrint("San Francisco hull down to 25 percent")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2SanFranciscoHull50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return
		else:
			return

	elif (sShipName == "JonKa"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pJonka = App.ShipClass_GetObject( App.SetClass_GetNull(), "JonKa")
		pJonkaSetName = pJonka.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if (pPlayerSetName != pJonkaSetName):
			return

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 50):
#				DebugPrint("Jonka shields down to 50 percent")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2JonkaShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 0):
#				DebugPrint("Jonka shields are gone!")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2JonkaShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 50):
#				DebugPrint("Jonka hull down to 50 percent")

				pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
				pKorbus	= App.CharacterClass_GetObject(pKorbusSet, "Korbus")

				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus1", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2JonkaHull25", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 25):
#				DebugPrint("Jonka hull down to 25 percent")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2JonkaHull50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return
		else:
			return

	elif (sShipName == "Chairo"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pChairo = App.ShipClass_GetObject( App.SetClass_GetNull(), "Chairo")
		pChairoSetName = pChairo.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if (pPlayerSetName != pChairoSetName):
			return

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 50):
#				DebugPrint("Chairo shields down to 50 percent")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ChairoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 0):
#				DebugPrint("Chairo shields are gone!")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ChairoShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 50):
#				DebugPrint("Chairo hull down to 50 percent")

				pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
				pTerrik	= App.CharacterClass_GetObject(pTerrikSet, "Terrik")

				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailTerrik1", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2ChairoHull25", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 25):
#				DebugPrint("Chairo hull down to 25 percent")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ChairoHull50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return
		else:
			return

	elif (sShipName == "Neb-lig"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pKessok = App.ShipClass_GetObject( App.SetClass_GetNull(), "Neb-lig")
		pKessokSetName = pKessok.GetContainingSet().GetName()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		if (pPlayerSetName != pKessokSetName):
			return

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 50):
#				DebugPrint("Neb-lig shields down to 50 percent")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2KessokShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 0):
#				DebugPrint("Kessok shields are gone!")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2KessokShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 50):
#				DebugPrint("Neb-lig hull down to 50 percent")

				pKessokSet = App.g_kSetManager.GetSet("KessokSet")
				pKessok	= App.CharacterClass_GetObject(pKessokSet, "Kessok")

				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok1", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2KessokHull25", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 25):
#				DebugPrint("Neb-lig hull down to 25 percent")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2KessokHull50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return
		else:
			return

	return 0


#
# Reset the Call Damage global
# Called from script above
#
def ReAllowDamageDialogue(pAction):
	#Make sure nothing overlaps
	global bAllowDamageDialogue
	bAllowDamageDialogue = 0

	return 0


#
# AIDone()
#
def AIDone(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
#	DebugPrint('AIDone() called for ' + pShip.GetName())

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# AIReachedWaypoint()
#
def AIReachedWaypoint(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
#	DebugPrint('AIReachedWaypoint() called for ' + pShip.GetName())
	pWay = pEvent.GetPlacement()
	
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# AIEndFiringRun()
#
def AIEndFiringRun(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
#	DebugPrint(pShip.GetName() + " ended its firing run.")

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)



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
	"An event triggered whenever an object enters a set."
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	if (pShip):
		pSet = pShip.GetContainingSet()
#		DebugPrint("Ship \"" + pShip.GetName() + "\" entered set \"" + pSet.GetName() + "\"")

		sShipName = pShip.GetName()
		sSetName = pSet.GetName()

		if (sSetName == "Starbase12") and (bOD5Flag == HASNT_ARRIVED) and not (sShipName == "Chairo"):
#			DebugPrint ("One of your allies (" + pShip.GetName() + ") has arrived, target him.")
			pPlayer = MissionLib.GetPlayer()
			pPlayer.SetTarget(sShipName)
#			DebugPrint("Target is now " + sShipName)

		elif (sSetName == "OmegaDraconis5"):
			if not (sShipName == "player"):
				if bOD5Flag == HASNT_ARRIVED and (pFriendlies.IsNameInGroup(sShipName)):
#					DebugPrint ("Making " + sShipName + " stay put.")
					pShip.SetAI(StayAI.CreateAI(pShip))

			else:
				if bOD5Flag == HASNT_ARRIVED:
					pPlayer = MissionLib.GetPlayer()
					pPlayer.SetTarget("")
	
#					DebugPrint ("Creating OD5 ships.\n")
					pKeldon1 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon1", "Kessok1 Start" )
					pKeldon2 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon2", "Kessok2 Start" )	
					pKeldon3 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon3", "Kessok3 Start" )	
					pKeldon4 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon4", "Kessok4 Start" )	
					pKeldon5 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon5", "Kessok5 Start" )	
					pTachyon = loadspacehelper.CreateShip( "CommLight", pSet, "Tachyon Emitter", "Emitter Location" )
	
				pSequence = App.TGSequence_Create()
				pAction = App.TGScriptAction_Create(__name__, "OD5Arrive")
				pSequence.AddAction(pAction, None, 5)

				MissionLib.QueueActionToPlay(pSequence)

		elif (sSetName == "OmegaDraconis3"):
			if not (sShipName == "player"):
				if bOD3Flag == HASNT_ARRIVED and (pFriendlies.IsNameInGroup(sShipName)):
#					DebugPrint ("Making " + sShipName + " stay put.")
					pShip.SetAI(StayAI.CreateAI(pShip))

			else:
				if bOD3Flag == HASNT_ARRIVED:
					MissionLib.SaveGame("E8M2-OmegaDraconis3-")
		
					pKeldon6 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon6", "Kessok5 Start" )
					pKeldon7 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon7", "Kessok6 Start" )
					pTachyon2 = loadspacehelper.CreateShip( "CommLight", pSet, "Tachyon Emitter 2", "Buster Location" )
					pKessokHeavy1 = loadspacehelper.CreateShip( "KessokHeavy", pSet, "KessokHeavy1", "Kessok2 Start" )
					pKessokHeavy2 = loadspacehelper.CreateShip( "KessokHeavy", pSet, "KessokHeavy2", "Kessok3 Start" )
					pKessokHeavy3 = loadspacehelper.CreateShip( "KessokHeavy", pSet, "KessokHeavy3", "Kessok4 Start" )
					# Check to see if the Kessoks are attacked by you
					pKessokHeavy1.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".KessoksAttacked")
					pKessokHeavy2.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".KessoksAttacked")
					pKessokHeavy3.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".KessoksAttacked")

				pSequence = App.TGSequence_Create()
				pAction = App.TGScriptAction_Create(__name__, "OD3Arrive")
				pSequence.AddAction(pAction, None, 5)

				MissionLib.QueueActionToPlay(pSequence)

			if (sShipName == "Keldon1") or (sShipName == "Keldon2") or (sShipName == "Keldon3") or (sShipName == "Keldon4") or (sShipName == "Keldon5"):
				if iOD5Keldons == 1:
#					DebugPrint("Only one OD5 Keldon left.  Going for reinforcements.")
					pShip.SetDeleteMe(1)
				elif iOD5KeldonsToOD3 < 3:
#					DebugPrint("Adding one OD5Keldon to iOD3Keldons")
					global iOD5KeldonsToOD3, iOD3Keldons
					iOD5KeldonsToOD3 = iOD5KeldonsToOD3 + 1
					iOD3Keldons = iOD3Keldons + 1
				else:
#					DebugPrint("Too many ships here.  Deleting ship.")
					pShip.SetDeleteMe(1)
		elif (sSetName == "OmegaDraconis1"):
			if not (sShipName == "player"):
				if bOD1Flag == HASNT_ARRIVED and (pFriendlies.IsNameInGroup(sShipName)):
#					DebugPrint ("Making " + sShipName + " stay put.")
					pShip.SetAI(StayAI.CreateAI(pShip))

			else:
				if bOD1Flag == HASNT_ARRIVED:

					# Delete extra sets, since we won't be returning
					App.g_kSetManager.DeleteSet("OmegaDraconis3")
					App.g_kSetManager.DeleteSet("OmegaDraconis5")
					App.g_kSetManager.DeleteSet("Starbase12")

					MissionLib.SaveGame("E8M2-OmegaDraconis1-")

					pBuster = loadspacehelper.CreateShip( "Sunbuster", pSet, "Solarformer", "Buster Location" )

					# Bring down Solarformer's shields
					pShields = pBuster.GetShields()
					if not pShields == None:
						MissionLib.SetConditionPercentage (pShields, 0)

#					DebugPrint("Adding LostImpulseHandler to player")
					pShip.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".LostImpulseHandler")

				OD1Arrive()

		if (sShipName == "Neb-lig"):
#			DebugPrint("Neb-lig is with you")
			global bKessokWithYou
			bKessokWithYou = TRUE

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# TorpedoEnterSet()
#
def TorpedoEnterSet(TGObject, pEvent):
	"An event triggered whenever an torpedo enters a set."
	pTorpedo = App.Torpedo_Cast(pEvent.GetDestination())

	if pTorpedo:
		if bLockOnMatan:
		 	# If you are locked onto Matan
#			DebugPrint("Attempting to hit Matan's cloaked Keldon")
			pTarget = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), pTorpedo.GetTargetID())

			if (pTarget.GetName() == "Matan's Keldon"):
				# Set the torpedo lifetime to 10 seconds
				pTorpedo.SetLifetime(10)
				global kTorpedo
				pMatanTorpedo = pTorpedo

				if (bTorpedoFired == FALSE):
					global bTorpedoFired
					bTorpedoFired = TRUE
	
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry8", None, 0, pMissionDatabase)
					pAction.Play()

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


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
		
#	if (pShip):
#		DebugPrint("Ship \"" + pShip.GetName() + "\" exited set \"" + sSetName + "\"")
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# TorpedoExitSet()
#
def TorpedoExitSet(TGObject, pEvent):
	"Triggered whenever a torpedo leaves a set."
	# Check and see if mission is terminating, if so return
	if (bMissionTerminate == TRUE):
		return

	if bTorpedoFired == TRUE and bMatanHit == FALSE:
	 	# If the Torpedo is trying to hit Matan
		pTorpedo = App.Torpedo_Cast(pEvent.GetDestination())

		if pTorpedo == pMatanTorpedo:
#			DebugPrint("The torpedo missed Matan!")

			global bTorpedoFired, bMatanHit
			bTorpedoFired = FALSE
			bMatanHit = -1

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)
	
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry9", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry4", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# ObjectDestroyed()
#
def ObjectDestroyed(TGObject, pEvent):
#	DebugPrint("Object Destroyed")
	pShip = App.ObjectClass_Cast(pEvent.GetDestination())

	if pShip:
		sShipName = pShip.GetName()
#		DebugPrint("Ship \"" + pShip.GetName() + "\" was destroyed")

		if (sShipName == "Keldon1") or (sShipName == "Keldon2") or (sShipName == "Keldon3") or (sShipName == "Keldon4") or (sShipName == "Keldon5"):
			global iOD5Keldons
			iOD5Keldons = iOD5Keldons - 1
#			DebugPrint(str(iOD5Keldons) + " OD5 Keldons left")

			if (iOD5Keldons == 0) and (pEvent.GetCString() == "OmegaDraconis5"):
				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD5CardDestroyed1", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				if (iTachyonEmitters == 2):
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD5CardDestroyed2", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

			elif (pEvent.GetCString() == "OmegaDraconis3"):
				global iOD3Keldons
				iOD3Keldons = iOD3Keldons - 1
#				DebugPrint(str(iOD3Keldons) + " OD3 Keldons left")

				if (iOD3Keldons == 0) and bMatanCanArrive:

					pSequence = App.TGSequence_Create()
					pAction = App.TGScriptAction_Create(__name__, "MatanCometh")
					pSequence.AppendAction(pAction, 5)

					MissionLib.QueueActionToPlay(pSequence)

		elif (sShipName == "Keldon6") or (sShipName == "Keldon7"):
			global iOD3Keldons
			iOD3Keldons = iOD3Keldons - 1
#			DebugPrint(str(iOD3Keldons) + " OD3 Keldons left")

			if iOD3Keldons == 0 and bMatanCanArrive:
				pSequence = App.TGSequence_Create()
				pAction = App.TGScriptAction_Create(__name__, "MatanCometh")
				pSequence.AppendAction(pAction, 5)

				MissionLib.QueueActionToPlay(pSequence)
	
		elif (sShipName == "KessokHeavy1") or (sShipName == "KessokHeavy2") or (sShipName == "KessokHeavy3"):
			global iOD3Kessoks
			iOD3Kessoks = iOD3Kessoks - 1
#			DebugPrint(str(iOD3Kessoks) + " OD3 Kessoks left")
			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			if not iOD3Kessoks == 0:
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3KesDestroyed1", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

				if iKessokState == ENEMY:
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3KesDestroyed2", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
			else:
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3KesDestroyed3", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3KesDestroyed4", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

		elif (sShipName == "Tachyon Emitter"):
#			DebugPrint ("Tachyon Emitter destroyed. One more remaining.")
			global iTachyonEmitters, bTachyonDissipating, iCommArrayPlayed
			iTachyonEmitters = iTachyonEmitters - 1
			bTachyonDissipating = 1

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD5EmitDestroyed", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			if bKessokWithYou:
				pKessokSet = App.g_kSetManager.GetSet("KessokSet")
				pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok1", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2ContactFailed3", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

			else:
				if iCommArrayPlayed == 0:
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray2", "E", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray3", "Captain", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray4", "Captain", 1, pMissionDatabase)
					pSequence.AddAction(pAction2, pAction, 20)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray5", "E", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray7", "E", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "L1")
					pSequence.AppendAction(pAction)
			
					global iCommArrayPlayed
					iCommArrayPlayed = 2

				elif App.g_kSetManager.GetSet("EngineeringSet") == None:
					pEngineering = MissionLib.SetupBridgeSet("EngineeringSet", "data/Models/Sets/SovereignEng/sovereignEng.nif")
					pEData = Bridge.Characters.Data.CreateCharacter(pEngineering)
					Bridge.Characters.Data.ConfigureForEngineering(pEData)
					pEData.SetTranslateXYZ(0, 0, 5)
				else:
					pEngineering = App.g_kSetManager.GetSet("EngineeringSet")
					pEData = App.CharacterClass_GetObject(pEngineering, "Data")

				pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ContactFailed1", None, 0, pMissionDatabase)
				if bDataInEngineering == FALSE:
					global bDataInEngineering
					bDataInEngineering = TRUE
					pSequence.AddAction(pAction2, pAction, 15)
				else:
					pSequence.AppendAction(pAction2)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EngineeringSet", "Data")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pEData, App.CharacterAction.AT_SAY_LINE, "E8M2ContactFailed2", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				
			pAction = App.TGScriptAction_Create(__name__, "TachyonDissipate")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Warp9", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

			if not iOD5Keldons == 0:
				pAction = App.TGScriptAction_Create(__name__, "KeldonsRetreat")
				pSequence.AppendAction(pAction)
				if iOD5Keldons == 1:
					pAction2 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD5CardRetreat1b", "Captain", 1, pMissionDatabase)
				else:
					pAction2 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD5CardRetreat1a", "Captain", 1, pMissionDatabase)
				pSequence.AddAction(pAction2, pAction, 5)
				pAction3 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2OD5CardRetreat2", "Captain", 1, pMissionDatabase)
				pSequence.AddAction(pAction3, pAction2, 2)

			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2StarbaseSuggest", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ContactFailed4", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

		elif (sShipName == "Tachyon Emitter 2"):
#			DebugPrint ("Tachyon Emitter destroyed. That's the last one.")
			global iTachyonEmitters, bTachyonDissipating
			iTachyonEmitters = iTachyonEmitters - 1
			bTachyonDissipating = 1

#			DebugPrint ("Removing ContactKessoks and DestroyEmitters Goals")
			MissionLib.RemoveGoal("E8ContactKessoksGoal", "E8DestroyEmittersGoal")

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3EmitDestroyed1", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2OD3EmitDestroyed2", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			if bKessokWithYou:
				pKessokSet = App.g_kSetManager.GetSet("KessokSet")
				pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks1a", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks2a", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction, 25)
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok1", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction, 10)
				pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks2c", None, 0, pMissionDatabase)
				pSequence.AddAction(pAction2, pAction)
				pAction3 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
				pSequence.AddAction(pAction3, pAction)
				pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks3b", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				if iOD3Keldons > 0:
					pAction = App.TGScriptAction_Create(__name__, "SetKessoksFriendly")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks4b", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

			else:
				if iCommArrayPlayed == 0:
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray2", "E", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray3", "Captain", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray4", "Captain", 1, pMissionDatabase)
					pSequence.AddAction(pAction2, pAction, 30)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray5", "E", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray7", "E", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "L1")
					pSequence.AppendAction(pAction)
			
					global bDataInEngineering, iCommArrayPlayed
					bDataInEngineering = TRUE
					iCommArrayPlayed = 3

				elif App.g_kSetManager.GetSet("EngineeringSet") == None:
					pEngineering = MissionLib.SetupBridgeSet("EngineeringSet", "data/Models/Sets/SovereignEng/sovereignEng.nif")
					pEData = Bridge.Characters.Data.CreateCharacter(pEngineering)
					Bridge.Characters.Data.ConfigureForEngineering(pEData)
					pEData.SetTranslateXYZ(0, 0, 5)
				else:
					pEngineering = App.g_kSetManager.GetSet("EngineeringSet")
					pEData = App.CharacterClass_GetObject(pEngineering, "Data")

				pAction2 = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2DataToBridge", "Data")
				if iCommArrayPlayed == 3:
					pSequence.AddAction(pAction2, pAction, 20)
				else:
					pSequence.AppendAction(pAction2)
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, pGeneralDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EngineeringSet", "Data")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pEData, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks1b", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks2a", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction, 25)
				pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2DataToBridge", "Data")
				pSequence.AppendAction(pAction, 10)
				pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks2c", None, 0, pMissionDatabase)
				pSequence.AddAction(pAction2, pAction)
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, pGeneralDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EngineeringSet", "Data")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pEData, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks2b", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				if iOD3Keldons > 0:
					pAction = App.TGScriptAction_Create(__name__, "KessokAttackWait")
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create(__name__, "SetKessoksFriendly")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks3", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks4", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pEData, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks5b", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ContactKessoks6b", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "KessokAttackWait", 0)
				pSequence.AppendAction(pAction)
				pAction2 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "X")
				pSequence.AddAction(pAction2, pAction, 20)

			if iOD3Keldons == 0:
				pAction = App.TGScriptAction_Create(__name__, "MatanCometh")
				pSequence.AppendAction(pAction)
			else:
				global bMatanCanArrive
				bMatanCanArrive = TRUE

			MissionLib.QueueActionToPlay(pSequence)

		elif (pHybridGroup.IsNameInGroup(sShipName)):
#			DebugPrint (sShipName + " destroyed.")

			# Remove this Hybrid from the group
			global pHybridGroup
			pHybridGroup.RemoveName(sShipName)

			# One less Hybrid
			global iNumHybrids
			iNumHybrids = iNumHybrids - 1

			if (iNumHybrids == 0):
				# That's the last of the Hybrids.  Matan leaves
				MatanLeaving()

		elif (sShipName[:len("Hybrid")] == "Hybrid"):
#			DebugPrint (sShipName + " destroyed. Setting timer to warp in new Hybrid.")

			fStartTime = App.g_kUtopiaModule.GetGameTime()

			iTimer = 0

			if iNewHybrids %2 == 0:
				iTimer = 30

			else:
				iTimer = 40

			MissionLib.CreateTimer(ET_NEW_HYBRID, __name__ + ".WarpInNewHybrid", fStartTime + iTimer, 0, 0)

#		elif (sShipName == "Matan's Ship"):
#			DebugPrint ("Um, Matan should be invincible.  Something has gone very wrong...")

		elif (sShipName == "USS Geronimo"):
#			DebugPrint ("Geronimo destroyed dialogue")
			Maelstrom.Maelstrom.bGeronimoAlive = FALSE

			g_pMiguel.SayLine(pMissionDatabase, "E8M2GeronimoDestroyed", "Captain", 1)

		elif (sShipName == "USS San Francisco"):
#			DebugPrint ("San Francisco destroyed dialogue")
			Maelstrom.Maelstrom.bZeissAlive = FALSE

			g_pMiguel.SayLine(pMissionDatabase, "E8M2SanFranciscoDestroyed", "Captain", 1)

		elif (sShipName == "JonKa"):
#			DebugPrint ("JonKa destroyed dialogue")

			global bJonkaAlive
			bJonkaAlive = FALSE

			g_pMiguel.SayLine(pMissionDatabase, "E8M2JonkaDestroyed", "Captain", 1)

		elif (sShipName == "Chairo"):
#			DebugPrint ("Chairo destroyed dialogue")

			global bChairoAlive
			bChairoAlive = FALSE

			g_pMiguel.SayLine(pMissionDatabase, "E8M2ChairoDestroyed", "Captain", 1)

		elif (sShipName == "Neb-lig"):
#			DebugPrint ("Neb-lig destroyed dialogue")

			global bKessokWithYou, bKessokAlive
			bKessokWithYou = FALSE
			bKessokAlive = FALSE

			g_pMiguel.SayLine(pMissionDatabase, "E8M2KessokDestroyed", "Captain", 1)

		elif (sShipName == "Starbase 12"):
			MissionLib.GameOver(None)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# The handler for object exploding event.
#
def ObjectExploding(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	
	sShipName = pShip.GetName()

	if (sShipName == "Solarformer"):
#		DebugPrint ("Solarformer destroyed. All is lost.")

		global bSolarformerFixed
		bSolarformerFixed = -1

		# Abort Sequence, if any is going on
		global idInterruptSequence
		pInterruptSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(idInterruptSequence))
		if (pInterruptSequence):
			pInterruptSequence.Completed()
			idInterruptSequence = App.NULL_ID

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create(__name__, "DisableTimedDialogue")
		pSequence.AppendAction(pAction)

		if bDataAway:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2BusterDestroyed1a", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2BusterDestroyed2a", "S", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2BusterDestroyed3a", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2BusterDestroyed4a", "S", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif bSolarformerScanned:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2BusterDestroyed5a", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

		else:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2BusterDestroyed5b", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2BusterDestroyed6", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		if bMatanSolarformer == TRUE:
#			DebugPrint ("Solarformer destroyed by Matan")
			pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2BusterDestroyed8a", "Matan")
			pSequence.AppendAction(pAction)
		else:
#			DebugPrint ("Solarformer destroyed by Player")
			pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2BusterDestroyed8b", "Matan")
			pSequence.AppendAction(pAction)

#		DebugPrint("The sun implodes.  Game over...")

		global iCountdownMinutes
		iCountdownMinutes = -1

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown0", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown0b", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = EndGameMovie ("data/Movies/FinalLose2.bik")
		pSequence.AppendAction(pAction)

		MissionLib.GameOver(None, pSequence)


#
# KessokAttackWait()
#
def KessokAttackWait(pAction, iInt = 1):
	global bKessokAttackWait

	if iInt:
		bKessokAttackWait = TRUE
	else:
		bKessokAttackWait = FALSE

	return 0


#
#	WarpInNewHybrid() - Warps in another Hybrid
#
def WarpInNewHybrid(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")
	pPlayerSet = MissionLib.GetPlayerSet()
	pMission = MissionLib.GetMission()
	if not pSet:
		return
	if not pPlayerSet:
		return

	# If player is in OmegaDraconis3, warp in another Hybrid
	if (pSet.GetName() == pPlayerSet.GetName()):
		global iNewHybrids
		iNewHybrids = iNewHybrids + 1

#		DebugPrint ("Warping in Hybrid" + str(iNewHybrids))

		pHybrid = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid " + str(iNewHybrids), "Hybrid1 Enter", 1 )

		global pEnemies
		pMission = MissionLib.GetMission()
		pEnemies = pMission.GetEnemyGroup()
		pEnemies.AddName("Hybrid " + str(iNewHybrids))

		pHybrid.SetAI(HybridFirstWaveAI.CreateAI(pHybrid))

		# Set up dialogue sequence for Felix to inform you of the new Hybrids
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids22", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		if iNewHybrids == 6:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids23", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif iNewHybrids == 7:
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids24", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids25", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids26", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

#	else: 
#		DebugPrint ("Player not in OmegaDraconis3.  Overriding new Hybrid")


#
#	SetKessoksNeutral() - Makes the Kessoks neutral to the player
#
def SetKessoksNeutral(pAction):
#	DebugPrint("Setting Kessoks AI to Neutral")

	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")

	pMission = MissionLib.GetMission()
	global pNeutrals, pEnemies
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.RemoveName("KessokHeavy1")
	pEnemies.RemoveName("KessokHeavy2")
	pEnemies.RemoveName("KessokHeavy3")
	pNeutrals = pMission.GetNeutralGroup()
	pNeutrals.AddName("KessokHeavy1")
	pNeutrals.AddName("KessokHeavy2")
	pNeutrals.AddName("KessokHeavy3")

	global iKessokState
	iKessokState = NEUTRAL
	# Set its AI
	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy1")
	if pKessok:
		pKessok.SetAI(OrbitColonyAI.CreateAI(pKessok))
	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy2")
	if pKessok:
		pKessok.SetAI(OrbitColonyAI.CreateAI(pKessok))
	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy3")
	if pKessok:
		pKessok.SetAI(OrbitColonyAI.CreateAI(pKessok))

	return 0

#
#	SetKessoksNeutral2() - Makes the Kessoks neutral to the player
#
def SetKessoksNeutral2(pAction):
#	DebugPrint("Setting Kessoks AI to Neutral again")

	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")

	pMission = MissionLib.GetMission()
	global pNeutrals, pFriendlies
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("KessokHeavy1")
	pFriendlies.AddName("KessokHeavy2")
	pFriendlies.AddName("KessokHeavy3")
	pNeutrals = pMission.GetNeutralGroup()
	pNeutrals.AddName("KessokHeavy1")
	pNeutrals.AddName("KessokHeavy2")
	pNeutrals.AddName("KessokHeavy3")

	global iKessokState
	iKessokState = NEUTRAL

	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy1")
	if pKessok:
		pKessok.SetAI(OrbitColonyAI.CreateAI(pKessok))

		pCloak = pKessok.GetCloakingSubsystem()
		if pCloak and not ((pKessok.IsCloaked()) or (pCloak.IsCloaking())):
#			DebugPrint("Cloaking " + pKessok.GetName())
			pCloak.StartCloaking()

	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy2")
	if pKessok:
		pKessok.SetAI(OrbitColonyAI.CreateAI(pKessok))

		pCloak = pKessok.GetCloakingSubsystem()
		if pCloak and not ((pKessok.IsCloaked()) or (pCloak.IsCloaking())):
#			DebugPrint("Cloaking " + pKessok.GetName())
			pCloak.StartCloaking()

	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy3")
	if pKessok:
		pKessok.SetAI(OrbitColonyAI.CreateAI(pKessok))

		pCloak = pKessok.GetCloakingSubsystem()
		if pCloak and not ((pKessok.IsCloaked()) or (pCloak.IsCloaking())):
#			DebugPrint("Cloaking " + pKessok.GetName())
			pCloak.StartCloaking()

	# Start a timer for Data's dialogue
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_KESSOKS_DISAPPEAR, __name__ + ".KessoksDisappear", fStartTime + 10, 0, 0)

	return 0


#
#	KessoksDisappear() - Removes the Kessoks from the set
#
def KessoksDisappear(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")

	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy1")
	if pKessok:
		pSet.DeleteObjectFromSet("KessokHeavy1")

	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy2")
	if pKessok:
		pSet.DeleteObjectFromSet("KessokHeavy2")

	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy3")
	if pKessok:
		pSet.DeleteObjectFromSet("KessokHeavy3")


#
#	SetKessoksFriendly() - Makes the Kessoks friendly to the player
#
def SetKessoksFriendly(pAction):
#	DebugPrint("Setting Kessoks AI to Friendly")

	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")

	pMission = MissionLib.GetMission()
	global pNeutrals, pEnemies, pFriendlies
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.RemoveName("KessokHeavy1")
	pEnemies.RemoveName("KessokHeavy2")
	pEnemies.RemoveName("KessokHeavy3")
	pNeutrals = pMission.GetNeutralGroup()
	pNeutrals.RemoveName("KessokHeavy1")
	pNeutrals.RemoveName("KessokHeavy2")
	pNeutrals.RemoveName("KessokHeavy3")
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("KessokHeavy1")
	pFriendlies.AddName("KessokHeavy2")
	pFriendlies.AddName("KessokHeavy3")

	global iKessokState
	iKessokState = FRIENDLY
	# Set its AI
	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy1")
	if pKessok:
		pKessok.SetAI(Friendly2AI.CreateAI(pKessok))
	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy2")
	if pKessok:
		pKessok.SetAI(Friendly2AI.CreateAI(pKessok))
	pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy3")
	if pKessok:
		pKessok.SetAI(Friendly2AI.CreateAI(pKessok))

	return 0


#
# MatanCometh() - Matan Arrives with his Hybrids
#
def MatanCometh(pAction):
	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")

	global bMatanArrived
	bMatanArrived = TRUE

	# Matan's Keldon is invisible to start
	pMatanKeldon = loadspacehelper.CreateShip("MatanKeldon", pSet, "Matan's Keldon", "Matan Start")
	pMatanKeldon.SetInvincible(1)
	pCloak = pMatanKeldon.GetCloakingSubsystem()
	pCloak.InstantCloak()

	pHybrid1 = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid 1", "Hybrid1 Enter", 1 )
	pHybrid2 = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid 2", "Hybrid2 Enter", 1 )
	pHybrid3 = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid 3", "Hybrid3 Enter", 1 )
	pHybrid4 = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid 4", "Hybrid4 Enter", 1 )

	global iNumHybrids
	iNumHybrids = 4

	global pHybridGroup

	pHybridGroup.AddName("Hybrid 1")
	pHybridGroup.AddName("Hybrid 2")
	pHybridGroup.AddName("Hybrid 3")
	pHybridGroup.AddName("Hybrid 4")

	pHybrid1.SetAI(HybridFirstWaveAI.CreateAI(pHybrid1))
	pHybrid2.SetAI(HybridFirstWaveAI.CreateAI(pHybrid2))
	pHybrid3.SetAI(HybridFirstWaveAI.CreateAI(pHybrid3))
	pHybrid4.SetAI(HybridFirstWaveAI.CreateAI(pHybrid4))

	# Check to see if Matan is disabled
	pMatanKeldon.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_DISABLED, __name__ + ".MatanDisableHandler")

	pMatanSet = MissionLib.SetupBridgeSet("MatanSet", "data/Models/Sets/Cardassian/cardbridge.nif")
	pMatan = MissionLib.SetupCharacter("Bridge.Characters.Matan", "MatanSet")

#	DebugPrint ("Adding GetMatanGoal")
	MissionLib.AddGoal("E8GetMatanGoal")

	# Start a timer for Picard to warp in
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_PICARD_TIMER, __name__ + ".PicardExMachina", fStartTime + 120, 0, 0)

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)
			
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids01", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids06", "C", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids08", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "TachyonDissipate")
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MatanSet", "Matan")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids09", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids10", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids11", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan01", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan02", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if not iOD3Kessoks == 0:
		pAction = App.TGScriptAction_Create(__name__, "SetKessoksNeutral2")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids12", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids13", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids14", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		if bKessokWithYou:
			pKessokSet = App.g_kSetManager.GetSet("KessokSet")
			pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")
	
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids15", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

	if (Maelstrom.Maelstrom.bZeissAlive == TRUE) and (bZeissChosen == TRUE):
		pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
		pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailZeiss1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids16", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bMacCrayChosen == TRUE):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailMcCray1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids17", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	if (bJonkaAlive == TRUE):
		pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
		pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids17c", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	if (bChairoAlive == TRUE):
		pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
		pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailTerrik1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids17b", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)


	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids18", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids19", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids20", "E", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Hybrids21", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# PicardExMachina() - The Enterprise arrives to save the day
#
def PicardExMachina(pObject, pEvent):
#	DebugPrint ("Picard Ex Machina")

	if App.g_kSetManager.GetSet("EBridgeSet") == None:
		pEBridgeSet = MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif")
	else:
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")

	pPicard = MissionLib.SetupCharacter("Bridge.Characters.Picard", "EBridgeSet")
	pPicard.SetLocation("SovereignSeated")

	#Get the set
	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")

	#Create the Enterprise and make it invincible
	pEnterprise = loadspacehelper.CreateShip( "Enterprise", pSet, "USS Enterprise", "Akira Start", 1 )
	pEnterprise.ReplaceTexture("Data/Models/Ships/Sovereign/Enterprise.tga", "ID")
	pEnterprise.SetInvincible(1)

	# Set its AI
	pEnterprise.SetAI(Friendly2AI.CreateAI(pEnterprise))

	# Add to Friendly Group
	global pFriendlies
	pMission = MissionLib.GetMission()
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("USS Enterprise")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2EnterpriseArrive2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction, 2)
	pAction = App.TGScriptAction_Create(__name__, "PicardGreeting")
	pSequence.AppendAction(pAction, 5)

	MissionLib.QueueActionToPlay(pSequence)


#
# PicardGreeting() - Picard's arrival greeting
#
def PicardGreeting(pAction, bFromHail = 0):
	if not bFromHail and (g_bPicardGreet == TRUE):
		return 0

	else:
		global g_bPicardGreet
		g_bPicardGreet = TRUE

	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
	pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if not (bFromHail):
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2EnterpriseArrive3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2EnterpriseArrive4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2EnterpriseArrive5", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2EnterpriseArrive6", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# MatanLeaving() - Matan goes to Omega Draconis 1
#
def MatanLeaving():
#	DebugPrint ("Matan Leaving...")

	pMatanSet = App.g_kSetManager.GetSet("MatanSet")
	pMatan = App.CharacterClass_GetObject (pMatanSet, "Matan")

	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
	pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan03", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan04", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan05", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MatanSet", "Matan")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart10", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan06", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "MatanFlee")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "CloakToggle", "Matan's Keldon", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan06b", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan07", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive04", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "SetFriendly2AI")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart11", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "MatanWarp")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart05", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart12", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "HybridSecondWave")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan08", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan09", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction, 2)
	if iOD3Kessoks > 0:
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan09b", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan09c", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan10", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart13", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "SetKessoksFriendly")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "AlliesSayGoodbye")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# AlliesSayGoodbye()
#
def AlliesSayGoodbye(pAction):
	global bAlliesStay
	bAlliesStay = TRUE

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if bKessokWithYou:
		pKessokSet = App.g_kSetManager.GetSet("KessokSet")
		pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2HailingKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	if (Maelstrom.Maelstrom.bZeissAlive == TRUE) and (bZeissChosen == TRUE):
		pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
		pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailZeiss2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2HailingZeiss2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bMacCrayChosen == TRUE):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailMcCray2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2HailingMacCray2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	if (bJonkaAlive == TRUE):
		pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
		pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2HailingKorbus2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	if (bChairoAlive == TRUE):
		pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
		pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailTerrik2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2HailingTerrik2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "BeginCountdown")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
#	MatanFlee() - Matan begins fleeing
#
def MatanFlee(pAction):
#	DebugPrint("Matan Fleeing...")
	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")
	pMatan = App.ShipClass_GetObject(pSet, "Matan's Keldon")

	if not (pMatan == None):
		pMatan.SetAI(FleeAI.CreateAI(pMatan))

	return 0


#
#	HybridSecondWave()
#
def HybridSecondWave(pAction):
	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")

	# Create Second Wave of Hybrids
	pHybrid1 = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid 5", "Kessok1 Start", 1 )
	pHybrid2 = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid 6", "Kessok2 Start", 1 )
	pHybrid3 = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid 7", "Kessok3 Start", 1 )
	pHybrid4 = loadspacehelper.CreateShip( "CardHybrid", pSet, "Hybrid 8", "Kessok4 Start", 1 )

	# Set Hybrid AI
	pHybrid1.SetAI(HybridAI.CreateAI(pHybrid1))
	pHybrid2.SetAI(HybridAI.CreateAI(pHybrid2))
	pHybrid3.SetAI(HybridAI.CreateAI(pHybrid3))
	pHybrid4.SetAI(HybridAI.CreateAI(pHybrid4))

	# Total number of Hybrids created so far
	global iNewHybrids
	iNewHybrids = 8

	return 0

#
# 	WatchMatan() - Watch Matan on the Viewscreen
#
def WatchMatan(pAction):
#	DebugPrint("Watching Matan...")
	pMatan = App.ShipClass_GetObject( App.SetClass_GetNull(), "Matan's Keldon")
	MissionLib.ViewscreenWatchObject(pMatan)

	return 0

#
# 	WatchSolarformer() - Watch Solarformer on the Viewscreen
#
def WatchSolarformer(pAction):
#	DebugPrint("Watching Solarformer...")
	pSolarformer = App.ShipClass_GetObject( App.SetClass_GetNull(), "Solarformer")
	MissionLib.ViewscreenWatchObject(pSolarformer)

	return 0


#
#	MatanWarp() - Matan Warps to OmegaDraconis1
#
def MatanWarp(pAction):
#	DebugPrint("Matan warping to OmegaDraconis1...")

	global bMatanDeparted
	bMatanDeparted = TRUE

	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")
	pMatan = App.ShipClass_GetObject(pSet, "Matan's Keldon")

	if not (pMatan == None):
		pMatan.SetAI(WarpToOD1AI.CreateAI(pMatan))

	return 0


#
#	BeginCountdown() - T minus 12 minutes until the sun burst
#
def BeginCountdown(pAction):
#	DebugPrint("Beginning the countdown.  Twelve minutes on the clock. ")

	# Start the countdown timer.  Check at 60 second intervals
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_COUNTDOWN, __name__ + ".Countdown", fStartTime + 60, 0, 0)

	return 0


#
#	Countdown() - Countdown until the sun explodes
#
def Countdown(pObject, pEvent):
#	DebugPrint("Countdown")

	if bSolarformerFixed == FALSE:
		global iCountdownMinutes
		iCountdownMinutes = iCountdownMinutes - 1

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pGame = App.Game_GetCurrentGame()
		pPlayerSet = pGame.GetPlayerSet()

		if iCountdownMinutes == 0:
#			DebugPrint("The sun implodes.  Game over...")
			pAction = App.TGScriptAction_Create(__name__, "DisableTimedDialogue")
			pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown0", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown0b", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = EndGameMovie ("data/Movies/FinalLose.bik")
			pSequence.AppendAction(pAction)

			MissionLib.GameOver(None, pSequence)

			return

		elif not bDisableDialogue:
			if (pPlayerSet.GetName() == "OmegaDraconis3"):
				if iCountdownMinutes == 10:
#					DebugPrint("Picard tells you to go to OD1")
	
					pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
					pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")
	
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2EnterpriseArrive3", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart14", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
					pSequence.AppendAction(pAction)
	
				else:
#					DebugPrint("Saffi tells you to go to OD1")
	
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart15", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
			elif iCountdownMinutes <= 10:
#				DebugPrint("You have " + str(iCountdownMinutes) + "minutes to reach a minimum safe distance")
	
				if bCountdownWarned == FALSE:
					global bCountdownWarned
					bCountdownWarned = TRUE
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2CountdownA", "Captain", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2CountdownB", "S", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				if iCountdownMinutes == 10:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown10", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 9:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown9", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 8:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown8", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 7:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown7", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 6:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown6", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 5:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown5", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 4:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown4", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 3:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown3", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 2:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown2", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
	
				elif iCountdownMinutes == 1:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Countdown1", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

		else:
			pSequence.Completed()

		if iCountdownMinutes > 0:
			# Set the timer for another 60 seconds
			fStartTime = App.g_kUtopiaModule.GetGameTime()
			MissionLib.CreateTimer(ET_COUNTDOWN, __name__ + ".Countdown", fStartTime + 60, 0, 0)


#
#	DestroyShip() - Destroys pShip
#
def DestroyShip(pAction, pShip):
	if pShip:
		pSystem = pShip.GetHull()
		if (pSystem):
#			DebugPrint("Destroying %s" % pShip.GetName())
			pSystem.SetConditionPercentage(0)
			
	return 0


#
# TachyonDissipate() - The Tachyon emissions have dissipated, allowing warp
#
def TachyonDissipate(pAction):
#	DebugPrint("Tachyon emissions have dissipated")
	global bTachyonDissipating
	bTachyonDissipating = 0

	return 0


#
# StopTimer() - Stop Liu's warning timer
#
def StopTimer():
#	DebugPrint("Trying to stop the timer...")
	global iLiuTimer
	if (iLiuTimer != App.NULL_ID):
#		DebugPrint("Timer exists with ID %d.  Removing it." % iLiuTimer)
		bSuccess = App.g_kTimerManager.DeleteTimer(iLiuTimer)
#		if bSuccess:
#			DebugPrint("Successfully removed.")
#		else:
#			DebugPrint("Failed to remove timer.")
		iLiuTimer = App.NULL_ID


#
# Briefing() - Briefing dialogue
#
def Briefing():
	global g_bBriefingPlayed
	g_bBriefingPlayed = TRUE

	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

#	DebugPrint ("Begin Briefing")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")

	### Add a delay here to prevent save/load timing issues
	### The other option would be to call the briefing from an event handler on MISSION_FINALLY_LOADED, but that
	### would be a larger change, so we'll do it the easy way.
	pSequence.AppendAction(pAction, 1)

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
	pSequence.AddAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB01", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB02", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB03", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB04", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB05", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "AddE8M2Goals")
	pSequence.AppendAction(pAction)

	if Maelstrom.Episode8.Episode8.KessoksFriendly == TRUE:
#		DebugPrint ("You made an ally of the KessokHeavy in E8M1")
		global iNumberChosen
		iNumberChosen = 1

		global kAllyList
		kAllyList.append("Neb-lig")

		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingA01", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingA02", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB06", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingA03", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingA04", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingA05", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB07", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingA06", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingA07", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "BattleGroupMenuOpen")
		pSequence.AppendAction(pAction)

	else:
#		DebugPrint ("You destroyed the KessokHeavy in E8M1")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB06", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingB01", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingB02", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingB03", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingB04", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingB05", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB07", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		if (Maelstrom.Maelstrom.bZeissAlive == TRUE) or (Maelstrom.Maelstrom.bGeronimoAlive == TRUE):
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingB06", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "BattleGroupMenuOpen")
			pSequence.AppendAction(pAction)

		else:
			# Geronimo and San Francisco are destroyed.  You're stuck with Korbus and Terrik, sucker

			pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
			pSequence.AppendAction(pAction)	
			pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "ContinueBriefing")
			pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# ContinueBriefing() - Continue Briefing dialogue after ChooseBattleGroup
#
def ContinueBriefing(pAction = 0):

	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

#	DebugPrint ("Continue Briefing")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)

	if bLiuChoose == TRUE:
#		DebugPrint ("Liu chooses for you")
		global bKorbusChosen
		bKorbusChosen = TRUE

		global kAllyList
		kAllyList.append("JonKa")

		if not Maelstrom.Episode8.Episode8.KessoksFriendly:
			global bTerrikChosen
			bTerrikChosen = TRUE

			kAllyList.append("Chairo")

	elif Maelstrom.Episode8.Episode8.KessoksFriendly:
		if bMacCrayChosen == TRUE:
#			DebugPrint ("Kessok and MacCray in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose01", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
		elif bZeissChosen == TRUE:
#			DebugPrint ("Kessok and Zeiss in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose02", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
		elif bKorbusChosen == TRUE:
#			DebugPrint ("Kessok and Korbus in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose03", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
		else:
#			DebugPrint ("Kessok and Terrik in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose04", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
	elif bMacCrayChosen == TRUE:
		if bZeissChosen == TRUE:
#			DebugPrint ("MacCray and Zeiss in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose05", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
		elif bKorbusChosen == TRUE:
#			DebugPrint ("MacCray and Korbus in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose06", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
		else:
#			DebugPrint ("MacCray and Terrik in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose07", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
	elif bZeissChosen == TRUE:
		if bKorbusChosen == TRUE:
#			DebugPrint ("Zeiss and Korbus in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose08", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
		else:
#			DebugPrint ("Zeiss and Terrik in Battle Group")
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose09", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
	elif bKorbusChosen == TRUE:
#		DebugPrint ("Korbus and Terrik in Battle Group")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose10", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
	else:
#		DebugPrint ("Korbus and Terrik are the only ones left alive")

		global bKorbusChosen, bTerrikChosen
		bKorbusChosen = TRUE
		bTerrikChosen = TRUE

		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChoose00", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pActionSaffi = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB08", None, 0, pMissionDatabase)
	pSequence.AddAction(pActionSaffi, pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB09", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB10", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB11", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB12", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingAB13", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Klystron1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Klystron2", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Klystron3", "E", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Klystron4", "C", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction2)

	if Maelstrom.Episode8.Episode8.KessoksFriendly == FALSE:
#		DebugPrint ("No Nebl-ebl, so Data talks about Comm Array.")
		global iCommArrayPlayed
		iCommArrayPlayed = 1

		pAction3 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray2", "E", 1, pMissionDatabase)
		pSequence.AddAction(pAction3, pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
		pSequence.AppendAction(pAction2)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray3b", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	if bMacCrayChosen == TRUE:
#		DebugPrint ("MacCray arrives after Briefing")
		pAction3 = App.TGScriptAction_Create(__name__, "WarpInMacCray")
	elif bZeissChosen == TRUE:
#		DebugPrint ("Zeiss arrives after Briefing")
		pAction3 = App.TGScriptAction_Create(__name__, "WarpInZeiss")
	elif bKorbusChosen == TRUE:
#		DebugPrint ("Korbus arrives after Briefing")
		pAction3 = App.TGScriptAction_Create(__name__, "WarpInKorbus")
	else:
#		DebugPrint ("Terrik arrives after Briefing")
		pAction3 = App.TGScriptAction_Create(__name__, "WarpInTerrik")

	pSequence.AddAction(pAction3, pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# AddE8M2Goals()  - Adding goals
#
def AddE8M2Goals(pAction):
#	DebugPrint ("Adding ContactKessoks and StopSolarformer Goals.")
	MissionLib.AddGoal("E8DestroyEmittersGoal", "E8ContactKessoksGoal", "E8StopSolarformerGoal")

	return 0


#
#	HailStarfleet()
#
def HailStarfleet(pObject, pEvent):
#	DebugPrint ("Contacting Starfleet...")

	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()
	if ((iTachyonEmitters == 2) and (pPlayerSetName == "OmegaDraconis5")) or ((iTachyonEmitters == 1) and (pPlayerSetName == "OmegaDraconis3")):
#		DebugPrint ("Can't hail Starfleet due to tachyon emitter")

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2HailFail2", "Captain", 1, pMissionDatabase)
		MissionLib.QueueActionToPlay(pAction)
		
		return

	else:
		pSequence = MissionLib.ContactStarfleet()

		if (iTachyonEmitters == 2):
#			DebugPrint("Liu says destroy the tachyon emitters and stop Matan")

			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2HailLiu", None, 0, pMissionDatabase)
	
		elif (iTachyonEmitters == 1):
#			DebugPrint("Liu says continue to OD3")

			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2OD5HailLiu", None, 0, pMissionDatabase)
	
		elif (iTachyonEmitters == 0) and (bSolarformerFixed == FALSE):
#			DebugPrint("Liu says stop the SolarFormer")

			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2OD1HailLiu", None, 0, pMissionDatabase)
	
		elif (iTachyonEmitters == 0) and (bMatanDisabled == FALSE):
#			DebugPrint("Liu says stop Matan")

			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2OD3HailLiu", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Nothing Special to handle")

			pSequence.Completed()
			pObject.CallNextHandler(pEvent)
			return

	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# BattleGroupMenuOpen()  - Open Battle Group menu
#
def BattleGroupMenuOpen(pAction):
#	DebugPrint("Opening Battle Group menu")
	
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	# Create timer for Liu to scold you
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pLiuTimer = MissionLib.CreateTimer(ET_LIU_TIMER, __name__ + ".LiuWarning", fStartTime + 15, 0, 0)
	# Save the ID of the timer, so we can stop it later.
	global iLiuTimer
	iLiuTimer = pLiuTimer.GetObjID()

	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_MENU_UP)
	pAction.Play()

	return 0


#
# BattleGroupMenuClose() - Close Battle Group menu
#
def BattleGroupMenuClose(pAction = 0):
#	DebugPrint("Closing Battle Group menu")
	
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_MENU_DOWN)
	pAction.Play()

	return 0


#
# WarpInMacCray() - MacCray is chosen for your Battle Group
#
def WarpInMacCray(pAction):
#	DebugPrint("MacCray warping in")
	pSet = App.g_kSetManager.GetSet("Starbase12")

	if App.g_kSetManager.GetSet("EBridgeSet") == None:
		pEBridgeSet = MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif")
	else:
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")

	pMacCray = MissionLib.SetupCharacter("Bridge.Characters.MacCray", "EBridgeSet")

	pGeronimo = loadspacehelper.CreateShip("Geronimo", pSet, "USS Geronimo", "Akira Start", 1)
	pGeronimo.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")
	MissionLib.AddCommandableShip("USS Geronimo")

	global pFriendlies
	pMission = MissionLib.GetMission()
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("USS Geronimo")

	global iGroupGreetings
	iGroupGreetings = iGroupGreetings + 1

	pSequence = App.TGSequence_Create()
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ArrivalMcCray", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "MacCrayGreeting")
	pSequence.AppendAction(pAction, 5)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# MacCrayGreeting() - MacCray's arrival greeting
#
def MacCrayGreeting(pAction, bFromHail = 0):
	if not bFromHail and (g_bMacCrayGreet == TRUE):
		return 0

	else:
		global g_bMacCrayGreet
		g_bMacCrayGreet = TRUE

	global iGroupGreetings

	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
	pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if not (bFromHail):
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailMcCray1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2GreetMcCray1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2GreetMcCray2", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2GreetMcCray3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if Maelstrom.Episode8.Episode8.KessoksFriendly:
		iGroupGreetings = iGroupGreetings + 1

		pKessokSet = App.g_kSetManager.GetSet("KessokSet")
		pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1201", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1204", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	if iGroupGreetings == 2:
		pAction = App.TGScriptAction_Create(__name__, "CourseSet")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "SetFriendlyAI")
		pSequence.AppendAction(pAction)
	elif bZeissChosen == TRUE:
#		DebugPrint ("Zeiss arrives after MacCray")
		pAction = App.TGScriptAction_Create(__name__, "WarpInZeiss")
		pSequence.AppendAction(pAction, 3)
	elif bKorbusChosen == TRUE:
#		DebugPrint ("Korbus arrives after MacCray")
		pAction = App.TGScriptAction_Create(__name__, "WarpInKorbus")
		pSequence.AppendAction(pAction, 3)
	else:
#		DebugPrint ("Terrik arrives after MacCray")
		pAction = App.TGScriptAction_Create(__name__, "WarpInTerrik")
		pSequence.AppendAction(pAction, 3)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# WarpInZeiss() - Zeiss is chosen for your Battle Group
#
def WarpInZeiss(pAction):
#	DebugPrint("Zeiss warping in")
	pSet = App.g_kSetManager.GetSet("Starbase12")

	pDBridgeSet = MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif")
	pZeiss = MissionLib.SetupCharacter("Bridge.Characters.Zeiss", "DBridgeSet")

	if bMacCrayChosen == TRUE:
		pGalaxy = loadspacehelper.CreateShip("Galaxy", pSet, "USS San Francisco", "Nebula Start", 1)
		pGalaxy.ReplaceTexture("data/Models/SharedTextures/FedShips/SanFrancisco.tga", "ID")
	else:
		pGalaxy = loadspacehelper.CreateShip("Galaxy", pSet, "USS San Francisco", "Akira Start", 1)
		pGalaxy.ReplaceTexture("data/Models/SharedTextures/FedShips/SanFrancisco.tga", "ID")

	MissionLib.AddCommandableShip("USS San Francisco")

	global pFriendlies
	pMission = MissionLib.GetMission()
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("USS San Francisco")

	global iGroupGreetings
	iGroupGreetings = iGroupGreetings + 1

	pSequence = App.TGSequence_Create()
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ArrivalZeiss", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "ZeissGreeting")
	pSequence.AppendAction(pAction, 5)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# ZeissGreeting() - Zeiss' arrival greeting
#
def ZeissGreeting(pAction, bFromHail = 0):
	if not bFromHail and (g_bZeissGreet == TRUE):
		return 0

	else:
		global g_bZeissGreet
		g_bZeissGreet = TRUE

	global iGroupGreetings

	pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
	pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if not (bFromHail):
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailZeiss1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2GreetZeiss1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2GreetZeiss2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	if Maelstrom.Episode8.Episode8.KessoksFriendly:
		iGroupGreetings = iGroupGreetings + 1

		pKessokSet = App.g_kSetManager.GetSet("KessokSet")
		pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	if iGroupGreetings == 2:
		pAction = App.TGScriptAction_Create(__name__, "CourseSet")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "SetFriendlyAI")
		pSequence.AppendAction(pAction)
	elif bKorbusChosen == TRUE:
#		DebugPrint ("Korbus arrives after Zeiss")
		pAction = App.TGScriptAction_Create(__name__, "WarpInKorbus")
		pSequence.AppendAction(pAction, 3)
	else:
#		DebugPrint ("Terrik arrives after Zeiss")
		pAction = App.TGScriptAction_Create(__name__, "WarpInTerrik")
		pSequence.AppendAction(pAction, 3)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# WarpInKorbus() - Korbus is chosen for your Battle Group
#
def WarpInKorbus(pAction):
#	DebugPrint("Korbus warping in")
	pSet = App.g_kSetManager.GetSet("Starbase12")

	pKorbusSet = MissionLib.SetupBridgeSet("KorbusSet", "data/Models/Sets/Klingon/BOPbridge.nif")
	pKorbus = MissionLib.SetupCharacter("Bridge.Characters.Korbus", "KorbusSet")
	pKorbus.SetLocation("KlingonSeated")

	global bJonkaAlive
	bJonkaAlive = TRUE

	if bZeissChosen == TRUE or bMacCrayChosen == TRUE:
		pVorcha = loadspacehelper.CreateShip("Vorcha", pSet, "JonKa", "Nebula Start", 1)
	else:
		pVorcha = loadspacehelper.CreateShip("Vorcha", pSet, "JonKa", "Akira Start", 1)

	MissionLib.AddCommandableShip("JonKa")

	global pFriendlies
	pMission = MissionLib.GetMission()
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("JonKa")

	global iGroupGreetings
	iGroupGreetings = iGroupGreetings + 1

	pSequence = App.TGSequence_Create()
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ArrivalKorbus", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "KorbusGreeting")
	pSequence.AppendAction(pAction, 5)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# KorbusGreeting() - Korbus' arrival greeting
#
def KorbusGreeting(pAction, bFromHail = 0):
	if not bFromHail and (g_bKorbusGreet == TRUE):
		return 0

	else:
		global g_bKorbusGreet
		g_bKorbusGreet = TRUE

	global iGroupGreetings

	pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
	pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if not (bFromHail):
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKorbus1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKorbus2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKorbus3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKorbus4", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if Maelstrom.Episode8.Episode8.KessoksFriendly:
		iGroupGreetings = iGroupGreetings + 1

		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1202", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pKessokSet = App.g_kSetManager.GetSet("KessokSet")
		pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1204", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	if iGroupGreetings == 2:
		pAction = App.TGScriptAction_Create(__name__, "CourseSet")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "SetFriendlyAI")
		pSequence.AppendAction(pAction)
	else:
#		DebugPrint ("Terrik arrives after Korbus")
		pAction = App.TGScriptAction_Create(__name__, "WarpInTerrik")
		pSequence.AppendAction(pAction, 3)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# WarpInTerrik() - Terrik is chosen for your Battle Group
#
def WarpInTerrik(pAction):
#	DebugPrint("Terrik warping in")
	pSet = App.g_kSetManager.GetSet("Starbase12")

	pTerrikSet = MissionLib.SetupBridgeSet("TerrikSet", "data/Models/Sets/Romulan/romulanbridge.nif")
	pTerrik = MissionLib.SetupCharacter("Bridge.Characters.Terrik", "TerrikSet")

	global bChairoAlive
	bChairoAlive = TRUE

	pWarbird = loadspacehelper.CreateShip("Warbird", pSet, "Chairo", "Nebula Start")

	MissionLib.AddCommandableShip("Chairo")

	# Cloak the Warbird to start
	pCloak = pWarbird.GetCloakingSubsystem()
	if (not App.IsNull(pCloak)):
#		DebugPrint("Instantly Cloaking Terrik")
		pCloak.TurnOn()
		pCloak.InstantCloak()

	global pFriendlies
	pMission = MissionLib.GetMission()
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("Chairo")

	global iGroupGreetings
	iGroupGreetings = iGroupGreetings + 1

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ArrivalTerrik1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "CloakToggle", "Chairo", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, pGeneralDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ArrivalTerrik2", "S", 1, pMissionDatabase)
	pSequence.AppendAction(pAction, 2)
	pAction = App.TGScriptAction_Create(__name__, "TerrikGreeting")
	pSequence.AppendAction(pAction, 5)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# TerrikGreeting() - Terrik's arrival greeting
#
def TerrikGreeting(pAction, bFromHail = 0):
	if not bFromHail and (g_bTerrikGreet == TRUE):
		return 0

	else:
		global g_bTerrikGreet
		g_bTerrikGreet = TRUE

	global iGroupGreetings

	pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
	pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if not (bFromHail):
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailTerrik1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2GreetTerrik1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	if bKorbusChosen == TRUE:
		pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
		pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1205", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1206", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1207", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1208", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	elif Maelstrom.Episode8.Episode8.KessoksFriendly:
		iGroupGreetings = iGroupGreetings + 1

		pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1203", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pKessokSet = App.g_kSetManager.GetSet("KessokSet")
		pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 2)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1204", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKessok3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "CourseSet")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "SetFriendlyAI")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
#	CourseSet()
#
def CourseSet(pAction):
#	DebugPrint("Course set for the Omega Draconis System")

	global bCourseSet
	bCourseSet = TRUE

	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return 0

	# Set the location on the warp menu
	pOmegaMenu = Systems.OmegaDraconis.OmegaDraconis.CreateMenus()
	pOmegaMenu.SetMissionName("Maelstrom.Episode8.E8M2.E8M2")

	pWarpButton.SetDestination("Systems.OmegaDraconis.OmegaDraconis5")
	g_pKiskaMenu.SetFocus(pWarpButton)

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2CourseSet", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if iCommArrayPlayed == 1:
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Klystron5", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray4", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray5", "E", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2CommArray6", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "L1")
		pSequence.AppendAction(pAction)

		global bDataInEngineering, iCommArrayPlayed
		bDataInEngineering = TRUE
		iCommArrayPlayed = 2

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
#	CloakToggle() - Cloaks a ship if it is uncloaked, uncloaks if it is cloaked.  
#					Pass 1 as the third parameter, to watch the ship
#
def CloakToggle(pAction, sShipName, *pInt):
	if not (sShipName == None):
		pShip = MissionLib.GetShip(sShipName)
		if pShip == None:
			return 0

		pSet = pShip.GetContainingSet()

		if pInt:
			MissionLib.ViewscreenWatchObject(pShip)

		pCloak = pShip.GetCloakingSubsystem()

		if pCloak == None:
			return 0

		if (pShip.IsCloaked()) or (pCloak.IsCloaking()):
#			DebugPrint("Decloaking " + pShip.GetName())
			pCloak.StopCloaking()
		else:
#			DebugPrint("Cloaking " + pShip.GetName())
			pCloak.StartCloaking()

#	else:
#		DebugPrint("Failed - ship not valid")
		
	return 0


#
#	LiuWarning() - Liu pressures you to hurry up deciding on your Battle Group members
#
def LiuWarning(pObject, pEvent):
#	DebugPrint("Liu Warning")
	
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	global iLiuWarning
	iLiuWarning = iLiuWarning + 1

	pSequence = App.TGSequence_Create()
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)

	if iLiuWarning == 1:
#		DebugPrint("First Warning")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChooseNow1", None, 0, pMissionDatabase)
	elif iLiuWarning == 2:
#		DebugPrint("Second Warning")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChooseNow2", None, 0, pMissionDatabase)
	elif iLiuWarning == 3:
#		DebugPrint("Third, and final, Warning")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChooseNow3", None, 0, pMissionDatabase)
	elif iLiuWarning == 4:
#		DebugPrint("You waited too long.  Liu chooses for you.")

		global bLiuChoose
		bLiuChoose = TRUE

		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M2BriefingChooseNow4", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "BattleGroupMenuClose")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ContinueBriefing")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_MENU_UP)
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	# Create timer for Liu to scold you
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pLiuTimer = MissionLib.CreateTimer(ET_LIU_TIMER, __name__ + ".LiuWarning", fStartTime + 15, 0, 0)
	# Save the ID of the timer, so we can stop it later.
	global iLiuTimer
	iLiuTimer = pLiuTimer.GetObjID()


#
#	ChooseMacCray() - MacCray is chosen for the BattleGroup
#
def ChooseMacCray(pObject, pEvent):
	# Remove McCrayButton from Battle Group menu
#	DebugPrint("Removing McCrayButton from menu")
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")
	pLiuMenu = pLiu.GetMenu()
	pLiuMenu.RemoveItemW(pMissionDatabase.GetString("McCrayButton"))

	global bMacCrayChosen
	bMacCrayChosen = TRUE

	global iNumberChosen
	iNumberChosen = iNumberChosen + 1

	global kAllyList
	kAllyList.append("USS Geronimo")

	if iNumberChosen == 1:
#		DebugPrint("MacCray chosen for Battle Group, position 1")

		# Stop Liu's timer
		StopTimer()
		# Create new timer for Liu
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		pLiuTimer = MissionLib.CreateTimer(ET_LIU_TIMER, __name__ + ".LiuWarning", fStartTime + 15, 0, 0)
		# Save the ID of the timer, so we can stop it later.
		global iLiuTimer
		iLiuTimer = pLiuTimer.GetObjID()

	elif iNumberChosen == 2:
#		DebugPrint("MacCray chosen for Battle Group, position 2")

		StopTimer()

		BattleGroupMenuClose()
		ContinueBriefing()


#
#	ChooseZeiss() - Zeiss is chosen for the BattleGroup
#
def ChooseZeiss(pObject, pEvent):
	# Remove ZeissButton from Battle Group menu
#	DebugPrint("Removing ZeissButton from menu")
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")
	pLiuMenu = pLiu.GetMenu()
	pLiuMenu.RemoveItemW(pMissionDatabase.GetString("ZeissButton"))

	global bZeissChosen
	bZeissChosen = TRUE

	global iNumberChosen
	iNumberChosen = iNumberChosen + 1

	global kAllyList
	kAllyList.append("USS San Francisco")

	if iNumberChosen == 1:
#		DebugPrint("Zeiss chosen for Battle Group, position 1")

		# Stop Liu's timer
		StopTimer()
		# Create new timer for Liu
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		pLiuTimer = MissionLib.CreateTimer(ET_LIU_TIMER, __name__ + ".LiuWarning", fStartTime + 15, 0, 0)
		# Save the ID of the timer, so we can stop it later.
		global iLiuTimer
		iLiuTimer = pLiuTimer.GetObjID()

	elif iNumberChosen == 2:
#		DebugPrint("Zeiss chosen for Battle Group, position 2")

		StopTimer()

		BattleGroupMenuClose()
		ContinueBriefing()


#
#	ChooseKorbus() - Korbus is chosen for the BattleGroup
#
def ChooseKorbus(pObject, pEvent):
	# Remove KorbusButton from Battle Group menu
#	DebugPrint("Removing KorbusButton from menu")
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")
	pLiuMenu = pLiu.GetMenu()
	pLiuMenu.RemoveItemW(pMissionDatabase.GetString("KorbusButton"))

	global bKorbusChosen
	bKorbusChosen = TRUE

	global iNumberChosen
	iNumberChosen = iNumberChosen + 1

	global kAllyList
	kAllyList.append("JonKa")

	if iNumberChosen == 1:
#		DebugPrint("Korbus chosen for Battle Group, position 1")

		# Stop Liu's timer
		StopTimer()
		# Create new timer for Liu
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		pLiuTimer = MissionLib.CreateTimer(ET_LIU_TIMER, __name__ + ".LiuWarning", fStartTime + 15, 0, 0)
		# Save the ID of the timer, so we can stop it later.
		global iLiuTimer
		iLiuTimer = pLiuTimer.GetObjID()

	elif iNumberChosen == 2:
#		DebugPrint("Korbus chosen for Battle Group, position 2")

		StopTimer()

		BattleGroupMenuClose()
		ContinueBriefing()


#
#	ChooseTerrik() - Terrik is chosen for the BattleGroup
#
def ChooseTerrik(pObject, pEvent):
	# Remove Terrik Button from Battle Group menu
#	DebugPrint("Removing TerrikButton from menu")
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")
	pLiuMenu = pLiu.GetMenu()
	pLiuMenu.RemoveItemW(pMissionDatabase.GetString("TerrikButton"))

	global bTerrikChosen
	bTerrikChosen = TRUE

	global iNumberChosen
	iNumberChosen = iNumberChosen + 1

	global kAllyList
	kAllyList.append("Chairo")

	if iNumberChosen == 1:
#		DebugPrint("Terrik chosen for Battle Group, position 1")

		# Stop Liu's timer
		StopTimer()
		# Create new timer for Liu
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		pLiuTimer = MissionLib.CreateTimer(ET_LIU_TIMER, __name__ + ".LiuWarning", fStartTime + 15, 0, 0)
		# Save the ID of the timer, so we can stop it later.
		global iLiuTimer
		iLiuTimer = pLiuTimer.GetObjID()

	elif iNumberChosen == 2:
#		DebugPrint("Terrik chosen for Battle Group, position 2")

		StopTimer()

		BattleGroupMenuClose()
		ContinueBriefing()


#
# OD5Arrive() 
#
def OD5Arrive(pAction):

	if bOD5Flag == HASNT_ARRIVED:

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2OD5Arrive1", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2OD5Arrive2", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD5Arrive3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2OD5Arrive4", "T", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD5Arrive5", "E", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "SetOD5AI")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD5CardSpotted", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bMacCrayChosen == TRUE):
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
			pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailMcCray2", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD501", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		if (Maelstrom.Maelstrom.bZeissAlive == TRUE) and bZeissChosen:
			pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
			pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailZeiss2", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD502", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		if (bJonkaAlive == TRUE):
			pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
			pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus2", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD503", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

			if (bChairoAlive == TRUE):
				pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
				pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")
	
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailTerrik2", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD504", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1207", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
			else:
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD505", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		if bKessokWithYou:
			pKessokSet = App.g_kSetManager.GetSet("KessokSet")
			pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD506", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# OD3Arrive() 
#
def OD3Arrive(pAction):

	pSequence = App.TGSequence_Create()

	if bOD3Flag == HASNT_ARRIVED:
		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive1", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive2", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		if not iOD5Keldons == 0:
			if iOD5Keldons == 1:
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive4c", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
			elif iOD5Keldons == 5:
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive4a", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
			else:
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive4b", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive5", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "SetOD3AI")
	pSequence.AppendAction(pAction)

	if bOD3Flag == HASNT_ARRIVED:
		if not bKessokWithYou and Maelstrom.Episode8.Episode8.KessoksFriendly == TRUE:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive6a", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pKessok = App.ShipClass_GetObject( App.SetClass_GetNull(), "Neb-lig")
			if pKessok:
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive7a", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
			else:
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive7b", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
		elif Maelstrom.Episode8.Episode8.KessoksFriendly == TRUE:
			pAction = App.TGScriptAction_Create(__name__, "SetKessoksNeutral")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive6c", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive7c", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive8c", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3Arrive9", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		if (Maelstrom.Maelstrom.bGeronimoAlive == TRUE) and (bMacCrayChosen == TRUE):
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
			pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailMcCray1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD301", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		if (Maelstrom.Maelstrom.bZeissAlive == TRUE) and (bZeissChosen == TRUE) and (bKessokWithYou == FALSE):
			pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
			pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailZeiss1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD302", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		if (bJonkaAlive == TRUE):
			pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
			pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKorbus1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD303", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

			if (bChairoAlive == TRUE):
				pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
				pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")
	
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailTerrik1", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD304", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2AllySB1207", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)

			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		if bKessokWithYou:
			pKessokSet = App.g_kSetManager.GetSet("KessokSet")
			pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2AllyOD306", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# OD1Arrive() 
#
def OD1Arrive():
	if bOD1Flag == HASNT_ARRIVED:
		global bOD1Flag
		bOD1Flag = HAS_ARRIVED

		pMission = App.Game_GetCurrentGame().GetCurrentEpisode().GetCurrentMission()
		# Torpedo Enter event
		App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TORPEDO_ENTERED_SET, pMission, __name__ +".TorpedoEnterSet")
		# Torpedo exit event
		App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TORPEDO_EXITED_SET, pMission, __name__ +".TorpedoExitSet")

		# Destroy player's repair system, because the engineering crew will be busy dealing with damage from the sun
		pPlayer = MissionLib.GetPlayer()
		if pPlayer == None:
			return
		pRepair = pPlayer.GetRepairSubsystem()
		if not pRepair == None:
			MissionLib.SetConditionPercentage (pRepair, 0)

		pMatanSet = App.g_kSetManager.GetSet("MatanSet")
		pMatan = App.CharacterClass_GetObject (pMatanSet, "Matan")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create(__name__, "DisableTimedDialogue")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive01", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive02", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive03", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "MatanOrbit")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "CloakToggle", "Matan's Keldon", 1)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan11", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan12", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2WhereMatan13", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive05", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MatanSet", "Matan")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive06", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "WatchSolarformer")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive07", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive08", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive09", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive10", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive11", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive12", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction2 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive13", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction2)
		pAction3 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN, "Science")
		pSequence.AddAction(pAction3, pAction, 1)
		pAction4 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN_BACK)
		pSequence.AddAction(pAction4, pAction2)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive14", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive15", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "EnableSolarformer")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2OD1Arrive16", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2SunDamage", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2SunDamage2", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2SunDamage3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction2 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Matan2ndMessage1", "Captain", 1, pMissionDatabase)
		pSequence.AddAction(pAction2, pAction, 5)
		pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2Matan2ndMessage2", "Matan")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg01", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg02", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg03", "S", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg04", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg05", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg06", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg07", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg08", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg09", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg10", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		if iOD3Kessoks > 0:
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg11", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "EnableTimedDialogue")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "StartTaunting")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)


#
# EnableSolarformer() - Enables dialogue for scanning Solarformer
#
def EnableSolarformer(pAction):

	global bSolarformerFlag
	bSolarformerFlag = TRUE

	return 0

#
# MatanOrbit() - Matan orbits the solarformer
#
def MatanOrbit(pAction):
#	DebugPrint("Matan orbits the Solarformer")

	pMatanKeldon = App.ShipClass_GetObject( App.SetClass_GetNull(), "Matan's Keldon")

	if not pMatanKeldon == None:
		pMatanKeldon.SetAI(OrbitSolarformerAI.CreateAI(pMatanKeldon))

#	else:
#		DebugPrint("ERROR - Matan's Keldon is None")

	return 0


#
# MatanAttackSolarformer() - Matan attacks the solarformer
#
def MatanAttackSolarformer(pAction):
#	DebugPrint("Matan attacks the Solarformer")

	global bMatanHit
	bMatanHit = TRUE

	global bMatanSolarformer
	bMatanSolarformer = TRUE

	pMatanKeldon = App.ShipClass_GetObject( App.SetClass_GetNull(), "Matan's Keldon")
	if not (pMatanKeldon == None):
		pMatanKeldon.SetAI(AttackSolarformerAI.CreateAI(pMatanKeldon))
		pMatanKeldon.SetHidden(0)
		pCloak = pMatanKeldon.GetCloakingSubsystem()
		if not (pCloak == None):
#			DebugPrint("Decloaking Matan")
			pCloak.StopCloaking()
	
	return 0


#
# MatanAttackPlayer() - Matan attacks the player
#
def MatanAttackPlayer(pAction):
#	DebugPrint("Matan attacks the Player")

	pMatanKeldon = App.ShipClass_GetObject( App.SetClass_GetNull(), "Matan's Keldon")

	if not (pMatanKeldon == None):
		pMatanKeldon.SetAI(AttackPlayerAI.CreateAI(pMatanKeldon))
	
	return 0


#
# StartTaunting() - Starts a timer for Matan to taunt you
#
def StartTaunting(pAction):
#	DebugPrint("Start timer for Matan taunting")

	# Start a timer for Data's dialogue
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_MATAN_TAUNT, __name__ + ".MatanTaunting", fStartTime + 45, 0, 0)

	# Test to see if Matan is hit
	pMatanKeldon = App.ShipClass_GetObject( App.SetClass_GetNull(), "Matan's Keldon")
	pMatanKeldon.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".WeaponHitMatan")

	global bCanDisableMatan
	bCanDisableMatan = TRUE

	# Add handlers for disabling Matan
	pCondition1 = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Matan's Keldon", App.CT_SHIELD_SUBSYSTEM, 1)
	pCondition2 = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Matan's Keldon", App.CT_IMPULSE_ENGINE_SUBSYSTEM, 1)
	pCondition3 = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Matan's Keldon", App.CT_WARP_ENGINE_SUBSYSTEM, 1)

	pMission = MissionLib.GetMission()

	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "DisableMatan", pCondition1)
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "DisableMatan", pCondition2)
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "DisableMatan", pCondition3)

	pMatanKeldon.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DESTROYED, __name__ + ".MatanDisableHandler")

	return 0


#
#	MatanTaunting()
#
def MatanTaunting(pObject, pEvent):
	if iMatanTaunt < 4 and bMatanHit == FALSE and not bStopMatanScan and not (bSolarformerFixed == -1):
		if not bDisableDialogue:
#			DebugPrint("Now go away before I taunt you a second time!")
			global iMatanTaunt
			iMatanTaunt = iMatanTaunt + 1
		
			pMatanSet = App.g_kSetManager.GetSet("MatanSet")
			pMatan = App.CharacterClass_GetObject (pMatanSet, "Matan")
	
			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)
	
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2MatanMsg12", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "MatanLock")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGSoundAction_Create("ViewOn")
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2MatanTaunt" + str(iMatanTaunt), "Matan")
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "LostMatanLock")
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "LostLockDialogue")
			pSequence.AppendAction(pAction)
	
			pSequence.Play()

		# Start a timer for Data's dialogue
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_MATAN_TAUNT, __name__ + ".MatanTaunting", fStartTime + 45, 0, 0)


#
# LostLockDialogue()
#
def LostLockDialogue(pAction):

	if bTorpedoFired and (bMatanHit == -1):
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry9", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry4", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	elif not bTorpedoFired and not bMatanHit:
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pSequence.Play()

	return 0


#
# MatanLock() - You've locked onto Matan and can fire
#
def MatanLock(pAction):
	if bMatanHit == FALSE:
#		DebugPrint("Locking onto Matan")
	
		global bLockOnMatan
		bLockOnMatan = TRUE
	
		pSet = App.g_kSetManager.GetSet("OmegaDraconis1")
		pPlayerShip = MissionLib.GetPlayer()
		pMatanKeldon = App.ShipClass_GetObject(pSet, "Matan's Keldon")

		pShields = pMatanKeldon.GetShields()
		if pShields:
			pShields.RemoveHandlerForInstance(App.ET_SHIELDS_SET_STATE, "MissionLib.IgnoreEventOnce")
			pShields.AddPythonFuncHandlerForInstance(App.ET_SHIELDS_SET_STATE, "MissionLib.IgnoreEventOnce")

		pMatanKeldon.SetHidden(1)
		pCloak = pMatanKeldon.GetCloakingSubsystem()
		pCloak.InstantDecloak()
	
		if pPlayerShip and pMatanKeldon:
			pPlayerShip.SetTarget("Matan's Keldon")

	return 0


#
# LostMatanLock() - You've lost your lock on Matan
#
def LostMatanLock(pAction):
#	DebugPrint("Lost lock on Matan")

	if not bMatanHit == TRUE:
		global bLockOnMatan
		bLockOnMatan = FALSE
	
		pMatanKeldon = App.ShipClass_GetObject( App.SetClass_GetNull(), "Matan's Keldon")
	
		if not pMatanKeldon.IsCloaked():
			pCloak = pMatanKeldon.GetCloakingSubsystem()
			pCloak.InstantCloak()
	
		if pMatanKeldon.IsHidden():
			pMatanKeldon.SetHidden(0)

	return 0


#
# WeaponHitMatan() - Matan has been hit
#
def WeaponHitMatan(pObject, pEvent):
#	DebugPrint("Weapon Hitting Matan")

	if not bMatanHit == TRUE:

		# If the weapon isn't a torpedo, bail...		
		if not (pEvent.GetWeaponType() == App.WeaponHitEvent.TORPEDO):
			global bTorpedoFired, bMatanHit
			bTorpedoFired = TRUE
			bMatanHit = -1

			return

#		DebugPrint("Matan's cloaking system is gone!")
		global bMatanHit
		bMatanHit = TRUE

		pMatanKeldon = App.ShipClass_GetObject( App.SetClass_GetNull(), "Matan's Keldon")

		pCloak = pMatanKeldon.GetCloakingSubsystem()

		if pMatanKeldon.IsHidden():
			pMatanKeldon.SetHidden(0)
			if not pMatanKeldon.IsCloaked():
				pCloak.InstantCloak()

		pCloak.SetConditionPercentage(0)

		# Make Matan temporarily invincible
		pMatanKeldon.SetHurtable(0)

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
		pAction1 = App.TGScriptAction_Create(__name__, "MatanAttackPlayer")
		pSequence.AppendAction(pAction1)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry5", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry6", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2MatanTry7", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pAction2 = App.TGScriptAction_Create(__name__, "MatanVulnerable")
		pSequence.AddAction(pAction2, pAction1, 5)

		pSequence.Play()

		pObject.CallNextHandler (pEvent)


	elif (bMatanPunishment == TRUE):
		global bMatanPunishment
		bMatanPunishment = FALSE

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2KeldonDamage1", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2KeldonDamage2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2KeldonDamage3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2KeldonDamage4", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)


#
# MatanVulnerable()
#
def MatanVulnerable(pAction):

	pMatanKeldon = App.ShipClass_GetObject( App.SetClass_GetNull(), "Matan's Keldon")
	pMatanKeldon.SetHurtable(1)

	# Raise Matan's shields
	pShields = pMatanKeldon.GetShields()
	if pShields:
		pShields.TurnOn()
		pShields.SetPowerPercentageWanted (1.0)

	return 0


#
# SetOD5AI()
#
def SetOD5AI(pAction):
#	DebugPrint("Setting OD5 AI")
	pSet = App.g_kSetManager.GetSet("OmegaDraconis5")

	if bOD5Flag == HASNT_ARRIVED:
		global bOD5Flag
		bOD5Flag = HAS_ARRIVED

		pKeldon = App.ShipClass_GetObject(pSet, "Keldon1")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon2")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon3")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon4")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon5")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))

		SetFriendlyAI(None)

	return 0


#
# KeldonsRetreat() - The Keldons warp to Omega Draconis 3
#
def KeldonsRetreat(pAction):
#	DebugPrint("Keldons Warping to OD3")
	pSet = App.g_kSetManager.GetSet("OmegaDraconis5")

	pKeldon = App.ShipClass_GetObject(pSet, "Keldon1")
	if pKeldon:
		pKeldon.SetAI(WarpToOD3AI.CreateAI(pKeldon, 5, "Kessok1 Start"))
	pKeldon = App.ShipClass_GetObject(pSet, "Keldon2")
	if pKeldon:
		pKeldon.SetAI(WarpToOD3AI.CreateAI(pKeldon, 6, "Galor Start"))
	pKeldon = App.ShipClass_GetObject(pSet, "Keldon3")
	if pKeldon:
		pKeldon.SetAI(WarpToOD3AI.CreateAI(pKeldon, 7, "Attacker 1 Start"))
	pKeldon = App.ShipClass_GetObject(pSet, "Keldon4")
	if pKeldon:
		pKeldon.SetAI(WarpToOD3AI.CreateAI(pKeldon, 8, "Attacker 2 Start"))
	pKeldon = App.ShipClass_GetObject(pSet, "Keldon5")
	if pKeldon:
		pKeldon.SetAI(WarpToOD3AI.CreateAI(pKeldon, 9, "Attacker 3 Start"))	

	return 0


#
# SetOD3AI()
#
def SetOD3AI(pAction):
#	DebugPrint("Setting OD3 AI")
	pSet = App.g_kSetManager.GetSet("OmegaDraconis3")
	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	if bOD3Flag == HASNT_ARRIVED:
		global bOD3Flag
		bOD3Flag = HAS_ARRIVED

		pKeldon = App.ShipClass_GetObject(pSet, "Keldon1")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon2")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon3")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon4")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon5")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon6")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))
		pKeldon = App.ShipClass_GetObject(pSet, "Keldon7")
		if not (pKeldon == None):
			pKeldon.SetAI(EnemyAI.CreateAI(pKeldon))

		SetFriendlyAI(None)

		pShip = App.ShipClass_GetObject( App.SetClass_GetNull(), "Neb-lig")
		if pShip:
			pSetName = pShip.GetContainingSet().GetName()
			if (pPlayerSetName == pSetName):
				return 0

		pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy1")
		if not (pKessok == None):
			pKessok.SetAI(EnemyAI.CreateAI(pKessok))
		pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy2")
		if not (pKessok == None):
			pKessok.SetAI(EnemyAI.CreateAI(pKessok))
		pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy3")
		if not (pKessok == None):
			pKessok.SetAI(EnemyAI.CreateAI(pKessok))

	else:
		if not iTachyonEmitters == 0:
			pShip = App.ShipClass_GetObject( App.SetClass_GetNull(), "Neb-lig")
			if pShip:
				pSetName = pShip.GetContainingSet().GetName()
				if (pPlayerSetName == pSetName):
					SetKessoksNeutral(None)

	return 0


#
# SetFriendlyAI()
#
def SetFriendlyAI(pAction):
#	DebugPrint("Setting Friendly AI")
	pPlayer = MissionLib.GetPlayer()
	pPlayerSet = pPlayer.GetContainingSet()

	for pcShipName in kAllyList:
		if not pcShipName == "player":
			# for each ship, assign it the AI if it's alive and in the player's set.
			pShip = App.ShipClass_GetObject(App.SetClass_GetNull(), pcShipName)
	
			if (pShip != None):
				pSet = pShip.GetContainingSet()
				if (pSet == None):
					continue
				if (pPlayerSet.GetName() == pSet.GetName()):
					pShip.SetAI(FriendlyAI.CreateAI(pShip, kAllyList))

	return 0


#
# SetFriendly2AI()
#
def SetFriendly2AI(pAction):
#	DebugPrint("Your allies will stay behind while you go fight Matan")
	pPlayer = MissionLib.GetPlayer()
	pPlayerSet = pPlayer.GetContainingSet()
	
	for pcShipName in kAllyList:
		if not pcShipName == "player":
			# for each ship, assign it the AI if it's alive and in the player's set.
			pShip = App.ShipClass_GetObject(App.SetClass_GetNull(), pcShipName)
	
			if (pShip != None):
				pSet = pShip.GetContainingSet()
				if (pSet == None):
					continue
				if (pPlayerSet.GetName() == pSet.GetName()):
					pShip.SetAI(Friendly2AI.CreateAI(pShip))
					if (pcShipName == "Nebl-lish"):
						global bKessokWithYou
						bKessokWithYou = FALSE

	return 0


#
#	KessoksAttacked() - Checks to see if you attacked one of the KessokShips.
#
def KessoksAttacked (pObject, pEvent):
#	DebugPrint("A Kessok ship is attacked")
	if not (iKessokState == ENEMY) and not bKessokAttackWait:
		pAttacker = App.ShipClass_Cast(pEvent.GetFiringObject())
	
		if pAttacker == None or bSkipAttackWarn == TRUE:
			pObject.CallNextHandler (pEvent)
		   	return

		sAttacker = pAttacker.GetName()
		
		if ((sAttacker == "player")
			or (sAttacker == "USS Geronimo") 
			or (sAttacker == "USS San Francisco") 
			or (sAttacker == "Neb-lig")
			or (sAttacker == "Chairo")
			or (sAttacker == "JonKa")):

			pTarget = pAttacker.GetTarget()
			if (pTarget == None):
				pObject.CallNextHandler (pEvent)
				return

			sTarget = pTarget.GetName()

			if ((sTarget == "KessokHeavy1") or 
				(sTarget == "KessokHeavy2") or 
				(sTarget == "KessokHeavy3") or 
				(sTarget == "Neb-lig")):
				if iAttackKessokWarn < 3:
#					DebugPrint("Player or ally fired on Kessok ship.  You get a warning.")
	
#					if iAttackKessokWarn == 1:
#						DebugPrint("Strike Two")

					if (sTarget == "Neb-lig") and (iAttackKessokWarn == 0):
						pKessokSet = App.g_kSetManager.GetSet("KessokSet")
						pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")

						pSequence = App.TGSequence_Create()

						pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
						pSequence.AppendAction(pAction)

						iNum = App.g_kSystemWrapper.GetRandomNumber(2)
						if iNum == 1:
							pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok1", None, 0, pMissionDatabase)
					
						else:
							pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2HailKessok2", None, 0, pMissionDatabase)
				
						pSequence.AppendAction(pAction, 3)

						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2HitKessok", None, 0, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
						pSequence.AppendAction(pAction)

						MissionLib.QueueActionToPlay(pSequence)

					else:
						pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3AttackKessoks1", None, 0, pMissionDatabase)
						pAction.Play()

					global iAttackKessokWarn, bSkipAttackWarn
					iAttackKessokWarn = iAttackKessokWarn + 1
					bSkipAttackWarn = TRUE
					# Start a timer to reset Saffi's warning
					fStartTime = App.g_kUtopiaModule.GetGameTime()
					MissionLib.CreateTimer(ET_ATTACK_KESSOK_RESET, __name__ + ".AttackKessokReset", fStartTime + 15, 0, 0)
	
				else:
#					DebugPrint("Player or ally fired on Kessok ship.  Strike three, game over.")
		
					pSequence = App.TGSequence_Create()

					pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
					pSequence.AppendAction(pAction)

					pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_WATCH_ME)
					pSequence.AddAction(pAction1)
					pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
					pSequence.AddAction(pAction2, pAction1)
					pAction3 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3AttackKessoks1", None, 0, pMissionDatabase)
					pSequence.AddAction(pAction3, pAction1)
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_TURN, "C1")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_TURN, "C1")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3AttackKessoks2", "Captain", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2OD3AttackKessoks3", "Captain", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
		
					MissionLib.GameOver(None, pSequence)

	pObject.CallNextHandler (pEvent)


#
#	AttackKessokReset() - Resets Saffi's warning
#
def AttackKessokReset(pObject, pEvent):
#	DebugPrint("Reset Kessok Attack warning")
	global bSkipAttackWarn
	bSkipAttackWarn = FALSE


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

	pSet = pPlayer.GetContainingSet()
	sSetName = pSet.GetName()

	pSequence = Bridge.HelmMenuHandlers.GetHailSequence()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (pFriendlies.IsNameInGroup(pTarget.GetName()) and not (sTarget[:len("KessokHeavy")] == "KessokHeavy")):

		if (sTarget == "Starbase 12"):
			pFedOutpostSet = App.g_kSetManager.GetSet("FedOutpostSet")
			pGraff = App.CharacterClass_GetObject(pFedOutpostSet, "Graff")

			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E8M2HailingStarbase", None, 0, pMissionDatabase)

		elif (sTarget == "Neb-lig"):
			pKessokSet = App.g_kSetManager.GetSet("KessokSet")
			pKessok = App.CharacterClass_GetObject (pKessokSet, "Kessok")
	
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
			pSequence.AppendAction(pAction)

			if (bAlliesStay == FALSE):
				pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2HailingKessok1", None, 0, pMissionDatabase)

			else:
				pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M2HailingKessok2", None, 0, pMissionDatabase)

		elif (sTarget == "USS San Francisco"):
			if not g_bZeissGreet:
				global g_bZeissGreet
				g_bZeissGreet = TRUE

				pAction = App.TGScriptAction_Create(__name__, "ZeissGreeting", 1)

			else:
				pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
				pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")
		
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
				pSequence.AppendAction(pAction)
	
				if (bAlliesStay == FALSE):
					pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2HailingZeiss1", None, 0, pMissionDatabase)
	
				else:
					pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M2HailingZeiss2", None, 0, pMissionDatabase)
	
		elif (sTarget == "USS Geronimo"):
			if not g_bMacCrayGreet:
				global g_bMacCrayGreet
				g_bMacCrayGreet = TRUE

				pAction = App.TGScriptAction_Create(__name__, "MacCrayGreeting", 1)

			else:
				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")
		
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
				pSequence.AppendAction(pAction)
	
				if (bAlliesStay == FALSE):
					pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2HailingMacCray1", None, 0, pMissionDatabase)
	
				else:
					pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M2HailingMacCray2", None, 0, pMissionDatabase)

		elif (sTarget == "JonKa"):
			if not g_bKorbusGreet:
				global g_bKorbusGreet
				g_bKorbusGreet = TRUE

				pAction = App.TGScriptAction_Create(__name__, "KorbusGreeting", 1)

			else:
				pKorbusSet = App.g_kSetManager.GetSet("KorbusSet")
				pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")
		
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KorbusSet", "Korbus")
				pSequence.AppendAction(pAction)
	
				if (bAlliesStay == FALSE):
					pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2HailingKorbus1", None, 0, pMissionDatabase)
	
				else:
					pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E8M2HailingKorbus2", None, 0, pMissionDatabase)
	
		elif (sTarget == "Chairo"):
			if not g_bTerrikGreet:
				global g_bTerrikGreet
				g_bTerrikGreet = TRUE

				pAction = App.TGScriptAction_Create(__name__, "TerrikGreeting", 1)

			else:
				pTerrikSet = App.g_kSetManager.GetSet("TerrikSet")
				pTerrik = App.CharacterClass_GetObject (pTerrikSet, "Terrik")
		
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TerrikSet", "Terrik")
				pSequence.AppendAction(pAction)
	
				if (bAlliesStay == FALSE):
					pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2HailingTerrik1", None, 0, pMissionDatabase)
	
				else:
					pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E8M2HailingTerrik2", None, 0, pMissionDatabase)
	
		elif (sTarget == "USS Enterprise"):
			if g_bPicardGreet:
				global g_bPicardGreet
				g_bPicardGreet = TRUE

				pAction = App.TGScriptAction_Create(__name__, "PicardGreeting", 1)

			else:
				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")
	
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
				pSequence.AppendAction(pAction)
	
				if (bAlliesStay == FALSE):
					pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2HailingPicard", None, 0, pMissionDatabase)
	
				else:
					pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDepart14", None, 0, pMissionDatabase)

		else:
			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif (sSetName == "OmegaDraconis5"):
		pEmitter = App.ShipClass_GetObject(pSet, "Tachyon Emitter")
		if not pEmitter == None:
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2HailFail", "Captain", 1, pMissionDatabase)

		else:
			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif (sSetName == "OmegaDraconis3"):
		pEmitter = App.ShipClass_GetObject(pSet, "Tachyon Emitter 2")
		if not pEmitter == None:
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2HailFail", "Captain", 1, pMissionDatabase)

		else:
			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	else:
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
	pPlayer = App.ShipClass_Cast(pGame.GetPlayer())
	pSet = pGame.GetPlayerSet()

	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return
	sDest	 	= pWarpButton.GetDestination()

	if ((iTachyonEmitters == 2) and (pSet.GetName() == "OmegaDraconis5")) or ((iTachyonEmitters == 1) and (pSet.GetName() == "OmegaDraconis3")):
#		DebugPrint("Can't warp because of the tachyon emitter")
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Warp1", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		if bWarpTried == FALSE:
			global bWarpTried
			bWarpTried = TRUE
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Warp2", "E", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Warp3", "H", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Warp4", "E", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)
		return

	elif bTachyonDissipating:
#		DebugPrint("Can't warp because tachyon emissions must dissipate")
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Warp5", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		if bWhyWarpSpeech == FALSE:
			global bWhyWarpSpeech
			bWhyWarpSpeech = TRUE
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Warp6", "E", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Warp7", "H", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Warp8", "E", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2GreetKorbus4", "C", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)
		return

	elif (bMatanArrived == TRUE) and (bMatanDeparted == FALSE):
#		DebugPrint("You must deal with Matan.")

		g_pSaffi.SayLine(pMissionDatabase, "E8M2WarpBack3", "Captain", 1)

		return

	elif iTachyonEmitters == 0 and not (sDest == "Systems.OmegaDraconis.OmegaDraconis1"):
		pSequence = App.TGSequence_Create()

#		DebugPrint("No time to warp back.")

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2WarpBack1", "H", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)

		if iWarpWarned > 2:
#			DebugPrint("Saffi warned you, but you didn't listen.  Game over.")
			pAction = App.TGScriptAction_Create(__name__, "DisableTimedDialogue")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2WarpBack4", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)	

			MissionLib.GameOver(None, pSequence)
			return

		elif (pSet.GetName() == "OmegaDraconis1") and bMatanDisabled == FALSE:
#			DebugPrint("You must deal with Matan.")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2WarpBack3", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)	

		else:
#			DebugPrint("You must deal with the Solarformer.")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2WarpBack2", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)	

		global iWarpWarned
		iWarpWarned = iWarpWarned + 1

		# Start a timer to reset Warp Warning
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_WARP_WARN_RESET, __name__ + ".WarpWarnReset", fStartTime + 60, 0, 0)

		MissionLib.QueueActionToPlay(pSequence)
		return

	elif (iTachyonEmitters == 1) and ((sDest == "Systems.OmegaDraconis.OmegaDraconis1") or (sDest == "Systems.OmegaDraconis.OmegaDraconis2")):
#		DebugPrint("Can't warp that far because of OD3 tachyon emitter.  Dropping out of warp at OD3.")

		# Altering warp course to OmegaDraconis3
		pWarpButton.SetDestination("Systems.OmegaDraconis.OmegaDraconis3")

	pObject.CallNextHandler(pEvent)


#
# WarpWarnReset() - Reset Saffi's Warp Warning
#
def WarpWarnReset(pObject, pEvent):

	global iWarpWarned
	iWarpWarned = 0


#
# ScanHandler()
#
def ScanHandler(pObject, pEvent):
#	DebugPrint("Scanning")

	pPlayer = MissionLib.GetPlayer()
	pSet = pPlayer.GetContainingSet()
	pSensors = pPlayer.GetSensorSubsystem()
	
	iScanType = pEvent.GetInt()

	pSequence = Bridge.ScienceCharacterHandlers.GetScanSequence()

	if not (pSequence):
		return

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if (iScanType == App.CharacterClass.EST_SCAN_AREA):
#		DebugPrint("Scanning Area")
		pSetName = pSet.GetName()

		if (pSetName[:len("OmegaDraconis")] == "OmegaDraconis"):
#			DebugPrint("Scanning Omega Draconis System")
			if bOmegaScanned == FALSE:
				global bOmegaScanned
				bOmegaScanned = TRUE
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanArea1", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2ScanArea3", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
			else:
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanArea4", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		else:
#			DebugPrint("Nothing new detected.")

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanArea5", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

	elif (iScanType == App.CharacterClass.EST_SCAN_OBJECT):
#		DebugPrint("Scanning Target")

		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
			pTarget = pPlayer.GetTarget()
	
		if pTarget == None:
			pSequence.Completed()
			return

		pcTargetName = pTarget.GetName()

		if pcTargetName == "Matan's Keldon":
#			DebugPrint("Scanning Matan's Keldon")

			if bMatanDisabled == FALSE:
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatanFail", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif bStopMatanScan:
				pSequence.Completed()
				pObject.CallNextHandler(pEvent)
	
				return

			else:
				if bMatanScanned == FALSE:
					global bMatanScanned
					bMatanScanned = TRUE

					if bDataWantsToGo:
						g_pDataMenu.RemoveItemW(pMissionDatabase.GetString("GoToSolarformer"))
	
						global bDataWantsToGo
						bDataWantsToGo = FALSE
	
					pAction = App.TGScriptAction_Create(__name__, "DisableTimedDialogue")
					pSequence.AppendAction(pAction)

					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatan1", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)			
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatan2", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)			
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatan3", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatan5", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatan6", "H", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					if bSolarformerScanned == FALSE:
						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatan6", "T", 1, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create(__name__, "EnableTimedDialogue")
						pSequence.AppendAction(pAction)

					else:
						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatan8", "T", 1, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.TGScriptAction_Create(__name__, "KiskaFoundSomething")
						pSequence.AppendAction(pAction)

				else:
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanMatan4", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

		elif pcTargetName == "Solarformer":
#			DebugPrint("Scanning Solarformer")
			if bSolarformerFlag == TRUE:
				# Get the distance between the player and the Solarformer
				vDiff = pPlayer.GetWorldLocation()
				vDiff.Subtract(pPlayer.GetTarget().GetWorldLocation())
				fDistance = vDiff.Length()
		
#				DebugPrint('Distance from Solarformer: ' + str(fDistance) + 'km')
				if fDistance <= 100:
#					DebugPrint("Within range of the Solarformer")

					global bSolarformerFlag, bSolarformerScanned
					bSolarformerFlag = FALSE
					bSolarformerScanned = TRUE

					MissionLib.QueueActionToPlay(pSequence)

					ScanningSolarformer()

					return

				else:
#					DebugPrint("Must get closer to the Solarformer")
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer01", "Captain", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)

			else:
#				DebugPrint("Nothing new detected")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanArea5", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		else:
#			DebugPrint("Nothing new detected")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanArea5", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

	else:
#		DebugPrint("Nothing new detected.")
	
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2ScanArea5", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# DisableTimedDialogue() - Stopping timed dialogue such as Matan taunting, so dialogue can play uninterrupted.
#
def DisableTimedDialogue(pAction):
#	DebugPrint ("Disable timed dialogue")

	global bDisableDialogue
	bDisableDialogue = TRUE

	return 0


#
# EnableTimedDialogue() - Reenabling timed dialogue
#
def EnableTimedDialogue(pAction):
#	DebugPrint ("Enable timed dialogue")

	global bDisableDialogue
	bDisableDialogue = FALSE

	return 0


#
# ScanningSolarformer() - Dialogue for scanning the Solarformer
#
def ScanningSolarformer():
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create(__name__, "DisableTimedDialogue")
	pSequence.AppendAction(pAction)
	
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer02", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer03", "S", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer04", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer05", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer07", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer08", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer09", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer10", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer11", "S", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer12", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer13", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN_BACK)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "ScanningSolarformer2")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# ScanningSolarformer2() - Continues dialogue for scanning the Solarformer
#
def ScanningSolarformer2(pAction):
	pSequence = App.TGSequence_Create()

	if bMatanScanned == FALSE:
#		DebugPrint("Try scanning Matan")
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer14a", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		if not bMatanHit == TRUE:
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer14b", "H", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
		elif bMatanDisabled == TRUE:
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer14c", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2DataVolunteer2", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2DataVolunteer3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		if bMatanDisabled == FALSE:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2DataVolunteer4", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2DataVolunteer5", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2DataVolunteer6", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "AddDataButton")
		pSequence.AppendAction(pAction)

	else:
#		DebugPrint("Matan already Scanned")
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer14d", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "KiskaFoundSomething")
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "EnableTimedDialogue")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# KiskaFoundSomething() - Kiska found the Code when you scanned Matan's ship
#
def KiskaFoundSomething(pAction):
#	DebugPrint ("Kiska found something...")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer15", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer16", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction2)
	pAction3 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer17", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction)
	pAction2 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction2)
	pAction3 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer18", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction2)
	pAction4 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction4)
	pAction5 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer19", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction5, pAction3, 4)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer20", "S", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer21", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer23", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "DealWithMatan")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	global bSolarformerFixed
	bSolarformerFixed = TRUE

	return 0


#
#	GoToSolarformer() - Data goes aboard the Solarformer
#
def GoToSolarformer(pObject, pEvent):
#	DebugPrint("Data goes to Solarformer")

	if not bDataWantsToGo:
		return

	g_pDataMenu.RemoveItemW(pMissionDatabase.GetString("GoToSolarformer"))

	global bDataWantsToGo
	bDataWantsToGo = FALSE

	global bStopMatanScan
	bStopMatanScan = TRUE

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "DisableScanMenu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M2DataTransport1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "DataLeaving")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
	pSequence.AppendAction(pAction)

	#Make this sequence interruptable
	global idInterruptSequence
	idInterruptSequence = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)


#
# DataLeaving()
#
def DataLeaving(pAction):

	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "L1")
	pAction.Play()

	# Create a Timer for Data to go aboard the Solarformer
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_DATA_SOLARFORMER, __name__ + ".AtSolarformer", fStartTime + 20, 0, 0)

	return 0


#
#	AtSolarformer() - Data is aboard the Solarformer
#
def AtSolarformer(pObject, pEvent):
	global bDataAway
	bDataAway = TRUE

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields", 0, 4)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2DataTransport2", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if bMatanDisabled == FALSE:
#		DebugPrint("Matan not disabled. He attacks the Solarformer")

		if not bMatanHit == TRUE:
			pAction = App.TGScriptAction_Create(__name__, "CloakToggle", "Matan's Keldon", 1)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "MatanAttackSolarformer")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2DataTransport3", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2DataTransport4", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2DataTransport5", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

		else:
			pAction = App.TGScriptAction_Create(__name__, "MatanAttackSolarformer")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2DataTransport5", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2DataTransport4", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2DataTransport6", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2DataSolarformer1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2DataSolarformer2", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "StartSolarformerTimer")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
	pSequence.AppendAction(pAction)

	#Make this sequence interruptable
	global idInterruptSequence
	idInterruptSequence = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)


#
#	StartSolarformerTimer()
#
def StartSolarformerTimer(pAction):

	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SOLARFORMER_TIMER, __name__ + ".GoToSolarformerPt2", fStartTime + 20, 0, 0)

	return 0


#
#	GoToSolarformerPt2() - Data aboard the Solarformer dialogue
#
def GoToSolarformerPt2(pObject, pEvent):
	pSequence = App.TGSequence_Create()

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2DataSolarformer1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2DataSolarformer3", "Data")
	pSequence.AppendAction(pAction)
	pAction2 = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M2DataSolarformer4", "Data")
	pSequence.AddAction(pAction2, pAction, 5)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2DataSolarformer5", "S", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields", 0, 4)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2DataSolarformer6", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "DataReturns")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "DealWithMatan")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
	pSequence.AppendAction(pAction)

	#Make this sequence interruptable
	global idInterruptSequence
	idInterruptSequence = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)


#
# ResetInterrupt()
#
def ResetInterrupt(pAction):

	global idInterruptSequence
	idInterruptSequence	= App.NULL_ID

	return 0


#
#	DataReturns() - Data is back from the Solarformer
#
def DataReturns(pAction):

	global bDataAway
	bDataAway = FALSE

	global bSolarformerFixed
	bSolarformerFixed = TRUE

	pSequence = App.TGSequence_Create()

	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "X")
	pSequence.AppendAction(pAction, 15)

	pSequence.Play()

	return 0


#
#	AddDataButton() - Adds Go to Solarform button in Data's menu
#
def AddDataButton(pAction):
	global bDataWantsToGo
	bDataWantsToGo = TRUE

	g_pData.AddPythonFuncHandlerForInstance(ET_GO_SOLARFORMER, __name__ + ".GoToSolarformer")
	g_pDataMenu.AddChild(CreateBridgeMenuButton(pMissionDatabase.GetString("GoToSolarformer"), ET_GO_SOLARFORMER, 0, g_pData))

	return 0


#
#	DealWithMatan() - Deal with Matan dialogue
#
def DealWithMatan(pAction):
#	DebugPrint("Time to deal with Matan")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer22", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	if bMatanDisabled == FALSE:
#		DebugPrint("Matan not disabled")

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer24", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Solarformer25", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create(__name__, "EnableTimedDialogue")
		pSequence.AppendAction(pAction)

	else:
		pAction = App.TGScriptAction_Create(__name__, "Aftermath")
		pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# LostImpulseHandler() - If Matan takes out players impulse system.
#
def LostImpulseHandler(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	
	if not pPlayer:
		pObject.CallNextHandler(pEvent)
		return

	# Make sure the subsystem is valid, so the game won't crash when I do a GetObjID
	if not (pPlayer.GetImpulseEngineSubsystem() == None):
		if pEvent.GetSource():
			if (pEvent.GetSource().GetObjID() == pPlayer.GetImpulseEngineSubsystem().GetObjID()):
	#			DebugPrint ("Our Impulse Engines Are Gone!")
				pSystem = App.ShipSubsystem_Cast(pEvent.GetSource())
				
				if pSystem:
					pSystem.SetConditionPercentage(.25)
	
				global bImpulseOut
				bImpulseOut = TRUE
	
				DisableMatan(None)
	
	#			DebugPrint("Removing LostImpulseHandler")
				pPlayer.RemoveHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".LostImpulseHandler")


#
# MatanDisableHandler() - Handles when a subsystem gets disabled on Matan's ship
#
def MatanDisableHandler(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("OmegaDraconis1")
	pMatan = App.ShipClass_GetObject(pSet, "Matan's Keldon")

	if bCanDisableMatan == FALSE:
		# Make sure Event Source is valid, so the game won't crash when I do a GetObjID
		if not (pEvent.GetSource() == None): 
			pSystem = App.ShipSubsystem_Cast(pEvent.GetSource())
			pSystem.SetConditionPercentage(pSystem.GetDisabledPercentage() + 0.1)
#			DebugPrint("Keeping Matan's " + pSystem.GetName() + " from being disabled")

	else:
		# Make sure Event Source is valid, so the game won't crash when I do a GetObjID
		if not (pEvent.GetSource() == None): 
			# Make sure the subsystem is valid, so the game won't crash when I do a GetObjID
			if not (pMatan.GetImpulseEngineSubsystem() == None):
				if (pEvent.GetSource().GetObjID() == pMatan.GetImpulseEngineSubsystem().GetObjID()):
#					DebugPrint ("Matan Impulse Engines Gone.")

					global iMatanDisableCount
					iMatanDisableCount = 2
					DisableMatan(None)

					return
	
			if not (pMatan.GetWarpEngineSubsystem() == None):
				if (pEvent.GetSource().GetObjID() == pMatan.GetWarpEngineSubsystem().GetObjID()):
#					DebugPrint ("Matan Warp Engines Gone.")

					global iMatanDisableCount
					iMatanDisableCount = 2
					DisableMatan(None)

					return
	
			if not (pMatan.GetShields() == None):
				if (pEvent.GetSource().GetObjID() == pMatan.GetShields().GetObjID()):
#					DebugPrint ("Matan Shields Gone.")

					global iMatanDisableCount
					iMatanDisableCount = 2
					DisableMatan(None)
	
					return

			if not (pMatan.GetPowerSubsystem() == None):
				if (pEvent.GetSource().GetObjID() == pMatan.GetPowerSubsystem().GetObjID()):
#					DebugPrint ("Matan Power Gone.")

					global iMatanDisableCount
					iMatanDisableCount = 2
					DisableMatan(None)
	
					return


#
# DisableMatan() - Player disables Matan
#
def DisableMatan(bCondition):
#	DebugPrint ("Disable Matan handler")

	global iMatanDisableCount
	iMatanDisableCount = iMatanDisableCount + 1

	if iMatanDisableCount >= 2 and bMatanDisabled == FALSE:

		global bMatanDisabled
		bMatanDisabled = TRUE
	
		pSet = App.g_kSetManager.GetSet("OmegaDraconis1")
		pMatan = App.ShipClass_GetObject(pSet, "Matan's Keldon")
	
#		DebugPrint("Removing MatanDisableHandler handler")
		pMatan.RemoveHandlerForInstance(App.ET_SUBSYSTEM_DISABLED, __name__ + ".MatanDisableHandler")
	
#		DebugPrint("Devastating a bunch of Matan's systems")
		pSystem = pMatan.GetShields()
		if (pSystem):
			pSystem.SetConditionPercentage (0.01)
	
		pSystem = pMatan.GetImpulseEngineSubsystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.01)
	
		pSystem = pMatan.GetWarpEngineSubsystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.01)
	
		pSystem = pMatan.GetTorpedoSystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.01)
	
		pSystem = pMatan.GetPhaserSystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.01)
	
		pSystem = pMatan.GetPulseWeaponSystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.01)
	
		pSystem = pMatan.GetTractorBeamSystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.01)
	
		# Send Matan towards the sun
#		DebugPrint("Sending Matan spinning into the Sun")
	
		pSun = App.PlacementObject_GetObject(pSet, "Sun")
		# Setting spin
		vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
		vVelocity.Scale(10.0 * App.PI / 180.0)
		pMatan.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
	
		# Setting direction
		vVelocity = pSun.GetWorldLocation()
		vVelocity.Subtract(pMatan.GetWorldLocation())
		vVelocity.Unitize()
		vVelocity.Scale(5)
		pMatan.SetVelocity(vVelocity)
	
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create(__name__, "DisableTimedDialogue")
		pSequence.AppendAction(pAction)

		if bImpulseOut:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated01", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		if bImpulseOut:
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated02", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated03", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated04", "E", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated05", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated06", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated07", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			if bSolarformerFixed:
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated08", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)		
	
#			DebugPrint("You plummet into the sun with Matan")
			pAction = EndGameMovie ("data/Movies/FinalLose3.bik")
			pSequence.AppendAction(pAction)

			MissionLib.GameOver(None, pSequence)
			return 
	
		else:
			if (bTractorTried == FALSE):
				global bTractorTried
				bTractorTried = TRUE
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated09", "E", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated10", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			if bSolarformerFixed == FALSE:
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2MatanDefeated12", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "MatanPunishment")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "EnableTimedDialogue")
				pSequence.AppendAction(pAction)

			else:
				pAction = App.TGScriptAction_Create(__name__, "Aftermath")
				pSequence.AppendAction(pAction)
	
		MissionLib.QueueActionToPlay(pSequence)


#
#	MatanPunishment() - Sets a flag that is used when Matan is disabled, but still being fired on
#
def MatanPunishment(pAction):

	global bMatanPunishment
	bMatanPunishment = TRUE

	return 0

#
#	Sparks() - Makes sparks
#
def Sparks(pAction = 0, bDuration = 30):

	Bridge.BridgeEffects.CreateSpark(bDuration)

	return 0


#
#	Aftermath() - Matan is disabled and the Solarformer is stopped
#
def Aftermath(pAction):
#	DebugPrint("Matan disabled. Solarformer stopped. Mission win dialogue.")

	MissionLib.ClearAllAI()

	Bridge.BridgeEffects.CreateSpark(45)

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "DisableTimedDialogue")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "Sparks")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Aftermath1", "S", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "Sparks")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M2Aftermath2", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "Sparks")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Aftermath3", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "Sparks")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Aftermath4", "H", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "Sparks")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M2Aftermath5", "C", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "Sparks")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M2Aftermath7", "E", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "Sparks")
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction, 3)
	pAction3 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_TURN, "Captain")
	pSequence.AddAction(pAction3, pAction, 6)
	pAction4 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M2Aftermath8", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction4, pAction)
	pAction = WinGameMovie()
	pSequence.AppendAction(pAction)

	GameOver(pSequence)

	return 0


def GameOver(pSequence):
	MissionLib.ClearAllAI()

	pGameOverSequence = App.TGSequence_Create()
	
	pChangeToBridge = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pGameOverSequence.AddAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pGameOverSequence.AppendAction(pChangeToBridge)

	pGameOverSequence.AppendAction(pSequence)
	pGameOverSequence.AppendAction(App.TGScriptAction_Create(__name__, "TerminateGame"))

	pSequence.SetSurviveGlobalAbort(1)
	pGameOverSequence.SetSurviveGlobalAbort(1)

	pGameOverSequence.Play()

def TerminateGame(pAction):
	if (pAction):
		pAction.SetSurviveGlobalAbort(1)
	App.Game_GetCurrentGame().Terminate()
	return 0

def InitEndMovie (pAction):
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return None

	pTopWindow.SetNotVisible()

	# Disable options menu
	pTopWindow.DisableOptionsMenu (1)
	pTopWindow.AllowKeyboardInput(0)
	pTopWindow.AllowMouseInput(0)

	return 0

def EndGameMovie (pcMovieName):
	pSequence = App.TGSequence_Create ()

	pAction = App.TGScriptAction_Create(__name__, "WinGameMovieSetID", pSequence.GetObjID ())
	pSequence.AppendAction(pAction, 0.5)

	pSequence.AddAction(App.TGMovieAction_Create(pcMovieName, 1, 1))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "WinGameMovieSetID", App.NULL_ID))

	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SwitchOutOfMovieMode"))

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ExitGame"))

	return pSequence

def SwitchOutOfMovieMode(pAction):
	App.g_kMovieManager.SwitchOutOfMovieMode()
	return 0

def SetupCreditsView(pAction):
	pWarpSet = App.WarpSet_Cast(App.WarpSequence_GetWarpSet())
	pCamera = App.SpaceCamera_Create("CreditsCam")
	pCamera.SetAngleAxisRotation(-1.57, 0, 0, 1)
	pWarpSet.AddCameraToSet(pCamera, "CreditsCam")
	pWarpSet.SetForceUpdate(1)
	pWarpSet.SetActiveCamera("CreditsCam")
	App.g_kSetManager.MakeRenderedSet("warp")

	return 0

def WinGameMovie ():
	pSequence = App.TGSequence_Create ()

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Ending.tgl")

	pAction = App.TGScriptAction_Create(__name__, "WinGameMovieSetID", pSequence.GetObjID ())
	pSequence.AddAction(pAction, None, 0.5)

	pAction = App.TGScriptAction_Create(__name__, "InitEndMovie")
	pSequence.AddAction(pAction)

	# Make sure text is white.
	App.TGCreditAction_SetDefaultColor(1.0, 1.0, 1.0, 1.0)

	pMovieSequence = App.TGSequence_Create ()
	pSequence.AddAction (pMovieSequence)

	pOpenMovie = App.TGMovieAction_Create("data/Movies/FinalWin.bik", 1, 1)
	pMovieSequence.AddAction(pOpenMovie)

	pMoviePane = App.TGPane_Create (1.0, 1.0)
	App.g_kRootWindow.PrependChild (pMoviePane)
	pMoviePane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD,	__name__ + ".HandleKeyboardCredits")

	# Subtitles.
	fTop = 0.927
	pAction = App.TGCreditAction_Create(pDatabase.GetString ("EndPicard01.wav"), pMoviePane, 0.00, fTop, 8.8, 0.25, 0.25, 6, App.TGCreditAction.JUSTIFY_CENTER, App.TGCreditAction.JUSTIFY_TOP)
	pOpenMovie.AddFrameAction (pAction, 240)
#	pMovieSequence.AddAction (pAction, None, 19.0)

	pAction = App.TGCreditAction_Create(pDatabase.GetString ("EndPicard01a.wav"), pMoviePane, 0.00, fTop, 10.5, 0.25, 0.25, 6, App.TGCreditAction.JUSTIFY_CENTER, App.TGCreditAction.JUSTIFY_TOP)
	pOpenMovie.AddFrameAction (pAction, 385)
#	pMovieSequence.AddAction (pAction, None, 28.6)

	pAction = App.TGCreditAction_Create(pDatabase.GetString ("EndPicard02.wav"), pMoviePane, 0.00, fTop, 6.8, 0.25, 0.25, 6, App.TGCreditAction.JUSTIFY_CENTER, App.TGCreditAction.JUSTIFY_TOP)
	pOpenMovie.AddFrameAction (pAction, 560)
#	pMovieSequence.AddAction (pAction, None, 40.3)

	pAction = App.TGCreditAction_Create(pDatabase.GetString ("EndPicard03.wav"), pMoviePane, 0.00, fTop, 10.1, 0.25, 0.25, 6, App.TGCreditAction.JUSTIFY_CENTER, App.TGCreditAction.JUSTIFY_TOP)
	pOpenMovie.AddFrameAction (pAction, 710)
#	pMovieSequence.AddAction (pAction, None, 50.3)

	pAction = App.TGCreditAction_Create(pDatabase.GetString ("EndPicard04.wav"), pMoviePane, 0.00, fTop, 9.5, 0.25, 0.25, 6, App.TGCreditAction.JUSTIFY_CENTER, App.TGCreditAction.JUSTIFY_TOP)
	pOpenMovie.AddFrameAction (pAction, 880)
#	pMovieSequence.AddAction (pAction, None, 61.6)

	pAction = App.TGCreditAction_Create(pDatabase.GetString ("EndPicard05.wav"), pMoviePane, 0.00, fTop, 5.1, 0.25, 0.25, 6, App.TGCreditAction.JUSTIFY_CENTER, App.TGCreditAction.JUSTIFY_TOP)
	pOpenMovie.AddFrameAction (pAction, 1035)
#	pMovieSequence.AddAction (pAction, None, 72.0)

	pAction = App.TGCreditAction_Create(pDatabase.GetString ("EndPicard06.wav"), pMoviePane, 0.00, fTop, 13.5, 0.25, 0.25, 6, App.TGCreditAction.JUSTIFY_CENTER, App.TGCreditAction.JUSTIFY_TOP)
	pOpenMovie.AddFrameAction (pAction, 1125)
#	pMovieSequence.AddAction (pAction, None, 78.0)

	pAction = App.TGScriptAction_Create(__name__, "SwitchOutOfMovieMode")
	pSequence.AppendAction (pAction)

	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "StartCinematicMode"))

	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "WinGameMovieSetID", App.NULL_ID))

	App.g_kLocalizationManager.Unload (pDatabase)

	pMainSequence = App.TGSequence_Create()
	pMainSequence.AppendAction(pSequence)
	pMainSequence.AppendAction(EndGameCredits())

	return pMainSequence


def SwitchOutOfMovieMode (pAction):
#	DebugPrint("Switching out of movie mode")

	App.g_kMovieManager.SwitchOutOfMovieMode ()
	return 0

def WinGameMovieSetID (pAction, iObjID):
	global g_idWinMovieSequence
	g_idWinMovieSequence = iObjID

	if g_idWinMovieSequence != App.NULL_ID:
		# Pause the game.
		App.g_kUtopiaModule.Pause(1)
		# Stop music.
		global g_bMusicEnabled
		g_bMusicEnabled = App.g_kMusicManager.IsEnabled()
		App.g_kMusicManager.SetEnabled(0)
	else:
		# Restart music.
		global g_bMusicEnabled
		try:
			bEnabled = g_bMusicEnabled
		except NameError:
			bEnabled = 1
		# Unpause the game.
		App.g_kMusicManager.SetEnabled(bEnabled)

	return 0

###############################################################################
#	CreateBridgeMenuButton()
#
#	Helper function for creating menu buttons
#
#	Args:	pName		- button name string
#			eType		- Event type sent on button press
#			iSubType	- Event subtype
#			pCharacter	- Character to send event to
#
#	Return:	none
###############################################################################
def CreateBridgeMenuButton(pName, eType, iSubType, pCharacter):
	pEvent = App.TGIntEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pCharacter)
	pEvent.SetInt(iSubType)
	BridgeMenuButton = App.STButton_CreateW(pName, pEvent)
	return BridgeMenuButton


#
# Terminate()
#
# Unload our mission database
#
def Terminate(pMission):
#	DebugPrint ("Terminating Episode 8, Mission 2.\n")

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()

	# Remove handler for Contact Starfleet
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	# Remove Science Scan event
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	# Remove Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	# Remove Hail event
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Remove Communicate handlers
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pDataMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	# Remove Data's Communicate button
	g_pDataMenu.RemoveItemW(pMenuDatabase.GetString("Communicate"))

	# Set our terminate flag to true
	global bMissionTerminate
	bMissionTerminate = TRUE

	if (pGeneralDatabase):
		App.g_kLocalizationManager.Unload(pGeneralDatabase)

	if(pMenuDatabase):
		App.g_kLocalizationManager.Unload(pMenuDatabase)

	# Clear the set course menu
	App.SortedRegionMenu_ClearSetCourseMenu()


def EndGameCredits():
	pSequence = App.TGSequence_Create ()

	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetupCreditsView"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetupCreditsPane"))

	return pSequence

def DebugPrintAction(pAction, pcString):
#	DebugPrint(pcString)
	App.g_kRootWindow.SetCursorVisible(1)
	return 0


def SetupCreditsPane(pPassedAction):
	pSequence = App.TGSequence_Create ()
	
	global g_idWinMovieSequence
	g_idWinMovieSequence = App.NULL_ID

	# Set font to moviemode size
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize[2])

	pCreditsPane = App.TGPane_Cast (App.g_kRootWindow.GetFirstChild ())

	pPane = App.TGPane_Create (1.0, 1.0)
	pCreditsPane.AddChild (pPane)

	# Create dark glass
	pGlass = App.TGIcon_Create(App.GraphicsModeInfo_GetCurrentMode().GetLcarsString(), 120)
	pGlass.Resize (1.0, 1.0, 0)
	pCreditsPane.AddChild (pGlass, 0, 0)

	# Go into cinematic mode

	pSubSeq = MainMenu.mainmenu.CreateCreditsSequence (pPane)
	pSequence.AppendAction (pSubSeq)

	pAction = App.TGScriptAction_Create(__name__, "CleanupCredits")
	pSequence.AppendAction (pAction)

	global g_idCreditsSequence
	g_idCreditsSequence = pSequence.GetObjID ()

	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize [MainMenu.mainmenu.g_iRes])

	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetObjPtr(pPassedAction)
	pSequence.AddCompletedEvent(pEvent)
	pSequence.SetSurviveGlobalAbort(1)
	pSequence.Play()

	return 1

def CleanupCredits (pAction):
#	DebugPrint("Cleaning up credits")
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow == None):
		return

	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcSmallFont, MainMenu.mainmenu.g_kSmallFontSize [MainMenu.mainmenu.g_iRes])

	pTopWindow.SetVisible ()

	# Enable options menu
	pTopWindow.DisableOptionsMenu (0)
	pTopWindow.AllowKeyboardInput(1)
	pTopWindow.AllowMouseInput(1)

	# delete pane that was displaying credits
	pPane = App.g_kRootWindow.GetNthChild (0)
	App.g_kRootWindow.DeleteChild (pPane)

	global g_idCreditsSequence
	g_idCreditsSequence = App.NULL_ID

	if pAction:
		pAction.SetSurviveGlobalAbort(1)

	TerminateGame(None)

	return 0

###############################################################################
#	HandleKeyboardCredits(pPane, pEvent)
#	
#	Keyboard handler for the top button area.
#	
#	Args:	pPane - the pane
#			pEvent		- the keyboard event
#	
#	Return:	none
###############################################################################
def HandleKeyboardCredits(pPane, pEvent):
	# Get the information we need about the key so we can
	# look it up in the table..
	eKeyType = pEvent.GetKeyState()
	cCharCode = pEvent.GetUnicode()

	global g_idCreditsSequence
	global g_idWinMovieSequence

	if eKeyType == App.TGKeyboardEvent.KS_KEYUP:
		if (cCharCode == App.WC_SPACE or cCharCode == App.WC_BACKSPACE or cCharCode == App.WC_ESCAPE):
			if (g_idWinMovieSequence):
				pSequence = App.TGSequence_Cast (App.TGObject_GetTGObjectPtr(g_idWinMovieSequence))
				if (pSequence):
					pSequence.Skip()

				g_idWinMovieSequence = App.NULL_ID
				App.g_kMovieManager.SwitchOutOfMovieMode ()

			elif (g_idCreditsSequence):
				pSequence = App.TGSequence_Cast (App.TGObject_GetTGObjectPtr(g_idCreditsSequence))
				if (pSequence):
					pSequence.Skip ()

				g_idCreditsSequence = App.NULL_ID

				CleanupCredits (None)

 			pEvent.SetHandled()

	if (pEvent.EventHandled() == 0):
		pPane.CallNextHandler(pEvent)

