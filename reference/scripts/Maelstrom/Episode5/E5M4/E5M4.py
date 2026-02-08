###############################################################################
#	Filename:	E5M4.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Episode 5 Mission 4
#
#	Created:	10/09/00 -	Bill Morrison
#	Modified:	01/21/02 - 	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import Bridge.ScienceCharacterHandlers

# For debugging
#kDebugObj = App.CPyDebug()

#
# Event types
#
ET_ONE_MINUTE			= App.Mission_GetNextEventType()
ET_FIRST_GROUP			= App.Mission_GetNextEventType()
ET_SECOND_GROUP			= App.Mission_GetNextEventType()
ET_GALOR_TIMER			= App.Mission_GetNextEventType()
ET_PLAYER_DETECTED		= App.Mission_GetNextEventType()

#
# Global variables
#
HASNT_ARRIVED		= 0
HAS_ARRIVED			= 1

iGroup1Destroyed	= 0
iSatsDestroyed		= 0
Alioth6Scanned		= 0
Alioth6Flag			= HASNT_ARRIVED
Alioth8Flag			= HASNT_ARRIVED
MatanFlag			= HASNT_ARRIVED

pMissionDatabase	= None
pGeneralDatabase	= None
pE5M2Database		= None
pDatabase			= None
pSatellites			= None
pEnemyShips			= None
pFriendlies			= None
pEnemies			= None
g_PlayerInOrbit		= 0
g_PlayerDetected	= 0
g_PlayerSeenPatrol	= 0
g_PlayerSeenSats	= 0
g_NavPlotted		= 0
g_DataOnSurface		= 0
g_PatrolAndSats		= 0
g_PursuersAlive		= 0
g_MissionWin		= 0
g_WarpingOut		= 0
g_Alioth8Seq		= None

KiskaComm			= 0
FelixComm			= 0
MiguelComm			= 0
SaffiComm			= 0
BrexComm			= 0
DataComm			= 0


fStartTime			= 0
kStartupSoundID		= App.PSID_INVALID

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
	loadspacehelper.PreloadShip("Shuttle", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)

	loadspacehelper.PreloadShip("CommLight", 6)
	loadspacehelper.PreloadShip("Keldon", 6)
	loadspacehelper.PreloadShip("Galor", 10)


###############################################################################
#
# Initialize()
#
# Called to initialize our mission
#
###############################################################################
def Initialize(pMission):
#	kDebugObj.Print ("Initializing Episode 5, Mission 4.\n")

	global pMissionDatabase, pGeneralDatabase, pDatabase, pE5M2Database
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 5/E5M4.tgl")
	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pE5M2Database = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 5/E5M2.tgl")
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	global g_PlayerInOrbit, g_PlayerDetected, iGroup1Destroyed, iSatsDestroyed, g_MissionWin, g_WarpingOut, g_Alioth8Seq
	global g_PlayerSeenPatrol, g_PlayerSeenSats, g_DataOnSurface, g_PatrolAndSats, g_NavPlotted, g_PursuersAlive

	iGroup1Destroyed	= 0
	iSatsDestroyed		= 0
	g_PlayerSeenPatrol	= 0
	g_PlayerSeenSats	= 0
	g_PlayerInOrbit		= 0
	g_PlayerDetected	= 0
	g_DataOnSurface		= 0
	g_PatrolAndSats		= 0
	g_PursuersAlive		= 0
	g_MissionWin		= 0
	g_NavPlotted		= 0
	g_WarpingOut		= 0
	g_Alioth8Seq		= None

	# Setting Game Difficulty Multipliers
	App.Game_SetDifficultyMultipliers(1.25, 1.25, 1.0, 1.0, 0.9, 0.9)

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	# Add Data to the bridge
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	import Bridge.Characters.Data
	pData = App.CharacterClass_GetObject(pBridgeSet, "Data")
	if not (pData):
		pData = Bridge.Characters.Data.CreateCharacter(pBridgeSet)
		Bridge.Characters.Data.ConfigureForSovereign(pData)
	
	# Adjust the Guest Chair
	import Bridge.Characters.CommonAnimations
	Bridge.Characters.CommonAnimations.PutGuestChairIn()

	#Init the Charactes
	InitCharacters()

	# Create the mission sets.
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()
	pSet2 = Systems.Starbase12.Starbase12.GetSet()

	import Systems.Alioth.Alioth1
	Systems.Alioth.Alioth1.Initialize()
	pAlioth1 = Systems.Alioth.Alioth1.GetSet()

	import Systems.Alioth.Alioth2
	Systems.Alioth.Alioth2.Initialize()
	pAlioth2 = Systems.Alioth.Alioth2.GetSet()

	import Systems.Alioth.Alioth3
	Systems.Alioth.Alioth3.Initialize()
	pAlioth3 = Systems.Alioth.Alioth3.GetSet()

	import Systems.Alioth.Alioth4
	Systems.Alioth.Alioth4.Initialize()
	pAlioth4 = Systems.Alioth.Alioth4.GetSet()

	import Systems.Alioth.Alioth5
	Systems.Alioth.Alioth5.Initialize()
	pAlioth5 = Systems.Alioth.Alioth5.GetSet()

	import Systems.Alioth.Alioth6
	Systems.Alioth.Alioth6.Initialize()
	pAlioth6 = Systems.Alioth.Alioth6.GetSet()

	import Systems.Alioth.Alioth7
	Systems.Alioth.Alioth7.Initialize()
	pAlioth7 = Systems.Alioth.Alioth7.GetSet()

	import Systems.Alioth.Alioth8
	Systems.Alioth.Alioth8.Initialize()
	pAlioth8 = Systems.Alioth.Alioth8.GetSet()


	# Load our placements into this set
	import Patrol_P
	Patrol_P.LoadPlacements(pAlioth1.GetName())
	Patrol_P.LoadPlacements(pAlioth2.GetName())
	Patrol_P.LoadPlacements(pAlioth3.GetName())
	Patrol_P.LoadPlacements(pAlioth4.GetName())
	Patrol_P.LoadPlacements(pAlioth5.GetName())
	Patrol_P.LoadPlacements(pAlioth7.GetName())

	import Alioth6_P
	Alioth6_P.LoadPlacements(pAlioth6.GetName())

	import EBridge_P
	EBridge_P.LoadPlacements(pBridgeSet.GetName())

	# Create character sets
	pLBridgeSet = MissionLib.SetupBridgeSet("LBridgeSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	pLiu = MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LBridgeSet")

	pMBridgeSet = MissionLib.SetupBridgeSet("MatanSet", "data/Models/Sets/Cardassian/cardbridge.nif")
	pMatan = MissionLib.SetupCharacter("Bridge.Characters.Matan", "MatanSet")

	# Data in Shuttle with planet behind
	pDataSet = MissionLib.SetupBridgeSet("DataSet", "data/Models/Sets/Shuttle/shuttle.nif")
	pData = MissionLib.SetupCharacter("Bridge.Characters.Data", "DataSet")
	pData.SetLocation("ShuttleSeated")

	# Data in Shuttle in space
	pDataSet2 = MissionLib.SetupBridgeSet("DataSet2", "data/Models/Sets/Shuttle/shuttle2.nif")
	pData2 = MissionLib.SetupCharacter("Bridge.Characters.Data", "DataSet2")
	pData2.SetLocation("ShuttleSeated2")

	# Create the ships and set their stats
#	kDebugObj.Print ("Creating ships.\n")

	######################
	# Setup Affiliations #
	######################
	global pFriendlies
	global pEnemies

	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Matan's Keldon")
	pEnemies.AddName("Keldon")
	pEnemies.AddName("Keldon1")
	pEnemies.AddName("Keldon2")
	pEnemies.AddName("Galor")
	pEnemies.AddName("Galor-1")
	pEnemies.AddName("Galor-2")
	pEnemies.AddName("Galor-3")
	pEnemies.AddName("Galor-4")
	pEnemies.AddName("Galor-5")
	pEnemies.AddName("Galor-6")
	pEnemies.AddName("Galor1")
	pEnemies.AddName("Galor2")
	pEnemies.AddName("Galor3")
	pEnemies.AddName("Galor4")
	pEnemies.AddName("Galor5")
	pEnemies.AddName("Satellite 1")
	pEnemies.AddName("Satellite 2")
	pEnemies.AddName("Satellite 3")
	pEnemies.AddName("Satellite 4")
	pEnemies.AddName("Satellite 5")
	pEnemies.AddName("Satellite 6")
	pEnemies.AddName("Keldon-R")
	pEnemies.AddName("Galor-R1")
	pEnemies.AddName("Galor-R2")

	global pSatellites
	pSatellites = App.ObjectGroup()
	pSatellites.AddName("Satellite 1")
	pSatellites.AddName("Satellite 2")
	pSatellites.AddName("Satellite 3")
	pSatellites.AddName("Satellite 4")
	pSatellites.AddName("Satellite 5")
	pSatellites.AddName("Satellite 6")

	global pEnemyShips
	pEnemyShips = App.ObjectGroup()
	pEnemyShips.AddName("Keldon")
	pEnemyShips.AddName("Galor")
	pEnemyShips.AddName("Galor-1")
	pEnemyShips.AddName("Galor-2")
	pEnemyShips.AddName("Galor-3")
	pEnemyShips.AddName("Galor-4")
	pEnemyShips.AddName("Galor-5")
	pEnemyShips.AddName("Galor-6")

	MissionLib.SetupFriendlyFire()

	######################
	# Starbase 12 Objects
	######################
	pPlayer   = MissionLib.CreatePlayerShip("Sovereign", pSet2, "player", "Player Start" )
	pStarbase = loadspacehelper.CreateShip( "FedStarbase", pSet2, "Starbase 12", "Starbase12 Location" )

	####################
	# Alioth 1 Objects
	####################
	pGalor6  = loadspacehelper.CreateShip( "Galor", pAlioth1, "Galor-5", "Placement 3" )
	pGalor7  = loadspacehelper.CreateShip( "Galor", pAlioth1, "Galor-6", "Placement 2" )

	import Orbit1AI
	pGalor6.SetAI(Orbit1AI.CreateAI(pGalor6))
	pGalor7.SetAI(Orbit1AI.CreateAI(pGalor7))

	####################
	# Alioth 2 Objects
	####################
	pComm5   = loadspacehelper.CreateShip( "CommLight", pAlioth2, "Satellite 5", "Placement 3" )
	pComm6	 = loadspacehelper.CreateShip( "CommLight", pAlioth2, "Satellite 6", "Placement 2" )

	import Orbit2AI
	pComm5.SetAI(Orbit2AI.CreateAI(pComm5))
	pComm6.SetAI(Orbit2AI.CreateAI(pComm6))


	####################
	# Alioth 3 Objects
	####################
	pKeldon  = loadspacehelper.CreateShip( "Keldon", pAlioth3, "Keldon", "Placement 3" )
	pGalor   = loadspacehelper.CreateShip( "Galor", pAlioth3, "Galor", "Placement 2" )

	import Orbit3AI
	pKeldon.SetAI(Orbit3AI.CreateAI(pKeldon))
	pGalor.SetAI(Orbit3AI.CreateAI(pGalor))


	####################
	# Alioth 4 Objects #
	####################
	pComm3   = loadspacehelper.CreateShip( "CommLight", pAlioth4, "Satellite 3", "Placement 3" )
	pComm4	 = loadspacehelper.CreateShip( "CommLight", pAlioth4, "Satellite 4", "Placement 2" )

	import Orbit4AI
	pComm3.SetAI(Orbit4AI.CreateAI(pComm3))
	pComm4.SetAI(Orbit4AI.CreateAI(pComm4))

	####################
	# Alioth 5 Objects
	####################

	pGalor2  = loadspacehelper.CreateShip( "Galor", pAlioth5, "Galor-1", "Placement 3" )
	pGalor3  = loadspacehelper.CreateShip( "Galor", pAlioth5, "Galor-2", "Placement 2" )



	import Orbit5AI
	pGalor2.SetAI(Orbit5AI.CreateAI(pGalor2))
	pGalor3.SetAI(Orbit5AI.CreateAI(pGalor3))

	####################
	# Alioth 6 Objects
	####################
	pComm1   = loadspacehelper.CreateShip( "CommLight", pAlioth6, "Satellite 1", "Sat 1 Start" )
	pComm2	 = loadspacehelper.CreateShip( "CommLight", pAlioth6, "Satellite 2", "Sat 2 Start" )

	import PatrolAI2
	pComm1.SetAI(PatrolAI2.CreateAI(pComm1))
	pComm2.SetAI(PatrolAI2.CreateAI(pComm2))

	####################
	# Alioth 7 Objects
	####################

	pGalor4  = loadspacehelper.CreateShip( "Galor", pAlioth7, "Galor-3", "Placement 3" )
	pGalor5  = loadspacehelper.CreateShip( "Galor", pAlioth7, "Galor-4", "Placement 2" )

	import Orbit7AI
	pGalor4.SetAI(Orbit7AI.CreateAI(pGalor4))
	pGalor5.SetAI(Orbit7AI.CreateAI(pGalor5))

	####################
	# Alioth 8 Objects
	####################

	###########################################

	########################################
	# Setup up Warp Menu Buttons for Helm  #
	########################################

	import Systems.Starbase12.Starbase
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()

	import Systems.Alioth.Alioth
	pAliothMenu = Systems.Alioth.Alioth.CreateMenus()

	# Setup more mission-specific events.
	SetupEventHandlers()

	# Set up Range Checks to call out the warnings
	pInRangeOfSats = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 570, "player", pSatellites)
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "CloseToSats", pInRangeOfSats)

	pInRangeOfPatrol = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 857, "player", pEnemyShips)
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "CloseToPatrol", pInRangeOfPatrol)

	pPlayerOrbitting = App.ConditionScript_Create("Conditions.ConditionPlayerOrbitting", "ConditionPlayerOrbitting")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "Orbitting", pPlayerOrbitting)

	MissionLib.SetTotalTorpsAtStarbase("Photon", 600)
	MissionLib.SetTotalTorpsAtStarbase("Quantum", 0)
	MissionLib.SetMaxTorpsForPlayer("Photon", 200)
	MissionLib.SetMaxTorpsForPlayer("Quantum", 60)

	LiuBriefing(None)

	MissionLib.SaveGame("E5M2-")

###############################################################################
#
# InitCharacters()
#
#	Sets up our Global Character pointers
#	so we don't need to keep "getting" the characters
#
###############################################################################
def InitCharacters():
	global pSaffi, pMiguel, pFelix, pKiska, pBrex, pData

	pBridge = App.g_kSetManager.GetSet("bridge")
	pSaffi = App.CharacterClass_GetObject (pBridge, "XO")
	pKiska = App.CharacterClass_GetObject (pBridge, "Helm")
	pFelix = App.CharacterClass_GetObject (pBridge, "Tactical")
	pBrex = App.CharacterClass_GetObject (pBridge, "Engineer")
	pMiguel = App.CharacterClass_GetObject (pBridge, "Science")
	pData = App.CharacterClass_GetObject (pBridge, "Data")

	# Initialize the Communicate Counters
	global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm, DataComm

	KiskaComm			= 0
	FelixComm			= 0
	MiguelComm			= 0
	SaffiComm			= 0
	BrexComm			= 0
	DataComm			= 0


###############################################################################
#
# LoadMiscellaneous()
#
###############################################################################
def LoadMiscellaneous(pSet):
	#Load and place the grid.
	pGrid = App.GridClass_Create ()
	pSet.AddObjectToSet (pGrid, "grid")
	pGrid.SetHidden (1)

###############################################################################
#
# SetupEventHandlers()
#
###############################################################################
def SetupEventHandlers():
	"Setup any event handlers to listen for broadcast events that we'll need."

	pMission = App.Game_GetCurrentGame().GetCurrentEpisode().GetCurrentMission()
	pPlayer = MissionLib.GetPlayer()

	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__+".EnterSet")
	# Exited warp event.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_WARP, pMission, __name__ + ".ExitedWarp")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__+".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ +".ObjectDestroyed")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectDying")

	# Handler for Winning the mission and going to Starbase 12
#	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_COURSE, pMission, __name__ + ".SetCourse")

	pWarpButton = App.SortedRegionMenu_GetWarpButton()
	if (pWarpButton):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED,	__name__ + ".WarpingOut")
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED,	__name__ + ".WarpCheck")

	# Ship Orbitting event
	#Handlers for boosting susbsytem power
	pPlayer.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_POWER_CHANGED, __name__+".PowerCheck")

	# SAFFI HANDLERS
	# Communicate
	pSaffi.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# MIGUEL HANDLERS
	# Science Scan event
	pMiguel.GetMenu().AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__+".ScanHandler")
	# Communicate with Miguel event
	pMiguel.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# KISKA HANDLERS
	# Communicate with Kiska event
	pKiska.GetMenu().AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	# Communicate with Kiska event
	pKiska.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Felix event
	pFelix.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Brex event
	pBrex.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Data event
	pData.GetMenu().AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")


#############################
# Mission Related Functions #
#############################

###############################################################################
#
# EnterSet()
#
###############################################################################
def EnterSet(TGObject, pEvent):
	"An event triggered whenever an object enters a set."
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	pPlayer = MissionLib.GetPlayer()

	if not(pPlayer):
		return

	if (pShip):
		# It's a ship.
		sShipName = pShip.GetName()
		pSet = pShip.GetContainingSet()
		sSetName = pSet.GetName()
		sPlayerSet = pPlayer.GetContainingSet()

#		kDebugObj.Print("Ship \"%s\" entered set \"%s\"" % (sShipName, sSetName))

		global Alioth6Flag
		global Alioth8Flag

		if (sShipName == "player"):
			PowerCheck(None, None)

		if ((sShipName[:len("Keldon")] == "Keldon")) and (sSetName == sPlayerSet.GetName()) and (sSetName != "warp"): 

			if MatanFlag != HAS_ARRIVED:
				pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4PatrolEnter", "Captain", 1, pMissionDatabase)
				pAction.Play()
			else:
				pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4PatrolFollow", "Captain", 1, pMissionDatabase)
				pAction.Play()


		if (sShipName == "player") and (sSetName == "Alioth8") and (Alioth8Flag == HASNT_ARRIVED):
			Alioth8Flag = HAS_ARRIVED
			Alioth8Arrive()

		if (sShipName == "player") and ((sSetName == "Alioth2") or (sSetName == "Alioth4")):
			ArriveSatelliteArea()

		if (sShipName == "player") and (sSetName == "Alioth6") and (Alioth6Flag == HASNT_ARRIVED):
			Alioth6Flag = HAS_ARRIVED
			ArriveSatelliteArea()

		if (sShipName == "player") and ((sSetName == "Alioth7") or (sSetName == "Alioth5") or (sSetName == "Alioth3") or (sSetName == "Alioth1")):
			ArrivePatrolArea()

		if (pShip.GetName() == "player") and (pSet.GetName() == "warp"):
			# Player entered warp set.
			# Adjust Communicate Counters
			global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm, DataComm
			global g_WarpingOut

			DataComm = 0
			KiskaComm = 0
			MiguelComm = 1
		#	FelixComm = 0
		#	BrexComm = 0

			if SaffiComm != 3:
				SaffiComm = 0


	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

def ExitedWarp(pMission, pEvent):
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	pPlayer = MissionLib.GetPlayer()

	if not(pPlayer):
		return

	if (pShip):
		# It's a ship.
		pSet = pShip.GetContainingSet()
		sSetName = pSet.GetName()

		if (pPlayer.GetObjID() == pShip.GetObjID()) and ((sSetName == "Starbase12") or (sSetName[:len("Prendel")] == "Prendel")):

			if (MatanFlag == HASNT_ARRIVED) and (g_PlayerDetected):
				MissionLoss()

			elif (iSatsDestroyed != 2) and (g_DataOnSurface):
				MissionLoss()

	# Broadcast handler, so we don't need to call next handler.

###############################################################################
#
# ExitSet()
#
###############################################################################
def ExitSet(TGObject, pEvent):
	"Triggered whenever an object leaves a set."
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()

	global Group1Destroyed
	global MatanFlag

	if (pShip):
		# It's a ship.
		sShipName = pShip.GetName()
#		kDebugObj.Print("Ship \"%s\" exited set \"%s\"" % (pShip.GetName(), sSetName))

		if (sShipName == "player"):
			global g_PlayerInOrbit
			g_PlayerInOrbit = 0

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


###############################################################################
#
# ObjectDestroyed()
#
###############################################################################
def ObjectDestroyed(TGObject, pEvent):
#	kDebugObj.Print("Object Destroyed")
	pShip = App.ObjectClass_Cast(pEvent.GetDestination())
#	kDebugObj.Print("Ship \"%s\" was destroyed" % pShip.GetName())

	if (pShip):

		global iGroup1Destroyed, g_PursuersAlive

		if ((pShip.GetName() == "Galor-R1") or (pShip.GetName() == "Galor-R2") or (pShip.GetName() == "Keldon-R")):
			iGroup1Destroyed = iGroup1Destroyed + 1
#			kDebugObj.Print("iGroup1Destroyed = %d" % iGroup1Destroyed)

			if (iGroup1Destroyed == 3):
#				kDebugObj.Print("Cards are gone")
				pSequence = App.TGSequence_Create()
				pAction1 = App.TGScriptAction_Create(__name__, "EnemyResponse")
				pSequence.AddAction(pAction1, None, 120)
				pSequence.Play()

				g_PursuersAlive = 0
				iGroup1Destroyed = 0

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

###############################################################################
#
# ObjectDying()
#
###############################################################################
def ObjectDying(TGObject, pEvent):
		
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return

	global iSatsDestroyed, g_MissionWin

	if ((pShip.GetName() == "Satellite 1") or (pShip.GetName() == "Satellite 2")):
		iSatsDestroyed = iSatsDestroyed + 1
#		kDebugObj.Print("iSatsDestroyed = %d" % iSatsDestroyed)

		if (iSatsDestroyed == 2):
#			kDebugObj.Print("Satellites Destroyed")

			if (MatanFlag == HAS_ARRIVED):

				pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiComm2", None, 0, pMissionDatabase)
				pAction.Play()
				
				MissionLib.RemoveGoal("E5DestroySatellitesGoal")
				
				g_MissionWin = 1

			#	pHelmMenu = pKiska.GetMenu()
			#	pCourseMenu = pHelmMenu.GetSubmenuW(pDatabase.GetString("Set Course"))
			#	pSBMenu = pCourseMenu.GetSubmenu("Starbase 12")
			#	pSBMenu = App.SortedRegionMenu_Cast(pSBMenu)

				import Systems.Starbase12.Starbase
				pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
				pSBMenu.SetEpisodeName("Maelstrom.Episode6.Episode6")

				# Set the Communicate Counters
				global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm
				FelixComm = 4
				SaffiComm = 2
				BrexComm = 3		
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


###############################################################################
#
# WarpingOut()
# Event handler for warping out.
#
###############################################################################

def WarpingOut(pObject, pEvent):
	# A course has been set. Check if it is the correct one.
	import Bridge.BridgeUtils
	pButton = Bridge.BridgeUtils.GetWarpButton()

	# For this example, we'll only add the special stuff if the player is going to Starbase 12.
	if ((pButton) and (pButton.GetDestination() == "Systems.Starbase12.Starbase12")) and (g_MissionWin):
		pButton.ClearBDASequences()	# clear anything left over from before

		# Create the MissionWin Sequence
		pSequence = MissionWin()

		# Now, we add the sequence before any of the usual "during warp" things happen.
		pButton.AddActionBeforeDuringWarp(pSequence)
		
	pObject.CallNextHandler(pEvent)

###############################################################################
#
# WarpCheck(pObject, pEvent)
#
###############################################################################
def WarpCheck(pObject, pEvent):
	if (Alioth6Scanned) and (MatanFlag != HAS_ARRIVED):
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4WarpWarn", None, 0, pMissionDatabase)
		pAction.Play()

	else:
		pObject.CallNextHandler(pEvent)

###############################################################################
#
# Orbitting()
#
###############################################################################
def Orbitting(pCondition):

	global g_PlayerInOrbit

	if pCondition:
#		print("In Orbit")
		g_PlayerInOrbit = 1

	else:
#		print("Leaving Orbit")
		g_PlayerInOrbit = 0
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaLeaveOrbit", None, 0, pGeneralDatabase)
		pAction.Play()

###############################################################################
#
# PowerCheck()
#
###############################################################################
def PowerCheck(pObject, pEvent):
#	print("Checking Power Settings")

	pPlayer = MissionLib.GetPlayer()
	pSet = pPlayer.GetContainingSet()
	sSetName = pSet.GetName()

	pSensorPower = pPlayer.GetSensorSubsystem().GetPowerPercentageWanted()
#	print("Sensors: " + str(pSensorPower))

	pShields = pPlayer.GetShields()
	pShieldPower = pPlayer.GetShields().GetPowerPercentageWanted()
#	print("Shields: " + str(pShieldPower))

	pEnginePower = pPlayer.GetImpulseEngineSubsystem().GetPowerPercentageWanted()
#	print("Engines: " + str(pEnginePower))

	pWeapons = pPlayer.GetPhaserSystem()
	pWeaponPower = pPlayer.GetPhaserSystem().GetPowerPercentageWanted()
#	print("Weapons: " + str(pWeaponPower))

	if (sSetName[:len("Alioth")] == "Alioth") and (sSetName != "Alioth8"):
#		print("We're somewhere in Alioth")

		if ( not pShields.IsOn() ) and ( not pWeapons.IsOn()) and (pEnginePower <= 1.01):
#			print("Power settings are acceptable: Not Detected Yet")
			pass		
		elif ((pShields.IsOn()) or (pWeapons.IsOn()) or (pEnginePower > 1.01)) and (not g_PlayerDetected):
#			print("Power settings too high: We've been detected")
			PlayerDiscovered()

#	else:
#		print("We're not in Alioth, we don't care about ship power")

###############################################################################
#
# SensorCheck()
#
###############################################################################
def SensorCheck():
#	print("Checking Sensor Settings")

	pPlayer = MissionLib.GetPlayer()
	pSet = pPlayer.GetContainingSet()
	sSetName = pSet.GetName()

	pSensorPower = pPlayer.GetSensorSubsystem().GetPowerPercentageWanted()

	if (sSetName[:len("Alioth")] == "Alioth") and (sSetName != "Alioth8"):
#		print("We're somewhere in Alioth")

		if (pSensorPower <= 1.01):
#			print("Power settings are acceptable: Not Detected Yet")
			pass
		elif (pSensorPower > 1.01) and (not g_PlayerDetected):
#			print("Power settings too high: We've been detected")
			PlayerDiscovered()

#	else:
#		print("We're not in Alioth, we don't care about sensor power")


###############################################################################
#
# CloseToSats
#
# Called from Distance Check AI
#
###############################################################################
def CloseToSats(bInRange):

	if not bInRange:
		return

	if g_PlayerDetected:
		return

	pSet	= MissionLib.GetPlayerSet()
	pPlayer = MissionLib.GetPlayer()

	if (pSet.GetName() == "warp"):
		return

	if pPlayer.IsDoingInSystemWarp():
#		print("Stopping the ship")
		MissionLib.SetPlayerAI(None, None)

	pSequence = App.TGSequence_Create()
	pAction1 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4SatsClose", "Captain", 1, pMissionDatabase)
	pAction2 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2KiskaProd1", "Captain", 0, pE5M2Database)

	pSequence.AddAction(pAction1)
	pSequence.AddAction(pAction2, pAction1)
	pSequence.Play()


###############################################################################
#
# CloseToPatrol
#
# Called from Distance Check AI
#
###############################################################################
def CloseToPatrol(bInRange):

	if not bInRange:
		return

	if g_PlayerDetected:
		return

	pSet = MissionLib.GetPlayerSet()
	pPlayer = MissionLib.GetPlayer()

	if (pSet.GetName() == "warp"):
		return

	if pPlayer.IsDoingInSystemWarp():
#		print("Stopping the ship")
		MissionLib.SetPlayerAI(None, None)

	pSequence = App.TGSequence_Create()

	pAction1 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4PatrolClose", "Captain", 1, pMissionDatabase)
	pAction2 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M2KiskaProd1", "Captain", 0, pE5M2Database)
	pSequence.AddAction(pAction1)

	pSequence.AddAction(pAction2, pAction1)
	pSequence.Play()


###############################################################################
#
# PlayerDiscovered()
#
###############################################################################
def PlayerDiscovered():
#	print("\n **** PLAYER HAS BEEN DETECTED **** \n")

	if g_PlayerDetected == 1:
		return

	global g_PlayerDetected
	g_PlayerDetected = 1

	# Send an ET_PLAYER_DETECTED event.
	pDetectedEvent = App.TGEvent_Create()
	pDetectedEvent.SetEventType( ET_PLAYER_DETECTED )
	pDetectedEvent.SetDestination( MissionLib.GetMission() )
	App.g_kEventManager.AddEvent( pDetectedEvent )

	pSequence = App.TGSequence_Create()

	pAction1 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4L030", None, 0, pMissionDatabase)
	pAction2 = App.TGScriptAction_Create(__name__, "EnemyResponse")

	pSequence.AddAction(pAction1)
	pSequence.AddAction(pAction2, pAction1, 10)
	pSequence.Play()

	# Add our Objectives
	MissionLib.RemoveGoal("E5AvoidDetectionGoal")

	# Set the Communicate Counters
	global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm
	FelixComm = 4
	SaffiComm = 3
	BrexComm = 2


###############################################################################
#
# EnemyResponse(pAction)
#
###############################################################################
def EnemyResponse(pAction):
#	kDebugObj.Print ("Creating Enemy Response Group.\n")

	if Alioth6Scanned:
#		kDebugObj.Print ("Creation Aborted... player in position over Alioth 6.\n")
		return 0

	pPlayer = MissionLib.GetPlayer()
	pSet = MissionLib.GetPlayerSet()

	if (pSet.GetName() == "warp"):
#		print("Retrying creation of Enemies in 5 seconds")
		
		pSequence = App.TGSequence_Create()
		pAction = App.TGScriptAction_Create(__name__, "EnemyResponse")
		pSequence.AddAction(pAction, None, 5)
		pSequence.Play()
		
		return 0 

	# Make a new waypoint for a ship to warp in to..
	pPlacement = App.PlacementObject_Create("Keldon 1 warp in", pSet.GetName(), None)
	kLocation = pPlayer.GetWorldLocation()
	# Position the waypoint on the opposite side of the player as the
	# planet...
	lPlanets = pSet.GetClassObjectList(App.CT_PLANET)
	
	for pEachPlanet in lPlanets:
		if pEachPlanet.GetName()[:len("Alioth")] == "Alioth":
			pPlanet = pEachPlanet
			break
				
	vDiff = pPlayer.GetWorldLocation()
	vDiff.Subtract(pPlanet.GetWorldLocation())
	# Put the new ship 200 units away from the player...
	vDiff.Unitize()
	vDiff.Scale(200.0)

	# Make sure the ship's location won't overlap any other objects in the world.
	kTestPosition = App.TGPoint3()
	kTestPosition.Set(kLocation)
	kTestPosition.Add(vDiff)
	while pSet.IsLocationEmptyTG(kTestPosition, pPlayer.GetRadius() * 1.5) == 0:
		ChooseNewLocation(kLocation, vDiff)
		kTestPosition.Set(kLocation)
		kTestPosition.Add(vDiff)
	kLocation.Set(kTestPosition)

	# Change the waypoint's orientation so it's facing toward the
	# player, so the new ships warp in toward the player.
	kFwd = pPlayer.GetWorldLocation()
	kFwd.Subtract( kLocation )
	kFwd.Unitize()
	kUp = pPlayer.GetWorldUpTG()
	kUp.GetPerpendicularComponent( kFwd )
	kUp.Unitize()

	pPlacement.SetTranslate(kLocation)
	pPlacement.AlignToVectors( kFwd, kUp )
	pPlacement.UpdateNodeOnly()

	# Add waypoints for 2 other ships.
	pPlace2 = App.PlacementObject_Create("Warp in 2", pSet.GetName(), None)
	kOffset = pPlacement.GetWorldRightTG()
	kOffset.Scale(50.0)
	kLocation2 = pPlacement.GetWorldLocation()
	kLocation2.Add( kOffset )
	pPlace2.SetTranslate(kLocation2)
	pPlace2.AlignToVectors( kFwd, kUp )
	pPlace2.UpdateNodeOnly()

	# Add waypoints for 2 other ships.
	pPlace3 = App.PlacementObject_Create("Warp in 3", pSet.GetName(), None)
	kOffset = pPlacement.GetWorldRightTG()
	kOffset.Scale(-50.0)
	kLocation3 = pPlacement.GetWorldLocation()
	kLocation3.Add( kOffset )
	pPlace3.SetTranslate(kLocation3)
	pPlace3.AlignToVectors( kFwd, kUp )
	pPlace3.UpdateNodeOnly()

	pKeldon = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon-R", "Keldon 1 warp in", 1 )
	pGalor1 = loadspacehelper.CreateShip( "Galor", pSet, "Galor-R1", "Warp in 2", 1 )
	pGalor2 = loadspacehelper.CreateShip( "Galor", pSet, "Galor-R2", "Warp in 3", 1 )

	import EnemyAI2
	pKeldon.SetAI(EnemyAI2.CreateAI(pKeldon))
	pGalor1.SetAI(EnemyAI2.CreateAI(pGalor1))
	pGalor2.SetAI(EnemyAI2.CreateAI(pGalor2))

	global g_PursuersAlive
	g_PursuersAlive = 1

	return 0

###############################################################################
#	ChooseNewLocation(vOrigin, vOffset)
#
#	Chooses a location for an incoming ship.
#
#	Args:	vOrigin		- the origin -- input parameter
#			vOffset		- the offset -- returns the location for the ship
#
#	Return:	zero
###############################################################################
def ChooseNewLocation(vOrigin, vOffset):
	# Add some random amount to vOffset
	fUnitRandom = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
	fUnitRandom = fUnitRandom * 20.0

	vOffset.SetX( vOffset.GetX() + fUnitRandom )


	fUnitRandom = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
	fUnitRandom = fUnitRandom * 20.0

	vOffset.SetY( vOffset.GetY() + fUnitRandom )


	fUnitRandom = (App.g_kSystemWrapper.GetRandomNumber(10001) - 5000.0) / 5000.0
	fUnitRandom = fUnitRandom * 20.0

	vOffset.SetZ( vOffset.GetZ() + fUnitRandom )

	return 0

###############################################################################
#
# Briefing from Liu
#
###############################################################################
def LiuBriefing(pAction):
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pLiu.SetHidden(0)

	if MissionLib.IsPlayerWarping():
		# Delay sequence 2 seconds. 
		pSequence = App.TGSequence_Create()
		pRePlayLiuBriefing	= App.TGScriptAction_Create(__name__, "LiuBriefing")
		pSequence.AppendAction(pRePlayLiuBriefing, 2)
		pSequence.Play()

		return 0

	pSequence = App.TGSequence_Create()
	pBridgeCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pBridgeCam)
	pAction	= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg5","Captain", 1, pGeneralDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4L001", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4L002", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4L003", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pStartCamera = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pStartCamera)
	pScienceCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pScienceCam)
	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4MiguelWonder", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pDataCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pDataCam)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4DataExplain", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pBrexCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1)
	pSequence.AppendAction(pBrexCam)
	pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4BrexDense", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pScienceCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pScienceCam)
	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4MiguelDense", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pDataCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
	pSequence.AppendAction(pDataCam)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4DataExplain2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pPlayerCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pPlayerCam)
	pEndCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pEndCamera)
	pAction	= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)
	pSequence.Play()

	# Add our Objectives
	MissionLib.AddGoal("E5LocateDeviceGoal")
	MissionLib.AddGoal("E5AvoidDetectionGoal")
	MissionLib.AddGoal("E5SearchAliothGoal")

	return 0

###############################################################################
#
# ScanHandler()
#
###############################################################################
def ScanHandler(pObject, pEvent):
#	kDebugObj.Print("Scanning")

	iScanType = pEvent.GetInt()

	pPlayer = MissionLib.GetPlayer()
	pSet = pPlayer.GetContainingSet()
	pcSetName = pSet.GetName()

	pSensors = pPlayer.GetSensorSubsystem()

	if (pSensors == None):
		pObject.CallNextHandler(pEvent)
		return

	if (pSensors.IsOn() == 0):
		pObject.CallNextHandler(pEvent)
		return


	# Adjust Communicate Counters
	global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm, DataComm

	if (iScanType == App.CharacterClass.EST_SCAN_OBJECT):

		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
			pTarget = pPlayer.GetTarget()

		if pTarget == None:
			return

		SensorCheck()

		pcTargetName = pTarget.GetName()

		if (pcTargetName[:len("Satellite")] == "Satellite"):
			pSequence = App.TGSequence_Create()
				
			pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4SatScanned", "Captain", 1, pMissionDatabase)	
			pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

			pSequence.AppendAction(pScanSequence)		
			pSequence.AppendAction(pAction)
			pSequence.AppendAction(pEnableScanMenu)	
			pSequence.Play()
			return

		if ((pcTargetName[:len("Galor")] == "Galor") or (pcTargetName[:len("Keldon")] == "Keldon")) and not (g_PlayerDetected):
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4ScanCardWarn", "Captain", 1, pMissionDatabase)
			pAction.Play()
			return
			
		############################################
		#
		# We're scanning one of the Alioth Planets
		#
		############################################
		if (pcTargetName[:len("Alioth")] == "Alioth"):		
				
			###########################################################
			# Trying to scan a planet while the Pursuit group is alive
			#  NO CAN DO.... Warn the player and bail
			###########################################################
			if (g_PursuersAlive):
#				print("Pursuers are around. Not safe to start Data's sequence / scan")
				pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4ScanCardWarn2", "Captain", 1, pMissionDatabase)
				pAction.Play()
				return
			
			
			###########################################################
			# Trying to scan while not in Orbit and Not Detected
			# NO CAN DO.... Warn the player and bail
			###########################################################
			elif not (g_PlayerInOrbit) and not (g_PlayerDetected):
#				print("Player not in orbit... not Detected")
				
				if (pcTargetName[:len("Alioth")] == "Alioth"):
					pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4NotInOrbit", "Captain", 1, pMissionDatabase)
					pAction.Play()
					return
		
			#####################################################################	
			# Either we're trying to scan while Not Detected and Orbitting - OK
			# Or We've been detected, so discovery by scanning is not an issue
			#####################################################################
			elif ((g_PlayerInOrbit) and not (g_PlayerDetected)) or (g_PlayerDetected):
				
				if (pcTargetName == "Alioth 6") and (not Alioth6Scanned):
#					kDebugObj.Print("Scanning Alioth 6")
					
					if (g_PlayerInOrbit):					
#						print("No Pursuers around. We're in Orbit. It's safe to start Data's sequence")
						global Alioth6Scanned
						Alioth6Scanned = 1
					
						pSequence = App.TGSequence_Create()
						pCineStart	= App.TGScriptAction_Create("MissionLib", "StartCutscene")
						pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
						pAction			= App.TGScriptAction_Create(__name__, "DataLeaves")
						pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
					
						pSequence.AppendAction(pCineStart)
						pSequence.AppendAction(pScanSequence)		
						pSequence.AppendAction(pAction)
						pSequence.AppendAction(pEnableScanMenu)	

						pSequence.Play()
						return

					else:
#						print("Pursuers are around, and we're trying to scan Alioth 6. Not in Orbit")
						pSequence = App.TGSequence_Create()
					
						pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
						pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4NotInOrbit2", "Captain", 1, pMissionDatabase)
						pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
						
						pSequence.AppendAction(pScanSequence)		
						pSequence.AppendAction(pAction)
						pSequence.AppendAction(pEnableScanMenu)					
					
						pSequence.Play()
						return


				if (pcTargetName == "Alioth 8"):
#					kDebugObj.Print("Scanning Alioth 8")
					pSequence = App.TGSequence_Create()

					pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
					pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L019", "Captain", 1, pMissionDatabase)
					pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

					pSequence.AppendAction(pScanSequence)		
					pSequence.AppendAction(pAction)
					pSequence.AppendAction(pEnableScanMenu)

					MiguelComm = 2
					DataComm = 1
					SaffiComm = 5
			
					pSequence.Play()
					return

				if (pcTargetName == "Alioth 7"):
#					kDebugObj.Print("Scanning Alioth 7")
					pSequence = App.TGSequence_Create()

					pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
					pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L018", "Captain", 1, pMissionDatabase)
					pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

					pSequence.AppendAction(pScanSequence)		
					pSequence.AppendAction(pAction)
					pSequence.AppendAction(pEnableScanMenu)

					MiguelComm = 2
					DataComm = 1
					SaffiComm = 5

					pSequence.Play()
					return

				if (pcTargetName == "Alioth 5"):
#					kDebugObj.Print("Scanning Alioth 5")
					pSequence = App.TGSequence_Create()

					pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
					pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L017", "Captain", 1, pMissionDatabase)
					pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

					pSequence.AppendAction(pScanSequence)		
					pSequence.AppendAction(pAction)
					pSequence.AppendAction(pEnableScanMenu)

					MiguelComm = 2
					DataComm = 1
					SaffiComm = 5

					pSequence.Play()
					return

				if (pcTargetName == "Alioth 4"):
#					kDebugObj.Print("Scanning Alioth 4")
					pSequence = App.TGSequence_Create()

					pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
					pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L016", "Captain", 1, pMissionDatabase)
					pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

					pSequence.AppendAction(pScanSequence)		
					pSequence.AppendAction(pAction)
					pSequence.AppendAction(pEnableScanMenu)

					MiguelComm = 2
					DataComm = 1
					SaffiComm = 5
					pSequence.Play()
					return

				if (pcTargetName == "Alioth 3"):
#					kDebugObj.Print("Scanning Alioth 3")
					pSequence = App.TGSequence_Create()

					pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
					pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4Planet3", "Captain", 1, pMissionDatabase)
					pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

					pSequence.AppendAction(pScanSequence)		
					pSequence.AppendAction(pAction)
					pSequence.AppendAction(pEnableScanMenu)

					MiguelComm = 2
					DataComm = 1
					SaffiComm = 5

					pSequence.Play()
					return

				if (pcTargetName == "Alioth 2"):
#					kDebugObj.Print("Scanning Alioth 2")
					pSequence = App.TGSequence_Create()

					pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
					pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4Planet2", "Captain", 1, pMissionDatabase)
					pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

					pSequence.AppendAction(pScanSequence)		
					pSequence.AppendAction(pAction)
					pSequence.AppendAction(pEnableScanMenu)

					MiguelComm = 2
					DataComm = 1
					SaffiComm = 5

					pSequence.Play()
					return

				if (pcTargetName == "Alioth 1"):
#					kDebugObj.Print("Scanning Alioth 1")
					pSequence = App.TGSequence_Create()

					pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
					pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4Planet1", "Captain", 1, pMissionDatabase)
					pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

					pSequence.AppendAction(pScanSequence)		
					pSequence.AppendAction(pAction)
					pSequence.AppendAction(pEnableScanMenu)

					MiguelComm = 2
					DataComm = 1
					SaffiComm = 5

					pSequence.Play()
					return


	if (iScanType == App.CharacterClass.EST_SCAN_AREA):

		SensorCheck()

		if (pcSetName[:len("Alioth")] == "Alioth"):
			pSequence = App.TGSequence_Create()

			pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence()
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4NotRightArea", "Captain", 1, pMissionDatabase)
			pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

			pSequence.AppendAction(pScanSequence)		
			pSequence.AppendAction(pAction)
			pSequence.AppendAction(pEnableScanMenu)
		
			pSequence.Play()
			return


#	kDebugObj.Print("Nothing Detected")
	pObject.CallNextHandler(pEvent)



###############################################################################
#
# CommunicateHandler()
#
###############################################################################
def CommunicateHandler(pObject, pEvent):
#	print("Communicating with crew")

	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())
	pPlayer = MissionLib.GetPlayer()
	if not pPlayer or not pMenu:
		return
	pSet = pPlayer.GetContainingSet()

	pBridge = App.g_kSetManager.GetSet("bridge")

	pSaffiMenu = pSaffi.GetMenu()
	pFelixMenu = pFelix.GetMenu()
	pKiskaMenu = pKiska.GetMenu()
	pMiguelMenu = pMiguel.GetMenu()
	pBrexMenu = pBrex.GetMenu()
	pDataMenu = pData.GetMenu()

	pAction = 0

	if pMenu.GetObjID() == pKiskaMenu.GetObjID():
#		print("Communicating with Kiska")

		if (KiskaComm == 1):
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4KiskaCommPatrol", None, 0, pMissionDatabase)

		if (KiskaComm == 2):
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4KiskaCommSat", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == pSaffiMenu.GetObjID():
#		print("Communicating with Saffi")

		if (SaffiComm == 1):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiComm1", None, 0, pMissionDatabase)

		elif (SaffiComm == 2):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiComm2", None, 0, pMissionDatabase)

		elif (SaffiComm == 3):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiCommDetected", None, 0, pMissionDatabase)

		elif (SaffiComm == 4):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiComm0", None, 0, pMissionDatabase)

		elif (SaffiComm == 5):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4NotRightPlanet", None, 0, pMissionDatabase)


	elif pMenu.GetObjID() == pMiguelMenu.GetObjID():
#		print("Communicating with Miguel")

		if (MiguelComm == 1):
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4MiguelComm1", None, 0, pMissionDatabase)

		if (MiguelComm == 2):
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4MiguelComm2", None, 0, pMissionDatabase)


	elif pMenu.GetObjID() == pFelixMenu.GetObjID():
#		print("Communicating with Felix")

		if (FelixComm == 1):
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4FelixComm1", None, 0, pMissionDatabase)

		elif (FelixComm == 2):
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4FelixComm2", None, 0, pMissionDatabase)

		elif (FelixComm == 3):
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4FelixComm3", None, 0, pMissionDatabase)

		elif (FelixComm == 4):
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4FelixComm4", None, 0, pMissionDatabase)


	elif pMenu.GetObjID() == pBrexMenu.GetObjID():
#		print("Communicating with Brex")

		if (BrexComm == 1):
			pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4BrexComm1", None, 0, pMissionDatabase)

		elif (BrexComm == 2):
			pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4BrexComm2", None, 0, pMissionDatabase)

		elif (BrexComm == 3):
			pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4BrexComm3", None, 0, pMissionDatabase)


	else:
#		print("Communicating with Data")

		if (DataComm == 1):
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4DataComm1", None, 0, pMissionDatabase)

		elif (DataComm == 2):
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4DataComm2", None, 0, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4DataNoComm", None, 0, pMissionDatabase)


	if pAction:
		pAction.Play()

	else:
#		print("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)


###############################################################################
#
# HailHandler()
#
###############################################################################
def HailHandler(pObject, pEvent):
#	print("Hailing")

	pShip = App.ObjectClass_Cast(pEvent.GetSource())

	if pShip == None:
		return

	pcShipName = pShip.GetName()

	if not (g_PlayerDetected):

		if ((pcShipName[:len("Galor")] == "Galor") or (pcShipName[:len("Keldon")] == "Keldon") or (pcShipName[:len("Satellite")] == "Satellite")):
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4HailWarn", "Captain", 1, pMissionDatabase)
			pAction.Play()

		else:
			pObject.CallNextHandler(pEvent)
	
	elif (g_PlayerDetected):

		if (pcShipName == "Alioth 6") and (MatanFlag == HAS_ARRIVED):
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4HailDataWarn", "Captain", 1, pMissionDatabase)
			pAction.Play()

		elif (pcShipName == "Matan"):
			pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4HailMatan", "Captain", 1, pMissionDatabase)
			pAction.Play()

		else:
			pObject.CallNextHandler(pEvent)


###############################################################################
#
# Alioth8Arrive()
#
###############################################################################
def Alioth8Arrive():
#	kDebugObj.Print("Trigger Alioth 8 Arrival")

	global g_Alioth8Seq

	pSequence = App.TGSequence_Create()
	g_Alioth8Seq = pSequence.GetObjID()

	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L007", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction, 5)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4L008", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4L009", "Captain", 1, pMissionDatabase)
#	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4L010", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4L011", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4L012c", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4BrexComm1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4FelixSuggest", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4L013", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4L014b", "Captain", 1, pMissionDatabase)
#	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L015", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiComment1", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiComment2", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pSequence.Play()

	# Set the Communicate Counters
	global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm
	FelixComm = 1
	SaffiComm = 4
	BrexComm = 1


###############################################################################
#
# ArriveSatelliteArea()
#
###############################################################################
def ArriveSatelliteArea():
#	kDebugObj.Print("Trigger Arrival in Satellite Area")

	global KiskaComm
	KiskaComm = 2

	if MatanFlag == HAS_ARRIVED:
		return

	if g_PlayerDetected:
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4SatsDetected", "Captain", 1, pMissionDatabase)
		pAction.Play()
		return

	pSequence = App.TGSequence_Create()

	if (not g_PlayerSeenSats):
		global g_PlayerSeenSats
		g_PlayerSeenSats = 1

		pAction1 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4SatsDetected", "Captain", 0, pMissionDatabase)
		pAction2 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4SatsDetected2", "Captain", 1, pMissionDatabase)
		pAction3 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiSuggest1", "Captain", 1, pMissionDatabase)

		pSequence.AddAction(pAction1, None, 5)
		pSequence.AddAction(pAction2, pAction1)
		pSequence.AddAction(pAction3, pAction2)

		if not(g_NavPlotted):
			pAction4 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4KiskaStop", "Captain", 0, pMissionDatabase)
			pSequence.AddAction(pAction4, pAction3)
			pAction5 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4KiskaStop2", "Captain", 1, pMissionDatabase)
			pSequence.AddAction(pAction5, pAction4)

			global g_NavPlotted
			g_NavPlotted = 1
				
	else:
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4MoreSats", "Captain", 1, pMissionDatabase)
		pSequence.AddAction(pAction, None, 5)

	if (g_PlayerSeenSats) and (g_PlayerSeenPatrol):
		DataRecommend(pSequence)


	if (g_Alioth8Seq != None) and (App.TGObject_GetTGObjectPtr(g_Alioth8Seq) != None):
		pSequence1 = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_Alioth8Seq))
		pSequence1.AppendAction(pSequence)
	else:
		pSequence.Play()

###############################################################################
#
# ArrivePatrolArea()
#
###############################################################################
def ArrivePatrolArea():
#	kDebugObj.Print("Trigger Arrival in Patrol Area")

	global KiskaComm
	KiskaComm = 1

	if MatanFlag == HAS_ARRIVED:
		return

	if g_PlayerDetected:
		pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4PatrolDetected", "Captain", 1, pMissionDatabase)
		pAction.Play()
		return

	pSequence = App.TGSequence_Create()

	if (not g_PlayerSeenPatrol):
		global g_PlayerSeenPatrol
		g_PlayerSeenPatrol = 1

		pAction1 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4PatrolDetected", "Captain", 1, pMissionDatabase)
		pAction2 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4PatrolDetected2", "Captain", 1, pMissionDatabase)

		pSequence.AddAction(pAction1, None, 5)
		pSequence.AddAction(pAction2, pAction1)

		if not(g_NavPlotted):
			pAction3 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4KiskaStop", "Captain", 0, pMissionDatabase)
			pSequence.AddAction(pAction3, pAction2)
			pAction4 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4KiskaStop2", "Captain", 1, pMissionDatabase)
			pSequence.AddAction(pAction4, pAction3)

			global g_NavPlotted
			g_NavPlotted = 1
				

	else:
	
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4MorePatrols", "Captain", 1, pMissionDatabase)
		pSequence.AddAction(pAction, None, 5)

	if (g_PlayerSeenSats) and (g_PlayerSeenPatrol):
		DataRecommend(pSequence)

	if (g_Alioth8Seq != None) and (App.TGObject_GetTGObjectPtr(g_Alioth8Seq) != None):
		pSequence1 = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_Alioth8Seq))
		pSequence1.AppendAction(pSequence)
	else:
		pSequence.Play()

###############################################################################
#
# DataRecommend()
#
###############################################################################
def DataRecommend(pSequence):
#	kDebugObj.Print("Data puts together the pieces")

	if not (g_PatrolAndSats):
		global g_PatrolAndSats
		g_PatrolAndSats = 1
	
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4DataComm2", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)


###############################################################################
#
# DataLeaves()
#
###############################################################################
def DataLeaves(pAction):
#	kDebugObj.Print("Trigger Data Leaving / Away Team")

	global g_DataOnSurface
	g_DataOnSurface = 1
	
	import BridgeHandlers
	BridgeHandlers.ViewscreenDirection("Forward")

	pDataSet = App.g_kSetManager.GetSet("DataSet")
	pData2 = App.CharacterClass_GetObject (pDataSet, "Data")

	pSequence = App.TGSequence_Create()

	pBridgeCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pBridgeCam)

	pStartMusic = App.TGScriptAction_Create(__name__, "StartMusic")	
	pSequence.AppendAction(pStartMusic)

	pStartCamera = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pStartCamera, 3)
	pScienceCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pScienceCam)
	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L020", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L021", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)


	pDataCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
	pSequence.AppendAction(pDataCam)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4L022", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pSaffiCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pSaffiCam)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4L023", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pBrexCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1)
	pSequence.AppendAction(pBrexCam)
	pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4L024", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	#ShuttleCraft
	pSaffiCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pSaffiCam)
	pAction = App.CharacterAction_Create(pSaffi,App.CharacterAction.AT_SAY_LINE, "E5M4L025", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pDataCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pDataCam)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4L026", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pSaffiCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam2", 1)
	pSequence.AppendAction(pSaffiCam)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4L027", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pKiskaCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Kiska Head", "Felix Cam", 1)
	pSequence.AppendAction(pKiskaCam)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4L036", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pDataCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pDataCam)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4L028", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_MOVE, "L1")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "DataCutscene")
	pSequence.AppendAction(pAction)

	pSequence.Play()

	return 0

###############################################################################
#
# Creates shuttlecraft
#
###############################################################################
def DataCutscene(pAction):

	pPlayer = MissionLib.GetPlayer()

	pDataSet2 = App.g_kSetManager.GetSet("DataSet2")
	pData2 = App.CharacterClass_GetObject (pDataSet2, "Data")

	pDataSet1 = App.g_kSetManager.GetSet("DataSet")
	pData1 = App.CharacterClass_GetObject (pDataSet1, "Data")

	pSequence = App.TGSequence_Create()

	pCamSwitch = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Alioth6")
	pSequence.AppendAction(pCamSwitch)

	pFlyby	= App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Alioth6", "player")
	pSequence.AppendAction(pFlyby)

	pChaseCam1	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChaseCam", "Alioth6", "player", 0, 0)
	pSequence.AppendAction(pChaseCam1, 4)

	pLaunch		= App.TGScriptAction_Create("Actions.ShipScriptActions", "LaunchObject", pPlayer.GetObjID(), "Shuttlecraft", App.ObjectEmitterProperty.OEP_SHUTTLE)
	pSequence.AppendAction(pLaunch)

	# This will also make the shuttle not collide with the player.
	pSetAI		= App.TGScriptAction_Create(__name__, "GiveShuttleAI")
	pSequence.AppendAction(pSetAI)

	pCamSwitch = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Alioth6")
	pSequence.AppendAction(pCamSwitch)

	pRevCam1	= App.TGScriptAction_Create("Actions.CameraScriptActions", "LockedView", "Alioth6", "Shuttlecraft", 350, 5, 1.15)
	pSequence.AppendAction(pRevCam1)

	pCamSwitch2 = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pCamSwitch2, 5)

	pPlayerCam	= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pPlayerCam)

	pKiskaLook = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pKiskaLook)

	pKiskaLin = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4L037", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pKiskaLin)

	pDataOn1	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DataSet2", "Data")
	pSequence.AppendAction(pDataOn1, 1)

	pDataLin  = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M4L029", None, 0, pMissionDatabase)
	pSequence.AppendAction(pDataLin, 1)

	pViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pViewOff, 1)

	pCamSwitch3 = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Alioth6")
	pSequence.AppendAction(pCamSwitch3, 2)

	pRevCam2	= App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Alioth6", "Shuttlecraft")
	pSequence.AppendAction(pRevCam2)

	pCamSwitch4 = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pCamSwitch4, 5)

	pRemShuttle = App.TGScriptAction_Create(__name__, "RemoveShuttle")
	pSequence.AppendAction(pRemShuttle)

	pKiskaLin2 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4L038", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pKiskaLin2, 2)

	pViewOn2   = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DataSet", "Data", 5, 5)
	pSequence.AppendAction(pViewOn2)

	pDataLin2  = App.CharacterAction_Create(pData1, App.CharacterAction.AT_SAY_LINE, "E5M4L039", None, 0, pMissionDatabase)
	pSequence.AppendAction(pDataLin2, 1)

	pViewOff2  = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pViewOff2, 1)



	pCamSwitch5 = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Alioth6")
	pSequence.AppendAction(pCamSwitch5, 2)

	pRevCam3	= App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Alioth6", "player")
	pSequence.AppendAction(pRevCam3)

	pCamSwitch6 = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pCamSwitch6, 5)



	pKiskaLin3 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4L040", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pKiskaLin3, 5)

	pDataLin3  = App.CharacterAction_Create(pData2, App.CharacterAction.AT_SAY_LINE, "E5M4L041", None, 0, pMissionDatabase)
	pSequence.AppendAction(pDataLin3, 1)

	pAction  = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4L030", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pMatanShow = App.TGScriptAction_Create(__name__, "MatanArrive")
	pSequence.AppendAction(pMatanShow)

	pSequence.Play()

	return 0

###############################################################################
#
# GiveShuttleAI
#
###############################################################################
def GiveShuttleAI(pAction):

	pSet		= App.g_kSetManager.GetSet("Alioth6")
	pShuttle	= App.ShipClass_GetObject(pSet, "Shuttlecraft")
	pPlayer		= MissionLib.GetPlayer()

	pShuttle.EnableCollisionsWith(pPlayer, 0)

	import ShuttleAI
	pShuttle.SetAI(ShuttleAI.CreateAI(pShuttle))

	return 0


def RemoveShuttle(pAction):

	pSet		= App.g_kSetManager.GetSet("Alioth6")
	pSet.DeleteObjectFromSet("Shuttlecraft")

	return 0

###############################################################################
#
# MatanArrive()  - Creates the Matan and his group
#
###############################################################################
def MatanArrive(pAction):
#	kDebugObj.Print("Creating first group of Cardies")

	if g_PlayerDetected != 1:

		global g_PlayerDetected
		g_PlayerDetected = 1

		# Send an ET_PLAYER_DETECTED event.
		pDetectedEvent = App.TGEvent_Create()
		pDetectedEvent.SetEventType( ET_PLAYER_DETECTED )
		pDetectedEvent.SetDestination( MissionLib.GetMission() )
		App.g_kEventManager.AddEvent( pDetectedEvent )

	# Add our Objectives
	MissionLib.RemoveGoal("E5LocateDeviceGoal")
	MissionLib.RemoveGoal("E5AvoidDetectionGoal")
	MissionLib.RemoveGoal("E5SearchAliothGoal")

	pSet = App.g_kSetManager.GetSet("Alioth6")

	pMatanSet = App.g_kSetManager.GetSet("MatanSet")
	pMatan = App.CharacterClass_GetObject (pMatanSet, "Matan")

	pMatanShip = loadspacehelper.CreateShip( "Keldon", pSet, "Matan's Keldon", "Matan Start" )
	pKeldon1 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon1", "Keldon1 Start" )
	pKeldon2 = loadspacehelper.CreateShip( "Keldon", pSet, "Keldon2", "Keldon2 Start" )

	pGalor1 = loadspacehelper.CreateShip( "Galor", pSet, "Galor1", "Galor1 Start" )
	pGalor2 = loadspacehelper.CreateShip( "Galor", pSet, "Galor2", "Galor2 Start" )
	pGalor3 = loadspacehelper.CreateShip( "Galor", pSet, "Galor3", "Galor3 Start" )
	pGalor4 = loadspacehelper.CreateShip( "Galor", pSet, "Galor4", "Galor4 Start" )
	pGalor5 = loadspacehelper.CreateShip( "Galor", pSet, "Galor5", "Galor5 Start" )

	pMatanShip.SetInvincible(1)
	MissionLib.MakeEnginesInvincible(pMatanShip)

	import MatanAI
	pMatanShip.SetAI(MatanAI.CreateAI(pMatanShip))

	import EnemyAI
	pKeldon1.SetAI(EnemyAI.CreateAI(pKeldon1))
	pKeldon2.SetAI(EnemyAI.CreateAI(pKeldon2))

	pGalor1.SetAI(EnemyAI.CreateAI(pGalor1))
	pGalor2.SetAI(EnemyAI.CreateAI(pGalor2))
	pGalor3.SetAI(EnemyAI.CreateAI(pGalor3))
	pGalor4.SetAI(EnemyAI.CreateAI(pGalor4))
	pGalor5.SetAI(EnemyAI.CreateAI(pGalor5))



	#############################
	# Matan's gloating sequence #
	#############################
	pSequence = App.TGSequence_Create()

	pStartMusic = App.TGScriptAction_Create(__name__, "StartMusic2")	
	pSequence.AppendAction(pStartMusic)

	pAction1 = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E5M4L042", "Captain", 1, pMissionDatabase)
	pAction2 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MatanSet", "Matan")
	pAction3 = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E5M4Matan1", None, 0, pMissionDatabase)
	pAction3a = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E5M4Matan2", None, 0, pMissionDatabase)
	pAction4 = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pCineEnd = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pEndCam  = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pAction5 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4L034", "E", 1, pMissionDatabase)
	pAction6 = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E5M4L032", "Captain", 1, pMissionDatabase)
	pAction7 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4Data1", "None", 1, pMissionDatabase)
	pAction8 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4Data2", "None", 1, pMissionDatabase)
	pAction9 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4Data3", "None", 1, pMissionDatabase)
	pAction10 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4Data4", "None", 1, pMissionDatabase)

	if (iSatsDestroyed != 2):
		pAction11 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4Data5", "None", 1, pMissionDatabase)
		pAction12 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4Data6", "None", 1, pMissionDatabase)
		pAction13 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4Data7", "None", 1, pMissionDatabase)
		pAddGoal  = App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E5DestroySatellitesGoal")

	pAction14 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4Data8", "None", 1, pMissionDatabase)
	pAction15 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E5M4Data9", "None", 1, pMissionDatabase)
	pSetFlag  = App.TGScriptAction_Create(__name__, "SetMatanFlag")
	pEndMusic = App.TGScriptAction_Create(__name__, "EndMusic")	
	pAction16 = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E5M4L044", "Captain", 1, pMissionDatabase)
	pAction17 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4L045", "S", 1, pMissionDatabase)
	pAction18 = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E5M4L035", "Captain", 1, pMissionDatabase)
	pAction19 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E5M4SaffiComm2", None, 0, pMissionDatabase)

	pSequence.AddAction(pAction1)
	pSequence.AddAction(pAction2, pAction1)
	pSequence.AddAction(pAction3, pAction2, 1)
	pSequence.AddAction(pAction3a, pAction3)
	pSequence.AddAction(pAction4, pAction3a, 1)
	pSequence.AddAction(pAction5, pAction4)
	pSequence.AddAction(pCineEnd, pAction4)	
	pSequence.AddAction(pEndCam, pCineEnd)	
	pSequence.AddAction(pAction6, pAction5)
	pSequence.AddAction(pAction7, pAction6)
	pSequence.AddAction(pAction8, pAction7)
	pSequence.AddAction(pAction9, pAction8)
	pSequence.AddAction(pAction10, pAction9)

	if (iSatsDestroyed != 2):
		pSequence.AddAction(pAction11, pAction10)
		pSequence.AddAction(pAction12, pAction11)
		pSequence.AddAction(pAction13, pAction12)
		pSequence.AddAction(pAddGoal, pAction13)
		pSequence.AddAction(pAction14, pAction13)
		pSequence.AddAction(pAction15, pAction14)
		pSequence.AddAction(pSetFlag, pAction15)
		pSequence.AddAction(pEndMusic, pSetFlag)			
		pSequence.AddAction(pAction16, pAction15)
		pSequence.AddAction(pAction17, pAction16)
	#	pSequence.AddAction(pAction18, pAction17)

		# Set the Communicate Counters
		global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm
		FelixComm = 3
		SaffiComm = 1
		BrexComm = 3
		KiskaComm = 0
		MiguelComm = 0

	else:
		pSequence.AddAction(pAction14, pAction10)
		pSequence.AddAction(pAction15, pAction14)
		pSequence.AddAction(pSetFlag, pAction15)
		pSequence.AddAction(pEndMusic, pSetFlag)
		pSequence.AddAction(pAction16, pAction15)
		pSequence.AddAction(pAction17, pAction16)
		pSequence.AddAction(pAction18, pAction17)
		pSequence.AddAction(pAction19, pAction18)

		global g_MissionWin
		g_MissionWin = 1

		import Systems.Starbase12.Starbase
		pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
		pSBMenu.SetEpisodeName("Maelstrom.Episode6.Episode6")

		# Set the Communicate Counters
		global KiskaComm, FelixComm, MiguelComm, SaffiComm, BrexComm
		FelixComm = 4
		SaffiComm = 2
		BrexComm = 3
		KiskaComm = 0
		MiguelComm = 0

	pSequence.Play()

	return 0

def SetMatanFlag(pAction):
	global MatanFlag
	MatanFlag = HAS_ARRIVED
	return 0

def StartMusic(pAction):

	import DynamicMusic
	DynamicMusic.OverrideMusic("Nebula Ambient")
	return 0

def StartMusic2(pAction):

	import DynamicMusic
	DynamicMusic.OverrideMusic("Nebula Combat")
	return 0

def EndMusic(pAction):

	import DynamicMusic
	DynamicMusic.StopOverridingMusic()
	return 0

###############################################################################
#
# MissionWin()  - Function that handles the win conditions of the mission 
#
###############################################################################
def MissionWin():
#	kDebugObj.Print("Mission Successful")
	# Set up Win dialogue Sequence
	pLBridgeSet =App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pLiu.SetHidden(0)

	pSequence = App.TGSequence_Create()

	pAction =  App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet2", None, 0, pGeneralDatabase)
	pSequence.AppendAction(pAction, 2)
	pAction =  App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet8", None, 0, pGeneralDatabase)
	pSequence.AppendAction(pAction, 3)
	pAction1 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pAction2 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4Debrief1", None, 0, pMissionDatabase)
	pAction3 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4Debrief2", None, 0, pMissionDatabase)
	pAction4 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4Debrief3", None, 0, pMissionDatabase)
	pAction5 = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pAction6 = App.TGScriptAction_Create(__name__, "LoadNext")

	pSequence.AddAction(pAction1, pAction, 1)
	pSequence.AddAction(pAction2, pAction1)
	pSequence.AddAction(pAction3, pAction2)
	pSequence.AddAction(pAction4, pAction3)
	pSequence.AddAction(pAction5, pAction4)
#	pSequence.AddAction(pAction6, pAction5, 3)

	return pSequence


###############################################################################
#
# MissionLoss()
#
###############################################################################
def MissionLoss():

#	kDebugObj.Print("*************** Mission Failed ***************")

	# Set up Loss dialogue Sequence
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pLiu.SetHidden(0)

	pSequence = App.TGSequence_Create()

	pAction1 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSequence.AppendAction(pAction1, 5)
	pAction2 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4Fail1", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction2)
	pAction3 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4Fail2", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction3)

	if ((iSatsDestroyed != 2) and (g_DataOnSurface)):
		pAction4 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4FailSats1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction4)
		pAction5 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4FailSats2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction5)

	pAction6 = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E5M4Fail3", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction6)


	MissionLib.GameOver(None, pSequence)

###############################################################################
#
# LoadNext(pAction)
#
# Loads Next Episode
#
###############################################################################
def LoadNext(pAction):

	#End the episode
	App.Game_GetCurrentGame().LoadEpisode("Maelstrom.Episode6.Episode6")

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


###############################################################################
#
# Terminate()
#
# Unload our mission database
#
###############################################################################
def Terminate(pMission):
#	kDebugObj.Print ("Terminating Episode 5, Mission 4.\n")

	MissionLib.ShutdownFriendlyFire()
	MissionLib.DeleteAllGoals()

	###################################
	# Remove Character Event Handlers #
	###################################
	pSaffi.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMiguel.GetMenu().RemoveHandlerForInstance(App.ET_SCAN, __name__+".ScanHandler")
	pMiguel.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pFelix.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pKiska.GetMenu().RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	pKiska.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = pKiska.GetMenu()
	pSetCourse = pMenu.GetSubmenuW(pDatabase.GetString("Set Course"))
	pAlioth = pSetCourse.GetSubmenu("Alioth")
	pSetCourse.DeleteChild(pAlioth)


	pBrex.GetMenu().RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = pData.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pBridge = App.g_kSetManager.GetSet("bridge")
	pBridge.DeleteObjectFromSet("Data")

	import Bridge.BridgeUtils
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpCheck")
	pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpingOut")

	pPlayer = MissionLib.GetPlayer()

	if (pPlayer):
		pPlayer.RemoveHandlerForInstance(App.ET_SUBSYSTEM_POWER_CHANGED, __name__+".PowerCheck")

	if(pGeneralDatabase):
		App.g_kLocalizationManager.Unload(pGeneralDatabase)

	if(pDatabase):
		App.g_kLocalizationManager.Unload(pDatabase)

	if (pE5M2Database):
		App.g_kLocalizationManager.Unload(pE5M2Database)

	# Clear globals that may no longer be valid, in case
	# save & load tries to save us.
	global pSaffi, pMiguel, pFelix, pKiska, pBrex, pData
	pSaffi = None
	pKiska = None
	pFelix = None
	pBrex = None
	pMiguel = None
	pData = None

