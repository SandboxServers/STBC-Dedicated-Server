###############################################################################
#	Filename:	E7M6.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 7 Mission 6
#	
#	Created:	08/30/00 -	David Litwin (added header)
#				01/16/02 - 	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Maelstrom
import LoadBridge
import Bridge.BridgeUtils
import Bridge.ScienceCharacterHandlers
import Bridge.Characters.Data
import Systems.Starbase12.Starbase
import Systems.Starbase12.Starbase12
import Systems.Alioth.Alioth
import Systems.Alioth.Alioth6
import Systems.Alioth.Alioth8
import Maelstrom.Episode7.E7M6.E7M6_P
import Maelstrom.Episode7.E7M6.Alioth8_P
import Maelstrom.Episode7.E7M6.Starbase12_P
import EBridge_P
import AlliedAI
import AkiraAI 
import BaseAI
import EnterpriseAI
import EnemyAI
import EnemyFollowAI
import WarpAwayAI
import FreighterAI

#
# Global variables
#
TRUE				= 1
FALSE				= 0
bDebugPrint			= 0

pMissionDatabase	= None
pGeneralDatabase 	= None
pMenuDatabase		= None

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

bMissionTerminate 	= FALSE
HASNT_ARRIVED		= 0
HAS_ARRIVED			= 1
Alioth6Flag			= HASNT_ARRIVED
Alioth8Flag			= HASNT_ARRIVED
fStartTime			= 0

kStartupSoundID		= App.PSID_INVALID
g_bInOrbit			= FALSE
pFriendlies			= 0
pEnemies 			= 0
pAlioth8Enemies		= 0
pHostiles			= 0
pGroup1ObjGroup		= 0

g_iGeronimoHit		= 0
g_iNumAttackers		= 0
g_iMaxTotalShips	= 50
g_iMaxEnemiesInSet	= 5
g_iGroup1Remaining	= 4
g_bStationDestroyed	= FALSE
g_bEnterpriseArrived = FALSE
g_bTryingData		= FALSE
g_bDataCanRespond	= FALSE
g_bDataContacted	= FALSE
g_bDataRescued		= FALSE
g_bAliothFollow		= FALSE
g_bAlioth6Follow	= FALSE
g_bHailedMacCray	= FALSE
g_bHailedKlingon	= FALSE
g_bHailedRomulan	= FALSE
g_bDataCommunicate	= FALSE
g_bDisruptorsGone	= FALSE
g_bFollowDialogue	= FALSE
g_bStopFollowHandle	= TRUE
g_bGeronimoCritical	= FALSE
g_bGeronimoWait 	= FALSE

g_bAllowDamage 		= 0		#Allows the damage dialogue to be spoken and not overlap

g_pEntSequence		= None

g_bGraffWarned 		= FALSE
g_bPicardWarned 	= FALSE
g_bVorchaWarned 	= FALSE
g_bWarbirdWarned 	= FALSE

g_bBriefingPlayed 	= FALSE

# Timer delays
EnterpriseWarpInDelay 	= 240
NextWaveDelay			= 90

#
# Event types
#
ET_BRIEFING_TIMER_EVENT		= App.Mission_GetNextEventType()
ET_ENTERPRISE_TIMER_EVENT 	= App.Mission_GetNextEventType()
ET_WAVE_ARRIVE_TIMER_EVENT 	= App.Mission_GetNextEventType()
ET_BEAM_UP_BUTTON_CLICKED	= App.Mission_GetNextEventType()
ET_RESET_GERONIMO			= App.Mission_GetNextEventType()


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
	loadspacehelper.PreloadShip("Vorcha", 1)
	loadspacehelper.PreloadShip("Warbird", 1)
	loadspacehelper.PreloadShip("Galor", 21)
	loadspacehelper.PreloadShip("Keldon", 16)
	if Maelstrom.Episode7.Episode7.iNumFreightersEscaped > 0:
		loadspacehelper.PreloadShip("CardFreighter", Maelstrom.Episode7.Episode7.iNumFreightersEscaped)


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
#	print ("Initializing Episode 7, Mission 6.\n")

	# Check and see if we have a player, if we don't
	# we aren't linking and will have to call the initial
	# briefing "by hand" and the end of Initialize
	bHavePlayer = 0
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		bHavePlayer = 1

	# For use by the Episode 7 Contact Starfleet handler
	Maelstrom.Episode7.Episode7.bE7M3_M4_M5 = 0

	# Debug print flag, used to turn on/off text to the debug window.
	global bDebugPrint
	bDebugPrint = FALSE
	
	global pMissionDatabase, pGeneralDatabase, pMenuDatabase
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 7/E7M6.tgl")
	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Specify (and load if necessary) our bridge
	LoadBridge.Load("SovereignBridge")

	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	# Create characters and their sets
#	DebugPrint("Creating characters and their sets")

	MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet", 0, 0, 5)

	MissionLib.SetupBridgeSet("FedOutpostSet", "data/Models/Sets/FedOutpost/fedoutpost.nif", -30, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Graff", "FedOutpostSet")

	MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif", -40, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.MacCray", "EBridgeSet")
	pPicard = MissionLib.SetupCharacter("Bridge.Characters.Picard", "EBridgeSet")
	pPicard.SetLocation("SovereignSeated")

	MissionLib.SetupBridgeSet("ShuttleSet", "data/Models/Sets/Shuttle/Shuttle.nif")
	pData = MissionLib.SetupCharacter("Bridge.Characters.Data", "ShuttleSet")
	# Move Data to Shuttle Seated Placement
	pData.SetLocation("ShuttleSeated")

	# Create space sets and loads placements.
	CreateSpaceSets()
	
	CreateMenus()

	# Create ships for mission and give them group affiliations.
	CreateShips(pMission)

	MissionLib.AddGoal("E7DestroyCardassianStationGoal")

	# Setup more mission-specific events.
	SetupEventHandlers(pMission)

	# If the player was created from scratch, call our initial briefing
	if (bHavePlayer == 0):
		Briefing()

	MissionLib.SaveGame("E7M4-")

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
#	CreateSpaceSets()
#
#	Create space sets used in this mission. Load placements into sets.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateSpaceSets():
	# Create and load the Space Sets we'll need for this mission
	Systems.Starbase12.Starbase12.Initialize()
	pSB12Set = Systems.Starbase12.Starbase12.GetSet()
	
	Systems.Alioth.Alioth6.Initialize()
	pAlioth6Set = Systems.Alioth.Alioth6.GetSet()

	Systems.Alioth.Alioth8.Initialize()
	pAlioth8Set = Systems.Alioth.Alioth8.GetSet()

	# Load our placements into this set
	Maelstrom.Episode7.E7M6.E7M6_P.LoadPlacements(pAlioth6Set.GetName())
	Maelstrom.Episode7.E7M6.Alioth8_P.LoadPlacements(pAlioth8Set.GetName())
	Maelstrom.Episode7.E7M6.Starbase12_P.LoadPlacements(pSB12Set.GetName())
	
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	EBridge_P.LoadPlacements(pBridgeSet.GetName())
	
	# Activate the proximity manager for our set.	
	pAlioth6Set.SetProximityManagerActive(1)


################################################################################
#	CreateShips()
#
#	Create ships used in this mission and set their group affiliations.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateShips(pMission):
	pSB12Set = Systems.Starbase12.Starbase12.GetSet()
	pAlioth6Set = Systems.Alioth.Alioth6.GetSet()

	# Create friendly ships.
	MissionLib.CreatePlayerShip("Sovereign", pSB12Set, "player", "Player Start")
	pStarbase = loadspacehelper.CreateShip("FedStarbase", pSB12Set, "Starbase 12", "Starbase12 Location")

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	# Create allied ships.
	pKlingon1 = loadspacehelper.CreateShip("Vorcha", pSB12Set, "HoH'egh", "Klingon 1 Start")
	pRomulan1 = loadspacehelper.CreateShip("Warbird", pSB12Set, "Chilvas", "Romulan 1 Start")

	# Create enemy ships in Alioth 6.										
	pDS9 = loadspacehelper.CreateShip("CardStarbase", pAlioth6Set, "Litvok Nor", "DS9 Start")
	loadspacehelper.CreateShip("Galor", pAlioth6Set, "Galor5", "Galor 1 Start")
	loadspacehelper.CreateShip("Galor", pAlioth6Set, "Galor6", "Galor 2 Start")
	loadspacehelper.CreateShip("Keldon", pAlioth6Set, "Keldon1", "Keldon 1 Start")

	# Add Instance Handler to detect if Base's are disabled
	pDS9.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DISABLED, __name__ + ".DisableSystemHandler")
										
	# Setup Affiliations
	global pFriendlies, pEnemies, pAlioth8Enemies, pHostiles, pGroup1ObjGroup

	pFriendlies		= pMission.GetFriendlyGroup()
	pEnemies 		= pMission.GetEnemyGroup()
	pAlioth8Enemies	= App.ObjectGroup()
	pHostiles		= App.ObjectGroup()
	pGroup1ObjGroup	= App.ObjectGroup()

	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("USS Enterprise")
	pFriendlies.AddName("HoH'egh")
	pFriendlies.AddName("Chilvas")
	pFriendlies.AddName("USS Geronimo")

	pEnemies.AddName("Litvok Nor")
	pEnemies.AddName("Galor5")
	pEnemies.AddName("Galor6")
	pEnemies.AddName("Keldon1")
	pEnemies.AddName("Galor1")
	pEnemies.AddName("Galor2")
	pEnemies.AddName("Galor3")
	pEnemies.AddName("Galor4")
	pEnemies.AddName("Freighter1")
	pEnemies.AddName("Freighter2")
	pEnemies.AddName("Freighter3")
	pEnemies.AddName("Freighter4")
	pAlioth8Enemies.AddName("Galor1")
	pAlioth8Enemies.AddName("Galor2")
	pAlioth8Enemies.AddName("Galor3")
	pAlioth8Enemies.AddName("Galor4")
	pHostiles.AddName("Galor5")
	pHostiles.AddName("Galor6")
	pHostiles.AddName("Keldon1")
	pHostiles.AddName("Galor1")
	pHostiles.AddName("Galor2")
	pHostiles.AddName("Galor3")
	pHostiles.AddName("Galor4")
	pGroup1ObjGroup.AddName("Galor1")
	pGroup1ObjGroup.AddName("Galor2")
	pGroup1ObjGroup.AddName("Galor3")
	pGroup1ObjGroup.AddName("Galor4")
										
	# Set their AI.
	SetAI(None, pKlingon1, AlliedAI)
	SetAI(None, pRomulan1, AlliedAI)

	# If Geronimo is still alive and rescued, create it.
	if (Maelstrom.Maelstrom.bGeronimoAlive):
#		DebugPrint("Geronimo is alive and rescued, so have her join the player")

		pGeronimo = loadspacehelper.CreateShip( "Geronimo", pSB12Set, "USS Geronimo", "Enterprise Start" )
		pGeronimo.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")

		# Give Geronimo AI
		pGeronimo.SetAI(AkiraAI.CreateAI(pGeronimo))

	pDS9.SetAI(BaseAI.CreateAI(pDS9))

	# Make allies commandable
	MissionLib.AddCommandableShip("USS Geronimo")
	MissionLib.AddCommandableShip("HoH'egh")
	MissionLib.AddCommandableShip("Chilvas")


################################################################################
#	CreateRandomShip(pcShipName)
#
#	Create random enemy ship, either Keldon or Galor type.
#
#	Args:	pcShipName, name of ship to create
#
#	Return:	None
################################################################################
def CreateRandomShip(pcShipName):		
	pAlioth6Set = Systems.Alioth.Alioth6.GetSet()

	pShip = None

	iShipNum = g_iNumAttackers

	while iShipNum > 12:
		iShipNum = iShipNum - 12

	if(App.g_kSystemWrapper.GetRandomNumber(2)):
		sShipType = "Galor"
	else:
		sShipType = "Keldon"

	pShip = loadspacehelper.CreateShip(sShipType, pAlioth6Set, pcShipName, "Random Start " + str(iShipNum))
#	DebugPrint("Creating random " + sShipType + ", " + pcShipName)

	# Set AI
	pShip.SetAI(EnemyAI.CreateAI(pShip))

	# Add ship to enemy group.
	pEnemies.AddName(pcShipName)
	pHostiles.AddName(pcShipName)

	
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
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
	pSBMenu.SetMissionName("Maelstrom.Episode7.E7M6.E7M6")

		
################################################################################
#	SetupEventHandlers()
#
#	Set up any event handlers for this mission.
#
#	Args:	None
#
#	Return:	None
################################################################################
def SetupEventHandlers(pMission):

	# Exit warp event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_WARP, pMission, __name__ + ".ExitWarp")
	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission,	__name__ +".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ +	".ObjectDestroyed")

	# Instance handler for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")

	# Contact Starfleet event
	g_pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")

	# Instance handler for Miguel's Scan Area button
	g_pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Instance handler for Helm Hail button.
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	# Setup a handler to call the InOrbitChanged function when the
	# player enters/exits orbit of "Alioth6"
	pCondition = App.ConditionScript_Create("Conditions.ConditionPlayerOrbitting", "ConditionPlayerOrbitting", "Alioth 6")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "InOrbitChanged", pCondition)

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


################################################################################
#	ObjectDestroyed(pObject, pEvent)
#
#	Object destroyed set event handler.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def ObjectDestroyed(TGObject, pEvent):
	assert pEvent
	if(pEvent is None):
		return
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip is None):
		return
		
	global g_iGroup1Remaining
	pcShipName = pShip.GetName()
	if(pcShipName):
		# Check if first group of ships destroyed.
		if(pGroup1ObjGroup.IsNameInGroup(pcShipName)):
			g_iGroup1Remaining = g_iGroup1Remaining - 1

			pGame = App.Game_GetCurrentGame()
			pSet = pGame.GetPlayerSet()

			if(not g_iGroup1Remaining) and not (pSet.GetName() == "Alioth6"):
				PlayGroup1Dialogue()

		elif(pcShipName == "USS Geronimo"):
#			DebugPrint ("Geronimo destroyed dialogue")
			Maelstrom.Maelstrom.bGeronimoAlive = FALSE

			g_pMiguel.SayLine(pMissionDatabase, "E7M6GeronimoDestroyed", "Captain", 1)

		elif(pcShipName == "HoH'egh"):
#			DebugPrint ("Vorcha destroyed dialogue")

			g_pMiguel.SayLine(pMissionDatabase, "E7M6VorchaDestroyed", "Captain", 1)

		elif(pcShipName == "Chilvas"):
#			DebugPrint ("Warbird destroyed dialogue")

			g_pMiguel.SayLine(pMissionDatabase, "E7M6WarbirdDestroyed", "Captain", 1)

		elif(pcShipName == "USS Enterprise"):
			pE7M1Database = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 7/E7M1.tgl")

			MissionLib.DeleteGoal("E7EnterpriseSurviveGoal")

			pSequence = App.TGSequence_Create()
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseDestroyed", "Captain", 1, pE7M1Database)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "GameOver")
			pSequence.AppendAction(pAction)

			pSequence.Play()

			App.g_kLocalizationManager.Unload(pE7M1Database)

		# Play voice line if station is destroyed.
		elif(pcShipName == "Litvok Nor"):
			StationDestroyed()

	TGObject.CallNextHandler(pEvent)


################################################################################
#	InOrbitChanged(bNewState)
#
#	Called when the player goes into/out of orbit around Alioth 6 planet.
#
#	Args:	bNewState - new state of condition
#
#	Return:	None
################################################################################
def InOrbitChanged(bNewState):
#	print __name__ + ": Player in orbit changed to %d" % bNewState
	global g_bInOrbit
	
	# Set our flag.
	g_bInOrbit = bNewState

	pPlayer = MissionLib.GetPlayer()

	if pPlayer == None:
		return

	pSet = App.g_kSetManager.GetSet("Alioth6")
	pPlanet = App.ObjectClass_GetObject(pSet, "Alioth 6")
	# Get the distance between the player and the planet
	vDiff = pPlayer.GetWorldLocation()
	vDiff.Subtract(pPlanet.GetWorldLocation())
	fDistance = vDiff.Length()

#	DebugPrint('Distance from Planet: ' + str(fDistance) + 'km')
				
	if (g_bInOrbit or (fDistance <= 170)) and MissionLib.IsBoosted(pPlayer.GetSensorSubsystem()) and g_bDataContacted:
		BeamDataAboard(None)


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
	if (g_bAllowDamage == 1):
		return
	global g_bAllowDamage
	g_bAllowDamage = 1

	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		return

	pPlayerSetName = pPlayer.GetContainingSet()

	pSequence = App.TGSequence_Create()

	if (sShipName == "USS Geronimo"):
		# Make sure player and ship are in the same set
		pGame = App.Game_GetCurrentGame()
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
		if (pPlayerSetName != pGeronimoSetName):
			pSequence.Completed()
			return

		if (sSystemName == "Shields"):
			if (iPercentageLeft == 0):
#				DebugPrint("Geronimo shields are gone!")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6GeronimoShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif (iPercentageLeft == 50):
#				DebugPrint("Geronimo shields down to 50 percent.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6GeronimoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 25):
#				DebugPrint("Geronimo hull down to 25 percent.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6GeronimoHull25", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

				global g_bGeronimoCritical
				g_bGeronimoCritical = TRUE

			elif (iPercentageLeft == 50):
#				DebugPrint("Geronimo hull down to 50 percent.")

				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6MacCrayHailing", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray", 1)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M6GeronimoHull50", None, 0, pMissionDatabase)	
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

				global g_bGeronimoCritical
				g_bGeronimoCritical = TRUE

	elif (sShipName == "USS Enterprise"):
		# Make sure player and ship are in the same set
		pEnterprise = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Enterprise")
		pEnterpriseSetName = pEnterprise.GetContainingSet().GetName()
		if (pPlayerSetName == pEnterpriseSetName):
			pE7M1Database = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 7/E7M1.tgl")

			if (sSystemName == "Shields"):
				if (iPercentageLeft == 0):
#					DebugPrint("Enterprise shields are gone!")

					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseShields0", "Captain", 0, pE7M1Database)
					pSequence.AppendAction(pAction)

				elif (iPercentageLeft == 50):
#					DebugPrint("Enterprise shields down to 50 percent")
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseShields50", "Captain", 1, pE7M1Database)
					pSequence.AppendAction(pAction)
	
			elif (sSystemName == "HullPower"):
				if (iPercentageLeft == 25):
#					DebugPrint("Enterprise hull down to 25 percent")
	
					pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
					pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M1PicardHail2", None, 0, pE7M1Database)
					pSequence.AppendAction(pAction)
					pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard", 1)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseHull25", None, 0, pE7M1Database)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
					pSequence.AppendAction(pAction)

					global bEnterpriseCritical
					bEnterpriseCritical = TRUE

				elif (iPercentageLeft == 50):
#					DebugPrint("Enterprise hull down to 50 percent")
	
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M1EnterpriseHull50", "Captain", 0, pE7M1Database)
					pSequence.AppendAction(pAction)

					global bEnterpriseCritical
					bEnterpriseCritical = TRUE

			App.g_kLocalizationManager.Unload(pE7M1Database)

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
	global g_bAllowDamage
	g_bAllowDamage = 0

	return 0


################################################################################
##	ScanHandler()
##
##	Handler called when one of Miguel's scan buttons is hit.
##
##	Args:	pObject	- The TGObject object.
##			pEvent	- The event that was sent.
##
##	Return:	None
################################################################################
def ScanHandler(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer == None:
		return
	pSet = pPlayer.GetContainingSet()

	iScanType = pEvent.GetInt()

	# If we're scanning the area in Alioth, do the line from Miguel.
	if (iScanType == App.CharacterClass.EST_SCAN_AREA):
		if (pSet.GetName()[:len("Alioth")] == "Alioth"):
			pSequence = Bridge.ScienceCharacterHandlers.GetScanSequence()		
			if (pSequence == None):
				# Sensors must be off, do nothing.
				return

			if not g_bStationDestroyed:
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateMiguel1", "Captain", 1, pMissionDatabase)

			else:
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateMiguel2", "Captain", 1, pMissionDatabase)

			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
			pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)
			
			return

	#All done, call the next handler for this event.
	pObject.CallNextHandler(pEvent)


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

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	if not pData == None:
		pDataMenu = pData.GetMenu()

	pAction = 0

	if pMenu.GetObjID() == g_pSaffiMenu.GetObjID():
#		DebugPrint("Communicating with Saffi")

		if not (pSet.GetName() == "Alioth6"):
#			DebugPrint("Time is wasting.  Get to Data")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateSaffi1", None, 0, pMissionDatabase)

		elif not g_bStationDestroyed:
#			DebugPrint("We should destroy the Base")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateSaffi2", None, 0, pMissionDatabase)

		elif not g_bDataRescued:
#			DebugPrint("Hail the planet")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateSaffi3", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Let's return to Starbase 12")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateSaffi4", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pKiskaMenu.GetObjID():
#		DebugPrint("Communicating with Kiska")

		if pSet.GetName() == "Alioth6":
			if not g_bStationDestroyed:
				if not g_bDisruptorsGone:
#					DebugPrint("Keep up our speed to dodge the disruptor barrage")
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateKiska1", None, 0, pMissionDatabase)
	
				else:
#					DebugPrint("The Base is still jamming our communications with the planet")
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateKiska2", None, 0, pMissionDatabase)
	
			else:
				if not g_bDataRescued:
					pPlanet = App.ObjectClass_GetObject(pSet, "Alioth 6")
					# Get the distance between the player and the planet
					vDiff = pPlayer.GetWorldLocation()
					vDiff.Subtract(pPlanet.GetWorldLocation())
					fDistance = vDiff.Length()
	
#					DebugPrint('Distance from Planet: ' + str(fDistance) + 'km')
				
					# Check if you are within 30km of the Planet and if power is diverted to sensors
					if (pPlayer.GetSensorSubsystem().GetNormalPowerPercentage() <= 1):
#						DebugPrint("We need to boost power to Sensors")
						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateKiska3", None, 0, pMissionDatabase)
	
					elif (fDistance > 170) and not g_bInOrbit:
#						DebugPrint("We need to get closer to the planet")
						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateKiska4", None, 0, pMissionDatabase)
	
					else:
#						DebugPrint("Ready to hail the planet")
						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateKiska5", None, 0, pMissionDatabase)

				else:
#					DebugPrint("Let's return to Starbase 12")
					pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateKiska6", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pFelixMenu.GetObjID():
#		DebugPrint("Communicating with Felix")

		if (pSet.GetName() == "Alioth6"):
			if not g_bStationDestroyed:
				if not g_bDisruptorsGone:
#					DebugPrint("Keep up our distance from the disruptor barrage")
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateFelix1", None, 0, pMissionDatabase)
	
				else:
#					DebugPrint("Let's Ace the Base!")
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateFelix2", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pMiguelMenu.GetObjID():
#		DebugPrint("Communicating with Miguel")

		if Maelstrom.Maelstrom.bGeronimoAlive and g_bGeronimoCritical and not (pSet.GetName() == "Starbase12"):
#			DebugPrint("The Geronimo is critical")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateMiguel3", None, 0, pMissionDatabase)

		elif (pSet.GetName() == "Alioth6"):
			if not g_bStationDestroyed:
#				DebugPrint("More waves of Cardassians coming")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateMiguel1", None, 0, pMissionDatabase)

			else:
#				DebugPrint("Cardassians retreating")
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateMiguel2", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pBrexMenu.GetObjID():
#		DebugPrint("Communicating with Brex")

		fFrontShields = pPlayer.GetShields().GetSingleShieldPercentage(App.ShieldClass.FRONT_SHIELDS)
		fRearShields = pPlayer.GetShields().GetSingleShieldPercentage(App.ShieldClass.REAR_SHIELDS)

		fHull = pPlayer.GetHull().GetConditionPercentage()
		fPower = pPlayer.GetPowerSubsystem().GetConditionPercentage()

		if (fFrontShields < .5) and (pPlayer.GetAlertLevel() == pPlayer.RED_ALERT):
#			DebugPrint("Front shields down to 50%")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateBrex1", None, 0, pMissionDatabase)
		
		elif (fRearShields < .5) and (pPlayer.GetAlertLevel() == pPlayer.RED_ALERT):
#			DebugPrint("Rear shields down to 50%")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateBrex2", None, 0, pMissionDatabase)

		elif (fHull < .4) or (fPower < .4):
#			DebugPrint("The Sovereign is critically damaged")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateBrex3", None, 0, pMissionDatabase)

	elif not pData == None:
#		DebugPrint("Communicating with Data")

		if (g_bDataCommunicate == FALSE):
			global g_bDataCommunicate
			g_bDataCommunicate = TRUE

#			DebugPrint("Thanks for rescuing me")
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateData1", None, 0, pMissionDatabase)

		else:
#			DebugPrint("Let's return to Starbase 12")
			pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateData2", None, 0, pMissionDatabase)

	if pAction:
		pAction.Play()

	else:
#		DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)


#
# Warphandler()
#
def WarpHandler(pObject, pEvent):
#	DebugPrint("Handling Warp")

	pWarpButton = App.STWarpButton_Cast(pEvent.GetDestination())
	pcDest	 	= pWarpButton.GetDestination()

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	if (pPlayerSetName == "Alioth6") and g_bStationDestroyed and not g_bDataRescued:
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pPicard = App.CharacterClass_GetObject (pEBridgeSet, "Picard")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L023", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6PicardWarpStop", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)
		
		return

	elif g_bDataRescued and (pcDest == "Systems.Starbase12.Starbase12"):
		# Load lighting for warp set
		# Ensure that the warp set is created.
		App.WarpSequence_GetWarpSet()
		import Warp_P
		Warp_P.LoadPlacements("warp")

		# Setup load for Episode 8
		pWarpButton.SetDestination("Systems.Starbase12.Starbase12",
								   "Maelstrom.Episode8.E8M1.E8M1", 
								   "Player Start", "Maelstrom.Episode8.Episode8")

		# Play the Episode 8 cutscene in the warp set
		pSequence = Episode8Cutscene()
		pWarpButton.AddActionBeforeDuringWarp(pSequence)

	pObject.CallNextHandler(pEvent)


#
#	DisableSystemHandler()
#
def DisableSystemHandler(pObject, pEvent):

	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if not pShip:
		return

	# Make sure Event Source is valid, so the game won't crash when I do a GetObjID
	if not (pEvent.GetSource() == None): 
		# Make sure the subsystem is valid, so the game won't crash when I do a GetObjID
		if not (pShip.GetPulseWeaponSystem() == None):
			if (pEvent.GetSource().GetObjID() == pShip.GetPulseWeaponSystem().GetObjID()):
#				DebugPrint ("Station's Disruptor System Disabled.")
				global g_bDisruptorsGone
				g_bDisruptorsGone = TRUE


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
#	DebugPrint("Contacting Starfleet")
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	pSequence = MissionLib.ContactStarfleet()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if not g_bStationDestroyed:
#		DebugPrint("Destroy the Base")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M6HailLiu1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
	
	elif not g_bDataRescued:
#		DebugPrint("Rescue Data")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M6HailLiu1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	else:
#		DebugPrint("Return to Starbase 12")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M6L064c", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


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
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6StarbaseHailing", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M6HitStarbase", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "USS Geronimo") and (g_bGeronimoWait == FALSE) and (g_iGeronimoHit < 2):
#		DebugPrint("MacCray warns you about hitting the Geronimo")

		global g_iGeronimoHit, g_bGeronimoWait
		g_iGeronimoHit = g_iGeronimoHit + 1
		g_bGeronimoWait = TRUE

		# Create a Timer that resets Geronimo Friendly Fire handler
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_RESET_GERONIMO, __name__ + ".ResetGeronimoHit", fStartTime + 20, 0, 0)

		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		if (g_iGeronimoHit == 1):
			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)
		
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6MacCrayHailing", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction, 3)
		
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)

			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M6HitGeronimo1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

			return

		elif (g_iGeronimoHit == 2) and (pSet.GetName() == "Alioth6") and (g_bStationDestroyed == FALSE):
			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)
		
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6MacCrayHailing", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction, 3)

			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M6HitGeronimo2", None, 0, pMissionDatabase)
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
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L023", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6HitPicard", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	elif (sShipName == "HoH'egh") and (g_bVorchaWarned == FALSE):
#		DebugPrint("Kiska warns you about hitting the HoH'egh")

		global g_bVorchaWarned
		g_bVorchaWarned = TRUE

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6HitVorcha", "Captain", 1, pMissionDatabase)
		pAction.Play()

		return

	elif (sShipName == "Chilvas") and (g_bWarbirdWarned == FALSE):
#		DebugPrint("Kiska warns you about hitting the Chilvas")

		global g_bWarbirdWarned
		g_bWarbirdWarned = TRUE

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6HitWarbird", "Captain", 1, pMissionDatabase)
		pAction.Play()

		return

	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)


#
#	ResetGeronimoHit() 
#
def ResetGeronimoHit(pObject, pEvent):
#	DebugPrint("Resetting Geronimo Attack handler")

	global g_bGeronimoWait
	g_bGeronimoWait = FALSE


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

		# Good luck on your mission
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E7M6HailingStarbase1", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6HailingStarbase2", None, 0, pMissionDatabase)

	elif (sTarget == "USS Geronimo"):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)

		if not g_bHailedMacCray:
			global g_bHailedMacCray
			g_bHailedMacCray = TRUE
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M6HailingMacCray1", None, 0, pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M6HailingMacCray2", None, 0, pMissionDatabase)

	elif (sTarget == "USS Enterprise") and (g_bStationDestroyed == FALSE):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6HailingPicard1", None, 0, pMissionDatabase)

	elif (sTarget == "HoH'egh"):
		if not g_bHailedKlingon:
			global g_bHailedKlingon
			g_bHailedKlingon = TRUE

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6HailingKlingon1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6HailingKlingon2", "H", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6HailingKlingon3", "T", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6HailingKlingon4", "H", 1, pMissionDatabase)

		else:
#			DebugPrint("Nothing Special to handle")

			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif (sTarget == "Chilvas"):
		if not g_bHailedRomulan:
			global g_bHailedRomulan
			g_bHailedRomulan = TRUE

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6HailingRomulan1", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6HailingRomulan2", "Captain", 1, pMissionDatabase)

		else:
#			DebugPrint("Nothing Special to handle")

			pSequence.Completed()
			pObject.CallNextHandler(pEvent)

			return

	elif (sTarget == "Alioth 6"):
#		DebugPrint("Hailing Alioth6")
		pSequence.Completed()
		if g_bDataCanRespond:
			HailAlioth6(None)

		return

	else:
#		DebugPrint("Nothing Special to handle")

		pSequence.Completed()
		pObject.CallNextHandler(pEvent)

		return

	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


################################################################################
#	PlayGroup1Dialogue()
#
#	Start dialogue after having destroyed group 1.
#
#	Args:	None
#			
#
#	Return:	None
################################################################################
def PlayGroup1Dialogue():

	pAction = Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E7M6L066", pMissionDatabase)
	pAction.Play()


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
def EnterSet(TGObject, pEvent):
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	if(pShip):
		# It's a ship.
		sShipName = pShip.GetName()

		pSet = pShip.GetContainingSet()
		sSetName = pSet.GetName()
#		DebugPrint("Ship \"" + sShipName + "\" entered set \"" + sSetName + "\"")
		
		# If Player entered set.			
		if(sShipName == "player"):

			# First time at Alioth6.
			if(sSetName == "Alioth6") and (Alioth6Flag == HASNT_ARRIVED):
				global Alioth6Flag
				Alioth6Flag = HAS_ARRIVED

				pPlanet = App.ObjectClass_GetObject(pSet, "Alioth 6")
				pPlanet.SetHailable(1)

				if (Maelstrom.Episode7.Episode7.iNumFreightersEscaped == 0):
#					DebugPrint("Litvok Nor's disruptors are out of juice")
					pBase = App.ShipClass_GetObject(pSet, "Litvok Nor")
					pSystem = pBase.GetPulseWeaponSystem()
					if (pSystem):
						MissionLib.SetConditionPercentage (pSystem, 0)

				else:
					iDisruptorTimer = 0
					if (Maelstrom.Episode7.Episode7.iNumFreightersEscaped > 0):
						pFreighter1 = loadspacehelper.CreateShip("CardFreighter", pSet, "Freighter1", "Freighter 1 Start")
						pFreighter1.SetAI(FreighterAI.CreateAI(pFreighter1, "Freighter Way1"))
	
						iDisruptorTimer = 120
	
					if (Maelstrom.Episode7.Episode7.iNumFreightersEscaped > 1):
						pFreighter2 = loadspacehelper.CreateShip("CardFreighter", pSet, "Freighter2", "Freighter 2 Start")
						pFreighter2.SetAI(FreighterAI.CreateAI(pFreighter2, "Freighter Way2"))
	
						iDisruptorTimer = 180
	
					if (Maelstrom.Episode7.Episode7.iNumFreightersEscaped > 2):
						pFreighter3 = loadspacehelper.CreateShip("CardFreighter", pSet, "Freighter3", "Freighter 3 Start")
						pFreighter3.SetAI(FreighterAI.CreateAI(pFreighter3, "Freighter Way3"))
	
						iDisruptorTimer = 240
	
					if (Maelstrom.Episode7.Episode7.iNumFreightersEscaped > 3):
						pFreighter4 = loadspacehelper.CreateShip("CardFreighter", pSet, "Freighter4", "Freighter 4 Start")
						pFreighter4.SetAI(FreighterAI.CreateAI(pFreighter4, "Freighter Way4"))
	
						iDisruptorTimer = 0

					if not iDisruptorTimer == 0:
						# Create timer to bring down the Base's disruptors
						fStartTime = App.g_kUtopiaModule.GetGameTime()
						MissionLib.CreateTimer(ET_DISRUPTORS_GONE, __name__ + ".DisruptorsGone", fStartTime + iDisruptorTimer, 0, 0)

				Alioth6Arrive()

			# First time at Alioth8.
			if((sSetName == "Alioth8") and (Alioth8Flag == HASNT_ARRIVED)):
				Alioth8Arrive()
			# Arrived at Starbase 12
			if(sSetName == "Starbase12") and (g_bAlioth6Follow == TRUE):
				# Cardassians have broken off pursuit
				g_pMiguel.SayLine(pMissionDatabase, "E7M6CardsFollow7", "Captain", 1)

		elif (g_bStopFollowHandle == FALSE) and pAlioth8Enemies.IsNameInGroup(sShipName) and not (sSetName == "Alioth6") and not (sSetName == "Starbase12") and not (sSetName == "warp") and (Alioth8Flag == HAS_ARRIVED):
			global g_bStopFollowHandle
			g_bStopFollowHandle = TRUE

			HandleBeingFollowed()

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
#	DisruptorsGone() - Litvok Nor's disruptors have run out of juice
#
def DisruptorsGone(pObject, pEvent):
	if not g_bStationDestroyed and not g_bDisruptorsGone:
#		DebugPrint("Litvok Nor's disruptors have run out of juice")
		pSet = App.g_kSetManager.GetSet("Alioth6")
	
		pBase = App.ShipClass_GetObject(pSet, "Litvok Nor")
		pSystem = pBase.GetPulseWeaponSystem()
		if (pSystem):
			MissionLib.SetConditionPercentage (pSystem, 0)

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6CardStation3", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction, 15)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CardStation4", "T", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CardStation5", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)


#
#	HandleBeingFollowed()
#
def HandleBeingFollowed():
	# Get bridge characters.
	
	pSequence = App.TGSequence_Create()
	
	if not g_bFollowDialogue:
		global g_bFollowDialogue
		g_bFollowDialogue = TRUE
	
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CardsFollow1", "Captain", 1, pMissionDatabase)
		
	else:
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CardsFollow5", "Captain", 1, pMissionDatabase)
	
	pSequence.AppendAction(pAction)
	
	if not g_bAliothFollow:
		global g_bAliothFollow
		g_bAliothFollow = TRUE
	
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6CardsFollow6", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)					
	
	MissionLib.QueueActionToPlay(pSequence)


################################################################################
#	ExitSet(pObject, pEvent)
#
#	Ship exited set event handler.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def ExitSet(TGObject, pEvent):
	# Check and see if mission is terminating, if so return
	if (bMissionTerminate == TRUE):
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()
		
	if(pShip):
		# It's a ship.
#		DebugPrint("Ship \"" + pShip.GetName() + "\" exited set \"" + sSetName + "\"")

		if (pShip.GetName() == "player"):
			global g_bStopFollowHandle
			g_bStopFollowHandle = FALSE
	
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
#	EnterpriseWarpIn(TGObject, pEvent)
#
#	Give the Enterprise AI to warp in.
#
#	Args:	None
#
#	Return:	None
################################################################################
def EnterpriseWarpIn(TGObject, pEvent):
	if(g_bEnterpriseArrived):
		return

	pGame = App.Game_GetCurrentGame()
	pSet = pGame.GetPlayerSet()

	if pSet == None:
		return

	# If player is in Alioth6, the Enterprise will arrive
	if (pSet.GetName() == "Alioth6"):
		MissionLib.AddGoal("E7EnterpriseSurviveGoal")

		pEnterprise = loadspacehelper.CreateShip("Enterprise", pSet, "USS Enterprise", "Enterprise Start")
		pEnterprise.ReplaceTexture("Data/Models/Ships/Sovereign/Enterprise.tga", "ID")

		SetAI(None, pEnterprise, EnterpriseAI)
	
		global g_bEnterpriseArrived
		g_bEnterpriseArrived = TRUE

		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet") 
		pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")
		
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
		
		# Enterprise arrival dialogue
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6L013", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L023", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 2)
		pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
		pSequence.AppendAction(pAction1)
		pAction2 = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AddAction(pAction2, pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L024", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L025", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L026", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L027", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "StationDestroyedOrNot")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ResetEntSequence")
		pSequence.AppendAction(pAction)

		# Add a special check for this sequence
		global g_pEntSequence
		g_pEntSequence = pSequence

		MissionLib.QueueActionToPlay(pSequence)

	# Player is not in Alioth6, the Enterprise will try again later
	else:
		# Create timer to have Enterprise warp in.
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_ENTERPRISE_TIMER_EVENT, __name__ + ".EnterpriseWarpIn", fStartTime + 30, 0, 0)


#
# StationDestroyedOrNot()
#
def StationDestroyedOrNot(pAction):
	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet") 
	pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")
	
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if not g_bStationDestroyed:
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L027b", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L027b2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	else:
		pSequence.AppendAction(PicardFindDataSequence())

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# ResetEntSequence()
#
def ResetEntSequence(pAction):
	global g_pEntSequence
	g_pEntSequence = None

	return 0


#
# PicardFindDataSequence()
#
def PicardFindDataSequence():
	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet") 
	pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")
		
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L027c", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L028", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6L029", "T", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L030", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L030b", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
	pSequence.AppendAction(pAction1)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L031", "E", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_BECOME_ACTIVE)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6L032", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_BECOME_INACTIVE)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L019c", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L020", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "SetDataRespondFlag")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "HailAlioth6")
	pSequence.AppendAction(pAction)

	return pSequence

#
# SetDataRespondFlag() - Set the flag so Data can respond to your hails
#
def SetDataRespondFlag(pAction):

	global g_bDataCanRespond
	g_bDataCanRespond = TRUE

	return 0


################################################################################
#	Briefing(pObject, pEvent)
#
#	Get the briefing dialogue from Admiral Liu.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Briefing():
	global g_bBriefingPlayed
	g_bBriefingPlayed = TRUE

	pLiuSet = App.g_kSetManager.GetSet("LiuSet") 
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pSequence.AddAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E7M6L001", pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E7M6L003", pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E7M6L004", pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E7M6L005", pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E7M6L006", pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E7M6L007", pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E7M6L008", pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	pAction = App.TGScriptAction_Create(__name__, "CreateAliothMenu")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L009", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if (Maelstrom.Maelstrom.bGeronimoAlive):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6MacCrayHailing", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E7M6GreetMacCray", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# CreateAliothMenu()
#
def CreateAliothMenu(pAction):
	pAliothMenu = Systems.Alioth.Alioth.CreateMenus()
	pAliothMenu.SetMissionName("Maelstrom.Episode7.E7M6.E7M6")

	return 0

################################################################################
#	Alioth6Arrive()
#
#	Called when player's ship first enters the Alioth 6 Region.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Alioth6Arrive():
	# Create sets used in this region.
	
	# Create timer to have Enterprise warp in.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_ENTERPRISE_TIMER_EVENT, __name__ + ".EnterpriseWarpIn", fStartTime + EnterpriseWarpInDelay, 0, 0)

	# Create timer for wave of cardassians
	MissionLib.CreateTimer(ET_WAVE_ARRIVE_TIMER_EVENT, __name__ + ".NextWave", fStartTime + 120, 0, 0)
							
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "SetTarget", "Litvok Nor")
	pSequence.AppendAction(pAction, 5)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6L065", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6CardStation1", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	# Add dialogue if you left any of the Cardassians in Alioth8 undestroyed
	if (g_iGroup1Remaining > 0):
		global g_bAlioth6Follow
		g_bAlioth6Follow = TRUE

		if not g_bFollowDialogue:
			global g_bFollowDialogue
			g_bFollowDialogue = TRUE
		
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CardsFollow1", "Captain", 1, pMissionDatabase)
			
		else:
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CardsFollow5", "Captain", 1, pMissionDatabase)

		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6CardsFollow2", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6CardsFollow3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CardsFollow4", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	if (Maelstrom.Episode7.Episode7.iNumFreightersEscaped == 0):
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6CardStation2", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6CardStation5", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	else:
		if (Maelstrom.Episode7.Episode7.iNumFreightersEscaped == 1):
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6Freighters1b", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction, 2)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6Freighters2b", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		else:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6Freighters1", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6Freighters2", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6Freighters3", "S", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6Freighters4", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6Freighters5", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L019", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6L019b", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L019c", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L020", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L022b", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L022c", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6L022d", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6L022e", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6L022f", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)
	
	# Get Enemy ships.
	pGalor1 = MissionLib.GetShip("Galor5")
	pGalor2 = MissionLib.GetShip("Galor6")
	pKeldon1 = MissionLib.GetShip("Keldon1")
	
	# Set enemy AI.
	pGalor1.SetAI(EnemyAI.CreateAI(pGalor1))
	pGalor2.SetAI(EnemyAI.CreateAI(pGalor2))
	pKeldon1.SetAI(EnemyAI.CreateAI(pKeldon1))


################################################################################
#	Alioth8Arrive()
#
#	Called when player's ship first enters the Alioth 8 Region.
#	Set AI for first Cardassian battle group, play Felix line.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Alioth8Arrive():
	# Play Felix line, Cardassians coming.
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction1 = App.TGScriptAction_Create(__name__, "WarpInGalor", 1)
	pSequence.AppendAction(pAction1, 2)
	pAction2 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6L010", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction2)
	pAction = App.TGScriptAction_Create(__name__, "WarpInGalor", 2)
	pSequence.AddAction(pAction, pAction1, 1)
	pAction = App.TGScriptAction_Create(__name__, "WarpInGalor", 3)
	pSequence.AddAction(pAction, pAction1, 2)
	pAction = App.TGScriptAction_Create(__name__, "WarpInGalor", 4)
	pSequence.AddAction(pAction, pAction1, 3)

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L011", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction, pAction2)
	pAction = App.TGScriptAction_Create(__name__, "AtAlioth8")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# WarpInGalor (Warps in the Galor
#
def WarpInGalor(pAction, iGalor):
	if (iGalor > 0) and (iGalor < 5):
		pSet = App.g_kSetManager.GetSet("Alioth8")
		pGalor = loadspacehelper.CreateShip("Galor", pSet, "Galor" + str(iGalor), "Attacker " + str(iGalor) + " Start", 1)
		pGalor.SetAI(EnemyFollowAI.CreateAI(pGalor))

		if (iGalor == 1):
			SetTarget(None, "Galor1")

	return 0

#
# AtAlioth8()
#
def AtAlioth8(pAction):
	global Alioth8Flag
	Alioth8Flag = HAS_ARRIVED

	return 0


################################################################################
#	StationDestroyed()
#
#	Play dialogue for station having been destroyed. 
#	Then play dialogue with Picard about rescuing data.
#
#	Args:	None
#
#	Return:	None
################################################################################
def StationDestroyed():
	# Set flag.
	global g_bStationDestroyed
	g_bStationDestroyed = TRUE
	
	MissionLib.RemoveGoal("E7DestroyCardassianStationGoal")
	MissionLib.AddGoal("E7RescueDataGoal")

	# Get bridge characters.
	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet") 
	pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")
	
	# Set dialogue Sequence
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	# Say "station has been destroyed".
	pSequence.AddAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E7M6L017", pMissionDatabase))

	# If any Cardassian ships left, play "Cardassians retreating" line.	
	if(pHostiles.GetNumActiveObjects()):
		pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E7M6L018", pMissionDatabase))

	# Make sure Enterprise is here before giving dialogue from Picard.
	if(not g_bEnterpriseArrived):
		EnterpriseWarpIn(None, None)

	elif (g_pEntSequence == None):
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L023", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L027b3", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pSequence.AppendAction(PicardFindDataSequence())

	pSequence.Play()


################################################################################
#	SensorsBoosted(pObject, pEvent)
#
#	Handler for when sensors are boosted in order to contact Data.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def SensorsBoosted(pObject, pEvent):
	pSubsystem = pEvent.GetSource()
	if(pSubsystem is None):
		return

	pPlayer = MissionLib.GetPlayer()

	if pPlayer == None:
		return

	pSet = App.g_kSetManager.GetSet("Alioth6")
	pPlanet = App.ObjectClass_GetObject(pSet, "Alioth 6")
	# Get the distance between the player and the planet
	vDiff = pPlayer.GetWorldLocation()
	vDiff.Subtract(pPlanet.GetWorldLocation())
	fDistance = vDiff.Length()

#	DebugPrint('Distance from Planet: ' + str(fDistance) + 'km')
				
	# Check if subsystem boosted is sensor system.
	if(App.SensorSubsystem_Cast(pSubsystem)):
		if (g_bInOrbit or (fDistance <= 170)) and g_bDataContacted:
			BeamDataAboard(None)

			# Remove event handler since function should not be called again.
			pMission = MissionLib.GetMission()
			App.g_kEventManager.RemoveBroadcastHandler(App.ET_SUBSYSTEM_POWER_CHANGED, pMission, __name__ + ".SensorsBoosted", pPlayer)


################################################################################
#	DataResponse()
#
#	Get dialogue sequence for Data responding from the planet.
#
#	Args:	None
#
#	Return:	pSequence, the dialogue sequence.
################################################################################
def DataResponse():
	pShuttleSet = App.g_kSetManager.GetSet("ShuttleSet")
	pData = App.CharacterClass_GetObject(pShuttleSet, "Data")
	
	# Set dialogue Sequence
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L022a", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L036", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction1, 3)
	pAction2 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L037", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction, 5)
	# Get Data on screen.
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "ShuttleSet", "Data", 0.25, 0.5)
	pSequence.AppendAction(pAction)

	pSequence2 = App.TGSequence_Create()

	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
	pSequence2.AddAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L038", None, 0, pMissionDatabase)
	pSequence2.AddAction(pAction)

	pSequence.AppendAction(pSequence2)

	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L039", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L043", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
	pSequence.AppendAction(pAction1)
	pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_BECOME_ACTIVE)
	pSequence.AddAction(pAction2, pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6L044", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_BECOME_INACTIVE)
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "CheckToGetData")
	pSequence.AppendAction(pAction)

	return pSequence


#
# CheckToGetData() - Plays a line depending on whether you are in orbit and have sensors boosted
#
def CheckToGetData(pAction):
	# Data contacted, set flag.
	global g_bDataContacted
	g_bDataContacted = TRUE

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pPlayer = MissionLib.GetPlayer()

	if pPlayer == None:
		return

	pSet = App.g_kSetManager.GetSet("Alioth6")
	pPlanet = App.ObjectClass_GetObject(pSet, "Alioth 6")
	# Get the distance between the player and the planet
	vDiff = pPlayer.GetWorldLocation()
	vDiff.Subtract(pPlanet.GetWorldLocation())
	fDistance = vDiff.Length()

#	DebugPrint('Distance from Planet: ' + str(fDistance) + 'km')
				
	# If not in orbit
	if not (g_bInOrbit or (fDistance <= 170)):
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L045", "Captain", 1, pMissionDatabase)

	# If in orbit but sensors are not boosted
	elif not MissionLib.IsBoosted(pPlayer.GetSensorSubsystem()):
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6L046", "Captain", 1, pMissionDatabase)

		pMission = MissionLib.GetMission()
		App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SUBSYSTEM_POWER_CHANGED, pMission, __name__ + ".SensorsBoosted", pPlayer)

	# Get Data Aboard
	else:
		pAction = App.TGScriptAction_Create(__name__, "BeamDataAboard")

	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


################################################################################
#	DataBeamUp()
#
#	Get dialogue sequence for beaming up Data from the planet.
#
#	Args:	None
#			
#	Return:	pSequence, the dialogue sequence.
################################################################################
def DataBeamUp(pAction):
	# Get bridge characters.
	pSet = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pSet, "Data")

	pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet") 
	pPicard = App.CharacterClass_GetObject(pEBridgeSet, "Picard")
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	# Set dialogue Sequence
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6L047", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	# Play Brex line "lowering shields" if shields are up.
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pShields = pPlayer.GetShields()
		if pShields:
			if pShields.IsOn():
				pAction = App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "LoweringShields", None, 0, pGeneralDatabase)
				pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E7M6L048", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Kiska Head", "Kiska Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L023", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Picard")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L049", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E7M6L049b", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "EnterpriseWarpOut")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_WATCH_ME)
	pSequence.AppendAction(pAction, 6)
	pAction1 = App.CharacterAction_Create(pData, App.CharacterAction.AT_MOVE, "X")
	pSequence.AppendAction(pAction1)
	pAction2 = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6DataOnBoard1", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction, 1)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_STOP_WATCHING_ME)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6DataOnBoard2", "X", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction1, 1)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6DataOnBoard3", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L050", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction, 2)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L051", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M6L052", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L053", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M6L054", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L055", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6L056", "X", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L057", "S", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L058", "X", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L059", "C", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M6L060", "X", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L061", "C", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E7M6L062", "X", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E7M6L063", "S", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
#	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M6L064", None, 0, pMissionDatabase)
#	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M6L064b", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E7M6L064c", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
#	EnterpriseWarpOut() - The Enterprise Warps out
#
def EnterpriseWarpOut(pAction):
#	DebugPrint("The Enterprise Warps out")
	pEnterprise = App.ShipClass_GetObject(App.SetClass_GetNull(), "USS Enterprise")

	if pEnterprise:
		MissionLib.ViewscreenWatchObject(pEnterprise)
		pEnterprise.SetAI(WarpAwayAI.CreateAI(pEnterprise))

		MissionLib.RemoveGoal("E7EnterpriseSurviveGoal")

	return 0


################################################################################
#	BeamDataAboard(pAction)
#
#	Beam Data from the planet and onto the bridge.
#
#	Args:	pAction, the script action.
#			
#	Return:	None
################################################################################
def BeamDataAboard(pAction):
#	DebugPrint ("Data is rescued")

	if not g_bDataRescued:
		global g_bDataRescued
		g_bDataRescued = TRUE
	
		RemoveHooks()
	
		# Get data from shuttle.
		pShuttleSet = App.g_kSetManager.GetSet("ShuttleSet")
		pData = App.CharacterClass_Cast(pShuttleSet.RemoveObjectFromSet("Data"))
		Bridge.Characters.Data.ConfigureForSovereign(pData)
	
		# Put him on the bridge.
		pBridgeSet = Bridge.BridgeUtils.GetBridge()
		pData.SetHidden(1)
		pBridgeSet.AddObjectToSet(pData, "Data")
		# Move data to EBridge placement Lift1
		pData.SetLocation("EBL1M")
	
		# Communicate with Data event
		pMenu = pData.GetMenu()
		pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
#		DebugPrint ("Removing RescueDataGoal")
		MissionLib.RemoveGoal("E7RescueDataGoal")
	
#		DebugPrint ("Adding ReturnToStarbaseGoal")
		MissionLib.AddGoal("E7ReturnToStarbaseGoal")
	
		DataBeamUp(None)

	return 0


#	Episode8Cutscene() - Data's personal log
#
def Episode8Cutscene():
	# Load Ep 8 Database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 8/E8M1.tgl")

	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	pSequence = App.TGSequence_Create()

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

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EpisodeTitleAction", "Ep8Title"))

	pAction = App.TGScriptAction_Create("MissionLib", "TextBanner", pDatabase.GetString("EnrouteToStarbase12"), 0, .15)
	pSequence.AppendAction(pAction, 6)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E8M1DataLog1", "Data")
	pSequence.AppendAction(pAction, 3)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "warp")	
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2", 1)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E8M1DataLog2", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E8M1DataLog3", "Data")
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(pData, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction)
	pAction3 = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pDatabase, "E8M1DataLog4", "Data")
	pSequence.AddAction(pAction3, pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)

	if(pDatabase):
		App.g_kLocalizationManager.Unload(pDatabase)

	return pSequence


#
# UnhidePlayer() - makes the player visible in the warp set
#
def UnhidePlayer(pAction):
	pPlayer = MissionLib.GetPlayer()
	pPlayer.SetHidden(0)

	return 0


################################################################################
#	HailAlioth6()
#
#	Play dialogue for attempting to hail Data on the planet, Alioth6.
#
#	Args:	pAction
#			
#	Return:	None
################################################################################
def HailAlioth6(pAction):
	if g_bDataRescued or g_bDataContacted or g_bTryingData:
		return 0

	pSet = App.g_kSetManager.GetSet("Alioth6")
	pPlanet = App.ObjectClass_GetObject(pSet, "Alioth 6")
	pPlayer = MissionLib.GetPlayer()

	if (pPlanet == None) or (pPlayer == None):
		return 0

	# Get the distance between the player and the planet
	vDiff = pPlayer.GetWorldLocation()
	vDiff.Subtract(pPlanet.GetWorldLocation())
	fDistance = vDiff.Length()

	global g_bTryingData
	g_bTryingData = TRUE

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "DisableHailMenu")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if not g_bStationDestroyed:

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateKiska2", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ResetTryingData")
		pSequence.AppendAction(pAction)

	elif not MissionLib.IsBoosted(pPlayer.GetSensorSubsystem()):
		# Unable to contact Data because of interference.
#		DebugPrint("We need to boost power to Sensors")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L022a", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L021", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L022", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)
		pAction = App.TGScriptAction_Create(__name__, "ResetTryingData")
		pSequence.AppendAction(pAction)

	elif (fDistance > 170) and not g_bInOrbit:
#		DebugPrint("We need to get closer to the planet")
#		DebugPrint('Distance from Planet: ' + str(fDistance) + 'km')

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L022a", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6L021", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E7M6CommunicateKiska4", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)
		pAction = App.TGScriptAction_Create(__name__, "ResetTryingData")
		pSequence.AppendAction(pAction)

	else:
		# If in orbit with sensors boosted, rescue data.
		pSequence.AppendAction(DataResponse())

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableHailMenu")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# ResetTryingData() - Couldn't get ahold of Data...
#
def ResetTryingData(pAction):
	global g_bTryingData
	g_bTryingData = FALSE

	return 0


################################################################################
#	NextWave()
#
#	Have next wave of ships enter Alioth 6.
#
#	Args:	None
#			
#
#	Return:	None
################################################################################
def NextWave(pObject, pEvent):
	if g_bStationDestroyed:
		return

	# If max number of ships have warped in, return.
	if(g_iNumAttackers > g_iMaxTotalShips):
#		DebugPrint("Maximum number of ships have warped in to set. Cardassian fleet depleted!.")
		return

	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		return

	pSet = pPlayer.GetContainingSet()

	# Warp in delay
	fDelay = App.g_kSystemWrapper.GetRandomNumber(30) + 30
#	DebugPrint("Delayed by: " + str(fDelay) + " seconds.")

	# Create timer for next wave
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_WAVE_ARRIVE_TIMER_EVENT, __name__ + ".NextWave", fStartTime + fDelay + NextWaveDelay, 0, 0)

	# If player is not at Alioth6
	if not (pSet.GetName() == "Alioth6"):
		return

	# Cap number of enemy ships in the set at one time.
	if(pHostiles.GetNumActiveObjects() > g_iMaxEnemiesInSet):
#		DebugPrint("NextWave() called, bailing because too many hostiles in set.")
		return

	global g_iNumAttackers

#	DebugPrint("\n***Starting NextWave!\n")
	# Get random number of ships, 1-3.
	iNumShips = App.g_kSystemWrapper.GetRandomNumber(3) + 1
#	DebugPrint("Number of Ships: " + str(iNumShips))

	for i in range(iNumShips):
		g_iNumAttackers = g_iNumAttackers + 1
		# Create next random ship and increment count.
		CreateRandomShip("Attacker"  + str(g_iNumAttackers))
#		DebugPrint("Ship Number: " + str(g_iNumAttackers))

	# Felix tells you about the new wave
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E7M6L012", "Captain", 1, pMissionDatabase)
	pAction.Play()

	
################################################################################
#	RemoveHooks()
#
#	Args:	None
#
#	Return:	None
################################################################################
def RemoveHooks():
	pAliothMenu = Systems.Alioth.Alioth.CreateMenus()


################################################################################
#	SetAI(pAction, pShip, AIModule)
#
#	Set ship AI action.
#
#	Args:	pAction, the action
#			pShip, Ship to set AI for
#			AIModule, AI module containing AI create function.
#
#	Return:	None
################################################################################
def SetAI(pAction, pShip, AIModule):
	pShip.SetAI(AIModule.CreateAI(pShip))
	return 0


################################################################################
#	SetTarget(pAction, pcShipName)
#
#	Action to set Player's target.
#
#	Args:	pAction, current action.
#			pcShipName, name of ship to target.
#
#	Return:	None
################################################################################
def SetTarget(pAction, pcShipName):
	pPlayerShip = MissionLib.GetPlayer()
	if(pPlayerShip):
		pPlayerShip.SetTarget(pcShipName)

	return 0


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


################################################################################
#	Terminate()
#
#	Stop mission, music and unload TGL database.
#
#	Args:	pMission, current mission playing.
#
#	Return:	None
################################################################################
def Terminate(pMission):
#	print ("Terminating Episode 7, Mission 6.\n")

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()

	# Remove handler for Contact Starfleet
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	# Remove Science Scan event
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	# Remove Hail handler
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Remove Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	# Remove Communicate handlers
	g_pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	g_pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	if not pData == None:
		pMenu = pData.GetMenu()
		pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	MissionLib.DeleteAllGoals()
	
	# Set our terminate flag to true
	global bMissionTerminate
	bMissionTerminate = TRUE

	if(pGeneralDatabase):
		App.g_kLocalizationManager.Unload(pGeneralDatabase)

	if(pMenuDatabase):
		App.g_kLocalizationManager.Unload(pMenuDatabase)

	# Clear the set course menu
	App.SortedRegionMenu_ClearSetCourseMenu()
