###############################################################################
#	Filename:	E4M6.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 4 Mission 6
#	
#	Created:	04/01/01 - 	Alberto Fonseca
#	Modified:	01/14/02 - 	Tony Evans		
###############################################################################
import App
import loadspacehelper
import MissionLib
import Bridge.BridgeUtils
import Maelstrom.Episode4.Episode4

#NonSerializedObjects = ( "debug", )
#debug = App.CPyDebug(__name__).Print


#
# Global variables
#
TRUE					= 1
FALSE					= 0
g_bDebugPrint			= TRUE

g_bLoaded				= 0

g_pMissionDatabase 		= 0
g_pGeneralDatabase		= 0
g_bPlayerFound 			= 0 # Tells if the player has messed up with the hiding bit
g_bRihaWon 				= 0	# Did we complete the Riha system?
g_bCebalraiWon 			= 0	# Did we complete the Cebalrai system?
g_bKlingonsAttack 		= 0	# Did the Klingons appear?
g_bPlayerInZone 		= 0	# Are we in the zone?
g_bNepentheWon 			= 0	# Has the conversation ended?
g_iCommSequenceID 		= 0 # The currently playing sequence(used to abort)
g_bBriefingPlayed		= 0	# Has mission briefing played
g_pFriendlies			= 0 # Friendly object group
g_pEnemies				= 0 # Enemy object group
g_pRihaHostiles			= 0 # Riha enemy object group
g_pRihaGroup1			= 0 # First enemy target group in Riha
g_pKlingons				= 0 # Klingon group in Riha
g_pCebalraiHostiles		= 0 # Cebalrai enemy object group
g_bRiha1GalorsArrived	= 0	# Did Riha1 reinforcing Galors arrive.
g_bDataScanning			= 0 # Is Commander Data scanning warp trail.
g_pNepentheHostiles		= 0	# Nepenthe enemy object group.
g_bMissionWon			= 0 # Has the player won the mission.
g_bMissionLost			= 0 # Has the player lost the mission.
g_iMissionProgress		= 0 # Keep track of mission progress.
g_bWarnPlayer			= 0 # Flag for wether to warn player when firing on friendlies.
g_pFriendlyWarningTimer	= 0 # Timer for friendly fire warning delay.
g_idFreighterProx		= 0 # Proximity check for freighters in Nepenthe.
g_idInZoneProx			= 0	# Proximity check for in safety zone.
g_idOutZoneProx			= 0 # Proximity check for out safety zone.
g_idGalor1Timer			= 0 # Nepenthe timer for Galor 1
g_idGalor2Timer			= 0 # Nepenthe timer for Galor 2
g_idKeldonTimer			= 0 # Nepenthe timer for Keldon
g_idKessokTimer			= 0 # Nepenthe timer for Kessok
g_iCebalraiEnemiesGone  = 0 # Flag for the number of Cebalrai Galors that have retreated.
g_bMissionTerminated	= 0
g_bRihaSystemDialog		= 0


# Arrival flags
g_bArrivedRiha1			= 0	
g_bArrivedNepenthe1		= 0	
g_bArrivedCebalrai2		= 0	
g_bArrivedNepenthe3		= 0	

# Define mission progress
FREIGHTERS_ESCAPE		= 1 # Freighters warp out from Riha to Cebalrai.
FREIGHTERS_IN_CEBALRAI	= 2 # Freighters warp out from Riha to Cebalrai.
MISSION_BRANCH			= 3 # Player has choice to go to Belaruz(E4M4) or Nepenthe.
IN_NEPENTHE				= 4 # In Nepenthe system.
ENEMY_ARRIVED			= 5 # Cardassian ships start warping in.
INTERCEPTED_COMM		= 6 # Player overhead communication with Kessok

#
# Constants
#
MISSION_BREIFING_DELAY  = 30
SAFE_ZONE_RADIUS		= 57.14
FREIGHTER_PROX_RADIUS	= -285
DATA_SCANNING_DELAY		= 25
ET_DELAY_TIMER			= App.Mission_GetNextEventType()

#
# Event types
#
ET_GALOR1_ARRIVES					= App.Mission_GetNextEventType()
ET_GALOR2_ARRIVES					= App.Mission_GetNextEventType()
ET_KELDON1_ARRIVES					= App.Mission_GetNextEventType()
ET_KESSOK_ARRIVE					= App.Mission_GetNextEventType()
ET_CEBALRAI_PROD					= App.Mission_GetNextEventType()
ET_BRANCH_PROD						= App.Mission_GetNextEventType()
ET_DATA_SCAN_TIMER_EVENT			= App.Mission_GetNextEventType()


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
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Sovereign", 1)
	loadspacehelper.PreloadShip("Keldon", 1)
	loadspacehelper.PreloadShip("Galor", 14)
	loadspacehelper.PreloadShip("RanKuf", 2)
	loadspacehelper.PreloadShip("CardFreighter", 8)
	loadspacehelper.PreloadShip("CardOutpost", 1)
	loadspacehelper.PreloadShip("KessokLight", 1)

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
#	DebugPrint("Initializing Episode 4, Mission6.")

	# Initialize all global variables.
	InitGlobals()

	# Try load mission if exists.
	global g_bLoaded
	g_bLoaded = MissionLib.TryLoadMission(__name__)

	# If coming from E4M4, delete all it's goals.
	if(Maelstrom.Episode4.Episode4.g_bMission4Win):
		MissionLib.DeleteAllGoals()

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	# Creates bridge sets and characters.
	
	# Create Liu and set.
	MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet")
		
	# Create Draxon set only when needed.
	if(not g_bRihaWon):
		# Draxon
		MissionLib.SetupBridgeSet("DXBridgeSet", "data/Models/Sets/Klingon/BOPbridge.nif")
		MissionLib.SetupCharacter("Bridge.Characters.Draxon", "DXBridgeSet")
	
	# Kessok
	MissionLib.SetupBridgeSet("KessokBridgeSet", "data/Models/Sets/Kessok/kessokbridge.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Kessok", "KessokBridgeSet")
		
	# Cardassian
	MissionLib.SetupBridgeSet("CBridgeSet", "data/Models/Sets/Cardassian/cardbridge.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Matan", "CBridgeSet")
	MissionLib.SetupCharacter("Bridge.Characters.Sek", "CBridgeSet")
	
	SetAffiliations(pMission) 	# Assigns ships to enemy and friendly groups
	CreateSpaceSets()			# Create space sets and load placements.
	CreateMenus()				# Put the menus into Kiska's menu system.
	CreateShips()				# Create ships for mission start.

	# Setup event handlers
	SetupEventHandlers(pMission)

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)

#	DebugPrint("E4M6.Initialize() - Player Found = " + str(g_bPlayerFound))

	MissionLib.SetupFriendlyFire()

################################################################################
#	InitGlobals()
#
#	Initialize global variables for whole mission.
#
#	Args:	None
#
#	Return:	None
################################################################################
def InitGlobals():
	pMission = MissionLib.GetMission()
	
	# Init globals.
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_bPlayerFound
	global g_bRihaWon
	global g_bCebalraiWon
	global g_iCommSequenceID
	global g_bArrivedNepenthe1
	global g_bKlingonsAttack
	global g_bArrivedRiha1
	global g_bArrivedCebalrai2
	global g_bArrivedNepenthe3
	global g_bPlayerInZone
	global g_bNepentheWon
	global g_pMissionDatabase
	global g_bBriefingPlayed
	global g_pFriendlies
	global g_pEnemies
	global g_pRihaHostiles
	global g_pRihaGroup1
	global g_pKlingons
	global g_pCebalraiHostiles
	global g_bRiha1GalorsArrived
	global g_bDataScanning
	global g_pNepentheHostiles
	global g_bMissionWon
	global g_bMissionLost
	global g_iMissionProgress
	global g_bWarnPlayer
	global g_pFriendlyWarningTimer
	global g_idFreighterProx
	global g_idInZoneProx
	global g_idOutZoneProx
	global g_idGalor1Timer
	global g_idGalor2Timer
	global g_idKeldonTimer
	global g_idKessokTimer
	global g_iCebalraiEnemiesGone
	global g_bMissionTerminated
	global g_bRihaSystemDialog

	g_pMissionDatabase 			= None
	g_bPlayerFound 				= 0	
	g_bRihaWon 					= 0	
	g_bCebalraiWon 				= 0	
	g_iCommSequenceID		 	= App.NULL_ID
	g_bArrivedNepenthe1 		= 0	
	g_bKlingonsAttack 			= 0			
	g_bArrivedRiha1				= 0		
	g_bArrivedCebalrai2 		= 0	
	g_bArrivedNepenthe3 		= 0		
	g_bPlayerInZone 			= 0		
	g_bNepentheWon 				= 0
	g_pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 4/E4M6.tgl")
	g_pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_bBriefingPlayed			= FALSE
	g_pFriendlies 				= pMission.GetFriendlyGroup()
	g_pEnemies 					= pMission.GetEnemyGroup()
	g_pRihaHostiles				= App.ObjectGroup()
	g_pRihaGroup1				= App.ObjectGroup()
	g_pCebalraiHostiles			= App.ObjectGroup()
	g_pKlingons					= App.ObjectGroup()
	g_pNepentheHostiles			= App.ObjectGroup()
	g_bRiha1GalorsArrived		= FALSE
	g_bDataScanning				= FALSE
	g_bMissionWon				= FALSE
	g_bMissionLost				= FALSE
	g_iMissionProgress			= 0
	g_bWarnPlayer				= TRUE
	g_pFriendlyWarningTimer		= None
	g_idFreighterProx			= App.NULL_ID
	g_idInZoneProx				= App.NULL_ID
	g_idOutZoneProx				= App.NULL_ID
	g_idGalor1Timer				= App.NULL_ID
	g_idGalor2Timer				= App.NULL_ID
	g_idKeldonTimer				= App.NULL_ID
	g_idKessokTimer				= App.NULL_ID
	g_iCebalraiEnemiesGone		= 0
	g_bMissionTerminated		= FALSE
	g_bRihaSystemDialog			= 0

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
	# Starbase 12
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()

	# Create the Nepenthe set.
	import Systems.Nepenthe.Nepenthe1
	Systems.Nepenthe.Nepenthe1.Initialize()

	# Create the Riha set
	import Systems.Riha.Riha1
	Systems.Riha.Riha1.Initialize()

	# Create the Cebalrai set
	import Systems.Cebalrai.Cebalrai2
	Systems.Cebalrai.Cebalrai2.Initialize()

	# Add our custom placement objects for this mission.
	import Maelstrom.Episode4.E4M6.E4M6_Nepenthe1_P
	pNepenthe1 = Systems.Nepenthe.Nepenthe1.GetSet()
	Maelstrom.Episode4.E4M6.E4M6_Nepenthe1_P.LoadPlacements(pNepenthe1.GetName())

	# Load custom placements for bridge.
	pBridgeSet = Bridge.BridgeUtils.GetBridge()
	import Maelstrom.Episode4.EBridge_P
	Maelstrom.Episode4.EBridge_P.LoadPlacements(pBridgeSet.GetName())

	#import Maelstrom.Episode4.E4M6.E4M6_Cebalrai3_P
	#pCebalrai3 = Systems.Cebalrai.Cebalrai3.GetSet()
	#Maelstrom.Episode4.E4M6.E4M6_Cebalrai3_P.LoadPlacements(pCebalrai3.GetName())

	import Maelstrom.Episode4.E4M6.E4M6_Cebalrai2_P
	pCebalrai2 = Systems.Cebalrai.Cebalrai2.GetSet()
	Maelstrom.Episode4.E4M6.E4M6_Cebalrai2_P.LoadPlacements(pCebalrai2.GetName())

	import Maelstrom.Episode4.E4M6.E4M6_Riha1_P
	pRiha1 = Systems.Riha.Riha1.GetSet()
	Maelstrom.Episode4.E4M6.E4M6_Riha1_P.LoadPlacements(pRiha1.GetName())

################################################################################
#	CreateShips()
#
#	Create ships used in this mission and set their group affiliations.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateShips():
	# Import sets.
	import Systems.Starbase12.Starbase12
	import Systems.Cebalrai.Cebalrai2
	import Systems.Riha.Riha1
	pStarbase12Set = Systems.Starbase12.Starbase12.GetSet()
	pCebalrai2 = Systems.Cebalrai.Cebalrai2.GetSet()
	pRiha1 = Systems.Riha.Riha1.GetSet()

   	# Starbase 12 ships
	pStarbase = loadspacehelper.CreateShip("FedStarbase", pStarbase12Set, 
											"Starbase 12", "Starbase12 Location")
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pStarbase12Set, "player", 
											"Player Start")
		
	if(not g_bRihaWon):
		# Riha1 ships
		loadspacehelper.CreateShip("Galor", pRiha1, 
												"Galor 1", "Galor1 Start")
		loadspacehelper.CreateShip("Galor", pRiha1, 
												"Galor 2", "Galor2 Start")
		loadspacehelper.CreateShip("RanKuf", pRiha1, 
												"RanKuf", "BOP1 Start")
		loadspacehelper.CreateShip("RanKuf", pRiha1, 
												"Trayor", "BOP2 Start")
		loadspacehelper.CreateShip("CardFreighter", pRiha1,
												"Freighter 1", "Freighter1 Start")
		loadspacehelper.CreateShip("CardFreighter", pRiha1, 
												"Freighter 2", "Freighter2 Start")
		loadspacehelper.CreateShip("CardFreighter", pRiha1,
												"Freighter 3", "Freighter3 Start") 
		loadspacehelper.CreateShip("CardFreighter", pRiha1, 
												"Freighter 4", "Freighter4 Start")

	if(not g_bCebalraiWon):
		# Cebalrai 2 ships
		loadspacehelper.CreateShip("CardOutpost", pCebalrai2,
												"Outpost", "Cardassian Outpost Start")
		loadspacehelper.CreateShip("CardFreighter", pCebalrai2,
												"Freighter 5", "Freighter5 Start" )
		loadspacehelper.CreateShip("CardFreighter", pCebalrai2, 
												"Freighter 6", "Freighter6 Start" )
		loadspacehelper.CreateShip("Galor", pCebalrai2, 
												"Galor 1", "Keldon1 Start" )
		loadspacehelper.CreateShip("Galor", pCebalrai2, 
												"Galor 2", "Keldon2 Start" )

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

	# Import Starbase 12 Menu Items
	import Systems.Starbase12.Starbase
	pStarbase12Menus = Systems.Starbase12.Starbase.CreateMenus()

	# Import Riha System Menu Items
	import Systems.Riha.Riha
	pRiha = Systems.Riha.Riha.CreateMenus()

	App.SortedRegionMenu_SetPauseSorting(0)


################################################################################
#	SetAffiliations(pMission)
#
# 	Create lists of who is a friend and who is not.
#
#	Args:	None
#
#	Return:	None
################################################################################
def SetAffiliations(pMission):
	g_pFriendlies.AddName("Starbase 12")
	g_pFriendlies.AddName("player")
	g_pFriendlies.AddName("RanKuf")
	g_pFriendlies.AddName("Trayor")

	g_pEnemies.AddName("Galor 1")
	g_pEnemies.AddName("Galor 2")
	g_pEnemies.AddName("Galor 3")
	g_pEnemies.AddName("Galor 4")
	g_pEnemies.AddName("Galor 5")
	g_pEnemies.AddName("Matan")
	g_pEnemies.AddName("GalorR1")
	g_pEnemies.AddName("GalorR2")
	g_pEnemies.AddName("GalorR3")
	g_pEnemies.AddName("GalorR4")
	g_pEnemies.AddName("GalorR5")
	g_pEnemies.AddName("Freighter 1")
	g_pEnemies.AddName("Freighter 2")
	g_pEnemies.AddName("Freighter 3")
	g_pEnemies.AddName("Freighter 4")
	g_pEnemies.AddName("Freighter 5")
	g_pEnemies.AddName("Freighter 6")
	g_pEnemies.AddName("Outpost")

	pNeutrals = pMission.GetNeutralGroup()
	pNeutrals.AddName("Strange Ship")
	
	# Enemy ships that must be destroyed to continue.
	g_pRihaHostiles.AddName("Galor 1")
	g_pRihaHostiles.AddName("Galor 2")
	g_pRihaHostiles.AddName("Galor 3")
	g_pRihaHostiles.AddName("Galor 4")
	g_pRihaHostiles.AddName("Galor 5")

	g_pRihaGroup1.AddName("Galor 1")
	g_pRihaGroup1.AddName("Galor 2")
	g_pRihaGroup1.AddName("Galor 3")

	g_pKlingons.AddName("RanKuf")
	g_pKlingons.AddName("BOP2")

	g_pCebalraiHostiles.AddName("Outpost")
	g_pCebalraiHostiles.AddName("Galor 1")
	g_pCebalraiHostiles.AddName("Galor 2")

	if g_pNepentheHostiles:
		g_pNepentheHostiles.AddName("Galor 1")
		g_pNepentheHostiles.AddName("Galor 2")
		g_pNepentheHostiles.AddName("GalorR1")
		g_pNepentheHostiles.AddName("GalorR2")
		g_pNepentheHostiles.AddName("GalorR3")
		g_pNepentheHostiles.AddName("GalorR4")
		g_pNepentheHostiles.AddName("GalorR5")

################################################################################
#	InitProxChecks(pAction)
#
#	Set up proximity check to flag player either in or out of asteroid field.
#	Add proximity check for player getting close to freighters.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def InitProxChecks(pAction):
#	DebugPrint("InitProxChecks() called.")

	# Get the player
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()

	# Get set
	pNepenthe1 = App.g_kSetManager.GetSet("Nepenthe1")

	# Setup proximity for being in/out of asteroid field.
	pSafe = App.PlacementObject_GetObject(pNepenthe1, "Center of Asteroid Field")
	if pSafe:
		global g_idInZoneProx
		global g_idOutZoneProx
		g_idInZoneProx = MissionLib.ProximityCheck(pSafe, - SAFE_ZONE_RADIUS, 
						[pPlayer], __name__+ ".InZone", pNepenthe1).GetObjID()
		g_idOutZoneProx = MissionLib.ProximityCheck(pSafe, SAFE_ZONE_RADIUS + 1.0, 
						[pPlayer], __name__+ ".OutZone", pNepenthe1).GetObjID()

	return 0

################################################################################
#	InitFreighterProxChecks(pAction)
#
#	Add proximity check for player getting close to freighters.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def InitFreighterProxChecks():
	pPlayer = MissionLib.GetPlayer()

	# Get set
	pNepenthe1 = App.g_kSetManager.GetSet("Nepenthe1")

	# Setup proximity for getting close to the freighters.
	pFreighter5 = MissionLib.GetShip("Freighter 5")
	if pFreighter5:
		global g_idFreighterProx
		g_idFreighterProx = MissionLib.ProximityCheck(pFreighter5, FREIGHTER_PROX_RADIUS,
				[pPlayer], __name__ + ".NepentheFreightersWarpOut", pNepenthe1).GetObjID()

################################################################################
#	RemoveSafetyZoneProx()
#
#	Remove proximity checks that flag player either in or out of asteroid field.
#
#	Args:	None
#
#	Return:	None
################################################################################
def RemoveSafetyZoneProx(pAction):
	global g_idInZoneProx
	global g_idOutZoneProx

	if g_idInZoneProx != App.NULL_ID:
		pProx = App.ProximityCheck_Cast(App.TGObject_GetTGObjectPtr(g_idInZoneProx))
		if pProx:
			pProx.RemoveAndDelete()
		g_idInZoneProx = App.NULL_ID

	if g_idOutZoneProx != App.NULL_ID:
		pProx = App.ProximityCheck_Cast(App.TGObject_GetTGObjectPtr(g_idOutZoneProx))
		if pProx:
			pProx.RemoveAndDelete()
		g_idOutZoneProx = App.NULL_ID

	return 0

################################################################################
#	SetupEventHandlers(pMission)
#
#	Set up any event handlers for this mission.
#
#	Args:	pMission, the current mission.
#
#	Return:	None
################################################################################
def SetupEventHandlers(pMission):
	import Bridge.HelmMenuHandlers

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission,
														__name__ + ".EnterSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, 
														__name__ + ".ExitSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, 
											pMission, __name__ + ".ObjectDestroyed")

	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pNavMenu = pKiska.GetMenu().GetSubmenuW(pDatabase.GetString("Nav Points"))
	App.g_kLocalizationManager.Unload(pDatabase)
	pNavMenu.AddPythonFuncHandlerForInstance(Bridge.HelmMenuHandlers.ET_SET_NAVPOINT_TARGET, __name__ + ".NavPointSelected")

	# Add handler for Miguel's Scan Area button
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pMiguel.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Instance handler for Kiska's Hail button
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pHelm.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	# Instance handler for Kiska's Warp button.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, 
													__name__ + ".WarpHandler")

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
#	debug("EnterSet() called")
	if g_bMissionTerminated:
#		debug("EnterSet() called after mission terminate")
		pObject.CallNextHandler(pEvent)
		return

	if g_bMissionLost:
#		debug("EnterSet() called after mission loss")
		pObject.CallNextHandler(pEvent)
		return

	# A ship entered a set. 
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip):
		pcShipName = pShip.GetName()
#		DebugPrint(str(pcShipName) + " entered set " + 
#					str(pShip.GetContainingSet().GetName()))

#		debug("EnterSet() called on ship " + pShip.GetName())

		pPlayer = MissionLib.GetPlayer()
		if(pPlayer is None):
#			debug("EnterSet() called after player died")
			return

		pcSetName = pShip.GetContainingSet().GetName()

		# If Player entering set.
#		debug("EnterSet() called going to " + pcSetName)
		if(pcShipName == pPlayer.GetName()):
			if pcSetName == "Starbase12": 
				if g_bBriefingPlayed:
					pObject.CallNextHandler(pEvent)
					return
				if not (g_bLoaded):
					MissionLib.SaveGame("E4M1-")
				StartKiskaLog()
			elif(pcSetName == "Nepenthe1"):
#				debug("value of ArrivedNepenthe1 = " + str(g_bArrivedNepenthe1))
				if(g_bArrivedNepenthe1):
					pObject.CallNextHandler(pEvent)
					return
				PlayerArrivedNepenthe1()
			elif(pcSetName == "Riha1"):
				if(g_bArrivedRiha1):
					pObject.CallNextHandler(pEvent)
					return
				PlayerArrivedRiha1()
			elif(pcSetName == "Cebalrai2"):
				if(g_bArrivedCebalrai2):
					pObject.CallNextHandler(pEvent)
					return
				PlayerArrivedCebalrai2()
		# Other ship entering set.
		else:
			if pcSetName == "Riha1":
				if(pcShipName == "Galor 3"):
					# Set flag.
					global g_bRiha1GalorsArrived
					g_bRiha1GalorsArrived = TRUE
			elif pcSetName == "Nepenthe1":
				if pcShipName == "Strange Ship":
					InterceptDialogue()

	pObject.CallNextHandler(pEvent)

################################################################################
#	ExitSet(pObject, pEvent)
#
#	Exited set event handler.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def ExitSet(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if pShip:
#		DebugPrint("%s exited set %s" % (pShip.GetName(), pEvent.GetCString()))

		pcName = pShip.GetName()
		pcSetName = pEvent.GetCString()
	
		if not pShip.IsDead():
			# If player is leaving Starbase 12 for the first time.
			if pcName == "player":
				if(pcSetName == "Starbase12" and (not g_bArrivedRiha1)):
					# Set up AI for ships in Riha.
					# This is done here so that the fight 
					# begins before the player arrives.
					SetRiha1ShipsAI()

			elif (pcName == "Freighter 5") and (pcSetName == "Nepenthe1"):
				pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, 
											"E4M6NepentheFreightersFlee",g_pMissionDatabase))
				if g_bPlayerFound:
					pSeq.AppendAction(App.TGScriptAction_Create(__name__, "QuickFoundOutDialogue"))
				MissionLib.QueueActionToPlay(pSeq)

			elif (pcSetName == "Cebalrai2") and ((pcName == "Galor 1") or (pcName == "Galor 2")):
				global g_iCebalraiEnemiesGone
				g_iCebalraiEnemiesGone = g_iCebalraiEnemiesGone + 1

				if g_iCebalraiEnemiesGone == 2:
					# Load TGL database from E6M1.
					pE6M1Database = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 6/E6M1.tgl")

					pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
					pSeq = MissionLib.NewDialogueSequence()
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E6M1Savoy3Warp1",
																			pE6M1Database))
					MissionLib.QueueActionToPlay(pSeq)

					# Unload TGL Database from E6M1
					if(pE6M1Database):
						App.g_kLocalizationManager.Unload(pE6M1Database)
						pE6M1Database = None

				
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
def ObjectDestroyed(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip):
		pcShipName = pShip.GetName()
#		DebugPrint(pcShipName + " was destroyed.")
		
		# Get player's set name.
		pPlayer = MissionLib.GetPlayer()
		if pPlayer is None:
			return
		pSet = pPlayer.GetContainingSet()
		if pSet is None:
			return
		pcSet = pSet.GetName()

		# If in Riha Set.
		if pcSet == "Riha1":
			# If ship in Riha enemy group.
			if g_pRihaHostiles.IsNameInGroup(pcShipName):
				# If all enemies destroyed, including reinforcements.
				if(g_bRiha1GalorsArrived and (MissionLib.GetNumObjectsAlive(g_pRihaHostiles) == 0)):
					global g_bRihaSystemDialog
					if not (g_bRihaSystemDialog):
						g_bRihaSystemDialog = 1
#						DebugPrint("Riha system completed.")
						PlayRiha1EndDialogue()
		elif pcSet == "Cebalrai2":
			if pcShipName == "Outpost":
				pSeq = App.TGSequence_Create()
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "CebalraiOutpostDestroyed"))

				if MissionLib.GetNumObjectsAlive(g_pCebalraiHostiles):
					pSeq.AppendAction(App.TGScriptAction_Create(__name__, "CebalraiWinSequence"), 10.0)
				else:
					pSeq.AppendAction(App.TGScriptAction_Create(__name__, "CebalraiWinSequence"), 4.0)

				MissionLib.QueueActionToPlay(pSeq)
		elif pcSet == "Nepenthe1":
			if g_bMissionWon and (MissionLib.GetNumObjectsAlive(g_pNepentheHostiles) == 0):
				MissionWon()

	# We're done.  Let any other handlers for this event handle it.
	pObject.CallNextHandler(pEvent)

################################################################################
#	TractorHandler(pObject, pEvent)
#
#	Tractor beam event handler.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def TractorHandler(pObject, pEvent):
#	debug("TractorHandler() called..")
	if g_bArrivedNepenthe1:
#		debug("In Nepenthe")
		pPlayer = MissionLib.GetPlayer()
		pTarget = pPlayer.GetTarget()
		if pTarget:
#			debug("Target: " + pTarget.GetName())
			if g_pEnemies.IsNameInGroup(pTarget.GetName()):
#				debug("Target in group. Player disovered..")
				# Player is no longer hidden
				QuickFoundOutDialogue()

################################################################################
#	NavPointSelected()
#
#	Handler called when the Nav Point is selected.
#
#	Args:	TGObject	- The TGObject object.
#			pEvent		- The event that was sent.
#
#	Return:	None
################################################################################
def NavPointSelected(pNavMenu, pEvent):
	pNavPoint = App.PlacementObject_Cast(pEvent.GetSource())
	if pNavPoint:
#		debug("NavPointSelected() - " + pNavPoint.GetName())
		if pNavPoint.GetName() == "Center of Asteroid Field":
#			debug("Matching center of field..")
			pPlayer = App.Game_GetCurrentPlayer()
			if pPlayer:
				pPlayer.SetTarget(pNavPoint.GetName())
				import CenterFieldAI
				MissionLib.SetPlayerAI("Helm", CenterFieldAI.CreateAI(pPlayer))
				pNavMenu.Close()
				pSet = App.g_kSetManager.GetSet("bridge")
				if pSet:
					pHelm = App.CharacterClass_GetObject(pSet, "Helm")
					if pHelm:
						App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, pHelm.GetCharacterName() + "Yes1", "Captain", 1, pHelm.GetDatabase()).Play()
#			debug("Returning..")
			return
	
	# All done, pass on the event
	pNavMenu.CallNextHandler(pEvent)

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

	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if pTarget:
		pcName = pTarget.GetName()
		import Bridge.HelmMenuHandlers
		if pcName == "RanKuf":
			pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HailRanKuf"))
			MissionLib.QueueActionToPlay(pSeq)
			return
		elif pcName == "Trayor":
			pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HailBOP2"))
			MissionLib.QueueActionToPlay(pSeq)
			return

	pObject.CallNextHandler(pEvent)

################################################################################
#	ScanHandler(pObject, pEvent)
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

	if (iScanType == App.CharacterClass.EST_SCAN_OBJECT):
		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
			pTarget = pPlayer.GetTarget()
		if pTarget is None:
			pObject.CallNextHandler(pEvent)
			return

		pcTargetName = pTarget.GetName()

		if (pcTargetName == "Freighter 5" or pcTargetName == "Freighter 6") and (g_iMissionProgress >= IN_NEPENTHE):
			pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
			pSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
			if pSeq is None:
				return
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6ScanFreighters", g_pMissionDatabase))
			pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
			pSeq.Play()
			return

	pObject.CallNextHandler(pEvent)

################################################################################
#	WarpHandler(pObject, pEvent)
#
#	Called when the "Warp" button in Kiska's menu is hit.  
#	Prevent player from warping out when it would jeapordize mission.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def WarpHandler(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if g_bMissionLost:
		return

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	pcPlayerSetName = MissionLib.GetPlayer().GetContainingSet().GetName()
	
	if pcPlayerSetName == "Riha1":
		if not g_bRihaWon:
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, 
											"WarpStop1", g_pGeneralDatabase))
			pSeq.Play()
			return
	elif pcPlayerSetName == "Cebalrai2":
		if not g_bCebalraiWon:
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, 
											"WarpStop2", g_pGeneralDatabase))
			pSeq.Play()
			return
	elif pcPlayerSetName == "Nepenthe1":
		pSeq = MissionLib.NewDialogueSequence()
		
		if g_bDataScanning:
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, 
											"E4M6CantLeave", g_pMissionDatabase))
		else:
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, 
											"WarpStop2", g_pGeneralDatabase))
		pSeq.Play()
		return

	pObject.CallNextHandler(pEvent)


################################################################################
#	HailRanKuf(pAction)
#
#	Hail the RanKuf.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def HailRanKuf(pAction):
	if not g_bRihaWon:
		pDraxon = GetDraxon()

		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn",
													"DXBridgeSet", "Draxon"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E4M6HailDraxon1", g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E4M6HailDraxon2", g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		pSeq.Play()

	return 0

################################################################################
#	HailBOP2(pAction)
#
#	Hail BOP2.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def HailBOP2(pAction):
	if not g_bRihaWon:
		pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6HailBOP1", g_pMissionDatabase))
		pSeq.Play()
	
	return 0

################################################################################
#	SetRiha1ShipsAI()
#
#	Set AI for ships in Riha1 region. This is called when the player leaves
#	the Starbase 12 set heading for the Riha system.
#
#	Args:	None
#
#	Return:	None
################################################################################
def SetRiha1ShipsAI():
	pRiha1 = App.g_kSetManager.GetSet("Riha1")
	pGalor1 = MissionLib.GetShip("Galor 1", pRiha1)
	pGalor2 = MissionLib.GetShip("Galor 2", pRiha1)

	pBOP1 = MissionLib.GetShip("RanKuf", pRiha1)
	pBOP2 = MissionLib.GetShip("Trayor", pRiha1)

	pFreighter1 = MissionLib.GetShip("Freighter 1", pRiha1)
	pFreighter2 = MissionLib.GetShip("Freighter 2", pRiha1)
	pFreighter3 = MissionLib.GetShip("Freighter 3", pRiha1)
	pFreighter4 = MissionLib.GetShip("Freighter 4", pRiha1)

	# Apply damage to Galors initially.
	DamageShip(pGalor1, 0.45, 0.75)
	DamageShip(pGalor2, 0.35, 0.45)

	# Disable shields on first Galor.
	pSystem = pGalor1.GetShields()
	if pSystem:
		pSystem.SetConditionPercentage(pSystem.GetDisabledPercentage())
		
	# Riha1 Galors
	# Attack Klingons
	import GalorAI
	if pGalor1:
		pGalor1.SetAI(GalorAI.CreateAI(pGalor1, "RanKuf"))
	if pGalor2:
		pGalor2.SetAI(GalorAI.CreateAI(pGalor2, "Trayor"))

	# Riha1 Klingons
	# Attack Galors
	import KlingonAI

	# Make Klingons invisible.
	# Make warp/impulse engines invincible.
	if pBOP1:
		pBOP1.SetAI(KlingonAI.CreateAI(pBOP1))
		pBOP1.SetInvincible(TRUE)
		MissionLib.MakeEnginesInvincible(pBOP1)
	if pBOP2:
		pBOP2.SetAI(KlingonAI.CreateAI(pBOP2))
		pBOP2.SetInvincible(TRUE)
		MissionLib.MakeEnginesInvincible(pBOP2)
	
	
	# Cebalrai2 transports
	# Set initial freighters AI.
	# Freighters begin to flee.
	import FreighterFleeAI

	if pFreighter1:
		pFreighter1.SetAI(FreighterFleeAI.CreateAI(pFreighter1))
	if pFreighter2:
		pFreighter2.SetAI(FreighterFleeAI.CreateAI(pFreighter2))
	if pFreighter3:
		pFreighter3.SetAI(FreighterFleeAI.CreateAI(pFreighter3))
	if pFreighter4:
		pFreighter4.SetAI(FreighterFleeAI.CreateAI(pFreighter4))

################################################################################
#	PlayerArrivedRiha1()
#
#	Handle player entering Riha 1 for the first time.
#
#	Args:	None
#
#	Return:	None
################################################################################
def PlayerArrivedRiha1():
	# Set flag.
	global g_bArrivedRiha1
	g_bArrivedRiha1 = TRUE
	
	RihaIntroDialogue()
	MissionLib.RemoveGoal("E4GoToRihaGoal")

	#MissionLib.SaveGame("E4M1-Riha-")

################################################################################
#	PlayerArrivedCebalrai2()
#
#	Handle player entering Cebalrai 2 for the first time.
#
#	Args:	None
#
#	Return:	None
################################################################################
def PlayerArrivedCebalrai2():
	# Set flag.
	global g_bArrivedCebalrai2
	g_bArrivedCebalrai2 = TRUE

	MissionLib.RemoveGoal("E4GoToCebalraiGoal")

	MissionLib.SaveGame("E4M1-Cebalrai-")

	SetCebalraiFreighterAI()
	Cebalrai2IntroDialogue()
	
################################################################################
#	PlayerArrivedNepenthe1()
#
#	Handle player entering Nepenthe 1 for the first time.
#
#	Args:	None
#
#	Return:	None
################################################################################
def PlayerArrivedNepenthe1():
#	DebugPrint("PlayerArrivedNepenthe1() called.")

	global g_bArrivedNepenthe1
	g_bArrivedNepenthe1 = TRUE

	MissionLib.RemoveGoal("E4GoToNepentheGoal")
	
	SetMissionProgress(None, IN_NEPENTHE)

	# Create freighters that escaped from Cebalrai.
	pNepenthe1 = App.g_kSetManager.GetSet("Nepenthe1")
	loadspacehelper.CreateShip("CardFreighter", pNepenthe1,
											"Freighter 5", "Freighter5 Start" )
	loadspacehelper.CreateShip("CardFreighter", pNepenthe1, 
											"Freighter 6", "Freighter6 Start" )
	
	# Init proximity checks for freighters.
	InitFreighterProxChecks()

	# Add tractor handler for enemy ships.
	pMission = MissionLib.GetMission()
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STARTED_HITTING, 
											pMission, __name__ + ".TractorHandler")

	# Setup event handlers so freighters warp out if fired on.
	pFreighter5 = MissionLib.GetShip("Freighter 5")
	if pFreighter5:
		pFreighter5.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
												".PlayerFired")
	pFreighter6 = MissionLib.GetShip("Freighter 6")
	if pFreighter6:
		pFreighter6.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
												".PlayerFired")

	MissionLib.SaveGame("E4M1-Nepenthe-")

	# Tell the player about the asteroids and create a nav point.
	TalkAboutRadiation()

	
################################################################################
#	CebalraiOutpostDestroyed(pAction)
#
#	Play dialogue when outpost in Cebalrai system is destroyed.
#	Add Cebalrai win sequence if all enemies destroyed.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CebalraiOutpostDestroyed(pAction):
	MissionLib.RemoveGoal("E4DestroyOutpostGoal")

	# If any Galors left after outpost destroyed.
	if MissionLib.GetNumObjectsAlive(g_pCebalraiHostiles):
		# Set galors to warp out.
		import WarpOutAI
		pGalor1 = MissionLib.GetShip("Galor 1")
		if pGalor1:
			pWarp = pGalor1.GetWarpEngineSubsystem()
			if pWarp and not pWarp.IsDisabled():
				pGalor1.SetAI(WarpOutAI.CreateAI(pGalor1))

		pGalor2 = MissionLib.GetShip("Galor 2")
		if pGalor2:
			pWarp = pGalor2.GetWarpEngineSubsystem()
			if pWarp and not pWarp.IsDisabled():
				pGalor2.SetAI(WarpOutAI.CreateAI(pGalor2))

	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6CebelraiOutpostDestroyed",
													g_pMissionDatabase))
	MissionLib.QueueActionToPlay(pSeq)

	return 0

################################################################################
#	InZone(pObject, pEvent)
#
#	Called by an event whenever the player enters the zone
#
#	Args:	None
#
#	Return:	None
################################################################################
def InZone(pObject, pEvent):
	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

	if(not g_bPlayerFound):
		# Make Kiska stay
		# First, check who's controlling the player's ship.  
		# We only want to override if it's not "Captain" or ourselves.
		if MissionLib.GetPlayerShipController() not in ("Captain", __name__):
			# Someone else is controlling the player's ship.  
			# Override their AI with our custom Stay AI.
			pPlayer = App.Game_GetCurrentPlayer()
			if pPlayer:
				import JustStayAI
				MissionLib.SetPlayerAI(__name__, JustStayAI.CreateAI(pPlayer))

		if(g_bPlayerInZone == 0):
			# Set flag.
			global g_bPlayerInZone
			g_bPlayerInZone = TRUE
			
			MissionLib.RemoveGoal("E4HideInAsteroidFieldGoal")

			pBridge = App.g_kSetManager.GetSet("bridge")
			pSci = App.CharacterClass_GetObject(pBridge, "Science")
			pInZone = App.CharacterAction_Create(pSci, App.CharacterAction.AT_SAY_LINE,
								"E4M6NepentheLowerShields4", "Captain", 1, g_pMissionDatabase)
			MissionLib.QueueActionToPlay(pInZone)


################################################################################
#	OutZone(pObject, pEvent)
#
# 	Called by an event whenever the player leaves the zone
#
#	Args:	None
#
#	Return:	None
################################################################################
def OutZone(pObject, pEvent):
	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

	if (g_bPlayerInZone == 0):
		return
	global g_bPlayerInZone
	g_bPlayerInZone = 0

	if not g_bPlayerFound:
		#Tell the player we're out
		pBridge = App.g_kSetManager.GetSet("bridge")
		pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
		pOutZone = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE,
							"E4M6NepentheLowerShields5", "Captain", 1, g_pMissionDatabase)
		pOutZone.Play()
		
		if g_iMissionProgress != INTERCEPTED_COMM and not g_bPlayerInZone:
			MissionLib.AddGoal("E4HideInAsteroidFieldGoal")
		
################################################################################
#	NepentheFreightersWarpOut(pObject, pEvent)
#
# 	Called by an event either when the player gets close to the Freighters
#	or fires on them. Freighters warp out of the system(to nowhere).
#
#	Args:	None
#
#	Return:	None
################################################################################
def NepentheFreightersWarpOut(pObject = None, pEvent = None):
	pFreighter5 = MissionLib.GetShip("Freighter 5")	
	pFreighter6 = MissionLib.GetShip("Freighter 6")
	
	# If called from proximity event.
	if pObject or pEvent:
		# Set discovered flag.
		global g_bPlayerFound
		g_bPlayerFound = TRUE
#		DebugPrint("E4M6.NepentheFreightersWarpOut() - Player Found!")
#		DebugPrint("g_bPlayerFound = " + str(g_bPlayerFound))

	# Remove proximity check.
	if g_idFreighterProx != App.NULL_ID:
		pProx = App.ProximityCheck_Cast(App.TGObject_GetTGObjectPtr(g_idFreighterProx))
		if pProx:
			pProx.RemoveAndDelete()
		global g_idFreighterProx
		g_idFreighterProx = App.NULL_ID

	# Abort sequence
	global g_iCommSequenceID
	pInterruptSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_iCommSequenceID))
	if (pInterruptSequence):
		pInterruptSequence.Skip()
		g_iCommSequenceID = App.NULL_ID

		MissionLib.ViewscreenOff(None, 0)

	if pFreighter5:
		import WarpOutAI
		pFreighter5.SetAI(WarpOutAI.CreateAI(pFreighter5))

	if pFreighter6:
		import WarpOutAI
		pFreighter6.SetAI(WarpOutAI.CreateAI(pFreighter6))


################################################################################
#	GetLiu()
#
#	Return the Liu character from the her set.
#
#	Args:	None
#
#	Return:	pLiu, Character object.
################################################################################
def GetLiu():
	pSet = App.g_kSetManager.GetSet("LiuSet")
	assert pSet
	if(pSet is None):
		return None
	return App.CharacterClass_GetObject(pSet, "Liu")
	
################################################################################
#	GetData()
#
#	Return the Data character from the bridge set.
#
#	Args:	None
#
#	Return:	pData, Character object.
################################################################################
def GetData():
	pSet = App.g_kSetManager.GetSet("bridge")
	assert pSet
	if(pSet is None):
		return None
	return App.CharacterClass_GetObject(pSet, "Data")

################################################################################
#	GetDraxon()
#
#	Return the Draxon character from the bridge set.
#
#	Args:	None
#
#	Return:	pDraxon, Character object.
################################################################################
def GetDraxon():
	pSet = App.g_kSetManager.GetSet("DXBridgeSet")
	assert pSet
	if(pSet is None):
		return None
	return App.CharacterClass_GetObject(pSet, "Draxon")

################################################################################
#	StartKiskaLog(pAction = None)
#
#	Play Kiska's log, introduction sequence.
#	Check's to see if player is currently in warp. If so call ourselves later.
#
#	Args:	None
#
#	Return:	None
################################################################################
def StartKiskaLog(pAction = None):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pWarp = pPlayer.GetWarpEngineSubsystem()
		if pWarp is None:
			return 0
			
		# If player is still in warp.
		if MissionLib.IsPlayerWarping():
			# Retry sequence in 1 second.
			pSeq = App.TGSequence_Create()
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartKiskaLog"), 1.0)
			pSeq.Play()
			return 0

	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", "Starbase12"))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraBegin", "Starbase12"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
									"DropAndWatch", "Starbase12", "player"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeOut", 0))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeIn", 3))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EpisodeTitleAction", "Ep4Title"))

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SubtitledLine", 
												g_pMissionDatabase, "E4M6Log1", "Kiska"), 3)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SubtitledLine", 
												g_pMissionDatabase, "E4M6Log2", "Kiska"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraEnd", "Starbase12"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"PlacementWatch", "bridge", "Kiska Head", "Kiska Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", "bridge"))	
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SubtitledLine", 
												g_pMissionDatabase, "E4M6Log3", "Kiska"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SubtitledLine", 
												g_pMissionDatabase, "E4M6Log5", "Kiska"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MissionBriefing"))
	MissionLib.QueueActionToPlay(pSeq)

	return 0

################################################################################
#	MissionBriefing(pAction)
#
#	Play mission briefing dialogue.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def MissionBriefing(pAction):
	# Set flag.
	global g_bBriefingPlayed
	g_bBriefingPlayed = TRUE
	
	pEpisodeDatabase = MissionLib.GetEpisode().GetDatabase()
	pLiu = GetLiu()
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSequence = MissionLib.NewDialogueSequence()
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", "bridge"))	
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4BriefingHail",
														pEpisodeDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
												"LiuSet", "Liu"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4BriefingLiu1",
														pEpisodeDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4BriefingLiu2",
														pEpisodeDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4BriefingLiu3",
														pEpisodeDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4BriefingLiu4",
														pEpisodeDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4BriefingLiu5",
														pEpisodeDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4BriefingLiu6",
														pEpisodeDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "OpenRiha"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	MissionLib.QueueActionToPlay(pSequence)

	return 0

################################################################################
#	RihaIntroDialogue()
#
#	Play dialogue upon entering the Riha system.
#
#	Args:	None
#
#	Return:	None
################################################################################
def RihaIntroDialogue():
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AddAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6Riha1", 
												g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6Riha2", 
												g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6Riha3", 
												g_pMissionDatabase, 1, "S"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RihaFreightersWarpToCebalrai"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6Riha4", 
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", FREIGHTERS_ESCAPE))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "CreateRiha1Galors"))												
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6Riha5", 
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E4AssistKlingonsGoal"))
	MissionLib.QueueActionToPlay(pSeq)
	
################################################################################
#	RihaFreightersWarpToCebalrai(pAction)
#
#	Give Riha freighters AI to warp to Cebalrai.
#
#	Args:	pAction, the Action.
#
#	Return:	None
################################################################################
def RihaFreightersWarpToCebalrai(pAction):
	# Set freighters AI.
	# Freighters warp out immediately.
	import RihaFreighterWarpAI
	pFreighter1 = MissionLib.GetShip("Freighter 1")
	pFreighter2 = MissionLib.GetShip("Freighter 2")
	pFreighter3 = MissionLib.GetShip("Freighter 3")
	pFreighter4 = MissionLib.GetShip("Freighter 4")
	
	if pFreighter1:
		pFreighter1.SetAI(RihaFreighterWarpAI.CreateAI(pFreighter1, "Freighter1 Start"))
	if pFreighter2:
		pFreighter2.SetAI(RihaFreighterWarpAI.CreateAI(pFreighter2, "Freighter2 Start"))
	if pFreighter3:
		pFreighter3.SetAI(RihaFreighterWarpAI.CreateAI(pFreighter3, "Freighter3 Start"))
	if pFreighter4:
		pFreighter4.SetAI(RihaFreighterWarpAI.CreateAI(pFreighter4, "Freighter4 Start"))
	
	return 0

################################################################################
#	RihaFreightersWarpOut(pAction)
#
#	Give Riha freighters(Now in Cebalrai 2) AI to warp out.
#
#	Args:	pAction, the Action.
#
#	Return:	None
################################################################################
def RihaFreightersWarpOut(pAction):
	# Set freighters AI.
	# Freighters warp out immediately.
	import RihaFreighterWarp2AI
	pFreighter1 = MissionLib.GetShip("Freighter 1")
	pFreighter2 = MissionLib.GetShip("Freighter 2")
	pFreighter3 = MissionLib.GetShip("Freighter 3")
	pFreighter4 = MissionLib.GetShip("Freighter 4")
	
	if pFreighter1:
		pFreighter1.SetAI(RihaFreighterWarp2AI.CreateAI(pFreighter1))
	if pFreighter2:
		pFreighter2.SetAI(RihaFreighterWarp2AI.CreateAI(pFreighter2))
	if pFreighter3:
		pFreighter3.SetAI(RihaFreighterWarp2AI.CreateAI(pFreighter3))
	if pFreighter4:
		pFreighter4.SetAI(RihaFreighterWarp2AI.CreateAI(pFreighter4))
	
	return 0
	
################################################################################
#	SetCebalraiShipsAI(pAction)
#
#	Setup AI for all ships in region.
#	Station and Keldon attack player.
#	Cebalrai freighters AI to flee.
#
#	Args:	pAction, the Action.
#
#	Return:	None
################################################################################
def SetCebalraiShipsAI(pAction):
	# Outpost AI.
	import OutpostAI
	pStation = MissionLib.GetShip("Outpost")
	if pStation:
		pStation.SetAI(OutpostAI.CreateAI(pStation))

	# Cebalrai2 Galor AI.
	import AttackPlayerAI
	pGalor1 = MissionLib.GetShip("Galor 1")
	if pGalor1:
		pGalor1.SetAI(AttackPlayerAI.CreateAI(pGalor1))

	pGalor2 = MissionLib.GetShip("Galor 2")
	if pGalor2:
		pGalor2.SetAI(AttackPlayerAI.CreateAI(pGalor2))

	return 0
	
################################################################################
#	CebalraiFreightersWarpOut(pAction)
#
#	Give Cebalrai freighters AI to warp out.
#
#	Args:	pAction, the Action.
#
#	Return:	None
################################################################################
def CebalraiFreightersWarpOut(pAction):
	# Set freighters AI.
	# Freighters warp out immediately.
	pFreighter5 = MissionLib.GetShip("Freighter 5")
	pFreighter6 = MissionLib.GetShip("Freighter 6")
	
	import WarpOutAI
	if pFreighter5:
		pFreighter5.SetAI(WarpOutAI.CreateAI(pFreighter5))
	if pFreighter6:
		pFreighter6.SetAI(WarpOutAI.CreateAI(pFreighter6))
	
	return 0
	
################################################################################
#	CreateRiha1Galors(pAction)
#
#	Create Galors that warp into Riha 1.
#
#	Args:	pAction, the Action.
#
#	Return:	None
################################################################################
def CreateRiha1Galors(pAction):
	pRiha1 = App.g_kSetManager.GetSet("Riha1")

	pGalor3 = loadspacehelper.CreateShip("Galor", pRiha1, "Galor 3", "Galor3 Start")
	pGalor4 = loadspacehelper.CreateShip("Galor", pRiha1, "Galor 4", "Galor4 Start")
	pGalor5 = loadspacehelper.CreateShip("Galor", pRiha1, "Galor 5", "Galor5 Start")
											
	# Give the ships AI
	import Galor2AI
	import Galor3AI

	if pGalor3:
		pGalor3.SetAI(Galor3AI.CreateAI(pGalor3))
	if pGalor4:
		pGalor4.SetAI(Galor2AI.CreateAI(pGalor4, "player"))
	if pGalor5:
		pGalor5.SetAI(Galor2AI.CreateAI(pGalor5, "player"))
	
	return 0

################################################################################
#	SetCebalraiFreighterAI()
#
# 	Set AI for freighters in Cebalrai 2 to flee.
#
#	Args:	None
#
#	Return:	None
################################################################################
def SetCebalraiFreighterAI():
	# Freighter flee AI.
	import FreighterFleeAI
	pFreighter1 = MissionLib.GetShip("Freighter 1")
	pFreighter2 = MissionLib.GetShip("Freighter 2")
	pFreighter3 = MissionLib.GetShip("Freighter 3")
	pFreighter4 = MissionLib.GetShip("Freighter 4")
	pFreighter5 = MissionLib.GetShip("Freighter 5")
	pFreighter6 = MissionLib.GetShip("Freighter 6")
	
	if pFreighter1:
		pFreighter1.SetAI(FreighterFleeAI.CreateAI(pFreighter1))
	if pFreighter2:
		pFreighter2.SetAI(FreighterFleeAI.CreateAI(pFreighter2))
	if pFreighter3:
		pFreighter3.SetAI(FreighterFleeAI.CreateAI(pFreighter3))
	if pFreighter4:
		pFreighter4.SetAI(FreighterFleeAI.CreateAI(pFreighter4))
	if pFreighter5:
		pFreighter5.SetAI(FreighterFleeAI.CreateAI(pFreighter5))
	if pFreighter6:
		pFreighter6.SetAI(FreighterFleeAI.CreateAI(pFreighter6))

################################################################################
#	Cebalrai2IntroDialogue()
#
# 	The introduction to what is going on that is played when you get to Cebalrai2
#
#	Args:	None
#
#	Return:	None
################################################################################
def Cebalrai2IntroDialogue():
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraBegin", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
												"ChangeRenderedSet", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"DropAndWatch", "Cebalrai2", "Outpost"))	
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6Cebelrai1",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
												"ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					  "SetViewscreenCamera", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
							"WatchShipLeave", "Cebalrai2", "Freighter 4"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RihaFreightersWarpOut"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6Cebelrai2",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraEnd", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraBegin", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					  "SetViewscreenCamera", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
												"ChangeRenderedSet", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
												"DropAndWatch", "Cebalrai2", "Freighter 5"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6Cebelrai3",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
												"ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6Cebelrai5",
												g_pMissionDatabase))
	# Watch the freighter leave.
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
							"WatchShipLeave", "Cebalrai2", "Freighter 5"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
							"PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6Cebelrai6",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "CebalraiFreightersWarpOut"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6Cebelrai7",
												g_pMissionDatabase), 3.0)											
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"PlacementWatch", "bridge", "Kiska Head", "Kiska Cam"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6Cebelrai8",
												g_pMissionDatabase))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6Cebelrai9",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction",
												"E4DestroyOutpostGoal"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
												"CutsceneCameraEnd", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					  "SetViewscreenCamera", "Cebalrai2"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "Outpost"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6Cebelrai9b",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetCebalraiShipsAI"), 5)
	MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	SetRihaWinFlag(pAction)
#
# 	Set flag allowing player to warp to next system.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def SetRihaWinFlag(pAction):
	global g_bRihaWon
	g_bRihaWon = TRUE

	return 0
	
################################################################################
#	PlayRiha1EndDialogue()
#
# 	Play dialogue in Riha 1 where Klingons thank player for help.
#
#	Args:	None
#
#	Return:	None
################################################################################
def PlayRiha1EndDialogue():
	pDraxon = GetDraxon()
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RemoveGoalAction",
												"E4AssistKlingonsGoal"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "IncomingMsg4",
															g_pGeneralDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
												"DXBridgeSet", "Draxon"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E4M6Riha7",
														g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6Riha8",
														g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E4M6Riha9",
														g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "KlingonsLeave"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetRihaWinFlag"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6Riha10",
														g_pMissionDatabase, 1, "S"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6Riha11",
														g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "OpenCebalrai"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", FREIGHTERS_IN_CEBALRAI))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProd"))
	MissionLib.QueueActionToPlay(pSeq)
	
	
################################################################################
#	CebalraiWinSequence(pAction)
#
# 	Cebalrai system objectives completed. 
#	Play dialogue with Korbus opening up E4M4.
#	Open up Nepenthe system.
#
#	Args:	None
#
#	Return:	pSeq, the sequence.
################################################################################
def CebalraiWinSequence(pAction):
	global g_bCebalraiWon
	g_bCebalraiWon = TRUE
	
	# Play dialogue where Korbus hails the Player and opens up E4M4.
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6Cebelrai10",
												g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6Cebelrai10a",
												g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6Cebelrai10b",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SubtitledLine",
											g_pMissionDatabase, "E4M6Cebelrai11", "Korbus"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SubtitledLine",
											g_pMissionDatabase, "E4M6Cebelrai11a", "Korbus"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6Cebelrai11b",
												g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6NepentheSetup",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "OpenNepenthe"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "OpenBelaruz"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", MISSION_BRANCH))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProd"))
	MissionLib.QueueActionToPlay(pSeq)

	return 0


################################################################################
#	KlingonsLeave(pAction)
#
# 	After Riha is won, change Klingons AI to warp out.
#
#	Args:	None
#
#	Return:	None
################################################################################
def KlingonsLeave(pAction):
	pBOP1 = MissionLib.GetShip("RanKuf")
	pBOP2 = MissionLib.GetShip("Trayor")
	
	import KlingonLeaveAI
	
	# Cloak ships and warp them out.
	if pBOP1:
		MissionLib.Cloak(None, pBOP1)		
		pBOP1.SetAI(KlingonLeaveAI.CreateAI(pBOP1))
	if pBOP2:
		MissionLib.Cloak(None, pBOP2)		
		pBOP2.SetAI(KlingonLeaveAI.CreateAI(pBOP2))
		
	return 0
	
################################################################################
#	StartProd(pAction = None)
#
# 	Decide which prods to use and sets the timer accordingly
#
#	Args:	None
#
#	Return:	None
################################################################################
def StartProd(pAction = None):
	# Get the current game time.
	fStartTime = App.g_kUtopiaModule.GetGameTime()

	if ((g_bCebalraiWon == 0) and (g_bRihaWon == 1)):
		# We need to go to Cebalrai
		MissionLib.CreateTimer(ET_CEBALRAI_PROD, __name__ + ".ProdToCebalrai", 
								fStartTime + 60, 0, 0)

	elif ((g_bCebalraiWon == 1) and (g_bRihaWon == 1)):
		# Player can move on
		if (g_bNepentheWon == 0):
			MissionLib.CreateTimer(ET_BRANCH_PROD, __name__ + ".ProdToBranch", 
									fStartTime + 60, 0, 0)

	return 0

################################################################################
#	ProdToCebalrai(TGObject, pEvent)
#
#	Prod the player to go to Cebalrai
#
#	Args:	None
#
#	Return:	None
################################################################################
def ProdToCebalrai(TGObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	# Make sure prod is needed.
	if(g_bArrivedCebalrai2):
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer.GetContainingSet().GetName() == "Riha1":
		# Say the line
		pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
		pSaffiProds = Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6ProdToCebalrai", 
													g_pMissionDatabase)
		pSaffiProds.Play()

		# Call prod function to start timer again.
		StartProd()

################################################################################
#	ProdToBranch(TGObject, pEvent)
#
#	Prod the player to go to either Nepenthe(E4M6) or Belaruz(E4M4).
#
#	Args:	None
#
#	Return:	None
################################################################################
def ProdToBranch(TGObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	# Make sure prod is needed.
	if(g_bArrivedNepenthe3):
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer.GetContainingSet().GetName() == "Cebalrai2":
		# Say the line
		pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
		pSaffiProds = Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6ProdToBranch", 
													g_pMissionDatabase)
		pSaffiProds.Play()

		# Call prod function to start timer again.
		StartProd()

################################################################################
#	OpenRiha(pAction)
#
#	Open the Riha system.
#
#	Args:	None
#
#	Return:	None
################################################################################
def OpenRiha(pAction):
	# Make Riha system available in warp menu.
	import Systems.Riha.Riha
	App.SortedRegionMenu_SetPauseSorting(TRUE)
	Systems.Riha.Riha.CreateMenus()
	App.SortedRegionMenu_SetPauseSorting(FALSE)

	# Link Riha 1 button to player start placement.
	MissionLib.LinkMenuToPlacement("Riha", None, "Player Start Riha1")

	# Add goal.
	MissionLib.AddGoal("E4GoToRihaGoal", "E4InvestigateAreaGoal")

	return 0
	
	
################################################################################
#	OpenCebalrai(pAction)
#
#	Open the Cebalrai system.
#
#	Args:	None
#
#	Return:	None
################################################################################
def OpenCebalrai(pAction):
	# Make Cebalrai system available in warp menu.
	import Systems.Cebalrai.Cebalrai
	App.SortedRegionMenu_SetPauseSorting(TRUE)
	pCebalrai = Systems.Cebalrai.Cebalrai.CreateMenus()
	App.SortedRegionMenu_SetPauseSorting(FALSE)
	pCebalrai.SetRegionName("Systems.Cebalrai.Cebalrai2")
	
	# Link Cebalrai 2 button to player start placement.
	MissionLib.LinkMenuToPlacement("Cebalrai", None, "Player Start Cebalrai2")
	
	# Add goal.
	MissionLib.AddGoal("E4GoToCebalraiGoal")

	return 0

################################################################################
#	OpenBelaruz(pAction)
#
#	Open the Belaruz system(E4M4).
#
#	Args:	pAction, the action.
#
#	Return:	None
################################################################################
def OpenBelaruz(pAction):
	# Link the Celi system to the next mission
	import Systems.Belaruz.Belaruz
	App.SortedRegionMenu_SetPauseSorting(TRUE)
	pMenu = Systems.Belaruz.Belaruz.CreateMenus()
	App.SortedRegionMenu_SetPauseSorting(FALSE)
	
	# Set the mission name for the button
	pMenu.SetMissionName("Maelstrom.Episode4.E4M4.E4M4")
	
	# Create the goal
	MissionLib.AddGoal("E4GoToBelaruzGoal")
	
	return 0

################################################################################
#	OpenNepenthe(pAction)
#
#	Open the Nepenthe system.
#
#	Args:	pAction, the action.
#
#	Return:	None
################################################################################
def OpenNepenthe(pAction):
	# Make Nepenthe system available in warp menu.
	import Systems.Nepenthe.Nepenthe
	App.SortedRegionMenu_SetPauseSorting(TRUE)
	pNepenthe = Systems.Nepenthe.Nepenthe.CreateMenus()
	App.SortedRegionMenu_SetPauseSorting(FALSE)
	pNepenthe.SetRegionName("Systems.Nepenthe.Nepenthe1")
	
	MissionLib.LinkMenuToPlacement("Nepenthe", None, "Player Start")

	# Create the goal
	MissionLib.AddGoal("E4GoToNepentheGoal")

	return 0

################################################################################
#	TalkAboutRadiation()
#
#	Tell the player about the radiation in the set and create a nav point.
#
#	Args:	None
#
#	Return:	None
################################################################################
def TalkAboutRadiation():
#	DebugPrint("TalkAboutRadiation() called.")

	# Say the lines
	pData = GetData()
	pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSequence = MissionLib.NewDialogueSequence()
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M6NepentheArrival2", 
											g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6NepentheArrival2a", 
											g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6NepentheArrival2b", 
											g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6NepentheArrival2c", 
											g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData,"E4M6NepentheArrival3",
											g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pXO,"E4M6NepentheArrival3b",
											g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska,"E4M6NepentheArrival4",
											g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CreateNavPoint"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "InitProxChecks"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CreateNepentheTimers"), 5.0)
	pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
	pSequence.AppendAction(pAction)

	# Set global pointer to sequence.
	global g_iCommSequenceID
	g_iCommSequenceID = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)


#
# ResetInterrupt()
#
def ResetInterrupt(pAction = None):

	global g_iCommSequenceID
	g_iCommSequenceID = App.NULL_ID

	return 0


################################################################################
#	CreateNavPoint(pAction)
#
#	Create Nav point to direct player to center of asteroid field.
#	Add goal.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def CreateNavPoint(pAction):
#	DebugPrint("CreateNavPoint() called.")	

	# Create waypoint at zone center
	MissionLib.AddNavPoints("Nepenthe1", "Center of Asteroid Field")
	pPlayer = MissionLib.GetPlayer()
	pPlayer.SetTarget("Center of Asteroid Field")

	if not g_bPlayerInZone:
		MissionLib.AddGoal("E4HideInAsteroidFieldGoal")
	
	return 0
	
################################################################################
#	ChangeShipAI(pAction)
#
#	This changes all ship AI to attack the player
#
#	Args:	None
#
#	Return:	None
################################################################################
def ChangeShipAI(pAction):
#	DebugPrint("Calling ChangeShipAI")

	# The Galors attack the player
	pGalor1 = App.ShipClass_GetObject(App.SetClass_GetNull(), "Galor 1")
	pGalor2 = App.ShipClass_GetObject(App.SetClass_GetNull(), "Galor 2")
	pKeldon1 = App.ShipClass_GetObject(App.SetClass_GetNull(), "Matan")

	import AttackPlayerAI
	if pGalor1:
		pGalor1.SetAI(AttackPlayerAI.CreateAI(pGalor1))
	if pGalor2:
		pGalor2.SetAI(AttackPlayerAI.CreateAI(pGalor2))
	
	# The ambassador and Matan run.
	pKessokAmbassador = MissionLib.GetShip("Strange Ship")
	import KessokAmbassadorAI
	if pKessokAmbassador:
		pKessokAmbassador.SetAI(KessokAmbassadorAI.CreateAI(pKessokAmbassador))

	import WarpOutAI
	if pKeldon1:
		pKeldon1.SetAI(WarpOutAI.CreateAI(pKeldon1))

	# Turn the Kessok into enemies on the targeting list
	g_pEnemies.AddName("Strange Ship")

	# Get the freighters to warp out.
	NepentheFreightersWarpOut()

	return 0

################################################################################
#	CreateNepentheTimers(pAction)
#
#	Create timers for Nepenthe events, dialogue, ships enetring, etc.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateNepentheTimers(pAction):
#	DebugPrint("CreateNepentheTimers() called.")
		
	fStartTime = App.g_kUtopiaModule.GetGameTime()

	pTimer = MissionLib.CreateTimer(ET_GALOR1_ARRIVES, __name__ + ".Galor1WarpsIn", 
							fStartTime + 30, 0, 0)
	# Store off the timer ID
	global g_idGalor1Timer
	g_idGalor1Timer = pTimer.GetObjID()

	pTimer = MissionLib.CreateTimer(ET_GALOR2_ARRIVES, __name__ + ".Galor2WarpsIn", 
							fStartTime + 35, 0, 0)

	# Store off the timer ID
	global g_idGalor2Timer
	g_idGalor2Timer = pTimer.GetObjID()

	pTimer = MissionLib.CreateTimer(ET_KELDON1_ARRIVES, __name__ + ".Keldon1WarpsIn", 
							fStartTime + 65, 0, 0)
	# Store off the timer ID
	global g_idKeldonTimer
	g_idKeldonTimer = pTimer.GetObjID()

	pTimer = MissionLib.CreateTimer(ET_KESSOK_ARRIVE, __name__ + ".KessokWarpIn", 
							fStartTime + 70, 0, 0)
	# Store off the timer ID
	global g_idKessokTimer
	g_idKessokTimer = pTimer.GetObjID()

	return 0

################################################################################
#	KillNepentheTimers()
#
#	Kill timers for Nepenthe events, dialogue, ships enetring, etc.
#
#	Args:	None
#
#	Return:	None
################################################################################
def KillNepentheTimers():
	global g_idGalor1Timer
	if g_idGalor1Timer != App.NULL_ID:
		App.g_kTimerManager.DeleteTimer(g_idGalor1Timer)
		g_idGalor1Timer = App.NULL_ID

	global g_idGalor2Timer
	if g_idGalor2Timer != App.NULL_ID:
		App.g_kTimerManager.DeleteTimer(g_idGalor2Timer)
		g_idGalor2Timer = App.NULL_ID

	global g_idKeldonTimer
	if g_idKeldonTimer != App.NULL_ID:
		App.g_kTimerManager.DeleteTimer(g_idKeldonTimer)
		g_idKeldonTimer = App.NULL_ID

	global g_idKessokTimer
	if g_idKessokTimer != App.NULL_ID:
		App.g_kTimerManager.DeleteTimer(g_idKessokTimer)
		g_idKessokTimer = App.NULL_ID

################################################################################
#	IncomingWarning()
#
#	Tell the player the Galors are coming
#
#	Args:	None
#
#	Return:	None
################################################################################
def IncomingWarning():
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	
	pSequence = MissionLib.NewDialogueSequence()

	if App.TopWindow_GetTopWindow().IsBridgeVisible():
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "Galor 1"))

	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", ENEMY_ARRIVED))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6NepentheLowerShields1a", 
													g_pMissionDatabase))

	if(not IsPoweredDown()):
		# Ask player to power down.
		pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M6NepentheLowerShields2",
														g_pMissionDatabase))
		pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6NepentheLowerShields2a",
														g_pMissionDatabase))
		pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6NepentheLowerShields3b",
														g_pMissionDatabase))
	else:
		# Tell player to stay powered down.
		pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M6NepentheShieldsDown",
														g_pMissionDatabase))

	pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
	pSequence.AppendAction(pAction)

	# Set global pointer to sequence.
	global g_iCommSequenceID
	g_iCommSequenceID = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)


################################################################################
#	Galor1WarpsIn(TGObject, pEvent)
#
#	Create the first Galor
#
#	Args:	None
#
#	Return:	None
################################################################################
def Galor1WarpsIn(TGObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Galor1WarpsIn() called.")
	
	if g_bPlayerFound:
		return

	pNepenthe1 = App.g_kSetManager.GetSet("Nepenthe1")

	# Create ships
	pGalor1 = loadspacehelper.CreateShip("Galor", pNepenthe1, 
										"Galor 1", "Galor1 Warp", TRUE)
	
	# Create Galor1's AI.
	import E4M6Galor1AI
	if pGalor1:
		pGalor1.SetAI(E4M6Galor1AI.CreateAI(pGalor1))

	# Warn the player of new ship.	
	IncomingWarning()

	# Make sure this ship isn't attacked
	pGalor1.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
											".PlayerFired")

################################################################################
#	Galor2WarpsIn(TGObject, pEvent)
#
#	Create the second Galor
#
#	Args:	None
#
#	Return:	None
################################################################################
def Galor2WarpsIn(TGObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Galor2WarpsIn() called.")
	
	if g_bPlayerFound:
		return

	pNepenthe1 = App.g_kSetManager.GetSet("Nepenthe1")

	# Create ships
	pGalor2 = loadspacehelper.CreateShip("Galor", pNepenthe1, 
										"Galor 2", "Galor2 Warp", TRUE)

	import E4M6Galor2AI
	if pGalor2:
		pGalor2.SetAI(E4M6Galor2AI.CreateAI(pGalor2))

	# Make sure this ship isn't attacked
	pGalor2.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
											".PlayerFired")

################################################################################
#	Keldon1WarpsIn(TGObject, pEvent)
#
#	Create Matan.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Keldon1WarpsIn(TGObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Keldon1WarpsIn() called.")
	
	if g_bPlayerFound:
		return

	ResetInterrupt()

	pNepenthe1 = App.g_kSetManager.GetSet("Nepenthe1")

	# Create ships
	pKeldon1 = loadspacehelper.CreateShip("Keldon", pNepenthe1, 
											"Matan", "Keldon1 Warp", TRUE)
	
	# Create Keldon1's AI.
	import E4M6Keldon1AI
	if pKeldon1:
		pKeldon1.SetAI(E4M6Keldon1AI.CreateAI(pKeldon1))

	# Make sure this ship isn't attacked
	pKeldon1.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
											".PlayerFired")

	# Get player system status.
	bPoweredDown = IsPoweredDown()
			
	# If in asteroid field and powered down.
	if(g_bPlayerInZone and bPoweredDown):
		# Tell the player that he wasn't discovered
		pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
		pSafeLine = Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6NepentheLowerShields3",
													g_pMissionDatabase)
		pSafeLine.Play()
		App.TGScriptAction_Create(__name__, "PlayFanfare").Play()
	else:
		QuickFoundOutDialogue()		

################################################################################
#	KessokWarpIn(TGObject, pEvent)
#
#	Create the Strange Ship
#
#	Args:	None
#
#	Return:	None
################################################################################
def KessokWarpIn(TGObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("KessokWarpIn() called.")

	if g_bPlayerFound:
		return

	pNepenthe1 = App.g_kSetManager.GetSet("Nepenthe1")

	# Create ships
	pKessok = loadspacehelper.CreateShip("KessokLight", pNepenthe1, 
								"Strange Ship", "KessokAmbassador", TRUE)
	
	# Make sure this ship isn't attacked
	pKessok.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, 
														__name__ + ".PlayerFired")

################################################################################
#	PlayerFired(pObject, pEvent)
#
#	Called whenever player fires on a specific ship.
#
#	Args:	None
#
#	Return:	None
################################################################################
def PlayerFired(pObject, pEvent):
	if g_bMissionWon or g_bMissionLost:
		return

	if g_bPlayerFound:
		return
		
	# Player is no longer hidden
	QuickFoundOutDialogue()

################################################################################
#	RemoveDetectionChecks(pAction)
#
#	Remove all listening handlers that check for the player
#	being detected. This phase of the mission is complete.
#
#	Args:	None
#
#	Return:	None
################################################################################
def RemoveDetectionChecks(pAction):
	pMission = MissionLib.GetMission()
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TRACTOR_BEAM_STARTED_HITTING, 
											pMission, __name__ + ".TractorHandler")

	pFreighter5 = MissionLib.GetShip("Freighter 5")
	if pFreighter5:
		pFreighter5.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
												".PlayerFired")
	pFreighter6 = MissionLib.GetShip("Freighter 6")
	if pFreighter6:
		pFreighter6.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
												".PlayerFired")
	pGalor1 = MissionLib.GetShip("Galor 1")
	if pGalor1:
		pGalor1.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
												".PlayerFired")
	pGalor2 = MissionLib.GetShip("Galor 2")
	if pGalor2:
		pGalor2.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
												".PlayerFired")
	pKeldon1 = MissionLib.GetShip("Matan")
	if pKeldon1:
		pKeldon1.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
												".PlayerFired")
	pKessok = MissionLib.GetShip("Strange Ship")
	if pKessok:
		pKessok.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ +
												 ".PlayerFired")

	return 0

################################################################################
#	IsPoweredDown()
#
#	Determine wether the player has powered down systems to keep him hidden
#	in the asteroid field.
#
#	Args:	None
#
#	Return:	bool
################################################################################
def IsPoweredDown():
	pPlayer = MissionLib.GetPlayer()
	bPoweredUp = FALSE
	bPoweredUp = pPlayer.GetPhaserSystem().IsOn() | bPoweredUp
	bPoweredUp = pPlayer.GetShields().IsOn() | bPoweredUp
	bPoweredUp = pPlayer.GetImpulseEngineSubsystem().IsOn() | bPoweredUp

	return not bPoweredUp

################################################################################
#	AttackDialogue(pAction)
#
#	Dialogue called when the player is discovered
#
#	Args:	None
#
#	Return:	None
################################################################################
def AttackDialogue(pAction):
	#Add a nav point so the user can escape the asteroid filed from the bridge and warp
	MissionLib.AddNavPoints("Nepenthe1", "Exit Asteroid Field")
	
	pCBridgeSet = App.g_kSetManager.GetSet("CBridgeSet")
	pMatan = App.CharacterClass_GetObject(pCBridgeSet, "Matan")
	pSek = App.CharacterClass_GetObject(pCBridgeSet, "Sek")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pData = GetData()

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSek, "E4M6Discovery1", 
													g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMatan, "E4M6Discovery2", 
													g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSek, "E4M6Discovery3", 
													g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RemoveSafetyZoneProx"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6Discovery4", 
													g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ChangeShipAI"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", INTERCEPTED_COMM))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6Discovery5", 
													g_pMissionDatabase), 2)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6Discovery6", 
													g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6MatanWarp", 
													g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6Discovery7", 
													g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M6Discovery8", 
													g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6Discovery9", 
													g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "DataStartScanning"))
	MissionLib.QueueActionToPlay(pSeq)

	return 0

################################################################################
#	DataStartScanning(pAction)
#
#	Create a timer while Data "scans" the area.
#
#	Args:	None
#
#	Return:	None
################################################################################
def DataStartScanning(pAction):
	# Create timer, when triggered call function to play dialogue.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_DATA_SCAN_TIMER_EVENT, 
							'Maelstrom.Episode4.E4M6.E4M6.DataScanComplete',
							fStartTime + DATA_SCANNING_DELAY, 0, 0)

	# Set flag.
	global g_bDataScanning
	g_bDataScanning = TRUE
							
	MissionLib.AddGoal("E4HoldOffCardassiansGoal")
	return 0
		
################################################################################
#	DataScanComplete(pObject, pEvent)
#
#	Play dialogue when Data is done scanning the area.
#	If E4M4 has been completed, player has all the info and is prodded to SB12.
#	If E4M4 hs not been completed, player is proded to meet with Korbus instead.
#
#	Args:	None
#
#	Return:	None
################################################################################
def DataScanComplete(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	MissionLib.RemoveGoal("E4HoldOffCardassiansGoal")

	Maelstrom.Episode4.Episode4.Mission6Complete()

	pData = GetData()
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AddAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M6Discovery10",
												g_pMissionDatabase))
	
	# If E4M4 completed, Player met with Korbus and obtained info.
	if(Maelstrom.Episode4.Episode4.g_bMission4Win):
		MissionLib.AddGoal("E4ReturnSB12Goal")
		MissionLib.RemoveGoal("E4InvestigateAreaGoal")

		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M6Discovery11",
													g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M6ProbeInfo",
													g_pMissionDatabase))
		pEpisodeDatabase = MissionLib.GetEpisode().GetDatabase()
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4DataFindings",
														pEpisodeDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6MoreIncoming",
														g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "Reinforcements"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6Discovery13",
														g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4SaffiProdToSB12",
														pEpisodeDatabase))

	# E4M4 not completed, Player needs to go to E4M4 for more info.														
	else:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M6Discovery12",
														g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6MoreIncoming",
														g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "Reinforcements"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6Discovery13",
														g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6DiscoveryProd",
														g_pMissionDatabase))
														
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6DiscoveryAdvice",
												g_pMissionDatabase))
	MissionLib.QueueActionToPlay(pSeq)

################################################################################
#	Reinforcements(pAction)
#
#	Have five Galors warp in and begin attacking the player.
#	Set flag for Data's scan being done and Mission Won.
#	This allows the player to warp out of the system.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Reinforcements(pAction):
	if g_bMissionTerminated:
		return 0

	# Set flags.
	global g_bDataScanning
	g_bDataScanning = FALSE

	global g_bMissionWon
	g_bMissionWon = TRUE

	pNepenthe1 = App.g_kSetManager.GetSet("Nepenthe1")
	pGalorR1 = loadspacehelper.CreateShip("Galor", pNepenthe1, 
										"GalorR1", "Placement 1", 1)
	pGalorR2 = loadspacehelper.CreateShip("Galor", pNepenthe1, 
										"GalorR2", "Placement 2", 1)
	pGalorR3 = loadspacehelper.CreateShip("Galor", pNepenthe1, 
										"GalorR3", "Placement 3", 1)
	pGalorR4 = loadspacehelper.CreateShip("Galor", pNepenthe1, 
										"GalorR4", "Placement 4", 1)
	pGalorR5 = loadspacehelper.CreateShip("Galor", pNepenthe1, 
										"GalorR5", "Placement 5", 1)
	
	import AttackPlayerAI
	if pGalorR1:
		pGalorR1.SetAI(AttackPlayerAI.CreateAI(pGalorR1))
	if pGalorR2:
		pGalorR2.SetAI(AttackPlayerAI.CreateAI(pGalorR2))
	if pGalorR3: 
		pGalorR3.SetAI(AttackPlayerAI.CreateAI(pGalorR3))
	if pGalorR4:
		pGalorR4.SetAI(AttackPlayerAI.CreateAI(pGalorR4))
	if pGalorR5:
		pGalorR5.SetAI(AttackPlayerAI.CreateAI(pGalorR5))

	return 0

################################################################################
#	QuickFoundOutDialogue(pAction = None)
#
#	If the Kessok aren't here, just tell the player he has been
#	discovered and attack
#
#	Args:	None
#
#	Return:	None
################################################################################
def QuickFoundOutDialogue(pAction = None):
	if g_bMissionWon:
		return

	global g_bMissionLost
	g_bMissionLost = TRUE

#	DebugPrint("Player discovered")
	global g_bPlayerFound
	g_bPlayerFound = TRUE
#	DebugPrint("E4M6.QuickFoundOutDialogue() - Player Found!")
#	DebugPrint("g_bPlayerFound = " + str(g_bPlayerFound))

	# Remove all timers so other events stop.
	KillNepentheTimers()

	# Abort sequence
	global g_iCommSequenceID
	pInterruptSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_iCommSequenceID))
	if (pInterruptSequence):
		pInterruptSequence.Skip()
		g_iCommSequenceID = App.NULL_ID

		MissionLib.ViewscreenOff(None, 0)

	# Create ending sequence.
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pLiu = GetLiu()
	pEndingSeq = MissionLib.NewDialogueSequence()
	pEndingSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, 
												"HailStarfleet1", g_pGeneralDatabase))
	pEndingSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, 
												"HailStarfleet5", g_pGeneralDatabase))
	pEndingSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, 
												"HailStarfleet8", g_pGeneralDatabase), 2.0)
	pEndingSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
												"LiuSet", "Liu"), 1)
	pEndingSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, 
												"E4M6EndingLose1", g_pMissionDatabase))
	pEndingSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, 
												"E4M6EndingLose2", g_pMissionDatabase))
	pEndingSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	# Now tell the player.
	pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pSequence = MissionLib.NewDialogueSequence()
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
													"ChangeRenderedSet", "bridge"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pScience, "E4M6NepentheFoundOut",
												g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "GameOver", pEndingSeq))

	MissionLib.QueueActionToPlay(pSequence)

	return 0
	
################################################################################
#	InterceptDialogue()
#
#	What the Cardassians and the Kessok say to each other.
#
#	Args:	None
#
#	Return:	None
################################################################################
def InterceptDialogue():
	pKessokBridgeSet = App.g_kSetManager.GetSet("KessokBridgeSet")
	pKessok = App.CharacterClass_GetObject (pKessokBridgeSet, "Kessok")

	# We don't know it's a Kessok yet.
	pKessok.SetCharacterName("Alien")

	pCBridgeSet = App.g_kSetManager.GetSet("CBridgeSet")
	pMatan = App.CharacterClass_GetObject (pCBridgeSet, "Matan")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pSci = App.CharacterClass_GetObject(pBridge, "Science")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")

	pPlayer = MissionLib.GetPlayer()
	pPlayer.SetAlertLevel(App.ShipClass.GREEN_ALERT)

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RemoveDetectionChecks"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Nepenthe1"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Nepenthe1"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetViewscreenCamera", "Nepenthe1"))

	# note: this watches the placement where the Kessok warps in.
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "WatchWarpPlacement", "Nepenthe1", "KessokAmbassador"))

	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M6LookAliens", g_pMissionDatabase), 3.0)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSci, "E4M6CantScan", g_pMissionDatabase), 1.0)
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Nepenthe1"), 2.0)
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetViewscreenCamera", "Nepenthe1"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pHelm, "E4M6Exchange1", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "CBridgeSet", "Matan", 0.5, 0.75))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMatan, "E4M6Exchange2",	g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	pViewscreenOn = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokBridgeSet", "Kessok", 0.5, 0.75)
	pSeq.AppendAction(pViewscreenOn)

	pKessokSeq = MissionLib.NewDialogueSequence()
	pKessokSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKessok, "E4M6Exchange3", g_pMissionDatabase))
#	pKessokSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKessok, "E4M6Exchange3b", g_pMissionDatabase))
	pKessokSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKessok, "E4M6Exchange3c", g_pMissionDatabase))
	pKessokSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKessok, "E4M6Exchange3d", g_pMissionDatabase))
	# Start playing Kessok babble sequence after viewscreen turns on.
	pSeq.AddAction(pKessokSeq, pViewscreenOn)

	pAction = App.TGScriptAction_Create(__name__, "PlayDataSeq")
	pSeq.AddAction(pAction, pViewscreenOn, 3)

	pAction = Bridge.BridgeUtils.MakeCharacterLine(pKessok, "E4M6Exchange5", g_pMissionDatabase)
	pSeq.AddAction(pAction, pKessokSeq)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "CBridgeSet", "Matan", 0.5, 0.75))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMatan, "E4M6Exchange6", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMatan, "E4M6Exchange7", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokBridgeSet", "Kessok", 0.5, 0.75))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKessok, "E4M6Exchange8", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKessok, "E4M6Exchange9", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "CBridgeSet", "Matan", 0.5, 0.75))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMatan, "E4M6Exchange10", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMatan, "E4M6Exchange11", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Maelstrom.Episode4.E4M6.E4M6", "AttackDialogue"))
	MissionLib.QueueActionToPlay(pSeq)

	return 0

#
# PlayDataSeq() - Plays Data's sequence about Universal Translator difficulties
#
def PlayDataSeq(pAction):

	pBridge = App.g_kSetManager.GetSet("bridge")
	pSci = App.CharacterClass_GetObject(pBridge, "Science")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")

	pDataSeq = MissionLib.NewDialogueSequence()

	pDataSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1"))
	pDataSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M6Exchange4", g_pMissionDatabase))
	pDataSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1"))
	pDataSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSci, "E4M6Exchange4b", g_pMissionDatabase))
	pDataSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Kiska Head", "Kiska Cam"))
	pDataSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pHelm, "E4M6Exchange4c", g_pMissionDatabase))
	pDataSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pDataSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSci, "E4M6Exchange4d", g_pMissionDatabase))
	pDataSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "BrexWatchRMed", "BrexCamRMed", 1))
	pDataSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M6Exchange4e", g_pMissionDatabase))
	pDataSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1"))
	pDataSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M6Exchange4f", g_pMissionDatabase))
	pDataSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))

	# Do not queue this, as it needs to play in concert with the Kessok/Matan InterceptDialogue sequence
	pDataSeq.Play()

	return 0


################################################################################
#	PlayFanfare(pAction)
#
#	Play music for arrival of the Kessok.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def PlayFanfare(pAction):
	App.g_kMusicManager.PlayFanfare("Kessok Fanfare")
	return 0

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
	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Saffi Communicating...")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	pSeq = MissionLib.NewDialogueSequence()

	if (g_iMissionProgress == FREIGHTERS_IN_CEBALRAI) and not g_bArrivedCebalrai2:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6CommSaffi1",
																g_pMissionDatabase))
	elif (g_iMissionProgress == MISSION_BRANCH):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6CommSaffi2",
																g_pMissionDatabase))
	elif (g_iMissionProgress == IN_NEPENTHE):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M6CommSaffi3",
																g_pMissionDatabase))
	else:
		pSeq.Completed()
		pObject.CallNextHandler(pEvent)
		return
			
	pSeq.Play()


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
	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Felix Communicating...")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == MISSION_BRANCH:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M6CommFelix1",
																g_pMissionDatabase))
	else:
		pSeq.Completed()
		pObject.CallNextHandler(pEvent)
		return

	pSeq.Play()


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
	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Kiska Communicating...")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == MISSION_BRANCH:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6CommKiska1",
																g_pMissionDatabase))
	elif g_iMissionProgress == IN_NEPENTHE:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6CommKiska3",
																g_pMissionDatabase))
	elif g_iMissionProgress == INTERCEPTED_COMM:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M6CommKiska2",
																g_pMissionDatabase))
	else:
		pSeq.Completed()
		pObject.CallNextHandler(pEvent)
		return

	pSeq.Play()

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
	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Miguel Communicating...")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == FREIGHTERS_ESCAPE or g_iMissionProgress == FREIGHTERS_IN_CEBALRAI:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6CommMiguel1",
																g_pMissionDatabase))
	elif g_iMissionProgress == MISSION_BRANCH:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6CommMiguel2",
																g_pMissionDatabase))
	elif g_iMissionProgress == IN_NEPENTHE:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6CommMiguel4",
																g_pMissionDatabase))
	elif g_iMissionProgress == INTERCEPTED_COMM:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M6CommMiguel3",
																g_pMissionDatabase))
	else:
		pSeq.Completed()
		pObject.CallNextHandler(pEvent)
		return

	pSeq.Play()

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
	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Brex Communicating...")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == MISSION_BRANCH:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M6CommBrex1",
																g_pMissionDatabase))
	else:
		pSeq.Completed()
		pObject.CallNextHandler(pEvent)
		return

	pSeq.Play()

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
	if g_bMissionLost:
		pObject.CallNextHandler(pEvent)
		return

#	DebugPrint("Brex Communicating...")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == MISSION_BRANCH:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M6CommData1",
																g_pMissionDatabase))
	elif g_iMissionProgress == INTERCEPTED_COMM:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M6CommData2",
																g_pMissionDatabase))
	else:
		pSeq.Completed()
		pObject.CallNextHandler(pEvent)
		return

	pSeq.Play()


################################################################################
#	SetMissionProgress(pAction, iProgress)
#
# 	Set mission progress flag.
#
#	Args:	pAction, TGAction
#			iProgress, new mission progress value.
#
#	Return:	None
################################################################################
def SetMissionProgress(pAction, iProgress):
	global g_iMissionProgress
	g_iMissionProgress = iProgress

	return 0

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
def DamageShip (pShip, fMinPercent, fMaxPercent):
	# Randomly damage all other systems.
	pSystem = pShip.GetHull()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetShields()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetPowerSubsystem ()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetSensorSubsystem ()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetImpulseEngineSubsystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		pSystem.SetConditionPercentage (r)

	# Warp system is disabled.
	pSystem = pShip.GetWarpEngineSubsystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetTorpedoSystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetPhaserSystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetPulseWeaponSystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetTractorBeamSystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		pSystem.SetConditionPercentage (r)

	pSystem = pShip.GetRepairSubsystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent
		pSystem.SetConditionPercentage (r)
		pSystem.TurnOff ()

	pSystem = pShip.GetCloakingSubsystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = r / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = r + fMinPercent

		# Make sure the cloaking system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		pSystem.SetConditionPercentage (r)
def MissionWon():
	MissionLib.LoadTorpedoes(None,"Quantum",1000)
	MissionLib.TextBanner(None, g_pMissionDatabase.GetString("Bonus1"), 0.05, 0.75, 4.0, 12, 1, 0)
###############################################################################
#	DebugPrint(pcString)
#
#	Wrapper for print function that checks debug flag.
#
#	Args:	pcString, string to print.
#
#	Return:	None
################################################################################
def DebugPrint(pcString):
	if(g_bDebugPrint):
		debug(pcString)

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
	MissionLib.SaveMission(__name__)

	global g_bMissionTerminated
	g_bMissionTerminated = TRUE

	# Remove communicate handlers.
	Bridge.BridgeUtils.RemoveCommunicateHandlers()
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	pMenu = pData.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + 
											".CommunicateData")

	# Instance handler for Miguel's Scan Area button
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pMiguel.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Remove Instance handler for Kiska's Hail button
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pHelm.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	# Remove instance handler for Kiska's Warp button.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pNavMenu = pHelm.GetMenu().GetSubmenuW(pDatabase.GetString("Nav Points"))
	App.g_kLocalizationManager.Unload(pDatabase)
	pNavMenu.RemoveHandlerForInstance(Bridge.HelmMenuHandlers.ET_SET_NAVPOINT_TARGET, __name__ + ".NavPointSelected")

	MissionLib.DeleteAllGoals()

	App.SortedRegionMenu_ClearSetCourseMenu()

	# Unload BridgeCrewGeneral database.
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)
		global g_pGeneralDatabase
		g_pGeneralDatabase = None

	MissionLib.ShutdownFriendlyFire()

#	DebugPrint("Terminating Episode 4, Mission 6.\n")

