###############################################################################
#	Filename:	E4M4.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 4 Mission 4
#	
#	Created:	04/19/01 - Alberto Fonseca(Added header)
#	Modified:	01/21/02 - Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Episode4.Episode4
import Bridge.BridgeUtils

#NonSerializedObjects = ( "debug", )
#debug = App.CPyDebug(__name__).Print
	
#kDebugObj = App.CPyDebug()

#
# Global variables
#
TRUE					= 1
FALSE					= 0
g_bDebugPrint			= TRUE

g_bMissionTerminated	= 0
g_pMissionDatabase		= None
g_pGeneralDatabase		= None
g_iMissionProgress		= 0		# Keep track of mission state.
g_bScanning				= 0		# Flag for wether we're scanning.
g_bHybridGone			= 0		# If Hybrid has warped out.
g_bHybridScanned		= 0		# If Hybrid ship has been scanned.
g_bMissionWon			= 0		# Mission has been won.
g_bMissionFailed		= 0		# Mission has been lost.
g_bFelixOnBOP			= 0		# Wether Felix is on the Mavjop.
g_bMavjopHailed			= 0		# Has the "Hail Mavjop" dialogue played.
g_iScanProdID			= 0		# Scan Prod ID.
g_pFriendlies			= 0		# Friendly object group
g_pEnemies				= 0		# Enemy object group
g_pNeutrals				= 0		# Neutral object group
g_bBriefingPlayed		= 0		# Has mission briefing played
g_bHybridWarpingOut		= 0		# Is Hybrid warping out.
g_bScanSeqPlayed		= 0
g_bGalorsArrived		= 0		# Flag for wether Galors have arrived.
g_bVoltair2Scanned		= 0		# Flag for wether player scanned Volatir 2.

# Arrival flags
g_bArrivedVoltair1		= 0
g_bArrivedVoltair2		= 0

#
# Event types
#
ET_PROD_SCAN				= App.Mission_GetNextEventType()


# Define mission progress
AT_BELARUZ			= 1
SAW_HYBRID			= 2
AT_END_NO_E4M6		= 3

#
# Constants
#
MIN_HYBRID_SCAN_DISTANCE	= 286	# 50km min dist to scan Hybrid from.


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
	loadspacehelper.PreloadShip("Nebula", 1)
	loadspacehelper.PreloadShip("BirdOfPrey", 1)
	loadspacehelper.PreloadShip("Keldon", 2)
	loadspacehelper.PreloadShip("Galor", 2)
	loadspacehelper.PreloadShip("CardHybrid", 2)

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
	# Check and see if we have a player, if we don't
	# we aren't linking and will have to call the initial
	# briefing "by hand" and the end of Initialize
	bHavePlayer = 0
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		bHavePlayer = 1
		
	# Initialize all global variables.
	InitGlobals()

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	# Creates the Starbase control room set, Admiral Liu.
	MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif",
							-40, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet",
							0, 0, 5)
	
	# Creating Data early, so his character isn't null in the Briefing
	Maelstrom.Episode4.Episode4.MakeDataOnBridge()

	# Creates Korbus' bridge set
	kBridgeSet = MissionLib.SetupBridgeSet("KBridgeSet", "data/Models/Sets/Klingon/BOPBridge.nif", -40, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Korbus", "KBridgeSet", 0, 0, -5)
	
	# Create Oben's bridge
	pOBridgeSet = MissionLib.SetupBridgeSet("OBridgeSet", "data/Models/Sets/Cardassian/cardbridge.nif", -40, 65, -1.55)
	pOben = MissionLib.SetupCharacter("Bridge.Characters.Oben", "OBridgeSet")
	pOben.SetHidden(0)
	
	# Set torp loadouts.
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)

	# Try load mission if exists.
	MissionLib.TryLoadMission(__name__)

	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pSaffi = App.CharacterClass_GetObject(pSet, "XO")
	pViewscreen = pSet.GetViewScreen()
	pViewscreen.SetMenu(pSaffi.GetMenu())

	CreateSpaceSets()			# Create space sets and load placements.
	CreateShips()				# Create ships for mission start.
	CreateMenus()				# Put the menus into Kiska's menu system.
	SetAffiliations(pMission) 	# Assigns ships to enemy and friendly groups

	# Setup event handlers
	SetupEventHandlers(pMission)

	# Delete all goals at the start.
	MissionLib.DeleteAllGoals()
	
	pEpisode = App.Game_GetCurrentGame().GetCurrentEpisode()
	MissionLib.AddGoal("E4TrackHybridGoal")

	# If the player was created from scratch, call our initial briefing
	if (bHavePlayer == 0):
		IntroDialogue()
		
	MissionLib.SetupFriendlyFire()

	MissionLib.SaveGame("E4M2-")

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
	global g_bMissionTerminated
	global g_pMissionDatabase	
	global g_pGeneralDatabase	
	global g_iMissionProgress	
	global g_bHybridGone	
	global g_bScanning	
	global g_bHybridScanned	
	global g_bMissionWon		
	global g_bMissionFailed	
	global g_bFelixOnBOP		
	global g_bMavjopHailed		
	global g_iScanProdID		
	global g_pFriendlies		
	global g_pEnemies			
	global g_pNeutrals	
	global g_bBriefingPlayed	
	global g_bHybridWarpingOut
	global g_bScanSeqPlayed	
	global g_bGalorsArrived
	global g_bVoltair2Scanned

	g_bMissionTerminated	= FALSE
	g_iMissionProgress		= AT_BELARUZ	
	g_bHybridGone			= FALSE		
	g_bScanning				= FALSE
	g_bHybridScanned		= FALSE	
	g_bMissionWon			= FALSE	
	g_bMissionFailed		= FALSE	
	g_bFelixOnBOP			= FALSE	
	g_bMavjopHailed			= FALSE	
	g_iScanProdID			= App.NULL_ID
	g_pFriendlies			= pMission.GetFriendlyGroup()	
	g_pEnemies				= pMission.GetEnemyGroup()	
	g_pNeutrals				= pMission.GetNeutralGroup()
	g_pMissionDatabase		= pMission.SetDatabase("data/TGL/Maelstrom/Episode 4/E4M4.tgl")
	g_pGeneralDatabase		= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_bBriefingPlayed		= FALSE
	g_bHybridWarpingOut		= FALSE
	g_bScanSeqPlayed		= FALSE
	g_bGalorsArrived		= FALSE
	g_bVoltair2Scanned		= FALSE

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
	# Starbase 12 Set.
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()
	pStarbase12 = Systems.Starbase12.Starbase12.GetSet()
	
	# Belaruz Sets.
	import Systems.Belaruz.Belaruz1
	Systems.Belaruz.Belaruz1.Initialize()
	pBelaruz1 = Systems.Belaruz.Belaruz1.GetSet()

	import Systems.Belaruz.Belaruz2
	Systems.Belaruz.Belaruz2.Initialize()
	pBelaruz2 = Systems.Belaruz.Belaruz2.GetSet()

	import Systems.Belaruz.Belaruz3
	Systems.Belaruz.Belaruz3.Initialize()
	pBelaruz3 = Systems.Belaruz.Belaruz3.GetSet()

	import Systems.Belaruz.Belaruz4
	Systems.Belaruz.Belaruz4.Initialize()
	pBelaruz4 = Systems.Belaruz.Belaruz4.GetSet()

	# Voltair sets.
	import Systems.Voltair.Voltair2
	Systems.Voltair.Voltair2.Initialize()
	pVoltair2 = Systems.Voltair.Voltair2.GetSet()

	import Systems.Voltair.Voltair1
	Systems.Voltair.Voltair1.Initialize()
	pVoltair1 = Systems.Voltair.Voltair1.GetSet()

	# Add our custom placement objects for this mission.
	import Maelstrom.Episode4.E4M4.E4M4_Starbase12_P
	import Maelstrom.Episode4.E4M4.E4M4_Belaruz4_P
	import Maelstrom.Episode4.E4M4.E4M4_Voltair1_P
	import Maelstrom.Episode4.E4M4.E4M4_Voltair2_P
	Maelstrom.Episode4.E4M4.E4M4_Starbase12_P.LoadPlacements(pStarbase12.GetName())
	Maelstrom.Episode4.E4M4.E4M4_Belaruz4_P.LoadPlacements(pBelaruz4.GetName())
	Maelstrom.Episode4.E4M4.E4M4_Voltair2_P.LoadPlacements(pVoltair2.GetName())
	Maelstrom.Episode4.E4M4.E4M4_Voltair1_P.LoadPlacements(pVoltair1.GetName())

	# Load custom placements for bridge.
	pBridgeSet = Bridge.BridgeUtils.GetBridge()
	import Maelstrom.Episode4.EBridge_P
	Maelstrom.Episode4.EBridge_P.LoadPlacements(pBridgeSet.GetName())

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
	# Get Starbase 12 set.
	import Systems.Starbase12.Starbase12
	pStarbase12 = Systems.Starbase12.Starbase12.GetSet()

	# Get Voltair 1 set.
	import Systems.Voltair.Voltair1
	pVoltair1 = Systems.Voltair.Voltair1.GetSet()

	# Get Belaruz 4 set.
	import Systems.Belaruz.Belaruz4
	pBelaruz4 = Systems.Belaruz.Belaruz4.GetSet()

	pKeldon1 = loadspacehelper.CreateShip("Keldon", pVoltair1, "Keldon 1", "Keldon1 Warp In")
	pKeldon2 = loadspacehelper.CreateShip("Keldon", pVoltair1, "Keldon 2", "Keldon2 Warp In")
	pHybrid = loadspacehelper.CreateShip("CardHybrid", pVoltair1, "Unknown Ship", "Hybrid Start")

	if pHybrid:
		pHybrid.SetInvincible(TRUE)
		MissionLib.MakeEnginesInvincible(pHybrid)

	MissionLib.CreatePlayerShip("Sovereign", pBelaruz4, "player", "Player Start")
	loadspacehelper.CreateShip("FedStarbase", pStarbase12, "Starbase 12", "Starbase12 Location")
	pNebula = loadspacehelper.CreateShip("Nebula", pStarbase12, "USS Prometheus", "Nebula Start")
	pNebula.ReplaceTexture("data/Models/SharedTextures/FedShips/Prometheus.tga", "ID")
	pMavjop = loadspacehelper.CreateShip("BirdOfPrey", pBelaruz4, "Mavjop", "Mavjop Start")

	# Set Nebula AI.
	import Maelstrom.Episode3.E3M1.E3M1NebulaAI
	pNebula.SetAI(Maelstrom.Episode3.E3M1.E3M1NebulaAI.CreateAI(pNebula))

	# Cloak the Mavjop instantly.
	if pMavjop:
		MissionLib.Cloak(None, pMavjop, TRUE)

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

	# Import Belaruz System Menu Items
	import Systems.Belaruz.Belaruz
	pBelaruz = Systems.Belaruz.Belaruz.CreateMenus()
	pBelaruz.SetMissionName(__name__)

	# Import Starbase System Menu Items
	import Systems.Starbase12.Starbase
	pStarbase = Systems.Starbase12.Starbase.CreateMenus()
	pStarbase.SetMissionName()

	App.SortedRegionMenu_SetPauseSorting(0)


################################################################################
#	SetAffiliations(pMission)
#
# 	Create lists of who is a friend and who is not.
#	Also create target object groups with info used by AI.
#
#	Args:	None
#
#	Return:	None
################################################################################
def SetAffiliations(pMission):
	"Assigns ships to either friendly, enemy, or neutral categories for the targeting list."
	global g_pFriendlies
	g_pFriendlies = pMission.GetFriendlyGroup()
	g_pFriendlies.AddName("player")
	g_pFriendlies.AddName("Mavjop")
	g_pFriendlies.AddName("Starbase 12")
	g_pFriendlies.AddName("USS Prometheus")

	global g_pEnemies
	g_pEnemies = pMission.GetEnemyGroup()
	g_pEnemies.AddName("Keldon 1")
	g_pEnemies.AddName("Keldon 2")
	g_pEnemies.AddName("Galor 1")
	g_pEnemies.AddName("Galor 2")

	global g_pNeutrals
	g_pNeutrals = pMission.GetNeutralGroup()
	g_pNeutrals.AddName("Unknown Ship")

	# Set up target groups used by AI.
	global g_pMavjopTargetGroup
	g_pMavjopTargetGroup = App.ObjectGroupWithInfo()
	g_pMavjopTargetGroup ["Keldon 1"] = { "Priority" : 1.0 }
	g_pMavjopTargetGroup ["Keldon 2"] = { "Priority" : 1.0 }
	g_pMavjopTargetGroup ["Galor 1"] = { "Priority" : 0.0 }
	g_pMavjopTargetGroup ["Galor 2"] = { "Priority" : 0.0 }

	global g_pMavjopTargetGroup2
	g_pMavjopTargetGroup2 = App.ObjectGroupWithInfo()
	g_pMavjopTargetGroup2 ["Keldon 1"] = { "Priority" : 0.0 }
	g_pMavjopTargetGroup2 ["Keldon 2"] = { "Priority" : 0.0 }
	g_pMavjopTargetGroup2 ["Galor 1"] = { "Priority" : 10.0 }
	g_pMavjopTargetGroup2 ["Galor 2"] = { "Priority" : 10.0 }

	global g_pFriendlyTargetGroup
	g_pFriendlyTargetGroup = App.ObjectGroupWithInfo()
	g_pFriendlyTargetGroup ["player"] = { "Priority" : 2.0 }
	g_pFriendlyTargetGroup ["Mavjop"] = { "Priority" : 0.0 }

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
	
	# Ship finished warping event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_WARP, pMission, __name__ + ".ExitedWarp")

	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ + ".ExitSet")

	# If a ship is destroyed
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ + ".ShipDestroyed")

	# Instance handler for Miguel's Scan Area button
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pMiguel.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Instance handler for Kiska's Hail button.
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pKiska.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Instance handler for Kiska's Warp button.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, 
													__name__ + ".WarpHandler")

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
#	print("Saffi Communicating...")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == AT_BELARUZ:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M4CommSaffi1",
																g_pMissionDatabase, 0, None))
	elif (g_bHybridScanned == 1) and (g_bMavjopHailed == 0): 
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M4CommSaffi2",
																g_pMissionDatabase, 0, None))
																
	elif (g_iMissionProgress == AT_END_NO_E4M6): 
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M4CommSaffi3",
																g_pMissionDatabase, 0, None))																
	
	else:
		pObject.CallNextHandler(pEvent)

	pSeq.Play()


################################################################################
#	CommunicateFelix(pObject, pEvent)
#
#	Handler for Korbus's Communicate button press event. 
#	Called "CommunicateFelix" because he's at tactical.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def CommunicateFelix(pObject, pEvent):
#	kDebugObj.Print("Korbus Communicating...")
	pKorbus = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pSeq = MissionLib.NewDialogueSequence()

	if (g_iMissionProgress == AT_BELARUZ) and (g_bFelixOnBOP == 1): 
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKorbus, "E4M4CommKorbus1",
																g_pMissionDatabase, 0, None))
	elif (g_bHybridScanned == 1): 
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKorbus, "E4M4CommKorbus2",
																g_pMissionDatabase, 0, None))																											
	# Korbus has no generic "nothing to add captain" line so use the first line otherwise.
	elif (g_bFelixOnBOP == 1): 
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKorbus, "E4M4CommKorbus1",
																g_pMissionDatabase, 0, None))

	else:
		pObject.CallNextHandler(pEvent)

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
#	print("Kiska Communicating...")
	# Kiska has no communicate dialogue
	pObject.CallNextHandler(pEvent)

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
#	print("Miguel Communicating...")
	# Miguel has no communicate dialogue
	pObject.CallNextHandler(pEvent)

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
#	print("Brex Communicating...")
	# Brex has no communicate dialogue
	pObject.CallNextHandler(pEvent)

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
#	print("Data Communicating...")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pSeq = MissionLib.NewDialogueSequence()
				
	if (g_bHybridScanned == 1) and (g_iMissionProgress == SAW_HYBRID): 
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M4CommData1", g_pMissionDatabase, 0, None))
	
	elif (g_bHybridScanned == 0) and (g_iMissionProgress == SAW_HYBRID): 
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M4CommData2", g_pMissionDatabase, 0, None))

	else:
		pObject.CallNextHandler(pEvent)
			
	pSeq.Play()


###############################################################################
#	ExitedWarp(pMission, pEvent)
#	
#	Called when the players ship has finished warping.
#	
#	Args:	pMission	- the mission
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def ExitedWarp(pMission, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetSource())

	if (not pShip) or (g_bMissionFailed):
		pMission.CallNextHandler(pEvent)
		return

	pPlayer = App.Game_GetCurrentPlayer()
	if (not pPlayer) or (pPlayer.GetObjID() != pShip.GetObjID()):
		pMission.CallNextHandler(pEvent)
		return

	pSet = pPlayer.GetContainingSet()
	if (pSet == None):
		pMission.CallNextHandler(pEvent)
		return
		
	# If we are entering Belaruz for the first time
	if (pSet.GetName() == "Belaruz4") and (not g_bBriefingPlayed):
		global g_iMissionProgress
		g_iMissionProgress = AT_BELARUZ
		MissionLib.RemoveGoal("E4GoToBelaruzGoal")
		IntroDialogue()
				
	# If we are arriving in Voltair1 for the first time.	
	elif (pSet.GetName() == "Voltair1") and (not g_bArrivedVoltair1):
		ArriveVoltair1()

	# If we are arriving in Voltair 2 for the first time.
	elif (pSet.GetName() == "Voltair2") and (not g_bArrivedVoltair2):
		ArriveVoltair2()

	# All done, call the next handler for the event.	
	pMission.CallNextHandler(pEvent)

################################################################################
#	ArriveVoltair2()
#
#	Handle player entering Voltair 2 for the first time.
#
#	Args:	None
#
#	Return:	None
################################################################################
def ArriveVoltair2():
	# Set arrival flag.
	global g_bArrivedVoltair2
	g_bArrivedVoltair2 = TRUE

	pBridge = App.g_kSetManager.GetSet("bridge")
	pMiguel = App.CharacterClass_GetObject(pBridge, "Science")

	pSeq = MissionLib.NewDialogueSequence()

	pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, 
							"E4M4SuggestScan", "Captain", 1, g_pMissionDatabase), 6.0)
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProdTimer"))

	MissionLib.QueueActionToPlay(pSeq)

	MissionLib.RemoveGoal("E4WarpToVoltairGoal")
	MissionLib.AddGoal("E4ScanAreaGoal")

	return 0


################################################################################
#	ArriveVoltair1()
#
#	Handle player entering Voltair 1 for the first time.
#
#	Args:	None
#
#	Return:	None
################################################################################
def ArriveVoltair1():
	# Set arrival flag.
	global g_bArrivedVoltair1
	g_bArrivedVoltair1 = TRUE

	MissionLib.AddGoal("E4ScanHybridGoal")
	MissionLib.AddGoal("E4ProtectKorbusShipGoal")
	MissionLib.RemoveGoal("E4TrackHybridGoal")
	MissionLib.RemoveGoal("E4WarpToVoltair1Goal")
	MissionLib.RemoveGoal("E4ScanAreaGoal")

	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pOBridgeSet = App.g_kSetManager.GetSet("OBridgeSet")
	pOben = App.CharacterClass_GetObject (pOBridgeSet, "Oben")
	pTact = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()
	pGame = App.Game_GetCurrentGame()
	pPlayer = App.Game_GetCurrentPlayer()

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "SetViewscreenCamera",
												pPlayer.GetContainingSet().GetName(), pGame.GetPlayerCamera().GetName()))
	pMiguelCam = App.TGScriptAction_Create("Actions.CameraScriptActions", 
					"PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1")
	pSeq.AppendAction(pMiguelCam)

	pHybridHere = None
	if g_bVoltair2Scanned:
		pHybridHere = Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M4LookHybridHere", g_pMissionDatabase)
		pSeq.AppendAction(pHybridHere)
	else:
		pHybridHere = Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M4LookHybridHere2", g_pMissionDatabase)
		pSeq.AppendAction(pHybridHere)

	pSeq.AddAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "Unknown Ship"), pMiguelCam, 1.0)
	pSeq.AddAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
								"PlacementWatch", "bridge", "View", "Player Cam"), pMiguelCam, 2.0)

	pSeq.AddAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4L019", "T", 0, g_pMissionDatabase), pHybridHere)
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pTact, "E4M4L020", g_pMissionDatabase, 0, "C"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4L021", "T", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pTact, "E4M4L022", g_pMissionDatabase, 1, "C"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2"))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4L023", "Captain", 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4WhoseTechnology", "X", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2"))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4CannotDetermine", "C", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam"))
	pSeq.AppendAction(App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E4M4L024", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E4M4L028", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E4M4L029", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "OBridgeSet", "Oben"))
	pSeq.AppendAction(App.CharacterAction_Create(pOben, App.CharacterAction.AT_SAY_LINE, "E4M4L030", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M4HybridPoweringUp", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetEnemyAI"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2"))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4ShouldScanHybrid", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", SAW_HYBRID))
	MissionLib.QueueActionToPlay(pSeq)

################################################################################
#	ExitSet()
#
#	Handler called when object exits a set.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def ExitSet(pObject, pEvent):
	if g_bMissionTerminated:
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if not App.IsNull(pShip):
		# Get the name of the set exited
		pcSetName	= pEvent.GetCString()

#		kDebugObj.Print("Object \"%s\" exited set \"%s\"" % (pShip.GetName(), pcSetName))

		if (pShip.GetName() == "Unknown Ship"):
			if (pcSetName == "Voltair1"):
				if g_bHybridGone == 0:
					global g_bHybridGone
					g_bHybridGone = TRUE

					pBridge = App.g_kSetManager.GetSet("bridge")
					pMiguel = App.CharacterClass_GetObject(pBridge, "Science")
					pData = App.CharacterClass_GetObject(pBridge, "Data")
					pSaffi = App.CharacterClass_GetObject(pBridge, "XO")
					pKorbus = App.CharacterClass_Cast(pBridge.GetObject("Tactical"))

					pSeq = App.TGSequence_Create()
					pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Voltair1"))
					# Only add the EndCutscene if the Hybrid was scaned
					if (g_bHybridScanned):
						pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))

					# If the Hybrid warped out without
					# the player scanning it, mission loss.
#					debug("Hybrid scanned: " + str(g_bHybridScanned))
					if not g_bHybridScanned:
						MissionLib.QueueActionToPlay(pSeq)
						MissionFailDialog()
						return

#					debug("Scanning Hybrid: " + str(g_bScanning))
					pSeq.AppendAction(App.TGScriptAction_Create(__name__, "GetScanTrailSequence"))

					MissionLib.QueueActionToPlay(pSeq)

					MissionLib.AddGoal ("E4AnalyzeDataGoal")
		elif (pShip.GetName () == "player"):
			# If the player is warping, set communicate to say nothing
			global g_iMissionProgress
			g_iMissionProgress = 0
			
			# If the player is warping, remove any prods.
			global g_iScanProdID
			if (g_iScanProdID != App.NULL_ID):
				App.g_kTimerManager.DeleteTimer(g_iScanProdID)
				g_iScanProdID = App.NULL_ID


################################################################################
#	GetScanTrailSequence()
#
#	The dialogue sequence telling the user to scan the Hybrid's trail.
#
#	Args:	pAction
#
#	Return:	0
################################################################################
def GetScanTrailSequence(pAction = None):
	if g_bScanSeqPlayed:
		return 0
	global g_bScanSeqPlayed
	g_bScanSeqPlayed = TRUE
#	debug("GetScanTrailSequence() called.")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pKorbus = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	pSeq = App.TGSequence_Create()
	pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M4L031", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4VeryInteresting", "Captain", 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4Hurry", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4DoMyBest", None, 1, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4L032", None, 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "GalorsWarpIn"), 1.0)
	MissionLib.QueueActionToPlay(pSeq)
	
	return 0


################################################################################
#	ShipDestroyed(pObject, pEvent)
#
#	Object destroyed set event handler.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def ShipDestroyed(pObject, pEvent):
	if g_bMissionTerminated:
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip):
		pcName = pShip.GetName()
#		kDebugObj.Print(pcName + " destroyed.")

		# Get player's set name.
		pcSet = MissionLib.GetPlayer().GetContainingSet().GetName()

		if (pcSet == "Voltair1" and MissionLib.GetNumObjectsAlive(g_pEnemies) == 0 and g_bGalorsArrived and g_bMissionWon == FALSE):
			WinDialogue()

		if(pcName == "Mavjop"):
			MissionFailDialog(TRUE)


################################################################################
#	AimAtPlayer(pAction)
#
#	Set's the Mavjops AI to "look at" the player.
#	This is using a stationary attack AI without a fire preprocess.
#
#	Args:	pAction, the action.
#
#	Return:	None
################################################################################
def AimAtPlayer(pAction):
	pMavjop = MissionLib.GetShip("Mavjop")

	# Give it AI
	import Maelstrom.Episode4.E4M4.LookAtPlayerAI
	if pMavjop:
		pMavjop.SetAI(Maelstrom.Episode4.E4M4.LookAtPlayerAI.CreateAI(pMavjop))

	return 0


################################################################################
#	FollowPlayer(pAction)
#
#	Gives the Mavjop AI to follow the player.
#
#	Args:	pAction, the action.
#
#	Return:	None
################################################################################
def FollowPlayer(pAction):
	pMavjop = MissionLib.GetShip("Mavjop")
	
	import Maelstrom.Episode4.E4M4.FollowPlayerAI
	if pMavjop:
		pMavjop.SetAI(Maelstrom.Episode4.E4M4.FollowPlayerAI.CreateAI(pMavjop))

	return 0


###############################################################################
#	MavjopOnScreen(pAction)
#	
#	Put the Mavjop on screen.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def MavjopOnScreen(pAction):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		pMavjop = MissionLib.GetShip("Mavjop", pSet)
		MissionLib.ViewscreenWatchObject(pMavjop)

	return 0


###############################################################################
#	KorbusAboard(pAction)
#	
#	Korbus comes on the bridge. Move him into the set, configure him, etc.
#	Move Felix onto the Klingon bridge set.
#	Play dialogue sequence of Korbus walking on, talking to player.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def KorbusAboard(pAction):
	global g_bFelixOnBOP
	g_bFelixOnBOP = TRUE

	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pKiska = App.CharacterClass_GetObject(pSet, "Helm")
	pData = App.CharacterClass_GetObject(pSet, "Data")

	# Move Korbus to the Sovereign.
	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_Cast(pKBridgeSet.RemoveObjectFromSet("Korbus"))
	pKorbus.SetLocation("EBL1L")
	pSet.AddObjectToSet(pKorbus, "Tactical")
	pKorbus.SetCharacterName("Korbus")

	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()

	import Bridge.Characters.Korbus
	pLight = pKBridgeSet.GetLight("ambientlight1")
	pLight.RemoveIlluminatedObject(pKorbus)

	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pKorbus)

	# Set up character configuration
	pKorbus.SetSize(App.CharacterClass.LARGE)
	pKorbus.SetRandomAnimationChance(0.75)
	pKorbus.SetAudioMode(App.CharacterClass.CAM_EXTREMELY_VOCAL)
	pKorbus.SetBlinkAnimation("data/Animations/korbus_blink.NIF")
	pKorbus.SetDatabase("data/TGL/Korbus Bridge General.tgl")
	Bridge.Characters.Korbus.ConfigureForShip(pSet, pPlayer)
	Bridge.Characters.Korbus.ConfigureForSovereign(pKorbus)

	import Bridge.TacticalCharacterHandlers
	Bridge.TacticalCharacterHandlers.AttachMenuToTactical(pKorbus)

	Bridge.Characters.Korbus.LoadSounds()

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "FollowPlayer"))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_MOVE, "T"))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4L001", "Captain", 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4L002", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4L003", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4L004", None, 1, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4L005", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4L016", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4L017", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M4L017a", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "OpenVoltair"))

	MissionLib.QueueActionToPlay(pSeq)

	return 0

###############################################################################
#	FelixLeave(pAction)
#	
#	Have Felix leave the bridge.
#	
#	Args:	pAction, the script action.
#	
#	Return:	1
###############################################################################
def FelixLeave(pAction):
	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pFelix = App.CharacterClass_Cast(pSet.GetObject("Tactical"))

	# This is kind of a weird check to see if the character's menu is up, because
	# of the differences in tactical...
	if (pFelix.GetMenu().IsVisible()):
		kMenuName = App.TGString()
		pFelix.GetMenu().GetName(kMenuName)
		import BridgeHandlers
		BridgeHandlers.ToggleCharacterMenuW(pFelix, kMenuName)

	pSeq = App.TGSequence_Create()
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_MOVE, "L1"))
	pSeq.Play()

	return 0

################################################################################
#	OpenVoltair(pAction)
#
#	Open the Voltair system.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def OpenVoltair(pAction):
	# Import Voltair System Menu Items
	import Systems.Voltair.Voltair
	pVoltair = Systems.Voltair.Voltair.CreateMenus()
	
	MissionLib.AddGoal ("E4WarpToVoltairGoal")

	return 0


################################################################################
#	IntroDialogue()
#
#	Play mission introduction. Mavjop decloaks, hails player.
#
#	Args:	None
#
#	Return:	None
################################################################################
def IntroDialogue():
	# We are done warping, do the cutscene
	global g_bBriefingPlayed
	g_bBriefingPlayed = TRUE

	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject(pKBridgeSet, "Korbus")

	pTact = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")

	pMavjop = MissionLib.GetShip("Mavjop")
	pPlayer = MissionLib.GetPlayer()

	if not pMavjop or not pPlayer:
		return

	# Make the Mavjop identified, to fix the viewscreen camera watch lag.
	pSensors = pPlayer.GetSensorSubsystem()
	if pSensors:
		pSensors.ForceObjectIdentified(pMavjop)

	MissionLib.AddCommandableShip("Mavjop", "AttackTarget", "HelpMe", "DockWithStarbase12")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "LookForward"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MavjopOnScreen"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "AimAtPlayer"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "DeCloak", pMavjop))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "IncomingMsg4", g_pGeneralDatabase), 5.0)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus"))

	# If player completed E4M6 first.
	if(Maelstrom.Episode4.Episode4.g_bMission6Win):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKorbus, "E4KorbusAngry", g_pMissionDatabase))
	else:
		pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4Brief1", None, 0, g_pMissionDatabase))

	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4Brief2", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E4M4Brief3", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
									"PlacementWatch", "bridge", "Guest Head", "Guest Cam2"))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4Recommend", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4SaffiOrder", "T", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pTact, "E4M4YesCommander", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "FelixLeave"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M4FelixtoMavjop1", g_pMissionDatabase), 3)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKorbus, "E4M4FelixtoMavjop2", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1), 2)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M4FelixtoMavjop3", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M4FelixtoMavjop4", g_pMissionDatabase, 1, "E"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1), 5)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M4FelixtoMavjop5", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1"), 4)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M4FelixtoMavjop6", g_pMissionDatabase, 1, "E"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"), 4)
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4FelixtoMavjop7", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2"))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4FelixtoMavjop8", "C", 1, g_pMissionDatabase))

	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1))
	pBrexLine = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E4M4FelixtoMavjop9", "C", 1, g_pMissionDatabase)
	pSeq.AppendAction(pBrexLine)
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", "Captain", 1, g_pGeneralDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SwapFelix"))

	MissionLib.QueueActionToPlay(pSeq)

#########################################
# SwapFelix() - Swaps Felix to KBridge
#
def SwapFelix(pAction):
	
	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")

	# Swap Felix over to the Mavjop
	pFelix = App.CharacterClass_Cast(pSet.RemoveObjectFromSet("Tactical"))
	import Bridge.TacticalCharacterHandlers
	Bridge.TacticalCharacterHandlers.DetachMenuFromTactical(pFelix)
	pKBridgeSet.AddObjectToSet(pFelix, "Felix")
	pFelix.SetLocation("KlingonSeated")

	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")

	pSeq = MissionLib.NewDialogueSequence()

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Felix"))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4FelixHi", None, 0, g_pMissionDatabase))

	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1))
	pBrexLine = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E4M4KlingonOnBoard", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction(pBrexLine)

	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4FelixChat1", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4FelixChat2", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4FelixChat3", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4FelixChat4", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	# Start sequence where Korbus comes on board and sits at tactical.
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "KorbusAboard"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))

	MissionLib.QueueActionToPlay(pSeq)

	return 0


################################################################################
#	GalorsWarpIn(pAction)
#
#	Have the Galors warp in and begin attack.
#	Play dialogue sequence and set Mavjop to distract Galors.
#
#	Args:	pObject, pEvent
#
#	Return:	None
################################################################################
def GalorsWarpIn(pAction):
	pVoltair1 = App.g_kSetManager.GetSet("Voltair1")

	pGalor1 = loadspacehelper.CreateShip("Galor", pVoltair1, "Galor 1", "Galor1 Start", TRUE)
	pGalor2 = loadspacehelper.CreateShip("Galor", pVoltair1, "Galor 2", "Galor2 Start", TRUE)
	global g_bGalorsArrived
	g_bGalorsArrived = TRUE

	# Do a sequence
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pSaffi = App.CharacterClass_GetObject(pBridge, "XO")
	pMiguel = App.CharacterClass_GetObject(pBridge, "Science")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	pSeq = MissionLib.NewDialogueSequence()

	pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M4NewContacts", "Captain", 1, g_pMissionDatabase), 4.0)
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetGalorAI"))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4NotSure", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E4M4DivertAttention", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4NotABadIdea", "H", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HailMavjopDialogue"))
	pSeq.Play ()

	return 0

################################################################################
#	HailMavjopDialogue(pAction)
#
#	Play dialogue sequence hailing Felix on the Mavjop.
#
#	Args:	pAction, script action.
#
#	Return:	0
################################################################################
def HailMavjopDialogue(pAction):
	global g_bMavjopHailed
	g_bMavjopHailed = TRUE

	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pFelix = App.CharacterClass_GetObject(pKBridgeSet, "Felix")

	pSeq = MissionLib.NewDialogueSequence()

	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons"))
	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, pKiska.GetDatabase()), 0.5)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Felix"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4FelixHere", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4Distract", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4GotIt", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MavjopDistractGalors"))
	pSeq.Play ()

	return 0


################################################################################
#	SetGalorAI(pAction)
#
#	Set AI for galors to attack.
#
#	Args:	pAction, script action.
#
#	Return:	0
################################################################################
def SetGalorAI(pAction):
	pVoltair1 = App.g_kSetManager.GetSet("Voltair1")
	
	pGalor1 = App.ShipClass_GetObject (pVoltair1, "Galor 1")
	pGalor2 = App.ShipClass_GetObject (pVoltair1, "Galor 2")

	import Maelstrom.Episode4.E4M4.GalorAI
	if pGalor1:
		pGalor1.SetAI(Maelstrom.Episode4.E4M4.GalorAI.CreateAI(pGalor1))

	if pGalor2:
		pGalor2.SetAI(Maelstrom.Episode4.E4M4.GalorAI.CreateAI(pGalor2))

	return 0


################################################################################
#	SetEnemyAI(pAction)
#
#	Set AI for Keldons to attack. Change Mavjop's AI.
#	Set AI for Hybrid to flee.
#
#	Args:	pAction, script action.
#
#	Return:	0
################################################################################
def SetEnemyAI(pAction):
	pKeldon1 = MissionLib.GetShip("Keldon 1")
	pKeldon2 = MissionLib.GetShip("Keldon 2")
	pHybrid = MissionLib.GetShip("Unknown Ship")

	import GalorAI
	import HybridAI
	if pKeldon1:
		pKeldon1.SetAI(GalorAI.CreateAI(pKeldon1))
	if pKeldon2:
		pKeldon2.SetAI(GalorAI.CreateAI(pKeldon2))
	if pHybrid:
		pHybrid.SetAI(HybridAI.CreateAI(pHybrid))

	# Also change Mavjop to attack AI.
	pMavjop = MissionLib.GetShip("Mavjop")
	if pMavjop:
		import Maelstrom.Episode4.E4M4.MavjopAttackAI
		pMavjop.SetAI(Maelstrom.Episode4.E4M4.MavjopAttackAI.CreateAI(pMavjop))

	return 0


################################################################################
#	MavjopDamaged()
#
#	Called from MavjopAttackAI2
#	Have Felix hail from the Mavjop if his ship is getting damaged.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MavjopDamaged():
	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pFelix = App.CharacterClass_GetObject (pKBridgeSet, "Felix")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M4KiskaFelixHail", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Felix"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4FelixHailBad", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))

	MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	WinDialogue()
#
#	Called after all enemy ships destroyed.
#	Play mission win dialogue.
#
#	Args:	None
#
#	Return:	None
################################################################################
def WinDialogue():
#	kDebugObj.Print("Player has won the mission")

	global g_bMissionWon
	g_bMissionWon = TRUE

	# If Mission 1 (E4M6) complete set up Mission 3 (E4M5) 
	if Maelstrom.Episode4.Episode4.g_bMission6Win:
		MissionWin()

	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")

	pBridge = App.g_kSetManager.GetSet("bridge")
	pKTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	pBrex = App.CharacterClass_GetObject(pBridge, "Engineer")
	pKiska = App.CharacterClass_GetObject (pBridge, "Helm")
	pFelix = App.CharacterClass_GetObject (pKBridgeSet, "Felix")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")

	pMavjop = MissionLib.GetShip("Mavjop")
	MissionLib.RemoveCommandableShip("Mavjop")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4DoneAnalyze", "Captain", 0, g_pMissionDatabase))
	
	# If E4M6 completed, inform player that all info gathered.
	if(Maelstrom.Episode4.Episode4.g_bMission6Win):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M4SimilarTrails", g_pMissionDatabase, 0, "Captain"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M4ScannedHybrid2",	g_pMissionDatabase, 1, "Captain"))
		pEpisodeDatabase = MissionLib.GetEpisode().GetDatabase()
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4DataFindings",	pEpisodeDatabase))

	# E4M6 not completed, inform player that not enough info.
	else:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M4ScannedHybrid1",	g_pMissionDatabase, 0, "Captain"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M4AddingToDatabase", g_pMissionDatabase, 1, "Captain"))

		global g_iMissionProgress
		g_iMissionProgress = AT_END_NO_E4M6
		
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSeq.AppendAction(pAction)
	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E4M4Signaling", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Felix"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4FelixReturn", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M4FelixReturn2", "C", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4FelixReturn3", "S", 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M4FelixReturn4", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E4M4FelixReturn6", "S", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam2"))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4FelixReturn7", "C", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1))
	pSeq.AppendAction(App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E4M4BeamedBack", "Captain", 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam"))
	pSeq.AppendAction(App.CharacterAction_Create(pKTact, App.CharacterAction.AT_SAY_LINE, "E4M4L036", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "KorbusLeave"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1), 8.0)
	pSeq.AppendAction(App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "KorbusReturn", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "FelixReturns"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MavjopOnScreen"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "Cloak", pMavjop))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MavjopWarpOut"))
	
	# If E4M6 complete, prod player to Starbase 12.
	if Maelstrom.Episode4.Episode4.g_bMission6Win:
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E4InvestigateAreaGoal"))
		pEpisodeDatabase = MissionLib.GetEpisode().GetDatabase()
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4SaffiProdToSB12", pEpisodeDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E4ReturnSB12Goal"))
	# If E4M6 not complete, prod player to Nepenthe.
	else:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M4SaffiProd",	g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MissionWin"))

	MissionLib.QueueActionToPlay(pSeq)

	MissionLib.RemoveGoal ("E4AnalyzeDataGoal")

	return 0


################################################################################
#	KorbusLeave(pAction)
#
#	Have Korbus leave the bridge.
#
#	Args:	pObject	- The TGObject object.
#			
#	Return:	None
################################################################################
def KorbusLeave(pAction):
#	debug("KorbusLeave() called.")

	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pKorbus = App.CharacterClass_Cast(pSet.GetObject("Tactical"))
#	debug("Korbus Loc: " + pKorbus.GetLocation())

	# This is kind of a weird check to see if the character's menu is up, because
	# of the differences in tactical...
	if (pKorbus.GetMenu().IsVisible()):
		kMenuName = App.TGString()
		pKorbus.GetMenu().GetName(kMenuName)
		import BridgeHandlers
		BridgeHandlers.ToggleCharacterMenuW(pKorbus, kMenuName)

	pSeq = App.TGSequence_Create()
	pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_MOVE, "L1"))
	pSeq.AddCompletedEvent(MissionLib.CreateCompletionEvent(pAction))
	pSeq.Play()

	return 1

################################################################################
#	FelixReturns(pAction)
#
#	Have Felix return to the bridge.
#
#	Args:	pObject	- The TGObject object.
#			
#	Return:	None
################################################################################
def FelixReturns(pAction):
	global g_bFelixOnBOP
	g_bFelixOnBOP = FALSE

	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))

	pKorbus = App.CharacterClass_GetObject(pSet, "Tactical")
	import Bridge.TacticalCharacterHandlers
	Bridge.TacticalCharacterHandlers.DetachMenuFromTactical(pKorbus)
	import Bridge.Characters.Korbus
	Bridge.Characters.Korbus.FreeSounds()	# Get rid of Korbus's sounds, or they'll replace Felix's.
	pSet.DeleteObjectFromSet("Tactical")

	# Move Felix back to your bridge
	
	# Set Felix as hidden before moving him.
	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pFelixOnKlingonBridge = App.CharacterClass_GetObject(pKBridgeSet, "Felix")
	pFelixOnKlingonBridge.SetHidden(1)
	
	pSet.AddObjectToSet(pKBridgeSet.RemoveObjectFromSet("Felix"), "Tactical")
	pFelix = App.CharacterClass_Cast(pSet.GetObject("Tactical"))
	pFelix.SetHidden(1)
	pFelix.SetLocation("EBL1L")
	import Bridge.Characters.Felix
	Bridge.Characters.Felix.LoadSounds()	# Reload Felix's sounds, since Korbus unloaded them.

	import Bridge.TacticalCharacterHandlers
	Bridge.TacticalCharacterHandlers.AttachMenuToTactical(pFelix)

	pMiguel = App.CharacterClass_GetObject(pSet, "Science")

	pSeq = App.TGSequence_Create()
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_MOVE, "T"))

	MissionLib.QueueActionToPlay(pSeq)

	return 0


################################################################################
#	MavjopWarpOut(pAction)
#
#	Set AI for the Mavjop to warp out.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MavjopWarpOut(pAction):
	pMavjop = MissionLib.GetShip("Mavjop")

	if pMavjop:
		import Maelstrom.Episode4.E4M4.FinalWarpOutAI
		pMavjop.SetAI(Maelstrom.Episode4.E4M4.FinalWarpOutAI.CreateAI(pMavjop))

	MissionLib.RemoveGoal ("E4ProtectKorbusShipGoal")

	return 0


################################################################################
#	HybridWarpOut()
#
#	Set AI for the Hybrd to warp out. Called either from HybridAI timer or
#	from ScanTargetComplete().
#	
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def HybridWarpOut(pAction = None):
	if g_bHybridWarpingOut:
		return 0
	global g_bHybridWarpingOut
	g_bHybridWarpingOut = TRUE

	import Maelstrom.Episode4.E4M4.FinalWarpOutAI

	pHybrid = MissionLib.GetShip("Unknown Ship")
	if pHybrid:
		pSeq = App.TGSequence_Create()
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Voltair1"))
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Voltair1"))
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "WatchShipLeave", "Voltair1", "Unknown Ship"))

		MissionLib.QueueActionToPlay(pSeq)

		pHybrid.SetAI(Maelstrom.Episode4.E4M4.FinalWarpOutAI.CreateAI(pHybrid))

	return 0


################################################################################
#	MissionWin(pAction)
#
# 	Call Episode level, open up next Episode.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MissionWin(pAction = None):
	Maelstrom.Episode4.Episode4.Mission4Complete()
	return 0


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
	
	if (not g_bMissionFailed):
		# Check if we're scanning the area.
		iScanType = pEvent.GetInt ()
		if(iScanType == App.CharacterClass.EST_SCAN_AREA):
			# Start system scan.
			pPlayer = MissionLib.GetPlayer()
			if pPlayer:
				pcSetName = pPlayer.GetContainingSet().GetName()

				if pcSetName == "Voltair2":
					global g_bVoltair2Scanned
					g_bVoltair2Scanned = TRUE

					global g_iScanProdID
					if g_iScanProdID != App.NULL_ID:
						App.g_kTimerManager.DeleteTimer(g_iScanProdID)
						g_iScanProdID = App.NULL_ID
					ScanVoltair2()
					return
		elif (iScanType == App.CharacterClass.EST_SCAN_OBJECT):
			pPlayer = MissionLib.GetPlayer()
			if pPlayer:
				# Get the target.
				pTarget = App.ObjectClass_Cast(pEvent.GetSource())
				if pTarget is None:
					pTarget = pPlayer.GetTarget()
				if pTarget:
					if (pTarget.GetName () == "Unknown Ship" and g_bHybridScanned == FALSE):
						ScanHybrid(pTarget)
						return					

	pObject.CallNextHandler(pEvent)


################################################################################
#	ScanVoltair2()
#
#	Called by ScanHandler() if the player scanning Voltair 2.
#
#	Args:	None
#
#	Return:	None
################################################################################
def ScanVoltair2():
	if g_bMissionTerminated:
		return

	MissionLib.RemoveGoal("E4ScanAreaGoal")

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pBridge = App.g_kSetManager.GetSet("bridge")
		pMiguel = App.CharacterClass_GetObject(pBridge, "Science")

		pSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
		if pSeq is None:
			return
		pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M4OuterSystem", "Captain", 1, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E4WarpToVoltair1Goal"))
		pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
	
		MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	ScanHybrid(pHybrid)
#
#	Handle scanning of the Hybrid ship. Determine if player is close
#	enought to perform scan. If so create timer to call ScanTargetComplete().
#
#	Args:	None
#
#	Return:	None
################################################################################
def ScanHybrid(pHybrid):
	assert pHybrid
	
	# Get distance between player and target.
	fLen = MissionLib.GetDistance(pHybrid)

	pMiguel	= Bridge.BridgeUtils.GetBridgeCharacter("Science")

	pSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
	if pSeq is None:
		return

	if (fLen > MIN_HYBRID_SCAN_DISTANCE):
		# We're too far.  Say line to this effect.
		pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M4TooFar", None, 1, g_pMissionDatabase))

	else:
		global g_bHybridScanned
		g_bHybridScanned = TRUE

		# Remove the scan target goal
		MissionLib.RemoveGoal ("E4ScanHybridGoal")

		# Do the sequence
		pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")

		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetScanningFlag", TRUE))
		pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M4ScanHybrid", "Captain", 1, g_pMissionDatabase))
		pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4ScanHybrid2", "Captain", 1, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetScanningFlag", FALSE))
		
#		debug("ScanTargetComplete() - Hybrid gone: " + str(g_bHybridGone))
		if g_bHybridGone:
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "GetScanTrailSequence"))

		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HybridWarpOut"))

	pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
	MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	SetScanningFlag(pAction, bState)
#
#	Set "scanning unknown ship" flag. Used for timing of warp out sequence.
#
#	Args:	pAction, the script action.
#			bState, new value for flag.
#
#	Return:	0
################################################################################
def SetScanningFlag(pAction, bState):
	global g_bScanning
	g_bScanning = bState

	return 0


################################################################################
#	HailHandler()
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

	if g_bMissionFailed:
		pObject.CallNextHandler(pEvent)
		return

	pTarget = App.ObjectClass_Cast(pEvent.GetSource())

	if pTarget is None:
		pObject.CallNextHandler(pEvent)
		return

	pcName = pTarget.GetName()
	if pcName == "Mavjop":
		import Bridge.HelmMenuHandlers
		pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HailMavjop"))

		MissionLib.QueueActionToPlay(pSeq)

		return

	pObject.CallNextHandler(pEvent)


################################################################################
#	HailMavjop(pAction)
#
#	Handle hailing Mavjop.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def HailMavjop(pAction):
	pKBridgeSet	= App.g_kSetManager.GetSet("KBridgeSet")
	pFelix		= App.CharacterClass_GetObject (pKBridgeSet, "Felix")
	pKiska		= Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()

	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, pKiska.GetDatabase()))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Felix"))

	if g_bMavjopHailed and not g_bMissionWon:
		pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4FelixHail", None, 0, g_pMissionDatabase))

	else:
		pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M4FelixHail2", None, 0, g_pMissionDatabase))

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))

	MissionLib.QueueActionToPlay(pSeq)

	return 0


################################################################################
#	WarpHandler(pObject, pEvent)
#
#	Called when the "Warp" button in Kiska's menu is hit.  
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

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pcPlayerSetName = MissionLib.GetPlayer().GetContainingSet().GetName()
	if pcPlayerSetName == "Voltair1":
		pBridge = App.g_kSetManager.GetSet("bridge")
		pSaffi = App.CharacterClass_GetObject (pBridge, "XO")

		if g_bHybridGone:
			pAction = Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M4CantWarp", g_pMissionDatabase)

		else:
			pAction = Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "WarpStop2", g_pGeneralDatabase)

		pAction.Play()

		return

	pObject.CallNextHandler(pEvent)


################################################################################
#	MavjopDistractGalors(pAction)
#
#	Change Mavjop's AI to attack Galors, to "distract" them.
#	Change Galor's AI to attack Mavjop, got their attention.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def MavjopDistractGalors(pAction):
	# Set Mavjop AI.
	pMavjop = MissionLib.GetShip("Mavjop")

	if pMavjop:
		import Maelstrom.Episode4.E4M4.MavjopAttackAI2
		pMavjop.SetAI(Maelstrom.Episode4.E4M4.MavjopAttackAI2.CreateAI(pMavjop))

	# Set Galor's AI.
	pGalor1 = MissionLib.GetShip("Galor 1")
	pGalor2 = MissionLib.GetShip("Galor 2")

	# Change the galor's AI to attack the Mavjop.
	import Maelstrom.Episode4.E4M4.GalorAI2
	if pGalor1:
		pGalor1.SetAI(Maelstrom.Episode4.E4M4.GalorAI2.CreateAI(pGalor1))
		
	if pGalor2:
		pGalor2.SetAI(Maelstrom.Episode4.E4M4.GalorAI2.CreateAI(pGalor2))
	
	return 0


################################################################################
#	MissionFailDialog(bMavjopKilled = FALSE)
#
#	Handle mission failure. Play loss dialogue from Admiral Liu.
#
#	Args:	bMavjopKilled, if mission loss is because Mavjop destroyed.
#			Defaults to false.
#
#	Return:	None
################################################################################
def MissionFailDialog(bMavjopKilled = FALSE):
	pBridge	= App.g_kSetManager.GetSet("bridge")
	pData	= App.CharacterClass_GetObject(pBridge, "Data")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pKorbus = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	pLiuSet	= App.g_kSetManager.GetSet("LiuSet")
	pLiu 	= App.CharacterClass_GetObject (pLiuSet, "Liu")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
												"ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
								"PlacementWatch", "bridge", "View", "Player Cam"))

	pEndSeq = App.TGSequence_Create()

	if bMavjopKilled:
		pEndSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKorbus, "E4M4MavjopDead", g_pMissionDatabase))
		pEndSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M4MissionFail", g_pMissionDatabase))
	else:
		pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M4CantAnalyze", "Captain", 1, g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "HailStarfleet2", g_pGeneralDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "IncomingMsg5", g_pGeneralDatabase))
		pEndSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu"), 2.0)
		pEndSeq.AppendAction(App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E4M4L046", None, 0, g_pMissionDatabase))
		pEndSeq.AppendAction(App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E4M4Return", None, 0, g_pMissionDatabase))
		pEndSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "GameOver", pEndSeq))

	MissionLib.QueueActionToPlay(pSeq)

	global g_bMissionFailed
	g_bMissionFailed = TRUE

	return 0


################################################################################
#	StartProdTimer(pAction)
#
#	Create timer to prod player to scan region.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def StartProdTimer(pAction):
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_SCAN, __name__ + ".SayScanProd", fStartTime + 30.0, 0, 0)

	# Store off the timer ID so we can remove the prod.
	global g_iScanProdID
	g_iScanProdID = pTimer.GetObjID ()
	
	return 0


################################################################################
#	SayScanProd(pObject, pEvent)
#
#	Triggered from prod timer, play prod dialogue.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def SayScanProd(pObject, pEvent):
	if g_bMissionTerminated:
		return

	if g_bMissionFailed:
		return

	pMiguel	= Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M4SuggestScan", g_pMissionDatabase))
	
	pSeq.Play ()

	# Timer has been triggered.  Clear the ID.
	global g_iScanProdID
	g_iScanProdID = App.NULL_ID

	pObject.CallNextHandler (pEvent)


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
#	Terminate(pMission)
#
# 	Unload TGL, remove instance handlers, clean up.
#
#	Args:	pAction, TGAction
#			iProgress, new mission progress value.
#
#	Return:	None
################################################################################
def Terminate(pMission):
	global g_bMissionTerminated
	g_bMissionTerminated = TRUE

	MissionLib.SaveMission(__name__)

	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	global g_iScanProdID
	if (g_iScanProdID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iScanProdID)
		g_iScanProdID = App.NULL_ID

	# Clear set course menu
	App.SortedRegionMenu_SetPauseSorting(1)
	# Import Belaruz System Menu Items
	import Systems.Belaruz.Belaruz
	pBelaruz = Systems.Belaruz.Belaruz.CreateMenus()
	pBelaruz.SetMissionName()

	# Import Starbase System Menu Items
	import Systems.Starbase12.Starbase
	pStarbase = Systems.Starbase12.Starbase.CreateMenus()
	pStarbase.SetMissionName()

	App.SortedRegionMenu_SetPauseSorting(0)

	# Remove communicate handlers.
	Bridge.BridgeUtils.RemoveCommunicateHandlers()
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	pMenu = pData.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateData")
	
	# Instance handler for Miguel's Scan Area button
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pMiguel.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Instance handler for Kiska's Hail button
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pKiska.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Remove instance handler for Kiska's Warp button.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	MissionLib.ShutdownFriendlyFire()

#	kDebugObj.Print ("Terminating Episode 4, Mission 4.\n")
