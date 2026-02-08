###############################################################################
#	Filename:	E4M5.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 4 Mission 5
#	
#	Created:	04/01/01 - Alberto Fonseca
#	Modified:	01/22/02 - Tony Evans
###############################################################################
import App
import Maelstrom.Episode4.Episode4
import loadspacehelper
import MissionLib
import Bridge.BridgeUtils

#NonSerializedObjects = ( "debug", )
#debug = App.CPyDebug(__name__).Print

#
# Place event types here
#
ET_PICARD_ARRIVES			= App.Mission_GetNextEventType()
ET_ENDING_DIALOGUE			= App.Mission_GetNextEventType()
ET_PROD_MISSION_START		= App.Mission_GetNextEventType()
ET_DELAY_TIMER				= App.Mission_GetNextEventType()
ET_CRITICAL_SEQUENCE_RETRY	= App.Mission_GetNextEventType()

#
# Global variables 
#
TRUE			= 1
FALSE			= 0
g_bDebugPrint	= FALSE

g_bMissionTerminated		= 0 # Has mission terminated.
g_bBriefingPlayed			= 0 # Has mission briefing played.
g_bAllowDamageDialogue		= 0	# Allows the damage dialogue to be spoken and not overlap
g_bEnterChambanaDialogue	= 0	# Make sure this is only said once
g_bArrivedChambana			= 0	# Make sure transport ai is only set once
g_pEnemies					= 0	# Object group of friendly ships
g_pFriendlies				= 0	# Object group of enemy ships
g_pNeutrals					= 0 # Object group of neutral ships
g_bPicardHailed				= 0 # Has Picard been hailed.
g_bPicardIntroPlayed		= 0	# Make sure intro is only played once
g_bEndDialoguePlayed		= 0 # Make sure ending is only played once
g_pProxShipyard				= 0	# Proximity check for Shipyard.
g_bHybridScanned			= 0	# Flag for wether Hybrid ship was scanned.
g_bShipyardScanned			= 0 # Flag for wether Shipyard was scanned.
g_bShipyardDestroyed		= 0 # Flag for wether Shipyard was destroyed.
g_iMissionProgress			= 0 # Keep track of mission state.
g_bMissionWon				= 0 # Flag for wether player won mission.
g_bWarnPlayer				= 0 # Flag for wether to warn player when firing on friendlies.
g_bHybridWarn				= 0 # Flag for wether to warn player when firing on hybrids.
g_idFriendlyWarningTimer	= 0 # Timer for friendly fire warning delay.
g_idHybridWarningTimer		= 0 # Timer for hybrid fire warning delay.
g_pMissionDatabase			= None
g_pGeneralDatabase			= None
g_bSequencePlaying			= None
g_bAllowWarp				= 0

# Timer constants
PICARD_ARRIVE_DELAY	= 15

# Mission progress
AT_SB_12			= 1
AT_CHAMBANA			= 2
	

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
	loadspacehelper.PreloadShip("Galor", 2)
	loadspacehelper.PreloadShip("Keldon", 2)
	loadspacehelper.PreloadShip("CardStation", 2)
	loadspacehelper.PreloadShip("CardHybrid", 4)
	loadspacehelper.PreloadShip("Enterprise", 1)

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
#	DebugPrint("Initializing Episode 4, Mission 5.\n")
	
	# Clear the set course menu
	App.SortedRegionMenu_ClearSetCourseMenu()

	InitGlobals(pMission)

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	# Create Picard's bridge set.
	MissionLib.SetupBridgeSet("PBridgeSet", "data/Models/Sets/EBridge/EBridge.nif")
	pPicard = MissionLib.SetupCharacter("Bridge.Characters.Picard", "PBridgeSet")
	if pPicard:
		pPicard.SetLocation("SovereignSeated")
	
	# Load custom placements for bridge.
	pBridgeSet = Bridge.BridgeUtils.GetBridge()
	if pBridgeSet:
		import Maelstrom.Episode4.EBridge_P
		Maelstrom.Episode4.EBridge_P.LoadPlacements(pBridgeSet.GetName())

	# Create Admiral Liu's set.
	pLBridgeSet = MissionLib.SetupBridgeSet("LBridgeSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu = MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LBridgeSet", 0, 0, 5)
	
	CreateMenus()
	SetAffiliations(pMission)	
	CreateSpaceSets()
	CreateShips()
	SetupEventHandlers(pMission)

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)

	MissionLib.SetupFriendlyFire()

	MissionLib.AddGoal("E4GoToChambana1Goal")

	MissionLib.SaveGame("E4M3-")

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
	global g_bAllowDamageDialogue
	global g_bEnterChambanaDialogue
	global g_bArrivedChambana
	global g_pEnemies
	global g_pFriendlies
	global g_pNeutrals
	global g_bPicardIntroPlayed
	global g_bEndDialoguePlayed
	global g_bPicardHailed
	global g_pProxShipyard
	global g_bHybridScanned
	global g_bShipyardScanned
	global g_bShipyardDestroyed
	global g_iMissionProgress
	global g_bMissionWon
	global g_bWarnPlayer
	global g_bHybridWarn
	global g_idFriendlyWarningTimer
	global g_idHybridWarningTimer
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_bSequencePlaying
	global g_bAllowWarp

	g_bMissionTerminated		= FALSE
	g_bBriefingPlayed			= FALSE
	g_pGeneralDatabase			= None
	g_bAllowDamageDialogue		= TRUE
	g_bEnterChambanaDialogue	= FALSE
	g_bArrivedChambana			= FALSE
	g_pEnemies					= None
	g_pFriendlies				= None
	g_pNeutrals					= None
	g_bPicardHailed				= FALSE
	g_bPicardIntroPlayed		= FALSE
	g_bEndDialoguePlayed		= FALSE
	g_pProxShipyard				= None
	g_bHybridScanned			= FALSE
	g_bShipyardScanned			= FALSE
	g_bShipyardDestroyed		= FALSE
	g_iMissionProgress			= AT_SB_12
	g_bMissionWon				= FALSE
	g_bWarnPlayer				= TRUE
	g_bHybridWarn				= TRUE
	g_idFriendlyWarningTimer	= App.NULL_ID
	g_idHybridWarningTimer		= App.NULL_ID
	g_bSequencePlaying			= FALSE
	g_bAllowWarp				= TRUE
	g_pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 4/E4M5.tgl")
	g_pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")	

################################################################################
#	SetSequencePlayingFlag(pAction, bVal)
#
#	Set flag for wether non-interruptible sequence is playing.
#
#	Args:	pAction, the script action.
#			bVal, True/False
#
#	Return:	0
################################################################################
def SetSequencePlayingFlag(pAction, bVal):
	global g_bSequencePlaying
	g_bSequencePlaying = bVal

	return 0

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
	# Import Starbase System Menu Items
	import Systems.Starbase12.Starbase
	pStarbase = Systems.Starbase12.Starbase.CreateMenus()

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
	pStarbase12 = Systems.Starbase12.Starbase12.GetSet()

	import Systems.Chambana.Chambana1
	Systems.Chambana.Chambana1.Initialize()
	pChambana1 = Systems.Chambana.Chambana1.GetSet()

	import Systems.Chambana.Chambana2
	Systems.Chambana.Chambana2.Initialize()
	pChambana2 = Systems.Chambana.Chambana2.GetSet()

	# Add our custom placement objects for this mission.
	import Maelstrom.Episode4.E4M5.E4M5_Starbase12_P
	import Maelstrom.Episode4.E4M5.E4M5_Chambana1_P
	import Maelstrom.Episode4.E4M5.E4M5_Chambana2_P
	Maelstrom.Episode4.E4M5.E4M5_Starbase12_P.LoadPlacements(pStarbase12.GetName())
	Maelstrom.Episode4.E4M5.E4M5_Chambana1_P.LoadPlacements(pChambana1.GetName())
	Maelstrom.Episode4.E4M5.E4M5_Chambana2_P.LoadPlacements(pChambana2.GetName())

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
	import Systems.Starbase12.Starbase12
	import Systems.Chambana.Chambana1
	pStarbase12 = Systems.Starbase12.Starbase12.GetSet()
	pChambana1 = Systems.Chambana.Chambana1.GetSet()

	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pStarbase12, "player", "Player Start")
	pStarbase = loadspacehelper.CreateShip("FedStarbase", pStarbase12, "Starbase 12", "Starbase12 Location")
	pNebula = loadspacehelper.CreateShip("Nebula", pStarbase12, "USS Prometheus", "Nebula Start")
	pNebula.ReplaceTexture("data/Models/SharedTextures/FedShips/Prometheus.tga", "ID")

	pGalor1 = loadspacehelper.CreateShip("Galor", pChambana1, "Galor 1", "Galor1 Start")
	pGalor2 = loadspacehelper.CreateShip("Galor", pChambana1, "Galor 2", "Galor2 Start")
	pKeldon1 = loadspacehelper.CreateShip("Keldon", pChambana1, "Keldon 1", "Keldon1 Start")
	pKeldon2 = loadspacehelper.CreateShip("Keldon", pChambana1, "Keldon 2", "Keldon2 Start")
	pShipyard = loadspacehelper.CreateShip("CardStation", pChambana1, "Cardassian Shipyard", "Hybrid Shipyard")
	pKessok1 = loadspacehelper.CreateShip("CardHybrid", pChambana1, "Hybrid 1", "Hybrid1 Start")
	pKessok2 = loadspacehelper.CreateShip("CardHybrid", pChambana1, "Hybrid 2", "Hybrid2 Start")
	pKessok3 = loadspacehelper.CreateShip("CardHybrid", pChambana1, "Hybrid 3", "Hybrid3 Start")
	pKessok4 = loadspacehelper.CreateShip("CardHybrid", pChambana1, "Hybrid 4", "Hybrid4 Start")

	# Set Shipyard's splash damage to 10% of player's hull per sec.	
	if pPlayer:
		pShipyard.SetSplashDamage(pPlayer.GetHull().GetMaxCondition() * 0.10, pShipyard.GetRadius())

	# Make Cardassian warp engines invaulnerable so they can warp out after station destruction.
	MissionLib.MakeEnginesInvincible(pGalor1)
	MissionLib.MakeEnginesInvincible(pGalor2)
	MissionLib.MakeEnginesInvincible(pKeldon1)
	MissionLib.MakeEnginesInvincible(pKeldon2)

	if pNebula:
		import Maelstrom.Episode4.E4M5.E4M5NebulaAI
		pNebula.SetAI(Maelstrom.Episode4.E4M5.E4M5NebulaAI.CreateAI(pNebula))

	# Make Kessok ships appear to be powered down.
	# Set Hybrid ships to not create hulks when destroyed.
	import StayAI
	if pKessok1:
		pKessok1.DisableGlowAlphaMaps()
		pKessok1.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
		pKessok1.SetAI(StayAI.CreateAI(pKessok1))
		pKessok1.SetAlertLevel(App.ShipClass.GREEN_ALERT)
	if pKessok2:
		pKessok2.DisableGlowAlphaMaps()
		pKessok2.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
		pKessok2.SetAI(StayAI.CreateAI(pKessok2))
		pKessok2.SetAlertLevel(App.ShipClass.GREEN_ALERT)
	if pKessok3:
		pKessok3.DisableGlowAlphaMaps()
		pKessok3.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
		pKessok3.SetAI(StayAI.CreateAI(pKessok3))
		pKessok3.SetAlertLevel(App.ShipClass.GREEN_ALERT)
	if pKessok4:
		pKessok4.DisableGlowAlphaMaps()
		pKessok4.AddPythonFuncHandlerForInstance(App.ET_OBJECT_CONVERTED_TO_HULK, "MissionLib.IgnoreEvent")
		pKessok4.SetAI(StayAI.CreateAI(pKessok4))
		pKessok4.SetAlertLevel(App.ShipClass.GREEN_ALERT)

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
	g_pFriendlies.AddName("USS Enterprise")
	g_pFriendlies.AddName("USS Bradley")
	g_pFriendlies.AddName("Starbase 12")
	g_pFriendlies.AddName("USS Prometheus")

	global g_pEnemies
	g_pEnemies = pMission.GetEnemyGroup()
	g_pEnemies.AddName("Galor 1")
	g_pEnemies.AddName("Galor 2")
	g_pEnemies.AddName("Galor 3")
	g_pEnemies.AddName("Galor 4")
	g_pEnemies.AddName("Galor 5")
	g_pEnemies.AddName("Galor 6")
	g_pEnemies.AddName("Keldon 1")
	g_pEnemies.AddName("Keldon 2")
	g_pEnemies.AddName("Cardassian Shipyard")

	global g_pNeutrals
	g_pNeutrals = pMission.GetNeutralGroup()
	g_pNeutrals.AddName("Hybrid 1")
	g_pNeutrals.AddName("Hybrid 2")
	g_pNeutrals.AddName("Hybrid 3")
	g_pNeutrals.AddName("Hybrid 4")


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
	MissionLib.SetupWeaponHitHandlers(list(g_pFriendlies.GetNameTuple()))
	MissionLib.SetupWeaponHitHandlers(list(g_pNeutrals.GetNameTuple()), "FireAtHybridHandler")

	# Instance handler for Kiska's Hail button
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pHelm.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Instance handler for Kiska's Warp button.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	# Instance handler for Miguel's Scan Area button
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pMiguel.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ + ".EnterSet")

	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ + ".ExitSet")

	# Ship destroyed
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ + ".ShipDestroyed")

################################################################################
#	RemoveEventHandlers()
#
#	Remove any event handlers for this mission.
#
#	Args:	None
#
#	Return:	None
################################################################################
def RemoveEventHandlers():
	# Remove communicate handlers.
	Bridge.BridgeUtils.RemoveCommunicateHandlers()
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	pMenu = pData.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + 
											".CommunicateData")

	MissionLib.RemoveWeaponHitHandlers(list(g_pFriendlies.GetNameTuple()))
	MissionLib.RemoveWeaponHitHandlers(list(g_pNeutrals.GetNameTuple()), "FireAtHybridHandler")

	# Instance handler for Kiska's Hail button
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pHelm.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Instance handler for Kiska's Warp button.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	# Instance handler for Miguel's Scan Area button
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pMiguel.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

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
				
	if g_iMissionProgress == AT_CHAMBANA:
		if not g_bHybridScanned:
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M5CommData1",
																	g_pMissionDatabase))
		else:
			pObject.CallNextHandler(pEvent)
	else:
		pObject.CallNextHandler(pEvent)
			
	pSeq.Play()


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

	if g_iMissionProgress == AT_SB_12:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5CommSaffi1",
																g_pMissionDatabase))
	elif g_iMissionProgress == AT_CHAMBANA:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5CommSaffi2",
																g_pMissionDatabase))
	else:
		pObject.CallNextHandler(pEvent)
			
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
#	print("Felix Communicating...")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == AT_SB_12:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M5CommFelix1",
																g_pMissionDatabase))
		# If player needs to reload torps.
		if not MissionLib.IsFullyLoaded():
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M5CommFelix2",
																	g_pMissionDatabase))
		# Ready to go.
		else:
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M5CommFelix3",
																	g_pMissionDatabase))
	elif g_iMissionProgress == AT_CHAMBANA:
		# Get shipyards shields status.
		pShipyard = MissionLib.GetShip("Cardassian Shipyard")
		if pShipyard:
				if MissionLib.IsAnyShieldBreached(pShipyard):
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M5CommFelix5",
																			g_pMissionDatabase))
				else:
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M5CommFelix4",
																			g_pMissionDatabase))
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
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == AT_SB_12:
		pObject.CallNextHandler(pEvent)
	elif g_iMissionProgress == AT_CHAMBANA:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M5CommKiska1",
																g_pMissionDatabase))
	else:
		pObject.CallNextHandler(pEvent)

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
#	print("Miguel Communicating...")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == AT_SB_12:
		pObject.CallNextHandler(pEvent)
	elif g_iMissionProgress == AT_CHAMBANA:
		pObject.CallNextHandler(pEvent)
	else:
		pObject.CallNextHandler(pEvent)

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
#	print("Brex Communicating...")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")

	if g_bMissionWon:
		pObject.CallNextHandler(pEvent)
		return

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == AT_SB_12:
		pObject.CallNextHandler(pEvent)
	elif g_iMissionProgress == AT_CHAMBANA:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pBrex, "E4M5CommBrex1",
																g_pMissionDatabase))
	else:
		pObject.CallNextHandler(pEvent)

	pSeq.Play()


################################################################################
#	WeaponHitHandler(pObject, pEvent)
#
#	Called when a hostile ship is hit.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def WeaponHitHandler(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	# Check for player firing on a valid target.
	pAttacker = App.ShipClass_Cast(pEvent.GetFiringObject())
	if not pAttacker:
		pObject.CallNextHandler(pEvent)
	   	return
	if pAttacker.GetName() != "player":
		pObject.CallNextHandler(pEvent)
		return
	else:
		pSet = pAttacker.GetContainingSet()
		if pSet is None:
			pObject.CallNextHandler(pEvent)
		   	return
	pTarget = App.ShipClass_Cast(pEvent.GetTargetObject())
	if pTarget is None:
		pObject.CallNextHandler(pEvent)
		return
		
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	# Only warn every so often and if Shipyard is alive.
	if g_bWarnPlayer and MissionLib.IsInSameSet("Cardassian Shipyard"):
		pTargetOfTarget = pTarget.GetTarget()
		if ((pTargetOfTarget != None) and (pTargetOfTarget.GetName() != "player")):
			pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
			pPicard = App.CharacterClass_GetObject(pPBridgeSet, "Picard")
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E4M5IncomingMessage", None, 0, g_pMissionDatabase))
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Picard"))
			pSeq.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5PicardFriendlyFire", None, 0, g_pMissionDatabase))
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
			MissionLib.QueueActionToPlay(pSeq)

		# Update hostile fire warning flag.
		UpdateHostileWarningDelay()

	pObject.CallNextHandler(pEvent)

################################################################################
#	UpdateHostileWarningDelay(pObject = None, pEvent = None)
#
#	Updates the warning delay flag when player fires at an enemy ship.
#	
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def UpdateHostileWarningDelay(pObject = None, pEvent = None):
	# Player firing..
	if (pObject is None) and (pEvent is None):
		if g_idFriendlyWarningTimer == App.NULL_ID:
#			print "Creating timer, Warning disabled...."
			# Start our timers to control the flags
			fStartTime	= App.g_kUtopiaModule.GetGameTime()
			pTimer = MissionLib.CreateTimer(ET_DELAY_TIMER, __name__ + 
							".UpdateHostileWarningDelay", fStartTime + 30, 0, 0)
			global g_idFriendlyWarningTimer
			g_idFriendlyWarningTimer = pTimer.GetObjID()
			global g_bWarnPlayer
			g_bWarnPlayer = FALSE
	# Timer elapsed.
	else:
#		print "TimerElapsed: Re-Enable warning."
		# Clear timer.
		global g_idFriendlyWarningTimer
		g_idFriendlyWarningTimer = App.NULL_ID

		# Re-enable warning.
		global g_bWarnPlayer
		g_bWarnPlayer = TRUE

################################################################################
#	FireAtHybridHandler(pObject, pEvent)
#
#	Called when player fires on a hybrid ship.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def FireAtHybridHandler(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	# Check for player firing on a valid target.
	pAttacker = pEvent.GetFiringObject()
	if not pAttacker:
		pObject.CallNextHandler(pEvent)
	   	return
	if pAttacker.GetName() != "player":
		pObject.CallNextHandler(pEvent)
		return
	else:
		pSet = pAttacker.GetContainingSet()
		if pSet is None:
			pObject.CallNextHandler(pEvent)
		   	return
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return
		
	pTarget = pPlayer.GetTarget()
	if pTarget is None:
		pObject.CallNextHandler(pEvent)
		return

#	print "FireAtHybridHandler: " + pTarget.GetName()

	# Only warn every so often and if Shipyard is alive.
	if g_bHybridWarn and MissionLib.IsInSameSet("Cardassian Shipyard"):
		pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pData, "E4M5CommData2", g_pMissionDatabase))
	
		MissionLib.QueueActionToPlay(pSeq)

		# Update friendly fire warning flag.
		UpdateHybridWarningDelay()

	pObject.CallNextHandler(pEvent)

################################################################################
#	UpdateHybridWarningDelay(pObject = None, pEvent = None)
#
#	Updates the warning delay flag when player fires at a hybrid ship.
#	
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def UpdateHybridWarningDelay(pObject = None, pEvent = None):
	# Player firing..
	if (pObject is None) and (pEvent is None):
		if g_idHybridWarningTimer == App.NULL_ID:
#			print "Creating timer, Warning disabled...."
			# Start our timers to control the flags
			fStartTime	= App.g_kUtopiaModule.GetGameTime()
			pTimer = MissionLib.CreateTimer(ET_DELAY_TIMER, __name__ + 
								".UpdateHybridWarningDelay", fStartTime + 30, 0, 0)

			global g_idHybridWarningTimer
			g_idHybridWarningTimer = pTimer.GetObjID()

			global g_bHybridWarn
			g_bHybridWarn = FALSE
	# Timer elapsed.
	else:
#		print "TimerElapsed: Re-Enable warning."
		# Clear timer.
		global g_idHybridWarningTimer
		g_idHybridWarningTimer = App.NULL_ID

		# Re-enable warning.
		global g_bHybridWarn
		g_bHybridWarn = TRUE

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

	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if pTarget:
		import Bridge.HelmMenuHandlers

		pcName = pTarget.GetName()
		pcSetName = pTarget.GetContainingSet().GetName()
		if pcName == "USS Enterprise":

			if pcSetName == "Starbase12":
				global g_bPicardHailed
				g_bPicardHailed = TRUE

				pSeq = Bridge.HelmMenuHandlers.GetHailSequence(1.5, "E4M5KiskaHailPicard", g_pMissionDatabase)

				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HailPicardSB12"))

			elif pcSetName == "Chambana1":
				if not g_bMissionWon:
					pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
					pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HailPicardChambana"))
			
				else:
					if MissionLib.GetNumObjectsAlive(g_pEnemies) == 0:
						pSeq = Bridge.HelmMenuHandlers.GetHailSequence(1.0, "E4M5KiskaHailPicard", g_pMissionDatabase)
						pSeq.AppendAction(App.TGScriptAction_Create(__name__, "EndingDialogue", None, TRUE))
					else:
						pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
						pSeq.AppendAction(App.TGScriptAction_Create(__name__, "PicardBusy"))
			else:
				pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "PicardBusy"))

			MissionLib.QueueActionToPlay(pSeq)

			return

	pObject.CallNextHandler(pEvent)

################################################################################
#	HailPicardSB12(pAction)
#
#	Hail the Enterprise while it's still at Starbase 12.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def HailPicardSB12(pAction):
	pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
	pPicard = App.CharacterClass_GetObject(pPBridgeSet, "Picard")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	if not g_bPicardIntroPlayed:
		PicardIntro()
		return 0
	
	if not g_bViewscreenInUse:
		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Picard"), 2.0)
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pPicard, "E4M5PicardHail1", g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
		MissionLib.QueueActionToPlay(pSeq)

	return 0

################################################################################
#	HailPicardChambana(pAction)
#
#	Hail the Enterprise while it's in Chambana 1, shipyard not destroyed.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def HailPicardChambana(pAction):
	pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
	pPicard = App.CharacterClass_GetObject(pPBridgeSet, "Picard")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pEnterprise = MissionLib.GetShip("USS Enterprise")

	fShields = 0.0
	pShields = pEnterprise.GetShields()
	if(pShields):
		fShields = pShields.GetConditionPercentage()

	fHull = pEnterprise.GetHull().GetConditionPercentage()
	fPower = pEnterprise.GetPowerSubsystem().GetConditionPercentage()
	
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Picard"))

	if (fHull < 0.75) or (fPower < 0.75):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pPicard, "E4M5PicardHail4", g_pMissionDatabase))
	elif fShields < 0.5:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pPicard, "E4M5PicardHail3", g_pMissionDatabase))
	else:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pPicard, "E4M5PicardHail2", g_pMissionDatabase))

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
	pSeq.Play()

	return 0

################################################################################
#	PicardBusy(pAction)
#
#	Hail the Enterprise while it's in Chambana 1 and shipyard destroyed.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def PicardBusy(pAction):
	pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
	pPicard = App.CharacterClass_GetObject(pPBridgeSet, "Picard")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pEnterprise = MissionLib.GetShip("USS Enterprise")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Picard"))

	pE7M1Database = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 7/E7M1.tgl")
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pPicard, "E7M1HailingPicard", pE7M1Database))
	App.g_kLocalizationManager.Unload(pE7M1Database)

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
	pSeq.Play()
	
	return 0

################################################################################
#	ScanHandler()
#
#	Called when the "Scan" button in Miguel's menu is hit.  
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

	import Bridge.ScienceCharacterHandlers

	# Check if we're scanning the area.
	iScanType = pEvent.GetInt()
	if iScanType == App.CharacterClass.EST_SCAN_OBJECT:
		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if pTarget is None:
			pTarget = MissionLib.GetPlayer().GetTarget()
		if(pTarget):
			pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")

			sTargetName = pTarget.GetName()
			if sTargetName[0:6] == "Hybrid":
				pShip = App.ShipClass_GetObject(App.SetClass_GetNull(), sTargetName)
				if g_bShipyardDestroyed or (pShip == None) or pShip.IsDying():
					pObject.CallNextHandler(pEvent)
					return

				pSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
				if pSeq is None:
					return

				if g_bHybridScanned:
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel,
					MissionLib.GetRandomLine(["gs038", "gs039", "gs040", "gs041"]), g_pGeneralDatabase))
				else:
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M5ScanKessok", g_pMissionDatabase))
					global g_bHybridScanned
					g_bHybridScanned = TRUE
			
				pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))

				MissionLib.QueueActionToPlay(pSeq)

				return

			elif sTargetName == "Cardassian Shipyard":
				pSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
				if pSeq is None:
					return
				if g_bShipyardScanned:
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel,
					MissionLib.GetRandomLine(["gs038", "gs039", "gs040", "gs041"]), 
																g_pGeneralDatabase))
				else:
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel,
										"E4M5ScanShipyard", g_pMissionDatabase))
					global g_bShipyardScanned
					g_bShipyardScanned = TRUE
				pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))

				MissionLib.QueueActionToPlay(pSeq)

				return
					
	pObject.CallNextHandler(pEvent)


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

	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		return

	pcPlayerSetName = pPlayer.GetContainingSet().GetName()
	if pcPlayerSetName == "Chambana1":
		if not g_bMissionWon:
			pEnterprise = MissionLib.GetShip("USS Enterprise")
			if pEnterprise:
				pBridge = App.g_kSetManager.GetSet("bridge")
				pKiska = App.CharacterClass_GetObject (pBridge, "Helm")

				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pPicard = App.CharacterClass_GetObject (pEBridgeSet, "Picard")

				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E4M5IncomingMessage", None, 0, g_pMissionDatabase))
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Picard"))
				pSeq.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5ProdNoWarp", None, 0, g_pMissionDatabase))
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
				MissionLib.QueueActionToPlay(pSeq)
				return
			else:
				pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "WarpStop1", g_pGeneralDatabase))
				pSeq.Play()
				return
		elif not g_bAllowWarp:
			pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "WarpStop1", g_pGeneralDatabase))
			pSeq.Play()
			return

	# Here we're adding the Chambana cutscene to the end
	# of the warp sequence so it plays properly.
	elif pcPlayerSetName == "Starbase12":
		EnterChambanaDialogue()

	pObject.CallNextHandler(pEvent)

################################################################################
#	ShipyardProx(pObject, pEvent)
#
#	Play warning dialogue when player get's too close to shipyards.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def ShipyardProx(pObject, pEvent):
	if g_bMissionTerminated:
		return

	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pAction = Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5ProdTooClose", g_pMissionDatabase)
	pAction.Play()

	# Remove proximity check
	global g_pProxShipyard
	if g_pProxShipyard:
		g_pProxShipyard.RemoveAndDelete()
		g_pProxShipyard = None

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

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return
		
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	pSet = App.g_kSetManager.GetRenderedSet()
	if not App.IsNull(pShip):
		# It's a ship.
		pSet = pShip.GetContainingSet()
		sSetName = pSet.GetName()
		sShipName = pShip.GetName()
		
		# Say Hi to the player if he's in the set \
		if(sShipName == "player"):
			if(sSetName == "Chambana1"):
				global g_iMissionProgress
				g_iMissionProgress = AT_CHAMBANA
				if not g_bArrivedChambana:
					global g_bArrivedChambana
					g_bArrivedChambana = TRUE

					# Prevent player from warping.
					global g_bAllowWarp
					g_bAllowWarp = FALSE

					# Update the goals
					MissionLib.AddGoal("E4DestroyShipyardsGoal")
					MissionLib.RemoveGoal("E4GoToChambana1Goal")

					# Create proximity checks
					global g_pProxShipyard
					pShipyard = MissionLib.GetShip("Cardassian Shipyard")
					pStarbase12 = pShipyard.GetContainingSet()
					g_pProxShipyard = MissionLib.ProximityCheck(pShipyard, -400, [pPlayer], __name__ + ".ShipyardProx", pStarbase12)
		
			elif(sSetName == "Starbase12"):
				global g_iMissionProgress
				if(not g_bBriefingPlayed):
					PlayBriefing()
					g_iMissionProgress = AT_SB_12
				else:
					g_iMissionProgress = FALSE

		if (sShipName == "USS Enterprise"):
			if (sSetName == "Starbase12"):
				if (pPlayer.GetContainingSet().GetName() == "Starbase12"):
					EnterpriseArrive()

	# We're done.  Let any other handlers for this event handle it.
	pObject.CallNextHandler(pEvent)

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

	if(pShip and (not pShip.IsDead()) and (not pShip.IsDying())):
		if pEvent.GetCString() == "Chambana1":
			if g_pEnemies.IsNameInGroup(pShip.GetName()):
				if MissionLib.GetNumObjectsAlive(g_pEnemies) == 0:
					MissionLib.RemoveGoal("E4ProtectEnterpriseGoal")
					if not g_bMissionWon:
						ShipyardDestroyed()
					App.TGScriptAction_Create(__name__, "EndingDialogue").Play()

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

	if g_iMissionProgress == AT_CHAMBANA:
		pShip = App.ShipClass_Cast(pEvent.GetDestination())
		if pShip:
			pcName = pShip.GetName()
#			debug(pcName + " destroyed.")
			if pcName == "player":
				return
			elif(pcName == "USS Enterprise"):
				FailGame()
			elif(pcName == "Cardassian Shipyard"):
				ShipyardDestroyed()

################################################################################
#	ShipyardDestroyed()
#
#	Handle shipyard being destroyed. Update goals, play dialogue.
#
#	Args:	None
#
#	Return:	None
################################################################################
def ShipyardDestroyed():
	MissionLib.RemoveGoal("E4DestroyShipyardsGoal")
	
	if g_bShipyardDestroyed:
		return

	global g_bShipyardDestroyed
	g_bShipyardDestroyed = TRUE

	if not g_bMissionWon:
		global g_bMissionWon
		g_bMissionWon = TRUE

	# Play dialogue telling player shipyard is destroyed and Hybrids self-destructing.
	pTact = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetSequencePlayingFlag", TRUE))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pTact, "E4M5L022", g_pMissionDatabase))

	# If any Hybrids alive.
	if(MissionLib.GetNumObjectsAlive(g_pNeutrals)):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M5KessokEnergy", g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "DestroyHybrids"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M5KessokDestruct", g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5KessokScanDebris", g_pMissionDatabase), 3.0)
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E4M5KessokNoDebris", g_pMissionDatabase))

	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetSequencePlayingFlag", FALSE))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E4ProtectEnterpriseGoal"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "EndingDialogue"), 2.0)

	MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	PlayBriefing()
#
#	Play mission briefing.
#
#	Args:	None
#
#	Return:	None
################################################################################
def PlayBriefing():
	global g_bBriefingPlayed
	g_bBriefingPlayed = TRUE
	
	# Get Liu
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	# Create and play sequence.
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M5LiuHail", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5SaffiOnScreen", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4M5Brief1", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4M5Brief1a", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4M5Brief2", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4M5Brief3", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "PicardWarpsIn"))

	MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	PicardWarpsIn(pAction)
#
#	Have the Enterprise warp in after mission briefing.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def PicardWarpsIn(pAction):
	pStarbase12 = App.g_kSetManager.GetSet("Starbase12")

	pEnterprise = loadspacehelper.CreateShip("Enterprise", pStarbase12, 
											"USS Enterprise", "Enterprise Start", TRUE)
	pEnterprise.ReplaceTexture("Data/Models/Ships/Sovereign/Enterprise.tga", "ID")
	
	import StayAI
	pEnterprise.SetAI(StayAI.CreateAI(pEnterprise))

	pEnterprise.SetHailable(0)

	MissionLib.MakeEnginesInvincible(pEnterprise)
	MissionLib.SetupWeaponHitHandlers(["Galor 1", "Galor 2", "Keldon 1", "Keldon 2"])
	MissionLib.AddGoal("E4ProtectEnterpriseGoal")

	return 0

################################################################################
#	EnterpriseArrive()
#
#	Notify player Enterprise is here. Called from EnterSet() for the Enterprise.
#
#	Args:	None
#
#	Return:	None
################################################################################
def EnterpriseArrive():
	if g_bPicardHailed:
		return
	if g_bPicardIntroPlayed:
		return

	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E4M5EnterpriseArrive", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE))
	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E4M5L008", "Captain", 1, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "PicardIntro"))

	MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	PicardIntro(pAction)
#
#	Play Captain Picard's intro dialogue. 
#	Called from EnterSet() for the Enterprise.
#
#	Args:	None
#
#	Return:	0
################################################################################
def PicardIntro(pAction):
	if g_bPicardIntroPlayed:
		return

	global g_bPicardIntroPlayed
	g_bPicardIntroPlayed = TRUE

	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	pSci = App.CharacterClass_GetObject(pBridge, "Science")
	pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
	pPicard = App.CharacterClass_GetObject (pPBridgeSet, "Picard")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetViewscreenFlag", TRUE))
	pSeq.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5L009", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5L010", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M5L011", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5L012", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5L013", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetViewscreenFlag", FALSE))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "OpenChambana"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetEnterpriseAI"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProdTimer"))

	MissionLib.QueueActionToPlay(pSeq)

	return 0

	
################################################################################
#	OpenChambana(pAction)
#
#	Open up the Chambana system.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def OpenChambana(pAction):
	# Import Chambana System Menu Items
	import Systems.Chambana.Chambana
	pChambana = Systems.Chambana.Chambana.CreateMenus()

	pChambana.SetRegionName("Systems.Chambana.Chambana1")

	# Link Chambana1 button to player start placement.
	MissionLib.LinkMenuToPlacement("Chambana", None, "Player Start Chambana1")

	return 0

################################################################################
#	SetEnterpriseAI(pAction = None)
#
#	Give Enterprise AI to follow player to Chambana and engage enemy.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def SetEnterpriseAI(pAction = None):
	pEnterprise = App.ShipClass_GetObject(None, "USS Enterprise")
	if pEnterprise:
		import Maelstrom.Episode4.E4M5.E4M5PicardAI
		pEnterprise.SetAI(Maelstrom.Episode4.E4M5.E4M5PicardAI.CreateAI(pEnterprise))

		pEnterprise.SetHailable(1)

	return 0

################################################################################
#	StartProdTimer(pAction = None)
#
#	Create timer to prod player to begin mission.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def StartProdTimer(pAction):
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_PROD_MISSION_START, __name__ + ".ProdPlayer", fStartTime + 60, 0, 0)
	return 0

################################################################################
#	ProdPlayer(pObject, pEvent)
#
#	Play dialogue prodding player to start mission.
#	Called from timer event.
#
#	Args:	pObject,
#			pEvent
#
#	Return:	None
################################################################################
def ProdPlayer(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		if pSet:
			if pSet.GetName() == "Starbase12":
				pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5ProdLeave", g_pMissionDatabase))

				MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	CallDamage(sShipName, sSystemName, iPercentageLeft)
#
#	Play damage dialogue when Enterprise takes damamge.
#	Called from AI.
#
#	Args:	sShipName		-	Name of the ship taking damage
#			sSystemName		-	Name of the system being damaged
#			iPercentageLeft -	How much they have left of the system
#
#	Return:	None
################################################################################
def CallDamage(sShipName, sSystemName, iPercentageLeft):
	# Make sure Enterprise is in player's set.
	if MissionLib.GetShip("USS Enterprise") == None:
		return

	if not g_bAllowDamageDialogue:
		return

	pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
	pPicard = App.CharacterClass_GetObject (pPBridgeSet, "Picard")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	bPicardHail = FALSE

	if sShipName == "USS Enterprise":
		if sSystemName == "Shields":
			if(iPercentageLeft == 50):
				pDialogue = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5L016", None, 0, g_pMissionDatabase)
			elif (iPercentageLeft == 25):
				pDialogue = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5L016a", None, 0, g_pMissionDatabase)
			elif (iPercentageLeft == 0):
				pDialogue = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5L016b", None, 0, g_pMissionDatabase)
			else:
				return

		elif sSystemName == "HullPower":
			bPicardHail = TRUE
			if (iPercentageLeft == 25):
				pDialogue = App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5L017", None, 0, g_pMissionDatabase)
			else:
				return
		else:
			return

	pPicardOn = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Picard")
	pViewOff = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pReAllow = App.TGScriptAction_Create("Maelstrom.Episode4.E4M5.E4M5", "ReAllowDamageDialogue")


	pSeq = MissionLib.NewDialogueSequence()
	if bPicardHail:
		pSeq.AppendAction(pPicardOn)
		pSeq.AppendAction(pDialogue)
		pSeq.AppendAction(pViewOff)
	else:
		pSeq.AppendAction(pDialogue)
	pSeq.AppendAction(pReAllow, 3.0)

	MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	ReAllowDamageDialogue(pAction)
#
#	Reset flag to allow Picard's damage dialogue to play.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def ReAllowDamageDialogue(pAction):
	global g_bAllowDamageDialogue
	g_bAllowDamageDialogue = TRUE

	return 0

################################################################################
#	EnterChambanaDialogue(pAction)
#
#	Play dialogue sequence right after player warps into the Chamban system.
#
#	Args:	None
#
#	Return:	None
################################################################################
def EnterChambanaDialogue():
	if g_bMissionTerminated:
		return

	if g_bEnterChambanaDialogue:
		return

	global g_bEnterChambanaDialogue
	g_bEnterChambanaDialogue = TRUE

	pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
	pPicard = App.CharacterClass_GetObject (pPBridgeSet, "Picard")
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", "Chambana1"))	

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Chambana1")
	pSeq.AppendAction(pAction)
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Chambana1", "Cardassian Shipyard"))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M5L014", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E4M5Several", None, 0, g_pMissionDatabase), 1)
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Chambana1", "Hybrid 1"))
	pSeq.AppendAction(App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E4M5NotSure", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "Hybrid 1"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Chambana1"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E4M5Hybrids", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1"))
	pSeq.AppendAction(App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E4M5KessokNoThreat", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam"))

	pSeq.AppendAction(App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E4M5IncomingMessage", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Picard"))
	pSeq.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E4M5PicardInChambana", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "Cardassian Shipyard"))
	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetEnemyShipAI"))
	
	# Add this sequence after the warp sequence.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.AddActionAfterWarp(pSeq, 0.0)

################################################################################
#	SetEnemyShipAI(pAction)
#
#	Set AI of enemy ships to attack player and Enterprise.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def SetEnemyShipAI(pAction):
	import KeldonAttackAI
	import GalorAttackAI
	import ShipyardAI
	
	pShipyard = MissionLib.GetShip("Cardassian Shipyard")
	assert pShipyard
	if(pShipyard):
		pShipyard.SetAI(ShipyardAI.CreateAI(pShipyard))

	pKeldon1 = MissionLib.GetShip("Keldon 1")
	assert pKeldon1
	if(pKeldon1):
		pKeldon1.SetAI(KeldonAttackAI.CreateAI(pKeldon1))
	
	pKeldon2 = MissionLib.GetShip("Keldon 2")
	assert pKeldon2
	if(pKeldon2):
		pKeldon2.SetAI(KeldonAttackAI.CreateAI(pKeldon2))

	pGalor1 = MissionLib.GetShip("Galor 1")
	assert pGalor1
	if(pGalor1):
		pGalor1.SetAI(GalorAttackAI.CreateAI(pGalor1, "player"))

	pGalor2 = MissionLib.GetShip("Galor 2")
	assert pGalor2
	if(pGalor2):
		pGalor2.SetAI(GalorAttackAI.CreateAI(pGalor2, "USS Enterprise"))

	return 0

################################################################################
#	PicardWarpOut(pAction)
#
#	Give Enterprise AI to warp out of system.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def PicardWarpOut(pAction):
	pEnterprise = MissionLib.GetShip("USS Enterprise")
	if pEnterprise:
		import Maelstrom.Episode4.E4M5.FinalWarpOutAI
		pEnterprise.SetAI(Maelstrom.Episode4.E4M5.FinalWarpOutAI.CreateAI(pEnterprise))
	return 0

################################################################################
#	DestroyHybrids(pAction)
#
#	Give self-destruct AI to any Hybrid ships remaining.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def DestroyHybrids(pAction):
	if g_bMissionTerminated:
		return 0

	# Destroy any existing Hybrids.
	pHybrid1 = MissionLib.GetShip("Hybrid 1")
	pHybrid2 = MissionLib.GetShip("Hybrid 2")
	pHybrid3 = MissionLib.GetShip("Hybrid 3")
	pHybrid4 = MissionLib.GetShip("Hybrid 4")

	import DestructAI
	if pHybrid1:
		pHybrid1.SetAI(DestructAI.CreateAI(pHybrid1), 0, 0)
	if pHybrid2:
		pHybrid2.SetAI(DestructAI.CreateAI(pHybrid2), 0, 0)
	if pHybrid3:
		pHybrid3.SetAI(DestructAI.CreateAI(pHybrid3), 0, 0)
	if pHybrid4:
		pHybrid4.SetAI(DestructAI.CreateAI(pHybrid4), 0, 0)

	return 0

################################################################################
#	EndingDialogue(pAction, pEvent = None, bPlayerHailing = FALSE)
#
#	Play mission ending dialogue with Picard. Load next episode.
#
#	Args:	pAction, the script action.
#			pEvent, default arg, can be called from timer as well..
#			bPlayerHailing, if the player hailed first.
#
#	Return:	0
################################################################################
def EndingDialogue(pAction, pEvent = None, bPlayerHailing = FALSE):
	if g_bEndDialoguePlayed:
		return 0

	if not g_bSequencePlaying:
		global g_bEndDialoguePlayed
		g_bEndDialoguePlayed = TRUE

		Maelstrom.Episode4.Episode4.Mission5Complete()

		SetAllowWarpFlag()

		pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
		pPicard = App.CharacterClass_GetObject (pPBridgeSet, "Picard")
		pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
		pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
		pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
		pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

		pSeq = MissionLib.NewDialogueSequence()
		if not bPlayerHailing:
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M5BeingHailed", g_pMissionDatabase), 3.0)
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5SaffiOnScreen", g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Picard"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pPicard, "E4M5L023", g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pPicard, "E4M5L024", g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "PicardWarpOut"))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M5StarfleetHailing", g_pMissionDatabase), 2.0)
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5StarfleetOnScreen", g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M5StarfleetAyeSir", g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4M5L025", g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4M5L026", g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E4M5L028", g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E4SB12Goal"))

		MissionLib.QueueActionToPlay(pSeq)

	# Can't interrupt, try again..
	else:
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_CRITICAL_SEQUENCE_RETRY, __name__ + ".EndingDialogue", 
								fStartTime + 5, 0, 0)
		
	return 0
	
################################################################################
#	SetAllowWarpFlag()
#
#	Set flag allowing player to warp once ending dialogue has played.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def SetAllowWarpFlag():
#	debug("Enabling player warp..")
	global g_bAllowWarp
	g_bAllowWarp = TRUE


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
	if(g_bDebugPrint):
		print(pcString)


################################################################################
#	FailGame()
#
#	Misison loss, play dialogue and bring up game over screen.
#
#	Args:	None
#
#	Return:	None
################################################################################
def FailGame():
	if g_bMissionTerminated:
		return

	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5EnterpriseDestroyed", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "HailStarfleet1", g_pGeneralDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M5StarfleetHailing", g_pMissionDatabase), 3.0)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E4M5StarfleetOnScreen", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pKiska, "E4M5StarfleetAyeSir", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu"))
	pSeq.AppendAction(App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E4M5EnterpriseDead", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	MissionLib.GameOver(None, pSeq)

################################################################################
#	SetViewscreenFlag(pAction, bVal)
#
# 	Set viewscreen "in use" flag.
#
#	Args:	pAction, the script action.
#			bVal, new value.
#
#	Return:	0
################################################################################
def SetViewscreenFlag(pAction, bVal):
	global g_bViewscreenInUse
	g_bViewscreenInUse = bVal

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

#	DebugPrint("Terminating Episode 4, Mission 5.\n")

	RemoveEventHandlers()

	MissionLib.DeleteAllGoals()
	App.SortedRegionMenu_ClearSetCourseMenu()

	# Unload BridgeCrewGeneral database.
	if g_pGeneralDatabase:
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)
		global g_pGeneralDatabase
		g_pGeneralDatabase = None
