###############################################################################
#	Filename:	E8M1.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 8 Mission 1
#	
#	Created:	11/09/00 -	Bill Morrison (added header)
#	Modified:	01/09/02 - 	Tony Evans
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Maelstrom
import Maelstrom.Episode8.Episode8
import LoadBridge
import Bridge.Characters.CommonAnimations
import Bridge.Characters.Data
import Bridge.BridgeMenus
import Bridge.BridgeUtils
import Bridge.ScienceCharacterHandlers
import Systems.Starbase12.Starbase
import Systems.Starbase12.Starbase12
import Systems.Riha.Riha
import Systems.Riha.Riha1
import Systems.Cebalrai.Cebalrai
import Systems.Cebalrai.Cebalrai1		
import Systems.Belaruz.Belaruz
import Systems.Belaruz.Belaruz1
import Systems.DeepSpace.DeepSpace
import Maelstrom.Episode7.E7M1.E7M1_P
import Maelstrom.Episode8.E8M1.E8M1_P
import EBridge_P
import Bridge.ScienceMenuHandlers
import FriendlyAI
import EnemyAI
import GalorAI
import KessokLightAI
import KessokHeavyAI
import FriendlyRiha1AI
import FriendlyRiha1AI2
import FriendlyCebalrai1AI
import FriendlyBelaruz1AI

#
# Event types
#
ET_ONE_MINUTE			= App.Mission_GetNextEventType()
ET_SAFFIWARN			= App.Mission_GetNextEventType()
ET_DATAINFO				= App.Mission_GetNextEventType()
ET_GO_KESSOK			= App.Mission_GetNextEventType()
ET_GALOR_PROD			= App.Mission_GetNextEventType()


#
# Global variables
#
bDebugPrint			= 1

pFriendlies			= None
pEnemies			= None

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

TRUE	= 1
FALSE	= 0

HASNT_ARRIVED		= 0
HAS_ARRIVED			= 1

pMissionDatabase	= None
pGeneralDatabase	= None
pMenuDatabase		= None
pEpisodeDatabase	= None

idInterruptData		= App.NULL_ID
idInterruptSequence	= App.NULL_ID

iBustersDestroyed	= 0
bBelaruz1Flag		= HASNT_ARRIVED	
bRiha1Flag			= HASNT_ARRIVED
bCebalrai1Flag		= HASNT_ARRIVED
iRihaKessoksLeft	= 2
iCebalraiKessoksLeft = 5
iBelaruzKessoksLeft	= 3
bScanningGalor		= FALSE
iGalorScanned		= 0
iGalorDisableCount	= 0
iDataToKessok		= 0
iGeronimoHailed		= 0
iZeissMacCrayTalk	= 0

g_bBriefingPlayed	= FALSE

bBelaruzScanned		= FALSE
bCebalraiScanned	= FALSE
bGalorDisabled		= FALSE
bGalorDestroyed		= FALSE
bDeviceScanned 		= FALSE
bDevice1Destroyed	= FALSE
bDevice2Destroyed	= FALSE
bDevice3Destroyed	= FALSE
bStarfleetContacted	= FALSE
bDataInfoPlayed		= FALSE
bKessokAttacked 	= FALSE
bCommandGeronimo	= FALSE
bGeronimoCritical 	= FALSE
bSanFranciscoCritical = FALSE
bKessokDetected		= FALSE
bKessokScanned		= FALSE
bKessokHailed		= FALSE

fStartTime			= 0
kStartupSoundID		= App.PSID_INVALID
kDevice1Subsystems	= 0
kDevice2Subsystems	= 0
kDevice3Subsystems	= 0

bMissionWon			= FALSE
bMissionTerminate	= FALSE
bAllowDamageDialogue = 0		#Allows the damage dialogue to be spoken and not overlap

bDataToKessokProd	= FALSE
bContactStarfleetProd = FALSE
bDestroyDeviceProd	= FALSE
iCourseSet 			= 0

g_bGraffWarned 		= FALSE
g_bMacCrayWarned 	= FALSE
g_bZeissWarned 		= FALSE

lAllies = [ "player", "USS San Francisco", "USS Geronimo" ]

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
	if Maelstrom.Maelstrom.bGeronimoAlive:
		loadspacehelper.PreloadShip("Geronimo", 1)
	if Maelstrom.Maelstrom.bZeissAlive:
		loadspacehelper.PreloadShip("Galaxy", 1)
	loadspacehelper.PreloadShip("KessokHeavy", 1)
	loadspacehelper.PreloadShip("KessokLight", 9)
	loadspacehelper.PreloadShip("Galor", 1)
	loadspacehelper.PreloadShip("Sunbuster", 3)


#
# Initialize()
#
# Called to initialize our mission
#
def Initialize(pMission):
#	DebugPrint ("Initializing Episode 8, Mission 1.\n")

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

	global pMissionDatabase, pGeneralDatabase, pMenuDatabase, pEpisodeDatabase
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 8/E8M1.tgl")
	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pEpisodeDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 8/Episode8.tgl")

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

	Systems.Riha.Riha1.Initialize()
	pRiha1Set = Systems.Riha.Riha1.GetSet()

	Systems.Cebalrai.Cebalrai1.Initialize()
	pCebalrai1Set = Systems.Cebalrai.Cebalrai1.GetSet()

	Systems.Belaruz.Belaruz1.Initialize()
	pBelaruz1Set = Systems.Belaruz.Belaruz1.GetSet()

	# Same for creating the Deep Space set.
	Systems.DeepSpace.DeepSpace.Initialize()
	pSet2 = Systems.DeepSpace.DeepSpace.GetSet()

	CreateMenus()

	# Load our placements into this set
	Maelstrom.Episode7.E7M1.E7M1_P.LoadPlacements(pSet.GetName())
	Maelstrom.Episode8.E8M1.E8M1_P.LoadPlacements(pRiha1Set.GetName())
	Maelstrom.Episode8.E8M1.E8M1_P.LoadPlacements(pCebalrai1Set.GetName())	
	Maelstrom.Episode8.E8M1.E8M1_P.LoadPlacements(pBelaruz1Set.GetName())	

	# Load custom placements for bridge.
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	EBridge_P.LoadPlacements(pBridgeSet.GetName())

	# Create character sets
	MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet")

	MissionLib.SetupBridgeSet("FedOutpostSet", "data/Models/Sets/FedOutpost/fedoutpost.nif", -30, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Graff", "FedOutpostSet")

	if Maelstrom.Maelstrom.bZeissAlive:
		MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif")
		MissionLib.SetupCharacter("Bridge.Characters.Zeiss", "DBridgeSet")

	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif")
		MissionLib.SetupCharacter("Bridge.Characters.MacCray", "EBridgeSet")

	# Activate the proximity manager for our set.	
	pSet.SetProximityManagerActive(1)
	
	# Create the ships and set their stats
#	DebugPrint ("Creating ships.\n")

	#
	# Starbase 12 ships
	#
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pSet, "player", "Player Start")
	pStarbase = loadspacehelper.CreateShip( "FedStarbase", pSet, "Starbase 12", "Starbase Location" )

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	if Maelstrom.Maelstrom.bZeissAlive:
		pGalaxy = loadspacehelper.CreateShip( "Galaxy", pSet, "USS San Francisco", "Enterprise Start" )
		pGalaxy.ReplaceTexture("data/Models/SharedTextures/FedShips/SanFrancisco.tga", "ID")

	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		pGeronimo = loadspacehelper.CreateShip( "Geronimo", pSet, "USS Geronimo", "Akira Start" )
		pGeronimo.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")

	######################
	# Setup Affiliations #
	######################

	global pFriendlies, pEnemies

	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("USS Geronimo")
	pFriendlies.AddName("USS San Francisco")
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Kessok1")
	pEnemies.AddName("Kessok2")
	pEnemies.AddName("Kessok3")
	pEnemies.AddName("Kessok4")
	pEnemies.AddName("Kessok5")
	pEnemies.AddName("Kessok6")
	pEnemies.AddName("Kessok7")
	pEnemies.AddName("Kessok8")
	pEnemies.AddName("Kessok9")
	pEnemies.AddName("KessokHeavy")
	pEnemies.AddName("Galor")
	pEnemies.AddName("Device 1")
	pEnemies.AddName("Device 2")

	MissionLib.AddCommandableShip("USS San Francisco")
	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		MissionLib.AddCommandableShip("USS Geronimo")
#		DebugPrint("Setup Fleet Command Attack Target handler")
		pCommandFleetMenu = MissionLib.GetCharacterSubmenu("Helm", "Hail")
		if pCommandFleetMenu:
			pCommandFleetMenu.AddPythonFuncHandlerForInstance(Bridge.HelmMenuHandlers.ET_FLEET_COMMAND_ATTACK_TARGET, __name__ + ".FleetCommandAttackTarget")
#		else:
#			DebugPrint(__name__ + " error: Unable to get Command Fleet menu.")

	#################
	# Setup ship AI #
	#################

	if Maelstrom.Maelstrom.bGeronimoAlive:
		pGeronimo.SetAI(FriendlyAI.CreateAI(pGeronimo, lAllies))
	if Maelstrom.Maelstrom.bZeissAlive:
		pGalaxy.SetAI(FriendlyAI.CreateAI(pGalaxy, lAllies))

	###############
	# End Ship AI #
	###############

	# Setup more mission-specific events.
	SetupEventHandlers(pMission)

	# If the player was created from scratch, call our initial briefing
	if (bHavePlayer == 0):
		Briefing()

	MissionLib.SaveGame("E8M1-")

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

	# Instance handler for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")

	# Contact Starfleet event
	g_pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET, __name__ + ".HailStarfleet")
	# Science Scan event
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
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1StarbaseHail", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet", "Graff")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E8M1HitStarbase", None, 0, pMissionDatabase)
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
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L035", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1HitGeronimo", None, 0, pMissionDatabase)
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
	
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L112", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1HitSanFrancisco", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		return

	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)


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

	if pMenu.GetObjID() == g_pKiskaMenu.GetObjID():
#		DebugPrint("Communicating with Kiska")

		if ((iCourseSet == 1 and sSetName == "Starbase12") or 
			(iCourseSet == 2 and sSetName == "Riha1") or
			(iCourseSet == 3 and sSetName == "Cebalrai1") or
			(iCourseSet == 4 and sSetName == "Belaruz1")):
#			DebugPrint("Ready to warp")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1KiskaProd1", None, 0, pMissionDatabase)

		elif (bGalorDisabled == TRUE) and (bGalorDestroyed == FALSE) and (iGalorScanned == 0) and (sSetName == "Riha1"):
#			DebugPrint("Scan the Galor")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1KiskaProd2", None, 0, pMissionDatabase)

		elif (sSetName == "Belaruz1") and bKessokDetected and not (bKessokHailed == 1) and not bKessokAttacked:
#			DebugPrint("Decide what to do about the KessokHeavy")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1KiskaProd4", None, 0, pMissionDatabase)

		elif (bDeviceScanned == FALSE) and (bDestroyDeviceProd == TRUE):
#			DebugPrint("Scan the Device")
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1KiskaProd3", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pFelixMenu.GetObjID():
#		DebugPrint("Communicating with Felix")

		if ((iRihaKessoksLeft > 0 and sSetName == "Riha1") or
			(iCebalraiKessoksLeft < 3 and sSetName == "Cebalrai1") or
			(iBelaruzKessoksLeft > 0 and sSetName == "Belaruz1" and bKessokAttacked)):
#			DebugPrint("Destroy Kessoks")
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1FelixProd1", None, 0, pMissionDatabase)

		elif (iCebalraiKessoksLeft > 2) and (sSetName == "Cebalrai1") and (bDestroyDeviceProd == TRUE):
#			DebugPrint("Destroy Device quickly!")
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1FelixProd2", None, 0, pMissionDatabase)

		elif (sSetName == "Belaruz1") and bKessokDetected and not bKessokAttacked and (iDataToKessok == 0):
#			DebugPrint("Decide what to do about the KessokHeavy quickly, sir")
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1FelixProd5", None, 0, pMissionDatabase)

		elif(bDestroyDeviceProd == TRUE) and (Maelstrom.Episode8.Episode8.KessoksFriendly == FALSE):
#			DebugPrint("Destroy Device")
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1FelixProd3", None, 0, pMissionDatabase)

		elif (bGalorDestroyed == FALSE) and (bScanningGalor == FALSE) and (sSetName == "Riha1"):
#			DebugPrint("Destroy the Galor")
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1FelixProd4", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pSaffiMenu.GetObjID():
#		DebugPrint("Communicating with Saffi")

		if (bGalorDisabled == TRUE) and (iGalorScanned > 0) and (bGalorDestroyed == FALSE) and (bScanningGalor == FALSE) and (sSetName == "Riha1"):
#			DebugPrint("Destroy the Galor")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd1", None, 0, pMissionDatabase)

		elif (iCebalraiKessoksLeft > 2) and (sSetName == "Cebalrai1") and (bDestroyDeviceProd == TRUE):
#			DebugPrint("Destroy Device quickly!")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd4", None, 0, pMissionDatabase)

		elif (sSetName == "Belaruz1") and (bKessokHailed == 1) and not bKessokAttacked and (iDataToKessok == 0):
#			DebugPrint("Decide what to do about the KessokHeavy quickly, sir")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd10", None, 0, pMissionDatabase)

		elif ((iCourseSet == 2 and sSetName == "Riha1") or
			(iCourseSet == 3 and sSetName == "Cebalrai1")):
#			DebugPrint("Go to next system")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd3", None, 0, pMissionDatabase)

		elif (bContactStarfleetProd == TRUE) and (bStarfleetContacted == FALSE):
#			DebugPrint("Contact Admiral Liu")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd5", None, 0, pMissionDatabase)

		elif (bMissionWon == TRUE):
#			DebugPrint("Return to Starbase12")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd6", None, 0, pMissionDatabase)

		elif (iCourseSet == 1) and (sSetName == "Starbase12"):
#			DebugPrint("Go to Riha system")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd7", None, 0, pMissionDatabase)

		elif ((iBustersDestroyed == 1 and bCebalraiScanned == FALSE) or 
			(iBustersDestroyed == 2 and bBelaruzScanned == FALSE) or 
			(iBustersDestroyed == 3 and bContactStarfleetProd == FALSE)):
#			DebugPrint("Look for another device")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd8", None, 0, pMissionDatabase)

		elif ((bCebalrai1Flag == HASNT_ARRIVED and sSetName[:len("Cebalrai")] == "Cebalrai") or 
			(bBelaruz1Flag == HASNT_ARRIVED and sSetName[:len("Belaruz")] == "Belaruz")):
#			DebugPrint("The Device is located near the sun")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd9", None, 0, pMissionDatabase)

		elif (bDestroyDeviceProd == TRUE) and (Maelstrom.Episode8.Episode8.KessoksFriendly == FALSE) and (iDataToKessok == 0):
#			DebugPrint("Destroy the Device")
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1SaffiProd2", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pMiguelMenu.GetObjID():
#		DebugPrint("Communicating with Miguel")

		if ((iBustersDestroyed == 1 and bCebalraiScanned == FALSE) or 
			(iBustersDestroyed == 2 and bBelaruzScanned == FALSE) or 
			(iBustersDestroyed == 3 and bContactStarfleetProd == FALSE)):
#			DebugPrint("Look for another device")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1MiguelProd1", None, 0, pMissionDatabase)

		elif (bGalorDisabled == FALSE) and (bGalorDestroyed == FALSE) and (sSetName == "Riha1"):
#			DebugPrint("Disable Galor")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1MiguelProd5", None, 0, pMissionDatabase)

		elif (bGalorDisabled == TRUE) and (bGalorDestroyed == FALSE) and (iGalorScanned == 0) and (sSetName == "Riha1"):
#			DebugPrint("Scan the Galor")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1MiguelProd6", None, 0, pMissionDatabase)

		elif (sSetName == "Belaruz1") and bKessokDetected and not bKessokScanned and not bKessokAttacked and not Maelstrom.Episode8.Episode8.KessoksFriendly:
#			DebugPrint("Decide what to do about the KessokHeavy")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1MiguelProd8", None, 0, pMissionDatabase)

		elif (bDeviceScanned == FALSE) and (bDestroyDeviceProd == TRUE):
#			DebugPrint("Scan the Device")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1MiguelProd7", None, 0, pMissionDatabase)

		elif ((bDevice1Destroyed == FALSE and sSetName[:len("Riha")] == "Riha") or 
			(bDevice2Destroyed == FALSE and sSetName[:len("Cebalrai")] == "Cebalrai") or 
			(bDevice3Destroyed == FALSE and sSetName[:len("Belaruz")] == "Belaruz")):
#			DebugPrint("Destroy device")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1MiguelProd2", None, 0, pMissionDatabase)

		elif (bDevice2Destroyed == FALSE):
#			DebugPrint("Go and destroy Cebalrai Device")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1MiguelProd3", None, 0, pMissionDatabase)

		elif (bDevice3Destroyed == FALSE):
#			DebugPrint("Go and destroy Belaruz Device")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1MiguelProd4", None, 0, pMissionDatabase)

	elif pMenu.GetObjID() == g_pBrexMenu.GetObjID():
#		DebugPrint("Communicating with Brex")

		if (sSetName == "Cebalrai1") and (iCebalraiKessoksLeft > 2) and (bDestroyDeviceProd == TRUE):
#			DebugPrint("Let's get out of here!")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1BrexProd1", None, 0, pMissionDatabase)

		elif (sSetName == "Riha1"):
			if (bGalorDisabled == FALSE) and (bGalorDestroyed == FALSE):
#				DebugPrint("Disable Galor")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1BrexProd2", None, 0, pMissionDatabase)

			elif (bGalorDisabled == TRUE) and (bGalorDestroyed == FALSE) and (iGalorScanned == 0):
#				DebugPrint("Scan the Galor")
				pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1BrexProd3", None, 0, pMissionDatabase)

		elif (sSetName == "Belaruz1") and bKessokDetected and not bKessokScanned and not bKessokAttacked and not Maelstrom.Episode8.Episode8.KessoksFriendly:
#			DebugPrint("Decide what to do about the KessokHeavy")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1BrexProd5", None, 0, pMissionDatabase)

		elif (bDeviceScanned == FALSE) and (bDestroyDeviceProd == TRUE):
#			DebugPrint("Scan the Device")
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1BrexProd4", None, 0, pMissionDatabase)

	else:
#		DebugPrint("Communicating with Data")

		if Maelstrom.Episode8.Episode8.KessoksFriendly:
#			DebugPrint("Nothing to add.")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataNothing", None, 0, pMissionDatabase)

		elif (bGalorDisabled == FALSE) and (bGalorDestroyed == FALSE) and (sSetName == "Riha1"):
#			DebugPrint("Disable Galor")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd1", None, 0, pMissionDatabase)

		elif (bGalorDisabled == TRUE) and (bGalorDestroyed == FALSE) and (iGalorScanned == 0) and (sSetName == "Riha1"):
#			DebugPrint("Scan the Galor")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd2", None, 0, pMissionDatabase)

		elif (bGalorDisabled == TRUE) and (iGalorScanned > 0) and (bGalorDestroyed == FALSE) and (bScanningGalor == FALSE) and (sSetName == "Riha1"):
#			DebugPrint("Destroy the Galor")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd3", None, 0, pMissionDatabase)

		elif (sSetName == "Belaruz1") and bDataToKessokProd == TRUE:
#			DebugPrint("Beam over to Kessok ship")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd7", None, 0, pMissionDatabase)

		elif (sSetName == "Belaruz1") and bKessokDetected and not bKessokAttacked:
#			DebugPrint("Decide what to do about the KessokHeavy")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd9", None, 0, pMissionDatabase)

		elif (bDeviceScanned == FALSE) and (bDestroyDeviceProd == TRUE):
#			DebugPrint("Scan the Device")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd4", None, 0, pMissionDatabase)

		elif (bDestroyDeviceProd == TRUE and ((bDevice1Destroyed == FALSE and sSetName == "Riha1") or 
											(bDevice2Destroyed == FALSE and sSetName == "Cebalrai1"))):
#			DebugPrint("Destroy device")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd5", None, 0, pMissionDatabase)

		elif ((iBustersDestroyed == 1 and bCebalraiScanned == FALSE) or 
			(iBustersDestroyed == 2 and bBelaruzScanned == FALSE) or 
			(iBustersDestroyed == 3 and bContactStarfleetProd == FALSE)):
#			DebugPrint("Look for another device")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd6", None, 0, pMissionDatabase)

		elif ((bCebalrai1Flag == HASNT_ARRIVED and sSetName[:len("Cebalrai")] == "Cebalrai") or 
			(bBelaruz1Flag == HASNT_ARRIVED and sSetName[:len("Belaruz")] == "Belaruz")):
#			DebugPrint("The Device is located near the sun")
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1DataProd8", None, 0, pMissionDatabase)

	if pAction:
		pAction.Play()

	else:
#		DebugPrint("Nothing special to handle.  Continue normal Communicate handler.")
		pObject.CallNextHandler(pEvent)


#
# AIDone()
#
def AIDone(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
#	DebugPrint("AIDone() called for %s" % pShip.GetName())

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
		# It's a ship.
		sShipName = pShip.GetName()
		pSet = pShip.GetContainingSet()
		sSetName = pSet.GetName()	

#		DebugPrint("Ship \"%s\" entered set \"%s\"" % (sShipName, sSetName))

		if ((pShip.GetName() == "player") and (pSet.GetName() == "Riha1")):
#			DebugPrint("Arrived at Riha")

			if bRiha1Flag == HASNT_ARRIVED:
				# Remove green highlight on the Set Course Menu
				pRihaMenu = Systems.Riha.Riha.CreateMenus()

				# Create the ships and set their stats
#				DebugPrint ("Creating Riha 1 ships.\n")
			
				#
				# Riha 1 Ships
				#
				pBuster1 = loadspacehelper.CreateShip( "Sunbuster", pSet, "Device 1", "Buster Location" )
				pCloak = pBuster1.GetCloakingSubsystem()
				pCloak.InstantCloak()
			
				pGalor = loadspacehelper.CreateShip( "Galor", pSet, "Galor", "Galor Start" )
				pKessok1 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok1", "Kessok1 Start" )
				pKessok2 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok2", "Kessok2 Start" )

				# Add handlers for disabling the Galor
				pCondition1 = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Galor", App.CT_SHIELD_SUBSYSTEM, 1)
				pCondition2 = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Galor", App.CT_IMPULSE_ENGINE_SUBSYSTEM, 1)
				pCondition3 = App.ConditionScript_Create("Conditions.ConditionSystemDisabled", "ConditionSystemDisabled", "Galor", App.CT_WARP_ENGINE_SUBSYSTEM, 1)

				pMission = MissionLib.GetMission()

				MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "DisableGalor", pCondition1)
				MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "DisableGalor", pCondition2)
				MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "DisableGalor", pCondition3)

				pGalor.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DESTROYED, __name__ + ".GalorDisableHandler")

				# Hide Device Subsystems
				global kDevice1Subsystems
				kDevice1Subsystems = MissionLib.HideSubsystems(pBuster1)
				MissionLib.ShowSubsystems([pBuster1.GetHull().GetObjID()])
		
				Riha1Arrive()

			else:
				SetRiha1AI(None)

		elif ((pShip.GetName() == "player") and (pSet.GetName() == "Cebalrai1")):
#			DebugPrint("Arrived at Cebalrai")

			if bCebalrai1Flag == HASNT_ARRIVED:
				# Remove green highlight on the Set Course Menu
				pCebalraiMenu = Systems.Cebalrai.Cebalrai.CreateMenus()

				MissionLib.SaveGame("E8M1-Cebalrai-")

				# Create the ships and set their stats
#				DebugPrint ("Creating Cebalrai1 ships.\n")
			
			
				#
				# Cebalrai 1 ships
				#
				pBuster2 = loadspacehelper.CreateShip( "Sunbuster", pSet, "Device 2", "Buster Location" )
				pKessok4 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok3", "Kessok1 Start" )
				pKessok5 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok4", "Kessok2 Start" )
				pKessok6 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok5", "Kessok3 Start" )
				pKessok7 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok6", "Kessok4 Start" )
				pKessok8 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok7", "Kessok5 Start" )
				pKessok9 = loadspacehelper.CreateShip( "KessokHeavy", pSet, "KessokHeavy", "Kessok6 Start" )

				pKessok9.SetInvincible(1)

#				DebugPrint ("Making Kessok Heavy Impulse and Warp Engines invincible.")
				pWarp = pKessok9.GetWarpEngineSubsystem()
				pImpulse = pKessok9.GetImpulseEngineSubsystem()
				if (pWarp and pImpulse):
					MissionLib.MakeSubsystemsInvincible(pImpulse, pWarp)

				global bDestroyDeviceProd
				bDestroyDeviceProd = TRUE

				if bDeviceScanned == FALSE:
					# Hide Device Subsystems
					global kDevice2Subsystems
					kDevice2Subsystems = MissionLib.HideSubsystems(pBuster2)
					MissionLib.ShowSubsystems([pBuster2.GetHull().GetObjID()])
			
				Cebalrai1Arrive()

			else:
				SetCebalrai1AI(None)

		elif ((pShip.GetName() == "player") and (pSet.GetName() == "Belaruz1")):
#			DebugPrint("Arrived at Belaruz")	

			if bBelaruz1Flag == HASNT_ARRIVED:
				# Remove green highlight on the Set Course Menu
				pBelaruzMenu = Systems.Belaruz.Belaruz.CreateMenus()

#				DebugPrint ("Creating Device 3 in Belaruz1.\n")
				pBuster3 = loadspacehelper.CreateShip( "Sunbuster", pSet, "Device 3", "Buster Location" )
				pKessok = loadspacehelper.CreateShip( "KessokHeavy", pSet, "KessokHeavy", "Galor Start" )

				if bDeviceScanned == FALSE:
					# Hide Device Subsystems
					global kDevice3Subsystems
					kDevice3Subsystems = MissionLib.HideSubsystems(pBuster3)
					MissionLib.ShowSubsystems([pBuster3.GetHull().GetObjID()])

				# Temporarily remove enemy state
				global pEnemies
				pEnemies.RemoveName("KessokHeavy")

				pKessok.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".KessokHeavyAttacked")
				pBuster3.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".KessokHeavyAttacked")

				Belaruz1Arrive()

			elif bKessokAttacked:
				SetBelaruz1AI(None)

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
		
	if (pShip):
		# It's a ship.
#		DebugPrint("Ship \"%s\" exited set \"%s\"" % (pShip.GetName(), sSetName))
		if (pShip.GetName() == "player"):
			global bDestroyDeviceProd
			bDestroyDeviceProd = FALSE
			global iCourseSet
			iCourseSet = 0

		elif (sSetName == "Cebalrai1"):
			if (pShip.GetName() == "Kessok3") or (pShip.GetName() == "Kessok4") or (pShip.GetName() == "Kessok5") or (pShip.GetName() == "Kessok6") or (pShip.GetName() == "Kessok7") or (pShip.GetName() == "KessokHeavy"):
				# If the ship is fleeing, not destroyed
				if not pShip.IsDead():
					global iCebalraiKessoksLeft
					iCebalraiKessoksLeft	= iCebalraiKessoksLeft - 1
#					DebugPrint(str(iCebalraiKessoksLeft))
	
					if (pShip.GetName() == "KessokHeavy") and (bDevice2Destroyed == FALSE):
#						DebugPrint ("KessokHeavy Fled")
		
						pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L126", "Captain", 1, pMissionDatabase)
						MissionLib.QueueActionToPlay(pAction)

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

	if (sShipName == "Galor") and (bGalorDestroyed == FALSE):
#		DebugPrint("Galor destroyed")
		global bGalorDestroyed
		bGalorDestroyed = TRUE

		# Abort Sequence, if any is going on
		AbortSequence()

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L089", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction, 3)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L057", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction2 = App.TGScriptAction_Create(__name__, "Decloak", 1)
		pSequence.AddAction(pAction2, pAction, 1)
		pAction3 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L058", None, 0, pMissionDatabase)
		pSequence.AddAction(pAction3, pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L058b", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L058c", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L058d", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		if iGalorScanned == 0:
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L059", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L060", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L061", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L062", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L063", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L064", "E", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L065", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
		pSequence.AppendAction(pAction)

		#Make this sequence interruptable
		global idInterruptSequence
		idInterruptSequence = pSequence.GetObjID()

		MissionLib.QueueActionToPlay(pSequence)


	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# ObjectDestroyed()
#
def ObjectDestroyed(TGObject, pEvent):
	pShip = App.ObjectClass_Cast(pEvent.GetDestination())

	if(pShip):
		sShipName = pShip.GetName()		
#		DebugPrint("Ship \"%s\" was destroyed" % pShip.GetName())

		if (sShipName == "USS Geronimo"):
#			DebugPrint ("Geronimo destroyed dialogue")
			Maelstrom.Maelstrom.bGeronimoAlive = FALSE

			g_pMiguel.SayLine(pMissionDatabase, "E8M1GeronimoDestroyed", "Captain", 1)

		elif (sShipName == "USS San Francisco"):
#			DebugPrint ("San Francisco destroyed dialogue")
			Maelstrom.Maelstrom.bZeissAlive = FALSE

			g_pMiguel.SayLine(pMissionDatabase, "E8M1SanFranciscoDestroyed", "Captain", 1)

		elif (sShipName == "Starbase 12"):
			MissionLib.GameOver(None)

		elif (sShipName == "Kessok1") or (sShipName == "Kessok2"):
			global iRihaKessoksLeft
			iRihaKessoksLeft = iRihaKessoksLeft - 1
		
			if iRihaKessoksLeft == 0:
#				DebugPrint ("All Riha Kessoks destroyed")
		
				pSequence = App.TGSequence_Create()
		
				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)
		
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L090", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction, 3)
		
				if iGalorScanned == 0 and bGalorDestroyed == FALSE:
#					DebugPrint ("Now let's see about that Galor")
		
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L032", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
		
				MissionLib.QueueActionToPlay(pSequence)
		
		elif (sShipName == "KessokHeavy"):
			Maelstrom.Episode8.Episode8.KessoksFriendly = FALSE
		
			global iBelaruzKessoksLeft
			iBelaruzKessoksLeft = iBelaruzKessoksLeft - 1
		
			pSequence = App.TGSequence_Create()
		
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L170", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction, 3)
		
			MissionLib.QueueActionToPlay(pSequence)
		
		elif (sShipName[:len("Kessok")] == "Kessok"):
			global iCebalraiKessoksLeft
			iCebalraiKessoksLeft	= iCebalraiKessoksLeft - 1
		
#			if iCebalraiKessoksLeft == 0:
#				DebugPrint ("All Cebalrai Kessoks destroyed")

		elif (sShipName == "Device 1") or (sShipName == "Device 2") or (sShipName == "Device 3"):
			global iBustersDestroyed
			iBustersDestroyed = iBustersDestroyed + 1
#			DebugPrint("SunBusters Destroyed = " +str(iBustersDestroyed))
		
			# Abort Sequence, if any is going on
			AbortSequence()
		
			global bDestroyDeviceProd
			bDestroyDeviceProd = FALSE
		
			if (sShipName == "Device 1"):
				global bDevice1Destroyed
				bDevice1Destroyed = TRUE
		
				pSequence = App.TGSequence_Create()
		
				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)
		
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L075", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L077", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L076", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L0775", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
		
				MissionLib.QueueActionToPlay(pSequence)
		
			elif (sShipName == "Device 2"):
				global bDevice2Destroyed
				bDevice2Destroyed = TRUE
		
				if iCebalraiKessoksLeft > 0:

					pSequence = App.TGSequence_Create()
				
					pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
					pSequence.AppendAction(pAction)
				
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L109", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L110", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction, 1)
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L111", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create(__name__, "ZeissMacCrayTalk")
					pSequence.AppendAction(pAction)

					MissionLib.QueueActionToPlay(pSequence)

				else:
					pSequence = App.TGSequence_Create()
		
					pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
					pSequence.AppendAction(pAction)
		
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L109", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction, 3)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L076", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
		
					MissionLib.QueueActionToPlay(pSequence)
		
			elif (sShipName == "Device 3"):
				global bDevice3Destroyed
				bDevice3Destroyed = TRUE

				Maelstrom.Episode8.Episode8.KessoksFriendly = FALSE

				RemoveHooks()

				pSequence = App.TGSequence_Create()
		
				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L170b", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L076", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L171", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				if iGalorScanned >= 1:
					# If you scanned the Galor and know about the fourth solar device
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L172", "Captain", 1, pMissionDatabase)
				else:
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L173", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

				pLiuSet = App.g_kSetManager.GetSet("LiuSet")
				pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

				pSequence.AppendAction(MissionLib.ContactStarfleet())

				pAction = App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E8DestroyDevicesGoal2")
				pSequence.AppendAction(pAction)	
	
				if iGalorScanned >= 1:
					pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L232", None, 0, pMissionDatabase)
	
				else:
					pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L233", None, 0, pMissionDatabase)
	
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L233b", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L232b", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)
		
			if iBustersDestroyed == 1:
#				DebugPrint("Swap DestroyDevices Goals")
		
				MissionLib.DeleteGoal("E8DestroyDevicesGoal")
				MissionLib.AddGoal("E8DestroyDevicesGoal2")
		
#			elif iBustersDestroyed == 3:
#				DebugPrint("Three solar devices destroyed.")

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# ZeissMacCrayTalk() - This function checks if MacCray and Zeiss are alive and plays dialogue
#
def ZeissMacCrayTalk(pAction):
	if (iZeissMacCrayTalk == 3):
		return 0

	global iZeissMacCrayTalk
	iZeissMacCrayTalk = iZeissMacCrayTalk + 1

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	pSequence = App.TGSequence_Create()

	# If the San Francisco is alive
	if (iZeissMacCrayTalk == 1) and (Maelstrom.Maelstrom.bZeissAlive == TRUE):
		# Make sure player and ship are in the same set
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		pSanFranciscoSetName = pSanFrancisco.GetContainingSet().GetName()

		if (pPlayerSetName == pSanFranciscoSetName):
			pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
			pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1L113", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

	# If the Geronimo is alive
	elif (iZeissMacCrayTalk == 2) and (Maelstrom.Maelstrom.bGeronimoAlive == TRUE):
		# Make sure player and ship are in the same set
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()

		if (pPlayerSetName == pGeronimoSetName):
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
			pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L114", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L115", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L116", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L117", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		elif Maelstrom.Maelstrom.bZeissAlive == TRUE:
			# Make sure player and ship are in the same set
			pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
			pSanFranciscoSetName = pSanFrancisco.GetContainingSet().GetName()

			if (pPlayerSetName == pSanFranciscoSetName):
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L116", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

	else:
		# Set the the flag to 3 to 
		# make sure this only plays once.
		global iZeissMacCrayTalk
		iZeissMacCrayTalk = 3
		
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L118", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L119", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L120", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L121", "Captain", 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L122", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L123", "S", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L124", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L125", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L076", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "ZeissMacCrayTalk")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	return 0


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

	if (sShipName == "USS San Francisco"):
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
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1SanFranciscoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 0):
#				DebugPrint("San Francisco shields are gone!")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1SanFranciscoShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 50):
#				DebugPrint("San Francisco hull down to 50 percent")

				global bSanFranciscoCritical
				bSanFranciscoCritical = TRUE

				pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
				pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L112", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1SanFranciscoHull50", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 25):
#				DebugPrint("San Francisco hull down to 25 percent")

				global bSanFranciscoCritical
				bSanFranciscoCritical = TRUE

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1SanFranciscoHull25", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return
		else:
			return

	elif (sShipName == "USS Geronimo"):
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
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1GeronimoShields50", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 0):
#				DebugPrint("Geronimo shields are gone!")

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1GeronimoShields0", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pReAllow = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pReAllow)

				MissionLib.QueueActionToPlay(pSequence)

			else:
				return

		elif (sSystemName == "HullPower"):
			if (iPercentageLeft == 50):
#				DebugPrint("Geronimo hull down to 50 percent.")

				global bGeronimoCritical
				bGeronimoCritical = TRUE

				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

				pSequence = App.TGSequence_Create()

				pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
				pSequence.AppendAction(pAction)

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L114", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1GeronimoHull50", None, 0, pMissionDatabase)	
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialogue")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

			elif (iPercentageLeft == 25):
#				DebugPrint("Geronimo hull down to 25 percent.")

				global bGeronimoCritical
				bGeronimoCritical = TRUE

				pSequence = App.TGSequence_Create()
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1GeronimoHull25", "Captain", 1, pMissionDatabase)
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
# Decloak()
#
def Decloak(pAction, iCloakNum):
	if iCloakNum == 1:
#		DebugPrint("Decloaking Device 1")

		global bDestroyDeviceProd
		bDestroyDeviceProd = TRUE

		pSet = App.g_kSetManager.GetSet("Riha1")
		pDevice1 = App.ShipClass_GetObject(pSet, "Device 1")

		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			pPlayer.SetTarget("Device 1")

		pCloak = pDevice1.GetCloakingSubsystem()
		if (not App.IsNull(pCloak)):
			pCloak.StopCloaking()

		# Set up weapon hit handler while we're at it.
		pDevice1.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".DeviceAttacked")

	else:
#		DebugPrint("Decloaking KessokLights")
		pSet = App.g_kSetManager.GetSet("Belaruz1")
		pKessok1 = App.ShipClass_GetObject(pSet, "Kessok8")
		pKessok2 = App.ShipClass_GetObject(pSet, "Kessok9")
	
		pCloak = pKessok1.GetCloakingSubsystem()
		if (not App.IsNull(pCloak)):
			pCloak.StopCloaking()

		pCloak = pKessok2.GetCloakingSubsystem()
		if (not App.IsNull(pCloak)):
			pCloak.StopCloaking()

#		DebugPrint("Identifying Kessoks")
		MissionLib.IdentifyObjects(pKessok1)
		MissionLib.IdentifyObjects(pKessok2)


	return 0



#
#	DeviceAttacked() 
#
def DeviceAttacked(pObject, pEvent):
#	DebugPrint("Device is attacked")

	# Your allies will join in on the attack on the Device
	SetRiha1AI(None, 1)

	# Removing DeviceAttacked instance handler
	pSet = App.g_kSetManager.GetSet("Riha1")
	pDevice1 = App.ShipClass_GetObject(pSet, "Device 1")
	if not (pDevice1 == None):
		pDevice1.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".DeviceAttacked")


#
# GalorDisableHandler()  - Player disables Galor
#
def GalorDisableHandler(pObject, pEvent):
	pSet = App.g_kSetManager.GetSet("Riha1")
	pGalor = App.ShipClass_GetObject(pSet, "Galor")

	if bGalorDisabled == FALSE:
		# Make sure Event Source is valid, so the game won't crash when I do a GetObjID
		if not (pEvent.GetSource() == None): 
			if not (pGalor):
				return

			# Make sure the subsystem is valid, so the game won't crash when I do a GetObjID
			if not (pGalor.GetImpulseEngineSubsystem() == None):
				if (pEvent.GetSource().GetObjID() == pGalor.GetImpulseEngineSubsystem().GetObjID()):
#					DebugPrint ("Galor Impulse Engines Gone.")

					global iGalorDisableCount
					iGalorDisableCount = 2
					DisableGalor(None)

					return
	
			if not (pGalor.GetWarpEngineSubsystem() == None):
				if (pEvent.GetSource().GetObjID() == pGalor.GetWarpEngineSubsystem().GetObjID()):
#					DebugPrint ("Galor Warp Engines Gone.")

					global iGalorDisableCount
					iGalorDisableCount = 2
					DisableGalor(None)

					return
	
			if not (pGalor.GetShields() == None):
				if (pEvent.GetSource().GetObjID() == pGalor.GetShields().GetObjID()):
#					DebugPrint ("Galor Shields Gone.")

					global iGalorDisableCount
					iGalorDisableCount = 2
					DisableGalor(None)
	
					return


#
# DisableGalor() - Player disables Galor
#
def DisableGalor(bCondition):
#	DebugPrint ("Disable Galor handler")
	global iGalorDisableCount
	iGalorDisableCount = iGalorDisableCount + 1

	if iGalorDisableCount >= 2 and bGalorDisabled == FALSE:
#		DebugPrint ("Galor is Disabled")

		pSet = App.g_kSetManager.GetSet("Riha1")
		pGalor = App.ShipClass_GetObject(pSet, "Galor")

		if not (pGalor) or pGalor.IsDead() or pGalor.IsDying():
			return

#		DebugPrint ("Removing Handler")
		pGalor.RemoveHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DESTROYED, __name__ + ".GalorDisableHandler")
	
		global bGalorDisabled
		bGalorDisabled = TRUE

		# Make the Galor spin
		vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
		vVelocity.Scale(10.0 * App.PI / 180.0)
		pGalor.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

		pSystem = pGalor.GetShields()
		if (pSystem):
			pSystem.SetConditionPercentage (.01)
	
		pSystem = pGalor.GetWarpEngineSubsystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.02)

		pSystem = pGalor.GetImpulseEngineSubsystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.2)
	
		pSystem = pGalor.GetTorpedoSystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.03)
	
		pSystem = pGalor.GetPhaserSystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.05)
	
		pSystem = pGalor.GetPulseWeaponSystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.1)
	
		pSystem = pGalor.GetTractorBeamSystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.3)
	
		pSystem = pGalor.GetRepairSubsystem()
		if (pSystem):
			pSystem.SetConditionPercentage (0.0)
	
		pSequence = App.TGSequence_Create()
	
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L030", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		if not iRihaKessoksLeft == 0:
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L031", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
	
		pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
		pSequence.AppendAction(pAction)
	
		#Make this sequence interruptable
		global idInterruptSequence
		idInterruptSequence = pSequence.GetObjID()

		MissionLib.QueueActionToPlay(pSequence)


#
# Briefing() - Briefing dialogue
#
def Briefing():
	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	global g_bBriefingPlayed
	g_bBriefingPlayed = TRUE

#	DebugPrint ("Begin Briefing")
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg6", None, 0, pGeneralDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L001", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L002", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L003", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L004", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L005", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if Maelstrom.Maelstrom.bGeronimoAlive and Maelstrom.Maelstrom.bZeissAlive:
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L007", None, 0, pMissionDatabase)
	elif Maelstrom.Maelstrom.bZeissAlive:
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L007a", None, 0, pMissionDatabase)
	elif Maelstrom.Maelstrom.bGeronimoAlive:
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L007b", None, 0, pMissionDatabase)

	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L008", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "AddE8M1Goal")
	pSequence.AppendAction(pAction)

	# If the Geronimo is alive
	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L035", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L009", None, 0, pMissionDatabase)	
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	# If the San Francisco is alive
	if Maelstrom.Maelstrom.bZeissAlive == TRUE:
		pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
		pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

		# Append Zeiss' dialogue
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1L010", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)

	# Continue Briefing dialogue
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L011", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L012", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L015", "E", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L016", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction)
	pAction3 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L017", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L019", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "CreateRihaMenu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L020", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
#	AddE8M1Goal()
#
def AddE8M1Goal(pAction):
#	DebugPrint ("Adding DestroyDevicesGoal.\n")

	MissionLib.AddGoal("E8DestroyDevicesGoal")

	return 0


#
# Riha1Arrive()
#
def Riha1Arrive():
#	DebugPrint ("Riha1Arrive function playing")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L021", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L022", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L023", "C", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L024", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "SetRiha1AI")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L025", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L026", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L027", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	# If the Geronimo is alive
	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		# Make sure player and ship are in the same set
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()

		if (pPlayerSetName == pGeronimoSetName):
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
			pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L035", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)	
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L028", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

	# If the San Francisco is alive
	if Maelstrom.Maelstrom.bZeissAlive == TRUE:
		# Make sure player and ship are in the same set
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		pSanFranciscoSetName = pSanFrancisco.GetContainingSet().GetName()

		if (pPlayerSetName == pSanFranciscoSetName):
			pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
			pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")
	
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1L029", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

#	DebugPrint ("Playing Riha1Arrive sequence")

	MissionLib.QueueActionToPlay(pSequence)


#
# Cebalrai1Arrive()
#
def Cebalrai1Arrive():
	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L092", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L093", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L094", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L095", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L096", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L097", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "SetCebalrai1AI")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L098", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	# If the Geronimo is alive
	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		# Make sure player and ship are in the same set
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()

		if (pPlayerSetName == pGeronimoSetName):
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
			pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")
	
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L114", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L099", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

	# If the San Francisco is alive
	if Maelstrom.Maelstrom.bZeissAlive == TRUE:
		# Make sure player and ship are in the same set
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		pSanFranciscoSetName = pSanFrancisco.GetContainingSet().GetName()

		if (pPlayerSetName == pSanFranciscoSetName):
			pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
			pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")
	
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1L100", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L101", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L102", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)

	# If the Geronimo is alive
	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		# Make sure player and ship are in the same set
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()

		if (pPlayerSetName == pGeronimoSetName):
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
			pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")
	
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L114", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L105", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

	# If the San Francisco is alive
	if Maelstrom.Maelstrom.bZeissAlive == TRUE:
		# Make sure player and ship are in the same set
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		pSanFranciscoSetName = pSanFrancisco.GetContainingSet().GetName()

		if (pPlayerSetName == pSanFranciscoSetName):
			pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
			pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")
	
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1L106", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
# KessokHeavyFlee() - You are told the KessokHeavy is fleeing.  Called from KessokHeavyAI.
#
def KessokHeavyFlee():
	if not bDevice2Destroyed:
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L111b", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L111c", "T", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pSequence.Play()


#
# Belaruz1Arrive()
#
def Belaruz1Arrive():
	global bBelaruz1Flag
	bBelaruz1Flag = HAS_ARRIVED

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		# Make sure player and ship are in the same set
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimo.SetAI(FriendlyAI.CreateAI(pGeronimo, lAllies))

	if Maelstrom.Maelstrom.bZeissAlive == TRUE:	
		# Make sure player and ship are in the same set
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		pSanFrancisco.SetAI(FriendlyAI.CreateAI(pSanFrancisco, lAllies))

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction(pAction, 5)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Belaruz1")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Belaruz1")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Belaruz1", "player")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L129", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction, 3)
	if iGalorScanned == 2:
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L130", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L131", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L132", "E", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L133", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L134", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Belaruz1")	
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L135", "S", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "MiguelWatch 1", "Miguel Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L136", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L137", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Miguel Head", "Miguel Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L138", "Captain", 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L139", "S", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "MiguelWatch 1", "Miguel Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L140", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L141", "H", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "NebulaNavPoints")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L142", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "BelaruzEvents")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)


#
#	NebulaNavPoints() - Adds nav points to/from the Kacheeti Nebula and targets the nebula nav point.
#
def NebulaNavPoints(pAction):
#	DebugPrint ("Setting Kacheeti Nebula nav points")

	MissionLib.AddNavPoints("Belaruz1", "Kacheeti Nebula", "Exit Nebula")

	pPlayerShip = MissionLib.GetPlayer()
	pPlayerShip.SetTarget("Kacheeti Nebula")

	return 0

#
#	BelaruzEvents() - Set up Belaruz event handlers
#
def BelaruzEvents(pAction):
#	DebugPrint("Setting up Belaruz1 events")

	# Check to see if Sensors are down
	pPlayer = MissionLib.GetPlayer()
	pSystem = pPlayer.GetSensorSubsystem()
	if (pSystem.IsDisabled()):
		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)
	
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L142a", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L142b", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

	pMission = MissionLib.GetMission()

	# Detecting Object in nebula event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_FAR_PROXIMITY, pMission, __name__ + ".DetectingObject")

	# Detecting Kessok ship in nebula event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_NEAR_PROXIMITY, pMission, __name__ + ".DetectingKessok")

	return 0


#
#	DetectingObject() - Sensors have picked up an object in the Nebula
#
def DetectingObject(pObject, pEvent):
#	DebugPrint("Sensors have detected something in far proximity")
	pShip = App.ShipClass_Cast(pEvent.GetSource())

	if (pShip == None) or bKessokAttacked:
		return

	pGame = App.Game_GetCurrentGame()
	pPlayer = MissionLib.GetPlayer()
	pSet = pPlayer.GetContainingSet()

	# If in Belaruz1 and detecting KessokHeavy
	if pSet.GetName() == "Belaruz1" and pShip.GetName() == "KessokHeavy":
#		DebugPrint("It's the Kessok ship.  Targeting.")
		pPlayer.SetTarget(pShip.GetName())

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L144", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L145", "S", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L146", "C", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		pMission = MissionLib.GetMission()
		App.g_kEventManager.RemoveBroadcastHandler(App.ET_SENSORS_SHIP_FAR_PROXIMITY, pMission, __name__ + ".DetectingObject")


#
#	DetectingKessok() - Sensors have picked up the Kessok in the Nebula
#
def DetectingKessok(pObject, pEvent):
#	DebugPrint("Sensors have detected something in close proximity")
	pShip = App.ShipClass_Cast(pEvent.GetSource())

	if (pShip == None) or bKessokAttacked:
		return

	pGame = App.Game_GetCurrentGame()
	pPlayer = MissionLib.GetPlayer()
	pSet = pPlayer.GetContainingSet()

	# If in Belaruz1 and detecting KessokHeavy
	if pSet.GetName() == "Belaruz1" and pShip.GetName() == "KessokHeavy":
#		DebugPrint("It's the Kessok ship!!!  Targeting.")
		pPlayer.SetTarget(pShip.GetName())

		# Restore enemy state
		global pEnemies
		pEnemies.AddName("KessokHeavy")
		pEnemies.AddName("Device 3")

		global bDestroyDeviceProd
		bDestroyDeviceProd = TRUE

		global bKessokDetected
		bKessokDetected = TRUE

		pDevice = App.ShipClass_GetObject(pSet, "Device 3")
		if pDevice:
#			DebugPrint("Identifying Device 3")
			MissionLib.IdentifyObjects(pDevice)

#		DebugPrint("Turning off KessokHeavy Shields")
		pShields = pShip.GetShields()
		pShields.TurnOff()

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L147", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L148", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L149", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L150", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L151", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L152", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pGame = App.Game_GetCurrentGame()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
		# If the Geronimo is alive
		if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
			# Make sure player and ship are in the same set
			pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
			pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
			if (pPlayerSetName == pGeronimoSetName):
				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L114", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L158", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

		# If the San Francisco is alive
		if Maelstrom.Maelstrom.bZeissAlive == TRUE:
			# Make sure player and ship are in the same set
			pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
			pSanFranciscoSetName = pSanFrancisco.GetContainingSet().GetName()
			if (pPlayerSetName == pSanFranciscoSetName):
				pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
				pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1L159", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L161", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L155", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L156", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L157", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
		pSequence.AppendAction(pAction)

		#Make this sequence interruptable
		global idInterruptSequence
		idInterruptSequence = pSequence.GetObjID()

		MissionLib.QueueActionToPlay(pSequence)

		pMission = MissionLib.GetMission()
		App.g_kEventManager.RemoveBroadcastHandler(App.ET_SENSORS_SHIP_NEAR_PROXIMITY, pMission, __name__ + ".DetectingKessok")


#
# SetRiha1AI()
#
def SetRiha1AI(pAction, iNum = 0):
#	DebugPrint ("Setting Riha1 AI")
	pSet = App.g_kSetManager.GetSet("Riha1")

	if bRiha1Flag == HASNT_ARRIVED:
		global bRiha1Flag
		bRiha1Flag = HAS_ARRIVED
	
		pKessok1 = App.ShipClass_GetObject(pSet, "Kessok1")
		pKessok2 = App.ShipClass_GetObject(pSet, "Kessok2")
		pGalor = App.ShipClass_GetObject(pSet, "Galor")

		pKessok1.SetAI(EnemyAI.CreateAI(pKessok1))
		pKessok2.SetAI(EnemyAI.CreateAI(pKessok2))
		pGalor.SetAI(GalorAI.CreateAI(pGalor))

	pPlayer = MissionLib.GetPlayer()
	pPlayerSetName = pPlayer.GetContainingSet().GetName()

	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		# Make sure player and ship are in the same set
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		if iNum == 0:
			pGeronimo.SetAI(FriendlyRiha1AI.CreateAI(pGeronimo, lAllies))

		else:
			pGeronimo.SetAI(FriendlyRiha1AI2.CreateAI(pGeronimo, lAllies))

	if Maelstrom.Maelstrom.bZeissAlive == TRUE:	
		# Make sure player and ship are in the same set
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		if iNum == 0:
			pSanFrancisco.SetAI(FriendlyRiha1AI.CreateAI(pSanFrancisco, lAllies))

		else:
			pSanFrancisco.SetAI(FriendlyRiha1AI2.CreateAI(pSanFrancisco, lAllies))

	return 0

#
# SetCebalrai1AI()
#
def SetCebalrai1AI(pAction):
#	DebugPrint ("Setting Cebalrai1 AI")
	pSet = App.g_kSetManager.GetSet("Cebalrai1")

	if bCebalrai1Flag == HASNT_ARRIVED:
		global bCebalrai1Flag
		bCebalrai1Flag = HAS_ARRIVED

		pKessok4 = App.ShipClass_GetObject(pSet, "Kessok3")
		pKessok5 = App.ShipClass_GetObject(pSet, "Kessok4")
		pKessok6 = App.ShipClass_GetObject(pSet, "Kessok5")
		pKessok7 = App.ShipClass_GetObject(pSet, "Kessok6")
		pKessok8 = App.ShipClass_GetObject(pSet, "Kessok7")
		pKessokHeavy = App.ShipClass_GetObject(pSet, "KessokHeavy")

		pKessok4.SetAI(KessokLightAI.CreateAI(pKessok4))
		pKessok5.SetAI(KessokLightAI.CreateAI(pKessok5))
		pKessok6.SetAI(KessokLightAI.CreateAI(pKessok6))
		pKessok7.SetAI(KessokLightAI.CreateAI(pKessok7))
		pKessok8.SetAI(KessokLightAI.CreateAI(pKessok8))
		pKessokHeavy.SetAI(KessokHeavyAI.CreateAI(pKessokHeavy))

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()

	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		# Make sure player and ship are in the same set
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimo.SetAI(FriendlyCebalrai1AI.CreateAI(pGeronimo, lAllies))

	if Maelstrom.Maelstrom.bZeissAlive == TRUE:	
		# Make sure player and ship are in the same set
		pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
		pSanFrancisco.SetAI(FriendlyCebalrai1AI.CreateAI(pSanFrancisco, lAllies))

	return 0


#
# SetBelaruz1AI()
#
def SetBelaruz1AI(pAction):
#	DebugPrint ("Setting Belaruz1 AI")
	pSet = App.g_kSetManager.GetSet("Belaruz1")

	if bKessokAttacked == TRUE:
		pKessok1 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok8", "Kessok2 Start" )
		pKessok2 = loadspacehelper.CreateShip( "KessokLight", pSet, "Kessok9", "Kessok4 Start" )

		# Instantly Cloak the Kessoks
		pCloak = pKessok1.GetCloakingSubsystem()
		pCloak.InstantCloak()
		pCloak = pKessok2.GetCloakingSubsystem()
		pCloak.InstantCloak()

		pKessok3 = App.ShipClass_GetObject(pSet, "KessokHeavy")
		pKessok3.SetInvincible(0)
		
		pKessok1.SetAI(EnemyAI.CreateAI(pKessok1))
		pKessok2.SetAI(EnemyAI.CreateAI(pKessok2))
		pKessok3.SetAI(EnemyAI.CreateAI(pKessok3))

		pGame = App.Game_GetCurrentGame()
		pPlayerSetName = pGame.GetPlayerSet().GetName()
	
		if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
			# Make sure player and ship are in the same set
			pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
			pGeronimo.SetAI(FriendlyBelaruz1AI.CreateAI(pGeronimo, lAllies))
	
		if Maelstrom.Maelstrom.bZeissAlive == TRUE:	
			# Make sure player and ship are in the same set
			pSanFrancisco = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS San Francisco")
			pSanFrancisco.SetAI(FriendlyBelaruz1AI.CreateAI(pSanFrancisco, lAllies))

	return 0


#
# AbortSequence() - Abort a sequence
#
def AbortSequence():
#	DebugPrint ("Aborting Sequence")

	global idInterruptSequence
	pInterruptSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(idInterruptSequence))
	if (pInterruptSequence):
		pInterruptSequence.Completed()
		idInterruptSequence = App.NULL_ID

		MissionLib.ViewscreenOff(None, 0)
		Bridge.BridgeUtils.EnableScanMenu()


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
		pcSetName = pSet.GetName()
		pGame = App.Game_GetCurrentGame()
		pPlayerSetName = pGame.GetPlayerSet().GetName()

		if pPlayerSetName == "Starbase12":

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L243", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif iBustersDestroyed == 0:
#			DebugPrint("Too much interference.  Must destroy Riha device.")

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L056", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

		elif iBustersDestroyed == 1:
			if bCebalraiScanned == FALSE:
#				DebugPrint("Found Cebalrai!")

				global bCebalraiScanned
				bCebalraiScanned = TRUE

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L091", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "CreateCebalraiMenu")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L055", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

 			elif pPlayerSetName == "Cebalrai1":
#				DebugPrint("Too much interference.  Must destroy Cebalrai device.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L056", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif (pcSetName[:len("Cebalrai")] == "Cebalrai"):
#				DebugPrint("Must go to Cebalrai1.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L021", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			else:
#				DebugPrint("Nothing new detected.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L018", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif iBustersDestroyed == 2:
			if bBelaruzScanned == FALSE:
#				DebugPrint("Found Belaruz!")
	
				global bBelaruzScanned
				bBelaruzScanned = TRUE

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L127", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create(__name__, "CreateBelaruzMenu")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L128", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

 			elif pPlayerSetName == "Belaruz1":
#				DebugPrint("Too much interference.  Must destroy Belaruz device.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L056", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			elif (pcSetName[:len("Belaruz")] == "Belaruz"):
#				DebugPrint("Must go to Belaruz1.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L021", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

			else:
#				DebugPrint("Nothing new detected.")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L018", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		else:
#			DebugPrint("Nothing new detected.  All three Busters destroyed.")
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L171", "Captain", 1, pMissionDatabase)
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

		if pcTargetName == "Galor":
#			DebugPrint("Scanning Galor")
			if bGalorDisabled == TRUE:
				global iGalorScanned, bScanningGalor
				
				bScanningGalor = TRUE

				if iGalorScanned == 0:
#					DebugPrint("Scanning Galor, first time.")
					iGalorScanned = 1

					# Add Scan Galor sequence
					pSequence.AppendAction(GetScanGalorSequence())

				elif iGalorScanned == 1:
#					DebugPrint("Scanning Galor, second time.")
					iGalorScanned = 2

					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L079", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L080", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L081", "Captain", 0, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L082", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN_BACK)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L083", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L084", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L085", None, 0, pMissionDatabase)					
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L086", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

				else:
#					DebugPrint("Scanning Galor, nothing new.")

					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L078", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

				pAction = App.TGScriptAction_Create(__name__, "ResetScanGalorFlag")
				pSequence.AppendAction(pAction)

			else:
#				DebugPrint("Can't scan past the Galor's shields")

				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L078", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif (pcTargetName[:len("Device")] == "Device"):
#			DebugPrint("Scanning Device")
			if bDeviceScanned == FALSE:
				pPlayer = MissionLib.GetPlayer()

				# Check if power is diverted to sensors
				if (pPlayer.GetSensorSubsystem().GetNormalPowerPercentage() > 1):
					global bDeviceScanned
					bDeviceScanned = TRUE

					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L067", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L068", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					if iBustersDestroyed == 0:
						pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L069", "Captain", 1, pMissionDatabase)
						pSequence.AppendAction(pAction)
						pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L070", "Captain", 1, pMissionDatabase)
						pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L071", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)
					pAction = App.TGScriptAction_Create(__name__, "EnableDeviceTarget")
					pSequence.AppendAction(pAction)
					pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L072", None, 0, pMissionDatabase)
					pSequence.AppendAction(pAction)

				else:
#					DebugPrint("Scanning Device... failed.  Power not diverted to sensors.")
					pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L066", "Captain", 1, pMissionDatabase)
					pSequence.AppendAction(pAction)

			else:
#				DebugPrint("Scanning Device, nothing new.")
	
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L078", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		elif (pcTargetName == "KessokHeavy") and not bKessokScanned:
			global bKessokScanned
			bKessokScanned = TRUE

			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L154", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

			if not (bKessokHailed == 0):
				pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L154b", "Captain", 1, pMissionDatabase)
				pSequence.AppendAction(pAction)

		else:
#			DebugPrint("Nothing new detected.")
		
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L078", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

	else:
#		DebugPrint("Nothing new detected.")
	
		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L078", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
	pSequence.AppendAction(pAction)

	#Make this sequence interruptable
	global idInterruptSequence
	idInterruptSequence = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)


#
# ResetScanGalorFlag() - Resets the flag for scanning the Galor
#
def ResetScanGalorFlag(pAction):
	global bScanningGalor
	bScanningGalor = FALSE

	return 0


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

		pAction = App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE, "E8M1HailingStarbase", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)

	elif (sTarget == "USS San Francisco"):
		pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
		pZeiss	= App.CharacterClass_GetObject(pDBridgeSet, "Zeiss")

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
		pSequence.AppendAction(pAction)

		if bSanFranciscoCritical:
			# Need to repair
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1HailingZeiss2", None, 0, pMissionDatabase)

		else:
			# Chat
			pAction = App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E8M1HailingZeiss1", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction)

	elif (sTarget == "USS Geronimo"):
		pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
		pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

		pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
		pSequence.AppendAction(pAction)

		if bGeronimoCritical:
			# Need repair
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1HailingMacCray4", None, 0, pMissionDatabase)

		elif not bCommandGeronimo and bGalorDestroyed and bGalorDisabled:
			# "Hey, I wanted to destroy that Galor"
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1HailingMacCray3", None, 0, pMissionDatabase)

		elif iGeronimoHailed == 1:
			# MacCray tells a joke
			global iGeronimoHailed
			iGeronimoHailed = iGeronimoHailed + 1

			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1HailingMacCray2a", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1HailingMacCray2b", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1HailingMacCray2c", "H", 1, pMissionDatabase)
			pSequence.AppendAction(pAction, 1)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1HailingMacCray2d", "E", 1, pMissionDatabase)

		else:
			global iGeronimoHailed
			iGeronimoHailed = iGeronimoHailed + 1

			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1HailingMacCray1", None, 0, pMissionDatabase)

		pSequence.AppendAction(pAction)

	elif (sTarget == "Galor") and (iGalorScanned == 0) and (bGalorDisabled == TRUE):
#		DebugPrint("Hailing/Scanning Galor, first time.")

		global iGalorScanned
		iGalorScanned = 1

		# Add Hail/Scan Galor sequence
		pSequence.AppendAction(GetScanGalorSequence())

		pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
		pSequence.AppendAction(pAction)

		#Make this sequence interruptable
		global idInterruptSequence
		idInterruptSequence = pSequence.GetObjID()

	elif (sTarget == "KessokHeavy") and not (bKessokHailed == 1):
		if bKessokDetected:
			# set flag for Hailing Kessok
			global bKessokHailed
			bKessokHailed = -1

			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)
			
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L152c", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "KessokTalk")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok02", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction, 10)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_BECOME_ACTIVE)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok03", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction, 1)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok05", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction, 6)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_BECOME_INACTIVE)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok07", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction, 2)
			pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok09", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction, 12)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok10", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L164", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L165", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L166", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "AddDataButton")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN_BACK)
			pSequence.AppendAction(pAction)

		else:
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L152b", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

	else:
#		DebugPrint("Nothing Special to handle")

		pSequence.Completed()
		pObject.CallNextHandler(pEvent)

		return

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)



#
# KessokTalk()
#
def KessokTalk(pAction):
	pKessokSet = MissionLib.SetupBridgeSet("KessokSet", "data/Models/Sets/Kessok/kessokbridge.nif")
	pKessok = MissionLib.SetupCharacter("Bridge.Characters.Kessok", "KessokSet")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok01", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok04", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction, 2)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok06", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1HailKessok08", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction, 2)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	pSequence.Play()

	return 0


#
# GetScanGalorSequence()
#
def GetScanGalorSequence():
	pSequence = App.TGSequence_Create()

	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L033", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L034", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	pGame = App.Game_GetCurrentGame()
	pPlayerSetName = pGame.GetPlayerSet().GetName()
	# If the Geronimo is alive and in the same set
	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()

		if (pPlayerSetName == pGeronimoSetName):
			pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
			pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L035", "C", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L036", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L037", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L038", "S", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L039", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction1)

	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
		if (pPlayerSetName == pGeronimoSetName):
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L040", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L041", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction1 = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction1)

	pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction1)
	pAction3 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L042", "H", 1, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction1)
	pAction4 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L043", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction4, pAction3)
	pAction5 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction5, pAction3)
	pAction6 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction6, pAction5, 3)
	pAction7 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L044", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction7, pAction5, 3)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L045")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L046", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L047")
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L048", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction1)
	pAction2 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction1)
	pAction3 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction3, pAction1, 5)
	pAction4 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L049", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction4, pAction1, 5)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L050")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L051", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L052", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)

	if Maelstrom.Maelstrom.bGeronimoAlive == TRUE:
		pGeronimo = App.ShipClass_GetObject( App.SetClass_GetNull(), "USS Geronimo")
		pGeronimoSetName = pGeronimo.GetContainingSet().GetName()
		if (pPlayerSetName == pGeronimoSetName):
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L053", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction)

	return pSequence


#
#	FleetCommandAttackTarget()
#
def FleetCommandAttackTarget(pMenu, pEvent):
#	DebugPrint("Fleet Command: Attack Target")
	pCommandedShip = App.ShipClass_Cast(pEvent.GetSource())
	pGame = App.Game_GetCurrentGame()
	pPlayer = App.ShipClass_Cast(pGame.GetPlayer())
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		pTarget = pPlayer.GetTarget()
		if pTarget:
			if (pCommandedShip.GetName() == "USS Geronimo") and (pTarget.GetName() == "Galor"):
#				DebugPrint("Player is commanding %s to attack the Galor." % pCommandedShip.GetName())

				global bCommandGeronimo
				bCommandGeronimo = TRUE

				pEBridgeSet = App.g_kSetManager.GetSet("EBridgeSet")
				pMacCray = App.CharacterClass_GetObject (pEBridgeSet, "MacCray")

				pSequence = App.TGSequence_Create()

				pAction	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "MacCray")
				pSequence.AppendAction(pAction)
				pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, "E8M1L054", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
				pSequence.AppendAction(pAction)

				MissionLib.QueueActionToPlay(pSequence)

	pMenu.CallNextHandler(pEvent)


#
# WarpHandler()
#
def WarpHandler(pObject, pEvent):
#	DebugPrint("Handling Warp")

	if iDataToKessok > 0:
		if iDataToKessok == 2:
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L242", "Captain", 1, pMissionDatabase)
			pAction.Play()

		else:
			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			# Data was en-route to the Transporter Room when you decided to warp out
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L236", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L237", "Data")
			pSequence.AppendAction(pAction)
			pAction2 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "X")
			pSequence.AddAction(pAction2, pAction, 15)
			pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_ENABLE_MENU)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "AddDataButton")
			pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)

		return

	pObject.CallNextHandler(pEvent)


#
#	AddDataButton() - Adds Go to Kessok Ship button in Data's menu
#
def AddDataButton(pAction):
#	DebugPrint("Adding Data's go to Kessok ship button")

	global bDataToKessokProd
	bDataToKessokProd = TRUE

	global bKessokHailed
	bKessokHailed = TRUE

	g_pData.AddPythonFuncHandlerForInstance(ET_GO_KESSOK, __name__ + ".GoToKessokShip")
	g_pDataMenu.AddChild(CreateBridgeMenuButton(pMissionDatabase.GetString("GoKessok"), ET_GO_KESSOK, 0, g_pData))

	return 0


#
#	RemoveDataButton() - Removes the Go to Kessok Ship button in Data's menu
#
def RemoveDataButton(pAction):
#	DebugPrint("Removing Data's go to Kessok ship button")
	global bDataToKessokProd
	bDataToKessokProd = FALSE

	g_pDataMenu.RemoveItemW(pMissionDatabase.GetString("GoKessok"))

	return 0


#
#	DataOnShip() - Data is now on the Kessok ship
#
def DataOnShip(pAction):
	global iDataToKessok
	iDataToKessok = 2

	return 0


#
#	GoToKessokShip() - Data is told to go aboard the Kessok ship
#
def GoToKessokShip(pObject, pEvent):
#	DebugPrint("Data told to go to the Kessok Ship")
	global iDataToKessok
	iDataToKessok = 1

	#Disable Data Menu
	g_pData.SetMenuEnabled(0)

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create(__name__, "RemoveDataButton")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L175", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "L1")
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L176", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction1, pAction, 5)
	pAction2 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L177", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction1, 5)
	pAction3 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L178", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction2, 8)
	pAction3b = App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields")
	pSequence.AddAction(pAction3b, pAction2, 11)
	pAction4 = App.TGScriptAction_Create(__name__, "DataOnShip")
	pSequence.AddAction(pAction4, pAction2, 12)
	pAction5 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L179", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction5, pAction3)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L180", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L181", "S", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L182", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L183", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction1, pAction, 2)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L184", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction1)
	pAction3 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L185", "C", 1, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction1)
	pAction4 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L186", "C", 1, pMissionDatabase)
	pSequence.AddAction(pAction4, pAction1)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L187", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L188", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L189", "S", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L190", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction, 8)
	pAction3 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L191", None, 0, pMissionDatabase)
	pSequence.AddAction(pAction3, pAction, 5)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L192", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L193", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L194", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L195", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L196", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L197", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)	
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L198", "Data")
	pSequence.AppendAction(pAction)
	pAction1 = App.TGScriptAction_Create(__name__, "OnKessokShip")
	pSequence.AddAction(pAction1, pAction, 2)
	pAction = App.TGScriptAction_Create(__name__, "ResetInterruptData")
	pSequence.AppendAction(pAction)

	#Make this sequence interruptable
	global idInterruptData
	idInterruptData = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)


#
#	OnKessokShip() - Data and Eepa dialogue on the Kessok ship
#
def OnKessokShip(pAction):
#	DebugPrint("Data is on Kessok ship. You've made friends of the Kessoks")

	global pFriendlies, pEnemies
	pEnemies.RemoveName("KessokHeavy")
	pEnemies.RemoveName("Device 3")
	pFriendlies.AddName("KessokHeavy")
	pFriendlies.AddName("Device 3")
	
	pKessokSet = App.g_kSetManager.GetSet("KessokSet")
	pKessok	= App.CharacterClass_GetObject(pKessokSet, "Kessok")

	pSequence = App.TGSequence_Create()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KessokSet", "Kessok")
	pSequence.AppendAction(pAction)
	pAction0 = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L200", "Data")
	pSequence.AppendAction(pAction0)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
	pSequence.AddAction(pAction2, pAction0)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1L201", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L202", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1L203", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L204", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L205", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L206", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1L207", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E8M1L208", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1L209", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L210", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1L211", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1L212", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L213", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1L214", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L217", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKessok, App.CharacterAction.AT_SAY_LINE, "E8M1L218", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L219", "Captain", 1, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L220", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L221", None, 0, pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L222", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L223", "Data")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
	pSequence.AppendAction(pAction1)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L224", "Captain", 1, pMissionDatabase)
	pSequence.AddAction(pAction2, pAction)
	pAction = App.TGScriptAction_Create(__name__, "SaffiTimer2")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "ResetInterruptData")
	pSequence.AppendAction(pAction)

	#Make this sequence interruptable
	global idInterruptData
	idInterruptData = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)

	return 0


#
# ResetInterrupt()
#
def ResetInterrupt(pAction):

	global idInterruptSequence
	idInterruptSequence	= App.NULL_ID

	return 0


#
# ResetInterruptData()
#
def ResetInterruptData(pAction):
	global idInterruptData
	idInterruptData = App.NULL_ID

	return 0


#
#	KessokHeavyAttacked() - Events for if you attack the KessokHeavy or the Sunbuster in Belaruz
#
def KessokHeavyAttacked(pObject, pEvent):
	if bKessokAttacked == FALSE:
		global bKessokAttacked
		bKessokAttacked = TRUE

		# Abort Sequence, if any is going on
		AbortSequence()

		# Abort Data and/or Eepa dialogue, if any is going on
		global idInterruptData
		pInterruptData = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(idInterruptData))
		if (pInterruptData):
			pInterruptData.Completed()
			idInterruptData = App.NULL_ID
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pAction.Play()

#		DebugPrint("You've made enemies of the Kessoks")
		pMission = MissionLib.GetMission()

		global pFriendlies, pEnemies
		pFriendlies.RemoveName("KessokHeavy")
		pFriendlies.RemoveName("Device 3")
		pEnemies.AddName("KessokHeavy")
		pEnemies.AddName("Device 3")

#		DebugPrint("Turning on KessokHeavy Shields")
		pSet = App.g_kSetManager.GetSet("Belaruz1")
		pKessok = App.ShipClass_GetObject(pSet, "KessokHeavy")
		if pKessok:
			pShields = pKessok.GetShields()
			if pShields:
				pShields.TurnOn()

		# Remove Weapon Hit Handlers
		pBuster = App.ShipClass_GetObject(pSet, "Device 3")
		pBuster.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".KessokHeavyAttacked")
		pKessok.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".KessokHeavyAttacked")

		if iDataToKessok == 2:
			# Data is on the KessokShip when you attack.  Game Over, imbecile.
			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_WATCH_ME)
			pSequence.AppendAction(pAction1)
			pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C1")
			pSequence.AddAction(pAction2, pAction1)
			pAction3 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L234", None, 0, pMissionDatabase)
			pSequence.AddAction(pAction3, pAction1)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_TURN, "C1")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_TURN, "C1")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L235", "Captain", 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

			MissionLib.GameOver(None, pSequence)

			return
	
		else:
			pSequence = App.TGSequence_Create()

			pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pSequence.AppendAction(pAction)

			pAction = App.TGScriptAction_Create(__name__, "SetBelaruz1AI")
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create(__name__, "RemoveDataButton")
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L167", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			if iDataToKessok == 1:
				# Data was en-route to the Transporter Room when you attacked
				pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L236", None, 0, pMissionDatabase)
				pSequence.AppendAction(pAction)
				pAction = App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E8M1L237", "Data")
				pSequence.AppendAction(pAction)
				pAction2 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "X")
				pSequence.AddAction(pAction2, pAction, 15)

				#Re-enable Data Menu
				g_pData.SetMenuEnabled(0)
	
			pAction = App.TGScriptAction_Create(__name__, "Decloak", 2)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E8M1L168", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L169", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)

			MissionLib.QueueActionToPlay(pSequence)


#
#	SaffiWarn() - Saffi tells you to contact Starfleet
#
def SaffiWarn(pObject, pEvent):
	if bStarfleetContacted == FALSE:
#		DebugPrint("Saffi Warn")

		g_pSaffi.SayLine(pMissionDatabase, "E8M1L174", "Captain", 1)


#
#	SaffiWarn2() - Saffi tells you to contact Starfleet, after you've made friends with Eepa
#
def SaffiWarn2(pObject, pEvent):
	if bStarfleetContacted == FALSE and bDataInfoPlayed == FALSE:
#		DebugPrint("Saffi Warn 2")

		g_pSaffi.SayLine(pMissionDatabase, "E8M1L225", "Captain", 1)

		# Start a timer for Data's dialogue
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_DATAINFO, __name__ + ".DataInfo", fStartTime + 60, 0, 0)


#
#	SaffiTimer2() - Init timer for SaffiWarning2 
#
def SaffiTimer2(pAction):
#	DebugPrint("Saffi Timer 2")

	global bContactStarfleetProd
	bContactStarfleetProd = TRUE

	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SAFFIWARN, __name__ + ".SaffiWarn2", fStartTime + 30, 0, 0)

	Maelstrom.Episode8.Episode8.KessoksFriendly = TRUE

	return 0


#
#	DataInfo() - Patient players who ignore Saffi are rewarded with some Data dialogue
#
def DataInfo(pObject, pEvent):
	if bStarfleetContacted == FALSE:
#		DebugPrint("DataInfo plays")

		pSequence = App.TGSequence_Create()

		pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pSequence.AppendAction(pAction)

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L226", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_SAY_LINE, "E8M1L227", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L228", "Captain", 1, pMissionDatabase)
		pSequence.AppendAction(pAction)

		MissionLib.QueueActionToPlay(pSequence)

		global bDataInfoPlayed
		bDataInfoPlayed = TRUE
		# Start a timer to repeat Saffi's warning
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_SAFFIWARN, __name__ + ".SaffiWarn", fStartTime + 30, 0, 0)


#
# EnableDeviceTarget() - Restores targeting info for the Devices
#
def EnableDeviceTarget(pAction):
#	DebugPrint("Reenable Device Targets")

	global kDevice1Subsystems, kDevice2Subsystems, kDevice3Subsystems

	if kDevice1Subsystems:
#		DebugPrint("Device 1 Targetable")
		MissionLib.ShowSubsystems(kDevice1Subsystems)
		kDevice1Subsystems = 0
	if kDevice2Subsystems:
#		DebugPrint("Device 2 Targetable")
		MissionLib.ShowSubsystems(kDevice2Subsystems)
		kDevice2Subsystems = 0
	if kDevice3Subsystems:
#		DebugPrint("Device 3 Targetable")
		MissionLib.ShowSubsystems(kDevice3Subsystems)
		kDevice3Subsystems = 0

	pGame = App.Game_GetCurrentGame()
	pSet = pGame.GetPlayerSet()

	if (pSet.GetName() == "Riha1"):
		pDevice = App.ShipClass_GetObject(pSet, "Device 1")
	elif (pSet.GetName() == "Cebalrai1"):
		pDevice = App.ShipClass_GetObject(pSet, "Device 2")
	else: 
		pDevice = App.ShipClass_GetObject(pSet, "Device 3")

#	DebugPrint("Targeting Device's Power Core")
	pPlayerShip = MissionLib.GetPlayer()
	pPlayerShip.SetTargetSubsystem(pDevice.GetPowerSubsystem())

	return 0


#
# CreateRihaMenu() - Creates the Riha Helm Menu
#
def CreateRihaMenu(pAction):
#	DebugPrint ("Adding Riha to Menu")

	global iCourseSet
	iCourseSet = 1

	pRihaMenu = Systems.Riha.Riha.CreateMenus()
	pRihaMenu.SetMissionName("Maelstrom.Episode8.E8M1.E8M1")

	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return 0

	# Set the location on the warp menu
	pWarpButton.SetDestination("Systems.Riha.Riha1")
	g_pKiskaMenu.SetFocus(pWarpButton)

	return 0


#
# CreateCebalraiMenu() - Creates the Cebalrai Helm Menu
#
def CreateCebalraiMenu(pAction):
#	DebugPrint ("Adding Cebalrai to Menu")

	global iCourseSet
	iCourseSet = 2

	pCebalraiMenu = Systems.Cebalrai.Cebalrai.CreateMenus()
	pCebalraiMenu.SetMissionName("Maelstrom.Episode8.E8M1.E8M1")

	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return 0

	# Set the location on the warp menu
	pWarpButton.SetDestination("Systems.Cebalrai.Cebalrai1")
	g_pKiskaMenu.SetFocus(pWarpButton)

	return 0


#
# CreateBelaruzMenu() - Creates the Belaruz Helm Menu
#
def CreateBelaruzMenu(pAction):
#	DebugPrint ("Adding Belaruz to Menu")

	global iCourseSet
	iCourseSet = 3

	pBelaruzMenu = Systems.Belaruz.Belaruz.CreateMenus()
	pBelaruzMenu.SetMissionName("Maelstrom.Episode8.E8M1.E8M1")

	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return 0

	# Set the location on the warp menu
	pWarpButton.SetDestination("Systems.Belaruz.Belaruz1")
	g_pKiskaMenu.SetFocus(pWarpButton)

	return 0


#
#	HailStarfleet()
#
def HailStarfleet(pObject, pEvent):
#	DebugPrint ("Hailing Starfleet...")

	pLiuSet = App.g_kSetManager.GetSet("LiuSet")
	pLiu = App.CharacterClass_GetObject (pLiuSet, "Liu")

	pSequence = MissionLib.ContactStarfleet()

	pAction = App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSequence.AppendAction(pAction)

	if bContactStarfleetProd == TRUE:
#		DebugPrint("Contact Starfleet Prod is True")

		if bStarfleetContacted == TRUE:
#			DebugPrint("Return to Starfleet")
	
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L232b", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)

		elif Maelstrom.Episode8.Episode8.KessoksFriendly == TRUE:
#			DebugPrint("Mission complete!  We've made friends with the Kessoks.")

			global bStarfleetContacted
			bStarfleetContacted = TRUE

			RemoveHooks()

#			DebugPrint ("Removing DestroyDevicesGoal2")
			MissionLib.RemoveGoal("E8DestroyDevicesGoal2")

			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L230", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L233b", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L231", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction)
			pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
			pSequence.AppendAction(pAction)
			pAction1 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E8M1L238", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction1)
			pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L239", "S", 1, pMissionDatabase)
			pSequence.AppendAction(pAction1)
			pAction1 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E8M1L240", None, 0, pMissionDatabase)
			pSequence.AppendAction(pAction1)
			pAction1 = App.TGScriptAction_Create(__name__, "EnableWarp")
			pSequence.AppendAction(pAction1)
			pAction1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E8M1L241", "Captain", 1, pMissionDatabase)
			pSequence.AppendAction(pAction1)
			pAction2 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_MOVE, "X")
			pSequence.AddAction(pAction2, pAction1, 15)
			pAction3 = App.CharacterAction_Create(g_pData, App.CharacterAction.AT_ENABLE_MENU)
			pSequence.AppendAction(pAction3)

	else:
#		DebugPrint("Mission not complete.")
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E8M1L229", None, 0, pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "ResetInterruptData")
		pSequence.AppendAction(pAction)
	
		#Make this sequence interruptable
		global idInterruptData
		idInterruptData = pSequence.GetObjID()

	MissionLib.QueueActionToPlay(pSequence)


#
#	EnableWarp() - Re-enables warp
#
def EnableWarp(pAction):
#	DebugPrint("Re-enable Warp")
	
	global iDataToKessok
	iDataToKessok = -1

	return 0


#
# Remove all mission hooks to the menus
#
def RemoveHooks(pAction = None):
#	DebugPrint("Removing Hooks")

	global bMissionWon
	bMissionWon = TRUE

	App.SortedRegionMenu_SetPauseSorting(1)

	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
	pSBMenu.SetMissionName("Maelstrom.Episode8.E8M2.E8M2")

	pRihaMenu = Systems.Riha.Riha.CreateMenus()
	pCebaraiMenu = Systems.Cebalrai.Cebalrai.CreateMenus()
	pBelaruzMenu = Systems.Belaruz.Belaruz.CreateMenus()

	App.SortedRegionMenu_SetPauseSorting(0)

#	DebugPrint("Done Removing Hooks")

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
#	DebugPrint ("Terminating Episode 8, Mission 1.\n")

	# Set our terminate flag to true
	global bMissionTerminate
	bMissionTerminate = TRUE

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()

	# Remove instance handlers
	# Remove Command fleet event
	pCommandFleetMenu = MissionLib.GetCharacterSubmenu("Science", "Command Fleet")
	if pCommandFleetMenu:
		pCommandFleetMenu.RemoveHandlerForInstance(Bridge.ScienceMenuHandlers.ET_FLEET_COMMAND_ATTACK_TARGET, __name__ + ".FleetCommandAttackTarget")
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

	# Remove Goal buttons from menu
	MissionLib.DeleteAllGoals()

	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if(pGeneralDatabase):
		App.g_kLocalizationManager.Unload(pGeneralDatabase)

	if(pMenuDatabase):
		App.g_kLocalizationManager.Unload(pMenuDatabase)

	# Clear the set course menu
	App.SortedRegionMenu_ClearSetCourseMenu()	
