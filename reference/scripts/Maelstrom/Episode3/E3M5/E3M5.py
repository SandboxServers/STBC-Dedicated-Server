###############################################################################
#	Filename:	E3M5.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 3 Mission 5
#	
#	Created:	05/07/01 -	Alberto Fonseca
#	Modified:	01/10/02 - 	Tony Evans
###############################################################################

import App
import loadspacehelper
import MissionLib
import Maelstrom.Episode3.Episode3
import Bridge.BridgeUtils

TRUE	= 1
FALSE	= 0

ET_DERELICT_FOUND		= App.Mission_GetNextEventType()
ET_PROD_SCAN_FOR_WARP	= App.Mission_GetNextEventType()

#
# Global variables 
#
g_pFriendlies			= None
g_pEnemies				= None
g_pMissionDatabase		= None
g_pGeneralDatabase		= None
g_idInterruptSequence	= App.NULL_ID
g_bPlayerHasAttacked	= 0		# Player has not participated in the fray yet.
g_bDisallowDamageDialog = 0
g_bJonKaHit				= 0
g_bBelaruz4Clear		= 0
g_bSystemScanned		= 0
g_bTargetScanned		= 0
g_bScannedForWarp		= 0
g_iScanForWarpProdID	= App.NULL_ID
g_bMissionFailed		= 0
g_bIntroPlayed			= 0
g_iNumGalors			= 0
g_bFirstCardFled		= 0
g_bReturnSB12			= 0
g_bEnteredBelaruz2		= 0
g_bMatanFled			= 0
g_bMissionTerminated	= 0
g_iMissionProgress		= 0


DERELICT_SCAN_RANGE		= 115	# Range at which player can scan derelict
NUM_BELARUZ4_ASTEROIDS	= 7		# Number of Asteroids in Belaruz 4.

DETECT_DERELICT			= 1



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
	loadspacehelper.PreloadShip("Sovereign", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("BirdOfPrey", 3)
	loadspacehelper.PreloadShip("Vorcha", 1)
	loadspacehelper.PreloadShip("Keldon", 1)
	loadspacehelper.PreloadShip("Galor", 4)

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
	global g_pFriendlies
	global g_pEnemies
	global g_bPlayerHasAttacked
	global g_bDisallowDamageDialog
	global g_bJonKaHit
	global g_bBelaruz4Clear
	global g_bSystemScanned
	global g_bTargetScanned
	global g_bScannedForWarp
	global g_iScanForWarpProdID
	global g_bMissionFailed
	global g_bMissionTerminated
	global g_iMissionProgress

	g_pFriendlies			= None
	g_pEnemies				= None
	g_bPlayerHasAttacked	= 0		
	g_bDisallowDamageDialog = TRUE
	g_bJonKaHit				= 0
	g_bBelaruz4Clear		= 0
	g_bSystemScanned		= 0
	g_bTargetScanned		= 0
	g_bScannedForWarp		= 0
	g_iScanForWarpProdID	= App.NULL_ID
	g_bMissionFailed		= 0
	g_bMissionTerminated	= FALSE
	g_iMissionProgress		= 0

	# Setup TGL's.
	# Get the Mission Database
	global g_pMissionDatabase
	g_pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 3/E3M5.tgl")
	global g_pGeneralDatabase
	g_pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	pLBridgeSet = MissionLib.SetupBridgeSet("LBridgeSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	pLiu = MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LBridgeSet")

	pKBridgeSet = MissionLib.SetupBridgeSet("KBridgeSet", "data/Models/Sets/Klingon/BOPBridge.nif")
	pKorbus = MissionLib.SetupCharacter("Bridge.Characters.Korbus", "KBridgeSet")

	pMBridgeSet = MissionLib.SetupBridgeSet("MBridgeSet", "data/Models/Sets/Cardassian/cardbridge.nif")
	pMatan = MissionLib.SetupCharacter("Bridge.Characters.Matan", "MBridgeSet")

	import Bridge.Characters.CommonAnimations
	Bridge.Characters.CommonAnimations.PutGuestChairIn()

	CreateData()
	SetAffiliations(pMission)
	CreateSpaceSets()
	CreateShips()
	CreateMenus()
	SetupEventHandlers(pMission)
	MissionLib.RemoveGoal("E3WarpToBelaruz4Goal")

	MissionLib.AddGoal ("E3RespondToDistressCallGoal")

#	print("Finished loading " + __name__)

	MissionLib.SaveGame("E3M4-")

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)

	MissionLib.SetupFriendlyFire()

################################################################################
#	CreateMenus()
#
#	Create system menus.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateMenus():
	import Systems.Belaruz.Belaruz
	pBelaruz = Systems.Belaruz.Belaruz.CreateMenus()
	pBelaruz.SetMissionName(__name__)

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
	# Sets up the mission database and region for Starbase 12 set
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()
	Systems.Starbase12.Starbase12.GetSet()

	import Systems.Belaruz.Belaruz4
	Systems.Belaruz.Belaruz4.Initialize()
	pSet = Systems.Belaruz.Belaruz4.GetSet()
	
	import Systems.Belaruz.Belaruz2
	Systems.Belaruz.Belaruz2.Initialize()
	pSet2 = Systems.Belaruz.Belaruz2.GetSet()

	# Load custom placements for bridge.
	pBridgeSet = Bridge.BridgeUtils.GetBridge()
	import Maelstrom.Episode3.EBridge_P
	Maelstrom.Episode3.EBridge_P.LoadPlacements(pBridgeSet.GetName())

	# Add our custom placement objects for this mission.
	import Maelstrom.Episode3.E3M5.E3M5_Belaruz4_P
	Maelstrom.Episode3.E3M5.E3M5_Belaruz4_P.LoadPlacements(pSet.GetName())
	import Maelstrom.Episode3.E3M5.E3M5_Belaruz2_P
	Maelstrom.Episode3.E3M5.E3M5_Belaruz2_P.LoadPlacements(pSet2.GetName())

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
	import Systems.Belaruz.Belaruz4
	import Systems.Starbase12.Starbase12
	pSet = Systems.Belaruz.Belaruz4.GetSet()
	pStarbase = Systems.Starbase12.Starbase12.GetSet()

	MissionLib.CreatePlayerShip("Sovereign", pSet, "player", "Player Start")
	loadspacehelper.CreateShip("FedStarbase", pStarbase, "Starbase 12", "Starbase12 Location")
	pBirdOfPrey3 = loadspacehelper.CreateShip("BirdOfPrey", pSet, "Gr'err", "BOP3 Start")
	pKahlessRo = loadspacehelper.CreateShip("BirdOfPrey", pSet, "Kahless Ro", "Kahless Ro Start")
	pJonka = loadspacehelper.CreateShip("Vorcha", pSet, "JonKa", "JonKa Start")
	CreateGonDev()

	CloakKlingonShips()

	# Add visible damage to Klingons.
	import DamageBOP1
	import DamageKR
	import DamageVorcha
	DamageBOP1.AddDamage(pBirdOfPrey3)
	DamageKR.AddDamage(pKahlessRo)
	DamageVorcha.AddDamage(pJonka)

	# Damage Klingon ship systems
	# Specify Min/Max percentage to damage.
	DamageKlingon(pBirdOfPrey3, 0.25, 0.37)
	DamageKlingon(pKahlessRo, 0.65, 0.85)
	DamageKlingon(pJonka, 0.15, 0.25)

	# Special damage for Jonka's impulse engines.
	pSystem = pJonka.GetImpulseEngineSubsystem()
	assert pSystem
	if pSystem:
		# Make sure system is disabled.
		MissionLib.SetConditionPercentage(pSystem, pSystem.GetDisabledPercentage() - .1)

################################################################################
#	CreateData()
#
#	Create Commander Data character on the bridge(guest).
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateData():
	# Add Data to the bridge
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	import Bridge.Characters.Data
	pData = App.CharacterClass_GetObject(pBridgeSet, "Data")
	if not (pData):
		pData = Bridge.Characters.Data.CreateCharacter(pBridgeSet)
		Bridge.Characters.Data.ConfigureForSovereign(pData)
		pData.SetLocation("EBGuest")

	# Communicate with Data event
	pMenu = pData.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateData")



######################################################		
# WarpHandler()
#
# This funtion will handle the use of the warp button
#
#	Args:	None
#
#	Return: None
#
######################################################
def WarpHandler(pObject, pEvent):

	if not g_bBelaruz4Clear:
		pBridge = App.g_kSetManager.GetSet("bridge")
		pXO = App.CharacterClass_GetObject (pBridge, "XO")

		pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "WarpStop2", "Captain", 1, g_pGeneralDatabase)
		pAction.Play()
	
		return

	pObject.CallNextHandler(pEvent)

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
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		return
	pSet = pPlayer.GetContainingSet()
	sSetName = pSet.GetName()
	if g_bBelaruz4Clear and not (sSetName == "Belaruz2") and not g_bEnteredBelaruz2:
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M5CommSaffi1", None, 0, g_pMissionDatabase)
 
	elif (sSetName == "Belaruz2") and (g_iNumGalors > 2):
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M5CommSaffi2", None, 0, g_pMissionDatabase)

	elif g_bReturnSB12:
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M5CommSaffi3", None, 0, g_pMissionDatabase)

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
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		return
	pSet = pPlayer.GetContainingSet()

	if g_bBelaruz4Clear and not (pSet.GetName() == "Belaruz2") and not g_bEnteredBelaruz2:
		pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E3M5CommFelix2", None, 0, g_pMissionDatabase)

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
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
 
	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		return
	pSet = pPlayer.GetContainingSet()

	if g_bBelaruz4Clear:
		pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")

		pSeq = MissionLib.NewDialogueSequence()

		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M5CommKiska1", None, 0, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E3M5CommFelix1", "H", 1, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M5CommKiska2", "T", 1, g_pMissionDatabase)
		pSeq.AppendAction(pAction)

		pAction.Play()

	else:
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
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")

	pSet = MissionLib.GetPlayerSet()
	if pSet is None:
		pObject.CallNextHandler(pEvent)
		return

	if g_iMissionProgress == DETECT_DERELICT:
		pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M5CommMiguel3", None, 0, g_pMissionDatabase)	
	elif g_bBelaruz4Clear:
		if (pSet.GetName() == "Belaruz2") and not g_bEnteredBelaruz2 and not g_bScannedForWarp:
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M5CommMiguel1", None, 0, g_pMissionDatabase)

		else:
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M5CommMiguel2", None, 0, g_pMissionDatabase)	
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
	pBridge = App.g_kSetManager.GetSet("bridge")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		return
	pSet = pPlayer.GetContainingSet()
	sSetName = pSet.GetName()

	if (g_bBelaruz4Clear and not (sSetName == "Belaruz2") and not g_bEnteredBelaruz2) or ((sSetName == "Belaruz2") and (g_iNumGalors > 2)):
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M5CommData1", None, 0, g_pMissionDatabase)

	elif g_bMatanFled:
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M5CommData2", None, 0, g_pMissionDatabase)

	else:
		pObject.CallNextHandler(pEvent)
		return

	pAction.Play()


###############################################################################
#	SetAffiliations(pMission)
#	
#	Setup friendly/enemy/neutral affiliations.
#	
#	Args:	pMission
#	
#	Return:	None
###############################################################################
def SetAffiliations(pMission):
	global g_pFriendlies
	global g_pEnemies

	g_pFriendlies = pMission.GetFriendlyGroup()
	g_pFriendlies.AddName("player")
	g_pFriendlies.AddName("Gr'err")
	g_pFriendlies.AddName("Kahless Ro")
	g_pFriendlies.AddName("JonKa")

	g_pEnemies = pMission.GetEnemyGroup()
	g_pEnemies.AddName("Galor1")
	g_pEnemies.AddName("Galor2")
	g_pEnemies.AddName("Galor3")
	g_pEnemies.AddName("Galor4")
	g_pEnemies.AddName("MatanShip")

###############################################################################
#	SetupEventHandlers(pMission)
#	
#	Setup event handlers for mission.
#	
#	Args:	pMission
#	
#	Return:	None
###############################################################################
def SetupEventHandlers(pMission):
	pSet = App.g_kSetManager.GetSet("Belaruz4")
	pKahless = MissionLib.GetShip("Kahless Ro", pSet)
	pJonka = MissionLib.GetShip("JonKa", pSet)

	pKahless.AddPythonFuncHandlerForInstance(App.ET_OBJECT_DESTROYED,	__name__ + ".KahlessDialog")
	pJonka.AddPythonFuncHandlerForInstance(App.ET_OBJECT_DESTROYED,	__name__ + ".JonkaDestroyed")
	pJonka.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT,	__name__ + ".JonKaHitByPlayer")

	# Instance handler for Miguel's Scan Area button
	pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pScience.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Warp event
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pHelm.GetMenu()
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ + ".EnterSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")

	# Add Communicate Handlers
	Bridge.BridgeUtils.SetupCommunicateHandlers()

###############################################################################
#	CloakKlingonShips()
#	
#	Instantly cloak ships for start of mission.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def CloakKlingonShips():
	pSet = App.g_kSetManager.GetSet("Belaruz4")

	pShip = App.ShipClass_GetObject(pSet, "JonKa")
	pCloak = pShip.GetCloakingSubsystem()
	if (pCloak):
		pCloak.InstantCloak()		

	pShip = App.ShipClass_GetObject(pSet, "Kahless Ro")
	pCloak = pShip.GetCloakingSubsystem()
	if (pCloak):
		pCloak.InstantCloak()		

	pShip = App.ShipClass_GetObject(pSet, "Gr'err")
	pCloak = pShip.GetCloakingSubsystem()
	if (pCloak):
		pCloak.InstantCloak()		
	return 0

###############################################################################
#	DecloakKlingonShips(pAction)
#	
#	De-cloak Klingon ships to greet player.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def DecloakKlingonShips(pAction):
	pSet = App.g_kSetManager.GetSet("Belaruz4")

	pShip = App.ShipClass_GetObject(pSet, "JonKa")
	pJonka = pShip
	pCloak = pShip.GetCloakingSubsystem()
	if (not App.IsNull(pCloak)):
		pCloak.StopCloaking()		

	pShip = App.ShipClass_GetObject(pSet, "Kahless Ro")
	pCloak = pShip.GetCloakingSubsystem()
	if (not App.IsNull(pCloak)):
		pCloak.StopCloaking()		

	pShip = App.ShipClass_GetObject(pSet, "Gr'err")
	pCloak = pShip.GetCloakingSubsystem()
	if (not App.IsNull(pCloak)):
		pCloak.StopCloaking()		

	MissionLib.ViewscreenWatchObject(pJonka)

	return 0

###############################################################################
#	IntroDialog()
#	
#	Play introduction sequence.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def IntroDialog():
	MissionLib.RemoveGoal("E3RespondToDistressCallGoal")

	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pXO = App.CharacterClass_GetObject (pBridge, "XO")
	pHelm = App.CharacterClass_GetObject (pBridge, "Helm")
	pScience = App.CharacterClass_GetObject (pBridge, "Science")

	pSeq = MissionLib.NewDialogueSequence()

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "DecloakKlingonShips")
	pSeq.AppendAction (pAction)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5Decloak", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

#	Removed to fix bug 3099 - Tony
#	pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M5L017", "Captain", 1, g_pMissionDatabase)
#	pSeq.AppendAction (pAction)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed")
	pSeq.AppendAction(pAction, 1)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", None, 0, g_pGeneralDatabase)
	pSeq.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L019", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5L020", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L021", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L022", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5L023", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L024", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5L025", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L026", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L027", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5L028", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L029", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L030", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5Maneuver", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5RepairsUnderway", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5AskForHelp", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction (pAction)

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSeq.AppendAction(pAction)

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))

	pAction = App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3ScanAreaGoal")
	pSeq.AppendAction (pAction)

	MissionLib.QueueActionToPlay(pSeq)


###############################################################################
#	MatanWarpsIn()
#	
#	Create Matan's ship warping in.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def MatanWarpsIn(pAction):
	pSet = App.g_kSetManager.GetSet("Belaruz4")

	# Import and create ships
	pKeldon = loadspacehelper.CreateShip("Keldon", pSet, "MatanShip", "Matan Warp In", TRUE)
	pKeldon.SetInvincible(TRUE)
	MissionLib.MakeEnginesInvincible(pKeldon)

	pKeldon.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".MatanWeaponHitHandler")

	# Reenable repairs on the klingon ships.
	pSet = App.g_kSetManager.GetSet ("Belaruz4")
	pShip = App.ShipClass_GetObject (pSet, "JonKa")
	pSystem = pShip.GetRepairSubsystem()
	pSystem.TurnOn()

	pShip = App.ShipClass_GetObject (pSet, "Gr'err")
	pSystem = pShip.GetRepairSubsystem()
	pSystem.TurnOn()
	
	return 0

###############################################################################
#	GalorsWarpIn()
#	
#	Create Galors and have them warp in with Matan.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def GalorsWarpIn(pAction):
	pSet = App.g_kSetManager.GetSet("Belaruz4")

	# Import and create ships
	pGalor1 = loadspacehelper.CreateShip("Galor", pSet, "Galor1", "Galor1 Warp In", TRUE)
	pGalor2 = loadspacehelper.CreateShip("Galor", pSet, "Galor2", "Galor2 Warp In", TRUE)

	pGalor1.SetInvincible(TRUE)
	pGalor2.SetInvincible(TRUE)
	MissionLib.MakeEnginesInvincible(pGalor1)
	MissionLib.MakeEnginesInvincible(pGalor2)

	# Setup weapon hit handlers.
	pGalor1.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".GalorHitByWeapon")
	pGalor2.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".GalorHitByWeapon")

	# Play arrival dialogue.
	CardEnterDialog()

	return 0

###############################################################################
#	CardEnterDialog()
#	
#	Dialog played after the Cardassians arrive. This continues a cutscene
#	already in progress.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def CardEnterDialog():
	# Set up Sequence for Matan's Conversation
	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pMBridgeSet = App.g_kSetManager.GetSet("MBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
	pMiguel = App.CharacterClass_GetObject(pBridge, "Science")
	pMatan = App.CharacterClass_GetObject (pMBridgeSet, "Matan")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraEnd", "Belaruz4"), 8.0)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "MatanShip"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
											"CutsceneCameraBegin", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
												"ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
							"PlacementWatch", "bridge", "View", "Player Cam"))
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5CardassiansWarpingIn", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M5L032", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	if not MissionLib.g_bViewscreenOn:
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
		pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L033", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5L034", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0))

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MBridgeSet", "Matan")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E3M5L035", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0))

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L036", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0))

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MBridgeSet", "Matan")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E3M5L037", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E3M5L038", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0))

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L039", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff", 0))

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MBridgeSet", "Matan")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E3M5MatanBad", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetAttackAI"))
	pSeq.AppendAction(App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M5OpenedFire", None, 0, g_pMissionDatabase))

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction(pAction)

	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraEnd", "bridge"))	
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))

	pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialog")
	pSeq.AppendAction (pAction)

	pAction = App.TGScriptAction_Create(__name__, "ProtectKorbusGoal")
	pSeq.AppendAction (pAction)

	MissionLib.QueueActionToPlay(pSeq)


###############################################################################
#	SetAttackAI(pAction)
#	
#	Set AI for Klingons and Cardassians to attack
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def SetAttackAI(pAction):
	pSet = App.g_kSetManager.GetSet("Belaruz4")

	# Get Cardassian ships
	pGalor1 = MissionLib.GetShip("Galor1", pSet)
	pGalor2 = MissionLib.GetShip("Galor2", pSet)
	pKeldon = MissionLib.GetShip("MatanShip", pSet)

	# Set their AI
	import GalorGroup1AI
	import MatanAI
	if pGalor1:
		pGalor1.SetAI(Maelstrom.Episode3.E3M5.GalorGroup1AI.CreateAI(pGalor1, "Galor1 Start"))
	if pGalor2:
		pGalor2.SetAI(Maelstrom.Episode3.E3M5.GalorGroup1AI.CreateAI(pGalor2, "Galor2 Start"))
	if pKeldon:
		pKeldon.SetAI(Maelstrom.Episode3.E3M5.MatanAI.CreateAI(pKeldon))

	# Get Klingon Ships
	pJonka = App.ShipClass_GetObject(pSet, "JonKa")
	pGrerr = App.ShipClass_GetObject(pSet, "Gr'err")
	pKahless = App.ShipClass_GetObject(pSet, "Kahless Ro")

	# Set their AI
	import E3M5BasicKlingonAI
	import E3M5JonKaAI
	if pJonka:
		pJonka.SetAI(E3M5JonKaAI.CreateAI(pJonka))
	if pGrerr:
		pGrerr.SetAI(E3M5BasicKlingonAI.CreateAI(pGrerr))
	if pKahless:
		pKahless.SetAI(E3M5BasicKlingonAI.CreateAI(pKahless))

	return 0

###############################################################################
#	KahlessDialog()
#	
#	Play dialogue when Kehless Ro is destroyed.
#	
#	Args:	pObject, pEvent
#	
#	Return:	None
###############################################################################
def KahlessDialog(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pXO = App.CharacterClass_GetObject (pBridge, "XO")
	pData = App.CharacterClass_GetObject (pBridge, "Data")

	pSeq = MissionLib.NewDialogueSequence()

	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5KahlessDead", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	global g_bPlayerHasAttacked 
	if (g_bPlayerHasAttacked == 0) and g_bTargetScanned:
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L041", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSeq.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M5NoKilling", "Captain", 1, g_pMissionDatabase)
		pSeq.AppendAction (pAction)

	MissionLib.QueueActionToPlay(pSeq)

	pObject.CallNextHandler(pEvent)


###############################################################################
#	MatanWeaponHitHandler()
#	
#	Matan's weapon hit handler. Make sure his ship isn't damaged too badly.
#	Set flag that player has attacked.
#	
#	Args:	pObject, pEvent
#	
#	Return:	None
###############################################################################
def MatanWeaponHitHandler(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if not g_bPlayerHasAttacked:




















		pFiringObject = pEvent.GetFiringObject()
		pPlayer = MissionLib.GetPlayer()

		if(pPlayer and pFiringObject):
			if(pFiringObject.GetObjID() == pPlayer.GetObjID()):
				# Firing object was the player's ship.  Set flag that says
				# that the player has tried to help the klingons.
				global g_bPlayerHasAttacked
				g_bPlayerHasAttacked = TRUE

	pShip = App.ShipClass_Cast (pEvent.GetDestination ())
	if(pShip):
		# Don't allow the keldon to get too damaged.
		pSystem = pShip.GetHull()
		if(pSystem):
			if(pSystem.GetConditionPercentage () < 0.15):
				MissionLib.SetConditionPercentage(pSystem, 0.15)

		pSystem = pShip.GetPowerSubsystem()
		if(pSystem):
			if(pSystem.GetConditionPercentage () < 0.15):
				MissionLib.SetConditionPercentage(pSystem, 0.15)

	pObject.CallNextHandler(pEvent)


###############################################################################
#	GalorHitByWeapon()
#	
#	Galor's weapon hit handler. Set flag that player has attacked.
#	
#	Args:	pObject, pEvent
#	
#	Return:	None
###############################################################################
def GalorHitByWeapon(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if(not g_bPlayerHasAttacked):
		pFiringObject = pEvent.GetFiringObject()
		pPlayer = MissionLib.GetPlayer()
		
		if(pPlayer and pFiringObject):
			if(pFiringObject.GetObjID() == pPlayer.GetObjID ()):
				# Firing object was the player's ship.  Set flag that says
				# that the player has tried to help the klingons.
				global g_bPlayerHasAttacked
				g_bPlayerHasAttacked = TRUE
				
				# Remove handler.
				pGalor = pEvent.GetDestination()
				pGalor.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".GalorHitByWeapon")

	# Call any other handlers for this class.
	pObject.CallNextHandler (pEvent)

###############################################################################
#	KillGonDev()
#	
#	Set GonDev as destroyed.
#	
#	Args:	pShip, the GonDev.
#	
#	Return:	None
###############################################################################
def KillGonDev(pShip):
	pSystem = pShip.GetHull()
	# Destroy the hull.
	pSystem.SetCondition(0)
	
	# Set ship invincible so it won't actually blow up.
	# We want to be able to target it.
	pShip.SetInvincible(1)

###############################################################################
#	DamageKlingon()
#	
#	Randomly damage ship systems.
#	
#	Args:	pShip, ship to damage.
#			fMinPercent, minimum damage to apply.
#			fMaxPercent, maximum damage to apply.
#	
#	Return:	None
###############################################################################
def DamageKlingon(pShip, fMinPercent, fMaxPercent):
	# Randomly damage all other systems.
	pSystem = pShip.GetHull()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetShields()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetPowerSubsystem ()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		MissionLib.SetConditionPercentage(pSystem, r)

	# Sensor system is disabled.
	pSystem = pShip.GetSensorSubsystem()
	if (pSystem):
		MissionLib.SetConditionPercentage(pSystem, pSystem.GetDisabledPercentage() - .05)

	pSystem = pShip.GetImpulseEngineSubsystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		MissionLib.SetConditionPercentage(pSystem, r)

	# Warp system is disabled.
	pSystem = pShip.GetWarpEngineSubsystem()
	if (pSystem):
		MissionLib.SetConditionPercentage(pSystem, pSystem.GetDisabledPercentage() - .05)

	pSystem = pShip.GetTorpedoSystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetPhaserSystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetPulseWeaponSystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		# Make sure the system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetTractorBeamSystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)
		MissionLib.SetConditionPercentage(pSystem, r)

	pSystem = pShip.GetRepairSubsystem()
	if (pSystem):
		pSystem.TurnOff()

	pSystem = pShip.GetCloakingSubsystem()
	if (pSystem):
		r = App.g_kSystemWrapper.GetRandomNumber (100)
		r = (r + 1) / 100.0
		r = r * (fMaxPercent - fMinPercent)
		r = 1 - (r + fMinPercent)

		# Make sure the cloaking system isn't disabled.
		if (r <= pSystem.GetDisabledPercentage ()):
			r = pSystem.GetDisabledPercentage () + 0.1
		MissionLib.SetConditionPercentage(pSystem, r)


###############################################################################
#	CallDamage(sShipName, sSystemName, iPercentageLeft)
#	
#	Damage dialogue, called from AI.
#	
#	Args:	sShipName = Name of the ship taking damage
#			sSystemName = Name of the system being damaged
#			iPercentageLeft = How much they have left of the system
#	
#	Return:	None
###############################################################################
def CallDamage(sShipName, sSystemName, iPercentageLeft ):
	# Make sure nothing overlaps
	global g_bDisallowDamageDialog
	if (g_bDisallowDamageDialog == TRUE):
		return 0

	if (sShipName != "JonKa"):
		# Only do call damage for JonKa
		return 0	   
			
	# Make sure player and JonKa are in the same set
	pShip = App.ShipClass_GetObject (None, sShipName)

	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()

	if (not pShip or not pPlayer):
		# Either the player or JonKa doesn't exist.  Don't do anything.
#		print ("Call damage no JonKa or player")
		return 0


	if (pShip.GetContainingSet ().GetName () != pPlayer.GetContainingSet ().GetName ()):
		# Player and JonKa not is same set.  Don't do anything.
#		print ("Call damage not in same set.")
		return 0		

	# Get korbus.
	pKorbusSet = App.g_kSetManager.GetSet ("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKorbusSet, "Korbus")

	# Determine if it's time to say some dialog
#	print ("Call damage " + sSystemName)
	if (sSystemName == "Shields"):
		if (iPercentageLeft == 0):
#			print ("Call damage shields at 0")
			# Shields down.
			pLine = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L043", None, 0, g_pMissionDatabase)
		else:
			return 0
	elif (sSystemName == "HullPower"):
		# Hull or powerplant damaged
		if (iPercentageLeft == 50):
			pLine = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L044", None, 0, g_pMissionDatabase)
		elif (iPercentageLeft == 25):
			pLine = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L045", None, 0, g_pMissionDatabase)
		else:
			return 0
	else:
		return 0

	g_bDisallowDamageDialog = TRUE

	pSeq = MissionLib.NewDialogueSequence()

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
	pSeq.AppendAction(pAction)

	# Append the line here
	pSeq.AppendAction (pLine)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction (pAction)

	pSeq.Play()

	return 0

###############################################################################
#	ReAllowDamageDialog()
#	
#	Reset the Call Damage global
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def ReAllowDamageDialog(pAction):
	# Make sure nothing overlaps
	global g_bDisallowDamageDialog
	g_bDisallowDamageDialog = FALSE

	return 0

###############################################################################
#	ProtectKorbusGoal()
#	
#	Add goals to protect Korbus.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def ProtectKorbusGoal (pAction):
	MissionLib.AddGoal("E3ProtectKorbusGoal")
	MissionLib.AddGoal("E3CardsWithdrawGoal")
	return 0

###############################################################################
#	JonKaHitByPlayer(pObject, pEvent)
#	
#	Play dialogue when JonKa is hit by player.
#	
#	Args:	pObject, pEvent
#	
#	Return:	None
###############################################################################
def JonKaHitByPlayer(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler (pEvent)
		return

	global g_bJonKaHit
	global g_bDisallowDamageDialog

	if g_bJonKaHit or g_bDisallowDamageDialog:
		pObject.CallNextHandler (pEvent)
		return 0

	pFiringObject = pEvent.GetFiringObject ()

	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()

	if (not pPlayer or not pFiringObject):
		pObject.CallNextHandler (pEvent)
	   	return

	if (pFiringObject.GetObjID () == pPlayer.GetObjID ()):
		# Firing object was the player's ship.  Set flag that says
		# that the player has hit the JonKa
		g_bJonKaHit = TRUE
		g_bDisallowDamageDialog = TRUE

		# Set up Sequence for Korbus
		pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
		pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")
		pBridge = App.g_kSetManager.GetSet("bridge")

		pSeq = MissionLib.NewDialogueSequence()

		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
		pSeq.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L046", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSeq.AppendAction (pAction)
		pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialog")
		pSeq.AppendAction (pAction, 3)		# Don't allow another line to come up for 3 seconds.

		MissionLib.QueueActionToPlay(pSeq)

	# Call any other handlers for this class.
	pObject.CallNextHandler (pEvent)

###############################################################################
#	JonKaWarpDialog()
#	
#	Play dialogue when JonKa is warping out, called from E3M5JonKaAI
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def JonKaWarpDialog():
	# Matan has left.  Korbus will warp out soon.  Say his lines and create new galors in
	# Belaruz 2
	
	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject (pBridge, "XO")
	pTact = App.CharacterClass_GetObject (pBridge, "Tactical")

	global g_bDisallowDamageDialog
	g_bDisallowDamageDialog = TRUE
	global g_bBelaruz4Clear
	g_bBelaruz4Clear = TRUE

	pSeq = MissionLib.NewDialogueSequence()
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5Avenge", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5JonKaLeft", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction, 3)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5StupidKlingons", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create(__name__, "ScanForWarpProd")
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create(__name__, "ReAllowDamageDialog")
	pSeq.AppendAction (pAction, 3)		# Don't allow another line to come up for 3 seconds.
	pAction = App.TGScriptAction_Create(__name__, "ResetInterrupt")
	pSeq.AppendAction(pAction)

	# Make this sequence interruptable
	global g_idInterruptSequence
	g_idInterruptSequence = pSeq.GetObjID()

	pSeq.Play ()
	
	# Create the galors in the other set if Galor1 and 2 did not survive.

	pSet2 = App.g_kSetManager.GetSet ("Belaruz2")

	pGalor1 = App.ShipClass_GetObject (None, "Galor1")
	pGalor2 = App.ShipClass_GetObject (None, "Galor2")

	iCount = 0
	if (pGalor1):
		iCount = iCount + 1
	if (pGalor2):
		iCount = iCount + 1

	iWant = 0

	fHullSystem = 1.0
	fPowerSystem = 1.0
	fWarpSystem = 1.0

	pBOP = App.ShipClass_GetObject (None, "Gr'err")
	if (pBOP):
		# Bird of prey still also alive.  iWant is always 5.
		iWant = 5
	else:
		pJonka = App.ShipClass_GetObject (None, "JonKa")
		pHullSystem = pJonka.GetHull()
		if (pHullSystem):
			fHullSystem = pHullSystem.GetConditionPercentage ()

		pPowerSystem = pJonka.GetPowerSubsystem ()
		if (pPowerSystem):
			fPowerSystem = pPowerSystem.GetConditionPercentage ()

		pWarpSystem = pJonka.GetWarpEngineSubsystem()
		if (pWarpSystem):
			fWarpSystem = pWarpSystem.GetConditionPercentage ()


		if (fHullSystem < 0.35 or fPowerSystem < 0.35 or fWarpSystem < 0.35):
			iWant = 3		# Only want three ships in Belaruz2
		elif (fHullSystem < 0.5 or fPowerSystem < 0.5 or fWarpSystem < 0.5):
			iWant = 4
		else:
			iWant = 5

	import Maelstrom.Episode3.E3M5.GalorGroup2AI

	if (iCount < iWant):
		pGalor3 = loadspacehelper.CreateShip("Galor", pSet2, "Galor3", "Galor3 Start")
		pGalor3.SetAI(Maelstrom.Episode3.E3M5.GalorGroup2AI.CreateAI(pGalor3, "Galor3 Start"))

		iCount = iCount + 1

	if (iCount < iWant):
		pGalor4 = loadspacehelper.CreateShip("Galor", pSet2, "Galor4", "Galor4 Start")
		pGalor4.SetAI(Maelstrom.Episode3.E3M5.GalorGroup2AI.CreateAI(pGalor4, "Galor4 Start"))

		iCount = iCount + 1

	global g_iNumGalors
	g_iNumGalors = iCount

	return

###############################################################################
#	ResetInterrupt()
#	
#	Reset ID of sequence.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def ResetInterrupt(pAction):
	global g_idInterruptSequence
	g_idInterruptSequence	= App.NULL_ID

	return 0

###############################################################################
#	ScanForWarpProd(pAction)
#	
#	Create prod to scan for warp trail.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def ScanForWarpProd (pAction):
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_SCAN_FOR_WARP, __name__ + ".SayScanForWarpProd", fStartTime + 30.0, 0, 0)

	# Store off the timer ID
	global g_iScanForWarpProdID
	g_iScanForWarpProdID = pTimer.GetObjID ()
	
	return 0

###############################################################################
#	SayScanForWarpProd(pObject, pEvent)
#	
#	Play prod to scan for warp trail.
#	
#	Args:	pObject, pEvent
#	
#	Return:	None
###############################################################################
def SayScanForWarpProd(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if not g_bMissionFailed:
		# If Player still in Belaruz 4.
		pSet = App.g_kSetManager.GetSet("Belaruz4")
		if MissionLib.GetShip("player", pSet):
				pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
				pSeq = MissionLib.NewDialogueSequence()
				pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, 
								"E3M5ScanForWarpProd", "Captain", 1, g_pMissionDatabase)
				pSeq.AppendAction (pAction)
				pSeq.Play()

	# Timer has been triggered.  Clear the ID.
	global g_iScanForWarpProdID
	g_iScanForWarpProdID = App.NULL_ID

	pObject.CallNextHandler (pEvent)

###############################################################################
#	MissionFail()
#	
#	Set mission fail flag.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def MissionFail():
	global g_bMissionFailed
	g_bMissionFailed = TRUE

###############################################################################
#	JonkaDestroyed(pObject, pEvent)
#	
#	Play dialogue when JonKa is destroyed.
#	
#	Args:	pObject, pEvent
#	
#	Return:	None
###############################################################################
def JonkaDestroyed(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if g_bMissionFailed:
		pObject.CallNextHandler(pEvent)
		return

	# Abort Sequence, if any is going on
	global g_idInterruptSequence
	pInterruptSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idInterruptSequence))
	if (pInterruptSequence):
		pInterruptSequence.Completed()
		g_idInterruptSequence = App.NULL_ID

	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E3M5KlingonsDestroyed", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "HailStarfleet1", g_pGeneralDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "HailStarfleet7", g_pGeneralDatabase))
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M5L049", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M5L050", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M5L051", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction(pAction)
	MissionLib.GameOver(None, pSeq)

	pObject.CallNextHandler(pEvent)


################################################################################
#	GalorFlees()
#
#	Notify player when Galors flee. Called form GalorGroup1AI.
#
#	Args:	None
#
#	Return:	None
################################################################################
def GalorFlees():
	if not g_bFirstCardFled:
		global g_bFirstCardFled
		g_bFirstCardFled = 1

		pBridge = App.g_kSetManager.GetSet("bridge")
		pTact = App.CharacterClass_GetObject(pBridge, "Tactical")

		pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5CardsFleeing", "Captain", 1, g_pMissionDatabase)
		MissionLib.QueueActionToPlay(pAction)

	elif g_iNumGalors == 1:
		pSet = MissionLib.GetPlayerSet()
		if pSet:
			if pSet.GetName() == "Belaruz4":
				pBridge = App.g_kSetManager.GetSet("bridge")
				pTact = App.CharacterClass_GetObject(pBridge, "Tactical")

				pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5LastOneRunning", "Captain", 1, g_pMissionDatabase)
				MissionLib.QueueActionToPlay(pAction)
	

################################################################################
#	MatanGoodbye()
#
#	Matan's departing dialogue. Called from MatanAI.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MatanGoodbye():
	# Matan bids you goodbye while running away

	global g_bMatanFled
	g_bMatanFled = 1

	pMBridgeSet = App.g_kSetManager.GetSet("MBridgeSet")
	pMatan = App.CharacterClass_GetObject (pMBridgeSet, "Matan")

	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")

	pSeq = MissionLib.NewDialogueSequence()

	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5L034", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MBridgeSet", "Matan")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMatan, App.CharacterAction.AT_SAY_LINE, "E3M5MatanFlees", None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3ScanForWarpGoal")
	pSeq.AppendAction (pAction)

	MissionLib.QueueActionToPlay(pSeq)


################################################################################
#	WinDialogue()
#
#	Play sequence at mission win. 
#
#	Args:	None
#
#	Return:	None
################################################################################
def WinDialog():
	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pXO = App.CharacterClass_GetObject (pBridge, "XO")
	pData = App.CharacterClass_GetObject (pBridge, "Data")

	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")

	pSeq = MissionLib.NewDialogueSequence()

	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", "bridge"))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraBegin", "bridge"))
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed")
	pSeq.AppendAction(pAction)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M5CardsGone", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M5JonkaHailing", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction, 1)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
	pSeq.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5MatanNotHere", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L047", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5L048", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction (pAction)
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "KorbusWarpOut"))
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1")
	pSeq.AppendAction(pAction, 5)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M5Win1", "Captain", 1, g_pMissionDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSeq.AppendAction(pAction, 2)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "HailStarfleet7", "Captain", 1, g_pGeneralDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "KiskaOnScreen2", None, 0, g_pGeneralDatabase)
	pSeq.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSeq.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSeq.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M5Win2", None, 0, g_pMissionDatabase)
	pSeq.AppendAction (pAction)

	if (Maelstrom.Episode3.Episode3.g_bWin4Good):
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M5WinGood", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M5WinGood2", None, 0, g_pMissionDatabase)
		pSeq.AppendAction (pAction)

	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M5WinReturnSB12", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3ReturnToSB12Goal"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetSB12ReturnFlag"))

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction (pAction)
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))

	MissionLib.QueueActionToPlay(pSeq)

	MissionLib.RemoveGoal("E3ProtectKorbusGoal", "E3CardsWithdrawGoal")
	
	# Import Starbase System Menu Items
	import Systems.Starbase12.Starbase
	pStarbase = Systems.Starbase12.Starbase.CreateMenus()
	
	pMenu = MissionLib.GetSystemOrRegionMenu("Starbase 12")
	pMenu.SetEpisodeName("Maelstrom.Episode4.Episode4")


################################################################################
#	SetSB12ReturnFlag(pAction)
#
#	Flag for wether we should return to SB 12. (Used for Communicate)
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def SetSB12ReturnFlag(pAction):
	global g_bReturnSB12
	g_bReturnSB12 = 1

	return 0

################################################################################
#	KorbusWarpOut(pAction)
#
#	Give Korbus AI to warp out.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def KorbusWarpOut(pAction):
	pJonka = MissionLib.GetShip("JonKa")
	if(pJonka):
		import KorbusWarpOutAI
		pJonka.SetAI(KorbusWarpOutAI.CreateAI(pJonka))
		
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
			pSet = MissionLib.GetPlayerSet()
			if pSet:
				if pSet.GetName() == "Belaruz4":
					# Start system scan.
					if (not g_bSystemScanned):
						ScanningSystem()
						return
					elif (not g_bScannedForWarp and g_bBelaruz4Clear):
						# Since you're doing the scan, remove the prod.
						global g_iScanForWarpProdID
						if (g_iScanForWarpProdID != App.NULL_ID):
							App.g_kTimerManager.DeleteTimer(g_iScanForWarpProdID)
							g_iScanForWarpProdID = App.NULL_ID
						ScanningSystem()
						return
		elif (iScanType == App.CharacterClass.EST_SCAN_OBJECT):
			if (g_bSystemScanned and g_bTargetScanned == 0):
				pGame = App.Game_GetCurrentGame()
				pPlayer = pGame.GetPlayer()
				if pPlayer is None:
					pObject.CallNextHandler()
					return

				pTarget = App.ObjectClass_Cast(pEvent.GetSource())
				if pTarget is None:
					pTarget = pPlayer.GetTarget()
				if pTarget:
					if (pTarget.GetName() == "Derelict Bird of Prey"):
						ScanDerelict()

						return

	pObject.CallNextHandler(pEvent)


################################################################################
#	ScanDerelict()
#
#	Play dialogue for scanning Derelict Bird of Prey.
#
################################################################################
def ScanDerelict(pAction = 0):
	pSet = App.g_kSetManager.GetSet("Belaruz4")
	pDerelict = App.ShipClass_GetObject(pSet, "Derelict Bird of Prey")

	pSeq = MissionLib.NewDialogueSequence()

	assert pDerelict
	if pDerelict is None:
		return pSeq

	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	if pPlayer is None:
		return pSeq

	kTargetPos = pDerelict.GetWorldLocation()
	kPlayerPos = pPlayer.GetWorldLocation()

	kPlayerPos.Subtract(kTargetPos)
	fLen = kPlayerPos.Length()

	if (fLen > DERELICT_SCAN_RANGE):
		# We're too far.  Say line to this effect.
		pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
		pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, 
											"E3M5TooFar", None, 1, g_pMissionDatabase)
		pSeq.AppendAction(pAction)
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	else:
		global g_bTargetScanned
		g_bTargetScanned = TRUE

		# Change the name of the GonDev
		pDerelict.SetName("Derelict GonDev")

		# Remove the scan target goal
		MissionLib.RemoveGoal("E3ScanDerelictGoal")

		pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
		pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")

		pScanSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
		if pScanSeq is None:
			return pSeq

		pSeq.AppendAction(pScanSeq)
		pSeq.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, 
											"E3M5ScanDerelict", "Captain", 1, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", DETECT_DERELICT + 1))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraBegin", "Belaruz4"))
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
													"ChangeRenderedSet", "Belaruz4"))
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
									"PlacementWatch", "Belaruz4", None, "MatanCam1"))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MatanWarpsIn"), 1.0)
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "GalorsWarpIn"))
		pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))

	MissionLib.QueueActionToPlay(pSeq)

	return 0


################################################################################
#	ScanningSystem()
#
#	Called by ScanHandler() if the player hits the "Scan" button
#
#	Args:	None
#
#	Return:	bool, TRUE if scanned, FALSE if not.
################################################################################
def ScanningSystem(bSkipScanSequence = 0):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return FALSE

	pSensors = pPlayer.GetSensorSubsystem()
	if pSensors is None:
		return FALSE

	# Set our system scan flag.
	global g_bSystemScanned
	g_bSystemScanned = TRUE

	# Remove the scan area goal
	MissionLib.RemoveGoal("E3ScanAreaGoal")

	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")
	pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pXO	= Bridge.BridgeUtils.GetBridgeCharacter("XO")

	pScanSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
	if pScanSeq is None:
		return TRUE

	pSeq = MissionLib.NewDialogueSequence()

	if not bSkipScanSequence:
		pSeq.AppendAction(pScanSeq)
		pSeq.AppendAction(pSensors.ScanAllObjects())

	if (not g_bScannedForWarp and g_bBelaruz4Clear):
		global g_bScannedForWarp
		g_bScannedForWarp = TRUE

		MissionLib.RemoveGoal("E3ScanForWarpGoal")

		pSeq.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M5Belaruz2", "Captain", 1, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3GoToBelaruz2Goal"))

		# This line is duplicated in the else, see comment below for the reason
		pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
		# End duplicated line

	else:
		pSeq.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M5AreaScan", "Captain", 0, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "TargetDerelict"))
		pSeq.AppendAction(App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M5VeryFaint", None, 1, g_pMissionDatabase))
		pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5HailKorbus", "Science", 1, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus"))
		pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5WhatFound", None, 0, g_pMissionDatabase))
		pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5ScanResult", None, 0, g_pMissionDatabase))
		pSeq.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3M5Good", None, 0, g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", DETECT_DERELICT))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3ScanDerelictGoal"))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "KlingonsCircleDerelict", "JonKa", "Gr'err", "Kahless Ro"))
		pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5SaffiOrderScan", "S", 1, g_pMissionDatabase))

		# This is here for a reason, do not remove
		# Okay, here's the deal - Enabling/disabling the scan menus is reference counted, but it's capped at 'visible'.  In other words,
		# you can be as 'disabled' as you want, but once you become enabled, you stay that way, and the ref count doesn't change.
		# Because of this, we must ensure that we enable the scan menu here, rather than after the ScanDerelict, otherwise we end up
		# having the scan menus disabled forever.  Have a nice day
		pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ScanDerelict"))
		# End do not remove section

	MissionLib.QueueActionToPlay(pSeq)

	return TRUE


#
# TargetDerelict()
#
def TargetDerelict(pAction = 0):
	# Make Gondev appear on the target list
	pSet = App.g_kSetManager.GetSet("Belaruz4")
	pGonDev = App.ShipClass_GetObject(pSet, "Derelict Bird of Prey")
	pGonDev.SetTargetable(1)
	pGonDev.SetScannable(1)
	pGonDev.SetHailable(1)

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.SetTarget("Derelict Bird of Prey")

	return 0


################################################################################
#	CreateGonDev()
#
#	Create derelict Klingon ship, the GonDev. 
#
#	Return:	0
################################################################################
def CreateGonDev():
	pSet = App.g_kSetManager.GetSet("Belaruz4")

	pGonDev = loadspacehelper.CreateShip("BirdOfPrey", pSet, "Derelict Bird of Prey", "Dead Ship")

	import DamageGonDev
	DamageGonDev.AddDamage(pGonDev)
	vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
	vVelocity.Scale( 10.0 * App.PI / 180.0 )	# Scale it to 10 degrees/second (converted to radians)
	pGonDev.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
	pGonDev.SetAlertLevel(App.ShipClass.GREEN_ALERT)

	# set this ship to not appear on the target list, we'll make it visable later
	pGonDev.SetTargetable(0)
	pGonDev.SetScannable(0)
	pGonDev.SetHailable(0)

	# Call this to damage klingon ships, the two numbers
	# represend min and max percentage of the systems.
	DamageKlingon (pGonDev, 0.75, 0.99)
	KillGonDev(pGonDev)		# Not only damage it, but kill it.

	pSeq = App.TGSequence_Create ()

	pConditionAction = App.TGConditionAction_Create()
	pConditionAction.AddCondition(App.ConditionScript_Create ("Conditions.ConditionInRange", "ConditionInRange", 170, "player", "Derelict Bird of Prey"))
	pSeq.AppendAction(pConditionAction)
	pAction = App.TGScriptAction_Create(__name__, "ScanForGonDev")
	pSeq.AddAction(pAction, pConditionAction)

	pSeq.Play()


#
# ScanForGonDev()
#
def ScanForGonDev(pAction):

	if not g_bSystemScanned:
		ScanningSystem(1)

	return 0


################################################################################
#	KlingonsCircleDerelict(pAction)
#
#	Set AI for Klingon ships to circle the Derelict BOP
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def KlingonsCircleDerelict(pAction, *pcShipNames):
	import CircleDerelictAI

	pSet = App.g_kSetManager.GetSet("Belaruz4")

	for sShipName in pcShipNames:
		pShip = App.ShipClass_GetObject(pSet, sShipName)

#		print sShipName

		pSystem = pShip.GetSensorSubsystem()
		if pSystem:
			fPercent = (pSystem.GetDisabledPercentage() + 0.1)
			if (pSystem.GetConditionPercentage() < fPercent):
#				print("Restoring Sensors")
				MissionLib.SetConditionPercentage(pSystem, fPercent)
		pSystem = pShip.GetWarpEngineSubsystem()
		if pSystem:
			fPercent = (pSystem.GetDisabledPercentage() + 0.1)
#			print("Restoring Warp")
			MissionLib.SetConditionPercentage(pSystem, fPercent)
		pSystem = pShip.GetImpulseEngineSubsystem()
		if pSystem:
			fPercent = (pSystem.GetDisabledPercentage() + 0.1)
#			print("Restoring Impulse")
			MissionLib.SetConditionPercentage(pSystem, fPercent)
	
		MissionLib.MakeEnginesInvincible(pShip)
	
		pShip.SetAI(CircleDerelictAI.CreateAI(pShip, "Derelict Bird of Prey"))

	return 0


################################################################################
#	RepairGalor(pShip)
#
#	Repair critical ship systems which are below 75%. Set back to 75%.
#
#	Args:	pShip, ship to repair.
#
#	Return:	None
################################################################################
def RepairGalor(pShip):
	pSystem = pShip.GetHull()
	if (pSystem):
		if (pSystem.GetConditionPercentage() < 0.75):
			MissionLib.SetConditionPercentage(pSystem, 0.75)

	pSystem = pShip.GetPowerSubsystem()
	if (pSystem):
		if (pSystem.GetConditionPercentage() < 0.75):
			MissionLib.SetConditionPercentage(pSystem, 0.75)


	# Warp system is disabled.
	pSystem = pShip.GetWarpEngineSubsystem()
	if (pSystem):
		if (pSystem.GetConditionPercentage() < 0.75):
			MissionLib.SetConditionPercentage(pSystem, 0.75)

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

	pShip = App.ShipClass_Cast (pEvent.GetDestination ())

	if (pShip):
		pGame = App.Game_GetCurrentGame()
		pPlayer = pGame.GetPlayer()
		if pPlayer is None:
			return

		pSet = pPlayer.GetContainingSet()
		sSetName = pSet.GetName()

		if (pShip.GetObjID () == pPlayer.GetObjID ()):
			# Player entered a new set.  Check which set it is
			if (sSetName == "Belaruz2"):
				# Player entered belaruz2.  Play dialog if JonKa still alive.
				pJonka = App.ShipClass_GetObject (pSet, "JonKa")
				if (pJonka):

					global g_bEnteredBelaruz2
					g_bEnteredBelaruz2 = 1

					# Remove the warp to belaruz2 goal
					MissionLib.RemoveGoal ("E3GoToBelaruz2Goal", "E3ScanForWarpGoal")

					# Okay, jonKa is here.  Play dialog
					pScience	= Bridge.BridgeUtils.GetBridgeCharacter("Science")
					pXO			= Bridge.BridgeUtils.GetBridgeCharacter("XO")
									
					pSeq = MissionLib.NewDialogueSequence()

					pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M5JonKaInTrouble", "Captain", 1, g_pMissionDatabase)
					pSeq.AppendAction (pAction)
					pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M5WeShouldAssist", "Captain", 1, g_pMissionDatabase)
					pSeq.AppendAction (pAction)

					pSeq.Play ()
			
			elif (sSetName == "Belaruz4"):
				if (g_bIntroPlayed == 0):
					IntroDialog()

					global g_bIntroPlayed
					g_bIntroPlayed = 1

		elif (sSetName == "Belaruz2") and (pShip.GetName() == "Galor1") or (pShip.GetName() == "Galor2"):
			pShip.SetInvincible(0)


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
def ExitSet(pObject, pEvent):
	if g_bMissionTerminated:
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()

	if pShip and (sSetName == "Belaruz2") and g_bBelaruz4Clear:
		if g_pEnemies.IsNameInGroup(pShip.GetName()):
			# Decrement enemies fleeing from Belaruz 2
			global g_iNumGalors
			g_iNumGalors = g_iNumGalors - 1

			if (g_iNumGalors == 0):
				WinDialog()

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

	global g_pGeneralDatabase
	if g_pGeneralDatabase:
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)
		g_pGeneralDatabase = None

	global g_iScanForWarpProdID
	if (g_iScanForWarpProdID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iScanForWarpProdID)
		g_iScanForWarpProdID = App.NULL_ID
	
	# Clear the mission from the belaruz system
	import Systems.Belaruz.Belaruz
	pBelaruz = Systems.Belaruz.Belaruz.CreateMenus()
	pBelaruz.SetMissionName()

	# Remove instance handler for Miguel's Scan Area button
	pScience = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	pMenu = pScience.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Removing instance handler for Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	# Removing Communicate handlers
	Bridge.BridgeUtils.RemoveCommunicateHandlers()

	# Remove Communicate with Data Handler.
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	if pData:
		pMenu = pData.GetMenu()
		if pMenu:
			pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateData")

	MissionLib.ShutdownFriendlyFire()

	# Clear the set course menu
	App.SortedRegionMenu_ClearSetCourseMenu()
