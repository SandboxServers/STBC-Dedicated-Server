###############################################################################
#	Filename:	E3M4.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 3 Mission 4
#	
#	Created:	05/07/01 -	Alberto Fonseca
#	Modified:	01/14/02 - 	Tony Evans
###############################################################################

import App
import loadspacehelper
import MissionLib
import Bridge.Characters.CommonAnimations
import Maelstrom.Episode3.Episode3
import BridgeHandlers

#Start debugger
#kDebugObj = App.CPyDebug()

TRUE	= 1
FALSE	= 0

#
# Place event types here
#
ET_DROP_SHIELDS_EVENT		= App.Mission_GetNextEventType()
ET_PROD_DISTRESS_CALL_EVENT	= App.Mission_GetNextEventType()
ET_FERENGI_KILLED_EVENT		= App.Mission_GetNextEventType()
ET_PROD_MOVE_ON_EVENT		= App.Mission_GetNextEventType()

PART_NOT_STARTED				= 0
PART_AVAILABLE					= 1

#
# Global variables 
#
g_pFriendlies				= None
g_pEnemies					= None
g_pMissionDatabase			= None
g_pGeneralDatabase			= None
g_pPartTwoGroup				= None

g_bMissionFailed			= 0					# Has the mission been failed
g_iPartOneProgress			= PART_AVAILABLE	# state flag for current mission progress
g_iPartTwoProgress			= PART_NOT_STARTED	# state flag for current mission progress
g_iPartThreeProgress		= PART_NOT_STARTED 	# state flag for current mission progress
g_bXiEntrades				= 0
g_bVoltair					= 0
g_bItari					= 0
g_iNumWarbirdsDisabled		= 0
g_iDropShieldsTimerID		= App.NULL_ID
g_iProdDistressCallTimerID	= App.NULL_ID
g_iFerengiKilledTimerID		= App.NULL_ID
g_iProdMoveOnTimerID		= App.NULL_ID
g_pcDestination				= None
g_iPlayedAttackingUs		= 0
g_iHailPartOne				= 0
g_iHailPartTwo				= 0
g_bTalkedToRomulan			= 0
g_bTalkedToFerengi			= 0
g_bKlingonDistressCall		= 0
g_bMissionTerminated		= 0
g_iMissionProgress			= 0

# Constants
PART_ONE_WARPING_TO				= 2
PART_ONE_CHOICE					= 3
PART_ONE_PEACEFUL_RESOLUTION	= 4
PART_ONE_MUST_DISABLE			= 5
PART_ONE_VIOLENT_RESOLUTION		= 6
PART_ONE_FAILED					= 7

PART_TWO_WARPING_TO				= 2
PART_TWO_DISTRESS_SIGNAL		= 3
PART_TWO_SAVE_FERENGI			= 4
PART_TWO_COMPLETE				= 5
PART_TWO_FAILED					= 6

PART_THREE_WARPING_TO 			= 2
PART_THREE_PROTECT_TERRIK		= 3
PART_THREE_COMPLETE				= 4
PART_THREE_FAILED				= 5

FIGHTING_TORENN					= 1

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
	import loadspacehelper
	loadspacehelper.PreloadShip("Sovereign", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Nebula", 3)
	loadspacehelper.PreloadShip("Warbird", 4)
	loadspacehelper.PreloadShip("Marauder", 1)
	loadspacehelper.PreloadShip("Galor", 6)
	loadspacehelper.PreloadShip("Keldon", 1)

###############################################################################
#	Initialize(pMission)
#	
#	Mission startup.
#	
#	Args:	pMission	- the mission object
#	
#	Return:	none
###############################################################################
def Initialize(pMission):
	global g_pMissionDatabase
	global g_pGeneralDatabase
	g_pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 3/E3M4.tgl")
	g_pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	pLBridgeSet = MissionLib.SetupBridgeSet("LBridgeSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	pLiu = MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LBridgeSet")

	pPBridgeSet = MissionLib.SetupBridgeSet("PBridgeSet", "data/Models/Sets/Ferengi/ferengibridge.nif")
	pPraag = MissionLib.SetupCharacter("Bridge.Characters.Praag", "PBridgeSet")

	MissionLib.SetupBridgeSet("TBridgeSet", "data/Models/Sets/Romulan/romulanbridge.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Terrik", "TBridgeSet")
	MissionLib.SetupCharacter("Bridge.Characters.Torenn", "TBridgeSet")

	CreateData()
	SetAffiliations(pMission)

	import Bridge.Characters.CommonAnimations
	Bridge.Characters.CommonAnimations.PutGuestChairIn()

	#Sets up the mission database and region for Starbase 12 set
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()
	pStarbase = Systems.Starbase12.Starbase12.GetSet()

	#Sets up the mission database and region for Voltair 2 set
	import Systems.Voltair.Voltair2
	Systems.Voltair.Voltair2.Initialize()
	pVoltair2 = Systems.Voltair.Voltair2.GetSet()

	#Sets up the mission database and region for Itari 8 set
	import Systems.Itari.Itari8
	Systems.Itari.Itari8.Initialize()
	pItari8 = Systems.Itari.Itari8.GetSet()

	#Sets up the mission database and region for XiEntrades 5 set
	import Systems.XiEntrades.XiEntrades5
	Systems.XiEntrades.XiEntrades5.Initialize()
	pXiEntrades5 = Systems.XiEntrades.XiEntrades5.GetSet()

	CreateMenus()

	# Add our custom placement objects for this mission.
	import Maelstrom.Episode3.E3M4.E3M4_Starbase12_P
	Maelstrom.Episode3.E3M4.E3M4_Starbase12_P.LoadPlacements(pStarbase.GetName())

	# Load placements for bridge.
	import Maelstrom.Episode3.EBridge_P
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	Maelstrom.Episode3.EBridge_P.LoadPlacements(pBridgeSet.GetName())

	###################################################
	#This next section will create the ships and set their stats

	#Importing all the ships we plan on using, to save time later

	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pStarbase, "player", "Player Start")
	pStarbase12 = loadspacehelper.CreateShip("FedStarbase", pStarbase, "Starbase 12", "Starbase12 Location")

	# The Berkeley is still docked from its ordeal in E3M2
	pBerkeley = loadspacehelper.CreateShip("Nebula", pStarbase, "USS Berkeley", "Berkeley Docked")
	pBerkeley.ReplaceTexture("data/Models/SharedTextures/FedShips/Berkeley.tga", "ID")

	import Maelstrom.Episode3.E3M2.DamageBerkeley
	Maelstrom.Episode3.E3M2.DamageBerkeley.AddDamage(pBerkeley)
	MissionLib.DamageShip("USS Berkeley", 0.25, 0.5)
	MissionLib.SetConditionPercentage(pBerkeley.GetHull(), .75)

	pBerkeley.SetStatic(TRUE)

	pNightingale = loadspacehelper.CreateShip("Nebula", pStarbase, "USS Nightingale", "Nightingale Start")
	pNightingale.ReplaceTexture("data/Models/SharedTextures/FedShips/Nightingale.tga", "ID")

	pNebula = loadspacehelper.CreateShip("Nebula", pStarbase, "USS Prometheus", "Circling Nebula")
	pNebula.ReplaceTexture("data/Models/SharedTextures/FedShips/Prometheus.tga", "ID")
	pNebula.SetAlertLevel(App.ShipClass.GREEN_ALERT)

	##################################
	#Create AI for pre-existing ships#
	##################################

	import Maelstrom.Episode3.E3M4.PeregrineAI
	pNebula.SetAI(Maelstrom.Episode3.E3M4.PeregrineAI.CreateAI(pNebula))

	import WarpAI
	pNightingale.SetAI(WarpAI.CreateAI(pNightingale, 15, "Starbase 12"))

	###########
	#End of AI#
	###########

	#Tell game which object the player is
	pGame = App.Game_GetCurrentGame()

	#Setup event handlers
#	print ("Event handlers")
	SetupEventHandlers(pMission, pPlayer)

#	print ("Create menus")

	#MissionLib.StandardMusic(pMission)	
	#Mission Goals

	MissionLib.AddGoal ("E3InvestigateAttacksGoal")
	MissionLib.AddGoal ("E3WarpToXiEntradesGoal")
	MissionLib.AddGoal ("E3WarpToItariGoal")       
	MissionLib.AddGoal ("E3WarpToVoltairGoal")     

	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()

#	print("Finished loading " + __name__)
	
	MissionLib.SaveGame("E3M3-")

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)

	MissionLib.SetupFriendlyFire()

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
	pStarbaseMenu = Systems.Starbase12.Starbase.CreateMenus()
	pStarbaseMenu.SetMissionName ()

	import Systems.Itari.Itari
	pItariMenu = Systems.Itari.Itari.CreateMenus()
	pItariMenu.SetMissionName (__name__)

	import Systems.Voltair.Voltair
	pVoltairMenu = Systems.Voltair.Voltair.CreateMenus()
	pVoltairMenu.SetMissionName (__name__)

	import Systems.XiEntrades.XiEntrades
	pXiEntradesMenu = Systems.XiEntrades.XiEntrades.CreateMenus()
	pXiEntradesMenu.SetMissionName (__name__)

	App.SortedRegionMenu_SetPauseSorting(0)


################################################################################
#	CreateData(None)
#
#	Create Commander Data in the guest chair.
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

	# Communicate with Data event
	pMenu = pData.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateData")

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
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")

	if g_bKlingonDistressCall:
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M4CommSaffi3", None, 0, g_pMissionDatabase)

	elif g_bTalkedToFerengi:
		pSequence = MissionLib.NewDialogueSequence()
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M4CommSaffi2", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M4CommData2", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pSequence.Play()
		return

	elif(g_iPartTwoProgress < PART_TWO_WARPING_TO):
		if g_bTalkedToRomulan:
			pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M4CommSaffi1", None, 0, g_pMissionDatabase)
		else:
			pObject.CallNextHandler(pEvent)
			return
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

	if g_iMissionProgress == FIGHTING_TORENN:
		pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E3M4CommFelix1a", None, 0, g_pMissionDatabase)
	elif g_bKlingonDistressCall:
		pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E3M4CommFelix1", None, 0, g_pMissionDatabase)
	elif(g_iPartTwoProgress < PART_TWO_WARPING_TO):
		if g_bTalkedToRomulan:
			pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E3M4CommFelix1", None, 0, g_pMissionDatabase)
		else:
			pObject.CallNextHandler(pEvent)
			return
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

	if g_bKlingonDistressCall:
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M4CommKiska2", None, 0, g_pMissionDatabase)

	elif g_bTalkedToRomulan and (g_iPartThreeProgress <= PART_THREE_WARPING_TO):
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M4CommKiska1", None, 0, g_pMissionDatabase)
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

	if(g_iPartTwoProgress < PART_TWO_WARPING_TO):
		if g_bTalkedToRomulan:
			pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M4CommMiguel1", None, 0, g_pMissionDatabase)
		else:
			pObject.CallNextHandler(pEvent)
			return
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

	if(g_iPartTwoProgress < PART_TWO_WARPING_TO):
		if g_bTalkedToRomulan:
			if not (g_iPartOneProgress == PART_ONE_VIOLENT_RESOLUTION):
				pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E3M4CommBrex1", None, 0, g_pMissionDatabase)
		
			else:
				pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E3M4CommBrex2", None, 0, g_pMissionDatabase)

		elif not (g_iDropShieldsTimerID == App.NULL_ID):
			pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E3M4CommBrex3", None, 0, g_pMissionDatabase)
		else:
			pObject.CallNextHandler(pEvent)
			return
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

	if g_bKlingonDistressCall:
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M4CommData3", None, 0, g_pMissionDatabase)

	elif not (g_iDropShieldsTimerID == App.NULL_ID):
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M4CommData4", None, 0, g_pMissionDatabase)

	elif g_bTalkedToRomulan:
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M4CommData1", None, 0, g_pMissionDatabase)

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
	global g_pFriendlies
	g_pFriendlies = pMission.GetFriendlyGroup()
	g_pFriendlies.AddName("player")
	g_pFriendlies.AddName("Chairo")
	g_pFriendlies.AddName("T'Awsun")
	g_pFriendlies.AddName("USS Prometheus")
	g_pFriendlies.AddName("USS Berkeley")
	g_pFriendlies.AddName("USS Nightingale")
	g_pFriendlies.AddName("Starbase 12")
	g_pFriendlies.AddName("Krayvis")

	global g_pEnemies
	g_pEnemies = pMission.GetEnemyGroup()
	g_pEnemies.AddName("Galor 1")
	g_pEnemies.AddName("Galor 2")
	g_pEnemies.AddName("Galor 3")
	g_pEnemies.AddName("Keldon 1")

	pNeutrals = pMission.GetNeutralGroup()
	pNeutrals.AddName("Soryak")
	pNeutrals.AddName("Chilvas")

	global g_pPartTwoGroup
	g_pPartTwoGroup = App.ObjectGroupWithInfo()
	g_pPartTwoGroup ["Krayvis"] = { "Priority" : 0.0 }


################################################################################
#	SetupEventHandlers(pMission)
#
#	Set up any event handlers for this mission.
#
#	Args:	pMission - Current mission.
#
#	Return:	None
################################################################################
def SetupEventHandlers(pMission, pPlayer):
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_START_WARP_NOTIFY, pMission, __name__ + ".StartWarpHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ + ".EnterSet")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__ + ".ShipDestroyed")

	pPlayer.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_STATE_CHANGED,	__name__ + ".SubsystemStateChanged")

	# Add Communicate Handlers
	Bridge.BridgeUtils.SetupCommunicateHandlers()

	# Instance handler for Kiska's Hail button
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pMenu = pHelm.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# Warp event
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")


################################################################################
#	WarpHandler(pObject, pEvent)
#
#	Called when the "Warp" button in Kiska's menu is clicked.
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

	# If player is engaged with Romulans.
	if (g_iPartOneProgress == PART_ONE_CHOICE) or (g_iPartOneProgress == PART_ONE_MUST_DISABLE):
		pSaffi = Bridge.BridgeUtils.GetBridgeCharacter("XO")
		pAction = Bridge.BridgeUtils.MakeCharacterLine(pSaffi, "E3M4NoWarp", g_pMissionDatabase)
		pAction.Play()

		return

	pObject.CallNextHandler(pEvent)


###############################################################
# Part one
###############################################################

def DoPartOneAction (pAction, pcDestinationSetName):
	DoPartOne (pcDestinationSetName)
	return 0

def DoPartOne (pcDestinationSetName):
#	print "Starting part one"
	# In this part, we create the romulan warbirds and stuff.
	pModule = __import__(__name__ + "PartOne" + pcDestinationSetName + "_P")

	pModule.LoadPlacements (pcDestinationSetName)

	pSet = App.g_kSetManager.GetSet (pcDestinationSetName)

	pWarbird1 = loadspacehelper.CreateShip("Warbird", pSet, "Soryak", "Warbird3 Start")
	pWarbird2 = loadspacehelper.CreateShip("Warbird", pSet, "Chilvas", "Warbird4 Start")
	
	pWarbird1.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".AttackedRomulans")
	pWarbird2.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".AttackedRomulans")

	# Add Tractor beam hitting handler, while we're at it
	pWarbird1.AddPythonFuncHandlerForInstance(App.ET_TRACTOR_BEAM_STARTED_HITTING, __name__ + ".AttackedRomulans")
	pWarbird2.AddPythonFuncHandlerForInstance(App.ET_TRACTOR_BEAM_STARTED_HITTING, __name__ + ".AttackedRomulans")

	# Cloak the ships to begin with.
	pCloak = pWarbird1.GetCloakingSubsystem()
	if (pCloak):
		pCloak.InstantCloak()		# will try to start cloaking

	pCloak = pWarbird2.GetCloakingSubsystem()
	if (pCloak):
		pCloak.InstantCloak()		# will try to start cloaking

	# Mission progress is now 1
	global g_iPartOneProgress
	g_iPartOneProgress = PART_ONE_WARPING_TO
			

def DoDecloakSequence():
	# Add new goal.
	MissionLib.AddGoal ("E3DecideGoal")

	pPlayer = MissionLib.GetPlayer()
	if (not pPlayer):
		return

	pcSetName = pPlayer.GetContainingSet().GetName()

	# Do the sequence of events.
	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	pData = App.CharacterClass_GetObject(pBridge, "Data")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
	pEngineer = App.CharacterClass_GetObject(pBridge, "Engineer")
	pRBridge = App.g_kSetManager.GetSet ("TBridgeSet")
	pRomulan = App.CharacterClass_GetObject(pRBridge, "Torenn")
	
	# Set the hail delay to zero unless player does not have shields up
	fHailDelay = 0
	
	pSequence = App.TGSequence_Create()
	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create(__name__, "UncloakWarbirds")
	pSequence.AppendAction(pAction, 3.0)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", pcSetName)
	pSequence.AppendAction(pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", pcSetName)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "TargetWatch", pcSetName, "player", "Soryak", 0)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4Decloak", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", pcSetName)
	pSequence.AppendAction(pAction, 3.0)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)

	if (pPlayer.GetAlertLevel() != pPlayer.RED_ALERT):
		pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1))
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "RedAlert"))
		# Set the delay on the "Being hailed" line
		fHailDelay = 3.0
	else:
		pSystem = pPlayer.GetShields ()
		if  ((not pSystem.IsOn ()) or pSystem.GetPowerPercentageWanted () == 0.0):
			pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam")
			pSequence.AppendAction (pAction)
			pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "gt014", None, 0, g_pGeneralDatabase)
			pSequence.AppendAction (pAction)
			pAction = App.TGScriptAction_Create(__name__, "RaiseShields")
			pSequence.AppendAction (pAction)
			# Set the delay on the "Being hailed" line
			fHailDelay = 3.0

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed", 1)
	pSequence.AppendAction(pAction, fHailDelay)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4Hailed", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Torenn")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4PrepareToDie", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4WhyAttackUs", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4SeveralShipsAttacked", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4Misunderstanding", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4HighlyDoubt", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4HowToProve", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4DropYourShields", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pXO, "E3M4Mute", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pHelm, "E3M4MuteAck", g_pMissionDatabase))
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SAY_LINE, "E3M4FirstThing", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam")
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4NotAGoodIdea", "C", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1", 1)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M4AvoidConfrontation", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4ChoiceIsYours", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pXO, "E3M4Resume", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pHelm, "E3M4MuteAck", g_pMissionDatabase))
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "EnablePartOneChoice"))
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4SixtySeconds", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create(__name__, "StartDropShieldsTimer")
	pSequence.AppendAction(pAction)
	pSequence.Play ()

	return 0

def EnablePartOneChoice(pAction):
	# we are now in progress 2.
	global g_iPartOneProgress
	g_iPartOneProgress = PART_ONE_CHOICE

	return 0

def UncloakWarbirds (pAction):
#	print ("Uncloaking warbirds")
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer ()

	pSet = pPlayer.GetContainingSet ()

	pShip = App.ShipClass_GetObject(None, "Soryak")
	pCloak = pShip.GetCloakingSubsystem()
	if (not App.IsNull(pCloak)):
		pCloak.StopCloaking()		# will try to start uncloaking

	pShip = App.ShipClass_GetObject(None, "Chilvas")
	pCloak = pShip.GetCloakingSubsystem()
	if (not App.IsNull(pCloak)):
		pCloak.StopCloaking()		# will try to start uncloaking

	MissionLib.ViewscreenWatchObject(pShip)
	
	return 0

def RaiseShields (pAction):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer == None:
		return

	pSystem = pPlayer.GetShields ()
	pSystem.TurnOn ()
	pSystem.SetPowerPercentageWanted (1.0)

	return 0

def StartDropShieldsTimer (pAction):
#	print ("Drop shields timer started")
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_DROP_SHIELDS_EVENT, __name__ + ".DidNotDropShields", fStartTime + 60.0, 0, 0)

	# Store off the timer ID so if the player does drop shields we can stop the timer.
	global g_iDropShieldsTimerID
	g_iDropShieldsTimerID = pTimer.GetObjID ()

	return 0


################################################################################
#	SubsystemStateChanged(pObject, pEvent)
#
#	Handle user changing subsystem levels event.
#
#	Args:	pObject,
#			pEvent
#
#	Return:	None
################################################################################
def SubsystemStateChanged (pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if (g_iPartOneProgress == PART_ONE_CHOICE):
		pSubsystem = pEvent.GetSource()
		if pSubsystem.IsTypeOf(App.CT_SHIELD_SUBSYSTEM):
			# Check if shields dropped.
			if pEvent.GetBool() == 0:
				# Remove Drop shields timer.
				global g_iDropShieldsTimerID
				if (g_iDropShieldsTimerID != App.NULL_ID):
					App.g_kTimerManager.DeleteTimer(g_iDropShieldsTimerID)
					g_iDropShieldsTimerID = App.NULL_ID

				# Start cutscene right away to prevent delay.
				MissionLib.StartCutscene(None)

				global g_iPartOneProgress
				g_iPartOneProgress = PART_ONE_PEACEFUL_RESOLUTION

				# Remove decide goal
				MissionLib.RemoveGoal("E3DecideGoal")

				# Update the set course menu to make this system not mission critical
				UpdateSetCourseMenu()

				# make part two available.
				global g_iPartTwoProgress
				g_iPartTwoProgress = PART_AVAILABLE
				
				RomulanPeaceDialogue()
			
	pObject.CallNextHandler(pEvent)

################################################################################
#	RomulanPeaceDialogue(pObject, pEvent)
#
#	Play "peaceful resolution" Romulan dialogue.
#
#	Args:	None
#
#	Return:	None
################################################################################
def RomulanPeaceDialogue():
	pSet = MissionLib.GetPlayerSet()
	pcSetName = pSet.GetName()

	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
	pEngineer = App.CharacterClass_GetObject(pBridge, "Engineer")
	pRBridge = App.g_kSetManager.GetSet ("TBridgeSet")
	pRomulan = App.CharacterClass_GetObject(pRBridge, "Torenn")

	pSequence = MissionLib.NewDialogueSequence()
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "StopFelix"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"), 3)
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed", 1))
	pSequence.AppendAction(App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4Hailed", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Torenn"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1))
	pSequence.AppendAction(App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4MayHaveBeenWrong", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1))
	pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4Patrolling", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1))
	pSequence.AppendAction(App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4Yes", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1))
	pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4AnyInfo", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1))
	pSequence.AppendAction(App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4CardassianBuildup", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1", 1))
	pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4SaffiThanks", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1))
	pSequence.AppendAction(App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4UntilWeMeetAgain", None, 0, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "WarbirdsWarpOut"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", pcSetName))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", pcSetName))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "TargetWatch", pcSetName, "player", "Chilvas", 0))
	pSequence.AppendAction(App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4WarbirdsWarpOut", "Captain", 1, g_pMissionDatabase, 3))
	pSequence.AppendAction(App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SAY_LINE, "E3M4TooClose", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", pcSetName))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L007b", "Captain", 1, g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AddProdMoveOnTimer"))
	pSequence.Play()

def AddProdMoveOnTimer (pAction):
#	print ("prod move on timer started")
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_MOVE_ON_EVENT, __name__ + ".MoveOn", fStartTime + 60.0, 0, 0)

	# Store off the timer ID so if the player warps we can get rid of it.
	global g_iProdMoveOnTimerID
	g_iProdMoveOnTimerID = pTimer.GetObjID ()

	return 0

def MoveOn(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	# Clear the timer global since it was just triggered.
	global g_iProdMoveOnTimerID
	g_iProdMoveOnTimerID = App.NULL_ID

	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")

	pSequence = App.TGSequence_Create ()
	
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L007b", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)

	pSequence.Play ()

	return 0

def WarbirdsWarpOut (pAction):
	import Maelstrom.Episode3.E3M4.E3M4WarpOutAI

	global g_bTalkedToRomulan
	g_bTalkedToRomulan = 1

	pShip = App.ShipClass_GetObject(None, "Soryak")
	if (pShip):
		# Repair warp system so it can warp out.
		pSystem = pShip.GetWarpEngineSubsystem()
		if (pSystem):
			fCondition = pSystem.GetConditionPercentage ()
			if (fCondition < pSystem.GetDisabledPercentage () + 0.1):
				pSystem.SetConditionPercentage (pSystem.GetDisabledPercentage () + 0.1)
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))


	pShip = App.ShipClass_GetObject(None, "Chilvas")
	if (pShip):
		# Repair warp system so it can warp out.
		pSystem = pShip.GetWarpEngineSubsystem()
		if (pSystem):
			fCondition = pSystem.GetConditionPercentage ()
			if (fCondition < pSystem.GetDisabledPercentage () + 0.1):
				pSystem.SetConditionPercentage (pSystem.GetDisabledPercentage () + 0.1)
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))

	return 0

def DidNotDropShields (pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	# Timer has been triggered.  Clear the id.
	global g_iDropShieldsTimerID
	g_iDropShieldsTimerID = App.NULL_ID

	if (g_iPartOneProgress == PART_ONE_CHOICE):
		pBridge = App.g_kSetManager.GetSet("bridge")
		pXO = App.CharacterClass_GetObject(pBridge, "XO")
		pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
		pRBridge = App.g_kSetManager.GetSet ("TBridgeSet")
		pRomulan = App.CharacterClass_GetObject(pRBridge, "Torenn")
		pData = App.CharacterClass_GetObject(pBridge, "Data")

		pSequence = App.TGSequence_Create ()

		pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4Hailed", None, 0, g_pMissionDatabase)
		pSequence.AppendAction (pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Torenn")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4TimeUp", None, 0, g_pMissionDatabase)
		pSequence.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4CannotBeTrusted", None, 0, g_pMissionDatabase)
		pSequence.AppendAction (pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction (pAction)
		pAction = App.TGScriptAction_Create(__name__, "WarbirdsAttack")
		pSequence.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M4CannotDestroy", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction (pAction)

		pSequence.Play ()

		pEpisode = App.Game_GetCurrentGame().GetCurrentEpisode()
		pMission = pEpisode.GetCurrentMission()

		pNeutrals = pMission.GetNeutralGroup()
		pNeutrals.RemoveName("Soryak")
		pNeutrals.RemoveName("Chilvas")

		global g_pEnemies
		g_pEnemies = pMission.GetEnemyGroup()
		g_pEnemies.AddName("Soryak")
		g_pEnemies.AddName("Chilvas")

		# Increment mission progress to 4
		global g_iPartOneProgress
		g_iPartOneProgress = PART_ONE_MUST_DISABLE

		# Remove decide goal
		MissionLib.RemoveGoal ("E3DecideGoal")
		
		# Add disable and survive goal
		MissionLib.AddGoal ("E3DisableWeaponsGoal")
		MissionLib.AddGoal ("E3WarbirdsMustSurviveGoal")

	pObject.CallNextHandler(pEvent)
	return 0

def WarbirdsAttack (pAction):
	global g_iMissionProgress
	g_iMissionProgress = FIGHTING_TORENN

	import Maelstrom.Episode3.E3M4.E3M4AttackPlayerAI
	pShip = App.ShipClass_GetObject(None, "Soryak")
	pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4AttackPlayerAI.CreateAI(pShip))
	pSystem = pShip.GetRepairSubsystem()
	pSystem.TurnOff ()	# Disable repair subsystem of this ship so it won't repair its weapons.

	pShip = App.ShipClass_GetObject(None, "Chilvas")
	pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4AttackPlayerAI.CreateAI(pShip))
	pSystem = pShip.GetRepairSubsystem()
	pSystem.TurnOff ()	# Disable repair subsystem of this ship so it won't repair its weapons.

	return 0

def WarbirdsDisabled (pShip):
	# Bail if the ship is dead or dying
	if not pShip or pShip.IsDying() or pShip.IsDead():
		return 0 

	global g_iMissionProgress
	g_iMissionProgress = FIGHTING_TORENN + 1

	# Clear it's AI.
	pShip.ClearAI ()

	global g_iNumWarbirdsDisabled
	g_iNumWarbirdsDisabled = g_iNumWarbirdsDisabled + 1

	if (g_iNumWarbirdsDisabled == 1):
		pBridge = App.g_kSetManager.GetSet("bridge")
		pTact = App.CharacterClass_GetObject(pBridge, "Tactical")

		pSequence = App.TGSequence_Create ()

		pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4OneDisabled", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction (pAction)

		pSequence.Play ()

	elif (g_iNumWarbirdsDisabled == 2):
		# Both warbirds have been disabled

		pPlayer = MissionLib.GetPlayer ()
		if not pPlayer:
			return

		pcSetName = pPlayer.GetContainingSet().GetName()

		pBridge = App.g_kSetManager.GetSet("bridge")
		pXO = App.CharacterClass_GetObject(pBridge, "XO")
		pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
		pEngineer = App.CharacterClass_GetObject(pBridge, "Engineer")
		pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
		pRBridge = App.g_kSetManager.GetSet ("TBridgeSet")
		pRomulan = App.CharacterClass_GetObject(pRBridge, "Torenn")

		pSequence = App.TGSequence_Create ()

		pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
		pSequence.AppendAction (pAction)

		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", pcSetName)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", pcSetName)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "TargetWatch", pcSetName, "player", "Soryak", 0)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4BothDisabled", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4Hailed", None, 0, g_pMissionDatabase)
		pSequence.AppendAction (pAction, 2)
		pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", pcSetName)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam", 1)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Torenn")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4AtYourMercy", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed", 1)
		pSequence.AppendAction(pAction)
		pWalkAndTalk = App.TGSequence_Create()
		pWalkAndTalk.AddAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_MOVE, "C1"))
		pWalkAndTalk.AddAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4Misunderstand2", None, 0, g_pMissionDatabase))
		pSequence.AppendAction(pWalkAndTalk)
		pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4Misjudged", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4AnyInfo", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4UnconfirmedReports", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4UntilWeMeetAgain", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create(__name__, "WarbirdsWarpOut")
		pSequence.AppendAction (pAction)
		pAction1 = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction(pAction1)
		pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_MOVE, "C")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", pcSetName)
		pSequence.AddAction(pAction, pAction1)
		pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", pcSetName)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "TargetWatch", pcSetName, "player", "Chilvas", 0)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4WarbirdsWarpOut", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction (pAction)
		pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", pcSetName)
		pSequence.AppendAction(pAction)
		pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pSequence.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SAY_LINE, "E3M4TooClose", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L007b", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pSequence.AppendAction(pAction)

		pAction = App.TGScriptAction_Create(__name__, "AddProdMoveOnTimer")
		pSequence.AppendAction(pAction)

		pSequence.Play ()

		# Increment mission progress to 4
		global g_iPartOneProgress
		g_iPartOneProgress = PART_ONE_VIOLENT_RESOLUTION

		# Update the set course menu to make this system not mission critical
		UpdateSetCourseMenu ()

		# make part two available.
		global g_iPartTwoProgress
		g_iPartTwoProgress = PART_AVAILABLE

		# Remove disable and survive goal
		MissionLib.RemoveGoal ("E3DisableWeaponsGoal")
		MissionLib.RemoveGoal ("E3WarbirdsMustSurviveGoal")

	return 0

def WarbirdsDestroyed():
#	print "WarbirdsDestroyed() called.."
	# Mission fail.
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")

	pBridge = App.g_kSetManager.GetSet("bridge")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")

	pSequence = MissionLib.NewDialogueSequence()

	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4StarfleetFrequency", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M4Reprimand1", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M4Reprimand2", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction (pAction)

	global g_iPartOneProgress
	g_iPartOneProgress = PART_ONE_FAILED

	MissionLib.GameOver(None, pSequence)


#
# AttackedRomulans() - You attacked the Romulans
#
def AttackedRomulans(pObject, pEvent):
	if (g_iPartOneProgress == PART_ONE_CHOICE):

		# Remove handlers
		pWarbird1 = App.ShipClass_GetObject(None, "Soryak")
		pWarbird2 = App.ShipClass_GetObject(None, "Chilvas")
		pWarbird1.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".AttackedRomulans")
		pWarbird2.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".AttackedRomulans")
		pWarbird1.RemoveHandlerForInstance(App.ET_TRACTOR_BEAM_STARTED_HITTING, __name__ + ".AttackedRomulans")
		pWarbird2.RemoveHandlerForInstance(App.ET_TRACTOR_BEAM_STARTED_HITTING, __name__ + ".AttackedRomulans")

		pBridge = App.g_kSetManager.GetSet("bridge")
		pXO = App.CharacterClass_GetObject(pBridge, "XO")
		pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
		pData = App.CharacterClass_GetObject(pBridge, "Data")
		pRBridge = App.g_kSetManager.GetSet ("TBridgeSet")
		pRomulan = App.CharacterClass_GetObject(pRBridge, "Torenn")
	
		pSequence = App.TGSequence_Create ()

		pAction = App.TGScriptAction_Create(__name__, "WarbirdsAttack")
		pSequence.AppendAction (pAction, 3)	
		pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4Hailed", None, 0, g_pMissionDatabase)
		pSequence.AppendAction (pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Torenn")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E3M4CannotBeTrusted", None, 0, g_pMissionDatabase)
		pSequence.AppendAction (pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction (pAction)
		pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M4CannotDestroy", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction (pAction)
	
		pSequence.Play ()
	
		# Remove decide goal
		MissionLib.RemoveGoal ("E3DecideGoal")

		global g_iPartOneProgress
		# Increment mission progress to 4
		g_iPartOneProgress = PART_ONE_MUST_DISABLE
	
		# make part two available.
		global g_iPartTwoProgress
		g_iPartTwoProgress = PART_AVAILABLE
	
		pEpisode = App.Game_GetCurrentGame().GetCurrentEpisode()
		pMission = pEpisode.GetCurrentMission()
	
		pNeutrals = pMission.GetNeutralGroup()
		pNeutrals.RemoveName("Soryak")
		pNeutrals.RemoveName("Chilvas")
	
		global g_pEnemies
		g_pEnemies = pMission.GetEnemyGroup()
		g_pEnemies.AddName("Soryak")
		g_pEnemies.AddName("Chilvas")

	# We're done.  Let any other handlers for this event handle it.
	pObject.CallNextHandler(pEvent)


################################################################################################
# Part Two
################################################################################################

def DoPartTwo (pcDestinationSetName):
#	print "Starting part two"

	pSet = None

	global g_pcDestination
	if (pcDestinationSetName == "XiEntrades5"):
		g_pcDestination = "XiEntrades3"
		import Systems.XiEntrades.XiEntrades3
		Systems.XiEntrades.XiEntrades3.Initialize()
		pSet = Systems.XiEntrades.XiEntrades3.GetSet()
	elif (pcDestinationSetName == "Itari8"):
		g_pcDestination = "Itari5"
		import Systems.Itari.Itari5
		Systems.Itari.Itari5.Initialize()
		pSet = Systems.Itari.Itari5.GetSet()
	else:
		g_pcDestination = "Voltair1"
		import Systems.Voltair.Voltair1
		Systems.Voltair.Voltair1.Initialize()
		pSet = Systems.Voltair.Voltair1.GetSet()

	# In this part, we create the romulan warbirds and stuff.
	pModule = __import__(__name__ + "PartTwo" + pcDestinationSetName + "_P")
	pModule.LoadPlacements (g_pcDestination)


	pMarauder = loadspacehelper.CreateShip("Marauder", pSet, "Krayvis", "Ferengi Start")
	pGalor1 = loadspacehelper.CreateShip("Galor", pSet, "Galor 1", "Galor1 Start")
	pGalor2 = loadspacehelper.CreateShip("Galor", pSet, "Galor 2", "Galor2 Start")
	pGalor3 = loadspacehelper.CreateShip("Galor", pSet, "Galor 3", "Galor3 Start")

	import DamageMarauder
	DamageMarauder.AddDamage(pMarauder)
	MissionLib.DamageShip("Krayvis", 0.2, 0.3, 1)

	# Update mission progress
	global g_iPartTwoProgress
	g_iPartTwoProgress = PART_TWO_WARPING_TO

def DoDistressSignalSequence ():
	# Create sequence where felix tells you situation
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	pScience = App.CharacterClass_GetObject(pBridge, "Science")

	pSequence = App.TGSequence_Create ()

	pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M4L008", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction, 3.0)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4Where", "Tactical", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)

	if (g_pcDestination == "XiEntrades3"):
		pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M4XiEntrades3", "Captain", 1, g_pMissionDatabase)
		# Add warp goal
		MissionLib.AddGoal ("E3WarpToXiEntrades3Goal")
	elif (g_pcDestination == "Itari5"):
		pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M4Itari5", "Captain", 1, g_pMissionDatabase)
		# Add warp goal
		MissionLib.AddGoal ("E3WarpToItari5Goal")
	else:
		pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M4Voltair1", "Captain", 1, g_pMissionDatabase)
		# Add warp goal
		MissionLib.AddGoal ("E3WarpToVoltair1Goal")

	pSequence.AppendAction (pAction)
	pSequence.Play ()

#	print ("Prod distress call timer started")
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_DISTRESS_CALL_EVENT, __name__ + ".ProdDistressCall", fStartTime + 60.0, 0, 0)

	# Store off the timer ID so if the player warps we can get rid of it.
	global g_iProdDistressCallTimerID
	g_iProdDistressCallTimerID = pTimer.GetObjID ()

#	print ("Ferengi killed timer started")
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_FERENGI_KILLED_EVENT, __name__ + ".DidNotRespondToDistressCall", fStartTime + 120.0, 0, 0)

	# Store off the timer ID so if the player warps we can get rid of it.
	global g_iFerengiKilledTimerID
	g_iFerengiKilledTimerID = pTimer.GetObjID ()

	return 0

def ProdDistressCall (pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if (g_iPartTwoProgress == PART_TWO_DISTRESS_SIGNAL):
		# Create sequence where felix tells you situation
		pBridge = App.g_kSetManager.GetSet("bridge")
		pXO = App.CharacterClass_GetObject(pBridge, "XO")

		pSequence = App.TGSequence_Create ()

		if (App.g_kSystemWrapper.GetRandomNumber (2) == 0):
			pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L038", "Captain", 1, g_pMissionDatabase)
		else:
			pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L037", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction (pAction)

		pSequence.Play ()		

		# Clear time id now that it's triggered
		global g_iProdDistressCallTimerID
		g_iProdDistressCallTimerID = App.NULL_ID

	pObject.CallNextHandler (pEvent)
	return 0

def DidNotRespondToDistressCall (pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if (g_iPartTwoProgress == PART_TWO_DISTRESS_SIGNAL):
		# Mission fail.
		pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
		pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")

		pBridge = App.g_kSetManager.GetSet("bridge")
		pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
		pSaffi = App.CharacterClass_GetObject(pBridge, "XO")
		pKiska = App.CharacterClass_GetObject(pBridge, "Helm")

		pE3M2Database = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 3/E3M2.tgl")
	
		pSequence = MissionLib.NewDialogueSequence()
	
		pAction = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4FerengiDestroyed", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction(pAction, 2)
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction(pAction)
		pAction2 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
		pSequence.AddAction(pAction2, pAction)
		pAction3 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed2", "Captain", 1, pE3M2Database)
		pSequence.AddAction(pAction3, pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed3", "Captain", 0, pE3M2Database)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed4", None, 0, pE3M2Database)
		pSequence.AppendAction(pAction, 1)
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_TURN_BACK)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M4FailedToSaveFerengi", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M4L040", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSequence.AppendAction (pAction)

		MissionLib.GameOver(None, pSequence)

		App.g_kLocalizationManager.Unload(pE3M2Database)

		global g_iPartTwoProgress
		g_iPartTwoProgress = PART_TWO_FAILED

		# Tell all ships to warp out.
		import Maelstrom.Episode3.E3M4.E3M4WarpOutAI
		pShip = App.ShipClass_GetObject(None, "Krayvis")
		if (pShip):
			pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))
		pShip = App.ShipClass_GetObject(None, "Galor 1")
		if (pShip):
			pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))
		pShip = App.ShipClass_GetObject(None, "Galor 2")
		if (pShip):
			pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))
		pShip = App.ShipClass_GetObject(None, "Galor 3")
		if (pShip):
			pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))

	pObject.CallNextHandler (pEvent)
	return 0
	
def DoSaveFerengiSequence ():
	# Remove timers.
	global g_iProdDistressCallTimerID
	if (g_iProdDistressCallTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iProdDistressCallTimerID)
		g_iProdDistressCallTimerID = App.NULL_ID

	global g_iFerengiKilledTimerID
	if (g_iFerengiKilledTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iFerengiKilledTimerID)
		g_iFerengiKilledTimerID = App.NULL_ID

	# Setup Ai of the ferengi and galors.
	import Maelstrom.Episode3.E3M4.E3M4FerengiAI
	pShip = App.ShipClass_GetObject(None, "Krayvis")
	pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4FerengiAI.CreateAI(pShip))

	#setup destroyed handler
	pShip.AddPythonFuncHandlerForInstance(App.ET_OBJECT_EXPLODING, __name__ + ".FerengiKilled")

	# Set player's target to nagus frek.
	pPlayer = MissionLib.GetPlayer ()
	pcSetName = pPlayer.GetContainingSet ().GetName ()

	# Make the Krayvis indentified
	pSensors = pPlayer.GetSensorSubsystem()
	if pSensors:
		pSensors.ForceObjectIdentified(pShip)

	import Maelstrom.Episode3.E3M4.E3M4GalorChaseAI
	pShip = App.ShipClass_GetObject(None, "Galor 1")
	pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4GalorChaseAI.CreateAI(pShip))
	pShip = App.ShipClass_GetObject(None, "Galor 2")
	pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4GalorChaseAI.CreateAI(pShip))

	import Maelstrom.Episode3.E3M4.E3M4GalorChaseAI2
	pShip = App.ShipClass_GetObject(None, "Galor 3")
	pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4GalorChaseAI2.CreateAI(pShip))

	# Setup sequence
	# Create sequence where felix tells you situation
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pEngineer = App.CharacterClass_GetObject(pBridge, "Engineer")

#	print ("Do save ferengi sequence")

	pSequence = App.TGSequence_Create ()

	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction (pAction, 5.0)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "StartCinematicMode", 0)
	pSequence.AppendAction(pAction)	# Start cinematic mode first

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", pcSetName)
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", pcSetName, "Krayvis")
	pSequence.AppendAction(pAction)

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", pcSetName)
	pSequence.AppendAction(pAction, 7.0)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "StopCinematicMode")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSequence.AppendAction(pAction)

	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "SetTarget", "Krayvis")
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4ReadingMarauder", "Captain", 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4FerengiUnderAttack", "Captain", 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4FerengiTooFar", None, 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pSystem = pPlayer.GetShields ()

	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction (pAction)

	if (pSystem.IsOn () == 0):
		# Shields off, remind the player to raise shields
		pAction = App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SAY_LINE, "E3M4ShouldRaiseShields", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction (pAction)

	pSequence.Play ()

	if (g_pcDestination == "XiEntrades3"):
		# Remove warp goal
		MissionLib.RemoveGoal ("E3WarpToXiEntrades3Goal")
	elif (g_pcDestination == "Itari5"):
		# Remove warp goal
		MissionLib.RemoveGoal ("E3WarpToItari5Goal")
	else:
		# Remove warp goal
		MissionLib.RemoveGoal ("E3WarpToVoltair1Goal")

	# Add protect Nagus Frek goal
	MissionLib.AddGoal ("E3ProtectNagusFrekGoal")

	return 0

def AttackingUs():
	if (g_iPlayedAttackingUs == 0):
		global g_iPlayedAttackingUs
		g_iPlayedAttackingUs = 1

	elif (g_iPlayedAttackingUs == 1):
		global g_iPlayedAttackingUs
		g_iPlayedAttackingUs = -1

		if MissionLib.IsInSameSet("Galor 1") and MissionLib.IsInSameSet("Galor 2"):
			# Create sequence where felix tells you both ships are engaging you
			pBridge = App.g_kSetManager.GetSet("bridge")
			pTact = App.CharacterClass_GetObject(pBridge, "Tactical")

			pSequence = App.TGSequence_Create ()

			pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4AttackingUs", "Captain", 1, g_pMissionDatabase)
			pSequence.AppendAction (pAction)

			pSequence.Play()

	return 0

def ShouldIgnoreAttack ():
	# Create sequence where felix tells you situation
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pScience = App.CharacterClass_GetObject(pBridge, "Science")
	pEngineer = App.CharacterClass_GetObject(pBridge, "Engineer")


	pSequence = App.TGSequence_Create ()

	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4BeenAttacked", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pScience, App.CharacterAction.AT_SAY_LINE, "E3M4NoChance", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pSequence.Play ()
	return 0

def FerengiKilled (pObject, pEvent):
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")

	pKrayvis = App.ShipClass_GetObject( App.SetClass_GetNull(), "Krayvis")
	if pKrayvis:
		MissionLib.ViewscreenWatchObject(pKrayvis)

	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pSaffi = App.CharacterClass_GetObject(pBridge, "XO")
	pKiska = App.CharacterClass_GetObject(pBridge, "Helm")

	pE3M2Database = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 3/E3M2.tgl")

	pSequence = MissionLib.NewDialogueSequence()

	pAction = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4FerengiDestroyed", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction(pAction, 2)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction)
	pAction3 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed2", "Captain", 1, pE3M2Database)
	pSequence.AddAction(pAction3, pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed3", "Captain", 0, pE3M2Database)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed4", None, 0, pE3M2Database)
	pSequence.AppendAction(pAction, 1)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_TURN_BACK)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M4FailedToSaveFerengi", None, 0, g_pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M4L040", None, 0, g_pMissionDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction (pAction)

	MissionLib.GameOver(None, pSequence)

	App.g_kLocalizationManager.Unload(pE3M2Database)

	global g_iPartTwoProgress
	g_iPartTwoProgress = PART_TWO_FAILED

	import Maelstrom.Episode3.E3M4.E3M4WarpOutAI
	pShip = App.ShipClass_GetObject(None, "Galor 1")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))
	pShip = App.ShipClass_GetObject(None, "Galor 2")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))
	pShip = App.ShipClass_GetObject(None, "Galor 3")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))


	pObject.CallNextHandler (pEvent)
	return 0


#
# Dialog called when you drive off the Galors attacking the Krayvis
#
def FerengiDialog():
	if (g_iPartTwoProgress == PART_TWO_FAILED):
		return 0

	# Watch the Krayvis on the Viewscreen
	pKrayvis = App.ShipClass_GetObject(App.SetClass_GetNull(), "Krayvis")
	if pKrayvis:
		MissionLib.ViewscreenWatchObject(pKrayvis)
		pKrayvis.ClearAI()

	pPBridgeSet = App.g_kSetManager.GetSet("PBridgeSet")
	pPraag = App.CharacterClass_GetObject (pPBridgeSet, "Praag")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")

	pSequence = MissionLib.NewDialogueSequence()

	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction (pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4L009", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4FerengiHail", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "PBridgeSet", "Praag")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4L010", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4HelloDaimon", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4YouAgain", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L011", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4L012", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L013", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L015", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4L016", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4Praag", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4L017", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L018", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4L021", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4L022", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4L023", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L033", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4RomulansNo", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pPraag, App.CharacterAction.AT_SAY_LINE, "E3M4L035", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction (pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction (pAction)

	pAction = App.TGScriptAction_Create(__name__, "AddProdMoveOnTimer")
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L007b", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)

	MissionLib.QueueActionToPlay(pSequence)

	# Update part two progress
	global g_iPartTwoProgress
	g_iPartTwoProgress = PART_TWO_COMPLETE

	global g_bTalkedToFerengi
	g_bTalkedToFerengi = 1

	# Update the set course menu to make this system not mission critical
	UpdateSetCourseMenu ()

	global g_iPartThreeProgress
	g_iPartThreeProgress = PART_AVAILABLE

	# Remove protect Nagus Frek goal
	MissionLib.RemoveGoal ("E3ProtectNagusFrekGoal")

	return 0



################################################################################################
# Part three
################################################################################################

def DoPartThree (pcDestinationSetName):
#	print "Starting part three"
	# In this part, we create the romulan warbirds and stuff.
	pModule = __import__(__name__ + "PartThree" + pcDestinationSetName + "_P")
	pModule.LoadPlacements (pcDestinationSetName)

	pSet = App.g_kSetManager.GetSet (pcDestinationSetName)

	import DamageGalor1
	import DamageGalor2
	import DamageGalor3
	pWarbird1 = loadspacehelper.CreateShip("Warbird", pSet, "Chairo", "Chairo")
	pWarbird2 = loadspacehelper.CreateShip("Warbird", pSet, "T'Awsun", "T'Awsun")
	pGalor1 = loadspacehelper.CreateShip("Galor", pSet, "Galor 1", "Galor 1")
	DamageGalor1.AddDamage(pGalor1)
	MissionLib.DamageShip("Galor 1", 0.05, 0.25, 0, 0, 0, 1)
	pGalor2 = loadspacehelper.CreateShip("Galor", pSet, "Galor 2", "Galor 2")
	DamageGalor2.AddDamage(pGalor2)
	MissionLib.DamageShip("Galor 2", 0.05, 0.25, 0, 0, 0, 1)
	pGalor3 = loadspacehelper.CreateShip("Galor", pSet, "Galor 3", "Galor 3")
	DamageGalor3.AddDamage(pGalor3)
	MissionLib.DamageShip("Galor 3", 0.05, 0.25, 0, 0, 0, 1)
	pKeldon1 = loadspacehelper.CreateShip("Keldon", pSet, "Keldon 1", "Keldon 1")

	import DamageTerrik
	DamageTerrik.AddDamage(pWarbird1)
	MissionLib.DamageShip("Chairo", 0.05, 0.25, 0, 0, 0, 1)
	import DamageWarbird
	DamageWarbird.AddDamage(pWarbird2)
	MissionLib.DamageShip("T'Awsun", 0.35, 0.55, 0, 0, 0, 1)

	# Mission progress is now 1
	global g_iPartThreeProgress
	g_iPartThreeProgress = PART_THREE_WARPING_TO
			

def DoBattleSequence ():
	#Get the ships
	pWarbird1 = App.ShipClass_GetObject( App.SetClass_GetNull(), "Chairo")
	pWarbird2 = App.ShipClass_GetObject( App.SetClass_GetNull(), "T'Awsun")
	pGalor1 = App.ShipClass_GetObject( App.SetClass_GetNull(), "Galor 1")
	pGalor2 = App.ShipClass_GetObject( App.SetClass_GetNull(), "Galor 2")
	pGalor3 = App.ShipClass_GetObject( App.SetClass_GetNull(), "Galor 3")
	pKeldon1 = App.ShipClass_GetObject( App.SetClass_GetNull(), "Keldon 1")

	#Assign the ships AI
	import Maelstrom.Episode3.E3M4.E3M4TerrikAI
	import Maelstrom.Episode3.E3M4.E3M4DeadWarbirdAI
	import Maelstrom.Episode3.E3M4.E3M4BasicGalorAI

	pWarbird1.SetAI(Maelstrom.Episode3.E3M4.E3M4TerrikAI.CreateAI(pWarbird1))
	pWarbird2.SetAI(Maelstrom.Episode3.E3M4.E3M4DeadWarbirdAI.CreateAI(pWarbird2))
	pGalor1.SetAI(Maelstrom.Episode3.E3M4.E3M4BasicGalorAI.CreateAI(pGalor1))
	pGalor2.SetAI(Maelstrom.Episode3.E3M4.E3M4BasicGalorAI.CreateAI(pGalor2))
	pGalor3.SetAI(Maelstrom.Episode3.E3M4.E3M4BasicGalorAI.CreateAI(pGalor3))
	pKeldon1.SetAI(Maelstrom.Episode3.E3M4.E3M4BasicGalorAI.CreateAI(pKeldon1))

	# Add destroyed handler for Terrik
	pWarbird1.AddPythonFuncHandlerForInstance(App.ET_OBJECT_DESTROYED, __name__ + ".TerrikKilled")

	pPlayer = MissionLib.GetPlayer ()
	pcSetName = pPlayer.GetContainingSet ().GetName ()

	# Create sequence where felix tells you situation
	pBridge = App.g_kSetManager.GetSet("bridge")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pEngineer = App.CharacterClass_GetObject(pBridge, "Engineer")
	pData = App.CharacterClass_GetObject(pBridge, "Data")

	pTBridgeSet = App.g_kSetManager.GetSet("TBridgeSet")
	pTerrik = App.CharacterClass_GetObject (pTBridgeSet, "Terrik")

	pSequence = App.TGSequence_Create ()

	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction (pAction, 6.0)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "StartCinematicMode", 0)
	pSequence.AppendAction(pAction)	# Start cinematic mode first

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", pcSetName)
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", pcSetName, "Keldon 1")
	pSequence.AppendAction(pAction)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", pcSetName, "T'Awsun")
	pSequence.AppendAction(pAction, 4.0)

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", pcSetName)
	pSequence.AppendAction(pAction, 4.0)

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "StopCinematicMode")
	pSequence.AppendAction(pAction)

	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "KiskaWatchRMed", "KiskaCamRMed")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "HackSubtitle")
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4L041", "Captain", 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4DistressCall", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Guest Head", "Guest Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pData, App.CharacterAction.AT_SAY_LINE, "E3M4L043", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SAY_LINE, "E3M4L043b", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4L045", None, 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Brex Head", "Brex Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pEngineer, App.CharacterAction.AT_SAY_LINE, "E3M4WhyShouldWe", None, 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Saffi Head", "Saffi Cam1")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4BecauseWeGood", None, 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4FelixAight", None, 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "Keldon 1"))
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4WarbirdHailing", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction, 1)

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Terrik")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E3M4JoinCardassians", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4CutOff", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)

	pSequence.Play ()

	# Add protect Chairo goal
	MissionLib.AddGoal ("E3ProtectTerrikGoal")

	return 0


def HackSubtitle(pAction):
	# Hack fix to make subtitles appear in their proper position.
	pSubtitle = App.TopWindow_GetTopWindow().FindMainWindow(App.MWT_SUBTITLE)
	pSubtitle = App.SubtitleWindow_Cast(pSubtitle)
	if (pSubtitle):
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_CINEMATIC)

	return 0


def TerrikKilled (pObject, pEvent):
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pMiguel = App.CharacterClass_GetObject(pBridge, "Science")
	pSaffi = App.CharacterClass_GetObject(pBridge, "XO")
	pKiska = App.CharacterClass_GetObject(pBridge, "Helm")

	pE3M2Database = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 3/E3M2.tgl")

	pSequence = MissionLib.NewDialogueSequence()

	pAction = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pMiguel, App.CharacterAction.AT_SAY_LINE, "E3M4L046", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction(pAction, 2)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSequence.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AddAction(pAction2, pAction)
	pAction3 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed2", "Captain", 1, pE3M2Database)
	pSequence.AddAction(pAction3, pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "LookForward")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed3", "Captain", 0, pE3M2Database)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E3M2BerkeleyDestroyed4", None, 0, pE3M2Database)
	pSequence.AppendAction(pAction, 1)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_TURN_BACK)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKiska, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M4L052", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3M4L040", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction (pAction)

	MissionLib.GameOver(None, pSequence)

	App.g_kLocalizationManager.Unload(pE3M2Database)

	global g_iPartThreeProgress
	g_iPartThreeProgress = PART_THREE_FAILED

	import Maelstrom.Episode3.E3M4.E3M4WarpOutAI
	pShip = App.ShipClass_GetObject(None, "Galor 1")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))
	pShip = App.ShipClass_GetObject(None, "Galor 2")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))
	pShip = App.ShipClass_GetObject(None, "Galor 3")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))
	pShip = App.ShipClass_GetObject(None, "Keldon 1")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))

	import Maelstrom.Episode3.E3M4.E3M4SelfDestructAI
	pShip = App.ShipClass_GetObject(None, "T'Awsun")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4SelfDestructAI.CreateAI(pShip))

	pObject.CallNextHandler (pEvent)

	# Remove investigate goal
	MissionLib.RemoveGoal ("E3InvestigateAttacksGoal")
	return 0



#
# Dialog called when all Galors are destroyed (ship destroyed global) and warp out
#
def TerrikApology():
	pTBridgeSet = App.g_kSetManager.GetSet("TBridgeSet")
	pTerrik = App.CharacterClass_GetObject (pTBridgeSet, "Terrik")
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pChairo = App.ShipClass_GetObject( App.SetClass_GetNull(), "Chairo")
	if pChairo:
		MissionLib.ViewscreenWatchObject(pChairo)

	pSequence = MissionLib.NewDialogueSequence()
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4WarbirdHailing", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "TBridgeSet", "Terrik")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E3M4L047", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E3M4L048", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pTerrik, App.CharacterAction.AT_SAY_LINE, "E3M4L049", None, 0, g_pMissionDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create(__name__, "TerrikWarpOut")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pSequence.AppendAction (pAction)

	pAction = App.TGScriptAction_Create(__name__, "MissionWinDialog")
	pSequence.AppendAction(pAction)

	MissionLib.QueueActionToPlay(pSequence)

	global g_iPartThreeProgress
	g_iPartThreeProgress = PART_THREE_COMPLETE

	# Update the set course menu to make this system not mission critical
	UpdateSetCourseMenu ()

	return 0

def TerrikWarpOut (pAction):
	import Maelstrom.Episode3.E3M4.E3M4WarpOutAI
	pShip = App.ShipClass_GetObject(None, "Chairo")
	if (pShip):
		pShip.SetAI(Maelstrom.Episode3.E3M4.E3M4WarpOutAI.CreateAI(pShip))

	return 0

def MissionWinDialog(pAction):
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	pHelm = App.CharacterClass_GetObject(pBridge, "Helm")
	pTact = App.CharacterClass_GetObject(pBridge, "Tactical")

	pSequence = MissionLib.NewDialogueSequence()

	pAction = App.CharacterAction_Create(pTact, App.CharacterAction.AT_SAY_LINE, "E3M4L050", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction, 5)
	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4KlingonDistressCall", "Captain", 1, g_pMissionDatabase)
	pSequence.AppendAction (pAction, 2.0)

	pAction = App.TGScriptAction_Create(__name__, "MissionWin")
	pSequence.AppendAction (pAction)

	pSequence.Play ()

	# Remove investigate goal
	MissionLib.RemoveGoal ("E3InvestigateAttacksGoal")
	MissionLib.RemoveGoal ("E3ProtectTerrikGoal")

	return 0


################################################################################################
# From here on, we deal with the end of the game
################################################################################################

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
	if (g_iPartOneProgress == PART_ONE_PEACEFUL_RESOLUTION):
		# A particularly good win.  Set the flag in the episode.
		Maelstrom.Episode3.Episode3.Mission4Complete(1)
	else:
		# A regular win.  Set the flag accordingly.
		Maelstrom.Episode3.Episode3.Mission4Complete(0)

	global g_bKlingonDistressCall
	g_bKlingonDistressCall = TRUE

	return 0

#
# Called when the player fails the mission for various reasons
#
def MissionFail():
#	print ("Player fails")

	global g_bMissionFailed
	g_bMissionFailed = 1

def StartWarpHandler (pObject, pEvent):
	if g_bMissionTerminated:
		return

	# Handle progression of mission.

	# If mission failed already, don't do anything.
	if (g_bMissionFailed):
		return 0
	
	# Get the ship doing the warping.
	pShip = App.ShipClass_Cast (pEvent.GetDestination ())
	if (not pShip):
		return 0

	# Check if it's the player.  If not, don't do anything.
	if (pShip.GetName () != "player"):
		return 0
		
	# Player is warping.  Remove the prod move on timer if it exists.
	global g_iProdMoveOnTimerID
	if (g_iProdMoveOnTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iProdMoveOnTimerID)
		g_iProdMoveOnTimerID = App.NULL_ID


	# Okay, we've got the player's ship.  Now check where he's going.  If it's one of the mission
	# critical sets, then we do something.
	pcDestinationSetName = pEvent.GetDestinationSetName ()

	if (g_iPartOneProgress == PART_AVAILABLE):
		# Nothing has happened yet.  This means we're checking for the romulan encounter.
		if (pcDestinationSetName == "Systems.XiEntrades.XiEntrades5"):
			global g_bXiEntrades
			g_bXiEntrades = 1
			MissionLib.RemoveGoal ("E3WarpToXiEntradesGoal")
			DoPartOne ("XiEntrades5")
		elif (pcDestinationSetName == "Systems.Itari.Itari8"):
			global g_bItari
			g_bItari = 1
			MissionLib.RemoveGoal ("E3WarpToItariGoal")
			DoPartOne ("Itari8")
		elif (pcDestinationSetName == "Systems.Voltair.Voltair2"):
			global g_bVoltair
			g_bVoltair = 1
			MissionLib.RemoveGoal ("E3WarpToVoltairGoal")
			DoPartOne ("Voltair2")
		else:
			# Nowhere that we care about.
			return 0
	elif (g_iPartTwoProgress == PART_AVAILABLE):
		# Nothing has happened yet.  This means we're checking for the ferengi encounter.
		if (pcDestinationSetName == "Systems.XiEntrades.XiEntrades5"):
			global g_bXiEntrades
			if (g_bXiEntrades == 0):
				g_bXiEntrades = 1
				MissionLib.RemoveGoal ("E3WarpToXiEntradesGoal")
				DoPartTwo ("XiEntrades5")
			else:
				return 0
		elif (pcDestinationSetName == "Systems.Itari.Itari8"):
			global g_bItari
			if (g_bItari == 0):
				g_bItari = 1
				MissionLib.RemoveGoal ("E3WarpToItariGoal")
				DoPartTwo ("Itari8")
			else:
				return 0
		elif (pcDestinationSetName == "Systems.Voltair.Voltair2"):
			if (g_bVoltair == 0):
				global g_bVoltair
				g_bVoltair = 1
				MissionLib.RemoveGoal ("E3WarpToVoltairGoal")
				DoPartTwo ("Voltair2")
			else:
				return 0
		else:
			# Nowhere that we care about.
			return 0
	elif (g_iPartThreeProgress == PART_AVAILABLE):
		# Nothing has happened yet.  This means we're checking for the ferengi encounter.
		if (pcDestinationSetName == "Systems.XiEntrades.XiEntrades5"):
			global g_bXiEntrades
			if (g_bXiEntrades == 0):
				g_bXiEntrades = 1
				MissionLib.RemoveGoal ("E3WarpToXiEntradesGoal")
				DoPartThree ("XiEntrades5")
			else:
				return 0
		elif (pcDestinationSetName == "Systems.Itari.Itari8"):
			global g_bItari
			if (g_bItari == 0):
				g_bItari = 1
				MissionLib.RemoveGoal ("E3WarpToItariGoal")
				DoPartThree ("Itari8")
			else:
				return 0
		elif (pcDestinationSetName == "Systems.Voltair.Voltair2"):
			if (g_bVoltair == 0):
				global g_bVoltair
				g_bVoltair = 1
				MissionLib.RemoveGoal ("E3WarpToVoltairGoal")
				DoPartThree ("Voltair2")
			else:
				return 0
		else:
			# Nowhere that we care about.
			return 0
	else:
		return 0			

def NotPartOfPatrol ():
	# first check what set we're in. 
	pPlayer = MissionLib.GetPlayer ()
	pcSetName = pPlayer.GetContainingSet ().GetName ()

	if (pcSetName == "Starbase12"):
		# Starbase 12 is always okay.
		return 0

	if (g_iPartTwoProgress == PART_AVAILABLE or g_iPartThreeProgress == PART_AVAILABLE):
		# Create sequence where felix tells you situation
		pBridge = App.g_kSetManager.GetSet("bridge")
		pXO = App.CharacterClass_GetObject(pBridge, "XO")

		pSequence = App.TGSequence_Create ()

		pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_LOOK_AT_ME)
		pSequence.AppendAction (pAction, 6)
		pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3M4L006", "Captain", 1, g_pMissionDatabase)
		pSequence.AppendAction (pAction)

		pSequence.Play ()	
	return 0

def StartPartOne(pAction):
	# You have just warped into the first mission area.
	DoDecloakSequence()

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

	if (g_bMissionFailed):
		return 0

	pShip = App.ShipClass_Cast (pEvent.GetDestination ())

	if (not pShip):
		return 0

	if (pShip.GetName () == "player"):
#		print ("In enter set handler for player")
		pcSetName = pShip.GetContainingSet ().GetName ()
		if (pcSetName != "warp"):
#			print ("Not the warp set")

			if (pcSetName != "Starbase12" and g_iPartOneProgress == PART_AVAILABLE):
#				print ("Mission linking.  Starting part one")
				pSequence = App.TGSequence_Create ()

				if (pcSetName == "XiEntrades5"):
					global g_bXiEntrades
					g_bXiEntrades = 1
					MissionLib.RemoveGoal ("E3WarpToXiEntradesGoal")

					pAction = App.TGScriptAction_Create(__name__, "DoPartOneAction", "XiEntrades5")
					pSequence.AppendAction (pAction)
				elif (pcSetName == "Itari8"):
					global g_bItari
					g_bItari = 1
					MissionLib.RemoveGoal ("E3WarpToItariGoal")

					pAction = App.TGScriptAction_Create(__name__, "DoPartOneAction", "Itari8")
					pSequence.AppendAction (pAction)
				elif (pcSetName == "Voltair2"):
					global g_bVoltair
					g_bVoltair = 1
					MissionLib.RemoveGoal ("E3WarpToVoltairGoal")

					pAction = App.TGScriptAction_Create(__name__, "DoPartOneAction", "Voltair2")
					pSequence.AppendAction (pAction)
	
				pSequence.AppendAction(App.TGScriptAction_Create(__name__, "StartPartOne"))
				pSequence.Play()
				
			elif (g_iPartOneProgress == PART_ONE_WARPING_TO):
#				print ("Part one warping to")

				# You have just warped into the first mission area.
				DoDecloakSequence ()

				# we are now in progress 2.
				global g_iPartOneProgress
				g_iPartOneProgress = PART_ONE_CHOICE
				return 0
			elif (g_iPartTwoProgress == PART_TWO_WARPING_TO):
				# You have just warped into the second mission area.			
				# we are now in progress 2.
				global g_iPartTwoProgress
				g_iPartTwoProgress = PART_TWO_DISTRESS_SIGNAL
				DoDistressSignalSequence ()
				return 0
			elif (g_iPartTwoProgress == PART_TWO_DISTRESS_SIGNAL):
				# You might have warped to the ferengi's set.
				pGame = App.Game_GetCurrentGame()
				pPlayer = pGame.GetPlayer ()
				pSet = pPlayer.GetContainingSet ()
				pcSetName = pSet.GetName ()

				if (pcSetName == g_pcDestination):
					DoSaveFerengiSequence ()

					global g_iPartTwoProgress
					g_iPartTwoProgress = PART_TWO_SAVE_FERENGI
					return 0		 
			elif (g_iPartThreeProgress == PART_THREE_WARPING_TO):
				DoBattleSequence ()

				# we are now in progress 2.
				global g_iPartThreeProgress
				g_iPartThreeProgress = PART_THREE_PROTECT_TERRIK
				return 0								
			else:
				NotPartOfPatrol ()

	return 0			

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
		if pcName == "Soryak":
			pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, 
								"E3M4SoyrakDead", g_pMissionDatabase))
			pSeq.Play()
		elif pcName == "Chilvas":
			pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMiguel, 
								"E3M4ChilvasDead", g_pMissionDatabase))
			pSeq.Play()

	pObject.CallNextHandler(pEvent)

################################################################################
#	UpdateSetCourseMenu()
#
#	Update the critical systems in the Set Course menu.
#	If the player hasn't gone to a system yet, set it to sort as critical.
#	Otherwise it will sort as not-critical.
#
#	Args:	None
#
#	Return:	None
################################################################################
def UpdateSetCourseMenu():
	App.SortedRegionMenu_SetPauseSorting(1)

	# Import Itari System Menu Items
	import Systems.Itari.Itari
	pItariMenu = Systems.Itari.Itari.CreateMenus()
	if (g_bItari == 0):
		pItariMenu.SetMissionName(__name__)
	else:
		pItariMenu.SetMissionName()

	# Import Voltair System Menu Items
	import Systems.Voltair.Voltair
	pVoltairMenu = Systems.Voltair.Voltair.CreateMenus()
	if (g_bVoltair == 0):
		pVoltairMenu.SetMissionName(__name__)
	else:
		pVoltairMenu.SetMissionName()

	# Import XiEntrades System Menu Items
	import Systems.XiEntrades.XiEntrades
	pXiEntradesMenu = Systems.XiEntrades.XiEntrades.CreateMenus()
	if (g_bXiEntrades):
		pXiEntradesMenu.SetMissionName(__name__)
	else:
		pXiEntradesMenu.SetMissionName()

	App.SortedRegionMenu_SetPauseSorting(0)


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

	pPlayer = MissionLib.GetPlayer()
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if pTarget is None:
		pTarget = pPlayer.GetTarget()
	
	if pTarget == None:
		pObject.CallNextHandler(pEvent)
		return

	pcTargetName = pTarget.GetName()
	import Bridge.HelmMenuHandlers

	if (pcTargetName == "Galor 1" or pcTargetName == "Galor 2" or pcTargetName == "Galor 3" or pcTargetName == "Keldon 1"):
		if (g_iPartThreeProgress == PART_THREE_PROTECT_TERRIK):
			BridgeHandlers.DropMenusTurnBack()

			pBridge = App.g_kSetManager.GetSet("bridge")
			pHelm = App.CharacterClass_GetObject(pBridge, "Helm")

			pSeq = Bridge.HelmMenuHandlers.GetHailSequence()
			pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3M4AudioOnly", None, 0, g_pMissionDatabase)
			pSeq.AppendAction(pAction, 1.0)

			r = App.g_kSystemWrapper.GetRandomNumber(2)
			pcLine = "E3M4Leave" + str (r + 1)

			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SubtitledLine", 
														g_pMissionDatabase, pcLine, "Cardassian Captain"))
		
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
			pSeq.Play()

			return 

	pObject.CallNextHandler(pEvent)

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

#	print ("Terminating Episode 3, Mission 4 database.\n")
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	global g_iDropShieldsTimerID
	if (g_iDropShieldsTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iDropShieldsTimerID)
		g_iDropShieldsTimerID = App.NULL_ID

	global g_iProdDistressCallTimerID
	if (g_iProdDistressCallTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iProdDistressCallTimerID)
		g_iProdDistressCallTimerID = App.NULL_ID

	global g_iFerengiKilledTimerID
	if (g_iFerengiKilledTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iFerengiKilledTimerID)
		g_iFerengiKilledTimerID = App.NULL_ID

	global g_iProdMoveOnTimerID
	if (g_iProdMoveOnTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iProdMoveOnTimerID)
		g_iProdMoveOnTimerID = App.NULL_ID

	App.SortedRegionMenu_ClearSetCourseMenu()

	# Delete python instance handlers
	# Instance handler for Miguel's Scan Area button
	pPlayer = MissionLib.GetPlayer()
	if(pPlayer):
		pPlayer.RemoveHandlerForInstance(App.ET_SUBSYSTEM_STATE_CHANGED, __name__ + ".SubsystemStateChanged")

	# Instance handler for Kiska's Hail button
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	if(pHelm):
		pMenu = pHelm.GetMenu()
		if(pMenu):
			pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

			pWarpButton = Bridge.BridgeUtils.GetWarpButton()
			
			if pWarpButton:
				pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	# Removing Communicate handlers
	Bridge.BridgeUtils.RemoveCommunicateHandlers()

	# Communicate with Data event
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	if pData:
		pMenu = pData.GetMenu()
		if pMenu:
			pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateData")

	MissionLib.ShutdownFriendlyFire()