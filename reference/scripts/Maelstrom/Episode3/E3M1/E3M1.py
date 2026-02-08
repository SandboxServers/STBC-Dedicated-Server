###############################################################################
#	Filename:	E3M1.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 3 Mission 1
#	
#	Created:	05/07/01 -	Alberto Fonseca
#	Modified:	01/11/02 - 	Tony Evans
###############################################################################

import App
import loadspacehelper
import MissionLib
import loadsplash
import LoadBridge
import Maelstrom.Episode3.Episode3
import Actions.ShipScriptActions
import Bridge.BridgeUtils
import Bridge.BridgeMenus
import Bridge.TacticalMenuHandlers
import Bridge.ScienceCharacterHandlers
import Bridge.EngineerCharacterHandlers
import Bridge.Characters.CommonAnimations
import Systems.Savoy.Savoy
import Systems.Starbase12.Starbase
import Systems.Starbase12.Starbase12
import Systems.Savoy.Savoy1
import Systems.Savoy.Savoy3
import E3M1_Starbase12_P
import E3M1_Savoy1_P
import E3M1_Savoy3_P
import ships.FedStarbase
import ships.Geronimo
import ships.Galaxy
import ships.Nebula
import ships.Ambassador
import ships.Sovereign
import ships.SpaceFacility
import ships.Amagon
import ships.BirdOfPrey
import ships.RanKuf
import AI.Player.Stay
import E3M1NebulaAI
import GeronimoArrivesAI
import GeronimoAttackAI
import GeronimoAttack2AI
import WarpOutAI
import RanKufAI
import RanKufStrongAI
import BOPAI
import WarpOutAI
import ShipStayAI

#kDebugObj = App.CPyDebug()
#kDebugObj.Print("Loading E3M1.\n")

#
# Global variables
#
g_pKiska				= None
g_pFelix				= None
g_pSaffi				= None
g_pMiguel				= None
g_pBrex					= None
						
g_pSaffiMenu			= None
g_pFelixMenu			= None
g_pKiskaMenu			= None
g_pMiguelMenu			= None
g_pBrexMenu				= None

TRUE					= 1
FALSE					= 0
g_pMissionDatabase		= None
g_pGeneralDatabase		= None
g_iProdTimer			= App.NULL_ID
g_iTargetingTimerID		= App.NULL_ID
g_sOldTargetName		= None	# Keeps track of the name of whatever is targeted
g_pOldTargetLocation	= 0		# Keeps track of where the targets subsystem should be
g_pOldTargetSubsystem	= None	# Pointer to the old target ship
g_iFixCounter			= 0		# Keeps track of how many times the targeting has been adjusted
g_bBrexTalking			= 0		# Don't test the tactical system until Brex stops talking
g_bPlayerUndocked		= 0		# If player undocked cutscene played.
g_pProxCheck			= None	# Proximity check for undock cutscene.
g_iMissionProgress		= 0		# Mission progress.
g_iInitialTorpCount		= [0, 0]# Initial number of torps before simulation.
g_bIssuedChallenge		= 0		# Has MacCray issued his challenge.
g_bMacCrayLost			= 0		# Flag for wether MacCray was defeated by player.
g_bBriefingPlayed		= 0		# Flag for wether mission briefing was played.
g_bTargetingFixed		= 0
g_pVisibleDamageState	= [0, 0, 0] # Saved visible damage user prefs.
g_bMissionTerminated	= 0
g_bRoughWarpUnloaded	= 0
g_bSimulationMode		= 0
g_iRoughWarpTime		= 0
g_iSavedWarpDuration	= 0		# Saved duration of warp sequence, so we can restore it.
g_bTauntPlaying			= 0
g_bMissionOver			= 0

# These variables are to allow Felix to carry out orders you 
# gave him before the simulation started
g_iLastFelixCommand = -1

g_iPhotons 				= 0
g_iQuantums 			= 0

g_bDeclinedOnce			= FALSE
g_iMacCrayTimer			= 0

# Define prods
PROD_NONE				= 0
PROD_UNDOCK				= 1
PROD_GO_TO_SAVOY		= 2
PROD_GO_TO_SAVOY1		= 3
PROD_SCAN				= 4
PROD_CALIBRATE			= 5

# Define mission progress
UNDOCK					= 1
GO_TO_SAVOY				= 2
AT_SAVOY_3				= 3
GO_TO_SAVOY1			= 5
SCAN_ASTEROID			= 6
SCANNING_ASTEROID		= 7
FIX_TARGETING			= 8
MACCRAY_CHALLENGE		= 9
ACCEPT_CHALLENGE		= 10
DECLINE_CHALLENGE1		= 11
DECLINE_CHALLENGE2		= 12
FIGHT_KLINGONS			= 13
						
MISSION_FAILED			= 101
MISSION_WIN				= 100

# Constants
ROUGH_WARP_DURATION		= 5.0
ROUGH_WARP_CAM_SHAKE	= 3.0
UNDOCK_RADIUS			= -12.3

#
# Event types
#
ET_ACCEPT_CHALLENGE		= App.Mission_GetNextEventType()
ET_DECLINE_CHALLENGE	= App.Mission_GetNextEventType()
ET_TIMES_UP				= App.Mission_GetNextEventType()
ET_BROKEN_TARGETING		= App.Mission_GetNextEventType()
ET_SIM_DONE_WAIT		= App.Mission_GetNextEventType()
ET_TARGET_SCAN_TIMER	= App.Mission_GetNextEventType()
ET_MACCRAY_TIMER		= App.Mission_GetNextEventType()
ET_TAUNT_COMPLETED		= App.Mission_GetNextEventType()


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
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Sovereign", 1)
	loadspacehelper.PreloadShip("Geronimo", 3)
	loadspacehelper.PreloadShip("Ambassador", 1)
	loadspacehelper.PreloadShip("Galaxy", 1)
	loadspacehelper.PreloadShip("Nebula", 1)
	loadspacehelper.PreloadShip("SpaceFacility", 1)
	loadspacehelper.PreloadShip("Amagon", 1)
	loadspacehelper.PreloadShip("RanKuf", 1)
	loadspacehelper.PreloadShip("BirdOfPrey", 1)

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
#	kDebugObj.Print("E3M1 initializing.\n")

	# Init global variables.
	global g_pMissionDatabase		
	global g_pGeneralDatabase		
	global g_iProdTimer			
	global g_iTargetingTimerID	
	global g_sOldTargetName		
	global g_pOldTargetLocation	
	global g_pOldTargetSubsystem	
	global g_iFixCounter		
	global g_bBrexTalking			
	global g_bPlayerUndocked
	global g_pProxCheck	
	global g_iMissionProgress
	global g_iInitialTorpCount
	global g_bIssuedChallenge
	global g_bMacCrayLost
	global g_pVisibleDamageState
	global g_bMissionTerminated
	global g_bRoughWarpUnloaded
	global g_bSimulationMode
	global g_iRoughWarpTime
	global g_iSavedWarpDuration
	global g_bTauntPlaying

	g_pMissionDatabase		= pMission.SetDatabase("data/TGL/Maelstrom/Episode 3/E3M1.tgl")
	g_pGeneralDatabase		= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_iProdTimer			= App.NULL_ID
	g_iTargetingTimerID		= App.NULL_ID
	g_sOldTargetName		= None	
	g_pOldTargetLocation	= 0		
	g_pOldTargetSubsystem	= None	
	g_iFixCounter			= 0		
	g_bBrexTalking			= FALSE		
	g_bPlayerUndocked		= FALSE	
	g_pProxCheck			= None
	g_iMissionProgress		= UNDOCK
	g_iInitialTorpCount		= [0, 0]
	g_bIssuedChallenge		= FALSE
	g_bMacCrayLost			= FALSE
	g_pVisibleDamageState	= [0, 0, 0]
	g_bMissionTerminated	= FALSE
	g_bRoughWarpUnloaded	= FALSE
	g_bSimulationMode		= FALSE
	g_iSavedWarpDuration	= 0
	g_iRoughWarpTime		= 0
	g_bTauntPlaying			= FALSE

	# Specify (and load if necessary) our bridge
	LoadBridge.Load("SovereignBridge")

	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	# Create various bridges we want to view
	MissionLib.SetupBridgeSet("LBridgeSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LBridgeSet", 0, 0, 5)
	MissionLib.SetupBridgeSet("GBridgeSet", "data/Models/Sets/FedOutpost/fedoutpost.nif", -30, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Graff", "GBridgeSet")
	MissionLib.SetupBridgeSet("DXBridgeSet", "data/Models/Sets/Klingon/BOPbridge.nif", -30, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Draxon", "DXBridgeSet", 0, 0, -5)
	MissionLib.SetupBridgeSet("MCBridgeSet", "data/Models/Sets/EBridge/EBridge.nif", -40, 65, -1.55)
	pMacCray = MissionLib.SetupCharacter("Bridge.Characters.MacCray", "MCBridgeSet", 0, 0, 0)

	# Load custom placements for bridge.
	pBridgeSet = Bridge.BridgeUtils.GetBridge()
	import EBridge_P
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	EBridge_P.LoadPlacements(pBridgeSet.GetName())

	# Create MacCray's viewscreen menu.
	pMenu = Bridge.BridgeMenus.CreateBlankCharacterMenu(g_pMissionDatabase.GetString("E3M1MacCrayMenu"),
														0.3, 0.20, 0.65, 0.05)
	pMacCray.SetMenu(pMenu)
	pMacCray.AddPythonFuncHandlerForInstance(ET_ACCEPT_CHALLENGE, __name__ + ".AcceptChallenge")	
	pMacCray.AddPythonFuncHandlerForInstance(ET_DECLINE_CHALLENGE, __name__ + ".DeclineHandler")	
	pMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("E3M1AcceptButton"),
															ET_ACCEPT_CHALLENGE, 0, pMacCray)) 
	pMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("E3M1DeclineButton"), 
															ET_DECLINE_CHALLENGE, 0, pMacCray))
	
	CreateSpaceSets()
	CreateShips()
	SetAffiliations(pMission) 
	MissionLib.SetupFriendlyFire()
	SetupEventHandlers(pMission)

	# Simulate targeting reticle being uncalibrated.
	BreakTargeting() 

	# Import Starbase System Menu Items
	pStarbaseMenu = Systems.Starbase12.Starbase.CreateMenus()

	InitProxCheck()

	# Add first goal.
	MissionLib.AddGoal("E3LeaveSpacedockGoal")

	# Disable the "Set Course" menu
	pSetCourseMenu = MissionLib.GetCharacterSubmenu("Helm", "Set Course")
	pSetCourseMenu.SetDisabled()

#	kDebugObj.Print("Finished loading " + __name__)

	MissionLib.SaveGame("E3M1-")

	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	MissionLib.SetMaxTorpsForPlayer("Photon", 300)

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
	Systems.Starbase12.Starbase12.Initialize()
	pStarbase12 = Systems.Starbase12.Starbase12.GetSet()
	Systems.Savoy.Savoy1.Initialize()
	pSavoy1 = Systems.Savoy.Savoy1.GetSet()
	Systems.Savoy.Savoy3.Initialize()
	pSavoy3 = Systems.Savoy.Savoy3.GetSet()

	# Load placements.
	E3M1_Starbase12_P.LoadPlacements(pStarbase12.GetName())
	E3M1_Savoy1_P.LoadPlacements(pSavoy1.GetName())
	E3M1_Savoy3_P.LoadPlacements(pSavoy3.GetName())


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
	# Get space sets.
	pStarbase12 = Systems.Starbase12.Starbase12.GetSet()
	pSavoy1 = Systems.Savoy.Savoy1.GetSet()

	# Create ships.
	MissionLib.CreatePlayerShip("Sovereign", pStarbase12, "player", 
											"Player At Starbase Start")
	# Player starts docked
	pButton = Bridge.BridgeUtils.GetDockButton()
	if not (pButton == None):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pButton.SetName(pDatabase.GetString("Undock"))
		pButton.SetEnabled()
		App.g_kLocalizationManager.Unload(pDatabase)

	loadspacehelper.CreateShip("FedStarbase", pStarbase12, "Starbase 12", 
											"Starbase12 Location")
	pGeronimo = loadspacehelper.CreateShip("Geronimo", pStarbase12, "USS Geronimo", 
											"Akira Start")
	pGeronimo.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")
	pGeronimo.SetStatic(TRUE)

	# Make Geronimo invincible.
	pGeronimo.SetInvincible(TRUE)
	MissionLib.MakeEnginesInvincible(pGeronimo)

	pExcalibur = loadspacehelper.CreateShip("Ambassador", pStarbase12, "USS Excalibur", 
											"Ambassador Start")
	pExcalibur.ReplaceTexture("Data/Models/Ships/Ambassador/Excalibur.tga", "ID")
	pExcalibur.SetStatic(TRUE)

	pDauntless = loadspacehelper.CreateShip("Galaxy", pStarbase12, "USS Dauntless", 
											"Icarus Start")
	pDauntless.ReplaceTexture("data/Models/SharedTextures/FedShips/Dauntless.tga", "ID")
	pDauntless.SetStatic(TRUE)

	pNebula = loadspacehelper.CreateShip("Nebula", pStarbase12, "USS Prometheus", 
											"Circling Nebula")
	pNebula.ReplaceTexture("data/Models/SharedTextures/FedShips/Prometheus.tga", "ID")
	# Set Nebula AI.
	pNebula.SetAI(E3M1NebulaAI.CreateAI(pNebula))

	loadspacehelper.CreateShip("SpaceFacility", pSavoy1, "Savoy Station", 
											"Station Location")
	pAmagon = loadspacehelper.CreateShip("Amagon", pSavoy1, "Asteroid Amagon", 
											"Amagon")

	pAmagon.SetHailable(FALSE)


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
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("USS Geronimo")
	pFriendlies.AddName("USS Excalibur")
	pFriendlies.AddName("USS Icarus")
	pFriendlies.AddName("USS Dauntless")
	pFriendlies.AddName("USS Prometheus")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("Savoy Station")
	pFriendlies.AddName("RanKuf")
	pFriendlies.AddName("BolWI'")

#	Inanimate space debris should not be Friendly, Enemy or Neutral
#
#	pNeutrals = pMission.GetNeutralGroup()
#	pNeutrals.AddName("Asteroid Amagon")

###############################################################################
#	StartBrexLog()
#	
#	Play Brex's log, introduction sequence.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def StartBrexLog():
	global g_bBriefingPlayed
	g_bBriefingPlayed = TRUE

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", "Starbase12"))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraBegin", "Starbase12"))	
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", 
												"Starbase12", "player", "CircleStarbase1"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeOut", 0))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeIn", 3))

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EpisodeTitleAction", "Ep3Title"))

	pSeq.AppendAction(App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, 
												"E3M1L001", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, 
												"E3M1L002", None, 0, g_pMissionDatabase), 0.5)
	pSeq.AppendAction(App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, 
												"E3M1L006", None, 0, g_pMissionDatabase), 0.5)
	pSeq.AppendAction(App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, 
												"E3M1L008", None, 0, g_pMissionDatabase), 0.5)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeOut"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
													"CutsceneCameraEnd", "Starbase12"))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", "bridge"))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraBegin", "bridge"))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					"PlacementWatch", "bridge", "BrexWatchRMed", "BrexCamRMed"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeIn"))
	pSeq.AppendAction(App.CharacterAction_Create(g_pBrex, 
								App.CharacterAction.AT_ENABLE_RANDOM_ANIMATIONS))
	pSeq.AppendAction(App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, 
												"E3M1L009", None, 0, g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
													"CutsceneCameraEnd", "bridge"))	
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartTheWalkOnSequence"))
	pSeq.Play()

###############################################################################
#	StartTheWalkOnSequence(pAction)
#
#	Create and play the sequence walking the camera on to the bridge.
#
#	Args:	pAction
#
#	Return:	none
###############################################################################
def StartTheWalkOnSequence(pAction):
	# Position camera at lift.
	pBridge = App.g_kSetManager.GetSet("bridge")
	pCamera = App.ZoomCameraObjectClass_GetObject(pBridge, "maincamera")
	if(pCamera):
		pAnimNode = pCamera.GetAnimNode()
		App.g_kAnimationManager.LoadAnimation("data/animations/eb_camera_capt_walk.nif", 
											"WalkCameraToCaptE")
		pAnimNode.UseAnimationPosition("WalkCameraToCaptE")

		pSequence = MissionLib.NewDialogueSequence()
		pAction = Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L010", g_pMissionDatabase, 0, None)
		pSequence.AddAction(pAction, None, 1.0)
		pAction = Bridge.Characters.CommonAnimations.WalkCameraToCaptOnE(pCamera)
		pSequence.AddAction(pAction, None, 1.0)
		pAction = App.TGScriptAction_Create(__name__, "IntroDialogue")
		pSequence.AppendAction(pAction, 2.0)
		pSequence.Play()

	return 0

################################################################################
#	SetupEventHandlers(pMission)
#
#	Set up any event handlers for this mission.
#
#	Args:	pMission - Current mission.
#
#	Return:	None
################################################################################
def SetupEventHandlers(pMission):
	assert pMission
	if pMission is None:
		return

	Bridge.BridgeUtils.SetupCommunicateHandlers()
	
	pMission.AddPythonFuncHandlerForInstance(ET_TAUNT_COMPLETED, 
										__name__ + ".SetTauntDialogueFlag")

	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, 
										__name__ + ".WarpButtonPressed")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, 
													__name__ + ".EnterSet")

	# Ship exploding event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, 
											pMission, __name__ + ".ShipDestroyed")

	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_DAMAGE, __name__ + ".SavoyHitByPlayer")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".SavoyDamagedByPlayer")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".SavoyDamagedLoose")

	# Add weapon hit handler for Amagon asteroid.
	pAmagon = App.ShipClass_GetObject(App.SetClass_GetNull(), "Asteroid Amagon")
	assert pAmagon
	if(pAmagon):
		pAmagon.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".AmagonHit")

	# Add handler for Miguel's Scan Area button
	g_pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Add handler for Kiska's Hail and Dock buttons
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	g_pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_DOCK, __name__ + ".UnDockHandler")

	pTacticalMenu = App.STTopLevelMenu_Cast(App.TGObject_GetTGObjectPtr(Bridge.TacticalMenuHandlers.g_idTacticalMenu))
	if pTacticalMenu:
		pTacticalMenu.AddPythonFuncHandlerForInstance(App.ET_MANEUVER, __name__ + ".FelixCommandHandler")

		# Stop manual fire until phasers are fixed
		pTacticalMenu.AddPythonFuncHandlerForInstance(App.ET_FIRE, __name__ + ".StopManualFire")
		pTacticalControl = App.TacticalControlWindow_GetTacticalControlWindow()
		pTacticalControl.AddPythonFuncHandlerForInstance(App.ET_INPUT_TOGGLE_PICK_FIRE, __name__ + ".StopManualFire")

		# Disable manual fire button until after phasers are fixed.
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pManualAim = pTacticalMenu.GetButtonW(pDatabase.GetString("Manual Aim"))
		if pManualAim:
			pManualAim.SetDisabled()

#
# StopManualFire()
#
def StopManualFire(TGObject, pEvent):

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	pTacticalMenu = App.STTopLevelMenu_Cast(App.TGObject_GetTGObjectPtr(Bridge.TacticalMenuHandlers.g_idTacticalMenu))
	pButton = pTacticalMenu.GetButtonW(pDatabase.GetString("Manual Aim"))
	pButton.SetChosen(0)

	App.g_kLocalizationManager.Unload(pDatabase)


################################################################################
#	PlayerPhaserHandler()
#
#	Handler called when player fires phasers. If setting up for simulation
#	mode, disable player firing weapons until ready to engage.
#
#	Args:	TGObject	- The TGObject object.
#			pEvent		- The event that was sent.
#
#	Return:	None
################################################################################
def PlayerPhaserHandler(TGObject, pEvent):
	if ((g_iMissionProgress == ACCEPT_CHALLENGE) or (g_iMissionProgress == FIGHT_KLINGONS) or 
		(g_iMissionProgress == MISSION_WIN) or (g_iMissionProgress == MISSION_FAILED)) and not g_bMissionOver:

		if g_bSimulationMode:
			TGObject.CallNextHandler(pEvent)
			return
		else:
			if pEvent.GetBool():
				g_pFelix.SayLine(g_pMissionDatabase, "E3M1NotReady", "Captain", 1)
				return

	TGObject.CallNextHandler(pEvent)

################################################################################
#	PlayerPhotonHandler()
#
#	Handler called when player fires photons. If setting up for simulation
#	mode, disable player firing weapons until ready to engage.
#
#	Args:	TGObject	- The TGObject object.
#			pEvent		- The event that was sent.
#
#	Return:	None
################################################################################
def PlayerPhotonHandler(TGObject, pEvent):
	if ((g_iMissionProgress == ACCEPT_CHALLENGE) or (g_iMissionProgress == FIGHT_KLINGONS) or 
		(g_iMissionProgress == MISSION_WIN) or (g_iMissionProgress == MISSION_FAILED)) and not g_bMissionOver:

		if g_bSimulationMode:
			TGObject.CallNextHandler(pEvent)
			return
		else:
			if pEvent.GetBool():
				g_pFelix.SayLine(g_pMissionDatabase, "E3M1NotReady", "Captain", 1)
				return

	TGObject.CallNextHandler(pEvent)

################################################################################
#	FelixCommandHandler()
#
#	Handler called when player gives Felix attack order. If setting up for 
#	simulation mode, disable player firing weapons until ready to engage.
#
#	Args:	TGObject	- The TGObject object.
#			pEvent		- The event that was sent.
#
#	Return:	None
################################################################################
def FelixCommandHandler(pObject, pEvent):
	if ((g_iMissionProgress == ACCEPT_CHALLENGE) or (g_iMissionProgress == FIGHT_KLINGONS) or 
		(g_iMissionProgress == MISSION_WIN) or (g_iMissionProgress == MISSION_FAILED)) and not g_bMissionOver:

		if g_bSimulationMode:
			pObject.CallNextHandler(pEvent)
			return
		else:
			# Save command to execute later
			import Bridge.TacticalMenuHandlers
			if pEvent.GetInt() >= Bridge.TacticalMenuHandlers.EST_FIRST_ORDER  and  pEvent.GetInt() <= Bridge.TacticalMenuHandlers.EST_LAST_ORDER:
				global g_iLastFelixCommand
				g_iLastFelixCommand = pEvent.GetInt()

			g_pFelix.SayLine(g_pMissionDatabase, "E3M1NotReady", "Captain", 1)
			return

	pObject.CallNextHandler(pEvent)


################################################################################
#	WarpButtonPressed(pObject, pEvent)
#
#	Handle player clicking on warp button. If player is warping to 
#	Savoy 1 for the first time, add rough warp sequence to warp sequence.
#
#	Args:	pObject, 
#			pEvent
#
#	Return:	None
################################################################################
def WarpButtonPressed(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return
	
	# Can't warp if you are in the mock combat sequence
	if (g_iMissionProgress >= MACCRAY_CHALLENGE) and (g_iMissionProgress <= FIGHT_KLINGONS):
		# We can't leave now
		if not (MissionLib.IsInSameSet("USS Geronimo") or MissionLib.IsInSameSet("RanKuf")):
			g_pSaffi.SayLine(g_pGeneralDatabase, "WarpStop1", "Captain", 1)
			return
		elif MissionLib.IsInSameSet("USS Geronimo"):
			if g_bIssuedChallenge:
				g_pSaffi.SayLine(g_pMissionDatabase, "E3M1L113", "Captain", 1)
				return
			else:
				g_pSaffi.SayLine(g_pGeneralDatabase, "WarpStop1", "Captain", 1)
				return
		else:
			g_pSaffi.SayLine(g_pGeneralDatabase, "WarpStop1", "Captain", 1)
			return
	elif g_iMissionProgress == SCANNING_ASTEROID:
		g_pSaffi.SayLine(g_pGeneralDatabase, "WarpStop4", "Captain", 1)
		return
		
	# Make the camera shake during warp on the trip to Savoy
	elif g_iMissionProgress == GO_TO_SAVOY:
		pWarpButton = App.STWarpButton_Cast(pEvent.GetDestination())
		if pWarpButton:
			pcDestination = pWarpButton.GetDestination()
			if pcDestination == "Systems.Savoy.Savoy3":
				global g_iSavedWarpDuration
				g_iSavedWarpDuration = pWarpButton.GetWarpTime()
				pWarpButton.SetWarpTime(ROUGH_WARP_DURATION)
				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
															"CutsceneCameraBegin", "bridge"))	
				pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", 
															"bridge", "View", "Player Cam", 1))
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RoughWarpSequence", ROUGH_WARP_DURATION))
				pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
																	"CutsceneCameraEnd", "bridge"))
				pWarpButton.AddActionDuringWarp(pSeq)
	elif g_iMissionProgress == GO_TO_SAVOY1:
		pWarpButton = App.STWarpButton_Cast(pEvent.GetDestination())
		if pWarpButton:
			pcDestination = pWarpButton.GetDestination()
			if pcDestination == "Systems.Savoy.Savoy1":
				StopProdTimer()
				global g_iSavedWarpDuration
				g_iSavedWarpDuration = pWarpButton.GetWarpTime()
				pWarpButton.SetWarpTime(g_iRoughWarpTime + 4)
				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
															"CutsceneCameraBegin", "bridge"))	
				pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", 
															"bridge", "View", "Player Cam", 1))
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RoughWarpSequence", g_iRoughWarpTime))
				pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
																	"CutsceneCameraEnd", "bridge"))
				pWarpButton.AddActionDuringWarp(pSeq)
	# Prevent player from Warping while Brex is going to Engineering.
	#elif g_iMissionProgress == AT_SAVOY_3:
	#	g_pKiska.SayLine(g_pMissionDatabase, "E3M1NoWarpYet", "Captain", 1)
	#	return

	pObject.CallNextHandler(pEvent)

################################################################################
#	RoughWarpSequence(pAction, iShakeTime)
#
#	Rough ride sequence played during warp. Shakes camera around.
#
#	Args:	pAction
#			iShakeTime, amount of time to shake for.
#
#	Return:	None
################################################################################
def RoughWarpSequence(pAction, iShakeTime):
	pSet = App.g_kSetManager.GetSet("bridge")
	pCamera = App.ZoomCameraObjectClass_GetObject(pSet, "maincamera")
	if pCamera:
		pCamera.SetShake(ROUGH_WARP_CAM_SHAKE, iShakeTime)


	# Play background "rough warp" sound.
	pSound = App.TGSound_Create("sfx/Bridge/br explo4a.mp3", "E3M1RoughWarp", 0)
	pSound.Play()
	
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

	# A ship entered a set.  
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip):
#		print(pShip.GetName() + " entered set.")
		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			if(pShip.GetName() == pPlayer.GetName()):
				pcSetName = pShip.GetContainingSet().GetName()
				if(pcSetName == "Starbase12"):
					if(not g_bBriefingPlayed):
						StartBrexLog()
				elif(pcSetName == "Savoy3"):
					if(g_iMissionProgress == GO_TO_SAVOY):
						StopProdTimer()
						ArrivedSavoy3()
				elif(pcSetName == "Savoy1"):
					if(g_iMissionProgress == GO_TO_SAVOY1):
						StopProdTimer()
						ArrivedSavoy1()
					else:
						ProdHandler(None, None)
				elif(pcSetName == "warp"):
					StopProdTimer()
				elif(pcSetName != "Starbase12"):
					if(g_iMissionProgress < MACCRAY_CHALLENGE):
						pAction = App.TGScriptAction_Create(__name__, "StartProdTimer",
															60.0, PROD_GO_TO_SAVOY1)
						pAction.Play()


################################################################################
#	PlayerCollisionHandler(pObject, pEvent)
#
#	Handle player colliding with another ship while in combat simulation.
#	Here we turn off the invincible flag and restore visible damage/breakage
#	and apply the damage immediately. If the player didn't die from collision,
#	set them invincible again and disable visible damage.
#
#	Args:	pObject, TGObject.
#			pEvent, event we are handling.
#
#	Return:	None
################################################################################
def PlayerCollisionHandler(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.SetInvincible(FALSE)
		RestoreVisibleDamage()
		pPlayer.DamageRefresh(TRUE)
		pObject.CallNextHandler(pEvent)

		if not pPlayer.IsDying():
			pPlayer.SetInvincible(TRUE)
			DisableVisibleDamage()

###############################################################################
#	ShipDestroyed(pObject, pEvent)
#	
#	Called whenever a ship starts exploding.
#	
#	Args:	pObject	- the target of the event
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def ShipDestroyed(pObject, pEvent):
	if g_bMissionTerminated:
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip):
		pcName = pShip.GetName()
#		print pcName + " destroyed."

		if pcName == "USS Excalibur" or pcName == "USS Dauntless" or pcName == "USS Prometheus" or pcName == "USS Geronimo":
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1DestroyedFedShip", g_pMissionDatabase))
			MissionLib.GameOver(None, pSeq)
		elif pcName == "RanKuf" or pcName == "BolWI'":
			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "DontShoot7", g_pGeneralDatabase))
			MissionLib.GameOver(None, pSeq)
		elif(pcName == "Asteroid Amagon") and (g_bTargetingFixed == FALSE):
			global g_bTargetingFixed
			g_bTargetingFixed = -1

			pPlayer = MissionLib.GetPlayer()
			if pPlayer:
				if not pPlayer.IsDying():
					pSeq = MissionLib.NewDialogueSequence()
					pSeq.AppendAction(App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME))
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1AmagonDead", g_pMissionDatabase))
					pSeq.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME))
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1CantContinue", g_pMissionDatabase))
					pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1MissionLoss", g_pMissionDatabase))
#					print "Player destroyed Asteroid Amagon before completing mission objectives. Game over.."
					MissionLib.GameOver(None, pSeq)
		elif pcName == "player":
			pShip.RemoveHandlerForInstance(App.ET_OBJECT_COLLISION, __name__ + 
													".PlayerCollisionHandler")
			if g_pProxCheck:
				# Delete proximity check.
				global g_pProxCheck
				g_pProxCheck.RemoveAndDelete()
				g_pProxCheck = None

################################################################################
#	InitProxCheck()
#
#	Initialize proximity check.
#
#	Args:	None
#
#	Return:	None
################################################################################
def InitProxCheck():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return

	# Get sets
	pStarbaseSet = App.g_kSetManager.GetSet("Starbase12")

	# Get the objects
	pPlacement = App.PlacementObject_GetObject(pStarbaseSet, "InsideDoors")
	assert pPlacement

	# Create proximity check, save it for later removal.
	# Trigger a cutscene when player first exits starbase.
	global g_pProxCheck
	g_pProxCheck = MissionLib.ProximityCheck(pPlacement, UNDOCK_RADIUS, [pPlayer], __name__ +
											".ShowStarbaseLeave", pStarbaseSet)
	g_pProxCheck.SetIgnoreObjectSize(TRUE)

	assert g_pProxCheck

################################################################################
#	MacCrayMenuUp(pAction)
#
#	Bring up MacCrays challenge menu.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def MacCrayMenuUp(pAction):
	pMacCray = GetMacCray()

	# Create timer for MacCray to taunt you
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pMacCrayTimer = MissionLib.CreateTimer(ET_MACCRAY_TIMER, __name__ + ".DeclineHandler", fStartTime + 15, 0, 0)
	# Save the ID of the timer, so we can stop it later.
	global g_iMacCrayTimer
	g_iMacCrayTimer = pMacCrayTimer.GetObjID()

	pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_MENU_UP)
	pAction.Play()

#	pMenu = pMacCray.GetMenu()
#	pMenu.ResizeToContents()
#	pMenu.GetParent().Resize(pMenu.GetWidth(), pMenu.GetHeight(), 0)
#	pMenu.GetParent().GetParent().Resize(pMenu.GetWidth(), pMenu.GetHeight(), 0)
#	pSubPane = App.STSubPane_Cast(pMenu.GetSubPane())
#	pSubPane.ResizeToContents()
#	App.STStylizedWindow_Cast(pMenu.GetConceptualParent()).InteriorChangedSize()
#	pViewScreen = MissionLib.GetViewScreen()
#	pViewScreen.SetMenu(pMacCray.GetMenu())
#	pEvent = App.TGBoolEvent_Create()
#	pEvent.SetDestination(pViewScreen)
#	pEvent.SetEventType(App.ET_CHARACTER_MENU)
#	pEvent.SetBool(1)
#	pAction.AddCompletedEvent(pEvent)
#	Bridge.BridgeUtils.SetMenuModal(TRUE)

	return 0

################################################################################
#	MacCrayMenuDown(pAction)
#
#	Bring down MacCrays challenge menu.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def MacCrayMenuDown(pAction):

	pMacCray = GetMacCray()
	pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_MENU_DOWN)
	pAction.Play()

#	pViewScreen = MissionLib.GetViewScreen()
#	pEvent = App.TGBoolEvent_Create()
#	pEvent.SetDestination(pViewScreen)
#	pEvent.SetEventType(App.ET_CHARACTER_MENU)
#	pEvent.SetBool(0)
#	pAction.AddCompletedEvent(pEvent)

#	Bridge.BridgeUtils.SetMenuModal(FALSE)

	return 0


################################################################################
#	StopProdTimer()
#
#	Disable the prod timer.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def StopProdTimer():
	global g_iProdTimer
	if(g_iProdTimer != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iProdTimer)
		g_iProdTimer = App.NULL_ID

################################################################################
#	StartProdTimer(pAction, fTime, iProdType)
#
#	Create the prod timer.
#
#	Args:	pAction
#			fTime
#
#	Return:	None
################################################################################
def StartProdTimer(pAction, fTime, iProdType):
	# Stop the old prod timer if it exists
	StopProdTimer()

	# Start a new prod timer.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_TIMES_UP, __name__ + ".ProdHandler", 
									fStartTime + fTime, 0, 0)

	# Save the ID of the prod timer, so we can stop it later.
	global g_iProdTimer
	g_iProdTimer = pTimer.GetObjID()

	# Set the new prod type.
	global g_iProdType
	g_iProdType = iProdType

	return 0

################################################################################
#	ProdHandler(pObject, pEvent)
#
#	Handles prod timer events and plays the appropriate prod.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def ProdHandler(pObject, pEvent):
	if g_bMissionTerminated:
		return

	if MissionLib.g_bViewscreenOn:
		return

	if(g_iProdType == PROD_UNDOCK):
		pSeq = MissionLib.NewDialogueSequence()

		# Still in space dock
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L172", 
							g_pMissionDatabase))						
		pSeq.Play()

	elif(g_iProdType == PROD_GO_TO_SAVOY):
		pSeq = MissionLib.NewDialogueSequence()

		# Return to starbase after mission over
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L173", 
							g_pMissionDatabase))						
		pSeq.Play()

	elif(g_iProdType == PROD_GO_TO_SAVOY1):
		pSeq = MissionLib.NewDialogueSequence()

		# Return to starbase after mission over
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L175", 
							g_pMissionDatabase))						
		pSeq.Play()

	elif(g_iProdType == PROD_CALIBRATE):
		pSeq = MissionLib.NewDialogueSequence()

		# Return to starbase after mission over
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L178", 
							g_pMissionDatabase))						
		pSeq.Play()

	elif(g_iProdType == PROD_SCAN):
		pSeq = MissionLib.NewDialogueSequence()

		# Return to starbase after mission over
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L177", 
							g_pMissionDatabase))						
		pSeq.Play()

################################################################################
#	IntroDialogue(pAction)
#
#	Play the introductory dialogue sequence.
#	At the end of this sequence we disable ship movement(speed keys, intercept, etc.)
#	This is done because the player has to undock first.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def IntroDialogue(pAction):
	# Get Liu and Graff.
	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject(pLBridgeSet, "Liu")
	pGBridgeSet = App.g_kSetManager.GetSet("GBridgeSet")
	pGraff = App.CharacterClass_GetObject(pGBridgeSet, "Graff")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L011", g_pMissionDatabase, 0))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "LookForward"))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"CutsceneCameraBegin", "bridge"))	
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					"PlacementWatch", "bridge", "BrexWatchLMed", "BrexCamLMed", 1))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L012", g_pMissionDatabase, 0, "C"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", 
												"bridge", "View", "Player Cam", 1))
	pSeq.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L030", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L031", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L031a", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L031b", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L032", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L033", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L034", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L035", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L035a", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L036", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L037", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pLiu, "E3M1L038", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					"PlacementWatch", "bridge", "SaffiWatchLMed", "SaffiCamLMed", 1))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L040", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					"PlacementWatch", "bridge", "BrexWatchRClose", "BrexCamRClose", 1))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L041", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					"PlacementWatch", "bridge", "KiskaWatchLMed", "KiskaCamLMed", 1))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L042", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					"PlacementWatch", "bridge", "MiguelWatchRMed", "MiguelCamRMed", 1))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1L043", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
					"PlacementWatch", "bridge", "FelixWatchRMed", "FelixCamRMed", 1))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L044", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", 
												"bridge", "View", "Player Cam", 1))
	pSeq.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", None, 0, g_pGeneralDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "GBridgeSet", "Graff"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pGraff, "E3M1L046", g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
														"CutsceneCameraEnd", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L047", g_pMissionDatabase, 0, "Captain"))
	pSeq.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_UP))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProdTimer", 60.0, PROD_UNDOCK))
#	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "DisableShipControls"))
#	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "DisableBridgeCharacters"))
	pSeq.Play()

	return 0

################################################################################
#	DisableShipControls(pAction)
#
#	Disable ship steering and movement controls.
#
#	Args:	pAction, the script action. Adds FilteredKeyboardHandler.
#
#	Return:	0
################################################################################
def DisableShipControls(pAction):
	# Set up handler for keyboard events.
	pTopWindow = App.TopWindow_GetTopWindow()
	if pTopWindow:
		pTopWindow.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD, __name__ + 
													".FilteredKeyboardHandler")	
		pTacticalWindow = pTopWindow.FindMainWindow(App.MWT_TACTICAL)
		if pTacticalWindow:
			pTacticalWindow.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD, 
											__name__ + ".FilteredKeyboardHandler")	

	return 0

################################################################################
#	DisableBridgeCharacters(pAction)
#
#	Disable bridge menus for Felix, Brex, and Miguel.
#
#	Args:	pAction, the script action. Adds FilteredKeyboardHandler.
#
#	Return:	0
################################################################################
def DisableBridgeCharacters(pAction):
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	if pFelix:
		pFelix.SetYesSir("E3M1L044")
		pFelix.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU, __name__ + 
												".EatEvent")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")
	if pBrex:
		#pBrex.SetYesSir("BrexNothingToAdd3", g_pGeneralDatabase)
		pBrex.SetYesSir("E3M1L041")
		pBrex.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU, __name__ + 
												".EatEvent")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	if pMiguel:
		pMiguel.SetYesSir("E3M1L043")
		pMiguel.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU, __name__ + 
												".EatEvent")

	return 0

################################################################################
#	EatEvent(pObject, pEvent)
#
#	Do nothing and don't call the next handler for this event.
#
#	Args:	pObject, pEvent
#
#	Return:	None
################################################################################
def EatEvent(pObject, pEvent):
	pass

################################################################################
#	EnableBridgeCharacters(pAction)
#
#	Enable bridge menus for Felix, Brex, and Miguel.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def EnableBridgeCharacters(pAction):
	pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
	if pFelix:
		pFelix.SetYesSir(None)
		pFelix.RemoveHandlerForInstance(App.ET_CHARACTER_MENU, __name__ + ".EatEvent")
	pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineer")
	if pBrex:
		pBrex.SetYesSir(None)
		pBrex.RemoveHandlerForInstance(App.ET_CHARACTER_MENU, __name__ + ".EatEvent")
	pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
	if pMiguel:
		pMiguel.SetYesSir(None)
		pMiguel.RemoveHandlerForInstance(App.ET_CHARACTER_MENU, __name__ + ".EatEvent")

	return 0

################################################################################
#	EnableShipControls(pAction)
#
#	Enable ship steering and movement controls. Removes FilteredKeyboardHandler.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def EnableShipControls(pAction):
	pTopWindow = App.TopWindow_GetTopWindow()
	if pTopWindow:
		pTopWindow.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".FilteredKeyboardHandler")	
		pTacticalWindow = pTopWindow.FindMainWindow(App.MWT_TACTICAL)
		if pTacticalWindow:
			pTacticalWindow.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".FilteredKeyboardHandler")	

	return 0

################################################################################
#	FilteredKeyboardHandler(pAction)
#
#	Intercepts keyboard events, ignores steering/movement keys.
#	Also intercepts "talk to Felix" event and has him play his communicate line.
#	Passes on any other keys as normal.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def FilteredKeyboardHandler(pObject, pEvent):
	assert pEvent.GetEventType() == App.ET_KEYBOARD
	
	# Get unicode character.
	wChar = pEvent.GetUnicode()

	# If it's any key that will steer or move the ship, set it as handled and don't pass it on.
	if wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, -2.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 1.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 2.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 3.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 4.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 5.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 6.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 7.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 8.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_SET_IMPULSE, App.KeyboardBinding.GET_FLOAT_EVENT, 9.0/9.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_INCREASE_SPEED, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TURN_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TURN_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TURN_DOWN, App.KeyboardBinding.GET_BOOL_EVENT, 1.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TURN_UP, App.KeyboardBinding.GET_BOOL_EVENT, 1.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_ROLL_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_ROLL_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1.0):
		pEvent.SetHandled()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_TACTICAL, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
		pFelix = Bridge.BridgeUtils.GetBridgeCharacter("Tactical")
		pLine = Bridge.BridgeUtils.MakeCharacterLine(pFelix, "E3M1L044", g_pMissionDatabase, 0, None)
		if pLine:
			pLine.Play()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_ENGINEERING, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
		pBrex = Bridge.BridgeUtils.GetBridgeCharacter("Engineering")
		pLine = Bridge.BridgeUtils.MakeCharacterLine(pBrex, "BrexNothingToAdd3", g_pGeneralDatabase, 0, None)
		if pLine:
			pLine.Play()
	elif wChar == App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TALK_TO_SCIENCE, App.KeyboardBinding.GET_EVENT, 0.0):
		pEvent.SetHandled()
		pMiguel = Bridge.BridgeUtils.GetBridgeCharacter("Science")
		pLine = Bridge.BridgeUtils.MakeCharacterLine(pMiguel, "E3M1L043", g_pMissionDatabase, 0, None)
		if pLine:
			pLine.Play()
	else:
		# Pass on any other keyboard event.
		pObject.CallNextHandler(pEvent)	

################################################################################
#	ShowStarbaseLeave(pObject, pEvent)
#
#	Cutscene showing you leave
#	Called when the player gets close to cleared spacedoors placement.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def ShowStarbaseLeave(pObject, pEvent):
	# If already triggered, exit.
	if(g_pProxCheck is None):
		return

	MissionLib.StopShip(None)

	# Stop any previous prods.
	StopProdTimer()

	# Delete proximity check.
	global g_pProxCheck
	g_pProxCheck.RemoveAndDelete()
	g_pProxCheck = None

	pPlayer = MissionLib.GetPlayer()
	if not pPlayer:
		return
	pSet = pPlayer.GetContainingSet()

	global g_bPlayerUndocked
	g_bPlayerUndocked = TRUE

	# Reset Docking button text and re-enable "All Stop" button.
	pButton = Bridge.BridgeUtils.GetDockButton()
	if not (pButton == None):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		pButton.SetName(pDatabase.GetString("Dock"))
		pButton.SetEnabled()
		App.g_kLocalizationManager.Unload(pDatabase)
		Bridge.BridgeUtils.EnableButton(None, "Helm", "All Stop")
		Bridge.BridgeUtils.EnableButton(None, "XO", "Red Alert")

	# Enable the "Set Course" menu.
	pSetCourseMenu	= MissionLib.GetCharacterSubmenu("Helm", "Set Course")
	pSetCourseMenu.SetEnabled()

	if pPlayer.IsDying():
		return

	MissionLib.StartCutscene(None)

	import AI.Compound.UndockFromStarbase
	pStarbase = MissionLib.GetShip("Starbase 12")
	MissionLib.SetPlayerAI("Helm", AI.Compound.UndockFromStarbase.CreateAI(pPlayer, pStarbase))

	# Stop the player's ship..
	kZero = App.TGPoint3()
	kZero.SetXYZ(0.0, 0.0, 0.0)
	pPlayer.SetVelocity(kZero)
	pPlayer.UpdateNodeOnly()

	# A sequence to link together the cinematic watching the
	# player exit the starbase.
	pSeq = MissionLib.NewDialogueSequence()

	# Create an action to change the rendered set.
	pTopWindow = App.TopWindow_GetTopWindow()
	bWasBridge = pTopWindow.IsBridgeVisible()

	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
												"ChangeRenderedSet", pPlayer.GetContainingSet().GetName()))	

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "MoveShipAction", pPlayer, "PlayerAIStart"))
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", 
												pPlayer.GetContainingSet().GetName()))

	# Set the camera to Placement Watch mode
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", 
										"PlacementWatch", pSet.GetName(), 
										pPlayer.GetName(), "SB Camera"),)	
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L052", g_pMissionDatabase, 0, None), 5)

	# Set the ship to coast out once it's cleared the doors.
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "PlayerShipCoast"))

	# An action to exit out of cinematic mode, once this is done.
	pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
										"CutsceneCameraEnd", pPlayer.GetContainingSet().GetName()), 2)
	if bWasBridge:
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions",
													"ChangeRenderedSet", "bridge"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))

#	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "EnableShipControls"))
#	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "EnableBridgeCharacters"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", GO_TO_SAVOY))

	# Add dialogue sequence instructing player to test warp drive.
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "WarpTestDialogue"))
	pSeq.Play()

###############################################################################
#	PlayerShipCoast
#	
#	Turn autopilot on for the player's ship, and have it coast away
#	from the starbase.
#	
#	Args:	pAction	- The scriptaction calling this function.
#	
#	Return:	0
###############################################################################
def PlayerShipCoast(pAction):
	# Set the ship to coast out at impulse 2.
	# Note that, with the AvoidObstacles in this AI, there's a good
	# chance the ship will take off a lot faster than impulse 2 at
	# the start, as it tries to get away from the starbase...
	import AI.Player.FlyForward
	pShip = App.Game_GetCurrentPlayer()
	if pShip:
		MissionLib.SetPlayerAI("Helm", AI.Player.FlyForward.CreateWithAvoid(pShip, 2.0 / 9.0))

	return 0

################################################################################
#	ArrivedSavoy3()
#
#	Called when the player arrives at Savoy 3.
#
#	Args:	None
#
#	Return:	None
################################################################################
def ArrivedSavoy3():
	if(g_iMissionProgress != GO_TO_SAVOY):
		return 0

	# Restore warp duration.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if pWarpButton:
		pWarpButton.SetWarpTime(g_iSavedWarpDuration)

	if not g_bRoughWarpUnloaded:
		App.g_kSoundManager.DeleteSound("E3M1RoughWarp")
		global g_bRoughWarpUnloaded
		g_bRoughWarpUnloaded = TRUE

	# Change goals
	MissionLib.RemoveGoal("E3TestWarpGoal")
	MissionLib.AddGoal("E3WarpToSavoy1Goal")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", GO_TO_SAVOY1))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetWarpDuration", 18.0))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1ArrivedSavoy3", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetWarpDuration", 17.0))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1L059", g_pMissionDatabase, 1, "S"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetWarpDuration", 16.0))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L060", g_pMissionDatabase, 1, "E"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetWarpDuration", 15.0))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L061", g_pMissionDatabase, 0, "C"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetWarpDuration", 13.0))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L062", g_pMissionDatabase, 1, "C"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetWarpDuration", 6.0))
	pSeq.AppendAction(App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_MOVE, "L1"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetWarpDuration", 2.0))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ProdSavoy1"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProdTimer", 60.0, PROD_GO_TO_SAVOY1))
	pSeq.Play()

################################################################################
#	SetWarpDuration(pAction, iNewTime)
#
#	Set's the duration of the warp sequence.
#
#	Args:	pAction
#			iNewTime, new time to set warp seq length to.
#
#	Return:	0
################################################################################
def SetWarpDuration(pAction, iNewTime):
	global g_iRoughWarpTime
	g_iRoughWarpTime = iNewTime
	return 0


################################################################################
#	ProdSavoy1(pAction)
#
#	Tells the player to test the warp drive.
#
#	Args:	pAction
#
#	Return:	0
################################################################################
def ProdSavoy1(pAction):
	pSet = MissionLib.GetPlayerSet()
	if pSet:
		if pSet.GetName() == "Savoy 3":
			Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1Continue", g_pMissionDatabase).Play()

	return 0

################################################################################
#	WarpTestDialogue(pAction)
#
#	Tells the player to test the warp drive.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def WarpTestDialogue(pAction):
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L056", 
															g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProdTimer", 60.0, 
												PROD_GO_TO_SAVOY))
	pSeq.Play()

	# Change goals
	MissionLib.RemoveGoal("E3LeaveSpacedockGoal")
	MissionLib.AddGoal("E3TestWarpGoal")

	# Make menu for Savoy
	pMenu = Systems.Savoy.Savoy.CreateMenus()

	return 0

################################################################################
#	ArrivedSavoy1()
#
#	Called when the player arrives at Savoy 1.
#
#	Args:	None
#
#	Return:	None
################################################################################
def ArrivedSavoy1():
	if(g_iMissionProgress != GO_TO_SAVOY1):
		return 0

	# Restore warp duration.
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	if pWarpButton:
		pWarpButton.SetWarpTime(g_iSavedWarpDuration)

	MissionLib.RemoveGoal("E3WarpToSavoy1Goal")

	pTopWindow = App.TopWindow_GetTopWindow()
	pTactical = pTopWindow.FindMainWindow(App.MWT_TACTICAL)
	if pTactical:
		pTactical.AddPythonFuncHandlerForInstance(App.ET_INPUT_FIRE_PRIMARY, __name__+".PlayerPhaserHandler")
		pTactical.AddPythonFuncHandlerForInstance(App.ET_INPUT_FIRE_SECONDARY, __name__+".PlayerPhotonHandler")

	pTacticalControl = App.TacticalControlWindow_GetTacticalControlWindow()
	if pTacticalControl:
		pTacticalControl.AddPythonFuncHandlerForInstance(App.ET_INPUT_FIRE_PRIMARY, __name__+".PlayerPhaserHandler")
		pTacticalControl.AddPythonFuncHandlerForInstance(App.ET_INPUT_FIRE_SECONDARY, __name__+".PlayerPhotonHandler")

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "HideAsteroid"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L058", 
													g_pMissionDatabase, 0, None), 5.0)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L063", 
													g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L064", 
													g_pMissionDatabase, 0, None))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1L065", 
													g_pMissionDatabase, 0, None))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ArrivedSavoy1ScriptAction"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L066", 
													g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProdTimer", 60.0, 
												PROD_SCAN))

	pSeq.Play()


################################################################################
#	ArrivedSavoy1ScriptAction()
#
#	Show the Asteroid on sensors, target it, set mission progress and add goal.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def ArrivedSavoy1ScriptAction(pAction):
	# Add the asteroid to our sensors
	pAmagon = MissionLib.GetShip("Asteroid Amagon")
	pAmagon.SetTargetable(TRUE)
	pAmagon.SetScannable(TRUE)

	# Get the Tactical station's menu so we can disable the "Target At Will"
	# because having it on will auto-target a subsystem, and be smart enough to 
	# avoid targeting anything if you have Disable selected, which we don't want
	# in this very special case.
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacWindow.GetTacticalMenu()
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTargetingButton = App.STButton_Cast(pMenu.GetButtonW(pDatabase.GetString("Target At Will")))
	pTargetingButton.SetChosen(0)	# Turn "Target At Will" off
	App.g_kLocalizationManager.Unload(pDatabase)

	# Now we can set the target and not have it mess up when we are on "Disable"
	MissionLib.SetTarget(None, "Asteroid Amagon")

	# Set our mission progress
	global g_iMissionProgress
	g_iMissionProgress = SCAN_ASTEROID

	# Set our new goal
	MissionLib.AddGoal("E3ScanAmagonGoal")

	return 0

################################################################################
#	HideAsteroid(pAction)
#
#	Hide Asteroid from sensors until dialogue plays.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def HideAsteroid(pAction):
	pAmagon = MissionLib.GetShip("Asteroid Amagon")
	pAmagon.SetTargetable(FALSE)
	pAmagon.SetScannable(FALSE)

	return 0

################################################################################
#	MacCrayWarpIn(pAction)
#
#	Assigns AI to the Geronimo to make it warp in.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def MacCrayWarpIn(pAction):

	pSet = App.g_kSetManager.GetSet("Starbase12")

	pGeronimo = App.ShipClass_GetObject(pSet, "USS Geronimo")
	if pGeronimo:
		pSet.DeleteObjectFromSet("USS Geronimo")

	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pGeronimo = loadspacehelper.CreateShip("Geronimo", pSavoy1, "USS Geronimo", 
											"Geronimo Start", 1)
	pGeronimo.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")

	return 0

################################################################################
#	MacCrayAttack(pAction)
#
#	Sets MacCray's AI to the attack pattern
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def MacCrayAttack(pAction):
	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pGeronimo = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")

	if(pGeronimo):
		MakeMacCrayAnEnemy()
		pGeronimo.SetAI(GeronimoAttackAI.CreateAI(pGeronimo))

		# Make Geronimo invincible.
		pGeronimo.SetInvincible(TRUE)

	return 0

################################################################################
#	MacCrayLeave(pAction)
#
#	Sets MacCray's AI to warp out.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def MacCrayLeave(pAction):
#	kDebugObj.Print("In MacCrayLeave()")
		
	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pGeronimo = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")

	if(pGeronimo):
		pGeronimo.SetAI(WarpOutAI.CreateAI(pGeronimo))

	pStarbase12 = App.g_kSetManager.GetSet("Starbase12")
	pGeronimo = loadspacehelper.CreateShip("Geronimo", pStarbase12, "USS Geronimo", 
											"Akira Start")
	pGeronimo.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")
	pGeronimo.SetStatic(TRUE)

	return 0


################################################################################
#	AcceptChallenge(pObject, pEvent)
#
#	If the player accepts MacCray's combat challenge.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def AcceptChallenge(pObject, pEvent):
	if(g_iMissionProgress != MACCRAY_CHALLENGE and g_iMissionProgress != DECLINE_CHALLENGE1):
		return 0

	StopTimer()
	MissionLib.AddGoal("E3DefeatMacCrayGoal")

	# Update mission progress
	global g_iMissionProgress
	g_iMissionProgress = ACCEPT_CHALLENGE

	# MacCray's bridge
	pMacCray = GetMacCray()

	pSeq = MissionLib.NewDialogueSequence()

	pAction = App.TGScriptAction_Create(__name__, "MacCrayMenuDown")
	pSeq.AppendAction(pAction)

	if(g_iMissionProgress != DECLINE_CHALLENGE1):
		pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN_BACK)
		pSeq.AddAction(pAction2, pAction, .7)
		pAction3 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_TURN_BACK)
		pSeq.AddAction(pAction3, pAction)
		pAction4 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_TURN_BACK)
		pSeq.AddAction(pAction4, pAction, .5)
		pAction5 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_TURN_BACK)
		pSeq.AddAction(pAction5, pAction)
		pAction6 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_TURN_BACK)
		pSeq.AddAction(pAction6, pAction, .25)

	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L110", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L120", g_pMissionDatabase, 1, "T"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L130", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L140", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L140b", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SaveTorpCount"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RedAlert"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MacCrayAttack"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartSimulation"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L150", g_pMissionDatabase))
	pSeq.Play()

#
# StopTimer() - Stop MacCray's timer
#
def StopTimer():
	global g_iMacCrayTimer
	if (g_iMacCrayTimer != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iMacCrayTimer)
		g_iMacCrayTimer = App.NULL_ID


################################################################################
#	DeclineHandler(pObject, pEvent)
#
#	Handles Decline button being pressed.
#	Calls different function if you've declined once or twice.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def DeclineHandler(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	StopTimer()

	if(g_iMissionProgress == MACCRAY_CHALLENGE):
		FirstDecline()
	else:
		SecondDecline()

################################################################################
#	FirstDecline()
#
#	If the player declines MacCray's first combat challenge.
#
#	Args:	None
#
#	Return:	None
################################################################################
def FirstDecline():
	if(g_iMissionProgress != MACCRAY_CHALLENGE):
		return

	if g_bDeclinedOnce:
		# Update mission progress
		global g_iMissionProgress
		g_iMissionProgress = DECLINE_CHALLENGE1

		sMacCrayTaunt = "E3M1L098"

	else:
		global g_bDeclinedOnce
		g_bDeclinedOnce = TRUE

		sMacCrayTaunt = "E3M1L099"

	# MacCray's bridge
	pMacCray = GetMacCray()

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MacCrayMenuDown"))

	pAction = App.CharacterAction_Create(pMacCray, App.CharacterAction.AT_SAY_LINE, sMacCrayTaunt, None, 0, g_pMissionDatabase)
	pSeq.AppendAction(pAction)

	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN, "Captain")
	pSeq.AddAction(pAction2, pAction, .7)
	pAction3 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_TURN, "Captain")
	pSeq.AddAction(pAction3, pAction)
	pAction4 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_TURN, "Captain")
	pSeq.AddAction(pAction4, pAction, .5)
	pAction5 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_TURN, "Captain")
	pSeq.AddAction(pAction5, pAction)
	pAction6 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_TURN, "Captain")
	pSeq.AddAction(pAction6, pAction, .25)
	pAction7 = App.TGScriptAction_Create(__name__, "MacCrayMenuUp")
	pSeq.AddAction(pAction7, pAction)

	pSeq.Play()

################################################################################
#	SecondDecline()
#
#	If the player declines a second time
#
#	Args:	None
#
#	Return:	None
################################################################################
def SecondDecline():
	if(g_iMissionProgress != DECLINE_CHALLENGE1):
		return

	# Update mission progress
	global g_iMissionProgress
	g_iMissionProgress = DECLINE_CHALLENGE2

	# MacCray's bridge
	pMacCray = GetMacCray()

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MacCrayMenuDown"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L100", 
															g_pMissionDatabase))
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSeq.AppendAction(pAction)
	pAction2 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_TURN_BACK)
	pSeq.AddAction(pAction2, pAction, .7)
	pAction3 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_TURN_BACK)
	pSeq.AddAction(pAction3, pAction)
	pAction4 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_TURN_BACK)
	pSeq.AddAction(pAction4, pAction, .5)
	pAction5 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_TURN_BACK)
	pSeq.AddAction(pAction5, pAction)
	pAction6 = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_TURN_BACK)
	pSeq.AddAction(pAction6, pAction, .25)
	pAction7 = App.TGScriptAction_Create(__name__, "TriggerKlingons")
	pSeq.AddAction(pAction7, pAction)

	pSeq.Play()

################################################################################
#	RecreatePlayer(pAction)
#
#	Brings the player back into the set with a repaired ship.
#
#	Args:	None
#
#	Return:	None
################################################################################
def RecreatePlayer(pAction):
	pGame = App.Game_GetCurrentGame()
	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")

	pPlayer = pGame.GetPlayer()
	if pPlayer:
		pShipID = pPlayer.GetObjID()

		# Repair and reload ship
		Actions.ShipScriptActions.RepairShipFully(None, pShipID)
		Actions.ShipScriptActions.ReloadShip(None, pShipID)

	MakePlayerInvincible(None)
	pPlayer.RemoveHandlerForInstance(App.ET_OBJECT_COLLISION, __name__ + ".PlayerCollisionHandler")
	pPlayer.AddPythonFuncHandlerForInstance(App.ET_OBJECT_COLLISION, __name__ + 
											".PlayerCollisionHandler")

	return 0

################################################################################
#	RecreateGeronimo(pAction = None)
#
#	Reset Geronimo, just recreates the ship.
#
#	Args:	None
#
#	Return:	None
################################################################################
def RecreateGeronimo(pAction = None):
	pGame = App.Game_GetCurrentGame()
	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pGeronimo = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")

	if(pGeronimo):
		pShipID = pGeronimo.GetObjID()

		# Repair and reload ship
		Actions.ShipScriptActions.RepairShipFully(None, pShipID)
		Actions.ShipScriptActions.ReloadShip(None, pShipID)

		# Make ship invincible
		pGeronimo.SetInvincible(TRUE)
		MissionLib.MakeEnginesInvincible(pGeronimo)

	# Make MacCray Friendly again
	pMission = MissionLib.GetMission()
	if(pMission):
		pFriendlies = pMission.GetFriendlyGroup()
		pEnemies = pMission.GetEnemyGroup()
		pEnemies.RemoveName("USS Geronimo")
		pFriendlies.AddName("USS Geronimo")

	return 0

################################################################################
#	EndShipSimulation(sShipName)
#
#	Reset Simulation for pShip.
#
#	Args:	sShipName, name of ship
#
#	Return:	None
################################################################################
def EndShipSimulation(sShipName):
	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pShip = App.ShipClass_GetObject(pSavoy1, sShipName)

	if(pShip is None):
		return

	pcShipName = pShip.GetName()

	pShipID = pShip.GetObjID()

	# Repair and reload ship
	Actions.ShipScriptActions.RepairShipFully(None, pShipID)
	Actions.ShipScriptActions.ReloadShip(None, pShipID)

	# Set AI to stay.
	pShip.SetAI(ShipStayAI.CreateAI(pShip))

	# Make ship invincible
	pShip.SetInvincible(TRUE)
	MissionLib.MakeEnginesInvincible(pShip)

	# Make Friendly again
	pMission = MissionLib.GetMission()
	if(pMission):
		pFriendlies = pMission.GetFriendlyGroup()
		pEnemies = pMission.GetEnemyGroup()
		pEnemies.RemoveName(pcShipName)
		pFriendlies.AddName(pcShipName)

	return 0

################################################################################
#	MakeMacCrayAnEnemy()
#
#	Change MacCrays affiliation to Enemy.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MakeMacCrayAnEnemy():
	pMission = MissionLib.GetMission()
	if(pMission):
		pEnemies = pMission.GetEnemyGroup()
		pFriendlies = pMission.GetFriendlyGroup()
		pFriendlies.RemoveName("USS Geronimo")
		pEnemies.AddName("USS Geronimo")

################################################################################
#	BreakTargeting()
#
#	Create repeating timer to update broken targeting.
#
#	Args:	None
#
#	Return:	None
################################################################################
def BreakTargeting():
	# Create repeating timer.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_BROKEN_TARGETING, __name__ + 
							".UpdateBrokenTargeting", fStartTime + 1, 1, -1)

	# Save it's ID so we can delete it later.
	global g_iTargetingTimerID
	g_iTargetingTimerID = pTimer.GetObjID()

################################################################################
#	UpdateBrokenTargeting(pObject, pEvent)
#
#	Simulate broken phaser targeting by using an offset.
#
#	Args:	None
#
#	Return:	None
################################################################################
def UpdateBrokenTargeting(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	# First, get the subsystem from the ship.  
	# We need to see what the player is targeting first.
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pSubsystem = pPlayer.GetTargetSubsystem()
		pMyTarget = pPlayer.GetTarget()
		if pMyTarget and pSubsystem:
			sTargetName = pMyTarget.GetName()

			# Has the target changed?
			if(g_sOldTargetName != sTargetName):		
				global g_pOldTargetLocation
				global g_sOldTargetName
				global g_pOldTargetSubsystem

				# Get the new old target
				g_sOldTargetName = sTargetName
				g_pOldTargetSubsystem = pSubsystem			
				pProperty = pSubsystem.GetProperty()
				g_pOldTargetLocation = pProperty.GetPositionTG()

			# Get the target's property info so we can move it around
			pProperty = pSubsystem.GetProperty()

			# Pick a random direction for the new position.
			kNewLocation = App.TGPoint3_GetRandomUnitVector()

			# And a random distance from the center, within some range.
			if(g_iFixCounter == 0):
				fMaxDistance = 30
			elif(g_iFixCounter == 1):
				fMaxDistance = 25
			elif(g_iFixCounter == 2):
				fMaxDistance = 15
			elif(g_iFixCounter == 3):
				fMaxDistance = 10
			else:
				fMaxDistance = 3

			fMinDistance = 0
			fDistance = fMinDistance + (fMaxDistance - fMinDistance) * App.g_kSystemWrapper.GetRandomNumber(1000) / 1000.0

			# Scale the direction by the distance to get the position...
			kNewLocation.Scale(fDistance)

			# Finally, retarget the player's phasers to aim using offset.
			pPhasers = pPlayer.GetPhaserSystem()
			if(pPhasers):
				if(pPhasers.IsFiring()):
					pPhasers.StopFiring()
					pPhasers.StartFiring(pPlayer.GetTarget(), kNewLocation)

################################################################################
#	AmagonHit(pObject, pEvent)
#
#	Called when asteroid Amagon is hit.  Allows the targeting to get better.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def AmagonHit(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	# If Brex is talking.
	if((g_iMissionProgress != FIX_TARGETING) or (g_bBrexTalking == 1)):
		return

	# If phaser generated hit event.
	if(pEvent.GetWeaponType() == App.WeaponHitEvent.PHASER):
		# Increment the counter.
		global g_iFixCounter
		g_iFixCounter = g_iFixCounter + 1

		# Tell the player
		BrexSaysTargetingFixed()

	pObject.CallNextHandler(pEvent)

################################################################################
#	SetupShieldGoalCheck(pAction)
#
#	Called when Player is hit by weapons. 
#	Checks to see if shields are up and removes "test shields" goal if so.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def SetupShieldGoalCheck(pAction):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".UpdateShieldsGoal")

	return 0

################################################################################
#	UpdateShieldsGoal(pObject, pEvent)
#
#	Called when Player is hit by weapons. 
#	Checks to see if shields are up and removes "test shields" goal if so.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def UpdateShieldsGoal(pObject, pEvent):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		if pPlayer.GetShields().IsOn():
			MissionLib.RemoveGoal("E3TestShieldsGoal")
			pPlayer.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".UpdateShieldsGoal")
	pObject.CallNextHandler(pEvent)

################################################################################
#	SavoyHitByPlayer(pObject, pEvent)
#
#	Called when Savoy Station is hit, play's dialogue.  
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def SavoyHitByPlayer(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return

	if (g_iMissionProgress == FIX_TARGETING):
		return

	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		if (pShip.GetName() == "Savoy Station"):
			pAction = Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1ShootingStation", g_pMissionDatabase)
			MissionLib.QueueActionToPlay(pAction)

			# Remove instance handler.
			pMission = MissionLib.GetMission()
			assert pMission
			if(pMission):
				pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_DAMAGE, __name__ + ".SavoyHitByPlayer")
			
			return

	pObject.CallNextHandler(pEvent)

################################################################################
#	SavoyDamagedByPlayer(pObject, pEvent)
#
#	Called when Savoy Station is damaged, play's dialogue.  
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def SavoyDamagedByPlayer(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return

	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		if pShip.GetName() == "Savoy Station":
			pAction = Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1DamagedSavoy", g_pMissionDatabase)
			MissionLib.QueueActionToPlay(pAction)

			# Remove instance handler.
			pMission = MissionLib.GetMission()
			assert pMission
			if(pMission):
				pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".SavoyDamagedByPlayer")
			
			return

	pObject.CallNextHandler(pEvent)

################################################################################
#	SavoyDamagedLoose(pObject, pEvent)
#
#	Called when Savoy Station is damaged more, play's dialogue, calls GameOver().
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def SavoyDamagedLoose(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return

	pShip = App.ShipClass_Cast(pEvent.GetSource())
	if pShip:
		if pShip.GetName() == "Savoy Station":
			# Remove instance handler.
			pMission = MissionLib.GetMission()
			assert pMission
			if(pMission):
				pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".SavoyDamagedLoose")

			pAction = Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1MissionLoss", g_pMissionDatabase)
			MissionLib.GameOver(None, pAction)
			return

	pObject.CallNextHandler(pEvent)

################################################################################
#	BrexSaysTargetingFixed()
#
#	Sequence called to tell the player that targeting is being fixed.
#
#	Args:	None
#
#	Return:	None
################################################################################
def BrexSaysTargetingFixed():
	if(g_iMissionProgress != FIX_TARGETING):
		return

	StopProdTimer()	

	pMacCray = GetMacCray()

	# Set flag so dialog doesn't overlap.
	global g_bBrexTalking
	g_bBrexTalking = TRUE		

	if(g_iFixCounter == 1):
		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L081", 
																g_pMissionDatabase, 0, None), 2)
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L082", 
																g_pMissionDatabase, 0, None))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "AllowFixes"))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProdTimer", 
													60.0, PROD_CALIBRATE))
		pSeq.Play()
	elif(g_iFixCounter == 5) and (g_bTargetingFixed == FALSE):
		global g_bTargetingFixed
		g_bTargetingFixed = TRUE

		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L083", 
																g_pMissionDatabase, 0, None), 3.0)
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "FixTargeting") )
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StopFelix"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L084", 
																g_pMissionDatabase, 0, None), 5.0)
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E3TestTacticalGoal"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L086", 
																g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3TestShieldsGoal"))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetupShieldGoalCheck"))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MacCrayWarpIn"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L087", 
																g_pMissionDatabase, 0, None), 3.0)
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L088", 
																g_pMissionDatabase, 0, None), 2.0)
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1OpenChannel", 
																g_pMissionDatabase, 0, None))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L089", 
																g_pMissionDatabase, 0, None))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
													"MCBridgeSet", "MacCray"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L090", 
																g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L091", 
																g_pMissionDatabase, 0, None))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L092", 
																g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L093", 
																g_pMissionDatabase, 0, None))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L094", 
																g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L095", 
																g_pMissionDatabase, 0, None))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L096", 
																g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L097", 
																g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "LookForward"))
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MacCrayMenuUp"))
		pSeq.AppendAction(App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_MOVE, "E"))

		pSeq.Play()

		# Remove handler for Amagon weapon hit.
		pAmagon = App.ShipClass_GetObject(App.SetClass_GetNull(), "Asteroid Amagon")
		if(pAmagon):
			pAmagon.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".AmagonHit")

		# Update mission progress
		global g_iMissionProgress
		g_iMissionProgress = MACCRAY_CHALLENGE
	else:
		pSeq = MissionLib.NewDialogueSequence()

		
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "AllowFixes"), 0.5)
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartProdTimer", 60.0, 
													PROD_CALIBRATE))
		pSeq.Play()


################################################################################
#	AllowFixes(pAction)
#
#	Set flag that tells you that you can test since Brex is silent.
#
#	Args:	None
#
#	Return:	None
################################################################################
def AllowFixes(pAction):
	global g_bBrexTalking
	g_bBrexTalking = FALSE
	return 0

################################################################################
#	FixTargeting(pAction)
#
#	Fix the targeting system. Remove targeting offset.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def FixTargeting(pAction):
	# Delete timer that updates broken targeting.
	global g_iTargetingTimerID
	if(g_iTargetingTimerID != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iTargetingTimerID)
		g_iTargetingTimerID = App.NULL_ID

	# Fix the targeted location to match the targeted subsystem.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pPlayer.UseTargetOffsetTG(0)

	# Remove handlers to StopManualFire
	g_pFelixMenu.RemoveHandlerForInstance(App.ET_FIRE, __name__ + ".StopManualFire")
	pTacticalControl = App.TacticalControlWindow_GetTacticalControlWindow()

	if pTacticalControl:
		pTacticalControl.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_PICK_FIRE, __name__ + ".StopManualFire")

	# Re-enable manual fire button.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pManualAim = g_pFelixMenu.GetButtonW(pDatabase.GetString("Manual Aim"))
	if pManualAim:
		pManualAim.SetEnabled()

	return 0

################################################################################
#	MissionOver(pAction)
#
#	Dialogue called when all objectives are met.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def MissionOver(pAction):
	global g_bMissionOver
	g_bMissionOver = TRUE

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SetupFriendlyFire"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L167", 
															g_pMissionDatabase))

	# If player won the battle.
	if(g_iMissionProgress == MISSION_WIN):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L168", 
																g_pMissionDatabase))
	else:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L169", 
																g_pMissionDatabase))
		
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1ReportingIn", 
																g_pMissionDatabase))

	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MissionWin"))
	pSeq.Play()

	# Change goals
	MissionLib.RemoveGoal("E3DefeatKlingonsGoal")

	# Re-enable spontaneus character lines.
	MissionLib.SetSpeakingVolume(None, App.CSP_SPONTANEOUS, 1.0)

	return 0

################################################################################
#	MissionWin(pAction)
#
#	Called when all the mission goals are complete. Calls Episode handler.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def MissionWin(pAction):
	SetMissionProgress(None, MISSION_WIN)
	Maelstrom.Episode3.Episode3.Mission1Complete()
	return 0

################################################################################
#	MissionFail()
#
#	Called when the player fails the mission.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MissionFail():
	# Call the Episode handler.
	Maelstrom.Episode3.Episode3.Mission1Fail()

################################################################################
#	HailHandler(pObject, pEvent)
#
#	Handles hailing.
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
	if pPlayer is None:
		pObject.CallNextHandler(pEvent)
		return
		
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if not (pTarget):
		pTarget = pPlayer.GetTarget()
	
	if pTarget is None:
		pObject.CallNextHandler(pEvent)
		return
	
	sTarget = pTarget.GetName()

	if (sTarget == "Savoy Station") and (g_bTargetingFixed == FALSE) and g_iFixCounter:
		import Bridge.HelmMenuHandlers
		pSequence = MissionLib.NewDialogueSequence()
		pSequence.AppendAction(Bridge.HelmMenuHandlers.GetHailSequence())
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E3M1HailSavoy2", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pSequence.Play()
	elif (sTarget == "Savoy Station") and (g_bTargetingFixed == FALSE):
		import Bridge.HelmMenuHandlers
		pSequence = MissionLib.NewDialogueSequence()
		pSequence.AppendAction(Bridge.HelmMenuHandlers.GetHailSequence())
		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E3M1HailSavoy", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pAction)
		pSequence.Play()
	elif sTarget == "Starbase 12":
		if not g_bPlayerUndocked:
			pSB12Control = App.g_kSetManager.GetSet("FedOutpostSet_Graff")
			pGraff = App.CharacterClass_GetObject(pSB12Control, "Graff")

			# Voice lines to choose from randomly.
			lsLines = [	"gg012",	# Hello, Captain.
						"gg013" ]	# Hello, Sovereign.

			import Bridge.HelmMenuHandlers
			pSequence = MissionLib.NewDialogueSequence()
			pSequence.AppendAction(Bridge.HelmMenuHandlers.GetHailSequence())
			pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "SB12_ControlRoomSet", "Graff"))
			pSequence.AppendAction(App.CharacterAction_Create(pGraff, App.CharacterAction.AT_SAY_LINE,
									lsLines[App.g_kSystemWrapper.GetRandomNumber(len(lsLines))],
									None, 0, g_pGeneralDatabase))
			pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
			pSequence.Play()
		else:
			pObject.CallNextHandler(pEvent)
			return
	else:
		# Nothing special to handle
		pObject.CallNextHandler(pEvent)
		return

################################################################################
#	UnDockHandler(pObject, pEvent)
#
#	Handles undocking for the first time.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def UnDockHandler(pObject, pEvent):
	if g_bMissionTerminated:
		pObject.CallNextHandler(pEvent)
		return

	if g_iMissionProgress == UNDOCK:
		pPlayer = MissionLib.GetPlayer()
		if pPlayer is None:
			pObject.CallNextHandler(pEvent)
			return

		pStarbase = MissionLib.GetShip("Starbase 12")

		pButton = Bridge.BridgeUtils.GetDockButton()
		if pButton:
			pButton.SetDisabled()
		Bridge.BridgeUtils.DisableButton(None, "Helm", "All Stop")
		Bridge.BridgeUtils.DisableButton(None, "XO", "Red Alert")

		# Move player to starting placement for undock sequence.
		pStarbase12 = Systems.Starbase12.Starbase12.GetSet()
		pWaypoint = App.PlacementObject_GetObject(pStarbase12, "Player At Starbase Start")
		pPlayer.SetTranslate(pWaypoint.GetWorldLocation())
		pPlayer.SetMatrixRotation(pWaypoint.GetWorldRotation())
		kZero = App.TGPoint3()
		kZero.SetXYZ(0.0, 0.0, 0.0)
		pPlayer.SetVelocity(kZero)
		pPlayer.UpdateNodeOnly()

		# Make sure player has power to impulse engines.
		pEngines = pPlayer.GetImpulseEngineSubsystem()
		if pEngines:
			if pEngines.GetPowerPercentageWanted() < 1.0:
				pEngines.TurnOn()
				pEngines.SetPowerPercentageWanted(1.0)

		import AI.Compound.UndockFromStarbase
		MissionLib.SetPlayerAI("Helm", AI.Compound.UndockFromStarbase.CreateAI(pPlayer, pStarbase))
		global g_bPlayerUndocked
		g_bPlayerUndocked = TRUE

		# Remove Instance handler for Kiska's dock button
		g_pKiskaMenu.RemoveHandlerForInstance(App.ET_DOCK, __name__ + ".UnDockHandler")

		pSeq = MissionLib.NewDialogueSequence()
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))
		pSeq.AppendAction(App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge"))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "LookForward"))	
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L054", g_pMissionDatabase, 1, "H"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L055", g_pMissionDatabase, 0, None))
		pSeq.Play()

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
		
	pSet = pPlayer.GetContainingSet()
	pSensors = pPlayer.GetSensorSubsystem()

	iScanType = pEvent.GetInt()

	if (iScanType == App.CharacterClass.EST_SCAN_OBJECT):
		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
			pTarget = pPlayer.GetTarget()
		if pTarget is None:
			pObject.CallNextHandler(pEvent)
			return

		pcTargetName = pTarget.GetName()

		if (pcTargetName == "Asteroid Amagon") and (g_iMissionProgress == SCAN_ASTEROID):
			# Remove prod
			StopProdTimer()

			# Set flag to scanning, so player doesn't warp out.
			SetMissionProgress(None, SCANNING_ASTEROID)

			pScanSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
			if pScanSeq is None:
				return

			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(pScanSeq)
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1L067", g_pMissionDatabase))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L068", g_pMissionDatabase, 1, "S"))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1L069", g_pMissionDatabase))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L070", g_pMissionDatabase, 1, "H"))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "OnScreen", g_pGeneralDatabase, 0, None), 1.0)
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "Engineering", "Engineer"))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L071", g_pMissionDatabase))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L072", g_pMissionDatabase, 0, None))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L073", g_pMissionDatabase, 0, None))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1L074", g_pMissionDatabase, 0 , None))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L075", g_pMissionDatabase, 0, None))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L076", g_pMissionDatabase, 0, None))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L077", g_pMissionDatabase, 0, None))
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1L078", g_pMissionDatabase), 5.0)
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L079", g_pMissionDatabase))
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L080", g_pMissionDatabase), 2.0)
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RedAlert"))
			pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", FIX_TARGETING))

		
			pAction = App.TGScriptAction_Create(__name__, "StartProdTimer", 60.0, PROD_CALIBRATE)
			pSeq.AppendAction(pAction)
			pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E3ScanAmagonGoal"))
			pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3TestTacticalGoal"))
			pSeq.Play()
			return
		elif (pcTargetName == "Savoy Station"):
			pScanSeq = Bridge.ScienceCharacterHandlers.GetScanSequence()
			if pScanSeq is None:
				return

			pSeq = MissionLib.NewDialogueSequence()
			pSeq.AppendAction(pScanSeq)
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1ScanSavoy", g_pMissionDatabase))
			pSeq.AppendAction(App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu"))
			pSeq.Play()
			return

	pObject.CallNextHandler(pEvent)

################################################################################
#	TriggerKlingons(pAction)
#
#	Trigger Klingons coming in after second decline to MacCrays challenge.
#
#	Args:	None
#
#	Return:	None
################################################################################
def TriggerKlingons(pAction):

	pMacCray = GetMacCray()
	pDXBridgeSet = App.g_kSetManager.GetSet("DXBridgeSet")
	pDraxon	= App.CharacterClass_GetObject(pDXBridgeSet, "Draxon")

	# Start the attack BOP cutscene.
	pSequence = MissionLib.NewDialogueSequence()
			
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "ClearAI"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CreateKlingons"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "UncloakShips"), .05)
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "KlingonManeuverAI"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, 
								"E3M1KlingonsDecloaking", g_pMissionDatabase), 5.0)
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "RanKuf"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, 
													"E3M1L129", g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", 
										"ViewscreenOn", "DXBridgeSet", "Draxon"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, 
										"E3M1DraxonDisapointed", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, 
													"E3M1L131", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, 
													"E3M1L132", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, 
													"E3M1L133", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, 
													"E3M1L134", g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, 
													"E3M1L135", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, 
													"E3M1L136", g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", FIGHT_KLINGONS))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, 
													"E3M1L137", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, 
													"E3M1L137a", g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L130",
													g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L140",
													g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L140b",
													g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SaveTorpCount"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "RedAlert"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "StartKlingonAttack"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "StartSimulation"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L150",
													g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L139", 
																	g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L138", 
																	g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, 
											"E3M1MacCrayStayingOut", g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "SetupMacCrayShotAtHandler"))
	pSequence.Play()

	return 0


################################################################################
#	SetupMacCrayShotAtHandler(pAction)
#
#	Add instance handler for Geronimo being fired on.
#	Since the Geronimo is "staying out" of the combat sim we want to keep
#	track of the player shooting at it which will trigger a response from him.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def SetupMacCrayShotAtHandler(pAction):
	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pGeronimo = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")
	assert pGeronimo
	if(pGeronimo):
		pGeronimo.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
																".GeronimoJoinIn")
	return 0

################################################################################
#	SaveTorpCount(pAction = None)
#
#	Save player's current torpedo count, before simulation.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def SaveTorpCount(pAction = None):
	global g_iInitialTorpCount

	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return 0

	pTorpSys = pPlayer.GetTorpedoSystem()
	if pTorpSys:
		global g_iInitialTorpCount
		g_iInitialTorpCount[0] = pTorpSys.GetNumAvailableTorpsToType(0)
		g_iInitialTorpCount[1] = pTorpSys.GetNumAvailableTorpsToType(1)

	return 0

################################################################################
#	RestoreTorpCount(pAction = None)
#
#	Restore player's torpedo count, after simulation.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def RestoreTorpCount(pAction = None):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return 0

	pTorpSys = pPlayer.GetTorpedoSystem()
	if pTorpSys:
		iPhotons = g_iInitialTorpCount[0] - pTorpSys.GetNumAvailableTorpsToType(0)
		iQuantums = g_iInitialTorpCount[1] - pTorpSys.GetNumAvailableTorpsToType(1)

		# Deduct torpedoes to initial count.
		pTorpSys.LoadAmmoType(0, iPhotons)
		pTorpSys.LoadAmmoType(1, iQuantums)

	return 0

################################################################################
#	StartSimulation(pAction = None)
#
#	Turns off visible damage and makes player's ship invincible.
#	Adds instance handler for Player's ship collisions.
#
#	Args:	pAction, the script action.
#
#	Return:	0
################################################################################
def StartSimulation(pAction = None):
#	print "Starting simulation.."

	# Re-enable spontaneus character lines.
	MissionLib.SetSpeakingVolume(None, App.CSP_SPONTANEOUS, 1.0)

	global g_bSimulationMode
	g_bSimulationMode = TRUE

	DisableVisibleDamage()
	MakePlayerInvincible()
	
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.RemoveHandlerForInstance(App.ET_OBJECT_COLLISION, __name__ + ".PlayerCollisionHandler")
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_OBJECT_COLLISION, __name__ + 
												".PlayerCollisionHandler")

	# Make Felix resume any postponed orders
	import Bridge.TacticalMenuHandlers
	global g_iLastFelixCommand
	if g_iLastFelixCommand >= Bridge.TacticalMenuHandlers.EST_FIRST_ORDER  and  g_iLastFelixCommand <= Bridge.TacticalMenuHandlers.EST_LAST_ORDER:
#		print "Updating orders to: %s" % g_iLastFelixCommand
		MissionLib.SetPlayerAI(None, None)
		Bridge.TacticalMenuHandlers.g_iOrderState = g_iLastFelixCommand - Bridge.TacticalMenuHandlers.EST_FIRST_ORDER
		Bridge.TacticalMenuHandlers.UpdateOrders(0)
		g_iLastFelixCommand = -1

	return 0

################################################################################
#	EndSimulation(pAction = None)
#
#	Restore visible damage and makes player's ship not invincible.
#	Removes instance handler for Player's ship collisions.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def EndSimulation(pAction = None):
#	print "Ending simulation.."

	MissionLib.StopFelix(None)

	# Temporarily mute spontaneus character lines.
	MissionLib.SetSpeakingVolume(None, App.CSP_SPONTANEOUS, 0.0)

	global g_bSimulationMode
	g_bSimulationMode = FALSE

	RestoreVisibleDamage()

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.SetInvincible(FALSE)
		pPlayer.RemoveHandlerForInstance(App.ET_OBJECT_COLLISION, __name__ + 
												".PlayerCollisionHandler")

	return 0

################################################################################
#	DisableVisibleDamage(pAction = None)
#
#	Disable visible damage during simulated combat.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def DisableVisibleDamage(pAction = None):
	# Save user's visible damage options.
	global g_pVisibleDamageState
	g_pVisibleDamageState[0] = App.DamageableObject_IsDamageGeometryEnabled()
	g_pVisibleDamageState[1] = App.DamageableObject_IsVolumeDamageGeometryEnabled()
	g_pVisibleDamageState[2] = App.DamageableObject_IsBreakableComponentsEnabled()

	#App.DamageableObject_SetDamageGeometryEnabled(0)
	#App.DamageableObject_SetVolumeDamageGeometryEnabled(0)
	#App.DamageableObject_SetBreakableComponentsEnabled(0)
	return 0

################################################################################
#	RestoreVisibleDamage(pAction = None)
#
#	Restore visible damage settings.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def RestoreVisibleDamage(pAction = None):
	#App.DamageableObject_SetDamageGeometryEnabled(g_pVisibleDamageState[0])
	#App.DamageableObject_SetVolumeDamageGeometryEnabled(g_pVisibleDamageState[1])
	#App.DamageableObject_SetBreakableComponentsEnabled(g_pVisibleDamageState[2])
	return 0

################################################################################
#	MakePlayerInvincible(pAction = None)
#
#	Make the player's ship invincible since we're in a simulation.
#
#	Args:	pAction, the script action.
#
#	Return:	None
################################################################################
def MakePlayerInvincible(pAction = None):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.SetInvincible(TRUE)

	return 0

################################################################################
#	SetTauntDialogueFlag()
#
#	Set flag for Tuant dialogue playing. Prevent overlap.
#
#	Args:	pObject, pEvent
#
#	Return:	None
################################################################################
def SetTauntDialogueFlag(pObject, pEvent):
	global g_bTauntPlaying
	g_bTauntPlaying = FALSE

################################################################################
#	MacCrayBattleLine()
#
#	Play dialogue from MacCray at various points throughout the battle.
#	This is triggered from GeronimoAttackAI and RankufAI.
#
#	Args:	sLine - This is the line for MacCray to speak, passed from AI script
#
#	Return:	None
################################################################################
def MacCrayBattleLine(sLine):
	if (sLine == None):
		return

	if (g_iMissionProgress == MISSION_WIN) or (not g_bSimulationMode):
		return

	# Special case check, "Running too slowly" line.
	# Bail if player is already at full impulse.
	if sLine == "E3M1L148":
		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			if pPlayer.GetImpulse() >= 1.0:
				return

	# Special case check, "save torps" line
	# Bail if player has plenty of quantums
	if sLine == "E3M1SaveTorps":
		pPlayer = MissionLib.GetPlayer()
		pTorpSys = pPlayer.GetTorpedoSystem()
		if pTorpSys:
			if pTorpSys.GetNumAvailableTorpsToType(1) > 48:
				return
		
	if MissionLib.g_bViewscreenOn:
		return

	if g_bTauntPlaying:
		return
	global g_bTauntPlaying
	g_bTauntPlaying = TRUE

	pMacCray = GetMacCray()
	pAction = Bridge.BridgeUtils.MakeCharacterLine(pMacCray, sLine, g_pMissionDatabase)

	# Add a completed event action to tell our parent sequence when walk is done.
	pMission = MissionLib.GetMission()
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(pMission)
	pEvent.SetEventType(ET_TAUNT_COMPLETED)
	pEvent.SetObjPtr(pAction)
	pAction.AddCompletedEvent(pEvent)

	pAction.Play()

################################################################################
#	FelixBattleLine()
#
#	Felix tells us how damaged we are. This is triggered from GeronimoAttackAI.
#
#	Args:	None
#
#	Return:	None
################################################################################
def FelixBattleLine():
	if MissionLib.g_bViewscreenOn:
		return

	if (g_iMissionProgress == MISSION_WIN) or (not g_bSimulationMode):
		return

	if g_bTauntPlaying:
		return
	global g_bTauntPlaying
	g_bTauntPlaying = TRUE

	pAction = Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L180", g_pMissionDatabase)

	# Add a completed event action to tell our parent sequence when walk is done.
	pMission = MissionLib.GetMission()
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(pMission)
	pEvent.SetEventType(ET_TAUNT_COMPLETED)
	pEvent.SetObjPtr(pAction)
	pAction.AddCompletedEvent(pEvent)

	pAction.Play()

################################################################################
#	DraxonBattleLine()
#
#	Draxon taunts you if you take a lot of damage.  Triggered from RankufAI.
#
#	Args:	None
#
#	Return:	None
################################################################################
def DraxonBattleLine():
	if MissionLib.g_bViewscreenOn:
		return

	if (g_iMissionProgress == MISSION_WIN) or (not g_bSimulationMode):
		return

	if g_bTauntPlaying:
		return
	global g_bTauntPlaying
	g_bTauntPlaying = TRUE

	pDXBridgeSet = App.g_kSetManager.GetSet("DXBridgeSet")
	pDraxon	= App.CharacterClass_GetObject(pDXBridgeSet, "Draxon")

	pAction = Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E3M1L152", g_pMissionDatabase)

	# Add a completed event action to tell our parent sequence when walk is done.
	pMission = MissionLib.GetMission()
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(pMission)
	pEvent.SetEventType(ET_TAUNT_COMPLETED)
	pEvent.SetObjPtr(pAction)
	pAction.AddCompletedEvent(pEvent)

	pAction.Play()

################################################################################
#	BOPCutscene(bPlayerWinning)
#
#	Start cutscene with Bird of Prey's being accidentally fired on by player.
#
#	Args:	bPlayerWinning, flag for wether player was winning.
#
#	Return:	None
################################################################################
def BOPCutscene(bPlayerWinning):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		if pPlayer.IsDying():
			return

	# Player can't be hurt
	pPlayer.SetHurtable(0)

	pMacCray = GetMacCray()
	pDXBridgeSet = App.g_kSetManager.GetSet("DXBridgeSet")
	pDraxon	= App.CharacterClass_GetObject(pDXBridgeSet, "Draxon")

	MissionLib.RemoveGoal("E3DefeatMacCrayGoal")

	# Start the attack BOP cutscene.
	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "EndSimulation"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ShutdownFriendlyFire"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ClearAI"))

	if(bPlayerWinning):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L111", g_pMissionDatabase), 5.0)
	else:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L111a", g_pMissionDatabase), 5.0)

	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RecreateGeronimo"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RecreatePlayer"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L112", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "CreateKlingons"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "UncloakShips"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "KlingonManeuverAI"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1KlingonsDecloaking", g_pMissionDatabase), 2.0)
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SetTarget", "RanKuf"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1L123", g_pMissionDatabase), 2)
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "SetMissionProgress", FIGHT_KLINGONS))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L121", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1LKlingonsHailing", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DXBridgeSet", "Draxon"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E3M1L124", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	
	if(bPlayerWinning):
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
													"MCBridgeSet", "MacCray"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L122", 
													g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L125", 
																g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L126", 
																g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L127", 
																g_pMissionDatabase))
	# Player loosing.
	else:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L139", 
																g_pMissionDatabase))
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L138", 
																g_pMissionDatabase))
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SubtitledLine", 
										g_pMissionDatabase, "E3M1MacCrayStayingOut", "MacCray"))

	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L140", g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L140b", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RestoreTorpCount"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartSimulation"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartKlingonAttack"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L150", g_pMissionDatabase))	

	if(bPlayerWinning):
		pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartGeronimoAttack2"))

	pSeq.Play()

################################################################################
#	PlayerFire(pAction, bStartFiring)
#
#	Force player's ship to fire on Bird of Prey.
#
#	Args:	pAction
#			bStartFiring, flag wether to start/stop firing.
#
#	Return:	None
################################################################################
def PlayerFire(pAction, bStartFiring):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return
	
	pPlayer.SetTarget("RanKuf")
	pPhasers = pPlayer.GetPhaserSystem()
	assert pPhasers
	if(pPhasers is None):
		return

	pRanKuf = MissionLib.GetShip("RanKuf")
	assert pRanKuf

	if(pRanKuf):
		if(bStartFiring):
			pPhasers.StartFiring(pRanKuf)
		else:
			pPhasers.StopFiring()

	return 0

################################################################################
#	CreateKlingons()
#
#	Cloak the Klingons at the beginning of the mission
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateKlingons(pAction):
	pSet = App.g_kSetManager.GetSet("Savoy1")

	pRanKuf = loadspacehelper.CreateShip("RanKuf", pSet, "RanKuf", "BOPCut1")
	pBOP = loadspacehelper.CreateShip("BirdOfPrey", pSet, "BolWI'", "BOPCut2")

	pRanKuf.SetInvincible(TRUE)
	pBOP.SetInvincible(TRUE)

	pCloak = pRanKuf.GetCloakingSubsystem()
	if(pCloak):
		pCloak.InstantCloak()	

	pCloak = pBOP.GetCloakingSubsystem()
	if(pCloak):
		pCloak.InstantCloak()		

	return 0


################################################################################
#	UncloakShips(pAction)
#
#	Bring the Klingons out of cloak when the player arrives
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def UncloakShips(pAction):
	pSet = App.g_kSetManager.GetSet("Savoy1")
	pShip = MissionLib.GetShip("RanKuf", pSet)
	if(pShip):
		MissionLib.DeCloak(None, pShip)
	pShip = MissionLib.GetShip("BolWI'", pSet)
	if(pShip):
		MissionLib.DeCloak(None, pShip)

	return 0

################################################################################
#	KlingonManeuverAI(pAction)
#
#	Set Klingon AI to maneuver.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def KlingonManeuverAI(pAction):
	import KlingonManeuverAI
	pSet = App.g_kSetManager.GetSet("Savoy1")
	pShip = MissionLib.GetShip("RanKuf", pSet)
	if(pShip):
		pShip.SetAI(KlingonManeuverAI.CreateAI(pShip))
	pShip = MissionLib.GetShip("BolWI'", pSet)
	if(pShip):
		pShip.SetAI(KlingonManeuverAI.CreateAI(pShip))

	return 0

################################################################################
#	StartKlingonAttack(pAction)
#
#	Set AI for Klingon ships and to attack player.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def StartKlingonAttack(pAction):
	# Make Klingons enemies
	pMission = MissionLib.GetMission()
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.RemoveName("RanKuf")
	pFriendlies.RemoveName("BolWI'")
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("RanKuf")
	pEnemies.AddName("BolWI'")

	MissionLib.AddGoal("E3DefeatKlingonsGoal")

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		# Player can be hurt again
		pPlayer.SetHurtable(1)

	pSet = App.g_kSetManager.GetSet("Savoy1")

	pShip = App.ShipClass_GetObject(pSet, "RanKuf")
	if(pShip):
		pShip.SetAI(RanKufAI.CreateAI(pShip))

	pShip = App.ShipClass_GetObject(pSet, "BolWI'")
	if(pShip):
		pShip.SetAI(BOPAI.CreateAI(pShip))

	return 0

################################################################################
#	StartGeronimoAttack2(pAction)
#
#	Set AI for Geronimo to attack player the second time.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def StartGeronimoAttack2(pAction):
	# Make MacCray an enemy again
	pMission = MissionLib.GetMission()
	if(pMission):
		pFriendlies = pMission.GetFriendlyGroup()
		pEnemies = pMission.GetEnemyGroup()
		pFriendlies.RemoveName("USS Geronimo")
		pEnemies.AddName("USS Geronimo")

	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pGeronimo = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")
	assert pGeronimo
	if(pGeronimo):
		pGeronimo.SetAI(GeronimoAttack2AI.CreateAI(pGeronimo))

	return 0


################################################################################
#	ClearTarget(pAction)
#
#	Clear the player's current target.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def ClearTarget(pAction):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.SetTarget("")

	return 0

################################################################################
#	BOPDestroyed()
#
#	Play dialogue from Draxon when his teammate is destroyed(simulated destruction).
#	Recreate the BolWI' and make it invincible now since it's standing down.
#	Change the RanKuf's AI to be more aggressive now.
#
#	Args:	None
#
#	Return:	None
################################################################################
def BOPDestroyed():
	# Get RanKuf and set new AI.
	pRanKuf = MissionLib.GetShip("RanKuf")
	assert pRanKuf
	if(pRanKuf):
		pRanKuf.SetAI(RanKufStrongAI.CreateAI(pRanKuf))

	pDXBridgeSet = App.g_kSetManager.GetSet("DXBridgeSet")
	pDraxon	= App.CharacterClass_GetObject(pDXBridgeSet, "Draxon")
	pMacCray = GetMacCray()

	pSeq = MissionLib.NewDialogueSequence()

	# Temporarily mute spontaneus character lines.
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SetSpeakingVolume", App.CSP_SPONTANEOUS, 0.0))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L146", 
															g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L157",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ResetBolWI"))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
												"DXBridgeSet", "Draxon"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E3M1KillBolWI",
												g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	# Resume spontaneus character lines.
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "SetSpeakingVolume", App.CSP_SPONTANEOUS, 1.0))
	MissionLib.QueueActionToPlay(pSeq)

################################################################################
#	ResetBolWI(pObject, pEvent)
#
#	Reset BolWI' since it's out of the simulation. Setup event handler
#	for it being fired on after it's friendly.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def ResetBolWI(pAction):
	# Get the BolWI'.
	pBolWI = MissionLib.GetShip("BolWI'")
	assert pBolWI
	if(pBolWI):
		# Reset ship.
		EndShipSimulation("BolWI'")

		# Add instance handler for BolWI' being fired on.
		pBolWI.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".BOPHit")

	return 0

################################################################################
#	BOPHit(pObject, pEvent)
#
#	Handler for BolWI' being fired on after it's out of simulation.
#	If Player did the firing, play line of Dialoge from Draxon.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def BOPHit(pObject, pEvent):
	pFiringObject = pEvent.GetFiringObject()
	if(pFiringObject):
		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			if(pFiringObject.GetName() == pPlayer.GetName()):
				# Play subtitled line from Draxon.
				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", 
															"SubtitledLine",
															g_pMissionDatabase,
															"E3M1WastingTime", 
															"DXBridgeSet", "Draxon"))
				pSeq.Play()

				# Remove instance handler.
				pShip = MissionLib.GetShip("BolWI'")
				assert pShip
				if(pShip):
					pShip.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".BOPHit")

	# Call any other handlers for this event.
	pObject.CallNextHandler(pEvent)

################################################################################
#	MacCrayDestroyed()
#
#	Play dialogue from MacCray when his ship is destroyed(simulated destruction).
#	Make the Geronimo invincible now since it's standing down.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MacCrayDestroyed():
	# Set flag.
	global g_bMacCrayLost
	g_bMacCrayLost = TRUE

	# Get MacCray.
	pMacCray = GetMacCray()

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
												"MCBridgeSet", "MacCray"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L154", 
															g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1MacCrayLost", 
															g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ResetGeronimo"))
	MissionLib.QueueActionToPlay(pSeq)

################################################################################
#	ResetGeronimo(pObject, pEvent)
#
#	Reset Geronimo since it's out of the simulation. Setup event handler
#	for it being fired on after it's friendly.
#
#	Args:	pObject
#			pEvent
#
#	Return:	0
################################################################################
def ResetGeronimo(pAction):
	# Reset MacCray's ship.
	EndShipSimulation("USS Geronimo")

	# Add instance handler for Geronimo being fired on.
	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pGeronimo = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")
	assert pGeronimo
	if(pGeronimo):
		pGeronimo.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__ + 
															".GeronimoHit")	
	return 0

################################################################################
#	GeronimoHit(pObject, pEvent)
#
#	Handler for Geronimo being fired on after it's out of simulation.
#	If Player did the firing, play line of Dialoge from MacCray.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def GeronimoHit(pObject, pEvent):
	pFiringObject = pEvent.GetFiringObject()
	if(pFiringObject):
		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			if(pFiringObject.GetName() == pPlayer.GetName()):
				# Play subtitled line from Draxon.
				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", 
															"SubtitledLine",
															g_pMissionDatabase,
															"E3M1WastingTime", "Draxon"))
				pSeq.Play()
				
				# Remove instance handler.
				pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
				pShip = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")
				assert pShip
				if(pShip):
					pShip.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".GeronimoHit")

	# Call any other handlers for this event.
	pObject.CallNextHandler(pEvent)

################################################################################
#	GeronimoJoinIn(pObject, pEvent)
#
#	Handler for Geronimo being fired on after it declined the challenge.
#	If Player did the firing, play Dialogue and have MacCray join in.
#
#	Args:	pObject
#			pEvent
#
#	Return:	None
################################################################################
def GeronimoJoinIn(pObject, pEvent):
	pFiringObject = pEvent.GetFiringObject()
	if(pFiringObject):
		pPlayer = MissionLib.GetPlayer()
		if pPlayer:
			if(pFiringObject.GetName() == pPlayer.GetName()):
				# Play line from MacCray.
				pMacCray = GetMacCray()
				pSeq = MissionLib.NewDialogueSequence()
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L088", 
																g_pMissionDatabase, 0, "Captain"), 3)
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
															"MCBridgeSet", "MacCray"))
				pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray,
																"E3M1GeronimoJoiningIn",
																g_pMissionDatabase))
				pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
				pSeq.AppendAction(App.TGScriptAction_Create(__name__, "StartGeronimoAttack2"))
				pSeq.Play()
				
				# Remove instance handler.
				pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
				pShip = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")
				assert pShip
				if(pShip):
					pShip.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__ + ".GeronimoJoinIn")

	# Call any other handlers for this event.
	pObject.CallNextHandler(pEvent)

################################################################################
#	BOPYouWin()
#
#	Have Klingons hail the player when player wins battle.
#
#	Args:	None
#
#	Return:	None
################################################################################
def BOPYouWin():
	if(g_iMissionProgress != FIGHT_KLINGONS):
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		if pPlayer.IsDying():
			return

	# Player can't be hurt
	pPlayer.SetHurtable(0)

	# Update mission progress
	global g_iMissionProgress
	g_iMissionProgress = MISSION_WIN

	MissionLib.RemoveGoal("E3DefeatKlingonsGoal")

	# Get Draxon.
	pDXBridgeSet = App.g_kSetManager.GetSet("DXBridgeSet")
	pDraxon	= App.CharacterClass_GetObject(pDXBridgeSet, "Draxon")

	# Get MacCray.
	pMacCray = GetMacCray()

	pSeq = MissionLib.NewDialogueSequence()
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "EndSimulation"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ClearAI"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "UncloakShips"), .05)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L158", 
															g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L158a", 
															g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "ResetAllShips"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RecreatePlayer"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "RestoreTorpCount"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L155", 
																g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
												"DXBridgeSet", "Draxon"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E3M1L153", 
															g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E3M1L159", 
															g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, 
										"E3M1DraxonMustLeave", g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "BOPWarpOut"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L161", 
														g_pMissionDatabase), 5.0)
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L162", 
														g_pMissionDatabase))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L163", 
														g_pMissionDatabase))
	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
												"MCBridgeSet", "MacCray"))
	if(g_bMacCrayLost):
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L164", 
															g_pMissionDatabase))
	else:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L165a", 
															g_pMissionDatabase))

	pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MacCrayLeave"))
	pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L166", 
														g_pMissionDatabase), 5.0)
	pSeq.AppendAction(App.TGScriptAction_Create(__name__, "MissionOver"))
	MissionLib.QueueActionToPlay(pSeq)

################################################################################
#	ResetAllShips()
#
#	End simulation for all ships.
#
#	Args:	None
#
#	Return:	None
################################################################################
def ResetAllShips(pAction):
	EndShipSimulation("USS Geronimo")
	EndShipSimulation("RanKuf")
	EndShipSimulation("BolWI'")

	return 0

################################################################################
#	BOPYouLose()
#
#	Have Klingons hail player when player looses battle.
#
#	Args:	None
#
#	Return:	None
################################################################################
def BOPYouLose():
	if(g_iMissionProgress != FIGHT_KLINGONS):
		return

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		if pPlayer.IsDying():
			return

	# Player can't be hurt
	pPlayer.SetHurtable(0)

	pDXBridgeSet = App.g_kSetManager.GetSet("DXBridgeSet")
	pDraxon	= App.CharacterClass_GetObject(pDXBridgeSet, "Draxon")

	# Get MacCray.
	pMacCray = GetMacCray()

	# Update mission progress
	global g_iMissionProgress
	g_iMissionProgress = MISSION_FAILED

	MissionLib.RemoveGoal("E3DefeatKlingonsGoal")

	pSequence = MissionLib.NewDialogueSequence()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "EndSimulation"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "ClearAI"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "UncloakShips"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L111a", 
																g_pMissionDatabase), 5.0)
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "RecreatePlayer"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "RestoreTorpCount"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "ResetAllShips"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1L155", 
																g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
														"DXBridgeSet", "Draxon"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pDraxon, "E3M1L156", 
																g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "BOPWarpOut"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L161", 
															g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1L162", 
														g_pMissionDatabase))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1L163", 
														g_pMissionDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", 
												"MCBridgeSet", "MacCray"))
	if(g_bMacCrayLost):
		pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L164", 
															g_pMissionDatabase))
	else:
		pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pMacCray, "E3M1L165a", 
															g_pMissionDatabase))

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "MacCrayLeave"))
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1L166", 
														g_pMissionDatabase))

	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "MissionOver"))
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
#	BOPWarpOut(pAction)
#
#	Make Birds of Prey warp out.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def BOPWarpOut(pAction):
	pShip = App.ShipClass_GetObject(None, "RanKuf")
	if(pShip):
		pShip.SetAI(WarpOutAI.CreateAI(pShip))

	pShip = App.ShipClass_GetObject(None, "BolWI'")
	if(pShip):
		pShip.SetAI(WarpOutAI.CreateAI(pShip))

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		# Player can be hurt again
		pPlayer.SetHurtable(1)

	return 0
	
################################################################################
#	ClearAI(pAction)
#
#	Clear AI Player and the Klingon ships.
#
#	Args:	pAction
#
#	Return:	None
################################################################################
def ClearAI(pAction):
	# Reset Friendly fire
	MissionLib.StopFelix()
	
	pShip = MissionLib.GetShip("RanKuf")
	if(pShip):
		pShip.SetAI(ShipStayAI.CreateAI(pShip))

	pShip = MissionLib.GetShip("BolWI'")
	if(pShip):
		pShip.SetAI(ShipStayAI.CreateAI(pShip))

	pSavoy1 = App.g_kSetManager.GetSet("Savoy1")
	pShip = App.ShipClass_GetObject(pSavoy1, "USS Geronimo")
	if(pShip):
		pShip.SetAI(ShipStayAI.CreateAI(pShip))

	return 0

################################################################################
#	GetMacCray()
#
#	Get MacCray character.
#
#	Args:	None
#
#	Return:	pMacCray
################################################################################
def GetMacCray():
	pMCBridgeSet = App.g_kSetManager.GetSet("MCBridgeSet")
	pMacCray = App.CharacterClass_GetObject(pMCBridgeSet, "MacCray")
	assert pMacCray
	return pMacCray

################################################################################
#	DebugFixTargeting()
#
#	Temporary test function. Fixes targeting system.
#
#	Args:	None
#
#	Return:	None
################################################################################
def DebugFixTargeting():
	global g_iFixCounter
	g_iFixCounter = 5

	global g_iMissionProgress
	g_iMissionProgress = FIX_TARGETING

	BrexSaysTargetingFixed()

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

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == UNDOCK:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1SaffiComm1",
																g_pMissionDatabase))
	elif g_iMissionProgress == GO_TO_SAVOY:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1SaffiComm2",
																g_pMissionDatabase))
	elif g_iMissionProgress == GO_TO_SAVOY1:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1SaffiComm3",
																g_pMissionDatabase))
	elif g_iMissionProgress == SCAN_ASTEROID:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1SaffiComm4",
																g_pMissionDatabase))
	elif g_iMissionProgress == FIX_TARGETING:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1SaffiComm5",
																g_pMissionDatabase))
	elif g_iMissionProgress == ACCEPT_CHALLENGE:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1SaffiComm6",
																g_pMissionDatabase))
	elif g_iMissionProgress == FIGHT_KLINGONS:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pSaffi, "E3M1SaffiComm7",
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
#	kDebugObj.Print("Felix Communicating...")

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == GO_TO_SAVOY1:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1FelixComm1",
																g_pMissionDatabase))
	elif g_iMissionProgress == FIX_TARGETING:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1FelixComm2",
																g_pMissionDatabase))
	elif g_iMissionProgress == ACCEPT_CHALLENGE:
		# If player using Quantums.
		if IsUsingQuantums():
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1FelixComm4",
																	g_pMissionDatabase))
		else:
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1FelixComm3",
																	g_pMissionDatabase))
	elif g_iMissionProgress == FIGHT_KLINGONS:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pFelix, "E3M1FelixComm5",
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
#	kDebugObj.Print("Kiska Communicating...")

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == UNDOCK:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1KiskaComm1",
																g_pMissionDatabase))
	elif g_iMissionProgress == GO_TO_SAVOY:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pKiska, "E3M1KiskaComm2",
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
	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == SCAN_ASTEROID:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1MiguelComm1",
																g_pMissionDatabase))
	elif g_iMissionProgress == FIGHT_KLINGONS:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pMiguel, "E3M1MiguelComm2",
																g_pMissionDatabase))
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
#	kDebugObj.Print("Brex Communicating...")

	pSeq = MissionLib.NewDialogueSequence()

	if g_iMissionProgress == GO_TO_SAVOY:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1BrexComm1",
																g_pMissionDatabase))
	elif g_iMissionProgress == GO_TO_SAVOY1:
		if Bridge.BridgeUtils.GetBridgeCharacter("Engineer") == None:
			pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1BrexComm2",
																	g_pMissionDatabase))
		else:
			pObject.CallNextHandler(pEvent)

	elif g_iMissionProgress == FIGHT_KLINGONS:
		pSeq.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(g_pBrex, "E3M1BrexComm3",
																g_pMissionDatabase))
	else:
		pObject.CallNextHandler(pEvent)

	pSeq.Play()

################################################################################
#	IsUsingQuantums()
#
#	Helper function to tell us if player has Quantum torpedoes currently selected.
#
#	Args:	None
#
#	Return:	Bool, 1-True, 0-False
################################################################################
def IsUsingQuantums():
	pPlayer = MissionLib.GetPlayer()
	if pPlayer is None:
		return FALSE

	pTorpSys = pPlayer.GetTorpedoSystem()
	if(pTorpSys):
		pAmmoType = pTorpSys.GetCurrentAmmoType()
		if(pAmmoType):
			import Tactical.Projectiles.QuantumTorpedo
			if pAmmoType.GetAmmoName() == Tactical.Projectiles.QuantumTorpedo.GetName():
				return TRUE
	return FALSE

################################################################################
#	RedAlert(pAction)
#
#	Set Player's ship to Red Alert if not already at Red Alert.
#
#	Args:	pAction
#
#	Return:	0
################################################################################
def RedAlert(pAction):
	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		if(pPlayer.GetAlertLevel() != pPlayer.RED_ALERT):
			MissionLib.RedAlert()

	return 0

################################################################################
#	SetIssuedChallengeFlag(pAction)
#
# 	Set flag for MacCray issuing challenge to player.
#
#	Args:	pAction, TGAction
#
#	Return:	None
################################################################################
def SetIssuedChallengeFlag(pAction):
	global g_bIssuedChallenge
	g_bIssuedChallenge = TRUE
	return 0

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
#	Mission terminate.
#
#	Args:	pMission, current mission.
#
#	Return:	None
################################################################################
def Terminate(pMission):
	global g_bMissionTerminated
	g_bMissionTerminated = TRUE

#	kDebugObj.Print("Terminating Episode 3, Mission 1.\n")

	StopProdTimer()

	# Unload BridgeCrewGeneral database.
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	pPlayer = MissionLib.GetPlayer()
	if pPlayer:
		pPlayer.RemoveHandlerForInstance(App.ET_OBJECT_COLLISION, __name__ + 
											".PlayerCollisionHandler")
		pPlayer.SetInvincible(FALSE)

	App.SortedRegionMenu_ClearSetCourseMenu()

	Bridge.BridgeUtils.RemoveCommunicateHandlers()

	pMission.RemoveHandlerForInstance(ET_TAUNT_COMPLETED, __name__ + ".SetTauntDialogueFlag")
	pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_DAMAGE, __name__ + ".SavoyHitByPlayer")
	pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".SavoyDamagedByPlayer")
	pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".SavoyDamagedLoose")

	# Remove instance handler for Miguel's scan area button.
	g_pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")

	# Remove handler for Kiska's Hail and dock buttons
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	g_pKiskaMenu.RemoveHandlerForInstance(App.ET_DOCK, __name__ + ".UnDockHandler")

	g_pFelixMenu.RemoveHandlerForInstance(App.ET_FIRE, __name__ + ".StopManualFire")

	pTopWindow = App.TopWindow_GetTopWindow()
	pTactical = pTopWindow.FindMainWindow(App.MWT_TACTICAL)
	if pTactical:
		pTactical.RemoveHandlerForInstance(App.ET_INPUT_FIRE_PRIMARY, __name__+".PlayerPhaserHandler")
		pTactical.RemoveHandlerForInstance(App.ET_INPUT_FIRE_PRIMARY, __name__+".PlayerPhotonHandler")

	pTacticalControl = App.TacticalControlWindow_GetTacticalControlWindow()
	if pTacticalControl:
		pTacticalControl.RemoveHandlerForInstance(App.ET_INPUT_FIRE_PRIMARY, __name__+".PlayerPhaserHandler")
		pTacticalControl.RemoveHandlerForInstance(App.ET_INPUT_FIRE_SECONDARY, __name__+".PlayerPhotonHandler")
		pTacticalControl.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_PICK_FIRE, __name__ + ".StopManualFire")

	MissionLib.ShutdownFriendlyFire()
	
