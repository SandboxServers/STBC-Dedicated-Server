###############################################################################
#	Filename:	E2M0.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 2, Mission 0
#	
#	Created:	3/21/01 -	Jess VanDerwalker
###############################################################################
import App
import loadspacehelper
import MissionLib
import Bridge.BridgeUtils
import Bridge.TacticalMenuHandlers
import Maelstrom.Episode2.Episode2
import Actions.MissionScriptActions
import Maelstrom.Episode2.E2M1.Ep2Cutscene
import Maelstrom.Episode2.AI_WarpOut

# Declare global variables here
TRUE				= 1
FALSE				= 0

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None
g_pDatabase			= None

g_bMissionTerminate	= None

g_iProdTimer			= None
g_bPlayerNotInTevron	= None
g_iPlayerNotInTevron	= None

g_bShipsIDd					= None
g_bSovHailDone				= None
g_bRanKufHailDone			= None
g_bWarbirdsOpenFire			= None
g_bSovDamaged				= None
g_bFirstCloakDone			= None
g_bSecondCloakDone			= None
g_pPicardSuggestRepair		= None
g_bWarbirdsWarpCalled		= None
g_bWarbirdsLeftPlayed		= None
g_pKlingonsDecloakCalled	= None
g_bMissionLost				= None
g_bPicardLeft				= None
g_bMissionWin				= None
g_bZhukovArrives			= None

g_bHailSovAtSB		= None
g_bHailZhukovAtSB	= None

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None

g_lFriendlyShips	= []

g_lEnemyShips	= []

g_lPicardTips	= []

g_lDamagedSubsystems	= []

g_pWarbird1Targets	= None
g_pWarbird2Targets	= None

g_idPlayerInHelpCondition = App.NULL_ID

g_iMissionState	= None
DEFAULT			= 0
ARRIVE_TEVRON	= 1
WARBIRDS_ATTACK	= 3
ATTACK_OVER		= 4

# Flags used in tutorial sequences
g_bInTutorial				= None
g_bCharWindowLock			= None
g_iTutorialCounter			= None

# Global used for info box ids
g_idSubsystemTargetBox1	= None
g_idSubsystemTargetBox2	= None
g_idRepairBox1			= None
g_idRepairBox2			= None
g_idRepairBox3			= None

# Global dictionary of arrows currently
# being displayed.
g_dCurrentArrows	= None

# Ennumeration used with g_dCurrentArrows
ARROW_OBJECT	= 0
ARROW_SPACING	= 1
ARROW_COLOR		= 2

# ID for the arrow refresh timer
g_idArrowRefreshTimer	= None

# Global for the current screen resolution
g_sResolutionSetting	= None
	
# Enumeration to access box specs
BOX_LEFT	= 0
BOX_TOP		= 1
BOX_WIDTH	= 2
BOX_HEIGHT	= 3

# Global dictonary for sizes and placement for info boxes.
g_dInfoBoxSpecs	= None

# Mission event types
ET_HAIL_TIMER			= None
ET_ATTACK_PLAYER_TIMER	= None
ET_PICARD_AUDIO_TIMER	= None
ET_PROD_TIMER			= None
ET_CLOSE_HELP_BOX		= None
ET_ARROW_REFRESH_TIMER	= None

# Event types for Picard's buttons
ET_SUBSYSTEM_TARGET_TUTORIAL	= None
ET_REPAIR_TUTORIAL				= None

# Create a special class for a condition that we'll
# be controlling from within the mission.  (Some of the
# AI is listening in on this condition, so it can change
# what it's doing when the condition changes).
class PlayerInHelp:
	def __init__(self, pCodeCondition):
		self.pCodeCondition = pCodeCondition

		# Save a reference to our module, so the module isn't
		# unloaded unexpectedly.
		self.pModule = __import__(__name__)

		# Initial state is false.
		self.pCodeCondition.SetStatus(0)

	def SetStatus(self, bNewStatus):
		self.pCodeCondition.SetStatus(bNewStatus)

###############################################################################
#	SetPlayerInHelp()
#	
#	Set the global condition for whether or not the player is in
#	Help mode right now...   This affects the AI...
#	
#	Args:	pTGAction	- For use with TGScriptAction's..
#			bInHelp		- True (1) if the player is going into Help, false (0) if exiting.
#	
#	Return:	none
###############################################################################
def SetPlayerInHelp(pTGAction, bInHelp):
	pPlayerInHelp = App.TGCondition_Cast( App.TGObject_GetTGObjectPtr( g_idPlayerInHelpCondition ) )
	if pPlayerInHelp:
		pPlayerInHelp.SetStatus(bInHelp)
	
	return 0

###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to load ship instances.
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("Galaxy", 1)
	loadspacehelper.PreloadShip("Sovereign", 1)	
	loadspacehelper.PreloadShip("E2M0Warbird", 2)
	loadspacehelper.PreloadShip("RanKuf", 2)
	loadspacehelper.PreloadShip("Ambassador", 1)
	loadspacehelper.PreloadShip("FedOutpost", 1)

################################################################################
##	Initialize()
##	
##  Called once when mission loads to initialize mission
##	
##	Args: 	pMission	- the mission object
##	
##	Return: None
################################################################################
def Initialize(pMission):
	# Initialize all our global variables
	InitializeGlobals(pMission)
	
	# Create Regions
	CreateStartingRegions()
	
	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")
	
	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	# Add Picard to the bridge and set up his buttons
	CreatePicard()
	
	# Create the set we'll need on the viewscreen
	CreateSets()
	
	# Create menus available at mission start
	CreateStartingMenus()
	
	# Create the starting objects
	CreateStartingObjects(pMission)
		
	# Setup more mission-specific events.
	SetupEventHandlers(pMission)

	# Get the current screen resolution
	GetCurrentResolution()
	
	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()

	# Setup the info boxes we'll need.
	SetupSubsystemTargetingInfoBoxes()
	SetupRepairInfoBoxes()
	
	# Call or function to start the mission
	PlayerEntersTevron()

# FIXME: Remove this function call after debugging the
# tutorial sequences
#	PicardTest()
	
	# Save the game
	MissionLib.SaveGame("E1M3-")

################################################################################
##	InitializeGlobals(pMission)
##
##	Initialize all the global variables used in this mission.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
	# General flags used in bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0
	
	# Set bMissionTerminate here in case mission gets reloaded
	global g_bMissionTerminate
	g_bMissionTerminate = 1

	# TGL Database globals
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 2/E2M0.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Globals used for prodding
	global g_iProdTimer
	global g_bPlayerNotInTevron
	global g_iPlayerNotInTevron
	g_iProdTimer			= App.NULL_ID
	g_bPlayerNotInTevron	= TRUE
	g_iPlayerNotInTevron	= 0
	
	# Flags for mission events
	global g_bShipsIDd
	global g_bSovHailDone
	global g_bRanKufHailDone
	global g_bWarbirdsOpenFire
	global g_bSovDamaged
	global g_bFirstCloakDone
	global g_bSecondCloakDone
	global g_pPicardSuggestRepair
	global g_bWarbirdsWarpCalled
	global g_bWarbirdsLeftPlayed
	global g_pKlingonsDecloakCalled
	global g_bMissionLost
	global g_bPicardLeft
	global g_bMissionWin
	global g_bZhukovArrives
	g_bShipsIDd					= FALSE
	g_bSovHailDone				= FALSE
	g_bRanKufHailDone			= FALSE
	g_bWarbirdsOpenFire			= FALSE
	g_bSovDamaged				= FALSE
	g_bFirstCloakDone			= FALSE
	g_bSecondCloakDone			= FALSE
	g_pPicardSuggestRepair		= FALSE
	g_bWarbirdsWarpCalled		= FALSE
	g_bWarbirdsLeftPlayed		= FALSE
	g_pKlingonsDecloakCalled	= FALSE
	g_bMissionLost				= FALSE
	g_bPicardLeft				= FALSE
	g_bMissionWin				= FALSE
	g_bZhukovArrives			= FALSE

	# Flags for hails after mission is done
	global g_bHailSovAtSB
	global g_bHailZhukovAtSB
	g_bHailSovAtSB		= FALSE
	g_bHailZhukovAtSB	= FALSE
	
	# Global lists of ship names
	global g_lFriendlyShips
	global g_lEnemyShips
	
	g_lFriendlyShips	= 	[
							"Starbase 12", "Sovereign", "RanKuf", "Trayor", "Zhukov"
							]
	
	g_lEnemyShips		=	[
							"Warbird 1", "Warbird 2"
							]
	
	# List of damaged subsystems on the players ship
	global g_lDamagedSubsystems
	g_lDamagedSubsystems = []
	
	# List of Picards tips that we can pull from
	global g_lPicardTips
	g_lPicardTips	=	[
						"E2M0PicardTargeting2", "E2M0PicardTargeting3", "E2M0PicardTargeting4",
						"E2M0PicardTargeting5", "E2M0PicardTargeting7", "E2M0PicardTargeting8"
						]
						
	# Target list for the Warbirds
	global g_pWarbird1Targets
	global g_pWarbird2Targets
	g_pWarbird1Targets = App.ObjectGroupWithInfo()
	g_pWarbird2Targets = App.ObjectGroupWithInfo()

	# Flags and such used for communicate
	global g_iMissionState
	global DEFAULT
	global ARRIVE_TEVRON
	global WARBIRDS_ATTACK
	global ATTACK_OVER

	g_iMissionState	= None
	DEFAULT			= 0
	ARRIVE_TEVRON	= 1
	SHIPS_ID		= 2
	WARBIRDS_ATTACK	= 3
	ATTACK_OVER		= 4

	# Flags used in tutorial sequences
	global g_bInTutorial
	global g_bCharWindowLock
	global g_iTutorialCounter
	g_bInTutorial				= FALSE
	g_bCharWindowLock			= FALSE
	g_iTutorialCounter			= FALSE

	# Global used for info box ids
	global g_idSubsystemTargetBox1
	global g_idSubsystemTargetBox2
	global g_idRepairBox1
	global g_idRepairBox2
	global g_idRepairBox3
	g_idSubsystemTargetBox1	= None
	g_idSubsystemTargetBox2	= None
	g_idRepairBox1			= None
	g_idRepairBox2			= None
	g_idRepairBox3			= None

	# Global dictionary of arrows currently
	# being displayed.
	global g_dCurrentArrows
	g_dCurrentArrows	= {}

	# Ennumeration used with g_dCurrentArrows
	global ARROW_OBJECT
	global ARROW_SPACING
	global ARROW_COLOR
	ARROW_OBJECT	= 0
	ARROW_SPACING	= 1
	ARROW_COLOR		= 2

	# ID for the arrow refresh timer
	global g_idArrowRefreshTimer
	g_idArrowRefreshTimer	= App.NULL_ID

	# Mission event types
	global ET_HAIL_TIMER
	global ET_ATTACK_PLAYER_TIMER
	global ET_PICARD_AUDIO_TIMER
	global ET_PROD_TIMER
	global ET_CLOSE_HELP_BOX
	global ET_ARROW_REFRESH_TIMER
	ET_HAIL_TIMER			= App.Mission_GetNextEventType()
	ET_ATTACK_PLAYER_TIMER	= App.Mission_GetNextEventType()
	ET_PICARD_AUDIO_TIMER	= App.Mission_GetNextEventType()
	ET_PROD_TIMER			= App.Mission_GetNextEventType()
	ET_CLOSE_HELP_BOX		= App.Mission_GetNextEventType()
	ET_ARROW_REFRESH_TIMER	= App.Mission_GetNextEventType()

	# Event types for Picard's buttons
	global ET_SUBSYSTEM_TARGET_TUTORIAL
	global ET_REPAIR_TUTORIAL
	ET_SUBSYSTEM_TARGET_TUTORIAL	= App.Mission_GetNextEventType()
	ET_REPAIR_TUTORIAL				= App.Mission_GetNextEventType()

	# Set our limits for the friendly fire warnings and game loss
	App.g_kUtopiaModule.SetMaxFriendlyFire(1500)			# how many damage points the player can do total before losing
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(500)	# how many damage points before Saffi warns you
	
	# Current screen resolution - set to 640x480 by default
	global g_sResolutionSetting
	g_sResolutionSetting	= "640x480"
	
	# Enumeration to access box specs
	global BOX_LEFT
	global BOX_TOP
	global BOX_WIDTH
	global BOX_HEIGHT
	BOX_LEFT	= 0
	BOX_TOP		= 1
	BOX_WIDTH	= 2
	BOX_HEIGHT	= 3
	
	# Global dictonary for sizes and placement for info boxes.
	global g_dInfoBoxSpecs

	# Get the language being used out of the E1M1HelpText.TGL
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 2/E2M0HelpText.tgl")
	pString = pDatabase.GetString("Language")
	App.g_kLocalizationManager.Unload(pDatabase)
	
	# We are using German Version
	if (pString.GetCString() == "German"):		
#####	German													 Left,	Top,	Width,	Height	
		g_dInfoBoxSpecs =	{
						"SubsystemTarget"	: {	"640x480"	:	[0.27,	0.135,	0.24,	0.37],
												"800x600"	:	[0.22,	0.135,	0.24,	0.32],
												"1024x768"	:	[0.17,	0.19,	0.24,	0.21],
												"1280x1024"	:	[0.15,	0.15,	0.24,	0.14],
												"1600x1200"	:	[0.15,	0.15,	0.24,	0.14],
												},
						"RepairBoxes"		: {	"640x480"	:	[0.38,	0.52,	0.6,	0.30],
												"800x600"	:	[0.47,	0.52,	0.5,	0.32],
												"1024x768"	:	[0.63,	0.37,	0.35,	0.28],
												"1280x1024"	:	[0.63,	0.28,	0.35,	0.16],
												"1600x1200"	:	[0.63,	0.28,	0.35,	0.16],
												},
						}
	# Default to English
	else:
#####	English													 Left,	Top,	Width,	Height	
		g_dInfoBoxSpecs =	{
						"SubsystemTarget"	: {	"640x480"	:	[0.27,	0.135,	0.24,	0.37],
												"800x600"	:	[0.22,	0.135,	0.24,	0.32],
												"1024x768"	:	[0.17,	0.19,	0.24,	0.21],
												"1280x1024"	:	[0.15,	0.15,	0.24,	0.14],
												"1600x1200"	:	[0.15,	0.15,	0.24,	0.14],
												},
						"RepairBoxes"		: {	"640x480"	:	[0.38,	0.50,	0.6,	0.30],
												"800x600"	:	[0.47,	0.57,	0.5,	0.25],
												"1024x768"	:	[0.63,	0.37,	0.35,	0.23],
												"1280x1024"	:	[0.63,	0.28,	0.35,	0.16],
												"1600x1200"	:	[0.63,	0.28,	0.35,	0.16],
												},
						}
						
################################################################################
##	GetCurrentResolution()
##
##	Helper funtion that set the value of g_sResolutionSetting to the current
##	resolution.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GetCurrentResolution():
	global g_sResolutionSetting

	# Check what resolution were at.
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	pRes = pMode.GetCurrentResolution()
	
	# Set the global
	if (pRes == App.GraphicsModeInfo.RES_640x480):
		g_sResolutionSetting = "640x480"
	elif (pRes == App.GraphicsModeInfo.RES_800x600):
		g_sResolutionSetting = "800x600"
	elif (pRes == App.GraphicsModeInfo.RES_1024x768):
		g_sResolutionSetting = "1024x768"
	elif (pRes == App.GraphicsModeInfo.RES_1280x1024):
		g_sResolutionSetting = "1280x1024"
	elif (pRes == App.GraphicsModeInfo.RES_1600x1200):
		g_sResolutionSetting = "1600x1200"
	else:
		g_sResolutionSetting = "640x480"
		
################################################################################
##	InitializeCrewPointers()
##
##	Initializes the global pointers to the bridge crew members.
##	NOTE: This must be called after the bridge has been loaded.
##
##	Args:	None
##
##	Return:	None
################################################################################
def InitializeCrewPointers():
	# Get the bridge
	pBridge = App.g_kSetManager.GetSet("bridge")
	
	# Set the globals
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

################################################################################
##	CreatePicard()
##
##	Adds Picard to the bridge and creates his menu buttons.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreatePicard():
	# Get the bridge
	pBridge = App.g_kSetManager.GetSet("bridge")
	# Import Picard and add him to the bridge
	import Bridge.Characters.Picard
	pPicard = App.CharacterClass_GetObject(pBridge, "Picard")
	if not (pPicard):
		pPicard = Bridge.Characters.Picard.CreateCharacter(pBridge)
		Bridge.Characters.Picard.ConfigureForGalaxy(pPicard)
		pPicard.SetLocation("DBGuest")
	
	# Create the buttons in Picards menu and create
	# function handlers for them.
	pPicard.AddPythonFuncHandlerForInstance(ET_SUBSYSTEM_TARGET_TUTORIAL,	__name__ + ".ExplainSubsystemTargeting")
	pPicard.AddPythonFuncHandlerForInstance(ET_REPAIR_TUTORIAL, 			__name__ + ".ExplainRepair")
	
	# Create his tutorial buttons and set them disabled
	pPicardMenu	= pPicard.GetMenu()
	pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("SubsystemTarget"),	ET_SUBSYSTEM_TARGET_TUTORIAL, 0, pPicard))
	pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Repair"),	ET_REPAIR_TUTORIAL, 0, pPicard))
	
	pSubsystems = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("SubsystemTarget"))
	if (pSubsystems != None):
		pSubsystems.SetDisabled()
	pRepair = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Repair"))
	if (pRepair != None):
		pRepair.SetDisabled()

################################################################################
##	PicardTest()
##
##	Testing function that creates all of Picards buttons at once so I don't
##	have to wade through the whole mission.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PicardTest():
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	pPicardMenu	= pPicard.GetMenu()
	
	# Create all of his buttons
	pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("SubsystemTarget"),	ET_SUBSYSTEM_TARGET_TUTORIAL, 0, pPicard))
	pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Repair"),	ET_REPAIR_TUTORIAL, 0, pPicard))
	
################################################################################
##	CreateSets()
##
##	Creates the sets that will be used on the viewscreen and popluates them.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateSets():
	# The Sovereign bridge with Captain Soto
	MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif", -40, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Soto", "EBridgeSet")
	
	# Klingon bridge with Captain Draxon
	MissionLib.SetupBridgeSet("KlingonSet", "data/Models/Sets/Klingon/BOPbridge.nif", -30, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Draxon", "KlingonSet", 0, 0, -5)
	
	# Romulan set with V'Lin
	MissionLib.SetupBridgeSet("RomulanSet", "data/Models/Sets/Romulan/romulanbridge.nif", -40, 65, -1.55, 0, -280, 0)
	MissionLib.SetupCharacter("Bridge.Characters.Torenn", "RomulanSet", 0, 0, 1)
	
	# DBridge set with Verata
	MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -40, 65, -1.55)
	MissionLib.ReplaceBridgeTexture(None, "DBridgeSet", "Map 7.tga", "data/Models/Sets/DBridge/AmbassadorLCARS.tga")
	MissionLib.SetupCharacter("Bridge.Characters.Verata", "DBridgeSet")
	
	# Starbase set with Liu
	MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -30, 65, -1.55)
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)

################################################################################
##	CreateStartingRegions()
##
##	Creates the regions that will be used in this mission.  Also loads
##	placement files if needed.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateStartingRegions():
	# Create Vesuvi6
	pVesuvi6Set = MissionLib.SetupSpaceSet("Systems.Vesuvi.Vesuvi6")	
	# Create Starbase12
	pStarbaseSet = MissionLib.SetupSpaceSet("Systems.Starbase12.Starbase12")
	# Create Tevron2
	pTevron2Set = MissionLib.SetupSpaceSet("Systems.Tevron.Tevron2")
	# Create Deep Space
	pDeepSpace = MissionLib.SetupSpaceSet("Systems.DeepSpace.DeepSpace")
	
	# Do our placements
	import E2M0_Tevron2_P
	import E2M0_Starbase12_P
	E2M0_Tevron2_P.LoadPlacements(pTevron2Set.GetName())
	E2M0_Starbase12_P.LoadPlacements(pStarbaseSet.GetName())
	
################################################################################
##	CreateStartingMenus()
##	
##  Creates menu items for systems we need at mission start in the "Helm" menu.
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def CreateStartingMenus():
	import Systems.Starbase12.Starbase
	import Systems.Tevron.Tevron
		
	Systems.Starbase12.Starbase.CreateMenus()
	Systems.Tevron.Tevron.CreateMenus()

	# Remove the Vesuvi system from the Set Course menu if it exists.
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu != None):
		pSetCourse = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
		if (pSetCourse != None):
			pVesuvi = pSetCourse.GetSubmenu("Vesuvi")
			if (pVesuvi != None):
				pSetCourse.DeleteChild(pVesuvi)

################################################################################
##	CreateStartingObjects()
##
##	Creates all objects that exist at the mission start.
##
##	Args:	pMission	- The mission object.	
##
##	Return:	None
################################################################################
def CreateStartingObjects(pMission):
	# Create our object affilations
	pFriendlyGroup = pMission.GetFriendlyGroup()
	for sName in g_lFriendlyShips:
		pFriendlyGroup.AddName(sName)
		
	pEnemyGroup = pMission.GetEnemyGroup()
	for sName in g_lEnemyShips:
		pEnemyGroup.AddName(sName)
		
	# Get the sets we need
	pTevron2Set		= App.g_kSetManager.GetSet("Tevron2")
	pStarbaseSet	= App.g_kSetManager.GetSet("Starbase12")
	
	# Create the players ship
	pPlayer	= MissionLib.CreatePlayerShip("Galaxy", pTevron2Set, "player", "Player Start")
	
	# Create other starting objects.
	pStarbase		= loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	pSovereign		= loadspacehelper.CreateShip("Sovereign", pTevron2Set, "Sovereign", "SovStart")
	pSovereign.ReplaceTexture("Data/Models/Ships/Sovereign/Sovereign.tga", "ID")
	pRanKuf			= loadspacehelper.CreateShip("RanKuf", pTevron2Set, "RanKuf", "RanKufStart")
	pTrayor			= loadspacehelper.CreateShip("RanKuf", pTevron2Set, "Trayor", "TrayorStart")

	# Pre-damage the systems on the Sovereign
	DamageSovereign(pSovereign)
	
	# Give the Trayor his orbit Sovereign AI
	import E2M0_AI_OrbitSov
	pTrayor.SetAI(E2M0_AI_OrbitSov.CreateAI(pTrayor))
	
	# Give the Sovereign its AI
	import E2M0_AI_Sovereign
	pSovereign.SetAI(E2M0_AI_Sovereign.CreateAI(pSovereign))

	# Set the default torp type of the Birds of Prey and
	# set their warp engines invincible
	for pShip in [pRanKuf, pTrayor]:
		pTorps = pShip.GetTorpedoSystem()
		pTorps.SetAmmoType(App.AT_TWO, 0)
		pWarp = pShip.GetWarpEngineSubsystem()
		MissionLib.MakeSubsystemsInvincible(pWarp)
		# Turn off collisions for these ships.
		pShip.SetCollisionsOn(FALSE)
	
	# Create our starting target list for Warbirds
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	global g_pWarbird1Targets
	g_pWarbird1Targets["RanKuf"]	= {"Priority" : 0.0}
	g_pWarbird1Targets["Trayor"]	= {"Priority" : 0.0}

	global g_pWarbird2Targets
	g_pWarbird2Targets["RanKuf"]	= {"Priority" : 0.0}
	g_pWarbird2Targets["Trayor"]	= {"Priority" : 0.0}
			
################################################################################
##	DamageSovereign()
##
##	Damage the warp and impulse engines on the Sovereign.
##
##	Args:	pShip	- The ship object to damage.
##
##	Return:	None
################################################################################
def DamageSovereign(pShip):
	if (pShip == None):
		return
		
	# Turn off the repair system
	pRepair = pShip.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)

	# Damage all the warp engines to their disabled percentage.
	pWarp = pShip.GetWarpEngineSubsystem()
	if (pWarp != None):
		# Get the warp engines one by one and damage each of them.
		for iCounter in range(pWarp.GetNumChildSubsystems()):
			pChild = pWarp.GetChildSubsystem(iCounter)
			# Get the disabled percentage for the warp engine and set it's
			# condidtion to that.
			pChild.SetConditionPercentage(pChild.GetDisabledPercentage() - 0.05)

	# Damage the impulse engines to their disabled percentage.
	pImpulse = pShip.GetImpulseEngineSubsystem()
	if (pImpulse != None):
		# Get the impulse engines one by one and damage each of them.
		for iCounter in range(pImpulse.GetNumChildSubsystems()):
			pChild = pImpulse.GetChildSubsystem(iCounter)
			# Get the disabled percentage for the impulse engine and set it's
			# condidtion to that.
			pChild.SetConditionPercentage(pChild.GetDisabledPercentage() - 0.05)
	
################################################################################
##	SetupEventHandlers()
##	
##	Sets up the event handlers that we're going to use in this mission
##	
##	Args:	pMission	- The mission object.
##	
##	Return: None
################################################################################
def SetupEventHandlers(pMission):
	# Ship entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ +".EnterSet")
	# Ship exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")
	# Ship dying event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectDying")
	# Target is ID'd by sensors event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_IDENTIFIED, pMission, __name__+".ShipIdentified")
	# Cloak beginning event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_CLOAK_BEGINNING, pMission, __name__+".CloakStarted")
	# De-cloak beginning event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_DECLOAK_BEGINNING, pMission, __name__+".DecloakStarted")
	# Resolution change event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_UI_REPOSITION, pMission, __name__ + ".ResolutionChanged")
	
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".FriendlyFireReportHandler")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".FriendlyFireGameOverHandler")

	# Handler for the in and out of tactical event
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow != None):
		pTopWindow.AddPythonFuncHandlerForInstance(App.ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL, __name__ + ".TacticalToggleHandler")
		# Handler for toggling to map mode
		pTacticalWindow = pTopWindow.FindMainWindow(App.MWT_BRIDGE)
		if (pTacticalWindow != None):
			pTacticalWindow.AddPythonFuncHandlerForInstance(App.ET_INPUT_TOGGLE_MAP_MODE,		__name__ + ".MapToggleHandler")
			pTacticalWindow.AddPythonFuncHandlerForInstance(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	__name__ + ".MapToggleHandler")

	pTevronSet = App.g_kSetManager.GetSet("Tevron2")
	# Instance handler on the Sovereign for the Weapon Hit event
	pSov = App.ShipClass_GetObject(pTevronSet, "Sovereign")
	if (pSov != None):
		pSov.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, __name__+".WeaponHitSov")
			
	# Instance handler on players ship for Weapon Fired event
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		# Instance handler for the Subsystem Damaged event.
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_DAMAGED, __name__+".PlayerSubsystemDamaged")
		
	# Instance handler for Kiska's menu
	pKiskaMenu = Bridge.BridgeUtils.GetBridgeMenu("Helm")
	if (pKiskaMenu != None):
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL,			__name__ + ".HailHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		# Instance handler for warp button
		pWarpButton = Bridge.BridgeUtils.GetWarpButton()
		if (pWarpButton != None):
			pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")

	# Instance handler for Miguel's menu
	pMiguelMenu = Bridge.BridgeUtils.GetBridgeMenu("Science")
	if (pMiguelMenu != None):
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN,		__name__ + ".ScanHandler")
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
	
	# Instance handlers for Saffi's menu
	pSaffiMenu = Bridge.BridgeUtils.GetBridgeMenu("XO")
	if (pSaffiMenu != None):
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
	
	# Instance handlers for Felix's menu
	pFelixMenu = Bridge.BridgeUtils.GetBridgeMenu("Tactical")
	if (pFelixMenu != None):
		pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
	
	# Instance handlers for Brex's menu
	pBrexMenu = Bridge.BridgeUtils.GetBridgeMenu("Engineer")
	if (pBrexMenu != None):
		pBrexMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,		__name__ + ".CommunicateHandler")

	# Handlers for the menu up and down event sent to the charater
	g_pFelix.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pSaffi.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pKiska.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pMiguel.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
	g_pBrex.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")

	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicard.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		
################################################################################
##	EnterSet()
##	
##	Event handler called whenever an object enters a set.
##	
##	Args: 	TGObject	- TGObject object.
##			pEvent		- The ScriptAction object.
##	
##	Return: None
################################################################################
def EnterSet(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	# Make sure it's a ship, return if not
	if (pShip == None):
		return
		
	pSet 		= pShip.GetContainingSet()
	sSetName 	= pSet.GetName()
	sShipName	= pShip.GetName()
	
	# Check and see if the Zhukov has entered the set
	if (sShipName == "Zhukov") and (sSetName == "Tevron2"):
		global g_bZhukovArrives
		g_bZhukovArrives = TRUE
		ZhukovEntersSet()

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ExitSet()
##	
##	Event handler called whenever an object leaves a set.
##	
##	Args: 	TGObject	- TGObject object.
##			pEvent		- The ScriptAction object.
##	
##	Return: None
################################################################################
def ExitSet(TGObject, pEvent):
	# Check and see if the mission is terminating
	if (g_bMissionTerminate != 1):
		return

	pShip		= App.ShipClass_Cast(pEvent.GetDestination())
	sSetName	= pEvent.GetCString()

	# Make sure it's a ship, return if not
	if (pShip == None):
		return
	
	sShipName	= pShip.GetName()

	# See where the player is going
	if (sShipName == "player"):
		PlayerExitsSet()
	
	# See if it's one of the Warbirds that has left
	if (sShipName in g_lEnemyShips):
		global g_lEnemyShips
		g_lEnemyShips.remove(sShipName)
		if (len(g_lEnemyShips) == 0):
			WarbirdsLeft()
	
	# We're done. Let any other event handlers for this event handle it
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ObjectDying()
##
##	Event handler called when an object starts dying.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ObjectDying(TGObject, pEvent):
	# Check and see if the mission is terminating
	if (g_bMissionTerminate != 1):
		return
		
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	pSet	= pShip.GetContainingSet()
	
	sShipName	= pShip.GetName()
	sSetName	= pSet.GetName()

	#  If the Sovereign was destroyed, mission lost
	if (sShipName == "Sovereign"):
		MissionLostSovereign()
		
	# Mission loss if either of the Klingons are destroyed
	elif (sShipName == "RanKuf") or (sShipName == "Trayor"):
		MissionLostKlingon(sShipName)
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ShipIdentified()
##
##	Event handler called when a ship is identified with the sensors.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent 		- The event that was sent.
##
##	Return:	None
################################################################################
def ShipIdentified(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sShipName = pShip.GetName()
	
	# If the player has IDd one of the friendly ships, set our
	# flag that will allow the hail dialogue to be played.
	if (sShipName in g_lFriendlyShips) and (g_bShipsIDd == FALSE):
		global g_bShipsIDd
		g_bShipsIDd = TRUE
		
	# We're done. Let any other event handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	CloakStarted()
##
##	Event handler called when a ship starts to cloak.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CloakStarted(TGObject, pEvent):
	# Get the ship that is cloaking
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
		
	sShipName	= pShip.GetName()

	# See if the Warbirds are cloaking for the first time after the cutscene
	if (sShipName == "Warbird 1") and (g_bFirstCloakDone == FALSE) and (g_bSovHailDone == TRUE):
		# Set the flag
		global g_bFirstCloakDone
		g_bFirstCloakDone = TRUE
	
	# Set our flag the second time the first Warbird cloaks
	elif (sShipName == "Warbird 1") and (g_bFirstCloakDone == TRUE) and (g_bSecondCloakDone == FALSE):
		global g_bSecondCloakDone
		g_bSecondCloakDone = TRUE
		
	# All done, let the next handler have the event
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	DecloakStarted()
##
##	Event handler called when a ship starts to decloak.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def DecloakStarted(TGObject, pEvent):
	# Get the destination - the ship that is decloaking.
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
		
	sShipName	= pShip.GetName()
	
	# See if we're decloaking after the first "real" cloak.
	if (sShipName == "Warbird 1") and (g_bFirstCloakDone == TRUE) and (g_bSecondCloakDone == FALSE):
		WarbirdSecondDecloak()

################################################################################
##	ResolutionChanged()
##
##	Broadcast handler called when the resolution changes.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ResolutionChanged(TGObject, pEvent):
	# See what the resolution is at now, and save the old font group.
	import MainMenu.mainmenu
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	pFontGroup = App.g_kFontManager.GetDefaultFont()
	App.g_kFontManager.SetDefaultFont(MainMenu.mainmenu.g_pcFlightSmallFont, MainMenu.mainmenu.g_kFlightSmallFontSize[pMode.GetCurrentResolution()])

	# Set the value of our resolution global
	GetCurrentResolution()
	
	# Get the list of IDds
	lBoxIds = GetBoxIDList()
	
	# Create a list of boxes that are visible
	lVisibleBoxes = []
	for idBox in lBoxIds:
		pInfoBox = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(idBox))
		if (pInfoBox == None):
			lVisibleBoxes.append(0)
		else:
			lVisibleBoxes.append(pInfoBox.IsVisible())	
				
	
	# Recreate all the info boxes so they are the right size
	# for the new resolution
	SetupSubsystemTargetingInfoBoxes()
	SetupRepairInfoBoxes()
	
	# Get the list of box IDs again since they are different
	lBoxIds = GetBoxIDList()
	# Make visible any boxes that were visible before	
	for iCounter in range (len(lVisibleBoxes)):
		if (lVisibleBoxes[iCounter]):
			pInfoBox = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(lBoxIds[iCounter]))
			if (pInfoBox != None):
				pInfoBox.SetVisible()

	# All done, call our next handler. Restore the old font first.
	App.g_kFontManager.SetDefaultFont(pFontGroup.GetFontName(), pFontGroup.GetFontSize())
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	GetBoxIDList()
##
##	Helper function that creates and returns a list of all info box global IDd
##
##	Args:	None
##
##	Return:	lBoxIDs	- List of info box IDs
################################################################################
def GetBoxIDList():
	# Create the list
	lBoxIDs =	[ 
				g_idSubsystemTargetBox1, g_idSubsystemTargetBox2, g_idRepairBox1,
				g_idRepairBox2, g_idRepairBox3
				]
				
	return lBoxIDs
		
################################################################################
##	FriendlyFireReportHandler()
##
##	Handler called if player has done enough damage to a friendly ship to get
##	Saffi to warn them.
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
	
	# If we need to, do our special line
	fTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - g_pSaffi.GetLastTalkTime()
	if (fTimeSinceTalk < 5.0):
		# All done, so call our next handler
		TGObject.CallNextHandler(pEvent)
		return
	else:
		# See who is being fired on and do the correct line
		if (sShipName == "RanKuf") or (sShipName == "Trayor"):
			# Get Draxon
			pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pKiskaFire1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0FireKlingons1", None, 0, g_pMissionDatabase)
			pDraxonFire2	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0FireKlingons2", None, 0, g_pMissionDatabase)

			pSequence.AppendAction(pKiskaFire1)
			pSequence.AppendAction(pDraxonFire2)

			# Register and play
			App.TGActionManager_RegisterAction(pSequence, "FriendlyFireWarning")
			pSequence.Play()
						
			return
			
		elif (sShipName == "Sovereign"):
			# Do Saffi's line
			pSequence = App.TGSequence_Create()
			pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0FireSov1", "Captain", 1, g_pMissionDatabase))
			App.TGActionManager_RegisterAction(pSequence, "FriendlyFireWarning")
			pSequence.Play()
			return
			
	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	FriendlyFireGameOverHandler()
##
##	Handler called if player does enough damage to friendly ship to get game
##	over.  We don't call the next handler because the game is over.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def FriendlyFireGameOverHandler(TGObject, pEvent):
	# Do the line from Saffi and end the game
	pSequence = App.TGSequence_Create()
	# If the viewscreen is on, turn it off
	if (MissionLib.g_bViewscreenOn == TRUE):
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	
	pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0FireFriend1", "Captain", 1, g_pMissionDatabase))
	
	# End the mission
	pGameOverSequence = App.TGSequence_Create()
	pGameOverSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "GameOver", pSequence))
	App.TGActionManager_RegisterAction(pGameOverSequence, "FriendlyFireGameOver")
	pGameOverSequence.Play()
	
	# Kill all the sequences
	App.TGActionManager_KillActions("Generic")
	App.TGActionManager_KillActions("MissionWin")
	
	return
	
################################################################################
##	TacticalToggleHandler()
##
##	Handler called when view between bridge and tactical is toggled.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def TacticalToggleHandler(TGObject, pEvent):
	# If we're in a tutorial sequence, just return to keep the
	# player on the bridge
	if (g_bInTutorial == TRUE):
		return
		
	# All done, pass it on to the next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	MapToggleHandler()
##
##	Handler called when player tries to toggle to map mode.  Also handles event
##	for toggling to cinematic mode.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def MapToggleHandler(TGObject, pEvent):
	# If the player is in the tutorial, just bail
	# and keep the player on the bridge.
	if (g_bInTutorial == TRUE):
		return
		
	# All done, pass on to the next handler
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	WarbirdSystemDisabled()
##
##	Event handler called when a system on a Warbird is disabled.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WarbirdSystemDisabled(TGObject, pEvent):
	# Get the system that was disabled.
	pSubsystem = App.ShipSubsystem_Cast(pEvent.GetSource())
	if (pSubsystem == None):
		return

	pParent = pSubsystem.GetParentSubsystem()

	#See if one of the warp engines has been knocked out.
	if (pParent != None):
		if (App.WarpEngineSubsystem_Cast(pParent)):
			# Call our function to have the Warbirds warp out.
			WarbirdsWarpOut()
	
		# See if one of the impulse engines have been disabled
		if (App.ImpulseEngineSubsystem_Cast(pParent)):
			WarbirdsWarpOut()
			
	# All done with this event, let the next handler have it
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	WarbirdWeaponFired()
##
##	Handler called when Warbird 1 fires their weapon.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WarbirdWeaponFired(TGObject, pEvent):
	# If this is the first time firing,
	# call our sequence
	if (g_bWarbirdsOpenFire == FALSE):
		global g_bWarbirdsOpenFire
		g_bWarbirdsOpenFire = TRUE
		WarbirdsAttack()

	# All done with this event, pass it on.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	WeaponHitSov()
##
##	Event handler called when Sovereign is hit by a weapon.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WeaponHitSov(TGObject, pEvent):
	# Find out who hit us.
	pAttacker = App.ShipClass_Cast(pEvent.GetFiringObject())
	if (pAttacker == None):
		return
		
	sAttackerName = pAttacker.GetName()
	
	# If it was one of the Warbirds, call our function
	if (sAttackerName in g_lEnemyShips):
		DoDamageToTheSovereign()
	
	# All done with this event, send it on.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	PlayerSubsystemDamaged()
##
##	Handler called when a subsystem on the players ship is damaged.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PlayerSubsystemDamaged(TGObject, pEvent):
	# Get the subsystem that was damaged
	pObjectPtr	= pEvent.GetObjPtr()
	if (pObjectPtr == None):
		return
		
	# Get the ID of the subsystem and store it in the list if it's unique
	global g_lDamagedSubsystems
	iSubsystemID	= pObjectPtr.GetObjID()
	if not (iSubsystemID in g_lDamagedSubsystems):
		g_lDamagedSubsystems.append(iSubsystemID)
		
	# If we have more than 5 damaged subsystems,
	# have Picard suggest the repair.
	if (len(g_lDamagedSubsystems) > 5) and (g_pPicardSuggestRepair == FALSE):
		global g_pPicardSuggestRepair
		g_pPicardSuggestRepair = TRUE
		PicardSuggestRepair()
	
	# All done with this event, call our next handler.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	HailHandler()
##
##	Instance handler called when Kiska's hail button is hit.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent 		- The event that was sent.
##
##	Return:	None
################################################################################
def HailHandler(TGObject, pEvent):
	# Get the players set.
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
		
	sSetName = pSet.GetName()
	
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if (pTarget == None):
		return
	sTargetName	= pTarget.GetName()
	
	# See if we're hailing the Sovereign for the first time
	if (sTargetName == "Sovereign") and(g_bSovHailDone == FALSE) and (sSetName == "Tevron2"):
		MissionLib.CallWaiting(None, TRUE)
		pKiskaHailOpen1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 0, g_pGeneralDatabase)
		pKiskaHailOpen1.Play()
		PlayerHailsSov(None)
	
	# See if we're hailing the RanKuf for the first time
	elif (sTargetName == "RanKuf") and (g_bRanKufHailDone == FALSE) and (sSetName == "Tevron2"):
		MissionLib.CallWaiting(None, TRUE)
		pKiskaHailOpen1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 0, g_pGeneralDatabase)
		pKiskaHailOpen1.Play()
		PlayerHailsDraxon(None)
	
	# See if we're hailing the Sovereign at Starbase 12
	elif (sTargetName == "Sovereign") and (g_bHailSovAtSB == FALSE) and (sSetName == "Starbase12"):
		global g_bHailSovAtSB
		g_bHailSovAtSB = TRUE
		MissionLib.CallWaiting(None, TRUE)
		HailSovAtStarbase()
	
	# See if we're hailing the Zhukov at Starbase 12
	elif (sTargetName == "Zhukov") and (g_bHailZhukovAtSB == FALSE) and (sSetName == "Starbase12"):
		global g_bHailZhukovAtSB
		g_bHailZhukovAtSB = TRUE
		MissionLib.CallWaiting(None, TRUE)
		HailZhukovAtSB()
		
	# Do the default
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	WarpButtonHandler()
##
##	Handler called when warp button is pressed
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WarpButtonHandler(TGObject, pEvent):
	# Get Kiska's destination
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu == None):
		return
		
	pWarpButton	= Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return
	pString	= pWarpButton.GetDestination()
	
	# Check if Picard is on still on the bridge, and keep the
	# player from warping until he's off.
	if (g_bPicardLeft == FALSE) or (g_bMissionWin == FALSE):
		# Do the line from Saffi
		pSaffiLine = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0PlayerLeaves4", "Captain", 1, g_pMissionDatabase)
		pSaffiLine.Play()
		return
		
	# If the player is leaving the set and going to the next mission,
	# do our cutscene.
	if (pString == "Systems.Vesuvi.Vesuvi6") and (g_bMissionWin == TRUE):
		# If it's playing, stop the MissionWin sequences
		App.TGActionManager_KillActions("MissionWin")
		
		pCutsceneSequence = App.TGScriptAction_Create("Maelstrom.Episode2.E2M1.Ep2Cutscene", "PlayCutscene")
		pWarpButton.AddActionAfterDuringWarp(pCutsceneSequence)
		
	# Call the next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ScanHandler()
##
##	Called when the "Scan" button in Miguel's menu is hit.  Performs tasks
##	based on what system we're in.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ScanHandler(TGObject, pEvent):
	# If the players sensors are off, do the default thing and bail
	pPlayer = MissionLib.GetPlayer()
	if(pPlayer == None):
		return
	pSensors = pPlayer.GetSensorSubsystem()
	if (pSensors == None):
		TGObject.CallNextHandler(pEvent)
		return
	if (pSensors.IsOn() == FALSE):
		TGObject.CallNextHandler(pEvent)
		return
	# See if we're scanning the area.
	iScanType = pEvent.GetInt()
	# Get the set the player is in.
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
		
	# See what type of scan we're doing.
	if (iScanType == App.CharacterClass.EST_SCAN_AREA):
		# We're scanning the area so see what set it is.
		if (pSet.GetName() == "Tevron2") and (g_bShipsIDd == FALSE):
			# Get the sensors and the scan sequence
			pPlayer = MissionLib.GetPlayer()
			if (pPlayer == None):
				return
			pSensors = pPlayer.GetSensorSubsystem()
			if (pSensors != None):	
				pSequence		= App.TGSequence_Create()
				pScanSequence	= pSensors.ScanAllObjects()
				pMiguelScan		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "MiguelScan", None, 0, g_pGeneralDatabase)
				
				pSequence.AppendAction(pMiguelScan)
				pSequence.AppendAction(pScanSequence)
			
				# Register and play
				App.TGActionManager_RegisterAction(pSequence, "Generic")
				pSequence.Play()
				
				# Return so we don't call the default behavior
				return
				
	# Nothing else to do.  Let any other events for this event handle it
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	CommunicateHandler()
##
##	Handler called when one of the crews communicate buttons is hit.  Checks
##	the mission state and calls functions that play the dialogue specific to
##	that part of the mission.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CommunicateHandler(TGObject, pEvent):
	# Get the menu that was clicked
	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())

	# Check the mission state variable and call our functions.
	if (g_iMissionState == ARRIVE_TEVRON):
		ArriveTevronCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == WARBIRDS_ATTACK):
		WarbirdsAttackCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == ATTACK_OVER):
		AttackOverCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	else:
		# Do the default thing
		TGObject.CallNextHandler(pEvent)

################################################################################
##	HandleMenuEvent()
##
##	Handler called when a characters menu is brought up or down.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def HandleMenuEvent(TGObject, pEvent):
	# If our flag is true, do nothing so the menu
	# won't open or close
	if (g_bCharWindowLock == TRUE):
		return
		
	# All done, do the normal stuff
	TGObject.CallNextHandler(pEvent)
		
################################################################################
##	PlayerExitsSet()
##
##	Called if player exits a set.  Checks and see's where the player is heading.
##
##	Args:	None
##
##	Return: None	
################################################################################
def PlayerExitsSet():
	# Get Kiska's warp heading and see where were headed
	pSet	= App.g_kSetManager.GetSet("bridge")
	pKiska	= App.CharacterClass_GetObject(pSet, "Helm")
	# Make sure pKiska exists
	if (pKiska == None):
		return
		
	pMenu		= pKiska.GetMenu()
	pWarpButton	= Bridge.BridgeUtils.GetWarpButton()
	if (pWarpButton == None):
		return
		
	pString		= pWarpButton.GetDestination()
	
	# See if the player is bailing before the mission is over
	if (g_bWarbirdsWarpCalled == FALSE) and (pString != "Systems.Tevron.Tevron2"):
		# They're bailing, so set our flag and start the
		# prod timer
		global g_bPlayerNotInTevron
		g_bPlayerNotInTevron = TRUE
		RestartProdTimer(None, 20)
		
	elif (g_bPlayerNotInTevron == TRUE) and (pString == "Systems.Tevron.Tevron2"):
		# Player is going back to Tevron, so clear our flags
		# and stop the prod timer
		global g_bPlayerNotInTevron
		g_bPlayerNotInTevron = FALSE
		StopProdTimer()

		# Reset the prod counter
		global g_iPlayerNotInTevron
		g_iPlayerNotInTevron = 1
		
################################################################################
##	PlayerEntersTevron()
##
##	Sequence that plays when the player starts mission.  Plays after player
##	has finished warping.  After first dialogue plays, runs script action that
##	checks to see if the Sov has been IDd.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing..
################################################################################
def PlayerEntersTevron(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check and see if the player is in warp.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
		
	pWarp = pPlayer.GetWarpEngineSubsystem()
	if (pWarp == None):
		return 0

	if MissionLib.IsPlayerWarping():
		# Delay sequence 1 second1.
		pSequence = App.TGSequence_Create()
		pEnterTevron	= App.TGScriptAction_Create(__name__, "PlayerEntersTevron")
		pSequence.AppendAction(pEnterTevron, 1)
		pSequence.Play()

		return 0
		
	else:
		# Set our mission state
		global g_iMissionState
		g_iMissionState = ARRIVE_TEVRON

		# Get the characters we need
		pPicard		= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")

		pSequence = App.TGSequence_Create()

		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaArrive1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0ArriveTevron1", "Captain", 1, g_pMissionDatabase)
		pSaffiArrive2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0ArriveTevron2", None, 0, g_pMissionDatabase)
		pMiguelArrive3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0ArriveTevron3", "Captain", 1, g_pMissionDatabase)
		pShipsIDd		= App.TGScriptAction_Create(__name__, "FriendliesIDd")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pKiskaArrive1)
		pSequence.AppendAction(pSaffiArrive2)
		pSequence.AppendAction(pMiguelArrive3)
		pSequence.AppendAction(pShipsIDd)

		MissionLib.QueueActionToPlay(pSequence)

		# Register our first goal
		MissionLib.AddGoal("E2ProtectSovGoal")
	
		return 0
		
################################################################################
##	FriendliesIDd()
##
##	Called as script action from PlayerEntersTevron().  Checks g_bShipsIDd and
##	plays the dialogue when it become true.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def FriendliesIDd(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check the value and see if it's time to play
	if (g_bShipsIDd == TRUE):
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pMiguelIDd1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0SovIDd1", "Captain", 1, g_pMissionDatabase)
		pCheckHail	= App.TGScriptAction_Create(__name__, "CheckIfHailed")
		
		pSequence.AppendAction(pMiguelIDd1)
		pSequence.AppendAction(pCheckHail)
		
		MissionLib.QueueActionToPlay(pSequence)
		
		# Start the timer for the hails
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_HAIL_TIMER, __name__ + ".CanSotoHail", fStartTime + 30, 0, 0)
		
	# The ships still haven't been IDd so recheck in 2 sec.
	else:
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "FriendliesIDd"), 2.0)
		pSequence.Play()

	return 0

################################################################################
##	CheckIfHailed()
##
##	Script action that checks flag to see if the player is hailing.  If not,
##	plays Kiska's prompt to hail.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CheckIfHailed(pTGAction):
	# Bail if we are already hailing
	if (g_bSovHailDone == TRUE) or (g_bRanKufHailDone == TRUE):
		return 0
	
	else:
		# Haven't hailed so do Kiska's line
		pKiskaIDd1a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0SovIDd1a", "Captain", 0, g_pMissionDatabase)
		pKiskaIDd1a.Play()
		
	return 0
	
################################################################################
##	CanSotoHail()
##
##	Called from timer.  Checks to see if the player has started hailing people
##	and has Soto hail them if not.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CanSotoHail(TGObject, pEvent):
	# Check both the flags and bail if either is true
	if (g_bSovHailDone == TRUE) or (g_bRanKufHailDone == TRUE):
		return
		
	else:
		# Engage CallWaiting()
		MissionLib.CallWaiting(None, TRUE)
		pKiskaIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg1", None, 0, g_pGeneralDatabase)
		pKiskaIncoming.Play()
		PlayerHailsSov(None)
		
################################################################################
##	PlayerHailsSov():
##
##	Called from HailHandler() if player hails the Sovereign or by timer event if
##	player is too slow.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PlayerHailsSov(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check and set our flag
	if (g_bSovHailDone == FALSE):
		global g_bSovHailDone
		g_bSovHailDone = TRUE
	else:
		return 0
		
	# Get the characters we need
	pSoto		= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("EBridgeSet"), "Soto")
	pPicard		= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")

	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaSotoHail1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0SotoHail1", "Captain", 1, g_pMissionDatabase)
	pEBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Soto", 0, 0, 0)
	pSotoHail2			= App.CharacterAction_Create(pSoto, App.CharacterAction.AT_SAY_LINE, "E2M0SotoHail2", None, 0, g_pMissionDatabase)
	pSotoHail3			= App.CharacterAction_Create(pSoto, App.CharacterAction.AT_SAY_LINE, "E2M0SotoHail3", None, 0, g_pMissionDatabase)
	pSotoHail3a			= App.CharacterAction_Create(pSoto, App.CharacterAction.AT_SAY_LINE, "E2M0SotoHail3a",  None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pPicardSotoHail4	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0SotoHail4", "Captain", 1, g_pMissionDatabase)

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaSotoHail1)
	pSequence.AppendAction(pEBridgeViewOn)
	pSequence.AppendAction(pSotoHail2)
	pSequence.AppendAction(pSotoHail3)
	pSequence.AppendAction(pSotoHail3a)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pPicardSotoHail4)

	# If we are hailing the Sovereign first,
	# play the hail from Draxon or start the cutscene
	# if we've done all the hailing
	if (g_bRanKufHailDone == FALSE):
		pKiskaIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg2", None, 0, g_pGeneralDatabase)
		pDraxonHail		= App.TGScriptAction_Create(__name__, "PlayerHailsDraxon")
		pSequence.AppendAction(pKiskaIncoming)
		pSequence.AppendAction(pDraxonHail)
	else:
		pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pWarbirdsDecloak 	= App.TGScriptAction_Create(__name__, "WarbirdsDecloak")
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AddAction(pWarbirdsDecloak, pViewOff, 4)
			
	# Register and play
	App.TGActionManager_RegisterAction(pSequence, "Generic")
	pSequence.Play()

	return 0
	
################################################################################
##	PlayerHailsDraxon()
##
##	Called from HailHandler() if the player hails the RanKuf.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from  crashing.
###############################################################################
def PlayerHailsDraxon(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check and set our flag
	if (g_bRanKufHailDone == FALSE):
		global g_bRanKufHailDone
		g_bRanKufHailDone = TRUE
	else:
		return 0
		
	# Get the characters we need
	pDraxon		= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonsSet"), "Draxon")

	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaDraxonHail1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0DraxonHail1", "Captain", 1, g_pMissionDatabase)
	pKlingonViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KlingonSet", "Draxon", 0, 0, 0)
	pDraxonHail2		= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0DraxonHail2", None, 0, g_pMissionDatabase)
	pDraxonHail3		= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0DraxonHail3", None, 0, g_pMissionDatabase)
	pSaffiDraxonHail4	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0DraxonHail4", None, 0, g_pMissionDatabase)
	pDraxonHail5		= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0DraxonHail5", None, 0, g_pMissionDatabase)
	pFelixDraxonHail6	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0DraxonHail6", None, 0, g_pMissionDatabase)
	pDraxonHail7		= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0DraxonHail7", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")	
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaDraxonHail1)
	pSequence.AppendAction(pKlingonViewOn)
	pSequence.AppendAction(pDraxonHail2)
	pSequence.AppendAction(pDraxonHail3)
	pSequence.AppendAction(pSaffiDraxonHail4)
	pSequence.AppendAction(pDraxonHail5)
	pSequence.AppendAction(pFelixDraxonHail6)
	pSequence.AppendAction(pDraxonHail7)
	pSequence.AppendAction(pViewOff)

	# If we are hailing the RanKuf first, then start the
	# Soto hail, if not then do WarbirdsDecloak.
	if (g_bSovHailDone == FALSE):
		pKiskaIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg2", None, 0, g_pGeneralDatabase)
		pSotoHail		= App.TGScriptAction_Create(__name__, "PlayerHailsSov")
		pSequence.AppendAction(pKiskaIncoming)
		pSequence.AppendAction(pSotoHail)
	else:
		pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pWarbirdsDecloak	= App.TGScriptAction_Create(__name__, "WarbirdsDecloak")
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AddAction(pWarbirdsDecloak, pFelixDraxonHail6, 12)

	# Register and play
	App.TGActionManager_RegisterAction(pSequence, "Generic")
	pSequence.Play()
	
	return 0
	
################################################################################
##	WarbirdsDecloak()
##
##	Creates and plays the sequence for the cutscene of the Warbirds decloaking.
##	Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep the callling sequence from crashing,
################################################################################
def WarbirdsDecloak(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1) or (MissionLib.GetPlayer() == None):
		return 0
		
	# Set our mission state
	global g_iMissionState
	g_iMissionState = WARBIRDS_ATTACK
	
	# Get the RanKuf and give it an AI to see if it helps collisions
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pRanKuf	= App.ShipClass_GetObject(pSet, "RanKuf")
	if (pRanKuf != None):
		import E2M0_AI_OrbitSov
		pRanKuf.SetAI(E2M0_AI_OrbitSov.CreateAI(pRanKuf))
	
	# Get the characters we need
	pRomulan	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("RomulanSet"), "Torenn")
	pDraxon		= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")

	pSequence = App.TGSequence_Create()

	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixDecloak1		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak1", "Captain", 0, g_pMissionDatabase)
	pCutsceneStart		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pCheckIfClear		= App.TGScriptAction_Create(__name__, "CheckIfPlayerClear")
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pLookForward		= App.TGScriptAction_Create("MissionLib", "LookForward")
	pMoveWarbirdsToSet	= App.TGScriptAction_Create(__name__, "CreateWarbirds")
	pFelixDecloak2		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak2", None, 1, g_pMissionDatabase)
	pStartTevronCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Tevron2")
	pSwitchTevron		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Tevron2")
	pStaticCamera		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "Tevron2", "CameraWatch", "WarbirdCamStatic")
	pMoveCamera			= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "Tevron2", "CameraWatch", "WarbirdCamStart")
	pDecloakWarbirds	= App.TGScriptAction_Create(__name__, "DecloakWarbirds")
	pChangeToBridge		= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pKiskaDecloak3		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak3", "Captain", 1, g_pMissionDatabase)
	pRomViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "RomulanSet", "Torenn")
	pRomulanDecloak4	= App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak4", None, 0, g_pMissionDatabase)
	pSaffiDecloak5		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak5", None, 0, g_pMissionDatabase)
	pRomulanDecloak6	= App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak6", None, 0, g_pMissionDatabase)
	pRomulanDecloak6a	= App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak6a", None, 0, g_pMissionDatabase)
	pRomulanDecloak7	= App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak7", None, 0, g_pMissionDatabase)
	pSaffiDecloak8		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak8", None, 0, g_pMissionDatabase)
	pRomulanDecloak9	= App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak9", None, 0, g_pMissionDatabase)
	pMiguelDecloak10	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak10", "Captain", 1, g_pMissionDatabase)
	pDraxonDecloak11	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak11", None, 0, g_pMissionDatabase)
	pRomulanDecloak12	= App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak12", None, 0, g_pMissionDatabase)
	pDraxonDecloak13	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak13", None, 0, g_pMissionDatabase)
	pFire1				= App.TGSoundAction_Create("Klingon Disruptor")
	pFire2				= App.TGSoundAction_Create("Klingon Disruptor")
	pFire3				= App.TGSoundAction_Create("Klingon Disruptor")
	pFire4				= App.TGSoundAction_Create("Klingon Disruptor")
	pFire5				= App.TGSoundAction_Create("Klingon Disruptor")
	pFelixDecloak14		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak14", "Captain", 1, g_pMissionDatabase)
	pRomulanDecloak15	= App.CharacterAction_Create(pRomulan, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsDecloak15", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")	
	pEndTevronCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Tevron2")
	pCutsceneEnd		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pGiveWarbirdsAI		= App.TGScriptAction_Create(__name__, "GiveWarbirdsAI")	
	pGiveKlingonsAI		= App.TGScriptAction_Create(__name__, "GiveKlingonsAI")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixDecloak1)
	pSequence.AppendAction(pCutsceneStart)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pLookForward)
	pSequence.AppendAction(pCheckIfClear)
	pSequence.AppendAction(pMoveWarbirdsToSet)
	pSequence.AppendAction(pFelixDecloak2)
	pSequence.AppendAction(pStartTevronCamera)
	pSequence.AppendAction(pSwitchTevron)
	pSequence.AppendAction(pStaticCamera)
	pSequence.AppendAction(pDecloakWarbirds)
	pSequence.AppendAction(pMoveCamera, 1.5)
	pSequence.AppendAction(pChangeToBridge, 12)	# Delay before switching to interior view
	pSequence.AppendAction(pKiskaDecloak3)
	pSequence.AppendAction(pRomViewOn)
	pSequence.AppendAction(pRomulanDecloak4)
	pSequence.AppendAction(pSaffiDecloak5)
	pSequence.AppendAction(pRomulanDecloak6)
	pSequence.AppendAction(pRomulanDecloak6a)
	pSequence.AppendAction(pRomulanDecloak7)
	pSequence.AppendAction(pSaffiDecloak8)
	pSequence.AppendAction(pRomulanDecloak9)
	pSequence.AppendAction(pMiguelDecloak10)
	pSequence.AppendAction(pDraxonDecloak11)
	pSequence.AppendAction(pRomulanDecloak12)
	pSequence.AppendAction(pDraxonDecloak13)
	pSequence.AppendAction(pFelixDecloak14)
	pSequence.AppendAction(pGiveWarbirdsAI)
	pSequence.AppendAction(pGiveKlingonsAI)
	pSequence.AppendAction(pRomulanDecloak15)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndTevronCamera)
	pSequence.AppendAction(pCutsceneEnd)
	
	# Add the sound effects of the BOPs firing
	pSequence.AddAction(pFire1, pDraxonDecloak13)
	pSequence.AddAction(pFire2, pDraxonDecloak13, 0.2)
	pSequence.AddAction(pFire3, pFire2)
	pSequence.AddAction(pFire4, pFire2, 0.3)
	pSequence.AddAction(pFire5, pFire4)
	
	# Register and play
	App.TGActionManager_RegisterAction(pSequence, "Generic")
	pSequence.Play()
	
	return 0

################################################################################
##	CheckIfPlayerClear()
##
##	Script action that checks to see if the player is in the way of the
##	Warbirds.  Moves them if necessary.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CheckIfPlayerClear(pTGAction):
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	if (pSet == None) or (g_bMissionTerminate != 1):
		return 0
		
	# Get the two Warbird placements.
	pPlace1	= App.PlacementObject_GetObjectBySetName("Tevron2", "Warbird1Start")
	pPlace2	= App.PlacementObject_GetObjectBySetName("Tevron2", "Warbird2Start")
	
	if (pPlace1 == None) or (pPlace2 == None):
		return 0
		
	pLocation1 = pPlace1.GetWorldLocation()
	pLocation2 = pPlace2.GetWorldLocation()
	
	# See if the placements are clear
	if (pSet.IsLocationEmptyTG(pLocation1, 15.0)) and (pSet.IsLocationEmptyTG(pLocation2, 15.0)):
		return 0
	else:
		# Player is in the way so move them.
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return 0
		pPlayer.PlaceObjectByName("PlayerBail")
		
	return 0
	
################################################################################
##	CreateWarbirds()
##
##	Script action that creates the Warbirds.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CreateWarbirds(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Shut Felix off if he's running.
	pFelixMenu = g_pFelix.GetMenu()
	if (pFelixMenu != None):
		pStopOrder = App.TGIntEvent_Create()
		pStopOrder.SetDestination(pFelixMenu)
		pStopOrder.SetEventType(App.ET_MANEUVER)
		pStopOrder.SetInt(Bridge.TacticalMenuHandlers.EST_ORDER_STOP)
		App.g_kEventManager.AddEvent(pStopOrder)

	# Get the needed set
	pTevron2Set		= App.g_kSetManager.GetSet("Tevron2")
	if (pTevron2Set == None) or (g_bMissionTerminate != 1):
		return 0
	
	pWarbird1	= loadspacehelper.CreateShip("E2M0Warbird", pTevron2Set, "Warbird 1", "Warbird1Start")
	pWarbird2	= loadspacehelper.CreateShip("E2M0Warbird", pTevron2Set, "Warbird 2", "Warbird2Start")
	
	# Cloak the Warbirds instantly
	MissionLib.Cloak(None, pWarbird1, TRUE)
	MissionLib.Cloak(None, pWarbird2, TRUE)
	
	# Make the Warbirds invincible
	pWarbird1.SetInvincible(TRUE)
	pWarbird2.SetInvincible(TRUE)

	# Set their Impulse engines invincible (we'll remove this after their first decloak)
	for pShip in [ pWarbird1, pWarbird2 ]:
		if (pShip != None):
			pImpulse = pShip.GetImpulseEngineSubsystem()
			if (pImpulse != None):
				MissionLib.MakeSubsystemsInvincible(pImpulse)

	# Instance handlers on both the Warbirds for system disabled events
	if (pWarbird1 != None):
		pWarbird1.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_DISABLED, __name__+".WarbirdSystemDisabled")
		# Instance handler for firing.
		pWarbird1.AddPythonFuncHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".WarbirdWeaponFired")
		
	if (pWarbird2 != None):
		pWarbird2.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_DISABLED, __name__+".WarbirdSystemDisabled")
	
	return 0

################################################################################
##	DecloakWarbirds()
##
##	Script action that de-cloaks the two Warbirds.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def DecloakWarbirds(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the Warbirds
	pSet = App.g_kSetManager.GetSet("Tevron2")
	pWarbird1 = App.ShipClass_GetObject(pSet, "Warbird 1")
	pWarbird2 = App.ShipClass_GetObject(pSet, "Warbird 2")
	
	if (pWarbird1 != None):
		MissionLib.DeCloak(None, pWarbird1)
	if (pWarbird2 != None):
		MissionLib.DeCloak(None, pWarbird2)
		
	return 0
		
################################################################################
##	GiveWarbirdsAI()
##
##	Assigns the AI to the two Warbirds.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def GiveWarbirdsAI(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the set and the ships
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pWarbird1	= App.ShipClass_GetObject(pSet, "Warbird 1")
	pWarbird2	= App.ShipClass_GetObject(pSet, "Warbird 2")

	# Create the condition we'll be using to tell the AI when the
	# player is in Help.
	global g_idPlayerInHelpCondition
	pPlayerInHelp = App.ConditionScript_Create(__name__, "PlayerInHelp")
	g_idPlayerInHelpCondition = pPlayerInHelp.GetObjID()

	# Import and assign the AI if the ships exist
	import E2M0_AI_Warbird
	if (pWarbird1 != None):
		pWarbird1.SetAI((E2M0_AI_Warbird.CreateAI(pWarbird1, g_pWarbird1Targets, pPlayerInHelp, "WarbirdWay1")), 0, 0)
	if (pWarbird2 != None):
		pWarbird2.SetAI((E2M0_AI_Warbird.CreateAI(pWarbird2, g_pWarbird2Targets, pPlayerInHelp, "WarbirdWay2")), 0, 0)

	return 0
	
################################################################################
##	GiveKlingonsAI()
##
##	Gets the two Klingon ships and assigns their AI.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def GiveKlingonsAI(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the set and the Klingon ships
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pRanKuf	= App.ShipClass_GetObject(pSet, "RanKuf")
	pTrayor	= App.ShipClass_GetObject(pSet, "Trayor")
	
	# If the ships exist, assign their AI
	import E2M0_AI_Klingon
	if (pRanKuf != None):
		pRanKuf.SetAI(E2M0_AI_Klingon.CreateAI(pRanKuf))
	if (pTrayor != None):
		pTrayor.SetAI(E2M0_AI_Klingon.CreateAI(pTrayor))
		
	return 0

################################################################################
##	WarbirdsAttack()
##
##	Called from WarbirdWeaponFired()  plays sequence that lets the player know the
##	Sovereign is being attacked by the Warbirds.
##
##	Args:	None
##
##	Return:	None
################################################################################
def WarbirdsAttack():
	# Get the characters we need
	pSoto	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("EBridgeSet"), "Soto")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixAttack1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsAttack1", "Captain", 1, g_pMissionDatabase)
	pFelixAttack2	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsAttack2", None, 0, g_pMissionDatabase)
	pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pKiskaAttack3	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg1", "Captain", 1, g_pGeneralDatabase)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Soto", 0.3, 0.6, 0)
	pSotoAttack4	= App.CharacterAction_Create(pSoto, App.CharacterAction.AT_SAY_LINE, "E2M0SovDamaged3", None, 0, g_pMissionDatabase)
	pViewOff1		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pRedAlertCheck	= App.TGScriptAction_Create(__name__, "RedAlertCheck")
		
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixAttack1)
	pSequence.AppendAction(pFelixAttack2)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pKiskaAttack3)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pSotoAttack4)
	pSequence.AppendAction(pViewOff1)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pRedAlertCheck)

	MissionLib.QueueActionToPlay(pSequence)

	# Add our Engage Warbirds goal
	MissionLib.AddGoal("E2EngageWarbirdsGoal")
	
################################################################################
##	DoDamageToTheSovereign()
##
##	Uses script to damage the Sovereign when it's first hit by the Warbirds.
##	Called from WeaponHitSov().
##
##	Args:	None
##
##	Return:	None
################################################################################
def DoDamageToTheSovereign():
	# Set our flag
	if (g_bSovDamaged == FALSE):
		global g_bSovDamaged
		g_bSovDamaged = TRUE
	else:
		return
		
	# Get the Sov
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pSov	= App.ShipClass_GetObject(pSet, "Sovereign")
	if (pSov == None):
		return
		
	# Remove the instance handler
	pSov.RemoveHandlerForInstance(App.ET_WEAPON_HIT, __name__+".WeaponHitSov")
	
	# Damage all the phasers below their disabled percentage
	pPhasers = pSov.GetPhaserSystem()
	if (pPhasers != None):
		# Get the phasers one by one and damage each of them.
		for iCounter in range(pPhasers.GetNumChildSubsystems()):
			pChild = pPhasers.GetChildSubsystem(iCounter)
			
			# Get a random number and use it to damage the system
			iNumber = App.g_kSystemWrapper.GetRandomNumber(pChild.GetDisabledPercentage() * 100.0)
			pChild.SetConditionPercentage(iNumber / 100.0)
	
	# Damage all the torpedoes
	pTorps = pSov.GetTorpedoSystem()
	if (pTorps != None):
		# Get the torps one by one and damage each below their disabled level
		for iCounter in range(pTorps.GetNumChildSubsystems()):
			pChild = pTorps.GetChildSubsystem(iCounter)
			iNumber = App.g_kSystemWrapper.GetRandomNumber(pChild.GetDisabledPercentage() * 100.0)
			pChild.SetConditionPercentage(iNumber / 100.0)
		
	# Damage the Sensor array
	pSensors = pSov.GetSensorSubsystem()
	if (pSensors != None):
		MissionLib.SetConditionPercentage(pSensors, 0.2)
		
################################################################################
##	WarbirdSecondDecloak()
##
##	Called from DecloakStarted() when the first Warbird decloaks the second
##	time.  Does sequence,
##
##	Args:	None
##
##	Return:	None
################################################################################
def WarbirdSecondDecloak():
	# Get Draxon and Picard
	pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")

	# Enable the targeting and repair buttons.
	if (pPicard != None):
		pPicardMenu	= pPicard.GetMenu()
		if (pPicardMenu != None):
			pSubsystems = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("SubsystemTarget"))
			if (pSubsystems != None):
				pSubsystems.SetEnabled()
			pRepair = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Repair"))
			if (pRepair != None):
				pRepair.SetEnabled()

	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pFelixAttack5	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsAttack5", None, 0, g_pMissionDatabase)
	pKiskaAttack6	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsAttack6", "Captain", 1, g_pMissionDatabase)
	pKlingonViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KlingonSet", "Draxon", 0, 0, 0)
	pDraxonAttack7	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0WarbirdsAttack7", None, 0, g_pMissionDatabase)
	pViewOff2		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pSaffiReport1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0FelixReport1", None, 0, g_pMissionDatabase)
	pFelixReport1a	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0FelixReport1a", None, 0, g_pMissionDatabase)
	pPicardReport4a	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0FelixReport4a", "Captain", 0, g_pMissionDatabase)
	pPicardTarget1	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardTargeting1", None, 0, g_pMissionDatabase)
	pWarbirdImpulse	= App.TGScriptAction_Create(__name__, "MakeWarbirdImpulseNotInvincible")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pFelixAttack5)
	pSequence.AppendAction(pKiskaAttack6)
	pSequence.AppendAction(pKlingonViewOn)
	pSequence.AppendAction(pDraxonAttack7)
	pSequence.AppendAction(pViewOff2)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pSaffiReport1)
	pSequence.AppendAction(pFelixReport1a)
	pSequence.AppendAction(pPicardReport4a)
	pSequence.AppendAction(pPicardTarget1)
	pSequence.AppendAction(pWarbirdImpulse)
	
	# Register and play
	MissionLib.QueueActionToPlay(pSequence)
	
	# Start our first Picard Tip timer
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_PICARD_AUDIO_TIMER, __name__ + ".PicardTip", fStartTime + 150, 0, 0)

	# Start the timer that will have Warbirds attack player
	MissionLib.CreateTimer(ET_ATTACK_PLAYER_TIMER, __name__ + ".AddPlayerToTargets", fStartTime + 20, 0, 0)

################################################################################
##	MakeWarbirdImpulseNotInvincible()
##
##	Script action that removes the invincible status of the Warbirds impulse
##	engines.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MakeWarbirdImpulseNotInvincible(pTGAction):
	# Get the Warbirds
	pSet = App.g_kSetManager.GetSet("Tevron2")
	for sName in g_lEnemyShips:
		pShip = App.ShipClass_GetObject(pSet, sName)
		if (pShip != None):
			# Set their Impulse engines NOT invincible.
			pImpulse = pShip.GetImpulseEngineSubsystem()
			if (pImpulse != None):
				MissionLib.MakeSubsystemsNotInvincible(pImpulse)

	return 0
	
################################################################################
##	AddPlayerToTargets()
##
##	Called from timer event.  Adds the players ship to the Warbirds target
##	group.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def AddPlayerToTargets(TGObject, pEvent):
	# Get the players name
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	
	# FIXME: We can change this based on the difficulty
	# Get the target lists and add the player to them.
	global g_pWarbird1Targets
	global g_pWarbird2Targets
	g_pWarbird1Targets[pPlayer.GetName()]	= {"Priority" : 3.0}
	g_pWarbird1Targets["RanKuf"]			= {"Priority" : 0.0}
	g_pWarbird1Targets["Trayor"]			= {"Priority" : 0.0}
	
	g_pWarbird2Targets[pPlayer.GetName()]	= {"Priority" : 1.0}
	g_pWarbird2Targets["RanKuf"]			= {"Priority" : 0.0}
	g_pWarbird2Targets["Trayor"]			= {"Priority" : 0.0}
	
################################################################################
##	RedAlertCheck()
##
##	Called as script action.  Checks to see if the player is at red alert, and
##	if not will prod them to go to red alert and engage the Warbirds.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def RedAlertCheck(pTGAction):
	# Get the players ship
	pPlayer = App.ShipClass_Cast(MissionLib.GetPlayer())
	if (pPlayer == None) or (g_bMissionTerminate != 1):
		return	0
	
	# If the player is at red alert
	if (pPlayer.GetAlertLevel() == App.ShipClass.RED_ALERT):
		pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
		
		pPicardAlertLine	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0GoToRedAlert3", "Captain", 1, g_pMissionDatabase)
		pPicardAlertLine.Play()
		
	# If the player is not at red alert
	else:
		pSequence = App.TGSequence_Create()
		pSaffiAlertLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0GoToRedAlert1", "Captain", 1, g_pMissionDatabase)
		pAlertProd		= App.TGScriptAction_Create(__name__, "AlertProd")
		
		pSequence.AppendAction(pSaffiAlertLine)
		pSequence.AppendAction(pAlertProd, 10)
		
		# Register and play
		App.TGActionManager_RegisterAction(pSequence, "Generic")
		pSequence.Play()
		
	return 0
	
################################################################################
##	AlertProd()
##
##	Called as script action.  Bugs the player about going to red alert if they
##	have not already done so.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def AlertProd(pTGAction):
	# Get the players ship and check the alert level.
	pPlayer = App.ShipClass_Cast(MissionLib.GetPlayer())
	if (pPlayer == None) or (g_bMissionTerminate != 1):
		return 0
		
	if (pPlayer.GetAlertLevel() != App.ShipClass.GREEN_ALERT):
		# We're not at red alert, so do our prod
		pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
		
		pSequence = App.TGSequence_Create()
		
		pSaffiAlertProd1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0RedAlertProd1", "Captain", 1, g_pMissionDatabase)
		pPicardAlertProd2	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0RedAlertProd2", "Captain", 1, g_pMissionDatabase)
		
		pSequence.AppendAction(pSaffiAlertProd1)
		pSequence.AppendAction(pPicardAlertProd2)
		
		# Register and play
		App.TGActionManager_RegisterAction(pSequence, "Generic")
		pSequence.Play()
		
	return 0

################################################################################
##	PicardSuggestRepair()
##
##	Plays line suggesting the player check the reapir menu, and creates the
##	tutorial button in Picard's menu.  Called from PlayerSubsystemDamaged() and
##	WarbirdsWarpOut() as a script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PicardSuggestRepair(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the Picard
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	
	# Do his line
	pPicardLine	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardRepair1", "Captain", 0, g_pMissionDatabase)
	# If we were not called as a script action, queue the line
	if (pTGAction == None):
		MissionLib.QueueActionToPlay(pPicardLine)
	else:
		pPicardLine.Play()
	
	# Change the priority of the player as a target
	if (g_bWarbirdsWarpCalled == FALSE):
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer != None):
			global g_pWarbird1Targets
			g_pWarbird1Targets[pPlayer.GetName()]	= {"Priority" : 0.0}

	return 0
	
################################################################################
##	SovDamaged()
##
##	Called when from E2M0_AI_Sovereign.py when the Sovereigns critical systems
##	fall below 50% and one of the shields is down.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SovDamaged():
	# Get Soto
	pSoto	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("EBridgeSet"), "Soto")

	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pMiguelShields1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0SovShieldsLow1", "Captain", 1, g_pMissionDatabase)
	pKiskaShields2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0SovShieldsLow2", "Captain", 1, g_pMissionDatabase)
	pEBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Soto", 0.7, 1, 0)
	pSotoShields3	= App.CharacterAction_Create(pSoto, App.CharacterAction.AT_SAY_LINE, "E2M0SovShieldsLow3", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)	

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pMiguelShields1)
	pSequence.AppendAction(pKiskaShields2)
	pSequence.AppendAction(pEBridgeViewOn)
	pSequence.AppendAction(pSotoShields3)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	KlingonTakingDamage()
##
##	Called from E2M0_AI_Klingon.py when the Klingon ship starts take damage.
##	Does short sequence.
##
##	Args:	sShipName	- String name of the ship that called us.
##
##	Return:	None
################################################################################
def KlingonTakingDamage(sShipName):
	# Do the sequence if it's the RanKuf
	if (sShipName == "RanKuf"):
		pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
		
		pSequence = App.TGSequence_Create()
		
		pKiskaDamage1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0KlingonDamaged1", "Captain", 1, g_pMissionDatabase)
		pDraxonDamage2	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0KlingonDamaged2", None, 0, g_pMissionDatabase)
		
		MissionLib.QueueActionToPlay(pSequence)

	# Sequence if it's the Trayor
	elif (sShipName == "Trayor"):
		pMiguelDamage3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0KlingonDamaged3", "Captain", 1, g_pMissionDatabase)
		MissionLib.QueueActionToPlay(pMiguelDamage3)
		
################################################################################
##	MissionLostSovereign()
##
##	Called from Object destroyed if the Sovereign was destroyed.  Ends game.
##
##	Args:	None
##
##	Return:	None
################################################################################
def MissionLostSovereign():
	# Set our flag
	if (g_bMissionLost == FALSE):
		global g_bMissionLost
		g_bMissionLost = TRUE
	else:
		return
		
	# Do our loss sequence
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	pLiu	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("StarbaseSet"), "Liu")
	
	pSequence = App.TGSequence_Create()
	
	# If the viewscreen is on, turn it off
	if (MissionLib.g_bViewscreenOn == TRUE):
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	pMiguelSov1		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0SovDestroyed1", "Captain", 1, g_pMissionDatabase)
	pPicardSov2		= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0SovDestroyed2", "Captain", 1, g_pMissionDatabase)
	pKiskaSov3		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0SovDestroyed3", "Captain", 0, g_pMissionDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet","Liu")
	pLiuSov4		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M0SovDestroyed4", None, 0, g_pMissionDatabase)
	pLiuSov5		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M0SovDestroyed5", None, 0, g_pMissionDatabase)
	pLiuSov6		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M0SovDestroyed6", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

	pSequence.AppendAction(pMiguelSov1)
	pSequence.AppendAction(pPicardSov2)
	pSequence.AppendAction(pKiskaSov3)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuSov4)
	pSequence.AppendAction(pLiuSov5)
	pSequence.AppendAction(pLiuSov6)
	pSequence.AppendAction(pViewOff)
	
	pGameOver	= App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()

	# Kill all the sequences
	App.TGActionManager_KillActions()
	MissionLib.DeleteQueuedActions()
	
################################################################################
##	MissionLostKlingon()
##
##	Called from ObjectDestroyed() if either of the Klingons are destroyed.
##	Ends game.
##
##	Args:	sShipName	- String name of ship destroyed.
##
##	Return:	None
################################################################################
def MissionLostKlingon(sShipName):
	# Set our flag
	if (g_bMissionLost == FALSE):
		global g_bMissionLost
		g_bMissionLost = TRUE
	else:
		return
	
	# See which line to play
	if (sShipName == "RanKuf"):
		pFelixKlingon1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0KlingonDestroyed1", "Captain", 1, g_pMissionDatabase)
	else:
		pFelixKlingon1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0KlingonDestroyed1a", "Captain", 1, g_pMissionDatabase)
	
	# Do our loss sequence
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	
	pSequence = App.TGSequence_Create()
	
	# If the viewscreen is on, turn it off
	if (MissionLib.g_bViewscreenOn == TRUE):
		pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

	pSaffiKlingon2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0KlingonDestroyed2", "Captain", 0, g_pMissionDatabase)
	pPicardKlingon3	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0KlingonDestroyed3", "Captain", 1, g_pMissionDatabase)
	pPicardKlingon4	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0KlingonDestroyed4", "Captain", 1, g_pMissionDatabase)

	pSequence.AppendAction(pFelixKlingon1)
	pSequence.AppendAction(pSaffiKlingon2)
	pSequence.AppendAction(pPicardKlingon3)
	pSequence.AppendAction(pPicardKlingon4)
	
	pGameOver	= App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()
	
	# Kill all the sequences
	App.TGActionManager_KillActions()
	MissionLib.DeleteQueuedActions()
	
################################################################################
##	WarbirdsWarpOut()
##
##	Called just before both the Warbirds warp out of the set by 
##	E2M0_AI_Warbird.py.  Does sequence that calls the Zhukov into the set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def WarbirdsWarpOut():
	# Don't play if we lost the mission
	if (g_bMissionLost == TRUE):
		return
		
	# Set our mission state
	global g_iMissionState
	g_iMissionState = ATTACK_OVER
	# Check our flag
	if (g_bWarbirdsWarpCalled == FALSE):
		global g_bWarbirdsWarpCalled
		g_bWarbirdsWarpCalled = TRUE
	else:
		return
	
	# Reset the Klingon's AI and the Warbirds
	ResetKlingonAI()
	ResetWarbirdAI()
	
	# Check the Warbirds conditions and play different lines based on that
	bCanCloak		= CheckCloakingSystems()
	bImpulseDamaged	= CheckImpulseSystems()
	
	
	# Build our sequence based on our flags
	if (bImpulseDamaged == TRUE):
		pFelixRetreat2	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0RomRetreat2", None, 0, g_pMissionDatabase)
	else:
		pFelixRetreat2	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0RomRetreat2a", None, 0, g_pMissionDatabase)
	
	if (bCanCloak == TRUE):
		pMiguelRetreat3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0RomRetreat3", "Captain", 1, g_pMissionDatabase)
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")	
	pSaffiRetreat1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0RomRetreat1", None, 0, g_pMissionDatabase)
	pCloakWarbirds	= App.TGScriptAction_Create(__name__, "CloakWarbirds")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pSaffiRetreat1)
	pSequence.AppendAction(pFelixRetreat2)
	pSequence.AddAction(pCloakWarbirds, pFelixRetreat2)

	# Add Miguel's line if they can cloak
	if (bCanCloak == TRUE):
		pSequence.AddAction(pMiguelRetreat3, pFelixRetreat2)
	
	# If we have damaged systems, have Picard suggest repair.
	pRepairPane = App.EngRepairPane_GetRepairPane()
	pRepair = App.TGPane_Cast(pRepairPane.GetNthChild(App.EngRepairPane.REPAIR_AREA))

	if (pRepair.GetNumChildren() > 0):
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "PicardSuggestRepair"))
		
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	CloakWarbirds()
##
##	Script action that gets the two Warbirds in the set and cloaks them.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CloakWarbirds(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the set and the ships
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pWarbird1	= App.ShipClass_GetObject(pSet, "Warbird 1")
	pWarbird2	= App.ShipClass_GetObject(pSet, "Warbird 2")
	
	# Cloak the Warbirds
	if (pWarbird1 != None):
		MissionLib.Cloak(None, pWarbird1)
	if (pWarbird2 != None):
		MissionLib.Cloak(None, pWarbird2)
	
	return 0
	
################################################################################
##	CheckCloakingSystems()
##
##	Checks the cloaking systems on the two Warbirds and returns false if one
##	of them is destroyed or disabled.
##
##	Args:	None
##
##	Return:	TRUE	- If both the Warbirds can cloak.
################################################################################
def CheckCloakingSystems():
	# Get the set and the ships
	for sName in ["Warbird 1", "Warbird 2"]:
		pWarbird	= App.ShipClass_GetObject(None, sName)
		if (pWarbird != None):
			pCloak	= pWarbird.GetCloakingSubsystem()
			if (pCloak.IsDisabled() == TRUE):
				return FALSE
	
	# Both Warbird have working cloaking systems.
	return TRUE

################################################################################
##	CheckImpulseSystems()
##
##	
##	Checks the condition of Warbird 1's impulse engines.
##
##	Args:	None
##
##	Return:	TRUE	- If an impluse engine has been damaged.
################################################################################
def CheckImpulseSystems():
	# Get the first Warbird and check it's impluse system.
	pSet		= App.g_kSetManager.GetSet("Tevron2")
	pWarbird1	= App.ShipClass_GetObject(pSet, "Warbird 1")
	
	if (pWarbird1 != None):
		pImpulseSystem	= pWarbird1.GetImpulseEngineSubsystem()
		if (pImpulseSystem != None):
			# Get the impulse engines one by one and check if disabled.
			for iCounter in range(pImpulseSystem.GetNumChildSubsystems()):
				pChild = pImpulseSystem.GetChildSubsystem(iCounter)
				if (pChild.IsDisabled() == TRUE):
					return TRUE
	
	# None of the impluse engines are disabled
	return FALSE

################################################################################
##	ResetWarbirdAI()
##
##	Resets the AI of the Warbirds so they warp out and turns off collisions
##
##	Args:	None
##
##	Return:	None
################################################################################
def ResetWarbirdAI():
	# Get the set and the Warbirds
	pSet = App.g_kSetManager.GetSet("Tevron2")
	pWarbird1 = App.ShipClass_GetObject(pSet, "Warbird 1")
	pWarbird2 = App.ShipClass_GetObject(pSet, "Warbird 2")
	
	import E2M0_AI_WarbirdWarp
	if (pWarbird1 != None):
		pWarbird1.SetAI(E2M0_AI_WarbirdWarp.CreateAI(pWarbird1))
		pWarbird1.SetCollisionsOn(FALSE)
	if (pWarbird2 != None):
		pWarbird2.SetAI(E2M0_AI_WarbirdWarp.CreateAI(pWarbird2))
		pWarbird2.SetCollisionsOn(FALSE)
	
	return 0
	
################################################################################
##	ResetKlingonAI()
##
##	Resets the AI of both the Klingon ships so the RanKuf will intercept the
##	player so we can get Picard off the birdge.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ResetKlingonAI():
	# Get the set and the ships
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pRanKuf	= App.ShipClass_GetObject(pSet, "RanKuf")
	pTrayor	= App.ShipClass_GetObject(pSet, "Trayor")
	
	# Import the AIs and assign if the ships exist
	import E2M0_AI_KlingonTransfer
	if (pRanKuf != None):
		pRanKuf.SetAI(E2M0_AI_KlingonTransfer.CreateAI(pRanKuf, "player"))
	if (pTrayor != None):
		pTrayor.SetAI(E2M0_AI_KlingonTransfer.CreateAI(pTrayor, "RanKuf"))
		
################################################################################
##	WarbirdsLeft()
##
##	Called from exit set when both the Warbirds finally leave the set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def WarbirdsLeft():
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Well call the sequence as a script action, so it
	# does it's checks at the right time.
	pWarbirdsLeftSequence = App.TGScriptAction_Create(__name__, "WarbirdsLeftSequence")
	MissionLib.QueueActionToPlay(pWarbirdsLeftSequence)
	
################################################################################
##	WarbirdsLeftSequence()
##
##	Called as a "queued" script action so the checks are done when it finally
##	plays.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def WarbirdsLeftSequence(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Set our flag
	global g_bWarbirdsLeftPlayed
	g_bWarbirdsLeftPlayed	= TRUE

	# Check the Warbirds conditions and play different lines based on that
	bCanCloak		= CheckCloakingSystems()	

	# Build our sequence based on our flags
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))

	if (bCanCloak == TRUE):
		pKiskaRetreat4	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0RomRetreat4", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pKiskaRetreat4)
	else:
		pMiguelRetreat3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0RomRetreat3a", "Captain", 1, g_pMissionDatabase)
		pKiskaRetreat4	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0RomRetreat4a", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pMiguelRetreat3)
		pSequence.AppendAction(pKiskaRetreat4)


	pFelixRetreat5	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0RomRetreat5", None, 0, g_pMissionDatabase)
	pRemoveGoal		= App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E2EngageWarbirdsGoal")

	pSequence.AppendAction(pFelixRetreat5)
	pSequence.AppendAction(pRemoveGoal)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	# Give the Sovereign back it's repair points
	pShip = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Tevron2"), "Sovereign")
	if (pShip != None):
		pRepair = pShip.GetRepairSubsystem()
		pProp 	= pRepair.GetProperty()
		pProp.SetMaxRepairPoints(50.0)

	return 1

################################################################################
##	KlingonsDecloak()
##
##	Called from E2M0_AI_KlingonTransfer.py when the Klingon ship decloaks.
##	Creates the Zhukov as script action ot end.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def KlingonsDecloak(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_bWarbirdsLeftPlayed == FALSE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "KlingonsDecloak")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Check our flag
		if (g_pKlingonsDecloakCalled == FALSE):
			global g_pKlingonsDecloakCalled
			g_pKlingonsDecloakCalled = TRUE
		else:
			return 0
		
		# Get the characters we need
		pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
		pDraxon	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("KlingonSet"), "Draxon")
	
		# Disable Picard's menu
		if (pPicard != None):
			pPicard.SetMenuEnabled(0)

		pSequence = App.TGSequence_Create()

		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
		pMiguelZhukov4	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters4", None, 0, g_pMissionDatabase)
		pKiskaZhukov5	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters5", "Captain", 1, g_pMissionDatabase)
		pKlingonViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KlingonSet", "Draxon", 0, 0, 0)
		pTurnShieldsOff	= App.TGScriptAction_Create(__name__, "TurnKlingonShieldsOff")
		pDraxonZhukov6	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters6", None, 0, g_pMissionDatabase)
		pPicardZhukov7	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters7", None, 0, g_pMissionDatabase)
		pDraxonZhukov8	= App.CharacterAction_Create(pDraxon, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters8", None, 0, g_pMissionDatabase)
		pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pPicardStand	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_MOVE, "P1")
		pPicardZhukov9	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters9", "Captain", 1, g_pMissionDatabase)
		pPicardWalkOff	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_MOVE, "L1")
		pDeletePicard	= App.TGScriptAction_Create(__name__, "DeleteThePicard", pPicard)
		pBrexSovThanks3	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M0SovThanks3", None, 0, g_pMissionDatabase)
		pShieldCheck	= App.TGScriptAction_Create(__name__, "CheckShields")
		pBrexSovThanks4	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M0SovThanks4", None, 0, g_pMissionDatabase)
		pSetPicardLeft	= App.TGScriptAction_Create(__name__, "SetPicardLeft")
		pBrexSovThanks5	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M0SovThanks5", None, 0, g_pMissionDatabase)
		pCreateZhukov	= App.TGScriptAction_Create(__name__, "CreateZhukov")

		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pCallWaiting)
		pSequence.AppendAction(pMiguelZhukov4)
		pSequence.AppendAction(pKiskaZhukov5)
		pSequence.AppendAction(pKlingonViewOn)
		pSequence.AppendAction(pDraxonZhukov6)
		pSequence.AppendAction(pPicardZhukov7)
		pSequence.AppendAction(pDraxonZhukov8)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AppendAction(pPicardZhukov9)
		pSequence.AppendAction(pPicardStand)
		pSequence.AppendAction(pPicardWalkOff)
		pSequence.AppendAction(pDeletePicard)
		pSequence.AppendAction(pTurnShieldsOff)
		pSequence.AppendAction(pBrexSovThanks3, 3)
		pSequence.AppendAction(pShieldCheck)
		pSequence.AppendAction(pBrexSovThanks4)
		pSequence.AppendAction(pSetPicardLeft)
		pSequence.AppendAction(pBrexSovThanks5)
		pSequence.AppendAction(pCreateZhukov)

		MissionLib.QueueActionToPlay(pSequence)
		
		# Enable collisions on the Birds of Prey
		pRanKuf	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Tevron2"), "RanKuf")
		pTrayor	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Tevron2"), "Trayor")
		if (pRanKuf != None):
			pRanKuf.SetCollisionsOn(TRUE)
		if (pTrayor != None):
			pTrayor.SetCollisionsOn(TRUE)
		
		return 0

################################################################################
##	TurnKlingonShieldsOff()
##
##	Turns the shields off on the Birds of Prey to make them look like Green
##	Alert.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def TurnKlingonShieldsOff(pTGAction):
	# Get the ships
	pRanKuf	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Tevron2"), "RanKuf")
	pTrayor	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Tevron2"), "Trayor")

	# Turn the shields off on each of the ships.
	for pShip in [ pRanKuf, pTrayor ]:
		if (pShip != None):
			pShields = pShip.GetShields()
			if (pShields != None):
				pShields.TurnOff()
				
	return 0

################################################################################
##	DeleteThePicard()
##
##	Script action that deletes The Picard from the bridge set.
##
##	Args:	pTGAction	- The script action object.
##			pPicard		- Pointer to The Picard character.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def DeleteThePicard(pTGAction, pPicard):
	# Remove The Picard
	if (pPicard != None):
		pSet = App.g_kSetManager.GetSet("bridge")
		if (pSet != None):
			pSet.DeleteObjectFromSet("Picard")
		
	return 0

################################################################################
##	CheckShields()
##
##	Check and see what alert level the ship is at to see if the shields are up
##	or down by check the power level of shield subsystem.  "Lower" the shields
##	and do Brex's line if we need to.
##
##	Args:	pTGAction	- Script action object.
##
##	Return:	1	- Return 1 to pause calling sequence.
################################################################################
def CheckShields(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	pShip = App.ShipClass_GetObject(None, "player")
	if (pShip == None):
		return 0
	pShields = pShip.GetShields()
	
	# If the shields are up, tell the player to lower them.
	if (pShields.IsOn() and not pShields.IsDisabled()):
		pSequence = App.TGSequence_Create()
		
		# Do Brex's line
		pBrexLowering		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "LoweringShields", None, 0, g_pGeneralDatabase)
		pFlickerShields		= App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields", 0, 4)
		
		pSequence.AppendAction(pBrexLowering)
		pSequence.AppendAction(pFlickerShields)

		# Add an action that will complete the event
		# so the calling sequence continues
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pTGAction)
		pSequence.AddCompletedEvent(pEvent)
		
		pSequence.Play()
		
		return 1
	
	return 0

################################################################################
##	CreateZhukov()
##
##	Creates Zhukov.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CreateZhukov(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Create the ship
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pZhukov	= loadspacehelper.CreateShip("Ambassador", pSet, "Zhukov", "ZhukovStart", 1)
	pZhukov.ReplaceTexture("Data/Models/Ships/Ambassador/Zhukov.tga", "ID")

	# Import and assing the AI
	if (pZhukov != None):
		import E2M0_AI_Zhukov
		pZhukov.SetAI(E2M0_AI_Zhukov.CreateAI(pZhukov))
	
	return 0

################################################################################
##	ZhukovEntersSet()
##
##	Called when the Zhukov enters the set.  Does sequence from Verata.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ZhukovEntersSet():
	# Don't play if we lost
	if (g_bMissionLost == TRUE):
		return
		
	# Get the characters we need
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	pVerata	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("DBridgeSet"), "Verata")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pMiguelZhukov1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters1", "Captain", 1, g_pMissionDatabase)
	pKiskaZhukov2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters2", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Verata", 0, 0, 0)
	pVerataZhukov3	= App.CharacterAction_Create(pVerata, App.CharacterAction.AT_SAY_LINE, "E2M0ZhukovEnters3", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pRemoveGoal		= App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E2ProtectSovGoal")
	pSovThanks		= App.TGScriptAction_Create(__name__, "SovereignThanks")

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pMiguelZhukov1)
	pSequence.AppendAction(pKiskaZhukov2)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pVerataZhukov3)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pRemoveGoal)
	pSequence.AppendAction(pSovThanks)

	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	SovereignThanks()
##
##	Called as script action, does sequence ending mission.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing
################################################################################
def SovereignThanks(pTGAction):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Set our flag
	global g_bMissionWin
	g_bMissionWin = TRUE
	
	# Get the characters we need.
	pSoto	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("EBridgeSet"), "Soto")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pKiskaSovThanks1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0SovThanks1", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Soto", 0, 0, 0)
	pSotoSovThanks2		= App.CharacterAction_Create(pSoto, App.CharacterAction.AT_SAY_LINE, "E2M0SovThanks2", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pResetSovAI			= App.TGScriptAction_Create(__name__, "ResetSovAI")
	pWarpKlingonsOut	= App.TGScriptAction_Create(__name__, "WarpKlingonsOut")
	pMiguelSovThanks6	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0SovThanks6", "Captain", 1, g_pMissionDatabase)
	pSaffiSovThanks8	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0SovThanks8", "Captain", 0, g_pMissionDatabase)
	pSaffiSovThanks8a	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0SovThanks8a", None, 1, g_pMissionDatabase)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pKiskaSovThanks1)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pSotoSovThanks2)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pResetSovAI)
	pSequence.AppendAction(pWarpKlingonsOut)
	pSequence.AppendAction(pMiguelSovThanks6)
	pSequence.AppendAction(pSaffiSovThanks8)
	pSequence.AppendAction(pSaffiSovThanks8a)
		
	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()
	
	# Link the next missions to the helm menu
	LinkMissionsToHelm()
	
	# Register our two goals
	MissionLib.AddGoal("E2SupplyCeli5Goal")

	return 1

################################################################################
##	SetPicardLeft()
##
##	Script action that set the value of g_bPicardLeft to TRUE.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from calling.
################################################################################
def SetPicardLeft(pTGAction):
	global g_bPicardLeft
	g_bPicardLeft = TRUE
	
	return 0
	
################################################################################
##	ResetSovAI()
##
##	Script action that resets the Sovereign and Zhukov's AI so they warp out
##	of the system.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetSovAI(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the set and the ship
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pSov	= App.ShipClass_GetObject(pSet, "Sovereign")
	pZhukov	= App.ShipClass_GetObject(pSet, "Zhukov")
	
	# Import and assign the AI if the ship exists
	import E2M0_AI_FedWarpOut
	if (pSov != None):
		pSov.SetAI(E2M0_AI_FedWarpOut.CreateAI(pSov, "SovEnter"))
	if (pZhukov != None):
		pZhukov.SetAI(E2M0_AI_FedWarpOut.CreateAI(pZhukov, "ZhukovEnter"))
		
	return 0
	
################################################################################
##	WarpKlingonsOut()
##
##	Reset the Klingon AI's so they warp out of the system.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def WarpKlingonsOut(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the set and the ships
	pSet	= App.g_kSetManager.GetSet("Tevron2")
	pRanKuf	= App.ShipClass_GetObject(pSet, "RanKuf")
	pTrayor	= App.ShipClass_GetObject(pSet, "Trayor")
	
	# Import the AIs and assign if the ships exist
	import Maelstrom.Episode2.AI_WarpOut
	if (pRanKuf != None):
		pRanKuf.SetAI(Maelstrom.Episode2.AI_WarpOut.CreateAI(pRanKuf))
	if (pTrayor != None):
		pTrayor.SetAI(Maelstrom.Episode2.AI_WarpOut.CreateAI(pTrayor))
		
	return 0

################################################################################
##	HailSovAtStarbase()
##
##	Called from HailHandler() if the player hails the Sovereign while at SB12.
##
##	Args:	None
##
##	Return:	None
################################################################################
def HailSovAtStarbase():
	# Get Soto
	pSoto	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("EBridgeSet"), "Soto")
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaSovSB1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0HailSovSB1", "Captain", 1, g_pMissionDatabase)
	pKiskaSotoHail1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0SotoHail1", None, 0, g_pMissionDatabase)
	pViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Soto", 0, 0, 0)
	pSotoSovSB2		= App.CharacterAction_Create(pSoto, App.CharacterAction.AT_SAY_LINE, "E2M0HailSovSB2", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaSovSB1)
	pSequence.AppendAction(pKiskaSotoHail1)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pSotoSovSB2)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	HailZhukovAtSB()
##
##	Called from HailHandler() if the player hails the Zhukov while at SB12
##
##	Args:	None
##
##	Return:	None
################################################################################
def HailZhukovAtSB():
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pKiskaZhukovSB1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0HailZhukovSB1", "Captain", 1, g_pMissionDatabase)
	pKiskaZhukovSB2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0HailZhukovSB2", None, 0, g_pMissionDatabase)
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		
	pSequence.AppendAction(pKiskaZhukovSB1)
	pSequence.AppendAction(pKiskaZhukovSB2)
	pSequence.AppendAction(pEndCallWaiting)
	
	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	ArriveTevronCommunicate()
##
##	Plays special communicate dialogue when the player first enters Tevron
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject sent to CommunicateHandler()
##			pEvent		- The event that was sent to CommunicateHandler()
##
##	Return:	None
################################################################################
def ArriveTevronCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID if the menu and see who it is
	if (iMenuID == idKiskaMenu) and (g_bShipsIDd == FALSE):
		pComLine = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0KiskaCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()

	elif (iMenuID == idFelixMenu):
		pComLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0FelixCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
	
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0MiguelCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M0BrexCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)

################################################################################
##	WarbirdsAttackCommunicate()
##
##	Plays special communicate dialogue after the Warbirds attack the Sovereign.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject sent to CommunicateHandler()
##			pEvent		- The event that was sent to CommunicateHandler()
##
##	Return:	None
################################################################################
def WarbirdsAttackCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID if the menu and see who it is
	if (iMenuID == idKiskaMenu):
		pComLine = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0KiskaCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()

	elif (iMenuID == idFelixMenu):
		pComLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0FelixCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
	
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0SaffiCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M0MiguelCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M0BrexCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)

################################################################################
##	AttackOverCommunicate()
##
##	Plays special communicate dialogue after the attack is over.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked.
##			TGObject	- The TGObject sent to CommunicateHandler()
##			pEvent		- The event that was sent to CommunicateHandler()
##
##	Return:	None
################################################################################
def AttackOverCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check the ID if the menu and see who it is
	if (iMenuID == idKiskaMenu):
		pComLine = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0KiskaCom3", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()

	elif (iMenuID == idFelixMenu):
		pComLine = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M0FelixCom3", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
	
	elif (iMenuID == idSaffiMenu):
		if (g_bZhukovArrives == FALSE):
			pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0PlayerLeaves4", "Captain", 1, g_pMissionDatabase)
			pComLine.Play()
		else:
			pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0SaffiCom3", "Captain", 1, g_pMissionDatabase)
			pComLine.Play()
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M0BrexCom3", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	else:
		# Do the default behavior for everyone else
		TGObject.CallNextHandler(pEvent)

################################################################################
##	PicardTip()
##
##	Called from timer event.  Checks a bunch of conditions and has Picard
##	and passes them on to a function that will figure out what line to play.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PicardTip(TGObject, pEvent):
	# Bail if we have no tips left
	if (len(g_lPicardTips) == 0):
		return
	
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Get the two Warbirds
	pSet		= App.g_kSetManager.GetSet("Tevron2")
	pWarbird1	= App.ShipClass_GetObject(pSet, "Warbird 1")
	pWarbird2	= App.ShipClass_GetObject(pSet, "Warbird 2")
	# Bail if one of the Warbirds doesn't exist
	if (pWarbird1 == None) or (pWarbird2 == None):
		return
	
	# Check and see if both the Warbirds are cloaked
	pCloak1	= pWarbird1.GetCloakingSubsystem()
	pCloak2	= pWarbird2.GetCloakingSubsystem()
	if ((pWarbird1.IsCloaked()) and (pWarbird2.IsCloaked())):
		bWarbirdsCloaked = TRUE
	else:
		bWarbirdsCloaked = FALSE
		
	# See if the Warbirds have a weak shield
	pShields1	= pWarbird1.GetShields()
	pShields2	= pWarbird2.GetShields()
	if (pShields1.IsAnyShieldBreached()) or (pShields2.IsAnyShieldBreached()):
		bHaveWeakShield = TRUE
	else:
		bHaveWeakShield = FALSE
	
	# See if the player is moving
	vVelocity = pPlayer.GetVelocityTG()
	vVelocity.Unitize()
	if (vVelocity.SqrLength() > 0.5):
		bPlayerMoving = TRUE
	else:
		bPlayerMoving = FALSE

	# Call our function to decide what line to play
	PlayPicardTip(bWarbirdsCloaked, bHaveWeakShield, bPlayerMoving)
	
################################################################################
##	PlayPicardTip()
##
##	Checks all the flags passed in an decides what line to play out of the ones
##	still available.
##
##	Args:	bWarbirdsCloaked	- TRUE if both Warbirds are cloaked
##			bHaveWeakShield		- TRUE if one of the Warbirds has a weak shield
##			bPlayerMoving		- TRUE if the players ship is moving.
##
##	Return:	None
################################################################################
def PlayPicardTip(bWarbirdsCloaked, bHaveWeakShield, bPlayerMoving):
	# Make our list of tips available
	global g_lPicardTips
	
	# Get Picard
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	
	# Check our flags and decide what line to play
	if (bPlayerMoving == FALSE) and ("E2M0PicardTargeting8" in g_lPicardTips):
		# Tell the player to start moving around
		pPicardLine	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardTargeting8", "Captain", 1, g_pMissionDatabase)
		MissionLib.QueueActionToPlay(pPicardLine)
		g_lPicardTips.remove("E2M0PicardTargeting8")

	elif (bWarbirdsCloaked == TRUE) and ("E2M0PicardTargeting2" in g_lPicardTips):
		pPicardLine	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardTargeting2", "Captain", 1, g_pMissionDatabase)
		MissionLib.QueueActionToPlay(pPicardLine)
		g_lPicardTips.remove("E2M0PicardTargeting2")

	elif ("E2M0PicardTargeting3" in g_lPicardTips):
		pPicardLine	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardTargeting3", "Captain", 1, g_pMissionDatabase)
		MissionLib.QueueActionToPlay(pPicardLine)
		g_lPicardTips.remove("E2M0PicardTargeting3")

	elif (bHaveWeakShield == TRUE) and ("E2M0PicardTargeting4" in g_lPicardTips):
		pPicardLine	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardTargeting4", "Captain", 1, g_pMissionDatabase)
		MissionLib.QueueActionToPlay(pPicardLine)
		g_lPicardTips.remove("E2M0PicardTargeting4")

	elif (bWarbirdsCloaked == TRUE) and ("E2M0PicardTargeting7" in g_lPicardTips):
		pPicardLine	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardTargeting7", "Captain", 1, g_pMissionDatabase)
		MissionLib.QueueActionToPlay(pPicardLine)
		g_lPicardTips.remove("E2M0PicardTargeting7")

	elif ("E2M0PicardTargeting5" in g_lPicardTips):
		pSequence	= App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardTargeting5", "Captain", 1, g_pMissionDatabase))
		pSequence.AppendAction(App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardTargeting6", "Captain", 1, g_pMissionDatabase))
		MissionLib.QueueActionToPlay(pSequence)
		g_lPicardTips.remove("E2M0PicardTargeting5")

	# Start the timer again to call the function
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_PICARD_AUDIO_TIMER, __name__ + ".PicardTip", fStartTime + 90, 0, 0)
	
################################################################################
##	ExplainSubsystemTargeting()
##
##	Picard tutorial sequence called when the player presses the
##	"Subsystem Targeting" button in Picards menu.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainSubsystemTargeting(TGObject, pEvent):
	# If KlingonsDecloak() has been called, don't play
	# because we need to get Picard off the bridge
	if (g_pKlingonsDecloakCalled == TRUE):
		return
	
	# Set our flags
	global g_iTutorialCounter
	g_iTutorialCounter	= 1
	
	# Get Picard and close his menu
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicard.SetMenuEnabled(FALSE)

	# Let the AIs know where in the "Help" mode.
	pPlayerInHelp = App.TGCondition_Cast( App.TGObject_GetTGObjectPtr( g_idPlayerInHelpCondition ) )
	if pPlayerInHelp:
		pPlayerInHelp.SetStatus(1)
		
	# Do the master sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSubTargetOne		= App.TGScriptAction_Create(__name__, "ExplainSubTargetOne")
	pSubTargetTwo		= App.TGScriptAction_Create(__name__, "ExplainSubTargetTwo")
	pSubTargetCleanUp	= App.TGScriptAction_Create(__name__, "ExplainSubTargetCleanUp")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pSubTargetOne)
	pSequence.AppendAction(pSubTargetTwo)
	pSequence.AppendAction(pSubTargetCleanUp)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	ExplainSubTargetOne()
##
##	First part of tutorial sequence for subsystem targeting. Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def ExplainSubTargetOne(pTGAction):
	# Get the UI stuff we'll need
	pTargetMenu = App.STTargetMenu_GetTargetMenu()
	# Get one of the Warbirds as a target
	if (App.STSubsystemMenu_Cast(pTargetMenu.GetSubmenuW(g_pMissionDatabase.GetString("Warbird 1")))):
		pTargetButton = App.STSubsystemMenu_Cast(pTargetMenu.GetSubmenuW(g_pMissionDatabase.GetString("Warbird 1")))
	elif (App.STSubsystemMenu_Cast(pTargetMenu.GetSubmenuW(g_pMissionDatabase.GetString("Warbird 2")))):
		pTargetButton = App.STSubsystemMenu_Cast(pTargetMenu.GetSubmenuW(g_pMissionDatabase.GetString("Warbird 2")))
	else:
		pTargetButton = None
		
	# Get Picard
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	
	# Do the sequence
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown		= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_MENU_DOWN)
	pMakeInvincible		= App.TGScriptAction_Create(__name__, "MakeShipInvincible", 1)
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pFelixMenuUp		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_UP)
	pRelocateSubtitle	= App.TGScriptAction_Create(__name__, "RelocateSubtitle")
	pSetCharLock		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pSetTutorial		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idSubsystemTargetBox1)
	pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pTargetButton, MissionLib.POINTER_LEFT)
	pPicardSubsystem1	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardSubsystem1", None, 0, g_pMissionDatabase)
	pPicardSubsystem2	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardSubsystem2", None, 0, g_pMissionDatabase)
	pCheckOneDone		= App.TGScriptAction_Create(__name__, "CheckSubOneDone", pTGAction.GetObjID())
	
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pMakeInvincible)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pRelocateSubtitle)
	pSequence.AppendAction(pFelixMenuUp)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardSubsystem1)
	pSequence.AppendAction(pPicardSubsystem2)
	pSequence.AppendAction(pCheckOneDone)

	pSequence.Play()

	return 1

################################################################################
##	CheckSubOneDone()
##
##	Script action that calls itself recursvily until flag allows us to complete
##	the script action that calls us - got it?
##
##	Args:	pTGAction	- The script action object.
##			idTGAction	- The object id this script action.
##
##	Return:	
################################################################################
def CheckSubOneDone(pTGAction, idCallingAction, idTGAction = App.NULL_ID):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0
	
	# We done, so allow the sequece to finish.
	if (g_iTutorialCounter > 1):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0

	if (idTGAction == App.NULL_ID):
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckSubOneDone", idCallingAction, pTGAction.GetObjID()), 1)
		pSequence.Play()
		return 1
	
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckSubOneDone", idCallingAction, idTGAction), 1)
	pSequence.Play()
	return 0

################################################################################
##	ExplainSubTargetTwo()
##
##	Second part of tutorial sequence for subsystem targeting.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def ExplainSubTargetTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Hide pointer arrow
	HideArrows()

	# Get Picard
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")

	# Do our sequence.
	pSequence = App.TGSequence_Create()

	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pHideInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSubsystemTargetBox1)
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idSubsystemTargetBox2)
	pPicardSubsystem3	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardSubsystem3", None, 0, g_pMissionDatabase)
	pPicardSubsystem4	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardSubsystem4", None, 0, g_pMissionDatabase)
	pCheckSubTwoDone	= App.TGScriptAction_Create(__name__, "CheckSubTwoDone", pTGAction.GetObjID())

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pHideInfoBox)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pPicardSubsystem3)
	pSequence.AppendAction(pPicardSubsystem4)
	pSequence.AppendAction(pCheckSubTwoDone)

	pSequence.Play()

	return 1

################################################################################
##	CheckSubTwoDone()
##
##	Script action that calls itself recursvily until flag allows us to complete
##	the script action that calls us - got it?
##
##	Args:	pTGAction	- The script action object.
##			idTGAction	- The object id this script action.
##
##	Return:	
################################################################################
def CheckSubTwoDone(pTGAction, idCallingAction, idTGAction = App.NULL_ID):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0
	
	# We done, so allow the sequece to finish.
	if (g_iTutorialCounter > 2):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0

	if (idTGAction == App.NULL_ID):
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckSubTwoDone", idCallingAction, pTGAction.GetObjID()), 1)
		pSequence.Play()
		return 1
	
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckSubTwoDone", idCallingAction, idTGAction), 1)
	pSequence.Play()
	return 0

################################################################################
##	ExplainSubTargetCleanUp()
##
##	Last part of subsystem targeting that clean every thing up.  Called as
##	script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainSubTargetCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Clear our tutorial counter
	global 	g_iTutorialCounter
	g_iTutorialCounter	= 0

	# Get Picard and make his menu active
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicard.SetMenuEnabled(TRUE)

	# Do our sequence
	pSequence = App.TGSequence_Create()

	pHideInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSubsystemTargetBox2)
	pRemoveControl		= App.TGScriptAction_Create("MissionLib", "RemoveControl")
	pSetCharLock		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
	pSetTutorial		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
	pRelocateSubtitle2	= App.TGScriptAction_Create(__name__, "RelocateSubtitle2")
	pFelixMenuDown		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_DOWN)
	pMakeVincible		= App.TGScriptAction_Create(__name__, "MakeShipInvincible", 0)
	pPlayerNotInHelp	= App.TGScriptAction_Create(__name__, "SetPlayerInHelp", 0)
	pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")

	pSequence.AppendAction(pHideInfoBox)
	pSequence.AppendAction(pRemoveControl)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pRelocateSubtitle2)
	pSequence.AppendAction(pFelixMenuDown)
	pSequence.AppendAction(pMakeVincible)
	pSequence.AppendAction(pPlayerNotInHelp)
	pSequence.AppendAction(pEndCutscene)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	return 1

################################################################################
##	SetupSubsystemTargetingInfoBoxes()
##
##	Create the info boxes that we need for Subsystem Targeting.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupSubsystemTargetingInfoBoxes():
	# Destroy the boxes if they already exist
	for idBox in [ g_idSubsystemTargetBox1, g_idSubsystemTargetBox2 ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)
			
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["SubsystemTarget"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 2/E2M0HelpText.tgl")
	
	## Box 1
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("SubsystemTargetHelpTitle"), 
				pDatabase.GetString("SubsystemTargetHelp1A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idSubsystemTargetBox1
	g_idSubsystemTargetBox1 = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".TargetInfoBoxClosed")
	
	
	## Box 2
	# Create the formated paragraph
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("SubsystemTargetHelp2A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pGray		= App.TGParagraph_CreateW(pDatabase.GetString("SubsystemTargetHelp2B"), fWidth, App.g_kDamageDisplayDisabledColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pGray)
	pMainText.AppendStringW(pDatabase.GetString("SubsystemTargetHelp2C"))

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("SubsystemTargetHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idSubsystemTargetBox2
	g_idSubsystemTargetBox2 = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".TargetInfoBoxClosed")

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	ExplainRepair()
##
##	Goes through using Brex's repair menu.  Called from button in Picard's menu.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainRepair(TGObject, pEvent):
	# If KlingonsDecloak() has been called, don't play
	# because we need to get Picard off the bridge
	if (g_pKlingonsDecloakCalled == TRUE):
		return
	
	# Get Picard and shut his menu down
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicard.SetMenuEnabled(FALSE)
		
	pPlayerInHelp = App.TGCondition_Cast( App.TGObject_GetTGObjectPtr( g_idPlayerInHelpCondition ) )
	if pPlayerInHelp:
		pPlayerInHelp.SetStatus(1)

	# Set our flags
	global g_iTutorialCounter
	g_iTutorialCounter	= 1
		
	# Do the sequence
	pSequence = App.TGSequence_Create()
	
	pExplainRepairOne		= App.TGScriptAction_Create(__name__, "ExplainRepairOne")	
	pExplainRepairTwo		= App.TGScriptAction_Create(__name__, "ExplainRepairTwo")
	pExplainRepairThree		= App.TGScriptAction_Create(__name__, "ExplainRepairThree")
	pExplainRepairCleanUp	= App.TGScriptAction_Create(__name__, "ExplainRepairCleanUp")

	pSequence.AppendAction(pExplainRepairOne)
	pSequence.AppendAction(pExplainRepairTwo)
	pSequence.AppendAction(pExplainRepairThree)
	pSequence.AppendAction(pExplainRepairCleanUp)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	ExplainRepairOne()
##
##	First part of the repair tutorial.  Called as script aciton.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return one to keep calling sequence paused.
################################################################################
def ExplainRepairOne(pTGAction):
	# Get Picard
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")

	# Get the buttons that we'll need.
	pRepairPane = App.EngRepairPane_GetRepairPane()
	# Returns the top area, where items being repaired are stored.
	pRepairArea = App.TGPane_Cast(pRepairPane.GetNthChild(App.EngRepairPane.REPAIR_AREA))

	# Do the sequence
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown		= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_MENU_DOWN)
	pMakeInvincible		= App.TGScriptAction_Create(__name__, "MakeShipInvincible", 1)
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pBrexMenuUp			= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_MENU_UP)
	pSetCharLock		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pSetTutorial		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idRepairBox1)
	pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pRepairArea, MissionLib.POINTER_LEFT)
	pPicardRepair2		= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardRepair2", None, 0, g_pMissionDatabase)
	pCheckOneDone		= App.TGScriptAction_Create(__name__, "CheckRepairOneDone", pTGAction.GetObjID())

	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pMakeInvincible)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pBrexMenuUp)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardRepair2)
	pSequence.AppendAction(pCheckOneDone)
	
	pSequence.Play()

	return 1
	
################################################################################
##	CheckRepairOneDone()
##
##	Script action that calls itself recursvily until flag allows us to complete
##	the script action that calls us - got it?
##
##	Args:	pTGAction	- The script action object.
##			idTGAction	- The object id this script action.
##
##	Return:	
################################################################################
def CheckRepairOneDone(pTGAction, idCallingAction, idTGAction = App.NULL_ID):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0
	
	# We done, so allow the sequece to finish.
	if (g_iTutorialCounter > 1):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0

	if (idTGAction == App.NULL_ID):
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckRepairOneDone", idCallingAction, pTGAction.GetObjID()), 1)
		pSequence.Play()
		return 1
	
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckRepairOneDone", idCallingAction, idTGAction), 1)
	pSequence.Play()
	return 0

################################################################################
##	ExplainRepairTwo()
##
##	Second part of the repair tutorial.  Called as script aciton.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 0 to keep calling sequence paused.
################################################################################
def ExplainRepairTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Hide any arrows
	HideArrows()

	# Get Picard
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")

	# Get the buttons that we'll need.
	pRepairPane = App.EngRepairPane_GetRepairPane()
	# Returns the bottom area, where items that are waiting are stored.
	pWaitingArea = App.TGPane_Cast(pRepairPane.GetNthChild(App.EngRepairPane.WAITING_AREA))

	# Do our sequence
	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idRepairBox2)
	pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pWaitingArea, MissionLib.POINTER_LEFT)
	pPicardRepair3	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardRepair3", None, 0, g_pMissionDatabase)
	pPicardRepair4	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardRepair4", None, 0, g_pMissionDatabase)
	pCheckTwoDone	= App.TGScriptAction_Create(__name__, "CheckRepairTwoDone", pTGAction.GetObjID())

	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardRepair3)
	pSequence.AppendAction(pPicardRepair4)
	pSequence.AppendAction(pCheckTwoDone)

	pSequence.Play()

	return 1

################################################################################
##	CheckRepairTwoDone()
##
##	Script action that calls itself recursvily until flag allows us to complete
##	the script action that calls us - got it?
##
##	Args:	pTGAction	- The script action object.
##			idTGAction	- The object id this script action.
##
##	Return:	
################################################################################
def CheckRepairTwoDone(pTGAction, idCallingAction, idTGAction = App.NULL_ID):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0
	
	# We done, so allow the sequece to finish.
	if (g_iTutorialCounter > 2):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0

	if (idTGAction == App.NULL_ID):
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckRepairTwoDone", idCallingAction, pTGAction.GetObjID()), 1)
		pSequence.Play()
		return 1
	
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckRepairTwoDone", idCallingAction, idTGAction), 1)
	pSequence.Play()
	return 0

################################################################################
##	ExplainRepairThree()
##
##	Third part of the repair tutorial.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainRepairThree(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Hide any arrows
	HideArrows()

	# Get Picard
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")

	# Do our sequence
	pSequence = App.TGSequence_Create()

	pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idRepairBox3)
	pPicardRepair5	= App.CharacterAction_Create(pPicard, App.CharacterAction.AT_SAY_LINE, "E2M0PicardRepair5", None, 0, g_pMissionDatabase)
	pCheckThreeDone	= App.TGScriptAction_Create(__name__, "CheckRepairThreeDone", pTGAction.GetObjID())

	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pPicardRepair5)
	pSequence.AppendAction(pCheckThreeDone)

	pSequence.Play()

	return 1

################################################################################
##	CheckRepairThreeDone()
##
##	Script action that calls itself recursvily until flag allows us to complete
##	the script action that calls us - got it?
##
##	Args:	pTGAction	- The script action object.
##			idTGAction	- The object id this script action.
##
##	Return:	
################################################################################
def CheckRepairThreeDone(pTGAction, idCallingAction, idTGAction = App.NULL_ID):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0
	
	# We done, so allow the sequece to finish.
	if (g_iTutorialCounter > 3):
		if (idTGAction == App.NULL_ID):
			pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
			pCallingAction.Completed()			
			return 0
		pOriginalAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idTGAction))
		pOriginalAction.Completed()
		pCallingAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idCallingAction))
		pCallingAction.Completed()			
		return 0

	if (idTGAction == App.NULL_ID):
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckRepairThreeDone", idCallingAction, pTGAction.GetObjID()), 1)
		pSequence.Play()
		return 1
	
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "CheckRepairThreeDone", idCallingAction, idTGAction), 1)
	pSequence.Play()
	return 0

################################################################################
##	ExplainRepairCleanUp()
##
##	Last part of repair tutorial that cleans eveything up.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainRepairCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Clear our tutorial counter
	global 	g_iTutorialCounter
	g_iTutorialCounter	= 0

	# Hide any arrows
	HideArrows()


	# Get Picard and make his menu active
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicard.SetMenuEnabled(TRUE)

	# Do our sequence
	pSequence = App.TGSequence_Create()

	pRemoveControl	= App.TGScriptAction_Create("MissionLib", "RemoveControl")
	pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
	pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
	pBrexMenuDown	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_MENU_DOWN)
	pMakeVincible	= App.TGScriptAction_Create(__name__, "MakeShipInvincible", 0)
	pCutsceneEnd	= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pNotInHelp		= App.TGScriptAction_Create(__name__, "SetPlayerInHelp", 0)

	pSequence.AppendAction(pRemoveControl)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pBrexMenuDown)
	pSequence.AppendAction(pMakeVincible)
	pSequence.AppendAction(pCutsceneEnd)
	pSequence.AppendAction(pNotInHelp)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	return 1

################################################################################
##	SetupRepairInfoBoxes()
##
##	Create the info boxes we need for the repair tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupRepairInfoBoxes():
	# Destroy the boxes if they already exist
	for idBox in [ g_idRepairBox1, g_idRepairBox2, g_idRepairBox3 ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)

	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
				
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["RepairBoxes"][g_sResolutionSetting]
	
	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 2/E2M0HelpText.tgl")

	## Box 1
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("RepairHelpTitle"), 
				pDatabase.GetString("RepairHelp1A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idRepairBox1
	g_idRepairBox1 = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".RepairInfoBoxClosed")
	

	## Box 2
	# Create the formated paragraph
	pMainText		= App.TGParagraph_CreateW(pDatabase.GetString("RepairHelp2A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("RepairHelp2B"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("RepairHelp2C"))
	pMainText.AppendChar(App.WC_RETURN)

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("RepairHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idRepairBox2
	g_idRepairBox2 = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".RepairInfoBoxClosed")


	## Box 3
	# Create the formated paragraph
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("RepairHelp3A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("RepairHelp3B"))
	pMainText.AppendChar(App.WC_RETURN)

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("RepairHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idRepairBox3
	g_idRepairBox3 = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".RepairInfoBoxClosed")

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	RepairInfoBoxClosed()
##
##	Handler called when one of the repair info boxes is closed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def RepairInfoBoxClosed(TGObject, pEvent):
	# Increase our tutorial counter
	global g_iTutorialCounter
	g_iTutorialCounter = g_iTutorialCounter + 1
		
	# All done, call our next handler.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	TargetInfoBoxClosed()
##
##	Handler called when one of the subsystem targeting info boxes is closed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def TargetInfoBoxClosed(TGObject, pEvent):
	# Increase our tutorial counter
	global g_iTutorialCounter
	g_iTutorialCounter = g_iTutorialCounter + 1
		
	# All done, call our next handler.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	SetCharWindowLock()
##
##	Script action that sets the flag g_bCharWindowLock to value passed in.
##
##	Args:	pTGAction	- The script action object.
##			bNewValue	- New value of the flag.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetCharWindowLock(pTGAction, bNewValue):
	global g_bCharWindowLock
	g_bCharWindowLock = bNewValue
	
	return 0

################################################################################
##	SetTutorialFlag()
##
##	Script action that sets the value of g_bInTutorial to the new value
##	passed in.
##
##	Args:	pTGAction	- The script action object.
##			bNewValue	- The value to set g_bInTutorial to.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetTutorialFlag(pTGAction, bNewValue):
	global g_bInTutorial
	g_bInTutorial = bNewValue
	
	return 0

################################################################################
##	MakeShipsInvincible()
##
##	Script action that makes all the ships invisible or return them to normal
##	so we can turn damage on and off during tutorial sequences.
##
##	Args:	pTGAction		- The script action object.
##			bInvisibleFlag	- 1 will set ships invincible, 0 will reset to normal
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MakeShipInvincible(pTGAction, bInvincibleFlag = 1):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the set were worried about
	pSet = App.g_kSetManager.GetSet("Tevron2")
	
	# Do all the friendly ships
	for sName in g_lFriendlyShips:
		pShip	= App.ShipClass_GetObject(pSet, sName)
		if (pShip != None):
			pShip.SetInvincible(bInvincibleFlag)
				
	# Do the player
	pShip = MissionLib.GetPlayer()
	if (pShip != None):
		pShip.SetInvincible(bInvincibleFlag)
			
	return 0

################################################################################
##	CheckAlertLevel()
##
##	Checks the players alert level and plays prompting line from Saffi if we
##	are not at RED_ALERT.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Retur 0 to keep calling sequence from crashing.
################################################################################
def CheckAlertLevel(pTGAction):
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None) or (g_bMissionTerminate != 1):
		return 0
	pShip	= App.ShipClass_Cast(pPlayer)
	
	# Check the alert level.
	if (pShip.GetAlertLevel() == App.ShipClass.RED_ALERT):
		return 0
	else:
		# We're not at red alert, so open Saffi's menu and
		# give her line
		pSequence = App.TGSequence_Create()
		
		pSaffiRedAlert	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2SaffiRedAlert1", "Captain", 0, g_pMissionDatabase)
		
		pSequence.AddAction(pSaffiRedAlert, None)

		# Add an action that will complete the event
		# so the calling sequence continues
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pTGAction)
		pSequence.AddCompletedEvent(pEvent)
		
		pSequence.Play()
		
		return 1

################################################################################
##	StopProdTimer()	
##
##	Removes old timer if goal is reached.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StopProdTimer():
	global g_iProdTimer
	if (g_iProdTimer != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_iProdTimer)

		g_iProdTimer = App.NULL_ID

################################################################################
##	RestartProdTimer()
##
##	Starts a timer to prod the player, called as a TGScriptAction
##
##	Args:	pTGAction	- Script action object
##			iTime 		- The length of time in seconds that the timer will run for.
##
##	Return:	0	- Return 0 so sequence that calls won't choke
################################################################################
def RestartProdTimer(pTGAction, iTime):
	# Stop the old prod timer.
	StopProdTimer()

	# Start a new prod timer.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_TIMER, __name__+".ProdPlayer", fStartTime + iTime, 0, 0)
	# Save the ID of the prod timer, so we can stop it later.
	global g_iProdTimer
	g_iProdTimer = pTimer.GetObjID()
	
	return 0

################################################################################
##	ProdPlayer()
##
##	Figure out what kind of prodding the player need and call the correct
##	function.
##
##	Args:	pTGObject	- The TGObject object
##			pEvent		- The event that was sent to the object
##
##	Return:	None
##
################################################################################
def ProdPlayer(pTGObject, pEvent):
	# Make sure the player hasn't returned to the Tevron system
	if (g_bPlayerNotInTevron == FALSE):
		return

	# Check our counter and see what line we should play
	if (g_iPlayerNotInTevron == 0):
		pSaffiLeave1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0PlayerLeaves1", "Captain", 1, g_pMissionDatabase)
		pSaffiLeave1.Play()
		RestartProdTimer(None, 60)
		
	elif (g_iPlayerNotInTevron == 1):
		pSaffiLeave2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0PlayerLeaves2", "Captain", 1, g_pMissionDatabase)
		pSaffiLeave2.Play()
		RestartProdTimer(None, 60)
		
	elif (g_iPlayerNotInTevron == 2):
		# That's it, game over
		pSequence = App.TGSequence_Create()
		# If the viewscreen is on, turn it off
		if (MissionLib.g_bViewscreenOn == TRUE):
			pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))

		pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0PlayerLeaves3", "Captain", 1, g_pMissionDatabase))
		
		pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
		pGameOver.Play()

		# Kill all the sequences
		App.TGActionManager_KillActions("Generic")
		App.TGActionManager_KillActions("MissionWin")

	# Increase the prod counter
	global g_iPlayerNotInTevron
	g_iPlayerNotInTevron = g_iPlayerNotInTevron + 1
	
################################################################################
##	LinkMissionsToHelm()
##
##	Link the Serris item in Helm to E2M2 and Vesuvi to E2M1.
##
##	Args:	None
##
##	Return:	None
################################################################################
def LinkMissionsToHelm():
	# Pause the menu sorting
	App.SortedRegionMenu_SetPauseSorting(1)
	
	# Do the linking for E2M1
	import Systems.Vesuvi.Vesuvi
	pVesuviMenu	= Systems.Vesuvi.Vesuvi.CreateMenus()
	pVesuviMenu.SetMissionName("Maelstrom.Episode2.E2M1.E2M1")

	# Restart menu sorting
	App.SortedRegionMenu_SetPauseSorting(0)
	
################################################################################
##	ShowArrow()
##
##	Script action that puts a pointer arrow next to a UI object.  Creates timer
##	that refreshes the arrow incase the object moves or no longer is visible.
##
##	Args:	pTGAction	- The script action object.
##			pUIObject	- The UIObject the arrow will point to.
##			eDirection	- the direction of the arrow (which way it points)
##						  uses ennumeration in MissionLib.py
##			fSpacing	- distance between arrow and object -- specified as a
##						  scale factor of the arrow's size
##			kColor		- optional color. If not specified, it uses white.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ShowArrow(pTGAction, pUIObject, eDirection, fSpacing = 0.0, kColor = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (pUIObject == None):
		return 0
		
	# Store our arrow information in global dictionary so we can access
	# to it later to refresh.  We're using the direction as the key, so
	# there cannot be two of the same type of arrow on the same UI object.
	global g_dCurrentArrows
	g_dCurrentArrows[eDirection] = [pUIObject, fSpacing, kColor]
	
	# Display the arrow
	MissionLib.ShowPointerArrow(None, pUIObject, eDirection, fSpacing, kColor)
	
	# Start a timer that will refresh the arrow every 1/4 sec.  If we already
	# have a timer, don't create another.
	if (g_idArrowRefreshTimer != App.NULL_ID):
		return 0
	
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	pTimer	= MissionLib.CreateTimer(ET_ARROW_REFRESH_TIMER, __name__ + ".RefreshArrows", fStartTime + 0.125, 0.125, -1)
	global g_idArrowRefreshTimer
	g_idArrowRefreshTimer = pTimer.GetObjID()
	
	return 0
	
################################################################################
##	RefreshArrows()
##
##	Redraw the arrows in our global dictionary.  Called from timer event.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def RefreshArrows(TGObject, pEvent):
	# Hide all the arrow so they don't overlap
	MissionLib.HidePointerArrows()
	
	# Go though the dictionary and update all our arrows
	lArrowDirections = g_dCurrentArrows.keys()
	for eDirection in lArrowDirections:
		MissionLib.ShowPointerArrow(None, g_dCurrentArrows[eDirection][ARROW_OBJECT], eDirection,
			g_dCurrentArrows[eDirection][ARROW_SPACING], g_dCurrentArrows[eDirection][ARROW_COLOR])

################################################################################
##	HideArrows()
##
##	Script action that hides any arrows in the global dictionary.  Stops the
##	refresh timer as well.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def HideArrows(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Clear the dictionary
	global g_dCurrentArrows
	g_dCurrentArrows = {}
	
	# Stop the timer
	if (g_idArrowRefreshTimer != App.NULL_ID):
		App.g_kTimerManager.DeleteTimer(g_idArrowRefreshTimer)
		global g_idArrowRefreshTimer
		g_idArrowRefreshTimer = App.NULL_ID
	
	# Hide the arrows
	MissionLib.HidePointerArrows()
	
	return 0
		
################################################################################
##	Terminate()
##	
##  Called when mission ends to free resources
##	
##	Args: pMission - the mission object
##	
##	Return: None
################################################################################
def Terminate(pMission):
	# Mark our flag
	global g_bMissionTerminate
	g_bMissionTerminate = 0

	# Remove any other ships that might be floating around the warp set.
	MissionLib.DeleteShipsFromWarpSetExceptForMe()
	
	# Hide all our arrows
	HideArrows()
	
	# Delete all of our goals
	MissionLib.DeleteAllGoals()
	
	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()
	
	# Destroy all our info boxes
	lBoxIDs	= GetBoxIDList()
	for idBox in lBoxIDs:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)
	
	# Remove the instance handlers
	RemoveInstanceHandlers()
	
	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if (g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# unload the database: "data/TGL/Bridge Menus.tgl"
	if (g_pDatabase):
		App.g_kLocalizationManager.Unload(g_pDatabase)
	
	# Stop the prod timer if it's running
	StopProdTimer()
	
################################################################################
##	RemoveInstanceHandlers()
##
##	Removes the instance handlers we registered with the players ship and crew
##	members.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RemoveInstanceHandlers():
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".FriendlyFireReportHandler")
		pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".FriendlyFireGameOverHandler")

	# Remove instance handler on players ship for Weapon Fired event
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		# Instance handler for the Subsystem Damaged event.
		pPlayer.RemoveHandlerForInstance(App.ET_SUBSYSTEM_DAMAGED, __name__+".PlayerSubsystemDamaged")

	# Handler for the in and out of tactical event
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow != None):
		pTopWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL, __name__ + ".TacticalToggleHandler")
		# Handler for toggling to map mode
		pTacticalWindow = pTopWindow.FindMainWindow(App.MWT_BRIDGE)
		if (pTacticalWindow != None):
			pTacticalWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_MAP_MODE,			__name__ + ".MapToggleHandler")
			pTacticalWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	__name__ + ".MapToggleHandler")

	# Picard handlers
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicard.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")		

	# Kiska handlers
	pKiska = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")
	if (pKiska != None):
		pKiska.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pKiskaMenu = pKiska.GetMenu()
		if (pKiskaMenu != None):
			pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL,		__name__ + ".HailHandler")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			# Remove instance handler on Warp button event
			pWarpButton = Bridge.BridgeUtils.GetWarpButton()
			if (pWarpButton != None):
				pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")

	# Miguel handlers
	pMiguel = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Science")
	if (pMiguel!= None):
		pMiguel.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pMiguelMenu = pMiguel.GetMenu()
		if (pMiguelMenu != None):
			pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN,			__name__ + ".ScanHandler")
			pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		
	# Saffi handlers
	pSaffi = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	if (pSaffi != None):
		pSaffi.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pSaffiMenu = pSaffi.GetMenu()
		if (pSaffiMenu != None):
			pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")	

	# Felix handlers
	pFelix = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if (pFelix != None):
		pFelix.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pFelixMenu = pFelix.GetMenu()
		if (pFelixMenu != None):
			pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Brex handlers
	pBrex = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
	if (pBrex != None):
		pBrex.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pBrexMenu = pBrex.GetMenu()
		if (pBrexMenu != None):
			pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")


def RelocateSubtitle (pAction):
	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
	pSubtitle.SetPositionForMode (App.SubtitleWindow.SM_SPECIAL_FELIX, 1)	# Now reposition subtitle for felix mode.
	return 0

def RelocateSubtitle2 (pAction):
	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
	pSubtitle.SetPositionForMode (App.SubtitleWindow.SM_CINEMATIC)	# Put subtitles back in cinematic mode.
	return 0

