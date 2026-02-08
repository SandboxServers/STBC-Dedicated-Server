###############################################################################
#	Filename:	E1M1.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Episode 1 Mission 1
#
#	Created:	10/24/00 -	Bill Morrison
#	Modified:	01/15/02 -	Jess VanDerwalker
###############################################################################
import App
import loadspacehelper
import MissionLib
import BridgeHandlers
import Actions.MissionScriptActions
import Bridge.BridgeUtils
import Bridge.BridgeMenus
import Bridge.HelmMenuHandlers
import Systems.Starbase12.Starbase12_S
import AI.Compound.DockWithStarbase

# For debugging
#kDebugObj = App.CPyDebug()

# Flags used for bools
TRUE				= 1
FALSE				= 0

#  Declare global variables
g_pMissionDatabase	= None
g_pGeneralDatabase	= None
g_pDatabase			= None

g_bMissionTerminate = None

g_bSequenceRunning	= None

g_pSaffi	= None
g_pKiska	= None
g_pFelix	= None
g_pMiguel	= None
g_pBrex		= None
g_pPicard	= None

g_bDryDockUndock		= None

g_idTextBanner	= None

g_bIntrosDone			= None
g_bCameraReset			= None
g_bInCharacterSelection	= None
g_bPlayerInspecting		= None
g_bSaffiClicked			= None
g_bKiskaCongrats		= None
g_bFelixCongrats		= None
g_bMiguelCongrats		= None
g_bBrexCongrats			= None

g_bInObjectives				= None
g_bPlayerCheckedObjective	= None

g_bTacticalViewChecked	= None
g_bInTacticalView		= None
g_bSuggestWarpDone		= None
g_bInNavTutorial		= None
g_bInWarpTutorial		= None
g_bInDockSequence		= None

g_iProdTimer		= None
g_iProdToStarbase12	= None
g_iProdToVesuvi6	= None

g_bPlayerArriveStarbase		= None
g_bPlayerCloseToStarbase	= None
g_bDockDisabled				= None
g_bGraffHailed				= None
g_bDryDockHailed			= None
g_bSFHailed					= None
g_bDevoreHailed				= None

g_bFirstDockWithStarbase	= None
g_bSuppliesReceived			= None
g_bPlayerUndockingSB		= None

g_lFriendlyShips	= []

g_iMissionState	= None
DEFAULT			= 0
IN_DRYDOCK		= 1
IN_STARBASE		= 2

g_bInTutorial				= None
g_iTutorialState			= None
g_bCharWindowLock			= None
g_bSettingCourseThreeDone	= None
g_bTacticalInfoBoxClosed	= None

# Global IDs for info boxes
g_idPicardTutorialBox	= None
g_idTacticalViewBox1	= None
g_idSettingCourseBox1	= None
g_idSettingCourseBox2	= None
g_idSettingCourseBox3	= None
g_idObjectivesBox1		= None
g_idObjectivesBox2		= None
g_idNavPointBox1		= None
g_idNavPointBox2		= None
g_idDockBox1			= None

# Global dictionary of arrows currently
# being displayed.
g_dCurrentArrows	= None

# Ennumeration used with g_dCurrentArrows
ARROW_OBJECT	= 0
ARROW_SPACING	= 1
ARROW_COLOR		= 2

# ID for the arrow refresh timer
g_idArrowRefreshTimer	= None

# Global dictonary for info box sizes
# and placement for different resolutions
g_dInfoBoxSpecs	= None

#Ennumeration to access g_dInfoBoxSpecs
BOX_LEFT	= 0
BOX_TOP		= 1
BOX_WIDTH	= 2
BOX_HEIGHT	= 3

# Global that tells us our resolution
g_sResolutionSetting	= None

# Event types
ET_PROD_TIMER			= None
ET_OBJECTIVE_PRESSED	= None
ET_SF_ARRIVE_TIMER		= None
ET_CLOSE_HELP_BOX		= None
ET_OBJECTIVES_MENU_OPEN	= None
ET_COURSE_MENU_OPEN		= None
ET_NAV_POINTS_MENU_OPEN	= None


# Event types for Picards help buttons
ET_CHARACTER_SELECT_TUTORIAL	= None
ET_OBJECTIVES_TUTORIAL			= None
ET_SET_COURSE_TUTORIAL			= None
ET_NAV_POINTS_TUTORIAL			= None
ET_DOCK_TUTORIAL				= None
ET_ARROW_REFRESH_TIMER			= None

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
	loadspacehelper.PreloadShip("Galaxy", 2)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("DryDock", 3)
	loadspacehelper.PreloadShip("Shuttle", 3)
	loadspacehelper.PreloadShip("SpaceFacility", 1)
	loadspacehelper.PreloadShip("Nebula", 1)
	loadspacehelper.PreloadShip("Akira", 1)
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
	# Initialize our global variables
	InitializeGlobals(pMission)

	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")

	# Create character sets
	CreateSets()

	# Add Picard to the bridge and set up his buttons
	CreatePicard()

	# Get the current resolution
	GetCurrentResolution()
	
	# Initalize global pointers for our bridge crew
	InitializeCrewPointers()
	
	# Create our starting systems and load placements
	CreateStartingRegions()
	
	# Create the starting systems in the helm menu
	CreateStartingMenus()
	
	# Start Saffi in the TurobLift
	g_pSaffi.SetStanding(1)
	g_pSaffi.SetRandomAnimationEnabled(0)
	g_pSaffi.SetHidden(1)
	g_pSaffi.SetLocation("DBL1M")

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()
		
	# Create our starting objects
	CreateStartingObjects(pMission)

	# Setup more mission-specific event handlers.
	SetupEventHandlers(pMission)
	
	# Set the starting state of the player
	SetPlayerState()

	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	
	# Create the info boxes
	SetupTacticalViewInfoBox()
	CreatePicardInfoBox()
	SetupSettingCourseInfoBoxes()
	SetupObjectiveInfoBoxes()
	SetupNavPointInfoBoxes()
	SetupDockInfoBoxes()

	# Start the mission
	Briefing()

################################################################################
##	InitializeGlobals()
##
##	Initializes all the values for our global variables.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
	# General flags used with bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0
	
	# Globals for the TGL database stuff
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 1/E1M1.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Flag to show when mission is ending
	global g_bMissionTerminate
	g_bMissionTerminate	= 1
	
	# Flag to check if sequence running
	global g_bSequenceRunning
	g_bSequenceRunning	= FALSE
	
	# Flag to see if we are undocking from drydock
	global g_bDryDockUndock
	g_bDryDockUndock	= FALSE
	
	# Global ID for the skip text banner
	global g_idTextBanner
	g_idTextBanner	= None
	
	# Flags to see if player has inspected crew
	global g_bIntrosDone
	global g_bCameraReset
	global g_bInCharacterSelection
	global g_bPlayerInspecting
	global g_bSaffiClicked
	global g_bKiskaCongrats
	global g_bFelixCongrats
	global g_bMiguelCongrats
	global g_bBrexCongrats
	g_bIntrosDone			= FALSE
	g_bCameraReset			= FALSE
	g_bInCharacterSelection	= FALSE
	g_bPlayerInspecting		= FALSE
	g_bSaffiClicked			= FALSE
	g_bKiskaCongrats		= FALSE
	g_bFelixCongrats		= FALSE
	g_bMiguelCongrats		= FALSE
	g_bBrexCongrats			= FALSE

	# Flag to see if player is checking objectives
	global g_bInObjectives
	global g_bPlayerCheckedObjective
	g_bInObjectives				= FALSE
	g_bPlayerCheckedObjective	= FALSE

	# Global flags to see what the player is doing
	global g_bTacticalViewChecked
	global g_bInTacticalView
	global g_bSuggestWarpDone
	global g_bInNavTutorial
	global g_bInWarpTutorial
	global g_bInDockSequence
	g_bTacticalViewChecked	= FALSE
	g_bInTacticalView		= FALSE
	g_bSuggestWarpDone		= FALSE
	g_bInNavTutorial		= FALSE
	g_bInWarpTutorial		= FALSE
	g_bInDockSequence		= FALSE
	
	# Globals used in prodding
	global g_iProdTimer
	global g_iProdToStarbase12
	global g_iProdToVesuvi6
	g_iProdTimer		= 0
	g_iProdToStarbase12	= 0
	g_iProdToVesuvi6	= 0

	
	# Globals to track player during Vesuvi6 supply stuff.
	global g_bGraffHailed
	global g_bPlayerArriveStarbase
	global g_bPlayerCloseToStarbase
	global g_bDockDisabled
	global g_bFirstDockWithStarbase
	global g_bSuppliesReceived
	global g_bPlayerUndockingSB
	g_bGraffHailed				= FALSE
	g_bPlayerCloseToStarbase	= FALSE
	g_bDockDisabled				= TRUE
	g_bPlayerArriveStarbase		= FALSE
	g_bFirstDockWithStarbase	= FALSE
	g_bSuppliesReceived			= FALSE
	g_bPlayerUndockingSB		= FALSE
	
	# Flags to track who we hailed
	global g_bDryDockHailed
	global g_bSFHailed
	global g_bDevoreHailed
	g_bDryDockHailed	= FALSE
	g_bSFHailed			= FALSE
	g_bDevoreHailed		= FALSE
	
	# List of friendly ships
	global g_lFriendlyShips
	g_lFriendlyShips	=	[
							"Starbase 12", "Devore", "San Francisco", "Dry Dock", "Dry Dock2", "Dry Dock3",
							"Station", "Shuttle1", "Shuttle2", "Shuttle3", "Nightingale"
							]

	# Flags used with communicate
	global g_iMissionState
	global DEFAULT
	global IN_DRYDOCK
	global IN_STARBASE
	g_iMissionState	= 0
	DEFAULT			= 0
	IN_DRYDOCK		= 1
	IN_STARBASE		= 2

	# Globals used in the tutorial sequences
	global g_bInTutorial
	global g_iTutorialState
	global g_bCharWindowLock
	global g_bSettingCourseThreeDone
	global g_bTacticalInfoBoxClosed
	g_bInTutorial				= FALSE
	g_iTutorialState			= 0
	g_bCharWindowLock			= FALSE
	g_bSettingCourseThreeDone	= FALSE
	g_bTacticalInfoBoxClosed	= FALSE
	
	# Global IDs for info boxes
	global g_idPicardTutorialBox
	global g_idTacticalViewBox1
	global g_idSettingCourseBox1
	global g_idSettingCourseBox2
	global g_idSettingCourseBox3
	global g_idObjectivesBox1
	global g_idObjectivesBox2
	global g_idNavPointBox1
	global g_idNavPointBox2
	global g_idDockBox1
	g_idPicardTutorialBox	= None
	g_idTacticalViewBox1	= None
	g_idSettingCourseBox1	= None
	g_idSettingCourseBox2	= None
	g_idSettingCourseBox3	= None
	g_idObjectivesBox1		= None
	g_idObjectivesBox2		= None
	g_idNavPointBox1		= None
	g_idNavPointBox2		= None
	g_idDockBox1			= None

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

	# Set our limits for the friendly fire warnings and game loss
	App.g_kUtopiaModule.SetMaxFriendlyFire(800)				# how many damage points the player can do total before losing
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(200)	# how many damage points before Saffi warns you

	# Event types
	global ET_PROD_TIMER
	global ET_OBJECTIVE_PRESSED
	global ET_SF_ARRIVE_TIMER
	global ET_CLOSE_HELP_BOX
	global ET_OBJECTIVES_MENU_OPEN
	global ET_COURSE_MENU_OPEN
	global ET_NAV_POINTS_MENU_OPEN
	ET_PROD_TIMER			= App.Mission_GetNextEventType()
	ET_OBJECTIVE_PRESSED	= App.Mission_GetNextEventType()
	ET_SF_ARRIVE_TIMER		= App.Mission_GetNextEventType()
	ET_CLOSE_HELP_BOX		= App.Mission_GetNextEventType()
	ET_OBJECTIVES_MENU_OPEN	= App.Mission_GetNextEventType()
	ET_COURSE_MENU_OPEN		= App.Mission_GetNextEventType()
	ET_NAV_POINTS_MENU_OPEN	= App.Mission_GetNextEventType()

	# Event types for Picards help buttons
	global ET_CHARACTER_SELECT_TUTORIAL
	global ET_OBJECTIVES_TUTORIAL
	global ET_SET_COURSE_TUTORIAL
	global ET_NAV_POINTS_TUTORIAL
	global ET_DOCK_TUTORIAL
	global ET_ARROW_REFRESH_TIMER
	ET_CHARACTER_SELECT_TUTORIAL	= App.Mission_GetNextEventType()
	ET_OBJECTIVES_TUTORIAL			= App.Mission_GetNextEventType()
	ET_SET_COURSE_TUTORIAL			= App.Mission_GetNextEventType()
	ET_NAV_POINTS_TUTORIAL			= App.Mission_GetNextEventType()
	ET_DOCK_TUTORIAL				= App.Mission_GetNextEventType()
	ET_ARROW_REFRESH_TIMER			= App.Mission_GetNextEventType()

	# Global that tells us our resolution
	# Set to 640x480 just to be safe
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
	# These values will be set depending on the language being used
	global g_dInfoBoxSpecs
	
	# Get the language being used out of the E1M1HelpText.TGL
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M1HelpText.tgl")
	pString = pDatabase.GetString("Language")
	App.g_kLocalizationManager.Unload(pDatabase)
	
	# We are using German Version
	if (pString.GetCString() == "German"):	
	#													 Left,	Top,	Width,	Height	
		g_dInfoBoxSpecs =	{
						"PicardBox"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.42],
										"800x600"	:	[0.68,	0.0,	0.3,	0.36],
										"1024x768"	:	[0.68,	0.0,	0.3,	0.26],
										"1280x1024"	:	[0.68,	0.0,	0.3,	0.15],
										"1600x1200"	:	[0.68,	0.0,	0.3,	0.11],
									},
						"TactView"	: {	"640x480"	:	[0.59,	0.0,	0.39,	0.565],
										"800x600"	:	[0.61,	0.0,	0.37,	0.51],
										"1024x768"	:	[0.68,	0.0,	0.3,	0.39],
										"1280x1024"	:	[0.68,	0.0,	0.3,	0.31],
										"1600x1200"	:	[0.68,	0.0,	0.3,	0.22],
									},
						"SetCourse"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.18],
										"800x600"	:	[0.5,	0.0,	0.3,	0.15],
										"1024x768"	:	[0.4,	0.0,	0.3,	0.11],
										"1280x1024"	:	[0.4,	0.0,	0.3,	0.06],
										"1600x1200"	:	[0.4,	0.0,	0.3,	0.04],
									},
						"Objectives": {	"640x480"	:	[0.68,	0.0,	0.3,	0.28],
										"800x600"	:	[0.68,	0.0,	0.3,	0.24],
										"1024x768"	:	[0.62,	0.0,	0.3,	0.16],
										"1280x1024"	:	[0.4,	0.0,	0.3,	0.1],
										"1600x1200"	:	[0.4,	0.0,	0.3,	0.07],
									},

						"NavBoxes"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.26],
										"800x600"	:	[0.5,	0.0,	0.3,	0.24],
										"1024x768"	:	[0.4,	0.0,	0.3,	0.14],
										"1280x1024"	:	[0.4,	0.0,	0.3,	0.11],
										"1600x1200"	:	[0.4,	0.0,	0.3,	0.08],
									},
						"DockBox"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.24],
										"800x600"	:	[0.5,	0.0,	0.3,	0.2],
										"1024x768"	:	[0.4,	0.0,	0.3,	0.13],
										"1280x1024"	:	[0.4,	0.0,	0.3,	0.09],
										"1600x1200"	:	[0.4,	0.0,	0.3,	0.05],
									},
						}

	# We will default to the English Version
	else:
		g_dInfoBoxSpecs =	{
	#													 Left,	Top,	Width,	Height	
						"PicardBox"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.5],
										"800x600"	:	[0.68,	0.0,	0.3,	0.36],
										"1024x768"	:	[0.68,	0.0,	0.3,	0.23],
										"1280x1024"	:	[0.68,	0.0,	0.3,	0.15],
										"1600x1200"	:	[0.68,	0.0,	0.3,	0.11],
									},
						"TactView"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.6],
										"800x600"	:	[0.68,	0.0,	0.3,	0.51],
										"1024x768"	:	[0.68,	0.0,	0.3,	0.36],
										"1280x1024"	:	[0.68,	0.0,	0.3,	0.26],
										"1600x1200"	:	[0.68,	0.0,	0.3,	0.22],
									},
						"SetCourse"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.5],
										"800x600"	:	[0.5,	0.0,	0.3,	0.13],
										"1024x768"	:	[0.4,	0.0,	0.3,	0.07],
										"1280x1024"	:	[0.4,	0.0,	0.3,	0.06],
										"1600x1200"	:	[0.4,	0.0,	0.3,	0.06],
									},
						"Objectives": {	"640x480"	:	[0.68,	0.0,	0.3,	0.5],
										"800x600"	:	[0.68,	0.0,	0.3,	0.22],
										"1024x768"	:	[0.62,	0.0,	0.3,	0.14],
										"1280x1024"	:	[0.4,	0.0,	0.3,	0.1],
										"1600x1200"	:	[0.4,	0.0,	0.3,	0.07],
									},

						"NavBoxes"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.5],
										"800x600"	:	[0.5,	0.0,	0.3,	0.2],
										"1024x768"	:	[0.4,	0.0,	0.3,	0.2],
										"1280x1024"	:	[0.4,	0.0,	0.3,	0.08],
										"1600x1200"	:	[0.4,	0.0,	0.3,	0.08],
									},
						"DockBox"	: {	"640x480"	:	[0.68,	0.0,	0.3,	0.5],
										"800x600"	:	[0.5,	0.0,	0.3,	0.2],
										"1024x768"	:	[0.4,	0.0,	0.3,	0.13],
										"1280x1024"	:	[0.4,	0.0,	0.3,	0.07],
										"1600x1200"	:	[0.4,	0.0,	0.3,	0.07],
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
##	We'll also set their initial yes sir line.
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
	global g_pPicard
	
	g_pKiska	= App.CharacterClass_GetObject(pBridge, "Helm")
	g_pFelix	= App.CharacterClass_GetObject(pBridge, "Tactical")
	g_pSaffi	= App.CharacterClass_GetObject(pBridge, "XO")
	g_pMiguel	= App.CharacterClass_GetObject(pBridge, "Science")
	g_pBrex		= App.CharacterClass_GetObject(pBridge, "Engineer")
	g_pPicard	= App.CharacterClass_GetObject(pBridge, "Picard")

	g_pKiska.SetYesSir("E1M1KiskaSir")
	g_pFelix.SetYesSir("E1M1FelixSir")
	g_pMiguel.SetYesSir("E1M1MiguelSir")
	g_pBrex.SetYesSir("E1M1BrexSir")

################################################################################
##	CreateStaringRegions()
##
##	Creates all the regions used in this mission and loads our mission
##	specific placement files into them.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateStartingRegions():
	# Create Starbase12
	pStarbaseSet	= MissionLib.SetupSpaceSet("Systems.Starbase12.Starbase12")
	# Create the Dry Dock set
	pDryDockSet = MissionLib.SetupSpaceSet("Systems.DryDock.DryDock")
	# Create Vesuvi6 set	
	pVesuvi6Set = MissionLib.SetupSpaceSet("Systems.Vesuvi.Vesuvi6")
	
	# Load our placements into the sets
	import Dock_P
	import E1M1_Starbase12_P
	
	Dock_P.LoadPlacements(pDryDockSet.GetName())
	E1M1_Starbase12_P.LoadPlacements(pStarbaseSet.GetName())
	
################################################################################
##	CreateStaringMenus()
##
##	Creates our starting system menus in Helm
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateStartingMenus():
	# Create the Starbase menu.
	import Systems.Starbase12.Starbase
	import Systems.DryDock.DryDockSystem
	pStarbaseMenu	= Systems.Starbase12.Starbase.CreateMenus()
	pDryDockMenu	= Systems.DryDock.DryDockSystem.CreateMenus()

	# Link the Starbase 12 menu to special placement
	MissionLib.LinkMenuToPlacement("Starbase 12", None, "PlayerSpecialStart")
	
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
	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	# Import Picard and add him to the bridge
	import Bridge.Characters.Picard
	pPicard = App.CharacterClass_GetObject(pBridgeSet, "Picard")
	if not (pPicard):
		pPicard = Bridge.Characters.Picard.CreateCharacter(pBridgeSet)
		Bridge.Characters.Picard.ConfigureForGalaxy(pPicard)
	pPicard.SetHidden(1)
	pPicard.SetLocation("DBL1M")

	# Create the buttons in Picards menu and create
	# function handlers for them.
	pPicard.AddPythonFuncHandlerForInstance(ET_CHARACTER_SELECT_TUTORIAL,	__name__ + ".ExplainCharacterSelect")
	pPicard.AddPythonFuncHandlerForInstance(ET_OBJECTIVES_TUTORIAL,			__name__ + ".ExplainObjectives")
	pPicard.AddPythonFuncHandlerForInstance(ET_SET_COURSE_TUTORIAL,			__name__ + ".ExplainWarp")
	pPicard.AddPythonFuncHandlerForInstance(ET_NAV_POINTS_TUTORIAL,			__name__ + ".ExplainNavPoints")
	pPicard.AddPythonFuncHandlerForInstance(ET_DOCK_TUTORIAL,				__name__ + ".ExplainDock")

	# Create the starting buttons in Picards menu
	pPicMenu = pPicard.GetMenu()
	pPicMenu.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("CrewSelect"), ET_CHARACTER_SELECT_TUTORIAL, 0, pPicard))
	pPicMenu.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Objectives"), ET_OBJECTIVES_TUTORIAL, 0, pPicard))
	pPicMenu.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("SettingCourse"), ET_SET_COURSE_TUTORIAL, 0, pPicard))

	# Disable Picards menu so we can't click
	# We'll enable it later if we need it.
	pPicard.SetMenuEnabled(0)

################################################################################
##	CreatePicardInfoBox()
##
##	Create the info box that will open and close with Picards menu.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreatePicardInfoBox():
	# Just in case the box already exists, destroy it
	if (g_idPicardTutorialBox != None):
		MissionLib.DestroyInfoBox(g_idPicardTutorialBox)

	# Check what resolution were at.
	pMode = App.GraphicsModeInfo_GetCurrentMode()
	pRes = pMode.GetCurrentResolution()

	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["PicardBox"][g_sResolutionSetting]
		
	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M1HelpText.tgl")
	
	# Get Picard so we can attach the box to his menu
	pPicard	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("PicardHelpTitle"), 
				pDatabase.GetString("PicardHelp1A"),
				fWidth, fHeight, None, None, App.ET_CHARACTER_MENU, pPicard, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idPicardTutorialBox
	g_idPicardTutorialBox = pBox.GetObjID()	

################################################################################
##	CreateSets()
##
##	Creates and populates the viewscreen sets we'll need for this mission.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateSets():
	# Starbase set with Liu and Graff
	pStarbaseSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -35, 65, -1.55)
	pLiu			= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)
	
	# Zeiss on the DBridgeSet
	pDBridgeSet	= MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -30, 65, -1.55)
	pZeiss		= MissionLib.SetupCharacter("Bridge.Characters.Zeiss", "DBridgeSet")
	
	# Martin and the E-bridge set
	pEBridgeSet	= MissionLib.SetupBridgeSet("EBridgeSet", "data/Models/Sets/EBridge/EBridge.nif", -30, 65, -1.55)
	pMartin 	= MissionLib.SetupCharacter("Bridge.Characters.Martin", "EBridgeSet")
	
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
	# Do our ship affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	for sName in g_lFriendlyShips:
		pFriendlies.AddName(sName)
	
	# Get the sets we need
	pStarbaseSet	= App.g_kSetManager.GetSet("Starbase12")
	pDryDockSet		= App.g_kSetManager.GetSet("DryDock")
	
	# Create the players ship
	pPlayer		= MissionLib.CreatePlayerShip("Galaxy", pDryDockSet, "player", "DryDock Start")
	# Create the other objects needed
	# In drydock set
	pDryDock	= loadspacehelper.CreateShip("DryDock", pDryDockSet, "Dry Dock", "DryDock Start")
	pDryDock1	= loadspacehelper.CreateShip("DryDock", pDryDockSet, "Dry Dock2", "DryDock2")
	pDryDock2	= loadspacehelper.CreateShip("DryDock", pDryDockSet, "Dry Dock3", "DryDock3")
	pStation	= loadspacehelper.CreateShip("SpaceFacility", pDryDockSet, "Station", "StationPlacement")
	pNight		= loadspacehelper.CreateShip("Nebula", pDryDockSet, "Nightingale", "DryDock2")
	pShuttle1	= loadspacehelper.CreateShip("Shuttle", pDryDockSet, "Shuttle1", "Shuttle1Start")
	pShuttle2	= loadspacehelper.CreateShip("Shuttle", pDryDockSet, "Shuttle2", "Shuttle2Start")
	pShuttle3	= loadspacehelper.CreateShip("Shuttle", pDryDockSet, "Shuttle3", "Shuttle3Start")

	# Set all the objects in the dry dock set not hailable
	for pObject in [ pShuttle1, pShuttle2, pShuttle3 ]:
		pObject.SetHailable(FALSE)
	# Set the none moving objects static
	for pObject in [ pDryDock, pDryDock1, pDryDock2, pStation, pNight ]:
		pObject.SetStatic(TRUE)
		
	# In StarbaseSet
	pStarbase	= loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	pDevore		= loadspacehelper.CreateShip("Akira", pStarbaseSet, "Devore", "Docking Exit")
	pDevore.ReplaceTexture("Data/Models/Ships/Akira/Devore.tga", "ID")

	# Disable collisions between the player and the drydock.  They'll be
	# reenabled once the ship finishes undocking.
	pDryDock.EnableCollisionsWith(pPlayer, 0)
	
	# Give all the dry dock ships AI
	import E1M1_AI_Stay
	import E1M1_AI_Shuttle1
	import E1M1_AI_Shuttle2
	pDryDock.SetAI(E1M1_AI_Stay.CreateAI(pDryDock))
	pDryDock1.SetAI(E1M1_AI_Stay.CreateAI(pDryDock1))
	pDryDock2.SetAI(E1M1_AI_Stay.CreateAI(pDryDock2))
	pStation.SetAI(E1M1_AI_Stay.CreateAI(pStation))
	pNight.SetAI(E1M1_AI_Stay.CreateAI(pNight))
	pShuttle1.SetAI(E1M1_AI_Shuttle1.CreateAI(pShuttle1))
	pShuttle2.SetAI(E1M1_AI_Shuttle2.CreateAI(pShuttle2))

################################################################################
##	SetupEventHandlers()
##	
##	Sets up the event handlers to listen for broadcast events that we're
##	going to use in this mission
##	
##	Args:	pMission	- The mission object.
##	
##	Return: None
################################################################################
def SetupEventHandlers(pMission):
	# Object entrance event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__+".EnterSet")
	# Ship dying event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectDying")
	# Goals button pressed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_REPORT_GOAL_INFO, pMission, __name__+".ObjectivePressed")
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
	
	# Special handlers for menu buttons
	# Helm buttons
	pKiskaMenu = Bridge.BridgeUtils.GetBridgeMenu("Helm")
	if (pKiskaMenu != None):
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_DOCK,				__name__ + ".DockButtonClicked")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL,				__name__ + ".HailHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_SET_COURSE,		__name__ + ".SetCourseHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(ET_COURSE_MENU_OPEN,		__name__ + ".CourseMenuOpened")
		pKiskaMenu.AddPythonFuncHandlerForInstance(ET_NAV_POINTS_MENU_OPEN,	__name__ + ".NavPointMenuOpened")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,		__name__ + ".CommunicateHandler")
		# Instance handler for warp button
		pWarpButton = Bridge.BridgeUtils.GetWarpButton()
		if (pWarpButton != None):
			pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")

	# XO buttons
	pSaffiMenu = Bridge.BridgeUtils.GetBridgeMenu("XO")
	if (pSaffiMenu != None):
		pSaffiMenu.AddPythonFuncHandlerForInstance(ET_OBJECTIVES_MENU_OPEN,	__name__ + ".ObjectiveMenuOpened")
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_SET_ALERT_LEVEL,	__name__ + ".SetAlertLevelHandler")
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
	
	# Instance handlers for Felix
	pFelixMenu = Bridge.BridgeUtils.GetBridgeMenu("Tactical")
	if (pFelixMenu != None):
		pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		
	# Instance handlers for Miguel
	pMiguelMenu = Bridge.BridgeUtils.GetBridgeMenu("Science")
	if (pMiguelMenu != None):
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		
	# Instance handlers for Brex
	pBrexMenu = Bridge.BridgeUtils.GetBridgeMenu("Engineer")
	if (pBrexMenu != None):
		pBrexMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,		__name__ + ".CommunicateHandler")
	
	# Instance handlers on the crews menu events.
	g_pFelix.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pSaffi.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pKiska.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pMiguel.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
	g_pBrex.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pPicard.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")

	# Create the proximity checks on the Starbase
	pStarbase	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Starbase12"), "Starbase 12")
	pPlayer		= MissionLib.GetPlayer()
	if (pStarbase != None) and (pPlayer != None):
		MissionLib.ProximityCheck(pStarbase, -690, [pPlayer], __name__+".StarbaseInnerProximity")
		MissionLib.ProximityCheck(pStarbase, 690, [pPlayer], __name__+".StarbaseOuterProximity")
		
################################################################################
##	EnterSet()
##
##	Event handler called whenever an object enters a set.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def EnterSet(TGObject, pEvent):
	# Check if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	# Make sure it's a ship
	if (pShip == None):
		return
	# Bail if it's dead
	if (pShip.IsDead()):
		return
	pSet		= pShip.GetContainingSet()
		
	sShipName	= pShip.GetName()
	sSetName 	= pSet.GetName()
	
	# If the player is entering warp, stop our timers
	if (sShipName == "player") and (sSetName == "warp"):
		StopProdTimer()
		
	# See if the player has entered Starbase 12.
	if (sShipName == "player") and (sSetName == "Starbase12") and (g_bPlayerArriveStarbase == FALSE) and (g_bSuppliesReceived == FALSE):
		global g_bPlayerArriveStarbase
		g_bPlayerArriveStarbase	= TRUE
		PlayerArrivesStarbase12()
		# If the cutscene bars are down, raise them
		pTop = App.TopWindow_GetTopWindow()
		if (pTop.IsCutsceneMode()):
			pTop.AbortCutscene()
		# Get the Starbase and force it to be IDd
		pStarbase = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Starbase12"), "Starbase 12")
		MissionLib.IdentifyObjects(pStarbase)
		# Disable the warp tutorial button
		pPicardMenu = g_pPicard.GetMenu()
		if (pPicardMenu != None):
			pButton = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("SettingCourse"))
			if (pButton != None):
				pButton.SetDisabled()
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ObjectDying()
##
##	Handler called if an object is exploding/ dying.
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

	# If a ship was destroyed in DryDock, must have been the player,
	# so kick 'em out of the captains chair
	if (sSetName == "DryDock") and (sShipName != "player"):
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "DontShoot7", "Captain", 1, g_pGeneralDatabase)
		
		pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
		pGameOver.Play()

	# All done, pass the event on
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ObjectivePressed()
##
##	Broadcast handler called when an objective is pressed in Saffi's menu.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- Thge event that was sent.
##
##	Return:	None
################################################################################
def ObjectivePressed(TGObject, pEvent):
	# Check our flag
	if (g_bPlayerCheckedObjective == FALSE) and (g_bInObjectives == TRUE):
		# We've been waiting for the player to hit the objectives
		# button.  Call our function
		global g_bPlayerCheckedObjective
		g_bPlayerCheckedObjective = TRUE
		global g_bInObjectives
		g_bInObjectives = FALSE
		
		CheckTacticalView()
	
	# If the player checks the objective during the inspection,
	# just set the flag.
	elif (g_bPlayerCheckedObjective == FALSE) and (g_bInCharacterSelection == TRUE):
		global g_bPlayerCheckedObjective
		g_bPlayerCheckedObjective = TRUE
	
	# If were in a tutorial sequence, increase our counter
	if (g_iTutorialState == 2):
		global g_iTutorialState
		g_iTutorialState = 3
		
	# All done so call our next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ResolutionChanged()
##
##	Broadcast handler called when the resolution changes.  Goes through and
##	checks to see what box is visible, so that it can be recreated.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ResolutionChanged(TGObject, pEvent):
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
	SetupTacticalViewInfoBox()
	CreatePicardInfoBox()
	SetupSettingCourseInfoBoxes()
	SetupObjectiveInfoBoxes()
	SetupNavPointInfoBoxes()
	SetupDockInfoBoxes()

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
				g_idPicardTutorialBox, g_idTacticalViewBox1, g_idSettingCourseBox1, g_idSettingCourseBox2,
				g_idSettingCourseBox3, g_idObjectivesBox1, g_idObjectivesBox2, g_idNavPointBox1,
				g_idNavPointBox2, g_idDockBox1
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
		if (sShipName == "Starbase 12"):
			pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1FriendlyFire1", "Captain", 1, g_pMissionDatabase)
		elif (sShipName == "Dry Dock") or (sShipName == "Dry Dock2") or (sShipName == "Dry Dock3") or (sShipName == "Station"):
			pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1FireDryDock1", "Captain", 1, g_pMissionDatabase)
		else:
			pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1FriendlyFire2", "Captain", 1, g_pMissionDatabase)

		pSaffiLine.Play()
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
	# Get the ship that was fired on
	pShip	= App.ShipClass_Cast(pEvent.GetSource())
	if (pShip == None):
		return
	sShipName	= pShip.GetName()
	
	pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1FriendlyFire3", "Captain", 1, g_pMissionDatabase)
	# End the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
	pGameOver.Play()
		
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
	
	# See if we're on the bridge or not
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow.IsBridgeVisible()):
		MissionLib.HideInfoBox(None, g_idTacticalViewBox1)
		# If we're comming back to the bridge, do the warp suggestion
		if (g_bInTacticalView == TRUE):
			WarpSequence()
	elif (g_bTacticalInfoBoxClosed == FALSE):
		MissionLib.ShowInfoBox(None, g_idTacticalViewBox1)

################################################################################
##	MapToggleHandler()
##
##	Handler called when player tries to toggle to map mode.  Also handles event
##	for toggling cinematic mode.
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
##	DockButtonClicked()
##
##	Handler called when Kiska's "Undock" button is pressed.  Takes us out of
##	the Dry Dock, and disables the button.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def DockButtonClicked(TGObject, pEvent):
	# Get the player.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# If we're doing the tutorial sequence, increase the counter
	if (g_bInDockSequence == TRUE) and (g_iTutorialState == 1):
		global g_iTutorialState
		g_iTutorialState = 2
		
	# If we're in the DockTutorial, do this stuff,
	# otherwise call the next handler.
	if (g_bDryDockUndock == TRUE):
		# Have Kiska turn back
		Bridge.BridgeMenus.ButtonClicked(TGObject, pEvent)
	
		# If were in the DockTutorial, do our short cutscene
		UndockCutscene()

	# We're docking with the Starbase for the first time so do our special sequence
	elif (pPlayer.GetContainingSet().GetName() == "Starbase12") and (g_bFirstDockWithStarbase == FALSE):
		global g_bFirstDockWithStarbase
		g_bFirstDockWithStarbase = TRUE
		
		# See if we're docking from inside the Starbase
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
		pStarbase = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Starbase12"), "Starbase 12")
		if (pStarbase == None):
			return
		bIsInside = AI.Compound.DockWithStarbase.IsInViewOfInsidePoints(pPlayer, pStarbase)
		
		# The players Impulse engines are not set to 100%,
		# set them to 100%.
		pImpulse = pPlayer.GetImpulseEngineSubsystem()
		if (pImpulse != None):
			fPercent = pImpulse.GetNormalPowerPercentage()			
			if (fPercent != 1.0) or (not pImpulse.IsOn()):
				pImpulse.TurnOn()
				pImpulse.SetPowerPercentageWanted(1.0)
				# Get the Warp engines and turn those on to
				pWarp = pPlayer.GetWarpEngineSubsystem()
				if (pWarp != None):
					pWarp.TurnOn()
					pWarp.SetPowerPercentageWanted(1.0)
		
		# Zoom the camera out.
		pSet = App.g_kSetManager.GetSet("bridge")
		if (pSet != None):
			pCamera = App.ZoomCameraObjectClass_Cast(pSet.GetCamera("maincamera"))
			if (pCamera != None):
				pCamera.ToggleZoom(App.g_kUtopiaModule.GetGameTime())

		# Set the sequence to play when docked
		Systems.Starbase12.Starbase12_S.SetGraffDockingAction(SpecialDockSequence(bIsInside))

		# Disable Picard's docking tutorial button so we can't do tutorial again
		pPicardMenu = g_pPicard.GetMenu()
		if (pPicardMenu != None):
			pButton = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Docking"))
			if (pButton != None):
				pButton.SetDisabled()
					
		# Play a line from Picard delayed if outside the starbase.
		if (bIsInside == FALSE):
			pSequence = App.TGSequence_Create()
			pPicardExplain1 = App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1ExplainStarbase1", None, 0, g_pMissionDatabase)
			pSequence.AppendAction(pPicardExplain1, 2.5)
			pSequence.Play()
		
		# Call the next handler so the thing plays
		TGObject.CallNextHandler(pEvent)
		
	else:
		# We're doing just the standard dock thing
		TGObject.CallNextHandler(pEvent)

###############################################################################
#	ReenablePlayerDrydockCollisions
#	
#	Reenable collisions between the player ship and the drydock.
#	
#	Args:	pAction	- The action that's calling us.
#	
#	Return:	0
###############################################################################
def ReenablePlayerDrydockCollisions(pAction):
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		pSet = pPlayer.GetContainingSet()
		if pSet:
			pDryDock = App.ShipClass_GetObject(pSet, "Dry Dock")
			if pDryDock:
				pDryDock.EnableCollisionsWith(pPlayer, 1)

	return 0

################################################################################
##	HailHandler()
##
##	Handler called when Kiska's hail button is pressed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def HailHandler(TGObject, pEvent):
	# Get the player and their target
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pTarget	= App.ObjectClass_Cast(pEvent.GetSource())
	if (pTarget == None):
		return
		
	sTargetName = pTarget.GetName()

	# See if the target is something we care about
	if (sTargetName == "Devore") and (g_bDevoreHailed == FALSE):
		global g_bDevoreHailed
		g_bDevoreHailed = TRUE
		MissionLib.CallWaiting(None, TRUE)		
		HailDevore()
		
	elif (sTargetName == "San Francisco") and (g_bSFHailed == FALSE):
		global g_bSFHailed
		g_bSFHailed = TRUE
		MissionLib.CallWaiting(None, TRUE)		
		HailSanFrancisco()
	
	elif (sTargetName == "Nightingale"):
		MissionLib.CallWaiting(None, TRUE)			
		NightingaleHail()
		
	elif (sTargetName in [ "Dry Dock", "Dry Dock2", "Dry Dock3", "Station" ]) and (g_bDryDockHailed == FALSE):
		global g_bDryDockHailed
		g_bDryDockHailed = TRUE
		MissionLib.CallWaiting(None, TRUE)
		pKiskaHail = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 0, g_pGeneralDatabase)
		pKiskaHail.Play()
		FirstDryDockHail()

	elif (sTargetName in [ "Dry Dock", "Dry Dock2", "Dry Dock3", "Station" ]) and (g_bDryDockHailed == TRUE):
		MissionLib.CallWaiting(None, TRUE)
		pKiskaHail = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 0, g_pGeneralDatabase)
		pKiskaHail.Play()
		SecondDryDockHail()
		
	# We're hail the Starbase for the first time
	elif (sTargetName == "Starbase 12") and (g_bGraffHailed == FALSE):
		MissionLib.CallWaiting(None, TRUE)
		pKiskaHail = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen1", None, 0, g_pGeneralDatabase)
		pKiskaHail.Play()
		CloseToStarbase()
		
	else:
		# Do nothing special, so call our next handler
		TGObject.CallNextHandler(pEvent)

################################################################################
##	SetCourseHandler()
##
##	Handler called if Intercept or course is selected.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def SetCourseHandler(TGObject, pEvent):
	# See if it's not intercept, it must mean the player is
	# setting a course.  See if were in a tutorial sequence as well
	if not (pEvent.GetInt() == App.CharacterClass.EST_SET_COURSE_INTERCEPT):
		if (g_iTutorialState == 2) and (g_bInNavTutorial == FALSE):
			global g_iTutorialState
			g_iTutorialState = 3
			
	# All done, pass on the event to the next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	CourseMenuOpened()
##
##	Handler called when the Course menu is opened in Kiska's menu.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CourseMenuOpened(TGObject, pEvent):
	# Increase our tutorial state if we need to
	if (g_iTutorialState == 1) and (g_bInNavTutorial == FALSE):
		global g_iTutorialState
		g_iTutorialState = 2
		
	# All done, pass it on
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	NavPointMenuOpened()
##
##	Handler called when the Nav Point menu is opened in Kiska's menu.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def NavPointMenuOpened(TGObject, pEvent):
	# Increase our tutorial state if we need to
	if (g_iTutorialState == 1):
		global g_iTutorialState
		g_iTutorialState = 2
		
	# All done, pass it on
	TGObject.CallNextHandler(pEvent)

################################################################################
##	WarpButtonHandler()
##
##	Handler called when the warp button is pressed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WarpButtonHandler(TGObject, pEvent):
	# Clear the tutorial flag so that we can get the
	# camera to do the right thing in the warp sequence.
	if (g_bInWarpTutorial == TRUE):
		global g_bInTutorial
		g_bInTutorial = FALSE
		# Let the menus drop if they need to
		MissionLib.RemoveControl(None)
		SetCharWindowLock(None, FALSE)
		HideArrows()
		if (g_iTutorialState > 1):
			global g_iTutorialState
			g_iTutorialState = 4

	# All done, pass event on.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ObjectiveMenuOpened()
##
##	Handler called when objective button is hit.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ObjectiveMenuOpened(TGObject, pEvent):
	# If were in the tutorial, increase our counter
	if (g_iTutorialState == 1):
		global g_iTutorialState
		g_iTutorialState = 2
		
	# All done with the event, pass it on
	TGObject.CallNextHandler(pEvent)

################################################################################
##	SetAlertLevelHandler()
##
##	Handler called when an alert level is set.  If we are in a tutorial, does
##	the normal stuff but does not close Saffi's menu.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def SetAlertLevelHandler(TGObject, pEvent):
	if (g_bInTutorial == TRUE):
		iType = pEvent.GetInt()

		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			TGObject.CallNextHandler(pEvent)
			return

		iLevel = 0
		if (iType == App.CharacterClass.EST_ALERT_GREEN):
			iLevel = pPlayer.GREEN_ALERT
		if (iType == App.CharacterClass.EST_ALERT_YELLOW):
			iLevel = pPlayer.YELLOW_ALERT
		if (iType == App.CharacterClass.EST_ALERT_RED):
			iLevel = pPlayer.RED_ALERT

		if (iLevel != pPlayer.GetAlertLevel()):
			if (iType == App.CharacterClass.EST_ALERT_GREEN):
				App.TGSoundAction_Create("GreenAlertSound").Play()
			if (iType == App.CharacterClass.EST_ALERT_YELLOW):
				App.TGSoundAction_Create("YellowAlertSound").Play()
			if (iType == App.CharacterClass.EST_ALERT_RED):
				App.TGSoundAction_Create("RedAlertSound").Play()

			# Set up an event to send to the ship, which will change its
			# alert level.
			pAlertEvent = App.TGIntEvent_Create()
			pAlertEvent.SetSource(TGObject)
			pAlertEvent.SetDestination(pPlayer)
			pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
			pAlertEvent.SetInt(iLevel)

			App.g_kEventManager.AddEvent(pAlertEvent)

	else:
		# Do the default behavior
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	CommunicateHandler()
##
##	Handler called when any of the Communicate buttons for crew are hit.  
##	Checks the state of the mission and calls dialogue based on that.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################\
def CommunicateHandler(TGObject, pEvent):
	# Get the menu that was clicked
	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())
	
	# Check mission state and call our funcitons based on that
	if (g_iMissionState == IN_DRYDOCK):
		DryDockCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == IN_STARBASE):
		StarbaseCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	else:
		# Call next handler and do the default stuff
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	StarbaseInnerProximity()
##
##	Handler called when player trips proximity check on the Starbase.  Lets
##	them know they can dock.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def StarbaseInnerProximity(TGObject, pEvent):
	# Set our flag
	global g_bPlayerCloseToStarbase
	g_bPlayerCloseToStarbase = TRUE
	
	# If Graff has been hailed, just enable the dock button
	if (g_bDockDisabled == TRUE) and (g_bGraffHailed == TRUE) and (g_bInNavTutorial == FALSE):
		global g_bDockDisabled
		g_bDockDisabled = FALSE
		Bridge.BridgeUtils.EnableButton(None, "Helm", "Dock")
		# Enable the docking tutorial button
		pPicardMenu = g_pPicard.GetMenu()
		if (pPicardMenu != None) and (g_bGraffHailed == TRUE):
			pButton = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Docking"))
			if (pButton != None):
				pButton.SetEnabled()

		# The player has already hailed Graff, let them know they can dock now
		pKiskaArriveSB3 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1ArriveStarbase3", "Captain", 0, g_pMissionDatabase)
		pKiskaArriveSB3.Play()
		return
		
	# Call the function that let's us know we can dock.
	if (g_bGraffHailed == FALSE):
		CloseToStarbase()

################################################################################
##	StarbaseOuterProximity()
##
##	Handler called when player leaves the proximity of the Starbase.  Disables
##	the dock button.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def StarbaseOuterProximity(TGObject, pEvent):
	# Set our flag
	global g_bPlayerCloseToStarbase
	g_bPlayerCloseToStarbase = FALSE
	
	# Disable the dock button
	if (g_bDockDisabled == FALSE) and (g_bInDockSequence == FALSE):
		global g_bDockDisabled
		g_bDockDisabled = TRUE
		Bridge.BridgeUtils.DisableButton(None, "Helm", "Dock")
		# Disable the docking tutorial button
		pPicardMenu = g_pPicard.GetMenu()
		if (pPicardMenu != None):
			pButton = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Docking"))
			if (pButton != None):
				pButton.SetDisabled()
	
################################################################################
##	HandleMenuEvent()
##
##	Handler called when one of the characters menus is opened.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def HandleMenuEvent(TGObject, pEvent):
	# Find out what character it is
	pCharacter = App.CharacterClass_Cast(pEvent.GetDestination())
	if (pCharacter == None):
		return
	# Get the name of the character
	sName = pCharacter.GetName()
	
	# If it's Picard and the window lock is not active, raise his info box
	if (sName == "Picard") and (g_bCharWindowLock == FALSE) and (pEvent.GetBool() == 1):
		# Only show if were on the bridge
		pTopWindow = App.TopWindow_GetTopWindow()
		if (pTopWindow.IsBridgeVisible()):
			MissionLib.ShowInfoBox(None, g_idPicardTutorialBox)
		
	# If the window lock is on, just return
	# so they won't open or close	
	if (g_bCharWindowLock == TRUE):
		return
		
	# If were opening a menu in tactical, close our info box
	if (pEvent.GetBool() == 1):
		# See if we're on the bridge or not
		pTopWindow = App.TopWindow_GetTopWindow()
		if not (pTopWindow.IsBridgeVisible()):
			MissionLib.HideInfoBox(None, g_idTacticalViewBox1)
		
	# Was the menu being opened and do we care
	if (g_bInCharacterSelection == TRUE) and (pEvent.GetBool() == 0):
		# Set our prodding flag
		global g_bPlayerInspecting
		g_bPlayerInspecting = TRUE
		
		# See which charcter was clicked, if was Saffi, see if
		# the player checked the Objectives while they were there
		if (g_bSaffiClicked == FALSE) and (sName == "XO"):
			global g_bSaffiClicked
			g_bSaffiClicked = TRUE
			if(g_bPlayerCheckedObjective == TRUE):
				CheckTacticalView()
			else:
				# Do the default thing that all the other characters would do
				Objectives()

		else:
			# It was one of the other characters, so suggest the Objectives
			Objectives()
			
	# Keep track of if the character has given the congrats line
	# and play if they haven't done it.
	if (pEvent.GetBool() == 1) and (g_bIntrosDone == TRUE):
		if (g_bKiskaCongrats == FALSE) and (sName == "Helm"):
			global g_bKiskaCongrats
			g_bKiskaCongrats = TRUE
			# Do Kiska's special line
			pGreeting = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1Congratulations3", None, 0, g_pMissionDatabase)
			MissionLib.QueueActionToPlay(pGreeting)
			
		elif (g_bFelixCongrats == FALSE) and (sName == "Tactical"):
			global g_bFelixCongrats
			g_bFelixCongrats = TRUE
			# Do Felix's special line
			pGreeting = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M1Congratulations2", None, 0, g_pMissionDatabase)
			MissionLib.QueueActionToPlay(pGreeting)
			
		elif (g_bMiguelCongrats == FALSE) and (sName == "Science"):
			global g_bMiguelCongrats
			g_bMiguelCongrats = TRUE
			# Do Miguel's special line
			pGreeting = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M1Congratulations1", None, 0, g_pMissionDatabase)
			MissionLib.QueueActionToPlay(pGreeting)
			
		elif (g_bBrexCongrats == FALSE) and (sName == "Engineer"):
			global g_bBrexCongrats
			g_bBrexCongrats = TRUE
			# Do Brex's special line
			pGreeting = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M1Congratulations4", None, 0, g_pMissionDatabase)
			MissionLib.QueueActionToPlay(pGreeting)

	# Change back the "Yes sir" line if the menu is being closed.
	elif (pEvent.GetBool() == 0) and (g_bIntrosDone == TRUE):
		if (g_bKiskaCongrats == TRUE) and (sName == "Helm"):
			g_pKiska.SetYesSir(None)
			
		elif (g_bFelixCongrats == TRUE) and (sName == "Tactical"):
			g_pFelix.SetYesSir(None)
			
		elif (g_bMiguelCongrats == TRUE) and (sName == "Science"):
			g_pMiguel.SetYesSir(None)
			
		elif (g_bBrexCongrats == TRUE) and (sName == "Engineer"):
			g_pBrex.SetYesSir(None)
	
	# All done, call the next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	SkipOpeningSequence()
##
##	Handler called when "skip" key is pressed.  Starts the Undock sequence.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def SkipOpeningSequence(TGObject, pEvent):
	# See if the key that was pressed matches the "SkipKey" string.
	iUnicode = pEvent.GetUnicode()
	kDisplayString = App.g_kInputManager.GetDisplayStringFromUnicode(iUnicode)
	
	kSkipKey = g_pMissionDatabase.GetString("SkipKey")
	
	if (kDisplayString.GetCString() == kSkipKey.GetCString()):
		# Call the undock sequence with a flag to let
		# us know were skipping it and Kill the running sequence
		# Kill the other sequences if this one was called
		App.TGActionManager_KillActions("CharacterIntros")
		UndockCutscene(TRUE)
		# Get rid of the text banner
		pTextBannerAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(g_idTextBanner))
		if (pTextBannerAction != None):
			pTextBannerAction.Completed()

	# All Done, pass on the event
	TGObject.CallNextHandler(pEvent)

################################################################################
##	SetPlayerState()
##
##	Set the buttons in menus to what we want.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetPlayerState():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	#Set player docked
	pPlayer.SetDocked(1)
	Bridge.BridgeUtils.UpdateDockButton()

	# Disable the "Undock" button	
	pButton = Bridge.BridgeUtils.GetDockButton()
	if(pButton):
		pButton.SetDisabled()
	
################################################################################
##	Briefing()
##
##	Starts a cutscene which does bridge walk on, plays briefing from Liu and
##	calls actions that do Picard and Saffi's walk-ons and Picards crew
##	introductions.
##
##	Args:	None
##
##	Return:	None
################################################################################
def Briefing():
	# Set our mission state
	global g_iMissionState
	g_iMissionState = IN_DRYDOCK
	
	# Get Liu
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu			= App.CharacterClass_GetObject (pStarbaseSet, "Liu")

	# Position camera at lift.
	pBridge = App.BridgeSet_Cast( App.g_kSetManager.GetSet("bridge") )
	pCamera = App.ZoomCameraObjectClass_GetObject(pBridge, "maincamera")
	if (pCamera != None):
		pAnimNode = pCamera.GetAnimNode()
		App.g_kAnimationManager.LoadAnimation("data/animations/db_camera_capt_walk.nif", "WalkCameraToCaptD")
		pAnimNode.UseAnimationPosition("WalkCameraToCaptD")
		
	# Create the action that calls the walk on sequence.
	import Bridge.Characters.CommonAnimations
	pWalkSequence = Bridge.Characters.CommonAnimations.WalkCameraToCaptOnD(pCamera)

	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pMiguelOnBridge	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M1Briefing1a", None, 0, g_pMissionDatabase)
	pKiskaIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg6", "Captain", 1, g_pGeneralDatabase)
	pKiskaOnScreen	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", "Captain", 1, g_pGeneralDatabase)
	pRemoveControl	= App.TGScriptAction_Create("MissionLib", "RemoveControl")
	pCutsceneStart	= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuBriefing1	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M1Briefing1", None, 0, g_pMissionDatabase)
	pLiuBriefing2	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M1Briefing2", None, 0, g_pMissionDatabase)
	pLiuBriefing4	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M1Briefing4", None, 0, g_pMissionDatabase)
	pLiuBriefing5	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M1Briefing5", None, 0, g_pMissionDatabase)
	pLiuBriefing6	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M1Briefing6", None, 0, g_pMissionDatabase)
	pLiuBriefing8	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M1Briefing8", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	# Do Picards and Saffi's walk on
	pPicardWalkOn	= App.TGScriptAction_Create(__name__, "PicardWalkOn")
	# Do the sequences that will introduce the crew to Saffi
	pCrewIntros		= App.TGScriptAction_Create(__name__, "CrewIntros")
	
	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pRemoveControl,		pPreLoad)
	pSequence.AddAction(pMiguelOnBridge,	pRemoveControl, 0.5)
	pSequence.AddAction(pKiskaIncoming,		pMiguelOnBridge, 1)
	pSequence.AddAction(pKiskaOnScreen,		pKiskaIncoming, 0.5)
	pSequence.AddAction(pWalkSequence,		pRemoveControl)
	pSequence.AppendAction(pCutsceneStart, 0.5)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuBriefing1)
	pSequence.AppendAction(pLiuBriefing2)
	pSequence.AppendAction(pLiuBriefing6)
	pSequence.AppendAction(pLiuBriefing4)
	pSequence.AppendAction(pLiuBriefing5)
	pSequence.AppendAction(pLiuBriefing8)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pPicardWalkOn)
	pSequence.AppendAction(pCrewIntros)
	
	pSequence.Play()
	
	# Add our Head to Starbase goal here
	MissionLib.AddGoal("E1HeadToStarbaseGoal")

################################################################################
##	PicardWalkOn()
##
##	Plays sequence of Picard and Saffi walking on the bridge.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def PicardWalkOn(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Get the bridge Camera and remove the standard Camera mode.
	pBridge = App.BridgeSet_Cast( App.g_kSetManager.GetSet("bridge") )
	pCamera = App.ZoomCameraObjectClass_GetObject(pBridge, "maincamera")
	pCamera.PopCameraMode("GalaxyBridgeCaptain")

	# Create the action that does the captain stand.
	import Bridge.Characters.CommonAnimations
	pCaptainStand = Bridge.Characters.CommonAnimations.DBCaptainStand(pCamera)

	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pLookForward		= App.TGScriptAction_Create("MissionLib", "LookForward", TRUE)
	pWatchPicard		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_WATCH_ME)
	pPicardWalkToP1		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MOVE, "P1")
	pPicardEntrance1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Entrance1", None, 0, g_pMissionDatabase)
	pSaffiIntro2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntro2", None, 0, g_pMissionDatabase)
	pStopWatchPicard	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_STOP_WATCHING_ME)
	pSaffiWalkToC2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C2")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pLookForward)
	pSequence.AppendAction(pCaptainStand)
	pSequence.AppendAction(pPicardWalkToP1)
	pSequence.AddAction(pSaffiWalkToC2, pCaptainStand, 0.7)
	pSequence.AddAction(pPicardEntrance1, pCaptainStand)
	pSequence.AddAction(pSaffiIntro2, pPicardEntrance1)
	pSequence.AddAction(pWatchPicard, pCaptainStand, 0.5)
	pSequence.AddAction(pStopWatchPicard, pPicardWalkToP1)

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
##	CrewIntros()
##
##	Script action does all the crew introductions to the player
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def CrewIntros(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Create and play an action for the text banner if the player has
	# skipped the  
	if (App.g_kVarManager.GetFloatVariable ("global", "PlayedTutorial") == 1.0):
		pTop = App.TopWindow_GetTopWindow()
		if (pTop == None):
			return 0
		pSubtitle = pTop.FindMainWindow(App.MWT_SUBTITLE)
		pSubtitle.SetVisible()
	
		# Get the Font size to use
		pFontGroup = App.g_kFontManager.GetDefaultFont ()
		if (pFontGroup != None):
			fFontSize = pFontGroup.GetFontSize ()
		
		pTextBanner = App.TGCreditAction_Create(g_pMissionDatabase.GetString("CutsceneTextBar"), pSubtitle,
							0, 0.05, 10, 0.25, 0.5, fFontSize, App.TGCreditAction.JUSTIFY_CENTER, App.TGCreditAction.JUSTIFY_TOP)
		global g_idTextBanner
		g_idTextBanner = pTextBanner.GetObjID()
		pTextBanner.Play()
		
		# Put a handler on the root window for our skip function
		App.g_kRootWindow.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD, __name__ + ".SkipOpeningSequence")
	
	# Do our intro sequence.
	pSequence = App.TGSequence_Create()
	
	# Create the script actions for each of the character intros and add our text banner.
	pSaffiIntro			= App.TGScriptAction_Create(__name__, "IntroduceSaffi")
	pSaffiIntroAgain	= App.TGScriptAction_Create(__name__, "IntroduceSaffiAgain")
	pBrexIntro			= App.TGScriptAction_Create(__name__, "IntroduceBrex")
	pMiguelIntro		= App.TGScriptAction_Create(__name__, "IntroduceMiguel")
	pFelixIntro			= App.TGScriptAction_Create(__name__, "IntroduceFelix")
	pKiskaIntro			= App.TGScriptAction_Create(__name__, "IntroduceKiska")

	pSequence.AppendAction(pSaffiIntro)
	pSequence.AppendAction(pSaffiIntroAgain)
	pSequence.AppendAction(pBrexIntro)
	pSequence.AppendAction(pMiguelIntro)
	pSequence.AppendAction(pFelixIntro)
	pSequence.AppendAction(pKiskaIntro)
	
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
##	IntroduceSaffi()
##
##	Does Picards introduction of Saffi.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
#################################################################################
def IntroduceSaffi(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pPicardSaffiIntro3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntro3", None, 0, g_pMissionDatabase)
	pPicardSaffiIntro4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntro4", None, 0, g_pMissionDatabase)
	pPicardSaffiIntro5	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntro5", None, 0, g_pMissionDatabase)
	pPointToSaffi		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_C_P")
	pPicardSaffiIntro6	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntro6", None, 0, g_pMissionDatabase)
	pEndPointToSaffi	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_C_End_P")
	pWatchSaffi			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSaffiIntro7		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntro7", None, 0, g_pMissionDatabase)
	pWatchPicard		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_LOOK_AT_ME)

	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pPicardSaffiIntro3, pPreLoad)
	pSequence.AddAction(pPicardSaffiIntro4,	pPicardSaffiIntro3)
	pSequence.AppendAction(pPicardSaffiIntro5)
	pSequence.AppendAction(pPointToSaffi)
	pSequence.AddAction(pEndPointToSaffi,	pPointToSaffi, 1)
	pSequence.AddAction(pPicardSaffiIntro6,	pPointToSaffi)
	pSequence.AddAction(pWatchSaffi,		pPointToSaffi, 0.5)
	pSequence.AddAction(pSaffiIntro7,		pPicardSaffiIntro6)
	pSequence.AddAction(pWatchPicard,		pSaffiIntro7)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	# Register this action so we can skip it
	App.TGActionManager_RegisterAction(pSequence, "CharacterIntros")

	pSequence.Play()

	return 1

################################################################################
##	ResetBridgeCamera()
##
##	Script action that resets the bridge camera.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetBridgeCamera(pTGAction):
	# Set our flag
	global g_bCameraReset
	g_bCameraReset = TRUE
	
	# Get the bridge Camera and remove the standard Camera mode.
	pBridge = App.BridgeSet_Cast( App.g_kSetManager.GetSet("bridge") )
	pCamera = App.ZoomCameraObjectClass_GetObject(pBridge, "maincamera")
	
	pCamera.PushCameraMode( pCamera.GetNamedCameraMode("GalaxyBridgeCaptain") )
	
	return 0
	
################################################################################
##	IntroduceBrex()
##
##	Does Picards introduction of Brex.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep t
################################################################################
def IntroduceBrex(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Get the repair button
	pBrexMenu = g_pBrex.GetMenu()
	if (pBrexMenu == None):
		return 0
	pReportButton = pBrexMenu.GetButtonW(g_pDatabase.GetString("Report"))
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pPicardEngIntro1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1BrexIntro1", None, 0, g_pMissionDatabase)
	pPointEng			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_E_P")
	pPointEngEnd		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_E_End_P")
	pBrexMenuUp			= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_MENU_UP)
	pMoveToCenter		= App.TGScriptAction_Create(__name__, "MoveMouseToCenter", 0.5)
	pHoldAtCenter		= App.TGScriptAction_Create(__name__, "HoldMouseAtCenter", 6)
	pMouseToReport		= App.TGScriptAction_Create(__name__, "MoveMouseToButton", pReportButton, 0.5)
	pHilightReport		= App.TGScriptAction_Create(__name__, "SetUIObjectHighlighted", pBrexMenu, pReportButton)
	pDeHilightReport	= App.TGScriptAction_Create(__name__, "SetUIObjectHighlighted", pBrexMenu, pReportButton, 0)
	pHoldAtReport		= App.TGScriptAction_Create(__name__, "HoldMouseAtButton", pReportButton, 10)
	pBrexEngIntro4		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M1BrexIntro4", None, 1, g_pMissionDatabase)
	pBrexMenuDown		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_MENU_DOWN)
	pLookPicard			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_LOOK_AT_ME)

	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pPicardEngIntro1,	pPreLoad)
	pSequence.AddAction(pPointEng,			pPreLoad, 0.5)
	pSequence.AddAction(pPointEngEnd,		pPointEng, 4)
	pSequence.AddAction(pBrexMenuUp,		pPointEng, 0.5)
	pSequence.AddAction(pMoveToCenter,		pBrexMenuUp)
	pSequence.AddAction(pHoldAtCenter,		pMoveToCenter, 0.5)
	pSequence.AddAction(pMouseToReport,		pBrexMenuUp, 3)
	
	pSequence.AddAction(pHilightReport,		pMouseToReport, 0.7)
	pSequence.AddAction(pDeHilightReport,	pHilightReport, 0.5)
	
	pSequence.AddAction(pHoldAtReport,	pMouseToReport, 0.5)
	pSequence.AddAction(pBrexEngIntro4,	pPicardEngIntro1)
	pSequence.AddAction(pBrexMenuDown,	pBrexEngIntro4)
	pSequence.AddAction(pLookPicard,	pBrexMenuDown)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	# Register this action so we can skip it
	App.TGActionManager_RegisterAction(pSequence, "CharacterIntros")

	return 1

################################################################################
##	IntroduceMiguel()
##
##	Does Picards introduction of Miguel.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def IntroduceMiguel(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Get the buttons we need
	pMiguelMenu = g_pMiguel.GetMenu()
	if (pMiguelMenu == None):
		return 0
	pScanArea	= pMiguelMenu.GetButtonW(g_pDatabase.GetString("Scan Area"))
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pPicardSciIntro4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1MiguelIntro4", None, 0, g_pMissionDatabase)
	pPointSci			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_S_P")
	pPointSciEnd		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_S_End_P")
	pMiguelMenuUp		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_MENU_UP)
	pMoveToCenter		= App.TGScriptAction_Create(__name__, "MoveMouseToCenter", 0.1)
	pHoldAtCenter		= App.TGScriptAction_Create(__name__, "HoldMouseAtCenter", 6)
	pMoveToScanArea		= App.TGScriptAction_Create(__name__, "MoveMouseToButton", pScanArea, 0.7)
	pHoldAtScanArea		= App.TGScriptAction_Create(__name__, "HoldMouseAtButton", pScanArea, 10)
	pHilightScanArea	= App.TGScriptAction_Create(__name__, "SetUIObjectHighlighted", pMiguelMenu, pScanArea)
	pDeHilightScanArea	= App.TGScriptAction_Create(__name__, "SetUIObjectHighlighted", pMiguelMenu, pScanArea, 0)
	pMiguelSciIntro5	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M1MiguelIntro5", "Captain", 1, g_pMissionDatabase)
	pMiguelMenuDown		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_MENU_DOWN)
	pPicardLook			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_LOOK_AT_ME)

	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pPicardSciIntro4,	pPreLoad)
	pSequence.AddAction(pPointSci,			pPreLoad, 1.5)
	pSequence.AddAction(pPointSciEnd,		pPointSci, 4)
	
	pSequence.AddAction(pMiguelMenuUp,	pPointSci, 0.3)
	pSequence.AddAction(pMoveToCenter,	pMiguelMenuUp)
	pSequence.AddAction(pHoldAtCenter,	pMoveToCenter, 0.1)
	
	pSequence.AddAction(pMoveToScanArea,	pMiguelMenuUp, 0.5)
	pSequence.AddAction(pHoldAtScanArea,	pMoveToScanArea, 0.7)
	pSequence.AddAction(pHilightScanArea,	pMoveToScanArea, 0.9)
	pSequence.AddAction(pDeHilightScanArea,	pHilightScanArea, 0.5)
	pSequence.AddAction(pMiguelSciIntro5,	pPicardSciIntro4)
	pSequence.AddAction(pMiguelMenuDown,	pMiguelSciIntro5)
	pSequence.AddAction(pPicardLook,		pMiguelMenuDown)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	# Register this action so we can skip it
	App.TGActionManager_RegisterAction(pSequence, "CharacterIntros")

	return 1

################################################################################
##	IntroduceFelix()
##
##	Does Picards introduction of Felix.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def IntroduceFelix(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Get the button we need
	pFelixMenu = g_pFelix.GetMenu()
	if (pFelixMenu == None):
		return 0
		
	pReportButton	= pFelixMenu.GetButtonW(g_pDatabase.GetString("Report"))
	
	pSequence = App.TGSequence_Create()

	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pPicardTactIntro4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1FelixIntro4", None, 0, g_pMissionDatabase)
	pPointTact			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_T_P")
	pFelixMenuUp		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_UP)
	pRelocateSubtitle	= App.TGScriptAction_Create(__name__, "RelocateSubtitle")
	pPointTactEnd		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_T_End_P")
	pMoveToCenter		= App.TGScriptAction_Create(__name__, "MoveMouseToCenter", 0.1)
	pHoldAtCenter		= App.TGScriptAction_Create(__name__, "HoldMouseAtCenter", 3)
	pMoveToReport		= App.TGScriptAction_Create(__name__, "MoveMouseToButton", pReportButton, 0.7)
	pHoldAtReport		= App.TGScriptAction_Create(__name__, "HoldMouseAtButton", pReportButton, 15)
	pHilightReport		= App.TGScriptAction_Create(__name__, "SetUIObjectHighlighted", pFelixMenu, pReportButton)
	pDeHiLightReport	= App.TGScriptAction_Create(__name__, "SetUIObjectHighlighted", pFelixMenu, pReportButton, 1)
	pFelixTactIntro5	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M1FelixIntro5", "Captain", 1, g_pMissionDatabase)
	pFelixMenuDown		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_DOWN)
	pRelocateSubtitle2	= App.TGScriptAction_Create(__name__, "RelocateSubtitle2")
	pLookPicard			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_LOOK_AT_ME)

	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pPicardTactIntro4,	pPreLoad)
	pSequence.AddAction(pPointTact,			pPreLoad, 0.5)
	pSequence.AddAction(pFelixMenuUp,		pPointTact, 1)
	pSequence.AddAction(pPointTactEnd,		pPointTact, 4)
	pSequence.AddAction(pMoveToCenter,		pFelixMenuUp)
	pSequence.AddAction(pHoldAtCenter,		pMoveToCenter, 0.1)
	pSequence.AddAction(pRelocateSubtitle,	pFelixMenuUp)
	pSequence.AddAction(pMoveToReport,		pMoveToCenter, 2)
	pSequence.AddAction(pHoldAtReport,		pMoveToReport, 0.7)
	pSequence.AddAction(pHilightReport,		pMoveToReport, 0.33)
	pSequence.AddAction(pDeHiLightReport,	pHilightReport, 0.4)
	pSequence.AddAction(pFelixTactIntro5,	pPicardTactIntro4)
	pSequence.AddAction(pRelocateSubtitle2,	pFelixTactIntro5)
	pSequence.AddAction(pFelixMenuDown,		pRelocateSubtitle2)
	pSequence.AddAction(pLookPicard,		pFelixMenuDown)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()
	
	# Assign the AI to shuttle 3 so maybe it flys by the window
	pShuttle = App.ShipClass_GetObject(App.g_kSetManager.GetSet("DryDock"), "Shuttle3")
	if (pShuttle != None):
		import E1M1_AI_Shuttle3
		pShuttle.SetAI(E1M1_AI_Shuttle3.CreateAI(pShuttle))
	
	# Register this action so we can skip it
	App.TGActionManager_RegisterAction(pSequence, "CharacterIntros")

	return 1

def RelocateSubtitle (pTGAction):
	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
	pSubtitle.SetPositionForMode (App.SubtitleWindow.SM_FELIX, 1)	# Now reposition subtitle for felix mode.
	return 0

def RelocateSubtitle2 (pTGAction):
	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
	pSubtitle.SetPositionForMode (App.SubtitleWindow.SM_CINEMATIC)	# Put subtitles back in cinematic mode.
	return 0

################################################################################
##	IntroduceSaffiAgain()
##
##	Does a little ditty about Saffi's duty while she sits down.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def IntroduceSaffiAgain(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Get the buttons we need
	pSaffiMenu = g_pSaffi.GetMenu()
	if (pSaffiMenu == None):
		return 0

	# Create the action that does the captain stand.
	pBridge = App.BridgeSet_Cast( App.g_kSetManager.GetSet("bridge") )
	pCamera = App.ZoomCameraObjectClass_GetObject(pBridge, "maincamera")
	import Bridge.Characters.CommonAnimations
	pCaptainSit = Bridge.Characters.CommonAnimations.DBCaptainSit(pCamera)
		
	pGreenAlert	= pSaffiMenu.GetButtonW(g_pDatabase.GetString("Green Alert"))
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pLookForward	= App.TGScriptAction_Create("MissionLib", "LookForward", TRUE)
	pResetBridgeCam	= App.TGScriptAction_Create(__name__, "ResetBridgeCamera")
	pPicardXOIntro1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntroB1", None, 0, g_pMissionDatabase)
	pSaffiWatch		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_WATCH_ME)
	pSaffiSit		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MOVE, "C")
	pStopSaffiWatch	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_STOP_WATCHING_ME)
	pSaffiMenuUp	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MENU_UP)
	pMoveToCenter	= App.TGScriptAction_Create(__name__, "MoveMouseToCenter", 0.1)
	pHoldAtCenter	= App.TGScriptAction_Create(__name__, "HoldMouseAtCenter", 20)
	pPicardXOIntro2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntroB2", None, 0, g_pMissionDatabase)
	pPicardXOIntro3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntroB3", None, 0, g_pMissionDatabase)
	pPicardXOIntro4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntroB4", None, 0, g_pMissionDatabase)
	pSaffiXOIntro5	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiIntroB5", None, 0, g_pMissionDatabase)
	pGreenSound		= App.TGSoundAction_Create("GreenAlertSound")
	pMoveToGreen	= App.TGScriptAction_Create(__name__, "MoveMouseToButton", pGreenAlert, 0.6)
	pHoldAtGreen	= App.TGScriptAction_Create(__name__, "HoldMouseAtButton", pGreenAlert, 10)
	pHilightGreen	= App.TGScriptAction_Create(__name__, "SetUIObjectHighlighted", pSaffiMenu, pGreenAlert)
	pDeHilightGreen	= App.TGScriptAction_Create(__name__, "SetUIObjectHighlighted", pSaffiMenu, pGreenAlert, 1)
	pSaffiMenuDown	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MENU_DOWN)
	pLookPicard		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_LOOK_AT_ME)
	
	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pPicardXOIntro1,	pPreLoad)
	pSequence.AddAction(pLookForward,		pPreLoad)
	pSequence.AddAction(pCaptainSit,		pLookForward)
	pSequence.AddAction(pResetBridgeCam,	pCaptainSit)
	pSequence.AddAction(pPicardXOIntro2,	pPicardXOIntro1)
	pSequence.AddAction(pSaffiSit,			pPicardXOIntro1)
	pSequence.AddAction(pSaffiWatch,		pPicardXOIntro1)
	pSequence.AddAction(pStopSaffiWatch,	pSaffiSit)
	pSequence.AddAction(pSaffiMenuUp,		pSaffiSit)
	pSequence.AddAction(pMoveToCenter,		pSaffiMenuUp)
	pSequence.AddAction(pHoldAtCenter,		pMoveToCenter, 0.1)
	pSequence.AddAction(pPicardXOIntro3,	pPicardXOIntro1)
	pSequence.AddAction(pPicardXOIntro4,	pPicardXOIntro3)
	pSequence.AddAction(pSaffiXOIntro5,		pPicardXOIntro4)
	pSequence.AddAction(pMoveToGreen,		pPicardXOIntro4, 0.3)
	pSequence.AddAction(pHoldAtGreen,		pMoveToGreen, 0.6)
	pSequence.AddAction(pHilightGreen,		pMoveToGreen, 0.8)
	pSequence.AddAction(pDeHilightGreen,	pHilightGreen, 0.5)
	pSequence.AddAction(pGreenSound,		pSaffiXOIntro5)
	pSequence.AddAction(pSaffiMenuDown,		pSaffiXOIntro5)
	pSequence.AppendAction(pLookPicard)

	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	# Register this action so we can skip it
	App.TGActionManager_RegisterAction(pSequence, "CharacterIntros")

	pSequence.Play()
	
	return 1

################################################################################
##	IntroduceKiska()
##
##	Does Picards introduction of Kiska.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def IntroduceKiska(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Set the state of the dock button and our flag
	# so that when Kiska "presses" the button it starts the 
	# Undock Cutscene
	global g_bDryDockUndock
	g_bDryDockUndock = TRUE

	# Get and enable the dock button.
	pDockButton	= Bridge.BridgeUtils.GetDockButton()
	pDockButton.SetEnabled()

	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pPicardHelmIntro4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1KiskaIntro4", None, 0, g_pMissionDatabase)
	pPointHelm			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_H_P")
	pKiskaMenuUp		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_UP)
	pMoveToCenter		= App.TGScriptAction_Create(__name__, "MoveMouseToCenter", 0.1)
	pHoldAtCenter		= App.TGScriptAction_Create(__name__, "HoldMouseAtCenter", 10)
	pPointHelmEnd		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_PLAY_ANIMATION_FILE, "db_P_Point_H_End_P")
	pKiskaHelmIntro5	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1KiskaIntro5", "Captain", 1, g_pMissionDatabase)
	pMoveToDock			= App.TGScriptAction_Create(__name__, "MoveMouseToButton", pDockButton, 0.6)
	pHoldAtDock			= App.TGScriptAction_Create(__name__, "HoldMouseAtButton", pDockButton, 10)
	pPressDockButton	= App.TGScriptAction_Create(__name__, "UIButtonPress", pDockButton)
	pKiskaMenuDown		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_DOWN) 
	
	# Script action to remove the skip handler and the text at top.
	pRemoveSpecialHandlers = App.TGScriptAction_Create(__name__, "RemoveSkipHandler")
	
	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pPicardHelmIntro4,		pPreLoad)
	pSequence.AddAction(pPointHelm,				None, 0.2)
	pSequence.AddAction(pPointHelmEnd,			pPointHelm)
	pSequence.AddAction(pKiskaMenuUp,			pPointHelm)
	pSequence.AddAction(pMoveToCenter,			pKiskaMenuUp)
	pSequence.AddAction(pHoldAtCenter,			pMoveToCenter, 0.1)
	pSequence.AddAction(pKiskaHelmIntro5,		pPicardHelmIntro4)
	pSequence.AddAction(pMoveToDock,			pPicardHelmIntro4, 2)
	pSequence.AddAction(pRemoveSpecialHandlers, pMoveToDock)
	pSequence.AddAction(pHoldAtDock,			pMoveToDock, 0.6)
	pSequence.AddAction(pPressDockButton,		pKiskaHelmIntro5, 0.3)
	pSequence.AppendAction(pKiskaMenuDown, 0.5)
	
	# Add an action that will complete the event
	# so the calling sequence continues
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	# Register this action so we can skip it
	App.TGActionManager_RegisterAction(pSequence, "CharacterIntros")

	return 1

################################################################################
##	RemoveSkipHandler()
##
##	Script action that removes the handler for the sequence skip key and
##	removes the text banner at top.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def RemoveSkipHandler(pTGAction = FALSE):
	# Remove the handler
	App.g_kRootWindow.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".SkipOpeningSequence")
	
	return 0
	
################################################################################
##	UndockCutscene()
##
##	Short cutscene that shows the ship leaving the dry dock.  Start the warp
##	part of the tutorial after it plays.  Can be called if the player skips
##	the opening sequence.
##
##	Args:	bPlayerSkipped	- TRUE if the player skipped the opening cutscene.
##
##	Return:	None
################################################################################
def UndockCutscene(bPlayerSkipped = FALSE):
	# Set the player's ship AI
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	import UndockAI
	MissionLib.SetPlayerAI("Helm", UndockAI.CreateAI(pPlayer))

	# Set the dock button and disable it
	#Set player docked
	pPlayer.SetDocked(0)
	Bridge.BridgeUtils.UpdateDockButton()

	# Disable the "Dock" button	
	pButton = Bridge.BridgeUtils.GetDockButton()
	if(pButton):
		pButton.SetDisabled()

	# Make sure the keyboard handler has been removed
	RemoveSkipHandler()
	
	# Close everyone's menu
	BridgeHandlers.DropMenusTurnBack()
	
	# Set our flag
	global g_bDryDockUndock
	g_bDryDockUndock = FALSE
	
	pSequence = App.TGSequence_Create()

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "DryDock"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "DryDock"))
	pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "DryDock", "player", "Cam Pos 1"))

	# Don't do the audio if sequence was skipped
	if (bPlayerSkipped == FALSE):
		pSequence.AppendAction(App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1LeavingDrydock1", None, 0, g_pMissionDatabase))
		pSequence.AppendAction(App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1LeavingDrydock2", None, 0, g_pMissionDatabase))

	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EpisodeTitleAction", "Ep1Title"))
		
	# Hold call a function to put everyone in their set if we skipped
	# and hold longer on exterior camera.
	if (bPlayerSkipped == TRUE):
		pSequence.AppendAction(App.TGScriptAction_Create(__name__, "PutEveryoneInSeats"))
		pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_STOP_WATCHING_ME)) 
		pSequence.AppendAction(App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_STOP_WATCHING_ME)) 
		pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "DryDock"), 13)
		pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
	else:
		pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "DryDock"), 6)	
		pSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge"))
		pSequence.AppendAction(App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_WATCH_ME))
		pSequence.AppendAction(App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MOVE, "P"))
		pSequence.AppendAction(App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_TURN, "Captain"))
		pSequence.AppendAction(App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_STOP_WATCHING_ME))
		
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "Inspection"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "ReenablePlayerDrydockCollisions"), 15.0)

	pSequence.Play()

################################################################################
##	PutEveryoneInSeats()
##
##	Script action that puts every one in their seat.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PutEveryoneInSeats(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Get the captian back in his seat. If we need to.
	if (g_bCameraReset == FALSE):
		pBridge = App.BridgeSet_Cast( App.g_kSetManager.GetSet("bridge") )
		pCamera = App.ZoomCameraObjectClass_GetObject(pBridge, "maincamera")
		import Bridge.Characters.CommonAnimations
		pCaptainSit = Bridge.Characters.CommonAnimations.DBCaptainSit(pCamera)
		pCaptainSit.Play()
		pCamera.PushCameraMode(pCamera.GetNamedCameraMode("GalaxyBridgeCaptain"))
	
	# Get Picard and Saffi in their seats.
	if (g_pSaffi != None):
		g_pSaffi.SetLocation("DBCommander")
	if (g_pPicard != None):
		g_pPicard.SetLocation("DBGuest")

	return 0
	
################################################################################
##	Inspection()
##
##	Set the g_bInCharacterSelection flag to true and does sequence from Picard
##	telling the player to open everyone's menu.  Called as script action.
##
##	Args:	pTGAction		- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def Inspection(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Stop any prod timer running
	StopProdTimer()

	# Get our flags
	global g_bIntrosDone
	global g_bInCharacterSelection
	g_bInCharacterSelection = TRUE
	g_bIntrosDone			= TRUE
	
	# Set Picard's menu so it's openable
	g_pPicard.SetMenuEnabled(1)
	
	# Do the sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pPicardInspection1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Inspection1", "Captain", 0, g_pMissionDatabase)
	pPicardInspection2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Inspection2", None, 0, g_pMissionDatabase)
	# We're ending the big cutscene at the beginning here
	pCutsceneEnd		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pPicardMenuUp		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_UP)
	pPicardAdvise1		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1StarbaseProd2", "Captain", 0, g_pMissionDatabase)
	pStartProdTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 60)
	pSaveGame			= App.TGScriptAction_Create(__name__, "SaveTheGame")
	
	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pPicardInspection1, pPreLoad)
	pSequence.AppendAction(pPicardInspection2)
	pSequence.AppendAction(pCutsceneEnd)
	pSequence.AddAction(pPicardMenuUp, pPicardInspection2)
	pSequence.AddAction(pPicardAdvise1, pPicardInspection2)
	pSequence.AppendAction(pStartProdTimer)
	pSequence.AppendAction(pSaveGame)
	
	pSequence.Play()
	
	return 0

################################################################################
##	SaveTheGame()
##
##	Script action that saves the game and sets the config flag that will allow
##	them to skip the next time through.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SaveTheGame(pTGAction):
	if (g_bMissionTerminate != 1):
		return 0
		
	# Save the game
	MissionLib.SaveGame("E1M1-")

	# Set the flag
	App.g_kVarManager.SetFloatVariable ("global", "PlayedTutorial", 1.0)
	
	return 0
	
################################################################################
##	Objectives()
##
##	Sequence that brings up Saffi's menu and goes through the "Objectives".
##
##	Args:	None
##
##	Return:	None
################################################################################
def Objectives():
	# Check  and set our flag
	if (g_bInObjectives == FALSE) and (g_bPlayerCheckedObjective == FALSE):
		global g_bInObjectives
		g_bInObjectives = TRUE
	else:
		return
		
	# Stop any prod timer running
	StopProdTimer()

	# Reset our flag from the last segment
	global g_bInCharacterSelection
	g_bInCharacterSelection = FALSE
	
	pSequence = App.TGSequence_Create()
	
	pPicardObjectives1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Objectives1", "Captain", 0, g_pMissionDatabase)
	pStartProdTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 90)
	
	pSequence.AddAction(pPicardObjectives1)
	pSequence.AppendAction(pStartProdTimer)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	CheckTacticalView()
##
##	Sequence that prods the player to check out the tactical view.  Called when
##	the	"Objectives" have been checked.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CheckTacticalView():
	# If we check the tactical view already, do the warp one.
	if (g_bTacticalViewChecked == TRUE) or (g_bPlayerArriveStarbase == TRUE) :
		WarpSequence()
		return
		
	# Set our flag
	global g_bInTacticalView
	g_bInTacticalView = TRUE
	
	# Clear flags from the previovs sections
	global g_bInObjectives
	global g_bInCharacterSelection
	g_bInObjectives			= FALSE
	g_bInCharacterSelection	= FALSE

	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad				= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pPicardTacticalView1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1TacticalView1", "Captain", 0, g_pMissionDatabase)
	pPicardTacticalView2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1TacticalView2", None, 1, g_pMissionDatabase)

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pPicardTacticalView1, 3.5)
	pSequence.AppendAction(pPicardTacticalView2)

	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	WarpSequence()
##
##	Plays sequence that goes through the warp stuff.
##
##	Args:	None
##
##	Return:	None
################################################################################
def WarpSequence():
	# Check and set our flag
	if (g_bSuggestWarpDone == FALSE):
		global g_bSuggestWarpDone
		g_bSuggestWarpDone = TRUE
	else:
		return
	
	# Don't play if we've arrived in Starbase 12
	if (g_bPlayerArriveStarbase == TRUE):
		return
		
	# Clear our previous flag
	global g_bInTacticalView
	g_bInTacticalView = FALSE
	
	# Stop any prod timer running
	StopProdTimer()
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pPicardWarp1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Warp1", None, 0, g_pMissionDatabase)
	pKiskaWarp2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1Warp2", "Captain", 0, g_pMissionDatabase)
	pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 60)
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pPicardWarp1, 3.5)
	pSequence.AppendAction(pKiskaWarp2)
	pSequence.AppendAction(pStartProdTimer)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	PlayerArrivesStarbase12()
##
##	Sequence played when player arrived at Starbase12 for first time.  Registers
##	and unregisters some of our goal as well.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesStarbase12():
	# Set our mission state
	global g_iMissionState
	g_iMissionState = IN_STARBASE

	# Disable the dock button
	pButton = Bridge.BridgeUtils.GetDockButton()
	if(pButton):
		pButton.SetDisabled()

	# Add the NavPoints and dock button to Picard menu
	pPicardMenu = g_pPicard.GetMenu()
	if (pPicardMenu != None):
		pPicardMenu.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("NavPoints"), ET_NAV_POINTS_TUTORIAL, 0, g_pPicard))
		pPicardMenu.AddChild(CreateBridgeMenuButton(g_pMissionDatabase.GetString("Docking"), ET_DOCK_TUTORIAL, 0, g_pPicard))
		# Disable the dock button until we're closer
		pButton = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Docking"))
		if (pButton != None):
			pButton.SetDisabled()

	# Set our sequence flag
	global g_bSequenceRunning
	g_bSequenceRunning = TRUE
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pKiskaArriveSB1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1ArriveStarbase1", "Captain", 0, g_pMissionDatabase)
	pKiskaFly1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1FlyToStarbase1", None, 0, g_pMissionDatabase)
	pPicardFly2		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1FlyToStarbase2", "Captain", 0, g_pMissionDatabase)
	pPicardFly3		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1FlyToStarbase3", None, 1, g_pMissionDatabase)
	pClearFlag		= App.TGScriptAction_Create(__name__, "ClearSequenceFlag")
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pKiskaArriveSB1, 4)
	pSequence.AppendAction(pKiskaFly1)
	pSequence.AppendAction(pPicardFly2)
	pSequence.AppendAction(pPicardFly3)
	pSequence.AppendAction(pClearFlag)

	pSequence.Play()

	# Give the Devore it's AI and start the timer
	# for the apperance of the San Francisco
	import E1M1_AI_Devore
	pSet	= App.g_kSetManager.GetSet("Starbase12")
	pShip	= App.ShipClass_GetObject(pSet, "Devore")
	if (pShip != None):
		pShip.SetAI(E1M1_AI_Devore.CreateAI(pShip))
	
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_SF_ARRIVE_TIMER, __name__ + ".CreateSanFrancisco", fStartTime + 40, 0, 0)

	# Remove the Dry Dock system from the Set Course menu if it exists.
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu != None):
		pSetCourse = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
		if (pSetCourse != None):
			pDryDock = pSetCourse.GetSubmenu("Dry Dock")
			if (pDryDock != None):
				pSetCourse.DeleteChild(pDryDock)

################################################################################
##	CloseToStarbase()
##
##	Sequence played when player gets close enough to Starbase to dock.  Called
##	from StarbaseInnerProximity() or HailHandler().  Loops if sequence is
##	running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 too keep calling sequence from crashing.
################################################################################
def CloseToStarbase(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1) or (g_bGraffHailed == TRUE):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "CloseToStarbase")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
		
	else:
		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE

		# Clear our flag from the previous section
		global g_bSuggestWarpDone
		g_bSuggestWarpDone = FALSE

		# Get the button we want to highlight
		pKiskaMenu = g_pKiska.GetMenu()
		if (pKiskaMenu == None):
			return 0
		pDockButton	= pKiskaMenu.GetButtonW(g_pDatabase.GetString("Dock"))

		pSequence = App.TGSequence_Create()

		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
		pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
		pKiskaArriveSB1a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1ArriaveStarbase1a", None, 1, g_pMissionDatabase)
		pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "FedOutpostSet_Graff", "Graff")
		pGraffArriveSB2a	= App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E1M1ArriaveStarbase2a", None, 0, g_pMissionDatabase)
		pGraffArriveSB2		= App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E1M1ArriveStarbase2", None, 0, g_pMissionDatabase)
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pEnableDockButton	= App.TGScriptAction_Create(__name__, "EnableDockButton")

		pSequence.AddAction(pPreLoad)
		pSequence.AppendAction(pCallWaiting)
		pSequence.AppendAction(pKiskaArriveSB1a)
		pSequence.AppendAction(pStarbaseViewOn)
		pSequence.AppendAction(pGraffArriveSB2a)
		pSequence.AppendAction(pGraffArriveSB2)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AppendAction(pEnableDockButton)

		pSequence.Play()

		return 0
		
################################################################################
##	EnableDockButton()
##
##	Enables the dock button if the player is close enough to the Starbase. Also
##	sets the g_bGraffHailed flag.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def EnableDockButton(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Set our flag
	global g_bGraffHailed
	g_bGraffHailed = TRUE

	# Bail if we are not close to the Starbase
	if (g_bPlayerCloseToStarbase == FALSE):
		return 0
		
	# Enable the dock button if we're close.
	if (g_bDockDisabled == FALSE):
		# Do the line from Kiska
		pKiskaArriveSB3 = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1ArriveStarbase3", "Captain", 0, g_pMissionDatabase)
		pKiskaArriveSB3.Play()
		pButton = Bridge.BridgeUtils.GetDockButton()
		if(pButton != None):
			pButton.SetEnabled()
			
	# Enable the docking tutorial button
	pPicardMenu = g_pPicard.GetMenu()
	if (pPicardMenu != None):
		pButton = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Docking"))
		if (pButton != None):
			pButton.SetEnabled()


	return 0
	
################################################################################
##	CreateSanFrancisco()
##
##	Creates the San Francisco and assigns it's AI.  Called from timer event.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CreateSanFrancisco(TGObject, pEvent):
	import E1M1_AI_SF
	
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Starbase12")
	
	# Create the ship
	pSF	= loadspacehelper.CreateShip("Galaxy", pSet, "San Francisco", "SFStart", 1)
	pSF.ReplaceTexture("data/Models/SharedTextures/FedShips/SanFrancisco.tga", "ID")
	
	# Assign AI
	if (pSF != None):
		pSF.SetAI(E1M1_AI_SF.CreateAI(pSF))
	
################################################################################
##	GivePlayerOrbitAI()
##
##	Script action that gives the players ships an AI to orbit the Starbase.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	-	Return 0 to keep calling sequence from crashing.
################################################################################
def GivePlayerOrbitAI(pTGAction):
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		import E1M1_AI_PlayerOrbitSB
		MissionLib.SetPlayerAI("Helm", E1M1_AI_PlayerOrbitSB.CreateAI(pPlayer))
		
	return 0
	
################################################################################
##	SpecialDockSequence()
##
##	Creates the special docking sequence that we'll use the first time we dock.
##
##	Args:	bIsInside	- True if the player is inside the Starbase
##
##	Return:	pSequence	- The sequence to play when we dock.
################################################################################
def SpecialDockSequence(bIsInside):
	# Set our flag
	global g_bSuppliesReceived
	g_bSuppliesReceived = TRUE
	
	pSequence = App.TGSequence_Create()

	# If we're outside the starbase do this sequence
	if (bIsInside == FALSE):
		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
		pGraffArriveSB1b	= App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies1b", None, 0, g_pMissionDatabase)
		pKiskaArriveSB1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies1", "Captain", 1, g_pMissionDatabase)
		pGraffArriveSB1a	= App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies1a", None, 0, g_pMissionDatabase)
		pFelixArriveSB3		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies2", "Captain", 1, g_pMissionDatabase)
		pBrexArriveSB4		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies3", "Captain", 1, g_pMissionDatabase)
		pAddGoal			= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E1SupplyCeli6Goal")
		pStartProdTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 90)	# 40 sec prod timer

		pSequence.AddAction(pPreLoad)
		pSequence.AppendAction(pGraffArriveSB1b)
		pSequence.AppendAction(pKiskaArriveSB1)
		pSequence.AppendAction(pGraffArriveSB1a)
		pSequence.AppendAction(pFelixArriveSB3, 3)
		pSequence.AppendAction(pBrexArriveSB4)
		pSequence.AppendAction(pStartProdTimer)

	# If we're inside do this sequence
	else:
		pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
		pGraffArriveSB1b	= App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies1b", None, 0, g_pMissionDatabase)		
		pKiskaArriveSB1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies1", "Captain", 1, g_pMissionDatabase)
		pGraffArriveSB1a	= App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies1a", None, 0, g_pMissionDatabase)
		pPicardExplain1 	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1ExplainStarbase1", None, 0, g_pMissionDatabase)
		pFelixArriveSB3		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies2", "Captain", 1, g_pMissionDatabase)
		pBrexArriveSB4		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M1TransferSupplies3", "Captain", 1, g_pMissionDatabase)
		pAddGoal			= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E1SupplyCeli6Goal")
		pStartProdTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 90)	# 40 sec prod timer

		pSequence.AddAction(pPreLoad)
		pSequence.AppendAction(pGraffArriveSB1b)
		pSequence.AppendAction(pKiskaArriveSB1)
		pSequence.AppendAction(pGraffArriveSB1a)
		pSequence.AppendAction(pPicardExplain1)
		pSequence.AppendAction(pFelixArriveSB3)
		pSequence.AppendAction(pBrexArriveSB4)
		pSequence.AppendAction(pStartProdTimer)
		
	# Remove our first goal - HeadToStarbase
	MissionLib.RemoveGoal("E1HeadToStarbaseGoal")
	# Add the goal for going to Haven
	MissionLib.AddGoal("E1SupplyCeli6Goal")

	# Link the Vesuvi system to the next mission
	import Systems.Vesuvi.Vesuvi
	pVesuviMenu = Systems.Vesuvi.Vesuvi.CreateMenus()
	
	# Set the mission name for the button
	pVesuviMenu.SetMissionName("Maelstrom.Episode1.E1M2.E1M2")

	# Clear the players target.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.SetTarget("")
		
	# Enable the warp tutorial button
	pPicardMenu = g_pPicard.GetMenu()
	if (pPicardMenu != None):
		pButton = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("SettingCourse"))
		if (pButton != None):
			pButton.SetEnabled()
	
	# Return the sequence so we can have it play in the
	# docking cutscene
	return pSequence

################################################################################
##	FirstDryDockHail()
##
##	Called from HailHandler() when player first hails the Dry Dock.  Calls
##	itself as script action if another sequence is running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def FirstDryDockHail(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "FirstDryDockHail")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
		
	else:
		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
	
		pSequence = App.TGSequence_Create()
		
		pKiskaHail1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1HailGeneric2", None, 0, g_pMissionDatabase)
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pClearFlag		= App.TGScriptAction_Create(__name__, "ClearSequenceFlag")
		
		pSequence.AppendAction(pKiskaHail1)
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AppendAction(pClearFlag)
		
		MissionLib.QueueActionToPlay(pSequence)
		
		return 0
		
################################################################################
##	SecondDryDockHail()
##
##	Called from HailHandler() when player hails the Dry Dock a second time.
##	Calls itself as script action if another sequence is running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SecondDryDockHail(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "SecondDryDockHail")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
		
	else:
		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE

		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
	
		pSequence = App.TGSequence_Create()
		
		pKiskaHail1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1HailGeneric1", None, 0, g_pMissionDatabase)
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pClearFlag		= App.TGScriptAction_Create(__name__, "ClearSequenceFlag")
		
		pSequence.AppendAction(pKiskaHail1)
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AppendAction(pClearFlag)
		
		MissionLib.QueueActionToPlay(pSequence)
		
		return 0

################################################################################
##	NightingaleHail()
##
##	Called from HailHandler() when player hails the Nightingale.  Calls
##	itself as script action if another sequence is running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def NightingaleHail(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "NightingaleHail")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
		
	else:
		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
	
		# Load the database we need
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 2/E2M0.tgl")
		pSequence = App.TGSequence_Create()
		
		pKiskaHail1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M0HailZhukovSB2", None, 0, pDatabase)
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pClearFlag		= App.TGScriptAction_Create(__name__, "ClearSequenceFlag")
		
		pSequence.AppendAction(pKiskaHail1)
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AppendAction(pClearFlag)
		
		MissionLib.QueueActionToPlay(pSequence)
		
		# Unload the database
		App.g_kLocalizationManager.Unload(pDatabase)
		
		return 0
		
################################################################################
##	HailDevore()
##
##	Called from HailHandler() the first time the player hails the Devore.  Does
##	little sequence.
##
##	Args:	None
##
##	Return:	None
################################################################################
def HailDevore():
	# Get Martin
	pMartin	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("EBridgeSet"), "Martin")
	
	# Do our little sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pKiskaDevore1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1HailDevore1", "Captain", 1, g_pMissionDatabase)
	pViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "EBridgeSet", "Martin")
	pMartinDevore2	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E1M1HailDevore2", None, 0, g_pMissionDatabase)
	pBrexDevore3	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M1HailDevore3", None, 0, g_pMissionDatabase)
	pMartinDevore4	= App.CharacterAction_Create(pMartin, App.CharacterAction.AT_SAY_LINE, "E1M1HailDevore4", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEnableHail		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pKiskaDevore1)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pMartinDevore2)
	pSequence.AppendAction(pBrexDevore3)
	pSequence.AppendAction(pMartinDevore4)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEnableHail)
	
	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	HailSanFrancisco()
##
##	Called from HailHandler() when the player first hails the San Francisco.
##
##	Args:	None
##
##	Return:	None
################################################################################
def HailSanFrancisco():
	# Get Zeiss
	pZeiss	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("DBridgeSet"), "Zeiss")
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad	= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pKiskaSF1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1HailSF1", "Captain", 1, g_pMissionDatabase)
	pViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Zeiss")
	pZeissSF2	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E1M1HailSF2", None, 0, g_pMissionDatabase)
	pZeissSF3	= App.CharacterAction_Create(pZeiss, App.CharacterAction.AT_SAY_LINE, "E1M1HailSF3", None, 0, g_pMissionDatabase)
	pViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEnableHail	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pKiskaSF1)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pZeissSF2)
	pSequence.AppendAction(pZeissSF3)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEnableHail)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	SetupTacticalViewInfoBox()
##
##	Create the info box for the tactical view.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupTacticalViewInfoBox():
	# Destroy the box if it exists
	if (g_idTacticalViewBox1 != None):
		MissionLib.DestroyInfoBox(g_idTacticalViewBox1)
		global g_idTacticalViewBox1
		g_idTacticalViewBox1 = None

	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["TactView"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M1HelpText.tgl")
	
	# Get all the bloody keys that we need to steer the ship
	# Up
	iUnicode = App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TURN_UP, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	kUp = App.g_kInputManager.GetDisplayStringFromUnicode(iUnicode)
	# Down
	iUnicode = App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TURN_DOWN, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	kDown = App.g_kInputManager.GetDisplayStringFromUnicode(iUnicode)
	# Left
	iUnicode = App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TURN_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	kLeft = App.g_kInputManager.GetDisplayStringFromUnicode(iUnicode)
	# Right
	iUnicode = App.g_kKeyboardBinding.FindKey(App.ET_INPUT_TURN_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	kRight = App.g_kInputManager.GetDisplayStringFromUnicode(iUnicode)
	# Roll left
	iUnicode = App.g_kKeyboardBinding.FindKey(App.ET_INPUT_ROLL_LEFT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	kRollLeft = App.g_kInputManager.GetDisplayStringFromUnicode(iUnicode)
	# Roll right
	iUnicode = App.g_kKeyboardBinding.FindKey(App.ET_INPUT_ROLL_RIGHT, App.KeyboardBinding.GET_BOOL_EVENT, 1)
	kRollRight = App.g_kInputManager.GetDisplayStringFromUnicode(iUnicode)

	# Create the formated paragraph
	pMainText		= App.TGParagraph_CreateW(pDatabase.GetString("TacticalViewHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pWKey			= App.TGParagraph_CreateW(kUp, fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pSKey			= App.TGParagraph_CreateW(kDown, fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pAKey			= App.TGParagraph_CreateW(kLeft, fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pDKey			= App.TGParagraph_CreateW(kRight, fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pQKey			= App.TGParagraph_CreateW(kRollLeft, fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pEKey			= App.TGParagraph_CreateW(kRollRight, fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pSpeeds			= App.TGParagraph_CreateW(pDatabase.GetString("TacticalViewHelp1O"), fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1B"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pWKey)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1D"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pSKey)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1F"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pAKey)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1H"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pDKey)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1J"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pQKey)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1L"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pEKey)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1N"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pSpeeds)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1P"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1Q"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("TacticalViewHelp1R"))

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("TacticalViewHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idTacticalViewBox1
	g_idTacticalViewBox1 = pBox.GetObjID()	
	
	# Attach a handler to the box
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".TacticalInfoBoxClosed")
	
################################################################################
##	TacticalInfoBoxClosed()
##
##	Handler called when the Tactical Info box is closed.  Sets flag so it
##	doesn't pop up again.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent 		- The event that was sent.
##
##	Return:	None
################################################################################
def TacticalInfoBoxClosed(TGObject, pEvent):
	# Set our flag
	global g_bTacticalInfoBoxClosed
	g_bTacticalInfoBoxClosed = TRUE
	
	# All done, pass on the event
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ExplainCharacterSelect()
##
##	Sequence thatshow player how to click on crew member.  Called from Picard
##	button.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainCharacterSelect(TGObject, pEvent):
	# Set our flag
	global g_bInCharacterSelection
	g_bInCharacterSelection = FALSE
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pForceToBridge      = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pRelocateSubtitle	= App.TGScriptAction_Create(__name__, "RelocateSubtitle")
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pPicardProd1		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1InspectionProd1", "Captain", 1, g_pMissionDatabase)
	pFelixLook			= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_LOOK_AT_ME)
	pFelixMenuUp		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_UP)
	pFelixMenuDown		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_DOWN)
	pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AddAction(pPicardProd1, pStartCutscene)
	pSequence.AddAction(pFelixLook, pStartCutscene, 1)
	pSequence.AppendAction(pFelixMenuUp, 1.5)
	pSequence.AppendAction(pRelocateSubtitle)
	pSequence.AppendAction(pFelixMenuDown, 2)
	pSequence.AppendAction(pEndCutscene)
	
	pSequence.Play()
	
################################################################################
##	ExplainWarp()
##
##	Sequence that runs through how to set a course and go into warp.  Called
##	Picard button.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainWarp(TGObject, pEvent):
	# Set our flag
	global g_bInCharacterSelection
	g_bInCharacterSelection = FALSE
	
	# Initialize our tutorial state
	global g_iTutorialState
	global g_bInWarpTutorial
	global g_bSettingCourseThreeDone
	g_iTutorialState			= 1
	g_bInWarpTutorial			= TRUE
	g_bSettingCourseThreeDone	= FALSE
	
	# Get the menu and attach an event for when the menu is open
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu == None):
		return
		
	pSetCourseMenu	= pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
	if (pSetCourseMenu != None):
		pEvent = App.TGEvent_Create()
		pEvent.SetDestination(pKiskaMenu)
		pEvent.SetEventType(ET_COURSE_MENU_OPEN)
		pSetCourseMenu.SetActivationEvent(pEvent)	
	
	# Clear any course the Warp button might have
	pWarpButton = App.SortedRegionMenu_GetWarpButton()
	if (pWarpButton != None):
		pWarpButton.SetDestination(None)
	
	# Disable the buttons in the menu that cause problems
	Bridge.BridgeUtils.DisableButton(None, "Helm", "Hail")
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	if (pSet.GetName() == "Starbase12"):
		Bridge.BridgeUtils.DisableButton(None, "Helm", "Dock")
		Bridge.BridgeUtils.DisableButton(None, "Helm", "Nav Points")
	
	# Get the buttons we need
	pSetCourseMenu	= pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
	
	# Do the first part of the sequence
	pSequence = App.TGSequence_Create()

	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pForceToBridge      = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSetTutorialFlag	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pPicardMenuDown		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pKiskaMenuUp		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_UP)
	pLockMenu			= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idSettingCourseBox1)
	pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pSetCourseMenu, MissionLib.POINTER_UR_CORNER)
	pPicardWarpProd2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1WarpProd2", None, 0, g_pMissionDatabase)
	pPicardWarpProd3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1WarpProd3", None, 0, g_pMissionDatabase)
	pSettingCourse2		= App.TGScriptAction_Create(__name__, "SettingCourseTwo")

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pSetTutorialFlag)
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pKiskaMenuUp)
	pSequence.AppendAction(pLockMenu)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardWarpProd2)
	pSequence.AppendAction(pPicardWarpProd3)
	pSequence.AppendAction(pSettingCourse2)
	
	pSequence.Play()

################################################################################
##	SettingCourseTwo()
##
##	Sequence that continues to show the player how to set a course.  Called as
##	script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SettingCourseTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialState < 2):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "SettingCourseTwo")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide pointer arrows
		HideArrows()
		
		# Do our sequence
		
		# If the player has skipped ahead in the tutorial, bail on the audio
		if (g_iTutorialState >= 4):
			pSequence = App.TGSequence_Create()
			
			pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSettingCourseBox1)
			pSettingCourse3	= App.TGScriptAction_Create(__name__, "SettingCourseThree")
			
			pSequence.AppendAction(pHideInfoBox)
			pSequence.AppendAction(pSettingCourse3)
			
			pSequence.Play()
			
			return 0
			
		# Do the normal tutorial progression
		else:	
			pSequence = App.TGSequence_Create()
			
			# Get the button we need
			pKiskaMenu = g_pKiska.GetMenu()
			if (pKiskaMenu == None):
				return 0
				
			pSetCourseMenu	= pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
			pSet = MissionLib.GetPlayerSet()
			if (pSet == None):
				return 0
			if (pSet.GetName() == "Starbase12"):
				pCourseMenu	= pSetCourseMenu.GetSubmenu("Vesuvi")
				pPicardWarpProd4 = App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1WarpProd4a", None, 0, g_pMissionDatabase)

			else:
				pCourseMenu	= pSetCourseMenu.GetSubmenu("Starbase 12")
				pPicardWarpProd4 = App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1WarpProd4", None, 0, g_pMissionDatabase)

			pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
			pHideInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSettingCourseBox1)
			pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idSettingCourseBox2)
			pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pCourseMenu, MissionLib.POINTER_LEFT)
			pSettingCourse3		= App.TGScriptAction_Create(__name__, "SettingCourseThree")

			pSequence.AddAction(pPreLoad)
			pSequence.AppendAction(pHideInfoBox)
			pSequence.AppendAction(pShowInfoBox)
			pSequence.AppendAction(pArrow1)
			pSequence.AppendAction(pPicardWarpProd4)
			pSequence.AppendAction(pSettingCourse3)

			pSequence.Play()

			return 0

################################################################################
##	SettingCourseThree()
##
##	Third part of the sequence explaining how to set course and warp.  Called as
##	script action.  NOTE: The clean up forthis sequence is called in
##	WarpButtonHandler()
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SettingCourseThree(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialState < 3):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "SettingCourseThree")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide arrows
		HideArrows()
		
		# Check and set our flag
		if (g_bSettingCourseThreeDone == FALSE):
			global g_bSettingCourseThreeDone
			g_bSettingCourseThreeDone = TRUE
		else:
			return 0
		
		# If we've skipped ahead in the tutorial, just do the two last lines
		if (g_iTutorialState >= 4):
			pSequence = App.TGSequence_Create()
			pCloseInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSettingCourseBox2)
			pPicardWarp1a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Warp1a", None, 0, g_pMissionDatabase)
			pPicardWarp1b	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Warp1b", None, 0, g_pMissionDatabase)
			pCleanUp		= App.TGScriptAction_Create(__name__, "SettingCourseCleanUp")

			pSequence.AppendAction(pCloseInfoBox)
			pSequence.AppendAction(pPicardWarp1a)
			pSequence.AppendAction(pPicardWarp1b)
			pSequence.AppendAction(pCleanUp)
			
			pSequence.Play()
			
			return 0
			
		# Do the normal tutorial progression
		else:
			# Get the button we need
			pWarpButton = Bridge.BridgeUtils.GetWarpButton()

			# Do our sequence
			pSequence = App.TGSequence_Create()

			pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
			pCloseInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSettingCourseBox2)
			pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idSettingCourseBox3)
			pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pWarpButton, MissionLib.POINTER_LEFT)
			pPicardWarpProd5	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1WarpProd5", None, 0, g_pMissionDatabase)
			pPicardWarp1a		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Warp1a", None, 0, g_pMissionDatabase)
			pPicardWarp1b		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1Warp1b", None, 0, g_pMissionDatabase)
			pCleanUp			= App.TGScriptAction_Create(__name__, "SettingCourseCleanUp")

			pSequence.AddAction(pPreLoad)
			pSequence.AppendAction(pCloseInfoBox)
			pSequence.AppendAction(pShowInfoBox)
			pSequence.AppendAction(pArrow1)
			pSequence.AppendAction(pPicardWarpProd5)
			pSequence.AppendAction(pPicardWarp1a)
			pSequence.AppendAction(pPicardWarp1b)
			pSequence.AppendAction(pCleanUp)

			pSequence.Play()

			return 0

################################################################################
##	SettingCourseCleanUp()
##
##	Last part of Setting Course tutorial that cleans eveything up.  Called as
##	script action.  Most of the clean up is handled by WarpButtonHandler() when
##	warp is pressed.
##
##	Args:	pTGAction	- The script action object
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SettingCourseCleanUp(pTGAction):		
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Hide our pointer arrows.
	HideArrows()

	# Set or tutorial state back to 0
	global g_iTutorialState
	global g_bInWarpTutorial
	g_iTutorialState 	= 0
	g_bInWarpTutorial	= FALSE

	# Do out sequence
	pSequence = App.TGSequence_Create()

	pCloseInfoBox1		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSettingCourseBox1)
	pCloseInfoBox2		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSettingCourseBox2)
	pCloseInfoBox3		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSettingCourseBox3)
	pEnableHail			= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "Helm", "Hail")
	pSetTutorialFlag	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
	pUnlockChars		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)

	pSequence.AppendAction(pCloseInfoBox1)
	pSequence.AppendAction(pCloseInfoBox2)
	pSequence.AppendAction(pCloseInfoBox3)
	pSequence.AppendAction(pEnableHail)
	pSequence.AppendAction(pSetTutorialFlag)
	pSequence.AppendAction(pUnlockChars)

	# Add an action to end the cutscene if its going on.
	pSet = MissionLib.GetPlayerSet()
	if (pSet != None):
		if (pSet.GetName() != "warp"):
			pTop = App.TopWindow_GetTopWindow()
			if (pTop.IsCutsceneMode()):
				pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "EndCutscene"))
		# If we're at Starbase 12, enable the Nav Menu
		if (pSet.GetName() == "Starbase12"):
			Bridge.BridgeUtils.EnableButton(None, "Helm", "Nav Points")
			
	pSequence.Play()

	return 0

################################################################################
##	SetupSettingCourseInfoBoxes()
##
##	Create the info boxes that we'll need for the Setting Course tutorial
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupSettingCourseInfoBoxes():
	# Destroy the info boxes if they've already been made
	for idBox in [ g_idSettingCourseBox1, g_idSettingCourseBox2, g_idSettingCourseBox3 ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)

	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["SetCourse"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M1HelpText.tgl")
	
	# Box Number 1
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("SettingCourseHelpTitle"), 
				pDatabase.GetString("SettingCourseHelp1A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idSettingCourseBox1
	g_idSettingCourseBox1 = pBox.GetObjID()	

	# Box Number 2
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("SettingCourseHelpTitle"), 
				pDatabase.GetString("SettingCourseHelp2A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idSettingCourseBox2
	g_idSettingCourseBox2 = pBox.GetObjID()	
	
	# Box Number 3
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("SettingCourseHelpTitle"), 
				pDatabase.GetString("SettingCourseHelp3A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idSettingCourseBox3
	g_idSettingCourseBox3 = pBox.GetObjID()	
	
	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)
	
################################################################################
##	ExplainObjectives()
##
##	Sequence that takes control away from the player and runs them through how
##	to get objectives from Saffi.  Called from Picard button.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainObjectives(TGObject, pEvent):
	# Set our flag
	global g_bInCharacterSelection
	g_bInCharacterSelection = FALSE
		
	# Set our starting tutorial state
	global g_iTutorialState
	g_iTutorialState = 1
	
	# Get the objective buttons that we need and attach an event for when it opens
	pSaffiMenu = g_pSaffi.GetMenu()
	if (pSaffiMenu == None):
		return 0
	pObjectivesMenu	= pSaffiMenu.GetSubmenuW(g_pDatabase.GetString("Objectives"))
	if (pObjectivesMenu != None):
		pEvent = App.TGEvent_Create()
		pEvent.SetDestination(pSaffiMenu)
		pEvent.SetEventType(ET_OBJECTIVES_MENU_OPEN)
		pObjectivesMenu.SetActivationEvent(pEvent)
	
	# Disable the Mission Log button and Contact Starfleet
	Bridge.BridgeUtils.DisableButton(None, "XO", "Show Mission Log")
	Bridge.BridgeUtils.DisableButton(None, "XO", "Contact Starfleet")
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad				= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pStartCutscene			= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pForceToBridge			= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSetTutorialFlag		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pPicardMenuDown			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pSaffiMenuUp			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MENU_UP)
	pLockCharWindows		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pShowInfoBox			= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idObjectivesBox1)
	pReturnControl			= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pArrow1					= App.TGScriptAction_Create(__name__, "ShowArrow", pObjectivesMenu, MissionLib.POINTER_UR_CORNER)
	pPicardObjectivesProd1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1ObjectivesProd1", "Captain", 1, g_pMissionDatabase)
	pObjectivesTwo			= App.TGScriptAction_Create(__name__, "ExplainObjectivesTwo")

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pSetTutorialFlag)
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pSaffiMenuUp)
	pSequence.AppendAction(pLockCharWindows)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardObjectivesProd1)
	pSequence.AppendAction(pObjectivesTwo)
	
	pSequence.Play()

################################################################################
##	ExplainObjectivesTwo()
##
##	Second part of sequence explaining objectives.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainObjectivesTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialState < 2):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainObjectivesTwo")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide our pointer arrows
		HideArrows()
		
		# Get the episode's TGL and the button we need.
		pEpisode	= MissionLib.GetEpisode()
		if (pEpisode == None):
			return
		pEpisodeDatabase	= pEpisode.GetDatabase()
		pSaffiMenu = g_pSaffi.GetMenu()
		if (pSaffiMenu == None):
			return 0
		pObjectivesMenu	= pSaffiMenu.GetSubmenuW(g_pDatabase.GetString("Objectives"))
		if (pObjectivesMenu != None):
			if (g_bSuppliesReceived == FALSE):
				pObjective	= pObjectivesMenu.GetButtonW(pEpisodeDatabase.GetString("E1HeadToStarbaseGoal"))
			else:
				pObjective	= pObjectivesMenu.GetButtonW(pEpisodeDatabase.GetString("E1SupplyCeli6Goal"))
				
		# Do our sequence
		pSequence = App.TGSequence_Create()

		pPreLoad				= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
		pCloseInfoBox			= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idObjectivesBox1)
		pShowInfoBox			= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idObjectivesBox2)
		pArrow1					= App.TGScriptAction_Create(__name__, "ShowArrow", pObjective, MissionLib.POINTER_LEFT)
		pPicardObjectivesProd2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1ObjectivesProd2", None, 0, g_pMissionDatabase)
		pCleanUp				= App.TGScriptAction_Create(__name__, "ObjectivesCleanUp")
	
		pSequence.AddAction(pPreLoad)
		pSequence.AppendAction(pCloseInfoBox)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardObjectivesProd2)
		pSequence.AppendAction(pCleanUp)

		pSequence.Play()
		
		return 0

################################################################################
##	ObjectivesCleanUp()
##
##	Last part of the Objectives tutorial sequence that cleans eveything up.
##	Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ObjectivesCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialState < 3):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ObjectivesCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide our pointer arrows
		HideArrows()
		
		# Set our tutorial state back to zero
		global g_iTutorialState
		g_iTutorialState = 0
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pCloseInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idObjectivesBox2)
		pRemoveControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
		pSetTutorialFlag	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pUnlockChars		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pSaffiMenuDown		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MENU_DOWN)
		pEnableLog			= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "XO", "Show Mission Log")
		pEnableContact		= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "XO", "Contact Starfleet")
		pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")

		pSequence.AppendAction(pCloseInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetTutorialFlag)
		pSequence.AppendAction(pUnlockChars)
		pSequence.AppendAction(pSaffiMenuDown)
		pSequence.AppendAction(pEnableLog)
		pSequence.AppendAction(pEnableContact)
		pSequence.AppendAction(pEndCutscene)

		pSequence.Play()
		
		return 0
		
################################################################################
##	SetupObjectiveInfoBoxes()
##
##	Create the info boxes that we'll need for the Objectives tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupObjectiveInfoBoxes():
	# Destroy the boxes if they exist
	for idInfo in [ g_idObjectivesBox1, g_idObjectivesBox2 ]:
		if (idInfo != None):
			MissionLib.DestroyInfoBox(idInfo)

	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["Objectives"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M1HelpText.tgl")
	
	# Box Number 1
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("ObjectivesHelpTitle"), 
				pDatabase.GetString("ObjectivesHelp1A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idObjectivesBox1
	g_idObjectivesBox1 = pBox.GetObjID()	

	# Box Number 2
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("ObjectivesHelpTitle"), 
				pDatabase.GetString("ObjectivesHelp2A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idObjectivesBox2
	g_idObjectivesBox2 = pBox.GetObjID()	

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	ExplainNavPoints()
##
##	Sequence that takes the player through using Kiska to dock.  Called from
##	Picard button.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainNavPoints(TGObject, pEvent):	
	# Set our starting tutorial state
	global g_bSequenceRunning
	global g_iTutorialState
	global g_bInNavTutorial
	g_bSequenceRunning	= TRUE
	g_iTutorialState	= 1
	g_bInNavTutorial	= TRUE

	# Get the menu and attach an event to it for when it's opened.
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu == None):
		return
		
	pNavMenu = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Nav Points"))
	if (pNavMenu == None):
		return
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pKiskaMenu)
	pEvent.SetEventType(ET_NAV_POINTS_MENU_OPEN)
	pNavMenu.SetActivationEvent(pEvent)
	
	# Attach a Nav Point changed handler to Nav Point menu
	import Bridge.HelmMenuHandlers
	pNavMenu.AddPythonFuncHandlerForInstance(Bridge.HelmMenuHandlers.ET_SET_NAVPOINT_TARGET, __name__ + ".NavPointSelected")
	
	# Disable the dock button
	Bridge.BridgeUtils.DisableButton(None, "Helm", "Dock")
	global g_bDockDisabled
	g_bDockDisabled = TRUE
	
	# Do the sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pStartCutscene 		= App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, FALSE)
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSetTutorialFlag	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pPicardMenuDown		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pKiskaMenuUp		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_UP)
	pLockChars			= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idNavPointBox1)
	pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pNavMenu, MissionLib.POINTER_UR_CORNER)
	pPicardNav1			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1ExplainNav1", None, 0, g_pMissionDatabase)
	pNavPointTwo		= App.TGScriptAction_Create(__name__, "ExplainNavPointsTwo")

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pSetTutorialFlag)
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pKiskaMenuUp)
	pSequence.AppendAction(pLockChars)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardNav1)
	pSequence.AppendAction(pNavPointTwo)
	
	pSequence.Play()
	
################################################################################
##	ExplainNavPointsTwo()
##
##	Second part of sequence explaing Nav Points.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainNavPointsTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialState < 2):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainNavPointsTwo")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide pointer arrows
		HideArrows()
		
		# Get the button we need
		pKiskaMenu = g_pKiska.GetMenu()
		if (pKiskaMenu == None):
			return 0
		pNavMenu	= pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Nav Points"))
		if (pNavMenu == None):
			return 0
		pNavPoint = pNavMenu.GetButtonW(g_pMissionDatabase.GetString("Starbase Nav"))

		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idNavPointBox1)
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idNavPointBox2)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pNavPoint, MissionLib.POINTER_LEFT)
		pPicardNav2		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1ExplainNav2", None, 0, g_pMissionDatabase)
		pPicardNav3		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1ExplainNav3", None, 0, g_pMissionDatabase)
		pCleanUp		= App.TGScriptAction_Create(__name__, "ExplainNavPointsCleanUp")

		pSequence.AddAction(pPreLoad)
		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardNav2)
		pSequence.AppendAction(pPicardNav3)
		pSequence.AppendAction(pCleanUp)
		
		pSequence.Play()
		
		return 0
		
################################################################################
##	ExplainNavPointsCleanUp()
##
##	Clean up the stuff left from the Nav Point tutorial and end it.  Called as
##	script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- The script action object.
################################################################################
def ExplainNavPointsCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialState < 3):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainNavPointsCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide our arrows
		HideArrows()
		
		# Set our tutorial state back to 0
		global g_iTutorialState
		global g_bInNavTutorial
		g_iTutorialState	= 0
		g_bInNavTutorial	= FALSE
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idNavPointBox2)
		pRemoveControl		= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pSetTutorialFlag	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pUnlockChars		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pKiskaMenuDown		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_DOWN)
		pClearFlag			= App.TGScriptAction_Create(__name__, "ClearSequenceFlag")
		pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
		
		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetTutorialFlag)
		pSequence.AppendAction(pUnlockChars)
		pSequence.AppendAction(pKiskaMenuDown)
		pSequence.AppendAction(pClearFlag)
		pSequence.AppendAction(pEndCutscene)
		
		pSequence.Play()
		
		return 0
		
################################################################################
##	SetupNavPointInfoBoxes()
##
##	Create the info boxes that we'll use in the Nav Point tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupNavPointInfoBoxes():
	# Destroy the boxes if they exist
	for idInfo in [ g_idNavPointBox1, g_idNavPointBox2 ]:
		if (idInfo != None):
			MissionLib.DestroyInfoBox(idInfo)

	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["NavBoxes"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M1HelpText.tgl")
	
	# Box Number 1
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("NavPointHelpTitle"), 
				pDatabase.GetString("NavPointHelp1A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idNavPointBox1
	g_idNavPointBox1 = pBox.GetObjID()	

	# Box Number 1
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("NavPointHelpTitle"), 
				pDatabase.GetString("NavPointHelp2A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idNavPointBox2
	g_idNavPointBox2 = pBox.GetObjID()	

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	NavPointSelected()
##
##	Handler called when the Nav Point is selected.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def NavPointSelected(TGObject, pEvent):
	# Increase our tutorial state
	global g_iTutorialState
	g_iTutorialState = 3
	
	# All done, pass on the event
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ExplainDock()
##
##	Sequence that takes the player through using Kiska to dock.  Called from
##	Picard button.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainDock(TGObject, pEvent):	
	# Set our flags
	global g_iTutorialState
	global g_bInDockSequence
	g_iTutorialState	= 1
	g_bInDockSequence	= TRUE
	
	# Get the buttons we'll need for this
	pDockButton	= Bridge.BridgeUtils.GetDockButton()
	
	# Make sure the Dock button is disabled
	pDockButton.SetEnabled()
	
	# Disable the Nav Point menu, the Set Course menu and the Hail menu
	Bridge.BridgeUtils.DisableButton(None, "Helm", "Nav Points")
	Bridge.BridgeUtils.DisableButton(None, "Helm", "Set Course")
	Bridge.BridgeUtils.DisableButton(None, "Helm", "Hail")
	Bridge.BridgeUtils.DisableButton(None, "Helm", "Orbit Planet")
	
	# Do the sequence.
	pSequence = App.TGSequence_Create()
		
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSetTutorialFlag	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pPicardMenuDown		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pKiskaMenuUp		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_UP)
	pLockChars			= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idDockBox1)
	pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pDockButton, MissionLib.POINTER_LEFT)
	pPicardDockProd		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1DockProd1", "Captain", 1, g_pMissionDatabase)
	pCleanUp			= App.TGScriptAction_Create(__name__, "ExplainDockCleanUp")

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pSetTutorialFlag)
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pKiskaMenuUp)
	pSequence.AppendAction(pLockChars)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardDockProd)
	pSequence.AppendAction(pCleanUp)
	
	pSequence.Play()

################################################################################
##	ExplainDockCleanUp()
##
##	End of tutorial explaining docking.  Cleans up.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Reutrn 0 to keep calling sequence from crashing.
################################################################################
def ExplainDockCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialState < 2):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainDockCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide our arrows
		HideArrows()
		
		# Set our tutorial state back to 0
		global g_iTutorialState
		global g_bInDockSequence
		g_iTutorialState	= 0
		g_bInDockSequence	= FALSE
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idDockBox1)
		pRemoveControl		= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pSetTutorialFlag	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pUnlockChars		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pKiskaMenuDown		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_DOWN)
		pEnableNav			= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "Helm", "Nav Points")
		pEnableSetCourse	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "Helm", "Set Course")
		pEnableHail			= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "Helm", "Hail")
		pEnableOrbit		= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "Helm", "Orbit Planet")
			
		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetTutorialFlag)
		pSequence.AppendAction(pUnlockChars)
		pSequence.AppendAction(pKiskaMenuDown)
		pSequence.AppendAction(pEnableNav)
		pSequence.AppendAction(pEnableSetCourse)
		pSequence.AppendAction(pEnableHail)
		pSequence.AppendAction(pEnableOrbit)
		
		pSequence.Play()
		
		return 0

################################################################################
##	SetupDockInfoBoxes()
##
##	Create the info boxes needed for the dock tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupDockInfoBoxes():
	# Destroy the boxes if they exist
	for idInfo in [ g_idDockBox1 ]:
		if (idInfo != None):
			MissionLib.DestroyInfoBox(idInfo)

	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["DockBox"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M1HelpText.tgl")
	
	# Create the formated paragraph
	pMainText		= App.TGParagraph_CreateW(pDatabase.GetString("DockHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pSecondLine		= App.TGParagraph_CreateW(pDatabase.GetString("DockHelp1B"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pSecondLine)
	pMainText.AppendChar(App.WC_RETURN)

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("DockHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idDockBox1
	g_idDockBox1 = pBox.GetObjID()	

	# Unload our database
	App.g_kLocalizationManager.Unload(pDatabase)

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
##	ClearSequenceFlag()
##
##	Script action that sets g_bSequenceRunning to FALSE.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ClearSequenceFlag(pTGAction = None):
	global g_bSequenceRunning
	g_bSequenceRunning = FALSE
	
	return 0
	
################################################################################
##	DryDockCommunicate()
##
##	Called from CommunicateHandler() if player is in DryDock set.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked on.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was sent to CommunicateHandler()
##
##	Return:	None
################################################################################
def DryDockCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")
	
	# Check the menu ID and see who it was
	if (iMenuID == idFelixMenu):
		pComLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M1FelixCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idSaffiMenu):
		pComLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1SaffiCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M1MiguelCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M1BrexCom1", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idKiskaMenu):
		pComLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1Warp2", "Captain", 0, g_pMissionDatabase)
		pComLine.Play()
		
	# Do the default action if the above tests didn't catch anything
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	StarbaseCommunicate()
##
##	Called from CommunicateHandler() if player is in Starbase set.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked on.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was sent to CommunicateHandler()
##
##	Return:	None
################################################################################
def StarbaseCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")
	
	# Check the menu ID and see who it was
	if (iMenuID == idFelixMenu):
		pComLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M1FelixCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
		
	elif (iMenuID == idMiguelMenu):
		pComLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M1MiguelCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()

	elif (iMenuID == idBrexMenu):
		pComLine	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M1BrexCom2", "Captain", 1, g_pMissionDatabase)
		pComLine.Play()
				
	elif (iMenuID == idKiskaMenu) and (g_bSuppliesReceived == FALSE) and (g_bDockDisabled == FALSE):
		pComLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1ArriveStarbase3", "Captain", 0, g_pMissionDatabase)
		pComLine.Play()
	elif (iMenuID == idKiskaMenu) and (g_bSuppliesReceived == FALSE) and (g_bDockDisabled == TRUE):
		pComLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M1FlyToStarbase1", "Captain", 0, g_pMissionDatabase)
		pComLine.Play()
		
	# Do the default action if the above tests didn't catch anything
	else:
		TGObject.CallNextHandler(pEvent)

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
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

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
	# Check and see if we're doing the "Inspection"
	if (g_bInCharacterSelection == TRUE):
		InspectionProd()
		return
	
	# See if were doing something that we have help for under
	# Picard's Menu.
	elif (g_bInObjectives == TRUE) or (g_bSuggestWarpDone == TRUE):
		# Remind the player Picard can help.
		pPicardAdvise1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1StarbaseProd2", "Captain", 0, g_pMissionDatabase)
		pPicardAdvise1.Play()
		
	# If the player hasn't docked with Starbase yet
	elif (g_bSuppliesReceived == FALSE) and (g_bPlayerArriveStarbase == TRUE) and (g_bFirstDockWithStarbase == FALSE):
		pSequence = App.TGSequence_Create()

		pPicardDockProd1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1DockProd1", "Captain", 1, g_pMissionDatabase)
		pRestartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 20)
		
		pSequence.AddAction(pPicardDockProd1)
		pSequence.AppendAction(pRestartProdTimer)
		
		pSequence.Play()
		
		return
		
	# If player hasn't gone to Vesuvi6
	elif (g_bSuppliesReceived == TRUE):
		ProdPlayerToVesuvi6()
		
		return

################################################################################
##	InspectionProd()
##
##	Called if player is taking to long to select characters.
##
##	Args:	None
##
##	Return:	None
################################################################################
def InspectionProd():
	# Check our flag
	if (g_bPlayerInspecting == TRUE):
		return
		
	pSequence = App.TGSequence_Create()	
	
	pPicardInspectionProd	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M1InspectionProd1", "Captain", 1, g_pMissionDatabase)
	pRestartProdTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 45)
	
	pSequence.AddAction(pPicardInspectionProd)
	pSequence.AppendAction(pRestartProdTimer)
	
	pSequence.Play()
	
################################################################################
##	ProdPlayerToStarbase12()
##
##	Proding specific to getting the player to Starbase 12. Uses the global
##	g_iProdToStarbase12 to keep track of lines played.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ProdPlayerToStarbase12():
	if (g_bSuppliesReceived == TRUE):
		return
		
	pSequence = App.TGSequence_Create()

	global g_iProdToStarbase12
	# First time ProdPlayer calls us
	if (g_iProdToStarbase12 == 0):
		pSaffiVesuviProd1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1VesuviProd1", "Captain", 1, g_pMissionDatabase)
		pRestartTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)
		
		pSequence.AddAction(pSaffiVesuviProd1)
		pSequence.AddAction(pRestartTimer, pSaffiVesuviProd1)
		
		pSequence.Play()
		
		g_iProdToStarbase12 = 1
	
	# Second time and after ProdPlayer calls us
	elif (g_iProdToStarbase12 == 1):
		pSaffiVesuviProd2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1VesuviProd2", "Captain", 1, g_pMissionDatabase)
		pRestartTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)

		pSequence.AddAction(pSaffiVesuviProd2)
		pSequence.AddAction(pRestartTimer, pSaffiVesuviProd2)

		pSequence.Play()
		
################################################################################
##	ProdPlayerToVesuvi6()
##
##	Proding specific to getting the player to Vesuvi6.  Uses the global
##	g_iProdToVesuvi6 to keep tack of what line to play.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ProdPlayerToVesuvi6():
	pSequence = App.TGSequence_Create()
	
	global g_iProdToVesuvi6
	# First time ProdPlayer calls us
	if (g_iProdToVesuvi6 == 0):
		pSaffiVesuviProd1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1VesuviProd1", "Captain", 1, g_pMissionDatabase)
		pRestartTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 40)
		
		pSequence.AddAction(pSaffiVesuviProd1)
		pSequence.AddAction(pRestartTimer, pSaffiVesuviProd1)
		
		pSequence.Play()
		
		g_iProdToVesuvi6 = 1
	
	# Second time and after ProdPlayer calls us
	elif (g_iProdToVesuvi6 == 1):
		pSaffiVesuviProd2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M1VesuviProd2", "Captain", 1, g_pMissionDatabase)
		pRestartTimer		= App.TGScriptAction_Create(__name__, "RestartProdTimer", 40)

		pSequence.AddAction(pSaffiVesuviProd2)
		pSequence.AddAction(pRestartTimer, pSaffiVesuviProd2)

		pSequence.Play()

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
##	SetUIObjectHighlighted()
##
##	Turns highlighting on or off on the button fed into the function.  Called as
##	a script action.
##
##	Args:	pTGAction		- The script action object.
##			pMenu			- Pointer to the character's menu that the button
##							  exists in.
##			pSubMenu		- The submenu button that is to be higlighted or not.
##			bHighlighted	- 1 if we want the menu item highlited (default),
##							  0 if we want to remove the highlighting.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
#################################################################################
def SetUIObjectHighlighted(pTGAction, pMenu, pSubMenu, bHighlighted = 1):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	if (pMenu != None):
		if (pSubMenu != None):
			if (bHighlighted == 1):
				pSubMenu.SetHighlighted()
				pMenu.SetFocus(pSubMenu)
			else:
				pSubMenu.SetNotHighlighted()
		
	return 0

################################################################################
##	UIButtonPress()
##
##	Sends an activation event to the button that is fed in as if the player had
##	clicked on the menu button.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##			pButton		- The button that we want to have "pressed".
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def UIButtonPress(pAction, pButton):
	
	if (pButton != None):
		pButton.SetSelected()
		pButton.SetNotSelected()
		pButton.SendActivationEvent()

	return 0

################################################################################
##	SetUIObjectOpen()
##
##	Script action that opens a submenu.
##
##	Args:	pTGAction	- The script action object.
##			pMenu		- Pointer to the menu to open.
##			bSelected	- 1 will open the menu (default), 0 to close it.
##
##	Return:	0	- Return 0 to keep the calling sequence from crashing.
################################################################################
def SetUIObjectOpen(pAction, pMenu, bSelected = 1):
	pParent = pMenu.GetParent()
	
	if (pParent != None):
		pParent.SetFocus(pMenu)
		
	if (bSelected == 1):
		pMenu.Open()
	else:
		pMenu.Close()

	return 0

################################################################################
##	MoveMouseToButton()
##
##	Script action that moves the mouse to the center of the button that is
##	passed in.
##
##	Args:	pTGAction	- The script action object.
##			pObject		- The UI object to move to.
##			fTime		- Amount of time movement will take. Default 0.5 sec
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MoveMouseToButton(pTGAction, pObject, fTime = 0.5):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Make sure the button still exists
	if (pObject != None):	
		MissionLib.MoveMouseCursorToUIObject(pObject, fTime)
	
	return 0

################################################################################
##	HoldMouseAtButton()
##
##	Scripted action that moves the mouse to the center of the button that is
##	passed in and holds it there for the time given.
##
##	Args:	pTGAction	- The script action object.
##			pObject		- The UI object to move to.
##			fTime		- Amount of time to hold at button.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def HoldMouseAtButton(pTGAction, pObject, fTime = 0.5):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Make sure the button still exists
	if (pObject != None):
		MissionLib.MoveMouseCursorToUIObject(pObject, 0)
		MissionLib.MoveMouseCursorToUIObject(pObject, fTime)
		
	return 0
	
################################################################################
##	MoveMouseToButtonTop()
##
##	Script action that moves the mouse to the top center of the UI object
##	passed in.
##
##	Args:	pTGAction	- The script action object.
##			pObject		- The UI object to move to.
##			fTime		- Amount of time movement will take.  Default 0.5 sec
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MoveMouseToButtonTop(pTGAction, pObject, fTime = 0.5):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Make sure the button still exists
	if (pObject != None):
		MissionLib.MoveMouseCursorToUIObjectTop(pObject, fTime)
		
	return 0
	
################################################################################
##	MoveMouseToCenter()
##
##	Script action that moves the mouse to the center of the screen.
##
##	Args:	pTGAction	- The script action object.
##			fTime		- Amount of time movement will take. 0.5sec default
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MoveMouseToCenter(pTGAction, fTime = 0.5):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	MissionLib.MoveMouseCursorToUIObject(App.g_kRootWindow, fTime)
	
	return 0

################################################################################
##	HoldMouseAtCenter()
##
##	Script action that holds the mouse at the center  of the screen.
##
##	Args:	pTGAction	- The script action object.
##			fTime		- The amount of time to hold the mouse at the center.
##
##	Return:	0	- Return 0 to keep the calling sequence from crashing.
################################################################################
def HoldMouseAtCenter(pTGAction, fTime = 0.5):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	MissionLib.MoveMouseCursorToUIObject(App.g_kRootWindow, 0)
	MissionLib.MoveMouseCursorToUIObject(App.g_kRootWindow, fTime)
	
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


	# Remove arrows if there are any
	HideArrows()
	
	# Remove all our info boxes
	lInfoBoxes = GetBoxIDList()
	for idInfo in lInfoBoxes:
		if (idInfo != None):
			MissionLib.DestroyInfoBox(idInfo)

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()
	
	# Delete all our mission goals
	MissionLib.DeleteAllGoals()
	
	# Stop the prod timer if it's running
	StopProdTimer()
	
	# Remove our instance handlers
	RemoveInstanceHandlers()
	
	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if (g_pGeneralDatabase != None):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# unload the database: "data/TGL/Bridge Menus.tgl"
	if (g_pDatabase != None):
		App.g_kLocalizationManager.Unload(g_pDatabase)
	
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
		pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")
		pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".FriendlyFireGameOverHandler")

	# Destroy all the buttons in Picards menu
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicardMenu = pPicard.GetMenu()
		if (pPicardMenu != None):
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("CrewSelect")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Objectives")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("SettingCourse")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("NavPoints")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Docking")))

	# Handler for the in and out of tactical event
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow != None):
		pTopWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL, __name__ + ".TacticalToggleHandler")
		# Handler for toggling to map mode
		pTacticalWindow = pTopWindow.FindMainWindow(App.MWT_BRIDGE)
		if (pTacticalWindow != None):
			pTacticalWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_MAP_MODE,			__name__ + ".MapToggleHandler")
			pTacticalWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	__name__ + ".MapToggleHandler")

	# Helm buttons
	pKiska = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")
	if (pKiska != None):
		# Remove the special yes sir line
		pKiska.SetYesSir(None)
		pKiska.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pKiskaMenu = pKiska.GetMenu()
		if (pKiskaMenu != None):
			pKiskaMenu.RemoveHandlerForInstance(App.ET_DOCK,				__name__ + ".DockButtonClicked")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL,				__name__ + ".Hailing")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_SET_COURSE,			__name__ + ".SetCourseHandler")
			pKiskaMenu.RemoveHandlerForInstance(ET_COURSE_MENU_OPEN,		__name__ + ".CourseMenuOpened")
			pKiskaMenu.RemoveHandlerForInstance(ET_NAV_POINTS_MENU_OPEN,	__name__ + ".NavPointMenuOpened")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,			__name__ + ".CommunicateHandler")
			# Instance handler for warp button
			pWarpButton = Bridge.BridgeUtils.GetWarpButton()
			if (pWarpButton != None):
				pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")

	# Picard handlers
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicard.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")

	# Saffi handlers
	pSaffi = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	if (pSaffi != None):
		# Remove the special yes sir line
		pSaffi.SetYesSir(None)
		pSaffi.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pSaffiMenu = pSaffi.GetMenu()
		if (pSaffiMenu != None):
			pSaffiMenu.RemoveHandlerForInstance(ET_OBJECTIVES_MENU_OPEN,	__name__ + ".ObjectiveMenuOpened")
			pSaffiMenu.RemoveHandlerForInstance(App.ET_SET_ALERT_LEVEL,		__name__ + ".SetAlertLevelHandler")
			pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,			__name__ + ".CommunicateHandler")
	
	# Felix handlers
	pFelix = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if (pFelix != None):
		# Remove the special yes sir line
		pFelix.SetYesSir(None)
		pFelix.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pFelixMenu = pFelix.GetMenu()
		if (pFelixMenu != None):
			pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Miguel handlers
	pMiguel = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Science")
	if (pMiguel!= None):
		# Remove the special yes sir line
		pMiguel.SetYesSir(None)
		pMiguel.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pMiguelMenu = pMiguel.GetMenu()
		if (pMiguelMenu != None):
			pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Brex handlers
	pBrex = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
	if (pBrex != None):
		# Remove the special yes sir line
		pBrex.SetYesSir(None)
		pBrex.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
		pBrexMenu = pBrex.GetMenu()
		if (pBrexMenu != None):
			pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			
	# Remove the skip handler if we can
	App.g_kRootWindow.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".SkipOpeningSequence")
