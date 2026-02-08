###############################################################################
#	Filename:	E1M2.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 1, Mission 2
#	
#	Created:	10/30/00 -	Jess VanDerwalker
#	Revised:	3/27/01	 -	Jess VanDerwalker (changed from E2M5 to E1M2)
###############################################################################
import App
import loadspacehelper
import MissionLib
import Actions.MissionScriptActions
import Bridge.PowerDisplay
import Bridge.TacticalMenuHandlers
import Tactical.Interface.TacticalControlWindow
import Bridge.BridgeUtils
import Maelstrom.Episode2.Episode2
import Effects

# Declare global variables
TRUE				= 1
FALSE				= 0

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None
g_pDatabase			= None

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None
g_pPicard	= None

g_bMissionTerminate	= None

g_iMissionState	= None
DEFAULT			= None
DEBRIS_DONE		= None
ATTACKING_FRAGS	= None
MISSION_WON		= None

g_iAsteroidsDestroyed	= None
g_bHavenColonyDestroyed	= None
g_bAllAsteroidsDone		= None
g_iNumberAsteroidsHit	= None

g_bSequenceRunning			= None
g_bAlertLevelDone			= None
g_bDestroyOrderGiven		= None
g_bPlayerEngagingAsteroids	= None
g_bAreaScanDone				= None
g_bRedAlertProdDone			= None
g_bInterceptDone			= None
g_bPicardSuggestFelix		= None
g_iNumberTimesWeaponFired	= None

# Debris flags
g_bHavenFirstHail		= None
g_bDebrisCleared		= None

g_bHavenSecondHail		= None
g_bFirstOrbitDone		= None
g_bHavenHailDone		= None
g_bMiguelScanning		= None
g_bScanComplete			= None
g_bFirstAtmoLinePlayed	= None
g_bStationHit			= None
g_bStationHitPlanet		= None
g_bAsteroidsStopped		= None
g_bStationStopped		= None
g_bMissionWinCalled		= None
g_bMissionLostPlayed	= None
g_bPlayerOrderedOrbit	= None
g_bPlayerInOrbit		= None
g_bCanTransferSupplies	= None
g_bSuppliesTransfered	= None

# Proximity globals
g_pOuterProximityCheck		= None
g_pInnerProximityCheck		= None
g_pAtmosphereProximityCheck	= None
g_bOuterProxCheckDelay		= None
g_bInnerProxCheckDelay		= None
g_pStationProximityCheck	= None
g_bPlayerProximityCheck		= None

g_iMiguelOuterLineCounter	= None
g_iMiguelInnerLineCounter	= None

g_iVelocityTimerID			= None
g_idStationVelocityTimer	= None

ASTER_TYPE			= None
ASTER_GROUP			= None
ASTER_SCALE			= None
ASTER_ROTATION		= None
ASTER_EASY_SPEED	= None
ASTER_MED_SPEED		= None
ASTER_HARD_SPEED	= None
ASTER_HULL			= None

g_lDebrisNames	= []

g_dAsteroidInfo	= {}

g_dObjectVelocity = {}

g_bFragsFrozen	= None

g_lStationAsteroids	= []

g_lFriendlyShips	= []

# Flags used in tutorial sequences
g_bInTutorial				= None
g_bCharWindowLock			= None
g_iTacticalTutorialState	= None
g_iTutorialCounter			= None
g_bInInterceptTutorial		= None
g_bInOrbitTutorial			= None
g_bManualFirePlayed			= None
g_bTractorTutorialDone		= None

# Global IDs for the info boxes
g_idTargetListHelpBox		= None
g_idAlertLevelHelpBox		= None
g_idReticuleHelpBox			= None
g_idAttackOrdersHelpBox		= None
g_idWeaponsDisplayHelpBox	= None
g_idWeaponsControlHelpBox	= None
g_idTractorHelpBox			= None
g_idDamageDisplayHelpBox	= None
g_idManualFireHelpBox		= None
g_idTargetAtWillHelpBox		= None
g_idHailInfoBox1			= None
g_idHailInfoBox2			= None
g_idInterceptInfoBox1		= None
g_idInterceptInfoBox2		= None
g_idScanInfoBox1			= None
g_idOrbitInfoBox1			= None
g_idOrbitInfoBox2			= None
g_idBoostInfoBox1			= None
g_idBoostInfoBox2			= None
g_idBoostInfoBox3			= None
g_idSecondTractorHelpBox	= None

# Enumeration for the tactical tutorial state
DEFAULT			= 0
TUTORIAL_START	= 1
ALERT_LEVELS	= 2
TARGET_RETICULE	= 3
FELIX_ORDERS	= 4
WEAPONS_DISPLAY	= 5
WEAPONS_CONTROL	= 6
TRACTOR_CONTROL	= 7
DAMAGE_DISPLAY	= 8
MANUAL_FIRE		= 9
TARGET_AT_WILL	= 10
CLEAN_UP		= 20

# Global dictionary of arrows currently
# being displayed.
g_dCurrentArrows	= None

# Ennumeration used with g_dCurrentArrows
ARROW_OBJECT	= 0
ARROW_SPACING	= 1
ARROW_COLOR		= 2

# ID for the arrow refresh timer
g_idArrowRefreshTimer	= None

# Global that tells us our resolution
g_sResolutionSetting	= None

# Enumeration to access box specs
BOX_LEFT	= 0
BOX_TOP		= 1
BOX_WIDTH	= 2
BOX_HEIGHT	= 3

# Global dictonary for sizes and placement for info boxes.
g_dInfoBoxSpecs	= None

# Event Types for mission
ET_PROD_TIMER					= None
ET_VELOCITY_CHECK_TIMER			= None
ET_STATION_VELOCITY_CHECK_TIMER	= None
ET_ARROW_REFRESH_TIMER			= None

# Event types for Picards tutorial buttons
ET_ORBIT_TUTORIAL			= None
ET_HAIL_TUTORIAL			= None
ET_SCAN_TUTORIAL			= None
ET_INTERCEPT_TUTORIAL		= None
ET_TACTICAL_TUTORIAL		= None
ET_BOOST_TUTORIAL			= None
ET_TRACTOR_TUTORIAL			= None

ET_HAIL_MENU_OPEN			= None
ET_ORBIT_MENU_OPEN			= None

# Event types used with the help boxes
ET_CLOSE_TARGET_LIST_BOX	= None
ET_CLOSE_ALERT_HELP			= None
ET_CLOSE_RETICULE_HELP		= None
ET_CLOSE_INTERCEPT_ONE_BOX	= None
ET_CLOSE_HELP_BOX			= None

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
	loadspacehelper.PreloadShip("Galaxy", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("FedOutpost", 2)
	loadspacehelper.PreloadShip("Asteroid", 3)
	loadspacehelper.PreloadShip("Asteroid1", 3) 
	loadspacehelper.PreloadShip("Asteroid2", 4) 
	loadspacehelper.PreloadShip("Asteroid3", 1)
	loadspacehelper.PreloadShip("CommLight", 2)

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
	# Check and see if we have a player, if we don't
	# we aren't linking and will have to call the initial
	# briefing "by hand" and the end of Initialize
	bHavePlayer = 0
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		bHavePlayer = 1

	# Initialize our global variables
	InitializeGlobals(pMission)

	# Create the regions we'll be using
	CreateRegions()
	
	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")
	
	# Create Picard and put him on the bridge
	CreatePicard()
	
	# Create needed sets
	pStarbaseSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu			= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)
	
	pMiscEng		= MissionLib.SetupBridgeSet("MiscEng", "data/Models/Sets/SovereignEng/MiscEng2.NIF", -40, 65, -1.55)
	pSoams			= MissionLib.SetupCharacter("Bridge.Characters.Soams", "MiscEng")
	
	# Hide our characters
	pLiu.SetHidden(1)
	pSoams.SetHidden(1)

	# Create menus available at mission start
	CreateStartingMenus()
	
	# Create all objects that exist at mission start
	CreateStartingObjects(pMission)
	
	# Initialize the global pointers to bridge characters
	InitializeCharacterPointers()
	
	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()
	
	# Setup more mission-specific events.
	SetupEventHandlers(pMission)
	
	# Get the current resolution
	GetCurrentResolution()
	
	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)
	
	# Call the functions that will set up all our info boxes
	SetupTargetingHelpInfoBox()
	SetupAlertLevelHelpInfoBox()
	SetupReticuleHelpInfoBox()
	SetupFelixAttackHelpInfoBox()
	SetupWeaponDisplayHelpInfoBox()
	SetupWeaponControlHelpInfoBox()
	SetupTractorHelpInfoBox()
	SetupDamageDisplayInfoBox()
	SetupManualFireHelpInfoBox()
	SetupTargetAtWillHelpInfoBox()
	SetupHailInfoBoxes()
	SetupInterceptInfoBoxes()
	SetupScanInfoBoxes()
	SetupOrbitInfoBoxes()
	SetupBoostInfoBoxes()
	SetupSecondTractorHelpBox()
		
# ***FIXME: The following function is called to create all the
# tutorial buttons at once.  Comment out before checking in.
#	PicardTest()

	# If the player was created from scratch, call our initial briefing
	if (bHavePlayer == 0):
		FirstHavenHail()
	
	# Save the Game
	MissionLib.SaveGame("E1M2-")
	
################################################################################
##	InitializeGlobals()
##
##	Initialize the values of all our global variables
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
	# Globals used with bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0
	
	# Set g_bMissionTerminate here in case mission gets reloaded
	global g_bMissionTerminate
	g_bMissionTerminate = 1

	# TGL database globals
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 1/E1M2.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Flags for tracking the state of the mission.
	# Used by the Communicate functions
	global g_iMissionState
	global DEFAULT
	global DEBRIS_DONE
	global ATTACKING_FRAGS
	global MISSION_WON
	
	g_iMissionState	= 0
	DEFAULT			= 0
	ATTACKING_FRAGS	= 1
	MISSION_WON		= 2
	DEBRIS_DONE		= 3

	# Global used to see if a sequence is running so they won't
	# overlap
	global g_bSequenceRunning
	g_bSequenceRunning	= FALSE

	# Globals used for tutorial specific events
	global g_bAlertLevelDone
	global g_bDestroyOrderGiven
	global g_bPlayerEngagingAsteroids
	global g_bAreaScanDone
	global g_bMiguelScanning
	global g_bScanComplete
	global g_bRedAlertProdDone
	global g_bInterceptDone
	global g_bPicardSuggestFelix
	global g_iNumberTimesWeaponFired
	g_bAlertLevelDone			= FALSE
	g_bDestroyOrderGiven		= FALSE
	g_bPlayerEngagingAsteroids	= FALSE
	g_bAreaScanDone				= FALSE
	g_bMiguelScanning			= FALSE
	g_bScanComplete				= FALSE
	g_bRedAlertProdDone			= FALSE
	g_bInterceptDone			= FALSE
	g_bPicardSuggestFelix		= FALSE
	g_iNumberTimesWeaponFired	= 0

	# Debirs flags
	global g_bHavenFirstHail
	global g_bDebrisCleared
	g_bHavenFirstHail	= FALSE
	g_bDebrisCleared	= FALSE
	
	# Fragment flags
	global g_bHavenSecondHail
	global g_bFirstOrbitDone
	global g_bHavenHailDone
	global g_iAsteroidsDestroyed
	global g_bHavenColonyDestroyed
	global g_bAllAsteroidsDone
	global g_iNumberAsteroidsHit
	global g_bFirstAtmoLinePlayed
	global g_bStationHit
	global g_bStationHitPlanet
	global g_bAsteroidsStopped
	global g_bStationStopped
	global g_bMissionWinCalled
	global g_bMissionLostPlayed
	global g_bPlayerOrderedOrbit
	global g_bPlayerInOrbit
	global g_bCanTransferSupplies
	global g_bSuppliesTransfered
	g_bHavenSecondHail		= FALSE
	g_bFirstOrbitDone		= FALSE
	g_bHavenHailDone		= FALSE
	g_iAsteroidsDestroyed	= 0
	g_bHavenColonyDestroyed	= FALSE
	g_bAllAsteroidsDone		= FALSE
	g_iNumberAsteroidsHit	= 0
	g_bFirstAtmoLinePlayed	= FALSE
	g_bStationHit			= FALSE
	g_bStationHitPlanet		= FALSE
	g_bAsteroidsStopped		= FALSE
	g_bStationStopped		= FALSE
	g_bMissionWinCalled		= FALSE
	g_bMissionLostPlayed	= FALSE
	g_bPlayerOrderedOrbit	= FALSE
	g_bPlayerInOrbit		= FALSE
	g_bCanTransferSupplies	= FALSE
	g_bSuppliesTransfered	= FALSE

	# Flags used to see if we can play a line when one of the prox
	# checks is triggered
	global g_bOuterProxCheckDelay 
	global g_bInnerProxCheckDelay
	g_bOuterProxCheckDelay	= FALSE
	g_bInnerProxCheckDelay	= FALSE
	
	# Global pointers that will be used by the proximity checks.
	global g_pOuterProximityCheck
	global g_pInnerProximityCheck
	global g_pAtmosphereProximityCheck
	global g_pStationProximityCheck
	global g_bPlayerProximityCheck
	g_pOuterProximityCheck		= None
	g_pInnerProximityCheck		= None
	g_pAtmosphereProximityCheck	= None	
	g_pStationProximityCheck	= None
	g_bPlayerProximityCheck		= None

	# Counters to keep track of the proximity lines
	global g_iMiguelOuterLineCounter
	global g_iMiguelInnerLineCounter
	g_iMiguelOuterLineCounter	= 0
	g_iMiguelInnerLineCounter	= 0
	
	# Global IDs for the velocity check timers
	global g_iVelocityTimerID
	global g_idStationVelocityTimer
	g_iVelocityTimerID			= App.NULL_ID
	g_idStationVelocityTimer	= App.NULL_ID
	
	# Globals to be used to access the dictonary set up below
	global ASTER_TYPE
	global ASTER_GROUP
	global ASTER_SCALE
	global ASTER_ROTATION
	global ASTER_EASY_SPEED
	global ASTER_MED_SPEED
	global ASTER_HARD_SPEED
	global ASTER_HULL
	ASTER_TYPE			= 0
	ASTER_GROUP			= 1
	ASTER_SCALE			= 2
	ASTER_ROTATION		= 3
	ASTER_EASY_SPEED	= 4
	ASTER_MED_SPEED		= 5
	ASTER_HARD_SPEED	= 6
	ASTER_HULL			= 7
	
	global g_dAsteroidInfo
	# Here's where we set up the dictonary of values associated with
	# each asteroid.
	#						Name,	      Type,		   Group,	Scale, Rotation, EasySpd, MedSpd, HardSpd, Hull Points
	g_dAsteroidInfo	=	{
						"Asteroid 5b":  [ "Asteroid2", 	"b",	10.0,	6.3,		3.72,	5.0,	6.0,	2500],
						"Asteroid 6b":  [ "Asteroid",	"b",	5.5,	4.5,		3.72,	5.0,	6.0, 	3500],
						"Asteroid 7b":  [ "Asteroid2",	"b",	8.0,	11.4,		3.72,	5.0,	6.0, 	3000],
						"Asteroid 8e":	[ "Asteroid1",	"e",	7.5,	25.0,		5.5,	6.6,	8.5, 	4000],
						"Asteroid 9e":	[ "Asteroid2",	"e",	6.5,	35.0,		5.5,	6.6,	8.5, 	3000],
						}

	# Global list of all the static debirs names
	global g_lDebrisNames
	g_lDebrisNames	=	[
						"Debris1", "Debris2", "Debris3", "Debris4", "Debris5", "Debris6"
						]
						
	# Global dictonary that will be used for
	# storing the velocities of the asteroids
	# when we freeze them
	global g_dObjectVelocity
	g_dObjectVelocity	= {}
	
	# Flag for when asteroids are frozen
	global g_bFragsFrozen
	g_bFragsFrozen	= FALSE
	
	# List of friendly ships
	global g_lFriendlyShips
	g_lFriendlyShips	=	[ "Facility", "Starbase 12" ]
	
	# Flags used in tutorial sequences
	global g_bInTutorial
	global g_iTacticalTutorialState
	global g_bCharWindowLock
	global g_iTutorialCounter
	global g_bInInterceptTutorial
	global g_bInOrbitTutorial
	global g_bManualFirePlayed
	global g_bTractorTutorialDone
	g_bInTutorial				= FALSE
	g_iTacticalTutorialState	= 0
	g_bCharWindowLock			= FALSE
	g_iTutorialCounter			= 0
	g_bInInterceptTutorial		= FALSE
	g_bInOrbitTutorial			= FALSE
	g_bManualFirePlayed			= FALSE
	g_bTractorTutorialDone		= FALSE
	
	# Globals for special info box IDs
	global g_idTargetListHelpBox
	global g_idAlertLevelHelpBox
	global g_idReticuleHelpBox
	global g_idAttackOrdersHelpBox
	global g_idWeaponsDisplayHelpBox
	global g_idWeaponsControlHelpBox
	global g_idTractorHelpBox
	global g_idDamageDisplayHelpBox
	global g_idManualFireHelpBox
	global g_idTargetAtWillHelpBox
	global g_idHailInfoBox1
	global g_idHailInfoBox2
	global g_idInterceptInfoBox1
	global g_idInterceptInfoBox2
	global g_idScanInfoBox1
	global g_idOrbitInfoBox1
	global g_idOrbitInfoBox2
	global g_idBoostInfoBox1
	global g_idBoostInfoBox2
	global g_idBoostInfoBox3
	global g_idSecondTractorHelpBox
	g_idTargetListHelpBox		= None
	g_idAlertLevelHelpBox		= None
	g_idReticuleHelpBox			= None
	g_idAttackOrdersHelpBox		= None
	g_idWeaponsDisplayHelpBox	= None
	g_idWeaponsControlHelpBox	= None
	g_idTractorHelpBox			= None
	g_idDamageDisplayHelpBox	= None
	g_idManualFireHelpBox		= None
	g_idTargetAtWillHelpBox		= None
	g_idHailInfoBox1			= None
	g_idHailInfoBox2			= None
	g_idInterceptInfoBox1		= None
	g_idInterceptInfoBox2		= None
	g_idScanInfoBox1			= None
	g_idOrbitInfoBox1			= None
	g_idOrbitInfoBox2			= None
	g_idBoostInfoBox1			= None
	g_idBoostInfoBox2			= None
	g_idBoostInfoBox3			= None
	g_idSecondTractorHelpBox	= None

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
	App.g_kUtopiaModule.SetMaxFriendlyFire(4000)			# how many damage points the player can do total before losing
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(600)	# how many damage points before Saffi warns you

	# Event Types for mission
	global ET_PROD_TIMER
	global ET_VELOCITY_CHECK_TIMER
	global ET_STATION_VELOCITY_CHECK_TIMER
	global ET_ARROW_REFRESH_TIMER
	ET_PROD_TIMER					= App.Mission_GetNextEventType()
	ET_VELOCITY_CHECK_TIMER			= App.Mission_GetNextEventType()
	ET_STATION_VELOCITY_CHECK_TIMER	= App.Mission_GetNextEventType()
	ET_ARROW_REFRESH_TIMER			= App.Mission_GetNextEventType()

	# Event types for Picards tutorial buttons
	global ET_ORBIT_TUTORIAL
	global ET_HAIL_TUTORIAL
	global ET_SCAN_TUTORIAL
	global ET_INTERCEPT_TUTORIAL
	global ET_TACTICAL_TUTORIAL
	global ET_BOOST_TUTORIAL
	global ET_TRACTOR_TUTORIAL
	ET_ORBIT_TUTORIAL			= App.Mission_GetNextEventType()
	ET_HAIL_TUTORIAL			= App.Mission_GetNextEventType()
	ET_SCAN_TUTORIAL			= App.Mission_GetNextEventType()
	ET_INTERCEPT_TUTORIAL		= App.Mission_GetNextEventType()
	ET_TACTICAL_TUTORIAL		= App.Mission_GetNextEventType()
	ET_BOOST_TUTORIAL			= App.Mission_GetNextEventType()
	ET_TRACTOR_TUTORIAL			= App.Mission_GetNextEventType()

	# Event types used with the help boxes
	global ET_HAIL_MENU_OPEN
	global ET_ORBIT_MENU_OPEN
	global ET_CLOSE_TARGET_LIST_BOX
	global ET_CLOSE_ALERT_HELP
	global ET_CLOSE_RETICULE_HELP
	global ET_CLOSE_INTERCEPT_ONE_BOX
	global ET_CLOSE_HELP_BOX
	ET_HAIL_MENU_OPEN			= App.Mission_GetNextEventType()
	ET_ORBIT_MENU_OPEN			= App.Mission_GetNextEventType()
	ET_CLOSE_TARGET_LIST_BOX	= App.Mission_GetNextEventType()
	ET_CLOSE_ALERT_HELP			= App.Mission_GetNextEventType()
	ET_CLOSE_RETICULE_HELP		= App.Mission_GetNextEventType()
	ET_CLOSE_INTERCEPT_ONE_BOX	= App.Mission_GetNextEventType()
	ET_CLOSE_HELP_BOX			= App.Mission_GetNextEventType()

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
	global g_dInfoBoxSpecs
	
	# Get the language being used out of the E1M2HelpText.TGL
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	pString = pDatabase.GetString("Language")
	App.g_kLocalizationManager.Unload(pDatabase)
	
	# We are using German Version
	if (pString.GetCString() == "German"):	
#####		German												 Left,	Top,	Width,	Height	
		g_dInfoBoxSpecs =	{
						"TargetListHelp"	: {	"640x480"	:	[0.27,	0.135,	0.37,	0.39],
												"800x600"	:	[0.22,	0.135,	0.31,	0.38],
												"1024x768"	:	[0.17,	0.19,	0.31,	0.26],
												"1280x1024"	:	[0.15,	0.15,	0.31,	0.18],
												"1600x1200"	:	[0.15,	0.15,	0.31,	0.13],
											},
						"AlertLevelHelp"	: {	"640x480"	:	[0.65,	0.0,	0.29,	0.29],
												"800x600"	:	[0.65,	0.0,	0.30,	0.27],
												"1024x768"	:	[0.57,	0.0,	0.30,	0.18],
												"1280x1024"	:	[0.57,	0.0,	0.27,	0.12],
												"1600x1200"	:	[0.57,	0.0,	0.27,	0.08],
											},
						"ReticuleHelp"		: {	"640x480"	:	[0.65,	0.094,	0.325,	0.456],
												"800x600"	:	[0.69,	0.08,	0.28,	0.48],
												"1024x768"	:	[0.69,	0.13,	0.24,	0.33],
												"1280x1024"	:	[0.73,	0.27,	0.24,	0.21],
												"1600x1200"	:	[0.73,	0.27,	0.24,	0.16],
											},
						"AttackOrdersHelp"	: {	"640x480"	:	[0.25,	0.135,	0.35,	0.30],
												"800x600"	:	[0.2,	0.135,	0.41,	0.22],
												"1024x768"	:	[0.16,	0.11,	0.35,	0.16],
												"1280x1024"	:	[0.15,	0.09,	0.28,	0.12],
												"1600x1200"	:	[0.15,	0.09,	0.28,	0.10],
											},
						"WeaponsDisplay"	: {	"640x480"	:	[0.25,	0.135,	0.52,	0.38],
												"800x600"	:	[0.2,	0.135,	0.44,	0.36],
												"1024x768"	:	[0.54,	0.33,	0.44,	0.26],
												"1280x1024"	:	[0.54,	0.33,	0.44,	0.17],
												"1600x1200"	:	[0.54,	0.33,	0.44,	0.13],
											},
						"WeaponsControl"	: {	"640x480"	:	[0.25,	0.135,	0.52,	0.36],
												"800x600"	:	[0.2,	0.135,	0.44,	0.40],
												"1024x768"	:	[0.54,	0.34,	0.44,	0.24],
												"1280x1024"	:	[0.54,	0.35,	0.44,	0.18],
												"1600x1200"	:	[0.54,	0.35,	0.44,	0.14],
											},
						"TractorHelpOne"	: {	"640x480"	:	[0.25,	0.135,	0.43,	0.35],
												"800x600"	:	[0.2,	0.135,	0.43,	0.29],
												"1024x768"	:	[0.54,	0.35,	0.43,	0.20],
												"1280x1024"	:	[0.54,	0.35,	0.43,	0.12],
												"1600x1200"	:	[0.54,	0.35,	0.43,	0.11],
											},
####		German												 Left,	Top,	Width,	Height	
						"DamageDisplay"		: {	"640x480"	:	[0.28,	0.135,	0.36,	0.39],
												"800x600"	:	[0.23,	0.135,	0.35,	0.33],
												"1024x768"	:	[0.53,	0.33,	0.35,	0.21],
												"1280x1024"	:	[0.53,	0.33,	0.35,	0.16],
												"1600x1200"	:	[0.53,	0.33,	0.35,	0.12],
											},
						"ManualFire"		: {	"640x480"	:	[0.25,	0.135,	0.43,	0.25],
												"800x600"	:	[0.2,	0.135,	0.4,	0.21],
												"1024x768"	:	[0.16,	0.1,	0.37,	0.15],
												"1280x1024"	:	[0.13,	0.08,	0.37,	0.11],
												"1600x1200"	:	[0.13,	0.08,	0.37,	0.08],
											},
						"TargetAtWill"		: {	"640x480"	:	[0.26,	0.135,	0.35,	0.215],
												"800x600"	:	[0.21,	0.135,	0.35,	0.185],
												"1024x768"	:	[0.19,	0.1,	0.35,	0.125],
												"1280x1024"	:	[0.13,	0.08,	0.35,	0.09],
												"1600x1200"	:	[0.13,	0.08,	0.35,	0.067],
											},
						"HailHelp"			: {	"640x480"	:	[0.35,	0.0,	0.3,	0.12],
												"800x600"	:	[0.35,	0.0,	0.3,	0.12],
												"1024x768"	:	[0.35,	0.0,	0.3,	0.09],
												"1280x1024"	:	[0.35,	0.02,	0.3,	0.06],
												"1600x1200"	:	[0.35,	0.02,	0.3,	0.04],
											},
						"InterceptOne"		: {	"640x480"	:	[0.25,	0.18,	0.3,	0.156],
												"800x600"	:	[0.22,	0.20,	0.3,	0.136],
												"1024x768"	:	[0.17,	0.2,	0.3,	0.10],
												"1280x1024"	:	[0.14,	0.15,	0.25,	0.07],
												"1600x1200"	:	[0.14,	0.15,	0.25,	0.05],
											},
						"InterceptTwo"		: {	"640x480"	:	[0.35,	0.0,	0.3,	0.26],
												"800x600"	:	[0.35,	0.0,	0.3,	0.22],
												"1024x768"	:	[0.35,	0.0,	0.3,	0.16],
												"1280x1024"	:	[0.35,	0.02,	0.3,	0.10],
												"1600x1200"	:	[0.35,	0.02,	0.3,	0.06],
											},

						"ScanHelp"			: {	"640x480"	:	[0.68,	0.0,	0.3,	0.66],
												"800x600"	:	[0.68,	0.0,	0.3,	0.57],
												"1024x768"	:	[0.65,	0.0,	0.3,	0.39],
												"1280x1024"	:	[0.60,	0.0,	0.3,	0.24],
												"1600x1200"	:	[0.35,	0.0,	0.3,	0.16],
											},

#####		German												 Left,	Top,	Width,	Height	
						"OrbitHelp"			: {	"640x480"	:	[0.35,	0.0,	0.3,	0.17],
												"800x600"	:	[0.35,	0.0,	0.3,	0.17],
												"1024x768"	:	[0.35,	0.0,	0.3,	0.10],
												"1280x1024"	:	[0.35,	0.02,	0.3,	0.06],
												"1600x1200"	:	[0.35,	0.02,	0.3,	0.05],
											},
						"SecondTractor"		: {	"640x480"	:	[0.63,	0.14,	0.34,	0.38],
												"800x600"	:	[0.63,	0.27,	0.34,	0.32],
												"1024x768"	:	[0.64,	0.36,	0.34,	0.22],
												"1280x1024"	:	[0.64,	0.36,	0.34,	0.135],
												"1600x1200"	:	[0.64,	0.36,	0.34,	0.12],
											},
						"BoostingHelp"		: {	"640x480"	:	[0.31,	0.486,	0.67,	0.37],
												"800x600"	:	[0.47,	0.46,	0.5,	0.37],
												"1024x768"	:	[0.63,	0.37,	0.35,	0.34],
												"1280x1024"	:	[0.63,	0.28,	0.35,	0.21],
												"1600x1200"	:	[0.63,	0.28,	0.35,	0.16],
											},
						}

	# Default to the English Version
	else:
#####		English												 Left,	Top,	Width,	Height	
		g_dInfoBoxSpecs =	{
						"TargetListHelp"	: {	"640x480"	:	[0.27,	0.135,	0.31,	0.37],
												"800x600"	:	[0.22,	0.135,	0.31,	0.32],
												"1024x768"	:	[0.17,	0.19,	0.31,	0.24],
												"1280x1024"	:	[0.15,	0.15,	0.31,	0.16],
												"1600x1200"	:	[0.15,	0.15,	0.31,	0.12],
											},
						"AlertLevelHelp"	: {	"640x480"	:	[0.65,	0.0,	0.27,	0.33],
												"800x600"	:	[0.65,	0.0,	0.27,	0.3],
												"1024x768"	:	[0.57,	0.0,	0.27,	0.18],
												"1280x1024"	:	[0.57,	0.0,	0.27,	0.14],
												"1600x1200"	:	[0.57,	0.0,	0.27,	0.14],
											},
						"ReticuleHelp"		: {	"640x480"	:	[0.64,	0.1,	0.34,	0.42],
												"800x600"	:	[0.69,	0.13,	0.28,	0.42],
												"1024x768"	:	[0.69,	0.13,	0.24,	0.33],
												"1280x1024"	:	[0.73,	0.27,	0.24,	0.21],
												"1600x1200"	:	[0.73,	0.27,	0.24,	0.21],
											},
						"AttackOrdersHelp"	: {	"640x480"	:	[0.25,	0.135,	0.35,	0.30],
												"800x600"	:	[0.2,	0.135,	0.35,	0.24],
												"1024x768"	:	[0.16,	0.11,	0.35,	0.16],
												"1280x1024"	:	[0.15,	0.09,	0.28,	0.12],
												"1600x1200"	:	[0.15,	0.09,	0.28,	0.12],
											},
						"WeaponsDisplay"	: {	"640x480"	:	[0.25,	0.135,	0.52,	0.38],
												"800x600"	:	[0.2,	0.135,	0.44,	0.36],
												"1024x768"	:	[0.54,	0.35,	0.44,	0.24],
												"1280x1024"	:	[0.15,	0.77,	0.44,	0.15],
												"1600x1200"	:	[0.15,	0.77,	0.44,	0.15],
											},
						"WeaponsControl"	: {	"640x480"	:	[0.25,	0.135,	0.52,	0.35],
												"800x600"	:	[0.2,	0.135,	0.44,	0.36],
												"1024x768"	:	[0.54,	0.35,	0.44,	0.23],
												"1280x1024"	:	[0.15,	0.77,	0.44,	0.15],
												"1600x1200"	:	[0.15,	0.77,	0.44,	0.15],
											},
						"TractorHelpOne"	: {	"640x480"	:	[0.25,	0.135,	0.43,	0.31],
												"800x600"	:	[0.2,	0.135,	0.43,	0.25],
												"1024x768"	:	[0.54,	0.35,	0.43,	0.19],
												"1280x1024"	:	[0.15,	0.77,	0.43,	0.12],
												"1600x1200"	:	[0.15,	0.77,	0.43,	0.12],
											},
####		English												 Left,	Top,	Width,	Height	
						"DamageDisplay"		: {	"640x480"	:	[0.28,	0.135,	0.35,	0.38],
												"800x600"	:	[0.2,	0.135,	0.35,	0.33],
												"1024x768"	:	[0.53,	0.33,	0.35,	0.24],
												"1280x1024"	:	[0.25,	0.76,	0.35,	0.17],
												"1600x1200"	:	[0.25,	0.76,	0.35,	0.17],
											},
						"ManualFire"		: {	"640x480"	:	[0.25,	0.135,	0.43,	0.22],
												"800x600"	:	[0.2,	0.135,	0.4,	0.21],
												"1024x768"	:	[0.16,	0.1,	0.37,	0.15],
												"1280x1024"	:	[0.13,	0.08,	0.37,	0.11],
												"1600x1200"	:	[0.13,	0.08,	0.37,	0.11],
											},
						"TargetAtWill"		: {	"640x480"	:	[0.26,	0.135,	0.35,	0.185],
												"800x600"	:	[0.21,	0.135,	0.35,	0.155],
												"1024x768"	:	[0.16,	0.1,	0.35,	0.125],
												"1280x1024"	:	[0.13,	0.08,	0.35,	0.097],
												"1600x1200"	:	[0.13,	0.08,	0.35,	0.097],
											},
						"HailHelp"			: {	"640x480"	:	[0.35,	0.0,	0.3,	0.12],
												"800x600"	:	[0.35,	0.0,	0.3,	0.12],
												"1024x768"	:	[0.35,	0.0,	0.3,	0.07],
												"1280x1024"	:	[0.35,	0.02,	0.3,	0.04],
												"1600x1200"	:	[0.35,	0.02,	0.3,	0.04],
											},
						"InterceptOne"		: {	"640x480"	:	[0.25,	0.18,	0.3,	0.156],
												"800x600"	:	[0.22,	0.20,	0.3,	0.136],
												"1024x768"	:	[0.17,	0.2,	0.3,	0.1],
												"1280x1024"	:	[0.14,	0.15,	0.25,	0.086],
												"1600x1200"	:	[0.14,	0.15,	0.25,	0.086],
											},
						"InterceptTwo"		: {	"640x480"	:	[0.35,	0.0,	0.3,	0.26],
												"800x600"	:	[0.35,	0.0,	0.3,	0.22],
												"1024x768"	:	[0.35,	0.0,	0.3,	0.16],
												"1280x1024"	:	[0.35,	0.02,	0.3,	0.1],
												"1600x1200"	:	[0.35,	0.02,	0.3,	0.1],
											},

						"ScanHelp"			: {	"640x480"	:	[0.68,	0.0,	0.3,	0.54],
												"800x600"	:	[0.68,	0.0,	0.3,	0.5],
												"1024x768"	:	[0.65,	0.0,	0.3,	0.3],
												"1280x1024"	:	[0.35,	0.0,	0.3,	0.18],
												"1600x1200"	:	[0.35,	0.0,	0.3,	0.18],
											},

#####		English												 Left,	Top,	Width,	Height	
						"OrbitHelp"			: {	"640x480"	:	[0.35,	0.0,	0.3,	0.14],
												"800x600"	:	[0.35,	0.0,	0.3,	0.12],
												"1024x768"	:	[0.35,	0.0,	0.3,	0.08],
												"1280x1024"	:	[0.35,	0.02,	0.3,	0.05],
												"1600x1200"	:	[0.35,	0.02,	0.3,	0.04],
											},
						"SecondTractor"		: {	"640x480"	:	[0.63,	0.22,	0.34,	0.32],
												"800x600"	:	[0.63,	0.27,	0.34,	0.27],
												"1024x768"	:	[0.17,	0.74,	0.34,	0.18],
												"1280x1024"	:	[0.26,	0.81,	0.34,	0.135],
												"1600x1200"	:	[0.26,	0.81,	0.34,	0.135],
											},
						"BoostingHelp"		: {	"640x480"	:	[0.38,	0.486,	0.6,	0.37],
												"800x600"	:	[0.47,	0.49,	0.5,	0.37],
												"1024x768"	:	[0.63,	0.37,	0.35,	0.3],
												"1280x1024"	:	[0.63,	0.28,	0.35,	0.2],
												"1600x1200"	:	[0.63,	0.28,	0.35,	0.2],
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
##	InitializeCharacterPointers()
##
##	Initializes our global pointers to the bridge crew characters, so we can
##	use them in actions.  This must be called after the bridge is loaded.
##
##	Args:	None
##
##	Return:	None
################################################################################
def InitializeCharacterPointers():
	# Create global pointers to the bridge crew characters
	global g_pKiska
	global g_pFelix
	global g_pSaffi
	global g_pMiguel
	global g_pBrex
	global g_pPicard
	
	# Get the bridge
	pBridge	= App.g_kSetManager.GetSet("bridge")
	
	g_pKiska	= App.CharacterClass_GetObject(pBridge, "Helm")
	g_pFelix	= App.CharacterClass_GetObject(pBridge, "Tactical")
	g_pSaffi	= App.CharacterClass_GetObject(pBridge, "XO")
	g_pMiguel	= App.CharacterClass_GetObject(pBridge, "Science")
	g_pBrex		= App.CharacterClass_GetObject(pBridge, "Engineer")
	g_pPicard	= App.CharacterClass_GetObject(pBridge, "Picard")

################################################################################
##	CreateRegions()
##
##	Creates the regions to be used in this mission and loads in any mission
##	specific placements needed.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateRegions():
	# Starbase 12
	import Systems.Starbase12.Starbase12
	Systems.Starbase12.Starbase12.Initialize()
	pStarbaseSet = Systems.Starbase12.Starbase12.GetSet()
	# Vesuvi 6
	import Systems.Vesuvi.Vesuvi6
	Systems.Vesuvi.Vesuvi6.Initialize()
	pVesuvi6Set = Systems.Vesuvi.Vesuvi6.GetSet()
	
	# Add our custom placement objects for this mission.
	import E1M2_Vesuvi6_P
	E1M2_Vesuvi6_P.LoadPlacements(pVesuvi6Set.GetName())

################################################################################
##	CreateStartingMenus()
##	
##  Creates menu items for Starbase and Vesuvi systems in "Helm" at mission start.
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def CreateStartingMenus ():
	import Systems.Starbase12.Starbase
	import Systems.Vesuvi.Vesuvi
	
	Systems.Starbase12.Starbase.CreateMenus()
	Systems.Vesuvi.Vesuvi.CreateMenus()

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
	pPicard.AddPythonFuncHandlerForInstance(ET_ORBIT_TUTORIAL,				__name__ + ".ExplainOrbit")
	pPicard.AddPythonFuncHandlerForInstance(ET_HAIL_TUTORIAL,				__name__ + ".ExplainHail")
	pPicard.AddPythonFuncHandlerForInstance(ET_SCAN_TUTORIAL,				__name__ + ".ExplainScan")
	pPicard.AddPythonFuncHandlerForInstance(ET_INTERCEPT_TUTORIAL,			__name__ + ".ExplainIntercept")
	pPicard.AddPythonFuncHandlerForInstance(ET_TACTICAL_TUTORIAL,			__name__ + ".ExplainTactical")
	pPicard.AddPythonFuncHandlerForInstance(ET_BOOST_TUTORIAL,				__name__ + ".ExplainBoost")
	pPicard.AddPythonFuncHandlerForInstance(ET_TRACTOR_TUTORIAL,			__name__ + ".ExplainTractor")

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
	if (pPicard != None):
		pPicardMenu = pPicard.GetMenu()
		if (pPicardMenu != None):
			# Create all of his buttons
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Hailing"),	ET_HAIL_TUTORIAL, 0, g_pPicard))
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Scanning"),	ET_SCAN_TUTORIAL,0, g_pPicard))
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Orbiting"),	ET_ORBIT_TUTORIAL,0, g_pPicard))
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Intercepting"),	ET_INTERCEPT_TUTORIAL,0, g_pPicard))
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Tractor Beam"),	ET_TRACTOR_TUTORIAL,0, g_pPicard))
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Boosting"),	ET_BOOST_TUTORIAL,0, g_pPicard))
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Tactical"),	ET_TACTICAL_TUTORIAL, 0, g_pPicard))

################################################################################
##	CreateStartingObjects()
##
##	Create all the objects that exist when the mission starts and their
##	affliations
##
##	Args:	pMission	- The mission object.
##
##	Return:	pPlayer		- The "player's" object.
################################################################################
def CreateStartingObjects(pMission):
	if (pMission == None):
		return
	
	# Setup object affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("Facility")
	
	# Set the affiliation for all the asteroids
	pEnemy = pMission.GetEnemyGroup()
	for sName in g_dAsteroidInfo.keys():
		pEnemy.AddName(sName)
	for sName in g_lDebrisNames:
		pEnemy.AddName(sName)
	
	# Make the station tractorable
	pTractorGroup = pMission.GetTractorGroup()
	pTractorGroup.AddName("Facility")
	
	# Get the sets we need
	pStarbaseSet	= App.g_kSetManager.GetSet("Starbase12")
	pVesuvi6Set		= App.g_kSetManager.GetSet("Vesuvi6")
	# Create the ships that exist at mission start
	pPlayer		= MissionLib.CreatePlayerShip("Galaxy", pVesuvi6Set, "player", "Player Start")
	pStarbase	= loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")

	# Create all the debris
	CreateDebris()
	
################################################################################
##	CreateDebris()
##
##	Creates all the asteroids that will be present in the set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateDebris():
	# Create and place the static asteroids around the station
	# Get the set we need
	pSet = App.g_kSetManager.GetSet("Vesuvi6")
	
	pDebris1 = loadspacehelper.CreateShip("Asteroid", pSet, "Debris1", "Asteroid1Static")
	pDebris2 = loadspacehelper.CreateShip("Asteroid1", pSet, "Debris2", "Asteroid2Static")
	pDebris3 = loadspacehelper.CreateShip("Asteroid2", pSet, "Debris3", "Asteroid3Static")
	pDebris4 = loadspacehelper.CreateShip("Asteroid3", pSet, "Debris4", "Asteroid4Static")
	pDebris5 = loadspacehelper.CreateShip("Asteroid", pSet, "Debris5", "Asteroid5Static")
	pDebris6 = loadspacehelper.CreateShip("Asteroid1", pSet, "Debris6", "Asteroid6Static")
	
	lDebrisObjects = [pDebris1, pDebris2, pDebris3, pDebris4, pDebris5, pDebris6]
	for pObject in lDebrisObjects:
		# Set the scale
		pObject.SetScale(3)
		# Mark them as not hailable
		pObject.SetHailable(FALSE)
		# Set their hull value to 300
		pHull = pObject.GetHull()
		pProp = pHull.GetProperty()
		pProp.SetMaxCondition(300.0)
		pHull.SetCondition(pProp.GetMaxCondition())
		pObject.SetDeathScript (__name__ + ".AsteroidExploding")
 		
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
	# Player exits warp event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_WARP, pMission, __name__ + ".ExitedWarp")
	# Object exploding event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__+".ObjectDestroyed")
	# Planet collision event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_PLANET_COLLISION, pMission, __name__+".PlanetCollision")
	# Collision event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_COLLISION, pMission, __name__+".ObjectCollision")
	# Weapon fired event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_WEAPON_FIRED, pMission, __name__+".WeaponFired")
	# Tractor beam starts hitting event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STARTED_HITTING, pMission, __name__+".TractorBeamOn")
	# Resolution change event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_UI_REPOSITION, pMission, __name__ + ".ResolutionChanged")

	# Instance handlers on the mission for friendly fire warnings and game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".FriendlyFireReportHandler")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".FriendlyFireGameOverHandler")

	# Hander for player's ship changing targets and firing
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_TARGET_WAS_CHANGED, __name__+".TargetChanged")
		
	# Handler for the in and out of tactical event
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow != None):
		pTopWindow.AddPythonFuncHandlerForInstance(App.ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL, __name__ + ".TacticalToggleHandler")
		# Handlers for toggling to map mode and cinematic mode
		pTacticalWindow = pTopWindow.FindMainWindow(App.MWT_BRIDGE)
		if (pTacticalWindow != None):
			pTacticalWindow.AddPythonFuncHandlerForInstance(App.ET_INPUT_TOGGLE_MAP_MODE,		__name__ + ".MapToggleHandler")
			pTacticalWindow.AddPythonFuncHandlerForInstance(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	__name__ + ".MapToggleHandler")
			
	# Instance handlers on Saffi's menu
	pSaffiMenu = Bridge.BridgeUtils.GetBridgeMenu("XO")
	if (pSaffiMenu != None):
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_SET_ALERT_LEVEL,	__name__ + ".SetAlertLevelHandler")
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,		__name__ + ".CommunicateHandler")
		
	# Instance handler for Miguel's menu
	pMiguelMenu = Bridge.BridgeUtils.GetBridgeMenu("Science")
	if (pMiguelMenu != None):
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN,		__name__ + ".ScanHandler")
	
	# Instance handler on Kiska's menu
	pKiskaMenu = Bridge.BridgeUtils.GetBridgeMenu("Helm")
	if (pKiskaMenu != None):
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_SET_COURSE,	__name__ + ".SetCourseHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL,			__name__ + ".HailHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(ET_HAIL_MENU_OPEN,	__name__ + ".HailMenuOpened")
		pKiskaMenu.AddPythonFuncHandlerForInstance(ET_ORBIT_MENU_OPEN,	__name__ + ".OrbitMenuOpened")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		# Instance handler for warp button
		pWarpButton = Bridge.BridgeUtils.GetWarpButton()
		if (pWarpButton != None):
			pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")	
		# Instance handler for Kiska's orbit button
		pOrbit = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Orbit Planet"))
		if (pOrbit != None):
			pOrbit.AddPythonFuncHandlerForInstance(App.ET_ORBIT_PLANET, __name__ + ".OrbitHandler")	
	
	# Instance handler for Felix's menu
	pFelixMenu = Bridge.BridgeUtils.GetBridgeMenu("Tactical")
	if (pFelixMenu != None):
		pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_MANEUVER,		__name__ + ".ManeuverHandler")
	
	# Instance handlers for Brex's menu
	pBrexMenu = Bridge.BridgeUtils.GetBridgeMenu("Engineer")
	if (pBrexMenu != None):
		pBrexMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Handlers for the menu up and down event sent to the charater
	g_pFelix.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pSaffi.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pKiska.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pMiguel.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
	g_pBrex.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,		__name__ + ".HandleMenuEvent")
	g_pPicard.AddPythonFuncHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")

	# Setup orbit event.
	SetupOrbitEvents()
	
###############################################################################
##	ExitedWarp(pMission, pEvent)
##	
##	Called when the players ship has finished warping.
##	
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent
##	
##	Return:	none
###############################################################################
def ExitedWarp(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetSource())
	pPlayer = App.Game_GetCurrentPlayer()

	if (pShip== None) or (pPlayer == None) or (g_bMissionTerminate != 1) or (pShip.GetObjID() != pPlayer.GetObjID()):
		TGObject.CallNextHandler(pEvent)
		return
	
	pSet = pShip.GetContainingSet()
	if (pSet == None):
		TGObject.CallNextHandler(pEvent)
		return
	
	# If the player is entering Vesuvi 6 for the first time,
	# call our sequence and start the cutscene
	if (pSet.GetName() == "Vesuvi6") and (g_bHavenFirstHail == FALSE):
		FirstHavenHail()
		
	# All done, call our next handler
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ObjectDestroyed()
##
##	Event handler called when a ship exploding event is sent.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- Event that was sent to the object.
##
##	Return:	None
################################################################################
def ObjectDestroyed(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	# Check and see if it's a ship, if not return
	if (pShip == None):
		return
	
	sShipName	= pShip.GetName()
	
	# See if it's Debris
	if (sShipName in g_lDebrisNames):
		# Remove the name from the list
		global g_lDebrisNames
		g_lDebrisNames.remove(sShipName)
		# If there are no other names, call our function to
		# create the asteroids heading toward the planet
		if (len(g_lDebrisNames) == 0):
			# Mark the debris flag
			global g_bDebrisCleared
			g_bDebrisCleared = TRUE
			DebrisCleared()
			
	# If it's and asteroid, call another function to handle the numbers
	for sName in g_dAsteroidInfo.keys():
		# Get the full name of the asteroid
		if (sShipName == sName):
			# Remove the asteroid from our list
			global g_dAsteroidInfo
			del g_dAsteroidInfo[sName]
			# Set our flag so we won't playout of date dialogue
			global g_bPlayerEngagingAsteroids
			g_bPlayerEngagingAsteroids = TRUE
			# Call our function
			AsteroidDestroyed()
	
	# If the station has been destroyed, and there are n0
	# asteroids, call mission win
	if (g_bAllAsteroidsDone == TRUE) and (g_bStationHitPlanet == FALSE) and (g_bStationHit == TRUE) and (sShipName == "Facility"):
		MissionWin()
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	PlanetCollision()
##
##	Event handler called if there is a collision with a planet.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def PlanetCollision(TGObject, pEvent):
	pPlanet = App.Planet_Cast(pEvent.GetSource())
	if (pPlanet == None):
		return
	
	# Get the object that hit
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	
	# Check and see if the planet is Haven
	if (pPlanet.GetName() == "Haven"):
		# It is so cycle through our names of asteroids and
		# see if one of them hit.
		for sName in g_dAsteroidInfo.keys():
			# Get the full name of the asteroid
			if (pShip.GetName() == sName):
				# Yes, one of the Asteroids hit, so remove it
				# from the dictonary and call our function
				global g_dAsteroidInfo
				del g_dAsteroidInfo[sName]
				AsteroidHitPlanet()
		
		# If it's the station that's hit, call mission lost
		if (pShip.GetName() == "Facility"):
			# Set our flag so MissionWin doesn't play
			global g_bStationHitPlanet
			g_bStationHitPlanet = TRUE
			MissionLost(None)
			
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ObjectCollision()
##
##	Event handler called when two objects collide.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ObjectCollision(TGObject, pEvent):
	pObjectHitting	= App.ObjectClass_Cast(pEvent.GetSource())
	pObjectHit		= App.ObjectClass_Cast(pEvent.GetDestination())
	
	# Make sure we actually have objects
	if (pObjectHitting == None) or (pObjectHit == None):
		return
		
	sHitterName	= pObjectHitting.GetName()
	sHitName	= pObjectHit.GetName()
	
	# Check and see if an asteroid has hit the Orbital Facility
	if (sHitName == "Facility"):
		# Get the list of the asteroids true names.
		for sName in g_dAsteroidInfo.keys():
			if (sHitterName == sName):
				# An asteroid hit the station, so send it
				# toward the planet
				AsteroidHitStation()
				
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	WeaponFired()
##
##	Handler called if a ship fires a weapon.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def WeaponFired(TGObject, pEvent):
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	pTargetShip	= App.ShipClass_Cast(pEvent.GetObjPtr())
	if (pTargetShip == None):
		return
	
	sSetName	= pShip.GetContainingSet().GetName()
	sShipName 	= pShip.GetName()
	sTargetName	= pTargetShip.GetName()
	
	# Keep track of how may times the player has fired
	# and at 10, do our Picard suggestion.  Make sure we only
	# do this after the hail is done.
	if (sShipName == "player") and (g_bHavenSecondHail == TRUE):
		global g_iNumberTimesWeaponFired
		g_iNumberTimesWeaponFired = g_iNumberTimesWeaponFired + 1
		# If we're at ten, call our function
		if (g_iNumberTimesWeaponFired == 10):
			PicardBoostWeapons()
	
	# Nothing else to do.  Let any other events for this event handle it
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
	# Bail if we're not in the right part of the tutorial
	if (g_iTacticalTutorialState == TUTORIAL_START):
		return

	# If we're in the tutorial, do everything but drop her menu
	if (g_bInTutorial == TRUE):
		iType = pEvent.GetInt()

		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			TGObject.CallNextHandler(pEvent)
			return
			
		# If were going to Red Alert during the tutorial, increase the state
		if (iType == App.CharacterClass.EST_ALERT_RED):
			if (g_iTacticalTutorialState == ALERT_LEVELS):
				if (g_bAlertLevelDone == TRUE):
					global g_iTacticalTutorialState
					g_iTacticalTutorialState = TARGET_RETICULE

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
				App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "RedAlert", None, 0, g_pGeneralDatabase).Play()
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
##	TractorBeamOn()
##
##	Handler called when tractor beam starts hitting planet.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def TractorBeamOn(TGObject, pEvent):
	# Get the event destination (the thing hit by tractor beam)
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sTargetName = pShip.GetName()
				
	# Get the tractor beam system that fired so we
	# can set it's behavior.
	pTractorProjector	= App.TractorBeamProjector_Cast(pEvent.GetSource())
	pTractorSystem		= App.TractorBeamSystem_Cast(pTractorProjector.GetParentSubsystem())

	# If it's the Facility, have the tractor beam do
	# the "hold" behavior.
	if (sTargetName == "Facility") and (g_bStationHit == TRUE):
		pSequence = App.TGSequence_Create()
		pFelixEngaged1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2TractorEngaged1", None, 0, g_pMissionDatabase)
		pFelixEngaged2	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2TractorEngaged2", None, 0, g_pMissionDatabase)

		pSequence.AppendAction(pFelixEngaged1)
		pSequence.AppendAction(pFelixEngaged2)

		pSequence.Play()

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
	SetupTargetingHelpInfoBox()
	SetupAlertLevelHelpInfoBox()
	SetupReticuleHelpInfoBox()
	SetupFelixAttackHelpInfoBox()
	SetupWeaponDisplayHelpInfoBox()
	SetupWeaponControlHelpInfoBox()
	SetupTractorHelpInfoBox()
	SetupDamageDisplayInfoBox()
	SetupManualFireHelpInfoBox()
	SetupTargetAtWillHelpInfoBox()
	SetupHailInfoBoxes()
	SetupInterceptInfoBoxes()
	SetupScanInfoBoxes()
	SetupOrbitInfoBoxes()
	SetupBoostInfoBoxes()
	SetupSecondTractorHelpBox()
	
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
				g_idTargetListHelpBox, g_idAlertLevelHelpBox, g_idReticuleHelpBox,
				g_idAttackOrdersHelpBox, g_idWeaponsDisplayHelpBox, g_idWeaponsControlHelpBox,
				g_idManualFireHelpBox, g_idTractorHelpBox, g_idTargetAtWillHelpBox, g_idDamageDisplayHelpBox,
				g_idHailInfoBox1, g_idHailInfoBox2, g_idInterceptInfoBox1, g_idInterceptInfoBox2,
				g_idScanInfoBox1, g_idOrbitInfoBox1, g_idOrbitInfoBox2, g_idBoostInfoBox1, g_idBoostInfoBox2,
				g_idBoostInfoBox3, g_idSecondTractorHelpBox
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
		if (sShipName == "Facility"):
			pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2FiresStation1", "Captain", 1, g_pMissionDatabase)
			pSaffiLine.Play()

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
	
	if (sShipName == "Facility"):
		# End all the tutorial sequences
		App.TGActionManager_KillActions("TacticalTutorial")
		
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME))
		pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2FiresStation2", "Captain", 1, g_pMissionDatabase))
		# End the mission
		pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
		pGameOver.Play()
		
		return

	# All done, call the default handler.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	TargetChanged()
##
##	Handler called when player changes targets.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def TargetChanged(TGObject, pEvent):
	# Get the new target
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	
	pTarget = pShip.GetTarget()
	if (pTarget == None):
		return
	sTargetName = pTarget.GetName()

	if (sTargetName in g_lDebrisNames) and (g_iTacticalTutorialState == TUTORIAL_START):
		global g_iTacticalTutorialState
		g_iTacticalTutorialState = ALERT_LEVELS
	
	# If we haven't suggested the intercept option, check the
	# distance to the object and if it's far enough away call our function
	fDistance = MissionLib.GetDistance(pShip, pTarget)
	if (fDistance >= 571) and (g_bInterceptDone == FALSE) and (g_bDebrisCleared == TRUE):
		PicardSuggestIntercept(None)
		
	TGObject.CallNextHandler(pEvent)

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
##	for cinematic mode.
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
##	ScanHander()
##
##	Event handler called when scan button is hit.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ScanHandler(TGObject, pEvent):
	# If the players sensors are off, do the default thing and bail
	pPlayer	= MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pSensors = pPlayer.GetSensorSubsystem()
	if (pSensors == None):
		TGObject.CallNextHandler(pEvent)
		return
	if (pSensors.IsOn() == FALSE):
		TGObject.CallNextHandler(pEvent)
		return

	# See what kind of scan we're doing and if we care.
	iScanType = pEvent.GetInt()
	# Get the players set
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
		
	if (iScanType == App.CharacterClass.EST_SCAN_AREA):
		# If we're in the tutorial, increase our counter
		if (g_iTutorialCounter == 1):
			global g_iTutorialCounter
			g_iTutorialCounter = 2
		
		# If we're scanning the area for the first time
		if (g_bAreaScanDone == FALSE) and (pSet.GetName() == "Vesuvi6") and (g_bHavenSecondHail == TRUE):
			global g_bAreaScanDone
			g_bAreaScanDone = TRUE
        	# Call our scan sequence and disable the button
			Bridge.BridgeUtils.DisableScanMenu()
			ScanComplete()
				
			# Return without calling next handler
			return

	TGObject.CallNextHandler(pEvent)

################################################################################
##	SetCourseHandler()
##
##	Handler called when the "Set Course" button is hit, includes Intercept
##	event.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def SetCourseHandler(TGObject, pEvent):
	# Get the type of SetCourse event
	iType = pEvent.GetInt()

	# See if the player is intercepting the Facility,
	# and if so do our special intercept AI
	if (iType == App.CharacterClass.EST_SET_COURSE_INTERCEPT):
		#If we're in the intercept tutorial, increase our counter
		if (g_bInInterceptTutorial == TRUE):
			global g_iTutorialCounter
			g_iTutorialCounter = 3
			
		# Get the player and their target
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
		pTarget = pPlayer.GetTarget()
		if (pTarget == None):
			TGObject.CallNextHandler(pEvent)
			return
		
		# If we are intercepting one of the fragments,
		# set our intercept flag to true
		if (pTarget.GetName() in g_dAsteroidInfo.keys()):
			global g_bInterceptDone
			g_bInterceptDone = TRUE
			
		# Check the name of the target
		if (pTarget.GetName() == "Facility"):
			# It is the facility, so assign the AI
			import E1M2_AI_Intercept
			MissionLib.SetPlayerAI("Helm", E1M2_AI_Intercept.CreateAI(pPlayer, "Facility"))
		else:
			# It's not the facility so do the normal stuff
			TGObject.CallNextHandler(pEvent)
	
	# If it's not anything we care about, do the normal
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	HailHandler()
##
##	Handler called when "Hail" button is pressed in Kiska's menu.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def HailHandler(TGObject, pEvent):
	# Get the players ship and it's target
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if (pTarget == None):
		return
	
	# If we're in the Hail tutorial, increase our counter
	if (g_iTutorialCounter > 0) and (g_bInInterceptTutorial == FALSE):
		global g_iTutorialCounter
		g_iTutorialCounter = 3
		
	# See if we're hailing Haven
	if (pTarget.GetName() == "Haven"):
		# If player is hailing again before clearing debris
		if (g_bHavenSecondHail == FALSE) and (g_bHavenFirstHail == TRUE) and (g_bDebrisCleared == FALSE):
			# Turn on call waiting
			MissionLib.CallWaiting(None, TRUE)
			pKiskaHailHaven1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase)
			pKiskaHailHaven1.Play()
			HavenDebrisNotClearedHail()
			return
			
		# Are we hailing haven after the debirs has been cleared.
		elif (g_bHavenSecondHail == FALSE) and (g_bHavenFirstHail == TRUE) and (g_bDebrisCleared == TRUE):
			# Turn on call waiting
			MissionLib.CallWaiting(None, TRUE)
			pKiskaHailHaven1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase)
			pKiskaHailHaven1.Play()
			SecondHavenHail(None)
			return
			
		# If player is hailing Haven after the second Haven Hail has played
		elif (g_bHavenSecondHail == TRUE) and (g_bMissionWinCalled == FALSE):
			# Turn on call waiting
			MissionLib.CallWaiting(None, TRUE)
			pKiskaHailHaven1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase)
			pKiskaHailHaven1.Play()
			AsteroidsNotDoneHail()
			return

	# See if the target is the Facility
	elif (pTarget.GetName() == "Facility"):
		pKiskaLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2HailStation1", "Captain", 1, g_pMissionDatabase)
		pKiskaLine.Play()
		return
		
	# All done, call the default behavior
	TGObject.CallNextHandler(pEvent)

################################################################################
##	OrbitHandler()
##
##	Handler called when player selects a planet to orbit in Kiska's menu.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def OrbitHandler(TGObject, pEvent):
	# If we're in the orbit tutorial, increase our counter
	if (g_iTutorialCounter == 2) and (g_bInOrbitTutorial == TRUE):
		global g_iTutorialCounter
		g_iTutorialCounter = 3
		
	# See if MissionWin has been called
	if (g_bMissionWinCalled == FALSE):
		# Bail
		TGObject.CallNextHandler(pEvent)
		return
	
	# Get the planet we're going to orbit and
	# see if it's Haven
	pPlanet = App.Planet_Cast(pEvent.GetSource())
	if (pPlanet != None):
		if (pPlanet.GetName() == "Haven"):
			# Set our flag
			global g_bPlayerOrderedOrbit
			g_bPlayerOrderedOrbit = TRUE
			
	# All done, call the next handler for the event
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ManeuverHandler()
##
##	Handler called if player gives Maneuver order to Felix.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ManeuverHandler(TGObject, pEvent):
	# See what kind of event it is.
	iType	= pEvent.GetInt()
	
	# Its a destroy event, see if we have the weapons online
	if (iType == Bridge.TacticalMenuHandlers.EST_ORDER_DESTROY):
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
		
		pPhasers 	= pPlayer.GetPhaserSystem()
		pAlertLevel	= pPlayer.GetAlertLevel()
		
		if not (pPhasers.IsOn()) and (pAlertLevel != App.ShipClass.RED_ALERT):
			#Saffi needs to remind the player, call our function
			NoWeaponPower()
		
		# If we're at the right stage in the tutorial, set our flag
		if (g_iTacticalTutorialState >= TUTORIAL_START) and (g_bDestroyOrderGiven == FALSE):
			global g_bDestroyOrderGiven
			g_bDestroyOrderGiven = TRUE
			# Play the "Engaging" line from Felix
			pFelixEngaging	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "gt213", None, 0, g_pGeneralDatabase)
			pFelixEngaging.Play()
			
	# All done with this event - carry on.
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

	# Check and see where we are and call the correct function
	if (g_iMissionState == DEBRIS_DONE):
		DebrisDoneCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == ATTACKING_FRAGS):
		AttackingFragsCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == MISSION_WON):
		MissionWonCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	else:
		# All done, so call the next handler for this event.
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
##	CreateProximityChecks()
##
##	Creates the two proximity checks around Haven that will trigger dialogue.
##	Called from CreateMovingAsteroids()
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateProximityChecks():
	# Get the objects for the proximtiy check
	pSet		= App.g_kSetManager.GetSet("Vesuvi6")
	pPlanet		= pSet.GetObject("Haven")
	pOutpost	= pSet.GetObject("Facility")
	
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	pPlayerObj	= App.ObjectClass_Cast(pPlayer)
	
	# Get the radius of the proximity checks.
	# fOrbitRadius will trigger when the player goes into
	# orbit around the planet.
	# fOuterRadius will trigger at 200 k from planet
	# fInnerRadius will trigger at 75 k from planet
	# fStationRadius will trigger at 100 k from station.
	fOrbitRadius	= pPlanet.GetRadius() + 200
	fOuterRadius	= pPlanet.GetRadius() + 1143
	fInnerRadius	= pPlanet.GetRadius() + 429
	fAtmoRadius		= pPlanet.GetRadius() + 120
	fStationRadius	= 571
	
	# Get our list of objects for the planet prox checks
	lAsteroidObjects = []
	for sName in g_dAsteroidInfo.keys():
		pObject = pSet.GetObject(sName)
		lAsteroidObjects.append(pObject)
	
	# Get a list of objects for the Outpost prox check...
	# These will only be the one's that are heading toward the station
	# asteroid group "e"
	lStationAsteroids = []
	for sName in g_dAsteroidInfo.keys():
		if (g_dAsteroidInfo[sName][ASTER_GROUP] == "e"):
			pObject = pSet.GetObject(sName)
			lStationAsteroids.append(pObject)
	
	# Call our MissionLib function to create the proximity checks
	# for both the outer and inner checks
	global g_pOuterProximityCheck
	g_pOuterProximityCheck = MissionLib.ProximityCheck(pPlanet, -fOuterRadius, lAsteroidObjects, __name__+".OuterPlanetProximity")
	
	global g_pInnerProximityCheck	
	g_pInnerProximityCheck = MissionLib.ProximityCheck(pPlanet, -fInnerRadius, lAsteroidObjects, __name__+".InnerPlanetProximity")
	
	global g_pStationProximityCheck
	g_pStationProximityCheck = MissionLib.ProximityCheck(pOutpost, -fStationRadius, lStationAsteroids, __name__+".StationProximity")
	
	global g_pAtmosphereProximityCheck
	g_pAtmosphereProximityCheck = MissionLib.ProximityCheck(pPlanet, -fAtmoRadius, lAsteroidObjects, __name__+".AtmosphereProximity")
	
	# Create the proximity check on the player that will trigger
	# some advise from Picard.
	global g_bPlayerProximityCheck
	g_bPlayerProximityCheck	= MissionLib.ProximityCheck(pPlayer, -285, lAsteroidObjects, __name__+".PicardSuggestFelix")

################################################################################
##	OuterPlanetProximity()
##
##	Called when outer proximity check on Haven is triggered.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def OuterPlanetProximity(TGObject, pEvent):
	# Get the object that triggered the event
	pObject = App.ObjectClass_Cast(pEvent.GetDestination())
	if (pObject == None):
		return
	# Get the set
	pSet	= pObject.GetContainingSet()
	
	# Find out what group the asteroid belongs to and remove the
	# the whole group from the proximity check.
	sObjectName = pObject.GetName()
	try:
		sGroup = g_dAsteroidInfo[sObjectName][ASTER_GROUP]
	except KeyError:
		return
	
	for sName in g_dAsteroidInfo.keys():
		try:
			if (g_dAsteroidInfo[sName][ASTER_GROUP] == sGroup):
				pObject	= App.ObjectClass_GetObject(pSet, sName)
				g_pOuterProximityCheck.RemoveObjectFromCheckList(pObject)
		except:
			pass
			
	# Play the line from Miguel only if the Haven hail is done.
	if (g_bHavenHailDone == TRUE) and (g_bSequenceRunning == FALSE):
		global g_iMiguelOuterLineCounter
		if (g_iMiguelOuterLineCounter == 0):
			pMiguelAsteroidClose1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidClose2", "Captain", 1, g_pMissionDatabase)
			pMiguelAsteroidClose1.Play()
			g_iMiguelOuterLineCounter = g_iMiguelOuterLineCounter + 1
		else:
			pMiguelAsteroidClose1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidClose1", "Captain", 1, g_pMissionDatabase)
			pMiguelAsteroidClose1.Play()

################################################################################
##	InnerPlanetProximity()
##
##	Called when inner proximity check on Haven is triggered.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def InnerPlanetProximity(TGObject, pEvent):
	# Get the object that triggered the event
	pObject = App.ObjectClass_Cast(pEvent.GetDestination())
	if (pObject == None):
		return
		
	# Get the set
	pSet	= pObject.GetContainingSet()
	
	# Find out what group the asteroid belongs to and remove the
	# the whole group from the proximity check.
	sObjectName = pObject.GetName()
	try:
		sGroup = g_dAsteroidInfo[sObjectName][ASTER_GROUP]
	except KeyError:
		return
	
	for sName in g_dAsteroidInfo.keys():
		try:
			if (g_dAsteroidInfo[sName][ASTER_GROUP] == sGroup):
				pObject	= App.ObjectClass_GetObject(pSet, sName)
				g_pInnerProximityCheck.RemoveObjectFromCheckList(pObject)
		except:
			pass
		
	# Play the line from Miguel
	if (App.g_kUtopiaModule.GetGameTime() - g_pMiguel.GetLastTalkTime() > 30) and (g_bSequenceRunning == FALSE):
		global g_iMiguelInnerLineCounter
		if (g_iMiguelInnerLineCounter == 0):
			pMiguelAsteroidClose = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidClose3", "Captain", 1, g_pMissionDatabase)
			pMiguelAsteroidClose.Play()
			g_iMiguelInnerLineCounter = g_iMiguelInnerLineCounter + 1
		else:
			pMiguelAsteroidClose = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidClose4", "Captain", 1, g_pMissionDatabase)
			pMiguelAsteroidClose.Play()

################################################################################
##	AtmosphereProximity()
##
##	Called when an asteroid gets "really" close to the planet.  Removes the
##	asteroid that called from the proximity check and plays some lines from
##	Miguel
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def AtmosphereProximity(TGObject, pEvent):
	# Get the object that triggered the event
	pObject = App.ObjectClass_Cast(pEvent.GetDestination())
	if (pObject == None):
		return
		
	# Get the set
	pSet	= pObject.GetContainingSet()
	
	# Find out what group the asteroid belongs to and remove the
	# the whole group from the proximity check.
	sObjectName = pObject.GetName()
	try:
		sGroup = g_dAsteroidInfo[sObjectName][ASTER_GROUP]
	except KeyError:
		return
	
	for sName in g_dAsteroidInfo.keys():
		try:
			if (g_dAsteroidInfo[sName][ASTER_GROUP] == sGroup):
				pObject	= App.ObjectClass_GetObject(pSet, sName)
				g_pAtmosphereProximityCheck.RemoveObjectFromCheckList(pObject)
		except:
			pass
		
	# Play the line from Miguel
	if (g_bFirstAtmoLinePlayed == FALSE) and (g_bSequenceRunning == FALSE):
		pMiguelLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidClose5", "Captain", 1, g_pMissionDatabase)
		pMiguelLine.Play()
		global g_bFirstAtmoLinePlayed
		g_bFirstAtmoLinePlayed = TRUE
	else:
		pMiguelLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidClose6", "Captain", 1, g_pMissionDatabase)
		pMiguelLine.Play()
	
################################################################################
##	StationProximity()
##
##	Called when one of the asteroids that is heading toward the station gets
##	near it.  Plays line from Miguel warning the player.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def StationProximity(TGObject, pEvent):
	# Remove the proximity check since we don't need it any more
	g_pStationProximityCheck.RemoveAndDelete()
	
	# See how many fragments are heading toward the station
	# play the right line.
	lAsteroids = g_dAsteroidInfo.keys()
	lAsteroids.sort()
	iCounter = 0
	# Now cycle through that list and place the asteroids
	for sAsteroidName in lAsteroids:
		if (g_dAsteroidInfo[sAsteroidName][ASTER_GROUP] == "e"):
			iCounter = iCounter + 1
			
	# Play our line from Miguel
	if (iCounter == 2):
		pMiguelStationLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2StationProxLine1", "Captain", 1, g_pMissionDatabase)
		pMiguelStationLine.Play()
	else:
		pMiguelStationLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2StationProxLine1a", "Captain", 1, g_pMissionDatabase)
		pMiguelStationLine.Play()
	
################################################################################
##	SetupOrbitEvents()
##
##	Sets up event handlers for the orbit events that we want to listen to.
##	NOTE: The planets must be created first so we can create the instance
##	handlers.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupOrbitEvents():
	# Create the Haven orbit handler
	pSet	= App.g_kSetManager.GetSet("Vesuvi6")
	pPlanet = App.Planet_GetObject(pSet, "Haven")
	
	pPlanet.AddPythonFuncHandlerForInstance(App.ET_AI_ORBITTING, __name__ + ".OrbitingHaven")

################################################################################
##	OrbitingHaven()
##
##	Handler called when the player orbits Haven or trips proximity check.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def OrbitingHaven(TGObject, pEvent):
	# Call transfer supplies once we get back into orbit.
	if (g_bMissionWinCalled == TRUE) and (g_bSuppliesTransfered == FALSE):
		# Set the flag
		global g_bPlayerInOrbit
		g_bPlayerInOrbit = TRUE
		# If the supplies haven't been transfered, do that now.
		if (g_bSuppliesTransfered == FALSE):
			TransferSupplies(None)
		
	# Done doing stuff.
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	MoveSubtitles()
##
##	Script action that moves the subtitles to the cinematic position.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MoveSubtitles(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Force the subtitles to the cinamatic position
	pTop = App.TopWindow_GetTopWindow()
	if (pTop == None):
		return 0
	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
	if (pSubtitle == None):
		return 0
	pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_CINEMATIC)

	return 0
	
################################################################################
##	FirstHavenHail()
##
##	Called we player first arrives in Vesuvi system.  Called when player is done
##	warping.
##
##	Args:	None
##
##	Return:	None
################################################################################
def FirstHavenHail():
	# Check our flags
	if (g_bHavenFirstHail == TRUE):
		return

	# Set our hailed flag
	global g_bHavenFirstHail
	g_bHavenFirstHail = TRUE

	# Make sure the hail menu is active
	Bridge.BridgeUtils.EnableButton(None, "Helm", "Hail")

	# Get Haven and make it hailable
	pSet	= App.g_kSetManager.GetSet("Vesuvi6")
	pPlanet	= pSet.GetObject("Haven")
	pPlanet.SetHailable(TRUE)

	# Create the Tactical Tutorial button in Picards menu
	pPicardMenu = g_pPicard.GetMenu()
	if (pPicardMenu != None):
		pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Tactical"),	ET_TACTICAL_TUTORIAL, 0, g_pPicard))

	# Get Soams
	pSoams	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("MiscEng"), "Soams")

	pSequence = App.TGSequence_Create()

	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pKiskaArrive1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2ArriveHaven1", None, 0, g_pMissionDatabase)
	pKiskaHailHaven1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven2a", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MiscEng", "Soams")
	pSoamsHail1			= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven1", None, 0, g_pMissionDatabase)
	pSoamsFirst1		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2FirstHail1", None, 0, g_pMissionDatabase)
	pSoamsFirst2		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2FirstHail2", None, 0, g_pMissionDatabase)
	pSoamsFirst3		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2FirstHail3", None, 0, g_pMissionDatabase)
	pSoamsFirst4		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2FirstHail4", None, 0, g_pMissionDatabase)
	pSoamsFirst5		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2FirstHail5", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEnableHail			= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableHailMenu")
	pFelixFirst6		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2FirstHail6", "Captain", 1, g_pMissionDatabase)
	pAddDebrisGoal		= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E1DestroyDebrisGoal")
	pPicardLook			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_LOOK_AT_ME)
	pPicardTactical1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalOver1", "Captain", 0, g_pMissionDatabase)
	pPicardMenuUp		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_UP)
	pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")

	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pKiskaArrive1)
	pSequence.AppendAction(pKiskaHailHaven1)
	pSequence.AppendAction(pStarbaseViewOn, 1)
	pSequence.AppendAction(pSoamsHail1)
	pSequence.AppendAction(pSoamsFirst1)
	pSequence.AppendAction(pSoamsFirst2)
	pSequence.AppendAction(pSoamsFirst3)
	pSequence.AppendAction(pSoamsFirst4)
	pSequence.AppendAction(pSoamsFirst5)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEnableHail)
	pSequence.AppendAction(pAddDebrisGoal)
	pSequence.AppendAction(pFelixFirst6)
	pSequence.AddAction(pPicardTactical1, pFelixFirst6)
	pSequence.AddAction(pPicardLook, pFelixFirst6, 0.1)
	pSequence.AppendAction(pPicardMenuUp)
	pSequence.AppendAction(pEndCutscene)

	MissionLib.QueueActionToPlay(pSequence)

	return 0
	
################################################################################
##	HavenDebrisNotClearedHail()
##
##	Called from HailHandler() if player hails Haven again before debris is
##	cleared.  Calls itself as script action if another sequence is running.
##
##	Args:	None
##
##	Return:	None
################################################################################
def HavenDebrisNotClearedHail():
	# Get Soams and do the sequence.
	pMiscEng	= App.g_kSetManager.GetSet("MiscEng")
	pSoams		= App.CharacterClass_GetObject(pMiscEng, "Soams")

	pSequence = App.TGSequence_Create()

	pKiskaOnScreen	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, g_pGeneralDatabase)
	pViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MiscEng", "Soams")
	pSoamsHail1		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2SoamsHail1", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)

	pSequence.AppendAction(pKiskaOnScreen)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pSoamsHail1)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)

	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	DebrisCleared()
##
##	Called when all the pieces of Debris have been destroyed.
##
##	Args:	None
##
##	Return:	None
################################################################################
def DebrisCleared():
	#Set the mission state
	global g_iMissionState
	g_iMissionState = DEBRIS_DONE
	
	# Create our hail and scan tutorial buttons.
	pPicardMenu = g_pPicard.GetMenu()
	if (pPicardMenu != None):
		pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Hailing"),	ET_HAIL_TUTORIAL, 0, g_pPicard))
		# Disable Picards Tactical Tutorial button
		pTactTutorial = pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Tactical"))
		if (pTactTutorial != None):
			pTactTutorial.SetDisabled()

	# Turn off Felix if he's running
	pFelixMenu = g_pFelix.GetMenu()
	if (pFelixMenu != None):
		pStopOrder = App.TGIntEvent_Create()
		pStopOrder.SetDestination(pFelixMenu)
		pStopOrder.SetEventType(App.ET_MANEUVER)
		pStopOrder.SetInt(Bridge.TacticalMenuHandlers.EST_ORDER_STOP)
		App.g_kEventManager.AddEvent(pStopOrder)

	# Remove our goal
	MissionLib.RemoveGoal("E1DestroyDebrisGoal")
	# Add Hail goal
	MissionLib.AddGoal("E1HailHavenGoal")
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pFelixClear1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2DebrisClear1", "Captain", 1, g_pMissionDatabase)
	pRemoveGoal		= App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E1DestroyDebrisGoal")
	pKiskaClear2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2DebrisClear2", "Captain", 0, g_pMissionDatabase)

	pSequence.AppendAction(pFelixClear1)
	pSequence.AppendAction(pRemoveGoal)
	pSequence.AppendAction(pKiskaClear2)
	
	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	SecondHavenHail()
##
##	Called when player hails the Haven colony after destroying the debris.
##	Checks to make sure another sequence is not running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SecondHavenHail(pTGAction):
	# Check our flag
	if (g_bHavenSecondHail == TRUE) or (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "SecondHavenHail")
		pSequence.AppendAction(pWaitLoop, 2)
		pSequence.Play()
		
		return 0
		
	else:
		# No other sequence is playing, so go ahead
		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		global g_bHavenSecondHail
		g_bHavenSecondHail = TRUE
		
		# Put the scan button in Picards menu
		pPicardMenu = g_pPicard.GetMenu()
		if (pPicardMenu != None):
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Scanning"),	ET_SCAN_TUTORIAL,0, g_pPicard))

		pMiscEng	= App.g_kSetManager.GetSet("MiscEng")
		pSoams		= App.CharacterClass_GetObject(pMiscEng, "Soams")

		pSequence = App.TGSequence_Create()

		pCutsceneStart		= App.TGScriptAction_Create("MissionLib", "StartCutscene")
		pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
		pLookAtKiska		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_LOOK_AT_ME)
		pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MiscEng", "Soams", 0, 0, 0)
		pSoamsHailHaven1	= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven1a", None, 0, g_pMissionDatabase)
		pSoamsHailHaven2	= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven2", None, 0, g_pMissionDatabase)
		pSoamsHailHaven3	= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven3", None, 0, g_pMissionDatabase)
		pSaffiHailHaven4	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven4", None, 0, g_pMissionDatabase)
		pSoamsHailHaven5	= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven5", None, 0, g_pMissionDatabase)
		pCreateAsteroids	= App.TGScriptAction_Create(__name__, "CreateMovingAsteroids")
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pSetAsteroidsGoal	= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E1DestroyAsteroidsGoal")
		pSetHavenHailDone	= App.TGScriptAction_Create(__name__, "SetHavenHailDone")
		pPicardScan1		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2Scan1", "Captain", 1, g_pMissionDatabase)
		pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
		pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)


		# See what Kiska's first line will be
		pSequence.AppendAction(pCutsceneStart)
		pSequence.AppendAction(pForceToBridge)
		pSequence.AppendAction(pLookAtKiska)
		
		if (pTGAction != None):
			pKiskaHailHaven1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven2a", "Captain", 1, g_pMissionDatabase)
			pSequence.AppendAction(pKiskaHailHaven1)

		pSequence.AppendAction(pStarbaseViewOn, 2)
		pSequence.AppendAction(pSoamsHailHaven1)
		pSequence.AppendAction(pSoamsHailHaven2)
		pSequence.AppendAction(pSoamsHailHaven3)
		pSequence.AppendAction(pSaffiHailHaven4)
		pSequence.AppendAction(pSoamsHailHaven5)
		pSequence.AppendAction(pCreateAsteroids)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pEndCutscene)
		pSequence.AppendAction(pSetAsteroidsGoal)
		pSequence.AppendAction(pSetHavenHailDone)
		pSequence.AppendAction(pPicardScan1)
		pSequence.AppendAction(pClearFlag)
		pSequence.AppendAction(pEndCallWaiting)

		MissionLib.QueueActionToPlay(pSequence)

		return 0

################################################################################
##	SetHavenHailDone()
##
##	Script action that sets the value of g_bHavenHailDone to TRUE and sets
##	g_iMissionState.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetHavenHailDone(pTGAction):
	global g_bHavenHailDone
	g_bHavenHailDone = TRUE

	global g_iMissionState
	g_iMissionState = ATTACKING_FRAGS

	# Remove our hail goal
	MissionLib.RemoveGoal("E1HailHavenGoal")
	
	return 0
	
################################################################################
##	AsteroidsNotDoneHail()
##
##	Called when player hails the Haven colony before destroying the fragments.
##	Checks to make sure another sequence is not running.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def AsteroidsNotDoneHail(pTGAction = None):
	# Check our flag
	if (g_bMissionTerminate != 1):
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "AsteroidsNotDoneHail")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
		
	else:
		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		
		# Get Soams and do the sequence.
		pMiscEng	= App.g_kSetManager.GetSet("MiscEng")
		pSoams		= App.CharacterClass_GetObject(pMiscEng, "Soams")

		pSequence = App.TGSequence_Create()
		
		pKiskaOnScreen	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "OnScreen", None, 0, g_pGeneralDatabase)
		pViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MiscEng", "Soams")
		pSoamsHail1		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidsHitting5", None, 0, g_pMissionDatabase)
		pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
		
		pSequence.AppendAction(pKiskaOnScreen)
		pSequence.AppendAction(pViewOn)
		pSequence.AppendAction(pSoamsHail1)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pEndCallWaiting)
		pSequence.AppendAction(pClearFlag)
		
		MissionLib.QueueActionToPlay(pSequence)
		
		return 0
		
################################################################################
##	ScanComplete()
##
##	Plays line from Miguel telling the player what's out there.  Called from
##	ScanHandler().  If sequence is already running, calls itself until the
##	flag is clear.
##
##	Args:	pTGAction	- The script action ojbect.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ScanComplete(pTGAction = None):
	# Check and see if this is still relevant
	if (g_bPlayerEngagingAsteroids == TRUE) or (g_bScanComplete == TRUE) or (g_bMissionTerminate != 1):
		Bridge.BridgeUtils.EnableScanMenu()
		return 0

	if (g_bSequenceRunning == TRUE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ScanComplete")
		# If Miguel hasn't given his scanning line, do it
		if (g_bMiguelScanning == FALSE):
			global g_bMiguelScanning
			g_bMiguelScanning = TRUE
			pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "MiguelScan", None, 1, g_pGeneralDatabase))
			pSequence.AppendAction(App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons"))
		# Add the call to this function
		pSequence.AppendAction(pWaitLoop, 2)
		pSequence.Play()
		
		return 0
		
	else:
		# No other sequence is playing, so go ahead
		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		global g_bScanComplete
		g_bScanComplete = TRUE
	
		# Get the players sensors and have them scan the system
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return 0
		pSensors	= pPlayer.GetSensorSubsystem()
		if (pSensors != None):
			pScanSequence	= pSensors.ScanAllObjects()
			pScanSequence.Play()
			
		# Do Miguel's sequence
		pSequence = App.TGSequence_Create()

		pMiguelScan5		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2Scan5", None, 0, g_pMissionDatabase)
		pMiguelScan2		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2Scan2", "Captain", 0, g_pMissionDatabase)
		pMiguelScan2a		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2Scan2a", "Captain", 0, g_pMissionDatabase)
		pMiguelScan3		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2Scan3", None, 0, g_pMissionDatabase)
		pPicardScan4		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2Scan4", None, 1, g_pMissionDatabase)
		pEnableScan			= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
		pCheckAlertLevel	= App.TGScriptAction_Create(__name__, "CheckAlertLevel")
		pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		# Add the scanning line if Miguel hasn't said it
		if (g_bMiguelScanning == FALSE):
			pMiguelScanLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "MiguelScan", None, 1, g_pGeneralDatabase)
			pSequence.AppendAction(pMiguelScanLine)
					
		pSequence.AppendAction(pMiguelScan5, 1)
		pSequence.AppendAction(pMiguelScan2)
		pSequence.AppendAction(pMiguelScan2a)
		pSequence.AppendAction(pMiguelScan3)
		pSequence.AppendAction(pPicardScan4)
		pSequence.AppendAction(pEnableScan)
		pSequence.AppendAction(pCheckAlertLevel)
		pSequence.AppendAction(pClearFlag, 6)

		pSequence.Play()

	return 0
	
################################################################################
##	PicardSuggestIntercept()
##
##	Called from TargetChanged() the first time a player targets an object
##	far away.  Does sequence from Picard.  Checks g_bSequenceRunning and if its
##	TRUE, loops back on itself until it can play.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PicardSuggestIntercept(pTGAction):
	# If mission is terminating or intercept is done, bail
	if (g_bMissionTerminate != 1) or (g_bInterceptDone == TRUE):
		return 0
		
	# Check our flags
	if (g_bSequenceRunning == TRUE) or (g_bHavenHailDone == FALSE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "PicardSuggestIntercept")
		pSequence.AppendAction(pWaitLoop, 2)
		pSequence.Play()
		return 0
		
	else:
		# No other sequence is playing, so go ahead
		# Set our sequence flag
		global g_bSequenceRunning
		global g_bInterceptDone
		g_bSequenceRunning	= TRUE
		g_bInterceptDone	= TRUE
	
		# Create Intercept button in Picards menu
		pPicardMenu = g_pPicard.GetMenu()
		if (pPicardMenu != None):
			pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Intercepting"), ET_INTERCEPT_TUTORIAL, 0, g_pPicard))

		
		pSequence = App.TGSequence_Create()

		pKiskaIntercept1a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2Intercept1a", "Captain", 1, g_pMissionDatabase)
		pAreWeIntercepting	= App.TGScriptAction_Create(__name__, "AreWeIntercepting")
		pCheckAlertLevel	= App.TGScriptAction_Create(__name__, "CheckAlertLevel")
		pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pKiskaIntercept1a)
		pSequence.AppendAction(pAreWeIntercepting)
		pSequence.AppendAction(pCheckAlertLevel)
		pSequence.AppendAction(pClearFlag)

		pSequence.Play()
		
		return 0

################################################################################
##	AreWeIntercepting()
##
##	Script action that double checks to see if we are intercepting the fragments
##	and if not, does Picards lines.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to pause calling sequence.
################################################################################
def AreWeIntercepting(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check our flag
	if (g_bInterceptDone == TRUE):
		return 0
		
	# We haven't done the intercept, so do Picards lines
	pSequence = App.TGSequence_Create()

	pPicardIntercept1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2Intercept1", "Captain", 0, g_pMissionDatabase)
	pPicardIntercept2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2Intercept2", None, 1, g_pMissionDatabase)

	pSequence.AppendAction(pPicardIntercept1)
	pSequence.AppendAction(pPicardIntercept2)
	
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
##	PicardSuggestFelix()
##
##	Called from proximity check on player. Plays sequence from Picard if we get
##	close to an asteroid that we have targeted.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PicardSuggestFelix(TGObject, pEvent):
	# Check our flag and bail if we've done this
	if (g_bPicardSuggestFelix == TRUE):
		return
		
	# Get the object that tripped us.
	pObject = App.ObjectClass_Cast(pEvent.GetDestination())
	if (pObject == None):
		return
	
	# Find out what the name of the asteroid is and see
	# if the player has it targeted.
	sObjectName = pObject.GetName()
	
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	pTarget	= App.ShipClass_Cast(pPlayer.GetTarget())
	if (pTarget == None):
		return

	# Check if Felix is in control of the ship
	if MissionLib.GetPlayerShipController() == "Tactical":
		return

	# Check if his orders are to destroy.
	import Bridge.TacticalMenuHandlers
	if Bridge.TacticalMenuHandlers.GetHighLevelOrder() == "Destroy":
		return

	# Doesn't have to be an enemy, really.  It just needs to not be a friendly.
	pMission = MissionLib.GetMission()
	if (pMission == None):
		return
	pFriendlyGroup = pMission.GetFriendlyGroup()
	if pFriendlyGroup.IsNameInGroup( pTarget.GetName() ):
		return

	sTargetName = pTarget.GetName()
	if (sTargetName  == sObjectName):
		global g_bPicardSuggestFelix
		g_bPicardSuggestFelix = TRUE
		
		# Have Picard do his line and create the button in his menu
		pPicardLine	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2FelixOrders1", "Captain", 1, g_pMissionDatabase)
		pPicardLine.Play()
		
		# Remove the proximity check
		g_bPlayerProximityCheck.RemoveAndDelete()

################################################################################
##	NoWeaponPower()
##
##	If there is no power to the weapons, has Saffi prod the player to go to
##	red alert if they are not already there.
##
##	Args:	None
##
##	Return:	None
################################################################################
def NoWeaponPower():
	# Do the line from Saffi with a delay on it.
	pSequence = App.TGSequence_Create()
	
	pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2SaffiRedAlert2", "Captain", 0, g_pMissionDatabase)
	
	pSequence.AppendAction(pSaffiLine, 3)
	
	pSequence.Play()
	
################################################################################
##	PicardBoostWeapons()
##
##	Called from WeaponFired() if the player fires phasers 10 times.  Plays
##	sequence from Picard in the system is not already boosted.
##
##	Args:	None
##
##	Return:	None
#################################################################################
def PicardBoostWeapons():
	# Create Picards Boost button
	pPicardMenu = g_pPicard.GetMenu()
	if (pPicardMenu != None):
		pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Boosting"), ET_BOOST_TUTORIAL, 0, g_pPicard))
	
	# Get the players weapon system and see
	# if it's boosted
	pShip = App.ShipClass_Cast(MissionLib.GetPlayer())
	if (pShip == None):
		return
	
	if not (MissionLib.IsBoosted(pShip.GetPhaserSystem(), 1.2)):
		# Set sequence flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		
		# The system is not boosted, so do our sequence.
		pSequence = App.TGSequence_Create()
		
		pPicardBoost1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostWeapons1", "Captain", 0, g_pMissionDatabase)
		pPicardBoost2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostWeapons2", None, 0, g_pMissionDatabase)
		pPicardBoost3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostWeapons3", None, 1, g_pMissionDatabase)
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
		
		pSequence.AddAction(pPicardBoost1)
		pSequence.AppendAction(pPicardBoost2)
		pSequence.AppendAction(pPicardBoost3)
		pSequence.AppendAction(pClearFlag)
		
		pSequence.Play()

################################################################################
##	PicardBoostEngines()
##
##	Called from AsteroidDestroyed() when the player has destroyed 3 asteroids.
##	Plays sequence from Picard that suggests the player boosts the engines if
##	they are not.
##
##	Args:	
##
##	Return:	
################################################################################
def PicardBoostEngines():
	# Bail if the mission is lost
	if (g_bHavenColonyDestroyed == TRUE):
		return
		
	# Get the players ship
	pShip = App.ShipClass_Cast(MissionLib.GetPlayer())
	if (pShip == None):
		return

	# If the engines aren't boosted, then do the sequence
	if not (MissionLib.IsBoosted(pShip.GetImpulseEngineSubsystem(), 1.2)):
		# SEt the sequence flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE
		
		pSequence = App.TGSequence_Create()
		
		pPicardImpulse2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostEngines2", "Captain", 0, g_pMissionDatabase)
		pPicardImpulse3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostEngines3", None, 1, g_pMissionDatabase)
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
		
		pSequence.AppendAction(pPicardImpulse2)
		pSequence.AppendAction(pPicardImpulse3)
		pSequence.AppendAction(pClearFlag)
		
		pSequence.Play()

################################################################################
##	CreateMovingAsteroids()
##
##	Called from ObjectDestroyed() once the player clears away the debris from
##	the station.  Creates the asteroids that move toward the planet and station.
##
##	Args:	pTGAction - The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CreateMovingAsteroids(pTGAction = None):
	# Bail if the mission is terminating.
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the set we need and the outpost
	pSet = App.g_kSetManager.GetSet("Vesuvi6")
	pOutpost	= App.ShipClass_GetObject(pSet, "Facility")
	if (pOutpost == None):
		return 0
		
	# Get our difficulity level and set the speeds based on that
	eDifficulty = App.Game_GetDifficulty()
	if (eDifficulty == App.Game.EASY):
		eSpeed = ASTER_EASY_SPEED
	elif (eDifficulty == App.Game.MEDIUM):
		eSpeed = ASTER_MED_SPEED
	elif (eDifficulty == App.Game.HARD):
		eSpeed = ASTER_HARD_SPEED

	# Get a list of the asteroid names and sort it
	lAsteroids = g_dAsteroidInfo.keys()
	lAsteroids.sort()
	# Now cycle through that list and place the asteroids
	for sAsteroidName in lAsteroids:
		# Import the module that we'll need for our asteroid
		# sAsteroidModule becomes the imported module
		sAsteroidType	= g_dAsteroidInfo[sAsteroidName][ASTER_TYPE]
		# Place the Asteroid
		pAsteroid = loadspacehelper.CreateShip(sAsteroidType, pSet, sAsteroidName, sAsteroidName + " Placement")

		# Set the scale of the asteroid object
		pAsteroid.SetScale( g_dAsteroidInfo[sAsteroidName][ASTER_SCALE] )
		
		#Rotate the asteroid
		vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
		vVelocity.Scale((g_dAsteroidInfo[sAsteroidName][ASTER_ROTATION]) * App.PI / 180.0)		# Scale it to value in dictonary
		pAsteroid.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
		
		# Send some of the asteroids straight toward the Outpost,
		# send one toward the freighter.
		if (g_dAsteroidInfo[sAsteroidName][ASTER_GROUP] == "e"):
			# As an alternative to sending the asteroid forward along
			# the direction of the placement, send the asteroid directly
			# toward the center of the station.
			vVelocity = pOutpost.GetWorldLocation()
			vVelocity.Subtract(pAsteroid.GetWorldLocation())
			vVelocity.Unitize()
			vVelocity.Scale(g_dAsteroidInfo[sAsteroidName][eSpeed])
			pAsteroid.SetVelocity(vVelocity)
		else:
			# Set the forward velocity of the asteroid
			vVelocity = pAsteroid.GetWorldForwardTG()
			vVelocity.Scale(g_dAsteroidInfo[sAsteroidName][eSpeed])	# Set velocity here with value from dictonary
			pAsteroid.SetVelocity(vVelocity)
			
		# Set the Asteroid unhailable
		pAsteroid.SetHailable(FALSE)
		# Set the hull strength of the fragments
		pHull = pAsteroid.GetHull()
		if (pHull != None):
			pProp = pHull.GetProperty()
			pProp.SetMaxCondition(g_dAsteroidInfo[sAsteroidName][ASTER_HULL] )
			pHull.SetCondition(pProp.GetMaxCondition())

		pAsteroid.SetDeathScript (__name__ + ".AsteroidExploding")

	# Create proximity checks around the planet and Outpost
	# and add the asteroids to them.
	CreateProximityChecks()

	# Start our timer for the velocity check.  This will continue through
	# the mission every 15 sec.
	fStartTime	= App.g_kUtopiaModule.GetGameTime()
	pTimer		= MissionLib.CreateTimer(ET_VELOCITY_CHECK_TIMER, __name__+".CheckAsteroidVelocity", fStartTime + 15, 15, -1)
	global g_iVelocityTimerID
	g_iVelocityTimerID = pTimer.GetObjID()

	return 0
	
################################################################################
##	AsteroidExploding()
##
##	Handler called when one of the asteroids starts to explode.
##
##	Args:	TGObject	- The TGObject object (in this case the asteroid object)
##
##	Return:	None
################################################################################
def AsteroidExploding(TGObject):
	pObject = App.DamageableObject_Cast(TGObject)

	if (pObject == None):
#		debug("Unexpected NULL Ptr")
		return

	# we need a set to put it in
	# this should never be null, but you never know
	pSet = pObject.GetContainingSet()
	if (pSet == None):
#		debug("Unexpected NULL Set Ptr")
		return

	# death only takes 1/2 second
	fTotalLifeLeft = 0.5

	pObject.SetLifeTime (fTotalLifeLeft)
	
	fExplosionTime = 0.0
	fLastSound = -1.0e20

	pFinalExplosionSequence = App.TGSequence_Create()
	
	# Note: Create more explosions with fewer patches
	pEmitPos = pObject.GetRandomPointOnModel()	

	pSparks = Effects.CreateDebrisSparks(1.0, pEmitPos, 0, pSet.GetEffectRoot())
	pFinalExplosionSequence.AddAction(pSparks)

	pExplosion = Effects.CreateDebrisExplosion(pObject.GetRadius(), 1.5, pEmitPos, 1, pSet.GetEffectRoot())
	pFinalExplosionSequence.AddAction(pExplosion)

	pSet = pObject.GetContainingSet()

	sSound = Effects.GetDeathExplosionSound(pObject)
	pSound = App.TGSoundAction_Create(sSound, 0, pSet.GetName())
	pSound.SetNode(pObject.GetNode())
	pFinalExplosionSequence.AddAction(pSound)
	
	pFinalExplosionSequence.Play()

	# Turn the collisions off on the asteroid.
	TGObject.SetCollisionsOn(FALSE)

	return	

################################################################################
##	AsteroidHitPlanet()
##
##	Called from PlanetCollision() if an asteroid hits Haven.  Checks and sees
##	if it's a mission loss.
##
##	Args:	None
##
##	Return:	None
################################################################################
def AsteroidHitPlanet():
	# Increase the counter
	global g_iNumberAsteroidsHit
	g_iNumberAsteroidsHit = g_iNumberAsteroidsHit + 1
	
	
	# Asteroids have started to hit the planet
	if(g_iNumberAsteroidsHit == 1):
		# Call CheckAllDone() to see if this was the last one
		CheckAllDone()
		AsteroidsStartHitting()
	
	if(g_iNumberAsteroidsHit == 2):
		MissionLost(None)
	
################################################################################
##	AsteroidsStartHitting()
##
##	Called when an asteroid starts hitting the planet.
##
##	Args: 	None
##
##	Return:	None
################################################################################
def AsteroidsStartHitting():
	# Make sure were not doing this when we've won or lost
	if (g_bAllAsteroidsDone == TRUE) or (g_bHavenColonyDestroyed == TRUE):
		return
		
	# Set our sequence flag
	global g_bSequenceRunning
	g_bSequenceRunning = TRUE
	
	pMiscEng	= App.g_kSetManager.GetSet("MiscEng")
	pSoams		= App.CharacterClass_GetObject(pMiscEng, "Soams")
	
	pSequence = App.TGSequence_Create()
	
	pKiskaIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg3", None, 0, g_pGeneralDatabase)
	pSoamsHitting1	= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidsHitting1", None, 0, g_pMissionDatabase)
	pSoamsHitting2	= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidsHitting2", None, 0, g_pMissionDatabase)
	pMiguelHitting7	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2AsteroidsHitting7", "Captain", 1, g_pMissionDatabase)
	pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
	
	pSequence.AppendAction(pKiskaIncoming)
	pSequence.AppendAction(pSoamsHitting1)
	pSequence.AppendAction(pSoamsHitting2)
	pSequence.AppendAction(pMiguelHitting7)
	pSequence.AppendAction(pClearFlag, 1)
	
	pSequence.Play()
	
################################################################################
##	AsteroidDestroyed()
##
##	Keeps track of how many asteroids have been destroyed and calls functions
##	based on how many are gone.  Based on 14 asteroids in system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def AsteroidDestroyed():
	global g_iAsteroidsDestroyed
	
	# Since we've been called, increase the counter by one
	g_iAsteroidsDestroyed = g_iAsteroidsDestroyed + 1
	
	# Check to see if were all done
	CheckAllDone()
	
	# If we've destroyed 4 asteroids, have Picard suggest
	# boosting the engines.
	if (g_iAsteroidsDestroyed == 3):
		PicardBoostEngines()
	
################################################################################
##	AsteroidHitStation()
##
##	Called from ObjectCollision() if one of the asteroids hits the station.
##	Changes it's velocity so it heads toward the planet and plays some dialogue.
##
##	Args:	None
##
##	Return:	None
################################################################################
def AsteroidHitStation():
	# Get the set and the station object
	pSet		= App.g_kSetManager.GetSet("Vesuvi6")
	pStation	= App.ShipClass_GetObject(pSet, "Facility")
	if (pStation == None):
		return
		
	# If we're playing with the hard difficulty setting, have the
	# station fall a little faster.
	eDifficulty = App.Game_GetDifficulty()
	if (eDifficulty == App.Game.HARD):
		fSpeed = 1.7
	else:
		fSpeed = 1
		
	# Send the station toward the Planet Location placement
	pPlacement = App.PlacementObject_GetObject(pSet, "Planet Location")
	vVelocity = pPlacement.GetWorldLocation()
	vVelocity.Subtract(pStation.GetWorldLocation())
	vVelocity.Unitize()
	vVelocity.Scale(fSpeed)
	pStation.SetVelocity(vVelocity)

	# Do the sequence that will let the player know to tractor
	# the station
	StationHitSequence()

################################################################################
##	StationHitSequence()
##
##	Sequence that lets the player know they need to tractor the asteroid.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationHitSequence():
	# Check and set our flag
	if (g_bStationHit == FALSE):
		global g_bStationHit
		g_bStationHit = TRUE
	else:
		return
		
	# Return if the mission loss has been called
	if (g_bHavenColonyDestroyed == TRUE):
		return
		
	# Create the button in Picards menu for the tractor beam
	pPicardMenu = g_pPicard.GetMenu()
	if (pPicardMenu != None):
		pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Tractor Beam"),	ET_TRACTOR_TUTORIAL,0, g_pPicard))
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pMiguelStationHit1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2StationHit1", "Captain", 1, g_pMissionDatabase)
	pFelixStationHit2	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2StationHit2", "Captain", 1, g_pMissionDatabase)
	pMiguelStationHit3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2StationHit3", "Captain", 1, g_pMissionDatabase)
	pAddGoal			= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E1TractorStationGoal")
	pPicardStationHit5	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2StationHit5", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AddAction(pMiguelStationHit1)
	pSequence.AppendAction(pFelixStationHit2)
	pSequence.AppendAction(pMiguelStationHit3)
	pSequence.AppendAction(pAddGoal)
	pSequence.AppendAction(pPicardStationHit5)
	
	pSequence.Play()

	# Speed up the timer that checks the velocity of the station
	fStartTime		= App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_STATION_VELOCITY_CHECK_TIMER, __name__ + ".CheckStationVelocity", fStartTime + 5, 1, -1)
	global g_idStationVelocityTimer
	g_idStationVelocityTimer = pTimer.GetObjID()
	
################################################################################
##	CheckAsteroidVelocity()
##
##	Called by timer every 15 sec. to check and see if there are still
##	asteroids heading toward the planet or the station.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CheckAsteroidVelocity(TGObject, pEvent):
	# Bail out of this function if we've frozen the fragments
	if (g_bFragsFrozen == TRUE):
		return

	# Set the default value of our flag
	bCanCollide = FALSE
	
	bCanCollide = AreObjectsHeadingTowardTarget("Vesuvi6", g_dAsteroidInfo.keys(), "Facility")
	if (bCanCollide == TRUE):
		return
		
	bCanCollide = AreObjectsHeadingTowardTarget("Vesuvi6", g_dAsteroidInfo.keys(), "Haven")
	if (bCanCollide == TRUE):
		return
	else:
		global g_bAsteroidsStopped
		g_bAsteroidsStopped	= TRUE

	# Check and see if all our asteroids are not heading toward the planet
	# and call mission win if the station has not been hit or has been
	# stopped
	if (bCanCollide == FALSE) and ((g_bStationHit == FALSE) or (g_bStationStopped == TRUE)):
		MissionWin()
		
################################################################################
##	AreObjectHeadingTowardTarget()
##
##	Checks to see if any of the object in lsObjectNames is heading toward the
##	sTargetObject.
##
##	Args:	sSetname		- Name of the set were checking in.
##			lsObjectNames	- List of object names to check.
##			sTargetObject	- Name of the object were checking the list against.
##
##	Return:	1	- Return if object is heading toward target, otherwise zero.
################################################################################
def AreObjectsHeadingTowardTarget(sSetname, lsObjectNames, sTargetObject):
	# Get the set that we're checking in.
	pSet = App.g_kSetManager.GetSet(sSetname)

	if pSet:
		# Get the target object..
		pTargetObject = App.ObjectClass_GetObject(pSet, sTargetObject)
		if pTargetObject:
			fSqrTargetRadius = pTargetObject.GetRadius()
			fSqrTargetRadius = fSqrTargetRadius * fSqrTargetRadius

			# Get the objects we're checking.
			pObjects = App.ObjectGroup_ForceToGroup(lsObjectNames)
			lpObjectsRemaining = pObjects.GetActiveObjectTupleInSet(pSet)
			for pObject in lpObjectsRemaining:
				# Check if this object is heading toward the target object.
				pPhysicsObject = App.PhysicsObjectClass_Cast(pObject)
				if pPhysicsObject:
					vVelocity = pPhysicsObject.GetVelocityTG()

					# Got its velocity direction.  If it's zero, it'll
					# never hit...
## FIXME: Try a lower value (was using 0.5)
					if vVelocity.SqrLength() < 0.1:
						continue

					vVelocity.Unitize()

					# Check if the target object is in the direction
					# the velocity is pointing.  Treat the target object
					# as a sphere, so it's a simple check.
					vTargetDirection = pTargetObject.GetWorldLocation()
					vTargetDirection.Subtract(pObject.GetWorldLocation())

					vVelocityProjection = App.TGPoint3()
					vVelocityProjection.Set(vVelocity)
					vVelocityProjection.Scale( vTargetDirection.Dot(vVelocity) )

					vCenterDistance = App.TGPoint3()
					vCenterDistance.Set(vTargetDirection)
					vCenterDistance.Subtract(vVelocityProjection)
					fSqrDistance = vCenterDistance.SqrLength()

					if fSqrDistance <= fSqrTargetRadius:
						# It's gonna collide.
						return TRUE

	# No collisions imminent
	return FALSE

################################################################################
##	CheckStationVelocity()
##
##	Checks the station velocity and sees if we've stopped it.  Called from timer
##	started when the station is hit.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CheckStationVelocity(TGObject, pEvent):
	# Return if the Frags are frozen
	if (g_bFragsFrozen == TRUE):
		return
		
	# Get the station
	pSet	= App.g_kSetManager.GetSet("Vesuvi6")
	pShip	= App.ShipClass_GetObject(pSet, "Facility")
	
	if pShip:
		vVelocity = pShip.GetVelocityTG()

		# Got its velocity direction.  If it's zero, it'll
		# never hit so call our function.
		if vVelocity.SqrLength() < 0.1:
			vVelocity.SetXYZ(0,0,0)
			pShip.SetVelocity(vVelocity)

			StationStopped()
			# Stop the check timer
			if (g_idStationVelocityTimer != App.NULL_ID):
				App.g_kTimerManager.DeleteTimer(g_idStationVelocityTimer)
				
################################################################################
##	StationStopped()
##
##	Called from CheckStationVelocity() if the station's velocity is zero.
##	Calls MissionWin() if the asteroids have stopped as well.
##
##	Args:	None
##
##	Return:	None
################################################################################
def StationStopped():
	# Bail if mission lost
	if (g_bHavenColonyDestroyed == TRUE):
		return
		
	# Check and set our flag
	if (g_bStationStopped == FALSE):
		global g_bStationStopped
		g_bStationStopped = TRUE
	else:
		return
		
	# Play a line from Felix
	pFelixLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2NavIntercept3", "Captain", 0, g_pMissionDatabase)
	pFelixLine.Play()
	
	# If the asteroids have stopped as well,
	# call mission win
	if (g_bAsteroidsStopped == TRUE):
		MissionWin()

################################################################################
##	CheckAllDone()
##
##	Check and see if the number destroyed by player plus the number that have
##	hit planet equal 5 - the magic number.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CheckAllDone():
	# Check our total
	if ((g_iAsteroidsDestroyed + g_iNumberAsteroidsHit) == 5):
		# It's twelve, so call AllDone()
		AllDone()
		
################################################################################
##	AllDone()
##
##	All the asteroids have been destroyed.  If the Haven colony has not been
##	destroyed, calls MissionWin()
##
##	Args:	None
##
##	Return:	None
################################################################################
def AllDone():
	if (g_bHavenColonyDestroyed == FALSE):
		# Set our flag
		global g_bAllAsteroidsDone
		g_bAllAsteroidsDone = TRUE
		# Make sure the station isn't heading toward the planet/
		if (g_bStationHit == FALSE):
			# Call our win message
			MissionWin()
	else:
		return
	
################################################################################
##	MissionWin()
##	
##  Called if all asteroids have been destroyed and Colony still exists.
##	Removes the Destroy Asteroid goal.
##	
##	Args: 	None
##	
##	Return: None
################################################################################		
def MissionWin():
	# Make sure the station hasn't hit the planet and that the Haven colony
	# still exists.
	if (g_bStationHitPlanet == TRUE) or (g_bHavenColonyDestroyed == TRUE) or (g_bMissionWinCalled == TRUE):
		return
	
	# Set our flag
	global g_bMissionWinCalled
	g_bMissionWinCalled = TRUE
	
	WinWithoutTransfer()

	# Remove the goals we completed
	MissionLib.RemoveGoal("E1DestroyAsteroidsGoal")
	MissionLib.RemoveGoal("E1TractorStationGoal")
	# Add our supply goal
	MissionLib.AddGoal("E1SupplyCeli6Goal")

################################################################################
##	WinWithoutTransfer()
##
##	Called from MissionWin() if the player is not in orbit aroud the planet.
##	Plays sequence that lets the player know to orbit the planet.
##
##	Args:	None
##
##	Return:	None
################################################################################
def WinWithoutTransfer():
	# Get Soams
	pMiscEng	= App.g_kSetManager.GetSet("MiscEng")
	pSoams			= App.CharacterClass_GetObject(pMiscEng, "Soams")

	pSequence = App.TGSequence_Create()

	# Create Picard's orbit bar
	pPicardMenu = g_pPicard.GetMenu()
	if (pPicardMenu != None):
		pPicardMenu.AddChild(Bridge.BridgeUtils.CreateBridgeMenuButton(g_pMissionDatabase.GetString("Orbiting"),	ET_ORBIT_TUTORIAL,0, g_pPicard))

	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	# Check and see what Felix line to use
	if (g_bStationHit == TRUE) or (g_bAsteroidsStopped == TRUE):
		pFelixWin1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2MissionWin1a", "Captain", 1, g_pMissionDatabase)
	else:
		pFelixWin1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2MissionWin1", "Captain", 1, g_pMissionDatabase)
	
	pKiskaHail2a		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2HailHaven2a", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MiscEng", "Soams", 0, 0, 0)
	pSoamsWin2			= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2MissionWin2", None, 0, g_pMissionDatabase)
	pCheckOrbitStatus	= App.TGScriptAction_Create(__name__, "CheckOrbitStatus")
	
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pFelixWin1)
	pSequence.AppendAction(pKiskaHail2a)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pSoamsWin2)
	pSequence.AppendAction(pCheckOrbitStatus)
	
	MissionLib.QueueActionToPlay(pSequence)

	global g_iMissionState
	g_iMissionState = MISSION_WON

################################################################################
##	CheckOrbitStatus()
##
##	Script action that checks to see if the player has ordered an orbit. Plays
##	prod line from Kiska if the player is not orbiting.  If player is in orbit.
##	at this point, plays transfering sequence.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling object from crashing.
################################################################################
def CheckOrbitStatus(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Get Soams
	pSoams	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("MiscEng"), "Soams")
	
	# Check our flags
	# If the player has not ordered an orbit yet.
	if (g_bPlayerOrderedOrbit == FALSE):
		pSequence = App.TGSequence_Create()
		
		pSoamsWin3		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2MissionWin3", None, 0, g_pMissionDatabase)
		pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pKiskaArrive2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2ArriveHaven2", "Captain", 0, g_pMissionDatabase)
		pSetTransFlag	= App.TGScriptAction_Create(__name__, "SetTransferFlag")
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)

		pSequence.AppendAction(pSoamsWin3)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pKiskaArrive2)
		pSequence.AppendAction(pSetTransFlag)
		pSequence.AppendAction(pEndCallWaiting)
		
		# Add an action that will complete the event
		# so the calling sequence continues
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pTGAction)
		pSequence.AddCompletedEvent(pEvent)

		pSequence.Play()
	
		return 1
		
	# If the player has ordered the orbit, but is not in orbit
	elif (g_bPlayerOrderedOrbit == TRUE) and (g_bPlayerInOrbit == FALSE):
		pSequence = App.TGSequence_Create()
		
		pSoamsWin3		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2MissionWin3", None, 0, g_pMissionDatabase)
		pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSetTransFlag	= App.TGScriptAction_Create(__name__, "SetTransferFlag")
		pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)

		pSequence.AppendAction(pSoamsWin3)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pSetTransFlag)
		pSequence.AppendAction(pEndCallWaiting)

		# Add an action that will complete the event
		# so the calling sequence continues
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pTGAction)
		pSequence.AddCompletedEvent(pEvent)

		pSequence.Play()
		
		return 1
		
	# If the player has ordered and is in orbit
	elif (g_bPlayerOrderedOrbit == TRUE) and (g_bPlayerInOrbit == TRUE):
		WinWithTransfer()
		
	return 0
	
################################################################################
##	SetTransferFlag()
##
##	Script action that sets the value of g_bCanTransferSupplies to TRUE.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetTransferFlag(pTGAction):
	global g_bCanTransferSupplies
	g_bCanTransferSupplies = TRUE
	
	return 0
	
################################################################################
##	WinWithTransfer()
##
##	Calls the win dialogue and does the stuff to transfer supplies as well.
##
##	Args:	None
##
##	Return:	None
################################################################################
def WinWithTransfer():
	# Set our flag
	if (g_bSuppliesTransfered == TRUE):
		return
	else:
		# Set the transfer flag so if the other function is running,
		# it will stop
		global g_bCanTransferSupplies
		g_bCanTransferSupplies = TRUE
	
	pMiscEng	= App.g_kSetManager.GetSet("MiscEng")
	pSoams		= App.CharacterClass_GetObject(pMiscEng, "Soams")
	
	pSequence = App.TGSequence_Create()
		
	# Do the rest of the sequence.
	pSoamsSupplies1		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies1", None, 0, g_pMissionDatabase)
	pBrexSupplies2		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies2", "Captain", 1, g_pMissionDatabase)
	pBrexLowering		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "LoweringShields", None, 0, g_pGeneralDatabase)
	pSoamsSupplies3		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies3", None, 0, g_pMissionDatabase)
	pBrexSupplies4		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies4", "Captain", 1, g_pMissionDatabase)
	pSoamsSupplies5		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies5", None, 0, g_pMissionDatabase)
	pStarbaseViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSuppliesTransfered	= App.TGScriptAction_Create(__name__, "SetSuppliesTransfered")
	pSaffiSupplies6		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies6", "Captain", 1, g_pMissionDatabase)
	pE2M0Briefing		= App.TGScriptAction_Create(__name__, "E2M0Briefing")
	
	pSequence.AppendAction(pSoamsSupplies1)
	pSequence.AppendAction(pBrexSupplies2)
	pSequence.AppendAction(pBrexLowering)
	pSequence.AppendAction(pSoamsSupplies3)
	pSequence.AppendAction(pBrexSupplies4)
	pSequence.AppendAction(pSoamsSupplies5)
	pSequence.AppendAction(pStarbaseViewOff)
	pSequence.AppendAction(pSuppliesTransfered)
	pSequence.AppendAction(pSaffiSupplies6)
	pSequence.AppendAction(pE2M0Briefing)

	MissionLib.QueueActionToPlay(pSequence)
		
	# Set our mission state for the communicate
	global g_iMissionState
	g_iMissionState = DEFAULT

	# Remove our supply goal
	MissionLib.RemoveGoal("E1SupplyCeli6Goal")
	
################################################################################
##	TransferSupplies()
##
##	Called from OrbitingHaven() if MissionWin() has been called.  Checks flags
##	and calls itself as script action until it's true.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def TransferSupplies(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1) or (g_bSuppliesTransfered == TRUE):
		return 0

	if (g_bSequenceRunning == TRUE) or (g_bCanTransferSupplies == FALSE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "TransferSupplies")
		pSequence.AppendAction(pWaitLoop, 2)
		pSequence.Play()
		
		return 0
		
	else:
		# No other sequence is playing, so go ahead
		# Set our sequence flag and hailed flag
		global g_bSequenceRunning
		g_bSequenceRunning = TRUE

		# Get Soams and do the sequence.
		pMiscEng	= App.g_kSetManager.GetSet("MiscEng")
		pSoams		= App.CharacterClass_GetObject(pMiscEng, "Soams")

		pSequence = App.TGSequence_Create()

		pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
		pKiskaIncoming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg1", "Captain", 1, g_pGeneralDatabase)
		pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MiscEng", "Soams", 0, 0, 0)
		pSoamsSupplies1		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies1", None, 0, g_pMissionDatabase)
		pBrexSupplies2		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies2", "Captain", 1, g_pMissionDatabase)
		pCheckShields		= App.TGScriptAction_Create(__name__, "CheckShields")	
		pSoamsSupplies3		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies3", None, 0, g_pMissionDatabase)
		pBrexSupplies4		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies4", "Captain", 1, g_pMissionDatabase)
		pSoamsSupplies5		= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies5", None, 0, g_pMissionDatabase)
		pStarbaseViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pSuppliesTransfered	= App.TGScriptAction_Create(__name__, "SetSuppliesTransfered")
		pSaffiSupplies6		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2TransferSupplies6", "Captain", 1, g_pMissionDatabase)
		pE2M0Briefing		= App.TGScriptAction_Create(__name__, "E2M0Briefing")

		pSequence.AppendAction(pCallWaiting)
		pSequence.AppendAction(pKiskaIncoming, 3)
		pSequence.AppendAction(pStarbaseViewOn)
		pSequence.AppendAction(pSoamsSupplies1)
		pSequence.AppendAction(pBrexSupplies2)
		pSequence.AppendAction(pCheckShields)
		pSequence.AppendAction(pSoamsSupplies3)
		pSequence.AppendAction(pBrexSupplies4, 3)
		pSequence.AppendAction(pSoamsSupplies5)
		pSequence.AppendAction(pStarbaseViewOff)
		pSequence.AppendAction(pSuppliesTransfered)
		pSequence.AppendAction(pSaffiSupplies6)
		pSequence.AppendAction(pE2M0Briefing)

		MissionLib.QueueActionToPlay(pSequence)

		# Set our mission state
		global g_iMissionState
		g_iMissionState = DEFAULT

		# Remove our supply goal
		MissionLib.RemoveGoal("E1SupplyCeli6Goal")

	return 0

################################################################################
##	SetSuppliesTransfered()
##
##	Script action that sets the value of g_bSuppliesTransfered to TRUE.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetSuppliesTransfered(pTGAction = None):
	global g_bSuppliesTransfered
	g_bSuppliesTransfered = TRUE
	
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
		pFlickerShields		= App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields", 0, 14)
		
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
##	E2M0Briefing()
##
##	Play our briefing for E2M0 and set our flag so that when we warp to Tevron,
##	the next episode starts.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def E2M0Briefing(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu			= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	pKiskaSovSOS1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2SovereignSOS1", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuSovSOS2			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M2SovereignSOS2", None, 0, g_pMissionDatabase)
	pLiuSovSOS3			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M2SovereignSOS3", None, 0, g_pMissionDatabase)
	pLiuSovSOS4			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M2SovereignSOS4", None, 0, g_pMissionDatabase)
	pLiuSovSOS5			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M2SovereignSOS5", None, 0, g_pMissionDatabase)
	pLiuSovSOS6			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M2SovereignSOS6", None, 0, g_pMissionDatabase)
	pLiuSovSOS7			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M2SovereignSOS7", None, 0, g_pMissionDatabase)
	pStarbaseViewOff	= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pAddTevronGoal		= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E1GoToTevronGoal")
	pAddTevronToMenu	= App.TGScriptAction_Create(__name__, "LinkToEpisode2")
	
	pSequence.AddAction(pKiskaSovSOS1)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuSovSOS2)
	pSequence.AppendAction(pLiuSovSOS3)
	pSequence.AppendAction(pLiuSovSOS4)
	pSequence.AppendAction(pLiuSovSOS5)
	pSequence.AppendAction(pLiuSovSOS6)
	pSequence.AppendAction(pLiuSovSOS7)
	pSequence.AppendAction(pStarbaseViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pAddTevronGoal)
	pSequence.AppendAction(pAddTevronToMenu)
	
	MissionLib.QueueActionToPlay(pSequence)
	
	return 0

################################################################################
##	LinkToEpisode2()
##
##	Script action that creates the Tevron system in the helm menu and links it
##	to Episode 2.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def LinkToEpisode2(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Create the system in the Helm menu
	import Systems.Tevron.Tevron
	Systems.Tevron.Tevron.CreateMenus()

	# Get the menu and link it to the next episode
	pMenu = MissionLib.GetSystemOrRegionMenu("Tevron")
	if (pMenu != None):
		pMenu.SetEpisodeName("Maelstrom.Episode2.Episode2")

	return 0
	
################################################################################
##	MissionLost()
##
##	Called if Haven colony is destroyed.  Checks g_bSequenceRunning and puts
##	itself into a loop until g_bSequenceRunning is FALSE.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def MissionLost(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Check and set our flag
	if (g_bHavenColonyDestroyed == FALSE):
		global g_bHavenColonyDestroyed
		g_bHavenColonyDestroyed = TRUE
	
	# Check and see if another sequence is running
	if (g_bSequenceRunning == TRUE):
		# One is, so put ourselves into a loop
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "MissionLost")
		pSequence.AppendAction(pWaitLoop, 2)
		pSequence.Play()
		return 0
		
	else:
		# If we've played before, don't play again
		if (g_bMissionLostPlayed == FALSE):
			global g_bMissionLostPlayed
			g_bMissionLostPlayed = TRUE
		else:
			return 0
			
		# No other sequence is running, so go ahead and play
		pStarbase	= App.g_kSetManager.GetSet("StarbaseSet")
		pLiu		= App.CharacterClass_GetObject(pStarbase, "Liu")
		
		pMiscEng	= App.g_kSetManager.GetSet("MiscEng")
		pSoams		= App.CharacterClass_GetObject(pMiscEng, "Soams")

		pSequence = App.TGSequence_Create()
		
		# If the station hit the planet, change the lines
		# to reflect that.
		if (g_bStationHitPlanet == TRUE):
			pLossLine1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2StationHitsPlanet1", "Captain", 0, g_pMissionDatabase)
			pLossLine3	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2StationHitsPlanet2", None, 0, g_pMissionDatabase)	
		else:
			pLossLine1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost1", "Captain", 0, g_pMissionDatabase)
			pLossLine3	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost3", None, 0, g_pMissionDatabase)
	

		pMiguelLost2		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost2", "Captain", 1, g_pMissionDatabase)
		pStarbaseViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "MiscEng", "Soams", 0.8, 1, 1)
		pSoamsLost4			= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost4", None, 0, g_pMissionDatabase)
		pSoamsLost5			= App.CharacterAction_Create(pSoams, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost5", None, 0, g_pMissionDatabase)
		pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
		pFelixLost6			= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost6", "Captain", 1, g_pMissionDatabase)
		pMiguelLost7		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost7", "Captain", 1, g_pMissionDatabase)
		pKiskaLost8			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost8", "Captain", 1, g_pMissionDatabase)
		pSaffiLost9			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost9", "Captain", 0, g_pMissionDatabase)
		pStarbaseViewOn2	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu", 0, 0, 1)
		pLiuLost10			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E1M2MissionLost10", None, 0, g_pMissionDatabase)
		pViewOff2			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

		pSequence.AppendAction(pLossLine1)
		pSequence.AppendAction(pMiguelLost2)
		pSequence.AppendAction(pLossLine3)
		pSequence.AppendAction(pStarbaseViewOn)
		pSequence.AppendAction(pSoamsLost4)
		pSequence.AppendAction(pSoamsLost5)
		pSequence.AppendAction(pViewOff)
		pSequence.AppendAction(pFelixLost6)
		pSequence.AppendAction(pMiguelLost7)
		pSequence.AppendAction(pKiskaLost8)
		pSequence.AppendAction(pSaffiLost9)
		pSequence.AppendAction(pStarbaseViewOn2)
		pSequence.AppendAction(pLiuLost10)
		pSequence.AppendAction(pViewOff2)

		# End the mission
		pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
		pGameOver.Play()
		
		return 0

################################################################################
##	SetSequenceRunning()
##
##	Script action that sets the value of g_bSequenceRunning to FALSE.
##	g_bSequenceRunning used as flag to see if it's okay to start running another
##	sequence.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetSequenceRunning(pTGAction):
	global g_bSequenceRunning
	g_bSequenceRunning = FALSE
	
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
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Check and set our flag
	if (g_bRedAlertProdDone == FALSE):
		global g_bRedAlertProdDone
		g_bRedAlertProdDone = TRUE
	else:
		return 0
		
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
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
##	DebrisDoneCommunicate
##
##	Called from CommunicateHandler() if has cleared debris.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked on.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was sent to CommunicateHandler()
##
##	Return:	None
################################################################################
def DebrisDoneCommunicate(iMenuID, TGObject, pEvent):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")

	# Check and see whose button got pushed and do their line.
	if (iMenuID == idKiskaMenu):
		pKiskaCom1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2ArriveHaven3", "Captain", 1, g_pMissionDatabase)
		pKiskaCom1.Play()

	else:
		# Do the default thing since we don't have a special line.
		TGObject.CallNextHandler(pEvent)

################################################################################
##	AttackingFragsCommunicate()
##
##	Called from CommunicateHandler() if player is supposed to be attacking the
##	fragments.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked on.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was sent to CommunicateHandler()
##
##	Return:	None
################################################################################
def AttackingFragsCommunicate(iMenuID, TGObject, pEvent):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	if (iMenuID == idFelixMenu):
		pFelixCom1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E1M2FelixCom1", "Captain", 1, g_pMissionDatabase)
		pFelixCom1.Play()
		
	elif (iMenuID == idSaffiMenu):
		pSaffiCom1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2SaffiCom1", "Captain", 1, g_pMissionDatabase)
		pSaffiCom1.Play()
		
	elif (iMenuID == idBrexMenu):
		# Get the ship and the impulse subsystem and see if it's boosted
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
		pImpulse	= pPlayer.GetImpulseEngineSubsystem()
		if (MissionLib.IsBoosted(pImpulse) == FALSE):
			pBrexCom1 = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M2Brex1", "Captain", 1, g_pMissionDatabase)
			pBrexCom1.Play()
		
	# Do the default action if the above tests didn't catch anything
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	MissionWonCommunicate()
##
##	Called from CommunicateHandler() if player has won the mission and not
##	received their briefing for E2M0.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked on.
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The event that was sent to CommunicateHandler()
##
##	Return:	None
################################################################################
def MissionWonCommunicate(iMenuID, TGObject, pEvent):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose button got pushed and do their line.
	if (iMenuID == idKiskaMenu):
		pKiskaCom2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E1M2KiskaCom2", "Captain", 1, g_pMissionDatabase)
		pKiskaCom2.Play()
		
	elif (iMenuID == idSaffiMenu):
		pSaffiCom2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2SaffiCom2", "Captain", 1, g_pMissionDatabase)
		pSaffiCom2.Play()
		
	elif (iMenuID == idBrexMenu):
		pBrexCom2	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E1M2Brex2", "Captain", 1, g_pMissionDatabase)
		pBrexCom2.Play()
		
	# Do the default action if the above tests didn't catch anything
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	ExplainTactical()
##
##	Sets up everything we need for the tactical tutorial
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainTactical(TGObject, pEvent):
	# Set our flags
	global g_iTacticalTutorialState
	global g_bManualFirePlayed
	g_iTacticalTutorialState	= TUTORIAL_START
	g_bManualFirePlayed			= FALSE

	# Send a stop event to Felix
	pFelixMenu = g_pFelix.GetMenu()
	if (pFelixMenu != None):
		pStopOrder = App.TGIntEvent_Create()
		pStopOrder.SetDestination(pFelixMenu)
		pStopOrder.SetEventType(App.ET_MANEUVER)
		pStopOrder.SetInt(Bridge.TacticalMenuHandlers.EST_ORDER_STOP)
		App.g_kEventManager.AddEvent(pStopOrder)

	# Close the "Orders" menus
	Bridge.TacticalMenuHandlers.g_pTacticsStatusUIMenu.Close()
	Bridge.TacticalMenuHandlers.g_pManeuversStatusUIMenu.Close()

	# Disable input to Felix orders until we're ready
	Bridge.TacticalMenuHandlers.g_pOrdersStatusUI.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
	Bridge.TacticalMenuHandlers.g_pOrdersStatusUI.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")
	Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
	Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")
	Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
	Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")

	# Make the orders buttons look disabled.
	lPanes =	[Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane, 
				Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane, 
				Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane]
	for pPane in lPanes:
		for i in range(pPane.GetNumChildren()):
			pButton = App.STButton_Cast(pPane.GetNthChild(i))
			if pButton:
				pButton.SetUseUIHeight(0)
				pButton.SetNormalColor(App.g_kSTMenu1Disabled)
				pButton.SetColorBasedOnFlags()

	# Shut every one else on the bridge up
	MissionLib.SetSpeakingVolume(None, App.CSP_SPONTANEOUS, 0)
	
	# Make sure the sensors are on
	TurnOnSensors()
	
	# Clear the ships current target.
	MissionLib.ClearTarget()
	
	# Call the first part of Picards tutorial
	TacticalSelectTarget()

################################################################################
##	IgnoreInput()
##
##	Handler called when someone trys to use Felix's orders buttons.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	
################################################################################
def IgnoreInput(TGObject, pEvent):
	# do NOT call next handler
	return

################################################################################
##	InfoBoxClosed()
##
##	Handler called when the Reticule Help box is closed by the player.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def InfoBoxClosed(TGObject, pEvent):
	# Increase our tutorial state so the next sequence will play
	global g_iTacticalTutorialState
	if (g_iTacticalTutorialState == TARGET_RETICULE):
		g_iTacticalTutorialState = FELIX_ORDERS
		
	elif (g_iTacticalTutorialState == FELIX_ORDERS):
		g_iTacticalTutorialState = WEAPONS_DISPLAY
		
	elif (g_iTacticalTutorialState == WEAPONS_DISPLAY):
		g_iTacticalTutorialState = WEAPONS_CONTROL
	
	elif (g_iTacticalTutorialState == WEAPONS_CONTROL):
		g_iTacticalTutorialState = TRACTOR_CONTROL

	elif (g_iTacticalTutorialState == TRACTOR_CONTROL):
		g_iTacticalTutorialState = DAMAGE_DISPLAY
		
	elif (g_iTacticalTutorialState == DAMAGE_DISPLAY):
		g_iTacticalTutorialState = MANUAL_FIRE
		
	elif (g_iTacticalTutorialState == MANUAL_FIRE):
		g_iTacticalTutorialState = TARGET_AT_WILL
		
	elif (g_iTacticalTutorialState == TARGET_AT_WILL):
		g_iTacticalTutorialState = CLEAN_UP

	# All done with the event, pass on to next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	SetupTargetingHelpInfoBox()
##
##	Create the info box for the targeting help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupTargetingHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	
	# Destroy the old info box if it exists
	if (g_idTargetListHelpBox != None):
		MissionLib.DestroyInfoBox(g_idTargetListHelpBox)
	
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["TargetListHelp"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	# Create the formated paragraph
	pMainText		= App.TGParagraph_CreateW(pDatabase.GetString("TargetListHelp1"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pBlueLine		= App.TGParagraph_CreateW(pDatabase.GetString("TargetListHelp2"), fWidth, App.g_kRadarFriendlyColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pWhiteLine		= App.TGParagraph_CreateW(pDatabase.GetString("TargetListHelp4"), fWidth, App.g_kRadarNeutralColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pYellowLine		= App.TGParagraph_CreateW(pDatabase.GetString("TargetListHelp6"), fWidth, App.g_kRadarEnemyColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pGrayLine		= App.TGParagraph_CreateW(pDatabase.GetString("TargetListHelp7A"), fWidth, App.g_kRadarUnknownColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pRemember		= App.TGParagraph_CreateW(pDatabase.GetString("TargetListHelp8"), fWidth, App.g_kRadarEnemyColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pBlueLine)
	pMainText.AppendStringW(pDatabase.GetString("TargetListHelp3"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pWhiteLine)
	pMainText.AppendStringW(pDatabase.GetString("TargetListHelp5"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pYellowLine)
	pMainText.AppendStringW(pDatabase.GetString("TargetListHelp7"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pGrayLine)
	pMainText.AppendStringW(pDatabase.GetString("TargetListHelp7B"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pRemember)
	pMainText.AppendStringW(pDatabase.GetString("TargetListHelp9"))

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("TargetListHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_TARGET_LIST_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idTargetListHelpBox
	g_idTargetListHelpBox = pBox.GetObjID()	
	
################################################################################
##	SetupAlertLevelHelpInfoBox()
##
##	Create the info box for the alert level help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupAlertLevelHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	if (g_idAlertLevelHelpBox != None):
		MissionLib.DestroyInfoBox(g_idAlertLevelHelpBox)
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["AlertLevelHelp"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	# Create the formatted paragraph
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("AlertLevelHelp1"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pLine2Hi	= App.TGParagraph_CreateW(pDatabase.GetString("AlertLevelHelp2"), fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pLine3Hi	= App.TGParagraph_CreateW(pDatabase.GetString("AlertLevelHelp3"), fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pLine4Hi	= App.TGParagraph_CreateW(pDatabase.GetString("AlertLevelHelp4"), fWidth, App.g_kMainMenuButton2HighlightedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pLine2Hi)
	pMainText.AppendStringW(pDatabase.GetString("AlertLevelHelp2a"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pLine3Hi)
	pMainText.AppendStringW(pDatabase.GetString("AlertLevelHelp3a"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pLine4Hi)
	pMainText.AppendStringW(pDatabase.GetString("AlertLevelHelp4a"))

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("AlertLevelHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_ALERT_HELP, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idAlertLevelHelpBox
	g_idAlertLevelHelpBox = pBox.GetObjID()	

################################################################################
##	SetupReticuleHelpInfoBox()
##
##	Create the info box for the reticule help.  Uses ET_CLOSE_RETICULE_HELP to
##	close the box.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupReticuleHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	if (g_idReticuleHelpBox != None):
		MissionLib.DestroyInfoBox(g_idReticuleHelpBox)
				
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["ReticuleHelp"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("ReticuleHelpTitle"), 
				pDatabase.GetString("ReticuleHelp"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idReticuleHelpBox
	g_idReticuleHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InfoBoxClosed")
	
################################################################################
##	SetupFelixAttackHelpInfoBox()
##
##	Create the info box for Felix's attack order help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupFelixAttackHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Destroy the old info box if it exists
	if (g_idAttackOrdersHelpBox != None):
		MissionLib.DestroyInfoBox(g_idAttackOrdersHelpBox)

	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["AttackOrdersHelp"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")

	pMainTextA	= App.TGParagraph_CreateW(pDatabase.GetString("AttackOrderHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pDestroyB	= App.TGParagraph_CreateW(pDatabase.GetString("AttackOrderHelp1B"), fWidth, App.g_kSTMenu1NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pDisableD	= App.TGParagraph_CreateW(pDatabase.GetString("AttackOrderHelp1D"), fWidth, App.g_kSTMenu1NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pStopF		= App.TGParagraph_CreateW(pDatabase.GetString("AttackOrderHelp1F"), fWidth, App.g_kSTMenu1NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pEvadeH		= App.TGParagraph_CreateW(pDatabase.GetString("AttackOrderHelp1H"), fWidth, App.g_kSTMenu1NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	
	pMainTextA.AppendChar(App.WC_RETURN)
	pMainTextA.AppendChar(App.WC_RETURN)
	pMainTextA.AppendChar(App.WC_CURSOR)
	pMainTextA.AddChild(pDestroyB)
	pMainTextA.AppendStringW(pDatabase.GetString("AttackOrderHelp1C"))
	pMainTextA.AppendChar(App.WC_RETURN)
	pMainTextA.AppendChar(App.WC_CURSOR)
	pMainTextA.AddChild(pDisableD)
	pMainTextA.AppendStringW(pDatabase.GetString("AttackOrderHelp1E"))
	pMainTextA.AppendChar(App.WC_RETURN)
	pMainTextA.AppendChar(App.WC_CURSOR)
	pMainTextA.AddChild(pStopF)
	pMainTextA.AppendStringW(pDatabase.GetString("AttackOrderHelp1G"))
	pMainTextA.AppendChar(App.WC_RETURN)
	pMainTextA.AppendChar(App.WC_CURSOR)
	pMainTextA.AddChild(pEvadeH)
	pMainTextA.AppendStringW(pDatabase.GetString("AttackOrderHelp1I"))
	
	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("AttackOrderHelpTitle"), pMainTextA,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idAttackOrdersHelpBox
	g_idAttackOrdersHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InfoBoxClosed")

################################################################################
##	SetupWeaponDisplayHelpInfoBox()
##
##	Create the info box for the weapons display help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupWeaponDisplayHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	if (g_idWeaponsDisplayHelpBox != None):
		MissionLib.DestroyInfoBox(g_idWeaponsDisplayHelpBox)
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["WeaponsDisplay"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("WeaponsDisplayHelpTitle"), 
				pDatabase.GetString("WeaponsDisplayHelp"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idWeaponsDisplayHelpBox
	g_idWeaponsDisplayHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InfoBoxClosed")

################################################################################
##	SetupWeaponControlHelpInfoBox()
##
##	Create the info box for the weapons display help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupWeaponControlHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	if (g_idWeaponsControlHelpBox != None):
		MissionLib.DestroyInfoBox(g_idWeaponsControlHelpBox)
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["WeaponsControl"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")

	# Create our formatted paragraph
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("WeaponsControlHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pHigh		= App.TGParagraph_CreateW(pDatabase.GetString("WeaponsControlHelpHigh"), fWidth, App.g_kSTMenu3NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pLow		= App.TGParagraph_CreateW(pDatabase.GetString("WeaponsControlHelpLow"), fWidth, App.g_kSTMenu3NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pHigh1		= App.TGParagraph_CreateW(pDatabase.GetString("WeaponsControlHelpHigh"), fWidth, App.g_kSTMenu3NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pLow1		= App.TGParagraph_CreateW(pDatabase.GetString("WeaponsControlHelpLow"), fWidth, App.g_kSTMenu3NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pType		= App.TGParagraph_CreateW(pDatabase.GetString("WeaponsControlHelpType"), fWidth, App.g_kSTMenu3NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pHigh1)
	pMainText.AppendStringW(pDatabase.GetString("WeaponsControlHelp1B"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pLow1)
	pMainText.AppendStringW(pDatabase.GetString("WeaponsControlHelp1C"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pHigh)
	pMainText.AppendStringW(pDatabase.GetString("WeaponsControlHelp1D"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pLow)
	pMainText.AppendStringW(pDatabase.GetString("WeaponsControlHelp1E"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("WeaponsControlHelp1F"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pType)
	pMainText.AppendStringW(pDatabase.GetString("WeaponsControlHelp1G"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("WeaponsControlHelp1H"))
	

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("WeaponsControlHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idWeaponsControlHelpBox
	g_idWeaponsControlHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InfoBoxClosed")

################################################################################
##	SetupTractorHelpInfoBox()
##
##	Create the info box for the weapons display help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupTractorHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Destroy the old info box if it exists
	if (g_idTractorHelpBox != None):
		MissionLib.DestroyInfoBox(g_idTractorHelpBox)

	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["TractorHelpOne"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")

	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("TractorHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pOn			= App.TGParagraph_CreateW(pDatabase.GetString("TractorHelpOn"), fWidth, App.g_kMainMenuButtonColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pOn)
	pMainText.AppendStringW(pDatabase.GetString("TractorHelp1B"))
	
	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("WeaponsControlHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idTractorHelpBox
	g_idTractorHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InfoBoxClosed")

################################################################################
##	SetupDamageDisplayInfoBox()
##
##	Create the info box for the damage display help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupDamageDisplayInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	if (g_idDamageDisplayHelpBox != None):
		MissionLib.DestroyInfoBox(g_idDamageDisplayHelpBox)
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["DamageDisplay"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	# Create the formatted paragraph
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("DamageDisplayHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pDamaged	= App.TGParagraph_CreateW(pDatabase.GetString("DamageDisplayHelp1C"), fWidth, App.g_kDamageDisplayDamagedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pDisabled	= App.TGParagraph_CreateW(pDatabase.GetString("DamageDisplayHelp1E"), fWidth, App.g_kDamageDisplayDisabledColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pDestroyed	= App.TGParagraph_CreateW(pDatabase.GetString("DamageDisplayHelp1G"), fWidth, App.g_kDamageDisplayDestroyedColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("DamageDisplayHelp1B"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pDamaged)
	pMainText.AppendStringW(pDatabase.GetString("DamageDisplayHelp1D"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pDisabled)
	pMainText.AppendStringW(pDatabase.GetString("DamageDisplayHelp1F"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pDestroyed)
	pMainText.AppendStringW(pDatabase.GetString("DamageDisplayHelp1H"))

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("DamageDisplayHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_ALERT_HELP, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idDamageDisplayHelpBox
	g_idDamageDisplayHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InfoBoxClosed")

################################################################################
##	SetupManualFireHelpInfoBox()
##
##	Create the info box for the manual fire help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupManualFireHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Destroy the old info box if it exists
	if (g_idManualFireHelpBox != None):
		MissionLib.DestroyInfoBox(g_idManualFireHelpBox)

	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["ManualFire"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	pMainText		= App.TGParagraph_CreateW(pDatabase.GetString("ManualFireHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pManualFire1	= App.TGParagraph_CreateW(pDatabase.GetString("ManualFireHelp1B"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pDestroy		= App.TGParagraph_CreateW(pDatabase.GetString("AttackOrderHelp1B"), fWidth, App.g_kSTMenu1NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pDisable		= App.TGParagraph_CreateW(pDatabase.GetString("AttackOrderHelp1D"), fWidth, App.g_kSTMenu1NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pManualFire1)
	pMainText.AppendStringW(pDatabase.GetString("ManualFireHelp1C"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pDestroy)
	pMainText.AppendStringW(pDatabase.GetString("ManualFireHelp1D"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pDisable)
	pMainText.AppendStringW(pDatabase.GetString("ManualFireHelp1E"))
	
	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("ManualFireHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idManualFireHelpBox
	g_idManualFireHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InfoBoxClosed")

################################################################################
##	SetupTargetAtWillHelpInfoBox()
##
##	Create info box for Target At Will help.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupTargetAtWillHelpInfoBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# Destroy the old info box if it exists
	if (g_idTargetAtWillHelpBox != None):
		MissionLib.DestroyInfoBox(g_idTargetAtWillHelpBox)

	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["TargetAtWill"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")

	pMainText	= App.TGParagraph_Create("",fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pPreString	= App.TGParagraph_CreateW(pDatabase.GetString("TargetAtWillHelp1A"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0)
	
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pPreString)
	pMainText.AppendStringW(pDatabase.GetString("TargetAtWillHelp1B"))
	
	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("TargetAtWillHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	App.g_kLocalizationManager.Unload(pDatabase)
	global g_idTargetAtWillHelpBox
	g_idTargetAtWillHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InfoBoxClosed")

################################################################################
##	TacticalSelectTarget()
##
##	First part of Tactical Tutorial - covers selecting a target.
##
##	Args:	None
##
##	Return:	None
################################################################################
def TacticalSelectTarget():
	# Set the sequence flag
	global g_bSequenceRunning
	g_bSequenceRunning = TRUE

	# Get the UI objects we need.
	pTacCtrlWindow		= App.TacticalControlWindow_GetTacticalControlWindow()	
	pTargetMenu			= pTacCtrlWindow.GetTargetMenu()
	
	# Do our sequence and put up our box
	pSequence = App.TGSequence_Create()

	pStartCutscene			= App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, FALSE)
	pForceToBridge			= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pSetGreenAlert			= App.TGScriptAction_Create(__name__, "SetGreenAlert")
	pSetTutorialFlag		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pFelixMenuUp			= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_UP)
	pRelocateSubtitle		= App.TGScriptAction_Create(__name__, "RelocateSubtitle")
	pLockMenu				= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pReturnControl			= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pPicardTacticalBrief4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief4", "Captain", 0, g_pMissionDatabase)
	pPicardTacticalBrief5	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief5", None, 0, g_pMissionDatabase)
	pOpenHelpBox			= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idTargetListHelpBox)
	pTargetArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pTargetMenu, MissionLib.POINTER_LEFT)
	pTargetArrow2			= App.TGScriptAction_Create(__name__, "ShowArrow", pTargetMenu, MissionLib.POINTER_DL)
	pTargetArrow3			= App.TGScriptAction_Create(__name__, "ShowArrow", pTargetMenu, MissionLib.POINTER_UL)
	pPicardTacticalBrief7	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief7", None, 0, g_pMissionDatabase)
	pPicardTacticalBrief9	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief9", None, 0, g_pMissionDatabase)
	pPicardTacticalBrief7a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief7a", None, 0, g_pMissionDatabase)
	pAlertLevels			= App.TGScriptAction_Create(__name__, "TacticalAlertLevel")	

	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pSetGreenAlert)
	pSequence.AppendAction(pSetTutorialFlag)
	pSequence.AppendAction(pFelixMenuUp)
	pSequence.AppendAction(pRelocateSubtitle)
	pSequence.AppendAction(pLockMenu)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pPicardTacticalBrief4)
	pSequence.AppendAction(pPicardTacticalBrief5)
	pSequence.AppendAction(pOpenHelpBox)
	pSequence.AppendAction(pTargetArrow1)
	pSequence.AppendAction(pTargetArrow2)
	pSequence.AppendAction(pTargetArrow3)
	pSequence.AppendAction(pPicardTacticalBrief7)
	pSequence.AppendAction(pPicardTacticalBrief9)
	pSequence.AppendAction(pPicardTacticalBrief7a)
	pSequence.AppendAction(pAlertLevels)
	
	pSequence.Play()

	# Register this sequence
	App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")
	
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

################################################################################
##	SetGreenAlert()
##
##	Script action that sets the player at green alert if they are at red.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequecnce from crashing.
################################################################################
def SetGreenAlert(pTGAction):
	# Set the ships state so that we're at green alert and Felix is not attacking	
	# Send a green alert event.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
	eAlert = pPlayer.GetAlertLevel()
	
	if (eAlert == App.ShipClass.RED_ALERT):
		# We are at Red alert, so switch to Green and have Saffi
		# do her call out.
		pAlertEvent = App.TGIntEvent_Create()
		pAlertEvent.SetDestination(pPlayer)
		pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
		pAlertEvent.SetInt(pPlayer.GREEN_ALERT)
		App.g_kEventManager.AddEvent(pAlertEvent)
		
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "GreenAlert", None, 0, g_pGeneralDatabase))
		pSequence.AppendAction(App.TGSoundAction_Create("GreenAlertSound"))
		
		# Add an action that will complete the event
		# so the calling sequence continues
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pTGAction)
		pSequence.AddCompletedEvent(pEvent)
		
		pSequence.Play()
		
		return 1
		
	else:
		return 0

################################################################################
##	TacticalAlertLevel()
##
##	Script action that goes through alert levels.  Calls itself until were
##	ready for it.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def TacticalAlertLevel(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState < ALERT_LEVELS):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "TacticalAlertLevel")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Close the previous help box
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return 0
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(ET_CLOSE_TARGET_LIST_BOX)
		pEvent.SetDestination(pPlayer)
		App.g_kEventManager.AddEvent(pEvent)

		# Set our flag
		global g_bAlertLevelDone
		g_bAlertLevelDone = TRUE
		
		# Get the buttons we need
		pSaffiMenu = g_pSaffi.GetMenu()
		if (pSaffiMenu == None):
			return 0
		pRedAlert = pSaffiMenu.GetButtonW(g_pDatabase.GetString("Red Alert"))
		# Disable the "Mission Log" button
		Bridge.BridgeUtils.DisableButton(None, "XO", "Show Mission Log")
		Bridge.BridgeUtils.DisableButton(None, "XO", "Contact Starfleet")
		
		# Do our sequence for red alert
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idTargetListHelpBox)
		pHideArrows		= App.TGScriptAction_Create(__name__, "HideArrows")
		pRemoveControl	= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pClearMenuLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pFelixMenuDown	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_DOWN)
		pRelocateSubtitle2 = App.TGScriptAction_Create(__name__, "RelocateSubtitle2")
		pSaffiMenuUp	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MENU_UP)
		pLockMenu		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
		pReturnControl	= App.TGScriptAction_Create("MissionLib", "ReturnControl")
		pPicardBoost2a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise2a", None, 0, g_pMissionDatabase)
		pOpenHelpBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idAlertLevelHelpBox)
		pRedAlertArrow	= App.TGScriptAction_Create(__name__, "ShowArrow", pRedAlert, MissionLib.POINTER_LEFT)
		pPicardBoost3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise3", None, 0, g_pMissionDatabase)
		pPicardBoost4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise4", None, 0, g_pMissionDatabase)
		pPicardBoost4a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise4a", None, 0, g_pMissionDatabase)
		pPicardBoost4b	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise4b", None, 0, g_pMissionDatabase)
		pReticule		= App.TGScriptAction_Create(__name__, "TacticalReticule")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pClearMenuLock)
		pSequence.AppendAction(pRelocateSubtitle2)
		pSequence.AppendAction(pFelixMenuDown)
		pSequence.AppendAction(pSaffiMenuUp, 0.25)
		pSequence.AppendAction(pLockMenu)
		pSequence.AppendAction(pReturnControl)
		pSequence.AppendAction(pPicardBoost2a)
		pSequence.AppendAction(pOpenHelpBox)
		pSequence.AppendAction(pRedAlertArrow)
		pSequence.AppendAction(pPicardBoost3)
		pSequence.AppendAction(pPicardBoost4)
		pSequence.AppendAction(pPicardBoost4a)
		pSequence.AppendAction(pPicardBoost4b)
		pSequence.AppendAction(pReticule)
		
		pSequence.Play()

		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")
		
		return 0

################################################################################
##	TacticalReticule()
##
##	Sequence that takes explians the targeting reticule to the player.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def TacticalReticule(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Get the player and his alert level.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
	eAlert = pPlayer.GetAlertLevel()
	
	if (g_iTacticalTutorialState != TARGET_RETICULE) or (eAlert != App.ShipClass.RED_ALERT):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "TacticalReticule")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Do our sequence for red alert
		pSequence = App.TGSequence_Create()

		pHideArrows			= App.TGScriptAction_Create(__name__, "HideArrows")
		pHideAlertBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idAlertLevelHelpBox)
		pRemoveControl		= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pClearMenuLock		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pSaffiMenuDown		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_MENU_DOWN)
		pEnableLog			= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "XO", "Show Mission Log")
		pEnableContact		= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "XO", "Contact Starfleet")
		pFelixMenuUp		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_UP)
		pRelocateSubtitle 	= App.TGScriptAction_Create(__name__, "RelocateSubtitle")
		pLockMenu			= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
		pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
		pOpenHelpBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idReticuleHelpBox)
		pPicardReticule1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2Reticule1", None, 0, g_pMissionDatabase)
		pPicardReticule2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2Reticule2", None, 0, g_pMissionDatabase)
		pPicardReticule3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2Reticule3", None, 0, g_pMissionDatabase)
		pPicardReticule4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2Reticule4", None, 0, g_pMissionDatabase)
		pTacticalOrders		= App.TGScriptAction_Create(__name__, "TacticalOrders")
		
		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pHideAlertBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pClearMenuLock)
		pSequence.AppendAction(pSaffiMenuDown)
		pSequence.AppendAction(pEnableLog)
		pSequence.AppendAction(pEnableContact)
		pSequence.AppendAction(pFelixMenuUp, 0.25)
		pSequence.AppendAction(pRelocateSubtitle)
		pSequence.AppendAction(pLockMenu)
		pSequence.AppendAction(pReturnControl)
		pSequence.AppendAction(pOpenHelpBox)
		pSequence.AppendAction(pPicardReticule1)
		pSequence.AppendAction(pPicardReticule2)
		pSequence.AppendAction(pPicardReticule3)
		pSequence.AppendAction(pPicardReticule4)
		pSequence.AppendAction(pTacticalOrders)
	
		pSequence.Play()
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")

		return 0
		
################################################################################
##	TacticalOrders()
##
##	Sequence that explains Felix's orders to the player.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def TacticalOrders(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState != FELIX_ORDERS):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "TacticalOrders")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Close the previous help box
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return 0
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(ET_CLOSE_HELP_BOX)
		pEvent.SetDestination(pPlayer)
		App.g_kEventManager.AddEvent(pEvent)

		# Activate input for Felix's order buttons.
		Bridge.TacticalMenuHandlers.g_pOrdersStatusUI.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
		Bridge.TacticalMenuHandlers.g_pOrdersStatusUI.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")
		Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
		Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")
		Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
		Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")

		# Make the orders buttons look enabled.
		lPanes = [Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane, Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane, Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane]

		for pPane in lPanes:
			for i in range(pPane.GetNumChildren()):
				pButton = App.STButton_Cast(pPane.GetNthChild(i))
				if (pButton != None):
					pButton.SetUseUIHeight(1)
					pButton.SetNormalColor(App.g_kSTMenu1NormalBase)
					pButton.SetColorBasedOnFlags()
		
		# Disable the "Disable" button again
		pButton = App.STButton_Cast(Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetNthChild(1))
		if (pButton != None):
			pButton.SetUseUIHeight(0)
			pButton.SetNormalColor(App.g_kSTMenu1Disabled)
			pButton.SetColorBasedOnFlags()
			pButton.AddPythonFuncHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
			pButton.AddPythonFuncHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")
			
		# Get the destroy button
		pDestroyButton = App.STButton_Cast(Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetNthChild(0))
		pDestroyButton.SetEnabled()

		# Do our sequence for Felix's attack orders
		pSequence = App.TGSequence_Create()

		pHideArrows		= App.TGScriptAction_Create(__name__, "HideArrows")
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idAttackOrdersHelpBox)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pDestroyButton, MissionLib.POINTER_UP)
		pPicardOrders1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2FelixOrders1", None, 0, g_pMissionDatabase)
		pPicardAdvise2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2FelixAdvise1", None, 0, g_pMissionDatabase)
		pWeaponsDisplay	= App.TGScriptAction_Create(__name__, "WeaponsDisplay")

		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardOrders1)
		pSequence.AppendAction(pPicardAdvise2)
		pSequence.AppendAction(pWeaponsDisplay)
		
		pSequence.Play()
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")

		return 0
		
################################################################################
##	WeaponsDisplay()
##
##	Sequence that explains the weapons display to the player.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def WeaponsDisplay(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState != WEAPONS_DISPLAY) or (g_bDestroyOrderGiven == FALSE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "WeaponsDisplay")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Get the buttons we need
		pTacCtrlWindow		= App.TacticalControlWindow_GetTacticalControlWindow()	
		pWeaponsDisplay		= pTacCtrlWindow.GetWeaponsDisplay()
		
		# Do our sequence for the weapons display
		pSequence = App.TGSequence_Create()

		pHideArrows		= App.TGScriptAction_Create(__name__, "HideArrows")
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idWeaponsDisplayHelpBox)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pWeaponsDisplay, MissionLib.POINTER_DR)
		pArrow2			= App.TGScriptAction_Create(__name__, "ShowArrow", pWeaponsDisplay, MissionLib.POINTER_DOWN)
		pPicardBrief13b	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief13b", None, 0, g_pMissionDatabase)
		pPicardBrief14	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief14", None, 0, g_pMissionDatabase)
		pPicardBrief14a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief14a", None, 0, g_pMissionDatabase)
		pPicardBrief14b	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief14b", None, 0, g_pMissionDatabase)
		pWeaponsContol	= App.TGScriptAction_Create(__name__, "WeaponsContolPanel")
		
		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pArrow2)
		pSequence.AppendAction(pPicardBrief13b)
		pSequence.AppendAction(pPicardBrief14)
		pSequence.AppendAction(pPicardBrief14a)
		pSequence.AppendAction(pPicardBrief14b)
		pSequence.AppendAction(pWeaponsContol)

		pSequence.Play()
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")

		return 0
		
################################################################################
##	WeaponsContolPanel()
##
##	Sequence that explains the weapons control panel to the player.  Called as
##	script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def WeaponsContolPanel(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState != WEAPONS_CONTROL):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "WeaponsContolPanel")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Get the UI objects we need
		pTacCtrlWindow	= App.TacticalControlWindow_GetTacticalControlWindow()	
		pWeaponsCtrl	= pTacCtrlWindow.GetWeaponsControl()
		
		# Do our sequence for the weapons control panel
		pSequence = App.TGSequence_Create()
		
		pHideArrows		= App.TGScriptAction_Create(__name__, "HideArrows")
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idWeaponsControlHelpBox)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pWeaponsCtrl, MissionLib.POINTER_DR)
		pArrow2			= App.TGScriptAction_Create(__name__, "ShowArrow", pWeaponsCtrl, MissionLib.POINTER_DOWN)
		pArrow3			= App.TGScriptAction_Create(__name__, "ShowArrow", pWeaponsCtrl, MissionLib.POINTER_DL)
		pPicardBrief12a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief12a", None, 0, g_pMissionDatabase)
		pPicardBrief13	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief13", None, 0, g_pMissionDatabase)
		pTractorControl	= App.TGScriptAction_Create(__name__, "TractorControl")
		
		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pArrow2)
		pSequence.AppendAction(pArrow3)
		pSequence.AppendAction(pPicardBrief12a)
		pSequence.AppendAction(pPicardBrief13)
		pSequence.AppendAction(pTractorControl)
		
		pSequence.Play()
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")

		return 0

################################################################################
##	TractorControl()
##
##	Sequence that explains tractor control in Weapons Control Panel.  Called as
##	script action.
##
##	Args:	pTGAction	- The script action.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def TractorControl(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState != TRACTOR_CONTROL):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "TractorControl")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Get the buttons that we need
		pPanel			= App.TacWeaponsCtrl_GetTacWeaponsCtrl()
		pTractorToggle	= pPanel.GetBeamToggle()

		# Do our sequence for the weapons control panel
		pSequence = App.TGSequence_Create()
		
		pHideArrows		= App.TGScriptAction_Create(__name__, "HideArrows")
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idTractorHelpBox)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pTractorToggle, MissionLib.POINTER_LEFT)
		pPicardBrief13a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief13a", None, 0, g_pMissionDatabase)
		pDamageDisplay	= App.TGScriptAction_Create(__name__, "DamageDisplay")
		
		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardBrief13a)
		pSequence.AppendAction(pDamageDisplay)

		pSequence.Play()
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")

		return 0

################################################################################
##	DamageDisplay()
##
##	Sequence that explains the Shield and Damage display.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def DamageDisplay(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState != DAMAGE_DISPLAY):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "DamageDisplay")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Get the windows that we need
		pTacCtrlWindow		= App.TacticalControlWindow_GetTacticalControlWindow()	
		pShipDisplay		= pTacCtrlWindow.GetShipDisplay()
		pEnemyShipDisplay	= pTacCtrlWindow.GetEnemyShipDisplay()
		pRadar 				= pTacCtrlWindow.GetRadarDisplay()

		# Make sure the displays are not minimized, and if we're in 640x480,
		# Minimize the radar
		if (g_sResolutionSetting == "640x480"):
			pRadar.SetMinimized(1)
			# Refresh the display
			Tactical.Interface.TacticalControlWindow.Refresh()
			
		pEnemyShipDisplay.SetNotMinimized(0)
		pShipDisplay.SetNotMinimized(0)
		# Refresh the display
		Tactical.Interface.TacticalControlWindow.Refresh()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()

		pHideArrows		= App.TGScriptAction_Create(__name__, "HideArrows")
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idDamageDisplayHelpBox)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pShipDisplay, MissionLib.POINTER_DOWN)
		pArrow2			= App.TGScriptAction_Create(__name__, "ShowArrow", pEnemyShipDisplay, MissionLib.POINTER_LEFT)
		pPicardBrief10a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief10", None, 0, g_pMissionDatabase)
		pPicardBrief10b	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief10b", None, 0, g_pMissionDatabase)
		pManualFire		= App.TGScriptAction_Create(__name__, "ManualFire")

		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pArrow2)
		pSequence.AppendAction(pPicardBrief10a)
		pSequence.AppendAction(pPicardBrief10b)
		pSequence.AppendAction(pManualFire)
		
		pSequence.Play()
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")

		return 0

################################################################################
##	ManualFire()
##
##	Sequence that explains Felix's manual fire option.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ManualFire(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState != MANUAL_FIRE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ManualFire")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Check and set our flag
		if (g_bManualFirePlayed == FALSE):
			global g_bManualFirePlayed
			g_bManualFirePlayed = TRUE
		else:
			return 0
			
		# Get the buttons that we need
		pFelixMenu = g_pFelix.GetMenu()
		if (pFelixMenu == None):
			return 0
		pManualFire = pFelixMenu.GetButtonW(g_pDatabase.GetString("Manual Aim"))
					
		# Do our sequence for the weapons control panel
		pSequence = App.TGSequence_Create()

		pHideArrows		= App.TGScriptAction_Create(__name__, "HideArrows")
		pShowInfoBox 	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idManualFireHelpBox)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pManualFire, MissionLib.POINTER_LEFT)
		pPicardFire1 	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2FireAdvise1", None, 0, g_pMissionDatabase)
		pTargetAtWill	= App.TGScriptAction_Create(__name__, "TargetAtWill")

		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardFire1)
		pSequence.AppendAction(pTargetAtWill)

		pSequence.Play()
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")

		return 0

################################################################################
##	TargetAtWill()
##
##	Sequence that explains Felix's "Target At Will" button.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def TargetAtWill(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState != TARGET_AT_WILL):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "TargetAtWill")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Get the buttons we need
		pFelixMenu = g_pFelix.GetMenu()
		if (pFelixMenu == None):
			return 0
		pTargetAtWill = pFelixMenu.GetButtonW(g_pDatabase.GetString("Target At Will"))
		# Do our sequence.
		pSequence = App.TGSequence_Create()
		
		pHideArrows		= App.TGScriptAction_Create(__name__, "HideArrows")
		pShowInfoBox 	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idTargetAtWillHelpBox)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pTargetAtWill, MissionLib.POINTER_LEFT)
		pPicardFelix2a	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2FelixAdvise2a", None, 0, g_pMissionDatabase)
		pPicardFelix2b	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2FelixAdvise2b", None, 0, g_pMissionDatabase)
		pCleanUp		= App.TGScriptAction_Create(__name__, "CleanUp")

		pSequence.AppendAction(pHideArrows)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardFelix2a)
		pSequence.AppendAction(pPicardFelix2b)
		pSequence.AppendAction(pCleanUp)
		
		pSequence.Play()
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")

		return 0
		
################################################################################
##	CleanUp()
##
##	Cleans up all the tutorial stuff and gets us back to normal running.  Called
##	as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTacticalTutorialState != CLEAN_UP):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "CleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide all our arrows
		HideArrows()
		
		# Do our sequence to clean eveything up
		pSequence = App.TGSequence_Create()
		
		pRemoveControl		= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pSetLockFlag		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pFelixMenuDown		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_DOWN)
		pRelocateSubtitle2	= App.TGScriptAction_Create(__name__, "RelocateSubtitle2")
		pPicardLook			= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_LOOK_AT_ME)
		pSetTutorialFlag	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pPicardTactical15	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief15", "Captain", 0, g_pMissionDatabase)
		pPicardTactical16	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TacticalBrief16", None, 1, g_pMissionDatabase)
		pResetVolume		= App.TGScriptAction_Create("MissionLib", "SetSpeakingVolume", App.CSP_SPONTANEOUS, 1)
		pSetSequenceFlag	= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetLockFlag)
		pSequence.AppendAction(pRelocateSubtitle2)
		pSequence.AppendAction(pFelixMenuDown)
		pSequence.AppendAction(pSetTutorialFlag)
		pSequence.AppendAction(pPicardLook)
		pSequence.AddAction(pEndCutscene, pPicardLook)
		pSequence.AddAction(pPicardTactical15, pPicardLook)
		pSequence.AppendAction(pPicardTactical16)
		pSequence.AppendAction(pResetVolume)
		pSequence.AppendAction(pSetSequenceFlag)
		
		pSequence.Play()
		
		# Set our flag back to 0
		global g_iTacticalTutorialState
		g_iTacticalTutorialState = DEFAULT
		
		# Register this sequence
		App.TGActionManager_RegisterAction(pSequence, "TacticalTutorial")
		
		# Re-enable the disable button
		pButton = App.STButton_Cast(Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetNthChild(1))
		if (pButton != None):
			pButton.SetUseUIHeight(0)
			pButton.SetNormalColor(App.g_kSTMenu1NormalBase)
			pButton.SetColorBasedOnFlags()
			pButton.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
			pButton.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")

		return 0
		
################################################################################
##	ExplainOrbit()
##
##	Handler for button in Picards menu that plays tutorial sequence for
##	orbiting a planet.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainOrbit(TGObject, pEvent):
	# Make sure the sensors are on
	TurnOnSensors()

	# Get the buttons that we'll need
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu == None):
		return 0
		
	# Get the Maelstrom TGL
	pMaelstromDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Maelstrom.TGL")
	pOrbitMenu = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Orbit Planet"))
	if (pOrbitMenu != None):
		pHavenButton = pOrbitMenu.GetButtonW(pMaelstromDatabase.GetString("Haven"))
	# Unload database
	App.g_kLocalizationManager.Unload(pMaelstromDatabase)
	
	# Set our flags
	global g_bSequenceRunning
	global g_bInOrbitTutorial
	global g_iTutorialCounter
	g_bSequenceRunning	= TRUE
	g_bInOrbitTutorial	= TRUE
	g_iTutorialCounter	= 1
		
	# Create the event that will let us know when the Orbit menu is opened.
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pKiskaMenu)
	pEvent.SetEventType(ET_ORBIT_MENU_OPEN)
	pOrbitMenu.SetActivationEvent(pEvent)	

	# Do our tutorial cutscene
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pStartCutscene	= App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, FALSE)
	pForceToBridge	= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pKiskaMenuUp	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_UP)
	pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pReturnControl	= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pOrbitMenu, MissionLib.POINTER_UR_CORNER)
	pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idOrbitInfoBox1)
	pPicardOrbit1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2OrbitAdvise1", None, 0, g_pMissionDatabase)
	pOrbitTwo		= App.TGScriptAction_Create(__name__, "ExplainOrbitTwo")
	
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pKiskaMenuUp)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardOrbit1)
	pSequence.AppendAction(pOrbitTwo)

	pSequence.Play()

################################################################################
##	ExplainOrbitTwo()
##
##	Second part of Orbit tutorial.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to calling sequence from crashing.
################################################################################
def ExplainOrbitTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 2):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainOrbitTwo")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Get the buttons that we'll need
		pKiskaMenu = g_pKiska.GetMenu()
		if (pKiskaMenu == None):
			return 0
		
		# Get the Maelstrom TGL
		pMaelstromDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Maelstrom.TGL")
		pOrbitMenu = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Orbit Planet"))
		if (pOrbitMenu != None):
			pHavenButton = pOrbitMenu.GetButtonW(pMaelstromDatabase.GetString("Haven"))
		# Unload database
		App.g_kLocalizationManager.Unload(pMaelstromDatabase)
		
		# Hide the arrows
		HideArrows()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()

		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idOrbitInfoBox1)
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idOrbitInfoBox2)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pHavenButton, MissionLib.POINTER_LEFT)
		pPicardOrbit2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2OrbitAdvise2", None, 0, g_pMissionDatabase)
		pPicardOrbit3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2OrbitAdvise3", None, 0, g_pMissionDatabase)
		pPicardOrbit4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2OrbitAdvise4", None, 0, g_pMissionDatabase)
		pCleanUp		= App.TGScriptAction_Create(__name__, "ExplainOrbitCleanUp")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardOrbit2)
		pSequence.AppendAction(pPicardOrbit3)
		pSequence.AppendAction(pPicardOrbit4)
		pSequence.AppendAction(pCleanUp)
		
		pSequence.Play()
		
		return 0

################################################################################
##	ExplainOrbitCleanUp()
##
##	Last part of Orbit tutorial that cleans everything up.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainOrbitCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 3):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainOrbitCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Clear our tutorial counter
		global g_bInOrbitTutorial
		global 	g_iTutorialCounter
		g_bInOrbitTutorial	= FALSE
		g_iTutorialCounter	= 0
		
		# Hide our arrows
		HideArrows()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idOrbitInfoBox2)
		pRemoveControl	= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
		pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pKiskaMenuDown	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_DOWN)
		pEndCutscene	= App.TGScriptAction_Create("MissionLib", "EndCutscene")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pClearFlag)
		pSequence.AppendAction(pSetCharLock)
		pSequence.AppendAction(pSetTutorial)
		pSequence.AppendAction(pKiskaMenuDown)
		pSequence.AppendAction(pEndCutscene)
		
		pSequence.Play()
		
		return 0

################################################################################
##	SetupOrbitInfoBoxes()
##
##	Create the info boxes used in the Orbit tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupOrbitInfoBoxes():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	for idBox in [ g_idOrbitInfoBox1, g_idOrbitInfoBox2 ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["OrbitHelp"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	# Box Number 1
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("OrbitHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pOrbit		= App.TGParagraph_CreateW(pDatabase.GetString("OrbitHelpOrbit"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pOrbit)
	pMainText.AppendStringW(pDatabase.GetString("OrbitHelp1B"))
	
	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("OrbitHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idOrbitInfoBox1
	g_idOrbitInfoBox1 = pBox.GetObjID()	

	# Box Number 2
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("OrbitHelp2A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pOrbit		= App.TGParagraph_CreateW(pDatabase.GetString("OrbitHelpOrbit"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pOrbit)
	pMainText.AppendStringW(pDatabase.GetString("OrbitHelp2B"))
	
	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("OrbitHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idOrbitInfoBox2
	g_idOrbitInfoBox2 = pBox.GetObjID()	

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	OrbitMenuOpened()
##
##	Handler called when the Orbit menu is opened.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def OrbitMenuOpened(TGObject, pEvent):
	# If we're in the orbit tutorial, increase our counter
	if (g_bInOrbitTutorial == TRUE):
		if (g_iTutorialCounter == 1):
			global g_iTutorialCounter
			g_iTutorialCounter = 2
			
	# All done, call the next handler
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
	pString		= pWarpButton.GetDestination()
	if (pString == None):
		return
	
	# Don't let the player leave until they've finished the mission
	if (g_bSuppliesTransfered == FALSE):
		# Do the line from Saffi
		pSaffiLine1 = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E1M2PlayerLeaves3", "Captain", 0, g_pMissionDatabase)
		pSaffiLine1.Play()
		return
		
	# Call the next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ExplainHail()
##
##	Handler for button in Picards menu that plays tutorial sequence for
##	hailing.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainHail(TGObject, pEvent):	
	# Set our flags
	global g_bSequenceRunning
	global g_iTutorialCounter
	g_bSequenceRunning	= TRUE
	g_iTutorialCounter	= 1
	
	# Get the buttons that we'll need
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu == None):
		return 0
	pHailMenu = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Hail"))

	# Create the event that will let us know when the Hail menu is opened.
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pKiskaMenu)
	pEvent.SetEventType(ET_HAIL_MENU_OPEN)
	pHailMenu.SetActivationEvent(pEvent)	

	# Clear the warp heading and disable the Set Course menu
	pWarpButton = App.SortedRegionMenu_GetWarpButton()
	pWarpButton.SetDestination(None)
	Bridge.BridgeUtils.DisableButton(None, "Helm", "Set Course")

	# Do the tutorial cutscene
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pStartCutscene	= App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, FALSE)
	pForceToBridge	= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pKiskaMenuUp	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_UP)
	pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pReturnControl	= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idHailInfoBox1)
	pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pHailMenu, MissionLib.POINTER_UR_CORNER)
	pPicardHail1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2HailAdvise4", None, 0, g_pMissionDatabase)
	pHailTwo		= App.TGScriptAction_Create(__name__, "ExplainHailTwo")

	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pKiskaMenuUp)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardHail1)
	pSequence.AppendAction(pHailTwo)
	
	pSequence.Play()

################################################################################
##	ExplainHailTwo()
##
##	Second part of the Hailing tutorial.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainHailTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 2):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainHailTwo")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Get the buttons that we'll need
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Maelstrom.tgl")
		pKiskaMenu = g_pKiska.GetMenu()
		if (pKiskaMenu == None):
			return 0
		pHailMenu = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Hail"))
		if (pHailMenu != None):
			pHavenButton = pHailMenu.GetButtonW(pDatabase.GetString("Haven"))
		App.g_kLocalizationManager.Unload(pDatabase)

		HideArrows()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idHailInfoBox1)
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idHailInfoBox2)
		pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pHavenButton, MissionLib.POINTER_LEFT)
		pPicardHail4	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2HailAdvise1", None, 0, g_pMissionDatabase)
		pCleanUp		= App.TGScriptAction_Create(__name__, "ExplainHailCleanUp")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardHail4)
		pSequence.AppendAction(pCleanUp)

		pSequence.Play()
		
		return 0
		
################################################################################
##	ExplainHailCleanUp()
##
##	Last part of Hailing tutorial that clean up. Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainHailCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 3):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainHailCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Clear our tutorial counter
		global 	g_iTutorialCounter
		g_iTutorialCounter	= 0
	
		HideArrows()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idHailInfoBox2)
		pRemoveControl		= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pSetCharLock		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pSetTutorial		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pKiskaMenuDown		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_DOWN)
		pEnableSetCourse	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableButton", "Helm", "Set Course")
		pEndCutscene		= App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pClearFlag			= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetCharLock)
		pSequence.AppendAction(pSetTutorial)
		pSequence.AppendAction(pKiskaMenuDown)
		pSequence.AppendAction(pEnableSetCourse)
		pSequence.AppendAction(pEndCutscene)
		pSequence.AppendAction(pClearFlag)
		
		pSequence.Play()
		
		return 0

################################################################################
##	SetupHailInfoBoxes()
##
##	Create the info boxes that we need for the Hailing tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupHailInfoBoxes():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	for idBox in [ g_idHailInfoBox1, g_idHailInfoBox2 ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["HailHelp"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("HailingHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pHail1		= App.TGParagraph_CreateW(pDatabase.GetString("HailingHelpHail"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pHail2		= App.TGParagraph_CreateW(pDatabase.GetString("HailingHelpHail"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pHail1)
	pMainText.AppendStringW(pDatabase.GetString("HailingHelp1B"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pHail2)
	pMainText.AppendStringW(pDatabase.GetString("HailingHelp1C"))
		
	# Box Number 1
	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("HailingHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idHailInfoBox1
	g_idHailInfoBox1 = pBox.GetObjID()	

	# Box Number 2
	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("HailingHelpTitle"), 
				pDatabase.GetString("HailingHelp2A"),
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idHailInfoBox2
	g_idHailInfoBox2 = pBox.GetObjID()	

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	HailMenuOpened()
##
##	Handler called when the hail menu is opened.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def HailMenuOpened(TGObject, pEvent):
	# If we're in the tutorial, increase our counter
	if (g_iTutorialCounter == 1):
		global g_iTutorialCounter
		g_iTutorialCounter = 2
		
	# All done, call our next handler
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ExplainScan()
##
##	Handler for button in Picards menu that plays tutorial sequence for scanning.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainScan(TGObject, pEvent):
	# Make sure the sensors are on
	TurnOnSensors()

	# Get the buttons that we'll need
	pMiguelMenu = g_pMiguel.GetMenu()
	if (pMiguelMenu == None):
		return 0
	pScanAreaButton	= pMiguelMenu.GetButtonW(g_pDatabase.GetString("Scan Area"))

	# Set our flags
	global g_bSequenceRunning
	global g_iTutorialCounter
	g_bSequenceRunning	= TRUE
	g_iTutorialCounter	= 1
	
	# Do the sequence
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pStartCutscene	= App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, FALSE)
	pForceToBridge	= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pMiguelMenuUp	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_MENU_UP)
	pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pReturnControl	= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idScanInfoBox1)
	pArrow1			= App.TGScriptAction_Create(__name__, "ShowArrow", pScanAreaButton, MissionLib.POINTER_LEFT)
	pPicardScan1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2ScanAdvise1", None, 0, g_pMissionDatabase)
	pPicardScan2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2ScanAdvise2", None, 0, g_pMissionDatabase)
	pPicardScan3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2ScanAdvise3", None, 0, g_pMissionDatabase)
	pCleanUp		= App.TGScriptAction_Create(__name__, "ExplainScanCleanUp")
	
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pMiguelMenuUp)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardScan1)
	pSequence.AppendAction(pPicardScan2)
	pSequence.AppendAction(pPicardScan3)
	pSequence.AppendAction(pCleanUp)

	pSequence.Play()

################################################################################
##	ExplainScanCleanUp()
##
##	Last part of Scan tutorial that cleans everything up.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainScanCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 2):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainScanCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Clear our tutorial counter
		global 	g_iTutorialCounter
		g_iTutorialCounter	= 0

		# Hide the arrows
		HideArrows()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idScanInfoBox1)
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")
		pRemoveControl	= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pMiguelMenuDown	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_MENU_DOWN)	
		pEndCutscene	= App.TGScriptAction_Create("MissionLib", "EndCutscene")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pClearFlag)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetCharLock)
		pSequence.AppendAction(pSetTutorial)
		pSequence.AppendAction(pMiguelMenuDown)
		pSequence.AppendAction(pEndCutscene)
		
		pSequence.Play()

		return 0
	
################################################################################
##	SetupScanInfoBoxes()
##
##	Create the info boxes used in the Scanning tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupScanInfoBoxes():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	for idBox in [ g_idScanInfoBox1 ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["ScanHelp"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	# Create the formatted paragraph
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("ScanHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pArea1		= App.TGParagraph_CreateW(pDatabase.GetString("ScanHelp1B"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pArea2		= App.TGParagraph_CreateW(pDatabase.GetString("ScanHelp1B"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pTarget		= App.TGParagraph_CreateW(pDatabase.GetString("ScanHelp1D"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pObject1	= App.TGParagraph_CreateW(pDatabase.GetString("ScanHelp1F"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pObject2	= App.TGParagraph_CreateW(pDatabase.GetString("ScanHelp1F"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pObject3	= App.TGParagraph_CreateW(pDatabase.GetString("ScanHelp1F"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pArea1)
	pMainText.AppendStringW(pDatabase.GetString("ScanHelp1C"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pTarget)
	pMainText.AppendStringW(pDatabase.GetString("ScanHelp1E"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pObject1)
	pMainText.AppendStringW(pDatabase.GetString("ScanHelp1G"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pObject2)
	pMainText.AppendStringW(pDatabase.GetString("ScanHelp1H"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pObject3)
	pMainText.AppendStringW(pDatabase.GetString("ScanHelp1I"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("ScanHelp1J"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pArea2)
	pMainText.AppendStringW(pDatabase.GetString("ScanHelp1K"))
	

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("ScanHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
	
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idScanInfoBox1
	g_idScanInfoBox1 = pBox.GetObjID()	

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	ExplainIntercept()
##
##	Handler for button in Picards menu that plays tutorial sequence for
##	intercepting a target.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainIntercept(TGObject, pEvent):
	# Make sure the sensors are on
	TurnOnSensors()

	# Get the buttons we'll need for the sequence.
	pTacCtrlWindow		= App.TacticalControlWindow_GetTacticalControlWindow()
	pTargetMenu			= pTacCtrlWindow.GetTargetMenu()

	# Set our flags
	global g_bSequenceRunning
	global g_iTutorialCounter
	global g_bInInterceptTutorial
	g_bSequenceRunning		= TRUE
	g_iTutorialCounter		= 1
	g_bInInterceptTutorial	= TRUE
	
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, FALSE)
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pFelixMenuUp		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_UP)
	pRelocateSubtitle 	= App.TGScriptAction_Create(__name__, "RelocateSubtitle")
	pSetCharLock		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pSetTutorial		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idInterceptInfoBox1)
	pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pTargetMenu, MissionLib.POINTER_LEFT)
	pPicardIntercept1	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2InterceptAdvise1", None, 0, g_pMissionDatabase)
	pInterceptTwo		= App.TGScriptAction_Create(__name__, "ExplainInterceptTwo")
	
	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pFelixMenuUp)
	pSequence.AppendAction(pRelocateSubtitle)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardIntercept1)
	pSequence.AppendAction(pInterceptTwo)
	
	pSequence.Play()	

################################################################################
##	ExplainInterceptTwo()
##
##	Second part of Intercept tutorial sequence.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainInterceptTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Get the player and their target.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
	pTarget = pPlayer.GetTarget()
	
	if (g_iTutorialCounter < 2) or (pTarget == None):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainInterceptTwo")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		HideArrows()
		
		# Get the buttons we need
		pKiskaMenu = g_pKiska.GetMenu()
		if (pKiskaMenu == None):
			return 0
		pInterceptButton = pKiskaMenu.GetButtonW(g_pDatabase.GetString("Intercept"))
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox		= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idInterceptInfoBox1)
		pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idInterceptInfoBox2)
		pRemoveControl		= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pUnlockChars		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pFelixMenuDown		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_DOWN)
		pRelocateSubtitle2 	= App.TGScriptAction_Create(__name__, "RelocateSubtitle2")
		pKiskaMenuUp		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_UP)
		pLockChars			= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
		pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
		pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pInterceptButton, MissionLib.POINTER_LEFT)
		pPicardIntercept2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2InterceptAdvise2", None, 0, g_pMissionDatabase)
		pPicardIntercept3	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2InterceptAdvise3", None, 0, g_pMissionDatabase)
		pCleanUp			= App.TGScriptAction_Create(__name__, "ExplainInterceptCleanUp")
		
		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pUnlockChars)
		pSequence.AppendAction(pRelocateSubtitle2)
		pSequence.AppendAction(pFelixMenuDown)
		pSequence.AppendAction(pKiskaMenuUp)
		pSequence.AppendAction(pLockChars)
		pSequence.AppendAction(pReturnControl)
		pSequence.AppendAction(pArrow1)
		pSequence.AppendAction(pPicardIntercept2)
		pSequence.AppendAction(pPicardIntercept3)
		pSequence.AppendAction(pCleanUp)

		pSequence.Play()
		
		return 0
		
################################################################################
##	ExplainInterceptCleanUp()
##
##	Last part of Intercept tutorial that cleans everything up.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainInterceptCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 3):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainInterceptCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Clear our flags
		global g_bInInterceptTutorial
		global g_iTutorialState
		g_bInInterceptTutorial	= FALSE
		g_iTutorialState		= TRUE

		HideArrows()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idInterceptInfoBox2)
		pRemoveControl	= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pKiskaMenuDown	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_MENU_DOWN)
		pEndCutscene	= App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetCharLock)
		pSequence.AppendAction(pSetTutorial)
		pSequence.AppendAction(pKiskaMenuDown)
		pSequence.AppendAction(pEndCutscene)
		pSequence.AppendAction(pClearFlag)
		
		pSequence.Play()

		return 0
			
################################################################################
##	SetupInterceptInfoBoxes()
##
##	Creates the info boxes used in the Intercept tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupInterceptInfoBoxes():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	for idBox in [ g_idInterceptInfoBox1, g_idInterceptInfoBox2 ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)
		
	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	# Box Number 1
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["InterceptOne"][g_sResolutionSetting]

	pBox = MissionLib.SetupInfoBox(pDatabase.GetString("InterceptHelpTitle"), 
				pDatabase.GetString("InterceptHelp1A"),
				fWidth, fHeight, None, None, ET_CLOSE_INTERCEPT_ONE_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idInterceptInfoBox1
	g_idInterceptInfoBox1 = pBox.GetObjID()	

	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["InterceptTwo"][g_sResolutionSetting]
	
	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".InterceptInfoBoxClosed")

	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("InterceptHelp2A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pIntercept	= App.TGParagraph_CreateW(pDatabase.GetString("InterceptHelpIntercept"), fWidth, App.g_kSTMenu2NormalBase, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pIntercept)
	pMainText.AppendStringW(pDatabase.GetString("InterceptHelp2B"))
	
	# Box Number 2
	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("InterceptHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 0)
				
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idInterceptInfoBox2
	g_idInterceptInfoBox2 = pBox.GetObjID()	

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	InterceptInfoBoxClosed()
##
##	Handler called when the first Intercept info box is closed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def InterceptInfoBoxClosed(TGObject, pEvent):
	# Increase our tutorial counter
	if (g_iTutorialCounter == 1):
		global g_iTutorialCounter
		g_iTutorialCounter = 2
		
	# All done, pass on the event
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	FindGoodTarget()
##
##	Goes through the objects in the set and finds one thats in that's visible
##	so we can get the button in our target list and return it.
##
##	Args:	pTargetMenu	- The target menu.
##
##	Return:	pTargetButton	- A named target button in the target list.
################################################################################
def FindGoodTarget(pTargetMenu):
	# Go though the list of asteroids and find one that is
	# visible in the target list.
	pSet	= App.g_kSetManager.GetSet("Vesuvi6")
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	
	# If the station has been hit, target that
	# otherwise, find a good asteroid
	if (g_bStationHit == TRUE):
		pTargetButton = pTargetMenu.GetSubmenu("Facility")
		return pTargetButton
	else:
		lAsteroidNames = g_dAsteroidInfo.keys()
		lAsteroidNames.sort()
		for sAsteroidName in lAsteroidNames:
			pAsteroid = App.ObjectClass_GetObject(pSet, sAsteroidName)
			if (pAsteroid != None):
				pSensors = pPlayer.GetSensorSubsystem()
				if (pSensors.IsObjectVisible(pAsteroid)):
					# The asteroid should be in the target list.
					# Get the button and return it.
					pTargetButton = pTargetMenu.GetSubmenu(sAsteroidName)
					# Return our button
					return pTargetButton

	# If we made it here, we couldn't find a good button,
	# so return none.
	return None

################################################################################
##	ExplainBoost()
##
##	Handler for button in Picards menu that plays tutorial sequence for boosting
##	subsystems in Brex's power menu.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainBoost(TGObject, pEvent):
	# Get the player, then systems that we can boost
	pShip 		= App.Game_GetCurrentPlayer()
	if (pShip == None):
		return
	pPhasers 	= pShip.GetPhaserSystem()
	pImpulse	= pShip.GetImpulseEngineSubsystem()
	pSensors	= pShip.GetSensorSubsystem()
	pShields	= pShip.GetShields()

	# Get the engineering menu control, then find the UI object corresponding
	# to the phasers.
	pCtrl		= App.EngPowerCtrl_GetPowerCtrl()
	pPhaserBar	= pCtrl.GetBarForSubsystem(pPhasers)
	pImpulseBar	= pCtrl.GetBarForSubsystem(pImpulse)
	pSensorsBar	= pCtrl.GetBarForSubsystem(pSensors)
	pShieldsBar	= pCtrl.GetBarForSubsystem(pShields)

	# Set our flags
	global g_bSequenceRunning
	global g_iTutorialCounter
	g_bSequenceRunning	= TRUE
	g_iTutorialCounter	= 1
		
	# Shut every one else on the bridge up
	MissionLib.SetSpeakingVolume(None, App.CSP_SPONTANEOUS, 0)

	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, FALSE)
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pBrexMenuUp			= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_MENU_UP)
	pSetCharLock		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pSetTutorial		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idBoostInfoBox1)
	pShowPhaserBar		= App.TGScriptAction_Create(__name__, "ShowArrow", pPhaserBar, MissionLib.POINTER_RIGHT)
	pShowImpulseBar		= App.TGScriptAction_Create(__name__, "ShowArrow", pImpulseBar, MissionLib.POINTER_RIGHT)
	pShowSensorBar		= App.TGScriptAction_Create(__name__, "ShowArrow", pSensorsBar, MissionLib.POINTER_RIGHT)
	pShowShieldsBar		= App.TGScriptAction_Create(__name__, "ShowArrow", pShieldsBar, MissionLib.POINTER_RIGHT)
	pFreezeFrags		= App.TGScriptAction_Create(__name__, "FreezeAsteroids")
	pPicardBoost1		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise1", None, 0, g_pMissionDatabase)
	pBoostTwo			= App.TGScriptAction_Create(__name__, "ExplainBoostTwo")

	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pBrexMenuUp)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pShowPhaserBar)
	pSequence.AppendAction(pShowImpulseBar)
	pSequence.AppendAction(pShowSensorBar)
	pSequence.AppendAction(pShowShieldsBar)
	pSequence.AppendAction(pFreezeFrags)
	pSequence.AppendAction(pPicardBoost1)
	pSequence.AppendAction(pBoostTwo)

	pSequence.Play()

################################################################################
##	ExplainBoostTwo()
##
##	Second part of the boosting tutorial.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainBoostTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 2):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainBoostTwo")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idBoostInfoBox2)
		pPicardBoost2	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise2", None, 0, g_pMissionDatabase)
		pBoostThree		= App.TGScriptAction_Create(__name__, "ExplainBoostThree")

		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pPicardBoost2)
		pSequence.AppendAction(pBoostThree)

		pSequence.Play()
		
		return 0
		
################################################################################
##	ExplainBoostThree()
##
##	Third part of the boosting tutorial.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainBoostThree(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 3):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainBoostThree")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Get the power bar at the top and the battery display
		pPowerDisplay	= App.EngPowerDisplay_Cast(App.TGObject_GetTGObjectPtr(Bridge.PowerDisplay.g_idPowerDisplay))
		if (pPowerDisplay != None):
			pPowerUsedBar	= pPowerDisplay.GetNthChild(Bridge.PowerDisplay.POWER_USED_BAR)
			pMainGauge		= pPowerDisplay.GetNthChild(Bridge.PowerDisplay.MAIN_GAUGE_PANE)

		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHidePointers	= App.TGScriptAction_Create(__name__, "HideArrows")
		pShowMainArrow	= App.TGScriptAction_Create(__name__, "ShowArrow", pMainGauge, MissionLib.POINTER_UP)
		pShowInfoBox	= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idBoostInfoBox3)
		pPicardBoost5	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise5", None, 0, g_pMissionDatabase)
		pPicardBoost6	= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2BoostAdvise6", None, 0, g_pMissionDatabase)
		pCleanUp		= App.TGScriptAction_Create(__name__, "ExplainBoostCleanUp")

		pSequence.AppendAction(pHidePointers)
		pSequence.AppendAction(pShowMainArrow)
		pSequence.AppendAction(pShowInfoBox)
		pSequence.AppendAction(pPicardBoost5)
		pSequence.AppendAction(pPicardBoost6)
		pSequence.AppendAction(pCleanUp)

		pSequence.Play()
		
		return 0
		
################################################################################
##	ExplainBoostCleanUp()
##
##	Last part of boost tutorial that cleans everything up.  Called as script
##	action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainBoostCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_iTutorialCounter < 4):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainBoostCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Clear our flags
		global g_iTutorialCounter
		g_iTutorialCounter	= 0
		
		# Hide all our arrows
		HideArrows()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idBoostInfoBox3)
		pRemoveControl	= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pBrexMenuDown	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_MENU_DOWN)
		pResetVolume	= App.TGScriptAction_Create("MissionLib", "SetSpeakingVolume", App.CSP_SPONTANEOUS, 1)
		pUnFreezeFrags	= App.TGScriptAction_Create(__name__, "UnFreezeAsteroids")
		pEndCutscene	= App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetCharLock)
		pSequence.AppendAction(pSetTutorial)
		pSequence.AppendAction(pBrexMenuDown)
		pSequence.AppendAction(pResetVolume)
		pSequence.AppendAction(pClearFlag)
		pSequence.AppendAction(pUnFreezeFrags)
		pSequence.AppendAction(pEndCutscene)
		
		pSequence.Play()

		return 0

################################################################################
##	SetupBoostInfoBoxes()
##
##	Create the info boxes we'll use for the boosting tutorial.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupBoostInfoBoxes():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	for idBox in [ g_idBoostInfoBox1, g_idBoostInfoBox2, g_idBoostInfoBox3 ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)
		
	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["BoostingHelp"][g_sResolutionSetting]

	# Get our database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	# Box 1
	# Create the formatted paragraph
	pMainText		= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pWeapons		= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp1B"), fWidth, App.g_kEngineeringWeaponsColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pEngines		= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp1D"), fWidth, App.g_kEngineeringEnginesColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pSensor			= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp1F"), fWidth, App.g_kEngineeringSensorsColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pShield			= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp1H"), fWidth, App.g_kEngineeringShieldsColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_RETURN)

	# Do not add this return if we are in German
	pString = pDatabase.GetString("Language")	
	# We are using German Version
	if (pString.GetCString() == "English"):		
		pMainText.AppendChar(App.WC_RETURN)

	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pWeapons)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp1C"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pEngines)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp1E"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pSensor)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp1G"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pShield)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp1I"))
	pMainText.AppendChar(App.WC_RETURN)

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("BoostHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))
	
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idBoostInfoBox1
	g_idBoostInfoBox1 = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".BoostInfoBoxClosed")

	### Box 2
	# Create the formatted paragraph
	pMainText	= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp2A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("BoostHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1, pDatabase.GetString("Continue"))

	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idBoostInfoBox2
	g_idBoostInfoBox2 = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".BoostInfoBoxClosed")

	### Box 3
	
	# Create the formatted paragraph
	pMainText		= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp3A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pWarpCore1		= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp3B"), fWidth, App.g_kEngineeringWarpCoreColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pMainBattery	= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp3D"), fWidth, App.g_kEngineeringMainPowerColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pReserveBattery	= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp3F"), fWidth, App.g_kEngineeringBackupPowerColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	pWarpCore2		= App.TGParagraph_CreateW(pDatabase.GetString("BoostHelp3I"), fWidth, App.g_kEngineeringWarpCoreColor, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pWarpCore1)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp3C"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pMainBattery)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp3E"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pReserveBattery)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp3G"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp3H"))
	pMainText.AppendChar(App.WC_CURSOR)
	pMainText.AddChild(pWarpCore2)
	pMainText.AppendStringW(pDatabase.GetString("BoostHelp3J"))

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("BoostHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1)
	
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idBoostInfoBox3
	g_idBoostInfoBox3 = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".BoostInfoBoxClosed")

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	BoostInfoBoxClosed()
##
##	Handler called when one of the info boxes is closed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def BoostInfoBoxClosed(TGObject, pEvent):
	# If a box closes, increase our counter.
	global g_iTutorialCounter
	g_iTutorialCounter = g_iTutorialCounter + 1
	
	# All done, call our next handler
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ExplainTractor()
##
##	Handler for button in Picards menu that plays tutorial sequence for using
##	the tractor beam.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ExplainTractor(TGObject, pEvent):
	# Make sure the sensors are on
	TurnOnSensors()

	# Set our sequence flag
	global g_bSequenceRunning
	global g_bTractorTutorialDone
	g_bSequenceRunning		= TRUE
	g_bTractorTutorialDone	= FALSE
		
	# Get the buttons that we need
	pTacCtrlWindow		= App.TacticalControlWindow_GetTacticalControlWindow()
	pTargetMenu			= pTacCtrlWindow.GetTargetMenu()
		
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPicardMenuDown		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_MENU_DOWN)
	pStartCutscene		= App.TGScriptAction_Create("MissionLib", "StartCutscene", 1.0, 0.125, FALSE)
	pForceToBridge		= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pFelixMenuUp		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_UP)
	pRelocateSubtitle 	= App.TGScriptAction_Create(__name__, "RelocateSubtitle")
	pSetCharLock		= App.TGScriptAction_Create(__name__, "SetCharWindowLock", TRUE)
	pSetTutorial		= App.TGScriptAction_Create(__name__, "SetTutorialFlag", TRUE)
	pReturnControl		= App.TGScriptAction_Create("MissionLib", "ReturnControl")
	pShowInfoBox		= App.TGScriptAction_Create("MissionLib", "ShowInfoBox", g_idSecondTractorHelpBox)
	pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pTargetMenu, MissionLib.POINTER_LEFT)
	pPicardTractor1		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TractorAdvise1", None, 0, g_pMissionDatabase)
	pTractorTwo			= App.TGScriptAction_Create(__name__, "ExplainTractorTwo")

	pSequence.AppendAction(pPicardMenuDown)
	pSequence.AppendAction(pStartCutscene)
	pSequence.AppendAction(pForceToBridge)
	pSequence.AppendAction(pFelixMenuUp)
	pSequence.AppendAction(pRelocateSubtitle)
	pSequence.AppendAction(pSetCharLock)
	pSequence.AppendAction(pSetTutorial)
	pSequence.AppendAction(pReturnControl)
	pSequence.AppendAction(pShowInfoBox)
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pPicardTractor1)
	pSequence.AppendAction(pTractorTwo)

	pSequence.Play()

################################################################################
##	ExplainTractorTwo()
##
##	Second part of tractor tutorial.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainTractorTwo(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Get the buttons we need
	pPanel				= App.TacWeaponsCtrl_GetTacWeaponsCtrl()
	pTractorToggle		= pPanel.GetBeamToggle()
	
	pSequence = App.TGSequence_Create()
	
	pArrow1				= App.TGScriptAction_Create(__name__, "ShowArrow", pTractorToggle, MissionLib.POINTER_LEFT)
	pArrow2				= App.TGScriptAction_Create(__name__, "ShowArrow", pTractorToggle, MissionLib.POINTER_RIGHT)
	pPicardTractor2		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TractorAdvise2", None, 0, g_pMissionDatabase)
	pPicardTractor3		= App.CharacterAction_Create(g_pPicard, App.CharacterAction.AT_SAY_LINE, "E1M2TractorAdvise3", None, 0, g_pMissionDatabase)
	pCleanUp			= App.TGScriptAction_Create(__name__, "ExplainTractorCleanUp")
	
	pSequence.AppendAction(pArrow1)
	pSequence.AppendAction(pArrow2)
	pSequence.AppendAction(pPicardTractor2)
	pSequence.AppendAction(pPicardTractor3)
	pSequence.AppendAction(pCleanUp)
	
	pSequence.Play()
	
	return 0

################################################################################
##	ExplainTractorCleanUp()
##
##	Cleans up the stuff from the tractor tutorial.  Called as script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ExplainTractorCleanUp(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	if (g_bTractorTutorialDone == FALSE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "ExplainTractorCleanUp")
		pSequence.AppendAction(pWaitLoop, 1)
		pSequence.Play()
		
		return 0
	
	else:
		# Hide all our arrows
		HideArrows()
		
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pHideInfoBox	= App.TGScriptAction_Create("MissionLib", "HideInfoBox", g_idSecondTractorHelpBox)
		pRemoveControl	= App.TGScriptAction_Create("MissionLib", "RemoveControl")
		pSetCharLock	= App.TGScriptAction_Create(__name__, "SetCharWindowLock", FALSE)
		pSetTutorial	= App.TGScriptAction_Create(__name__, "SetTutorialFlag", FALSE)
		pFelixMenuDown	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_MENU_DOWN)
		pRelocateSubtitle2 	= App.TGScriptAction_Create(__name__, "RelocateSubtitle2")
		pEndCutscene	= App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pClearFlag		= App.TGScriptAction_Create(__name__, "SetSequenceRunning")

		pSequence.AppendAction(pHideInfoBox)
		pSequence.AppendAction(pRemoveControl)
		pSequence.AppendAction(pSetCharLock)
		pSequence.AppendAction(pSetTutorial)
		pSequence.AppendAction(pRelocateSubtitle2)
		pSequence.AppendAction(pFelixMenuDown)
		pSequence.AppendAction(pClearFlag)
		pSequence.AppendAction(pEndCutscene)
		
		pSequence.Play()

		return 0

################################################################################
##	SetupSecondTractorHelpBox()
##
##	Create the second tractor beam help box.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupSecondTractorHelpBox():
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return

	# Destroy the old info box if it exists
	for idBox in [ g_idSecondTractorHelpBox ]:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)

	# Get the position and size of the box based on resolution
	fLeft, fTop, fWidth, fHeight = g_dInfoBoxSpecs["SecondTractor"][g_sResolutionSetting]

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 1/E1M2HelpText.tgl")
	
	# Create the formatted paragraph
	pMainText		= App.TGParagraph_CreateW(pDatabase.GetString("TractorBeamHelp1A"), fWidth, App.NiColorA_WHITE, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)
	
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("TractorBeamHelp1B"))
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendChar(App.WC_RETURN)
	pMainText.AppendStringW(pDatabase.GetString("TractorBeamHelp1C"))

	pBox = MissionLib.SetupInfoBoxFromParagraph(pDatabase.GetString("TractorBeamHelpTitle"), pMainText,
				fWidth, fHeight, None, None, ET_CLOSE_HELP_BOX, pPlayer, 1)
	
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pTacticalControlWindow.AddChild(pBox, fLeft, fTop)
	global g_idSecondTractorHelpBox
	g_idSecondTractorHelpBox = pBox.GetObjID()	

	# Attach an instance handler to the box so we can know when it closes
	pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".TractorHelpBoxClosed")

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

################################################################################
##	TractorHelpBoxClosed()
##
##	Handler called when the tractor help box is closed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def TractorHelpBoxClosed(TGObject, pEvent):
	# Set our flag
	global g_bTractorTutorialDone
	g_bTractorTutorialDone = TRUE
	
	# All done, pass the event on
	TGObject.CallNextHandler(pEvent)

################################################################################
##	TurnOnSensors()
##
##	Turns on the players sensors if they have been turned off or lowered.
##
##	Args:	None
##
##	Return:	None
################################################################################
def TurnOnSensors():
	# Set the level on the sensors to 100% if the player has shut them off
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pSensors = pPlayer.GetSensorSubsystem()
	if (pSensors == None):
		return
	fPercent = pSensors.GetNormalPowerPercentage()
	# If the are off or set below 100%, set them at that level
	if (not pSensors.IsOn()) or (fPercent < 1.0):
		pSensors.TurnOn()
		pSensors.SetPowerPercentageWanted(1.0)
		
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
##	FreezeAsteroids()
##
##	Script action that saves the velocities of the asteroids and then sets them
##	to zero.  Used with Picards tutorial sequences.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def FreezeAsteroids(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Set our flag
	global g_bFragsFrozen
	g_bFragsFrozen = TRUE
	
	global g_dObjectVelocity
	
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Vesuvi6")
	# Go thorough the dictonary of asteroids, add the station,
	# get and save their velocity in a global dictonary.
	lObjectList = g_dAsteroidInfo.keys()
	lObjectList.append("Facility")
	
	for sObjectName in lObjectList:
		# Get the object
		pObject = App.ShipClass_GetObject(pSet, sObjectName)
		if (pObject != None):
			# Get the velocity
			kVelocity = pObject.GetVelocityTG()
			# Save the velocity of the asteroid in a dictonary and
			# use the object name as the key
			g_dObjectVelocity[sObjectName] = kVelocity
			# Set the velocity of the asteroid to zero
			kZero = App.TGPoint3()
			kZero.SetXYZ(0.0, 0.0, 0.0)
			pObject.SetVelocity(kZero)

	return 0
	
################################################################################
##	UnFreezeAsteroids()
##
##	Script action that restores the velocities of the asteroids that were
##	set to 0 by FreezeAsteroids().
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Retur 0 to keep calling sequence from crashing.
################################################################################
def UnFreezeAsteroids(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0

	# Set our flag
	global g_bFragsFrozen
	g_bFragsFrozen = FALSE

	global g_dObjectVelocity
	
	# Get the set
	pSet = App.g_kSetManager.GetSet("Vesuvi6")
	# Go through our dictonary, get the objects and
	# restore them to the velocity saved
	for sObjectName in g_dObjectVelocity.keys():
		# Get the object
		pObject = App.ShipClass_GetObject(pSet, sObjectName)
		# Set the velocity if the object exists
		if (pObject != None):
			pObject.SetVelocity(g_dObjectVelocity[sObjectName])
			
	# Clear the dictonary
	g_dObjectVelocity = {}
	
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
	# Hide any arrows that might be around
	HideArrows()
	
	# Delete all our mission goals
	MissionLib.DeleteAllGoals()

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()
	
	# Mark our flag
	global g_bMissionTerminate
	g_bMissionTerminate = 0
	
	# Destroy all the info boxes
	lBoxIds = GetBoxIDList()
	for idBox in lBoxIds:
		if (idBox != None):
			MissionLib.DestroyInfoBox(idBox)

	# Destroy all of Picards buttons
	DestroyPicardButtons()
	
	# Remove all our instance handlers
	RemoveInstanceHandlers()
	
	# unload the database: "data/TGL/Bridge Crew General.tgl"
	global g_pGeneralDatabase
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# unload the database: "data/TGL/Bridge Menus.tgl"
	global g_pDatabase
	if(g_pDatabase):
		App.g_kLocalizationManager.Unload(g_pDatabase)

################################################################################
##	DestroyPicardButtons()
##
##	Destroy all of Picard's buttons in his menu.
##
##	Args:	None
##
##	Return:	None
################################################################################
def DestroyPicardButtons():
	# Get Picard and his menu
	pPicard		= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicardMenu	= pPicard.GetMenu()
		if (pPicardMenu != None):
			# Delete the buttons
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Hailing")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Orbiting")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Scanning")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Tactical")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("TacticalOrders")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Targeting")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Intercepting")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Tractor Beam")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("Boosting")))
			pPicardMenu.DeleteChild(pPicardMenu.GetButtonW(g_pMissionDatabase.GetString("AlertLevels")))

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
	# Remove the Haven orbit handler
	pSet	= App.g_kSetManager.GetSet("Vesuvi6")
	pPlanet = App.Planet_GetObject(pSet, "Haven")
	if (pPlanet != None):
		pPlanet.RemoveHandlerForInstance(App.ET_AI_ORBITTING, __name__ + ".OrbitingHaven")
	
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".FriendlyFireReportHandler")
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".FriendlyFireGameOverHandler")

	# Hander for player's ship changing targets
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.RemoveHandlerForInstance(App.ET_TARGET_WAS_CHANGED,	__name__+".TargetChanged")

	# Handler for the in and out of tactical event
	pTopWindow = App.TopWindow_GetTopWindow()
	if (pTopWindow != None):
		pTopWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_BRIDGE_AND_TACTICAL, __name__ + ".TacticalToggleHandler")
		# Handler for toggling to map mode
		pTacticalWindow = pTopWindow.FindMainWindow(App.MWT_BRIDGE)
		if (pTacticalWindow != None):
			pTacticalWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_MAP_MODE,			__name__ + ".MapToggleHandler")
			pTacticalWindow.RemoveHandlerForInstance(App.ET_INPUT_TOGGLE_CINEMATIC_MODE,	__name__ + ".MapToggleHandler")

	# Instance handlers on Picard
	pPicard = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Picard")
	if (pPicard != None):
		pPicard.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		
	# Instance handler on Saffi's alert level change
	pSaffi = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	if (pSaffi != None):
		pSaffi.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pSaffiMenu = pSaffi.GetMenu()
		if (pSaffiMenu != None):
			pSaffiMenu.RemoveHandlerForInstance(App.ET_SET_ALERT_LEVEL,	__name__ + ".SetAlertLevelHandler")
			pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,		__name__ + ".CommunicateHandler")

	# Instance handler for Miguel's Scan Area button
	pMiguel = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Science")
	if (pMiguel!= None):
		pMiguel.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pMiguelMenu = pMiguel.GetMenu()
		if (pMiguelMenu != None):
			pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN,			__name__ + ".ScanHandler")
			pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Instance handlers on Kiska's menu
	pKiska = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")
	if (pKiska != None):
		pKiska.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pKiskaMenu = pKiska.GetMenu()
		if (pKiskaMenu != None):
			pKiskaMenu.RemoveHandlerForInstance(App.ET_SET_COURSE,	__name__ + ".SetCourseHandler")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL,		__name__ + ".HailHandler")
			pKiskaMenu.RemoveHandlerForInstance(ET_HAIL_MENU_OPEN,	__name__ + ".HailMenuOpened")
			pKiskaMenu.RemoveHandlerForInstance(ET_ORBIT_MENU_OPEN,	__name__ + ".OrbitMenuOpened")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			# Instance handler for Kiska's orbit button
			pOrbit = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Orbit Planet"))
			if (pOrbit != None):
				pOrbit.RemoveHandlerForInstance(App.ET_ORBIT_PLANET, __name__ + ".OrbitHandler")	
			# Remove instance handler on Warp button event
			pWarpButton = Bridge.BridgeUtils.GetWarpButton()
			if (pWarpButton != None):
				pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")

	# Instance handler for Felix's Maneuvers
	pFelix = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if (pFelix != None):
		pFelix.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pFelixMenu = pFelix.GetMenu()
		if (pFelixMenu != None):
			pFelixMenu.RemoveHandlerForInstance(App.ET_MANEUVER,	__name__ + ".ManeuverHandler")
			pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")

	# Remove the instance handler for the communicate buttons
	pBrex = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
	if (pBrex != None):
		pBrex.RemoveHandlerForInstance(App.ET_CHARACTER_MENU,	__name__ + ".HandleMenuEvent")
		pBrexMenu = pBrex.GetMenu()
		if (pBrexMenu != None):
			pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
			
	# Make sure these have been removed
	# Activate input for Felix's order buttons.
	if (Bridge.TacticalMenuHandlers.g_pOrdersStatusUI != None):
		Bridge.TacticalMenuHandlers.g_pOrdersStatusUI.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
		Bridge.TacticalMenuHandlers.g_pOrdersStatusUI.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")
	if (Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane != None):
		Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
		Bridge.TacticalMenuHandlers.g_pTacticsStatusUIPane.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")
	if (Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane != None):
		Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
		Bridge.TacticalMenuHandlers.g_pManeuversStatusUIPane.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")

	pButton = App.STButton_Cast(Bridge.TacticalMenuHandlers.g_pOrdersStatusUIPane.GetNthChild(1))
	if (pButton != None):
		pButton.RemoveHandlerForInstance(App.ET_MOUSE, __name__ + ".IgnoreInput")
		pButton.RemoveHandlerForInstance(App.ET_KEYBOARD, __name__ + ".IgnoreInput")
