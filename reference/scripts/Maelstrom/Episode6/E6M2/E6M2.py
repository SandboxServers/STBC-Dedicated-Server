###############################################################################
#	Filename:	E6M2.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Episode 6, Mission 2
#
#	Created:	12/12/00 -	Jess VanDerwalker
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Episode6.Episode6
import Bridge.BridgeUtils

# For debug output
#kDebugObj = App.CPyDebug()
#kDebugObj.Print('Loading Episode 6 Mission 2 definition...\n')


# Global variables
TRUE	= 1
FALSE	= 0

g_bMissionTerminate	= FALSE

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None
g_pDatabase			= None

g_iProdTimer			= 0
g_sProdLine				= None
g_iCapturedGeblePods	= 0

g_bPlayerArriveGeble3		= None
g_bPlayerArriveGeble4		= None
g_bPlayerArriveSerris3		= None
g_bSerris3SensorsOff		= None
g_bPlayerArriveSerris1		= None

g_bHeadingToStarbase12		= None
g_bPlayerArriveStarbase12	= None

g_bWarningGiven		= None
g_bCombat1Called	= None
g_bCombat2Called	= None

g_bNightArriveGeble3	= None
g_bNightArriveSerris1	= None

g_bFirstGalorCreated	= None
g_bSecondGalorCreated	= None
g_bThirdGalorCreated	= None

g_bGebleDialogPlayed	= None
g_bAdamsScanned			= None
g_bAllGeblePodsCaptured	= None
g_bGeblePodDestroyed	= None
g_bPlayerDockedPod		= None
g_iNumberOfNightPods	= None

g_iTimeWithShieldsDown	= 0
g_bDauntlessCleared		= None

g_bNightTakingDamageCalled	= None
g_bNightUnderFire2Called	= None
g_bNightUnderFireCalled		= None

g_bNightDestroyed		= None
g_bGalor1Destroyed		= None
g_bKeldon2Destroyed		= None
g_bGalor1Replaced		= None

g_pGeblePodTargets		= None
g_pGalorGebleTargets	= None
g_pGalor1SerrisTargets	= None
g_pGalor2SerrisTargets	= None

g_fLastCheckTime		= None

g_lsGeblePodNames	= []

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None

# Event types for mission
ET_PROD_TIMER				= App.Mission_GetNextEventType()
ET_FIRST_GALOR_TIMER		= App.Mission_GetNextEventType()
ET_SECOND_GALOR_TIMER		= App.Mission_GetNextEventType()
ET_DAUNTLESS_CLEAR_TIMER	= App.Mission_GetNextEventType()
ET_GALORS_ENTER_SERRIS		= App.Mission_GetNextEventType()

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
	loadspacehelper.PreloadShip("Peregrine", 1)
	loadspacehelper.PreloadShip("Nebula", 1)
	loadspacehelper.PreloadShip("Galaxy", 3)
	loadspacehelper.PreloadShip("Galor", 4)
	loadspacehelper.PreloadShip("Keldon", 1)
	loadspacehelper.PreloadShip("EscapePod", 6)
	loadspacehelper.PreloadShip("Transport", 1)

################################################################################
##	Initialize()
##
##  Called to initialize mission when it first loads.
##
##	Args: 	pMission	- The mission object
##
##	Return: None
################################################################################
def Initialize(pMission):
	"Event handler called on episode start.  Create the episode objects here."
#	kDebugObj.Print ("Initializing Episode 6, Mission 2.\n")
	
	# Initialize all our global variables
	InitializeGlobals(pMission)
	
	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("SovereignBridge")

	# Create the regions that we'll need
	# We'll also do our placement stuff from inside this function
	CreateRegions()
	
	#set the diffucultly level - easy Offense, Defense, med O, D, Hard O, D
	App.Game_SetDifficultyMultipliers(1.15, 1.0, 0.8, 0.8, 0.6, 0.7)

	# Create needed viewscreen sets
	pLBridgeSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu		= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)

	# Since Jadeja is used most (and he has a Nebula) we replace the texture right off and have Yi replace it
	# back to the Galaxy the one time he shows up.
	pDBridgeSet	= MissionLib.SetupBridgeSet("DBridgeSet", "data/Models/Sets/DBridge/DBridge.nif", -30, 65, -1.55)
	MissionLib.ReplaceBridgeTexture(None, "DBridgeSet", "Map 7.tga", "data/Models/Sets/DBridge/NebulaLCARS.tga")
	pJadeja		= MissionLib.SetupCharacter("Bridge.Characters.Jadeja", "DBridgeSet")
	pYi			= MissionLib.SetupCharacter("Bridge.Characters.Yi", "DBridgeSet")

	# Import all the ships we'll be using and place them
	CreateStartingObjects(pMission)
	
	# Recreate the ships that survived in E6M1
	RecreateSurvivingShips()
	
	# Initialize global pointer to all the 5 bridge crew members
	InitializeCrewPointers()

	# Create menus available at mission start
	CreateStartingMenus()
	
	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()
	
	# Setup more mission-specific events.
	SetupEventHandlers()
	
	# Remove the HeadToHome goal if it's carried over from E6M1
	MissionLib.RemoveGoal("E6HeadHomeGoal")

	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)

	# Call liu's briefing
	LiuBriefing(None)
	
	# Save the Game
	MissionLib.SaveGame("E6M2-")

################################################################################
##	InitializeGlobals()
##
##	Initialize our global variables to their starting defaults.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def InitializeGlobals(pMission):
#	kDebugObj.Print("Initializing global variables")
	
	# Global used with bools
	global TRUE
	global FALSE
	TRUE	= 1
	FALSE	= 0

	# Set the Mission terminate flag
	global g_bMissionTerminate
	g_bMissionTerminate = FALSE

	# Globals for the TGL databases
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 6/E6M2.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Global timer ID for prodding
	global g_iProdTimer
	g_iProdTimer	= 0
	global g_sProdLine
	g_sProdLine		= "E6M2Prod2"
	
	# Globals for number of captured escape pods
	global g_iCapturedGeblePods
	g_iCapturedGeblePods	= 0

	# Global flags for tracking player
	global g_bPlayerArriveGeble3
	global g_bPlayerArriveGeble4
	global g_bPlayerArriveSerris3
	global g_bSerris3SensorsOff
	global g_bPlayerArriveSerris1
	global g_bHeadingToStarbase12
	global g_bPlayerArriveStarbase12
	g_bPlayerArriveGeble3		= FALSE
	g_bPlayerArriveGeble4		= FALSE
	g_bPlayerArriveSerris3		= FALSE
	g_bSerris3SensorsOff		= FALSE
	g_bPlayerArriveSerris1		= FALSE
	g_bHeadingToStarbase12		= FALSE
	g_bPlayerArriveStarbase12	= FALSE

	# globals that deal with firing on friendly ships
	global g_bWarningGiven
	global g_bCombat1Called
	global g_bCombat2Called
	g_bWarningGiven		= FALSE
	g_bCombat1Called	= FALSE
	g_bCombat2Called	= FALSE

	# Global flags for tracking Nightingale
	global g_bNightArriveGeble3
	global g_bNightArriveSerris1
	g_bNightArriveGeble3	= FALSE
	g_bNightArriveSerris1	= FALSE

	# Global flags for mission events
	global g_bFirstGalorCreated
	global g_bSecondGalorCreated
	global g_bThirdGalorCreated
	global g_bGebleDialogPlayed
	global g_bAdamsScanned
	global g_bAllGeblePodsCaptured
	global g_bGeblePodDestroyed
	global g_bPlayerDockedPod
	global g_iNumberOfNightPods
	global g_bNightDestroyed
	global g_bGalor1Destroyed
	global g_bKeldon2Destroyed
	global g_bGalor1Replaced

	g_bFirstGalorCreated	= FALSE
	g_bSecondGalorCreated	= FALSE
	g_bThirdGalorCreated	= FALSE
	g_bGebleDialogPlayed	= FALSE
	g_bAdamsScanned			= FALSE
	g_bAllGeblePodsCaptured	= FALSE
	g_bGeblePodDestroyed	= FALSE
	g_bPlayerDockedPod		= FALSE
	g_iNumberOfNightPods	= 0
	g_bNightDestroyed		= FALSE
	g_bGalor1Destroyed		= FALSE
	g_bKeldon2Destroyed		= FALSE
	g_bGalor1Replaced		= FALSE
	
	# Counter used to track amount of time Nightingale
	# has it's shields down around the Dauntless
	global g_iTimeWithShieldsDown
	global g_bDauntlessCleared
	g_iTimeWithShieldsDown 	= 0
	g_bDauntlessCleared		= FALSE
	
	# Flags used to check if sequences have played
	global g_bNightTakingDamageCalled
	global g_bNightUnderFire2Called
	global g_bNightUnderFireCalled
	g_bNightTakingDamageCalled	= FALSE
	g_bNightUnderFire2Called	= FALSE
	g_bNightUnderFireCalled		= FALSE
	
	# Global pointers to target groups used in AI
	global g_pGeblePodTargets
	global g_pGalorGebleTargets
	global g_pGalor1SerrisTargets
	global g_pGalor2SerrisTargets
	g_pGeblePodTargets		= None
	g_pGalorGebleTargets	= None
	g_pGalor1SerrisTargets	= None
	g_pGalor2SerrisTargets	= None
	
	# Global lists of ship names
	global g_lFriendlyShips
	
	g_lFriendlyShips	= 	[
							"Starbase 12", "Nightingale", "Dauntless", "Escape Pod 1", "Escape Pod 2", "Escape Pod 3", "Escape Pod 4", "Escape Pod 5", "Escape Pod 6"
							]
	
	global g_fLastCheckTime
	g_fLastCheckTime		= 0
	
	# List of pod and target names
	global g_lsGeblePodNames
	for iCounter in range(1, 7):
		g_lsGeblePodNames.append("Escape Pod " + str(iCounter))
		
	# Set our limits for the friendly fire warnings and game loss
	App.g_kUtopiaModule.SetMaxFriendlyFire(3000)			# how many damage points the player can do total before losing
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(800)	# how many damage points before Saffi warns you

################################################################################
##	InitializeCrewPointers()
##
##	Initializes the global pointers to the bridge crew members and thier menus as well
##	NOTE: This must be called after the bridge is loaded.
##
##	Args:	None
##
##	Return:	None
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

	g_pKiska	= App.CharacterClass_GetObject(pBridge, "Helm")
	g_pFelix	= App.CharacterClass_GetObject(pBridge, "Tactical")
	g_pSaffi	= App.CharacterClass_GetObject(pBridge, "XO")
	g_pMiguel	= App.CharacterClass_GetObject(pBridge, "Science")
	g_pBrex		= App.CharacterClass_GetObject(pBridge, "Engineer")
	
################################################################################
##	CreateRegions()
##
##	Create all the regions that we will be using in this mission.  Also load
## 	our mission specific placements.
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
	#Geble4 system
	import Systems.Geble.Geble4
	Systems.Geble.Geble4.Initialize()
	pGeble4Set = Systems.Geble.Geble4.GetSet()
	# Geble3 system
	import Systems.Geble.Geble3
	Systems.Geble.Geble3.Initialize()
	pGeble3Set = Systems.Geble.Geble3.GetSet()
	# Serris3 system
	import Systems.Serris.Serris3
	Systems.Serris.Serris3.Initialize()
	pSerris3Set = Systems.Serris.Serris3.GetSet()
	# Serris1 system
	import Systems.Serris.Serris1
	Systems.Serris.Serris1.Initialize()
	pSerris1Set = Systems.Serris.Serris1.GetSet()
	# Deep space
	import Systems.DeepSpace.DeepSpace
	Systems.DeepSpace.DeepSpace.Initialize()
	pDeepSpace = Systems.DeepSpace.DeepSpace.GetSet()

	# Get the Bridge for the cutscene
	pBridge = App.g_kSetManager.GetSet("bridge")

	# Load our mission specific placements
	import E6M2_Starbase_P
	import E6M2_Geble4_P
	import E6M2_Geble3_P
	import E6M2_Serris3_P
	import E6M2_Serris1_P
	import E6M2_DeepSpace_P
	import E6M2_EBridge_P
	
	
	E6M2_Starbase_P.LoadPlacements(pStarbaseSet.GetName())
	E6M2_Geble4_P.LoadPlacements(pGeble4Set.GetName())
	E6M2_Geble3_P.LoadPlacements(pGeble3Set.GetName())
	E6M2_Serris3_P.LoadPlacements(pSerris3Set.GetName())
	E6M2_Serris1_P.LoadPlacements(pSerris1Set.GetName())
	E6M2_DeepSpace_P.LoadPlacements(pDeepSpace.GetName())
	E6M2_EBridge_P.LoadPlacements(pBridge.GetName())

################################################################################
##	CreateStartingMenus()
##
##  Creates menus for systems in "Helm", 
##
##	Args:	None
##
##	Return: None
################################################################################
def CreateStartingMenus():
	import Systems.Starbase12.Starbase

	Systems.Starbase12.Starbase.CreateMenus()

	
	# pull out the systems from e6m1 out so the user doesn't go there too soon.
	pKiskaMenu = g_pKiska.GetMenu()
	pSetCourse = pKiskaMenu.GetSubmenuW(g_pDatabase.GetString("Set Course"))
		
	pOna = pSetCourse.GetSubmenu("Ona")
	pSetCourse.DeleteChild(pOna)
	pArtrus = pSetCourse.GetSubmenu("Artrus")
	pSetCourse.DeleteChild(pArtrus)
	pSavoy = pSetCourse.GetSubmenu("Savoy")
	pSetCourse.DeleteChild(pSavoy)

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
	# Make pod tractorable
	pTractorList = pMission.GetTractorGroup()
	for sName in g_lsGeblePodNames:
		pTractorList.AddName(sName)
		
	# Setup object affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Devore")
	pFriendlies.AddName("Inverness")
	pFriendlies.AddName("Shannon")
	pFriendlies.AddName("Cambridge")
	pFriendlies.AddName("Venture")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("San Francisco")
	pFriendlies.AddName("Dauntless")
	pFriendlies.AddName("Nightingale")

	# Add the pods to the Friendly list
	for sName in g_lsGeblePodNames:
		pFriendlies.AddName(sName)
		
	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Galor 1")
	pEnemies.AddName("Galor 2")
	pEnemies.AddName("Galor 3")
	pEnemies.AddName("Keldon 1")

	# Get the sets we need
	pStarbaseSet = App.g_kSetManager.GetSet("Starbase12")
	pGeble4Set = App.g_kSetManager.GetSet("Geble4")
	pGeble3Set = App.g_kSetManager.GetSet("Geble3")
	
	# Place the players ship
	pPlayer = MissionLib.CreatePlayerShip("Sovereign", pStarbaseSet, "player", "Player Start")
	
	# Place the other starting objects and ships
	pStarbase12 = loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	pNight		= loadspacehelper.CreateShip("Peregrine", pGeble4Set, "Nightingale", "NightEnter")
	pNight.ReplaceTexture("data/Models/SharedTextures/FedShips/Nightingale.tga", "ID")
	pHulk1		= loadspacehelper.CreateShip("Galaxy", pGeble3Set, "Hulk 1", "Derelict1Start")
	pHulk2		= loadspacehelper.CreateShip("Nebula", pGeble3Set, "Hulk 2", "Derelict2Start")
	pHulk3		= loadspacehelper.CreateShip("Galaxy", pGeble3Set, "Hulk 3", "Derelict3Start")
	
	pHulk1.SetHailable(0)
	pHulk2.SetHailable(0)
	pHulk3.SetHailable(0)
	
	# make the Night's engines and rear tractor invincible
	MissionLib.MakeEnginesInvincible(pNight)
	pTractor = pNight.GetTractorBeamSystem()
	if (pTractor):
		MissionLib.MakeSubsystemsInvincible(pTractor)
	
	# call a function that will damage the hulks
	DamageGebleHulks(pHulk1, pHulk2, pHulk3)
			
	# Call our function that places the escape pods
	CreateGeble3Pods() 
	
	# Create target lists
	CreateTargetLists()
	
################################################################################
##	RecreateSurvivingShips()
##
##	Recreates the ships that survived E6M1 and places them in the Starbase12 set.
##	Will not create any ships if the mission is started from scratch, since the
##	pointers at episode level are initialize to None.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RecreateSurvivingShips():
	# Get the Starbase set
	pSet	= App.g_kSetManager.GetSet("Starbase12")
	
	# Go through all our episode level pointers and recreate the
	# ones that are not None.
	
	# San Francisco
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(Maelstrom.Episode6.Episode6.g_idSanFrancisco))
	if (pShip != None):
		pSet.AddObjectToSet(pShip, pShip.GetName())

		pShip.PlaceObjectByName("SFStart")
		# clear out your global!!!
		Maelstrom.Episode6.Episode6.g_idSanFrancisco = App.NULL_ID

	# Devore
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(Maelstrom.Episode6.Episode6.g_idDevore))
	if (pShip != None):
		pSet.AddObjectToSet(pShip, pShip.GetName())

		pShip.PlaceObjectByName("DevoreStart")
		# clear out your global!!!
		Maelstrom.Episode6.Episode6.g_idDevore = App.NULL_ID

	# Venture
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(Maelstrom.Episode6.Episode6.g_idVenture))
	if (pShip != None):
		pSet.AddObjectToSet(pShip, pShip.GetName())

		pShip.PlaceObjectByName("VentureStart")
		# clear out your global!!!
		Maelstrom.Episode6.Episode6.g_idVenture = App.NULL_ID

	# Shannon
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(Maelstrom.Episode6.Episode6.g_idShannon))
	if (pShip != None):
		pSet.AddObjectToSet(pShip, pShip.GetName())

		pShip.PlaceObjectByName("ShannonStart")
		# clear out your global!!!
		Maelstrom.Episode6.Episode6.g_idShannon = App.NULL_ID

	# Inverness
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(Maelstrom.Episode6.Episode6.g_idInverness))
	if (pShip != None):
		pSet.AddObjectToSet(pShip, pShip.GetName())

		pShip.PlaceObjectByName("InvernessStart")
		# clear out your global!!!
		Maelstrom.Episode6.Episode6.g_idInverness = App.NULL_ID

	# Cambridge
	pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(Maelstrom.Episode6.Episode6.g_idCambridge))
	if (pShip != None):
		pSet.AddObjectToSet(pShip, pShip.GetName())

		pShip.PlaceObjectByName("CambridgeStart")
		# clear out your global!!!
		Maelstrom.Episode6.Episode6.g_idCambridge = App.NULL_ID
	
################################################################################
##	DamageGebleHulks(pHulk1, pHulk2, pHulk3)
##
##	This fuction will damage the hulks in Geble, and set them spinning
##
##	Args:	pHulk1, pHulk2, pHulk3
##
##	Return:	
################################################################################
def DamageGebleHulks(pHulk1, pHulk2, pHulk3):
	
	# Import our damaged script ship and apply it to the Hulk1
	import Hulk1Damaged
	Hulk1Damaged.AddDamage(pHulk1)
	
	# Turn off the ships repair
	pRepair = pHulk1.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)

	# Damage the Hulk1...
	# Turn off the shields
	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(pHulk1)
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(pHulk1.GREEN_ALERT)

	App.g_kEventManager.AddEvent(pAlertEvent)

	# Damage the hull - 500 pts left
	pHulk1.DamageSystem(pHulk1.GetHull(), 5000)
	
	# Dont allow the user to see the sub-systems
	MissionLib.HideSubsystems(pHulk1)
	
	# Spin the hulk
	MissionLib.SetRandomRotation(pHulk1, 7)
	
	# Import our damaged script ship and apply it to the Hulk2
	import Hulk2Damaged
	Hulk2Damaged.AddDamage(pHulk2)

	# Turn off the ships repair
	pRepair = pHulk2.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)

	# Damage the Hulk2...
	# Turn off the shields
	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(pHulk2)
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(pHulk2.GREEN_ALERT)

	App.g_kEventManager.AddEvent(pAlertEvent)

	# Damage the hull - 500 pts left
	pHulk2.DamageSystem(pHulk2.GetHull(), 3000)
	
	# Dont allow the user to see the sub-systems
	MissionLib.HideSubsystems(pHulk2)
	
	# Spin the hulk
	MissionLib.SetRandomRotation(pHulk2, 10)
		
	# Import our damaged script ship and apply it to the Hulk3
	import Hulk3Damaged
	Hulk3Damaged.AddDamage(pHulk3)

	# Turn off the ships repair
	pRepair = pHulk3.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)

	# Damage the Hulk3...
	# Turn off the shields
	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(pHulk3)
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(pHulk3.GREEN_ALERT)

	App.g_kEventManager.AddEvent(pAlertEvent)

	# Damage the hull - 500 pts left
	pHulk3.DamageSystem(pHulk3.GetHull(), 4500)
	
	# Dont allow the user to see the sub-systems
	MissionLib.HideSubsystems(pHulk3)
	
	# Spin the hulk
	MissionLib.SetRandomRotation(pHulk3, 15)

	
################################################################################
##	CreateTargetLists()
##
##	Creates the global target lists to be used by the AI ships.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateTargetLists():
	# Create the list of escape pods in Geble3
	global g_pGeblePodTargets
	g_pGeblePodTargets = App.ObjectGroup()
	# Add all the pods to the group
	for iCounter in range(1, 7):
		g_pGeblePodTargets.AddName("Escape Pod " + str(iCounter))
		
	# Get the players ship name.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	sPlayerName = pPlayer.GetName()
	
	# Create the target lists for the Galors
	global g_pGalorGebleTargets
	global g_pGalor1SerrisTargets
	global g_pGalor2SerrisTargets
	
	# Geble target list
	g_pGalorGebleTargets = App.ObjectGroupWithInfo()
	g_pGalorGebleTargets["Nightingale"]	= {"Priority" : 0.8}
	g_pGalorGebleTargets[sPlayerName]	= {"Priority" : 0.0}
	
	# Target list for Galor 1 in Serris
	g_pGalor1SerrisTargets = App.ObjectGroupWithInfo()
	g_pGalor1SerrisTargets["Nightingale"]	= {"Priority" : 0.2}
	g_pGalor1SerrisTargets[sPlayerName]		= {"Priority" : 0.0}
	
	# Target list for Keldon 1 in Serris
	g_pGalor2SerrisTargets = App.ObjectGroupWithInfo()
	g_pGalor2SerrisTargets["Nightingale"]	= {"Priority" : 1.1}
	g_pGalor2SerrisTargets[sPlayerName]		= {"Priority" : 0.0}
	
################################################################################
##	CreateGeble3Pods()
##
##	Creates the escape pods present in the Geble 3 system 
## 
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateGeble3Pods():
	pEpisode = App.Game_GetCurrentGame().GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()

	# Get the set
	pSet = App.g_kSetManager.GetSet("Geble3")
	# Get the "Friendly" group
	pFriendlies = pMission.GetFriendlyGroup()
	pNight = App.ShipClass_GetObject(None, "Nightingale")
	# Create the pods at their placements and add to friendly group
	for iCounter in range(1, 7):
		pProbe = loadspacehelper.CreateShip("EscapePod", pSet, ("Escape Pod " + str(iCounter)), ("Pod"+str(iCounter)+"Start"))
		pFriendlies.AddName("Escape Pod " + str(iCounter))
		# turn off collisions with probe to nightingale
		pNight.EnableCollisionsWith(pProbe, 0)
		# set the probe to not appear on the target list, we'll make them visable later
		pProbe.SetTargetable(0)
		pProbe.SetScannable(0)
		pProbe.SetHailable(0)
		
################################################################################
##	SetupEventHandlers()
##
##  Sets up event types we want to listen for and the handlers to call
##
##	Args: 	None
##
##	Return: None
################################################################################
def SetupEventHandlers():
	"Setup any event handlers to listen for broadcast events that we'll need."
	pEpisode = App.Game_GetCurrentGame().GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()

	# Object entering set event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET, pMission, __name__ +".EnterSet")
	# Object exit event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_EXITED_SET, pMission, __name__ +".ExitSet")
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__+".ObjectDestroyed")
	# Tractor beam target docked event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_TARGET_DOCKED, pMission, __name__+".TractorTargetDocked")
	# Tractor beam starts hitting event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STARTED_HITTING, pMission, __name__+".TractorBeamOn")

	# Instance handlers on the mission for friendly fire warnings and game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")
	
	# Instance handler for Kiska's Hail button
	pMenu = g_pKiska.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")

	# and her Warp button
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	
	# Instance handler on players ship for Weapon Fired event, for fire on firendlys
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")
			
	# Need to get the Helm character, so we can add our own handler for
	# the Intercept button...
	pSet	= App.g_kSetManager.GetSet("bridge")
	pKiska	= App.CharacterClass_GetObject(pSet, "Helm")
	pMenu	= pKiska.GetMenu()
	# Add the handler...
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SET_COURSE,	__name__ + ".SetCourse")
	
	# Instance handler for Miguel's Scan button
	pSet	= App.g_kSetManager.GetSet("bridge")
	pSci	= App.CharacterClass_GetObject(pSet, "Science")
	pMenu	= pSci.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	
#	kDebugObj.Print("Adding Crew Communicate Handlers")
	pBridge = App.g_kSetManager.GetSet("bridge")
	# Communicate with Saffi event
	pSaffi = App.CharacterClass_GetObject(pBridge, "XO")
	pMenu = pSaffi.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Felix event
	pFelix = App.CharacterClass_GetObject(pBridge, "Tactical")
	pMenu = pFelix.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Kiska event
	pKiska = App.CharacterClass_GetObject(pBridge, "Helm")
	pMenu = pKiska.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Miguel event
	pMiguel = App.CharacterClass_GetObject(pBridge, "Science")
	pMenu = pMiguel.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Communicate with Brex event
	pBrex = App.CharacterClass_GetObject(pBridge, "Engineer")
	pMenu = pBrex.GetMenu()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

##################################################		
##
## WarpHandler()
##
## This funtion will handle the use of the warp button
##
##	Args:	None
##
##	Return: None
##
###################################################
def WarpHandler(pObject, pEvent):
#	kDebugObj.Print("Handling Warp")

	# Get the player and the set their in
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()

	if (sSetName == "Serris1") and (g_bHeadingToStarbase12 == FALSE):
		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2Prod1", None, 0, g_pMissionDatabase)
		pAction.Play()
	
		return

	pObject.CallNextHandler(pEvent)
	
################################################################################
##	HailHandler()
##
##	Event handler called when Kiska's "Hail" button is pressed. 
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def HailHandler(TGObject, pEvent):
	# Get the player and his target
	pPlayer = MissionLib.GetPlayer ()
	if (pPlayer == None):
		return
		
	pTarget = App.ObjectClass_Cast(pEvent.GetSource())
	if (pTarget):
		if (pTarget.GetName () == "Nightingale"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			
			pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pNightHailed		= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6HailNightingale", "Jadeja")
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pPreLoad)
			pSequence.AppendAction(pCallWaiting)		
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pNightHailed, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
		elif (pTarget.GetName () == "Dauntless"):
			# Do little sequence
			pSequence = App.TGSequence_Create()
			
			pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pKiskaNoAnswer		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6HailAnyone4", None, 0, MissionLib.GetEpisode().GetDatabase())
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pPreLoad)
			pSequence.AppendAction(pCallWaiting)					
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pKiskaNoAnswer, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
			
		elif (pTarget.GetName () in g_lFriendlyShips):	
			# Do little sequence
			pSequence = App.TGSequence_Create()
			
			pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
			pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
			pKiskaHailing		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "KiskaYes4", None, 0, g_pGeneralDatabase)
			pKiskaNoResponse	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6HailAnyone3", None, 0, MissionLib.GetEpisode().GetDatabase())
			pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
			
			pSequence.AppendAction(pPreLoad)
			pSequence.AppendAction(pCallWaiting)					
			pSequence.AppendAction(pKiskaHailing)
			pSequence.AppendAction(pKiskaNoResponse, 2)
			pSequence.AppendAction(pEndCallWaiting)
			
			pSequence.Play()
		
		else:
			TGObject.CallNextHandler(pEvent)
	
################################################################################
##	PlayerWeaponFired()
##
##	Handler called when player fires a weapon.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PlayerWeaponFired(TGObject, pEvent):
	# Get the players target.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	pTarget = pPlayer.GetTarget()
	if(pTarget == None):
		return
		
	sTargetName = pTarget.GetName()
	
#	kDebugObj.Print("player fired on " +sTargetName + " " +str(g_bCombat1Called))

	if App.TractorBeamProjector_Cast(pEvent.GetSource()):
		# It was a tractor beam that was fired.
		return
			
	#see if the user is firing on the Galor 1 or Galor 2 for the first time.
	if (sTargetName == "Galor 1") and (g_bCombat1Called == FALSE):
		global g_bCombat1Called
		g_bCombat1Called = TRUE
		# Do little sequence
#		kDebugObj.Print("firing on galor 1")
		pSequence 		= App.TGSequence_Create()
		pFelixCombat	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2Combat2", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pFelixCombat, 1)
		pSequence.Play()
		
	if (sTargetName == "Galor 2") and (g_bCombat2Called == FALSE):
		global g_bCombat2Called
		g_bCombat2Called = TRUE
#		kDebugObj.Print("firing on galor 2")
		# Do little sequence
		pSequence 		= App.TGSequence_Create()
		pFelixCombat	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2Combat8", None, 0, g_pMissionDatabase)
		pSequence.AppendAction(pFelixCombat, 1)
		pSequence.Play()	
		
################################################################################
##	PlayerFiringOnFriend()
##
##	Called if the player continues to fire on the Marauder after it's been
##	disabled.  Called from the weapon fired handler.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PlayerFiringOnFriend(TGObject, pEvent):
	# Get the ship that was hit
	pShip	= App.ShipClass_Cast(pEvent.GetSource())
	if (pShip == None):
		return
	sShipName = pShip.GetName()
	
	# If we need to, do our special line
	fTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - g_pSaffi.GetLastTalkTime()
	if (fTimeSinceTalk < 10.0):
		# All done, so call our next handler
		TGObject.CallNextHandler(pEvent)
		return
	fKiskaTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - g_pKiska.GetLastTalkTime()
	if (fKiskaTimeSinceTalk < 10.0):
		# All done, so call our next handler
		TGObject.CallNextHandler(pEvent)
		return
	else:
		# See who is being fired on and do the correct line
		if (sShipName == "Nightingale"):
	
			# Do little sequence
			pSequence = App.TGSequence_Create()
			pKiskaIncomming		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg3", None, 0, g_pGeneralDatabase)
			pNightingaleFire	= App.TGScriptAction_Create("MissionLib", "SubtitledLine", MissionLib.GetEpisode().GetDatabase(), "E6DontShoot6", "Jadeja")
					
			pSequence.AppendAction(pKiskaIncomming, 2)
			pSequence.AppendAction(pNightingaleFire, 2)
			
			pSequence.Play()
			return

	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)	
################################################################################
##	PlayerStillFiringOnFriend()
##
##	Called if the player continues to fire on friend  Ends the game because 
##  the player is being a bastard.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def PlayerStillFiringOnFriend(TGObject, pEvent):
	#kill any registered sequences
	App.TGActionManager_KillActions()
	
	# Do the line from Saffi and end the game
	pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "DontShoot3", "Captain", 1, g_pGeneralDatabase)
	
	# End the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
	pGameOver.Play()


################################################################################
##	EnterSet()
##
##	Event handler called whenever an object enters a set.
##
##	Args: 	TGObject	- The TGObject oject.
##			pEvent		- Pointer to the event that was sent to the object
##
##	Return: None
################################################################################
def EnterSet(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	# Make sure it's a ship, return if not
	if (pShip == None):
		return
	
	# Make sure the ship is not dead
	if (pShip.IsDead()):
		return
	pSet		= pShip.GetContainingSet()
	sSetName 	= pSet.GetName()
	sShipName	= pShip.GetName()

#	kDebugObj.Print("Object \"%s\" entered set \"%s\"" % (sShipName, sSetName))
	
	# If it's the player, track him
	if (sShipName == "player"):
		if (sSetName == "warp"):
			PlayerEntersWarpSet()
		else:
			TrackPlayer(sSetName)
	
	# Check and see if it's a Galor in Serris
	if (sShipName == "Keldon 1") and (sSetName == "Serris1"):
		GalorsEnterSerris1()
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ExitSet()
##
##	Event handler called whenever an object leaves a set.
##
##	Args: 	TGObject	- The TGObject object
##			pEvent		- Pointer to the event that was sent to the object
##
##	Return: None
################################################################################
def ExitSet(TGObject, pEvent):
	# See if our mission is terminating
	if (g_bMissionTerminate == TRUE):
		return

	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	sSetName = pEvent.GetCString()

	# Make sure it's a ship, return if not
	if (pShip == None):
		return 0
		
	# Bail if the ship is dead
	if (pShip.IsDead()):
		return

	sShipName = pShip.GetName()

#	kDebugObj.Print("Object \"%s\" exited set \"%s\"" % (sShipName, sSetName))
	
	if (sShipName == "Galor 1") and (sSetName == "Geble3"):
		GalorWarpOut()
	
	# We're done. Let any other event handlers for this event handle it
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ObjectDestroyed()
##
##	Event handler called when a ship destroyed event is sent.
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
	global g_iCapturedGeblePods
	global g_bGeblePodDestroyed
	global g_bAllGeblePodsCaptured
	sShipName	= pShip.GetName()
	pSet = pShip.GetContainingSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()

#	kDebugObj.Print("Object \"%s\" was destroyed in set \"%s\"" % (sShipName, sSetName))
	
	# If the Nightingale was destroyed, call mission lost
	if (sShipName == "Nightingale"):
		#kill any sequences with Jadea
		App.TGActionManager_KillActions("Jadeja")
		MissionLost()
		
	# If the Dauntless was destroyed before self-dustructing, call mission lost
	if (sShipName == "Dauntless") and (g_bDauntlessCleared == FALSE):
		DauntlessMissionLost()
	
	# If both the Galor and the keldon have been destroyed, hurry up
	# the Dauntless clearing
	if (sShipName == "Galor 1") and (sSetName == "Serris1"):
		global g_bGalor1Destroyed
		g_bGalor1Destroyed	= TRUE
	elif (sShipName == "Keldon 1"):
		global g_bKeldon2Destroyed
		g_bKeldon2Destroyed	= TRUE
		
	if (g_bGalor1Destroyed == TRUE) and (g_bKeldon2Destroyed == TRUE):
		# Start the timer that will speed things up
		fStartTime	= App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_DAUNTLESS_CLEAR_TIMER, __name__+".DauntlessClear", fStartTime + 8, 0, 0)
	
	# if this is the first Geble pod lost it is okay.
	if (sShipName[:10] == "Escape Pod") and (sSetName == "Geble3"):
		# First, remove assosiated nav points
		if (sShipName == "Escape Pod 1"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 1")
		if (sShipName == "Escape Pod 2"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 2")
		if (sShipName == "Escape Pod 3"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 3")
		if (sShipName == "Escape Pod 4"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 4")
		if (sShipName == "Escape Pod 5"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 5")
		if (sShipName == "Escape Pod 6"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 6")
		# Second, check our flag
		if (g_bGeblePodDestroyed == FALSE):
			g_iCapturedGeblePods = g_iCapturedGeblePods + 1
			g_bGeblePodDestroyed = TRUE
			PodLost()
				# If we've captured all the pods in a system, call our function
				# for the Geble system... 
			if (g_iCapturedGeblePods == 6) and (g_bAllGeblePodsCaptured == FALSE):
				g_bAllGeblePodsCaptured = TRUE
				AllGeblePodsCaptured()		
		else:
			PodMissionLost()
		
	# check if Galor 1 dies too early, if so, re create him.
	if (sShipName == "Galor 1") and (sSetName != "Serris1"): 
		global g_bGalor1Replaced
		g_bGalor1Replaced = TRUE
			
		pSequence = App.TGSequence_Create()
		pAction	= App.TGScriptAction_Create(__name__, "CreateReplacementGalor", sShipName)	
		pSequence.AppendAction(pAction, 10) #ten second delay so the first galor is really gone
		pSequence.Play()
		

	# check if Galor 1 dies
	if (sShipName == "Galor 1") and (sSetName == "Serris1"): 
		pSequence = App.TGSequence_Create()
	
		pMiguel	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2Combat9", None, 0, g_pMissionDatabase)
	
		pSequence.AppendAction(pMiguel, 2) #2 second delay
			
		pSequence.Play() 
	
	# check if Galor 2 dies
	if (sShipName == "Galor 2"): 
#		kDebugObj.Print("galor 2 dies baby")
		pSequence = App.TGSequence_Create()
	
		pMiguel	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2Combat11", None, 0, g_pMissionDatabase)
	
		pSequence.AppendAction(pMiguel, 2) #2 second delay
			
		pSequence.Play() 
		
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	CreateReplacementGalor(pAction, sShipName)
##
##	Creates the Second Galor that attacks the player in Geble 3 and give new AI to galor 1
##
##	Args:	pAction - passed on by the sequence
##			sShipName	- the galor that was destroyed
##			
##  Return:	return 0 - to dismiss the pAction that had to be passed on
##	
################################################################################
def CreateReplacementGalor(pAction, sShipName):
#	kDebugObj.Print("Now making a replacement galor")
	# Get the set
	pSet = App.g_kSetManager.GetSet("DeepSpace")
	
	if (sShipName == "Galor 1") and (g_bGalor1Replaced == TRUE):
		# re-create the ship 
		pGalor1 = loadspacehelper.CreateShip("Galor", pSet, "Galor 1", "Galor2Enter")
		
		# Check our flag, if second wave has not been made, start a timer to call them back
		if (g_bSecondGalorCreated == FALSE):
			fStartTime = App.g_kUtopiaModule.GetGameTime()
			MissionLib.CreateTimer(ET_SECOND_GALOR_TIMER, __name__+".CreateSecondGalor", fStartTime + 55, 0, 0)
		
	return 0

################################################################################
##	TractorTargetDocked()
##
##	Event handler called when tractor target has docked with ship.
##
##	Args:	pTGObject	- The TGObject object
##			pEvent		- The event that was sent to the object
##
##	Return:	None
################################################################################
def TractorTargetDocked(pTGObject, pEvent):
#	kDebugObj.Print("Calling TractorTargetDocked()")
	# Get the object that was docked and it's name
	pObject	= App.ShipClass_Cast(pEvent.GetObjPtr())
	if (pObject == None):
		return
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sShipName	= pShip.GetName()
	sName 	= pObject.GetName()
	pSet	= pObject.GetContainingSet()
	
	global g_iCapturedGeblePods
	global g_bAllGeblePodsCaptured

	# If the object is a escape pod, remove it from the set
	# and increase the captured count
#	kDebugObj.Print("Object name is: " + sName)
	if (sName[:10] == "Escape Pod"):
		pObject.SetDeleteMe(1)
		
		if (sShipName == "Nightingale"):
			# Play the audio line that will let the player know Nightingale docked a pod
			global g_iNumberOfNightPods
			g_iNumberOfNightPods = g_iNumberOfNightPods + 1
			if (g_iNumberOfNightPods == 1):
				pFelixLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2PodDocked2", "Captain", 1, g_pMissionDatabase)
				pFelixLine.Play()
			elif (g_iNumberOfNightPods == 2):
				pKiskaLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2NightTwoPods2", "Captain", 1, g_pMissionDatabase)
				pKiskaLine.Play()
			else:
				pFelixLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2PodDocked2", "Captain", 1, g_pMissionDatabase)
				pFelixLine.Play()
		elif (sShipName == "player"):
			# Play the audio line that will let the player know pod is docked
			pSequence = App.TGSequence_Create()
	
			pFelixLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2PodDocked", "Captain", 1, g_pMissionDatabase)
			pSequence.AppendAction(pFelixLine, 2) #2 second delay
			
			pSequence.Play() 
			
			# set flag so dialogue knows the player docked a pod
			global g_bPlayerDockedPod
			g_bPlayerDockedPod = TRUE
	
		# Set what set the pod was captured in and increase the correct counter
		if (pSet.GetName() == "Geble3"):
			g_iCapturedGeblePods = g_iCapturedGeblePods + 1
				
		# If we've captured all the pods in a system, call our function
		# for the Geble system... # FIXME: SHAWN: set one pod to be docked to call the victory
		if (g_iCapturedGeblePods == 6) and (g_bAllGeblePodsCaptured == FALSE):
			g_bAllGeblePodsCaptured = TRUE
			AllGeblePodsCaptured()
		
		#remove assosiated nav points
		if (sName == "Escape Pod 1"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 1")
		if (sName == "Escape Pod 2"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 2")
		if (sName == "Escape Pod 3"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 3")
		if (sName == "Escape Pod 4"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 4")
		if (sName == "Escape Pod 5"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 5")
		if (sName == "Escape Pod 6"):
			MissionLib.RemoveNavPoints("Geble3", "Pod 6")
	

################################################################################
##	TractorBeamOn()
##
##	Event handler called when tractor beam starts hitting a target.  Checks to
##	see if the target is a pod and starts docking behavior if it is.
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
	
	# Get the name of the ship that fired
	pShip = pTractorSystem.GetParentShip()
	if (pShip == None):
		return
	sFiringShipName = pShip.GetName()
	
	# See if it's an escape pod
	global g_fLastCheckTime
	fStartTime = App.g_kUtopiaModule.GetGameTime()	
	
	if (sTargetName[:10] == "Escape Pod"):
		# If their using the forward tractor, tell them
		# it won't work and bail out
		pProp = pTractorProjector.GetProperty()
		if (pProp.GetWeaponID() == 1):
			if (g_fLastCheckTime + 5 < fStartTime): 
				g_fLastCheckTime = fStartTime
				pFelixLine	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2WrongTractorBeam", "Captain", 1, g_pMissionDatabase)
				pFelixLine.Play()
			return

		# It's a pod so start our docking behavior and have Felix
		# say his line
		if (pTractorSystem != None):
			# set the tractor beam to pull in and dock the pod
			pTractorSystem.SetMode(pTractorSystem.TBS_DOCK_STAGE_1)
			# If the ship that's firing is the player, then
			# play Felix's line, and remove the name of the pod
			# from our list so this audio doesn't repeat
			pPlayer = MissionLib.GetPlayer()
			if (pPlayer == None):
				return
			pSet = pPlayer.GetContainingSet()
			if(sFiringShipName == pPlayer.GetName()) and (pSet.GetName() == "Geble3"):
#				kDebugObj.Print("Player is in geble 3 and is firing their tractor beam on a pod")
				global g_lsGeblePodNames
				for sName in g_lsGeblePodNames:
					if(sName == sTargetName):
						# remove it from the list and play the line
#						kDebugObj.Print("Playing Brex's .attempting to dock pod. line")	
						g_lsGeblePodNames.remove(sName)
						pBrexLine = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M2FelixDockPod", "Captain", 1, g_pMissionDatabase)
						pBrexLine.Play()

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	SetCourse()
##	
##	Intercept the helm's handling of the Intercept button, and override
##	it with our own custom AI.
##	
##	Args:	TGObject	- The TGObject object.
##			pEvent		- A Set Course event.  Maybe the Intercept one.
##	
##	Return: None
################################################################################
def SetCourse(TGObject, pEvent):
	# Intercept the helm menu's Set-Course related functions, so we can
	# override the intercept button.
	if (pEvent.GetInt() == App.CharacterClass.EST_SET_COURSE_INTERCEPT):
		# This is the event we're trying to intercept.  Set our
		# new Intercept AI.
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer != None):
			pTarget = pPlayer.GetTarget()
			if (pTarget != None):
				if (pTarget.GetName()[:10] == "Escape Pod"):
					import E6M2_AI_Intercept
					pAI = E6M2_AI_Intercept.CreateAI(pPlayer, pTarget.GetName())
					MissionLib.SetPlayerAI("Helm", pAI)
					# Play audio line for Kiska
					pKiskaYes = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "gh007", "Captain", 1, g_pGeneralDatabase)
					pKiskaYes.Play()
				else:
					# Do the default stuff.
					TGObject.CallNextHandler(pEvent)
	else:
		# Do the default stuff.
		TGObject.CallNextHandler(pEvent)
	
################################################################################
##	InPosition()
##
##	Called from AI_intercept.py when in position to tractor
##	
##
##	Args:	None
##
##	Return:	None
################################################################################
def InPosition():
	pSequence = App.TGSequence_Create()
	
	pKiskaLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2TractorPods0", None, 0, g_pMissionDatabase)
	
	pSequence.AppendAction(pKiskaLine, 1)
		
	pSequence.Play()
		
################################################################################
##	TrackPlayer()
##
##	See what set the player has just entered into and call functions based on
##	that.
##
##	Args:	sSetName	- The name of the set the player has entered.
##
##	Return:	None
################################################################################
def TrackPlayer(sSetName):
	global g_bPlayerArriveGeble3
	global g_bPlayerArriveGeble4
	global g_bPlayerArriveSerris3
	global g_bPlayerArriveSerris1
	global g_bPlayerArriveStarbase12

	# If player is entering Geble4, restart prod timer with
	# a 30 sec timer.
	if (sSetName == "Geble4") and (g_bPlayerArriveGeble3 == FALSE):
		RestartProdTimer(App.TGAction_CreateNull(), 30)
		
	# See if we're entering Geble3 for first time
	if (sSetName == "Geble4") and (g_bPlayerArriveGeble4 == FALSE):
		StopProdTimer()
		JadejaBriefing()
		g_bPlayerArriveGeble4 = TRUE
		
	# See if we're entering Geble3 for first time
	if (sSetName == "Geble3") and (g_bPlayerArriveGeble3 == FALSE):
		StopProdTimer()
		g_bPlayerArriveGeble3 = TRUE
		
	# See if we're entering Serris3, restart prod timer with
	# 60 sec timer
	if (sSetName == "Serris3") and (g_bPlayerArriveSerris3 == FALSE):
		g_bPlayerArriveSerris3 = TRUE
		RestartProdTimer(App.TGAction_CreateNull(), 70)
		PlayerArrivesSerris3()
		
	# See if we're entering Serris1 for first time
	if (sSetName == "Serris1") and (g_bPlayerArriveSerris1 == FALSE):
		StopProdTimer()
		g_bPlayerArriveSerris1 = TRUE
		PlayerArrivesSerris1()
		

################################################################################
##	PlayerEntersWarpSet()
##
##	Called if player enters warp set.  Keeps track of were the player is headed
##	for proding needs and creating ships while were in warp.
##
##	Args:	None
##
##	Return: None
################################################################################
def PlayerEntersWarpSet():
	# Get Kiska's warp heading and see where were headed
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pString 	= pWarpButton.GetDestination()
	
	# See if we're heading to Geble system for first time
	if (pString == "Systems.Geble.Geble4") and (g_bPlayerArriveGeble3 == FALSE):
		StopProdTimer()
	# See if we're heading to Geble3
	if (pString == "Systems.Geble.Geble3") and (g_bPlayerArriveGeble3 == FALSE):
		StopProdTimer()
	# See if we're entering Serris1 for first time
	if (pString == "Systems.Serris.Serris3") and (g_bPlayerArriveSerris3 == FALSE):
		StopProdTimer()
	# See if we're entering Serris1 for first time
	if (pString == "Systems.Serris.Serris1") and (g_bPlayerArriveSerris1 == FALSE):
		StopProdTimer()
	# See if we're heading back to Starbase 12
	if (pString == "Systems.Starbase12.Starbase12") and (g_bHeadingToStarbase12 == TRUE) and (g_bPlayerArriveStarbase12 == FALSE):
		StopProdTimer()

################################################################################
##	ScanHandler()
##
##	Called when Miguels Scan Area button is pressed.  Initiates behavior based
##	on what set the player is in.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ScanHandler(TGObject, pEvent):
	
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	# If the players sensors are off, do the default thing and bail
	pSensors = pPlayer.GetSensorSubsystem()
	if (pSensors == None):
		TGObject.CallNextHandler(pEvent)
		return
	if (pSensors.IsOn() == FALSE):
		TGObject.CallNextHandler(pEvent)
		return
	
	# Get the player and the set their in	
	pSet		= pPlayer.GetContainingSet()
	sSetName	= pSet.GetName()
	iType		= pEvent.GetInt()
#	kDebugObj.Print("Scan Handler")	
	
	# Check what set it is and if we haven't scanned it
	# before, call our function, unless it is a scan target on the kessok.
	if (iType == App.CharacterClass.EST_SCAN_OBJECT):
		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if not (pTarget):
#			kDebugObj.Print("You're scanning the target")
			pTarget = pPlayer.GetTarget()
		if (pTarget): 
			if (pTarget.GetName() == "Hulk 1"):
#				kDebugObj.Print("You're scanning hulk 1")
				ScanningHulk1()
			elif (pTarget.GetName() == "Hulk 2"):
#				kDebugObj.Print("You're scanning the hulk 2")
				ScanningHulk2()	
			elif (pTarget.GetName() == "Hulk 3"):
#				kDebugObj.Print("You're scanning the hulk 3")
				ScanningHulk3()	
			elif (pTarget.GetName() == "Dauntless"):
#				kDebugObj.Print("You're scanning the Dauntless")
				ScanningDauntless()	
			elif (pTarget.GetName()[:10] == "Escape Pod"):
#				kDebugObj.Print("You're scanning a Escape pod")
				ScanningPod()	
			elif (pTarget.GetName() == "Nightingale"):
#				kDebugObj.Print("You're scanning the nightingale")
				ScanningNightingale()			
			elif (pTarget.GetName() == "Adams")	and (g_bAdamsScanned == FALSE):
				global g_bAdamsScanned
				g_bAdamsScanned = TRUE
#				kDebugObj.Print("You're scanning the Adams")
				ScanningAdams()	
			# if scaning nothing we care about do default
			else:
				TGObject.CallNextHandler(pEvent)
	else:
		TGObject.CallNextHandler(pEvent)			
	
################################################################################
##	ScanningHulk1()
##
##  Creates sequence for ScanningHulk1 and plays it.  
##
##	Args: 	None
##
##	Return: None
################################################################################
def ScanningHulk1():
	
	pSequence = App.TGSequence_Create()
	
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "gs007", g_pGeneralDatabase)
	pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ScanHulk1", None, 0, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pScanSequence)		
	pSequence.AppendAction(pMiguelLine02)
	pSequence.AppendAction(pEnableScanMenu)
		
	pSequence.Play()
				
################################################################################
##	ScanningHulk2()
##
##  Creates sequence for ScanningHulk2 and plays it.  
##
##	Args: 	None
##
##	Return: None
################################################################################
def ScanningHulk2():
	
	#set up a random line
	pcLine = MissionLib.GetRandomLine(["E6M2ScanHulk2", "E6M2ScanHulk4"])
	
	pSequence = App.TGSequence_Create()
	
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "gs028", g_pGeneralDatabase)
	pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, pcLine, None, 0, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pScanSequence)		
	pSequence.AppendAction(pMiguelLine02)
	pSequence.AppendAction(pEnableScanMenu)
		
	pSequence.Play()
				
################################################################################
##	ScanningHulk3()
##
##  Creates sequence for ScanningHulk3 and plays it.  
##
##	Args: 	None
##
##	Return: None
################################################################################
def ScanningHulk3():
	
	pSequence = App.TGSequence_Create()
	
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "MiguelYes1", g_pGeneralDatabase)
	pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ScanHulk3", None, 0, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pScanSequence)		
	pSequence.AppendAction(pMiguelLine02)
	pSequence.AppendAction(pEnableScanMenu)
		
	pSequence.Play()
	
################################################################################
##	ScanningDauntless()
##
##  Creates sequence for ScanningDauntless and plays it.  
##
##	Args: 	None
##
##	Return: None
################################################################################
def ScanningDauntless():
	
	#set up a random line
	pcLine = MissionLib.GetRandomLine(["E6M2ScanDauntless1", "E6M2ScanDauntless2", "E6M2ScanDauntless3"])
	
	pSequence = App.TGSequence_Create()
	
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "MiguelYes2", g_pGeneralDatabase)
	pMiguelLine02 	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, pcLine, None, 0, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pScanSequence)		
	pSequence.AppendAction(pMiguelLine02)
	pSequence.AppendAction(pEnableScanMenu)	
		
	pSequence.Play()

################################################################################
##	ScanningPod()
##
##  Creates sequence for ScanningPod and plays it. 
##
##	Args: 	None
##
##	Return: None
################################################################################
def ScanningPod():
	#set up a random line
	pcLine = MissionLib.GetRandomLine(["E6M2ScanPod2", "E6M2ScanPod1", "E6M2ScanPod3"])
	
	pSequence = App.TGSequence_Create()
	
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "MiguelScan", g_pGeneralDatabase)
	pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, pcLine, None, 0, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pScanSequence)		
	pSequence.AppendAction(pMiguelLine02)
	pSequence.AppendAction(pEnableScanMenu)
		
	pSequence.Play()

################################################################################
##	ScanningNightingale()
##
##  Creates sequence for ScanningNightingale and plays it. 
##
##	Args: 	None
##
##	Return: None
################################################################################
def ScanningNightingale():
	
	pcLine = MissionLib.GetRandomLine(["E6M2ScanNight1", "E6M2ScanNight2"])
	
	pSequence = App.TGSequence_Create()
	
	pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "MiguelYes4", g_pGeneralDatabase)
	pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, pcLine, None, 0, g_pMissionDatabase)
	pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	
	pSequence.AppendAction(pScanSequence)		
	pSequence.AppendAction(pMiguelLine02)
	pSequence.AppendAction(pEnableScanMenu)
		
	pSequence.Play()

################################################################################
##	ScanningAdams()
##
##  Creates sequence for ScanningAdams and plays it. 
##
##	Args: 	None
##
##	Return: None
################################################################################
def ScanningAdams():
#	kDebugObj.Print("Scanning the hulk, finding torps")
	
	#first, find out if the user has 60 quantums already.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	pTorpSys = pPlayer.GetTorpedoSystem()
	iNumQuantumsLeft = 0
	if (pTorpSys):
		# Find proper torps..
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			pTorpType = pTorpSys.GetAmmoType(iType)
			# set iNumQuantumsLeft to equal the number of quantums the user has.
			if (pTorpType.GetAmmoName() == "Quantum"):
				iNumQuantumsLeft = pTorpSys.GetNumAvailableTorpsToType(iType)

	if (iNumQuantumsLeft != 60):
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "E6M4ScanTransport1", MissionLib.GetEpisode().GetDatabase())
		pMiguelLine00	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ScanAdams", None, 0, g_pMissionDatabase)
		pMiguelLine01	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport3", None, 1, MissionLib.GetEpisode().GetDatabase())
		pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport4", None, 1, MissionLib.GetEpisode().GetDatabase())
		pBrexLine03		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport5a", None, 1, MissionLib.GetEpisode().GetDatabase())
		pBrexLine04		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M4ScanTransport6", None, 1, MissionLib.GetEpisode().GetDatabase())
		pFlickerShields	= App.TGScriptAction_Create("Actions.ShipScriptActions", "FlickerShields")
		pTransTorps		= App.TGScriptAction_Create("MissionLib", "LoadTorpedoes", "Quantum", 15)
		pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pScanSequence)	
		pSequence.AppendAction(pMiguelLine00)
		pSequence.AppendAction(pMiguelLine01)
		pSequence.AppendAction(pMiguelLine02)
		pSequence.AppendAction(pBrexLine03)
		pSequence.AddAction(pBrexLine04, pBrexLine03)
		pSequence.AddAction(pFlickerShields, pBrexLine03, 1.5)
		pSequence.AppendAction(pTransTorps, 0.5)
		pSequence.AppendAction(pEnableScanMenu)
		
		pSequence.Play()

	elif (iNumQuantumsLeft == 60):
		# Do our sequence
		pSequence = App.TGSequence_Create()
		
		pScanSequence	= Bridge.ScienceCharacterHandlers.GetScanSequence(0, None, "E6M4ScanTransport1", MissionLib.GetEpisode().GetDatabase())
		pMiguelLine00	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ScanAdams", None, 0, g_pMissionDatabase)
		pEnableScanMenu	= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
		
		pSequence.AppendAction(pScanSequence)					
		pSequence.AppendAction(pMiguelLine00)
		pSequence.AppendAction(pEnableScanMenu)
				
		pSequence.Play()

##################################################		
##
## CommunicateHandler()
##
## This funtion will handle the use of the communicate button
##
##	Args:	None
##
##	Return: None
##
###################################################

def CommunicateHandler(pObject, pEvent):

	# check whose menu was clicked.
	pMenu = App.STTopLevelMenu_Cast(pEvent.GetDestination())

	# Do a quick error check
	pSet 	= MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()

	# pick a communicate dialogue, or behave normally
	if pMenu and (sSetName == "Geble3") and (g_bAllGeblePodsCaptured == FALSE):
		PodCommunicate(pMenu.GetObjID()) #pass on whose menu was clicked to PodCommunicate
		
	elif pMenu and (sSetName == "Serris1") and (g_bDauntlessCleared == FALSE):
		DauntlessCommunicate(pMenu.GetObjID()) #pass on whose menu was clicked to DauntlessCommunicate
		
	else:
		pObject.CallNextHandler(pEvent)
		
#####################################################################
##
## PodCommunicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def PodCommunicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2Communicate1", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")

		pShip = MissionLib.GetPlayer()
		pTractors = pShip.GetTractorBeamSystem()
		if pTractors and (pTractors.IsFiring() == 0):
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2Communicate2", None, 0, g_pMissionDatabase)
		else:
			pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble13", None, 0, g_pMissionDatabase)
		
	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi")

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6RecoverPodsGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID():
#		kDebugObj.Print("Communicating with Miguel")

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2Communicate4", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")

		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M2Communicate3", None, 0, g_pMissionDatabase)

	pAction.Play()

#####################################################################
##
## DauntlessCommunicate(iMenuID)
##
##	Args:	iMenuID - whose communicate button was pressed
##
##	Return: None
##
####################################################################		
def DauntlessCommunicate(iMenuID):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pSaffiMenu = g_pSaffi.GetMenu()
	pFelixMenu = g_pFelix.GetMenu()
	pMiguelMenu = g_pMiguel.GetMenu()
	
	if iMenuID == pKiskaMenu.GetObjID():
#		kDebugObj.Print("Communicating with Kiska")

		pAction = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2Communicate5", None, 0, g_pMissionDatabase)

	elif iMenuID == pFelixMenu.GetObjID():
#		kDebugObj.Print("Communicating with Felix")

		pAction = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2Communicate6", None, 0, g_pMissionDatabase)

	elif iMenuID == pSaffiMenu.GetObjID():
#		kDebugObj.Print("Communicating with Saffi")

		pAction = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6EngageCardsGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	elif iMenuID == pMiguelMenu.GetObjID():
#		kDebugObj.Print("Communicating with Miguel")

		pAction = App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2Communicate8", None, 0, g_pMissionDatabase)

	else:
#		kDebugObj.Print("Communicating with Brex")

		pAction = App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M2Communicate7", None, 0, g_pMissionDatabase)

	pAction.Play()	
	
################################################################################
##	LiuBriefing()
##
##  Creates sequence for first breifing and plays it.  Registers our first
##	goals.
##
##	Args: 	pTGAction
##
##	Return: None
################################################################################
def LiuBriefing(pTGAction):
	# check if the player is done warping in, if not call this function again in 2 seconds
	if MissionLib.IsPlayerWarping():
		# Delay sequence 2 seconds.
		pSequence = App.TGSequence_Create()
		pRePlayBriefing	= App.TGScriptAction_Create(__name__, "LiuBriefing")
		pSequence.AppendAction(pRePlayBriefing, 2)
		pSequence.Play()

		return 0
	
	pStarbaseSet	= App.g_kSetManager.GetSet("StarbaseSet")
	
	pLiu 	= App.CharacterClass_GetObject(pStarbaseSet, "Liu")
	
	# Un-hide Liu
	pLiu.SetHidden(0)

	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pOnScreen		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2Briefing1", None, 0, g_pMissionDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLine001		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2Briefing2", None, 0, g_pMissionDatabase)
	pLiuLine002		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2Briefing3", None, 0, g_pMissionDatabase)
	pLiuLine002a	= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2Briefing3a", None, 0, g_pMissionDatabase)
	pLiuLine003		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2Briefing4", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 45)	# 45sec prod timer
	pAddGoal 		= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E6MeetNightingaleGoal")
	pAddGebleToCorseList	= App.TGScriptAction_Create(__name__, "AddGebleToCorseList")
	pSetCourse		= App.TGScriptAction_Create(__name__, "GebleCourseSet")
	pKiska			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2Plot1", None, 0, g_pMissionDatabase)	
	
	pSequence.AppendAction(pOnScreen, 5)
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuLine001)
	pSequence.AppendAction(pLiuLine002)
	pSequence.AppendAction(pLiuLine002a)
	pSequence.AppendAction(pLiuLine003)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pStartProdTimer)
	pSequence.AppendAction(pAddGoal)
	pSequence.AppendAction(pAddGebleToCorseList)
	pSequence.AppendAction(pSetCourse)
	pSequence.AppendAction(pKiska)
				
	pSequence.Play()
	
	return 0
	
################################################################################
##	AddGebleToCorseList()
##
##	Adds Geble to the user's course.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def AddGebleToCorseList(pTGAction):
	import Systems.Geble.Geble
	Systems.Geble.Geble.CreateMenus()
	
	return 0

###############################################################################
#	GebleCourseSet()
#
#	this sets course for Geble 4
#
#	Args:	pAction
#
#	Return:	0
###############################################################################
def GebleCourseSet(pAction):
	
	pKiskaMenu = g_pKiska.GetMenu()
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	# Set the location on the warp menu
	pWarpButton.SetDestination("Systems.Geble.Geble4")
	pKiskaMenu.SetFocus(pWarpButton)

	return 0	

################################################################################
##	JadejaBriefing()
##
##  Creates sequence for Jadeja Briefing and plays it.  Registers our next
##	goals.
##
##	Args: 	None
##
##	Return: None
################################################################################
def JadejaBriefing():
	global g_sProdLine
	g_sProdLine = "E6M2Prod6"
	
	pDBridgeSet		= App.g_kSetManager.GetSet("DBridgeSet")

	pJadeja	= App.CharacterClass_GetObject(pDBridgeSet, "Jadeja")

	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixLine01	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg2", None, 0, g_pGeneralDatabase)
	pSaffiLine02	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "gf013", None, 0, g_pGeneralDatabase)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Jadeja")
	pJadejaLine004	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2Briefing5", None, 0, g_pMissionDatabase)
	pJadejaLine005	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2Briefing6", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)	# 30sec prod timer
	pSetNightAI		= App.TGScriptAction_Create(__name__, "SetFirstNightAI")
			
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixLine01, 6)
	pSequence.AppendAction(pSaffiLine02)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pJadejaLine004)
	pSequence.AppendAction(pJadejaLine005)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pStartProdTimer)
	pSequence.AppendAction(pSetNightAI, 5)
		
	pSequence.Play()
	
	# Register our next goals and remove the first
	MissionLib.RemoveGoal("E6MeetNightingaleGoal")
	MissionLib.AddGoal("E6EscortNightingaleGoal")
	MissionLib.AddGoal("E6HeadToGeble3Goal")

################################################################################
##	SetFirstNightAI()
##
##	Sets the first Nightingale AI that will warp to Geble 3.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetFirstNightAI(pTGAction):
#	kDebugObj.Print("Setting Nightingale AI to Geble")
	# Import the AI
	import E6M2_AI_Night_Geble
	# Get the ship and set the AI
	pNight = App.ShipClass_GetObject(App.SetClass_GetNull(), "Nightingale")
	pNight.SetAI(E6M2_AI_Night_Geble.CreateAI(pNight))
	
	return 0
	
################################################################################
##	PlayerArrivesGeble3()
##
##	Called when the player arrives in Geble 3 with the Nightingale.
##  This is called by the Nightingale's AI
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesGeble3():
	# Don't play if this has been called before
	if (g_bGebleDialogPlayed == TRUE):
		return
	global g_bGebleDialogPlayed
	g_bGebleDialogPlayed = TRUE
	
	pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
	pJadeja		= App.CharacterClass_GetObject(pDBridgeSet, "Jadeja")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguel0Line1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble1", None, 0, g_pMissionDatabase)
	pSaffiLine02	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble2", None, 0, g_pMissionDatabase)
	pMiguelLine03	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble3", None, 0, g_pMissionDatabase)
	pKiskaLine04	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble4", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Jadeja")
	pJadejaLine05	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble5", None, 0, g_pMissionDatabase)
	pSaffiLine06	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble6", None, 0, g_pMissionDatabase)
	pKiskaLine07	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble7", None, 0, g_pMissionDatabase)
	pJadejaLine08	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble8", None, 0, g_pMissionDatabase)
	pSaffiLine09	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble9", None, 0, g_pMissionDatabase)
	pJadejaLine10	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble10", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pKiskaLine11	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble11", "Captain", 1, g_pMissionDatabase)
	pMakePodsTargetable	= App.TGScriptAction_Create(__name__, "MakePodsTargetable")
	pKiskaLine12	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveGeble12", None, 0, g_pMissionDatabase)
	pSaffiLine13	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6RecoverPodsGoalAudio", None, 0, MissionLib.GetEpisode().GetDatabase())

	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguel0Line1, 6)	# 6 sec delay before sequence starts
	pSequence.AppendAction(pSaffiLine02)
	pSequence.AppendAction(pMiguelLine03)
	pSequence.AppendAction(pKiskaLine04)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pJadejaLine05)
	pSequence.AppendAction(pSaffiLine06)
	pSequence.AppendAction(pKiskaLine07)
	pSequence.AppendAction(pJadejaLine08)
	pSequence.AppendAction(pSaffiLine09)
	pSequence.AppendAction(pJadejaLine10)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pKiskaLine11)
	pSequence.AppendAction(pMakePodsTargetable)
	pSequence.AppendAction(pKiskaLine12)
	pSequence.AppendAction(pSaffiLine13)
	
	pSequence.Play()
	
	# Start the timer that will create the first Galor
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_FIRST_GALOR_TIMER, __name__+".CreateFirstGalor", fStartTime + 60, 0, 0)
	
	# Remove our HeadToGeble goal and add recover pod goal
	MissionLib.RemoveGoal("E6HeadToGeble3Goal")
	MissionLib.AddGoal("E6RecoverPodsGoal")
	
################################################################################
##	MakePodsTargetable(pTGAction)
##
##	Places the pods on the user's target list
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	return 0
################################################################################
def MakePodsTargetable(pTGAction):
	
	# Get the set
	pSet = App.g_kSetManager.GetSet("Geble3")
	
	for iCounter in range(1, 7):
		pProbe = App.ShipClass_GetObject(pSet, ("Escape Pod " + str(iCounter)))
		
		# set the probe to appear on the target list
		pProbe.SetTargetable(1)
		pProbe.SetScannable(1)
		
		# Add Nav Points
		MissionLib.AddNavPoints("Geble3", ("Pod " + str(iCounter)))
			
	return 0
	
################################################################################
##	CreateFirstGalor()
##
##	Creates the first Galor that attacks the player in Geble 3
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CreateFirstGalor(TGObject, pEvent):
	
	# Check our flag
	if (g_bFirstGalorCreated == FALSE):
		global g_bFirstGalorCreated
		g_bFirstGalorCreated = TRUE
	else:
		return

#	kDebugObj.Print("Creating the first galor wave")	

	# Import the AI an needed ship
	import E6M2_AI_Galor1_Geble
	# Get the set
	pSet = App.g_kSetManager.GetSet("Geble3")
	# Create the ship and assign AI
	pGalor1 = loadspacehelper.CreateShip("Galor", pSet, "Galor 1", "Galor1Enter")
	pGalor1.SetAI(E6M2_AI_Galor1_Geble.CreateAI(pGalor1, g_pGalorGebleTargets))
	
	# Make the galor's impulse and warp engines invincibale so it can escape.
#	kDebugObj.Print ("Making Galor Impulse and Warp Engines invincible.")
	pWarp = pGalor1.GetWarpEngineSubsystem()
	pImpulse = pGalor1.GetImpulseEngineSubsystem()
	if (pWarp and pImpulse):
		MissionLib.MakeSubsystemsInvincible(pImpulse, pWarp)
	
	# Call the dialogue that plays when Galor enters
	GalorEntersGeble()
	
################################################################################
##	CreateSecondGalor()
##
##	Creates the Second Galor that attacks the player in Geble 3 and give new AI to galor 1
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CreateSecondGalor(TGObject, pEvent):
	
	# Check our flag
	if (g_bSecondGalorCreated == FALSE):
		global g_bSecondGalorCreated
		g_bSecondGalorCreated = TRUE
	else:
		return
	
#	kDebugObj.Print("Creating the second galor wave")
	
	#import E6M2_AI_Galor2_Geble
	import E6M2_AI_Galor3_Geble
	
	# Get the set
	pSet = App.g_kSetManager.GetSet("DeepSpace")
	
	# Create the second ship and assign AI
	pGalor2 = loadspacehelper.CreateShip("Galor", pSet, "Galor 2", "Galor1Enter")
	pGalor3 = loadspacehelper.CreateShip("Galor", pSet, "Galor 3", "Galor3Enter")
	
	pGalor3.SetAI(E6M2_AI_Galor3_Geble.CreateAI(pGalor3, g_pGalorGebleTargets, "Galor1Returns"))
	pGalor2.SetAI(E6M2_AI_Galor3_Geble.CreateAI(pGalor2, g_pGalorGebleTargets, "Galor2Enters"))
	
	# Call the dialogue that plays when Galor enters
	GalorReenterGeble()
	
################################################################################
##	GalorEntersGeble()
##
##	Called when Galor 1 is created in the Geble system.  Add the EngageCards
##	goal.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GalorEntersGeble():
	# Get the player and the set their in
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	# Make sure they are in Geble 3
	if (sSetName == "Geble3"):
		
		pSequence = App.TGSequence_Create()
		
		pFelixLine011	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2GalorAppears1", "Captain", 1, g_pMissionDatabase)
		pSaffiLine012	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2GalorAppears2", "Captain", 1, g_pMissionDatabase)
		
		pSequence.AddAction(pFelixLine011)
		pSequence.AppendAction(pSaffiLine012)
		
		pSequence.Play()
		
	# Add the engage Cards goal
	MissionLib.AddGoal("E6EngageCardsGoal")
	
################################################################################
##	GalorWarpOut()
##
##	Called when Galor 1 is chased out of Geble 3.  Called from
##	Exit set.  Removes the Engage Card goal
##
##	Args:	None
##
##	Return:	None
################################################################################
def GalorWarpOut():
	# Make sure the Galor survives the next few seconds.
	pGalor = App.ShipClass_GetObject(None, "Galor 1")
	if (pGalor == None):
		return
	# but only if the player is not in serris already
	if (g_bPlayerArriveSerris1 == FALSE):
		pGalor.SetInvincible(1)
	
	# Get the player and the set their in
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	# Make sure they are in Geble 3
	if (sSetName == "Geble3"):
		pSequence = App.TGSequence_Create()
	
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pFelixLine01	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2GalorRetreats1", "Captain", 1, g_pMissionDatabase)
		pKiskaLine02	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2GalorRetreats2", None, 0, g_pMissionDatabase)
		pMiguelLine03	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2GalorRetreats3", "Captain", 1, g_pMissionDatabase)
		pSaffiLine04	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2GalorRetreats4", None, 0, g_pMissionDatabase)
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pFelixLine01, 2)	# 2 sec delay while Galor is warping out
		pSequence.AppendAction(pKiskaLine02)
		pSequence.AppendAction(pMiguelLine03)
		pSequence.AppendAction(pSaffiLine04)
	
		pSequence.Play()
			
	# Remove the EngageCards goal
	MissionLib.RemoveGoal("E6EngageCardsGoal")
	
	# Check our flag, if second wave has not been made, start a timer to call them back
	if (g_bSecondGalorCreated == FALSE):
		fStartTime = App.g_kUtopiaModule.GetGameTime()
		MissionLib.CreateTimer(ET_SECOND_GALOR_TIMER, __name__+".CreateSecondGalor", fStartTime + 55, 0, 0)
		
################################################################################
##	GalorReenterGeble()
##
##	Called when Galor 2 and 3 enter Geble. Add the EngageCards
##	goal.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GalorReenterGeble():
	# Get the player and the set their in
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	# Make sure they are in Geble 3
	if (sSetName == "Geble3"):
		
		pSequence = App.TGSequence_Create()
		
		pFelixLine01	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2GalorsReturn1", "Captain", 1, g_pMissionDatabase)
		pFelixLine02	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2GalorsReturn2", None, 0, g_pMissionDatabase)
		
		pSequence.AppendAction(pFelixLine01, 10)
		pSequence.AppendAction(pFelixLine02)
		
		pSequence.Play()
		
	# Add the engage Cards goal
	MissionLib.AddGoal("E6EngageCardsGoal")
	

################################################################################
##	AllGeblePodsCaptured()
##
##	This script is  being called when all pods are docked in Geble 3.  Does the
##	sequence that lets the player know they can move on.  Also creates function
##	to create Dauntless in Serris 1.
##
##	Args:	
##
##	Return:	None
################################################################################
def AllGeblePodsCaptured():
	global g_sProdLine
	g_sProdLine = "E6M2Prod5"
	# Create the Dauntless
	CreateDauntless()
	
	pDBridgeSet	= App.g_kSetManager.GetSet("DBridgeSet")
	pJadeja		= App.CharacterClass_GetObject(pDBridgeSet, "Jadeja")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelLine02		= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2GebleClear2", "Captain", 1, g_pMissionDatabase)
	pKiskaLine03		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2GebleClear3", "Captain", 1, g_pMissionDatabase)
	pDBridgeViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Jadeja")
	if (g_bPlayerDockedPod == TRUE):
		pJadejaLine04		= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2GebleClear4", None, 0, g_pMissionDatabase)
	else:
		pJadejaLine04		= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2GebleClear4a", None, 0, g_pMissionDatabase)
	
	pKiskaLine05		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2GebleClear5", "Captain", 1, g_pMissionDatabase)
	pJadejaLine06		= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2GebleClear6", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pRestartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 25)	# 15 sec on prod timer
	pResetNightAI		= App.TGScriptAction_Create(__name__, "ResetNightAIForSerris")
		
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pMiguelLine02, 4)
	pSequence.AppendAction(pKiskaLine03)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pJadejaLine04)
	pSequence.AppendAction(pKiskaLine05)
	pSequence.AppendAction(pJadejaLine06)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pRestartProdTimer)
	pSequence.AppendAction(pResetNightAI)
		
	pSequence.Play()
	
	# Remove our RecoverPods goal and
	# add our Serris goal
	MissionLib.RemoveGoal("E6RecoverPodsGoal")
	MissionLib.AddGoal("E6HeadToSerris1Goal")
	# Remove the EngageCards goal
	MissionLib.RemoveGoal("E6EngageCardsGoal")

################################################################################
##	CreateDauntless()
##
##	Creates the Dauntless in the Serris 1 system.  Also damages it with script.
##	Also creates damaged hulk in serris 3.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateDauntless():
	
	# Get the transport's set
	pSerris3 = App.g_kSetManager.GetSet("Serris3")
	# Place the transport
	pTransport	= loadspacehelper.CreateShip("Transport", pSerris3, "Adams", "TransStart")
	
	# a damage script is imported and applied to the hulk.
	import AdamsDamaged
	AdamsDamaged.AddDamage(pTransport)	
	
	# Turn off the transport repair
	pRepair = pTransport.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)

	# Damage the transport...
	# Destroy the shield generator
	pShields = pTransport.GetShields()
	pTransport.DamageSystem(pShields, pShields.GetMaxCondition() / 1)

	# Damage the transport power Plant - 1287 pts of damage
	pTransport.DamageSystem(pTransport.GetPowerSubsystem(), 1287)
	# Damage the transport hull - 2000 pts of damage
	pTransport.DamageSystem(pTransport.GetHull(), 2000)
	
	pSystem = pTransport.GetTractorBeamSystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0.78)
	
	pSystem = pTransport.GetSensorSubsystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0.05)
		
	pSystem = pTransport.GetTorpedoSystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0.36)

	pSystem = pTransport.GetPhaserSystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0.49)
	
	# Spin the Transport slowly
	MissionLib.SetRandomRotation(pTransport, 3)
		
	# Get the dauntless' set
	pSet = App.g_kSetManager.GetSet("Serris1")
	# Place the ship
	pShip	= loadspacehelper.CreateShip("Galaxy", pSet, "Dauntless", "DauntlessStart")
	pShip.ReplaceTexture("data/Models/SharedTextures/FedShips/Dauntless.tga", "ID")
	#make it's splash damage = zero
	pShip.SetSplashDamage(0.0, pShip.GetRadius() * 4.0) 
	
	# Import our damaged script ship and apply it to the Dauntless
	import DauntlessDamaged
	DauntlessDamaged.AddDamage(pShip)
	
	# Turn off the ships repair
	pRepair = pShip.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)

	# Damage the ship...
	# Destroy the shield generator
	pShields = pShip.GetShields()
	pShip.DamageSystem(pShields, pShields.GetMaxCondition() / 1)

	# Damage the Power Planet - 5000 pts of damage
	pShip.DamageSystem(pShip.GetPowerSubsystem(), 5000)
	# Damage the hull - 11246 pts of damage
	pShip.DamageSystem(pShip.GetHull(), 11246)
	# Damage the Impulse engines - 0 pts each
	pImpulse = pShip.GetImpulseEngineSubsystem()
	pShip.DamageSystem(pImpulse.GetChildSubsystem(0), 2200)
	pShip.DamageSystem(pImpulse.GetChildSubsystem(1), 2400)
	pShip.DamageSystem(pImpulse.GetChildSubsystem(2), 2550)
	
	pSystem = pShip.GetTorpedoSystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, .45)
		
	pSystem = pShip.GetSensorSubsystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, 0.85)

	pSystem = pShip.GetPhaserSystem()
	if pSystem:
		MissionLib.SetConditionPercentage(pSystem, .37)
	
	# Spin the Daunless slowly
	MissionLib.SetRandomRotation(pShip, 1)
	
################################################################################
##	ResetNightAIForSerris()
##
##	Loads in a new AI for the Nightingale that it will use in the Serris
##	system.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ResetNightAIForSerris(pTGAction):
	
	#add serris to the helm menu
	import Systems.Serris.Serris
	Systems.Serris.Serris.CreateMenus()
	
#	kDebugObj.Print("Setting Nightingale AI to Serris")
	# Import the AI
	import E6M2_AI_Night_Serris
	# Get the ship and reset the AI
	pNight = App.ShipClass_GetObject(App.SetClass_GetNull(), "Nightingale")
	pNight.SetAI(E6M2_AI_Night_Serris.CreateAI(pNight))
	
	return 0

################################################################################
##	PlayerArrivesSerris3()
##
##	Called when the player first arrives in Serris3.  
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesSerris3():
	
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
	# If the player's sensors are off, we don't detect the Adams and set a flag
	pSensors = pPlayer.GetSensorSubsystem()
	global g_bSerris3SensorsOff
	if (pSensors == None):
		g_bSerris3SensorsOff = TRUE
	if (pSensors.IsOn() == FALSE):
		g_bSerris3SensorsOff = TRUE
		
	# play the right sequence based on our flag
	if (g_bSerris3SensorsOff == FALSE):
		pSequence = App.TGSequence_Create()
	
		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pKiskaLine01	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveOuterSerris1", "Captain", 1, g_pMissionDatabase)
		pMiguelLine02	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveOuterSerris2", None, 0, g_pMissionDatabase)
		pAdamsOnScreen	= App.TGScriptAction_Create(__name__, "AdamsOnScreen")
		pSaffiLine03	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveOuterSerris3", None, 0, g_pMissionDatabase)
		pMiguelLine04	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveOuterSerris4", None, 0, g_pMissionDatabase)
		
		pSequence.AppendAction(pPreLoad)
		pSequence.AppendAction(pKiskaLine01)
		pSequence.AppendAction(pMiguelLine02)
		pSequence.AppendAction(pAdamsOnScreen)
		pSequence.AppendAction(pSaffiLine03)
		pSequence.AppendAction(pMiguelLine04)
		
		pSequence.Play()
		
	if (g_bSerris3SensorsOff == TRUE):	
		pSequence = App.TGSequence_Create()
	
		pKiskaLine01	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveOuterSerris1", "Captain", 1, g_pMissionDatabase)
		pMiguelLine04	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveOuterSerris4", None, 0, g_pMissionDatabase)
		
		pSequence.AppendAction(pKiskaLine01)
		pSequence.AppendAction(pMiguelLine04)
		
		pSequence.Play()
	
###############################################################################
##
## AdamsOnScreen()
##
## Puts the Adams on the Viewscreen
##
##	Args:	pAction passed on from the sequence
##
##	Return:	return 0 to dismiss the pAction
################################################################################
def AdamsOnScreen(pAction):
	pSet = App.g_kSetManager.GetSet("Serris3")
	pAdams = App.ShipClass_GetObject(pSet, "Adams")

	MissionLib.ViewscreenWatchObject(pAdams)
		
	return 0

################################################################################
##	PlayerArrivesSerris1()
##
##	Called when the player first arrives in Serris1.  Starts the timer that
##	will call the Galors into action.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesSerris1():
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	
	pJadeja	= App.CharacterClass_GetObject(pDBridge, "Jadeja")
	pYi		= App.CharacterClass_GetObject(pDBridge, "Yi")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pDauntOnScreen	= App.TGScriptAction_Create(__name__, "DauntlessOnScreen")
	pFelixLine01	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveSerris1", "Captain", 1, g_pMissionDatabase)
	pSwapToGalaxy	= App.TGScriptAction_Create("MissionLib", "ReplaceBridgeTexture", "DBridgeSet", "NebulaLCARS.tga", "data/Models/Sets/DBridge/Map 7.tga")
	pDBridgeViewOn1	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Yi", 0.5, 1)
	pYiLine02		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE,  "E6M2ArriveSerris2", None, 0, g_pMissionDatabase)
	pJadejaLine03	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE,  "E6M2ArriveSerris3", None, 0, g_pMissionDatabase)
	pYiLine04		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveSerris4", None, 0, g_pMissionDatabase)
	pYiLine05		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveSerris5", None, 0, g_pMissionDatabase)
	pMiguelLine06	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveSerris6", None, 0, g_pMissionDatabase)
	pBrexLine07		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveSerris7", None, 0, g_pMissionDatabase)
	pJadejaLine08	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE,  "E6M2ArriveSerris8", None, 0, g_pMissionDatabase)
	pYiLine09		= App.CharacterAction_Create(pYi, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveSerris9", None, 0, g_pMissionDatabase)
	pJadejaLine10	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE,  "E6M2ArriveSerris10", None, 0, g_pMissionDatabase)
	pViewOff1		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSwapToNebula	= App.TGScriptAction_Create("MissionLib", "ReplaceBridgeTexture", "DBridgeSet", "Map 7.tga", "data/Models/Sets/DBridge/NebulaLCARS.tga")
	pDBridgeViewOn2	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Jadeja")
	pJadejaLine11	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2ArriveSerris11", None, 0, g_pMissionDatabase)
	pViewOff2		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pGalorsTimer	= App.TGScriptAction_Create(__name__, "SerrisGalorsTimer")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pDauntOnScreen)
	pSequence.AppendAction(pFelixLine01, 3)
	pSequence.AppendAction(pSwapToGalaxy)
	pSequence.AppendAction(pDBridgeViewOn1)
	pSequence.AppendAction(pYiLine02)
	pSequence.AppendAction(pJadejaLine03)
	pSequence.AppendAction(pYiLine04)
	pSequence.AppendAction(pYiLine05)
	pSequence.AppendAction(pMiguelLine06)
	pSequence.AppendAction(pBrexLine07)
	pSequence.AppendAction(pJadejaLine08)
	pSequence.AppendAction(pYiLine09)
	pSequence.AppendAction(pJadejaLine10)
	pSequence.AppendAction(pViewOff1)
	pSequence.AppendAction(pSwapToNebula)
	pSequence.AppendAction(pDBridgeViewOn2)
	pSequence.AppendAction(pJadejaLine11)
	pSequence.AppendAction(pViewOff2)
	pSequence.AppendAction(pGalorsTimer)
	
	pSequence.Play()
		
	# Remove the HeadToSerris goal
	MissionLib.RemoveGoal("E6HeadToSerris1Goal")

################################################################################
##	SerrisGalorsTimer()
##
##	Start the timer for the serris round of Cardassians
##
##	Args:	pAction	- Because it is called as a script action
##			
##	Return:	return 0 because the action that is passed on is unused
##	
################################################################################
def SerrisGalorsTimer(pAction):
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	MissionLib.CreateTimer(ET_GALORS_ENTER_SERRIS, __name__+".CreateSerrisGalors", fStartTime + 7, 0, 0)
	
	return 0

################################################################################
##	CreateSerrisGalor()
##
##	Creates Keldon 1 in DeepSpace, and resets the AI of Galor 1 so they both
##	warp into Serris 3
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CreateSerrisGalors(TGObject, pEvent):
	# Import the ship
	import ships.Keldon
	# Get the DeepSpace set
	pSet = App.g_kSetManager.GetSet("DeepSpace")
	# Get Galor 1
	pGalor1 = App.ShipClass_GetObject(App.SetClass_GetNull(), "Galor 1")
	pGalor1.SetInvincible(0)
	# Make Galor 1's impulse and warp engines NOT invincibale since it's done escapeing.
#	kDebugObj.Print ("Making Galor 1's Impulse and Warp Engines NOT invincible.")
	pWarp = pGalor1.GetWarpEngineSubsystem()
	pImpulse = pGalor1.GetImpulseEngineSubsystem()
	if (pWarp and pImpulse):
		MissionLib.MakeSubsystemsNotInvincible(pImpulse, pWarp)
	
	
	# Create the second Galor and assign AI's to both of them
	pKeldon1 = loadspacehelper.CreateShip("Keldon", pSet, "Keldon 1", "Galor2Start")
	# Import and assign our AI's
	import E6M2_AI_Galor1_Serris
	import E6M2_AI_Galor2_Serris
	pGalor1.SetAI(E6M2_AI_Galor1_Serris.CreateAI(pGalor1, g_pGalor1SerrisTargets))
	pKeldon1.SetAI(E6M2_AI_Galor2_Serris.CreateAI(pKeldon1, g_pGalor2SerrisTargets))
	
################################################################################
##	NightFiveSecondsAtDauntless()
##
##	Called from GettingDauntlessPassengers.py whenever the Nightingale is able
##	to keep it's shields down for five seconds while in orbit around the
##	Dauntless.  Icreases our counter and checks to see if enough time has
##	passed.
##
##	Args:	None
##
##	Return:	None
################################################################################
def NightFiveSecondsAtDauntless():
	# Get the player and the set their in
	pSet = MissionLib.GetPlayerSet()
	if (pSet == None):
		return
	sSetName	= pSet.GetName()
	# Make sure they are in Serris 1
	if (sSetName != "Serris1"):
		return
	
	# Increase our global counter and check and see if we've spent
	# enough time around the Dauntless
	global g_iTimeWithShieldsDown
	g_iTimeWithShieldsDown = g_iTimeWithShieldsDown + 1
	
	# See if its been about 5 minutes
	if (g_iTimeWithShieldsDown == 60):
		DauntlessClear(None, None)
		
################################################################################
##	GalorsEnterSerris1()
##
##	Called when Keldon 1 enters the Serris 1 system.  Add back our EngageCards
##	goal.
##
##	Args:	None
##
##	Return:	None
################################################################################
def GalorsEnterSerris1():
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixLine01	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2GalorsSerris1", "Captain", 0, g_pMissionDatabase)
	pBrexLine02		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M2GalorsSerris2", None, 0, g_pMissionDatabase)
	if (g_bGalor1Replaced == FALSE):
		pSaffiLine03	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2GalorsSerris3", None, 0, g_pMissionDatabase)
		pMiguelLine04	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2GalorsSerris4", None, 0, g_pMissionDatabase)	
		
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixLine01)
	pSequence.AppendAction(pBrexLine02)
	if (g_bGalor1Replaced == FALSE):
		pSequence.AppendAction(pSaffiLine03)
		pSequence.AppendAction(pMiguelLine04)
		
	pSequence.Play()
	
	# Add our EngageCards goal
	MissionLib.AddGoal("E6EngageCardsGoal")
	
################################################################################
##	DauntlessClear()
##
##	Called from NightFiveSecondsAtDauntless after the Nightingale has had it's
##	shields down for approx. 5 minutes.  Lets the player know they can leave the
##	system.  Also can be called by timer started if both Galors are destroyed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent
##
##	Return:	None
################################################################################
def DauntlessClear(TGObject, pEvent):
	# Check our flag
	if (g_bDauntlessCleared == FALSE):
		global g_bDauntlessCleared
		g_bDauntlessCleared = TRUE
	else:
		return
		
	# Make sure that the Nightingale exists
	if (g_bNightDestroyed == TRUE):
		return
		
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	pJadeja	= App.CharacterClass_GetObject(pDBridge, "Jadeja")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pCutsceneStart	= App.TGScriptAction_Create("MissionLib", "StartCutscene")
	pPlayerAI		= App.TGScriptAction_Create(__name__, "GivePlayerAI")
	pChangeToBridge	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pStartBridgeCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "bridge")
	pFelixCam1		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Kiska Head", "Kiska Cam")
	pFelixLine01	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2SerrisClear1", "Captain", 1, g_pMissionDatabase)
	pViewCam1		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "View", "Player Cam")
	pDBridgeViewOn1	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Jadeja")
	pJadejaLine02	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2SerrisClear2", None, 0, g_pMissionDatabase)
	pJadejaLine03	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2SerrisClear3", None, 0, g_pMissionDatabase)
	pFelixCam2		= App.TGScriptAction_Create("Actions.CameraScriptActions", "PlacementWatch", "bridge", "Felix Head", "Felix Cam")
	pFelixLine04	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2DauntlessDestroyed1", None, 0, g_pMissionDatabase)
	pChangeToSerris1	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "Serris1")
	pStartSerris1Camera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraBegin", "Serris1")
	pDauntlessCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "DropAndWatch", "Serris1", "Dauntless")
	pSelfDistruct	= App.TGScriptAction_Create(__name__, "DauntlessSelfDistructs")
	pSaffiOnScreen	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "gf013", None, 0, g_pGeneralDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pDauntOnScreen	= App.TGScriptAction_Create(__name__, "DauntlessOnScreen")
	pFelixLine05	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2DauntlessDestroyed2", "Captain", 1, g_pMissionDatabase)
	pBrexLine06		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E6M2DauntlessDestroyed3", None, 0, g_pMissionDatabase)
	pKiskaLine07	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2DauntlessDestroyed4", None, 0, g_pMissionDatabase)
	pEndSerris1Camera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "Serris1")
	pEndBridgeCamera	= App.TGScriptAction_Create("Actions.CameraScriptActions", "CutsceneCameraEnd", "bridge")
	pChangeToBridge2	= App.TGScriptAction_Create("Actions.CameraScriptActions", "ChangeRenderedSet", "bridge")
	pCutsceneEnd	= App.TGScriptAction_Create("MissionLib", "EndCutscene")
	pNoPlayerAI		= App.TGScriptAction_Create(__name__, "NoPlayerAI")
	pHeadBackToStarbase12	= App.TGScriptAction_Create(__name__, "HeadBackToStarbase12")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pCutsceneStart, 3)
	pSequence.AppendAction(pPlayerAI)
	pSequence.AppendAction(pChangeToBridge)
	pSequence.AppendAction(pStartBridgeCamera)
	pSequence.AppendAction(pFelixCam1)
	pSequence.AppendAction(pFelixLine01, 0.5)
	pSequence.AppendAction(pViewCam1)
	pSequence.AppendAction(pDBridgeViewOn1)
	pSequence.AddAction(pJadejaLine02, pDBridgeViewOn1)
	pSequence.AddAction(pJadejaLine03, pJadejaLine02)
	pSequence.AppendAction(pFelixCam2)
	pSequence.AddAction(pFelixLine04, pFelixCam2)
	pSequence.AppendAction(pChangeToSerris1)
	pSequence.AppendAction(pStartSerris1Camera)
	pSequence.AppendAction(pDauntlessCamera)
	pSequence.AppendAction(pSelfDistruct, 2)
	pSequence.AddAction(pSaffiOnScreen, pSelfDistruct)
	pSequence.AddAction(pViewOff, pSaffiOnScreen)
	pSequence.AppendAction(pDauntOnScreen)
	pSequence.AppendAction(pFelixLine05, 8)
	pSequence.AddAction(pBrexLine06, pFelixLine05)
	pSequence.AddAction(pKiskaLine07, pBrexLine06)
	pSequence.AppendAction(pEndSerris1Camera)
	pSequence.AppendAction(pEndBridgeCamera)
	pSequence.AppendAction(pChangeToBridge2)
	pSequence.AppendAction(pNoPlayerAI)
	pSequence.AppendAction(pCutsceneEnd)
	pSequence.AppendAction(pHeadBackToStarbase12)
	
	MissionLib.QueueActionToPlay(pSequence)
	
	# Remove the EngageCardsGoal
	MissionLib.RemoveGoal("E6EngageCardsGoal")
	
################################################################################
##	GivePlayerAI()
##
##	Gives the player an AI for the cutscene 
##
##	Args:	pAction	- Because it is called as a script action
##			
##	Return:	return 0 because the action that is passed on is unused
##	
################################################################################
def GivePlayerAI(pAction):
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
	
	# assign the AI
	import AI.Player.DefenseNoTarget
	MissionLib.SetPlayerAI("Tactical", AI.Player.DefenseNoTarget.CreateAI(pPlayer))
	
	return 0	
	
################################################################################
##	NoPlayerAI()
##
##	Gives the player a stay AI after the cutscene 
##
##	Args:	pAction	- Because it is called as a script action
##			
##	Return:	return 0 because the action that is passed on is unused
##	
################################################################################
def NoPlayerAI(pAction):
	# Get the player
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return 0
	
	# assign the AI
	import AI.Player.Stay
	MissionLib.SetPlayerAI("Tactical", AI.Player.Stay.CreateAI(pPlayer))
	
	return 0	
	
###############################################################################
##
## DauntlessOnScreen()
##
## Puts the Dauntless ship on the Viewscreen
##
##	Args:	pAction passed on from the sequence
##
##	Return:	return 0 to dismiss the pAction
################################################################################
def DauntlessOnScreen(pAction):
	pSet = App.g_kSetManager.GetSet("Serris1")
	pDauntless = App.ShipClass_GetObject(pSet, "Dauntless")

	MissionLib.ViewscreenWatchObject(pDauntless)
		
	return 0
	
###############################################################################
##
## DauntlessSelfDistructs()
##
## This function will causethe dauntless to self-distruct.
##
## Args: pTGAction	- The script action object.
##
## Return: return 0 - to dismiss the pTGAction
##
################################################################################
def DauntlessSelfDistructs(pTGAction):
#	kDebugObj.Print("The Dauntless has run out of juice")
		
	pSet = App.g_kSetManager.GetSet("Serris1")
	pDauntless = App.ShipClass_GetObject(pSet, "Dauntless")
	pSystem = pDauntless.GetHull()
	if (pSystem):
		pDauntless.DamageSystem(pSystem, 15000)	
	return 0

################################################################################
##	HeadBackToStarbase12()
##
##	Will be called
##	after Serris system  Constitutes a
##	"mission win" and calls function to link us to E6M3.
##
##	Args:	pTGAction	- The script action object
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def HeadBackToStarbase12(pTGAction):
	global g_sProdLine
	g_sProdLine = "E6HeadHomeGoalAudio"
	
	# Set our flag
	global g_bHeadingToStarbase12
	g_bHeadingToStarbase12 = TRUE
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pKiskaLine01	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2Complete1", None, 0, g_pMissionDatabase)
	pSaffiLine02	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2Complete2", "Captain", 1, g_pMissionDatabase)
	pResetNightAI	= App.TGScriptAction_Create(__name__, "ResetNightAIForStarbase")
	pRestartProd	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)	# 30sec prod timer
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pKiskaLine01)
	pSequence.AppendAction(pSaffiLine02)
	pSequence.AppendAction(pResetNightAI)
	pSequence.AppendAction(pRestartProd)
	
	MissionLib.QueueActionToPlay(pSequence)
	
	# Call our function to link us to E6M3 in the "Helm" menu
	LinkToE6M3()
	
	# Add the HeadHome goal to the objectives
	MissionLib.AddGoal("E6HeadHomeGoal")
	
	return 0
	
################################################################################
##	ResetNightAIForStarbase()
##
##	Resets the Nightingale's AI so it warps to Starbase12
##
##	Args:	pTGAction	- The script action object
##
##	Return:	0	- Return 0 to keep calling object from crashing.
################################################################################
def ResetNightAIForStarbase(pTGAction):
#	kDebugObj.Print("Setting Nightingale AI to Starbase")
	# Get the ship
	pNight	= App.ShipClass_GetObject(App.SetClass_GetNull(), "Nightingale")
	# Import the AI and assign
	import E6M2_AI_Night_Starbase
	pNight.SetAI(E6M2_AI_Night_Starbase.CreateAI(pNight))
	
	return 0

################################################################################
##	NightUnderFire()
##
##	Called by Nightingale if they come under fire from one of the Galors.
##	Playes sequence from Jadeja.  Uses g_bNightUnderFireCalled to see if
##	sequence can play.
##
##	Args:	None
##
##	Return:	None
################################################################################
def NightUnderFire():
#	kDebugObj.Print("NightUnderFire")
	# first check if the dauntless is clear, return if it is.
	if (g_bDauntlessCleared == TRUE):
		return
	
	# Check our flag
	if (g_bNightUnderFireCalled == FALSE):
		global g_bNightUnderFireCalled
		g_bNightUnderFireCalled = TRUE
	else:
		return
	
	pcLine = MissionLib.GetRandomLine(["E6M2NightAttacked2", "E6M2NightAttacked3"])
	
	pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
	pJadeja		= App.CharacterClass_GetObject(pDBridge, "Jadeja")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixCombat1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2NightAttacked1", None, 0, g_pMissionDatabase)
	pKiskaIncomming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", None, 0, g_pGeneralDatabase)
	pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Jadeja")
	pJadejaLine033	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, pcLine, None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixCombat1)
	pSequence.AppendAction(pKiskaIncomming, 1)
	pSequence.AppendAction(pDBridgeViewOn)
	pSequence.AppendAction(pJadejaLine033)
	pSequence.AppendAction(pViewOff)
	
	MissionLib.QueueActionToPlay(pSequence)


################################################################################
##	NightUnderFire2()
##
##	Called by Nightingale if they come under fire from Galor 2 in gebble.
##	 Uses g_bNightUnderFire2Called to see if
##	sequence can play.
##
##	Args:	None
##
##	Return:	None
################################################################################
def NightUnderFire2():
#	kDebugObj.Print("NightUnderFire2")
	# first check if the dauntless is clear, return if it is.
	if (g_bDauntlessCleared == TRUE):
		return
	
	if (g_bNightUnderFire2Called == FALSE):
		global g_bNightUnderFire2Called
		g_bNightUnderFire2Called = TRUE
	
		# Do our sequence
		pSequence = App.TGSequence_Create()

		pMiguelCombat1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E6M2Combat6", None, 0, g_pMissionDatabase)
		pKiskaCombat1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E6M2Combat7", None, 0, g_pMissionDatabase)
		
		pSequence.AppendAction(pMiguelCombat1, 1)
		pSequence.AppendAction(pKiskaCombat1)

		MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	NightTakingDamage()
##
##	Called from the Nightingale AIs when they takes damage.  Uses
##	bNightTakingDamageCalled to see if the sequence can play.
##
##	Args:	None
##
##	Return:	None
################################################################################
def NightTakingDamage():
	
	# first check if the dauntless is clear, return if it is.
	if (g_bDauntlessCleared == TRUE):
		return
	
	if (g_bNightTakingDamageCalled == FALSE):
		global g_bNightTakingDamageCalled
		g_bNightTakingDamageCalled = TRUE
		
		# Do our sequence
		pDBridge	= App.g_kSetManager.GetSet("DBridgeSet")
		pJadeja	= App.CharacterClass_GetObject(pDBridge, "Jadeja")

		pSequence = App.TGSequence_Create()

		App.TGActionManager_RegisterAction(pSequence, "Jadeja")

		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
		pFelixLine036	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2NightDamaged2", "Captain", 1, g_pMissionDatabase)
		pDBridgeViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DBridgeSet", "Jadeja")
		pJadejaLine037	= App.CharacterAction_Create(pJadeja, App.CharacterAction.AT_SAY_LINE, "E6M2NightDamaged1", None, 0, g_pMissionDatabase)
		pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

		pSequence.AppendAction(pPreLoad)
		pSequence.AddAction(pFelixLine036)
		pSequence.AddAction(pDBridgeViewOn, pFelixLine036)
		pSequence.AddAction(pJadejaLine037, pDBridgeViewOn)
		pSequence.AddAction(pViewOff, pJadejaLine037)

		MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	LinkToE6M3()
##
##	Creates to E6M3 through "Starbase 12" in helm menu.
##
##	Args:	None
##
##	Return:	None
################################################################################
def LinkToE6M3():
	import Systems.Starbase12.Starbase
	# Create the menu and link it.
	pStarbaseMenu = Systems.Starbase12.Starbase.CreateMenus()
	pStarbaseMenu.SetMissionName("Maelstrom.Episode6.E6M3.E6M3")

################################################################################
##	PodLost()
##
##	Called When an escape Pod is destroyed. 
##  
##
##	Args:	None
##
##	Return:	None
################################################################################
def PodLost():
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "PodLost")
	
	pFelixLine01		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2PodLost1", None, 0, g_pMissionDatabase)
	pSaffiLine02		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2PodLost2", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AddAction(pFelixLine01)
	pSequence.AddAction(pSaffiLine02, pFelixLine01)
		
	pSequence.Play()
	
################################################################################
##	MissionLost()
##
##	Called if Nightingale is destroyed.
##
##	Args:	None
##
##	Return:	None
################################################################################
def MissionLost():
	#kill any registered sequences
	App.TGActionManager_KillActions()
	
	pStarbase	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu	= App.CharacterClass_GetObject(pStarbase, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixLine01	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed1", "Captain", 1, g_pMissionDatabase)
	pFelixIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg6", "Captain", 1, g_pGeneralDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLine02		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed2", None, 0, g_pMissionDatabase)
	pLiuLine03		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed3", None, 0, g_pMissionDatabase)
	pLiuLine04		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed4", None, 0, g_pMissionDatabase)
	pLiuLine05		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed5", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixLine01)
	pSequence.AppendAction(pFelixIncoming, 4)	# 4 sec delay before Liu hails
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuLine02)
	pSequence.AppendAction(pLiuLine03)
	pSequence.AppendAction(pLiuLine04)
	pSequence.AppendAction(pLiuLine05)
	pSequence.AppendAction(pViewOff)
		
	# Do the cutscene stuff to end the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()
	
	return 0
	
################################################################################
##	DauntlessMissionLost()
##
##	Called if Dauntless is destroyed before self-dustructing.
##
##	Args:	None
##
##	Return:	None
################################################################################
def DauntlessMissionLost():
	#kill any registered sequences
	App.TGActionManager_KillActions()
	
	pStarbase	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu	= App.CharacterClass_GetObject(pStarbase, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pFelixLine01	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E6M2DauntlessDestroyed1", "Captain", 1, g_pMissionDatabase)
	pFelixIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg6", "Captain", 1, g_pGeneralDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLine02		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2DauntlessDestroyed5", None, 0, g_pMissionDatabase)
	pLiuLine03		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed3", None, 0, g_pMissionDatabase)
	pLiuLine04		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed4", None, 0, g_pMissionDatabase)
	pLiuLine05		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed5", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pFelixLine01)
	pSequence.AppendAction(pFelixIncoming, 4)	# 4 sec delay before Liu hails
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuLine02)
	pSequence.AppendAction(pLiuLine03)
	pSequence.AppendAction(pLiuLine04)
	pSequence.AppendAction(pLiuLine05)
	pSequence.AppendAction(pViewOff)
		
	# Do the cutscene stuff to end the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()
	
	return 0

################################################################################
##	PodMissionLost()
##
##	Called if two pods are lost
##
##	Args:	None
##
##	Return:	None
################################################################################
def PodMissionLost():
	#kill any registered sequences
	App.TGActionManager_KillActions()
	
	pStarbase	= App.g_kSetManager.GetSet("StarbaseSet")
	pLiu	= App.CharacterClass_GetObject(pStarbase, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	App.TGActionManager_RegisterAction(pSequence, "ViewscreenOn")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pSaffiLine01	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E6M2PodLost3", "Captain", 1, g_pMissionDatabase)
	pFelixIncoming	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg5", "Captain", 1, g_pGeneralDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLine02		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2PodLost4", None, 0, g_pMissionDatabase)
	pLiuLine03		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed3", None, 0, g_pMissionDatabase)
	pLiuLine04		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed4", None, 0, g_pMissionDatabase)
	pLiuLine05		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E6M2NightDestroyed5", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AppendAction(pPreLoad)
	pSequence.AppendAction(pSaffiLine01)
	pSequence.AppendAction(pFelixIncoming, 4)	# 4 sec delay before Liu hails
	pSequence.AppendAction(pStarbaseViewOn)
	pSequence.AppendAction(pLiuLine02)
	pSequence.AppendAction(pLiuLine03)
	pSequence.AppendAction(pLiuLine04)
	pSequence.AppendAction(pLiuLine05)
	pSequence.AppendAction(pViewOff)
		
	# Do the cutscene stuff to end the mission
	pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()
	
	return 0

	
################################################################################
##	ProdPlayer()
##
##	Prods player with audio if not completing mission goals
##
##	Args:	TGObject	- TGObject object
##			pEvent		- Event sent to object
##
##	Return:	None
################################################################################
def ProdPlayer(TGObject, pEvent):
#	kDebugObj.Print("Prodding player")
	# Check and see what prodding line we need to play and restart the prod.
	if (g_sProdLine == "E6M2Prod2") and (g_bPlayerArriveGeble4 == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 25)
	elif (g_sProdLine == "E6M2Prod6") and (g_bPlayerArriveGeble3 == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 25)
	elif (g_sProdLine == "E6M2Prod5") and (g_bPlayerArriveSerris1 == FALSE):
		g_pSaffi.SpeakLine(g_pMissionDatabase, g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 25)
	elif (g_sProdLine == "E6HeadHomeGoalAudio"):
		g_pSaffi.SpeakLine(MissionLib.GetEpisode().GetDatabase(), g_sProdLine, App.CSP_MISSION_CRITICAL)
		RestartProdTimer(None, 25)

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
#	print "Trying to stop the HurryUp timer..."
	global g_iProdTimer
	if (g_iProdTimer != App.NULL_ID):
#		print "Timer exists with ID %d.  Removing it." % g_iProdTimer
		bSuccess = App.g_kTimerManager.DeleteTimer(g_iProdTimer)
#		if bSuccess:
#			print "Successfully removed."
#		else:
#			print "Failed to remove timer.  Prod warning may trigger inappropriately.  :("
		g_iProdTimer = App.NULL_ID

################################################################################
##	RestartProdTimer()
##
##	Starts a timer to prod the player.
##
##	Args:	pTGAction	- The script action object.
##			iTime		- The length of time in seconds that the timer will run for.
##
##	Return:	None
################################################################################
def RestartProdTimer(pTGActon, iTime):
#	print "Creating prod timer for %d seconds." % iTime

	# Stop the old prod timer.
	StopProdTimer()

	# Start a new prod timer.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_PROD_TIMER, __name__+".ProdPlayer", fStartTime + iTime, 0, 0)
	# Save the ID of the prod timer, so we can stop it later.
	global g_iProdTimer
	g_iProdTimer = pTimer.GetObjID()
#	print "New prod timer ID is " + str(g_iProdTimer)

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
#	kDebugObj.Print ("Terminating Episode 6, Mission 2.\n")
	
	# Delete all our mission goals
	MissionLib.DeleteAllGoals()
	
	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()
	
	# Remove all of our instance handlers
	RemoveInstanceHandlers()

	# Mission is terminating, so lets set our flag
	global g_bMissionTerminate
	g_bMissionTerminate = TRUE

	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if(g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# unload the database: "data/TGL/Bridge Menus.tgl"
	if(g_pDatabase):
		App.g_kLocalizationManager.Unload(g_pDatabase)
	
	# now remove any remaining ships in the warp set
	MissionLib.DeleteShipsFromWarpSetExceptForMe()
	
	StopProdTimer()

################################################################################
##	RemoveInstanceHandlers()
##
##	Remove any instance handlers we've registered in this mission.
##
##	Args:	None
##
##	Return:	None
################################################################################
def RemoveInstanceHandlers():
	# Instance handlers on the mission for friendly fire warnings and game over
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".PlayerFiringOnFriend")
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".PlayerStillFiringOnFriend")

	pHelmMenu	= g_pKiska.GetMenu()
	pHelmMenu.RemoveHandlerForInstance(App.ET_SET_COURSE, __name__ + ".SetCourse")
	
	# Remove instance handler on players ship for Weapon Fired event
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		pPlayer.RemoveHandlerForInstance(App.ET_WEAPON_FIRED, __name__+".PlayerWeaponFired")
	
	# Remove instance handler for Kiska's Hail button
	pMenu = g_pKiska.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_HAIL, __name__ + ".HailHandler")
	
	# and her Warp button
	pWarpButton = Bridge.BridgeUtils.GetWarpButton()
	pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")
	
	pSciMenu	= g_pMiguel.GetMenu()
	pSciMenu.RemoveHandlerForInstance(App.ET_SCAN, __name__ + ".ScanHandler")
	
	pMenu = g_pSaffi.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
	pMenu = g_pFelix.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = g_pKiska.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = g_pMiguel.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	pMenu = g_pBrex.GetMenu()
	pMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
