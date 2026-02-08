###############################################################################
#	Filename:	E2M1.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Episode 2, Mission 1
#	
#	Created:	11/3/00 -	Jess VanDerwalker (revised)
###############################################################################
import App
import loadspacehelper
import MissionLib
import Maelstrom.Maelstrom
import Bridge.BridgeUtils
import Bridge.XOCharacterHandlers
import Maelstrom.Episode2.Episode2
import Maelstrom.Episode2.AI_WarpOut
import Actions.MissionScriptActions
import DynamicMusic

# Declare global variables here
TRUE				= 1
FALSE				= 0

g_pMissionDatabase 	= None
g_pGeneralDatabase 	= None
g_pDatabase			= None

g_bMissionTerminate	= None

g_iProdTimer			= None
g_iProdToSOS			= None
g_bPlayerNotInBeol		= None
g_iProdToBeolCounter	= None

g_iMissionState	= None
DEFAULT			= None
SOS_RECEIVED	= None
PLAYER_BEOL		= None
KAROON_DRIFTING	= None
WARBIRD_ATTACK	= None
GEKI_SUPPLY		= None
IN_VESUVI		= None

g_bPlayerArriveVesuvi6	= None
g_bPlayerArriveGeki		= None
g_bPlayerArriveBeol		= None
g_bPlayerInOrbit		= None
g_bGekiHailed			= None
g_bBeamingSupplies		= None
g_bPlayerReceivedSOS	= None
g_bGekiSupplied			= None

g_bBeolShipsCreated		= None
g_bShipOnListPlayed		= None
g_bShipsIDd				= None
g_bShipIDdCalled		= None
g_bBeolEntryPlayed		= None
g_bPlayerTriedHail		= None
g_bWarbirdHailed		= None
g_bKaroonScanned		= None
g_bFirstCloak			= None
g_bKaroonHitAsteroid	= None
g_bKaroonTractored		= None
g_bKaroonStopped		= None
g_bSecondCloak			= None
g_bKaroonDestroyed		= None
g_bSOSCompleted			= None
g_bWarbirdAttacksKaroon	= None
g_bLiuHailDone			= None

g_idVelocityTimer	= None

g_fCloakNormalPower	= None
g_bCloakPowerReset	= None

g_pKiska	= None
g_pFelix	= None
g_pSaffi	= None
g_pMiguel	= None
g_pBrex		= None

# Event Types for mission
ET_PROD_TIMER				= App.Mission_GetNextEventType()
ET_KAROON_VELOCITY_CHECK	= App.Mission_GetNextEventType()

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
	loadspacehelper.PreloadShip("Sovereign", 1)
	loadspacehelper.PreloadShip("Ambassador", 1)
	loadspacehelper.PreloadShip("FedStarbase", 1)
	loadspacehelper.PreloadShip("FedOutpost", 2)
	loadspacehelper.PreloadShip("Freighter", 2)
	loadspacehelper.PreloadShip("CardFreighter", 1)
	loadspacehelper.PreloadShip("E2M0Warbird", 1)
	loadspacehelper.PreloadShip("CommLight", 2)
	loadspacehelper.PreloadShip("Asteroid", 5)
	loadspacehelper.PreloadShip("Asteroid1", 4)
	loadspacehelper.PreloadShip("Asteroid2", 4)
	loadspacehelper.PreloadShip("Asteroid", 3)
	

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
	"Event handler called on episode start.  Create the episode objects here."
	# Initialize all our global variables
	InitializeGlobals(pMission)
	
	# Create Regions
	CreateStartingRegions()
	
	# Specify (and load if necessary) our bridge
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")
	
	# Create needed sets for viewscreen
	CreateSets()

	# Initialize global pointers to the bridge crew
	InitializeCrewPointers()

	# Create menus available at mission start
	CreateStartingMenus()

	# Start the friendly fire watches
	MissionLib.SetupFriendlyFire()
	
	# Create the starting objects
	CreateStartingObjects(pMission)

	# Create the range check around Geki planet
	CreatePlanetProximityCheck(pMission)
	
	# Setup more mission-specific events.
	SetupEventHandlers(pMission)

	# Set the stats on the players ship
	App.Game_SetDifficultyMultipliers(1.25, 1.4, 1.0, 1.3, 0.75, 1.1)

	# Set the torp load of the Starbase
	MissionLib.SetTotalTorpsAtStarbase("Photon", -1)

	# Add our goal
	MissionLib.AddGoal("E2SupplyCeli5Goal")

	# Start the mission
	PlayPlayerArrivesHaven()
	
	# Save the game
	MissionLib.SaveGame("E2M1-")
	
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

	# Set g_bMissionTerminate here in case mission gets reloaded
	global g_bMissionTerminate
	g_bMissionTerminate = 1

	# TGL database globals.
	global g_pMissionDatabase
	global g_pGeneralDatabase
	global g_pDatabase
	g_pMissionDatabase 	= pMission.SetDatabase("data/TGL/Maelstrom/Episode 2/E2M1.tgl")
	g_pGeneralDatabase	= App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	g_pDatabase 		= App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Counters used in prodding player and running sequences
	global g_iProdTimer
	global g_iProdToSOS
	global g_bPlayerNotInBeol
	global g_iProdToBeolCounter

	g_iProdTimer			= App.NULL_ID
	g_iProdToSOS			= 0
	g_bPlayerNotInBeol		= FALSE
	g_iProdToBeolCounter	= 0
	
	# Globals used in the Communicate functions
	global g_iMissionState
	global DEFAULT
	global SOS_RECEIVED
	global PLAYER_BEOL
	global WARBIRD_ATTACK
	global KAROON_DRIFTING
	global GEKI_SUPPLY
	global IN_VESUVI

	g_iMissionState	= 0
	DEFAULT			= 0
	SOS_RECEIVED	= 1
	PLAYER_BEOL		= 2
	WARBIRD_ATTACK	= 3
	KAROON_DRIFTING	= 4
	GEKI_SUPPLY		= 5
	IN_VESUVI		= 6
	
	# Flags used to track player
	global g_bPlayerArriveVesuvi6
	global g_bPlayerArriveGeki
	global g_bPlayerArriveBeol
	
	g_bPlayerArriveVesuvi6	= FALSE
	g_bPlayerArriveGeki		= FALSE
	g_bPlayerArriveBeol		= FALSE
	
	# Flags used for mission events
	global g_bPlayerInOrbit
	global g_bGekiHailed
	global g_bBeamingSupplies
	global g_bShipOnListPlayed
	global g_bShipsIDd
	global g_bShipIDdCalled
	global g_bBeolEntryPlayed
	global g_bPlayerTriedHail
	global g_bWarbirdHailed
	global g_bKaroonScanned
	global g_bFirstCloak
	global g_bKaroonHitAsteroid
	global g_bKaroonTractored
	global g_bKaroonStopped
	global g_bSecondCloak
	global g_bKaroonDestroyed
	global g_bSOSCompleted
	global g_bPlayerReceivedSOS
	global g_bBeolShipsCreated
	global g_bGekiSupplied
	global g_bWarbirdAttacksKaroon
	global g_bLiuHailDone
	
	g_bPlayerInOrbit		= FALSE
	g_bGekiHailed			= FALSE
	g_bBeamingSupplies		= FALSE
	g_bShipOnListPlayed		= FALSE
	g_bShipsIDd				= FALSE
	g_bShipIDdCalled		= FALSE
	g_bBeolEntryPlayed		= FALSE
	g_bPlayerTriedHail		= FALSE
	g_bWarbirdHailed		= FALSE
	g_bKaroonScanned		= FALSE
	g_bFirstCloak			= FALSE
	g_bKaroonHitAsteroid	= FALSE
	g_bKaroonTractored		= FALSE
	g_bKaroonStopped		= FALSE
	g_bSecondCloak			= FALSE
	g_bKaroonDestroyed		= FALSE
	g_bSOSCompleted			= FALSE
	g_bPlayerReceivedSOS	= FALSE
	g_bBeolShipsCreated		= FALSE
	g_bGekiSupplied			= FALSE
	g_bWarbirdAttacksKaroon	= FALSE
	g_bLiuHailDone			= FALSE

	# Global ID for the timer used to check
	# the Karoons velocity
	global g_idVelocityTimer
	g_idVelocityTimer	= App.NULL_ID
	
	# Global used to hold the original power consumption
	# value of the Warbirds bloaking device.
	global g_fCloakNormalPower
	global g_bCloakPowerReset
	g_fCloakNormalPower = 1
	g_bCloakPowerReset	= FALSE
	
	# Set our limits for the friendly fire warnings and game loss
	App.g_kUtopiaModule.SetMaxFriendlyFire(3000)			# how many damage points the player can do total before losing
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(400)	# how many damage points before Saffi warns you

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
	# Create Starbase12
	pStarbaseSet	= MissionLib.SetupSpaceSet("Systems.Starbase12.Starbase12")
	# Create Vesuvi6
	pVesuvi6Set		= MissionLib.SetupSpaceSet("Systems.Vesuvi.Vesuvi6")
	# Create Vesuvi 5
	pVesuvi5Set		= MissionLib.SetupSpaceSet("Systems.Vesuvi.Vesuvi5")
	#Create Beol4
	pBeolSet		= MissionLib.SetupSpaceSet("Systems.Beol.Beol4")
	# Create Serris3
	pSerrisSet		= MissionLib.SetupSpaceSet("Systems.Serris.Serris3")
	
	# Add our custom placement objects for this mission.
	import E2M1_Vesuvi6_P
	E2M1_Vesuvi6_P.LoadPlacements(pVesuvi6Set.GetName())
	
	import E2M1_Beol4_P
	E2M1_Beol4_P.LoadPlacements(pBeolSet.GetName())
	
################################################################################
##	CreateSet()
##
##	Loads and populates the sets that we'll need for the viewscreen.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateSets():
	# Starbase set with Liu and Takahara
	pStarbaseSet	= MissionLib.SetupBridgeSet("StarbaseSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -30, 65, -1.55)
	pLiu			= MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "StarbaseSet", 0, 0, 5)

	# Takahara on the D-Bridge engineering
	pDEngSet		= MissionLib.SetupBridgeSet("DEngSet", "data/Models/Sets/GalaxyEng/GalaxyEng.nif", -30, 65, -1.55)
	pTakahara		= MissionLib.SetupCharacter("Bridge.Characters.Takahara", "DEngSet")


	# Cardassian bridge and Card Capt.
	pCardSet	= MissionLib.SetupBridgeSet("CardSet", "data/Models/Sets/Cardassian/cardbridge.NIF", -30, 65, -1.55)
	pCardCapt	= MissionLib.SetupCharacter("Bridge.Characters.CardCapt", "CardSet")

	# Romulan set with Torenn
	MissionLib.SetupBridgeSet("RomulanSet", "data/Models/Sets/Romulan/romulanbridge.nif", -40, 65, -1.55, 0, -280, 0)
	MissionLib.SetupCharacter("Bridge.Characters.Torenn", "RomulanSet", 0, 0, 1)

################################################################################
##	CreateStartingMenus()
##	
##  Creates menu items for systems we need at mission start in the "Helm" menu.
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def CreateStartingMenus ():
	import Systems.Starbase12.Starbase
	import Systems.Vesuvi.Vesuvi
	
	Systems.Vesuvi.Vesuvi.CreateMenus()
	Systems.Starbase12.Starbase.CreateMenus()
	
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
	# Setup ship affiliations
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Starbase 12")
	pFriendlies.AddName("Karoon")
	pFriendlies.AddName("Facility")
	pFriendlies.AddName("Freighter 1")
	pFriendlies.AddName("Freighter 2")
	pFriendlies.AddName("GekiStation") 
	pFriendlies.AddName("GekiSatellite1") 
	pFriendlies.AddName("GekiSatellite2") 
	
	pNeutral = pMission.GetNeutralGroup()
	pNeutral.AddName("Warbird")
	
	# Make the Karoon tractorable
	pTractorGroup = pMission.GetTractorGroup()
	pTractorGroup.AddName("Karoon")
	
	# Get the sets we need 
	pStarbaseSet	= App.g_kSetManager.GetSet("Starbase12")
	pVesuvi6Set		= App.g_kSetManager.GetSet("Vesuvi6")
	pVesuvi5Set		= App.g_kSetManager.GetSet("Vesuvi5")
		
	# Create other objects we need.
	pPlayer			= MissionLib.CreatePlayerShip("Galaxy", pVesuvi6Set, "player", "Player Start")
	pStarbase		= loadspacehelper.CreateShip("FedStarbase", pStarbaseSet, "Starbase 12", "Starbase12 Location")
	# Create the asteroids
	CreateAsteroids()
	# Create the station and ships for Vesuvi 6
	CreateVesuvi6Ships(pVesuvi6Set)

################################################################################
##	CreateAsteroids()
##
##	Create the mission specific asteroids in Beol 4.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateAsteroids():
	# Get the set we need
	pSet = App.g_kSetManager.GetSet("Beol4")
	
	# Create a dictionary with the various asteroid stats
	#						Name,			Type,	   Scale,	 Placement
	dAsteroidStats	=	{
						"Asteroid 0":	["Asteroid",	13.1,	"AsteroidP 0"],
						"Asteroid 1":	["Asteroid1",	21.0,	"AsteroidP 1"],
						"Asteroid 2":	["Asteroid2",	9.0,	"AsteroidP 2"],
						"Asteroid 3":	["Asteroid",	15.0,	"AsteroidP 3"],
						"Asteroid 4":	["Asteroid",	14.2,	"AsteroidP 4"],
						"Asteroid 5":	["Asteroid1",	22.0,	"AsteroidP 5"],
						"Asteroid 6":	["Asteroid2",	6.5,	"AsteroidP 6"],
						"Asteroid 7":	["Asteroid3",	4.2,	"AsteroidP 7"],
						"Asteroid 8":	["Asteroid",	15.0,	"AsteroidP 8"],
						"Asteroid 9":	["Asteroid1",	18.0,	"AsteroidP 9"],
						"Asteroid 10":	["Asteroid2",	10.0,	"AsteroidP 10"],
						"Asteroid 11":	["Asteroid3",	5.0,	"AsteroidP 11"],
						"Asteroid 12":	["Asteroid",	15.1,	"AsteroidP 12"],
						"Asteroid 13":	["Asteroid1",	20.0,	"AsteroidP 13"],
						"Asteroid 14":	["Asteroid2",	8.5,	"AsteroidP 14"],
						"Asteroid 15":	["Asteroid3",	3.5,	"AsteroidP 15"],
					}

	# Go through the dictionary and create the asteroids
	lAsteroidKeys = dAsteroidStats.keys()
	for sAsteroid in lAsteroidKeys:
		pAsteroid = loadspacehelper.CreateShip(dAsteroidStats[sAsteroid][0], pSet, sAsteroid, dAsteroidStats[sAsteroid][2])
		if (pAsteroid != None):
			pAsteroid.SetScale(dAsteroidStats[sAsteroid][1])
			pAsteroid.SetTargetable(FALSE)
			pAsteroid.SetHailable(FALSE)
			pAsteroid.SetStatic(TRUE)
			pAsteroid.SetScannable(FALSE)

################################################################################
##	CreateVesuvi6Ships()
##
##	Creates the Orbital facility in Haven and a couple of transports.
##
##	Args:	pSet	- The Vesuvi6 set object.
##
##	Return:	None
################################################################################
def CreateVesuvi6Ships(pSet):
	pFreighter1	= loadspacehelper.CreateShip("Freighter", pSet, "Freighter 1", "Freighter1Start")
	pFreighter2	= loadspacehelper.CreateShip("Freighter", pSet, "Freighter 2", "Freighter2Start")
		
	# Give the second Freighter an orbit AI
	import E2M1_AI_FreightOrbit
	pFreighter2.SetAI(E2M1_AI_FreightOrbit.CreateAI(pFreighter2))

################################################################################
##	CreateBeolShips()
##
##	Called from PlayerExitsSet() if player has received the SOS and is heading
##	to the Beol system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def CreateBeolShips():
	# Check our flag
	global g_bBeolShipsCreated
	if (g_bBeolShipsCreated == FALSE):
		g_bBeolShipsCreated = TRUE
	else:
		return
	
	# Get the set we need
	pBeol4Set		= App.g_kSetManager.GetSet("Beol4")
	# Create the ships
	pKaroon		= loadspacehelper.CreateShip("CardFreighter", pBeol4Set, "Karoon", "Karoon Start")
	pWarbird	= loadspacehelper.CreateShip("E2M0Warbird", pBeol4Set, "Warbird", "WarbirdStart")

	# Bail if either of our ships are None
	if (pKaroon == None) or (pWarbird == None):
		return
		
	# Set the AIs
	import E2M1_Karoon_AI
	pKaroon.SetAI(E2M1_Karoon_AI.CreateAI(pKaroon))
	import E2M1_AI_WarbirdTow
	pWarbird.SetAI(E2M1_AI_WarbirdTow.CreateAI(pWarbird))
	
	# Make the Warbird invincible and turn collisions off
	pWarbird.SetCollisionsOn(FALSE)
	pWarbird.SetInvincible(TRUE)
	
	# Set the power consumption on the cloaking system to "very low".
	pCloak		= pWarbird.GetCloakingSubsystem()
	pProperty	= pCloak.GetProperty()
	# Save the normal power consumption to a global so we can reassign it later.
	global g_fCloakNormalPower
	g_fCloakNormalPower	= pProperty.GetNormalPowerPerSecond()
	# Now set it to the "very low" value.
	pProperty.SetNormalPowerPerSecond(0.00001)
	
	# Set the power of the tractor beam so it can ALWAYS
	# tow the Karoon
	pTractors = pWarbird.GetTractorBeamSystem()
	# Iterate over all tractor beams
	for iCounter in range(pTractors.GetNumChildSubsystems()):
		pBeam = App.TractorBeamProjector_Cast(pTractors.GetChildSubsystem(iCounter))
		pProp = pBeam.GetProperty()
		# set the strength of the tractor beam
		pProp.SetMaxDamage(1000000000.0)

	# Damage Karoon with script
	DamageKaroon(pKaroon)

	# Attach an instance handler to the Karoon that will cause the AI dormant
	# event to be ignored
	pKaroon.AddPythonFuncHandlerForInstance(App.ET_AI_DORMANT, "MissionLib.IgnoreEvent")
	
	# Instance handler on collisions so we can see if the Karoon
	# hits the asteroid.
	pKaroon.AddPythonFuncHandlerForInstance(App.ET_OBJECT_COLLISION, __name__ + ".KaroonCollision")
	
################################################################################
##	DamageKaroon()
##
##	Give starting damage to Karoon through script so it looks like it's
##	been attacked.  Also turns off it's repair ability.
##
##	Args:	pShip	- The ship object.
##
##	Return:	None
################################################################################
def DamageKaroon(pShip):
	if (pShip == None):
		return
	# Import our damaged script ship and apply it to the Karoon
	import DamagedKaroon
	DamagedKaroon.AddDamage(pShip)

	# Turn off the repair system
	pRepair = pShip.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(0.0)
	
	# Damage the shields
	pShields = pShip.GetShields()
	# Front to 20%
	pShields.SetCurShields(pShields.FRONT_SHIELDS, pShields.GetMaxShields(pShields.REAR_SHIELDS) / 5.0 )
	# Rear to 0%
	pShields.SetCurShields(pShields.REAR_SHIELDS, 0) 
	# Left to 75%
	pShields.SetCurShields(pShields.LEFT_SHIELDS, pShields.GetMaxShields(pShields.LEFT_SHIELDS) / 1.33) 
	# Right to 30%
	pShields.SetCurShields(pShields.RIGHT_SHIELDS, pShields.GetMaxShields(pShields.RIGHT_SHIELDS) / 3.33)
	# Top to 80%
	pShields.SetCurShields(pShields.TOP_SHIELDS, pShields.GetMaxShields(pShields.TOP_SHIELDS) / 1.25) 
	# Bottom to 50%
	pShields.SetCurShields(pShields.BOTTOM_SHIELDS, pShields.GetMaxShields(pShields.BOTTOM_SHIELDS) / 2.0)

	# Disable one of the impulse engines and disable the other.
	pImpulse = pShip.GetImpulseEngineSubsystem()
	if (pImpulse != None):
		pImpulse.GetChildSubsystem(0).SetConditionPercentage(pImpulse.GetChildSubsystem(0).GetDisabledPercentage() - 0.10)
		pImpulse.GetChildSubsystem(1).SetConditionPercentage(pImpulse.GetChildSubsystem(0).GetDisabledPercentage() - 0.15)
		
	# Damage the warp engines
	pWarp = pShip.GetWarpEngineSubsystem()
	if (pWarp != None):
		# Get the warp engines one by one and damage each of them.
		for iCounter in range(pWarp.GetNumChildSubsystems()):
			pChild = pWarp.GetChildSubsystem(iCounter)
			
			# Get a random number and use it to damage the system
			iNumber = App.g_kSystemWrapper.GetRandomNumber(pChild.GetDisabledPercentage() * 100.0)
			pChild.SetConditionPercentage(iNumber / 100.0)
			
	# Damage the Power Plant below the disabled level.
	pPowerSystem = pShip.GetPowerSubsystem()
	if (pPowerSystem != None):
		pPowerSystem.SetConditionPercentage(0.55)
		
	# Damage the hull
	pHull = pShip.GetHull()
	if (pHull != None):
		pHull.SetConditionPercentage(0.70)

################################################################################
##	KaroonCollision()
##
##	Handler called if the Karoon collides with anything.  Calls mission loss
##	if that anything was an asteroid.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def KaroonCollision(TGObject, pEvent):
	# Make sure it's an asteroid the Karoon hit.
	pHitObject = App.ShipClass_Cast(pEvent.GetSource())
	if (pHitObject == None):
		return
		
	sName	= pHitObject.GetName()
	
	if(sName[:8] == "Asteroid") and (g_bKaroonHitAsteroid == FALSE):
		global g_bKaroonHitAsteroid
		g_bKaroonHitAsteroid = TRUE
		KaroonHitAsteroid()
	
	# All done, call our next handler for this event
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	CreatePlanetProximityCheck()
##
##	Creates condition to check if the player is close enough to hail the planet.
##
##	Args:	pMission	- The mission object.
##
##	Return:	None
################################################################################
def CreatePlanetProximityCheck(pMission):
	# Get the planet
	pSet	= App.g_kSetManager.GetSet("Vesuvi5")
	if (pSet == None):
		return
	pPlanet = App.Planet_GetObject(pSet, "Geki")
	fDistance = (pPlanet.GetRadius()) + 200
	
	# Create the in range condition
	pCondition = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", fDistance, "player", "Geki")
	MissionLib.CallFunctionWhenConditionChanges(pMission, __name__, "OrbitingGeki", pCondition)

	# Make the planet hailable while were here
	pPlanet.SetHailable(TRUE)

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
	# Object destroyed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, pMission, __name__+".ObjectDestroyed")
	# Weapon fired event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_WEAPON_FIRED, pMission, __name__+".WeaponFired")
	# Tractor beam starts hitting event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STARTED_HITTING, pMission, __name__+".TractorBeamOn")
	# Tractor beam stopped hitting event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STOPPED_HITTING, pMission, __name__+".TractorBeamOff")
	# Cloak beginning event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_CLOAK_BEGINNING, pMission, __name__+".CloakStarted")
	# De-cloak beginning event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_DECLOAK_BEGINNING, pMission, __name__+".DecloakStarted")
	# De-cloak completed event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_DECLOAK_COMPLETED, pMission, __name__ + ".DecloakCompleted")
	# Target is ID'd by sensors event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SENSORS_SHIP_IDENTIFIED, pMission, __name__+".ShipIdentified")
	# Target appears on target list event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TARGET_LIST_OBJECT_ADDED, pMission, __name__+".ShipOnTargetList")
	
	# Instance handlers on the mission for friendly fire warnings
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")
	# Instance handler on the mission for friendly fire game over
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".FriendlyFireGameOverHandler")
	
	# Instance handler for Kiska's menu
	pKiskaMenu = Bridge.BridgeUtils.GetBridgeMenu("Helm")
	if (pKiskaMenu != None):
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_HAIL,			__name__ + ".HailHandler")
		pKiskaMenu.AddPythonFuncHandlerForInstance(App.ET_SET_COURSE,	__name__ + ".SetCourseHandler")
		# Instance handler for warp button
		pWarpButton = Bridge.BridgeUtils.GetWarpButton()
		if (pWarpButton != None):
			pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")
	
	# Instance handler for Miguel's menu
	pMiguelMenu = Bridge.BridgeUtils.GetBridgeMenu("Science")
	if (pMiguelMenu != None):
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_SCAN,		__name__ + ".ScanHandler")
		pMiguelMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Instance handler for Saffi's menu
	pSaffiMenu = Bridge.BridgeUtils.GetBridgeMenu("XO")
	if (pSaffiMenu != None):
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE,			__name__ + ".CommunicateHandler")
		pSaffiMenu.AddPythonFuncHandlerForInstance(App.ET_CONTACT_STARFLEET,	__name__ + ".HailStarfleet")

	# Instance handlers for Felix's menu
	pFelixMenu = Bridge.BridgeUtils.GetBridgeMenu("Tactical")
	if (pFelixMenu != None):
		pFelixMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")

	# Instance handlers for Brex's menu
	pBrexMenu = Bridge.BridgeUtils.GetBridgeMenu("Engineer")
	if (pBrexMenu != None):
		pBrexMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, __name__ + ".CommunicateHandler")
	
###############################################################################
##	HailStarfleet()
##
##	Contact Starfleet
##
##	Args:	TGObject	- TGObject object
##			pEvent		- The event that was sent,
##
##	Return:	none
###############################################################################
def HailStarfleet(TGObject, pEvent):
	# If the SOS is completed, do our debrief.
	if (g_bSOSCompleted == TRUE) and (g_bLiuHailDone == FALSE):
		# Call our debrief
		LiuHail(None)
		
	else:
		# Starbase can't be hailed because you're not done with the mission.
		TGObject.CallNextHandler(pEvent)

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
	if (pTarget == None):
		return
		
	if (pTarget.GetName () == "Warbird") and (g_bFirstCloak == FALSE) and (g_bWarbirdHailed == FALSE):
		# The player is hailing the Warbird before the first cloak
		# Play the line from Kiska and disable the Hail menu
		pKiskaHailOpen2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase)
		pKiskaHailOpen2.Play()
		# Set our flag
		global g_bPlayerTriedHail
		g_bPlayerTriedHail = TRUE
		
	elif (pTarget.GetName () == "Warbird") and (g_bWarbirdHailed == TRUE):
		# The player is hailing the Warbird before the first cloak
		pSequence = App.TGSequence_Create()
		
		pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
		pKiskaHailing1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1HailWarbird1", None, 0, g_pMissionDatabase)
		pKiskaHailing2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1HailWarbird2", None, 0, g_pMissionDatabase)
		pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)

		pSequence.AppendAction(pCallWaiting)
		pSequence.AppendAction(pKiskaHailing1)
		pSequence.AppendAction(pKiskaHailing2, 2)
		pSequence.AppendAction(pEndCallWaiting)
		
		# Register and play
		App.TGActionManager_RegisterAction(pSequence, "Generic")
		pSequence.Play()

	elif (pTarget.GetName() == "Geki") and (g_bGekiHailed == FALSE) and (g_bPlayerInOrbit == TRUE):
		# Player is hailing the Geki colony for the first time
		global g_bGekiHailed
		g_bGekiHailed = TRUE
		PlayerHailingGeki()

	elif (pTarget.GetName() == "Geki") and (g_bGekiHailed == FALSE) and (g_bPlayerInOrbit == FALSE):
		# Player is not in orbit, so let them know they need to be
		pKiskaArriveGeki1a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveGeki1a", "Captain", 1, g_pMissionDatabase)
		pKiskaArriveGeki1a.Play()
		
	else:
		TGObject.CallNextHandler(pEvent)
			
	
################################################################################
##	EnterSet()
##	
##	Event handler called whenever an object enters a set.
##	
##	Args: 	TGObject	- The TGObject object.
##			pEvent		- Pointer to the event that was sent to the object
##	
##	Return: None
################################################################################
def EnterSet(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	# Make sure it's a ship, return if not
	if (pShip == None):
		return
	
	# Make sure the ship is alive
	if (pShip.IsDead()):
		return
		
	pSet		= pShip.GetContainingSet()
	sSetName 	= pSet.GetName()
	sShipName	= pShip.GetName()
	
	# See if it's the players ship and call
	# TrackPlayer() if it is.
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer != None):
		if (pPlayer.GetName() == sShipName):
			TrackPlayer(sSetName)
					
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ExitSet()
##	
##	Event handler called whenever an object leaves a set.
##	
##	Args: 	TGObject	-
##			pEvent		- Pointer to the event that was sent to the object
##	
##	Return: None
################################################################################
def ExitSet(TGObject, pEvent):
	# Check and see if the mission is terminating
	if (g_bMissionTerminate != 1):
		return

	pShip		= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
		
	sSetName	= pEvent.GetCString()
	sShipName	= pShip.GetName()
	
	# Make sure it's a ship, return if not
	if (pShip == None):
		return
	
	# Get the players ship name
	pPlayer = MissionLib.GetPlayer()
	if (pPlayer == None):
		return
		
	# See where the player is going
	if (sShipName == pPlayer.GetName()):
		PlayerExitsSet()

	# Check and see if it's the Warbird that has left the set.
	# If the Karoon has survived
	if (sShipName == "Warbird") and (sSetName == "Beol4") and (g_bKaroonDestroyed == FALSE):
		# Set our mission state to the default
		global g_iMissionState
		g_iMissionState = DEFAULT
		KaroonSurvives()
		
	# We're done. Let any other event handlers for this event handle it
	TGObject.CallNextHandler(pEvent)
	
################################################################################
##	ObjectDestroyed()
##
##	Event handler called when an object destroyed event is sent.
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
	sSetName	= pEvent.GetCString()

	# Check and see if the Karoon has been destroyed.
	global g_bKaroonDestroyed
	if (sShipName == "Karoon") and (sSetName == "Beol4") and (g_bKaroonHitAsteroid == FALSE):
		g_bKaroonDestroyed = TRUE
		# Set our mission state to the default.
		global g_iMissionState
		g_iMissionState = DEFAULT
		KaroonDestroyed()
	
	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

################################################################################
##	WeaponFired()
##
##	Event handler called when a weapon is fired.
##
##	Args:	TGObject	- The TGObject object
##			pEvent		- The event sent.
##
##	Return:	None
################################################################################
def WeaponFired(TGObject, pEvent):
	# Get the ship that fired
	pShip	= App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	# Get the target
	pTargetShip	= App.ShipClass_Cast(pEvent.GetObjPtr())
	if (pTargetShip == None):
		return

	sShipName	= pShip.GetName()
	sTargetName	= pTargetShip.GetName()
	# Check and see if it's the Warbird firing a weapon at the Karoon
	if (sShipName == "Warbird") and (sTargetName == "Karoon") and (g_bWarbirdAttacksKaroon == FALSE):
		# Cast the event to all the weapon systems, and if it turns
		# out to be one of them, call our function.
		pPhaser = App.PhaserBank_Cast(pEvent.GetSource())
		pTorp = App.TorpedoTube_Cast(pEvent.GetSource())
		pDisruptor = App.PulseWeapon_Cast(pEvent.GetSource())
		if (pPhaser != None) or (pTorp != None) or (pDisruptor != None):
			global g_bWarbirdAttacksKaroon
			# It is, so call our function
			g_bWarbirdAttacksKaroon = TRUE
			WarbirdAttacksKaroon()

	# We're done. Let any other event handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

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

	# If the tractor beam is hitting the Karoon for the first time
	if (sFiringShipName == "player") and (sTargetName == "Karoon"):
		# Have the tractor beam stop the Karoon
		if (pTractorSystem != None):
			pTractorSystem.SetMode(pTractorSystem.TBS_HOLD)
		
		# Only play Felix's line once.
		if (g_bKaroonTractored == FALSE):
			global g_bKaroonTractored
			g_bKaroonTractored = TRUE

			# Play the line from Felix
			pSequence = App.TGSequence_Create()
			pFelixTractor2	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1TractorKaroon2", None, 0, g_pMissionDatabase)
			pSequence.AppendAction(pFelixTractor2, 2)
			pSequence.Play()
		
			# Start the timer that will check the speed of the Karoon
			fStartTime	= App.g_kUtopiaModule.GetGameTime()
			pTimer = MissionLib.CreateTimer(ET_KAROON_VELOCITY_CHECK, __name__ + ".CheckKaroonVelocity", fStartTime + 5, 1, -1)
			# Save the ID of the timer, so we can stop it later.
			global g_idVelocityTimer
			g_idVelocityTimer = pTimer.GetObjID()
	
	# All done here, pass the event onto it's next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	TractorBeamOff()
##
##	Event handler called if a tractor beam stops hitting a target.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def TractorBeamOff(TGObject, pEvent):
	# Get the destination (the ship that was being hit by the tractor beam)
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sTargetName = pShip.GetName()
		
	# Get the tractor beam system that fired so we
	# can set it's behavior.
	pTractorProjector	= App.TractorBeamProjector_Cast(pEvent.GetSource())
	pTractorSystem		= App.TractorBeamSystem_Cast(pTractorProjector.GetParentSubsystem())
	
	# Get the name of the ship that fired
	pFiringShip = pTractorSystem.GetParentShip()
	if (pFiringShip == None):
		return
	sFiringShipName = pFiringShip.GetName()

	# If the tractor beam was being fired by the Warbird and was
	# hitting the Karoon, send the Karoon towards Asteroid 3
	if (sFiringShipName == "Warbird") and (sTargetName == "Karoon"):
		# Get the Asteroid 3 object
		pAsteroid = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Beol4"), "Asteroid 3")
		if (pAsteroid == None):
			return
		# Now send the Karoon toward the Asteroid
		vVelocity = pAsteroid.GetWorldLocation()
		vVelocity.Subtract(pShip.GetWorldLocation())
		vVelocity.Unitize()
		vVelocity.Scale(1.5)
		pShip.SetVelocity(vVelocity)

		# Don't allow the ship's disabled engines to slow
		# the ship to a stop.
		pShip.SetDisabledEngineDeceleration(0.0)
		
	# All done, so call lthe next handler for the event
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
	
	# See if its the Warbird cloaking (it should be since its the
	# only ship around with a cloaking devise.
	if (sShipName == "Warbird"):
		# Check our flags and see if we need to do anything
		if (g_bFirstCloak == FALSE):
			global g_bFirstCloak
			g_bFirstCloak = TRUE
			# Play a line from Felix and then call our sequence if
			# the ships have been IDd
			if (g_bShipsIDd == TRUE):
				pFelixCloak1 = App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1WarbirdCloaks1", None, 0, g_pMissionDatabase)
				pFelixCloak1.Play()
				WarbirdCloaks()
		
		# If the Warbird is cloaking for the second time, call
		# our function
		elif (g_bFirstCloak == TRUE) and (g_bSecondCloak == FALSE):
			global g_bSecondCloak
			g_bSecondCloak = TRUE
			WarbirdCloaksAgain()
			
	# All done, call our next handler for this event
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
	
	# See if it's the Warbird and then check our flags to see
	# what we should do
	if (sShipName == "Warbird"):
		# If it's the first time, play a line
		# from Miguel
		if (g_bFirstCloak == TRUE) and (g_bSecondCloak == FALSE) and (g_bKaroonHitAsteroid == FALSE):
			pMiguelLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1WarbirdDecloaks1", None, 0, g_pMissionDatabase)
			pMiguelLine.Play()
			
			# Set our mission state
			global g_iMissionState
			g_iMissionState = WARBIRD_ATTACK
			
		# If it's decloaking for the second time
		elif (g_bFirstCloak == TRUE) and (g_bSecondCloak == TRUE):
			# If we haven't done it already, reset the power consumption
			# of the cloaking system.
			if (g_bCloakPowerReset == FALSE):
				global g_bCloakPowerReset
				g_bCloakPowerReset = TRUE
				pWarbird = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Beol4"), "Warbird")
				if (pWarbird != None):
					pCloak		= pWarbird.GetCloakingSubsystem()
					pProperty	= pCloak.GetProperty()
					# Now set it to the original value.
					pProperty.SetNormalPowerPerSecond(g_fCloakNormalPower)
				# Turn collisions back on for the Warbird
				pShip.SetCollisionsOn(TRUE)

	# All done, pass on our event
	TGObject.CallNextHandler(pEvent)

################################################################################
##	DecloakCompleted()
##
##	Handler called when a decloak is completed.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def DecloakCompleted(TGObject, pEvent):
	# Make sure it's after the second cloak
	if (g_bFirstCloak == TRUE) and (g_bSecondCloak == TRUE):
		# Make sure the sensor system isn't disabled
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
		pSensors = pPlayer.GetSensorSubsystem()
		if (pSensors != None) and (pSensors.IsDisabled() != TRUE) and (g_bShipsIDd == TRUE):
			pMiguelLine	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1WarbirdDecloaks2", None, 0, g_pMissionDatabase)
			pMiguelLine.Play()

	# All done, pass on our event
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ShipOnTargetList()
##
##	Event handler called when a ship(object) is added to the target list.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent 		- The event that was sent.
##
##	Return:	None
################################################################################
def ShipOnTargetList(TGObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if (pShip == None):
		return
	sShipName = pShip.GetName()
	
	# if the warbird and/or the Karoon appear on the target list, play a line.
	if ((sShipName == "Warbird") or (sShipName == "Karoon")) and (g_bShipOnListPlayed == FALSE) and (g_bShipsIDd == FALSE):
		PlayMiguelUnknownLine()

	# We're done. Let any other event handlers for this event handle it.
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
	
	# If the Karoon has been IDd and the Warbird has already cloaked
	# then just do the lines about it heading towards the asteroids.
	if (sShipName == "Karoon") and (g_bShipsIDd == FALSE) and (g_bFirstCloak == TRUE):
		global g_bShipsIDd
		g_bShipsIDd = TRUE
		KaroonDrifting()
		
	# The Warbird hasn't cloaked yet, so do the normal stuff
	if ((sShipName == "Karoon") or (sShipName == "Warbird")) and (g_bShipsIDd == FALSE):
		global g_bShipsIDd
		g_bShipsIDd = TRUE
		
	# If we already played the entry sequence, play the
	# ShipsIDd sequence now
	elif (g_bBeolEntryPlayed == TRUE) and (g_bShipsIDd == TRUE) and (g_bFirstCloak == FALSE):
		ShipsIDd()
	
	# We're done. Let any other event handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)

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
	
	# If its the Karoon, do our special line from Saffi
	if (sShipName == "Karoon"):
		fTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - g_pSaffi.GetLastTalkTime()
		if (fTimeSinceTalk < 5.0):
			return
		else:
			pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1FiresKaroon1", "Captain", 1, g_pMissionDatabase)
			pSaffiLine.Play()
			return
			
	# All done, so call our next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	FriendlyFireGameOverHandler()
##
##	Handler called if player does enough damage to friendly ship to get game
##	over.
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
	
	# If it's the Karoon, do our mission specific loss
	if (sShipName == "Karoon"):
		# Do the line from Saffi and end the game
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1FiresKaroon2", "Captain", 1, g_pMissionDatabase)
		# End the mission
		pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
		pGameOver.Play()
		
		return
		
	# All done, call the next handler for the event
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
		# Get the player and their target
		pPlayer = MissionLib.GetPlayer()
		if (pPlayer == None):
			return
		pTarget = pPlayer.GetTarget()
		if (pTarget == None):
			TGObject.CallNextHandler(pEvent)
			return
			
		# Check the name of the target
		if (pTarget.GetName() == "Karoon") or (pTarget.GetName() == "Warbird"):
			# It is the facility, so assign the AI
			import E2M1_AI_Intercept
			MissionLib.SetPlayerAI("Helm", E2M1_AI_Intercept.CreateAI(pPlayer, pTarget.GetName()))
			# Play intercept line from Kiska
			pKiskaLine = App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "gh081", None, 0, g_pGeneralDatabase)
			pKiskaLine.Play()
		else:
			# It's not the facility so do the normal stuff
			TGObject.CallNextHandler(pEvent)
	
	# If it's not anything we care about, do the normal
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
	# Check and see if we're trying to beam down supplies.
	if (g_bBeamingSupplies == TRUE):
		# Do the line from Saffi
		pSaffiLine = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerLeaves4", "Captain", 1, g_pMissionDatabase)
		pSaffiLine.Play()
		
		return
	
	# If we're trying to stop the Karoon, don't allow the player to warp.
	if (g_bPlayerArriveBeol == TRUE) and (g_bKaroonStopped == FALSE):
		# Do a line from Saffi
		pSaffiLine = App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerLeaves2", "Captain", 1, g_pMissionDatabase)
		pSaffiLine.Play()		
		return
			
	# See if we are in an asteroid field
	pShip = MissionLib.GetPlayer()
	if (pShip == None):
		return
	pSet = pShip.GetContainingSet()
	if (pSet == None):
		return
	lAsteroidFields = pSet.GetClassObjectList(App.CT_ASTEROID_FIELD)
	for i in lAsteroidFields:
		pField = App.AsteroidField_Cast(i)
		if (pField != None):
			if (pField.IsShipInside(pShip)):
				# Have Kiska tell the player how to play game
				pSequence = App.TGSequence_Create()
				pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "CantWarp4", "Captain", 0))
				pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1FieldNavProd", None, 1, g_pMissionDatabase))
				pSequence.Play()
				return

	# Call the next handler
	TGObject.CallNextHandler(pEvent)

################################################################################
##	ScanHandler()
##
##	Called one of Miguel's scan buttons is hit.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def ScanHandler(TGObject, pEvent):
	# Get the player
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
	
	# Get the event type.
	iType	= pEvent.GetInt()
	
	# Check what set it is and if we haven't scanned it
	# before, call our function, unless it is a scan target on the kessok.
	if (iType == App.CharacterClass.EST_SCAN_OBJECT):
		pTarget = App.ObjectClass_Cast(pEvent.GetSource())
		if (pTarget == None):
			# Target is none, so player must be scanning target
			pTarget = pPlayer.GetTarget()
		if (pTarget != None): 
			sTargetName = pTarget.GetName()
			# See if we're scanning the Karoon for the first time.
			if (sTargetName == "Karoon") and (g_bKaroonScanned == FALSE) and (g_bShipsIDd == TRUE):
				global g_bKaroonScanned
				g_bKaroonScanned = TRUE
				KaroonScanned()
			else:
				TGObject.CallNextHandler(pEvent)
			
	else:
		# Nothing special to do
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

	# Check the mission state and call functions based on that
	if (g_iMissionState == GEKI_SUPPLY):
		SupplyGekiCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == SOS_RECEIVED):
		SosReceivedCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == PLAYER_BEOL):
		PlayerInBeolCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == KAROON_DRIFTING):
		KaroonDriftingCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == WARBIRD_ATTACK):
		WarbirdAttacksCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	elif (g_iMissionState == IN_VESUVI):
		InVesuviCommunicate(pMenu.GetObjID(), TGObject, pEvent)
		
	# g_iMissionState must be DEFAULT so just call the next handler
	else:
		TGObject.CallNextHandler(pEvent)
	
################################################################################
##	TrackPlayer()
##
##	Called from EnterSet() if the ship that enters the set is the players ship.
##
##	Args:	sSetName	- The name of the set entered
##
##	Return:	None
################################################################################
def TrackPlayer(sSetName):
	# Keep track of the players movements, and call functions based on that
	global g_bPlayerArriveBeol
	global g_bPlayerArriveGeki
	
	# See if were arriving in Vesuvi 6 for the first time and start the
	# mission if we are
	if (sSetName == "Vesuvi6") and (g_bPlayerArriveVesuvi6 == FALSE):
		global g_bPlayerArriveVesuvi6
		g_bPlayerArriveVesuvi6 = TRUE
		
	# See if we have arrived at Beol4 for first time
	elif (sSetName == "Beol4") and (g_bPlayerReceivedSOS == TRUE) and (g_bPlayerArriveBeol == FALSE):
		g_bPlayerArriveBeol = TRUE
		PlayerArrivesBeol()
		# Change the music to netural combat
		import DynamicMusic
		DynamicMusic.OverrideMusic("Combat Neutral")


	# See if we have arrived at Vesuvi5 for first time
	elif (sSetName == "Vesuvi5") and (g_bPlayerArriveGeki == FALSE):
		g_bPlayerArriveGeki = TRUE
		PlayerArrivesGeki()

	# See if were entering Starbase 12 for the first time after the SOS
	# has been completed
	elif (sSetName == "Starbase12") and (g_bSOSCompleted == TRUE) and (g_bLiuHailDone == FALSE):
		LiuHail(None)
		
################################################################################
##	PlayerExitsSet()
##
##	Called if player exits a set.  Keeps track of the player and were he's
##	going for proding needs.
##
##	Args:	None
##
##	Return: None	
################################################################################
def PlayerExitsSet():
	# Get Kiska's warp heading and see where were headed
	pKiskaMenu = g_pKiska.GetMenu()
	if (pKiskaMenu == None):
		return
	pWarpButton	= Bridge.BridgeUtils.GetWarpButton()
	if(pWarpButton == None):
		return
	pString = pWarpButton.GetDestination()
	
	# See if we're responding to the SOS
	if (pString == "Systems.Beol.Beol4") and (g_bPlayerArriveBeol == FALSE) and (g_bPlayerReceivedSOS == TRUE):
		StopProdTimer()
		CreateBeolShips()
	
	# If the player is trying to bail from Beol, start prodding
	elif (g_bPlayerNotInBeol == FALSE) and (g_bPlayerArriveBeol == TRUE) and(g_bSOSCompleted == FALSE) and (pString != "Systems.Beol.Beol4"):
		global g_bPlayerNotInBeol
		g_bPlayerNotInBeol = TRUE
		RestartProdTimer(None, 20)
	
	# If the player is returning to Beol, clear the flag
	# and stop the timer.
	elif (g_bPlayerNotInBeol == TRUE) and (pString == "Systems.Beol.Beol4") and (g_bPlayerArriveBeol == TRUE):
		global g_bPlayerNotInBeol
		g_bPlayerNotInBeol = FALSE
		StopProdTimer()
		
		# Reset our prod timer counter
		global g_iProdToBeolCounter
		g_iProdToBeolCounter = 1
		
	# See if we're player moving after SOS
	elif ((pString == "Systems.Vesuvi.Vesuvi5") or (pString == "Systems.Serris.Serris3")) and (g_bSOSCompleted == TRUE):
		StopProdTimer()

################################################################################
##	OrbitingGeki()
##
##	Called when in range conditon changes.
##
##	Args:	bNewState	- The new state of the condition.
##
##	Return:	None
################################################################################
def OrbitingGeki(bNewState):
	# Set our flag so to the new state
	global g_bPlayerInOrbit
	g_bPlayerInOrbit = bNewState

	# Check our flags and see if we've already been here.
	if (g_bGekiSupplied == FALSE) and (g_bPlayerInOrbit == TRUE):
		global g_bGekiSupplied
		g_bGekiSupplied = TRUE
		# Play prodding line from Kiska to get player to hail
		pSequence = App.TGSequence_Create()
		pSequence.AppendAction(App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1OrbitGeki1a", "Captain", 0, g_pMissionDatabase), 1)
		pSequence.Play()

################################################################################
##	PlayPlayerArrivesHaven()
##
##	Calls PlayerArrivesHaven() as a script action so it will call itself until
##	warp is completed.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def PlayPlayerArrivesHaven(pTGAction = None):
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
		pEnterHaven	= App.TGScriptAction_Create(__name__, "PlayPlayerArrivesHaven")

		pSequence.AppendAction(pEnterHaven, 1)
		pSequence.Play()

		return 0
		
	else:
		# Enable the hail menu in case it was disabled in the previous mission
		Bridge.BridgeUtils.EnableHailMenu()
		
		pSequence = App.TGSequence_Create()

		pEndCutscene = App.TGScriptAction_Create("MissionLib", "EndCutscene")
		pArriveHaven	= App.TGScriptAction_Create(__name__, "PlayerArrivesHaven")

		pSequence.AppendAction(pArriveHaven)
		pSequence.AppendAction(pEndCutscene)

		pSequence.Play()

		return 0
		
################################################################################
##	PlayerArrivesHaven()
##
##	Plays dialogue letting the player know where they are.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesHaven(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Set the mission state for communicate
	global g_iMissionState
	g_iMissionState = IN_VESUVI
	
	pSequence = App.TGSequence_Create()
	
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

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pForceToBridge	= App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pKiskaArrive1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveVesuvi1", "Captain", 0, g_pMissionDatabase)
	pKiskaArrive1a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveVesuvi1a", None, 1, g_pMissionDatabase)

	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pForceToBridge, pPreLoad)
	pSequence.AddAction(pWalkSequence, pForceToBridge, 1)
	pSequence.AddAction(pKiskaArrive1, pForceToBridge, 1.5)
	pSequence.AppendAction(pKiskaArrive1a)
	
	pSequence.Play()

	return 0
	
################################################################################
##	PlayerArrivesGeki()
##
##	Called when player first arrives in Vesuvi 5.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerArrivesGeki():
	# Set our mission state for the communicate
	global g_iMissionState
	g_iMissionState = GEKI_SUPPLY
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pKiskaArriveGeki1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveGeki1", "Captain", 0, g_pMissionDatabase)
	pKiskaOrbit			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1OrbitGeki1", None, 1, g_pMissionDatabase)
	
	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pKiskaArriveGeki1, pPreLoad, 4)
	pSequence.AppendAction(pKiskaOrbit)
	
	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	PlayerHailingGeki()
##
##	Called when player goes into orbit around Geki and it has not yet been
##	supplied.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayerHailingGeki():
	# Set our beaming flag
	global g_bBeamingSupplies
	g_bBeamingSupplies = TRUE
	
	pDEngSet	= App.g_kSetManager.GetSet("DEngSet")
	pTakahara	= App.CharacterClass_GetObject(pDEngSet, "Takahara")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad				= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pCallWaiting			= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pKiskaHailOpen			= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "HailOpen2", None, 0, g_pGeneralDatabase)
	pKiskaOrbitGeki1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1OrbitGeki", None, 0, g_pMissionDatabase)
	pStarbaseViewOn1		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DEngSet", "Takahara")
	pTakaharaArriveGeki2	= App.CharacterAction_Create(pTakahara, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveGeki2", None, 0, g_pMissionDatabase)
	pTakaharaArriveGeki3	= App.CharacterAction_Create(pTakahara, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveGeki3", None, 0, g_pMissionDatabase)
	pViewOff1				= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pBrexArriveGeki8		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveGeki8", "Captain", 1, g_pMissionDatabase)
	pShieldLevelCheck		= App.TGScriptAction_Create(__name__, "CheckShields")
	pBrexArriveGeki9		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveGeki9", "Captain", 1, g_pMissionDatabase)
	pStarbaseViewOn2		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "DEngSet", "Takahara")
	pTakaharaArriveGeki10	= App.CharacterAction_Create(pTakahara, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveGeki10", None, 0, g_pMissionDatabase)
	pViewOff2				= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting			= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)	
	pClearBeamingFlag		= App.TGScriptAction_Create(__name__, "ClearBeamingFlag")
	pRemoveGoal				= App.TGScriptAction_Create("MissionLib", "RemoveGoalAction", "E2SupplyCeli5Goal")
	# Call our episode level function to play
	# the Karoon's SOS
	pPlaySOS				= App.TGScriptAction_Create(__name__, "PlayerGetsSOS")
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pKiskaHailOpen)
	pSequence.AppendAction(pKiskaOrbitGeki1, 0.5)
	pSequence.AppendAction(pStarbaseViewOn1)
	pSequence.AppendAction(pTakaharaArriveGeki2)
	pSequence.AppendAction(pTakaharaArriveGeki3)
	pSequence.AppendAction(pViewOff1)
	pSequence.AppendAction(pBrexArriveGeki8)
	pSequence.AppendAction(pShieldLevelCheck)
	pSequence.AppendAction(pBrexArriveGeki9, 3)
	pSequence.AppendAction(pStarbaseViewOn2, 2)
	pSequence.AppendAction(pTakaharaArriveGeki10)
	pSequence.AppendAction(pViewOff2)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pClearBeamingFlag)
	pSequence.AppendAction(pRemoveGoal)
	pSequence.AppendAction(pPlaySOS)

	MissionLib.QueueActionToPlay(pSequence)

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
##	ClearBeamingFlag()
##
##	Script action that sets the value of g_bBeamingSupplies to FALSE.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def ClearBeamingFlag(pTGAction):
	global g_bBeamingSupplies
	g_bBeamingSupplies = FALSE
	
	return 0
	
################################################################################
##	PlayerGetsSOS()
##
##	Calls episode level function to play SOS, set our local flag.  Called as
##	script action.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep the calling sequence from crashing.
################################################################################
def PlayerGetsSOS(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Set our flag
	global g_bPlayerReceivedSOS
	g_bPlayerReceivedSOS	= TRUE
	
	# Do the SOS sequence.
	pSequence = App.TGSequence_Create()
	
	pCardSet	= App.g_kSetManager.GetSet("CardSet")
	pCardCapt	= App.CharacterClass_GetObject(pCardSet, "CardCapt")
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pKiskaSOS1		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS0", "Captain", 1, g_pMissionDatabase)
	pKiskaSOS2		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS1", None, 0, g_pMissionDatabase)
	pKiskaSOS3		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS2", None, 0, g_pMissionDatabase)
	pCommOn			= App.TGSoundAction_Create("ViewOn")
	pCardCaptSOS5	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1SOS5", None, 0, g_pMissionDatabase)
	pKiskaSOS6		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS6", "Captain", 0, g_pMissionDatabase)
	pKiskaGoToBeol1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1GoToBeol1", "Captain", 1, g_pMissionDatabase)
	pSaffiSOS4		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SOSProd3", "Captain", 1, g_pMissionDatabase)
	pAddBeolToMenu	= App.TGScriptAction_Create(__name__, "AddBeolToMenu")
	pAddGoal		= App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E2AidKrellGoal")
	pStartProdTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 20)
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pKiskaSOS1)
	pSequence.AppendAction(pKiskaSOS2)
	pSequence.AppendAction(pKiskaSOS3)
	pSequence.AppendAction(pCommOn)
	pSequence.AppendAction(pCardCaptSOS5)
	pSequence.AppendAction(pKiskaSOS6)
	pSequence.AppendAction(pAddBeolToMenu)
	pSequence.AppendAction(pKiskaGoToBeol1)
	pSequence.AppendAction(pSaffiSOS4)
	pSequence.AppendAction(pAddGoal)
	pSequence.AppendAction(pStartProdTimer)
	
	MissionLib.QueueActionToPlay(pSequence)

	return 0

################################################################################
##	AddBeolToMenu()
##
##	Script action that adds Beol to the Set Course menu.  Also changes
##	g_iMissionState to reflect current mission state.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep call sequence from crashing.
################################################################################
def AddBeolToMenu(pTGAction):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Pause the menu sorting
	App.SortedRegionMenu_SetPauseSorting(1)
	
	import Systems.Beol.Beol
	Systems.Beol.Beol.CreateMenus()

	# Unpause menu sorting
	App.SortedRegionMenu_SetPauseSorting(0)
	
	# Set our mission state
	global g_iMissionState
	g_iMissionState = SOS_RECEIVED
	
	return 0
	
################################################################################
##	PlayerArrivesBeol()
##	
##  Called when player arrives in Beol system after receiving KaroonSOS
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def PlayerArrivesBeol():
	# Set our mission state
	global g_iMissionState	
	g_iMissionState = PLAYER_BEOL
	
	# Do the sequence
	pCardSet	= App.g_kSetManager.GetSet("CardSet")
	pCardCapt	= App.CharacterClass_GetObject(pCardSet, "CardCapt")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pKiskaInBeol1a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol1a", None, 0, g_pMissionDatabase)
	pKiskaInBeol1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol1", "Captain", 1, g_pMissionDatabase)
	pCardInBeol2	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1KrellAttacked2", None, 0, g_pMissionDatabase)
	pKiskaInBeol3	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol3", "Captain", 1, g_pMissionDatabase)
	pShipsIDd		= App.TGScriptAction_Create(__name__, "ShipsIDd")
	pSetFlag		= App.TGScriptAction_Create(__name__, "SetBeolEntryPlayed")
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pKiskaInBeol1a)
	pSequence.AppendAction(pKiskaInBeol1)
	pSequence.AppendAction(pCardInBeol2)
	pSequence.AppendAction(pKiskaInBeol3)
	pSequence.AppendAction(pShipsIDd)
	pSequence.AppendAction(pSetFlag)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	PlayMiguelUnknownLine()
##
##	Plays the line that lets the player know there are contacts in the set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def PlayMiguelUnknownLine():
	# Bail if terminating
	if (g_bMissionTerminate != 1):
		return

	# Bail if we've been called
	if (g_bShipOnListPlayed == FALSE):
		global g_bShipOnListPlayed
		g_bShipOnListPlayed = TRUE
	else:
		return
	
	# play Miguel's line
	pMiguelInBeol4	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol4", None, 0, g_pMissionDatabase)	
	MissionLib.QueueActionToPlay(pMiguelInBeol4)

################################################################################
##	ShipsIDd()
##
##	Called as script action or from ShipIdentified().  Tells player what the
##	ships are and what their doing.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling seuqence from crashing.
################################################################################
def ShipsIDd(pTGAction = None):
	# Check and make sure the ships have been IDd
	if (g_bShipsIDd == FALSE) or (g_bMissionTerminate != 1):
		return 0

	# Bail if we've been called
	if (g_bShipIDdCalled == FALSE):
		global g_bShipIDdCalled
		g_bShipIDdCalled = TRUE
	else:
		return 0

	# Do the sequence
	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pMiguelInBeol4a	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol4a", None, 0, g_pMissionDatabase)	
	pMiguelInBeol5	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol5", "Captain", 1, g_pMissionDatabase)
	pBrexInBeol6	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol6", None, 0, g_pMissionDatabase)
	pKiskaInBeol6a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol6a", None, 0, g_pMissionDatabase)
	pFelixInBeol7	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol7", "Captain", 1, g_pMissionDatabase)
	pHailWarbird	= App.TGScriptAction_Create(__name__, "HailWarbird")

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pMiguelInBeol4a)
	pSequence.AppendAction(pMiguelInBeol5)
	pSequence.AppendAction(pBrexInBeol6)
	pSequence.AppendAction(pKiskaInBeol6a)
	pSequence.AppendAction(pFelixInBeol7)
	pSequence.AppendAction(pHailWarbird)

	MissionLib.QueueActionToPlay(pSequence)

	return 0
	
################################################################################
##	SetBeolEntryPlayed()
##
##	Script action that sets g_bBeolEntryPlayed to TRUE.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def SetBeolEntryPlayed(pTGAction):
	global g_bBeolEntryPlayed
	g_bBeolEntryPlayed = TRUE
	
	return 0
	
################################################################################
##	HailWarbird()
##
##	Called from ShipsIDd().
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def HailWarbird(pTGAction):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# Set our hail flag
	global g_bWarbirdHailed
	g_bWarbirdHailed = TRUE
	
	# Get Torenn
	pTorenn = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("RomulanSet"), "Torenn")

	# Do our sequence
	pSequence = App.TGSequence_Create()

	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	if (g_bPlayerTriedHail == TRUE):
		pKiskaHailing3a		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1HailWarbird3a", None, 0, g_pMissionDatabase)
	else:
		pKiskaHailing3a		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", "Captain", 1, g_pGeneralDatabase)
	pViewOn				= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "RomulanSet", "Torenn")
	pTorennHailing4		= App.CharacterAction_Create(pTorenn, App.CharacterAction.AT_SAY_LINE, "E2M1HailWarbird4", None, 0, g_pMissionDatabase)
	pSaffiHailing5		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1HailWarbird5", None, 0, g_pMissionDatabase)
	pTorennHailing6		= App.CharacterAction_Create(pTorenn, App.CharacterAction.AT_SAY_LINE, "E2M1HailWarbird6", None, 0, g_pMissionDatabase)
	pTorennHailing7		= App.CharacterAction_Create(pTorenn, App.CharacterAction.AT_SAY_LINE, "E2M1HailWarbird7", None, 0, g_pMissionDatabase)
	pTorennHailing8		= App.CharacterAction_Create(pTorenn, App.CharacterAction.AT_SAY_LINE, "E2M1HailWarbird8", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pKiskaHailing3a, 3)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pTorennHailing4)
	pSequence.AppendAction(pSaffiHailing5)
	pSequence.AppendAction(pTorennHailing6)
	pSequence.AppendAction(pTorennHailing7)
	pSequence.AppendAction(pTorennHailing8)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)

	MissionLib.QueueActionToPlay(pSequence)

	return 0
	
################################################################################
##	WarbirdCloaks()
##
##	Called from CloakStarted() when the Warbird does it's first cloak.  Calls
##	itself recursively until if ships have not been IDd.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def WarbirdCloaks(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return

	if (g_bShipsIDd == FALSE):
		# We can't run yet, so put ourselves into a loop.
		pSequence = App.TGSequence_Create()
		pWaitLoop = App.TGScriptAction_Create(__name__, "WarbirdCloaks")
		pSequence.AppendAction(pWaitLoop, 2)
		pSequence.Play()
		
		return 0
	
	else:
		# Set our mission state for the communicate
		global g_iMissionState
		g_iMissionState		= KAROON_DRIFTING

		# Do the sequence that lets the player know they
		# need to tractor the Karoon
		pCardCapt	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("CardSet"), "CardCapt")
		
		pSequence = App.TGSequence_Create()

		pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
		pMiguelInBeol9	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol9", "Captain", 0, g_pMissionDatabase)
		pKiskaInBeol10	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol10", "Captain", 1, g_pMissionDatabase)
		pCardInBeol11	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE,"E2M1PlayerInBeol11", None, 0, g_pMissionDatabase)
		pSaffiInBeol12	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol12", None, 0, g_pMissionDatabase)
		pFelixInBeol13	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol13", "Captain", 0, g_pMissionDatabase)
		pKiskaCom3		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1KiskaCom3", "Captain", 1, g_pMissionDatabase)

		pSequence.AddAction(pPreLoad)
		pSequence.AppendAction(pMiguelInBeol9)
		pSequence.AppendAction(pKiskaInBeol10)
		pSequence.AppendAction(pCardInBeol11)
		pSequence.AppendAction(pSaffiInBeol12)
		pSequence.AppendAction(pFelixInBeol13)
		pSequence.AppendAction(pKiskaCom3)

		MissionLib.QueueActionToPlay(pSequence)

		return 0

################################################################################
##	KaroonDrifting()
##
##	Sequence that plays if the player never IDs the Warbird and it has a chance
##	to cloak.  Shorter version of the sequence above.
##
##	Args:	None
##
##	Return:	None
################################################################################
def KaroonDrifting():
	# Set our mission state for the communicate
	global g_iMissionState
	g_iMissionState = KAROON_DRIFTING
	
	# Get the Cardassian Captain
	pCardCapt = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("CardSet"), "CardCapt")
	
	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pMiguelInBeol9	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol9", "Captain", 0, g_pMissionDatabase)
	pKiskaInBeol10	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol10", "Captain", 1, g_pMissionDatabase)
	pCardInBeol11	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE,"E2M1PlayerInBeol11", None, 0, g_pMissionDatabase)
	pSaffiInBeol12	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerInBeol12", None, 0, g_pMissionDatabase)
	pKiskaCom3		= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1KiskaCom3", "Captain", 1, g_pMissionDatabase)

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pMiguelInBeol9)
	pSequence.AppendAction(pKiskaInBeol10)
	pSequence.AppendAction(pCardInBeol11)
	pSequence.AppendAction(pSaffiInBeol12)
	pSequence.AppendAction(pKiskaCom3)
	
	MissionLib.QueueActionToPlay(pSequence)
	
################################################################################
##	KaroonHitAsteroid()
##
##	Called from KaroonCollision() if the Karoon hit an asteroid.  Ends the
##	mission.
##
##	Args:	None
##
##	Return:	None
################################################################################
def KaroonHitAsteroid():
	# Get the Karoon and damage it so it always blows up.
	pShip	= App.ShipClass_GetObject(App.g_kSetManager.GetSet("Beol4"), "Karoon")
	if (pShip != None):
		pShip.DestroySystem (pShip.GetPowerSubsystem ())
	
	# Kill any other sequences that were playing
	MissionLib.DeleteQueuedActions()
	
	# Get Liu
	pLiu	= App.CharacterClass_GetObject(App.g_kSetManager.GetSet("StarbaseSet"), "Liu")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pFelixDestroyed1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1KrellDestroyed1", "Captain", 1, g_pMissionDatabase)
	pSaffiLook			= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
	pSaffiDestroyed2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1KrellDestroyed2", None, 0, g_pMissionDatabase)
	pMiguelDestroyed3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1KrellDestroyed3", None, 0, g_pMissionDatabase)
	pSaffiKaroonHit1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1KaroonHits1", "Captain", 0, g_pMissionDatabase)
	pViewOn				= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuKaroonHit2		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M1KaroonHits2", None, 0, g_pMissionDatabase)
	pLiuKaroonHit3		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M1KaroonHits3", None, 0, g_pMissionDatabase)
	pLiuKaroonHit4		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M1KaroonHits4", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pFelixDestroyed1, 2)
	pSequence.AppendAction(pSaffiLook)
	pSequence.AppendAction(pSaffiDestroyed2)
	pSequence.AppendAction(pMiguelDestroyed3)
	pSequence.AppendAction(pSaffiKaroonHit1)
	pSequence.AppendAction(pViewOn)
	pSequence.AppendAction(pLiuKaroonHit2)
	pSequence.AppendAction(pLiuKaroonHit3)
	pSequence.AppendAction(pLiuKaroonHit4)
	pSequence.AppendAction(pViewOff)

	
	# End the game
	pGameOver	= App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
	pGameOver.Play()
	
################################################################################
##	InTractorRange()
##
##	Called from E2M1_Karoon_AI.py when the player is within tractoring range of
##	the Karoon.
##
##	Args:	None
##
##	Return:	None
################################################################################
def InTractorRange():
	# Do line from Kiska letting the player know their in range
	pKiskaLine	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1TractorKaroon1", None, 0, g_pMissionDatabase)
	pKiskaLine.Play()

################################################################################
##	CheckKaroonVelocity()
##
##	Checks the Karoon's velocity and sees if we've stopped it.  Called from timer
##	started when the tractor beam hits the Karoon.
##
##	Args:	TGObject	- The TGObject object.
##			pEvent		- The event that was sent.
##
##	Return:	None
################################################################################
def CheckKaroonVelocity(TGObject, pEvent):
	# Check our flags
	if (g_bKaroonStopped == TRUE) or (g_bKaroonHitAsteroid == TRUE):
		return

	# Get the Karoon
	pSet	= App.g_kSetManager.GetSet("Beol4")
	pShip	= App.ShipClass_GetObject(pSet, "Karoon")
	
	if (pShip != None):
		vVelocity = pShip.GetVelocityTG()

		# Got its velocity direction.  If it's zero, it'll
		# never hit so call our function and stop the timer
		if (vVelocity.SqrLength() < 0.01):
			App.g_kTimerManager.DeleteTimer(g_idVelocityTimer)
			KaroonStopped()
	
################################################################################
##	KaroonStopped()
##
##	Called from TractorBeamOn() when the player first fires their tractor beam
##	at the Karoon and stops it.
##
##	Args:	None
##
##	Return:	None
################################################################################
def KaroonStopped():
	# Check and set our flag
	if (g_bKaroonStopped == FALSE) and (g_bKaroonHitAsteroid == FALSE):
		global g_bKaroonStopped
		g_bKaroonStopped = TRUE
	else:
		return
		
	# Remove the instance handler from the Karoon so that is slows to a stop
	# when the tractor beam is released.
	pShip = App.ShipClass_GetObject(App.g_kSetManager.GetSet("Beol4"), "Karoon")
	if (pShip != None):
		pShip.RemoveHandlerForInstance(App.ET_AI_DORMANT, "MissionLib.IgnoreEvent")
		# Give the Karoon a stay AI so it doesn't drift off
		import E2M1_AI_KaroonStay
		pShip.SetAI(E2M1_AI_KaroonStay.CreateAI(pShip))
	
	# Change our music back to the default
	import DynamicMusic
	DynamicMusic.StopOverridingMusic()
	
	# Set our mission state
	global g_iMissionState
	g_iMissionState = DEFAULT
	
	# Get the Cardassian captain
	pCardSet	= App.g_kSetManager.GetSet("CardSet")
	pCardCapt = App.CharacterClass_GetObject(pCardSet, "CardCapt")

	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pFelixTractor3	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1TractorKaroon3", "Captain", 1, g_pMissionDatabase)
	pKiskaBeol2a	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveBeol2a", "Captain", 1, g_pMissionDatabase)
	pCardViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "CardSet", "CardCapt")
	pCardSOS7		= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1SOS7", None, 0, g_pMissionDatabase)
	pCardBeol3		= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveBeol3", None, 0, g_pMissionDatabase)
	pCardBeol3a		= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveBeol3a", None, 0, g_pMissionDatabase)
	pBrexBeol4		= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveBeol4", None, 0, g_pMissionDatabase)
	pCardBeol5		= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveBeol5", None, 0, g_pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting	= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	pGiveRepair		= App.TGScriptAction_Create(__name__, "GiveRepairToKaroon")
	pResetWarbirdAI	= App.TGScriptAction_Create(__name__, "ResetWarbirdAI")

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pFelixTractor3)
	pSequence.AppendAction(pKiskaBeol2a)
	pSequence.AppendAction(pCardViewOn)
	pSequence.AppendAction(pCardSOS7)
	pSequence.AppendAction(pCardBeol3)
	pSequence.AppendAction(pCardBeol3a)
	pSequence.AppendAction(pBrexBeol4)
	pSequence.AppendAction(pCardBeol5)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	pSequence.AppendAction(pGiveRepair)
	pSequence.AppendAction(pResetWarbirdAI, 3)

	MissionLib.QueueActionToPlay(pSequence)
		
################################################################################
##	KaroonScanned()
##
##	Called from ScanHandler() the first time the player scans the Karoon.
##	Can be called as script action from KaroonSurvives()
##
##	Args:	pTGAction		- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def KaroonScanned(pTGAction = None):
	# Bail if mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
	
	# If we were called by the scan handler, disable the menu
	if (pTGAction == None):
		pScanSequence = Bridge.ScienceCharacterHandlers.GetScanSequence()
		if (pScanSequence != None):
			pScanSequence.Play()
			
	# Do the sequence
	pSequence = App.TGSequence_Create()

	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines")
	pMiguelScan1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1ScanKaroon1", "Captain", 0, g_pMissionDatabase)
	pSaffiScan2		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1ScanKaroon2", "Captain", 0, g_pMissionDatabase)
	pMiguelScan3	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1ScanKaroon3", None, 0, g_pMissionDatabase)
	pSaffiScan4		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1ScanKaroon4", None, 1, g_pMissionDatabase)
	pMiguelScan5	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1ScanKaroon5", None, 1, g_pMissionDatabase)
	pEnableScan		= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pMiguelScan1)
	pSequence.AppendAction(pSaffiScan2)
	pSequence.AppendAction(pMiguelScan3)
	pSequence.AppendAction(pSaffiScan4)
	pSequence.AppendAction(pMiguelScan5)
	pSequence.AppendAction(pEnableScan)

	# If we were called not called as a script action, 
	# queue the action to play.
	if (pTGAction == None):
		MissionLib.QueueActionToPlay(pSequence)
		return 0
		
	else:
		# If we were called as a script action, add a completed action
		# so calling sequence unpauses and do not queue the action
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetObjPtr(pTGAction)
		pSequence.AddCompletedEvent(pEvent)

		pSequence.Play()

		return 1

################################################################################
##	GiveRepairToKaroon()
##
##	Called from PlayerArrivesBeol() as script action.  Gives repair points back
##	to the Karoon so they can start repairing the damage.  Ups shield recharge
##	as well.
##
##	Args:	pTGAction	- The script action.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def GiveRepairToKaroon(pTGAction):
	# Get the set
	pSet	= App.g_kSetManager.GetSet("Beol4")
	# Get the ship
	pShip	= App.ShipClass_GetObject(pSet, "Karoon")
	if (pShip == None):
		return 0
		
	# Give it back some repair points
	pRepair = pShip.GetRepairSubsystem()
	pProp 	= pRepair.GetProperty()
	pProp.SetMaxRepairPoints(10.0)

	# Up the shield recharge rate so it's a little hard to kill
	pShields = pShip.GetShields()
	if (pShields != None):
		pProp = pShields.GetProperty()
		pProp.SetShieldChargePerSecond(App.ShieldClass.REAR_SHIELDS, 6.000000)
		pProp.SetShieldChargePerSecond(App.ShieldClass.TOP_SHIELDS, 6.000000)
		pProp.SetShieldChargePerSecond(App.ShieldClass.BOTTOM_SHIELDS, 6.000000)
		pProp.SetShieldChargePerSecond(App.ShieldClass.LEFT_SHIELDS, 6.000000)
		pProp.SetShieldChargePerSecond(App.ShieldClass.RIGHT_SHIELDS, 6.000000)
	
	return 0

################################################################################
##	ResetWarbirdAI()
##
##	Called as script action.  Resets the Warbird's AI so that it decloaks and
##	fires on the player.
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	None
################################################################################
def ResetWarbirdAI(pTGAction):
	# Get the set and the Warbird
	pSet	= App.g_kSetManager.GetSet("Beol4")
	pShip	= App.ShipClass_GetObject(pSet, "Warbird")
	
	if (pShip != None):	
		# set the warbird to be an enemy
		pEpisode = App.Game_GetCurrentGame().GetCurrentEpisode()
		pMission = pEpisode.GetCurrentMission()
		pEnemies = pMission.GetEnemyGroup()
		pEnemies.AddName("Warbird")
		# Import the AI and assign it
		import E2M1_AI_Warbird
		pShip.SetAI(E2M1_AI_Warbird.CreateAI(pShip))
	
		
	return 0

################################################################################
##	WarbirdCloaksAgain()
##
##	Called from CloakStarted() when the Warbird cloaks for the second time.
##	Plays sequence.
##
##	Args:	None
##
##	Return:	None
################################################################################
def WarbirdCloaksAgain():
	# Do our sequence
	pSequence = App.TGSequence_Create()
	
	pPreLoad		= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pMiguelCloak2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1WarbirdCloaks2", None, 0, g_pMissionDatabase)
	pKiskaCloak3	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1WarbirdCloaks3", "Captain", 1, g_pMissionDatabase)
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pMiguelCloak2)
	pSequence.AppendAction(pKiskaCloak3)
	
	# If the player has taken a lot of damage, do the damage report
	pRepairPane = App.EngRepairPane_GetRepairPane()
	pRepair = App.TGPane_Cast(pRepairPane.GetNthChild(App.EngRepairPane.REPAIR_AREA))
	if (pRepair.GetNumChildren() > 4):
		pSequence.AppendAction(App.TGScriptAction_Create("Bridge.XOCharacterHandlers", "Report"))
	
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	WarbirdAttacksKaroon()
##	
##  Called from WeaponFired() when the Warbird first opens fire on the Karoon.
##
##	Args: 	None
##	
##	Return: None
################################################################################
def WarbirdAttacksKaroon():
	pCardSet	= App.g_kSetManager.GetSet("CardSet")
	pCardCapt = App.CharacterClass_GetObject(pCardSet, "CardCapt")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad			= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pFelixAttacked1 	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1KrellAttacked1", "Captain", 1, 				g_pMissionDatabase)
	pCardViewOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "CardSet", "CardCapt")
	pCardCaptAttacked3	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1KrellAttacked3", None, 0, g_pMissionDatabase)
	pCardCaptAttacked4	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1KrellAttacked4", None, 0, g_pMissionDatabase)
	pViewOff			= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting		= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)
	
	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pFelixAttacked1)
	pSequence.AppendAction(pCardViewOn)
	pSequence.AppendAction(pCardCaptAttacked3)
	pSequence.AppendAction(pCardCaptAttacked4)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)
	
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
##	KaroonAlmostDestroyed()
##	
##	Called from E2M1_Karoon_AI.py when Karoon's hull falls below 50%.
##	Plays dialog line.
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def KaroonAlmostDestroyed():
	pCardSet	= App.g_kSetManager.GetSet("CardSet")
	pCardCapt	= App.CharacterClass_GetObject(pCardSet, "CardCapt")
	
	pCardCaptKaroonDamaged1 = App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1KrellDamaged1", None, 0, g_pMissionDatabase)
	
	MissionLib.QueueActionToPlay(pCardCaptKaroonDamaged1)

################################################################################
##	KaroonDestroyed()
##	
##	Called in ShipDestroyed() if Karoon is destroyed.  Plays sequence and
##	also calls Episode level function so we know that Karoon is destroyed
##	later.
##	
##	Args: 	None
##	
##	Return: None
################################################################################
def KaroonDestroyed():
	# Set our episode level flag.
	Maelstrom.Episode2.Episode2.g_bKaroonDestroyed = TRUE
	
	# Mark the SOS as completed
	global g_bSOSCompleted
	global g_iMissionState
	g_bSOSCompleted = TRUE
	g_iMissionState	= DEFAULT

	pSequence = App.TGSequence_Create()
	
	pPreLoad				= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pFelixKaroonDestroyed1	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1KrellDestroyed1", "Captain", 1, g_pMissionDatabase)
	pSaffiKaroonDestroyed2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1KrellDestroyed2", None, 0, g_pMissionDatabase)
	pMiguelKaroonDestroyed2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1KrellDestroyed3", "Captain", 1, g_pMissionDatabase)
	pLiuHail				= App.TGScriptAction_Create(__name__, "LiuHail")
	
	pSequence.AddAction(pPreLoad)
	pSequence.AddAction(pFelixKaroonDestroyed1)
	pSequence.AddAction(pSaffiKaroonDestroyed2, pFelixKaroonDestroyed1)
	pSequence.AddAction(pMiguelKaroonDestroyed2, pSaffiKaroonDestroyed2, 3)	# 3 second delay after Saffi's line
	pSequence.AppendAction(pLiuHail)
		
	MissionLib.QueueActionToPlay(pSequence)
		
	# Remove our goal and add head home goal
	MissionLib.RemoveGoal("E2AidKrellGoal")

################################################################################
##	KaroonSurvives()
##
##	Called if Warbird escapes and Karoon still exists in set.
##
##	Args:	None
##
##	Return:	None
################################################################################
def KaroonSurvives():
	# Set the mission state back to the default
	global g_iMissionState
	g_iMissionState	= DEFAULT
	
	# Remove the Karoon from the tractorable list
	pMission = MissionLib.GetMission()
	if (pMission == None):
		return
	pTractorGroup = pMission.GetTractorGroup()
	pTractorGroup.RemoveName("Karoon")

	pCardSet	= App.g_kSetManager.GetSet("CardSet")
	pCardCapt	= App.CharacterClass_GetObject(pCardSet, "CardCapt")
	
	pSequence = App.TGSequence_Create()
	
	pPreLoad					= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pCallWaiting				= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)
	pKiskaIncoming				= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "IncomingMsg4", "Captain", 1, g_pGeneralDatabase)
	pCardViewOn					= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "CardSet", "CardCapt")
	pCardCaptKaroonSurvives1	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives1", None, 0, g_pMissionDatabase)
	pFelixKaroonSurvives2a		= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives2a", "Captain", 1, g_pMissionDatabase)
	pSaffiKaroonSurvives2b		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives2b", "Captain", 1, g_pMissionDatabase)
	pCardCaptKaroonSurvives2c	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives2c", None, 0, g_pMissionDatabase)
	pSaffiKaroonSurvives2d		= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives2d", "Captain", 1, g_pMissionDatabase)
	pCardCaptKaroonSurvives3	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives3", None, 0, g_pMissionDatabase)
	pViewOff					= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pKaroonWarp					= App.TGScriptAction_Create(__name__, "KaroonWarpOut")
	pEnableScan					= App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanMenu")
	pHailLiu					= App.TGScriptAction_Create(__name__, "LiuHail")
		
	# If the Karoon hasn't been scanned, do it automatically
	# here
	if (g_bKaroonScanned == FALSE):
		pScanKaroon	= App.TGScriptAction_Create(__name__, "KaroonScanned")
	else:
		pMiguelKaroonSurvives3a	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives3a", "Captain", 1, g_pMissionDatabase)
		pBrexKaroonSurvives3b	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives3b", None, 0, g_pMissionDatabase)
		pSaffiKaroonSurvives3c	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1KrellSurvives3c", None, 0, g_pMissionDatabase)

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pKiskaIncoming, 1)
	pSequence.AppendAction(pCardViewOn, 0.5)
	pSequence.AppendAction(pCardCaptKaroonSurvives1)
	pSequence.AppendAction(pFelixKaroonSurvives2a)
	pSequence.AppendAction(pSaffiKaroonSurvives2b)
	pSequence.AppendAction(pCardCaptKaroonSurvives2c)
	pSequence.AppendAction(pSaffiKaroonSurvives2d)
	pSequence.AppendAction(pCardCaptKaroonSurvives3)
	pSequence.AppendAction(pViewOff)		
	pSequence.AddAction(pKaroonWarp, pViewOff, 10)
	
	# Append the KaroonScanned sequence if we need it
	if (g_bKaroonScanned == FALSE):
		pSequence.AddAction(pScanKaroon, pViewOff)
	else:
		pSequence.AddAction(pMiguelKaroonSurvives3a, pViewOff)
		pSequence.AppendAction(pBrexKaroonSurvives3b)
		pSequence.AppendAction(pSaffiKaroonSurvives3c)
	
	# We always want this action.
	pSequence.AppendAction(pEnableScan)
	pSequence.AppendAction(pHailLiu)
		
	MissionLib.QueueActionToPlay(pSequence)
	
	# Mark the SOS as completed
	global g_bSOSCompleted
	g_bSOSCompleted = TRUE

	# Remove our goal and add head home goal
	MissionLib.RemoveGoal("E2AidKrellGoal")

################################################################################
##	KaroonWarpOut()
##
##	Called from sequence.  Resets the Karoon's AI so it warps out to
##	Starbase12
##
##	Args:	pTGAction	- The script action object
##
##	Return:	0	- Return 0 to keep calling sequence from crashing
################################################################################
def KaroonWarpOut(pTGAction):	
	# Get the set and the ship
	pSet	= App.g_kSetManager.GetSet("Beol4")
	pKaroon	= App.ShipClass_GetObject(pSet, "Karoon")
	
	# If the ship exists, set it's AI and turn collisions off
	if (pKaroon != None):
		import Maelstrom.Episode2.AI_WarpOut
		pKaroon.SetAI(Maelstrom.Episode2.AI_WarpOut.CreateAI(pKaroon))
		pKaroon.SetCollisionsOn(FALSE)
	
	return 0

################################################################################
##	LiuHail()
##
##	Sequence that lets the player know what to do next.  Called automatically as
##	script action when the mission ends either from WarbirdLeaves() or
##	KaroonSurvives().
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	1	- Return 1 to keep calling sequence paused.
################################################################################
def LiuHail(pTGAction):
	# Bail if the mission is terminating
	if (g_bMissionTerminate != 1):
		return 0
		
	# Check and set out flag
	if (g_bLiuHailDone == FALSE):
		global g_bLiuHailDone
		g_bLiuHailDone = TRUE
	else:
		return 0

	# Get the Database for E2M2
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 2/E2M2.TGL")

	# Get Liu
	pLiuSet = App.g_kSetManager.GetSet("StarbaseSet")
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")

	pSequence = App.TGSequence_Create()	

	pPreLoad				= App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines") 
	pCallWaiting			= App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE)	
	pSaffiHailStarfleet2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet2", "Captain", 1, g_pGeneralDatabase)
	pSaffiHailStarfleet7	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "HailStarfleet7", None, 0, g_pGeneralDatabase)
	pViewscreenOn			= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	if (g_bKaroonDestroyed == FALSE):
		pHailLiu1			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M1HailLiu1a", None, 0, g_pMissionDatabase)
	else:
		pHailLiu1			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M1HailLiu1", None, 0, g_pMissionDatabase)
	pHailLiu2				= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M1HailLiu2", None, 0, g_pMissionDatabase)
	pHailLiu3				= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M1HailLiu3", None, 0, g_pMissionDatabase)
	pLiuBriefing1			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M2Briefing1", None, 0, pDatabase)
	pLiuBriefing2			= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M2Briefing2", None, 0, pDatabase)
	pCreateSerris			= App.TGScriptAction_Create(__name__, "CreateSerris")
	pViewOff				= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pEndCallWaiting			= App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE)

	pSequence.AddAction(pPreLoad)
	pSequence.AppendAction(pCallWaiting)
	pSequence.AppendAction(pSaffiHailStarfleet2)
	pSequence.AppendAction(pSaffiHailStarfleet7, 1)
	pSequence.AppendAction(pViewscreenOn)
	pSequence.AppendAction(pHailLiu1)
	pSequence.AppendAction(pHailLiu2)
	pSequence.AppendAction(pHailLiu3)
	pSequence.AppendAction(pLiuBriefing1)
	pSequence.AppendAction(pLiuBriefing2)
	pSequence.AppendAction(pCreateSerris)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pEndCallWaiting)

	# Send event to tell calling sequence this one is done
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetObjPtr(pTGAction)
	pSequence.AddCompletedEvent(pEvent)

	pSequence.Play()

	# Unload the database
	App.g_kLocalizationManager.Unload(pDatabase)

	return 1
	
################################################################################
##	CreateSerris()
##
##	Creates the Serris system and links it to the next Mission.  Sets it as the
##	course heading
##
##	Args:	pTGAction	- The script action object.
##
##	Return:	0	- Return 0 to keep calling sequence from crashing.
################################################################################
def CreateSerris(pTGAction):
	# Pause the menu sorting
	App.SortedRegionMenu_SetPauseSorting(1)

	# Create the Serris buttons in the helm.
	import Systems.Serris.Serris
	pSerrisMenu	= Systems.Serris.Serris.CreateMenus()
	# Link the course in helm to the next mission
	pSerrisMenu.SetMissionName("Maelstrom.Episode2.E2M2.E2M2")

	# Unpause the menu sorting
	App.SortedRegionMenu_SetPauseSorting(0)

	# Set our goal
	MissionLib.AddGoal("E2InvestigateSerrisGoal")

	return 0

################################################################################
##	SupplyGekiCommunicate()
##
##	Called when player hits the communicate button on a character while
##	delivering supplies to Geki.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The caught by the CommunicateHandler()
##
##	Return:	None
################################################################################
def SupplyGekiCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose button got pushed and do their line.
	if (iMenuID == idKiskaMenu) and (g_bPlayerArriveGeki == TRUE) and (g_bGekiHailed == FALSE):
		pKiskaCom1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveGeki1a", "Captain", 1, g_pMissionDatabase)
		pKiskaCom1.Play()
		
	elif (iMenuID == idSaffiMenu) and (g_bGekiHailed == FALSE):
		# Get the episode level TGL
		pEpisode = MissionLib.GetEpisode()
		if (pEpisode != None):
			pDatabase = pEpisode.GetDatabase()
			pSaffiCom1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2SupplyCeli5GoalAudio", "Captain", 1, pDatabase)
			pSaffiCom1.Play()
		
	# Do the default action if the above tests didn't catch anything
	else:
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	SosReceivedCommunicate(pMenu.GetObjID(), TGObject, pEvent)
##
##	Called when player hits the communicate button on a character after they
##	have received the SOS.  Does special lines.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The caught by the CommunicateHandler()
##
##	Return:	None
################################################################################
def SosReceivedCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose button got pushed and do their line.
	if (iMenuID == idKiskaMenu):
		pKiskaCom1	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1KiskaCom1", "Captain", 1, g_pMissionDatabase)
		pKiskaCom1.Play()
		
	elif (iMenuID == idSaffiMenu):
		pSaffiCom1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SOSProd3", "Captain", 1, g_pMissionDatabase)
		pSaffiCom1.Play()
		
	elif (iMenuID == idMiguelMenu):
		pMiguelCom1	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1MiguelCom1", "Captain", 1, g_pMissionDatabase)
		pMiguelCom1.Play()
		
	elif (iMenuID == idBrexMenu):
		pBrexCom1	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1BrexCom1", "Captain", 1, g_pMissionDatabase)
		pBrexCom1.Play()
		
	# Do the default action if the above tests didn't catch anything
	else:
		TGObject.CallNextHandler(pEvent)
		
################################################################################
##	PlayerInBeolCommunicate()
##
##	Called when player hits the communicate button on a character after they
##	enter the Beol system.  Does special lines.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The caught by the CommunicateHandler()
##
##	Return:	None
################################################################################
def PlayerInBeolCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose button got pushed and do their line.
	if (iMenuID == idKiskaMenu) and (g_bFirstCloak == TRUE):
		pKiskaCom2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1KiskaCom3", "Captain", 1, g_pMissionDatabase)
		pKiskaCom2.Play()
		
	elif (iMenuID == idMiguelMenu):
		pMiguelCom2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1MiguelCom2", "Captain", 1, g_pMissionDatabase)
		pMiguelCom2.Play()
		
	elif (iMenuID == idBrexMenu):
		pBrexCom2	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1BrexCom2", "Captain", 1, g_pMissionDatabase)
		pBrexCom2.Play()
		
	# Do the default action if the above tests didn't catch anything
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	KaroonDriftingCommunicate()
##
##	Called when player hits the communicate button on a character after the
##	Karoon is sent drifting.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The caught by the CommunicateHandler()
##
##	Return:	None
################################################################################
def KaroonDriftingCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose button got pushed and do their line.
	if (iMenuID == idKiskaMenu) and (g_bFirstCloak == TRUE):
		pKiskaCom2	= App.CharacterAction_Create(g_pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1KiskaCom3", "Captain", 1, g_pMissionDatabase)
		pKiskaCom2.Play()
		
	elif (iMenuID == idFelixMenu) and (g_bFirstCloak == TRUE):
		pFelixCom2	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1FelixCom2", "Captain", 1, g_pMissionDatabase)
		pFelixCom2.Play()
		
	elif (iMenuID == idSaffiMenu):
		pSaffiCom2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SaffiCom2", "Captain", 1, g_pMissionDatabase)
		pSaffiCom2.Play()
		
	elif (iMenuID == idMiguelMenu):
		pMiguelCom2	= App.CharacterAction_Create(g_pMiguel, App.CharacterAction.AT_SAY_LINE, "E2M1MiguelCom2", "Captain", 1, g_pMissionDatabase)
		pMiguelCom2.Play()
		
	elif (iMenuID == idBrexMenu):
		pBrexCom2	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1BrexCom2", "Captain", 1, g_pMissionDatabase)
		pBrexCom2.Play()
		
	# Do the default action if the above tests didn't catch anything
	else:
		TGObject.CallNextHandler(pEvent)


################################################################################
##	WarbirdAttacksCommunicate()
##
##	Called when player hits the communicate button on a character after they
##	have been attacked by the Warbird.  Does special lines.
##
##	Args:	iMenuID		- The object ID of the menu that was clicked
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The caught by the CommunicateHandler()
##
##	Return:	None
################################################################################
def WarbirdAttacksCommunicate(iMenuID, TGObject, pEvent):
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose button got pushed and do their line.
	if (iMenuID == idFelixMenu):
		pFelixCom3	= App.CharacterAction_Create(g_pFelix, App.CharacterAction.AT_SAY_LINE, "E2M1FelixCom3", "Captain", 1, g_pMissionDatabase)
		pFelixCom3.Play()
		
	elif (iMenuID == idSaffiMenu):
		pSaffiCom3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1WarbirdCloaks4", "Captain", 1, g_pMissionDatabase)
		pSaffiCom3.Play()
		
	elif (iMenuID == idBrexMenu):
		pBrexCom3	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1BrexCom3", "Captain", 1, g_pMissionDatabase)
		pBrexCom3.Play()
		
	# Do the default action if the above tests didn't catch anything.
	else:
		TGObject.CallNextHandler(pEvent)

################################################################################
##	InVesuviCommunicate()
##
##	Called when player hits communicate button when first in Vesuvi
##
##	Args:	iMenuID		- The object ID of the menu that was clicked
##			TGObject	- The TGObject that was sent to CommunicateHandler()
##			pEvent		- The caught by the CommunicateHandler()
##
##	Return:	None
################################################################################
def InVesuviCommunicate(iMenuID, TGObject, pEvent):
	# If the player is not in Vesuvi 6, bail
	pSet = MissionLib.GetPlayerSet()
	if (pSet != None):
		if (pSet.GetName() != "Vesuvi6"):
			TGObject.CallNextHandler(pEvent)
			return
		
	# Get the IDs for all the menus.
	idKiskaMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Helm")
	idFelixMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("Tactical")
	idSaffiMenu 	= Bridge.BridgeUtils.GetBridgeMenuID("XO")
	idMiguelMenu	= Bridge.BridgeUtils.GetBridgeMenuID("Science")
	idBrexMenu		= Bridge.BridgeUtils.GetBridgeMenuID("Engineer")

	# Check and see whose button got pushed and do their line.

	if (iMenuID == idSaffiMenu):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 2/E2M0.TGL")
		E2M0SaffiCom3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M0SaffiCom3", "Captain", 1, pDatabase)
		E2M0SaffiCom3.Play()
		App.g_kLocalizationManager.Unload(pDatabase)
		
	elif (iMenuID == idBrexMenu):
		pBrexArrive4	= App.CharacterAction_Create(g_pBrex, App.CharacterAction.AT_SAY_LINE, "E2M1ArriveVesuvi4", None, 0, g_pMissionDatabase)
		pBrexArrive4.Play()
		
	# Do the default action if the above tests didn't catch anything.
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
	# If player hasn't responded to SOS
	if (g_bPlayerReceivedSOS == TRUE) and (g_bPlayerArriveBeol ==FALSE):
		ProdPlayerToSOS()
		
	elif(g_bPlayerNotInBeol == TRUE):
		ProdBackToBeol()
		
################################################################################
##	ProdPlayerToSOS()
##
##	Prodding specific to getting player to respond to SOS.  Uses global
##	g_iProdToSOS to keep track of which line to play.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ProdPlayerToSOS():

	pSequence = App.TGSequence_Create()

	global g_iProdToSOS
	# First time ProdPlayer calls us
	if (g_iProdToSOS == 0):
		pSaffiSOSProd1	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SOSProd1", "Captain", 0, g_pMissionDatabase)
		pSaffiSOSProd2	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SOSProd2", "Captain", 1, g_pMissionDatabase)
		pRestartTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)
		
		pSequence.AddAction(pSaffiSOSProd1)
		pSequence.AddAction(pSaffiSOSProd2, pSaffiSOSProd1)
		pSequence.AddAction(pRestartTimer, pSaffiSOSProd2)
		
		pSequence.Play()
		
		g_iProdToSOS = 1
	
	# Second time and after ProdPlayer calls us
	elif (g_iProdToSOS == 1):
		pSaffiSOSProd3	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SOSProd3", "Captain", 1, g_pMissionDatabase)
		pRestartTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)

		pSequence.AddAction(pSaffiSOSProd3)
		pSequence.AddAction(pRestartTimer, pSaffiSOSProd3)

		pSequence.Play()

		g_iProdToSOS = 2
		
	elif (g_iProdToSOS == 2):
		pSaffiSOSProd4	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SOSProd4", "Captain", 1, g_pMissionDatabase)
		pRestartTimer	= App.TGScriptAction_Create(__name__, "RestartProdTimer", 30)

		pSequence.AddAction(pSaffiSOSProd4)
		pSequence.AddAction(pRestartTimer, pSaffiSOSProd4)

		# End the mission
		pGameOver = App.TGScriptAction_Create("MissionLib", "GameOver", pSequence)
		pGameOver.Play()

################################################################################
##	ProdBackToBeol()
##
##	Called from ProdPlayer() if the player need to be prodded back to the Beol
##	system.
##
##	Args:	None
##
##	Return:	None
################################################################################
def ProdBackToBeol():
	# Check our flag and make sure we need to play
	if (g_bPlayerNotInBeol == FALSE):
		return
		
	# Check our prod counter and see what line we should play.
	if (g_iProdToBeolCounter == 0):
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerLeaves1", "Captain", 0, g_pMissionDatabase)
		pSaffiLine.Play()
		RestartProdTimer(None, 30)
		
	elif (g_iProdToBeolCounter == 1):
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerLeaves2", "Captain", 0, g_pMissionDatabase)
		pSaffiLine.Play()
		RestartProdTimer(None, 30)
		
	elif (g_iProdToBeolCounter == 2):
		# Alright kids! I'm turning this mission around right now!
		pSaffiLine	= App.CharacterAction_Create(g_pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1PlayerLeaves3", "Captain", 0, g_pMissionDatabase)
		pGameOver	= App.TGScriptAction_Create("MissionLib", "GameOver", pSaffiLine)
		pGameOver.Play()
		
	#Increase our counter
	global g_iProdToBeolCounter
	g_iProdToBeolCounter = g_iProdToBeolCounter + 1
	
################################################################################
##	ProdPlayerToVesuvi5OrSerris()
##
##	Prodding specific to getting the player to do something after SOS complete
##
##	Args:	None
##
##	Return:	None
################################################################################
def ProdPlayerToVesuvi5OrSerris():
	# Restart timer with 30 sec delay
	RestartProdTimer(App.TGAction_CreateNull(), 30)

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

	# Stop the friendly fire stuff
	MissionLib.ShutdownFriendlyFire()
	
	# Reset the viewscreen
	MissionLib.ResetViewscreen()
	
	# Remove our instance handlers
	RemoveInstanceHandlers()
	
	# unload the database: "data/TGL/Bridge Crew General.tgl"
	if (g_pGeneralDatabase):
		App.g_kLocalizationManager.Unload(g_pGeneralDatabase)

	# unload the database: "data/TGL/Bridge Menus.tgl"
	if (g_pDatabase):
		App.g_kLocalizationManager.Unload(g_pDatabase)
	
	# Stop our prod timer if it's running
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
	# Remove instance handler for friendly fire
	pMission = MissionLib.GetMission()
	if (pMission != None):
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT, __name__ + ".FriendlyFireReportHandler")
		# Instance handler on the mission for friendly fire game over
		pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER, __name__ + ".FriendlyFireGameOverHandler")
		
	# Kiska handlers
	pKiska = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Helm")
	if (pKiska != None):
		pKiskaMenu = pKiska.GetMenu()
		if (pKiskaMenu != None):
			pKiskaMenu.RemoveHandlerForInstance(App.ET_SET_COURSE,	__name__ + ".SetCourseHandler")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_HAIL,		__name__ + ".HailHandler")
			pKiskaMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")	
			# Remove instance handler for warp button
			pWarpButton = Bridge.BridgeUtils.GetWarpButton()
			if (pWarpButton != None):
				pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpButtonHandler")

	# Miguel handlers
	pMiguel = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Science")
	if (pMiguel != None):
		pMiguelMenu = pMiguel.GetMenu()
		if (pMiguelMenu != None):
			pMiguelMenu.RemoveHandlerForInstance(App.ET_SCAN,			__name__ + ".ScanHandler")
			pMiguelMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
	
	# Saffi handlers
	pSaffi = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	if (pSaffi != None):
		pSaffiMenu = pSaffi.GetMenu()
		if (pSaffiMenu != None):
			pSaffiMenu.RemoveHandlerForInstance(App.ET_CONTACT_STARFLEET,	__name__ + ".HailStarfleet")
			pSaffiMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,			__name__ + ".CommunicateHandler")	

	# Felix handlers
	pFelix = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Tactical")
	if (pFelix != None):
		pFelixMenu = pFelix.GetMenu()
		if (pFelixMenu != None):
			pFelixMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
	
	# Brex handlers
	pBrex = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
	if (pBrex != None):
		pBrexMenu = pBrex.GetMenu()
		if (pBrexMenu != None):
			pBrexMenu.RemoveHandlerForInstance(App.ET_COMMUNICATE,	__name__ + ".CommunicateHandler")
