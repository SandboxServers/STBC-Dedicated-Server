###############################################################################
#	Filename:	M2Objects.py
#	
#	Confidential and Proprietary, Copyright 2002 by Totally Games
#	
#	Basic mission in the tutorial, showing off some object creation.
#	
#	Created:	2/4/2002	- Erik Novales (ripped off of E2M6 because Jess
#							  has good style :P )
###############################################################################
import App
import loadspacehelper
import MissionLib

###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to add instances of ships we'll use. This is not mandatory,
#	but will prevent hitching when ships are created.
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	# Pre-create three Galaxy ships.
	loadspacehelper.PreloadShip("Galaxy", 3)
	
################################################################################
#	Initialize()
#	
#	Called once when mission loads to initialize mission.
#	
#	Args: 	pMission	- the mission object
#	
#	Return: None
################################################################################
def Initialize(pMission):
	# Specify (and load if necessary) the player's bridge. This is only
	# necessary for the first mission in the game, unless you're switching
	# bridges.
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")

	# Create the regions for this mission
	CreateRegions()
	
	# Create the starting objects
	CreateStartingObjects(pMission)

	# Setup object AI.
	SetupAI()
	
################################################################################
#	CreateRegions()
#
#	Creates the regions we'll be using in this mission.  Also loads in any
#	mission placement files we need.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateRegions():
	# Biranu 1
	import Systems.Biranu.Biranu
	pBiranuMenu		= Systems.Biranu.Biranu.CreateMenus()
	pBiranu1Set = MissionLib.SetupSpaceSet("Systems.Biranu.Biranu1")
	
	# Add our custom placement objects for this mission.
	import M2Biranu1_P
	M2Biranu1_P.LoadPlacements(pBiranu1Set.GetName())

################################################################################
#	CreateStartingObjects()
#
#	Creates all the objects that exist at the beginning of the mission and sets
# 	up the affiliations for all objects that will occur in the mission.
#
#	Args:	pMission	- The mission object.
#
#	Return:	None
################################################################################
def CreateStartingObjects(pMission):
	# get the sets we need
	pBiranu1Set		= App.g_kSetManager.GetSet("Biranu1")
	
	# Create the ships that exist at mission start
	pPlayer			= MissionLib.CreatePlayerShip("Galaxy", pBiranu1Set, "player", "Player Start")
	pGalaxy1		= loadspacehelper.CreateShip("Galaxy", pBiranu1Set, "Galaxy 1", "Galaxy1Start")
	pGalaxy2		= loadspacehelper.CreateShip("Galaxy", pBiranu1Set, "Galaxy 2", "Galaxy2Start")

	# Setup ship affiliations.
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Galaxy 1")

	pNeutrals = pMission.GetNeutralGroup()
	# No neutrals in this mission.

	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Galaxy 2")

###############################################################################
#	SetupAI()
#	
#	Sets up object AI.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupAI():
	pSet = App.g_kSetManager.GetSet("Biranu1")
	pGame = App.Game_GetCurrentGame()

	pGalaxy1 = App.ShipClass_GetObject(pSet, "Galaxy 1")
	pGalaxy2 = App.ShipClass_GetObject(pSet, "Galaxy 2")

	import EnemyAI
	import FriendlyAI

	pGalaxy1.SetAI(FriendlyAI.CreateAI(pGalaxy1))
	pGalaxy2.SetAI(EnemyAI.CreateAI(pGalaxy2))

	
################################################################################
#	Terminate()
#	
#	Called when mission ends to free resources
#	
#	Args: pMission - the mission object
#	
#	Return: None
################################################################################
def Terminate(pMission):
	# Clear out all the systems in the set course menu.
	App.SortedRegionMenu_ClearSetCourseMenu()
