###############################################################################
#	Filename:	M1Basic.py
#	
#	Confidential and Proprietary, Copyright 2002 by Totally Games
#	
#	Basic mission in the tutorial, to illustrate the minimum a mission needs
#	to be functional.
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
	# Pre-create one Galaxy.
	loadspacehelper.PreloadShip("Galaxy", 1)
	
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
	
################################################################################
#	CreateStartingObjects()
#
#	Creates all the objects that exist at the beginning of the mission.
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
