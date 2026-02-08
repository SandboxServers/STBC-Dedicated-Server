###############################################################################
#	Filename:	Maelstrom.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	The game script for the Maelstrom campaign.
#	
#	Created:	8/11/2000 -	David Litwin
###############################################################################
import App
import MissionLib

#
# This is where you would put Game level module globals
#

# Number of freighters created/destroyed in E7M5(Bonus branch)
# These are checked in Episode 8.
iNumFreighters			= 0	
iNumFreightersDestroyed = 0

# Keep track of Geronimo and San Francisco's state throughout game.
bGeronimoAlive 			= 0
bZeissAlive				= 0

g_idPlayer				= App.NULL_ID

#
# Initialize() function
#
def Initialize(pGame):
	"Called Initialize and activate our Game"
	#
	# This is where you might set up your Game level module globals
	# don't forget to declare them global so they aren't treated as
	# Initialize() local functions.
	#

	# Set our Game level TGL
	pGame.SetDatabase("data/TGL/Maelstrom/Maelstrom.tgl")

	# Set the game name, for use with data files and such
	App.g_kUtopiaModule.SetGameName("Maelstrom")

	global g_bOrbitalFacilityHit
	global iNumFreighters
	global iNumFreightersDestroyed
	global bGeronimoAlive, bZeissAlive
	
	# Flag set to true if Orbital Facility hit in E1M2
	g_bOrbitalFacilityHit	= 0
	
	# Cardassian freighters created in E7M5 bonus.
	iNumFreighters = 4
	iNumFreightersDestroyed = 0 

	# Start off Geronimo and San Francisco as alive.	
	bGeronimoAlive 	= 1
	bZeissAlive = 1

	#
	# This is where you might call code to play the opening cutscene 
	#

	#
	# This is where you might setup handlers to listen for Episode
	# completion events, to trigger Game events that are handled by
	# loading up the next Episode and playing mid-game cutscenes
	#
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_DESTROYED, 
											pGame, __name__ + ".ObjectDestroyed")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER,
											pGame, __name__ + ".HandlePlayerChanged")
	
	#
	# Load the Game persistent stuff.
	#

	#
	# Start up the music system.
	#
	SetupMusic(pGame)

	# Load the Sounds for Tactical Station
	import LoadTacticalSounds
	LoadTacticalSounds.LoadSounds()


	#
	# Clear our SetManager and start loading the initial Episode
	#
	App.g_kSetManager.ClearRenderedSet()

	# Check if there is an episode override, and if so, then
	# use it.
	pcOverride = App.g_kVarManager.GetStringVariable("Options", "EpisodeOverride")

	if (pcOverride != ""):
		pGame.LoadEpisode("Maelstrom." + pcOverride + "." + pcOverride)
		App.g_kVarManager.SetStringVariable("Options", "EpisodeOverride", "")
	else:
		pGame.LoadEpisode("Maelstrom.Episode7.Episode7")



#
# SetupMusic
#
def SetupMusic(pGame):
	# Start up dynamic music.
	import DynamicMusic
	DynamicMusic.Initialize(pGame,
		# Base songs/fanfares to use as music...
		(("sfx/Music/Episode 2.mp3", "Starting Ambient"),
		("sfx/Music/Starbase12.mp3", "Starbase12 Ambient"),
		("sfx/Music/Nebula 1.mp3", "Nebula Ambient"),
		("sfx/Music/Panic-9a.mp3", "Cbt Panic 1"),
		("sfx/Music/Panic-9b.mp3", "Cbt Panic 2"),
		("sfx/Music/Panic-9c.mp3", "Cbt Panic 3"),
		("sfx/Music/Panic-9d.mp3", "Cbt Panic 4"),
		("sfx/Music/Panic-9e.mp3", "Cbt Panic 5"),
		("sfx/Music/Panic-9f.mp3", "Cbt Panic 6"),
		("sfx/Music/Panic-9g.mp3", "Cbt Panic 7"),
		("sfx/Music/Neutral-10i.mp3", "Cbt Neutral 1"),
		("sfx/Music/Neutral-10b.mp3", "Cbt Neutral 2"),
		("sfx/Music/Neutral-10c.mp3", "Cbt Neutral 3"),
		("sfx/Music/Neutral-10d.mp3", "Cbt Neutral 4"),
		("sfx/Music/Neutral-10e.mp3", "Cbt Neutral 5"),
		("sfx/Music/Neutral-10f.mp3", "Cbt Neutral 6"),
		("sfx/Music/Neutral-10g.mp3", "Cbt Neutral 7"),
		("sfx/Music/Neutral-10h.mp3", "Cbt Neutral 8"),
		("sfx/Music/Neutral-10a.mp3", "Cbt Neutral 9"),
		("sfx/Music/Confident-11a.mp3", "Cbt Confident 1"),
		("sfx/Music/Confident-11b.mp3", "Cbt Confident 2"),
		("sfx/Music/Confident-11c.mp3", "Cbt Confident 3"),
		("sfx/Music/Confident-11d.mp3", "Cbt Confident 4"),
		("sfx/Music/Confident-11e.mp3", "Cbt Confident 5"),
		("sfx/Music/Confident-11f.mp3", "Cbt Confident 6"),
		("sfx/Music/Confident-11g.mp3", "Cbt Confident 7")),
		# Which music to use as a transition between 2
		# other pieces.
		(),
		# Special music states which are collections of
		# pieces of music, played in random order.
		(("Nebula Ambient", ("Nebula1",
				"Nebula2")),
		("Combat Panic", ("Cbt Panic 1",
				"Cbt Panic 2",
				"Cbt Panic 3",
				"Cbt Panic 4",
				"Cbt Panic 5",
				"Cbt Panic 6",
				"Cbt Panic 7")),
		("Combat Neutral", ("Cbt Neutral 1",
				"Cbt Neutral 2",
				"Cbt Neutral 3",
				"Cbt Neutral 4",
				"Cbt Neutral 5",
				"Cbt Neutral 6",
				"Cbt Neutral 7",
				"Cbt Neutral 8",
				"Cbt Neutral 9")),
		("Combat Confident", ("Cbt Confident 1",
				"Cbt Confident 2",
				"Cbt Confident 3",
				"Cbt Confident 4",
				"Cbt Confident 5",
				"Cbt Confident 6",
				"Cbt Confident 7"))),
		# Which state machine to use
		DynamicMusic.StandardCombatMusic
		)

################################################################################
#	ObjectDestroyed(pObject, pEvent)
#
#	Called when an object is destroyed. If it's the player's ship,
#	return the player to the main menu.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def ObjectDestroyed(pObject, pEvent):
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	if(pShip):
		pcName = pShip.GetName()
		if(pcName == "player"):
			pSequence = App.TGSequence_Create()
			pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "FadeOut"))
			pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ExitGame"))
			pSequence.Play()

###############################################################################
#	HandlePlayerChanged(pGame, pEvent)
#	
#	Called when the player is changed. Sets up handlers for the player's
#	warp engines.
#	
#	Args:	pGame	- the game
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def HandlePlayerChanged(pGame, pEvent):
#	debug = App.CPyDebug(__name__).Print
#	debug("In HandlePlayerChanged()")

	global g_idPlayer

	if (g_idPlayer != App.NULL_ID):
		pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(g_idPlayer))
		if (pShip != None):
			pShip.RemoveHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DESTROYED, __name__ + ".HandleSubsystemDestroyed")

	pPlayer = App.Game_GetCurrentPlayer()
	if (pPlayer == None):
		g_idPlayer = App.NULL_ID
		return

	g_idPlayer = pPlayer.GetObjID()
	pPlayer.AddPythonFuncHandlerForInstance(App.ET_SUBSYSTEM_COMPLETELY_DESTROYED, __name__ + ".HandleSubsystemDestroyed")

###############################################################################
#	HandleSubsystemDestroyed(pObject, pEvent)
#	
#	Called when a subsystem belonging to the player has been destroyed. If
#	both of their warp engines are gone, the player should be destroyed.
#	
#	Args:	pPlayer	- the target of the event
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def HandleSubsystemDestroyed(pPlayer, pEvent):
#	debug = App.CPyDebug(__name__).Print

	if (pPlayer == None):
		return

	pWarp = App.WarpEngineSubsystem_Cast(pEvent.GetSource())
	pHull = pPlayer.GetHull()
	if (pWarp == None) or (pHull == None):
		return

	# The player will be destroyed if his warp engines are destroyed.
	pPlayer.DestroySystem(pHull)
#	debug("Warp engines destroyed, player is being killed")

#
# Terminate() function
#
def Terminate(pGame):
	# This is where we cleanup any game specific variables
	
	#
	# Unload our bridge set, which is specifically ignored from 
	# mission to mission, and generally ignored by the Episodes
	# (except the special case Galaxy->Sovereign switch in Ep 3)
	#
	App.g_kSetManager.DeleteAllSets()

	import DynamicMusic
	DynamicMusic.Terminate(pGame)
