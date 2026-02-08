###############################################################################
# MultiplayerGame.py
#
# The game script to run a multiplayer game
#
# Created 10-18-00	Alby
###############################################################################
import App

#
# This is where you would put Game level module globals
#



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

	#
	# This is where you might call code to play the opening cutscene 
	#

	#
	# This is where you might setup handlers to listen for Episode
	# completion events, to trigger Game events that are handled by
	# loading up the next Episode and playing mid-game cutscenes
	#

	#
	# Load the Game persistant stuff.
	#

	# Load the Sounds for Tactical Station
	import LoadTacticalSounds
	LoadTacticalSounds.LoadSounds()

	# Load Red/Yellow/Green alert sounds.
	pGame.LoadSound("sfx/redalert.wav", "RedAlertSound", 0)
	pGame.LoadSound("sfx/yellowalert.wav", "YellowAlertSound", 0)
	pGame.LoadSound("sfx/greenalert.wav", "GreenAlertSound", 0)

	# Start up the music system.
	SetupMusic(pGame)

	#
	# Clear our SetManager and start loading the initial Episode
	#
	App.g_kSetManager.ClearRenderedSet()
	pGame.LoadEpisode("Multiplayer.Episode.Episode")

	# In the multiplayer pre-game pane, enable the "Exit Multiplayer" button
	# and disable the buttons to start a new multiplayer game
	import Multiplayer.MultiplayerMenus
	Multiplayer.MultiplayerMenus.g_pClientButton.SetDisabled()
	Multiplayer.MultiplayerMenus.g_pHostButton.SetDisabled()
	Multiplayer.MultiplayerMenus.g_pExitButton.SetEnabled()


###############################################################################
#	SetupMusic()
#	
#	Sets up the music for this game
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def SetupMusic(pGame):
	# Start up dynamic music.
	import DynamicMusic
	DynamicMusic.Initialize(pGame,
		# Base songs/fanfares to use as music...
		(("sfx/Music/EpisGen3.mp3", "Starting Ambient"),
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
		("sfx/Music/Confident-11g.mp3", "Cbt Confident 7"),
		("sfx/Music/Failure-8d.mp3", "Lose"),
		("sfx/Music/Success-12.mp3", "Win")),
		# Which music to use as a transition between 2
		# other pieces.
		(),
		# Special music states which are collections of
		# pieces of music, played in random order.
		(("Combat Panic", ("Cbt Panic 1",
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
		# Which state machine to use.
		DynamicMusic.StandardCombatMusic)


#
# Terminate() function
#
def Terminate(pGame):

	# Turn off the music
	import DynamicMusic
	DynamicMusic.Terminate(pGame)
	
	# Enable and disable the appropriate buttons in the multiplayer
	# pre-game menu
	import Multiplayer.MultiplayerMenus
	Multiplayer.MultiplayerMenus.g_pClientButton.SetEnabled()
	Multiplayer.MultiplayerMenus.g_pHostButton.SetEnabled()
	Multiplayer.MultiplayerMenus.g_pExitButton.SetDisabled()

	# Hide the mission-specific pane
	Multiplayer.MultiplayerMenus.HideMissionPane()


	# This is where we cleanup any game specific variables
	#
	# Unload our bridge set, which is specifically ignored from 
	# mission to mission, and generally ignored by the Episodes
	# (except the special case Galaxy->Sovereign switch in Ep 3)
	#
	App.g_kSetManager.DeleteAllSets()
