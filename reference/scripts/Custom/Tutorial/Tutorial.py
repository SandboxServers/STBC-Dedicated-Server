###############################################################################
#	Filename:	Tutorial.py
#	
#	Confidential and Proprietary, Copyright 2002 by Totally Games
#	
#	The game script for the mission scripting tutorial.
#	
#	Created:	2/4/2002 -	Erik Novales
###############################################################################
import App
import MissionLib

# Globals
g_idPlayer = App.NULL_ID

###############################################################################
#	Initialize(pGame)
#	
#	Initializes the game.
#	
#	Args:	pGame	- the game object
#	
#	Return:	none
###############################################################################
def Initialize(pGame):
	"Called Initialize and activate our Game"
	#
	# This is where you might set up your Game level module globals
	# don't forget to declare them global so they aren't treated as
	# Initialize() locals.
	#

	# Set our Game level TGL
	pGame.SetDatabase("data/TGL/Tutorial/Tutorial.tgl")

	# Set the game name, for use with data files and such
	App.g_kUtopiaModule.SetGameName("Tutorial")

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
		pGame.LoadEpisode("Custom.Tutorial." + pcOverride + "." + pcOverride)
		App.g_kVarManager.SetStringVariable("Options", "EpisodeOverride", "")
	else:
		pGame.LoadEpisode("Custom.Tutorial.Episode.Episode")



###############################################################################
#	SetupMusic(pGame)
#	
#	Sets up the dynamic music system.
#	
#	Args:	pGame	- the game object
#	
#	Return:	none
###############################################################################
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
	if pShip and (pShip.GetObjID() == g_idPlayer):
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
	global g_idPlayer

	pPlayer = App.Game_GetCurrentPlayer()
	if (pPlayer == None):
		g_idPlayer = App.NULL_ID
		return

	g_idPlayer = pPlayer.GetObjID()

###############################################################################
#	MakeMissionButton(sName)
#	
#	Makes a mission button for this campaign.
#	
#	Args:	sName	- the name for the button
#	
#	Return:	the button
###############################################################################
def MakeMissionButton(sName):
	import MainMenu.mainmenu

	pButton = App.STButton_Create(sName)
	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(MainMenu.mainmenu.ET_CUSTOM_MISSION)
	pEvent.SetDestination(pButton)
	pButton.SetActivationEvent(pEvent)
	pButton.AddPythonFuncHandlerForInstance(MainMenu.mainmenu.ET_CUSTOM_MISSION, __name__ + ".MissionHandler")

	return pButton

###############################################################################
#	CreateMenu()
#	
#	Creates a menu for the custom mission menu. Allows the player to select
#	any mission in this campaign.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def CreateMenu():
	pMenu = App.STMenu_Create("Tutorial")

	pMenu.AddChild(MakeMissionButton("M1Basic"))
	pMenu.AddChild(MakeMissionButton("M2Objects"))
	pMenu.AddChild(MakeMissionButton("M3Gameflow"))
	pMenu.AddChild(MakeMissionButton("M4Complex"))

	return pMenu

###############################################################################
#	MissionHandler(pButton, pEvent)
#	
#	Handler for button presses, for the mission selection menu.
#	
#	Args:	pButton	- the button that triggered us. Used to determine the
#					  correct override mission.
#			pEvent	- the event
#	
#	Return:	none
###############################################################################
def MissionHandler(pButton, pEvent):
	pButton = App.STButton_Cast(pButton)
	if not pButton:
		App.Breakpoint()
	import MainMenu.mainmenu

	dButtonToOverride = {
		"M1Basic":		["Episode", "M1Basic"],
		"M2Objects":	["Episode", "M2Objects"],
		"M3Gameflow":	["Episode",	"M3Gameflow"],
		"M4Complex":	["Episode", "M4Complex"]
	}

	kString = App.TGString()
	pButton.GetName(kString)

	sName = kString.GetCString()

	if dButtonToOverride.has_key(sName):
		App.g_kVarManager.SetStringVariable("Options", "EpisodeOverride", dButtonToOverride[sName][0])
		App.g_kVarManager.SetStringVariable("Options", "MissionOverride", dButtonToOverride[sName][1])
	else:
		App.g_kVarManager.SetStringVariable("Options", "EpisodeOverride", "")
		App.g_kVarManager.SetStringVariable("Options", "MissionOverride", "")

	# Send the override mission event.
	pTop = App.TopWindow_GetTopWindow()
	pOptions = pTop.FindMainWindow(App.MWT_OPTIONS)
	pEvent = App.TGStringEvent_Create()
	pEvent.SetEventType(MainMenu.mainmenu.ET_CUSTOM_MISSION)
	pEvent.SetDestination(pOptions)
	pEvent.SetString("Tutorial")
	App.g_kEventManager.AddEvent(pEvent)
	return

###############################################################################
#	Terminate(pGame)
#	
#	Cleans up the game.
#	
#	Args:	pGame	- the game object
#	
#	Return:	none
###############################################################################
def Terminate(pGame):
	#
	# Unload our bridge set, which is specifically ignored from 
	# mission to mission, and generally ignored by the Episodes
	#
	App.g_kSetManager.DeleteAllSets()

	import DynamicMusic
	DynamicMusic.Terminate(pGame)
