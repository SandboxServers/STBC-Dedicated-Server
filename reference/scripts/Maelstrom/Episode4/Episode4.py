###############################################################################
#	Filename:	Episode4.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Episode 4
#
#	Created 01-11-01	Matthew Kagle
#			04-19-01	Alberto Fonseca
#
###############################################################################
import App
import MissionLib
import Bridge.BridgeUtils

#NonSerializedObjects = ( "debug", )
#debug = App.CPyDebug(__name__).Print


TRUE	= 1
FALSE	= 0

#
# Episode level globals
#
g_bMission4Win 		= 0
g_bMission6Win 		= 0
g_pEpisodeDatabase 	= 0

################################################################################
#	Initialize(pEpisode)
#
#	Called at episode start.
#
#	Args:	pEpisode - Current episode starting.
#
#	Return:	None
################################################################################
def Initialize(pEpisode):
	App.g_kUtopiaModule.LoadEpisodeSounds("Episode 4")

	# Set episode database global.
	global g_pEpisodeDatabase
	g_pEpisodeDatabase = pEpisode.SetDatabase("data/TGL/Maelstrom/Episode 4/Episode4.tgl")

	# Create Korbus bridge set.
	#MissionLib.SetupBridgeSet("KBridgeSet", "data/Models/Sets/Klingon/BOPBridge.nif", -40, 65, -1.55)
	#MissionLib.SetupCharacter("Bridge.Characters.Korbus", "KBridgeSet", 0, 0, -5)

	#
	# Setup music for this episode.
	#
	SetupMusic()

	#
	# Start in the default mission of this episode.
	#
	pMissionStartEvent = App.TGEvent_Create()
	pMissionStartEvent.SetEventType(App.ET_MISSION_START)
	pMissionStartEvent.SetDestination(pEpisode)
	
	# Add instance handler to handle mission start event.
	pEpisode.AddPythonFuncHandlerForInstance(App.ET_MISSION_START, __name__ +".MissionLoaded")

	# Start in the default mission of this episode.
	# Check if there is a mission override, and if so, then
	# use it.
	pcOverride = App.g_kVarManager.GetStringVariable("Options", "MissionOverride")

	if (pcOverride != ""):
		pEpisode.LoadMission("Maelstrom.Episode4." + pcOverride + "." + pcOverride, pMissionStartEvent)
		App.g_kVarManager.SetStringVariable("Options", "MissionOverride", "")
	else:
		pEpisode.LoadMission("Maelstrom.Episode4.E4M6.E4M6", pMissionStartEvent)
		
################################################################################
#	MissionLoaded(pObject, pEvent)
#
#	Event handler for ET_MISSION_START event. 
#	Called when mission is done loading.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MissionLoaded(pObject, pEvent):
	# Create Data bridge character and set him up on bridge.
	MakeDataOnBridge()

	# Setup communicate handlers for all characters in mission.
	Bridge.BridgeUtils.SetupCommunicateHandlers()
	pData = Bridge.BridgeUtils.GetBridgeCharacter("Data")
	pMenu = pData.GetMenu()
	pcScript = MissionLib.GetMission().GetScript()
	pMenu.AddPythonFuncHandlerForInstance(App.ET_COMMUNICATE, pcScript + 
											".CommunicateData")

	pObject.CallNextHandler(pEvent)
	
################################################################################
#	MakeDataOnBridge()
#
#	Make Data and put him on the bridge if he's not already there.
#
#	Args:	None
#
#	Return:	None
################################################################################
def MakeDataOnBridge():
#	print "Episode4.py - MakeDataOnBridge() called."
	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
#	if(pSet is None):
#		debug("MakeDataOnBridge(), Bridge set not found.")
	pData = App.CharacterClass_GetObject(pSet, "Data")
	if(pData is None):
#		debug("MakeDataOnBridge(), Data not found.")
		import Bridge.Characters.Data
		pData = App.CharacterClass_GetObject(pSet, "Data")
		if not (pData):
			pData = Bridge.Characters.Data.CreateCharacter(pSet)
			Bridge.Characters.Data.ConfigureForSovereign(pData)
			pData.SetLocation("EBGuest")
		import Bridge.Characters.CommonAnimations
		Bridge.Characters.CommonAnimations.PutGuestChairIn()

################################################################################
#	Mission4Dialogue(pAction)
#
#	Dialogue to tell you mission 4 can be played.
#
#	Args:	pAction - the action.
#
#	Return:	None
################################################################################
def Mission4Dialogue(pAction):
#	debug("Mission 4 is now available")

	# Enable Belaruz
	import Systems.Belaruz.Belaruz
	pBelaruzMenu = Systems.Belaruz.Belaruz.CreateMenus()
	pBelaruzMenu.SetMissionName("Maelstrom.Episode4.E4M4.E4M4")

	pKBridgeSet = App.g_kSetManager.GetSet("KBridgeSet")
	pKorbus = App.CharacterClass_GetObject (pKBridgeSet, "Korbus")

	# Play sequence
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn",
													"KBridgeSet", "Korbus"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", TRUE))
	pSequence.AppendAction(App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE,
							"E4KorbusBriefing", None, 0, g_pEpisodeDatabase))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOff"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
	pSequence.Play()

	# E4M4 initial goal.
	MissionLib.AddGoal("E4MeetWithKorbusGoal")

	return 0

################################################################################
#	Mission4Complete()
#
#	Called when E4M4 is won. 
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission4Complete():
#	debug("Mission 4 Completed")
	global g_bMission4Win
	g_bMission4Win = 1
	
	# If both E4M4 and E4M6 have been won.
	if(g_bMission4Win and g_bMission6Win):
		# Enable Mission 5
		import Systems.Starbase12.Starbase
		pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
		pSBMenu.SetMissionName("Maelstrom.Episode4.E4M5.E4M5")
	else:
		# Setup return to Mission 6
		import Systems.Nepenthe.Nepenthe
		pNepentheMenu = Systems.Nepenthe.Nepenthe.CreateMenus()
		pNepentheMenu.SetMissionName("Maelstrom.Episode4.E4M6.E4M6")
		pNepentheMenu.SetRegionName("Systems.Nepenthe.Nepenthe1")
		MissionLib.AddGoal("E4GoToNepentheGoal")

################################################################################
#	Mission5Complete()
#
#	Called when E4M5 is won. Loads Episode 5.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission5Complete():
#	debug("Episode 4 Completed")
	pMenu = MissionLib.GetSystemOrRegionMenu("Starbase 12")
	pMenu.SetEpisodeName("Maelstrom.Episode5.Episode5")

################################################################################
#	Mission6Complete()
#
#	Called when E4M6 is won.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission6Complete():
#	debug("Mission 6 Completed")
	global g_bMission6Win
	g_bMission6Win = 1

	# If both E4M4 and E4M6 have been won.
	if(g_bMission4Win and g_bMission6Win):
		# Link Starbase 12 menu item to mission E4M5.
		import Systems.Starbase12.Starbase
		pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
		pSBMenu.SetMissionName("Maelstrom.Episode4.E4M5.E4M5")

################################################################################
#	SetupMusic
#
#	Set the music to this episode's music.
#
#	Args:	None
#
#	Return:	None
################################################################################
def SetupMusic():
	import DynamicMusic
	DynamicMusic.ChangeMusic(
		# Base songs/fanfares to use as music...
		(("sfx/Music/Episode 5b.mp3", "Kessok Fanfare"),
		("sfx/Music/Episode 4.mp3", "Starting Ambient"),
		("sfx/Music/Starbase12.mp3", "Starbase12 Ambient"),
		("sfx/Music/Nebula 1.mp3", "Nebula Ambient"),
		("sfx/Music/Cutscene_Generic.mp3", "Generic Cutscene"),
		("sfx/Music/EpisGen1.mp3", "Generic Episode 1"),
		("sfx/Music/EpisGen2.mp3", "Generic Episode 2"),
		("sfx/Music/EpisGen3.mp3", "Generic Episode 3"),
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

################################################################################
#	Terminate()
#
#	End of episode.
#
#	Args:	pEpisode, current episode playing.
#
#	Return:	None
################################################################################
def Terminate(pEpisode):
	global g_pEpisodeDatabase
	g_pEpisodeDatabase = None

