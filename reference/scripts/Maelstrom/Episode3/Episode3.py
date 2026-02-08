###############################################################################
# Episode3.py
#
# This is a the Episode 3 script
#
# 	Created:	01-03-01	Matthew Kagle
# 	Modified:	12-20-01	Tony Evans
###############################################################################
import App
import MissionLib
import Bridge.BridgeUtils


TRUE	= 1
FALSE	= 0

#
# Place event types here
#
ET_DIALOGUE_WAIT	= App.Episode_GetNextEventType()

#
# Global variables 
#
bMission1Win		= 0
bMission2Win		= 0
bMission4Win		= 0
g_bWin4Good			= 0
pEpisodeDatabase	= None

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
	App.g_kUtopiaModule.LoadEpisodeSounds("Episode 3")

	"Called Initialize and activate an Episode"
	#
	# This is where you might set up your Episode level module globals
	# don't forget to declare them global so they aren't treated as
	# Initialize() local functions.
	#
	#Load sounds
	global pEpisodeDatabase
	pEpisodeDatabase = pEpisode.SetDatabase("data/TGL/Maelstrom/Episode 3/Episode3.tgl")

	#Load goal database and sounds
	pEpisode.SetDatabase("data/TGL/Maelstrom/Episode 3/Episode3.tgl")

	#
	# This is where you preload all the things you want for this Episode
	#

	#
	# This is where code would go putting location items
	# into the helm menu, which would trigger calls to LoadMission()
	# to switch the missions.
	#

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

	#
	# Start in the default mission of this episode.
	#

	# Check if there is a mission override, and if so, then
	# use it.
	pcOverride = App.g_kVarManager.GetStringVariable("Options", "MissionOverride")

	if (pcOverride != ""):
		pEpisode.LoadMission("Maelstrom.Episode3." + pcOverride + "." + pcOverride, pMissionStartEvent)
		App.g_kVarManager.SetStringVariable("Options", "MissionOverride", "")
	else:
		pEpisode.LoadMission("Maelstrom.Episode3.E3M1.E3M1", pMissionStartEvent)

################################################################################
#	Mission2Briefing()
#
#	Briefing sequence for mission 2.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission2Briefing(TGObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()

	MissionLib.DeleteAllGoals()

	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")

	pSequence = MissionLib.NewDialogueSequence()

	pAction = App.CharacterAction_Create(pHelm, App.CharacterAction.AT_SAY_LINE, "E3LiuM2Brief0", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LBridgeSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM2Brief1", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM2Brief2", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM2Brief3", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM2Brief4", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM2Brief5", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM2Brief6", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM2Brief8", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3WarpToCeli4Goal"))
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "AddGoalAction", "E3MeetWithBerkeleyGoal"))
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "OpenMission2"))
	MissionLib.QueueActionToPlay(pSequence)


################################################################################
#	OpenMission2(pAction)
#
#	Create Vesuvi system and add it to warp menu.
#
#	Args:	None
#
#	Return:	None
################################################################################
def OpenMission2(pAction):
	App.SortedRegionMenu_SetPauseSorting(1)

	import Systems.Starbase12.Starbase
	import Systems.Vesuvi.Vesuvi
	pVesuviMenu = Systems.Vesuvi.Vesuvi.CreateMenus()
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
	pVesuviMenu.SetMissionName("Maelstrom.Episode3.E3M2.E3M2")
	pSBMenu.SetMissionName("Maelstrom.Episode3.E3M2.E3M2")

	App.SortedRegionMenu_SetPauseSorting(0)

	return 0

################################################################################
#	Mission4Briefing()
#
#	Briefing sequence for mission 4.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission4Briefing(TGObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()

	pLBridgeSet = App.g_kSetManager.GetSet("LBridgeSet")
	pLiu = App.CharacterClass_GetObject (pLBridgeSet, "Liu")

	pSequence = MissionLib.NewDialogueSequence()
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM4Brief1", None, 0, pEpisodeDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM4Brief2", None, 0, pEpisodeDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM4Brief2b", None, 0, pEpisodeDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM4Brief3", None, 0, pEpisodeDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM4Brief4", None, 0, pEpisodeDatabase)
	pSequence.AppendAction (pAction)
	pAction = App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E3LiuM4Brief5", None, 0, pEpisodeDatabase)
	pSequence.AppendAction (pAction)
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "OpenMission4"))
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction (pAction)
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "CallWaiting", FALSE))
	MissionLib.QueueActionToPlay(pSequence)

###############################################################################
#	OpenMission4(pAction)
#	
#	Create goals and systems for Mission 4.
#	
#	Args:	pAction	- the script action.
#	
#	Return:	none
###############################################################################
def OpenMission4(pAction):
	MissionLib.DeleteAllGoals()

	# E3M4 Goals
	pEpisode = MissionLib.GetEpisode()
	pEpisode.RegisterGoal("E3WarpToXiEntradesGoal")
	pEpisode.RegisterGoal("E3WarpToItariGoal")
	pEpisode.RegisterGoal("E3WarpToVoltairGoal")
	pEpisode.RegisterGoal("E3InvestigateAttacksGoal")

	App.SortedRegionMenu_SetPauseSorting(1)

	# Create systems for Mission 4.
	import Systems.Voltair.Voltair
	pVoltairMenu = Systems.Voltair.Voltair.CreateMenus()
	pVoltairMenu.SetMissionName("Maelstrom.Episode3.E3M4.E3M4")

	import Systems.XiEntrades.XiEntrades
	pXiEntradesMenu = Systems.XiEntrades.XiEntrades.CreateMenus()
	pXiEntradesMenu.SetMissionName("Maelstrom.Episode3.E3M4.E3M4")

	import Systems.Itari.Itari
	pItariMenu = Systems.Itari.Itari.CreateMenus()
	pItariMenu.SetMissionName("Maelstrom.Episode3.E3M4.E3M4")

	import Systems.Starbase12.Starbase
	pSBMenu = Systems.Starbase12.Starbase.CreateMenus()
	pSBMenu.SetMissionName("Maelstrom.Episode3.E3M4.E3M4")

	App.SortedRegionMenu_SetPauseSorting(0)

	return 0

################################################################################
#	Mission5Briefing()
#
#	Briefing sequence for mission 5.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission5Briefing(pEvent, TGObject):
	pKBridgeSet = MissionLib.SetupBridgeSet("KBridgeSet", "data/Models/Sets/Klingon/BOPBridge.nif", -40, 65, -1.55)
	pKorbus = MissionLib.SetupCharacter("Bridge.Characters.Korbus", "KBridgeSet", 0, 0, -5)
	pHelm = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	pXO = Bridge.BridgeUtils.GetBridgeCharacter("XO")

	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()

	MissionLib.DeleteAllGoals()

	pSequence = MissionLib.NewDialogueSequence()

	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "KBridgeSet", "Korbus")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3KorbusBrief1", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_Create(pKorbus, App.CharacterAction.AT_SAY_LINE, "E3KorbusBrief2", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pSequence.AppendAction(Bridge.BridgeUtils.MakeCharacterLine(pHelm, "E3KorbusBrief2b", pEpisodeDatabase))
	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "E3KorbusBrief3", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "OpenMission5"))
	MissionLib.QueueActionToPlay(pSequence)

################################################################################
#	OpenMission5()
#
#	Create menu for mission 5 and add goals.
#
#	Args:	None
#
#	Return:	None
################################################################################
def OpenMission5(pAction):
	MissionLib.AddGoal("E3RespondToDistressCallGoal")
	MissionLib.AddGoal("E3WarpToBelaruz4Goal")

	import Systems.Belaruz.Belaruz
	pBelaruzMenu = Systems.Belaruz.Belaruz.CreateMenus()
	pBelaruzMenu.SetMissionName("Maelstrom.Episode3.E3M5.E3M5")

	return 0

################################################################################
#	Mission1Complete()
#
#	Called when E3M1 is won.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission1Complete():
#	print("Mission 1 Completed")
	global bMission1Win
	bMission1Win = 1

	# Delay before starting briefing.
	fStartTime = App.g_kUtopiaModule.GetGameTime()
	pTimer = MissionLib.CreateTimer(ET_DIALOGUE_WAIT, __name__ + ".Mission2Briefing",
									fStartTime + 5, 0, 0)

################################################################################
#	Mission2Complete()
#
#	Called when E3M2 is won.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission2Complete():
#	print("Mission 2 Completed")
	global bMission2Win
	bMission2Win = 1

	Mission4Briefing(None, None)

################################################################################
#	Mission4Complete()
#
#	Called when E3M4 is won.
#
#	Args:	None
#
#	Return:	None
################################################################################
def Mission4Complete(bGoodWin = 0):
#	print("Mission 4 Completed")
	global bMission4Win
	bMission4Win = 1

	# Set flag for whether you won this mission in a good way.
	global g_bWin4Good
	g_bWin4Good = bGoodWin

	Mission5Briefing(None, None)

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
		(("sfx/Music/Episode 3.mp3", "Starting Ambient"),
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
	global pEpisodeDatabase
	pEpisodeDatabase = None
	
	MissionLib.DeleteAllGoals()
	App.SortedRegionMenu_ClearSetCourseMenu()
	

