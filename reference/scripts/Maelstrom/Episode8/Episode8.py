###############################################################################
# Episode8.py
#
# Script for Episode 8
#
# 	Created:	10/07/00	Bill Morrison
#	Modified:	11/02/01	Tony Evans
###############################################################################
import App

#
# This is where you would put Episode level module globals
#

pEpisodeDatabase	= None

# Keep track of Zeiss' state throughout the Episode.
bZeissAlive 			= 0

# Tells you if Kessoks are friendly
KessoksFriendly			= 0


#
# Initialize our Episode
#
def Initialize(pEpisode):
	App.g_kUtopiaModule.LoadEpisodeSounds("Episode 8")

	"Called Initialize and activate an Episode"
	#
	# This is where you might set up your Episode level module globals
	# don't forget to declare them global so they aren't treated as
	# Initialize() local functions.
	#

	global bZeissAlive

	# Start off Zeiss' ship as alive.	
	bZeissAlive = 1

	#
	# This is where you preload all the things you want for this Episode
	#

	#Load goal database and sounds
	global pEpisodeDatabase
	pEpisodeDatabase = pEpisode.SetDatabase("data/TGL/Maelstrom/Episode 8/Episode8.tgl")

	#Bridge Crew General global Goal sounds
#	print ("Loading global Goal sounds.")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8NewGoalAdded")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8NewGoalsAdded")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8GoalComplete")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8GoalsComplete")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8MissionFailed")

	#E8M1 Goals
#	print ("Loading E8M1 Goal sounds.")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8DestroyDevicesGoalAudio")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8DestroyDevicesGoal2Audio")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8Starbase12GoalAudio")

	#E8M2 Goals
#	print ("Loading E8M2 Goal sounds.")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8ContactKessoksGoalAudio")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8StopSolarformerGoalAudio")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8DestroyEmittersGoalAudio")
	pEpisode.LoadDatabaseSound(pEpisodeDatabase, "E8GetMatanGoalAudio")

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
		pEpisode.LoadMission("Maelstrom.Episode8." + pcOverride + "." + pcOverride, pMissionStartEvent)
		App.g_kVarManager.SetStringVariable("Options", "MissionOverride", "")
	else:
		pEpisode.LoadMission("Maelstrom.Episode8.E8M1.E8M1", pMissionStartEvent)



################################################################################
##	SetupMusic
##
##	Set the music to this episode's music.
##
##	Args:	None
##
##	Return:	None
################################################################################
def SetupMusic():
	import DynamicMusic
	DynamicMusic.ChangeMusic(
		# Base songs/fanfares to use as music...
		(("sfx/Music/Episode 8.mp3", "Starting Ambient"),
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

#
# Terminate our Episode
#
def Terminate(pEpisode):
	"Called Terminate and de-activate an Episode"

	pass
	

