###############################################################################
# Episode2.py
#
# Episode level script.  Holds variables and functions global to Episode
#
# Created 11-13-00	Jess VanDerwalker
###############################################################################
import App
import MissionLib

# For debugging
#kDebugObj = App.CPyDebug()


# Declare global variables
TRUE	= 1
FALSE	= 0

g_bKaroonDestroyed = None

################################################################################
##	Initialize()
##	
##  Called once when episode loads to initialize episode
##	
##	Args: 	pEpisode	- The episode object
##	
##	Return: None
################################################################################
def Initialize(pEpisode):
	App.g_kUtopiaModule.LoadEpisodeSounds("Episode 2")

	"Called Initialize and activate an Episode"	
	
	# Initialize our global variables
	global g_bKaroonDestroyed
	g_bKaroonDestroyed = FALSE
	
	# Set our Episode level TGL
	pEpisode.SetDatabase("data/TGL/Maelstrom/Episode 2/Episode2.tgl")
	
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

	# Start in the default mission of this episode.
	# Check if there is a mission override, and if so, then
	# use it.
	pcOverride = App.g_kVarManager.GetStringVariable("Options", "MissionOverride")

	if (pcOverride != ""):
		pEpisode.LoadMission("Maelstrom.Episode2." + pcOverride + "." + pcOverride, pMissionStartEvent)
		App.g_kVarManager.SetStringVariable("Options", "MissionOverride", "")
	else:
		pEpisode.LoadMission("Maelstrom.Episode2.E2M0.E2M0", pMissionStartEvent)
	
################################################################################
##	E2M1KrellSOS()
##
##	Creates the sets, play the SOS from the Krell.
##
##	Args:	None
##
##	Return:	None
################################################################################
def E2M1KrellSOS():
#	kDebugObj.Print("E2M1 Krell SOS sequence.")
	# Create the Cardassian bridge
	pCardSet = MissionLib.SetupBridgeSet("CardSet", "data/Models/Sets/Cardassian/cardbridge.nif", -30, 65, -1.55)
	pCardCapt = MissionLib.SetupCharacter("Bridge.Characters.CardCapt", "CardSet")
	pCardCapt.SetHidden(1)

	
	pMission = MissionLib.GetMission()
	if (pMission == None):
		return
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 2/E2M1.TGL")
	
	# Do the SOS sequence.
	pSequence = App.TGSequence_Create()
	
	pBridge		= App.g_kSetManager.GetSet("bridge")
	pCardSet	= App.g_kSetManager.GetSet("CardSet")
	
	pSaffi		= App.CharacterClass_GetObject(pBridge, "XO")
	pKiska		= App.CharacterClass_GetObject(pBridge, "Helm")
	pCardCapt	= App.CharacterClass_GetObject(pCardSet, "CardCapt")
	
	pKiskaSOS1		= App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS1", None, 0, pMissionDatabase)
	pKiskaSOS2		= App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS2", None, 0, pMissionDatabase)
	pKiskaSOS3		= App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS3", "Captain", 1, pMissionDatabase)
	pCommOn			= App.TGSoundAction_Create("ViewOn")
	pCardCaptSOS5	= App.TGScriptAction_Create("MissionLib", "SubtitledLine", pMissionDatabase, "E2M1SOS5")
	pKiskaSOS6		= App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS6", "Captain", 1, pMissionDatabase)
	pSaffiSOS4		= App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SOS4", None, 0, pMissionDatabase)
	pCardViewOn		= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "CardSet", "CardCapt")
	pCardCaptSOS8	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1SOS8", None, 0, pMissionDatabase)
	pCardCaptSOS9	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1SOS9", None, 0, pMissionDatabase)
	pCardCaptSOS10	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1SOS10", None, 0, pMissionDatabase)
	pSaffiSOS11		= App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E2M1SOS11", None, 0, pMissionDatabase)
	pCardCaptSOS12	= App.CharacterAction_Create(pCardCapt, App.CharacterAction.AT_SAY_LINE, "E2M1SOS12", None, 0, pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pKiskaSOS13		= App.CharacterAction_Create(pKiska, App.CharacterAction.AT_SAY_LINE, "E2M1SOS13", "Captain",0, pMissionDatabase)
	
	
	pSequence.AppendAction(pKiskaSOS1)
	pSequence.AppendAction(pKiskaSOS2)
	pSequence.AppendAction(pKiskaSOS3)
	pSequence.AppendAction(pCommOn)
	pSequence.AppendAction(pCardCaptSOS5)
	pSequence.AppendAction(pKiskaSOS6)
	pSequence.AppendAction(pSaffiSOS4)
	pSequence.AppendAction(pCardViewOn)
	pSequence.AppendAction(pCardCaptSOS8)
	pSequence.AppendAction(pCardCaptSOS9)
	pSequence.AppendAction(pCardCaptSOS10)
	pSequence.AppendAction(pSaffiSOS11)
	pSequence.AppendAction(pCardCaptSOS12)
	pSequence.AppendAction(pViewOff)
	pSequence.AppendAction(pKiskaSOS13)
	
	pSequence.Play()

	# Get the Episode and register our Aid Krell Goal
	# Remove the SupplyGeki goal if it's still there
	MissionLib.AddGoal("E2AidKrellGoal")

################################################################################
##	E2M3Briefing()
##
##	Plays the briefing and links us to Episode 2 Mission 3.
##
##	Args:	None
##
##	Return:	None
################################################################################
def E2M3Briefing():
#	kDebugObj.Print("Starting E2M3")
	# Set the TGL for the mission and load the sounds
	# that we need.
	pMission = MissionLib.GetMission()
	if (pMission == None):
		return
	pMissionDatabase = pMission.SetDatabase("data/TGL/Maelstrom/Episode 2/E2M3.TGL")
		
	# Do our intro sequence
	pBridge		= App.g_kSetManager.GetSet("bridge")
	pStarbase	= App.g_kSetManager.GetSet("StarbaseSet")
	
	pFelix	= App.CharacterClass_GetObject(pBridge, "Tactical")
	pLiu	= App.CharacterClass_GetObject(pStarbase, "Liu")
	
	pSequence = App.TGSequence_Create()
	
	pFelixLine027	= App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E2M3Briefing1", "Captain", 1, pMissionDatabase)
	pStarbaseViewOn	= App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "StarbaseSet", "Liu")
	pLiuLine028		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M3Briefing2", None, 0, pMissionDatabase)
	pLiuLine029		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M3Briefing3", None, 0, pMissionDatabase)
	pLiuLine030		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M3Briefing4", None, 0, pMissionDatabase)
	pLiuLine031		= App.CharacterAction_Create(pLiu, App.CharacterAction.AT_SAY_LINE, "E2M3Briefing5", None, 0, pMissionDatabase)
	pViewOff		= App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	
	pSequence.AddAction(pFelixLine027)
	pSequence.AddAction(pStarbaseViewOn, pFelixLine027)
	pSequence.AddAction(pLiuLine028, pStarbaseViewOn)
	pSequence.AddAction(pLiuLine029, pLiuLine028)
	pSequence.AddAction(pLiuLine030, pLiuLine029)
	pSequence.AddAction(pLiuLine031, pLiuLine030)
	pSequence.AddAction(pViewOff, pLiuLine031)
	
	pSequence.Play()
	
	# Link the warp button to the new menu
	import Systems.Vesuvi.Vesuvi
	pVesuviMenu = Systems.Vesuvi.Vesuvi.CreateMenus()

	# Set the mission name for the button
	pVesuviMenu.SetMissionName("Maelstrom.Episode2.E2M3.E2M3")

	# Remove our goal to Supply Vesuvi 5 and add the 
	# Head to Vesuvi 6 goal
	MissionLib.RemoveGoal("E2SupplyCeli5Goal")
	MissionLib.AddGoal("E2HeadToCeli6Goal")

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
		(("sfx/Music/Episode 2.mp3", "Starting Ambient"),
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
##	Terminate()
##
##	Called to terminate our episode.
##
##	Args:	pEpisode	- The episode level object.
##
##	Return:	None
################################################################################
def Terminate(pEpisode):
	"Called Terminate and de-activate an Episode"
	pass
