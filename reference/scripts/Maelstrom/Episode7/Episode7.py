###############################################################################
# Episode7.py
#
# This is a sample Episode script
#
# Created	08/11/00	David Litwin
# Modified	11/21/01 	Tony Evans
###############################################################################
import App
import MissionLib
import Maelstrom
import Tactical.Projectiles.PhasedPlasma

# For debugging
#kDebugObj = App.CPyDebug()

#
# Episode level globals
#

pEpisodeDatabase		= None
iNumFreightersEscaped	= 4		# Keeps track of the number of Freighters that escaped in 7.3, for use in 7.6

TRUE		= 1
FALSE		= 0

g_bPhasedTorpFail 		= FALSE
g_bTorpWait				= FALSE

#
# Initialize our Episode
#
def Initialize(pEpisode):
	App.g_kUtopiaModule.LoadEpisodeSounds("Episode 7")

	# Torpedo Enter event
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TORPEDO_FIRED, pEpisode, __name__ +".TorpedoFired")

	"Called Initialize and activate an Episode"
	#
	# This is where you might set up your Episode level module globals
	# don't forget to declare them global so they aren't treated as
	# Initialize() local functions.

	global pEpisodeDatabase
	pEpisodeDatabase = pEpisode.SetDatabase("data/TGL/Maelstrom/Episode 7/Episode7.tgl")

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
		pEpisode.LoadMission("Maelstrom.Episode7." + pcOverride + "." + pcOverride, pMissionStartEvent)
		App.g_kVarManager.SetStringVariable("Options", "MissionOverride", "")
	else:
		pEpisode.LoadMission("Maelstrom.Episode7.E7M1.E7M1", pMissionStartEvent)


#
# TorpedoFired()
#
def TorpedoFired(TGObject, pEvent):
	# Check if torpedo being fired is Phased Plasma
	pTorpedo = App.Torpedo_Cast(pEvent.GetSource())

	if pTorpedo and not g_bTorpWait:
		pPlayer = MissionLib.GetPlayer()
		if pPlayer and (pPlayer.GetObjID() == pTorpedo.GetParentID()):
			# It's the player shooting.
			pTorpSys = pPlayer.GetTorpedoSystem()
			if pTorpSys:
				pAmmoType = pTorpSys.GetCurrentAmmoType()
				if pAmmoType:
					# Torpedo is Phased Plasma
					if pAmmoType.GetAmmoName() == Tactical.Projectiles.PhasedPlasma.GetName():
						# Find out how many Phased Plasma torps are left
						iNumTypes = pTorpSys.GetNumAmmoTypes()
						for iType in range(iNumTypes):
							pTorpType = pTorpSys.GetAmmoType(iType)
							if (pTorpType.GetAmmoName() == pAmmoType.GetAmmoName()):
								if (pTorpSys.GetNumAvailableTorpsToType(iType) <= 0):
									# Remove Handler if Phased Plasma torp count is 0
									App.g_kEventManager.RemoveBroadcastHandler(App.ET_TORPEDO_FIRED, MissionLib.GetEpisode(), __name__ +".TorpedoFired")

						iNum = App.g_kSystemWrapper.GetRandomNumber(10)
						# 10% chance of Phased Plasma torpedo leaking plasma
						if iNum == 1:
							# Destroy the torpedo tube
							pLauncher = App.ShipSubsystem_Cast(pEvent.GetDestination())
							MissionLib.SetConditionPercentage(pLauncher, 0)

							# Add explosion sound.
							pAction = App.TGSoundAction_Create("Explosion 5")
							pAction.Play()
							
							pBridge = App.g_kSetManager.GetSet("bridge")
							pFelix	= App.CharacterClass_GetObject(pBridge, "Tactical")
							pSaffi	= App.CharacterClass_GetObject(pBridge, "XO")
							pBrex	= App.CharacterClass_GetObject(pBridge, "Engineer")

							global g_bTorpWait
							g_bTorpWait = TRUE

							pSequence = App.TGSequence_Create()

							if (pLauncher.GetName()[:len("Forward")] == "Forward"):
								bForwardLauncher = TRUE
							else:
								bForwardLauncher = FALSE

							if bForwardLauncher:
								# Forward launcher damaged
								pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps11", "Captain", 1, pEpisodeDatabase)
							else:
								# Aft launcher damaged
								pAction = App.CharacterAction_Create(pFelix, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps12", "Captain", 1, pEpisodeDatabase)

							pSequence.AppendAction(pAction, 2)

							if not g_bPhasedTorpFail:
								pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps13", "E", 0, pEpisodeDatabase)
								pSequence.AppendAction(pAction)
								pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps14", "C", 0, pEpisodeDatabase)
								pSequence.AppendAction(pAction)
	
							if bForwardLauncher:
								# Forward launcher damaged
								pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps15", "C", 0, pEpisodeDatabase)
								pSequence.AppendAction(pAction)
								pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps17", "C", 0, pEpisodeDatabase)

							else:
								# Aft launcher damaged
								pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps16", "C", 0, pEpisodeDatabase)
								pSequence.AppendAction(pAction)
								pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps18", "C", 0, pEpisodeDatabase)
	
								pSequence.AppendAction(pAction)

							if not g_bPhasedTorpFail:
								pAction = App.CharacterAction_Create(pBrex, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps19", "C", 1, pEpisodeDatabase)
								pSequence.AppendAction(pAction)
								pAction = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps20", "Captain", 1, pEpisodeDatabase)
								pSequence.AppendAction(pAction)
								pAction = App.TGScriptAction_Create(__name__, "SetupLiuDockingDialogue")
								pSequence.AppendAction(pAction)

								# First time a Phased Plasma Torpedo fails
								global g_bPhasedTorpFail
								g_bPhasedTorpFail = TRUE

							pAction = App.TGScriptAction_Create(__name__, "ResetTorpWait")
							pSequence.AppendAction(pAction)

							MissionLib.QueueActionToPlay(pSequence)

	# We're done.  Let any other handlers for this event handle it.
	TGObject.CallNextHandler(pEvent)


#
# SetupLiuDockingDialogue()
#
def SetupLiuDockingDialogue(pAction):

	pGeneralDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	pSequence = App.TGSequence_Create()

	pAction = App.CharacterAction_CreateByName("FedOutpostSet_Graff", "Graff", App.CharacterAction.AT_SAY_LINE, "gg011", None, 0, pGeneralDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create(__name__, "CreateLiuSet")
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu")
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_CreateByName("LiuSet", "Liu", App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps21", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_CreateByName("LiuSet", "Liu", App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps22", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_CreateByName("LiuSet", "Liu", App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps23", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.CharacterAction_CreateByName("LiuSet", "Liu", App.CharacterAction.AT_SAY_LINE, "E7M1NewTorps24", None, 0, pEpisodeDatabase)
	pSequence.AppendAction(pAction)
	pAction = App.TGScriptAction_Create("MissionLib", "ViewscreenOff")
	pSequence.AppendAction(pAction)

	import Systems.Starbase12.Starbase12_S
	Systems.Starbase12.Starbase12_S.SetGraffDockingAction(pSequence)

	App.g_kLocalizationManager.Unload(pGeneralDatabase)

	return 0


#
#	CreateLiuSet - Creates Liu's Set for the Docking Action
#
def CreateLiuSet(pAction):
	MissionLib.SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif")
	MissionLib.SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet")

	return 0


#
# ResetTorpWait()
#
def ResetTorpWait(paction):
	global g_bTorpWait
	g_bTorpWait = FALSE

	return 0


################################################################################
##	UnloadDatabase()
##
##	Unload the TGL that we loaded to play the sequence.  Called as script action
##
##	Args:	pTGAction	- The script action object
##			pDatabase	- The database that needs to be unloaded
##
##	Return:	0	- Return 0 to keep calling sequence from crashing
################################################################################
def UnloadDatabase(pTGAction, pDatabase):
	# unload the database
	if ((not App.IsNull(pDatabase)) and (pDatabase != None)):
		App.g_kLocalizationManager.Unload(pDatabase)
	
	return 0



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
		(("sfx/Music/Episode 7.mp3", "Starting Ambient"),
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
