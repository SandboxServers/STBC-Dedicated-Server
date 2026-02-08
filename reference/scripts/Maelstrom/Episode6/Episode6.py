###############################################################################
# Episode6.py
#
# Episode 6 script.
#
# Created 08-11-00	David Litwin
###############################################################################
import App
import Maelstrom.Maelstrom

#
# Episode level module globals
#
TRUE	= 1
FALSE	= 0

g_bVentureDestroyedInOna	= None
g_bSFDestroyedInOna		= None

g_bVentureDestroyed	= None
g_bSFDestroyed		= None
g_bDevoreDestroyed	= None

g_idSanFrancisco	= None
g_idVenture		= None
g_idDevore		= None
g_idCambridge	= None
g_idInverness	= None
g_idShannon		= None

################################################################################
##	Initialize() 
##
##	Initializes our Episode.
##
##	Args:	pEpisode	- The episode object.
##
##	Return:	None
################################################################################
def Initialize(pEpisode):
	App.g_kUtopiaModule.LoadEpisodeSounds("Episode 6")

	"Called Initialize and activate an Episode"
	#
	# Initialize all our Episode level global variables
	#
	# Globals used for tracking destroyed ships
	global g_bVentureDestroyedInOna
	global g_bSFDestroyedInOna
	global g_bVentureDestroyed
	global g_bSFDestroyed
	global g_bDevoreDestroyed
	g_bVentureDestroyedInOna	= FALSE
	g_bSFDestroyedInOna		= FALSE
	g_bVentureDestroyed		= FALSE
	g_bSFDestroyed			= FALSE
	g_bDevoreDestroyed		= FALSE

	# Global pointers to ship objects so we can recreate
	# them if they survive
	global g_idSanFrancisco
	global g_idVenture
	global g_idDevore
	global g_idCambridge
	global g_idInverness
	global g_idShannon
	g_idSanFrancisco	= App.NULL_ID
	g_idVenture		= App.NULL_ID
	g_idDevore		= App.NULL_ID
	g_idCambridge	= App.NULL_ID
	g_idInverness	= App.NULL_ID
	g_idShannon		= App.NULL_ID
		
	# Set our Episode level TGL
	pEpisode.SetDatabase("data/TGL/Maelstrom/Episode 6/Episode6.tgl")
	
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
		pEpisode.LoadMission("Maelstrom.Episode6." + pcOverride + "." + pcOverride, pMissionStartEvent)
		App.g_kVarManager.SetStringVariable("Options", "MissionOverride", "")
	else:
		pEpisode.LoadMission("Maelstrom.Episode6.E6M1.E6M1", pMissionStartEvent)



#
# Termintate our Episode
#
def Terminate(pEpisode):
	# Delete all the ships we were holding on to.
	for idShip in (
		g_idSanFrancisco,
		g_idDevore,
		g_idVenture,
		g_idShannon,
		g_idInverness,
		g_idCambridge
		):
		pShip = App.ShipClass_Cast(App.TGObject_GetTGObjectPtr(idShip))
		if pShip:
			# Got it.  Send an event to delete it.
			pEvent = App.TGEvent_Create()
			pEvent.SetEventType(App.ET_DELETE_OBJECT_PUBLIC)
			pEvent.SetDestination(pShip)
			App.g_kEventManager.AddEvent(pEvent)

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
		(("sfx/Music/Episode 6.mp3", "Starting Ambient"),
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
##	SetVentureDestroyedInOna()
##
##	Set the status of g_bVentureDestroyedInOna.  Called in E6M1
##
##	Args:	bNewValue	- New value for g_bVentureDestroyedInOna
##
##	Return:	None
################################################################################
def SetVentureDestroyedInOna(bNewValue):
	# Check and make sure we have a valid number
	if ((bNewValue != TRUE) and (bNewValue != FALSE)):
#		print "Can't set bVentureDestroyedInOna.  Sent value: " + str(bNewValue)
		return
	
	# Set the new value
	global g_bVentureDestroyedInOna
	g_bVentureDestroyedInOna = bNewValue

	return

################################################################################
##	GetVentureDestroyedInOna()
##
##	Returns the value of g_bVentureDestroyedInOna
##
##	Args:	None
##
##	Return:	g_bVentureDestroyedInOna
################################################################################
def GetVentureDestroyedInOna():
	# Return the value
	return g_bVentureDestroyedInOna
	
################################################################################
##	SetSFDestroyedInOna()
##
##	Set the status of g_bSFDestroyedInOna.  Called in E6M1
##
##	Args:	bNewValue	- New value for g_bSFDestroyedInOna
##
##	Return:	None
################################################################################
def SetSFDestroyedInOna(bNewValue):
	# Check and make sure we have a valid number
	if ((bNewValue != TRUE) and (bNewValue != FALSE)):
#		print "Can't set g_bSFDestroyedInOna.  Sent value: " + str(bNewValue)
		return
	
	# Set the new value
	global g_bSFDestroyedInOna
	g_bSFDestroyedInOna = bNewValue

	return

################################################################################
##	GetSFDestroyedInOna()
##
##	Returns the value of g_bSFDestroyedInOna
##
##	Args:	None
##
##	Return:	bSFDestroyedInOna
################################################################################
def GetSFDestroyedInOna():
	# Return the value
	return g_bSFDestroyedInOna

################################################################################
##	SetSFDestroyed()
##
##	Set the status of g_bSFDestroyed.  Called in E6M1
##
##	Args:	bNewValue	- New value for g_bSFDestroyed
##
##	Return:	None
################################################################################
def SetSFDestroyed(bNewValue):
	# Check and make sure we have a valid number
	if ((bNewValue != TRUE) and (bNewValue != FALSE)):
#		print "Can't set g_bSFDestroyed.  Sent value: " + str(bNewValue)
		return
	
	# Set the new value
	global g_bSFDestroyed
	g_bSFDestroyed = bNewValue

	# Set bZeissAlive to false so Tony knows that the SF was destroyed for E8
	Maelstrom.Maelstrom.bZeissAlive = 0
	
	return

################################################################################
##	IsSFDestroyed()
##
##	Returns the value of g_bSFDestroyed
##
##	Args:	None
##
##	Return:	bSFDestroyed
################################################################################
def IsSFDestroyed():
	# Return the value
	return g_bSFDestroyed

################################################################################
##	SetVentureDestroyed()
##
##	Set the status of bVentureDestroyed.  Called in E6M1
##
##	Args:	bNewValue	- New value for g_bVentureDestroyed
##
##	Return:	None
################################################################################
def SetVentureDestroyed(bNewValue):
	# Check and make sure we have a valid number
	if ((bNewValue != TRUE) and (bNewValue != FALSE)):
#		print "Can't set g_bVentureDestroyed.  Sent value: " + str(bNewValue)
		return
	
	# Set the new value
	global g_bVentureDestroyed
	g_bVentureDestroyed = bNewValue

	return

################################################################################
##	IsVentureDestroyed()
##
##	Returns the value of g_bVentureDestroyed
##
##	Args:	None
##
##	Return:	g_bVentureDestroyed
################################################################################
def IsVentureDestroyed():
	# Return the value
	return g_bVentureDestroyed

################################################################################
##	SetDevoreDestroyed()
##
##	Set the status of g_bDevoreDestroyed.  Called in E6M1
##
##	Args:	bNewValue	- New value for g_bDevoreDestroyed
##
##	Return:	None
################################################################################
def SetDevoreDestroyed(bNewValue):
	# Check and make sure we have a valid number
	if ((bNewValue != TRUE) and (bNewValue != FALSE)):
#		print "Can't set g_bDevoreDestroyed.  Sent value: " + str(bNewValue)
		return
	
	# Set the new value
	global g_bDevoreDestroyed
	g_bDevoreDestroyed = bNewValue

	return

################################################################################
##	IsDevoreDestroyed()
##
##	Returns the value of g_bDevoreDestroyed
##
##	Args:	None
##
##	Return:	bDevoreDestroyed
################################################################################
def IsDevoreDestroyed():
	# Return the value
	return g_bDevoreDestroyed
