###############################################################################
# QuickBattleEpisode.py
#
# Simply load the QuickBattle mission
#
# Created 10-19-00	David Litwin
###############################################################################
import App

#
# This is where you would put Episode level module globals
#


#
# Initialize our Episode
#
def Initialize(pEpisode):
	"Called Initialize and activate an Episode"
	#
	# This is where you might set up your Episode level module globals
	# don't forget to declare them global so they aren't treated as
	# Initialize() local functions.
	#

	#
	# This is where you preload all the things you want for this Episode
	#

	#
	# This is where code would go putting location items
	# into the helm menu, which would trigger calls to LoadMission()
	# to switch the missions.
	#

	#
	# Start in the default mission of this episode.
	#
	pMissionStartEvent = App.TGEvent_Create()
	pMissionStartEvent.SetEventType(App.ET_MISSION_START)
	pMissionStartEvent.SetDestination(pEpisode)

	pEpisode.LoadMission("QuickBattle.QuickBattle", pMissionStartEvent)



#
# Termintate our Episode
#
def Terminate(pEpisode):
	"Called Terminate and de-activate an Episode"
	pass

