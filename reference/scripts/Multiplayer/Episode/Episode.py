###############################################################################
# Episode.py
#
# This is a sample Episode script
#
# Created 10-18-00	Alby
###############################################################################
import App

#
# This is where you would put Episode level module globals
#


###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to add models to be pre loaded
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	return 0

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
	
	# Make sure the chat window is properly positioned
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
	pChatWindow = pMultWindow.GetChatWindow()
	pChatWindow.SetPosition(0.0, 0.0, 0)
	if pChatWindow.IsVisible():
		pMultWindow.ToggleChatWindow()

	#
	# Get the mission name from the var manager.
	#
	pMissionStartEvent = App.TGEvent_Create()
	pMissionStartEvent.SetEventType(App.ET_MISSION_START)
	pMissionStartEvent.SetDestination(pEpisode)

	pcMissionScript = App.g_kVarManager.GetStringVariable ("Multiplayer", "Mission")
	pEpisode.LoadMission(pcMissionScript, pMissionStartEvent)


#
# Termintate our Episode
#
def Terminate(pEpisode):
	"Called Terminate and de-activate an Episode"
	pass

