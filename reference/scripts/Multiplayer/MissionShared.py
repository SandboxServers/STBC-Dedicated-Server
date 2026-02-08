import App

# Setup the debugging output function.
#debug = App.CPyDebug(__name__).Print
#debug("Loading multiplayer module: " + __name__)

#global variables
NonSerializedObjects = (
#"debug",
"g_pStartingSet",
"g_pDatabase",
"g_pShipDatabase",
"g_pSystemDatabase",
)

# Global variables.  
# Start messages at +10 so that there's some room for stuff like
# chat messages and such.
MISSION_INIT_MESSAGE = App.MAX_MESSAGE_TYPES + 10
SCORE_CHANGE_MESSAGE = App.MAX_MESSAGE_TYPES + 11
SCORE_MESSAGE = App.MAX_MESSAGE_TYPES + 12
END_GAME_MESSAGE = App.MAX_MESSAGE_TYPES + 13
RESTART_GAME_MESSAGE = App.MAX_MESSAGE_TYPES + 14

END_ITS_JUST_OVER = 0
END_TIME_UP = 1
END_NUM_FRAGS_REACHED = 2
END_SCORE_LIMIT_REACHED = 3
END_STARBASE_DEAD = 4
END_BORG_DEAD = 5
END_ENTERPRISE_DEAD = 6

#define event types.  For multiplayer missions, start at 50.
ET_UPDATE_TIME_LEFT		= App.g_kVarManager.MakeEpisodeEventType(50)
ET_GAME_END				= App.g_kVarManager.MakeEpisodeEventType(51)
ET_RESTART_GAME			= App.g_kVarManager.MakeEpisodeEventType(52)
ET_SUBTITLED_SOUND_DONE	= App.g_kVarManager.MakeEpisodeEventType(53)



g_pStartingSet = None
g_pDatabase = None
g_pShipDatabase = None
g_pSystemDatabase = None

g_bGameOver = 0

g_iTimeLeft = 0.0
g_idTimeLeftTimer = App.NULL_ID
g_iTimerIncrement = 1

#Kill the Mission database
def Terminate(pMission):
	import MissionMenusShared
	import MissionLib
	
	# Turn off friendly fire warnings
	MissionLib.ShutdownFriendlyFireNoGameOver()

	pWarpButton = App.SortedRegionMenu_GetWarpButton() 
	if (pWarpButton):
		pWarpButton.RemoveHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	# Unload databases.
	App.g_kLocalizationManager.Unload(g_pDatabase)
	App.g_kLocalizationManager.Unload(g_pShipDatabase)
	App.g_kLocalizationManager.Unload(g_pSystemDatabase)

	# Destroy panes built by this mission.
	MissionMenusShared.DeleteMissionMenus ()
	# Kill the timers
	global g_idTimeLeftTimer
	if (g_idTimeLeftTimer):
		App.g_kTimerManager.DeleteTimer(g_idTimeLeftTimer)
		g_idTimeLeftTimer = App.NULL_ID

	# Clear globals
	global g_pStartingSet
	g_pStartingSet = None
	global g_pDatabase
	g_pDatabase = None
	global g_pShipDatabase
	g_pShipDatabase = None
	global g_pSystemDatabase
	g_pSystemDatabase = None

	g_bGameOver = 0

	g_iTimeLeft = 0.0
	g_idTimeLeftTimer = App.NULL_ID
	g_iTimerIncrement = 1

	MissionMenusShared.g_iUseScoreLimit = 0
	MissionMenusShared.g_iSpecies = 0
	MissionMenusShared.g_iSystem = 0
	MissionMenusShared.g_iTimeLimit = -1
	MissionMenusShared.g_iFragLimit = -1
	MissionMenusShared.g_iPlayerLimit = MissionMenusShared.MAX_PLAYER_LIMIT

	MissionMenusShared.g_bShipSelectState = 0

	MissionMenusShared.g_bAllowNoTimeLimit = 1
	MissionMenusShared.g_bGameStarted = 0

	MissionMenusShared.g_pShipIcon = None
	MissionMenusShared.g_pShipSideText = None
	MissionMenusShared.g_pShipDescText = None
	MissionMenusShared.g_pShipNameText = None
	MissionMenusShared.g_pSystemDescText = None
	MissionMenusShared.g_pTimeLimitButton = None
	MissionMenusShared.g_pTimeLimitText = None
	MissionMenusShared.g_pFragLimitButton = None
	MissionMenusShared.g_pFragLimitText = None
	MissionMenusShared.g_pPlayerLimitText = None
	MissionMenusShared.g_pPlayerLimitButton = None
	MissionMenusShared.g_pStartButton = None
	MissionMenusShared.g_pInfoPane = None
	MissionMenusShared.g_pSystemPane = None
	MissionMenusShared.g_pSystemDescPane = None
	MissionMenusShared.g_pSystemIcon = None
	MissionMenusShared.g_pShipSelectWindow = None
	MissionMenusShared.g_pEndOkayButton = None
	MissionMenusShared.g_pEndRestartButton = None
	MissionMenusShared.g_pEndTimePane = None
	MissionMenusShared.g_pEndFragPane = None
	MissionMenusShared.g_pEndGlass = None
	MissionMenusShared.g_pEndGameOverText = None
	MissionMenusShared.g_pEndReasonText = None
	MissionMenusShared.g_pEndInstructionText = None
	MissionMenusShared.g_pEndWinnerText = None
	MissionMenusShared.g_pEndPlayerListWindow = None
	MissionMenusShared.g_pEndPlayerListMenu = None
	MissionMenusShared.g_pEndPlayerListPane = None
	MissionMenusShared.g_pEndChatWindow = None
	MissionMenusShared.g_pEndChatSubPane = None
	MissionMenusShared.g_pBackButton = None
	MissionMenusShared.g_pChosenSpecies = None
	MissionMenusShared.g_pChosenSystem = None
	MissionMenusShared.g_pSystemDescWindow = None


#Mission startup
def Initialize(pMission):
	import Multiplayer.MultiplayerMenus
	import LoadBridge
	import MissionLib

	LoadBridge.CreateCharacterMenus ()

	# Turn on friendly fire warnings
	MissionLib.SetupFriendlyFireNoGameOver()
	App.g_kUtopiaModule.SetFriendlyFireWarningPoints(100)

	# Load databases
	global g_pDatabase
	global g_pShipDatabase
	global g_pSystemDatabase

	### Load database
	g_pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")
	g_pShipDatabase = App.g_kLocalizationManager.Load("data/TGL/Ships.tgl")
	g_pSystemDatabase = App.g_kLocalizationManager.Load("data/TGL/Systems.tgl")

	#Setup event handlers
	SetupEventHandlers(pMission)

	global g_idTimeLeftTimer
	g_idTimeLeftTimer = App.NULL_ID

	global g_bGameOver
	g_bGameOver = 0

	Multiplayer.MultiplayerMenus.g_bExitPressed = 0

	# Load string database
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	pGame = App.Game_GetCurrentGame()
	pGame.LoadDatabaseSoundInGroup(pDatabase, "MiguelScan", "BridgeGeneric")
	pGame.LoadDatabaseSoundInGroup(pDatabase, "gs038", "BridgeGeneric")

	App.g_kLocalizationManager.Unload(pDatabase)
	# Now we're done.  The menu will do the work to create the ship.
	

# setup any event handlers specific to this mission.
def SetupEventHandlers (pMission):
	# setup handler for listening for packets.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NETWORK_MESSAGE_EVENT, pMission, __name__ + ".ProcessMessageHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SCAN, pMission, __name__ + ".ScanHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(ET_SUBTITLED_SOUND_DONE, pMission, __name__ + ".SoundDoneHandler")

	pWarpButton = App.SortedRegionMenu_GetWarpButton() 
	pWarpButton.AddPythonFuncHandlerForInstance(App.ET_WARP_BUTTON_PRESSED, __name__ + ".WarpHandler")

	return 0

def WarpHandler (pSelf, pEvent):
	pPlayer = App.Game_GetCurrentGame ().GetPlayer ()
	if (pPlayer):
		if (not (pPlayer.IsDying () or pPlayer.IsDead ())):
			# Only do the warp if we're not already dying.
			pSelf.CallNextHandler (pEvent)
	return

def ProcessMessageHandler (self, pEvent):
	import MissionMenusShared
	import MissionLib

	pMessage = pEvent.GetMessage()
	if not App.IsNull(pMessage):
		# Get the data from the message
		# Open a buffer stream to read the data
		kStream = pMessage.GetBufferStream ();

		cType = kStream.ReadChar ();

		cType = ord (cType)

		if (cType == END_GAME_MESSAGE):
			# End a game due to time or frag limit.
			global g_bGameOver
			g_bGameOver = 1
			ClearShips ()	# Clear any ships and torps
			
			# Find out why the game is over:
			cType = kStream.ReadInt();

			pString = None
			if cType == END_TIME_UP:
				pString = g_pDatabase.GetString("Time Expired")
			elif cType == END_NUM_FRAGS_REACHED:
				pString = g_pDatabase.GetString("Frag Limit Reached")
			elif cType == END_SCORE_LIMIT_REACHED:
				pString = g_pDatabase.GetString("Score Limit Reached")
			elif cType == END_STARBASE_DEAD:
				pString = g_pDatabase.GetString("Starbase Destroyed")
				# If we're playing mission 5 or 6, we should make sure that the
				# starbase has been marked as having been killed
				pcMissionName = MissionLib.GetMission().GetScript()

				if pcMissionName == "Multiplayer.Episode.Mission5.Mission5" or pcMissionName == "Multiplayer.Episode.Mission6.Mission6":
					pMissionScript = __import__(pcMissionName)
					pMissionScript.g_bStarbaseDead = 1
			elif cType == END_BORG_DEAD:
				pString = g_pDatabase.GetString("Borg Destroyed")

				pcMissionName = MissionLib.GetMission().GetScript()

				# If we're playing mission 7, we should make sure that the
				# Borg has been marked as having been killed
				pcMissionName = MissionLib.GetMission().GetScript()
				if pcMissionName == "Multiplayer.Episode.Mission7.Mission7":
					pMissionScript = __import__(pcMissionName)
					pMissionScript.g_bBorgDead = 1
			elif cType == END_ENTERPRISE_DEAD:
				pString = g_pDatabase.GetString("Enterprise Destroyed")

				pcMissionName = MissionLib.GetMission().GetScript()

				# If we're playing mission 9, we should make sure that the
				# Enterprise has been marked as having been killed
				pcMissionName = MissionLib.GetMission().GetScript()
				if pcMissionName == "Multiplayer.Episode.Mission9.Mission9":
					pMissionScript = __import__(pcMissionName)
					pMissionScript.g_bEnterpriseDead = 1
			else:
				pString = None
				
			MissionMenusShared.DoEndGameDialog(1, pString, 1)

		kStream.Close ()

def CreateTimeLeftTimer (iTimeLeft):
	import MissionLib

	global g_iTimeLeft
	g_iTimeLeft = iTimeLeft
	
	# Create an infinte timer to update the time left.
	# ***FIXME: TGTimer::DURATION_INFINITE needs to be wrapped
	pTimer = MissionLib.CreateTimer(ET_UPDATE_TIME_LEFT, __name__ + ".UpdateTimeLeftHandler", App.g_kUtopiaModule.GetRealTime() + g_iTimerIncrement, g_iTimerIncrement, -1.0, 0, 1)

	global g_idTimeLeftTimer
	g_idTimeLeftTimer = pTimer.GetObjID()	# used to delete timer on exit

def UpdateTimeLeftHandler (pObject, pEvent):
	import MissionMenusShared
	if (g_bGameOver):
		# Don't update time if game is over
		return

	# decrement time left by g_iTimerIncrement
	global g_iTimeLeft
	if (g_iTimeLeft > 0):
		g_iTimeLeft = g_iTimeLeft - g_iTimerIncrement
		if g_iTimeLeft <= 0: 
			g_iTimeLeft = 0
			if App.g_kUtopiaModule.IsHost():
				EndGame(END_TIME_UP)

	MissionMenusShared.UpdateTimeLeftDisplay(None, 1)

	if (pObject):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	EndGame()
#	
#	The game is over. Send a message to all computers and tell them so
#	
#	Args:	int		iReason		- a flag explaining why the game is over
#	
#	Return:	None
###############################################################################
def EndGame(iReason = END_ITS_JUST_OVER):
	pNetwork = App.g_kUtopiaModule.GetNetwork ()

	if (not pNetwork):
		return

	# Send a message to everybody telling them to restart their game.
	pMessage = App.TGMessage_Create ()
	pMessage.SetGuaranteed (1)		# Yes, this is a guaranteed packet
	
	# Setup the stream.
	kStream = App.TGBufferStream ()		# Allocate a local buffer stream.
	kStream.OpenBuffer (256)				# Open the buffer stream with a 256 byte buffer.
	
	# Write relevant data to the stream.
	# First write message type.
	kStream.WriteChar (chr (END_GAME_MESSAGE))
	kStream.WriteInt(iReason)
	
	# Okay, now set the data from the buffer stream to the message
	pMessage.SetDataFromStream (kStream)

	# Send the message.
	pNetwork.SendTGMessage (0, pMessage)

	# We're done.  Close the buffer.
	kStream.CloseBuffer ()

	pMultGame = App.MultiplayerGame_Cast (App.Game_GetCurrentGame ())
	pMultGame.SetReadyForNewPlayers (0)

def ClearShips ():
	import MissionLib

	# Clear target menu
	pTargetMenu = App.STTargetMenu_GetTargetMenu()
	if (pTargetMenu != None):
		pTargetMenu.ClearTargetList ()
		pTargetMenu.ClearPersistentTarget ()

	# Clear the set of all player ships.
	pGame = App.MultiplayerGame_Cast (App.Game_GetCurrentGame ())	
	pGame.DeletePlayerShipsAndTorps ()

	# Call mission specific clear ships.
	try:
		pcMissionName = MissionLib.GetMission().GetScript()
		pMissionScript = __import__(pcMissionName)
		pMissionScript.ClearShips ()
	except:
		pass

################################################################################
#	ScanHandler()
#
#	Called when the "Scan" button in Miguel's menu is hit.  
#	Performs tasks based on what system we're in.
#
#	Args:	pObject	- The TGObject object.
#			pEvent	- The event that was sent.
#
#	Return:	None
################################################################################
def ScanHandler(pObject, pEvent):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")

	iScanType = pEvent.GetInt()

	# construct a sequence to say scanning, blah blah blah
	pSequence = App.TGSequence_Create ()
	pString = pDatabase.GetString ("MiguelScan")

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "DisableScanObjectMenu")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "DisableScanTargetButton")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "DisableScanAreaButton")
	pSequence.AppendAction (pAction)

	pSoundAction = CreateSubtitledSoundAction (pDatabase, "MiguelScan")
	pSequence.AppendAction (pSoundAction)
	pSoundAction = CreateSubtitledSoundAction  (pDatabase, "gs038");
	pSequence.AppendAction (pSoundAction)

	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanObjectMenu")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanTargetButton")
	pSequence.AppendAction (pAction)
	pAction = App.TGScriptAction_Create("Bridge.BridgeUtils", "EnableScanAreaButton")
	pSequence.AppendAction (pAction)

	pSequence.Play ()

	App.g_kLocalizationManager.Unload(pDatabase)

	pObject.CallNextHandler(pEvent)

def CreateSubtitledSoundAction (pDatabase, pcSoundName):
	import MissionLib

	pSequence = App.TGSequence_Create ()

	pMission = MissionLib.GetMission ()

	pEvent = App.TGEvent_Create ()
	pEvent.SetEventType (ET_SUBTITLED_SOUND_DONE)
	pEvent.SetDestination (pMission)
	pEvent.SetSource (pSequence)
	pSoundAction = App.TGSoundAction_Create (pcSoundName);
	pSoundAction.AddCompletedEvent (pEvent)
	pSequence.AddAction (pSoundAction)

	pSubtitleAction = App.SubtitleAction_Create (pDatabase, pcSoundName)
	pSequence.AddAction (pSubtitleAction)
	return pSequence

def SoundDoneHandler (pObject, pEvent):
	pSequence = App.TGSequence_Cast (pEvent.GetSource ())
	pSequence.Completed ()