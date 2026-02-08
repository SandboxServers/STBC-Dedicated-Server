###############################################################################
#	Filename:	M3Gameflow.py
#	
#	Confidential and Proprietary, Copyright 2002 by Totally Games
#	
#	Slightly more complicated mission, illustrating the use of event handlers,
#	sequences, and timers.
#	
#	Created:	2/4/2002	- Erik Novales (ripped off of E2M6 because Jess
#							  has good style :P )
###############################################################################
import App
import loadspacehelper
import MissionLib

# Globals
g_pMissionTGL = None		# string database for the mission
g_bEnteredBiranu1 = 0		# flag keeping track of whether player has visited
							# Biranu 1 yet
g_idNagTimer = App.NULL_ID	# ID of timer to nag the player to hurry up and
							# destroy the enemy in Biranu 1

###############################################################################
#	PreLoadAssets()
#	
#	This is called once, at the beginning of the mission before Initialize()
#	to allow us to add instances of ships we'll use. This is not mandatory,
#	but will prevent hitching when ships are created.
#	
#	Args:	pMission	- the Mission object
#	
#	Return:	none
###############################################################################
def PreLoadAssets(pMission):
	# Pre-create three Galaxy ships.
	loadspacehelper.PreloadShip("Galaxy", 3)
	
################################################################################
#	Initialize()
#	
#	Called once when mission loads to initialize mission.
#	
#	Args: 	pMission	- the mission object
#	
#	Return: None
################################################################################
def Initialize(pMission):
	global g_pMissionTGL
	g_pMissionTGL = App.g_kLocalizationManager.Load("data/TGL/Tutorial/Episode/M3Gameflow.tgl")
	g_bEnteredBiranu1 = 0

	# Specify (and load if necessary) the player's bridge. This is only
	# necessary for the first mission in the game, unless you're switching
	# bridges.
	import LoadBridge
	LoadBridge.Load("GalaxyBridge")

	# Create the regions for this mission
	CreateRegions()
	
	# Create the starting objects
	CreateStartingObjects(pMission)

	# Setup object AI.
	SetupAI()

	# Setup event handlers.
	SetupEventHandlers(pMission)

	# Start the briefing sequence.
	StartBriefingSequence()
	
################################################################################
#	CreateRegions()
#
#	Creates the regions we'll be using in this mission.  Also loads in any
#	mission placement files we need.
#
#	Args:	None
#
#	Return:	None
################################################################################
def CreateRegions():
	# Biranu 1
	import Systems.Biranu.Biranu
	pBiranuMenu		= Systems.Biranu.Biranu.CreateMenus()
	pBiranu1Set = MissionLib.SetupSpaceSet("Systems.Biranu.Biranu1")

	# Biranu 2
	pBiranu2Set = MissionLib.SetupSpaceSet("Systems.Biranu.Biranu2")
	
	# Add our custom placement objects for this mission.
	import M3Biranu1_P
	M3Biranu1_P.LoadPlacements(pBiranu1Set.GetName())

################################################################################
#	CreateStartingObjects()
#
#	Creates all the objects that exist at the beginning of the mission and sets
# 	up the affiliations for all objects that will occur in the mission.
#
#	Args:	pMission	- The mission object.
#
#	Return:	None
################################################################################
def CreateStartingObjects(pMission):
	# get the sets we need
	pBiranu1Set		= App.g_kSetManager.GetSet("Biranu1")
	pBiranu2Set		= App.g_kSetManager.GetSet("Biranu2")
	
	# Create the ships that exist at mission start
	pPlayer			= MissionLib.CreatePlayerShip("Galaxy", pBiranu2Set, "player", "Player Start")
	pGalaxy1		= loadspacehelper.CreateShip("Galaxy", pBiranu1Set, "Galaxy 1", "Galaxy1Start")
	pGalaxy2		= loadspacehelper.CreateShip("Galaxy", pBiranu1Set, "Galaxy 2", "Galaxy2Start")

	# Setup ship affiliations.
	pFriendlies = pMission.GetFriendlyGroup()
	pFriendlies.AddName("player")
	pFriendlies.AddName("Galaxy 1")

	pNeutrals = pMission.GetNeutralGroup()
	# No neutrals in this mission.

	pEnemies = pMission.GetEnemyGroup()
	pEnemies.AddName("Galaxy 2")

###############################################################################
#	SetupAI()
#	
#	Sets up object AI.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupAI():
	pSet = App.g_kSetManager.GetSet("Biranu1")
	pGame = App.Game_GetCurrentGame()

	pGalaxy1 = App.ShipClass_GetObject(pSet, "Galaxy 1")
	pGalaxy2 = App.ShipClass_GetObject(pSet, "Galaxy 2")

	import EnemyAI
	import FriendlyAI

	pGalaxy1.SetAI(FriendlyAI.CreateAI(pGalaxy1))
	pGalaxy2.SetAI(EnemyAI.CreateAI(pGalaxy2))

###############################################################################
#	SetupEventHandlers(pMission)
#	
#	Sets up event handlers for this mission. They use the mission as the
#	object for the handler, so that when the mission is over, the handler is
#	automatically destroyed.
#	
#	Args:	pMission	- the mission
#	
#	Return:	none
###############################################################################
def SetupEventHandlers(pMission):
	# When any ET_ENTERED_SET event is sent, we will do special handling if
	# it's the player.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_ENTERED_SET,
		pMission, __name__ + ".HandleEnterSet")

	# When an object is exploding (about to be officially destroyed), we 
	# will run some script to check if it's an enemy.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING,
		pMission, __name__ + ".HandleObjectExploding")

###############################################################################
#	StartBriefingSequence()
#	
#	Plays the introductory briefing sequence.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def StartBriefingSequence():
	pSequence = App.TGSequence_Create()

	# Subtitle-only lines will remain until they are brought down. Voice lines
	# go down when the sound ends. Since we are using subtitle-only lines here,
	# we'll add another script action to bring down each line.
	pLine1 = App.SubtitleAction_Create(g_pMissionTGL, "Briefing1")
	pSequence.AddAction(pLine1)
	pLineDown1 = App.TGScriptAction_Create(__name__, "EndAction", pLine1.GetObjID())
	# We use App.TGAction_CreateNull() here because we don't want
	# this action to follow the line -- we want it to just happen 
	# 8 seconds after the sequence starts. Normally, we'd put the action
	# we wanted to follow in that place.
	pSequence.AddAction(pLineDown1, App.TGAction_CreateNull(), 8.0)

	pLine2 = App.SubtitleAction_Create(g_pMissionTGL, "Briefing2")
	pSequence.AddAction(pLine2, pLine1, 1.0)
	pLineDown2 = App.TGScriptAction_Create(__name__, "EndAction", pLine2.GetObjID())
	pSequence.AddAction(pLineDown2, pLineDown1, 10.0)

	pLine3 = App.SubtitleAction_Create(g_pMissionTGL, "Briefing3")
	pSequence.AddAction(pLine3, pLine2, 1.0)
	pLineDown3 = App.TGScriptAction_Create(__name__, "EndAction", pLine3.GetObjID())
	pSequence.AddAction(pLineDown3, pLineDown2, 6.0)

	# Play the sequence.
	pSequence.Play()

###############################################################################
#	EndAction(pAction, idActionToEnd)
#	
#	Ends the action with the specified ID. Used above to remove subtitle-only
#	lines.
#	
#	Args:	pAction			- this action, passed in automatically
#			idActionToEnd	- the object ID of the action to end
#	
#	Return:	zero, for normal action end
###############################################################################
def EndAction(pAction, idActionToEnd):
	pAction = App.TGAction_Cast(App.TGObject_GetTGObjectPtr(idActionToEnd))

	if pAction:
		pAction.Completed()	# Finish the action.

	return 0

###############################################################################
#	HandleEnterSet(pMission, pEvent)
#	
#	This is called when an ET_ENTERED_SET event is sent. We check to see if
#	it's the player entering Biranu 1 for the first time, and then play a
#	sequence if it is.
#	
#	Args:	pMission	- the mission (this argument is specified when the 
#						  event handler is setup)
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def HandleEnterSet(pMission, pEvent):
	# Destination of the event is the object that triggered the event. Check
	# if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())

	if pShip:
		# It's a ship. Now, check if it's the player.
		pPlayer = App.Game_GetCurrentPlayer()

		if pPlayer and (pShip.GetObjID() == pPlayer.GetObjID()):
			# It was the player. Now, check the set that the player is in. If 
			# it's Biranu 1, then they're entering Biranu 1.
			pSet = pShip.GetContainingSet()
			if pSet and pSet.GetName() == "Biranu1":
				# They're entering Biranu 1. See if this is the first time
				# they're entering this set.
				if g_bEnteredBiranu1 == 0:
					global g_bEnteredBiranu1

					# Set the flag so this doesn't happen again.
					g_bEnteredBiranu1 = 1

					# Play the sequence for when the player enters Biranu 1 the
					# first time. This is similar to StartBriefingSequence() above.
					pSequence = App.TGSequence_Create()

					pLine1 = App.SubtitleAction_Create(g_pMissionTGL, "Biranu1Enter1")
					pSequence.AddAction(pLine1)
					pLineDown1 = App.TGScriptAction_Create(__name__, "EndAction", pLine1.GetObjID())
					# We use App.TGAction_CreateNull() here because we don't want
					# this action to follow the line -- we want it to just happen 
					# 12 seconds after the sequence starts. Normally, we'd put the action
					# we wanted to follow in that place.
					pSequence.AddAction(pLineDown1, App.TGAction_CreateNull(), 12.0)

					pLine2 = App.SubtitleAction_Create(g_pMissionTGL, "Biranu1Enter2")
					pSequence.AddAction(pLine2, pLine1, 1.0)
					pLineDown2 = App.TGScriptAction_Create(__name__, "EndAction", pLine2.GetObjID())
					pSequence.AddAction(pLineDown2, pLineDown1, 10.0)

					pLine3 = App.SubtitleAction_Create(g_pMissionTGL, "Biranu1Enter3")
					pSequence.AddAction(pLine3, pLine2, 1.0)
					pLineDown3 = App.TGScriptAction_Create(__name__, "EndAction", pLine3.GetObjID())
					pSequence.AddAction(pLineDown3, pLineDown2, 10.0)

					# Add an action to create the nag timer, just after the last
					# line goes down.
					pCreateNag = App.TGScriptAction_Create(__name__, "CreateNagTimer")
					pSequence.AddAction(pCreateNag, pLineDown3)

					pSequence.Play()

	pMission.CallNextHandler(pEvent)

###############################################################################
#	HandleObjectExploding(pMission, pEvent)
#	
#	Event handler for when an object is exploding and about to be destroyed.
#	(ET_OBJECT_EXPLODING) If it's an enemy, we'll take some action.
#	
#	Args:	pMission	- the mission (this argument is specified when the 
#						  event handler is setup)
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def HandleObjectExploding(pMission, pEvent):
	# Destination of the event is the object that triggered the event. Check
	# if it's a ship.
	pShip = App.ShipClass_Cast(pEvent.GetDestination())
	
	if pShip:
		# Check if it's an enemy.
		pEnemies = pMission.GetEnemyGroup()
		
		if pEnemies.IsNameInGroup(pShip.GetName()):
			# It was an enemy.

			# Play a sequence. This is similar to StartBriefingSequence() above.
			pSequence = App.TGSequence_Create()

			# Create a voice line for one of the characters. Get it out of the
			# QuickBattle database.
			pBridge = App.g_kSetManager.GetSet("bridge")
			pFelix = App.CharacterClass_GetObject(pBridge, "Tactical")
			pDatabase = App.g_kLocalizationManager.Load("data/TGL/QuickBattle/QuickBattle.tgl")

			pSpokenLine1 = App.CharacterAction_Create(pFelix,	# Character
				App.CharacterAction.AT_SAY_LINE,				# action type
				"QBFelixWin",									# name of line in database
				"Captain",										# character turns to look at whom?
				1,												# turn back after done?
				pDatabase)										# database to use

			pSequence.AddAction(pSpokenLine1)

			pLine1 = App.SubtitleAction_Create(g_pMissionTGL, "Exploding1")
			pSequence.AddAction(pLine1, pSpokenLine1)
			pLineDown1 = App.TGScriptAction_Create(__name__, "EndAction", pLine1.GetObjID())
			# Take the subtitle line down 30 seconds after the spoken line is done.
			pSequence.AddAction(pLineDown1, pSpokenLine1, 30.0)

			pSequence.Play()

			# Remove the nag timer.
			global g_idNagTimer
			App.g_kTimerManager.DeleteTimer(g_idNagTimer)
			g_idNagTimer = App.NULL_ID

			# Unload the database once we're done with it. This is a special
			# case, because we're using a database from a mission other than us.
			# Normally, you'd keep a mission database pointer, and only unload
			# it on termination. However, we're OK in this case because the
			# spoken line will run as soon as the sequence plays, and it will
			# no longer need the database.
			App.g_kLocalizationManager.Unload(pDatabase)

	pMission.CallNextHandler(pEvent)

###############################################################################
#	CreateNagTimer(pAction)
#	
#	Script action that creates the nag timer, to remind the player to
#	destroy the enemy.
#	
#	Args:	pAction			- this action, passed in automatically
#	
#	Return:	zero, for normal action end
###############################################################################
def CreateNagTimer(pAction):
	# We don't want to use a predefined event type, since this is a mission-
	# specific thing, so we'll ask the mission for the next available event
	# type. Then, we'll create a timer to send an event of that type
	# periodically, then handle it elsewhere.
	pGame = App.Game_GetCurrentGame()
	pEpisode = pGame.GetCurrentEpisode()
	pMission = pEpisode.GetCurrentMission()

	# Get our event type.
	eNagEventType = App.Mission_GetNextEventType()

	# Create the event for nag timer.
	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pMission)
	pEvent.SetEventType(eNagEventType)

	# Create the timer that will send the event. We keep track of the ID of
	# the timer so we can delete it later.
	pTimer = App.TGTimer_Create()
	# Don't start immediately, start 15 seconds from now.
	pTimer.SetTimerStart(App.g_kUtopiaModule.GetGameTime() + 15.0)
	# 15 seconds between each trigger.
	pTimer.SetDelay(15.0)
	pTimer.SetDuration(-1.0)	# will keep going forever, until we explicitly
								# delete it.
	pTimer.SetEvent(pEvent)

	global g_idNagTimer
	g_idNagTimer = pTimer.GetObjID()

	# Set up the mission to handle the event.
	pMission.AddPythonFuncHandlerForInstance(eNagEventType, __name__ + ".HandleNagTimer")

	# Add the timer to the timer manager, and we're done.
	App.g_kTimerManager.AddTimer(pTimer)

	return 0

###############################################################################
#	HandleNagTimer(pMission, pEvent)
#	
#	Handles the nag timer for when the player is in Biranu 1.
#	
#	Args:	pMission	- the mission (this argument is specified when the 
#						  event handler is setup)
#			pEvent		- the event
#	
#	Return:	none
###############################################################################
def HandleNagTimer(pMission, pEvent):
	# Play a sequence with a subtitle-only line. This is similar to 
	# StartBriefingSequence() above.
	pSequence = App.TGSequence_Create()

	pLine1 = App.SubtitleAction_Create(g_pMissionTGL, "Nag1")
	pSequence.AddAction(pLine1)
	pLineDown1 = App.TGScriptAction_Create(__name__, "EndAction", pLine1.GetObjID())
	# We use App.TGAction_CreateNull() here because we don't want
	# this action to follow the line -- we want it to just happen 
	# 5 seconds after the sequence starts. Normally, we'd put the action
	# we wanted to follow in that place.
	pSequence.AddAction(pLineDown1, App.TGAction_CreateNull(), 5.0)

	pSequence.Play()

	pMission.CallNextHandler(pEvent)

################################################################################
#	Terminate()
#	
#	Called when mission ends to free resources
#	
#	Args: pMission - the mission object
#	
#	Return: None
################################################################################
def Terminate(pMission):
	# Clear out all the systems in the set course menu.
	App.SortedRegionMenu_ClearSetCourseMenu()

	global g_pMissionTGL
	if g_pMissionTGL:
		App.g_kLocalizationManager.Unload(g_pMissionTGL)
		g_pMissionTGL = None

	# Clear the nag timer, if it's still there.
	global g_idNagTimer
	if g_idNagTimer != App.NULL_ID:
		App.g_kTimerManager.DeleteTimer(g_idNagTimer)
		g_idNagTimer = App.NULL_ID
