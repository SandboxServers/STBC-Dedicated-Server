import App

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading Dynamic Music module (%s)...\n" % __name__)

g_bInitialized = 0

def Initialize(pGame, lMusic, lTransitions, lGroups, pStateMachineClass):
	global lMusicQueue, sCurrentMusicType, sCurrentMusicName, sMusicOverride
	global pStateMachine
	global g_bInitialized

	g_bInitialized = 1

	# Setup our event handling hooks.
	SetupEventHandling(pGame)

	# Setup the music queue.
	sMusicOverride = None
	lMusicQueue = []
	sCurrentMusicType = None
	sCurrentMusicName = None

	# Load the music.
	LoadMusic(lMusic, lTransitions, lGroups)

	# Setup the state machine...
	pStateMachine = pStateMachineClass()

def ChangeMusic(lMusic, lTransitions, lGroups, pStateMachineClass):
	global pStateMachine

	# Check if the state machine needs to change.
	if (not pStateMachine)  or  (pStateMachineClass != pStateMachine.__class__):
		pStateMachine = None

	# Stop and unload the old music.
	StopMusic()
	UnloadMusic()

	# Load the new music.
	LoadMusic(lMusic, lTransitions, lGroups)

	if not pStateMachine:
		pStateMachine = pStateMachineClass()
	else:
		# Make sure the old state machine is updated for its new state.
		pStateMachine.EvaluateMusicState()

def LoadMusic(lMusic, lTransitions, lGroups):
	global dsMusicTypes, dsTransitions, dlGroups
	global lMusicQueue

	# Setup the various music types we can play.
	dsMusicTypes = {}
	for sFile, sMusicType in lMusic:
		# ***FIXME: Get accurate beat info.
		App.g_kMusicManager.LoadMusic(sFile, sMusicType, 2.0)
		dsMusicTypes[sMusicType] = sMusicType

	# Setup which types we have transitions for.
	dsTransitions = {}
	for sStart, sEnd, sTransition in lTransitions:
		dsTransitions[(sStart, sEnd)] = sTransition

	# Setup group info.
	dlGroups = {}
	for sMusicType, lGroup in lGroups:
		dlGroups[sMusicType] = lGroup

def UnloadMusic():
	StopMusic()

	# Unload the music itself.
	for sMusic in dsMusicTypes.values():
		App.g_kMusicManager.UnloadMusic(sMusic)

	# Clear out our variables.
	global dsMusicTypes, dsTransitions, dlGroups
	global lMusicQueue
	dsMusicTypes = {}
	dsTransitions = {}
	dlGroups = {}

def Terminate(pGame):
	global g_bInitialized
	if (not g_bInitialized):
		return

	g_bInitialized = 0

#	debug("Shutting down dynamic music.")

	# Remove the music state machine.
	global pStateMachine
	if (pStateMachine):
		del pStateMachine

	# Stop playing.
	StopMusic()

	# Unload all the music we loaded.
	UnloadMusic()

def SetupEventHandling(pGame):
	App.g_kEventManager.AddBroadcastPythonFuncHandler(
		App.ET_MUSIC_DONE,
		pGame,
		__name__ + ".MusicDone")

def StopMusic():
	global lMusicQueue, sCurrentMusicType, sCurrentMusicName, sMusicOverride
	lMusicQueue = []
	sCurrentMusicType = None
	sCurrentMusicName = None
	sMusicOverride = None
	App.g_kMusicManager.StopMusic()

def MusicDone(pObject, pEvent):
	# The current piece of music is done playing.  If
	# we have a song in the queue, start up that one.
	if sCurrentMusicType  and  pEvent.GetCString() == dsMusicTypes[sCurrentMusicType]:
		#debug("Song %s done." % pEvent.GetCString())
		ProcessQueue()

def EnqueueMusic(sMusicType, bLooping = 1, fStartTime = 0.0):
	global lMusicQueue
	lMusicQueue.append((sMusicType, bLooping, fStartTime))

def ProcessQueue():
	global lMusicQueue
	global sCurrentMusicType
	global sCurrentMusicName
	global sMusicOverride

	#debug("Processing music queue...")

	# If the music is being overridden, make sure the music
	# that's overriding the system is the first in the queue.
	if sMusicOverride:
		# Remove old copies...
		RemoveOverrideMusicFromQueue()

		# Insert our copy..
		lMusicQueue.insert(0, (sMusicOverride, 1, 0.0))

	while len(lMusicQueue)  or  sMusicOverride:
		# There's something in the queue.  Get its name.
		sMusicType, bLooping, fStartTime = lMusicQueue[0]
		bRemove = 0

		# Check if this is in the Groups list..
		if dlGroups.has_key(sMusicType):
			# Yep, it is.  Play one of the songs
			# from this group, at random.
			lGroup = dlGroups[sMusicType]
			bLooping = 0

			#debug("Choosing music from: " + str(lGroup))
			while 1:
				iRandom = App.g_kSystemWrapper.GetRandomNumber(len(lGroup))
				sMusicType = lGroup[iRandom]
				if sMusicType != sCurrentMusicType:
					sMusicName = dsMusicTypes[sMusicType]
					#debug("Playing random music " + sMusicName)
					break

		elif dsMusicTypes.has_key(sMusicType):
			# Get the music name for the new type of music.
			sMusicName = dsMusicTypes[sMusicType]

			# Remove this music from the queue.
			bRemove = 1

		# Switch to the new music.
		if App.g_kMusicManager.StartMusic(sMusicName, bLooping):
			# Successful switch.  Done processing
			# the queue.
			sCurrentMusicType = sMusicType
			break
		else:
#			debug("Failed to play music: " + str(sMusicName))
			bRemove = 1

		if bRemove:
			lMusicQueue = lMusicQueue[1:]

def SwitchMusic(sNewMusicType):
	global lMusicQueue

	# Make sure the new music type is defined.
	if not dsMusicTypes.has_key(sNewMusicType)  and  not dlGroups.has_key(sNewMusicType):
		return

	#debug("Switching music to " + sNewMusicType)

	# Clear out any entries that are currently in the queue.
	lMusicQueue = []

	# Got the song name.  Does a transition exist from our
	# current music to the new music?
	if dsTransitions.has_key((sCurrentMusicType, sNewMusicType)):
		# Yes, there's a transition.  Put it in the queue
		# before the new music, so it's played first.
		#debug("Adding transition: " + dsTransitions[(sCurrentMusicType, sNewMusicType)])
		EnqueueMusic(dsTransitions[(sCurrentMusicType, sNewMusicType)], 0)

	EnqueueMusic(sNewMusicType)
	ProcessQueue()

def PlayFanfare(sMusicType):
	# Play a piece of music once, interrupting the current
	# music, and resuming the current music at its old position
	# when done.
	# Make sure the new music type is defined.
	if not dsMusicTypes.has_key(sMusicType):
		return

	sMusicName = dsMusicTypes[sMusicType]
	App.g_kMusicManager.PlayFanfare(sMusicName)

def OverrideMusic(sMusicType):
	# Make sure the new music type is defined.
	if not dsMusicTypes.has_key(sMusicType) and not dlGroups.has_key(sMusicType):
#		debug("Tried to override music with invalid type: %s" % sMusicType)
#		debug("Valid types are:\n%s or %s" % (dsMusicTypes.keys(), dlGroups.keys()))
		return

	global sMusicOverride, lMusicQueue, sCurrentMusicType
	# If the music was being overridden before, stop the old music.
	if sMusicOverride:
		StopOverridingMusic()

	# Set the overriding music type.
	sMusicOverride = sMusicType

	# Now that the override music has been setup, process the music queue.
	ProcessQueue()

def StopOverridingMusic():
	global sMusicOverride, lMusicQueue, pStateMachine
	if not sMusicOverride:
		return

	# Remove any instances of the overriding music from the music queue.
	RemoveOverrideMusicFromQueue()

	sMusicOverride = None

	# Empty the queue, and put the music that we should be playing at the head of the queue.
	lMusicQueue = []
	EnqueueMusic( pStateMachine.GetMusicState() )
	ProcessQueue()

def RemoveOverrideMusicFromQueue():
	while 1:
		iOldLen = len(lMusicQueue)
		try:
			lMusicQueue.remove( (sMusicOverride, 1, 0.0) )
		except ValueError: pass

		if iOldLen == len(lMusicQueue):
			break

#
# Classes that define the music state machine, and choose
# when to switch from one track to another track.
#
class StandardCombatMusic:
	def __init__(self):
		# Initialize our current state..
		self.sCurrentState = None

		# Setup our condition handling things.
		self.pEventHandler = App.TGPythonInstanceWrapper()
		self.pEventHandler.SetPyWrapper(self)

		# Need a handler for when a new mission is started, since
		# some of our conditions are based on info in the mission.
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_MISSION_START, self.pEventHandler, "NewMission")
		# And a handler for when the player is changed, because some
		# conditions are based on the player.
		App.g_kEventManager.AddBroadcastPythonMethodHandler(App.ET_SET_PLAYER, self.pEventHandler, "PlayerChanged")

		self.pConditionEventCreator = App.ConditionEventCreator()
		pEvent = App.TGEvent_Create()
		pEvent.SetEventType(App.ET_MUSIC_CONDITION_CHANGED)
		pEvent.SetDestination(self.pEventHandler)
		self.pConditionEventCreator.SetEvent(pEvent)

		self.pEventHandler.AddPythonMethodHandlerForInstance(App.ET_MUSIC_CONDITION_CHANGED, "ConditionChanged")

		# Get the player object and the enemy group object,
		# for our conditions.
		pPlayer = App.Game_GetCurrentPlayer()
		if pPlayer:
			self.PlayerChanged()

		import MissionLib
		pMission = MissionLib.GetMission()
		if pMission:
			self.NewMission()

		# Add conditions to the handler.
		self.pFriendliesWinning = App.ConditionScript_Create("Conditions.FriendliesInPlayerSetStronger", "FriendliesInPlayerSetStronger", 2.0)
		self.pFriendliesNotLosing = App.ConditionScript_Create("Conditions.FriendliesInPlayerSetStronger", "FriendliesInPlayerSetStronger", 0.5)

		self.pConditionEventCreator.AddCondition(self.pFriendliesWinning)
		self.pConditionEventCreator.AddCondition(self.pFriendliesNotLosing)

		self.EvaluateMusicState()

	def __getstate__(self):
		self.pEventHandler.pContainingInstance = self
		return self.__dict__

	def __setstate__(self, dict):
		self.__dict__ = dict
		del self.pEventHandler.pContainingInstance

	def SetMusicState(self, sNewState):
		#debug("SetMusicState %s" % sNewState)
		if self.sCurrentState != sNewState:
			# State is changing.  Switch the music.
			self.sCurrentState = sNewState
			SwitchMusic(sNewState)
		elif (not lMusicQueue)  and  (sCurrentMusicType is None):
			# Our state hasn't changed, but the music system isn't currently
			# playing any music.  Have it play this music.
			SwitchMusic(sNewState)

	def GetMusicState(self):
		return self.sCurrentState

	def NewMission(self, pEvent = None):
		# A new mission has been started.  Fix things that are dependant on the mission.
		#debug("Mission start handling...")

		# Remove conditions based on the old mission.
		self.RemoveConditions("pEnemiesInRange")

		import MissionLib
		pMission = MissionLib.GetMission()
		pPlayer = App.Game_GetCurrentPlayer()

		# Add conditions based on the new mission.
		if pMission and pPlayer:
			pEnemyGroup = pMission.GetEnemyGroup()
			self.pEnemiesInRange = App.ConditionScript_Create("Conditions.ConditionInRange", "ConditionInRange", 400, pPlayer.GetName(), pEnemyGroup)
			self.pConditionEventCreator.AddCondition(self.pEnemiesInRange)
#		else:
#			debug("No mission or no player in NewMission.  Can't create Enemies In Range condition.")

	def PlayerChanged(self, pEvent = None):
		# The player's ship has been changed.  If we had conditions based
		# on the old ship, get rid of them.
		#debug("Player changed handling.")
		self.RemoveConditions("pPlayerInStarbase12Set", "pPlayerInNebula")

		self.NewMission()
		
		# Get the new player...
		pPlayer = App.Game_GetCurrentPlayer()
		if pPlayer:
			sPlayerName = pPlayer.GetName()
		else:
			# This shouldn't happen.  It could, but it shouldn't.
#			debug("Player doesn't exist in PlayerChanged call.  Guessing player name. :(")
			sPlayerName = "Player"

		self.pPlayerInStarbase12Set = App.ConditionScript_Create("Conditions.ConditionInSet", "ConditionInSet", sPlayerName, "Starbase12")
		self.pPlayerInNebula = App.ConditionScript_Create("Conditions.ConditionInNebula", "ConditionInNebula", sPlayerName)

		self.pConditionEventCreator.AddCondition(self.pPlayerInStarbase12Set)
		self.pConditionEventCreator.AddCondition(self.pPlayerInNebula)

	def RemoveConditions(self, *lsAttributeNames):
		for sAttr in lsAttributeNames:
			if hasattr(self, sAttr):
				self.pConditionEventCreator.RemoveCondition( getattr(self, sAttr) )
				delattr(self, sAttr)

	def ConditionChanged(self, pEvent):
		self.EvaluateMusicState()
		self.pEventHandler.CallNextHandler(pEvent)

	def EvaluateMusicState(self):
		# Reevaluate what our current music state should be.
		#debug("EvaluateMusicState")
		# Get the state of our conditions...
		bMissionWon = 0
		bMissionLost = 0
		try:
			bEnemiesNear = self.pEnemiesInRange.GetStatus()
		except:
			bEnemiesNear = 0
		bFriendliesWinning = self.pFriendliesWinning.GetStatus()
		bFriendliesNotLosing = self.pFriendliesNotLosing.GetStatus()
		try:
			bAtStarbase12 = self.pPlayerInStarbase12Set.GetStatus()
		except:
			bAtStarbase12 = 0
		try:
			bInNebula = self.pPlayerInNebula.GetStatus()
		except:
			bInNebula = 0

		if bMissionWon:
			self.SetMusicState("Ambient Done")
		elif bMissionLost:
			self.SetMusicState("Combat Failure")
		else:
			if bEnemiesNear:
				# We're on combat.
				if bFriendliesWinning:
					self.SetMusicState("Combat Confident")
				elif bFriendliesNotLosing:
					self.SetMusicState("Combat Neutral")
				else:
					self.SetMusicState("Combat Panic")
			else:
				# Not in combat.
				if bAtStarbase12:
					self.SetMusicState("Starbase12 Ambient")
				elif bInNebula:
					self.SetMusicState("Nebula Ambient")
				else:
					self.SetMusicState("Starting Ambient")
