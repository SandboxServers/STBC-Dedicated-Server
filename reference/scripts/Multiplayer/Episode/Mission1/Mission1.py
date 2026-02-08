import App
import loadspacehelper
import MissionLib

#Start debugger
#debug = App.CPyDebug(__name__).Print
#debug("Loading multiplayer mission: " + __name__)

#global variables
NonSerializedObjects = (
#"debug",
"g_kKillsDictionary",
"g_kDeathsDictionary",
"g_kScoresDictionary",
"g_kDamageDictionary"
)

# Global variables.  

# setup scoring objects
g_kKillsDictionary = {}
g_kDeathsDictionary = {}
g_kScoresDictionary = {}
g_kDamageDictionary = {}

###############################################################################
#	GetWinString()
#	
#	Returns a string that describes who won
#	
#	Args:	None
#	
#	Return:	char*
###############################################################################
def GetWinString():
	# Get a list of players sorted by scores
	# Reconstruct the menu, first storing it in a python list.
	pSortList = []

	pNetwork = App.g_kUtopiaModule.GetNetwork()
	pPlayerList = pNetwork.GetPlayerList()
	iNumPlayers = pPlayerList.GetNumPlayers()
	
	for i in range(iNumPlayers):
		pPlayer = pPlayerList.GetPlayerAtIndex(i)
		if (g_kKillsDictionary.has_key(pPlayer.GetNetID())):
			# This is an actual player in the game.  Add him/her to the sort
			# list for later sorting/
			pSortList.append(pPlayer)

	if len(pSortList) < 1:
		# There are no players. Nobody has won.
#		debug("The game is over, but there are no players.")
		return ""

	
	# Okay, now we have a list of all the players in the game.  Sort it
	# using the ComparePlayer function to do comparisons.
	import Mission1Menus
	pSortList.sort(Mission1Menus.ComparePlayer)

	# Find the top score
	iPlayerID = pSortList[0].GetNetID()
	iTopScore = 0
	if g_kScoresDictionary.has_key(iPlayerID):
		iTopScore = g_kScoresDictionary[iPlayerID]

	# Now build a list of players whose scores are equal to the top player's
	# score, and play the appropriate win/lose fanfare
	import DynamicMusic
	bMusicPlayed = 0
	pTopPlayers = []
	for pPlayer in pSortList:
		iPlayerID = pPlayer.GetNetID()
		if g_kScoresDictionary.has_key(iPlayerID):
			iScore = g_kScoresDictionary[iPlayerID]
		else:
			iScore = 0
		if iScore == iTopScore:
			pTopPlayers.append(pPlayer.GetName().GetCString())
			if iPlayerID == App.g_kUtopiaModule.GetNetwork().GetLocalID():
				DynamicMusic.PlayFanfare("Win")
				bMusicPlayed = 1

	if not bMusicPlayed:
		DynamicMusic.PlayFanfare("Lose")

	# Now build a string that describes the winner(s)
	import Multiplayer.MissionShared
	pDatabase = Multiplayer.MissionShared.g_pDatabase
	if len(pTopPlayers) == 1:
		pcString = pDatabase.GetString("Has Won").GetCString() % pTopPlayers[0]
	elif len(pTopPlayers) == 2:
		pcString = pTopPlayers[0] +	" " + pDatabase.GetString("and player").GetCString() % pTopPlayers[1] + pDatabase.GetString("Tied for the lead").GetCString()
	else:
		pcString = ""
		iNumIters = len(pTopPlayers) - 1
		for iIter in range(iNumIters):
			pcString = pcString + pDatabase.GetString("player,").GetCString() % pTopPlayers[iIter]
		pcString = pcString + pDatabase.GetString("and player").GetCString() % pTopPlayers[len(pTopPlayers) - 1] + pDatabase.GetString("Tied for the lead").GetCString()

#	debug(str(pcString))
	return pcString

#Kill the Mission database
def Terminate(pMission):
	import Multiplayer.MissionShared
	import Mission1Menus
#	debug("Terminating multiplayer mission 1.")

	# Terminate common stuff, which will handle delete of mission
	# menus as well.
	Multiplayer.MissionShared.Terminate (pMission)

	# Clear dictionaries
	global g_kKillsDictionary 
	global g_kDeathsDictionary 
	global g_kScoresDictionary 
	global g_kDamageDictionary 

	for iKey in g_kKillsDictionary.keys ():
		del g_kKillsDictionary [iKey]		

	for iKey in g_kDeathsDictionary.keys ():
		del g_kDeathsDictionary [iKey]		

	for iKey in g_kScoresDictionary.keys ():
		del g_kScoresDictionary [iKey]		

	for iKey in g_kDamageDictionary.keys ():
		del g_kDamageDictionary [iKey]		

	Mission1Menus.g_iIdOfCurrentlySelectedPlayer = App.TGNetwork.TGNETWORK_INVALID_ID
	Mission1Menus.g_pOptionsWindowBootButton = None
	Mission1Menus.g_pOptionsWindowPlayerMenu = None

#Episode level stuff
def CreateMenus():
	return 0


def RemoveHooks():
	return


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
	return

#Mission startup
def Initialize(pMission):
	import Multiplayer.MissionShared
	import Mission1Menus
#	debug("Multiplayer mission start.")
	# Call common initialize routine
	Multiplayer.MissionShared.Initialize (pMission)

	# Now we're done.  The menu will do the work to create the ship.
	if (App.g_kUtopiaModule.IsHost ()):
		Mission1Menus.BuildMission1Menus ()


	#Setup event handlers
	SetupEventHandlers(pMission)

	if (App.g_kUtopiaModule.IsHost () and App.g_kUtopiaModule.IsClient ()):
		pNetwork = App.g_kUtopiaModule.GetNetwork ()
		iPlayerID = pNetwork.GetHostID ()

		if (not g_kKillsDictionary.has_key (iPlayerID)):
			# Add a blank key
			global g_kKillsDictionary
			g_kKillsDictionary [iPlayerID] = 0		# No kills

		if (not g_kDeathsDictionary.has_key (iPlayerID)):
			# Add a blank key
			global g_kDeathsDictionary
			g_kDeathsDictionary [iPlayerID] = 0		# No kills


# setup any event handlers specific to this mission.
def SetupEventHandlers (pMission):
	import Multiplayer.MissionShared
	if (App.g_kUtopiaModule.IsHost ()):
		# Only hosts handling scoring.
		App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectKilledHandler")
		App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_WEAPON_HIT, pMission, __name__ + ".DamageEventHandler")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NEW_PLAYER_IN_GAME, pMission, __name__ + ".NewPlayerHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NETWORK_DELETE_PLAYER, pMission, __name__ + ".DeletePlayerHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_CREATED_NOTIFY, pMission, __name__ + ".ObjectCreatedHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NETWORK_NAME_CHANGE_EVENT, pMission, __name__ + ".ProcessNameChangeHandler")

	# setup handler for listening for packets.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NETWORK_MESSAGE_EVENT, pMission, __name__ + ".ProcessMessageHandler")

	pMission.AddPythonFuncHandlerForInstance(Multiplayer.MissionShared.ET_RESTART_GAME, __name__ + ".RestartGameHandler")

	return 0

def ProcessNameChangeHandler (self, pEvent):
	import Mission1Menus
	import Multiplayer.MissionMenusShared

	if (Multiplayer.MissionMenusShared.g_pInfoPane != None):
		# A player's name has changed.  Rebuild the info pane.
		Mission1Menus.RebuildInfoPane ()
	return


def ProcessMessageHandler (self, pEvent):
	import Multiplayer.SpeciesToSystem
	import Multiplayer.MissionShared
	import Mission1Menus
	import Multiplayer.MissionMenusShared

	pMission = MissionLib.GetMission ()
	if (pMission == None):
		# Mission is over, don't process messages.
		return

	pMessage = pEvent.GetMessage()
	if not App.IsNull(pMessage):
		# Get the data from the message
		# Open a buffer stream to read the data
		kStream = pMessage.GetBufferStream ();

		cType = kStream.ReadChar ();

		cType = ord (cType)

		if (cType == Multiplayer.MissionShared.MISSION_INIT_MESSAGE):
			# Read the max number of players
			Multiplayer.MissionMenusShared.g_iPlayerLimit = ord(kStream.ReadChar())
			
			# Read the system species
			Multiplayer.MissionMenusShared.g_iSystem = ord (kStream.ReadChar ())
			iNum = ord (kStream.ReadChar())
			if (iNum == 255):
				Multiplayer.MissionMenusShared.g_iTimeLimit = -1
			else:
				Multiplayer.MissionMenusShared.g_iTimeLimit = iNum
				iEndTime = kStream.ReadInt()
				Multiplayer.MissionShared.CreateTimeLeftTimer(iEndTime - int(App.g_kUtopiaModule.GetGameTime()))

			iNum = ord (kStream.ReadChar ())
			if (iNum == 255):
				Multiplayer.MissionMenusShared.g_iFragLimit = -1
			else:
				Multiplayer.MissionMenusShared.g_iFragLimit = iNum

			# Create the system
#			debug("Creating system")
			Multiplayer.MissionShared.g_pStartingSet = Multiplayer.SpeciesToSystem.CreateSystemFromSpecies (Multiplayer.MissionMenusShared.g_iSystem)

			# Build the menus now that we're ready to display them.
			Mission1Menus.BuildMission1Menus ()

			# Update info
			Mission1Menus.ResetLimitInfo ()
			Mission1Menus.RebuildInfoPane ()
		elif (cType == Multiplayer.MissionShared.SCORE_CHANGE_MESSAGE):
			global g_kScoresDictionary

			# Read the player id of killer
			iFiringPlayerID = kStream.ReadLong ()

			iKills = 0
			if (iFiringPlayerID != 0):
				# Read the kills
				iKills = kStream.ReadLong ()

				# Read the firing player's score
				g_kScoresDictionary [iFiringPlayerID] = kStream.ReadLong ()

			# Read the player id of killed
			iKilledPlayerID = kStream.ReadLong ()

			# Read the deaths
			iDeaths = kStream.ReadLong ()

			# Read the number of players
			iScoreCount = ord (kStream.ReadChar ())
#			debug("Received " + str (iScoreCount) + "scores")

			while (iScoreCount > 0):
				iPlayerID = kStream.ReadLong ()
				if (iPlayerID != 0):
					iPlayerScore = kStream.ReadLong ()

					g_kScoresDictionary [iPlayerID] = iPlayerScore
				iScoreCount = iScoreCount - 1

			UpdateScore (iFiringPlayerID, iKills, iKilledPlayerID, iDeaths)

		elif (cType == Multiplayer.MissionShared.SCORE_MESSAGE):
			global g_kKillsDictionary
			global g_kDeathsDictionary
			global g_kScoresDictionary


			# Read the key id.
			iKey = kStream.ReadLong ()

			# Read Kills
			iKills = kStream.ReadLong ()

			# Read deaths
			iDeaths = kStream.ReadLong ()
			
			# Read score
			iScore = kStream.ReadLong ()
			
			g_kKillsDictionary [iKey] = iKills
			g_kDeathsDictionary [iKey] = iDeaths
			g_kScoresDictionary [iKey] = iScore

			Mission1Menus.RebuildPlayerList ()
		elif (cType == Multiplayer.MissionShared.RESTART_GAME_MESSAGE):
			RestartGame ()		

		kStream.Close ()

# This method is called if you are the host and a new player joins.  Use this
# method to send any relevant information about the game to the player joining.
# For example, the name of the system that the mission takes place in would
# be something the hosts decides in his menus and then sends to other players.
def InitNetwork (iToID):
	import Multiplayer.MissionShared
	import Multiplayer.MissionMenusShared

	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	if (not pNetwork):
		# Huh?  No network?  bail.
		return

	###############################################################
	# Send mission init message with info needed to start mission
	# allocate the message.
	pMessage = App.TGMessage_Create ()
	pMessage.SetGuaranteed (1)		# Yes, this is a guaranteed packet
	
	# Setup the stream.
	kStream = App.TGBufferStream ()		# Allocate a local buffer stream.
	kStream.OpenBuffer (256)				# Open the buffer stream with a 256 byte buffer.
	
	# Write relevant data to the stream.
	# First write message type.
	kStream.WriteChar (chr (Multiplayer.MissionShared.MISSION_INIT_MESSAGE))

	# Write the maximum number of players
	kStream.WriteChar(chr(Multiplayer.MissionMenusShared.g_iPlayerLimit))
	
	# Write the system species
	kStream.WriteChar (chr (Multiplayer.MissionMenusShared.g_iSystem))

	if (Multiplayer.MissionMenusShared.g_iTimeLimit == -1):
		kStream.WriteChar (chr (255))
	else:
		kStream.WriteChar(chr(Multiplayer.MissionMenusShared.g_iTimeLimit))
		kStream.WriteInt(Multiplayer.MissionShared.g_iTimeLeft + int(App.g_kUtopiaModule.GetGameTime()))

	if (Multiplayer.MissionMenusShared.g_iFragLimit == -1):
		kStream.WriteChar (chr (255))
	else:
		kStream.WriteChar (chr (Multiplayer.MissionMenusShared.g_iFragLimit))

	# Okay, now set the data from the buffer stream to the message
	pMessage.SetDataFromStream (kStream)

	# Send the message.
	pNetwork.SendTGMessage (iToID, pMessage)

	# We're done.  Close the buffer.
	kStream.CloseBuffer ()

	###############################################################
	# Send the scores for each player in the dictionary
	# allocate the message.
	global g_kKillsDictionary
	global g_kDeathsDictionary
	global g_kScoresDictionary

	# Construct a new dictionary containing the keys of 
	# people in the game.
	pDict = {}

	for iKey in g_kKillsDictionary.keys ():
		pDict [iKey] = 1

	for iKey in g_kDeathsDictionary.keys ():
		pDict [iKey] = 1

	for iKey in g_kScoresDictionary.keys ():
		pDict [iKey] = 1

	# Now go through the keys in the new dictionary
	# and send that person's score around.

	for iKey in pDict.keys ():
		iKills = 0
		iDeaths = 0
		iScore = 0
		
		if (g_kKillsDictionary.has_key (iKey)):
			iKills = g_kKillsDictionary [iKey]
					
		if (g_kDeathsDictionary.has_key (iKey)):
			iDeaths = g_kDeathsDictionary [iKey]
					
		if (g_kScoresDictionary.has_key (iKey)):
			iScore = g_kScoresDictionary [iKey]

		pMessage = App.TGMessage_Create ()
		pMessage.SetGuaranteed (1)		# Yes, this is a guaranteed packet
		
		# Setup the stream.
		kStream = App.TGBufferStream ()		# Allocate a local buffer stream.
		kStream.OpenBuffer (256)				# Open the buffer stream with a 256 byte buffer.
		
		# Write relevant data to the stream.
		# First write message type.
		kStream.WriteChar (chr (Multiplayer.MissionShared.SCORE_MESSAGE))

		# write kills and deaths
		kStream.WriteLong (iKey)
		kStream.WriteLong (iKills)
		kStream.WriteLong (iDeaths)
		kStream.WriteLong (iScore)

		# Okay, now set the data from the buffer stream to the message
		pMessage.SetDataFromStream (kStream)

		# Send the message.
		pNetwork.SendTGMessage (iToID, pMessage)

		# We're done.  Close the buffer.
		kStream.CloseBuffer ()

	return 1


def DamageEventHandler(pObject, pEvent):
	if (pEvent.IsHullHit() == 1):
		DamageHandler(pObject, pEvent, 1)
	else:
		DamageHandler(pObject, pEvent, 0)


def DamageHandler (TGObject, pEvent, bHullDamage):
	import Multiplayer.Modifier
	import Multiplayer.SpeciesToShip

	# Damage was done.  We need to record this for scoring purposes.
	# Get the player id of the shooter.
	iHitterID = pEvent.GetFiringPlayerID ()

	if (iHitterID == 0):
		# No player doing the hitting.  Don't record.
		return

	pShip = App.ShipClass_Cast (pEvent.GetDestination ())
	if (not pShip):
		# not a ship, so don't bother keeping track
		return

	if (pShip.IsPlayerShip () == 0):
		# Not a player ship, don't bother keeping track.
		return

	# Get the object id of the ship that was hit.
	iHitID = pShip.GetObjID ()

	iHitClass = 0
	iHitterClass = 0

	# Get the hitter's ship.
	pGame = App.MultiplayerGame_Cast(App.Game_GetCurrentGame())
	pHitterShip = pGame.GetShipFromPlayerID (iHitterID)
	if (pHitterShip):
		iHitterClass = Multiplayer.SpeciesToShip.GetClassFromSpecies (pHitterShip.GetNetType ())

	iHitClass = Multiplayer.SpeciesToShip.GetClassFromSpecies (pShip.GetNetType ())

	# Get the amount of damage done.
	fDamage = pEvent.GetDamage ()

	# Modifify damage based on ship class
	fDamage = fDamage * Multiplayer.Modifier.GetModifier (iHitterClass, iHitClass)

	# Get the dictionary that stores all the people that have hit this object.
	global g_kDamageDictionary
	pDamageByDict = None
	if (g_kDamageDictionary.has_key (iHitID)):
		# This object has been hit before.  Fetch it's damage by dictionary
		pDamageByDict = g_kDamageDictionary [iHitID]
	else:
		# Create a new dictionary since this object has not been hit by a player
		# before
		pDamageByDict = {}
		g_kDamageDictionary [iHitID] = pDamageByDict

	# Update the damage by dictinary.
	fPreviousDamageDone = 0.0
	pDamageList = None
	if (pDamageByDict.has_key (iHitterID)):
		# This player has done damage before.  Fetch previous damage done.
		# Get the list from the damage dict
		pDamageList = pDamageByDict [iHitterID]
		fPreviousDamageDone = pDamageList [bHullDamage]	# zero is shield, 1 is hull
	else:
		# This player has not done damage before.  Create a new damage list
		# to add to the damage dict.
		pDamageList = [0, 0]		# List of two elements
		pDamageByDict [iHitterID] = pDamageList

	# Add in the damage done this time.
	fPreviousDamageDone = fPreviousDamageDone + fDamage

	# Store it in the database
	pDamageList [bHullDamage] = fPreviousDamageDone

	
# This handler updates the score when an object is killed.
def ObjectKilledHandler (pObject, pEvent):
	import Multiplayer.MissionShared
	if (Multiplayer.MissionShared.g_bGameOver != 0):
		# If the game is over, then don't do anymore score processing
		return

	# Get the player ID of the firing object from the event
	iFiringPlayerID = pEvent.GetFiringPlayerID ()

	# Get the player id of the player who got killed.  It could be AI object,
	# in which case the ID is zero.
	iShipID = App.NULL_ID

	pKilledObject = pEvent.GetDestination ()
	if (pKilledObject.IsTypeOf (App.CT_SHIP)):
		pShip = App.ShipClass_Cast (pKilledObject)

		if (pShip.IsPlayerShip () == 0):
			# Not a player ship, don't bother giving kills and such.
			return

		# Get the player id of the ship from the multiplayer game.
		iKilledPlayerID = pShip.GetNetPlayerID ()
		iShipID = pShip.GetObjID ()
	else:
		# Not a ship, don't bother giving score for killing non-player ships.
		return
#		iKilledPlayerID = 0

	# At this point, we have the player id of the person who made the killing shot.
	# Award a frag to him.
	iKills = 0
	if (iFiringPlayerID != 0):
		# Get the previous frag count.
		global g_kKillsDictionary
		if (g_kKillsDictionary.has_key (iFiringPlayerID) == 1):
			# There is already this player is the kill table.  Get his previous kill total.
			iKills = g_kKillsDictionary [iFiringPlayerID]	
		else:
			# First kill.
			iKills = 0

		# Increment kills by one to count for this current kill.
		iKills = iKills + 1

	# Award a death to the person that just got killed.
	global g_kDeathsDictionary
	if (g_kDeathsDictionary.has_key (iKilledPlayerID) == 1):
		# There is already this player is the death table.  Get his previous death total.
		iDeaths = g_kDeathsDictionary [iKilledPlayerID]	
	else:
		# First death
		iDeaths = 0

	# Increment Deaths by one to count for this current kill.
	iDeaths = iDeaths + 1

	# Okay, now give all the player's who damaged this object credit.
	iScoreUpdateCount = 0		# Keep track of how many players had their score changed.
	iFiringPlayerScore = 0		# Keep track of this to send the event later.
	global g_kDamageDictionary
	global g_kScoresDictionary

	pDamageByDict = None

	if (iShipID != App.NULL_ID):
		if (g_kDamageDictionary.has_key (iShipID)):
			# Okay, there are player damage points to award.
			pDamageByDict = g_kDamageDictionary [iShipID]

	if (pDamageByDict):
		# Okay, there are player damage points to award.
		pDamageByDict = g_kDamageDictionary [iShipID]

		# Loop through the player list and award score.
		for iPlayerID in pDamageByDict.keys ():
			# Get shield and hull damage done by this player.
			pDamageList = pDamageByDict [iPlayerID]
			fShieldDamageDone = pDamageList [0]
			fHullDamageDone = pDamageList [1]

			# Compute damage done based on some formula.  For now
			# it is simple addition.
			fDamageDone = fShieldDamageDone + fHullDamageDone
			fDamageDone = fDamageDone / 10.0		# Reduce points by factor of 10 to keep numbers reasonable

			# Get previous score
			fScore = 0.0
			if (g_kScoresDictionary.has_key (iPlayerID)):
				fScore = g_kScoresDictionary [iPlayerID]
			
			fScore = fScore + fDamageDone

			# Count the number of non firing player scores.  This is
			# used to send the scores later.  The firing player has
			# his score sent separately, so it shouldn't to be counted.
			if (iPlayerID == iFiringPlayerID):
				iFiringPlayerScore = int (fScore)
			else:
#				debug("Counting " + str (iPlayerID))
				iScoreUpdateCount = iScoreUpdateCount + 1
											
			g_kScoresDictionary [iPlayerID] = int (fScore)


	# Update the score
	UpdateScore (iFiringPlayerID, iKills, iKilledPlayerID, iDeaths)

	# Now send a message to everybody else that the score was updated.
	# allocate the message.
	pMessage = App.TGMessage_Create ()
	pMessage.SetGuaranteed (1)		# Yes, this is a guaranteed packet
	
	# Setup the stream.
	kStream = App.TGBufferStream ()		# Allocate a local buffer stream.
	kStream.OpenBuffer (256)				# Open the buffer stream with a 256 byte buffer.
	
	# Write relevant data to the stream.
	# First write message type.
	kStream.WriteChar (chr (Multiplayer.MissionShared.SCORE_CHANGE_MESSAGE))

	# Write the player id of killer
	kStream.WriteLong (iFiringPlayerID)

	if (iFiringPlayerID != 0):
		# Write the kills
		kStream.WriteLong (iKills)

		# Write the score as a long
		kStream.WriteLong (iFiringPlayerScore)

	# Write the player id of killed
	kStream.WriteLong (iKilledPlayerID)
	
	# Write the deaths
	kStream.WriteLong (iDeaths)

	# Write out the number of score changes
	kStream.WriteChar (chr (iScoreUpdateCount))

	# Write out scores for all the players that have score changes.
	iCount = 0
	if (pDamageByDict):
		# Loop through the player list and store the score.
		for iPlayerID in pDamageByDict.keys ():
#			debug("Checking " + str (iPlayerID))
			if (iPlayerID != iFiringPlayerID and iPlayerID != 0):	# firing player already has his score stored
#				debug("Writing score for " + str (iPlayerID) + " for " + str (g_kScoresDictionary [iPlayerID]) + " points.")
				kStream.WriteLong (iPlayerID)
				kStream.WriteLong (g_kScoresDictionary [iPlayerID])
				iCount = iCount + 1

	# Error condition.  Just put some filler in.
	while (iCount < iScoreUpdateCount):
		kStream.WriteLong (0)

	# Okay, now set the data from the buffer stream to the message
	pMessage.SetDataFromStream (kStream)

	# Send the message to everybody but me.  Use the NoMe group, which
	# is set up by the multiplayer game.
	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	if (not App.IsNull (pNetwork)):
		pNetwork.SendTGMessageToGroup ("NoMe", pMessage)

	# We're done.  Close the buffer.
	kStream.CloseBuffer ()

	# Clear the damage dictionary for this object since it is now
	# dead an we don't want memory wasted storing who did damage to
	# this thing anymore.
	if (iShipID != App.NULL_ID):
		if (g_kDamageDictionary.has_key (iShipID)):
			del g_kDamageDictionary [iShipID]

	# Check frag limit to see if game is over
	CheckFragLimit ()

	return

def CheckFragLimit ():
	import Multiplayer.MissionShared
	import Multiplayer.MissionMenusShared

	if (Multiplayer.MissionShared.g_bGameOver):
		# Don't check frag limit if game is over
		return

	iFragLimit = Multiplayer.MissionMenusShared.g_iFragLimit
	if (iFragLimit == -1):
		# There are no frag limits
		return

	# Go through kill list to determine if anybody has reached the frag limit.
	bOver = 0
	if (Multiplayer.MissionMenusShared.g_iUseScoreLimit):
		for iKey in g_kScoresDictionary.keys ():
			if (g_kScoresDictionary [iKey] >= iFragLimit * 10000):
				# Yes, game is over.
				bOver = 1				
				break
	else:
		for iKey in g_kKillsDictionary.keys ():
			if (g_kKillsDictionary [iKey] >= iFragLimit):
				# Yes, game is over.
				bOver = 1				
				break

	if (bOver):
		Multiplayer.MissionShared.EndGame(Multiplayer.MissionShared.END_SCORE_LIMIT_REACHED)

def UpdateScore (iFiringPlayerID, iKills, iKilledPlayerID, iDeaths):
	import Mission1Menus

	# Set the new value in the dictionary
	global g_kKillsDictionary
	global g_kDeathsDictionary

	if (iFiringPlayerID != 0):
		g_kKillsDictionary [iFiringPlayerID] = iKills

	g_kDeathsDictionary [iKilledPlayerID] = iDeaths

	# Do a little subtitle announcing the kill.
	DoKillSubtitle (iFiringPlayerID, iKilledPlayerID)

	# Update the interface
	Mission1Menus.RebuildPlayerList ()

def DoKillSubtitle (iFiringPlayerID, iKilledPlayerID):
	import Multiplayer.MissionShared
	pDatabase = Multiplayer.MissionShared.g_pDatabase

	pcSubString = None
	pcName = None
	pcKilledName = None
	pcString = None

	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	if (pNetwork):
		# Create a subtitle action to display the fact that a kill/death occurred.
		pPlayerList = pNetwork.GetPlayerList ()

		# Get killer's name
		if (iFiringPlayerID != 0):
			pPlayer = pPlayerList.GetPlayer (iFiringPlayerID)
			if (pPlayer):
				kName = pPlayer.GetName ()
				pcName = kName.GetCString ()

		# Get killed name
		if (iKilledPlayerID != 0):
			pPlayer = pPlayerList.GetPlayer (iKilledPlayerID)
			if (pPlayer):
				kName = pPlayer.GetName ()
				pcKilledName = kName.GetCString ()

			# The ship name is more likely to be accurate than the listing from the
			# Network (what if the killed player has disconnected?). We use that
			# instead, if we can.
			pGame = App.MultiplayerGame_Cast(App.Game_GetCurrentGame())
			pShip = pGame.GetShipFromPlayerID(iKilledPlayerID)
			if pShip:
				if pShip.GetName():
					pcKilledName = pShip.GetName()
					
		if (pcName != None and pcKilledName != None):	
			# Player killed by player

			# Get the main string from the database.  The main
			# string will have formatting information in it for
			# translation reasons.
			pString = pDatabase.GetString ("Killed By")
			pcString = pString.GetCString ()

			# Construct the sentence in manner similar to sprintf.
			# Use the formatting information in pString to 
			# construct the sentence.
			pcSubString = pcString % (pcKilledName, pcName)
		elif (iKilledPlayerID != 0 and iFiringPlayerID == 0):
			# AI killed player
			# Get the main string from the database.  The main
			# string will have formatting information in it for
			# translation reasons.
			pString = pDatabase.GetString ("Was Killed")
			pcString = pString.GetCString ()

			# Construct the sentence in manner similar to sprintf.
			# Use the formatting information in pString to 
			# construct the sentence.
			pcSubString = pcString % pcKilledName

	if (pcSubString != None):
		# Okay, there's a subtitle to display
		pSequence = App.TGSequence_Create ()
		pSubtitleAction = App.SubtitleAction_CreateC (pcSubString)
		pSubtitleAction.SetDuration (5.0)
		pSequence.AddAction (pSubtitleAction)
		pSequence.Play ()
		
def NewPlayerHandler (TGObject, pEvent):
	import Mission1Menus
	# check if player is host and not dedicated server.  If dedicated server, don't
	# add the host in as a player.
	iPlayerID = pEvent.GetPlayerID ()

	# Check if this player is already in the dictionary.
	global g_kKillsDictionary 
	global g_kDeathsDictionary 

	if (not g_kKillsDictionary.has_key (iPlayerID)):
		# Add a blank key
		g_kKillsDictionary [iPlayerID] = 0		# No kills

	if (not g_kDeathsDictionary.has_key (iPlayerID)):
		# Add a blank key
		g_kDeathsDictionary [iPlayerID] = 0		# No deaths

	# Rebuild the player list since a new player was added
	Mission1Menus.RebuildPlayerList ()

	return

def DeletePlayerHandler (TGObject, pEvent):
	import Mission1Menus
	# We only handle this event if we're still connected.  If we've been disconnected,
	# then we don't handle this event since we want to preserve the score list to display
	# as the end game dialog.

	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	if (pNetwork):
		if (pNetwork.GetConnectStatus () == App.TGNETWORK_CONNECTED or pNetwork.GetConnectStatus () == App.TGNETWORK_CONNECT_IN_PROGRESS):
			# We do not remove the player from the dictionary.  This way, if the
			# player rejoins, his score will be preserved.
			
			# Rebuild the player list since a player was removed.
			Mission1Menus.RebuildPlayerList ()
	return

def ObjectCreatedHandler (TGObject, pEvent):
	import Mission1Menus
	# We only care about ships.
	pShip = App.ShipClass_Cast (pEvent.GetDestination ())
	if (pShip):
		# We only care about ships.
		if (pShip.IsPlayerShip ()):
			# A player ship just got created, we need to update the info pane
			Mission1Menus.RebuildInfoPane ()

		ResetEnemyFriendlyGroups()

def ResetEnemyFriendlyGroups():
	# Go through all the ships in the world and make them enemies

	# Go through player list, trying to find all the ships
	pNetwork = App.g_kUtopiaModule.GetNetwork ()
	pGame = App.MultiplayerGame_Cast (App.Game_GetCurrentGame ())

	if (pNetwork and pGame):
		pMission = MissionLib.GetMission ()
		pEnemyGroup = pMission.GetEnemyGroup ()

		# First clear the groups.  We will be readding everybody
		# so we want to start with an empty group.
		pEnemyGroup.RemoveAllNames ()

		pPlayerList = pNetwork.GetPlayerList ()
		iNumPlayers = pPlayerList.GetNumPlayers ()

		for i in range(iNumPlayers):
			pPlayer = pPlayerList.GetPlayerAtIndex (i)
			iPlayerID = pPlayer.GetNetID ()
			pShip = pGame.GetShipFromPlayerID (iPlayerID)		

			if (pShip and iPlayerID != pNetwork.GetLocalID ()):
				# Good, there is a ship for this player
#				debug("adding to enemy group: %s" % pShip.GetName())
				pEnemyGroup.AddName (pShip.GetName ())

def RestartGameHandler (pObject, pEvent):
	import Multiplayer.MissionShared
	pNetwork = App.g_kUtopiaModule.GetNetwork ()

	if (not pNetwork):
		return

	# Okay, we're restarting the game.
	
	# Send Message to everybody to restart
	pMessage = App.TGMessage_Create ()
	pMessage.SetGuaranteed (1)		# Yes, this is a guaranteed packet
	
	# Setup the stream.
	kStream = App.TGBufferStream ()		# Allocate a local buffer stream.
	kStream.OpenBuffer (256)				# Open the buffer stream with a 256 byte buffer.
	
	# Write relevant data to the stream.
	# First write message type.
	kStream.WriteChar (chr (Multiplayer.MissionShared.RESTART_GAME_MESSAGE))

	# Okay, now set the data from the buffer stream to the message
	pMessage.SetDataFromStream (kStream)

	# Send the message.
	pNetwork.SendTGMessage (0, pMessage)

def RestartGame ():
	import Multiplayer.MissionShared
	import Mission1Menus
	import Multiplayer.MissionMenusShared

	# Reset scoreboard.
	# Clear dictionaries
	global g_kKillsDictionary 
	global g_kDeathsDictionary 
	global g_kScoresDictionary 
	global g_kDamageDictionary 

	for iKey in g_kKillsDictionary.keys ():
		g_kKillsDictionary [iKey] = 0	

	for iKey in g_kDeathsDictionary.keys ():
		g_kDeathsDictionary [iKey] = 0

	for iKey in g_kScoresDictionary.keys ():
		g_kScoresDictionary [iKey] = 0

	for iKey in g_kDamageDictionary.keys ():
		g_kDamageDictionary [iKey] = 0

	# Clear game over flag
	Multiplayer.MissionShared.g_bGameOver = 0

	# Clear ships again just in case
	Multiplayer.MissionShared.ClearShips ()

	# Rebuild score board
	Mission1Menus.RebuildPlayerList ()

#	debug("Restarting game")
	# Reset time limit
	if (Multiplayer.MissionMenusShared.g_iTimeLimit != -1):
		Multiplayer.MissionShared.g_iTimeLeft = Multiplayer.MissionMenusShared.g_iTimeLimit * 60

	# Turn off the chat window and put it back where it belongs
	pTopWindow = App.TopWindow_GetTopWindow()
	pMultWindow = App.MultiplayerWindow_Cast(pTopWindow.FindMainWindow(App.MWT_MULTIPLAYER))
	pChatWindow = pMultWindow.GetChatWindow()
	pChatWindow.SetPosition(0.0, 0.0, 0)
	if pChatWindow.IsVisible():
		pMultWindow.ToggleChatWindow()

	# Treat as if ship got killed, so go to select ship screen.
	Multiplayer.MissionMenusShared.ShowShipSelectScreen ()
