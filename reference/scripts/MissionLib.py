import App
import loadspacehelper

import Bridge.TacticalCharacterHandlers
import Bridge.HelmCharacterHandlers
import Bridge.XOCharacterHandlers
import Bridge.ScienceCharacterHandlers
import Bridge.EngineerCharacterHandlers

TRUE = 1
FALSE = 0

POINTER_LEFT			= 0
POINTER_UL				= 1
POINTER_UP				= 2
POINTER_UR				= 3
POINTER_RIGHT			= 4
POINTER_DR				= 5
POINTER_DOWN			= 6
POINTER_DL				= 7
POINTER_UL_CORNER		= 8
POINTER_UR_CORNER		= 9

# Folder where temporary mission save files are stored.
TEMP_MISSION_SAVE_FOLDER = "\Data\MissionTemp\\"

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print
#debug("Loading " + __name__ + " module...")

g_lMissionTimers		= []
g_lEpisodeTimers		= []
g_lInfoBoxes			= []
g_lInfoOpenSource		= []
g_lInfoCloseSource		= []
g_lInfoOpenEvent		= []
g_lInfoCloseEvent		= []

g_idLargeLoadingScreen	= App.NULL_ID
g_lPointerArrows		= []

g_bViewscreenOn			= 0
g_bFFGameOver			= 0

g_idMasterSequenceObj	= App.NULL_ID

g_fTractorStartFiring	= 0.0


###############################################################################
#	SetRandomRotation(pShip, fSpeed)
#
#	Setup the ship so it spins along a random axis at the given speed.
#	
#	Args:	pShip  - The ship whose angular velocity will be set...
#			fSpeed - The speed of the rotation, in degrees per second.
#	
#	Return:	none
###############################################################################
def SetRandomRotation(pShip, fSpeed):
	# Create the vector
	vVelocity = App.TGPoint3()
	
	# Set it to a random direction...
	vVelocity.SetXYZ( (App.g_kSystemWrapper.GetRandomNumber(20001) - 10000) / 10000.0, (App.g_kSystemWrapper.GetRandomNumber(20001) - 10000) / 10000.0, (App.g_kSystemWrapper.GetRandomNumber(20001) - 10000) / 10000.0)

	# Set the length to the specified speed.  Convert degrees
	# to radians, since the game works with radians...
	vVelocity.Unitize()
	vVelocity.Scale( fSpeed * App.HALF_PI / 180.0 )
	
	# Now that the angular velocity vector is setup, tell the
	# ship to spin along it...  Since this is a random vector,
	# it doesn't really matter if it's in world or model space.
	# Use world space because it's probably marginally faster.
	pShip.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_WORLD_SPACE)

###############################################################################
#	CreateTimer(eType, sFunctionHandler, fStart, fDelay, fDuration, bEpisode)
#	
#	A simplified function for creating a script-based timer event.
#	
#	Args:	eType				- event type to use
#			sFunctionHandler	- function to run
#			fStart				- when this starts firing
#			fDelay				- delay between firings
#			fDuration			- how long this fires for
#			bEpisode			- does this go in the mission or episode list?
#
#	Return:	pTimer
###############################################################################
def CreateTimer(eType, sFunctionHandler, fStart, fDelay, fDuration, bEpisode = 0, bRealTime = 0):
	"A simplified function for creating a script-based timer event."

	# Setup the handler function.
	pGame = App.Game_GetCurrentGame()
	if (pGame == None):
		return None
	pEpisode = pGame.GetCurrentEpisode()
	if (pEpisode == None):
		return None
	pMission = pEpisode.GetCurrentMission()
	if (pMission == None):
		return None

	pMission.AddPythonFuncHandlerForInstance( eType, sFunctionHandler )

	# Create the event and the event timer.
	pEvent = App.TGEvent_Create()
	pEvent.SetEventType(eType)
	pEvent.SetDestination(pMission)
	pTimer = App.TGTimer_Create()
	pTimer.SetTimerStart(fStart)
	pTimer.SetDelay(fDelay)
	pTimer.SetDuration(fDuration)
	pTimer.SetEvent(pEvent)
	if (bRealTime):
		App.g_kRealtimeTimerManager.AddTimer(pTimer)
	else:
		App.g_kTimerManager.AddTimer(pTimer)

	if (bEpisode == 0):
		global g_lMissionTimers
		g_lMissionTimers.append(pTimer.GetObjID())
	else:
		global g_lEpisodeTimers
		g_lEpisodeTimers.append(pTimer.GetObjID())
	
	return pTimer

###############################################################################
#	DeleteAllMissionTimers()
#	
#	Destroys all timers created using MissionLib.CreateTimer()
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def DeleteAllMissionTimers():
	global g_lMissionTimers
	for idTimer in g_lMissionTimers:
		App.g_kTimerManager.DeleteTimer(idTimer)
		App.g_kRealtimeTimerManager.DeleteTimer(idTimer)
	g_lMissionTimers = []

###############################################################################
#	DeleteAllEpisodeTimers()
#	
#	Destroys all timers created using MissionLib.CreateTimer() for the episode
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def DeleteAllEpisodeTimers():
	global g_lEpisodeTimers
	for idTimer in g_lEpisodeTimers:
		App.g_kTimerManager.DeleteTimer(idTimer)
		App.g_kRealtimeTimerManager.DeleteTimer(idTimer)
	g_lEpisodeTimers = []


###############################################################################
#	ProximityCheck
#
#	Next create a ProximityCheck, setup its parameters,
#	and attach it the Main object
#	
#	Args:	pMainObj			- The object the check is centered around
#			fRadius				- Radius to check against (Negative means the prox
#								  check will trigger when objects are inside, positive
#								  means it'll trigger when they are outside)
#			pObjList			- A (python) list of objects that can trigger the check.
#			sFunctionHandler	- The function to call (including the module name) when
#								  the proximity check is triggered.
#			pSet				- The set the proximity check will be created in.  If the
#								  pMainObj exists, this doesn't need to be specified.
#			eEventType			- If specified, this is the event type that's used for
#								  the events that the proximity check creates.
#	
#	Return:	The proximity check.
###############################################################################
def ProximityCheck(pMainObj, fRadius, pObjList, sFunctionHandler, pSet = None, eEventType = None):
	if not pMainObj:
		return 0

	# Make a new event type for this proximity check.
	if not eEventType:
		eEventType = App.Game_GetNextEventType()

	# Make sure we know which set to put the prox check in.
	if not pSet:
		pSet = pMainObj.GetContainingSet()

	# Next create a ProximityCheck, setup its parameters, and attach
	# it the Main object
	pProximityManager = pSet.GetProximityManager()
	pProximity = App.ProximityCheck_Create(eEventType)

	if pMainObj:
		pMainObj.AttachObject(pProximity)

	# Add the check to the proximity manager, so it can actually
	# be triggered.
	pProximityManager.AddObject(pProximity)

	# Negative radius means to check inside, positive means
	# to check outside...
	if (fRadius < 0):
		fRadius = -fRadius
		insideoutsideflag =  App.ProximityCheck.TT_INSIDE
	else:
		insideoutsideflag =  App.ProximityCheck.TT_OUTSIDE
	pProximity.SetRadius(fRadius)

	# Then add any objects that you want checked against 
	for pObj in pObjList:
		pProximity.AddObjectToCheckList(pObj, insideoutsideflag)

	# Finally, add the event handler to tell the game which function to
	# call when this is triggered:
	pMission = GetMission()
	if (pMission == None):
		return 0
	App.g_kEventManager.AddBroadcastPythonFuncHandler( eEventType, pMission, sFunctionHandler )

	# Return the proximity check, in case the user wants to do
	# anything with it.
	return pProximity

###############################################################################
#	SetDisplayNames(pDatabase)
#	
#	Look through all the objects in all the sets.  If their name
#	is found in the given database, set their Display Name to what's
#	listed in the database.
#	
#	Args:	pDatabase	- The TGL database to get names from.
#	
#	Return:	none
###############################################################################
def SetDisplayNames(pDatabase):
	leSkipObjects = ( 
		App.CT_NEBULA,
		App.CT_ASTEROID_TILE,
		App.CT_ASTEROID_FIELD,
		App.CT_GRID,
		App.CT_BACKDROP
		)

	# Get all sets:
	lSets = App.g_kSetManager.GetAllSets()

	# Loop through all the sets...
	for pSet in lSets:
		# Skip the bridge set.
		if pSet.GetName() == "bridge":
			continue

		# Get all the objects in this set.
		lObjects = pSet.GetClassObjectList(App.CT_OBJECT)
		for pObject in lObjects:
			# Skip certain types of objects.
			bSkip = 0
			for eObjectType in leSkipObjects:
				if pObject.IsTypeOf(eObjectType):
					bSkip = 1

			if bSkip:
				continue

			SetSingleDisplayName(pDatabase, pObject)

###############################################################################
#	SetSingleDisplayName
#	
#	Find this object's display name in the given database,
#	and set the object's Display Name to match it.
#	
#	Args:	pDatabase	- The TGL database to grab the display name from
#			pObject		- The object whose Display Name we're setting.
#	
#	Return:	None
###############################################################################
def SetSingleDisplayName(pDatabase, pObject):
	# Get this object's normal name...
	sName = pObject.GetName()
	if sName:
		# Is there a string for this name in the given database?
		kDisplayName = pDatabase.GetString(sName)
		if kDisplayName:
			# Yep, found one.  Set the display name of the object.
			pObject.SetDisplayName(kDisplayName)

###############################################################################
#	IgnoreEvent
#	
#	Take the given event and don't allow it to pass on to other
#	handlers.  This is an event handler that can be assigned to
#	various objects to remove their default behavior.
#	Note: In its current implementation, this will not prevent
#	broadcast handlers from handling the event.
#	
#	Args:	pObject	- The object the event is sent to.
#			pEvent	- The event.
#	
#	Return:	None
###############################################################################
def IgnoreEvent(pObject, pEvent):
	pass

def IgnoreEventOnce(pObject, pEvent):
	pObject.RemoveHandlerForInstance(pEvent.GetEventType(), __name__ + ".IgnoreEventOnce")

###############################################################################
#	OrientWaypointsTowardPlayer
#	
#	Orient the first waypoint so it's facing the player, matching its
#	up vector, too, if possible.  For the remaining waypoints that are
#	given, rotate them around the first waypoint, so the whole set appears
#	to be moving as one big set, rotating around that first waypoint..
#	Any waypoints connected (in a path) after the specified waypoints are
#	also rotated.
#	As an example...  If this is called like this:
#	OrientWaypointsToPlayer("Way1", "Way2"), and Way2 has been placed off to
#	the right of Way1... ...and Way3 is in front of Way2, connected after Way2
#	in a path...  ...then Way1 will turn to face the player, Way2 will be moved
#	so it is in the same position relative to Way1, off to Way1's right, and Way3
#	will be moved so it stays in front of Way2.
#	
#	Args:	sInitialWaypoint	- Name of the primary waypoint that will be
#								  turned to face the player.
#			*lsWaypointNames	- The names of additional waypoints to rotate
#								  around sInitialWaypoint.
#	
#	Return:	none
###############################################################################
def OrientWaypointsTowardPlayer(sInitialWaypoint, *lsWaypointNames):
	# Get the player.
	pGame = App.Game_GetCurrentGame()
	pPlayer = pGame.GetPlayer()
	if (pPlayer == None):
		return

	# And get the player's set, so we know where to look for
	# the waypoints.
	pSet = pPlayer.GetContainingSet()
	if (pSet == None):
		return

	# Grab the initial waypoint.
	pPrimaryPlacement = App.PlacementObject_GetObject(pSet, sInitialWaypoint)
	if (pPrimaryPlacement == None):
		# Couldn't find the waypoint.
		return

	# Determine the orientation needed so pPrimaryPlacement will face pPlayer.
	vDirection = pPlayer.GetWorldLocation()
	vDirection.Subtract( pPrimaryPlacement.GetWorldLocation() )
	vDirection.Unitize()
	if vDirection.Length() < 0.5:
		# The player is in the same location as the placement.  Don't rotate.
		return

	# Find a good Up vector.  It needs to be perpendicular to vDirection.
	vUp = pPlayer.GetWorldUpTG()
	vRight = vDirection.Cross(vUp)
	vUp = vRight.UnitCross(vDirection)
	if vUp.Length() < 0.5:
		# Ugh.  Player's up is aligned to vDirection.  Use the player's Forward
		# vector instead.
		vUp = pPlayer.GetWorldForwardTG()

	# Ok, we've got the forward and up vectors we'll need to match.  Save our
	# current rotation, and align ourselves with the new orientation...
	mOldRotation = pPrimaryPlacement.GetWorldRotation()
	pPrimaryPlacement.AlignToVectors(vDirection, vUp)
	pPrimaryPlacement.UpdateNodeOnly()

	# Determine what the difference in rotation was...
	# ***CHECKME:  :)  Check that the right matrix is transposed, and the multiplication
	# is done in the right order...  (If either is wrong, it'll be obvious).
	#mRotationDifference = mOldRotation.Transpose().MultMatrix( pPrimaryPlacement.GetRotation() )
	mRotationDifference = pPrimaryPlacement.GetRotation().MultMatrix( mOldRotation.Transpose() )

	# Undo the rotation, since it will be done again in the code below...
	pPrimaryPlacement.Rotate( mRotationDifference.Transpose() )

	# Build up a list of all the placements that will be rotated
	# around the primary one.  Add the primary placement to this list so
	# that we rotate all the waypoints after it in its path.
	lpRotatedPlacements = []
	for sName in (sInitialWaypoint,) + lsWaypointNames:
		pPlacement = App.PlacementObject_GetObject(pSet, sName)
		if (pPlacement != None):
			# Found the placement.  Add it to the list...
			lpRotatedPlacements.append( pPlacement )

			# And, if it's a waypoint, add all the placements in the path after it.
			pWaypoint = App.Waypoint_Cast(pPlacement)
			if (pWaypoint != None):
				# It's a waypoint..  Anything after it?
				pAfter = pWaypoint.GetNext()
				while (pAfter != None)  and  (not pAfter.GetName() in lsWaypointNames):
					# Add this one to the list...
					lpRotatedPlacements.append(pAfter)

					# And loop...
					pAfter = pAfter.GetNext()
			# Finished adding waypoints in the path.
	# Ok, all done building the list of waypoints to rotate.
	# Now rotate all of them.
	for pPlacement in lpRotatedPlacements:
		# We're rotating this around the primary placement...
		vPositionDiff = pPlacement.GetWorldLocation()
		vPositionDiff.Subtract( pPrimaryPlacement.GetWorldLocation() )

		# Rotate the position...
		vPositionDiff.MultMatrixLeft( mRotationDifference )
		vPositionDiff.Add( pPrimaryPlacement.GetWorldLocation() )
		pPlacement.SetTranslate( vPositionDiff )

		# And rotate the orientation of this placement...
		pPlacement.Rotate( mRotationDifference )
		pPlacement.UpdateNodeOnly()
	# All done.

###############################################################################
#	OrientObjectTowardObject
#	
#	Turn Object 1 so it's facing Object 2, with its Up vector roughly
#	aligned to Object 2's up vector.
#	
#	Args:	pObject1	- The object whose orientation is being adjusted
#			pObject2	- The object that object 1 is being oriented towards
#	
#	Return:	None
###############################################################################
def OrientObjectTowardObject(pObject1, pObject2):
	if None in (pObject1, pObject2):
		return

	# Get the direction that object 1 needs to face..
	vDirection = pObject2.GetWorldLocation()
	vDirection.Subtract( pObject1.GetWorldLocation() )
	vDirection.Unitize()

	# Find an Up vector that's perpendicular to vDirection and aligned
	# to pObject2's up vector...
	vRight = vDirection.Cross( pObject2.GetWorldUpTG() )
	vUp = vRight.UnitCross(vDirection)

	# Align pObject1 to the fwd/up vectors...
	pObject1.AlignToVectors(vDirection, vUp)
	pObject1.UpdateNodeOnly()

###############################################################################
#	AddNavPoints
#	RemoveNavPoints
#	
#	Let the game know that certain placements within the given set
#	are Nav Points (or are no longer Nav Points).
#	
#	Args:	sSet			- Name of the set in which these placements exist.
#			lsNavPointNames	- Names of all the placements to change.
#	
#	Return:	None
###############################################################################
def AddNavPoints(sSet, *lsNavPointNames):
	pSet = App.g_kSetManager.GetSet(sSet)
	if pSet:
		for sNavPoint in lsNavPointNames:
			pPlacement = App.PlacementObject_GetObject(pSet, sNavPoint)
			if pPlacement:
				pPlacement.SetNavPoint(1)

def RemoveNavPoints(sSet, *lsNavPointNames):
	pSet = App.g_kSetManager.GetSet(sSet)
	if pSet:
		for sNavPoint in lsNavPointNames:
			pPlacement = App.PlacementObject_GetObject(pSet, sNavPoint)
			if pPlacement:
				pPlacement.SetNavPoint(0)

###############################################################################
#	AddCommandableShip
#	RemoveCommandableShip
#	RemoveAllCommandableShips
#	
#	Change the list of ships that can be commanded by the player
#	using the player's "Command Fleet" button.
#	
#	Args:	sShipName	- Name of the ship to add/remove from the list.
#			lsCommands	- A list of which commands are available.  The commands
#						  listed here MUST match up with the commands available
#						  in ScienceMenuHandlers.py (Look in that file for what's
#						  available.  Look for "### AVAILABLE FLEET COMMANDS:").
#						  Or don't add extra arguments, and all commands will be
#						  available.
#						  Current Commands:	"AttackTarget"
#											"DisableTarget"
#											"DefendTarget"
#											"HelpMe"
#
#	Examples:	AddCommandableShip("Geronimo", "HelpMe")	# Geronimo will only help
#				AddCommandableShip("Enterprise")			# All options available.
#				AddCommandableShip("Indefatigable", "DisableTarget", "HelpMe")	# Will disable your target or help you.
#				RemoveCommandableShip("Enterprise")
#				RemoveAllCommandableShips()
#	
#	Return:	None
###############################################################################
def AddCommandableShip(sShipName, *lsCommands):
	Bridge.HelmMenuHandlers.AddCommandableShip(sShipName, lsCommands)

def RemoveCommandableShip(sShipName):
	Bridge.HelmMenuHandlers.RemoveCommandableShip(sShipName)

def RemoveAllCommandableShips():
	Bridge.HelmMenuHandlers.RemoveAllCommandableShips()

###############################################################################
#	CreatePlayerShip()
#	
#	Create the player's ship, if there isn't one already, or if the existing
#	one is not of the correct type.  In the latter case we remove the old ship.
#	
#	Args:	sShipClass	- Class of ship (a ship file)
#			pSet		- Set into which to place the player
#			pcName		- name of the player
#			sWaypoint	- Waypoint name at which to set the player
#			bUnloadShip	- Do we want to unload all torps the player is carrying?
#
#	Return:	none
###############################################################################
def CreatePlayerShip(sShipClass, pSet, pcName, sWaypoint, bUnloadShip = 0):
	pGame = App.Game_GetCurrentGame()

	#
	# Ugly, Ugly, Ugly
	#
	# Until we fix the type vs. string typing issue, we can't know if what they
	# want (string) is the same as what we have (type) without doing a big 'if'
	# check, which of course limits us.
	#

	# Don't show an entering banner this time..
	import Bridge.HelmMenuHandlers
	Bridge.HelmMenuHandlers.g_bShowEnteringBanner = 0

	bCreateNewShip = 1
	pPlayer = pGame.GetPlayer()
	if pPlayer:
		pOldSet = pPlayer.GetContainingSet()
		# Player exists...   But are they about to die?  If they're
		# Dead and they're not in a set, assume that they're about to
		# be deleted, and create a new player.
		if (not pPlayer.IsDead()):
			# Player isn't dead.  Check the player's ship to see if
			# a new one should be created.
			kSpecies = pPlayer.GetShipProperty().GetSpecies()

			if (((kSpecies == App.SPECIES_GALAXY) and (sShipClass != "Galaxy")) or
				((kSpecies == App.SPECIES_SOVEREIGN) and (sShipClass != "Sovereign"))):
				# Remove any old menus/handlers before setting up the new ship
				DetachCrewMenus()

				pOldSet.DeleteObjectFromSet(pPlayer.GetName())
			else:
				bCreateNewShip = 0
		else:
			if (pOldSet != None):
				# Remove any old menus/handlers before setting up the new ship
				DetachCrewMenus()

				pOldSet.DeleteObjectFromSet(pPlayer.GetName())

	# If the ships aren't the same (or no previous ship), create the new one
	if (bCreateNewShip == 1):
		pShipMod = __import__("ships." + sShipClass)
#		kShipStats = pShipMod.GetShipStats()
		pPlayer = loadspacehelper.CreateShip(sShipClass, pSet, pcName, sWaypoint)

		if (pPlayer != None):
			pGame.SetPlayer(pPlayer)
			#
			# If a federation ship, give it a default NCC
			if (sShipClass == "Sovereign"):
				pPlayer.ReplaceTexture("Data/Models/Ships/Sovereign/Sovereign.tga", "ID")
			elif (sShipClass == "Galaxy"):
				pPlayer.ReplaceTexture("Data/Models/SharedTextures/FedShips/Dauntless.tga", "ID")
			elif (sShipClass == "Nebula"):
				pPlayer.ReplaceTexture("Data/Models/SharedTextures/FedShips/Berkeley.tga", "ID")
			elif (sShipClass == "Akira"):
				pPlayer.ReplaceTexture("Data/Models/Ships/Akira/Geronimo.tga", "ID")
			elif (sShipClass == "Ambassador"):
				pPlayer.ReplaceTexture("Data/Models/Ships/Ambassador/Zhukov.tga", "ID")

			# Set the variable for the player's hardpoint file, so we can use
			# it later if the difficulty level is changed.
			App.Game_SetPlayerHardpointFileName(pShipMod.GetShipStats()["HardpointFile"])
			loadspacehelper.AdjustShipForDifficulty(pPlayer, App.Game_GetPlayerHardpointFileName())
			pPlayer.SetAlertLevel(App.ShipClass.GREEN_ALERT)

			pTorpSys = pPlayer.GetTorpedoSystem()
			if(pTorpSys):
				if (bUnloadShip != 0):
					# Unloads all torps, and resets the current loads to 0
					pTorpSys.SetAmmoType(0, 0)

					# Unload all other torps from the system
					iNumTypes = pTorpSys.GetNumAmmoTypes()
					for iType in range(iNumTypes):
						pTorpType = pTorpSys.GetAmmoType(iType)

						# Unload current load
						pTorpSys.LoadAmmoType(iType, -pTorpSys.GetNumAvailableTorpsToType(iType))

	return (pPlayer)


###############################################################################
#	SubtitledLine(pAction, pDatabase, pcString, pcSet, pcCharacter)
#	
#	Play audio line with subtitle given string database and a string ID.
#	Called as script action or with NULL/None.
#	
#	Args:	pAction		- The script action passed in
#			pDatabase	- string database to use.
#			pcString	- string identifier.
#			pcSet		- name of the set for a character, if needed
#			pcCharacter	- name of a character, if needed
#			bAddToLog	- do we add the line to the mission log?
#	
#	Return:	0
###############################################################################
def SubtitledLine(pAction, pDatabase, pcString, pcSet = None, pcCharacter = None, bAddToLog = 1):
	assert pDatabase
	assert pcString

	if (pcSet):
		pSet = App.g_kSetManager.GetSet(pcSet)
		if not (pSet):
			# Okay, assume the pcSet was really a character name, and run based off that...
			pSubtitle = App.CharacterAction_Create(None, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, pcString, pcSet, 0, pDatabase)
			pEvent = App.TGObjPtrEvent_Create()
			assert pEvent
			pEvent.SetEventType(App.ET_ACTION_COMPLETED)
			pEvent.SetDestination(App.g_kTGActionManager)
			pEvent.SetObjPtr(pAction)
			pSubtitle.AddCompletedEvent(pEvent)
			pSubtitle.Play()

			return 1
		pCharacter = App.CharacterClass_GetObject(pSet, pcCharacter)
		if (pCharacter):
			pSubtitle = App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS, pcString, None, 0, pDatabase)
			pEvent = App.TGObjPtrEvent_Create()
			assert pEvent
			pEvent.SetEventType(App.ET_ACTION_COMPLETED)
			pEvent.SetDestination(App.g_kTGActionManager)
			pEvent.SetObjPtr(pAction)
			pSubtitle.AddCompletedEvent(pEvent)
			pSubtitle.Play()

			return 1

	# Check to see if the sound is loaded.  If not, try to load it
	if not (App.g_kSoundManager.GetSound(pcString)):
		pGame = App.Game_GetCurrentGame()
		if not (pGame):
			return 0

		# Check if we're streaming voice files...
		iLoadFlags = 0
		if App.g_kConfigMapping.HasValue("Sound", "StreamVoices")  and  App.g_kConfigMapping.GetIntValue("Sound", "StreamVoices"):
			iLoadFlags = App.TGSound.LS_STREAMED

		pGame.LoadDatabaseSoundInGroup(pDatabase, pcString, "LoadedOnDemand", iLoadFlags)
		if not App.g_kSoundManager.GetSound(pcString):
			# Still unable to load sound, bail
			return 0

	pSequence = App.TGSequence_Create()
	assert pSequence
	pSound = App.TGSoundAction_Create(pcString, App.TGSAF_DEFAULTS + App.TGSAF_VOICE)
	assert pSound
	pSubtitle = App.SubtitleAction_Create(pDatabase, pcString)

	pEvent = App.TGObjPtrEvent_Create()
	assert pEvent
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetObjPtr(pSubtitle)
	pSound.AddCompletedEvent(pEvent)

	pSound.SetSkippable(1)
	pSequence.AddAction(pSound)
	pSequence.AddAction(pSubtitle)

	# Add an event to end this action when the sound finishes, so the sequence
	# acts properly
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetObjPtr(pAction)
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pSequence.AddCompletedEvent(pEvent)

	# Add the line to the mission log, if desired
	if (bAddToLog):
		App.STMissionLog_GetMissionLog().AddLine(pDatabase.GetString(pcString))

	pSequence.Play()

	return 1
	
###############################################################################
#	StartCutscene(pAction)
#	
#	Function that starts the letterbox cutscene bars
#	
#	Args:	pAction			- Action from the cutscene sequence
#			fTimeToComeIn	- time to come in
#			fCoveredArea	- how much of the screen is covered
#			bHideReticle	- do we want to hide the reticle
#			bSilenceCallOuts - do we want the crew call outs silenced.
#	
#	Return:	0 - Action completed
###############################################################################
def StartCutscene(pAction, fTimeToComeIn = 1.0, fCoveredArea = 0.125, bHideReticle = 1, bSilenceCallOuts = 1, bStopTractor = 1):
#	debug("Starting Cutscene")

	# Turn off Tractor Beam
	if bStopTractor:
		pPlayer = GetPlayer()
		if pPlayer:
			pTractor = pPlayer.GetTractorBeamSystem()
			if (pTractor):
				pTractor.StopFiring()

	import BridgeHandlers
	BridgeHandlers.DropMenusTurnBack()
	pTop = App.TopWindow_GetTopWindow()
	pMap = App.MapWindow_Cast(pTop.FindMainWindow(App.MWT_TACTICAL_MAP))

	if pMap and pMap.IsWindowActive():
		pTop.ToggleMapWindow()

	pTop.StartCutscene(fTimeToComeIn, fCoveredArea, bHideReticle)

	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()
	pTCW.SetNotVisible(0)

	pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
	pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_CINEMATIC)

	# Shut everyone up if flagged
	if (bSilenceCallOuts):
		SetSpeakingVolume(None, App.CSP_SPONTANEOUS, 0)
	
	return 0


###############################################################################
#	EndCutscene(pAction)
#	
#	Function that ends the letterbox cutscene bars
#	
#	Args:	pAction - Action from the cutscene sequence
#	
#	Return:	0 - Action completed
###############################################################################
def EndCutscene(pAction, fTimeToLeave = 1.0):
#	debug("Ending Cutscene")
	App.TopWindow_GetTopWindow().EndCutscene(fTimeToLeave)

	pTop = App.TopWindow_GetTopWindow()
	pTCW = App.TacticalControlWindow_GetTacticalControlWindow()

	# Ensure that the cinematic window is set interactive. If we were in warp
	# during a cutscene, then the normal mechanism will not be triggered.
	pCinematic = App.CinematicWindow_Cast(pTop.FindMainWindow(App.MWT_CINEMATIC))
	if pCinematic:
		pCinematic.SetInteractive(1)

	pBridgeSet = App.g_kSetManager.GetSet("bridge")
	pRenderedSet = App.g_kSetManager.GetRenderedSet()

	# If the bridge is not the rendered set, then force tactical to be visible.
	# Otherwise, make sure that the bridge is visible.
	if (str(pBridgeSet) != str(pRenderedSet)):
		pTop.ForceTacticalVisible()
		pTCW.SetVisible()

		pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_END_CINEMATIC)	# first cancel cinematic mode.
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_TACTICAL)
	else:
		pTop.ForceBridgeVisible()

		pSubtitle = App.SubtitleWindow_Cast(pTop.FindMainWindow(App.MWT_SUBTITLE))
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_END_CINEMATIC)	# first cancel cinematic mode.
		pSubtitle.SetPositionForMode(App.SubtitleWindow.SM_BRIDGE)
		
	# Make sure the call-outs are back at their previous levels
	SetSpeakingVolume(None, App.CSP_SPONTANEOUS, 1.0)

	return 0


###############################################################################
#	FadeOut
#	
#	Fade to black.  Useful for cutscenes and things.  Be careful
#	doing this if interface is up.  Some strangeness may occur.
#	
#	Args:	pAction		- The action calling this function
#			fFadeTime	- Time to take to fade out
#	
#	Return:	0 or 1.
###############################################################################
def FadeOut(pAction, fFadeTime = 1.5):
	pTop = App.TopWindow_GetTopWindow()
	if not pTop:
		return 0

	if not pTop.FadeOut(fFadeTime):
		return 0

#	debug("Fading out...")

	# Send ourselves an event so we're done when the fade should be done.
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetObjPtr(pAction)

	pTimer = App.TGTimer_Create()
	pTimer.SetTimerStart( App.g_kUtopiaModule.GetGameTime() + fFadeTime )
	pTimer.SetEvent(pEvent)

	App.g_kTimerManager.AddTimer(pTimer)
	return 1

###############################################################################
#	FadeIn
#	
#	Fade back in, from a previous FadeOut.
#	
#	Args:	pAction		- The action calling this function
#			fFadeTime	- Time to take to fade back in.
#	
#	Return:	
###############################################################################
def FadeIn(pAction, fFadeTime = 1.5):
	pTop = App.TopWindow_GetTopWindow()
	if not pTop:
		return 0

	if not pTop.FadeIn(fFadeTime):
		return 0

#	debug("Fading back in...")

	# Send ourselves an event so we're done when the fade should be done.
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetObjPtr(pAction)

	pTimer = App.TGTimer_Create()
	pTimer.SetTimerStart( App.g_kUtopiaModule.GetGameTime() + fFadeTime )
	pTimer.SetEvent(pEvent)

	App.g_kTimerManager.AddTimer(pTimer)
	return 1

###############################################################################
#	RemoveControl(pAction)
#	
#	Function that takes control away from the player
#	
#	Args:	pAction - Action from the cutscene sequence
#	
#	Return:	0 - Action completed
###############################################################################
def RemoveControl(pAction = None):
#	debug("Removing Player Control")
	App.TopWindow_GetTopWindow().AllowKeyboardInput(0)
	App.TopWindow_GetTopWindow().AllowMouseInput(0)
	return 0


###############################################################################
#	ReturnControl(pAction)
#	
#	Function that returns control to the player
#	
#	Args:	pAction - Action from the cutscene sequence
#	
#	Return:	0 - Action completed
###############################################################################
def ReturnControl(pAction = None):
#	debug("Returning Player Control")
	App.TopWindow_GetTopWindow().AllowKeyboardInput(1)
	App.TopWindow_GetTopWindow().AllowMouseInput(1)
	return 0

###############################################################################
#	SaveMission(pcModuleName)
#	
#	Save the mission state variables.
#	
#	Args:	pcModuleName, name of module to save.
#	
#	Return:	none
###############################################################################
def SaveMission(pcModuleName):
	return App.g_kUtopiaModule.SaveMissionState(pcModuleName)

###############################################################################
#	TryLoadMission(pcModuleName)
#	
#	Look for a mission save file for this mission. 
#	If one exists load it, restoring mission state variables.
#	
#	Args:	pcModuleName, name of module to load.
#	
#	Return:	True if mission file loaded, False if not found.
###############################################################################
def TryLoadMission(pcModuleName):
	return App.g_kUtopiaModule.LoadMissionState(pcModuleName)

###############################################################################
#	GetEpisode()
#	
#	Get current episode.
#	
#	Args:	None
#	
#	Return:	Current episode if any, otherwise returns None.
###############################################################################
def GetEpisode():
	pGame = App.Game_GetCurrentGame()
	if(pGame is None):
		return None
	return pGame.GetCurrentEpisode()

###############################################################################
#	GetMission()
#	
#	Get current mission.
#	
#	Args:	None
#	
#	Return:	Current mission if any, otherwise returns None.
###############################################################################
def GetMission():
	pGame = App.Game_GetCurrentGame()
	if(pGame is None):
		return None
	pEpisode = pGame.GetCurrentEpisode()
	if(pEpisode is None):
		return None
	return pEpisode.GetCurrentMission()

###############################################################################
#	GetPlayer()
#	
#	Get the player's ship.
#	
#	Args:	none
#	
#	Return:	pPlayer, returns None if not able to get it.
###############################################################################
def GetPlayer():	
	return App.Game_GetCurrentPlayer()

###############################################################################
#	GetPlayerSet()
#	
#	Get the set the player is currently in.
#	
#	Args:	none
#	
#	Return:	pSet, returns None if not able to get it.
###############################################################################
def GetPlayerSet():	
	pPlayer = GetPlayer()
	if(pPlayer):
		return pPlayer.GetContainingSet()
		
	return None

###############################################################################
#	GetShip(pcShipName, pSet = None)
#	
#	Get a ship from specified set. 
#	If no set specified, try to get ship from Player's set.
#	
#	Args:	pcShipName, string name of ship to get.
#			pSet, optional argument, set object to look in.
#			bAnySet, optional argument, look in all sets.
#	
#	Return:	pShip, None if not found.
###############################################################################
def GetShip(pcShipName, pSet = None, bAnySet = FALSE):	
	assert pcShipName
	if(pSet):
		return App.ShipClass_GetObject(pSet, pcShipName)
	elif bAnySet:
		return App.ShipClass_GetObject(None, pcShipName)
	# In Player's set.
	else:
		pPlayer = GetPlayer()
		if(pPlayer is None):
			return None
		pSet = pPlayer.GetContainingSet()
		return App.ShipClass_GetObject(pSet, pcShipName)

###############################################################################
#	IsInSameSet(pcShip)
#	
#	Return wether a ship is in the same set as the player.
#	
#	Args:	pcShipName, string name of ship to check.
#	
#	Return:	bool
###############################################################################
def IsInSameSet(pcShip):	
	assert pcShip
	pShip = GetShip(pcShip)
	if pShip:
		if not pShip.IsDying():
			return TRUE
	return FALSE

###############################################################################
#	GetViewScreen()
#	
#	Get the viewscreen object.
#
#	Args:	none
#	
#	Return:	pViewscreen
###############################################################################
def GetViewScreen():
	pSet = App.BridgeSet_Cast(App.g_kSetManager.GetSet ("bridge"))
	if(pSet):
		return pSet.GetViewScreen()
	
	return None

###############################################################################
#	GetViewScreenCamera
#	
#	Get the camera the viewscreen is using right now.
#	
#	Args:	None
#	
#	Return:	The camera used by the viewscreen, or None.
###############################################################################
def GetViewScreenCamera():
	# Get the viewscreen camera.
	pViewscreen = GetViewScreen()
	if pViewscreen:
		return pViewscreen.GetRemoteCam()

	return None

################################################################################
#	GetSystemName(pcLocation)
#
#	Helper function to get the system name from the location string.
#	Used by SetLocationInHelmMenu.
#
#	Args:	pcLocation, name of system location.
#			Should be in the format: "Systems.Dir.System"
#
#	Return:	None
################################################################################
def GetSystemName(pcLocation):
	i = len("Systems.")
	pcName = ""
	while(pcLocation[i] != "." and i < 255):
		pcName = pcName + pcLocation[i]
		i = i + 1
	return pcName

################################################################################
#	SetLocationInHelmMenu(pcLocation, pcSystem)
#
#	Sets our current location in the warp button and sets system menu openable.
#
#	Args:	pcLocation, name of system to set as location.
#			Should be in the format: "Systems.Dir.System"
#			pcSystemName, optional argument used when system menu name
#			is different than "Dir" as specified in pcLocation.
#
#	Return:	None
################################################################################
def SetLocationInHelmMenu(pcLocation, pcSystemName = None):
	assert pcLocation
	if(pcLocation):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
		assert pDatabase
		if(pDatabase is None):
			return
		
		# Get the warp menu
		pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
		assert pTacticalControlWindow
		if(pTacticalControlWindow is None):
			App.g_kLocalizationManager.Unload(pDatabase)
			return
		pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))
		assert pMenu
		if(pMenu is None):
			App.g_kLocalizationManager.Unload(pDatabase)
			return

		pWarpButton = App.SortedRegionMenu_GetWarpButton()
		assert pWarpButton
		if(pWarpButton is None):
			App.g_kLocalizationManager.Unload(pDatabase)
			return
	
		# Set the location on the warp menu
		pWarpButton.SetLocation(pcLocation)
	
		# How to get a System menu.
		# Use Kiska's menu to look for the "Set Course" menu, which you need to get
		# by using the database, because it might be translated one day.  This means
		# you have to use the GetSubmenuW() function:
		pSetCourseMenu = pMenu.GetSubmenuW(pDatabase.GetString("Set Course"))
		assert pSetCourseMenu
		if(pSetCourseMenu is None):
			App.g_kLocalizationManager.Unload(pDatabase)
			return

		# Unload TGL database.			
		App.g_kLocalizationManager.Unload(pDatabase)

		###
		### Very temporary for now, until we get the "starting fresh" vs. warp
		### in stuff figured out.  Pretend like we always start at this mission
		### which means that we have to set the Vesuvi system openable to make the
		### other regions available
		###
		# Now the System names happen (at this point) not to be localized, so we use
		# their direct string name and GetSubmenu().  When we create a systems.tgl
		# this will probably revert to GetSubmenuW() like the above.
		if not pcSystemName:
			pcSystemName = GetSystemName(pcLocation)
			assert pcSystemName

		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Systems.tgl")
		pSystem = pSetCourseMenu.GetSubmenuW(pDatabase.GetString (pcSystemName))
		App.g_kLocalizationManager.Unload(pDatabase)

		assert pSystem
		if(pSystem is None):
			return
		
		# Set system menu openable.
		pSystem.SetOpenable()

	
###############################################################################
#	HideCharacters()
#	
#	Hides all the characters on a set
#	
#	Args:	pSet	- set on which characters reside
#	
#	Return:	none
###############################################################################
def HideCharacters(pSet):
	# Index through ALL objects on bridge set, if they're characters, hide them
	pObject = pSet.GetFirstObject()
	pFirstObject = pObject
	while not (App.IsNull(pObject)):
		pCharacter = App.CharacterClass_Cast(pObject)
#		debug(pObject.GetName())
		pObject = pSet.GetNextObject(pObject.GetObjID())

		if (pObject.GetObjID() == pFirstObject.GetObjID()):
			pObject = App.CharacterClass_CreateNull()

		if (pCharacter):
			pCharacter.SetHidden(1)


###############################################################################
#	ViewscreenOn()
#	
#	A script action function which generically turns on the viewscreen to
#	look at a particular set. If we are in cutscene mode, Menu's drop and 
#	camera looks forward by default.
#	
#	Args:	pAction		 - the script action which called this
#			pcLookAtSet	 - the name of the set to look at
#			pcName		 - the name of the character to look at
#			fMinStatic	 - the minimum static value
#			fMaxStatic	 - the maximum static value
#			bDropAndLook - drop menus and look forward.
#			iPlaySound 	 - If == 1, play ViewOff sound
#	
#	Return:	none
###############################################################################
def ViewscreenOn(pAction, pcLookAtSet, pcName = None, fMinStatic = 0, fMaxStatic = 0, bDropAndLook = 0, idActionToComplete = App.NULL_ID):
#	print "MissionLib.ViewscreenOn() called."	
	pBridge = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pLookAtSet = App.g_kSetManager.GetSet(pcLookAtSet)
	pTop = App.TopWindow_GetTopWindow()

	if not (pLookAtSet):
#		debug("ViewScreenOn: No set (%s) to look at" % pcLookAtSet)
		return 0

	global g_bViewscreenOn

	# Set the bridge view screen
	if (pBridge):
		pViewScreen = pBridge.GetViewScreen()
		if (pViewScreen):
			pActionToComplete = App.TGAction_Cast( App.TGObject_GetTGObjectPtr( idActionToComplete ) )
			if (g_bViewscreenOn):
				# Okay.. the viewscreen is in use.. call waiting time
				if not (pAction):
					if pActionToComplete:
						# Ummm..
#						debug("ARGH, failure")
						pActionToComplete.Completed()
						return
					pActionToComplete = App.TGScriptAction_Create(__name__, "ViewscreenOn", pcLookAtSet, pcName, fMinStatic, fMaxStatic, bDropAndLook)
				if not (pActionToComplete):
					pActionToComplete = pAction

				pSequence = App.TGSequence_Create()
				idActionToComplete = App.NULL_ID
				if pActionToComplete:
					idActionToComplete = pActionToComplete.GetObjID()
				pSequence.AppendAction(App.TGScriptAction_Create(__name__, "ViewscreenOn", pcLookAtSet, pcName, fMinStatic, fMaxStatic, bDropAndLook, idActionToComplete), 2)
				pSequence.Play()
				return 1

			if (pActionToComplete):
				ViewscreenOn(pActionToComplete, pcLookAtSet, pcName, fMinStatic, fMaxStatic, bDropAndLook)
				return 0


		if (pcName):
			HideCharacters(pLookAtSet)		# Hide all the characters on the destination set

		pMainCamera = pLookAtSet.GetCamera("maincamera")
		pZoomCamera = App.ZoomCameraObjectClass_GetObject(pBridge, "maincamera")

		if bDropAndLook or pTop.IsCutsceneMode():
			pZoomCamera.LookForward()

			# Only drop menus if the player is on the bridge. Otherwise, this is a
			# major annoyance.
			if (pTop.IsBridgeVisible()):
				import BridgeHandlers
				BridgeHandlers.DropMenusTurnBack()

		if (pViewScreen):
			pViewScreen.SetRemoteCam(pMainCamera)
			pViewScreen.SetIsOn(1)

			# Check our static flag and turn it on if it's wanted
			if (fMaxStatic > 0):
				pViewScreen.SetStaticTextureIconGroup("View Screen Static")
				pViewScreen.SetStaticIsOn(1)
				pViewScreen.SetStaticVariation(fMinStatic, fMaxStatic)

		if (pcName):					# Only un-hide the one we want to see
			pCharacter = App.CharacterClass_GetObject(pLookAtSet, pcName)
			if (pCharacter):
				pCharacter.SetHidden(0)

		g_bViewscreenOn = 1

		# Disable Hail and Contact Starfleet menus
		CallWaiting(None, TRUE)

		pSoundAction = App.TGSoundAction_Create("ViewOn")

		if (pAction):
			# Create an event to tell the sequence that the script action completed when the sound does
			pEvent = App.TGObjPtrEvent_Create()
			pEvent.SetEventType(App.ET_ACTION_COMPLETED)
			pEvent.SetDestination(App.g_kTGActionManager)
			pEvent.SetObjPtr(pAction)

			pSoundAction.AddCompletedEvent(pEvent)

		pSoundAction.Play()

		return 1

	return 0


###############################################################################
#	ViewscreenOff(pAction)
#	
#	A script action function which generically turns the viewscreen off
#	
#	Args:	pAction	- the script action which called this
#			iPlaySound - If == 1, play ViewOff sound
#	
#	Return:	none
###############################################################################
def ViewscreenOff(pAction = None, iPlaySound = 1):
#	print "MissionLib.ViewscreenOff() called."

	if not g_bViewscreenOn:
		# Viewscreen isn't on, so do nothing
		return 0 

	# Change the camera back to the player ship camera.
	pGame = App.Game_GetCurrentGame()
	if not pGame:
		return 0

	pCamera = pGame.GetPlayerCamera()
	if not pCamera:
#		debug("ViewscreenOff: No player camera for %s.  Can't turn off viewscreen." % __name__)
		return 0

	#Reset the Viewscreen
	pBridge = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	if (pBridge):
		pViewScreen = pBridge.GetViewScreen()
		if (pViewScreen):
			pViewScreen.SetRemoteCam(pCamera)
			pViewScreen.SetIsOn(1)

			# If the static in on, turn it off
			if (pViewScreen.IsStaticOn()):
				pViewScreen.SetStaticIsOn(0)

	global g_bViewscreenOn
	g_bViewscreenOn = 0

	# Enable Hail and Contact Starfleet menus
	CallWaiting(None, FALSE)

	if iPlaySound:
		#Play the Viewscreen off sound
		pSoundAction = App.TGSoundAction_Create("ViewOff")
	
		if (pAction):
			# Create an event to tell the sequence that the script action completed when the sound does
			pEvent = App.TGObjPtrEvent_Create()
			pEvent.SetEventType(App.ET_ACTION_COMPLETED)
			pEvent.SetDestination(App.g_kTGActionManager)
			pEvent.SetObjPtr(pAction)
	
			pSoundAction.AddCompletedEvent(pEvent)
		pSoundAction.Play()

	return 0

def IsViewscreenOn():
	return g_bViewscreenOn

def SetViewscreenOn():
	global g_bViewscreenOn
	g_bViewscreenOn = 1

def ResetViewscreen():
	global g_bViewscreenOn
	g_bViewscreenOn = 0
	CallWaiting(None, 0)
	

###############################################################################
#	ViewscreenWatchObject
#	
#	Set the viewscreen to watch the given target.  This is handy for
#	setting the viewscreen to watch a particular ship or object in
#	the world.
#	If the viewscreen isn't using player ship camera, or if the player
#	isn't on the bridge set looking at the viewscreen, this will still
#	set the viewscreen to watch the object, but there won't be any
#	immediate visible effect.
#	
#	Args:	pObject	- The object to watch, presumably in the same set
#					  as the player's ship.
#	
#	Return:	1 on success, 0 on failure.
###############################################################################
def ViewscreenWatchObject(pObject):
	pGame = App.Game_GetCurrentGame()
	if pGame:
		pCamera = pGame.GetPlayerCamera()
		if pCamera:
			pViewscreenTargetMode = pCamera.GetNamedCameraMode("ViewscreenZoomTarget")
			if pViewscreenTargetMode:
				pViewscreenTargetMode.SetAttrIDObject("Target", pObject)
				pCamera.AddModeHierarchy("InvalidViewscreen", "ViewscreenZoomTarget")
				return 1
	return 0

################################################################################
#	ClearTarget(pAction = None)
#
#	Script action that clears the player's target.
#
#	Args:	None
#			
#	Return:	0	- Return 0, in case called from sequence.
################################################################################
def ClearTarget(pAction = None):
	pPlayer = GetPlayer()
	if pPlayer:
		pPlayer.SetTarget(None)
	
	return 0

###############################################################################
#	SetupSpaceSet()
#	
#	Creates and returns a specified space set
#	
#	Args:	pcSetName	- the name of the system to create
#	
#	Return:	pSet		- the created set
###############################################################################
def SetupSpaceSet(pcSetName):
	pModule = __import__(pcSetName)
	pModule.Initialize()
	return pModule.GetSet()


###############################################################################
#	SetupBridgeSet()
#	
#	Creates and returns a specified bridge set
#	
#	Args:	pcSetName		- the name of the set to create
#			pcModelName		- the name of the model to use
#			fX, fY, fZ		- X, Y, Z translation of the camera
#			fMX, fMY, fMZ	- Offset of the set
#	
#	Return:	pSet		- the newly created set
###############################################################################
def SetupBridgeSet(pcSetName, pcModelName, fX = -40, fY = 65, fZ = -1.55, fMX = 0, fMY = 0, fMZ = 0):
	pSet = App.g_kSetManager.GetSet(pcSetName)
	if (pSet):
		# Set already exists, just return it
		return pSet

	pSet = App.SetClass_Create()

	App.g_kSetManager.AddSet (pSet, pcSetName)

	#Create ambient light source
	pSet.CreateAmbientLight (1.0, 1.0, 1.0, 19.0, "ambientlight1")

	# Tell the set what background model to use
	pSet.SetBackgroundModel(pcModelName, 0.0, 0.0, 0.0)

	pNiCamera = App.g_kModelManager.CloneCamera(pcModelName)

	if (pNiCamera is None):
		pSet.SetBackgroundModel(pcModelName, fMX, fMY, fMZ)

		# Do special checks for the D and E bridges, we know what numbers we want for them...
		if (pcModelName == "data/Models/Sets/DBridge/DBridge.nif"):
			pCamera = App.CameraObjectClass_Create(0, 50, 47, -1.55, 0, 0, 1, "maincamera")
		elif (pcModelName == "data/Models/Sets/EBridge/EBridge.nif"):
			pCamera = App.CameraObjectClass_Create(0, 95, 64, -1.55, 0, 0, 1, "maincamera")
		else:
			pCamera = App.CameraObjectClass_Create(fX, fY, fZ, 0, 0, 0, 1, "maincamera")

		pSet.AddCameraToSet (pCamera, "maincamera")
		pCamera.SetNearAndFarDistance(1.0, 800.0)
	else:
		pCamera = App.CameraObjectClass_CreateFromNiCamera(pNiCamera, "maincamera")
		pSet.AddCameraToSet (pCamera, "maincamera")		
		kFrustum = pCamera.GetNiFrustum()
		kFrustum.m_fLeft   = kFrustum.m_fLeft *0.5
		kFrustum.m_fRight  = kFrustum.m_fRight *0.5
		kFrustum.m_fTop    = kFrustum.m_fTop *0.5
		kFrustum.m_fBottom = kFrustum.m_fBottom *0.5
		pCamera.SetNiFrustum(kFrustum)

	return pSet



###############################################################################
#	ReplaceBridgeTexture()
#	
#	Function to get a Bridge object model and replace a texture on it
#	
#	Args:	pAction			- in case this is called as a script action
#			pcSetName		- Name of set on which to perform replacement
#			pcOldTexture	- Texture to replace.  No path needed.
#			pcNewTexture	- New Texture.  Needs a path, minus the High/Medium/Low
#	
#	Return:	None
###############################################################################
def ReplaceBridgeTexture(pAction, pcSetName, pcOldTexture, pcNewTexture):
	pSet = App.g_kSetManager.GetSet(pcSetName)
	if (pSet == None):
		return 0

	pBridge = pSet.GetObject("BackgroundModel")
	pBridge = App.ObjectClass_Cast(pBridge)
	if (pBridge == None):
		return 0

	pBridge.ReplaceTexture(pcNewTexture, pcOldTexture)
	return 0


###############################################################################
#	SetupCharacter(pcCharacterPath, pcSetName, fX = 0, fY = 0, fZ = 0)
#	
#	Helper function which loads and sets up a character
#	
#	Args:	pcCharacterPath	- path of the character (ex Liu for Liu.py)
#			pcSetName		- name of the set to add the character to (set
#								must be created by this point)
#			fX, fY, fZ		- X, Y, Z translation of the character [IGNORED]
#	
#	Return:	pCharacter		- newly created character
###############################################################################
def SetupCharacter(pcCharacterPath, pcSetName, fX = 0, fY = 0, fZ = 0):
	pSet = App.g_kSetManager.GetSet(pcSetName)
	if not (pSet):
		return None

	pModule = __import__(pcCharacterPath)
	pCharacter = pModule.CreateCharacter(pSet)

	return pCharacter

###############################################################################
#	SetupExtra()
#	
#	Creates an extra on a bridge - will only do basic movements.
#	
#	Args:	pcBridge		- the bridge to appear on
#			pcName			- name of the extra
#			pcLocation		- where to put the extra
#			pcHeadNIF		- the .NIF file to use for their head
#			pcBodyNIF		- the .NIF file to use for their body
#			pcHeadTexture	- the .TGA file to use for their head
#			pcBodyTexture	- the .TGA file to use for their body
#	
#	Return:	pCharacter		- newly created character
###############################################################################
def SetupExtra(pcBridge, pcName, pcLocation, pcHeadNIF, pcBodyNIF, pcHeadTexture, pcBodyTexture):
	import Bridge.Characters.CharacterPaths
	Bridge.Characters.CharacterPaths.UpdatePaths()

	pSet = App.g_kSetManager.GetSet(pcBridge)
	if not (pSet):
		return None

	App.g_kModelManager.LoadModel(Bridge.Characters.CharacterPaths.g_pcBodyNIFPath + pcBodyNIF, "Bip01")
	App.g_kModelManager.LoadModel(Bridge.Characters.CharacterPaths.g_pcHeadNIFPath + pcHeadNIF, None)
	pCharacter = App.CharacterClass_Create(Bridge.Characters.CharacterPaths.g_pcBodyNIFPath + pcBodyNIF, Bridge.Characters.CharacterPaths.g_pcHeadNIFPath + pcHeadNIF)
	pCharacter.ReplaceBodyAndHead(Bridge.Characters.CharacterPaths.g_pcBodyTexPath + pcBodyTexture, Bridge.Characters.CharacterPaths.g_pcHeadTexPath + pcHeadTexture)

	pSet.AddObjectToSet(pCharacter, pcName)
	pLight = pSet.GetLight("ambientlight1")
	pLight.AddIlluminatedObject(pCharacter)

	pCharacter.SetRandomAnimationChance(.01)
	pCharacter.SetBlinkChance(0.1)

	import Bridge.Characters.Guest
	Bridge.Characters.Guest.ConfigureForGeneric(pCharacter)

	pCharacter.SetCharacterName(pcName)
	pCharacter.SetLocation(pcLocation)

	return pCharacter

###############################################################################
#	AddGoal(pcGoalStringID)
#	
#	Register goal with current episode.
#	
#	Args:	pcGoalStringID, string ID of goal to register.
#	
#	Return:	None
###############################################################################
def AddGoal(*pcGoalStringID):
	assert pcGoalStringID
	if(pcGoalStringID is None):
		return
	pGame = App.Game_GetCurrentGame()
	if(pGame is None):
		return
	pEpisode = pGame.GetCurrentEpisode()
	if(pEpisode is None):
		return
	for theGoal in pcGoalStringID:
		pEpisode.RegisterGoal(theGoal)

################################################################################
#	AddGoalAction(pTGAction, pcGoalStringID)
#
#	Script action that calls AddGoal().
#
#	Args:	pTGAction		- The script action object (passed in automatically)
#			pcGoalStringID	- String ID of goal to add.
#
#	Return:	0	- To keep calling sequence from tanking.
################################################################################
def AddGoalAction(pTGAction, pcGoalStringID):
	AddGoal(pcGoalStringID)
	return 0
	
###############################################################################
#	RemoveGoal(pcGoalStringID)
#	
#	Disables goal button
#	
#	Args:	pcGoalStringID, string ID of goal to remove.
#	
#	Return:	None
###############################################################################
def RemoveGoal(*pcGoalStringID):
	assert pcGoalStringID
	if(pcGoalStringID is None):
		return
	pBridge = App.g_kSetManager.GetSet("bridge")
	if(pBridge is None):
		return
	pSaffi = App.CharacterClass_GetObject (pBridge, "XO")
	if(pSaffi is None):
		return
	pSaffiMenu = pSaffi.GetMenu()
	if(pSaffiMenu is None):
		return
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pGoalMenu = pSaffiMenu.GetSubmenuW(pMenuDatabase.GetString("Objectives"))
	App.g_kLocalizationManager.Unload(pMenuDatabase)
	
	if(pGoalMenu is None):
		return
	pGame = App.Game_GetCurrentGame()
	if(pGame is None):
		return
	pEpisode = pGame.GetCurrentEpisode()
	if(pEpisode is None):
		return
	pEpisodeDatabase = pEpisode.GetDatabase()
	if(pEpisodeDatabase is None):
		return
	for theGoal in pcGoalStringID:
		pGoalButton = pGoalMenu.GetButtonW(pEpisodeDatabase.GetString(theGoal))
		if(pGoalButton is None):
			return
		pGoalButton.SetDisabled()

################################################################################
#	RemoveGoalAction(pTGAction, pcGoalStringID)
#
#	Script action that calls RemoveGoal().
#
#	Args:	pTGAction		- The script action object (passed in automatically)
#			pcGoalStringID	- String ID of goal to add.
#
#	Return:	0	- To keep calling sequence from tanking.
################################################################################
def RemoveGoalAction(pTGAction, pcGoalStringID):
	RemoveGoal(pcGoalStringID)
	return 0
	
###############################################################################
#	DeleteGoal(pcGoalStringID)
#	
#	Removes the goal button in the Objectives
#	
#	Args:	pcGoalStringID, string ID of goal to remove.
#	
#	Return:	None
###############################################################################
def DeleteGoal(*pcGoalStringID):
	assert pcGoalStringID
	if(pcGoalStringID is None):
		return
	pGame = App.Game_GetCurrentGame()
	if(pGame is None):
		return
	pEpisode = pGame.GetCurrentEpisode()
	if(pEpisode is None):
		return
	for theGoal in pcGoalStringID:
		pEpisode.RemoveGoal(theGoal)

###############################################################################
#	DeleteAllGoals()
#	
#	Removes all goal buttons in the Objectives menu
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def DeleteAllGoals():
	pBridge = App.g_kSetManager.GetSet("bridge")
	if(pBridge is None):
		return
	pSaffi = App.CharacterClass_GetObject (pBridge, "XO")
	if(pSaffi is None):
		return
	pSaffiMenu = pSaffi.GetMenu()
	if(pSaffiMenu is None):
		return
	pMenuDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pGoalMenu = pSaffiMenu.GetSubmenuW(pMenuDatabase.GetString("Objectives"))
	App.g_kLocalizationManager.Unload(pMenuDatabase)
	
	if(pGoalMenu is None):
		return
	pGoalMenu.KillChildren()

###############################################################################
#	GetCharacterSubmenu
#	
#	Get a submenu from one of the character menus.  Helm's "Set Course" menu,
#	for instance, or Tactical's "Orders" menu.
#	
#	Args:	sCharacter	- Which character to get the menu from.  (eg. "Science",
#						  "Helm", "Tactical", etc.)
#			sMenu		- Which submenu to get from that character's menu.
#						  (eg. "Set Course", "Orders", etc.)
#	
#	Return:	The requested submenu, or None
###############################################################################
def GetCharacterSubmenu(sCharacter, sMenu):
	pReturn = None

	# Load the Bridge Menus database, since sMenu refers to a string
	# in the database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")

	# Get the menu for the specified character.
	pTopWindow = App.TopWindow_GetTopWindow()
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	pMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString(sCharacter))

	if pMenu:
		# Get the requested menu from that character.
		pReturn = App.STMenu_Cast(pMenu.GetSubmenuW(pDatabase.GetString(sMenu)))

	# Done with the string database...
	App.g_kLocalizationManager.Unload(pDatabase)

	return pReturn


###############################################################################
#	GetCharacterButton
#	
#	Get a button from one of the character menus.  Helm's "Warp" button,
#	for instance.
#	
#	Args:	sCharacter	- Which character to get the button from.  (eg. "Science",
#						  "Helm", "Tactical", etc.)
#			sButton		- Which button to get from that character's menu.
#						  (eg. "Warp", etc.)
#	
#	Return:	The requested button, or None
###############################################################################
def GetCharacterButton(sCharacter, sButton):
	pButton = None

	pBridge = App.g_kSetManager.GetSet("bridge")
	if pBridge:
		pCharacter = App.CharacterClass_GetObject(pBridge, sCharacter)
		if pCharacter:
			pMenu = pCharacter.GetMenu()
			if (pMenu):
				pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
				pButton = pMenu.GetButtonW(pDatabase.GetString(sButton))
				App.g_kLocalizationManager.Unload(pDatabase)

	return pButton


###############################################################################
#	GetPositionOrientationFromProperty
#	
#	Get position and orientation values from the PositionOrientationProperty
#	with the given name, on the specified object.
#	
#	Args:	pObject			- The object to get the information from.
#			sPropertyName	- Name of the property whose position and
#							  orientation we're trying to retrieve.
#	
#	Return:	(vPosition, vForward, vUp), or (None, None, None)
###############################################################################
def GetPositionOrientationFromProperty(pObject, sPropertyName):
	pObject = App.DamageableObject_Cast(pObject)
	pPropSet = pObject.GetPropertySet()
	pInstanceList = pPropSet.GetPropertiesByType(App.CT_POSITION_ORIENTATION_PROPERTY)
	#debug("GetPositionOrientationFromProperty: Got %d properties" % pInstanceList.TGGetNumItems())

	pInstanceList.TGBeginIteration()
	for i in range(pInstanceList.TGGetNumItems()):
		pProperty = App.PositionOrientationProperty_Cast(pInstanceList.TGGetNext().GetProperty())

		# Check if this property has the name we're looking for.
		if pProperty  and  (not pProperty.GetName().CompareC(sPropertyName, 1)):
			# Yep.  Get its position, and Fwd/Up vectors.
			pInstanceList.TGDoneIterating()
			pInstanceList.TGDestroy()
			return (pProperty.GetPosition(), pProperty.GetForward(), pProperty.GetUp())

	pInstanceList.TGDoneIterating()
	pInstanceList.TGDestroy()
	return (None, None, None)

###############################################################################
#	SetPlayerAI
#	
#	Functions for setting AI to control the player's ship.
#	If the AI isn't None, it's given to the player's ship.  The
#	name of the controller is always saved.  It should be
#	either "Captain", None, or the name of one of the positions
#	that can control the ship ("Helm", "Tactical", etc.).
#	
#	Args:	pAI			- AI to give to the player's ship.
#			sController	- Name of the position controlling the ship.
#	
#	Return:	Name of the position controlling the ship.
###############################################################################
def SetPlayerAI(sController, pAI):
	# Save the name of whoever's controlling the ship now, whether
	# or not setting the AI is successful.
	global g_sPlayerShipController
	g_sPlayerShipController = sController

	# Give the AI to the player.
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		if pAI:
			pPlayer.SetAI(pAI)
		else:
			pPlayer.ClearAI()

	# If someone other than Tactical is controlling the ship
	# right now, clear Tactical's orders.
	if sController not in (None, "Tactical"):
		import Bridge.TacticalMenuHandlers
		Bridge.TacticalMenuHandlers.UpdateOrders(0)

def GetPlayerShipController():
	try:
		return g_sPlayerShipController
	except NameError:
		return None

###############################################################################
#	ClearAllAI()
#
#	Clear all AI's in the game.
#
#	Args:	None
#	
#	Return:	None
###############################################################################
def ClearAllAI(pAction = None):
	pPlayer = App.Game_GetCurrentPlayer()

	SetsTuple = App.g_kSetManager.GetAllSets()
	if SetsTuple:
		for pSet in SetsTuple:
			if pSet:
				ObjTuple = pSet.GetClassObjectList(App.CT_SHIP)
				if ObjTuple:
					for pShip in ObjTuple:
						if pShip:
							pShip.ClearAI()
							if (pPlayer):
								if (pPlayer.GetObjID () == pShip.GetObjID ()):	
									# Clear AI doesn't stop the ship, so we
									# explicitly stop the ship here.
									pPlayer.CompleteStop ()
	return 0

###############################################################################
#	GameOver()
#
#	End the game with a cutscene that has no end
#	
#	Args:	pAction	- The script action passed in
#			pSequence - The action(s) or sequence(s) that are passed in
#	
#	Return:	None
###############################################################################
def GameOver(pAction, *pSequence):
	if (g_bFFGameOver):
#		debug("We're already in a game over sequence... abort the new one")
		if len(pSequence):
			for theSequence in pSequence:
				theSequence.Abort()
		return 0

#	debug("MissionLib.GameOver() called.")
	
	# If the player is none or dying, bail
	pPlayer = GetPlayer()
	if (pPlayer == None) or (pPlayer.IsDying()):
		if len(pSequence):
			for theSequence in pSequence:
				theSequence.Abort()
		return 0
		
	ClearAllAI()

	pGameOverSequence = App.TGSequence_Create()
	
	pChangeToBridge = App.TGScriptAction_Create("Actions.MissionScriptActions", "ChangeToBridge")
	pGameOverSequence.AddAction(App.TGScriptAction_Create(__name__, "StartCutscene"))
	pGameOverSequence.AppendAction(pChangeToBridge)

	pSequenceDatabase = None

	if len(pSequence) is 0:
#		debug("No sequence/action parameters.  Using standard sequence")
		pSequenceDatabase = App.g_kLocalizationManager.Load("data/TGL/Maelstrom/Episode 7/E7m1.tgl")
		pSet =App.g_kSetManager.GetSet("bridge")		
		pSaffi = App.CharacterClass_GetObject (pSet, "XO")

		pGameOverAction1 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_LOOK_AT_ME)
		pGameOverAction2 = App.CharacterAction_Create(pSaffi, App.CharacterAction.AT_SAY_LINE, "E7M1FailedMission", "Captain", 0, pSequenceDatabase)
		pGameOverSequence.AddAction(pGameOverAction1, pChangeToBridge)
		pGameOverSequence.AddAction(pGameOverAction2, pGameOverAction1, 3)

	else:
#		debug("Using specified sequence(s)")
		for theSequence in pSequence:
			pGameOverSequence.AppendAction(theSequence)

	pGameOverSequence.AppendAction(App.TGScriptAction_Create("Actions.CameraScriptActions", "StartCinematicMode"))
	pGameOverSequence.AppendAction(App.TGScriptAction_Create(__name__, "FadeOut"))
	pGameOverSequence.AppendAction(App.TGScriptAction_Create(__name__, "ExitGame"))

	pGameOverSequence.Play()

	# Done with the string database (CharacterAction[AT_SAY_LINE] will keep a ref)
	if (pSequenceDatabase):
		App.g_kLocalizationManager.Unload(pSequenceDatabase)

	return 0

###############################################################################
#	ExitGame(pAction)
#	
#	Put up a screen saying "Game Over", and have a restart button
#	
#	Args:	pAction - Action from the cutscene sequence
#	
#	Return:	0 - Action completed
###############################################################################
def ExitGame(pAction = None):
	# Make sure we're in the game font
	# Because in 8.2, we play cutscenes and do credits and such
	import MainMenu.mainmenu
	MainMenu.mainmenu.SetupGameFont()

	global g_bViewscreenOn
	g_bViewscreenOn = 0

	global g_bFFGameOver
	g_bFFGameOver = 0

	pTop = App.TopWindow_GetTopWindow()
	if not (pTop):
#		debug("Unable to find TopWindow")
		return 0

	pCinematic = pTop.FindMainWindow(App.MWT_CINEMATIC)
	if not (pCinematic):
		return 0

	App.TopWindow_GetTopWindow().AbortCutscene()

#	debug("Exiting Game")

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.TGL")

	pWindow = App.STStylizedWindow_Create("StylizedWindow", "RightBorder", None)

	pPane = App.TGPane_Create(0.5, 0.5)
	pWindow.AddChild(pPane)
	pWindow.SetVisible()

	pParagraph = App.TGParagraph_CreateW(pDatabase.GetString("Game Over"), 0.45, None, "Serpentine", 12)

	pPane.AddChild(pParagraph, 0.25 - pParagraph.GetWidth()/2.0, 0.25 - pParagraph.GetHeight()/1.5)

	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pPane)
	pEvent.SetEventType(App.ET_LOAD_GAME)

	pButton = App.STButton_CreateW(pDatabase.GetString("Restart"), pEvent, App.STBSF_SIZE_TO_TEXT)
	pPane.AddChild(pButton, 0.25 - pButton.GetWidth()/2.0, 0.45 - 2.25*pButton.GetHeight())

	pEvent = App.TGEvent_Create()
	pEvent.SetDestination(pPane)
	pEvent.SetEventType(App.ET_CANCEL)

	pButton = App.STButton_CreateW(pDatabase.GetString("Quit to Main Menu"), pEvent, App.STBSF_SIZE_TO_TEXT)
	pPane.AddChild(pButton, 0.25 - pButton.GetWidth()/2.0, 0.45 - pButton.GetHeight())

	pPane.AddPythonFuncHandlerForInstance(App.ET_LOAD_GAME, __name__ + ".RestartGame")
	pPane.AddPythonFuncHandlerForInstance(App.ET_CANCEL, __name__ + ".ShutdownGame")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_NEW_GAME, pPane, __name__ + ".DestroyGameOverScreen")

	pParentPane = App.TGPane_Create(1.0, 1.0)
	pParentPane.AddChild(pWindow, 0.25, 0.25)
	pParentPane.SetFocus(pWindow)

	pCinematic.AddChild(pParentPane, 0.0, 0.0)
	pCinematic.MoveToFront(pParentPane)
	pCinematic.SetFocus(pParentPane)

	App.g_kUtopiaModule.Pause(1)

	pWindow.InteriorChangedSize()
	App.InterfaceModule_DoTheRightThing()

	App.g_kLocalizationManager.Unload(pDatabase)
	return 0



###############################################################################
#	RestartGame()
#	
#	Restart from our last save game
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def RestartGame(pObject, pEvent):
	pTop = App.TopWindow_GetTopWindow()
	if (pTop):
		pTop.AbortFade()

	pObject.CallNextHandler(pEvent)
#	debug("Restarting from last save")
	App.g_kUtopiaModule.LoadFromFile(None)

###############################################################################
#	ShutdownGame()
#	
#	Called by the Quit button on the Game Over screen, terminates the old game
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ShutdownGame(pObject, pEvent):
	pTop = App.TopWindow_GetTopWindow()
	if (pTop):
		pTop.AbortFade()

	pObject.CallNextHandler(pEvent)
	DestroyGameOverScreen(None, None)
	App.Game_GetCurrentGame().Terminate()


###############################################################################
#	DestroyGameOverScreen()
#	
#	Destroys the game over screen, since a new game is starting
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def DestroyGameOverScreen(pObject, pEvent):
	App.g_kUtopiaModule.Pause(0)

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

	pTop = App.TopWindow_GetTopWindow()
	if not (pTop):
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	pCinematic = pTop.FindMainWindow(App.MWT_CINEMATIC)
	iNumChildren = pCinematic.GetNumChildren()
	for i in range (iNumChildren):
		pChild = App.STStylizedWindow_Cast(pCinematic.GetNthChild(i))
		if (pChild):
			pCinematic.DeleteChild(pChild)
			if (pObject and pEvent):
				pObject.CallNextHandler(pEvent)
			return

###############################################################################
#	LookForward()
#	
#	Forces the camera to look forward
#	
#	Args:	pAction			- the action that called this function
#			bWaitForSweep	- If true, the action isn't done until the view
#							  sweep is done.  If false, the action is done immediately,
#							  and the sweep continues on its own..
#	
#	Return:	0
###############################################################################
def LookForward(pAction, bWaitForSweep = 0):
	pBridgeSet = App.g_kSetManager.GetSet("bridge")

	pMainCamera = App.ZoomCameraObjectClass_GetObject(pBridgeSet, "maincamera")
	if not (pMainCamera):
		return 0

	pMainCamera.LookForward()

	pTop = App.TopWindow_GetTopWindow()
	# Only drop menus if the player is on the bridge. Otherwise, this is a
	# major annoyance.
	if (pTop.IsBridgeVisible()):
		import BridgeHandlers
		BridgeHandlers.DropMenusTurnBack()

	if bWaitForSweep:
		# Sweep takes 1 second.  Hopefully this won't change.
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetEventType(App.ET_ACTION_COMPLETED)
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetObjPtr(pAction)

		pTimer = App.TGTimer_Create()
		pTimer.SetTimerStart(App.g_kUtopiaModule.GetGameTime() + 1.0)
		pTimer.SetEvent(pEvent)
		App.g_kTimerManager.AddTimer(pTimer)

		return 1
	return 0

###############################################################################
#	HideSubsystem(pSubsystem, kRecords)
#	
#	Hides a subsystem, if necessary, and adds it to the list of records
#	of subsystems that have been hidden.
#	
#	Args:	pSubsystem	- the subsystem to check
#			kRecords	- list containing subsystems that have been hidden
#	
#	Return:	none
###############################################################################
def HideSubsystem(pSubsystem, kRecords):
	pProp = pSubsystem.GetProperty()
	if (pProp.IsTargetable() == 1):
		kRecords.append(pSubsystem.GetObjID())
		pProp.SetTargetable(0)

	for i in range(pSubsystem.GetNumChildSubsystems()):
		pChild = pSubsystem.GetChildSubsystem(i)
		HideSubsystem(pChild, kRecords)

###############################################################################
#	HideSubsystems(pShip)
#	
#	Hides all subsystems on a ship.
#	
#	Args:	pShip	- the ship
#	
#	Return:	a list of records which should be passed in to ShowSubsystems(),
#			below, if you want to unhide these subsystems.
###############################################################################
def HideSubsystems(pShip):
	kIter = pShip.StartGetSubsystemMatch(App.CT_SHIP_SUBSYSTEM)
	pSubsystem = pShip.GetNextSubsystemMatch(kIter)

	kRecords = []

	while (pSubsystem != None):
		HideSubsystem(pSubsystem, kRecords)
		pSubsystem = pShip.GetNextSubsystemMatch(kIter)
		
	pShip.EndGetSubsystemMatch(kIter)

	pMenu = App.STTargetMenu_GetTargetMenu()
	if (pMenu != None):
		pMenu.RebuildShipMenu(pShip)

	return(kRecords)

###############################################################################
#	ShowSubsystems(kRecords)
#	
#	Un-hides subsystems hidden with HideSubsystems(), above.
#	
#	Args:	kRecords	- the return value of HideSubsystems().
#	
#	Return:	none
###############################################################################
def ShowSubsystems(kRecords):
	pShip = None
	for idSubsystem in kRecords:
		pSubsystem = App.ShipSubsystem_Cast(App.TGObject_GetTGObjectPtr(idSubsystem))
		if (pSubsystem != None):
			pShip = pSubsystem.GetParentShip()
			pProp = pSubsystem.GetProperty()
			pProp.SetTargetable(1)

	if (pShip != None):
		pMenu = App.STTargetMenu_GetTargetMenu()
		if (pMenu != None):
			pMenu.RebuildShipMenu(pShip)

###############################################################################
#	MakeSubsystemsInvincible(*kSubsystems)
#	MakeSubsystemsNotInvincible(*kSubsystems)
#	
#	Makes the specified subsystems invincible/not invincible to damage.
#	
#	Args:	kSubsystems	... - subsystems that will be affected
#	
#	Return:	none
###############################################################################
def MakeSubsystemsInvincible(*kSubsystems):
	for pSubsystem in kSubsystems:
		pSubsystem.SetInvincible(1)

		for i in range(pSubsystem.GetNumChildSubsystems()):
			pChild = pSubsystem.GetChildSubsystem(i)
			MakeSubsystemsInvincible(pChild)

def MakeSubsystemsNotInvincible(*kSubsystems):
	for pSubsystem in kSubsystems:
		pSubsystem.SetInvincible(0)
		
		for i in range(pSubsystem.GetNumChildSubsystems()):
			pChild = pSubsystem.GetChildSubsystem(i)
			MakeSubsystemsNotInvincible(pChild)

###############################################################################
#	MakeEnginesInvincible(pShip)
#	
#	Makes the warp and impulse subsystems invincible to damage.
#	
#	Args:	pShip, ship to act on.
#			bReverse, pass 1 to make engines not invincible
#
#	Return:	none
###############################################################################
def MakeEnginesInvincible(pShip, bReverse = 0):
	if pShip:
		pWarp = pShip.GetWarpEngineSubsystem()
		pImpulse = pShip.GetImpulseEngineSubsystem()
		if pWarp:
			if not bReverse:
				MakeSubsystemsInvincible(pWarp)

			else:
				MakeSubsystemsNotInvincible(pWarp)
		
		if pImpulse:
			if not bReverse:
				MakeSubsystemsInvincible(pImpulse)

			else:
				MakeSubsystemsNotInvincible(pImpulse)

###############################################################################
#	SetConditionPercentage(pSubsystem, fPercent, bIsChild)
#	
#	Sets the condition of a subsystem's children.
#	
#	Args:	pSubsystem	- the subsystem
#			fPercent	- the desired condition percentage
#			bIsChild	- whether or not to affect the given subsystem, or
#						  just its children.
#	
#	Return:	none
###############################################################################
def SetConditionPercentage(pSubsystem, fPercent, bIsChild = 0):
	if (bIsChild != 0) or (pSubsystem.GetNumChildSubsystems() == 0):
		pSubsystem.SetConditionPercentage(fPercent)

	for i in range(pSubsystem.GetNumChildSubsystems()):
		pChild = pSubsystem.GetChildSubsystem(i)

		if (pChild != None):
			SetConditionPercentage(pChild, fPercent, 1)

###############################################################################
#	IsBoosted(pSubsystem, fBoostLevel)
#	
#	Returns wether a Ship's subsystem is currently boosted above fBoostLevel.
#	fBoostLevel is an optional argument which defaults to 100%.
#	
#	Args:	pSubsystem - subsystem we are checking.
#			fBoostLevel - boost level to check against.
#	
#	Return:	1 if boosted, 0 if not boosted.
###############################################################################
def IsBoosted(pSubsystem, fBoostLevel = 1.0):
	assert pSubsystem
	if(pSubsystem):
		fPercent = pSubsystem.GetNormalPowerPercentage()
		if(fPercent > fBoostLevel):
			return 1
		else:
			return 0

###############################################################################
#	GetDistance(pObj1, pObj2 = None)
#	
#	Returns the distance between the two objects.
#	
#	Args:	pObj1, pObj2	- the objects
#	
#	Return:	float - the distance between the objects
###############################################################################
def GetDistance(pObj1, pObj2 = None):
	assert pObj1

	if pObj2 is None:
		pObj2 = GetPlayer()
		assert pObj2
	
	assert(repr(pObj1.GetContainingSet()) == repr(pObj2.GetContainingSet()))

	kLoc1 = pObj1.GetWorldLocation()
	kLoc2 = pObj2.GetWorldLocation()
	kLoc2.Subtract(kLoc1)

	return(kLoc2.Length())

###############################################################################
#	FindShuttleBay(iShipID)
#	
#	Returns a shuttle bay from the given ship.
#	
#	Args:	iShipID	- the ID of the ship to search
#	
#	Return:	ObjectEmitterProperty * - the shuttle bay property, or None
###############################################################################
def FindShuttleBay(iShipID):
	pShip = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), iShipID)

	# Find any object emitter properties on the ship.
	pPropSet = pShip.GetPropertySet()
	pEmitterInstanceList = pPropSet.GetPropertiesByType(App.CT_OBJECT_EMITTER_PROPERTY)

	pEmitterInstanceList.TGBeginIteration()
	iNumItems = pEmitterInstanceList.TGGetNumItems()

	pLaunchProperty = None

	for i in range(iNumItems):
		pInstance = pEmitterInstanceList.TGGetNext()

		# Check to see if the property for this instance is a shuttle
		# emitter point.
		pProperty = App.ObjectEmitterProperty_Cast(pInstance.GetProperty())
		if (pProperty != None):
			if (pProperty.GetEmittedObjectType() == App.ObjectEmitterProperty.OEP_SHUTTLE):
				pLaunchProperty = pProperty
				break

	pEmitterInstanceList.TGDoneIterating()
	pEmitterInstanceList.TGDestroy()

	return(pLaunchProperty)

###############################################################################
#	MoveToShuttleBay(iMovedObjectID, iShipID, fDistanceFrom)
#	
#	Moves the specified object to the ship's shuttle bay, and moves it out
#	from the shuttle bay the specified amount.
#	
#	Args:	iMovedObjectID	- the object to move
#			iShipID			- the ship to which we're moving the object
#	
#	Return:	none
###############################################################################
def MoveToShuttleBay(iMovedObjectID, iShipID):
	pObject = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), iMovedObjectID)
	pShip = App.ShipClass_GetObjectByID(App.SetClass_GetNull(), iShipID)

	pProperty = FindShuttleBay(iShipID)

	if (pProperty == None):
		return

	# Now change the position and facing of the object to match the emitter.
	kFwd = pProperty.GetForward()
	kFwd2 = pProperty.GetForward()
	kUp = pProperty.GetUp()

	kRotation = pShip.GetWorldRotation()

	kPosition = pProperty.GetPosition()
	kFwd.MultMatrixLeft(kRotation)
	kUp.MultMatrixLeft(kRotation)
	kFwd2.MultMatrixLeft(kRotation)
	kFwd2.Scale(5.0)

	kPosition.MultMatrixLeft(kRotation)
	kPosition.Add(pShip.GetWorldLocation())
	kPosition.Add(kFwd2)
	pObject.SetTranslate(kPosition)

	kFwd.MultMatrixLeft(kRotation)
	kUp.MultMatrixLeft(kRotation)
	pObject.AlignToVectors(kFwd, kUp)

###############################################################################
#	IdentifyObjects(*pList)
#	
#	Forcibly identifies the objects passed in.
#	
#	Args:	*pList	- the objects to be identified
#	
#	Return:	none
###############################################################################
def IdentifyObjects(*pList):
	pPlayer = GetPlayer()

	if (pPlayer == None):
		return
	pSensors = pPlayer.GetSensorSubsystem()
	if (pSensors == None):
		return

	for pObject in pList:
		pSensors.ForceObjectIdentified(pObject)
	
###############################################################################
#	CallFunctionWhenConditionChanges
#	
#	Setup stuff to call the specified function whenever the given
#	condition changes.  The function is called with 1 argument: the
#	new state of the condition (1 for true, 0 for false... -1 if there
#	was an error).
#	
#	Args:	pMission	- The mission object.
#			sModule		- Name of the module that has the function (eg. Maelstrom.Episode1.E1M1.E1M1)
#			sFunction	- Name of the function to call (eg. "AsteroidProximityChanged")
#	
#	Return:	None
###############################################################################
g_dConditionEventTriggers = {}
def CallFunctionWhenConditionChanges(pMission, sModule, sFunction, pCondition):
	if (pMission == None):
		return 0

	global g_dConditionEventTriggers

	pConditionEventTrigger = App.ConditionEventCreator()
	if not g_dConditionEventTriggers.has_key(pMission.GetObjID()):
		g_dConditionEventTriggers[ pMission.GetObjID() ] = []
	g_dConditionEventTriggers[ pMission.GetObjID() ].append( (pConditionEventTrigger, sModule, sFunction) )

	pEvent = App.TGStringEvent_Create()
	eEventType = App.Game_GetNextEventType()
	pEvent.SetEventType( eEventType )
	pEvent.SetSource( pCondition )
	pEvent.SetDestination( pMission )
	pEvent.SetString( sModule + "*" + sFunction )

	pConditionEventTrigger.SetEvent(pEvent)

	pConditionEventTrigger.AddCondition( pCondition )

	# Setup the event handler for the event that's triggered.
	pMission.AddPythonFuncHandlerForInstance(eEventType, __name__ + ".ConditionChangedRedirect")

	# Listen for when the Mission object goes away, so we can delete the pConditionEventTrigger object.
	pMission.AddPythonFuncHandlerForInstance( App.ET_DELETE_OBJECT_PUBLIC, __name__ + ".MissionDeleted" )

###############################################################################
#	StopCallingFunctionWhenConditionChanges
#	
#	Stop calling a function that was setup with CallFunctinWhenConditionChanges.
#	If multiple calls to CallFunctionWhenConditionChanges were made with the
#	same function name, this removes all of them.
#	
#	Args:	sModule		- Name of the module that has the function.
#			sFunction	- Name of the function being called.
#	
#	Return:	None
###############################################################################
def StopCallingFunctionWhenConditionChanges(sModule, sFunction):
	global g_dConditionEventTriggers

	pMission = GetMission()
	if not pMission:
		return

	try:
		lHandlers = g_dConditionEventTriggers[ pMission.GetObjID() ]
	except KeyError:
		return

	# Look through all the handlers attached to this mission and
	# remove the ones that call the given function.
	for lEntry in lHandlers[:]:
		pTrigger, sExistingModule, sExistingFunction = lEntry
		if sExistingModule == sModule  and  sExistingFunction == sFunction:
			# Remove this handler.
			lHandlers.remove(lEntry)

	# If lHandlers is now empty, remove this entry from the dictionary.
	if not lHandlers:
		del g_dConditionEventTriggers[ pMission.GetObjID() ]

#
# ConditionChangedRedirect
#
# Helper function for CallFunctionWhenConditionChanges()
#
def ConditionChangedRedirect(pMission, pEvent):
	if (pMission == None):
		return 0

	# Get the status of the condition.
	pCondition = App.TGCondition_Cast(pEvent.GetSource())
	if pCondition:
		bStatus = pCondition.GetStatus()

		# Get the name of the module and function we're redirecting to.
		sModuleAndFunction = pEvent.GetCString()
		import strop
		sModule, sFunction = strop.split(sModuleAndFunction, "*")

		# Import the module and call the function with the status as the argument.
		pModule = __import__(sModule)
		pFunction = getattr(pModule, sFunction)
		pFunction(bStatus)

	# No CallNextHandler.  We're the only handler for this event type.

#
# MissionDeleted
#
# Helper function for CallFunctionWhenConditionChanges()
#
def MissionDeleted(pMission, pEvent):
	try:
		del g_dConditionEventTriggers[ pMission.GetObjID() ]
	except:
		pass

	pMission.CallNextHandler(pEvent)

###############################################################################
#	GetSystemOrRegionMenu(pcSystem, pcRegion = None)
#	
#	Returns the helm menu associated with the given system and region.
#	
#	Args:	pcSystem	- the system to search for
#			pcRegion	- the region to search for, if any
#	
#	Return:	the menu, None if not found
###############################################################################
def GetSystemOrRegionMenu(pcSystem, pcRegion = None):
	# Get the warp menu
	import Bridge.BridgeUtils
	pKiska = Bridge.BridgeUtils.GetBridgeCharacter("Helm")
	assert pKiska
	if(pKiska is None):
		return None
	pMenu = pKiska.GetMenu()
	assert pMenu
	if(pMenu is None):
		return None
	
	# Get the set course menu.
	# This menu is localized so load/unload database.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	assert pDatabase
	if(pDatabase is None):
		return None
	pSetCourseMenu = pMenu.GetSubmenuW(pDatabase.GetString("Set Course"))
	App.g_kLocalizationManager.Unload(pDatabase)
	
	assert pSetCourseMenu
	if(pSetCourseMenu is None):
		return None
	
	# Get system menu.
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Systems.tgl")
	pSystem = pSetCourseMenu.GetSubmenuW(pDatabase.GetString (pcSystem))
	assert pSystem
	if(pSystem is None):
		App.g_kLocalizationManager.Unload(pDatabase)
		return None
	
	# Get region button if any.
	pMenu = None
	if(pcRegion):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Systems.tgl")
		pMenu = App.SortedRegionMenu_Cast(pSystem.GetSubmenuW(pDatabase.GetString (pcRegion)))
		assert pMenu
		if(pMenu is None):
			App.g_kLocalizationManager.Unload(pDatabase)
			return None
	# Just use the system menu.
	else:
		pMenu = App.SortedRegionMenu_Cast(pSystem)
		assert pMenu
		if(pMenu is None):
			App.g_kLocalizationManager.Unload(pDatabase)
			return None

	App.g_kLocalizationManager.Unload(pDatabase)

	return pMenu

################################################################################
#	LinkMenuToPlacement()
#
#	Links one of the helm menu buttons to a placement other than the default
#	"Player Start". If pcRegion is None, will set placement for the system.
#
#	Args:	pcSystem, system menu name
#			pcRegion, region button name
#			pcPlacementName, name of placement to link to.
#
#	Return:	None
################################################################################
def LinkMenuToPlacement(pcSystem, pcRegion, pcPlacementName):
	assert pcSystem
	assert pcPlacementName
	
	pMenu = GetSystemOrRegionMenu(pcSystem, pcRegion)

	if (pMenu != None):
		# Set the placement that this system will be linked to.
		pMenu.SetPlacementName(pcPlacementName)

################################################################################
#	Cloak(pAction, pShip, bInstantly = FALSE)
#
#	Cloaks the ship.
#
#	Args:	pAction		- the action.
#			pShip		- ship to cloak.
#			bInstantly	- optional instant cloak flag. Defaults to FALSE.
#
#	Return:	None
################################################################################
def Cloak(pAction, pShip, bInstantly = FALSE):
	assert pShip
	if(pShip):
		pCloakingSys = pShip.GetCloakingSubsystem()
		if(pCloakingSys):
			if (bInstantly == TRUE):
				pCloakingSys.InstantCloak()
			else:
				pCloakingSys.StartCloaking()
			
	return 0

################################################################################
#	DeCloak(pAction, pShip, bInstantly = FALSE)
#
#	Decloaks the ship.
#
#	Args:	pAction		- the action.
#			pShip		- ship to decloak.
#			bInstantly	- optional instant decloak flag. Defaults to FALSE.
#
#	Return:	None
################################################################################
def DeCloak(pAction, pShip, bInstantly = FALSE):
	assert pShip
	if(pShip):
		pCloakingSys = pShip.GetCloakingSubsystem()
		if(pCloakingSys):
			if (bInstantly == TRUE):
				pCloakingSys.InstantDecloak()
			else:
				pCloakingSys.StopCloaking()
			
	return 0

###############################################################################
#	RemoveBridgeCharacterMenus()
#	
#	Removes menus from bridge characters (useful on shutdown)
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def RemoveBridgeCharacterMenus():
	pSet = App.g_kSetManager.GetSet("bridge")
	if not (pSet):
		# No bridge, we bail
		return

	pTactical = App.CharacterClass_GetObject(pSet, "Tactical")
	if (pTactical):
		pMenu = pTactical.GetMenu()
		if (pMenu):
			Bridge.TacticalCharacterHandlers.DetachMenuFromTactical(pTactical)

	pHelm = App.CharacterClass_GetObject(pSet, "Helm")
	if (pHelm):
		pMenu = pHelm.GetMenu()
		if (pMenu):
			Bridge.HelmCharacterHandlers.DetachMenuFromHelm(pHelm)

	pCommander = App.CharacterClass_GetObject(pSet, "XO")
	if (pCommander):
		pMenu = pCommander.GetMenu()
		if (pMenu):
			Bridge.XOCharacterHandlers.DetachMenuFromXO(pCommander)

	pScience = App.CharacterClass_GetObject(pSet, "Science")
	if (pScience):
		pMenu = pScience.GetMenu()
		if (pMenu):
			Bridge.ScienceCharacterHandlers.DetachMenuFromScience(pScience)

	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if (pEngineer):
		pMenu = pEngineer.GetMenu()
		if (pMenu):
			Bridge.EngineerCharacterHandlers.DetachMenuFromEngineer(pEngineer)

###############################################################################
#	GetSubsystemByName(pShip, pcSubsystemName)
#	
#	Returns the subsystem with the given name.
#	
#	Args:	pShip			- the ship
#			pcSubsystemName	- the name of the subsystem to look for
#	
#	Return:	ShipSubsystem * - the subsystem, or None if not found
###############################################################################
def GetSubsystemByName(pShip, pcSubsystemName):
	if (pShip == None):
		return None

	kIterator = pShip.StartGetSubsystemMatch(App.CT_SHIP_SUBSYSTEM)
	while (1):
		pSubsystem = pShip.GetNextSubsystemMatch(kIterator)

		if (pSubsystem == None):
			pShip.EndGetSubsystemMatch(kIterator)
			return(None)

		if (pSubsystem.GetName() == pcSubsystemName):
			pShip.EndGetSubsystemMatch(kIterator)
			return(pSubsystem)

		for i in range(pSubsystem.GetNumChildSubsystems()):
			pChild = pSubsystem.GetChildSubsystem(i)

			if (pChild != None) and (pChild.GetName() == pcSubsystemName):
				pShip.EndGetSubsystemMatch(kIterator)
				return(pChild)
		
	pShip.EndGetSubsystemMatch(kIterator)
	return(None)

###############################################################################
#	SaveGame()
#	
#	Saves your game (used automatically by missions)
#	
#	Args:	pcGameName	- name of the game to append to the Captain's name
#	
#	Return:	none
###############################################################################
def SaveGame(pcGameName):
	pGame = App.Game_GetCurrentGame()
	if not (pGame):
		return

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Options.tgl")
	
	iDifficulty = App.Game_GetDifficulty()
	if (iDifficulty == 0):
		kString = pDatabase.GetString("First Officer Save")
	if (iDifficulty == 1):
		kString = pDatabase.GetString("Captain Save")
	if (iDifficulty == 2):
		kString = pDatabase.GetString("Admiral Save")
	pcTrueName = "saves//" + kString.GetCString() + "-" + pcGameName + App.g_kUtopiaModule.GetCaptainName().GetCString() + ".BCS"

	App.g_kLocalizationManager.Unload(pDatabase)

	App.g_kUtopiaModule.SaveToFile(pcTrueName)

################################################################################
#	RedAlert(pAction = None)
#
#	Set player to Red Alert.
#
#	Args:	pAction
#
#	Return:	0
################################################################################
def RedAlert(pAction = None):
	pPlayer = GetPlayer()
	if(pPlayer is None):
		return 0

	# Create event to set Red Alert.
	pSeq = App.TGSequence_Create()
	pAlertEvent = App.TGIntEvent_Create()
	pAlertEvent.SetDestination(pPlayer)
	pAlertEvent.SetEventType(App.ET_SET_ALERT_LEVEL)
	pAlertEvent.SetInt(pPlayer.RED_ALERT)
	App.g_kEventManager.AddEvent(pAlertEvent)

	pSequence = App.TGSequence_Create()

	pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")
	if (pXO):
		pDatabase = pXO.GetDatabase()

		pShields = pPlayer.GetShields()
	
		if not pShields.IsOn():
			# "Red Alert, shields up"
			pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "RedAlert", None, 0, pDatabase))

		else:
			# "Red Alert"
			pSeq.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "RedAlert2", None, 0, pDatabase))

	# Add Red Alert sound.
	pSeq.AppendAction(App.TGSoundAction_Create("RedAlertSound"))

	pSeq.Play()

	return 0


################################################################################
#	MoveMouseCursorToUIObject()
#
#	Move the mouse cursor to the center of a UIObject
#
#	Args:	TGUIObject	pObject	- object to which to move
#			float		fTime	- time in secondsto complete move (default .5)
#
#	Return:	None
################################################################################
def MoveMouseCursorToUIObject(pObject, fTime = 0.5):
	kOffset = App.NiPoint2(0,0)
	pObject.GetScreenOffset(kOffset)
	fX = kOffset.x + (pObject.GetWidth() / 2)
	fY = kOffset.y + (pObject.GetHeight() / 2)
	App.g_kInputManager.MoveMouseCursorTo(fX, fY, fTime)


################################################################################
#	MoveMouseCursorToUIObjectTop()
#
#	Move the mouse cursor to the top center of a UIObject
#
#	Args:	TGUIObject	pObject	- object to which to move
#			float		fTime	- time in secondsto complete move (default .5)
#
#	Return:	None
################################################################################
def MoveMouseCursorToUIObjectTop(pObject, fTime = 0.5):
	kOffset = App.NiPoint2(0,0)
	pObject.GetScreenOffset(kOffset)
	fX = kOffset.x + (pObject.GetWidth() / 2)
	fY = kOffset.y
	App.g_kInputManager.MoveMouseCursorTo(fX, fY, fTime)


###############################################################################
#	DetachCrewMenus()
#	
#	Detaches all menus and handlers from the default crew members.  Good for
#	changing ships.
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def DetachCrewMenus():
	pSet = App.g_kSetManager.GetSet("bridge")
	if not (pSet):
		# No bridge, no crew, no work
		return

	import Bridge.EngineerCharacterHandlers
	pEngineer = App.CharacterClass_GetObject(pSet, "Engineer")
	if (pEngineer):
		Bridge.EngineerCharacterHandlers.DetachMenuFromEngineer(pEngineer)

	import Bridge.ScienceCharacterHandlers
	pScience = App.CharacterClass_GetObject(pSet, "Science")
	if (pScience):
		Bridge.ScienceCharacterHandlers.DetachMenuFromScience(pScience)

	import Bridge.XOCharacterHandlers
	pXO = App.CharacterClass_GetObject(pSet, "XO")
	if (pXO):
		Bridge.XOCharacterHandlers.DetachMenuFromXO(pXO)

	import Bridge.TacticalCharacterHandlers
	pTactical = App.CharacterClass_GetObject(pSet, "Tactical")
	if (pTactical):
		Bridge.TacticalCharacterHandlers.DetachMenuFromTactical(pTactical)

	import Bridge.HelmCharacterHandlers
	pHelm = App.CharacterClass_GetObject(pSet, "Helm")
	if (pHelm):
		Bridge.HelmCharacterHandlers.DetachMenuFromHelm(pHelm)

###############################################################################
#	SetMaxTorpsForPlayer()
#	
#	This is a helper function for the Mission Builders to tell Starbase 12
#	how many of a particular type of torpedo the player is allowed to carry
#	at a particular time.
#	
#	Args:	pcTorpName	- name of the torp type we care about
#			iNumTorps	- number of torps player can have
#			bLoadTorps	- to load the torps or not (usually only done 
#													at Episode start)
#	
#	Return:	none
###############################################################################
def SetMaxTorpsForPlayer(pcTorpName, iNumTorps, bLoadTorps = 0):
	pShip = GetPlayer()
	if not (pShip):
		return

	pTorpSys = pShip.GetTorpedoSystem()
	if(pTorpSys):
		# Find proper torps..
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			pTorpType = pTorpSys.GetAmmoType(iType)
			if (iNumTorps == -1):
				iNumTorps = pTorpType.GetMaxTorpedoes()

			if (pTorpType.GetAmmoName() == pcTorpName):
				App.g_kUtopiaModule.SetMaxTorpedoLoad(iType, iNumTorps)
				if (bLoadTorps != 0):
					pTorpSys.LoadAmmoType(iType, iNumTorps)
				return

###############################################################################
#	SetTotalTorpsAtStarbase()
#	
#	This is a helper function for the Mission Builders to tell Starbase 12
#	how many of a particular type of torpedo it currently holds.
#	
#	Args:	pcTorpName	- name of the torp type we care about
#			iNumTorps	- number of torps the starbase will carry
#	
#	Return:	none
###############################################################################
def SetTotalTorpsAtStarbase(pcTorpName, iNumTorps):
	pShip = GetPlayer()
	if not (pShip):
		return

	pTorpSys = pShip.GetTorpedoSystem()
	if(pTorpSys):
		# Find proper torps..
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			pTorpType = pTorpSys.GetAmmoType(iType)

			if (pTorpType.GetAmmoName() == pcTorpName):
				App.g_kUtopiaModule.SetCurrentStarbaseTorpedoLoad(iType, iNumTorps)
				return


###############################################################################
#	LoadTorpedoes()
#	
#	Load iLoad torpedoes of type pcName on to the Player's ship
#	
#	Args:	pAction	- script action that called this
#			pcName	- name of torpedo to load
#			iLoad	- number of torps to load
#	
#	Return:	0		- complete immediately
###############################################################################
def LoadTorpedoes(pAction, pcName, iLoad):
	pShip = GetPlayer()
	if not (pShip):
		return 0

	pTorpSys = pShip.GetTorpedoSystem()
	if(pTorpSys):
		# Find proper torps..
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			pTorpType = pTorpSys.GetAmmoType(iType)

			if (pTorpType.GetAmmoName() == pcName):
				pTorpSys.LoadAmmoType(iType, iLoad)
	return 0

###############################################################################
#	IsFullyLoaded(pShip = GetPlayer())
#	
#	Determine wether ship has full complement of torpedoes on board.
#	If no ship is passed, check's the player's ship.
#	
#	Args:	pShip	- ship to check, default arg.
#	
#	Return:	bool	- TRUE if it is, FALSE if it ain't.
###############################################################################
def IsFullyLoaded(pShip = None):
	if pShip is None:
		pShip = GetPlayer()
	if(pShip is None):
		return FALSE

	pTorpSys = pShip.GetTorpedoSystem()
	if(pTorpSys):
		# Check all torp types.
		iNumTypes = pTorpSys.GetNumAmmoTypes()
		for iType in range(iNumTypes):
			pTorpType = pTorpSys.GetAmmoType(iType)
			if pTorpSys.GetNumAvailableTorpsToType(iType) != pTorpType.GetMaxTorpedoes():
				return FALSE
		return TRUE
	return FALSE

###############################################################################
#	TextBanner()
#	
#	Put up a text banner, using a TGString as a source
#	
#	Args:	pAction		- Action that called us, if this is a TGScriptAction call
#			fX, fY		- position of the banner
#			iSize		- font size
#			fDuration	- time the banner lasts
#			bHCentered	- to center horizontally or not
#			bVCentered	- to center vertically or not
#	
#	Return:	0 to indicate to return now
###############################################################################
def TextBanner(pAction, kTextString, fX, fY, fDuration = 3.0, iSize = 16, 
				bHCentered = 1, bVCentered = 0):
#	debug("Doing TextBanner " + kTextString.GetCString())

	App.TGCreditAction_SetDefaultColor(0.65, 0.65, 1.0, 1.0)

	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = pTop.FindMainWindow(App.MWT_SUBTITLE)
	pSubtitle.SetVisible()
	
	if (bHCentered):
		iJustifyX = App.TGCreditAction.JUSTIFY_CENTER
	else:
		iJustifyX = App.TGCreditAction.JUSTIFY_LEFT

	if (bVCentered):
		iJustifyY = App.TGCreditAction.JUSTIFY_CENTER
	else:
		iJustifyY = App.TGCreditAction.JUSTIFY_TOP

	pTextBanner = App.TGCreditAction_Create(kTextString, pSubtitle,
						fX, fY, fDuration, 0.25, 0.5, iSize, iJustifyX, iJustifyY)
	pTextBanner.Play()

	return 0

###############################################################################
#	ShowLoadingText()
#	
#	Shows "Loading" on screen, to indicate progress
#	
#	Args:	pAction - the action that called us
#	
#	Return:	0
###############################################################################
def ShowLoadingText(pAction):
	LookForward(None)
	pViewscreen = GetViewScreen()
	if (pViewscreen):
		pViewscreen.SetOffTexture("data/Icons/ViewscreenLoading.tga")
		pViewscreen.SetIsOn(0)
		pViewscreen.SetStaticIsOn(0)


	# Add a handler to remove the screen when the mission is done loading
	pGame = App.Game_GetCurrentGame()
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_MISSION_START, pGame,	__name__ + ".EndLoadingText")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_MISSION_START, pGame, __name__ + ".EndLoadingText")

	return 0


###############################################################################
#	EndLoadingText()
#	
#	Stops the "Loading" on screen, for when the mission is loaded
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def EndLoadingText(pObject, pEvent):
	pViewscreen = GetViewScreen()
	if (pViewscreen):
		pViewscreen.SetIsOn(1)

	pGame = App.Game_GetCurrentGame()
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_MISSION_START, pGame,	__name__ + ".EndLoadingText")

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	ShowLargeLoadingScreen(pAction)
#	
#	Shows a full-screen loading screen.
#	
#	Args:	pAction	- the action
#	
#	Return:	zero for end
###############################################################################
def ShowLargeLoadingScreen(pAction):
	# Shows a large loading screen.
	# Check if it's already up.
	global g_idLargeLoadingScreen
	pScreen = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idLargeLoadingScreen))
	if (pScreen != None):
		return 0	# already up

	# Create the loading screen.
	pScreen = App.TGPane_Create(1.0, 1.0)
	
	pIcon1 = App.TGIcon_Create("SplashScreen", 1)
	pIcon2 = App.TGIcon_Create("SplashScreen", 2)
	pIcon3 = App.TGIcon_Create("SplashScreen", 3)
	pIcon4 = App.TGIcon_Create("SplashScreen", 4)

	pIcon1.Resize(0.5, 0.5, 0)
	pIcon2.Resize(0.5, 0.5, 0)
	pIcon3.Resize(0.5, 0.5, 0)
	pIcon4.Resize(0.5, 0.5, 0)

	pScreen.AddChild(pIcon1, 0.0, 0.0, 0)
	pScreen.AddChild(pIcon2, 0.5, 0.0, 0)
	pScreen.AddChild(pIcon3, 0.0, 0.5, 0)
	pScreen.AddChild(pIcon4, 0.5, 0.5, 0)
	pScreen.Resize(1.0, 1.0, 0)

	# Attach it to the root pane.
	App.g_kRootWindow.PrependChild(pScreen, 0.0, 0.0)
	g_idLargeLoadingScreen = pScreen.GetObjID()

	return 0

###############################################################################
#	HideLargeLoadingScreen(pAction)
#	
#	Hides the full-screen loading screen.
#	
#	Args:	pAction	- the action
#	
#	Return:	zero for end
###############################################################################
def HideLargeLoadingScreen(pAction):
#	debug("HideLargeLoadingScreen(): entered")
	# Hides the large loading screen.
	global g_idLargeLoadingScreen
	pScreen = App.TGPane_Cast(App.TGObject_GetTGObjectPtr(g_idLargeLoadingScreen))
	if (pScreen != None):
#		debug("HideLargeLoadingScreen(): Found screen")
		if (pScreen.GetParent() != None):
#			debug("HideLargeLoadingScreen(): removing screen")
			pScreen.GetParent().DeleteChild(pScreen)

	g_idLargeLoadingScreen = App.NULL_ID
	return 0

###############################################################################
#	FireTorpFromPlacement(pAction, pcPlacementName, 
#						  pcTorpScriptName, idTarget = App.NULL_ID, 
#						  idTargetSubsystem = App.NULL_ID, fSpeed = 0.0,
#						  pcSetName = None)
#	
#	Fires a torpedo from the specified placement.
#	
#	Args:	pAction				- the action, if called as a script action
#			pcPlacementName		- the name of the placement to use
#			idTarget			- ID of the target
#			idTargetSubsystem	- ID of the target subsystem, if any
#			fSpeed				- overrides normal launch speed of torpedo,
#								  if specified
#			pcSetName			- the name of the set to use
#	
#	Return:	0 for end
###############################################################################
def FireTorpFromPlacement(pAction, pcPlacementName, 
						  pcTorpScriptName, idTarget = App.NULL_ID, 
						  idTargetSubsystem = App.NULL_ID, fSpeed = 0.0, 
						  pcSetName = None):
	pTarget = App.ObjectClass_GetObjectByID(App.SetClass_GetNull(), idTarget)

	if (pcSetName != None):
		pSet = App.g_kSetManager.GetSet(pcSetName)
	elif (pTarget != None):
		pSet = pTarget.GetContainingSet()
	else:
		# No idea what set this is supposed to be in.
		return 0

	if (pSet == None):
		# No set.
		return 0

	# Create the torpedo.
	kPoint = App.TGPoint3()
	kPoint.SetXYZ(0.0, 0.0, 0.0)
	pTorp = App.Torpedo_Create(pcTorpScriptName, kPoint)
	pTorp.UpdateNodeOnly()

	# Set up its target and target subsystem, if necessary.
	pTorp.SetTarget(idTarget)

	if (idTargetSubsystem != App.NULL_ID):
		pSubsystem = App.ShipSubsystem_Cast(App.TGObject_GetTGObjectPtr(idTargetSubsystem))
		if (pSubsystem != None):
			pTorp.SetTargetOffset(pSubsystem.GetPosition())
		else:
			pTorp.SetTargetOffset(kPoint)
	else:
		pTorp.SetTargetOffset(kPoint)

	# No parent for the torpedo.
	pTorp.SetParent(App.NULL_ID)

	# Add the torpedo to the set, and place it at the specified placement.
	pSet.AddObjectToSet(pTorp, None)
	pTorp.PlaceObjectByName(pcPlacementName)

	pTorp.UpdateNodeOnly()

	# If there was a target, then orient the torpedo towards it.
	if (pTarget != None):
		kTorpLocation = pTorp.GetWorldLocation()
		kTargetLocation = pTarget.GetWorldLocation()

		kTargetLocation.Subtract(kTorpLocation)
		kFwd = kTargetLocation
		kFwd.Unitize()
		kPerp = kFwd.Perpendicular()
		kPerp2 = App.TGPoint3()
		kPerp2.SetXYZ(kPerp.x, kPerp.y, kPerp.z)

		pTorp.AlignToVectors(kFwd, kPerp2)
		pTorp.UpdateNodeOnly()

	# Give the torpedo an appropriate speed.
	kVelocity = pTorp.GetWorldForwardTG()
	if (fSpeed == 0.0):
		kVelocity.Scale(pTorp.GetLaunchSpeed())
	else:
		kVelocity.Scale(fSpeed)

	pTorp.SetVelocity(kVelocity)

	# Play the torpedo firing sound
	pcLaunchSound = pTorp.GetLaunchSound()
	if pcLaunchSound != None:
		pSound = App.g_kSoundManager.GetSound(pcLaunchSound)
		if pSound != None:
			pSound.AttachToNode(pTorp.GetNode())

			# Associate this sound with the sound region for the set we're in.
			pSoundRegion = App.TGSoundRegion_GetRegion(pSet.GetName())
			if pSoundRegion != None:
				pSoundRegion.AddSound(pSound)

			pSound.Play()

	return 0

###############################################################################
#	FireTorpFromPoint(pAction, kPoint, 
#					  pcTorpScriptName, idTarget = App.NULL_ID, 
#					  idTargetSubsystem = App.NULL_ID, fSpeed = 0.0,
#					  pcSetName = None)
#	
#	Fires a torpedo from the specified placement.
#	
#	Args:	pAction				- the action, if called as a script action
#			kPoint				- the point, in world space, from which to shoot
#			idTarget			- ID of the target
#			idTargetSubsystem	- ID of the target subsystem, if any
#			fSpeed				- overrides normal launch speed of torpedo,
#								  if specified
#			pcSetName			- the name of the set to use
#	
#	Return:	0 for end
###############################################################################
def FireTorpFromPoint(pAction, kPoint, 
					  pcTorpScriptName, idTarget = App.NULL_ID, 
					  idTargetSubsystem = App.NULL_ID, fSpeed = 0.0, 
					  pcSetName = None):
	pTarget = App.ObjectClass_GetObjectByID(App.SetClass_GetNull(), idTarget)

	if (pcSetName != None):
		pSet = App.g_kSetManager.GetSet(pcSetName)
	elif (pTarget != None):
		pSet = pTarget.GetContainingSet()
	else:
		# No idea what set this is supposed to be in.
		return 0

	if (pSet == None):
		# No set.
		return 0

	# Create the torpedo.
	pTorp = App.Torpedo_Create(pcTorpScriptName, kPoint)
	pTorp.UpdateNodeOnly()

	# Set up its target and target subsystem, if necessary.
	pTorp.SetTarget(idTarget)

	if (idTargetSubsystem != App.NULL_ID):
		pSubsystem = App.ShipSubsystem_Cast(App.TGObject_GetTGObjectPtr(idTargetSubsystem))
		if (pSubsystem != None):
			pTorp.SetTargetOffset(pSubsystem.GetPosition())
		else:
			pTorp.SetTargetOffset(kPoint)
	else:
		pTorp.SetTargetOffset(kPoint)

	# No parent for the torpedo.
	pTorp.SetParent(App.NULL_ID)

	# Add the torpedo to the set, and place it at the specified placement.
	pSet.AddObjectToSet(pTorp, None)

	pTorp.UpdateNodeOnly()

	# If there was a target, then orient the torpedo towards it.
	if (pTarget != None):
		kTorpLocation = pTorp.GetWorldLocation()
		kTargetLocation = pTarget.GetWorldLocation()

		kTargetLocation.Subtract(kTorpLocation)
		kFwd = kTargetLocation
		kFwd.Unitize()
		kPerp = kFwd.Perpendicular()
		kPerp2 = App.TGPoint3()
		kPerp2.SetXYZ(kPerp.x, kPerp.y, kPerp.z)

		pTorp.AlignToVectors(kFwd, kPerp2)
		pTorp.UpdateNodeOnly()

	# Give the torpedo an appropriate speed.
	kVelocity = pTorp.GetWorldForwardTG()
	if (fSpeed == 0.0):
		kVelocity.Scale(pTorp.GetLaunchSpeed())
	else:
		kVelocity.Scale(fSpeed)

	pTorp.SetVelocity(kVelocity)

	# Play the torpedo firing sound
	pcLaunchSound = pTorp.GetLaunchSound()
	if pcLaunchSound != None:
		pSound = App.g_kSoundManager.GetSound(pcLaunchSound)
		if pSound != None:
			pSound.AttachToNode(pTorp.GetNode())

			# Associate this sound with the sound region for the set we're in.
			pSoundRegion = App.TGSoundRegion_GetRegion(pSet.GetName())
			if pSoundRegion != None:
				pSoundRegion.AddSound(pSound)

			pSound.Play()

	return 0

###############################################################################
#	GetRandomLine(StringList)
#	
#	Pick a random line from a list of strings. Returns string chosen.
#	
#	Args:	StringList - List of strings. ex: ["Line1", "Line2", LineX"]
#	
#	Return:	String chosen, or "".
###############################################################################
def GetRandomLine(StringList):
	if(StringList):
		i = len(StringList)
		if i:
			return StringList[App.g_kSystemWrapper.GetRandomNumber(i)]
	return ""

################################################################################
#	SetupWeaponHitHandlers(NameList)
#
#	Sets up Weapon Hit handler for ships in NameTuple.
#
#	Args:	NameList, List of ship names to add handlers for.
#
#	Return:	None
################################################################################
def SetupWeaponHitHandlers(NameList, pcFuncName = None):
	pcScript = GetMission().GetScript()
	if pcScript is None:
		return

	# Make sure we don't add the player.
	if "Player" in NameList:
		NameList.remove("Player")

	for pcShip in NameList:
		pShip = GetShip(pcShip, None, TRUE)
		if pShip:
#			debug("SetupWeaponHitHandlers, adding handler for: " + pcShip)
			if pcFuncName:
				pShip.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, pcScript + 
														"." + pcFuncName)
			else:
				pShip.AddPythonFuncHandlerForInstance(App.ET_WEAPON_HIT, pcScript + 
														".WeaponHitHandler")

################################################################################
#	RemoveWeaponHitHandlers(NameList, pcFuncName = None)
#
#	Removes Weapon Hit handler for ships in NameTuple.
#
#	Args:	NameList, List of ship names to remove handlers for.
#
#	Return:	None
################################################################################
def RemoveWeaponHitHandlers(NameList, pcFuncName = None):
	pcScript = GetMission().GetScript()
	if pcScript is None:
		return

	for pcShip in NameList:
		pShip = GetShip(pcShip)
		if pShip:
			if pcFuncName:
				pShip.RemoveHandlerForInstance(App.ET_WEAPON_HIT, pcScript + 
														"." + pcFuncName)
			else:
				pShip.RemoveHandlerForInstance(App.ET_WEAPON_HIT, pcScript + 
														".WeaponHitHandler")

################################################################################
#	SetTarget(pAction, pcShipName)
#
#	Action to set Player's target. Only changes target for player if
#	in cutscene mode OR on bridge, captin controlling, no target.
#
#	Args:	pAction, current action.
#			pcShipName, name of ship to target.
#
#	Return:	None
################################################################################
def SetTarget(pAction, pcShipName):
	if App.TopWindow_GetTopWindow().IsCutsceneMode():
		pPlayerShip = GetPlayer()
		if pPlayerShip:
			pPlayerShip.SetTarget(pcShipName)
	elif App.TopWindow_GetTopWindow().IsBridgeVisible():
		if GetPlayerShipController() != "Tactical":
			pPlayerShip = GetPlayer()
			if pPlayerShip:
				pPlayerShip.SetTarget(pcShipName)

	return 0

################################################################################
#	IsAnyShieldBreached(pShip)
#
#	Determine wether any shield on ship has been breached.
#
#	Args:	pShip, ship to check.
#
#	Return:	bool
################################################################################
def IsAnyShieldBreached(pShip):
	if pShip is None:
		return FALSE

	pShieldSys = pShip.GetShields()
	if pShieldSys:
		for i in range(App.ShieldClass.NUM_SHIELDS):
			pPercent = pShieldSys.GetSingleShieldPercentage(i)
			if pPercent < 0.05:
				return TRUE
		
		return FALSE
	return TRUE

###############################################################################
#	ContactStarfleet()
#	
#	Plays a sequence of contacting starfleet
#	
#	Args:	none
#	
#	Return:	pContactSequence	- the contact sequence
###############################################################################
def ContactStarfleet():
	pXO = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "XO")

	pXO.MenuDown()

	CallWaiting(None, TRUE)

	pContactSequence = App.TGSequence_Create()
	
	iSequenceNum = App.g_kSystemWrapper.GetRandomNumber(2)

	if (iSequenceNum == 0):
		iLine = App.g_kSystemWrapper.GetRandomNumber(2) * 2 + 1
		pContactSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "HailStarfleet" + str(iLine), "Captain", 1))
	else:
		iLine = App.g_kSystemWrapper.GetRandomNumber(2) * 2 + 2
		pContactSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "HailStarfleet" + str(iLine), "Captain", 1))

	pContactSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_PLAY_ANIMATION, "PushingButtons", None, 1))

	if (App.g_kSystemWrapper.GetRandomNumber(2)):
		iLine = App.g_kSystemWrapper.GetRandomNumber(2) + 5
		pContactSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SPEAK_LINE, "HailStarfleet" + str(iLine)), 0.25)

	if (iSequenceNum == 0):
		pContactSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SPEAK_LINE, "HailStarfleet7"), 2)
	else:
		pContactSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SPEAK_LINE, "HailStarfleet8"), 2)

	# Now grab Liu and her set (or create them if they don't yet exist..)
	pLiuSet = SetupBridgeSet("LiuSet", "data/Models/Sets/StarbaseControl/starbasecontrolRM.nif", -40, 65, -1.55)
	pLiu = App.CharacterClass_GetObject(pLiuSet, "Liu")
	if not (pLiu):
		pLiu = SetupCharacter("Bridge.Characters.Admiral_Liu", "LiuSet", 0, 0, 5)

	pContactSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "ViewscreenOn", "LiuSet", "Liu"), 0.5)

	return pContactSequence

###############################################################################
#	SetupFriendlyFire(pAction = None)
#	
#	Sets up friendly fire handlers for this mission
#	
#	Args:	pAction, the script action, optional arg.
#	
#	Return:	none
###############################################################################
def SetupFriendlyFire(pAction = None):
	# Remove any old handlers
	ShutdownFriendlyFire()

	pMission = GetMission()
	if not (pMission):
		return 0

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_WEAPON_HIT, pMission, __name__ + ".FriendlyFireHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_COLLISION, pMission, __name__ + ".FriendlyFireCollisionHandler")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,	__name__ + ".FriendlyFireWarningHandler")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,__name__ + ".FriendlyFireGameOverHandler")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_TRACTOR_REPORT,__name__ + ".FriendlyTractorWarningHandler")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STARTED_HITTING, pMission, __name__ + ".FriendlyTractorStartHandler")
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_TRACTOR_BEAM_STOPPED_HITTING, pMission, __name__ + ".FriendlyTractorStopHandler")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectStartedExploding")

	ResetFriendlyFire()

	return 0

###############################################################################
#	SetupFriendlyFireNoGameOver()
#	
#	Sets up friendly fire handlers for this mission
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def SetupFriendlyFireNoGameOver():
	# Remove any old handlers
	ShutdownFriendlyFireNoGameOver()

	pMission = GetMission()
	if not (pMission):
		return

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_WEAPON_HIT, pMission, __name__ + ".FriendlyFireHandler")
	pMission.AddPythonFuncHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".FriendlyFireWarningHandler")
	ResetFriendlyFire()


###############################################################################
#	ShutdownFriendlyFireNoGameOver()
#	
#	Removes the handlers for friendly fire
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def ShutdownFriendlyFireNoGameOver():
	pMission = GetMission()
	if not (pMission):
		return

	App.g_kEventManager.RemoveBroadcastHandler(App.ET_WEAPON_HIT, pMission,	__name__ + ".FriendlyFireHandler")
	pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".FriendlyFireWarningHandler")


###############################################################################
#	ShutdownFriendlyFire(pAction = None)
#	
#	Removes the handlers for friendly fire
#	
#	Args:	pAction, the script action, optional arg.
#	
#	Return:	none
###############################################################################
def ShutdownFriendlyFire(pAction = None):
	pMission = GetMission()
	if not (pMission):
		return 0

	App.g_kEventManager.RemoveBroadcastHandler(App.ET_WEAPON_HIT, pMission,	__name__ + ".FriendlyFireHandler")
	pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_REPORT,		__name__ + ".FriendlyFireWarningHandler")
	pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_TRACTOR_REPORT,	__name__ + ".FriendlyTractorWarningHandler")
	pMission.RemoveHandlerForInstance(App.ET_FRIENDLY_FIRE_GAME_OVER,	__name__ + ".FriendlyFireGameOverHandler")

	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TRACTOR_BEAM_STARTED_HITTING, pMission, __name__ + ".FriendlyTractorStartHandler")
	App.g_kEventManager.RemoveBroadcastHandler(App.ET_TRACTOR_BEAM_STOPPED_HITTING, pMission, __name__ + ".FriendlyTractorStopHandler")

	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_OBJECT_EXPLODING, pMission, __name__ + ".ObjectStartedExploding")
	return 0


###############################################################################
#	ResetFriendlyFire()
#	
#	Resets all the friendly fire counters
#	
#	Args:	none
#	
#	Return:	none
###############################################################################
def ResetFriendlyFire():
	App.g_kUtopiaModule.SetCurrentFriendlyFire(0.0)
	App.g_kUtopiaModule.SetFriendlyTractorTime(0.0)

	global g_fTractorStartFiring
	g_fTractorStartFiring = 0.0


###############################################################################
#	FriendlyFireHandler()
#	
#	Called on the WeaponHit event
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def FriendlyFireHandler(pObject, pEvent):
	# Check for player firing on a valid target.
	pAttacker = pEvent.GetFiringObject()
	pPlayer = GetPlayer()
	if not pPlayer:
		pObject.CallNextHandler(pEvent)
		return
	if not pAttacker:
		pObject.CallNextHandler(pEvent)
	   	return
	if pAttacker.GetObjID() != pPlayer.GetObjID():
		pObject.CallNextHandler(pEvent)
		return
	else:
		pSet = pAttacker.GetContainingSet()
		if pSet is None:
			pObject.CallNextHandler(pEvent)
		   	return

	pMission = GetMission()
	if not (pMission):
		pObject.CallNextHandler(pEvent)
		return

	pPlayer = App.ShipClass_Cast(pAttacker)
	pTarget = App.ShipClass_Cast(pEvent.GetDestination())
	if pTarget is None:
		pObject.CallNextHandler(pEvent)
		return
	
	if not (pEvent.GetWeaponType() == pEvent.TRACTOR_BEAM):
		# Okay, it is the player, and they are firing, check for friendly target
		if (pMission.GetFriendlyGroup().IsNameInGroup(pTarget.GetName())):
			# You are firing on a friendly craft
			fOldFriendlyDamage = App.g_kUtopiaModule.GetCurrentFriendlyFire()
			fNewFriendlyDamage = fOldFriendlyDamage + pEvent.GetDamage()
			App.g_kUtopiaModule.SetCurrentFriendlyFire(fNewFriendlyDamage)

			fFriendlyWarning = App.g_kUtopiaModule.GetFriendlyFireWarningPoints()
			fMaxDamage = App.g_kUtopiaModule.GetFriendlyFireTolerance()
			if (fNewFriendlyDamage >= fMaxDamage):
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetSource(pTarget)
				pEvent.SetDestination(pMission)
				pEvent.SetEventType(App.ET_FRIENDLY_FIRE_GAME_OVER)
				App.g_kEventManager.AddEvent(pEvent)

			elif (int(fNewFriendlyDamage/fFriendlyWarning) > int(fOldFriendlyDamage/fFriendlyWarning) or (fOldFriendlyDamage < fFriendlyWarning/3 and fNewFriendlyDamage >= fFriendlyWarning/3)):
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetSource(pTarget)
				pEvent.SetDestination(pMission)
				pEvent.SetEventType(App.ET_FRIENDLY_FIRE_REPORT)
				App.g_kEventManager.AddEvent(pEvent)

			else:
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetSource(pTarget)
				pEvent.SetDestination(pMission)
				pEvent.SetEventType(App.ET_FRIENDLY_FIRE_DAMAGE)
				App.g_kEventManager.AddEvent(pEvent)
	else:
		# Okay, it is the player, and they are firing, check for non-tractor target
		if (pMission.GetFriendlyGroup().IsNameInGroup(pTarget.GetName()) and not pMission.GetTractorGroup().IsNameInGroup(pTarget.GetName())):
			global g_fTractorStartFiring
			if (g_fTractorStartFiring == 0.0):
				g_fTractorStartFiring = App.g_kUtopiaModule.GetGameTime()
			
			fTime = App.g_kUtopiaModule.GetGameTime() - g_fTractorStartFiring
			AddTractorTime(fTime)

	pObject.CallNextHandler(pEvent)

def FriendlyTractorStartHandler(pObject, pEvent):
	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

	global g_fTractorStartFiring

	pProjector = App.TractorBeamProjector_Cast(pEvent.GetSource())
	if not (pProjector):
		return

	pShip = pProjector.GetParentShip()
	pPlayer = GetPlayer()
	if not (pShip and pPlayer):
#		debug("Either the ship or the player didn't exist")
		return

	pTractor = pPlayer.GetTractorBeamSystem()
	if not (pTractor.IsOn()):
#		debug("This player isn't really firing")
		g_fTractorStartFiring = 0
		return

#	debug("Firing ship is " + pShip.GetName() + ", event ID is " + str(pEvent.GetObjID()))

	if not (pShip.GetObjID() == pPlayer.GetObjID()):
#		debug("Not the player - ID " + str(pShip.GetObjID()) + " as oppsed to " + str(pPlayer.GetObjID()))
		return

#	debug("You started firing your tractor beam")
	g_fTractorStartFiring = App.g_kUtopiaModule.GetGameTime()

	# Setup up a recurring script action to deal with this..
	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AddTractorTimeAction"), 5)
	pSequence.Play()

def AddTractorTimeAction(pAction):
	global g_fTractorStartFiring
	if (g_fTractorStartFiring <= 0.0):
		return 0

	pPlayer = GetPlayer()
	if not (pPlayer):
		return 0

	pTractor = pPlayer.GetTractorBeamSystem()
	if not (pTractor.IsOn()):
#		debug("This player isn't really firing")
		g_fTractorStartFiring = 0
		return 0

	fTime = App.g_kUtopiaModule.GetGameTime() - g_fTractorStartFiring
	g_fTractorStartFiring = App.g_kUtopiaModule.GetGameTime()
	AddTractorTime(fTime)

	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create(__name__, "AddTractorTimeAction"), 5)
	pSequence.Play()

	return 0

def FriendlyTractorStopHandler(pObject, pEvent):
	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

	pProjector = App.TractorBeamProjector_Cast(pEvent.GetSource())
	if not (pProjector):
		return

	pShip = pProjector.GetParentShip()
	pPlayer = GetPlayer()
	if not (pShip and pPlayer):
#		debug("Either the ship or the player didn't exist")
		return

	if not (pShip.GetObjID() == pPlayer.GetObjID()):
		return

#	debug("You stopped firing your tractor beam")
	global g_fTractorStartFiring
	fTime = App.g_kUtopiaModule.GetGameTime() - g_fTractorStartFiring
	AddTractorTime(fTime, 1)
	g_fTractorStartFiring = 0.0

def AddTractorTime(fTime, bForce = 0):
	pPlayer = GetPlayer()
	if not pPlayer:
		g_fTractorStartFiring = 0
		return

	pTractor = pPlayer.GetTractorBeamSystem()
	if not (pTractor.IsOn() and bForce == 0):
#		debug("This player isn't really firing")
		g_fTractorStartFiring = 0
		return

	pMission = GetMission()
	if not (pMission):
		g_fTractorStartFiring = 0
		return

	pTarget = App.ShipClass_Cast(pPlayer.GetTarget())
	if pTarget is None:
		g_fTractorStartFiring = 0
		return

#	debug("Just fired for an additional " + str(fTime))
	if (pMission.GetFriendlyGroup().IsNameInGroup(pTarget.GetName()) and not pMission.GetTractorGroup().IsNameInGroup(pTarget.GetName())):
#		debug("It's a friendly, not in the safe tractor list")
		if (fTime > 0.0):
			fOldTractorTime = App.g_kUtopiaModule.GetFriendlyTractorTime()
			fTractorWarning = App.g_kUtopiaModule.GetFriendlyTractorWarning()
			fCurrentTractorTime = fOldTractorTime + fTime
			App.g_kUtopiaModule.SetFriendlyTractorTime(fCurrentTractorTime)
			fMaxTractorTime = App.g_kUtopiaModule.GetMaxFriendlyTractorTime()
			g_fTractorStartFiring = App.g_kUtopiaModule.GetGameTime()

			if (fCurrentTractorTime >= fMaxTractorTime):
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetSource(pTarget)
				pEvent.SetDestination(pMission)
				pEvent.SetEventType(App.ET_FRIENDLY_FIRE_GAME_OVER)
				App.g_kEventManager.AddEvent(pEvent)

			elif (int(fCurrentTractorTime/fTractorWarning) > int(fOldTractorTime/fTractorWarning) or (fOldTractorTime < fTractorWarning/3 and fCurrentTractorTime >= fTractorWarning/3)):
				# We've passed a threshold..
				pEvent = App.TGFloatEvent_Create()
				pEvent.SetSource(pTarget)
				pEvent.SetDestination(pMission)
				pEvent.SetEventType(App.ET_FRIENDLY_TRACTOR_REPORT)
				App.g_kEventManager.AddEvent(pEvent)


###############################################################################
#	FriendlyFireCollisionHandler
#	
#	Someone collided with something.  If it's the player colliding
#	with a friendly ship, trigger friendly fire warnings.
#	
#	Args:	pMission	- The mission object.
#			pEvent		- The ET_OBJECT_COLLISION event we're handling.
#	
#	Return:	None
###############################################################################
def FriendlyFireCollisionHandler(pMission, pEvent):
	# Check if the player is the colliding ship.  (Only need to
	# check either the source or the destination, since there's an
	# event sent for each).
	pObject1 = App.ShipClass_Cast( pEvent.GetDestination() )
	pPlayer = App.Game_GetCurrentPlayer()
	try:
		if pPlayer.GetObjID() != pObject1.GetObjID():
			return
	except AttributeError:
		# One or the other is null.
		return

	# The player collided with someone.  Is that someone a friendly ship?
	pFriendlyGroup = pMission.GetFriendlyGroup()
	pCollidee = App.ObjectClass_Cast( pEvent.GetSource() )
	if not pFriendlyGroup.IsNameInGroup( pCollidee.GetName() ):
		# Not a friendly.
		return

	# The player collided with a friendly craft.  Bad player.  This conduct is inexcusable.  Game over.
	pEvent = App.TGFloatEvent_Create()
	pEvent.SetSource(pCollidee)
	pEvent.SetDestination(pMission)
	pEvent.SetEventType(App.ET_FRIENDLY_FIRE_GAME_OVER)

	# Don't trigger the game over for a short time, so the player can see the collision
	# (and fear the impending doom).
	pTimer = App.TGTimer_Create()
	pTimer.SetTimerStart(App.g_kUtopiaModule.GetGameTime() + 1.5)
	pTimer.SetEvent(pEvent)
	App.g_kTimerManager.AddTimer(pTimer)

###############################################################################
#	FriendlyFireWarningHandler()
#	
#	You have hurt a friendly craft - say so
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def FriendlyFireWarningHandler(pObject, pEvent):
	if (g_bFFGameOver):
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	if (App.g_kUtopiaModule.IsMultiplayer()):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.TGL")
		TextBanner(None, pDatabase.GetString("Friendly Fire"), 0, 0.25, 5.0, 12, 1)
		App.g_kLocalizationManager.Unload(pDatabase)
		pObject.CallNextHandler(pEvent)
		return

	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	if not (pXO):
		pObject.CallNextHandler(pEvent)
		return

	fTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - pXO.GetLastTalkTime()
	if (fTimeSinceTalk < 5.0):
		pObject.CallNextHandler(pEvent)
		return

	if (App.g_kSystemWrapper.GetRandomNumber(2) == 0):
		pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "DontShoot2", "Captain", 1)
		App.TGActionManager_RegisterAction(pAction, "FriendlyFireWarning")
		pAction.Play()
	else:
		pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "DontShoot" + str(App.g_kSystemWrapper.GetRandomNumber(2) + 4), "Captain", 1)
		App.TGActionManager_RegisterAction(pAction, "FriendlyFireWarning")
		pAction.Play()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	FriendlyTractorWarningHandler()
#	
#	You have tractored a friendly craft - say so
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def FriendlyTractorWarningHandler(pObject, pEvent):
	if (g_bFFGameOver):
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

	if (App.g_kUtopiaModule.IsMultiplayer()):
		pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.TGL")
		TextBanner(None, pDatabase.GetString("Friendly Fire"), 0, 0.25, 5.0, 12, 1)
		App.g_kLocalizationManager.Unload(pDatabase)
		pObject.CallNextHandler(pEvent)
		return

	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	if not (pXO):
		pObject.CallNextHandler(pEvent)
		return

	fTimeSinceTalk = App.g_kUtopiaModule.GetGameTime() - pXO.GetLastTalkTime()
	if (fTimeSinceTalk < 5.0):
		pObject.CallNextHandler(pEvent)
		return

	pAction = App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "DontShoot" + str(App.g_kSystemWrapper.GetRandomNumber(2) + 8), "Captain", 1)
	App.TGActionManager_RegisterAction(pAction, "FriendlyFireWarning")
	pAction.Play()

	pObject.CallNextHandler(pEvent)

###############################################################################
#	ObjectStartedExploding()
#	
#	An object started exploding - if it was friendly, and you did it, bye bye!
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def ObjectStartedExploding(pObject, pEvent):
	if (App.g_kUtopiaModule.IsMultiplayer()):
		# Ummm, do we do anything here?
		pObject.CallNextHandler(pEvent)
		return

	pMission = GetMission()
	if not (pMission):
		return

	idPlayer = App.NULL_ID
	pPlayer = GetPlayer()
	if (pPlayer):
		idPlayer = pPlayer.GetObjID()
	else:
		pObject.CallNextHandler(pEvent)
		return

	pDyingObject = App.DamageableObject_Cast(pEvent.GetDestination())
	if (pEvent.GetFiringPlayerID() == idPlayer):
		#debug("Well, the player was the one to kill them...")
		if (pMission.GetFriendlyGroup().IsNameInGroup(pDyingObject.GetName())):
#			debug("Woah, you killed a friendly, even if you didn't hurt them that much")
			# You killed them!!
			pEvent = App.TGFloatEvent_Create()
			pEvent.SetSource(pDyingObject)
			pEvent.SetDestination(pMission)
			pEvent.SetEventType(App.ET_FRIENDLY_FIRE_GAME_OVER)
			App.g_kEventManager.AddEvent(pEvent)
	else:
		pass
		#debug("Not killed by player?")

	pObject.CallNextHandler(pEvent)

###############################################################################
#	FriendlyFireGameOverHandler()
#	
#	You did too much, you went too far, now the game is over
#	Liu - You have failed me for the last time, Captain.  You are in command
#		  now, Captain Larsen
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def FriendlyFireGameOverHandler(pObject, pEvent):
	global g_bFFGameOver
	if (g_bFFGameOver):
		if (pObject and pEvent):
			pObject.CallNextHandler(pEvent)
		return

#	debug("Admiral Liu: You have failed me for the last time, Captain.  You are in command now, Captain Larsen")

	if (App.g_kUtopiaModule.IsMultiplayer()):
		# Ummm, do we do anything here?
		pObject.CallNextHandler(pEvent)
		return

	pSequence = App.TGSequence_Create()
	pSequence.AppendAction(App.TGScriptAction_Create("MissionLib", "StartCutscene"))

	pBridge = App.g_kSetManager.GetSet("bridge")
	pXO = App.CharacterClass_GetObject(pBridge, "XO")
	if (pXO):
		pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_LOOK_AT_ME))

		if (App.g_kSystemWrapper.GetRandomNumber(2) == 0):
			pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "DontShoot6", "Captain", 1))
		else:
			pSequence.AppendAction(App.CharacterAction_Create(pXO, App.CharacterAction.AT_SAY_LINE, "DontShoot" + str(App.g_kSystemWrapper.GetRandomNumber(2) + 6), "Captain", 1))

	App.TGActionManager_RegisterAction(pSequence, "FriendlyFireGameOver")

	App.TGActionManager_KillActions("FriendlyFireWarning")

	pScriptAction = App.TGScriptAction_Create(__name__, "GameOver", pSequence)
	App.TGActionManager_RegisterAction(pScriptAction, "FriendlyFireGameOver")
	pScriptAction.Play()

	g_bFFGameOver = 1

	if (pObject and pEvent):
		pObject.CallNextHandler(pEvent)

###############################################################################
#	GetNumObjectsAlive(pObjectGroup)
#	
#	Returns number of objects alive in an object group.
#	
#	Args:	pObjectGroup, the ObjectGroup object.
#	
#	Return:	iNumAlive - Number of objects alive in group.
###############################################################################
def GetNumObjectsAlive(pObjectGroup):
	assert pObjectGroup
	pPlayer = GetPlayer()
	if pPlayer is None:
		return 0

	iNumAlive = 0
	if pObjectGroup:
		ObjTuple = pObjectGroup.GetActiveObjectTupleInSet(pPlayer.GetContainingSet())
		if len(ObjTuple):
			for i in ObjTuple:
				pObj = App.DamageableObject_Cast(i)
				if pObj:
					if not (pObj.IsDead() or pObj.IsDying()):
						iNumAlive = iNumAlive + 1
	return iNumAlive


###############################################################################
#	SetLoadFromFileName()
#	
#	This is used because UtopiaModule is not an event handling object
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def SetLoadFromFileName(pObject, pEvent):
	App.g_kUtopiaModule.SetLoadFromFileName(pEvent.GetCString())

###############################################################################
#	CancelLoad()
#	
#	This is used because UtopiaModule is not an event handling object
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def CancelLoad(pObject, pEvent):
	pGame = App.Game_GetCurrentGame()
	if not (pGame):
		return

	pGame.RemoveHandlerForInstance(App.ET_SET_LOAD_FILE, "MissionLib.SetLoadFromFileName")
	pGame.RemoveHandlerForInstance(App.ET_CANCEL_LOAD, "MissionLib.CancelLoad")


###############################################################################
#	SetupInfoBox() and SetupInfoBoxFromParagraph()
#	
#	Sets up an "extra information box", which comes up on command, goes away
#	on command, holds some text, and might have a close button to make it
#	disappear forcibly.
#	
#	Args:	pTitleString	- title of the box, from a TGL
#			pTextString		- text of the box, from a TGL
#				OR
#			pParagraph		- formatted paragraph for use in box
#			iWidth			- width of the box
#			iHeight			- height of the box
#			kOpenEvent		- event the box opens on
#			pOpenTarget		- target of the event that opens us
#			kCloseEvent		- event that we close on
#			pCloseTarget	- target of the event that closes us
#			bCloseButton	- do we also have a close button?
#			pCloseString	- do we specify a string for the close button?
#	
#	Return:	the newly created box
###############################################################################
def SetupInfoBox(pTitleString, pTextString, iWidth, iHeight,
		kOpenEvent, pOpenTarget, kCloseEvent, pCloseTarget, bCloseButton = 1, pCloseString = None):

	pParagraph = App.TGParagraph_CreateW(pTextString, iWidth, None, "", 0.0, App.TGParagraph.TGPF_READ_ONLY | App.TGParagraph.TGPF_WORD_WRAP)

	return SetupInfoBoxFromParagraph(pTitleString, pParagraph, iWidth, iHeight,
				kOpenEvent, pOpenTarget, kCloseEvent, pCloseTarget, bCloseButton, pCloseString)

def SetupInfoBoxFromParagraph(pTitleString, pParagraph, iWidth, iHeight,
		kOpenEvent, pOpenTarget, kCloseEvent, pCloseTarget, bCloseButton = 1, pCloseString = None):

	# Import resolution dependent LCARS module for size/placement variables.
	LCARS = __import__(App.GraphicsModeInfo_GetCurrentMode().GetLcarsModule())

	# Create the box.
	pBox = App.STStylizedWindow_CreateW("StylizedWindow", "RightBorder", pTitleString)

	# Make a pane for the text, so the pane is always the same size.
	pBoxPane = App.TGPane_Create(iWidth, iHeight)
	pBox.AddChild(pBoxPane, 0, 0, 0)

	# Create the text object.
	pBoxPane.AddChild(pParagraph, 0, 0, 0)

	# Add a "Close" button if desired
	if (bCloseButton == 1):
		if (pCloseString == None):
			pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
			pCloseString = pDatabase.GetString("Close")
			App.g_kLocalizationManager.Unload(pDatabase)

		pEvent = App.TGEvent_Create()
		pEvent.SetDestination(pBox)
		pEvent.SetEventType(App.ET_INPUT_CLOSE_MENU)

		pButton = App.STButton_CreateW(pCloseString, pEvent)

		# Set the color of the button
		pButton.SetUseUIHeight(0)	# overrides normal colors
		pButton.SetNormalColor(App.g_kSTMenu2NormalBase)
		pButton.SetSelectedColor(App.g_kSTMenu2Selected)
		pButton.SetHighlightedColor(App.g_kSTMenu2HighlightedBase)
		pButton.SetDisabledColor(App.g_kSTMenu2Disabled)
		pButton.SetColorBasedOnFlags()
		
		pBoxPane.AddChild(pButton, 0, pBoxPane.GetHeight() - pButton.GetHeight())
		pBox.AddPythonFuncHandlerForInstance(App.ET_INPUT_CLOSE_MENU, __name__ + ".CloseInfoBox")

	# Finish setting up the overall box.
	pBox.InteriorChangedSize()
	pBox.SetNotVisible()
	pBox.SetNoFocus()

	if (kOpenEvent == kCloseEvent):
		# If we get the same source and dest event, it must be a bool event, so use the toggle handler
		pOpenTarget.AddPythonFuncHandlerForInstance(kOpenEvent, __name__ + ".ToggleInfoTarget")
	else:
		if (pOpenTarget != None):
			pOpenTarget.AddPythonFuncHandlerForInstance(kOpenEvent, __name__ + ".OpenInfoTarget")
		pCloseTarget.AddPythonFuncHandlerForInstance(kCloseEvent, __name__ + ".CloseInfoTarget")

	global g_lInfoBoxes, g_lInfoOpenSource, g_lInfoCloseSource, g_lInfoOpenEvent, g_lInfoCloseEvent

	g_lInfoBoxes.append(pBox.GetObjID())
	if (pOpenTarget != None):
		g_lInfoOpenSource.append(pOpenTarget.GetObjID())
	else:
		g_lInfoOpenSource.append(App.NULL_ID)
	g_lInfoCloseSource.append(pCloseTarget.GetObjID())
	g_lInfoOpenEvent.append(kOpenEvent)
	g_lInfoCloseEvent.append(kCloseEvent)

	idBox = pBox.GetObjID()
	iIndex = g_lInfoBoxes.index(idBox)
#	debug("Added info box of index " + str(iIndex) + ", ID " + str(idBox))

	# Return the new box
	return pBox

###############################################################################
#	DestroyInfoBox()
#	
#	Destroys a previously created info box
#	
#	Args:	idBox	- ID of the box to destroy
#	
#	Return:	none
###############################################################################
def DestroyInfoBox(idBox):
	global g_lInfoBoxes, g_lInfoOpenSource, g_lInfoCloseSource, g_lInfoOpenEvent, g_lInfoCloseEvent
	iIndex = g_lInfoBoxes.index(idBox)
#	debug("Removing info box of index " + str(iIndex) + ", ID " + str(idBox))
	g_lInfoBoxes.remove(idBox)

	idOpenSource = g_lInfoOpenSource[iIndex]
	pOpenSource = App.TGObject_GetTGObjectPtr(idOpenSource)
	pOpenSource = App.TGEventHandlerObject_Cast(pOpenSource)
	kInfoOpenEvent = g_lInfoOpenEvent[iIndex]
	if (pOpenSource):
		pOpenSource.RemoveHandlerForInstance(kInfoOpenEvent, __name__ + ".OpenInfoTarget")
		pOpenSource.RemoveHandlerForInstance(kInfoOpenEvent, __name__ + ".ToggleInfoTarget")
	g_lInfoOpenEvent.remove(kInfoOpenEvent)
	g_lInfoOpenSource.remove(idOpenSource)

	idCloseSource = g_lInfoCloseSource[iIndex]
	pCloseSource = App.TGObject_GetTGObjectPtr(idCloseSource)
	pCloseSource = App.TGEventHandlerObject_Cast(pCloseSource)
	kInfoCloseEvent = g_lInfoCloseEvent[iIndex]
	if (pCloseSource):
		pCloseSource.RemoveHandlerForInstance(kInfoCloseEvent, __name__ + ".CloseInfoTarget")
	g_lInfoCloseEvent.remove(kInfoCloseEvent)
	g_lInfoCloseSource.remove(idCloseSource)

	pBox = App.TGObject_GetTGObjectPtr(idBox)
	pBox = App.STStylizedWindow_Cast(pBox)
	if not (pBox):
#		debug("Unable to destroy info box of id " + str(idBox))
		return

	pParent = pBox.GetParent()
	if not (pParent):
#		debug("Unable to get info box's parent, attempting to destroy manually")
		del pBox
		return
	
	pParent.DeleteChild(pBox)

###############################################################################
#	Open..() and Close..()
#	
#	Shows or hides the info box
#	
#	Args:	pObject, pEvent	- the object and event that called us
#	
#	Return:	none
###############################################################################
def OpenInfoTarget(pObject, pEvent):
	global g_lInfoOpenSource,g_lInfoBoxes
	iIndex = g_lInfoOpenSource.index(pObject.GetObjID())
	idBox = g_lInfoBoxes[iIndex]
	pBox = App.TGObject_GetTGObjectPtr(idBox)
	pBox = App.STStylizedWindow_Cast(pBox)
	pBox.SetVisible()
	pObject.CallNextHandler(pEvent)
	
def CloseInfoTarget(pObject, pEvent):
	global g_lInfoCloseSource,g_lInfoBoxes
	iIndex = g_lInfoCloseSource.index(pObject.GetObjID())
	idBox = g_lInfoBoxes[iIndex]
	pBox = App.TGObject_GetTGObjectPtr(idBox)
	pBox = App.STStylizedWindow_Cast(pBox)
	pBox.SetNotVisible()
	pObject.CallNextHandler(pEvent)

def ToggleInfoTarget(pObject, pEvent):
	global g_lInfoOpenSource,g_lInfoBoxes
	iIndex = g_lInfoOpenSource.index(pObject.GetObjID())
	idBox = g_lInfoBoxes[iIndex]
	pBox = App.TGObject_GetTGObjectPtr(idBox)
	pBox = App.STStylizedWindow_Cast(pBox)
	if (pEvent.GetBool() == 1):
		pBox.SetVisible()
	else:
		pBox.SetNotVisible()
	pObject.CallNextHandler(pEvent)

def ShowInfoBox(pAction, idBox):
	pBox = App.TGObject_GetTGObjectPtr(idBox)
	pBox = App.STStylizedWindow_Cast(pBox)
	if (pBox):
		pBox.SetVisible()

	return 0

def HideInfoBox(pAction, idBox):
	pBox = App.TGObject_GetTGObjectPtr(idBox)
	pBox = App.STStylizedWindow_Cast(pBox)
	if (pBox):
		pBox.SetNotVisible()

	return 0

def CloseInfoBox(pObject, pEvent):
	pBox = App.STStylizedWindow_Cast(pEvent.GetDestination())
	pBox.SetNotVisible()
	pObject.CallNextHandler(pEvent)


###############################################################################
#	GetMissionDatabase()
#	
#	Returns the current mission database
#	
#	Args:	none
#	
#	Return:	The current Mission database
###############################################################################
def GetMissionDatabase():
	pMission = GetMission()
	if not (pMission):
		return None

	return pMission.GetDatabase()

###############################################################################
#	ShowPointerArrow(pAction, idUIObject, eDirection, fSpacing, kColor)
#	
#	Adds a pointer arrow pointing to the specified object.
#	
#	Args:	pAction		- the action
#			pUIObject	- the object
#			eDirection	- the direction of the arrow (which way it points)
#			fSpacing	- distance between arrow and object -- specified as a
#						  scale factor of the arrow's size
#			kColor		- optional color. If not specified, it uses white.
#	
#	Return:	none
###############################################################################
def ShowPointerArrow(pAction, pUIObject, eDirection, fSpacing = 0.0, kColor = None):
	if (pUIObject == None):
		return 0
	if (pUIObject.IsCompletelyVisible() == 0):
		return 0

	if (kColor == None):
		kColor = App.NiColorA_WHITE

	if eDirection <= POINTER_DL:
		pIcon = App.TGIcon_Create(App.GraphicsModeInfo_GetCurrentMode().GetLcarsString(), 
								  220 + eDirection, kColor)
	else:
		if eDirection == POINTER_UL_CORNER:
			pIcon = App.TGIcon_Create(App.GraphicsModeInfo_GetCurrentMode().GetLcarsString(),
									  220 + POINTER_RIGHT, kColor)
		else:
			pIcon = App.TGIcon_Create(App.GraphicsModeInfo_GetCurrentMode().GetLcarsString(),
									  220 + POINTER_LEFT, kColor)

	pIcon.Resize(pIcon.GetWidth(), pIcon.GetHeight(), 0)

	pTop = App.TopWindow_GetTopWindow()
	kOffset = App.NiPoint2(0.0, 0.0)
	pUIObject.GetScreenOffset(kOffset)

	fHalfWidth = pUIObject.GetWidth() / 2.0
	fHalfHeight = pUIObject.GetHeight() / 2.0

	fHalfArrowWidth = pIcon.GetWidth() / 2.0
	fHalfArrowHeight = pIcon.GetHeight() / 2.0

	if eDirection == POINTER_LEFT:
		pTop.PrependChild(pIcon, kOffset.x + pUIObject.GetWidth() + (pIcon.GetWidth() * fSpacing), 
					  kOffset.y + fHalfHeight - fHalfArrowHeight, 0)
	elif eDirection == POINTER_UL:
		pTop.PrependChild(pIcon, kOffset.x + pUIObject.GetWidth() + (pIcon.GetWidth() * fSpacing), 
					  kOffset.y + pUIObject.GetHeight() + (pIcon.GetHeight() * fSpacing), 0)
	elif eDirection == POINTER_UP:
		pTop.PrependChild(pIcon, kOffset.x + fHalfWidth - fHalfArrowWidth, 
					  kOffset.y + pUIObject.GetHeight() + (pIcon.GetHeight() * fSpacing), 0)
	elif eDirection == POINTER_UR:
		pTop.PrependChild(pIcon, kOffset.x - (pIcon.GetWidth() * (fSpacing + 1.0)), 
					  kOffset.y + pUIObject.GetHeight() + (pIcon.GetHeight() * fSpacing), 0)
	elif eDirection == POINTER_RIGHT:
		pTop.PrependChild(pIcon, kOffset.x - (pIcon.GetWidth() * (fSpacing + 1.0)), 
					  kOffset.y + fHalfHeight - fHalfArrowHeight, 0)
	elif eDirection == POINTER_DR:
		pTop.PrependChild(pIcon, kOffset.x - (pIcon.GetWidth() * (fSpacing + 1.0)), 
					  kOffset.y - (pIcon.GetHeight() * (fSpacing + 1.0)), 0)
	elif eDirection == POINTER_DOWN:
		pTop.PrependChild(pIcon, kOffset.x + fHalfWidth - fHalfArrowWidth, 
					  kOffset.y - (pIcon.GetHeight() * (fSpacing + 1.0)), 0)
	elif eDirection == POINTER_DL:
		pTop.PrependChild(pIcon, kOffset.x + pUIObject.GetWidth() + (pIcon.GetWidth() * fSpacing), 
					  kOffset.y - (pIcon.GetHeight() * (fSpacing + 1.0)), 0)
	elif eDirection == POINTER_UL_CORNER:
		pTop.PrependChild(pIcon, kOffset.x - (pIcon.GetWidth() * (fSpacing + 1.0)),
						  kOffset.y, 0)
	elif eDirection == POINTER_UR_CORNER:
		pTop.PrependChild(pIcon, kOffset.x + pUIObject.GetWidth() + (pIcon.GetWidth() * fSpacing),
						  kOffset.y, 0)

	pIcon.Layout()

	global g_lPointerArrows
	g_lPointerArrows.append(pIcon.GetObjID())

	return 0

###############################################################################
#	HidePointerArrows(pAction)
#	
#	Removes all pointer arrows.
#	
#	Args:	pAction	- the action, if called as an action
#	
#	Return:	none
###############################################################################
def HidePointerArrows(pAction = None):
	global g_lPointerArrows

	for idArrow in g_lPointerArrows:
		pIcon = App.TGIcon_Cast(App.TGObject_GetTGObjectPtr(idArrow))

		if (pIcon != None) and (pIcon.GetParent() != None):
			pIcon.GetParent().DeleteChild(pIcon)

	g_lPointerArrows = []

	if (pAction != None):
		return 0


###############################################################################
#	CallWaiting()
#	
#	Disables/enables menus dealing with contacting others
#	
#	Args:	bOn	- do we turn on call waiting?
#	
#	Return:	0, to continue the script action
###############################################################################
def CallWaiting(pAction, bOn):
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Bridge Menus.tgl")
	pTacticalControlWindow = App.TacticalControlWindow_GetTacticalControlWindow()
	if not (pTacticalControlWindow):
		App.g_kLocalizationManager.Unload(pDatabase)
		return 0

	pXOMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Commander"))
	pHelmMenu = pTacticalControlWindow.FindMenu(pDatabase.GetString("Helm"))

	lButtons = []

	# Make a list of all buttons/menus to disable/enable
	if (pXOMenu):
		lButtons.append(pXOMenu.GetButtonW(pDatabase.GetString("Contact Starfleet")))

		pEngineer = App.CharacterClass_GetObject(App.g_kSetManager.GetSet("bridge"), "Engineer")
		if not (pEngineer):
			lButtons.append(pXOMenu.GetButtonW(pDatabase.GetString("Contact Engineering")))

	if (pHelmMenu):
		lButtons.append(pHelmMenu.GetSubmenuW(pDatabase.GetString("Hail")))

	for pButton in lButtons:
		if (bOn == 0):
			pButton.SetEnabled(0)
		else:
			if (pButton.IsTypeOf(App.CT_ST_MENU)):
				pButton = App.STMenu_Cast(pButton)
				pButton.Close()
			pButton.SetDisabled(0)

	App.g_kLocalizationManager.Unload(pDatabase)
	
	return 0


###############################################################################
#	SetSpeakingVolume()
#	
#	Sets the speaking volume for various types
#	(CSP_SPONTANEOUS, CSP_NORMAL, CSP_MISSION_CRITICAL)
#	
#	Args:	pAction	- the TGScriptAction that called us
#			iType	- the type of line to set volume for
#			fVolume	- how loud to be, 0 = mute, 1 = full volume
#	
#	Return:	0, to continue the script action
###############################################################################
def SetSpeakingVolume(pAction, iType, fVolume):

	App.CharacterClass_SetVolumeForLineType(iType, fVolume)

	return 0


###############################################################################
#	MoveShip(pShip, pcPlacement)
#	
#	Move a ship to a given named placement.
#	
#	Args:	pShip		- the ship to move.
#			pcPlacement - name of placement to move ship to(in same set).
#	
#	Return:	None
###############################################################################
def MoveShip(pShip, pcPlacement):
	assert pShip
	assert pcPlacement
	if pShip and pcPlacement:
		pPlacement = App.PlacementObject_GetObject(pShip.GetContainingSet(), pcPlacement)
		if pPlacement:
			pShip.SetTranslate(pPlacement.GetWorldLocation())
			pShip.SetMatrixRotation(pPlacement.GetWorldRotation())
			pShip.UpdateNodeOnly()

###############################################################################
#	MoveShipAction(pShip, pcPlacement)
#	
#	Move a ship to a given named placement.
#	
#	Args:	pAction		- the script action
#			pShip		- the ship to move.
#			pcPlacement - name of placement to move ship to(in same set).
#	
#	Return:	0
###############################################################################
def MoveShipAction(pAction, pShip, pcPlacement):
	assert pShip
	assert pcPlacement
	if pShip and pcPlacement:
		pPlacement = App.PlacementObject_GetObject(pShip.GetContainingSet(), pcPlacement)
		if pPlacement:
			pShip.SetTranslate(pPlacement.GetWorldLocation())
			pShip.SetMatrixRotation(pPlacement.GetWorldRotation())
			pShip.UpdateNodeOnly()
	return 0

###############################################################################
#	StopShip(pAction = None)
#	
#	Stop the player's ship, either player or AI controlled.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def StopShip(pAction = None):
	pPlayer = GetPlayer()

	if GetPlayerShipController() == "Tactical":
		# Tell Felix not to do anything
		import Bridge.TacticalMenuHandlers
		Bridge.TacticalMenuHandlers.g_iOrderState = Bridge.TacticalMenuHandlers.EST_ORDER_STOP
		Bridge.TacticalMenuHandlers.UpdateOrders(0)	# No acknowledgement.
	else:
		pPlayer.SetSpeed(0.0, App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
		pPlayer.SetVelocity(App.TGPoint3_GetModelForward())
		pPlayer.SetAngularVelocity(App.TGPoint3_GetModelForward(), App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)

	return 0

###############################################################################
#	StopFelix(pAction = None)
#	
#	Tell Felix to stop what he's doing.
#	
#	Args:	pAction, the script action.
#	
#	Return:	0
###############################################################################
def StopFelix(pAction = None):
	# Make sure felix is in control...
	if GetPlayerShipController() != "Tactical":
		return 0

	# Tell Felix not to do anything
	import Bridge.TacticalMenuHandlers
	Bridge.TacticalMenuHandlers.g_iOrderState = (Bridge.TacticalMenuHandlers.EST_ORDER_STOP - 
												Bridge.TacticalMenuHandlers.EST_FIRST_ORDER)
	Bridge.TacticalMenuHandlers.UpdateOrders(0)	# No acknowledgement.

	return 0

###############################################################################
#	PreloadMissionLines
#	
#	Load mission-specific sounds (for briefings and things) into memory,
#	so they don't hitch the framerate when they have to play.
#	
#	Args:	bDelayed	- If this is true (1), then sounds are loaded in over time, so they
#						  don't cause 1 big hit to the framerate.  If this is false (0), they're
#						  all loaded right now.
#			lsLines		- The lines to preload (eg. "E6Intro1", "E6Intro2", "E6Intro3"...)
#	
#	Return:	None
###############################################################################
def PreloadMissionLines(bDelayed, *lsLines):
	pMission = GetMission()
	if not pMission:
		# Need to have an action mission to do this.
		return
	idMission = pMission.GetObjID()

	if bDelayed:
		# Setup actions to load the lines in series...
		pSequence = App.TGSequence_Create()

		fDelay = 0.0
		pPrevious = None
		for sLine in lsLines:
			pSequence.AppendAction( App.TGScriptAction_Create(__name__, "PreloadMissionLine", idMission, sLine), fDelay )
			fDelay = 0.001

		pSequence.Play()
	else:
		# Load all the sounds right now.
		for sLine in lsLines:
			PreloadMissionLine(None, idMission, sLine)

###############################################################################
#	PreloadMissionLine
#	
#	Load a mission-specific line.
#	
#	Args:	pAction		- An action, or None.  This is unused.
#			idMission	- The object ID of the mission these are loaded under.
#						  This is here just to make sure we don't try to load
#						  sounds for an old mission.
#			sLine		- The line to load.
#	
#	Return:	0
###############################################################################
def PreloadMissionLine(pAction, idMission, sLine):
	# If this sound is already loaded, skip it.
	if App.g_kSoundManager.GetSound(sLine):
		return 0

	# If, for some reason, the current mission isn't the mission we started loading under,
	# don't load the sound.
	pMission = GetMission()
	if (not pMission)  or  (pMission.GetObjID() != idMission):
		return 0

	# Sounds will be loaded from the mission database if possible, and the
	# episode database if they don't appear in the mission one.  If it doesn't
	# appear in either of those, try the Bridge Crew General database.
	pBridgeCrewGeneral = App.g_kLocalizationManager.Load("data/TGL/Bridge Crew General.tgl")
	lsLoaders = (
		( "Mission", GetMission(), GetMission().GetDatabase() ),
		( "Episode", GetEpisode(), GetEpisode().GetDatabase() ),
		( "Bridge Crew", None, pBridgeCrewGeneral ),
		)

	iLoadFlags = 0
	if App.g_kConfigMapping.HasValue("Sound", "StreamVoices")  and  App.g_kConfigMapping.GetIntValue("Sound", "StreamVoices"):
		iLoadFlags = App.TGSound.LS_STREAMED

	# Try to load them at the mission level, or at the episode level if the
	# mission level fails.  If both fail, load it from bridge crew general.
	for sDescription, pScriptObject, pDatabase in lsLoaders:
		if pDatabase is None:
			# No database?  Why couldn't we get this database?
#			debug("PreloadMissionLine unable to load %s database.  Can't preload line %s." % (sDescription, sLine))
			pass
		elif pDatabase.HasString(sLine):
			if pScriptObject:
				pScriptObject.LoadDatabaseSound(pDatabase, sLine, iLoadFlags) # Don't stream.
			else:
				App.TGSound_Create(pDatabase.GetFilename(sLine), sLine, iLoadFlags)

			break

	# Check if there were problems loading the sound.
	pSound = App.g_kSoundManager.GetSound(sLine)
	if pSound:
		# Set the sound so that it unloads itself after it's been played.
		pSound.SetSingleShot(1)

		# If it's not in a sound group, put it in the mission's sound group,
		# so it's unloaded when the mission goes away.
		if not pSound.GetGroup():
			pSound.SetGroup(GetMission().GetScript())

	App.g_kLocalizationManager.Unload(pBridgeCrewGeneral)

	return 0

###############################################################################
#	PreloadSequenceLines()
#	
#	Search through the sequence that containes this action, and
#	find any actions that will play voice lines.  Stream those
#	lines into memory, so the rest of the sequence doesn't hitch
#	when it reaches those lines.
#	
#	Args:	pAction	- The action whose sequence we search.
#	
#	Return:	0
###############################################################################
def PreloadSequenceLines(pAction):
	kProfiling = App.TGProfilingInfo("MissionLib.PreloadSequenceLines")

	# Look through our sequence...
	pSequence = pAction.GetSequence()
	if pSequence:
		lsLines = GetVoiceLinesFromSequence(pSequence)
		if lsLines:
			# Stream the lines in over the next several frames.
			apply(PreloadMissionLines, (1,) + tuple(lsLines))

	return 0


###############################################################################
#	GetVoiceLinesFromSequence()
#	
#	Helper function for PreloadSequenceLines.
#	
#	Args:	TGSequence pSequence	- Sequence from which to get voice lines
#	
#	Return:	list of lines
###############################################################################
def GetVoiceLinesFromSequence(pSequence):
	lsLines = []

	# Save pSequence.GetAction as a local variable, for faster lookups of the function.
	GetSequenceAction = pSequence.GetAction

	# Search through the actions contained by this sequence...
	for iAction in range(pSequence.GetNumActions()):
		pAction = GetSequenceAction(iAction)
		if not pAction:
			continue

		# Check if the action is another sequence..
		pActSequence = App.TGSequence_Cast(pAction)
		if pActSequence:
			# Yep, it is.  Go through this sequence.
			lsLines.extend( GetVoiceLinesFromSequence(pActSequence) )
			continue

		# Check if the action is a CharacterAction.
		pActCharacter = App.CharacterAction_Cast(pAction)
		if pActCharacter:
			# If it's any of AT_SPEAK_LINE, AT_SPEAK_LINE_NO_FLAP_LIPS,
			# AT_SAY_LINE, or AT_SAY_LINE_AFTER_TURN, preload its voice line.
			if pActCharacter.GetActionType() in (
				App.CharacterAction.AT_SPEAK_LINE,
				App.CharacterAction.AT_SPEAK_LINE_NO_FLAP_LIPS,
				App.CharacterAction.AT_SAY_LINE,
				App.CharacterAction.AT_SAY_LINE_AFTER_TURN
				):
				# Yep, it is.  Add it to the list to preload...
				lsLines.append( pActCharacter.GetDetail() )

	return lsLines


###############################################################################
#	QueueActionToPlay()
#	
#	Queue up an action to play, after any other things similarly queued.
#	If there is no already playing actions, create a master sequence and add
#	ourselves to it.
#	If there is an existing master sequence playing, add ourselves to it.
#	Once the master sequence completes, the g_idMasterSequenceObj ID becomes
#	invalid, and if invalid won't be used.
#	
#	Args:	TGAction	pAction	- The action to queue up.  Probably a TGSequence
#	
#	Return:	None
###############################################################################
def QueueActionToPlay(pActionToAdd):
	global g_idMasterSequenceObj

	assert pActionToAdd
	if pActionToAdd is None:
		return

	pPlayingSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idMasterSequenceObj))

	# If the player is none or dying, bail
	pPlayer = GetPlayer()
	if (pPlayer == None) or (pPlayer.IsDying()):
		# Create event to skip action.
		pEvent = App.TGObjPtrEvent_Create()
		pEvent.SetDestination(App.g_kTGActionManager)
		pEvent.SetEventType(App.ET_ACTION_SKIP)
		pEvent.SetObjPtr(pActionToAdd)
		App.g_kEventManager.AddEvent(pEvent)

		if pPlayingSequence:
			# Create event to skip master sequence.
			pEvent = App.TGObjPtrEvent_Create()
			pEvent.SetDestination(App.g_kTGActionManager)
			pEvent.SetEventType(App.ET_ACTION_SKIP)
			pEvent.SetObjPtr(pPlayingSequence)
			App.g_kEventManager.AddEvent(pEvent)

		return

	if (pPlayingSequence):
		pPlayingSequence.AppendAction(pActionToAdd)
	else:
		pPlayingSequence = App.TGSequence_Create()
		pPlayingSequence.AddAction(pActionToAdd)
		g_idMasterSequenceObj = pPlayingSequence.GetObjID()
		pPlayingSequence.Play()


###############################################################################
#	DeleteQueuedActions()
#	
#	Delete any queued TGActions that had been requested to play.
#	
#	Args:	None
#	
#	Return:	None
###############################################################################
def DeleteQueuedActions():
	pPlayingSequence = App.TGSequence_Cast(App.TGObject_GetTGObjectPtr(g_idMasterSequenceObj))
	if (pPlayingSequence):
		pPlayingSequence.Abort()

###############################################################################
#	GrabWarpObstaclesFromSet
#	
#	Grab any obstacles in the specified path that could prevent a
#	ship from warping along that path.
#	
#	Args:	vStart		- Start of the line segment to check...
#			vEnd		- End of the segment.
#			pSet		- The set in which to search.
#			fShipRadius	- Radius around the line to check.
#			bCheckNebulas- True if nebulas are considered obstacles, false if not.
#			idIgnore	- Ignore the object with this ID.
#	
#	Return:	A list of (Object, vCenter, fSize) tuples for objects
#			that lie along the path between vStart and
#			vEnd that could get in the way of a warping ship.
###############################################################################
g_lWarpDontAvoidTypes = (
	App.CT_PROXIMITY_CHECK,
	App.CT_TORPEDO,
	App.CT_NEBULA )
def GrabWarpObstaclesFromSet(vStart, vEnd, pSet, fShipRadius, bCheckNebulas, idIgnore):
	lpEncompassingIDs = GrabWarpEncompassingObstacles(pSet, vStart, fShipRadius)

	lsObstacles = []
	if pSet:
		pProxManager = pSet.GetProximityManager()
		if not pProxManager:
			return []

		kIter = pProxManager.GetLineIntersectObjects(vStart, vEnd, fShipRadius, 1)
		while 1:
			pObject = pProxManager.GetNextObject(kIter)
			if not pObject:
				break

			# What type of object is this?  Ignore
			# certain types...
			bIgnore = 0
			for eType in g_lWarpDontAvoidTypes:
				if pObject.IsTypeOf(eType):
					bIgnore = 1
					break

			# If this is the object we ignore, ignore it..  :)
			if pObject.GetObjID() == idIgnore:
				bIgnore = 1

			# If this is an encompassing object, we need some
			# extra handling...
			if pObject.GetObjID() in lpEncompassingIDs:
				# If this is a ship or a planet, do some more specific ray casts to see if
				# we're actually going to hit it.
				pLineObstacle = App.ShipClass_Cast(pObject)
				if not pLineObstacle:
					pLineObstacle = App.Planet_Cast(pObject)

				if pLineObstacle:
					if (not pLineObstacle.LineCollides(vStart, vEnd))  and  (not pLineObstacle.LineCollides(vEnd, vStart)):
						# The line doesn't collide directly with this object.
						# It's safe to ignore it.
						bIgnore = 1
				else:
					# It's not a ship.  Ignore it.
					bIgnore = 1

			if not bIgnore:
				# Can't ignore this object.  Add
				# this to our list of obstacles
				# we need to turn away from.
				#debug("GrapWarpObstacles adding obstacle %s" % pObject.GetName())
				lsObstacles.append( (pObject, pObject.GetWorldLocation(), pObject.GetRadius()) )

		pProxManager.EndObjectIteration(kIter)

		if bCheckNebulas:
			# Add nebula spheres.
			fSqrShipRadius = fShipRadius
			fSqrShipRadius = fSqrShipRadius * fSqrShipRadius
			vFwd = App.TGPoint3()
			vFwd.Set( vEnd )
			vFwd.Subtract( vStart )
			vFwd.Unitize()
			for pNebula in pSet.GetClassObjectList( App.CT_NEBULA ):
				pNebula = App.MetaNebula_Cast( pNebula )
				if not pNebula:
					continue

				lSpheres = pNebula.GetNebulaSpheres()
				#debug("Testing %d spheres." % len(lSpheres))
				for vCenter, fRadius in lSpheres:
					# Check if this sphere encompasses us.  If so, ignore it.
					vDiff = App.TGPoint3()
					vDiff.Set( vCenter )
					vDiff.Subtract(vStart)
					if vDiff.SqrLength() < (fSqrShipRadius):
						# It encompasses us.  Skip it.
						#debug("Nebula %s encompasses warping ship." % (pNebula.GetName()))
						continue

					# It's not encompassing us.  Check if we're going to go through
					# it if we warp.
					fFwdDot = vFwd.Dot( vDiff )
					if fFwdDot <= 0.0:
						continue

					vPerpDiff = App.TGPoint3()
					vPerpDiff.Set( vFwd )
					vPerpDiff.Scale( -fFwdDot )
					vPerpDiff.Add( vDiff )
					fBadRadius = fShipRadius + fRadius
					if vPerpDiff.SqrLength() < (fBadRadius * fBadRadius):
						# This sphere is in the way.
						lsObstacles.append( (pNebula.GetName(), vCenter, fRadius) )
						break

	return lsObstacles

###############################################################################
#	GrabWarpEncompassingObstacles
#	
#	Helper function for GrabWarpObstaclesFromSet.  Grab any obstacles
#	that encompass the given location.
#	
#	Args:	pSet		- The set in which to search.
#			vLocation	- The location around which to grab objects
#			fRadius		- Radius around the location
#	
#	Return:	A list of ID's of objects that are within the given space.
###############################################################################
def GrabWarpEncompassingObstacles(pSet, vLocation, fRadius):
	lpEncompassingIDs = []
	if pSet:
		pProxManager = pSet.GetProximityManager()
		if pProxManager:
			kIter = pProxManager.GetNearObjects(vLocation, fRadius, 1)
			while 1:
				pObject = pProxManager.GetNextObject(kIter)
				if not pObject:
					break

				# What type of object is this?  Ignore
				# certain types...
				bIgnore = 0
				for eType in g_lWarpDontAvoidTypes:
					if pObject.IsTypeOf(eType):
						bIgnore = 1
						break

				if not bIgnore:
					# Can't ignore this object.  Add
					# this to our list of obstacles
					# we need to turn away from.
					lpEncompassingIDs.append(pObject.GetObjID())

			pProxManager.EndObjectIteration(kIter)

	return lpEncompassingIDs

###############################################################################
#	NewDialogueSequence()
#	
#	Create and return new TGSequence that pre-loads any voice lines.
#
#	Args:	None
#	
#	Return:	pSeq, the new TGSequence.
###############################################################################
def NewDialogueSequence(bMute = TRUE, bSoft = TRUE):
	pSeq = App.TGSequence_Create()
	if pSeq:
		pSeq.AppendAction(App.TGScriptAction_Create("MissionLib", "PreloadSequenceLines"))

	return pSeq



###############################################################################
#	PushButtons()
#	
#	pCharacter will push buttons.
#
#	Args:	pAction
#			pCharacter	- the pointer to the character you want to press buttons
#	
#	Return:	0
###############################################################################
def PushButtons(pAction, pCharacter):

	if not (pCharacter):
		return 0

	pAction = App.CharacterAction_Create(pCharacter, App.CharacterAction.AT_PLAY_ANIMATION, "PushButtons")
	pAction.Play()

	return 0

###############################################################################
#	GetFriendlyGroup
#	GetEnemyGroup
#	GetNeutralGroup
#	GetTractorGroup
#	
#	Get the Friendly/Enemy/Neutral/Tractor group for the currently
#	running mission.  If no mission is active, this returns None.
#	
#	Args:	None
#	
#	Return:	The requested group, or None
###############################################################################
def GetFriendlyGroup():
	pMission = GetMission()
	if pMission:
		return pMission.GetFriendlyGroup()
	return None

def GetEnemyGroup():
	pMission = GetMission()
	if pMission:
		return pMission.GetEnemyGroup()
	return None

def GetNeutralGroup():
	pMission = GetMission()
	if pMission:
		return pMission.GetNeutralGroup()
	return None

def GetTractorGroup():
	pMission = GetMission()
	if pMission:
		return pMission.GetTractorGroup()
	return None

###############################################################################
#	CreateCompletionEvent()
#	
#	Creates and returns completed action event.
#
#	Args:	pAction
#	
#	Return:	pEvent
###############################################################################
def CreateCompletionEvent(pAction):
	assert pAction
	pEvent = App.TGObjPtrEvent_Create()
	pEvent.SetEventType(App.ET_ACTION_COMPLETED)
	pEvent.SetDestination(App.g_kTGActionManager)
	pEvent.SetObjPtr(pAction)
	return pEvent

###############################################################################
#	IsPlayerInsideStarbase12
#	
#	Check if the player's ship is inside the Starbase12 starbase.
#	
#	Args:	None
#	
#	Return:	True if the player is in the starbase, false if not.
###############################################################################
def IsPlayerInsideStarbase12():
	# Check if the player and starbase 12 are in the Starbase12 set...
	pPlayer = App.Game_GetCurrentPlayer()
	if not pPlayer:
		return 0

	pSet = pPlayer.GetContainingSet()
	if pSet.GetName() != "Starbase12":
		return 0

	pStarbase = App.ShipClass_GetObject(pSet, "Starbase 12")
	if not pStarbase:
		return 0

	# Both are.  Check if the player is inside the starbase.
	import AI.Compound.DockWithStarbase
	return AI.Compound.DockWithStarbase.IsInViewOfInsidePoints(pPlayer, pStarbase)


###############################################################################
#	NumGroupInSet
#	
#	Count the number of ships in a group in a given set
#	or in the player's set
#	
#	Args:	pGroup 	- The Object group
#			pSet	- The set to count in.  If not specified, will use player set
#	
#	Return:	The number of ships
###############################################################################
def NumGroupInSet(pGroup, pSet = None):

	# If pSet is not given, get player set
	if pSet == None:
		pGame = App.Game_GetCurrentGame()
		pSet = pGame.GetPlayerSet()

	iNumShips = 0
	pObject = pSet.GetFirstObject()
	pFirstObject = pObject
	while not (App.IsNull(pObject)):
		if pGroup.IsNameInGroup(pObject.GetName()):
			iNumShips = iNumShips + 1

		pObject = pSet.GetNextObject(pObject.GetObjID())

		if (pObject.GetObjID() == pFirstObject.GetObjID()):
			# Exit loop
			pObject = None

	return iNumShips


################################################################################
#	DamageShip()
#
#	Randomly damage ship systems within Min/Max percentages.
#
#	Args:	sShip			- name of ship to damage.
#			fMinPercent		- minimum damage percentage.
#			fMaxPercent		- maximum damage percentage.
#			bDisableNothing	- if 1, don't disable any systems
#			bDisableWeapons - if 1, you may disable Weapon systems
#			bDisableEngines - if 1, you may disable Engine systems
#			bDisableSpecial - if 1, you may disable Repair and Cloaking systems
#
#	Return:	None
################################################################################
def DamageShip (sShipName, fMinPercent = 0.25, fMaxPercent = 0.75, bDisableNothing = 0, 
				bDisableWeapons = 0, bDisableEngines = 0, bDisableSpecial = 0):

	pShip = GetShip(sShipName, None, 1)
	if pShip == None:
		return

	lMain	 = [pShip.GetHull(), pShip.GetShields(), pShip.GetPowerSubsystem(), pShip.GetSensorSubsystem()]
	lWeapons = [pShip.GetTorpedoSystem(), pShip.GetPhaserSystem(), pShip.GetPulseWeaponSystem(), pShip.GetTractorBeamSystem()]
	lEngines = [pShip.GetImpulseEngineSubsystem(), pShip.GetWarpEngineSubsystem()]
	lSpecial = [pShip.GetRepairSubsystem(), pShip.GetCloakingSubsystem()]
	
	for pSystem in lMain:
		if pSystem:
			r = GetRandomDamage(fMinPercent, fMaxPercent)
			if bDisableNothing:
				# Make sure the system isn't disabled.
				if (r <= pSystem.GetDisabledPercentage ()):
					r = pSystem.GetDisabledPercentage () + 0.1
	
			SetConditionPercentage(pSystem, r)

	for pSystem in lWeapons:
		if pSystem:
			r = GetRandomDamage(fMinPercent, fMaxPercent)
			if bDisableNothing or not bDisableWeapons:
				# Make sure the system isn't disabled.
				if (r <= pSystem.GetDisabledPercentage ()):
					r = pSystem.GetDisabledPercentage () + 0.1
	
			SetConditionPercentage(pSystem, r)

	for pSystem in lEngines:
		if pSystem:
			r = GetRandomDamage(fMinPercent, fMaxPercent)
			if bDisableNothing or not bDisableEngines:
				# Make sure the system isn't disabled.
				if (r <= pSystem.GetDisabledPercentage ()):
					r = pSystem.GetDisabledPercentage () + 0.1
	
			SetConditionPercentage(pSystem, r)

	for pSystem in lSpecial:
		if pSystem:
			r = GetRandomDamage(fMinPercent, fMaxPercent)
			if bDisableNothing or not bDisableSpecial:
				# Make sure the system isn't disabled.
				if (r <= pSystem.GetDisabledPercentage ()):
					r = pSystem.GetDisabledPercentage () + 0.1
	
			SetConditionPercentage(pSystem, r)


#
# GetRandomDamage() - Helper Function for DamageShip()
#
def GetRandomDamage(fMinPercent, fMaxPercent):
	# Get a random number between 1 and 100
	r = App.g_kSystemWrapper.GetRandomNumber(100) + 1

	# Divide by 100 to get a percentage
	r = r / 100.0

	# Multiply by the average of Min and Max damage
	r = r * (fMaxPercent - fMinPercent)

	# Subtract from 1 and add Min damage to get amount of damage to apply
	r = 1 - (r + fMinPercent)

	return r

###############################################################################
#	PauseExtras()
#	
#	Keeps extras from moving, or allows them to move again
#	
#	Args:	pAction	- in case this is called by a script action
#			bUnpause - Let extra's move again
#
#	Return:	0		- for when this is called by a script action
###############################################################################
def PauseExtras(pAction = None, bUnpause = 0):

	if not (bUnpause == 0) and not (bUnpause == 1):
		bUnpause = 1

	App.CharacterClass_SetAllowExtras(bUnpause)

	return 0


###############################################################################
#	DeleteShipsFromWarpSetExceptFormMe()
#	
#	Deletes ships in the warp set except for the player
#	
#	Args:	pAction	- in case this is called by a script action
#	
#	Return:	0		- for when this is called by a script action
###############################################################################
def DeleteShipsFromWarpSetExceptForMe(pAction = None):
	pSet = App.WarpSequence_GetWarpSet()
	if not (pSet):
		return 0

	pPlayer = GetPlayer()
	if not (pPlayer):
		return 0

	for pShip in (pSet.GetClassObjectList(App.CT_SHIP)):
		if (pShip.GetObjID() != pPlayer.GetObjID()):
			if (pShip.GetName()):
#				debug("Deleting " + pShip.GetName() + " from warp set")
				pSet.DeleteObjectFromSet(pShip.GetName())
#			else:
#				debug("Ack, bad, there was a ship of ID " + str(pShip.GetObjID()) + " in the Warp set with no name!!")

	return 0

###############################################################################
#	IsPlayerWarping
#	
#	Check if the cutscene for the player warping someplace is still
#	playing.
#	
#	Args:	None
#	
#	Return:	True if the player is warping, false if not.
###############################################################################
def IsPlayerWarping():
	# Get the player and check if there's a warp sequence
	# controlling the player's warp engines.
	# Note that the warp engines change state to WES_NOT_WARPING
	# a little while before this cutscene is finished, which is
	# why this is checking the sequence, rather than the warp engine state.
	try:
		pPlayer = App.Game_GetCurrentPlayer()
		pWarp = pPlayer.GetWarpEngineSubsystem()
		if pWarp.GetWarpSequence():
			# Warp sequence is controlling the system.  Player is still
			# warping in.
			return 1
	except AttributeError:
		# No player or no warp engine system.  Guess the player
		# isn't warping in.
		return 0

	# Not warping in.
	return 0


###############################################################################
#	AllowExtrasAction()
#	
#	Helper function to quickly allow and disallow extras from a sequence
#	
#	Args:	pAction			- the script action that called us
#			bAllowExtras	- do we allow extras or not?
#	
#	Return:	0, to continue the sequence
###############################################################################
def AllowExtrasAction(pAction, bAllowExtras):
	App.CharacterClass_SetAllowExtras(bAllowExtras)

	return 0


###############################################################################
#	EpisodeTitleAction()
#	
#	Display the title of this episode
#	
#	Args:	pAction		- the action that called us
#			pcTitle		- the title of the episode
#			pcDatabase	- the filename of the database to use
#	
#	Return:	0, to continue the sequence
###############################################################################
def EpisodeTitleAction(pAction, pcTitle, pcDatabase = "data/TGL/Maelstrom/Maelstrom.TGL"):
	pSeq = App.TGSequence_Create()

	pTop = App.TopWindow_GetTopWindow()
	pSubtitle = pTop.FindMainWindow(App.MWT_SUBTITLE)
	pSubtitle.SetVisible()

	pDatabase = App.g_kLocalizationManager.Load(pcDatabase)

	App.TGCreditAction_SetDefaultColor(0.65, 0.65, 1.00, 1.00)
	pSeq.AddAction(App.TGCreditAction_Create(pDatabase.GetString(pcTitle), pSubtitle, 0.5, 0.025, 5, 0.25, 0.5, 12))
	App.g_kLocalizationManager.Unload(pDatabase)

	pSeq.Play()

	return 0
	
