###############################################################################
#	Filename:	Camera.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Handy functions that used to be handled by the TacticalCamera class,
#	and are now handled (for any camera) by camera modes.
#	
#	Created:	2/27/2001 -	KDeus
###############################################################################
import App
import MissionLib

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

#
#
# High-level functions.  Nice things that work well when called from
# scripts.  These may make some assumptions (like using the Active camera) that
# the low-level functions won't.
#
#

###############################################################################
#	Various camera modes
#	
#	Using set names and object names, put the active camera in that
#	set into the requested camera mode.  If the set name isn't specified,
#	these use the Player ship's camera, by default.
#	
###############################################################################
def Chase(sTarget, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			LowChaseCam(pCamera, pTarget, bSweep, bReplace)

def Reverse(sTarget, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			LowReverseChaseCam(pCamera, pTarget, bSweep, bReplace)

def Target(sSource, sTarget, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			pSource = GetObjectOrPlacement(pSet, sSource)
			if pSource:
				LowWatchTarget(pCamera, pSource, pTarget, bSweep, bReplace)

def Map(sTarget, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			LowMapMode(pCamera, pTarget, bSweep, bReplace)

def DropAndWatch(sTarget, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			LowDropAndWatch(pCamera, pTarget, bSweep, bReplace)

def Placement(sPlacement, sTarget = None, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		if sTarget:
			pTarget = GetObjectOrPlacement(pSet, sTarget)
		else:
			pTarget = None

		pSource = GetObjectOrPlacement(pSet, sPlacement)
		if pSource:
			LowPlacementWatch(pCamera, pSource, pTarget, bSweep, bReplace)

def ZoomTarget(sSource, sTarget, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			pSource = GetObjectOrPlacement(pSet, sSource)
			if pSource:
				LowZoomTarget(pCamera, pSource, pTarget, bSweep, bReplace)

def LockedNormal(sTarget, vPosition, vForward, vUp, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			LowLocked(pCamera, pTarget, vPosition, vForward, vUp, bSweep, bReplace)

def LockedSphericalLookCenter(sTarget, fDegreesAround, fDegreesHeight, fDistance, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			# Calculate the position, based on the given spherical coordinates.
			vPos = CalcSphericalPosition(fDegreesAround, fDegreesHeight, 1.0)

			# Got the position, in vPos, as a unit vector.
			# The direction to look is -vPos, with the Up vector
			# aligned with App.TGPoint3_GetModelUp().
			vOrientationForward = App.TGPoint3()
			vOrientationForward.Set(vPos)
			vOrientationForward.Scale(-1.0)
			vOrientationRight = vOrientationForward.Cross( App.TGPoint3_GetModelUp() )
			vOrientationUp = vOrientationRight.UnitCross( vOrientationForward )

			# Finally, push the Position out by the fDistance factor...
			vPos.Scale(fDistance)

			# Done.  Pass our args to the low-level function.
			LowLocked(pCamera, pTarget, vPos, vOrientationForward, vOrientationUp, bSweep, bReplace)

def LockedSpherical(sTarget, fPositionDegreesAround, fPositionDegreesHeight, fPositionDistance,
					fForwardDegreesAround, fForwardDegreesHeight, sSet = None, bSweep = 1, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			# Calculate the position, based on the given spherical coordinates.
			vPos = CalcSphericalPosition(fPositionDegreesAround, fPositionDegreesHeight, fPositionDistance)

			# Got the position.  Calculate the forward direction, based on the
			# given spherical coordinates.
			vForward = CalcSphericalPosition(fForwardDegreesAround, fForwardDegreesHeight, 1.0)

			# Find the up vector aligned with App.TGPoint3_GetModelUp()
			vRight = vForward.Cross( App.TGPoint3_GetModelUp() )
			vUp = vRight.UnitCross( vForward )

			# Done.  Pass our args to the low-level function.
			LowLocked(pCamera, pTarget, vPos, vForward, vUp, bSweep, bReplace)

def FirstPerson(sTarget, sSet = None, bReplace = 1):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		pTarget = GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			LowFirstPerson(pCamera, pTarget, bReplace)

def Pop(sSet = None, sMode = None):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		LowPop(pCamera, sMode)

###############################################################################
#	CalcSphericalPosition
#	
#	Calculate a model-space position vector from the given spherical
#	coordinates.  Degrees around start at forward and circle around
#	to right, back, then left.  Degrees height start in the fwd/right
#	plane and go to Up at 90, down at -90.
#	
#	Args:	fDegreesAround	- Degrees around the fwd/right plane.
#			fDegreesHeight	- Degrees up/down
#			fDistance		- Distance from <0, 0, 0>
#	
#	Return:	A TGPoint3 with the requested position.
###############################################################################
def CalcSphericalPosition(fDegreesAround, fDegreesHeight, fDistance):
	# Degrees Around specify degrees, with 0 being forward, 90
	# being right, 180 being back, 270 being left.  (Clockwise from
	# forward).
	# Degrees Height has 0 forward, 90 up, -90 down.
	fRadiansAround = fDegreesAround * App.PI / 180.0
	fRadiansHeight = fDegreesHeight * App.PI / 180.0
	import math
	# Calculate position along the fwd/right plane.
	vFwd = App.TGPoint3_GetModelForward()
	vRight = App.TGPoint3_GetModelRight()
	vFwd.Scale( math.cos(fRadiansAround) )
	vRight.Scale( math.sin(fRadiansAround) )
	vPos = vFwd
	vPos.Add(vRight)

	# Calculate position along the vPos/Up plane.
	vUp = App.TGPoint3_GetModelUp()
	vPos.Scale( math.cos(fRadiansHeight) )
	vUp.Scale( math.sin(fRadiansHeight) )
	vPos.Add(vUp)

	# Got the position, in vPos, as a unit vector.
	# Scale it to the right distance.
	vPos.Scale(fDistance)

	return vPos


###############################################################################
#	Various info retrieval functions
#	
#	From the given set name, get the active camera in that set
#	and retrieve information from it.  If the set isn't specified,
#	these use the Player's set, by default.
#	
#	
###############################################################################
def GetChaseObject(sSet = None):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		return LowGetChaseObject(pCamera)

def GetWatchTargetSource(sSet = None):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		return LowGetWatchTargetSource(pCamera)

def GetWatchTargetDestination(sSet = None):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		return LowGetWatchTargetDestination(pCamera)

def GetMapModeCenter(sSet = None):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		return LowGetMapModeCenter(pCamera)

def GetDropAndWatchObject(sSet = None):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		return LowGetDropAndWatchObject(pCamera)

def GetPlacementWatchObject(sSet = None):
	pSet, pCamera = GetSetAndCamera(sSet)
	if pSet and pCamera:
		return LowPlacementWatchObject(pCamera)



#
#
# Low-level functions.  These take objects and deal with them directly:
#
#

###############################################################################
#	Various camera modes, with their arguments.
#	
#	A long series of really simple functions to setup the various
#	camera modes available.
#	
#	Args:	pCamera		- The camera to act on.
#			bSweep		- True if the camera should sweep smoothly from its
#						  current position to its destination, false if it
#						  should snap there instantly.
#			bReplace	- True if this should replace the current camera
#						  mode, false if it should be pushed on top of it.
#	
#	Return:	1 on success, 0 on failure.
###############################################################################
def LowChaseCam(pCamera, pTarget, bSweep = 1, bReplace = 1):
	NewMode(pCamera, "Chase", bSweep, bReplace, [("Target", pTarget)])

def LowReverseChaseCam(pCamera, pTarget, bSweep = 1, bReplace = 1):
	NewMode(pCamera, "ReverseChase", bSweep, bReplace, [("Target", pTarget)])

def LowWatchTarget(pCamera, pSource, pTarget, bSweep = 1, bReplace = 1):
	NewMode(pCamera, "Target", bSweep, bReplace,
		[
		("Source",	pSource),
		("Target",	pTarget)
		])

def LowMapMode(pCamera, pTarget, bSweep = 1, bReplace = 1):
	NewMode(pCamera, "Map", bSweep, bReplace, [("Target", pTarget)])

def LowDropAndWatch(pCamera, pTarget, bSweep = 1, bReplace = 1):
	NewMode(pCamera, "DropAndWatch", bSweep, bReplace, [("Target", pTarget)])

def LowPlacementWatch(pCamera, pPlacement, pTarget, bSweep = 1, bReplace = 1):
	NewMode(pCamera, "Placement", bSweep, bReplace,
		[
		("Source", pPlacement),
		("Target", pTarget)
		])

def LowZoomTarget(pCamera, pSource, pTarget, bSweep = 1, bReplace = 1):
	NewMode(pCamera, "ZoomTarget", bSweep, bReplace,
		[
		("Source",	pSource),
		("Target",	pTarget)
		])

def LowLocked(pCamera, pTarget, vPos, vFwd, vUp, bSweep = 1, bReplace = 1):
	NewMode(pCamera, "Locked", bSweep, bReplace,
		[
		("Target", pTarget),
		("Position", vPos),
		("Forward", vFwd),
		("Up", vUp)
		])

def LowFirstPerson(pCamera, pTarget, bReplace = 1):
	# Get first person position information from the target object.
	vPos, vFwd, vUp = MissionLib.GetPositionOrientationFromProperty(pTarget, "FirstPersonCamera")
	if not (vPos and vFwd and vUp):
		raise KeyError, "Ship %s model has no Position/Orientation hardpoint \"FirstPersonCamera\"." % pTarget.GetName()

	NewMode(pCamera, "FirstPerson", 0, bReplace,
		[
		("Target", pTarget),
		("Position", vPos),
		("Forward", vFwd),
		("Up", vUp)
		])

def LowPop(pCamera, sMode):
	pCamera.PopCameraMode(sMode)

def SetupViewscreenModeFromHardpoint(pMode, pTarget, sHardpointName):
	vPos, vFwd, vUp = MissionLib.GetPositionOrientationFromProperty(pTarget, sHardpointName)

	pMode.SetAttrIDObject("Target", pTarget)
	if vPos and vFwd and vUp:
		pMode.SetAttrPoint("Position", vPos)
		pMode.SetAttrPoint("Forward", vFwd)
		pMode.SetAttrPoint("Up", vUp)
#	else:
#		print __name__ + ".SetupViewscreenModeFromHardpoint: Object (%s) has no hardpoint (%s)" % (pTarget.GetName(), sHardpointName)

###############################################################################
#	Various object retrieval functions.
#	
#	These are called generally so the caller can make some assumptions
#	about the current camera mode, and retrieve information about it.
#	If their assumptions are wrong, these return some sort of None or
#	None-like result, as appropriate.
#	
#	Args:	None
#	
#	Return:	The info requested, or None
###############################################################################
def LowGetChaseObject(pCamera):
	return GetModeInfo(pCamera, App.ChaseCameraMode_Cast, "Target")

def LowGetWatchTargetSource(pCamera):
	return GetModeInfo(pCamera, App.TargetCameraMode_Cast, "Source")

def LowGetWatchTargetDestination(pCamera):
	return GetModeInfo(pCamera, App.TargetCameraMode_Cast, "Target")

def LowGetMapModeCenter(pCamera):
	return GetModeInfo(pCamera, App.MapCameraMode_Cast, "Target")

def LowGetDropAndWatchObject(pCamera):
	return GetModeInfo(pCamera, App.DropAndWatchMode_Cast, "Target")

def LowGetPlacementWatchObject(pCamera):
	return GetModeInfo(pCamera, App.PlacementWatchMode_Cast, "Target")

def LowGetLockedObject(pCamera):
	return GetModeInfo(pCamera, App.LockedPositionMode_Cast, "Target")

###############################################################################
#	GetObjectOrPlacement
#	
#	Get the named object, whether it's ObjectClass-derived or
#	PlacementObject-derived.
#	
#	Args:	pSet		- The set to retrieve it from.
#			sObjectName	- Name of the object.
#	
#	Return:	The requested object, or None.
###############################################################################
def GetObjectOrPlacement(pSet, sObjectName):
	pObject = App.ObjectClass_GetObject(pSet, sObjectName)
	if not pObject:
		pObject = App.PlacementObject_GetObject(pSet, sObjectName)

	return pObject

###############################################################################
#	GetSetAndCamera
#	
#	Get the requested Set and the active camera from that set.
#	
#	Args:	sSet	- Name of the set.  If this is None, this gets
#					  the player ship's camera (and set).
#	
#	Return:	(pSet, pCamera), or (None, None)
###############################################################################
def GetSetAndCamera(sSet = None):
	if sSet is not None:
		pSet = App.g_kSetManager.GetSet(sSet)
		if not pSet:
			# The set might be a region module pathname.
			try:
				pModule = __import__(sSet)
				pSet = pModule.GetSet()
			except (ImportError, NameError):
				pass
	else:
		pGame = App.Game_GetCurrentGame()
		if pGame:
			pCamera = pGame.GetPlayerCamera()
			if pCamera:
				pSet = pCamera.GetContainingSet()
				return (pSet, pCamera)
			else:
				# No player camera, somehow.  Get the player's set.
				pSet = pGame.GetPlayerSet()

	if pSet:
		return (pSet, pSet.GetActiveCamera())

	return (None, None)

###############################################################################
#	NewMode
#	
#	Low level function that takes a camera, the name of a named
#	camera mode, the sweep/replace arguments, and a list of pairs
#	of setup function names and argument tuples to pass to those
#	functions, for setting up the mode.
#	
#	Args:	pCamera		- The camera to apply the new mode to.
#			sMode		- Name of the named camera mode to use.
#			bSweep		- Whether or not to sweep smoothly into position.
#			bReplace	- True to replace the current mode, false to push
#						  on top of it.
#			lSetup		- A list (or tuple) of pairs.  Each pair contains
#						  the name of an attribute to set on the camera mode
#						  and the argument to pass to that function.  The type
#						  of attribute to set is guessed from the type of the
#						  argument.
#	
#	Return:	1 on success, 0 on failure.
###############################################################################
def NewMode(pCamera, sMode, bSweep, bReplace, lSetup, UseInvalid = 0):
	if not pCamera:
		return 0

	# Get the requested camera mode.
	pMode = pCamera.GetNamedCameraMode(sMode)
	if not pMode:
		return 0

	# Replace or add to the camera mode.
	if pMode:
		# Setup the attributes for this mode, first
		for sAttribute, pArgument in lSetup:
			# Determine which type of attribute to set:
			if isinstance(pArgument, App.ObjectClass)  or  (pArgument is None):
				pFunc = pMode.SetAttrIDObject
			elif isinstance(pArgument, App.TGPoint3):
				pFunc = pMode.SetAttrPoint
			else:
				pFunc = pMode.SetAttrFloat

			# Call the function with the given arg.
			pFunc(sAttribute, pArgument)

		# If the mode is valid now, give it to the camera.
		if pMode.IsValid()  or  UseInvalid:
			# If it's already the active mode, do nothing more.
			pCurrentMode = pCamera.GetCurrentCameraMode(0)
			if pCurrentMode  and  (pCurrentMode.GetObjID() == pMode.GetObjID()):
				return 1

			if bReplace:
				# Replace the current camera mode with this mode.
				pCamera.PopCameraMode()

			# Put in the new camera mode.
			pCamera.PushCameraMode(pMode)

			# If it needs to be snapped into position, do so.
			if not bSweep:
				# Get the current camera mode, which may not be
				# the mode we pushed, if the mode we pushed was invalid.
				pSnapMode = pCamera.GetCurrentCameraMode()
				try:
					pSnapMode.SnapToIdealPosition()
				except AttributeError:
					pass
	
			pMode.Update()

			# Success.
			return 1

	# Failure.  No mode, or the mode wasn't valid.
	return 0

###############################################################################
#	GetModeInfo
#	
#	Low-level function to retrieve information from the given
#	camera if the camera is in a specific camera mode.
#	
#	Args:	pCamera			- The camera to get information from.
#			pModeCastFunc	- The Cast function for the desired camera mode.
#			sAttribute		- The attribute to get from that camera mode.
#	
#	Return:	The requested info, or None.
###############################################################################
def GetModeInfo(pCamera, pModeCastFunc, sAttribute):
	if not pCamera:
		return None

	# Is the camera in the required mode?
	pMode = pModeCastFunc(pCamera.GetCurrentCameraMode())
	if pMode:
		# Yep.  Get the requested attribute.
		return pMode.GetAttrIDObject(sAttribute)

	return None



###############################################################################
#	KeepCameraInPlayerSet
#	
#	Setup event handlers to keep the given camera in the same
#	set as the player ship, at all times, even as the player moves
#	across different sets and (ideally) missions.
#	
#	Args:	pCamera	- The camera to keep in the player's set.
#	
#	Return:	None
###############################################################################
g_dCameraPlayerInfo = {}

def KeepCameraInPlayerSet(pCamera):
	if g_dCameraPlayerInfo.has_key(pCamera.GetObjID()):
		# This camera is already being kept in the player's set.
		return

	# Check if the player exists right now, and if we're in
	# the right set.
	CheckPlayer(pCamera)

	# Need to setup a broadcast handler listening for the ET_SET_PLAYER event.
	App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pCamera, __name__ + ".PlayerChanged");

	# And listen for when the player enters a set.
	pGame = App.Game_GetCurrentGame()
	pPlayerGroup = pGame.GetPlayerGroup()
	App.g_kEventManager.AddBroadcastPythonFuncHandler(
		App.ET_OBJECT_GROUP_OBJECT_ENTERED_SET,
		pCamera,
		__name__ + ".PlayerEnteredSet",
		pPlayerGroup);

###############################################################################
# Event handlers and sub-functions for KeepCameraInPlayerSet
#
def CheckPlayer(pCamera):
	#print __name__ + ".CheckPlayer"
	# Grab the current the player's ID, for future reference.
	idPlayer = App.NULL_ID
	pPlayer = App.Game_GetCurrentPlayer()
	if pPlayer:
		idPlayer = pPlayer.GetObjID()

		# Player exists.  Make sure we're in the right set.
		PlaceCameraInPlayerSet(pCamera, pPlayer)

	# Save info about the camera.
	g_dCameraPlayerInfo[pCamera.GetObjID()] = idPlayer

def PlaceCameraInPlayerSet(pCamera, pPlayer):
	#print __name__ + ".PlaceCameraInPlayerSet"
	pCameraSet = pCamera.GetContainingSet()
	pPlayerSet = pPlayer.GetContainingSet()
	if pPlayerSet:
		# If the camera was active in the old set, it should
		# be active in the new set.
		iActive = 0
		#if pCameraSet:
		#	pActiveCamera = pCameraSet.GetActiveCamera()
		#	if pActiveCamera  and  (pActiveCamera.GetObjID() == pCamera.GetObjID()):
		#		iActive = 1

		if not (pCameraSet  and  (pCameraSet.GetName() == pPlayerSet.GetName())):
			#print __name__ + ".PlaceCameraInPlayerSet: Has to move sets."
			# Camera's in the wrong set, or isn't in a set at all.
			if pCameraSet:
				#print __name__ + ".PlaceCameraInPlayerSet: Removing from set %s." % pCameraSet.GetName()
				pCameraSet.RemoveCameraFromSet(pCamera.GetName())
			#print __name__ + ".PlaceCameraInPlayerSet: Adding to set %s (active is %d)." % (pPlayerSet.GetName(), iActive)
			pPlayerSet.AddCameraToSet(pCamera, pCamera.GetName())

			if iActive:
				pPlayerSet.SetActiveCamera(pCamera.GetName())

def PlayerChanged(pCamera, pEvent):
	#print __name__ + ".PlayerChanged"
	# Check if the player exists right now, and if we're in
	# the right set.
	CheckPlayer(pCamera)

def PlayerEnteredSet(pCamera, pEvent):
	#print __name__ + ".PlayerEnteredSet"
	# Check if we're in the right set.
	CheckPlayer(pCamera)
#
#
###############################################################################

###############################################################################
#	MakePlayerCamera
#	
#	Create the main Player camera, that follows the player around
#	(always in the same set as the player's ship).
#	
#	Args:	None
#	
#	Return:	The ID of the created camera.
###############################################################################
def MakePlayerCamera():
	pCamera = App.SpaceCamera_Create("MainPlayerCamera")
	if pCamera:
		KeepCameraInPlayerSet(pCamera)

		# It needs some special named modes which are always invalid.
		pCamera.AddNamedCameraMode("InvalidViewscreen", App.CameraMode_Create("Chase", pCamera));
		pCamera.AddNamedCameraMode("InvalidSpace", App.CameraMode_Create("Chase", pCamera));
		pCamera.AddNamedCameraMode("InvalidCinematic", App.CameraMode_Create("Chase", pCamera));
		pCamera.AddNamedCameraMode("InvalidMap", App.CameraMode_Create("Chase", pCamera));

		# Setup the mode hierarchy.  By default, viewscreen mode (using "InvalidViewscreen")
		# falls to ViewscreenZoomTarget, which falls to ViewscreenForward.
		pCamera.AddModeHierarchy("InvalidViewscreen", "ViewscreenZoomTarget")
		pCamera.AddModeHierarchy("ViewscreenZoomTarget", "ViewscreenForward")

		# And the hierarchy for the space modes.
		pCamera.AddModeHierarchy("InvalidSpace", "Target")
		pCamera.AddModeHierarchy("Target", "Chase")
		pCamera.AddModeHierarchy("ZoomTarget", "Chase")

		# Cinematic modes.
		pCamera.AddModeHierarchy("InvalidCinematic", "DropAndWatch")
		pCamera.AddModeHierarchy("TorpCam", "Chase")
		pCamera.AddModeHierarchy("CinematicReverseTarget", "Chase")

		# Map mode.
		pCamera.AddModeHierarchy("InvalidMap", "Map")

		# Need an event handler for when the player changes.
		App.g_kEventManager.AddBroadcastPythonFuncHandler(App.ET_SET_PLAYER, pCamera, __name__ + ".MakePlayerCamera_PlayerChanged");
		pPlayer = App.Game_GetCurrentPlayer()
		if pPlayer:
			MakePlayerCamera_PlayerChanged(pCamera)

		return pCamera.GetObjID()

	return App.NULL_ID

###############################################################################
# Event handlers and sub-functions for MakePlayerCamera
#
g_idOldPlayerID = None
g_sOldPlayerShipScript = None

def ClearGlobals():
	global g_idOldPlayerID, g_sOldPlayerShipScript
	g_idOldPlayerID = None
	g_sOldPlayerShipScript = None

def MakePlayerCamera_PlayerChanged(pCamera, pEvent = None):
	global g_idOldPlayerID
	pPlayer = App.Game_GetCurrentPlayer()

	# Remove handlers for the old player.
	if g_idOldPlayerID is not None:
		pOldPlayer = App.ShipClass_GetObjectByID(None, g_idOldPlayerID)
		if pOldPlayer:
			pOldPlayer.RemoveHandlerForInstance(App.ET_TARGET_WAS_CHANGED, __name__ + ".PlayerTargetChanged")
		g_idOldPlayerID = None

	# Undo camera mode changes from the old ship.
	if g_sOldPlayerShipScript:
		RestoreCameraModesFromShip(g_sOldPlayerShipScript)

	# Setup the camera's modes so they're centered around the player.
	for sMode, sAttr in (
		("Chase",					"Target"),
		("Target",					"Source"),
		("ReverseChase",			"Target"),
		("ZoomTarget",				"Source"),
		("Map",						"Target"),
		("WideTarget",				"Source"),
		("FreeOrbit",				"Target"),
		("DropAndWatch",			"Target"),
		("ViewscreenZoomTarget",	"Source"),
		("ViewscreenForward",		"Target"),
		("ViewscreenBack",			"Target"),
		("ViewscreenLeft",			"Target"),
		("ViewscreenRight",			"Target"),
		("ViewscreenUp",			"Target"),
		("ViewscreenDown",			"Target"),
		("FirstPerson",				"Target"),
		("TorpCam",					"Target"),
		("CinematicReverseTarget",	"Target")):

		pMode = pCamera.GetNamedCameraMode(sMode)
		if pMode:
			pMode.SetAttrIDObject(sAttr, pPlayer)

	if pPlayer:
		# Save the player's ID for later.
		g_idOldPlayerID = pPlayer.GetObjID()

		# Some of the camera modes need special adjustments based on what
		# kind of ship the player now has.  Make those adjustments.
		AdjustModesForShip(pCamera, pPlayer)

		# Add an event handler for when the player's target changes, so we
		# can update the modes that need to know about that.
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_TARGET_WAS_CHANGED, __name__ + ".PlayerTargetChanged")
		#pPlayer.AddPythonFuncHandlerForInstance(App.ET_TARGET_OFFSET_CHANGED, __name__ + ".PlayerTargetOffsetChanged")
		pPlayer.AddPythonFuncHandlerForInstance(App.ET_TARGETED_SUBSYSTEM_CHANGED, __name__ + ".PlayerTargetOffsetChanged")

		# Setup the viewscreen mode positions from the new ship.
		for sMode in (
			"ViewscreenForward",
			"ViewscreenBack",
			"ViewscreenLeft",
			"ViewscreenRight",
			"ViewscreenUp",
			"ViewscreenDown",
			"FirstPerson" ):

			pMode = pCamera.GetNamedCameraMode(sMode)
			if pMode:
				SetupViewscreenModeFromHardpoint(pMode, pPlayer, sMode)

def AdjustModesForShip(pCamera, pShip):
	# Get the ship module for this ship.
	pModule = __import__(pShip.GetScript())

	# If the module has a function for adjusting camera modes, call it.
	if hasattr(pModule, "AdjustCameraModesForShip"):
		getattr(pModule, "AdjustCameraModesForShip")(pCamera)

def RestoreCameraModesFromShip(sScript):
	# Get the ship module for this ship.
	pModule = __import__(sScript)

	# If the module has a function for restoring camera modes, call it.
	if hasattr(pModule, "RestoreCameraModesForShip"):
		getattr(pModule, "RestoreCameraModesForShip")(pCamera)

def PlayerTargetChanged(pPlayer, pEvent):
	# The player's target changed.  Update all the camera modes that depend on the
	# player's target.
	pGame = App.Game_GetCurrentGame()
	if pGame:
		pCamera = pGame.GetPlayerCamera()
		pTarget = pPlayer.GetTarget()
		for sMode in (
			"Target",
			"ZoomTarget",
			"ViewscreenZoomTarget",
			"WideTarget" ):

			pMode = pCamera.GetNamedCameraMode(sMode)
			if pMode:
				pMode.SetAttrIDObject("Target", pTarget)

	pPlayer.CallNextHandler(pEvent)

def PlayerTargetOffsetChanged(pPlayer, pEvent):
	pGame = App.Game_GetCurrentGame()
	if pGame:
		pCamera = pGame.GetPlayerCamera()

		# Change the target ofset for the Target camera mode.
		pMode = pCamera.GetNamedCameraMode("Target")
		if pMode:
			pMode.SetAttrPoint("BetweenPositionStart", pMode.GetAttrPoint("TargetOffset"))
			pMode.SetAttrFloat("BetweenTimeStart", App.g_kUtopiaModule.GetGameTime())
			pMode.SetAttrPoint("TargetOffset", pPlayer.GetTargetOffsetTG())

	pPlayer.CallNextHandler(pEvent)

def GetPlayerCamera():
	pGame = App.Game_GetCurrentGame()
	if pGame:
		return pGame.GetPlayerCamera()
	return App.NULL_ID

def PlayerCameraAsViewscreen():
	#print __name__ + ": As viewscreen"
	pCamera = GetPlayerCamera()
	if pCamera:
		# Set its current mode to viewscreen mode.
		NewMode(pCamera, "InvalidViewscreen", 0, 1, (), UseInvalid = 1)
		pCamera.Update(App.g_kUtopiaModule.GetGameTime())

def PlayerCameraAsSpace():
	#print __name__ + ": As space"
	pCamera = GetPlayerCamera()
	if pCamera:
		# Set its current mode to space mode.
		NewMode(pCamera, "InvalidSpace", 0, 1, (), UseInvalid = 1)
		pCamera.Update(App.g_kUtopiaModule.GetGameTime())

def PlayerCameraAsCinematic():
	#print __name__ + ": As cinematic"
	pCamera = GetPlayerCamera()
	if pCamera:
		# Set its current mode to cinematic mode.
		NewMode(pCamera, "InvalidCinematic", 0, 1, (), UseInvalid = 1)
		pCamera.Update(App.g_kUtopiaModule.GetGameTime())

def PlayerCameraAsMap():
	#print __name__ + ": As map"
	pCamera = GetPlayerCamera()
	if pCamera:
		# Set its current mode to map mode.
		NewMode(pCamera, "InvalidMap", 0, 1, (), UseInvalid = 1)
		pCamera.Update(App.g_kUtopiaModule.GetGameTime())
#
#
###############################################################################
