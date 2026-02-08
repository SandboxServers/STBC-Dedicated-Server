###############################################################################
#	Filename:	CameraScriptActions.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Script Actions that affect cameras.
#	
#	Created:	2/12/2001 -	KDeus
###############################################################################
import App
import Camera
import MissionLib

#NonSerializedObjects = ( "debug", )

#debug = App.CPyDebug(__name__).Print

###############################################################################
#	ChangeRenderedSet
#	
#	Change the set that's currently being rendered.
#	
#	Args:	sNewSet	- Name of the set to render.
#	
#	Return:	0
###############################################################################
def ChangeRenderedSet(pAction, sNewSet):
	pPlayer = MissionLib.GetPlayer()
	if not (pPlayer):
		return 0
	if (pPlayer.IsDying()):
		return 0

	if (sNewSet == "bridge"):
		App.g_kSetManager.MakeRenderedSet("bridge")
		pTop = App.TopWindow_GetTopWindow()
		if (pTop):
			pTop.ForceBridgeVisible()
	else:
		App.g_kSetManager.MakeRenderedSet(sNewSet)

	return 0

###############################################################################
#	SetViewscreenCamera(pAction, sSetName, sCameraName)
#	
#	Sets the viewscreen camera to the one specified.
#	
#	Args:	pAction		- the action
#			sSetName	- the name of the set to use
#			sCameraName	- the name of the camera to use. If none, uses the 
#						  active camera in the specified set.
#	
#	Return:	zero for end
###############################################################################
def SetViewscreenCamera(pAction, sSetName, sCameraName = None):
	pBridge = App.BridgeSet_Cast(App.g_kSetManager.GetSet("bridge"))
	pSet = App.g_kSetManager.GetSet(sSetName)

	if (pBridge == None) or (pSet == None):
		return 0

	pViewscreen = pBridge.GetViewScreen()
	if (sCameraName != None):
		pCamera = App.CameraObjectClass_GetObject(pSet, sCameraName)
	else:
		pCamera = pSet.GetActiveCamera()
		if (pCamera == None):
			# Try getting the player's camera from the game.
			pCamera = App.Game_GetPlayerCamera()

			if (pCamera == None):
				# Try getting "MainPlayerCamera".
				pCamera = App.CameraObjectClass_GetObject(pSet, "MainPlayerCamera")

	if (pViewscreen == None) or (pCamera == None):
		return 0

	pViewscreen.SetRemoteCam(pCamera)
	pViewscreen.SetIsOn(1)

	return 0

###############################################################################
#	SetCameraPositionAndFacing(pAction, sSetName, sCameraName,
#							   fPosX, fPosY, fPosZ,
#							   fFwdX, fFwdY, fFwdZ,
#							   fUpX, fUpY, fUpZ)
#	
#	Sets a camera's position and facing.
#	
#	Args:	pAction		- the action
#			sSetName	- the name of the set in which the camera resides
#			sCameraName	- the name of the camera
#			fPosX, Y, Z	- the position of the camera
#			fFwdX, Y, Z - the forward vector
#			fUpX, Y, Z	- the up vector
#	
#	Return:	zero for end
###############################################################################
def SetCameraPositionAndFacing(pAction, sSetName, sCameraName,
							   fPosX, fPosY, fPosZ,
							   fFwdX, fFwdY, fFwdZ,
							   fUpX, fUpY, fUpZ):
	pSet = App.g_kSetManager.GetSet(sSetName)
	if (pSet == None):
		return 0

	pCamera = App.CameraObjectClass_GetObject(pSet, sCameraName)
	if (pCamera == None):
		return 0

	kPoint = App.TGPoint3()
	kPoint.SetXYZ(fPosX, fPosY, fPosZ)

	kFwd = App.TGPoint3()
	kFwd.SetXYZ(fFwdX, fFwdY, fFwdZ)

	kUp = App.TGPoint3()
	kUp.SetXYZ(fUpX, fUpY, fUpZ)

	pCamera.SetTranslate(kPoint)
	pCamera.AlignToVectors(kFwd, kUp)

	return 0

###############################################################################
#	CutsceneCameraBegin
#	
#	Create a camera for use by cutscenes, in the specified set.
#	The new camera becomes the Active camera for that set.
#	
#	Args:	sSet	- Name of the set (eg. "bridge") in which to
#					  make a camera for cutscenes.
#			sCamera	- Name to give to the cutscene camera.  Default
#					  is "CutsceneCam".  Unless you have a good reason
#					  for using something else, leave this parameter off.
#	
#	Return:	0
###############################################################################
def CutsceneCameraBegin(pAction, sSet, sCamera = "CutsceneCam"):
	pSet = App.g_kSetManager.GetSet(sSet)
	if pSet:
		if not pSet.GetCamera(sCamera):
			# Set exists, and doesn't yet have a cutscene camera. If it's the
			# warp set, make a space camera. Otherwise, just use a regular
			# camera.
			pCamera = App.CameraObjectClass_Create(0, -40, 65, -1.55, 0, 0, 1, sCamera)

			# Put the new camera in the same place as the currently active camera.
			pActiveCam = pSet.GetActiveCamera()
			if pActiveCam:
				#pCamera.AlignToObject( pActiveCam )
				pCamera.SetMatrixRotation( pActiveCam.GetWorldRotation() )
				pCamera.SetTranslate( pActiveCam.GetWorldLocation() )

			pSet.AddCameraToSet(pCamera, sCamera)
			pCamera.UpdateNodeOnly()
			pSet.SetActiveCamera(sCamera)
		else:
			raise KeyError, "CutsceneCameraBegin(%s) has already been called on the set: %s" % (sCamera, sSet)
	else:
		raise KeyError, "Bad set name (%s) for CutsceneCameraBegin(%s); set doesn't exist." % (sSet, sCamera)

	return 0

###############################################################################
#	CutsceneCameraEnd
#	
#	Remove the camera being used for cutscenes in the specified set.
#	
#	Args:	sSet	- Name of the set (eg. "bridge") in which to
#					  remove the cutscene camera.
#			sCamera	- Name of the cutscene camera that we're done with.
#	
#	Return:	0
###############################################################################
def CutsceneCameraEnd(pAction, sSet, sCamera = "CutsceneCam"):
	pSet = App.g_kSetManager.GetSet(sSet)
	if pSet:
		if pSet.GetCamera(sCamera):
			pSet.DeleteCameraFromSet(sCamera)
		else:
			raise KeyError, "CutsceneCameraEnd(%s) called on set %s multiple times, or without a CutsceneCameraBegin call." % (sCamera, sSet)
	else:
		raise KeyError, "Bad set name (%s) for CutsceneCameraEnd(%s); set doesn't exist." % (sSet, sCamera)
	return 0

###############################################################################
#	ChaseCam
#	
#	Set the camera in the specified set to chase the given target.
#	
#	Args:	pAction		- The script action object
#			sSet		- Name of the set this takes effect in
#			sTarget		- Name of the object to chase.
#			bSweep		- True if the camera should sweep smoothly to its final
#						  position, rather than snapping immediately to it.
#			bReplace	- True if this should replace the current camera,
#						  false if it should be pushed on top of it.
#	
#	Return:	0
###############################################################################
def ChaseCam(pAction, sSet, sTarget, bSweep = 1, bReplace = 1):
	Camera.Chase(sTarget, sSet, bSweep, bReplace)
	return 0

###############################################################################
#	ReverseChaseCam
#	
#	Set the camera in the specified set to move in front of the
#	given target, looking behind it.
#	
#	Args:	pAction		- The script action object
#			sSet		- Name of the set this takes effect in
#			sTarget		- Name of the object to chase.
#			bSweep		- True if the camera should sweep smoothly to its final
#						  position, rather than snapping immediately to it.
#			bReplace	- True if this should replace the current camera,
#						  false if it should be pushed on top of it.
#	
#	Return:	0
###############################################################################
def ReverseChaseCam(pAction, sSet, sTarget, bSweep = 1, bReplace = 1):
	Camera.Reverse(sTarget, sSet, bSweep, bReplace)
	return 0

###############################################################################
#	TargetWatch
#	
#	Set the camera in the specified set to watch from one
#	object to another object, in the Target Camera mode..
#	
#	Args:	pAction	- The script action object.
#			sSet	- Name of the set this takes effect in
#			sSource	- Name of the source object to look from.
#			sTarget	- Name of the target object to look at.
#			bSweep	- True if the camera should sweep into position.
#	
#	Return:	0
###############################################################################
def TargetWatch(pAction, sSet, sSource, sTarget, bSweep = 1, bReplace = 1):
	Camera.Target(sSource, sTarget, sSet, bSweep, bReplace)
	return 0

def DropAndWatch(pAction, sSet, sTarget, bSweep = 1, bReplace = 1):
	Camera.DropAndWatch(sTarget, sSet, bSweep, bReplace)
	return 0

###############################################################################
#	PlacementWatch
#	
#	Set the camera in the specified set to watch an object
#	from a placment in that set.
#	
#	Args:	pAction		- The script action object
#			sSet		- Name of the set this takes effect in
#			sTarget		- Name of the object to watch
#			sPlacement	- Name of the placement to watch from.
#			bReplace	- True if this should replace the current camera,
#						  false if it should be pushed on top of it.
#	
#	Return:	0
###############################################################################
def PlacementWatch(pAction, sSet, sTarget, sPlacement, bReplace = 1):
	Camera.Placement(sPlacement, sTarget, sSet, 0, bReplace)
	return 0

###############################################################################
#	PlacementOffsetWatch
#	
#	Like PlacementWatch, but with a worldspace offset on the target.
#	For example, if the offset is specified as 0, 20, 0, the camera will
#	watch a place 20 units away from the target along the Y axis.
#	
#	Args:	pAction		- The script action object
#			sSet		- Name of the set this takes effect in
#			sTarget		- Name of the object to watch
#			sPlacement	- Name of the placement to watch from.
#			fOffsetX	- Worldspace X target offset.
#			fOffsetY	- Worldspace Y target offset.
#			fOffsetZ	- Worldspace Z target offset.
#	
#	Return:	0
###############################################################################
def PlacementOffsetWatch(pAction, sSet, sTarget, sPlacement, fOffsetX, fOffsetY, fOffsetZ):
	pSet, pCamera = Camera.GetSetAndCamera(sSet)
	if pSet and pCamera:
		vOffset = App.TGPoint3()
		vOffset.SetXYZ( fOffsetX, fOffsetY, fOffsetZ )

		pTarget = Camera.GetObjectOrPlacement(pSet, sTarget)
		if pTarget:
			pSource = Camera.GetObjectOrPlacement(pSet, sPlacement)
			if pSource:
				Camera.NewMode(pCamera, "Placement", 0, 1,
					[
						("Source", pSource),
						("Target", pTarget),
						("TargetOffsetWorld", vOffset)
					])

	return 0

###############################################################################
#	LockedView
#	
#	Lock the camera view to an object, looking directly at the object.
#	
#	Args:	pAction			- The script action object
#			sSet			- Name of the set whose camera we're changing
#			fDegreesAround	- Degrees around the ship (along its Fwd/Right plane) to
#							  position the camera.  Degrees start with 0 at forward,
#							  and positive numbers circling clockwise (90 degrees is
#							  right, 180 is back, 270 is left, etc.)
#			fDegreesHeight	- Degrees up to position the camera.  These start with 0
#							  in the plane of the ship, and positive numbers circling
#							  up (90 degrees is directly above, -90 is directly below, etc.)
#			fDistance		- Distance from the target to place the camera.
#			bReplace		- True if this should replace the current camera,
#							  false if it should be pushed on top of it.  This
#							  should only be false if you use PopCameraMode later
#							  to undo the effects of this camera.
#	
#	Return:	0
###############################################################################
def LockedView(pAction, sSet, sTarget, fDegreesAround, fDegreesHeight, fDistance, bReplace = 1):
	Camera.LockedSphericalLookCenter(sTarget, fDegreesAround, fDegreesHeight, fDistance, sSet, 0, bReplace)
	return 0

###############################################################################
#	LockedViewAnyAngle
#	
#	
#	
#	Args:	pAction				- The script action object
#			sSet				- Name of the set whose camera we're changing
#			fDegreesAround		- Degrees around the ship (along its Fwd/Right plane) to
#								  position the camera.  Degrees start with 0 at forward,
#								  and positive numbers circling clockwise (90 degrees is
#								  right, 180 is back, 270 is left, etc.)
#			fDegreesHeight		- Degrees up to position the camera.  These start with 0
#								  in the plane of the ship, and positive numbers circling
#								  up (90 degrees is directly above, -90 is directly below, etc.)
#			fViewDegreesAround	- Similar to fDegreesAround, but this specifies which
#								  direction the camera is looking (0 is forward)
#			fViewDegreesHeight	- Similar to fDegreesHeight, but specifying which direction
#								  the camera is looking (90 is up).
#			fDistance			- Distance from the target to place the camera.
#			bReplace			- True if this should replace the current camera,
#								  false if it should be pushed on top of it.  This
#								  should only be false if you use PopCameraMode later
#								  to undo the effects of this camera.
#	
#	Return:	0
###############################################################################
def LockedViewAnyAngle(pAction, sSet, sTarget, fDegreesAround, fDegreesHeight, fDistance,
						fViewDegreesAround, fViewDegreesUp, bReplace = 1):
	Camera.LockedSpherical(sTarget, fDegreesAround, fDegreesHeight, fDistance,
		fViewDegreesAround, fViewDegreesUp, sSet, 0, bReplace)
	return 0

###############################################################################
#	PopCameraMode
#	
#	Pop the current camera mode off the camera mode stack,
#	for the active camera in the specified set.
#	
#	Args:	pAction	- The script action object
#			sSet	- Name of the set this takes effect in.
#	
#	Return:	0
###############################################################################
def PopCameraMode(pAction, sSet):
	Camera.Pop(sSet)
	return 0

###############################################################################
#	StartCinematicMode
#	StopCinematicMode
#	
#	Switch the game into or out of Cinematic mode.  By default, this
#	automatically switches the camera to the player ship's set, and
#	does a Drop And Watch camera on it.
#	
#	Args:	pAction		- The action calling this function.
#			bInteractive- 1 if the Cinematic mode should allow input from
#						  the user, 0 if it should ignore user input (the default).
#	
#	Return:	None
###############################################################################
def StartCinematicMode(pAction, bInteractive = 0):
	# Change into cinematic mode..
	pTopWindow = App.TopWindow_GetTopWindow()
	pFocus = pTopWindow.GetFocus()
	pCinematic = App.CinematicWindow_Cast(pTopWindow.FindMainWindow(App.MWT_CINEMATIC))

	if pCinematic:
		# Only switch into Cinematic if we're not already in Cinematic..
		if (not pFocus)  or  (pFocus.GetObjID() != pCinematic.GetObjID()):
			# Toggle into cinematic.
			pTopWindow.ToggleCinematicWindow()

			# Specify whether it's interactive or not.
			pCinematic.SetInteractive(bInteractive)

	return 0

def StopCinematicMode(pAction):
	# Change out of cinematic mode..
	pTopWindow = App.TopWindow_GetTopWindow()
	pFocus = pTopWindow.GetFocus()
	pCinematic = App.CinematicWindow_Cast(pTopWindow.FindMainWindow(App.MWT_CINEMATIC))

	if pCinematic:
		# Only toggle out if we're currently in Cinematic mode.
		if pFocus  and  (pFocus.GetObjID() == pCinematic.GetObjID()):
			# Toggle out..
			pTopWindow.ToggleCinematicWindow()

			# Set it interactive again.
			pCinematic.SetInteractive(1)

	return 0

###############################################################################
#	SetModeAttribute
#	
#	Set an attribute on one of the camera modes of a camera.
#	
#	Args:	pAction	- The TGScriptAction that calls this.  (ignored)
#			sSet	- The set with the camera we'll be working with.
#			sCamera	- Name of the camera to modify.
#			sMode	- Name of the camera mode on that camera.
#			sFuncti - Name of the SetAttr(Float|ID|Point|IDObject) function to call.
#			sAttrib	- Name of the attribute to set.
#			pValue	- New value for the attribute.
#	
#	Return:	0
###############################################################################
def SetModeAttribute(pAction, sSet, sCamera, sMode, sFunction, sAttribute, pValue):
	try:
		pSet = App.g_kSetManager.GetSet(sSet)
		pCamera = pSet.GetCamera(sCamera)
		pMode = pCamera.GetNamedCameraMode(sMode)
		getattr(pMode, sFunction)(sAttribute, pValue)
	except AttributeError:
		# One of the required things didn't exist.  Oh, well.
		pass
#		debug("SetModeAttribute(%s, %s, %s, %s, %s, %s): Something failed." % (sSet, sCamera, sMode, sFunction, sAttribute, pValue))

	return 0

###############################################################################
#	WatchWarpPlacement(pAction, sSet, sCamera = None)
#	
#	Sets up a camera to watch a ship entering the set from warp.
#	
#	Args:	pAction		- the action
#			sSet		- the set name
#			sPlacement	- the placement name
#			sCamera		- the camera name to use. If none, then uses active
#						  camera
#	
#	Return:	zero for end
###############################################################################
def WatchWarpPlacement(pAction, sSet, sPlacement, sCamera = "CutsceneCam"):
	pSet = App.g_kSetManager.GetSet(sSet)

	if not pSet:
		return 0

	pCamera = App.CameraObjectClass_GetObject(pSet, sCamera)

	if not pCamera:
		return 0

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", 
							  "DropAndWatch", sSet, sPlacement)

	pAction.Play()

	pMode = pCamera.GetCurrentCameraMode()
	if not pMode:
		return 0

	pMode.SetAttrFloat("AwayDistance", -1.0)
	pMode.SetAttrFloat("ForwardOffset", 10.0)
	pMode.SetAttrFloat("SideOffset", -7.0)
	pMode.SetAttrFloat("RangeAngle1", 70.0)
	pMode.SetAttrFloat("RangeAngle2", 110.0)
	pMode.SetAttrFloat("RangeAngle3", -10.0)
	pMode.SetAttrFloat("RangeAngle4", 10.0)
	pMode.Update()
	pMode.SetAttrFloat("AwayDistance", 100000.0)
	pMode.Update()

	return 0

###############################################################################
#	WatchShipLeave(pAction, sSet, sObjectName, sCamera = "CutsceneCam")
#	
#	Sets up a camera to watch a ship leave the set (via warp).
#	
#	Args:	pAction		- the action
#			sSet		- the set name
#			sObjectName - the object name
#			sCamera		- the camera name to use. If none, then uses active
#						  camera
#	
#	Return:	
###############################################################################
def WatchShipLeave(pAction, sSet, sObjectName, sCamera = "CutsceneCam"):
	pSet = App.g_kSetManager.GetSet(sSet)

	if not pSet:
		return 0

	pCamera = App.CameraObjectClass_GetObject(pSet, sCamera)

	if not pCamera:
		return 0

	pAction = App.TGScriptAction_Create("Actions.CameraScriptActions", 
							  "DropAndWatch", sSet, sObjectName)

	pAction.Play()

	pMode = pCamera.GetCurrentCameraMode()
	if not pMode:
		return 0

	pMode.SetAttrFloat("AwayDistance", -1.0)
	pMode.SetAttrFloat("ForwardOffset", -7.0)
	pMode.SetAttrFloat("SideOffset", -7.0)
	pMode.SetAttrFloat("RangeAngle1", 230.0)
	pMode.SetAttrFloat("RangeAngle2", 310.0)
	pMode.SetAttrFloat("RangeAngle3", -10.0)
	pMode.SetAttrFloat("RangeAngle4", 10.0)
	pMode.Update()
	pMode.SetAttrFloat("AwayDistance", 100000.0)

	return 0

###############################################################################
#	PopCameraMode(pAction, sSet, sCamera = "CutsceneCam", sMode = None)
#	
#	Removes a camera mode from the mode stack.
#	
#	Args:	
#	
#	Return:	
###############################################################################
def PopCameraMode(pAction, sSet, sCamera = "CutsceneCam", sMode = None):
	pSet = App.g_kSetManager.GetSet(sSet)

	if not pSet:
		return 0

	pCamera = App.CameraObjectClass_GetObject(pSet, sCamera)

	if not pCamera:
		return 0

	if not sMode:
		pCamera.PopCameraMode()
	else:
		pCamera.PopCameraMode(sMode)

	return 0
