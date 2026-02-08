###############################################################################
#	Filename:	CameraModes.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Functions for creating the various named camera modes.
#	
#	Created:	2/12/2001 -	KDeus
###############################################################################
import App

def Chase(pCamera):
	pMode = App.CameraMode_Create("Chase", pCamera)

	vViewPos = App.TGPoint3()
	vViewPos.SetXYZ(0, 0, 0.1)
	vCameraPos = App.TGPoint3()
	vCameraPos.SetXYZ(0, -1.0, 0.1)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			1.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		2.0),
		( pMode.SetAttrFloat,	"Distance",				4.0),
		( pMode.SetAttrFloat,	"MaximumDistance",		40.0),
		( pMode.SetAttrPoint,	"ViewTargetOffset",		vViewPos),
		( pMode.SetAttrPoint,	"DefaultPosition",		vCameraPos),
		( pMode.SetAttrFloat,	"MaxLagDist",			2.0)
		):
		pFunc(sAttr, kValue)

	return pMode

def ReverseChase(pCamera):
	pMode = App.CameraMode_Create("Chase", pCamera)

	vViewPos = App.TGPoint3()
	vViewPos.SetXYZ(0, 0, 0.1)
	vCameraPos = App.TGPoint3()
	vCameraPos.SetXYZ(0, 1.0, 0.1)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			1.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		2.0),
		( pMode.SetAttrFloat,	"Distance",				4.0),
		( pMode.SetAttrFloat,	"MaximumDistance",		40.0),
		( pMode.SetAttrPoint,	"ViewTargetOffset",		vViewPos),
		( pMode.SetAttrPoint,	"DefaultPosition",		vCameraPos)
		):
		pFunc(sAttr, kValue)

	return pMode

def Target(pCamera):
	pMode = App.CameraMode_Create("Target", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			1.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		2.0 ),
		( pMode.SetAttrFloat,	"Distance",				4.0 ),
		( pMode.SetAttrFloat,	"MaximumDistance",		40.0 ),
		( pMode.SetAttrFloat,	"BackWatchPos",			7.95 ),
		( pMode.SetAttrFloat,	"UpWatchPos",			0.95 ),
		( pMode.SetAttrFloat,	"LookBetween",			0.05 ),
		( pMode.SetAttrFloat,	"MaxLagDist",			1.0),
		( pMode.SetAttrFloat,	"MaxUpAngleChange",		App.PI / 2.0)
		):
		pFunc(sAttr, kValue)

	return pMode

def WideTarget(pCamera):
	pMode = App.CameraMode_Create("Target", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			1.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		8.0 ),
		( pMode.SetAttrFloat,	"Distance",				32.0 ),
		( pMode.SetAttrFloat,	"MaximumDistance",		64.0 ),
		( pMode.SetAttrFloat,	"BackWatchPos",			8.0 ),
		( pMode.SetAttrFloat,	"UpWatchPos",			1.25 ),
		( pMode.SetAttrFloat,	"LookBetween",			0.05 ),
		( pMode.SetAttrFloat,	"MaxUpAngleChange",		App.PI / 2.0)
		):
		pFunc(sAttr, kValue)

	return pMode

def ZoomTarget(pCamera):
	pMode = App.CameraMode_Create("ZoomTarget", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			1.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		4.0 ),
		( pMode.SetAttrFloat,	"Distance",				4.0 ),
		( pMode.SetAttrFloat,	"MaximumDistance",		20.0 ),
		( pMode.SetAttrFloat,	"MaxLagDist",			1.0)
		):
		pFunc(sAttr, kValue)

	return pMode

def Map(pCamera):
	pMode = App.CameraMode_Create("Map", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			0.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		400.0),
		( pMode.SetAttrFloat,	"Distance",				1000.0),
		( pMode.SetAttrFloat,	"MaximumDistance",		10000.0)
		):
		pFunc(sAttr, kValue)

	return pMode

#	Old map mode:
## 	pMode = App.CameraMode_Create("Chase", pCamera)

## 	vViewPos = App.TGPoint3()
## 	vViewPos.SetXYZ(0, 0, 0)
## 	vCameraPos = App.TGPoint3()
## 	vCameraPos.SetXYZ(-0.2, -1.0, 0.6)
## 	for pFunc, sAttr, kValue in (
## 		( pMode.SetAttrFloat,	"SweepTime",			1.0 ),
## 		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
## 		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
## 		( pMode.SetAttrFloat,	"MinimumDistance",		600.0 / 4.0),
## 		( pMode.SetAttrFloat,	"Distance",				1000.0 / 4.0),
## 		( pMode.SetAttrFloat,	"MaximumDistance",		1500.0 / 4.0),
## 		( pMode.SetAttrPoint,	"ViewTargetOffset",		vViewPos),
## 		( pMode.SetAttrPoint,	"DefaultPosition",		vCameraPos)
## 		):
## 		pFunc(sAttr, kValue)

def DropAndWatch(pCamera):
	pMode = App.CameraMode_Create("DropAndWatch", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"AwayDistance",			0.0 ),
		( pMode.SetAttrFloat,	"RotateSpeed",			0.0 ),
		( pMode.SetAttrFloat,	"AnticipationTime",		2.5 ),
		( pMode.SetAttrFloat,	"ForwardOffset",		0.5 ),
		( pMode.SetAttrFloat,	"SideOffset",			3.0 ),
		( pMode.SetAttrFloat,	"AwayDistanceFactor",	1.2 ),
		( pMode.SetAttrFloat,	"AxisAvoidAngles",		45.0 ),
		( pMode.SetAttrFloat,	"SlowSpeedThreshold",	0.5 ),
		( pMode.SetAttrFloat,	"SlowRotationThreshold",0.1 ),
		( pMode.SetAttrFloat,	"RotateSpeedAccel",		0.025 ),
		( pMode.SetAttrFloat,	"MaxRotateSpeed",		0.2 ),
		):
		pFunc(sAttr, kValue)

	return pMode

def Placement(pCamera):
	pMode = App.CameraMode_Create("PlacementWatch", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"PathSpeedScale",		0.2 ),
		( pMode.SetAttrFloat,	"TimeAlongPath",		0.0 ),
		):
		pFunc(sAttr, kValue)

	return pMode

def ViewscreenZoomTarget(pCamera):
	pMode = App.CameraMode_Create("ZoomTarget", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			0.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		2.0 ),
		( pMode.SetAttrFloat,	"Distance",				8.0 ),
		( pMode.SetAttrFloat,	"MaximumDistance",		32.0 ),
		( pMode.SetAttrFloat,	"MaxLagDist",			1.0)
		):
		pFunc(sAttr, kValue)

	return pMode

def ViewscreenForward(pCamera):
	pMode = App.CameraMode_Create("Locked", pCamera)

	vPos = App.TGPoint3()
	vPos.SetXYZ(0, 2.4, 0.265)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrPoint,	"Position",			vPos ),
		( pMode.SetAttrPoint,	"Forward",			App.TGPoint3_GetModelForward() ),
		( pMode.SetAttrPoint,	"Up",				App.TGPoint3_GetModelUp() ),
		):
		pFunc(sAttr, kValue)

	return pMode

def ViewscreenLeft(pCamera):
	pMode = App.CameraMode_Create("Locked", pCamera)

	vPos = App.TGPoint3()
	vPos.SetXYZ(0, 2.4, 0.275)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrPoint,	"Position",			vPos ),
		( pMode.SetAttrPoint,	"Forward",			App.TGPoint3_GetModelLeft() ),
		( pMode.SetAttrPoint,	"Up",				App.TGPoint3_GetModelUp() ),
		):
		pFunc(sAttr, kValue)

	return pMode

def ViewscreenRight(pCamera):
	pMode = App.CameraMode_Create("Locked", pCamera)

	vPos = App.TGPoint3()
	vPos.SetXYZ(0, 2.4, 0.275)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrPoint,	"Position",			vPos ),
		( pMode.SetAttrPoint,	"Forward",			App.TGPoint3_GetModelRight() ),
		( pMode.SetAttrPoint,	"Up",				App.TGPoint3_GetModelUp() ),
		):
		pFunc(sAttr, kValue)

	return pMode

def ViewscreenBack(pCamera):
	pMode = App.CameraMode_Create("Locked", pCamera)

	vPos = App.TGPoint3()
	vPos.SetXYZ(0, 2.4, 0.275)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrPoint,	"Position",			vPos ),
		( pMode.SetAttrPoint,	"Forward",			App.TGPoint3_GetModelBackward() ),
		( pMode.SetAttrPoint,	"Up",				App.TGPoint3_GetModelUp() ),
		):
		pFunc(sAttr, kValue)

	return pMode

def ViewscreenUp(pCamera):
	pMode = App.CameraMode_Create("Locked", pCamera)

	vPos = App.TGPoint3()
	vPos.SetXYZ(0, 2.4, 0.275)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrPoint,	"Position",			vPos ),
		( pMode.SetAttrPoint,	"Forward",			App.TGPoint3_GetModelUp() ),
		( pMode.SetAttrPoint,	"Up",				App.TGPoint3_GetModelBackward() ),
		):
		pFunc(sAttr, kValue)

	return pMode

def ViewscreenDown(pCamera):
	pMode = App.CameraMode_Create("Locked", pCamera)

	vPos = App.TGPoint3()
	vPos.SetXYZ(0, 2.4, -0.275)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrPoint,	"Position",			vPos ),
		( pMode.SetAttrPoint,	"Forward",			App.TGPoint3_GetModelDown() ),
		( pMode.SetAttrPoint,	"Up",				App.TGPoint3_GetModelForward() ),
		):
		pFunc(sAttr, kValue)

	return pMode

def Locked(pCamera):
	pMode = App.CameraMode_Create("Locked", pCamera)

	vPos = App.TGPoint3()
	vPos.SetXYZ(0, 2.4, 0.275)
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrPoint,	"Position",			vPos ),
		( pMode.SetAttrPoint,	"Forward",			App.TGPoint3_GetModelForward() ),
		( pMode.SetAttrPoint,	"Up",				App.TGPoint3_GetModelUp() ),
		):
		pFunc(sAttr, kValue)

	return pMode

def FirstPerson(pCamera):
	pMode = App.CameraMode_Create("Locked", pCamera)

	vPos = App.TGPoint3()
	vPos.SetXYZ(0, 0, 0)	# All these values will be changed when this mode is enabled.
	for pFunc, sAttr, kValue in (
		( pMode.SetAttrPoint,	"Position",			vPos ),
		( pMode.SetAttrPoint,	"Forward",			App.TGPoint3_GetModelForward() ),
		( pMode.SetAttrPoint,	"Up",				App.TGPoint3_GetModelUp() ),
		):
		pFunc(sAttr, kValue)

	return pMode

def FreeOrbit(pCamera):
	pMode = App.CameraMode_Create("Map", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			1.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		30.0 ),
		( pMode.SetAttrFloat,	"Distance",				75.0 ),
		( pMode.SetAttrFloat,	"MaximumDistance",		125.0 )
		):
		pFunc(sAttr, kValue)

	return pMode

def TorpCam(pCamera):
	pMode = App.CameraMode_Create("TorpCam", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			2.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"DelayAfterTorpGone",	2.0 ),
		( pMode.SetAttrFloat,	"StartDistance",		4.0 ),
		( pMode.SetAttrFloat,	"LaterDistance",		8.0 ),
		( pMode.SetAttrFloat,	"MoveDistanceTime",		6.0 )
		):
		pFunc(sAttr, kValue)

	return pMode

def CinematicReverseTarget(pCamera):
	pMode = App.CameraMode_Create("Target", pCamera)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"SweepTime",			1.0 ),
		( pMode.SetAttrFloat,	"PositionThreshold",	0.01 ),
		( pMode.SetAttrFloat,	"DotThreshold",			0.98 ),
		( pMode.SetAttrFloat,	"MinimumDistance",		2.0 ),
		( pMode.SetAttrFloat,	"Distance",				4.0 ),
		( pMode.SetAttrFloat,	"MaximumDistance",		16.0 ),
		( pMode.SetAttrFloat,	"BackWatchPos",			7.95 ),
		( pMode.SetAttrFloat,	"UpWatchPos",			0.95 ),
		( pMode.SetAttrFloat,	"LookBetween",			0.05 ),
		( pMode.SetAttrFloat,	"MaxUpAngleChange",		App.PI / 2.0)
		):
		pFunc(sAttr, kValue)

	return pMode

def GalaxyBridgeCaptain(pCamera):
	pMode = App.CameraMode_Create("PlaceByDirection", pCamera)

	import Bridge.GalaxyBridge
	vBase = App.TGPoint3()
	apply(vBase.SetXYZ, Bridge.GalaxyBridge.GetBaseCameraPosition())

	# Move forward and up.  -Y axis is forward, +Z axis is up.
	vMovement = App.TGPoint3()
	vMovement.SetXYZ(0.0, -15.0, 15.0)

	for pFunc, sAttr, kValue in (
		( pMode.SetAttrFloat,	"StartMoveAngle",		1.25 ),
		( pMode.SetAttrFloat,	"EndMoveAngle",			2.5 ),
		( pMode.SetAttrPoint,	"BasePosition",			vBase),
		( pMode.SetAttrPoint,	"Movement",				vMovement)
		):
		pFunc(sAttr, kValue)

	return pMode
