import App
import Multiplayer.SpeciesToShip

g_dSavedCameraModeInfo = {}

def GetShipStats():
	kShipStats = {
		"FilenameHigh": "data/Models/Ships/Warbird/Warbird.nif",
		"FilenameMed": "data/Models/Ships/Warbird/WarbirdMed.nif",
		"FilenameLow": "data/Models/Ships/Warbird/WarbirdLow.nif",
		"Name": "E2M0Warbird",
		"HardpointFile": "e2m0warbird",
		"Species": Multiplayer.SpeciesToShip.WARBIRD
	}
	return kShipStats

def LoadModel(bPreLoad = 0):
	pStats = GetShipStats()

	# Create the LOD info
	if (not App.g_kLODModelManager.Contains(pStats["Name"])):
		# Params are: File Name, PickLeafSize, SwitchOut Distance,
		# Surface Damage Res, Internal Damage Res, Burn Value, Hole Value,
		# Search String for Glow, Search string for Specular, Suffix for specular
		pLODModel = App.g_kLODModelManager.Create(pStats["Name"])
		pLODModel.AddLOD(pStats["FilenameHigh"], 10,  125.0, 25.0, 25.0, 400, 900, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameMed"],  10,  250.0, 25.0, 25.0, 400, 900, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameLow"],  10, 1500.0, 25.0, 50.0, 400, 900, "_glow", None, None)

#		kDebugObj = App.CPyDebug()
		if (bPreLoad == 0):
			pLODModel.Load()
#			kDebugObj.Print("Loading " + pStats["Name"] + "\n")
		else:
			pLODModel.LoadIncremental()
#			kDebugObj.Print("Queueing " + pStats["Name"] + " for pre-loading\n")

def PreLoadModel():
	LoadModel(1)

###############################################################################
#	AdjustCameraModesForShip
#	
#	If this function exists, it is called for the player's camera,
#	in case the settings on the various camera modes need to be adjusted
#	for a specific ship type.
#	
#	Args:	pCamera	- The player's camera, in need of adjustment.
#	
#	Return:	None
###############################################################################
def AdjustCameraModesForShip(pCamera):
	FLOAT = 0
	OBJECT = 1
	POINT = 2
	lsFuncs = (
		( "GetAttrFloat", "SetAttrFloat" ),
		( "GetAttrIDObject", "SetAttrIDObject" ),
		( "GetAttrPoint", "SetAttrPoint" )
		)

	lSetValues = (
		( "Target", "BackWatchPos",		FLOAT,	8.0 ),
		( "Target", "UpWatchPos",		FLOAT,	2.0 )
		)

	lsSaved = []
	g_dSavedCameraModeInfo[pCamera.GetObjID()] = lsSaved
	for sMode, sAttribute, iType, pNewValue in lSetValues:
		pMode = pCamera.GetNamedCameraMode(sMode)
		if pMode:
			# Save old values, so they can be restored...
			# Save (Camera Mode, Attribute Name, Set Function Name, Current Value)
			lsSaved.append( (sMode, sAttribute, lsFuncs[iType][1], getattr(pMode, lsFuncs[iType][0])(sAttribute)) )

			# Set the new value.
			getattr(pMode, lsFuncs[iType][1])(sAttribute, pNewValue)

###############################################################################
#	RestoreCameraModesFromShip
#	
#	Called sometime after a call to AdjustCameraModesForShip, to
#	restore the old values of the camera modes.
#	
#	Args:	pCamera	- The camera whose modes we need to restore to
#	their old values.
#	
#	Return:	None
###############################################################################
def RestoreCameraModesFromShip(pCamera):
	if g_dSavedCameraModeInfo.has_key(pCamera.GetObjID()):
		lsInfo = g_dSavedCameraModeInfo[pCamera.GetObjID()]
		del g_dSavedCameraModeInfo[pCamera.GetObjID()]

		for sMode, sAttribute, sFunction, pValue in lsInfo:
			pMode = pCamera.GetNamedCameraMode(sMode)
			if pMode:
				getattr(pMode, sFunction)(sAttribute, pValue)
