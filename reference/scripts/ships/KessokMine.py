import App
import Multiplayer.SpeciesToShip

def GetShipStats():
	kShipStats = {
		"FilenameHigh": "data/Models/Misc/KessokMissleLauncher/KessokMissile_high.NIF",
		"FilenameLow": "data/Models/Misc/KessokMissleLauncher/KessokMissile_low.NIF",
		"Name": "KessokMine",
		"HardpointFile": "kessokmine",
		"Species": Multiplayer.SpeciesToShip.KESSOKMINE
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
		pLODModel.AddLOD(pStats["FilenameHigh"],	10, 200.0, 15.0, 15.0, 400, 1500, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameLow"], 	10, 400.0, 15.0, 15.0, 400, 1500, "_glow", None, None)

#		kDebugObj = App.CPyDebug()
		if (bPreLoad == 0):
			pLODModel.Load()
#			kDebugObj.Print("Loading " + pStats["Name"] + "\n")
		else:
			pLODModel.LoadIncremental()
#			kDebugObj.Print("Queueing " + pStats["Name"] + " for pre-loading\n")

def PreLoadModel():
	LoadModel(1)
