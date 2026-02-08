import App
import Multiplayer.SpeciesToShip

def GetShipStats():
	kShipStats = {
		"FilenameHigh": "data/Models/Bases/CardOutpost/CardOutpost.NIF",
		"FilenameMed": "data/Models/Bases/CardOutpost/CardOutpostMed.NIF",
		"FilenameLow": "data/Models/Bases/CardOutpost/CardOutpostLow.NIF",
		"Name": "Cardassian Outpost",
		"HardpointFile": "cardoutpost",
		"Species": Multiplayer.SpeciesToShip.CARDOUTPOST,
		"DamageRadMod" : 8.0,
		"DamageStrMod" : 0.125
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
		pLODModel.AddLOD(pStats["FilenameHigh"], 10,  300.0, 85.0,  85.0, 400, 900, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameMed"],  10,  800.0, 85.0,  85.0, 400, 900, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameLow"],  10, 4000.0, 85.0, 100.0, 400, 900, "_glow", None, None)
		pLODModel.SetTextureSharePath("data/Models/SharedTextures/CardBases")

#		kDebugObj = App.CPyDebug()
		if (bPreLoad == 0):
			pLODModel.Load()
#			kDebugObj.Print("Loading " + pStats["Name"] + "\n")
		else:
			pLODModel.LoadIncremental()
#			kDebugObj.Print("Queueing " + pStats["Name"] + " for pre-loading\n")

def PreLoadModel():
	LoadModel(1)
