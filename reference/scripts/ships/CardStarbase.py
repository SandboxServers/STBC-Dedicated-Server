import App
import Multiplayer.SpeciesToShip

def GetShipStats():
	kShipStats = {
		"FilenameHigh": "data/Models/Bases/CardStarbase/CardStarbase.nif",
		"FilenameMed": "data/Models/Bases/CardStarbase/CardStarbaseMed.nif",
		"FilenameLow": "data/Models/Bases/CardStarbase/CardStarbaseLow.nif",
		"Name": "Cardassian Starbase",
		"HardpointFile": "cardstarbase",
		"Species": Multiplayer.SpeciesToShip.CARDSTARBASE,
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
		pLODModel.AddLOD(pStats["FilenameHigh"], 10,   400.0, 85.0,  85.0, 400, 900, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameMed"],  10,  1000.0, 85.0,  85.0, 400, 900, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameLow"],  10, 10000.0, 85.0, 100.0, 400, 900, "_glow", None, None)
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
