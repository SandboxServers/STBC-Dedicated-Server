import App
import Multiplayer.SpeciesToShip

def GetShipStats():
	kShipStats = {
		"FilenameHigh": "data/Models/Misc/Asteroids/asteroidh3.NIF",
		"Name": "Asteroid",
		"HardpointFile": "asteroidh3",
		"Species": Multiplayer.SpeciesToShip.ASTEROIDH3
	}
	return kShipStats

def LoadModel(bPreLoad = 0):
	pStats = GetShipStats()

	# Create the LOD info
	if (not App.g_kLODModelManager.Contains(pStats["Name"])):
		pLODModel = App.g_kLODModelManager.Create(pStats["Name"])
		pLODModel.AddLOD(pStats["FilenameHigh"], 10, 1000.0, 15.50, 15.50, 499, 500, None, None, None)

		if (bPreLoad == 0):
			pLODModel.Load()
		else:
			pLODModel.LoadIncremental()

def PreLoadModel():
	LoadModel(1)
