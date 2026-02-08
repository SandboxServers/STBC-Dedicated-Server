###############################################################################
#	Filename:	GenericTemplate.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	This is a generic "ship file" template. Save this as another name, and
#	modify the data fields below to add a new ship.
#
#	Note that this is different from the hardpoint file, which is in the
#	Hardpoints subdirectory.
#	
#	Created:	8/29/00 -	Erik Novales
###############################################################################

import App
import LoadSpaceHelper
import Multiplayer.SpeciesToShip


#kDebugObj = App.CPyDebug()

def GetShipStats():
	kShipStats = {
		"FilenameHigh": "data/Models/Ships/BlahBlah.nif",	# filename of High NIF model
		"FilenameMed": "data/Models/Ships/BlahBlahMed.nif",	# filename of Med NIF model
		"FilenameLow": "data/Models/Ships/BlahBlahLow.nif",	# filename of Low NIF model
		"Name": "BlahBlah",									# name of ship. Note that
															# this will go away
															# eventually, because the
															# ship name will be set in
															# the ship property.
		"HardpointFile": "blahblah",						# file name of hardpoint file
		"Species": Multiplayer.SpeciesToShip.AKIRA			# Network species of the object
	}														# Create a new species number in
															# Multiplayer.SpeciesToShip when
															# you add a new ship type
	return kShipStats

def LoadModel(bPreLoad = 0):
	pStats = GetShipStats()

	# Create the LOD info
	if (not App.g_kLODModelManager.Contains(pStats["Name"])):
		# Params are: File Name, PickLeafSize, SwitchOut Distance,
		# Surface Damage Res, Internal Damage Res, Burn Value, Hole Value,
		# Search String for Glow, Search string for Specular, Suffix for specular
		pLODModel = App.g_kLODModelManager.Create(pStats["Name"])
		pLODModel.AddLOD(pStats["FilenameHigh"], 10,  25.0, 15.0, 15.0, 400, 900, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameMed"],  10,  50.0, 15.0, 15.0, 400, 900, "_glow", None, "_specular")
		pLODModel.AddLOD(pStats["FilenameLow"],  10, 300.0, 15.0, 30.0, 400, 900, "_glow", None, None)

#		kDebugObj = App.CPyDebug()
		if (bPreLoad == 0):
			pLODModel.Load()
#			kDebugObj.Print("Loading " + pStats["Name"] + "\n")
		else:
			pLODModel.LoadIncremental()
#			kDebugObj.Print("Queueing " + pStats["Name"] + " for pre-loading\n")

def PreLoadModel():
	LoadModel(1)
