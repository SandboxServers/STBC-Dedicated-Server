###############################################################################
#	Filename:	Belaruz2_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Belaruz 2 static objects.  Called by Belaruz2.py when region is created
#	
#	Created:	9/24/00 - Alberto Fonseca
###############################################################################
import App

def Initialize(pSet):
#	print "Creating static objects for Belaruz2 region"

	# Model and placement for Belaruz2
	pPlanet = App.Planet_Create(120.0, "data/models/environment/BlueRockyPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Belaruz 2")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
