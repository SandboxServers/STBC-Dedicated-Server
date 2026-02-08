###############################################################################
#	Filename:	Belaruz3_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Belaruz 3 static objects.  Called by Belaruz3.py when region is created
#	
#	Created:	9/24/00 - Alberto Fonseca
###############################################################################
import App

def Initialize(pSet):
#	print "Creating static objects for Belaruz3 region"

	# Model and placement for Belaruz3
	pPlanet = App.Planet_Create(360.0, "data/models/environment/PurplePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Belaruz 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
