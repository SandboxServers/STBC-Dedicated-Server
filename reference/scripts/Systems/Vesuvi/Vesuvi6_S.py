###############################################################################
#	Filename:	Vesuvi6_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Vesuvi 6 static objects.  Called by Vesuvi6.py when region is created
#	
#	Created:	12/26/00 -	Jess VanDerwalker
###############################################################################
import App
import loadspacehelper

def Initialize(pSet):
#	print "Creating static objects for Vesuvi6 region"

	# Model and placement for Haven in Vesuvi6 set
	pPlanet = App.Planet_Create(90.0, "data/models/environment/GreenPurplePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Haven")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
	# Set the radius on the atomsphere
	pPlanet.SetAtmosphereRadius(50)

	
	# Model and placement for moon #1 in Vesuvi6 set
	pMoon1 = App.Planet_Create(80.0, "data/models/environment/RockyPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Moon 1")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()
	
	# Set the radius on the atomsphere
	pMoon1.SetAtmosphereRadius(50)

	# Create the station here so we don't have to worry about it
	# when it appears in later missions
	loadspacehelper.CreateShip("FedOutpost", pSet, "Facility", "Station Location")
	