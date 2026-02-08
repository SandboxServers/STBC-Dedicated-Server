###############################################################################
#	Filename:	Beol2_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Beol 2 static objects.  Called by Beol2.py when region is created
#	
#	Created:	09/24/01 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(4000.0, 4000, 500, "data/Textures/SunBlueWhite.tga", "data/Textures/Effects/SunFlaresWhite.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Blue lens flare, attached to the sun
	Tactical.LensFlares.BlueLensFlare(pSet, pSun)

	# Model and placement for Beol 2 in Beol2 set
	pPlanet = App.Planet_Create(200.0, "data/models/environment/GreenPurplePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Beol 2")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	# Model and placement for moon #1 in Beol2 set
	pMoon1 = App.Planet_Create(85.0, "data/models/environment/GreenPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Ohmine")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()
