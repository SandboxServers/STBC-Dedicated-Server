###############################################################################
#	Filename:	Beol3_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Beol 3 static objects.  Called by Beol3.py when region is created
#	
#	Created:	09/24/01 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(3000.0, 3000, 500, "data/Textures/SunBlueWhite.tga", "data/Textures/Effects/SunFlaresWhite.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Blue lens flare, attached to the sun
	Tactical.LensFlares.BlueLensFlare(pSet, pSun)

	# Model and placement for Beol 3 in Beol3 set
	pPlanet = App.Planet_Create(200.0, "data/models/environment/BlueRockyPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Beol 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
	# Model and placement for moon #1 in Beol3 set
	pMoon1 = App.Planet_Create(85.0, "data/models/environment/RockyPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Kerry")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()
	
	
	# Model and placement for moon #2 in Beol3 set
	pMoon2 = App.Planet_Create(110.0, "data/models/environment/IcePlanet.nif")
	pSet.AddObjectToSet(pMoon2, "Legare")

	# Place the object at the specified location.
	pMoon2.PlaceObjectByName("Moon2 Location")
	pMoon2.UpdateNodeOnly()