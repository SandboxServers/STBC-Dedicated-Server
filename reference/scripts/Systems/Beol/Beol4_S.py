###############################################################################
#	Filename:	Beol4_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Beol 4 static objects.  Called by Beol4.py when region is created
#	
#	Created:	02/19/00 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(2000.0, 2000, 500, "data/Textures/SunBlueWhite.tga", "data/Textures/Effects/SunFlaresWhite.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Blue lens flare, attached to the sun
	Tactical.LensFlares.BlueLensFlare(pSet, pSun)

	# Model and placement for Beol 4 in Beol4 set
	pPlanet = App.Planet_Create(115.0, "data/models/environment/SnowPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Beol 4")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
	# Model and placement for moon #1 in Beol4 set
	pMoon1 = App.Planet_Create(60.0, "data/models/environment/moon.nif")
	pSet.AddObjectToSet(pMoon1, "Moon 1")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()
	
	
	# Model and placement for moon #2 in Beol4 set
	pMoon2 = App.Planet_Create(75.0, "data/models/environment/GrayPlanet.nif")
	pSet.AddObjectToSet(pMoon2, "Moon 2")

	# Place the object at the specified location.
	pMoon2.PlaceObjectByName("Moon2 Location")
	pMoon2.UpdateNodeOnly()