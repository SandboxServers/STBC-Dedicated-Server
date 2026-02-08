###############################################################################
#	Filename:	Beol1_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Beol 1 static objects.  Called by Beol1.py when region is created
#	
#	Created:	09/24/01 - Jess VanDerwalker
#	Modified:	12/11/01 - Jess VanDerwalker
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):

	# Add a sun, far far away
	pSun = App.Sun_Create(5000.0, 5000, 500, "data/Textures/SunBlueWhite.tga", "data/Textures/Effects/SunFlaresWhite.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Blue lens flare, attached to the sun
	Tactical.LensFlares.BlueLensFlare(pSet, pSun)

	# Model and placement for Beol 1 in Beol1 set
	pPlanet = App.Planet_Create(185.0, "data/models/environment/BlueWhiteGasPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Beol 1")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
	# Model and placement for moon #1 in Beol1 set
	pMoon1 = App.Planet_Create(110.0, "data/models/environment/GrayPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Beol 1 Moon 1")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()


	# Model and placement for moon #2 in Beol1 set
	pMoon1 = App.Planet_Create(75.0, "data/models/environment/moon.nif")
	pSet.AddObjectToSet(pMoon1, "Beol 1 Moon 2")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon2 Location")
	pMoon1.UpdateNodeOnly()


	# Model and placement for moon #3 in Beol1 set
	pMoon1 = App.Planet_Create(140.0, "data/models/environment/PurplePlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Beol 1 Moon 3")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon3 Location")
	pMoon1.UpdateNodeOnly()
