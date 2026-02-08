###############################################################################
#	Filename:	Geble3_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Geble 3 static objects.  Called by Geble3.py when region is created
#	
#	Created:	03/05/01 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(2000.0, 2000, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for Geble 3 in Geble3 set
	pPlanet = App.Planet_Create(180.0, "data/models/environment/PinkGasPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Geble 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	
	# Model and placement for Moon in Geble3 set
	pMoon1 = App.Planet_Create(100.0, "data/models/environment/BrownBluePlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Moon 1")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()
	
	# Set the radius on the atomsphere
	pMoon1.SetAtmosphereRadius(100)
	
	# Model and placement for Moon2 in Geble3 set
	pMoon2 = App.Planet_Create(130.0, "data/models/environment/PurplePlanet.nif")
	pSet.AddObjectToSet(pMoon2, "Moon 2")

	# Place the object at the specified location.
	pMoon2.PlaceObjectByName("Moon2 Location")
	pMoon2.UpdateNodeOnly()