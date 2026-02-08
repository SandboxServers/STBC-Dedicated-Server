###############################################################################
#	Filename:	Tevron2_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Tevron 2 static objects.  Called by Tevron2.py when region is created
#	
#	Created:	05/14/01 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(1500.0, 1500, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for Tevron 2 in Tevron2 set
	pPlanet = App.Planet_Create(200.0, "data/models/environment/IcePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Tevron 2")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	
	# Model and placement for moon #1 in Tevron2 set
	pMoon1 = App.Planet_Create(110.0, "data/models/environment/BlueWhiteGasPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Moon 1")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()