###############################################################################
#	Filename:	Tevron1_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Tevron 1 static objects.  Called by Tevron1.py when region is created
#	
#	Created:	08/02/01 - Jess VanDerwalker
#	Modified:	12/11/01 - Jess VanDerwalker
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(3000.0, 3000, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for Tevron 1 in Tevron1 set
	pPlanet = App.Planet_Create(190.0, "data/models/environment/TanGasPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Tevron 1")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Placement")
	pPlanet.UpdateNodeOnly()

	
	# Model and placement for moon #1 in Tevron1 set
	pMoon1 = App.Planet_Create(70.0, "data/models/environment/SulfurPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Tevron 1 Moon 1")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Placement")
	pMoon1.UpdateNodeOnly()
	
	
	# Model and placement for moon #2 in Tevron1 set
	pMoon2 = App.Planet_Create(105.0, "data/models/environment/TanPlanet.nif")
	pSet.AddObjectToSet(pMoon2, "Tevron 1 Moon 2")

	# Place the object at the specified location.
	pMoon2.PlaceObjectByName("Moon2 Placement")
	pMoon2.UpdateNodeOnly()