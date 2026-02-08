###############################################################################
#	Filename:	Geble4_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Geble 4 static objects.  Called by Geble4.py when region is created
#	
#	Created:	09/24/01 - Ben Schulson
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(1000.0, 1000, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")

	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for Geble 4 in Geble4 set
	pPlanet = App.Planet_Create(120.0, "data/models/environment/RedPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Geble 4")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	
	# Model and placement for Moon in Geble4 set
	pMoon1 = App.Planet_Create(50.0, "data/models/environment/TanPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Moon 1")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()
	

