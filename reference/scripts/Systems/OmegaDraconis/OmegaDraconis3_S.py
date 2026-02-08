###############################################################################
#	Filename:	OmegaDraconis3_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Omega Draconis 3 static objects.  
#	Called by OmegaDraconis3.py when region is created
#	
#	Created:	09/01/01 - Tony Evans
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(4000.0, 4000, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	pPlanet = App.Planet_Create(100.0, "data/models/environment/PurplePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Kessok Colony")
	
	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Colony" )
	pPlanet.UpdateNodeOnly()

