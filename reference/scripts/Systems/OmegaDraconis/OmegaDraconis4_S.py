###############################################################################
#	Filename:	OmegaDraconis4_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Omega Draconis 4 static objects.  
#	Called by OmegaDraconis4.py when region is created
#	
#	Created:	09/01/01 - Tony Evans
#	Modified:	10/04/01 - Tony Evans
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

	# Builds a yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	pPlanet = App.Planet_Create(200.0, "data/models/environment/PinkGasPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Omega Draconis 4")
	
	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Planet1" )
	pPlanet.UpdateNodeOnly()
