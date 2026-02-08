###############################################################################
#	Filename:	Artrus3_S.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Creates Artrus 3 static objects.  Called by Artrus3.py when region is created
#
#	Created:	01/16/01 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(1000.0, 1000, 500, "data/Textures/SunBlueWhite.tga", "data/Textures/Effects/SunFlaresWhite.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Blue lens flare, attached to the sun
	Tactical.LensFlares.BlueLensFlare(pSet, pSun)

	# Model and placement for Artrus 3 in Artrus3 set
	pPlanet = App.Planet_Create(90.0, "data/models/environment/BlueRockyPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Artrus 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

