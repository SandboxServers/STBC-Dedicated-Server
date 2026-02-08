###############################################################################
#	Filename:	Artrus2_S.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Creates Artrus 2 static objects.  Called by Artrus2.py when region is created
#
#	Created:	01/16/01 - Jess VanDerwalker
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

	# Model and placement for Artrus 2 in Artrus2 set
	pPlanet = App.Planet_Create(90.0, "data/models/environment/RockyPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Artrus 2")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

