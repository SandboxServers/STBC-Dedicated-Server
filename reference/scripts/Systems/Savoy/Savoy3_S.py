###############################################################################
#	Filename:	Savoy3_S.py
#
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#
#	Creates Savoy 3 static objects.  Called by Savoy3.py when region is created
#
#	Created:	1/16/01 -	Jess VanDerwalker
#	Modified:	10/09/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(1000.0, 1000, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresOrange.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for "Savoy 3" in Savoy3 set
	pPlanet = App.Planet_Create(90.0, "data/models/environment/IcePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Savoy 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

