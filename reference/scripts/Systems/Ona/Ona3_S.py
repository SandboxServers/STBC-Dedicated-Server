###############################################################################
#	Filename:	Ona3_S.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Creates Ona 3 static objects.  Called by Ona3.py when region is created
#
#	Created:	01/16/01 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(1000.0, 1000, 500, "data/Textures/SunRed.tga", "data/Textures/Effects/SunFlaresRedOrange.tga")
	pSet.AddObjectToSet(pSun, "Sun")

	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	# Model and placement for "Ona 3" in Ona3 set
	pPlanet = App.Planet_Create(90.0, "data/models/environment/SulfurPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Ona 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

