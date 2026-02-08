###############################################################################
#	Filename:	Geble2_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Geble 2 static objects.  Called by Geble2.py when region is created
#	
#	Created:	09/24/01 - Ben Schulson
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

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for Geble 2 in Geble2 set
	pPlanet = App.Planet_Create(180.0, "data/models/environment/GrayPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Geble 2")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	