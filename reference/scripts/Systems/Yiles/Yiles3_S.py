###############################################################################
#	Filename:	Yiles3_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Yiles 3 static objects.  Called by Yiles3.py when region is created
#	
#	Created:	09/17/01
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(2000.0, 2000, 500, "data/Textures/SunRedOrange.tga", "data/Textures/Effects/SunFlaresRedOrange.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	# Model and placement for Yiles2
	pPlanet = App.Planet_Create(90.0, "data/models/environment/IcePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Yiles 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
