###############################################################################
#	Filename:	Tezle2_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Tezle 2 static objects.  Called by Tezle2.py when region is created
#	
#	Created:	03/06/01 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(3000.0, 3000, 500, "data/Textures/SunBlueWhite.tga", "data/Textures/Effects/SunFlaresBlue.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Blue lens flare, attached to the sun
	Tactical.LensFlares.BlueLensFlare(pSet, pSun)

	# Model and placement for Tezle2
	pPlanet = App.Planet_Create(125.0, "data/models/environment/RootBeerPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Tezle 2")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	

	# Model and placement for Moon
	pPlanet = App.Planet_Create(80.0, "data/models/environment/TanPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Moon")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Moon1 Location")
	pPlanet.UpdateNodeOnly()
