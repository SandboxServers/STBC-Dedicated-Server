###############################################################################
#	Filename:	Serris2_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Serris 2 static objects.  Called by Serris2.py when region is created
#	
#	Created:	02/12/00 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(3500.0, 3500, 500, "data/Textures/SunRed.tga", "data/Textures/Effects/SunFlaresRedOrange.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	# Model and placement for Serris 2 in Serris2 set
	pPlanet = App.Planet_Create(180.0, "data/models/environment/BlueWhiteGasPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Serris 2")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	
	# Model and placement for Moon in Serris2 set
	pMoon1 = App.Planet_Create(70.0, "data/models/environment/BrownPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Serris 2 Moon")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()