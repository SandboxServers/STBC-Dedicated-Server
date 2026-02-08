###############################################################################
#	Filename:	Serris3_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Serris 3 static objects.  Called by Serris3.py when region is created
#	
#	Created:	07/12/00 - Benjamin Schulson
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(2000.0, 2000, 500, "data/Textures/SunRed.tga", "data/Textures/Effects/SunFlaresRedOrange.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	# Model and placement for Serris 3 in Serris3 set
	pPlanet = App.Planet_Create(100.0, "data/models/environment/GreenPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Serris 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	
	# Model and placement for Moon in Serris3 set
	pMoon1 = App.Planet_Create(7.0, "data/models/environment/BrownPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Serris 3 Moon 1")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()
	
	# Model and placement for Moon2 in Serris3 set
	pMoon2 = App.Planet_Create(20.0, "data/models/environment/IcePlanet.nif")
	pSet.AddObjectToSet(pMoon2, "Serris 3 Moon 2")
	
	# Place the object at the specified location.
	pMoon2.PlaceObjectByName("Moon2 Location")
	pMoon2.UpdateNodeOnly()