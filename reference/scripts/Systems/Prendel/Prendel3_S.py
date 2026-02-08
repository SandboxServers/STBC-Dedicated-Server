###############################################################################
#	Filename:	Prendel1_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Prendel 1 static objects.  Called by Prendel1.py when region is created
#	
#	Created:	10/02/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(2000.0, 2000, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	#Blue White Planet
	pPlanet = App.Planet_Create(360.0, "data/models/environment/PurplePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Prendel 3")

	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Planet" )
	pPlanet.UpdateNodeOnly()

	#Moon2
	pMoon2 = App.Planet_Create(90.0, "data/models/environment/Moon.nif")
	pSet.AddObjectToSet(pMoon2, "Moon 1")

	# Place the object at the specified location.
	pMoon2.PlaceObjectByName( "Moon2" )
	pMoon2.UpdateNodeOnly()

	#Moon1
	pMoon1 = App.Planet_Create(90.0, "data/models/environment/GrayPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Moon 2")

	# Place the object at the specified location.
	pMoon1.PlaceObjectByName( "Moon1" )
	pMoon1.UpdateNodeOnly()
