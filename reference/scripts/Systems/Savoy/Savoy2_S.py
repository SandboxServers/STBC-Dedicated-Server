###############################################################################
#	Filename:	Savoy2_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Savoy 2 static objects.  Called by Savoy2.py when region is created
#	
#	Created:	10/02/01 - Tony Evans (Added Header)
#	Modified:	10/09/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	sSetName = pSet.GetName()

	# Add a sun, far far away
	pSun = App.Sun_Create(2500.0, 2500, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresOrange.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	pPlanet = App.Planet_Create(160.0, "data/models/environment/iceplanet.nif")
	pSet.AddObjectToSet(pPlanet, "Savoy 2")
	
	# Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
