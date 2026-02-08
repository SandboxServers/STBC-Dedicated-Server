###############################################################################
#	Filename:	Biranu2_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Biranu 2 static objects.  Called by Biranu1.py when region is created
#	
#	Created:	12/28/00 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(2000.0, 2000, 500)
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for Osa in Biranu 1set
	pPlanet = App.Planet_Create(160.0, "data/models/environment/SulfurPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Osa")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
	
	# Model and placement for the moon.
	pMoon = App.Planet_Create(80.0, "data/models/environment/moon.nif")
	pSet.AddObjectToSet(pMoon, "Moon")
	
	# Place the moon at the specified location
	pMoon.PlaceObjectByName("Moon Location")
	pMoon.UpdateNodeOnly()

