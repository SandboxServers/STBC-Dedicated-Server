###############################################################################
#	Filename:	Poseidon2_S.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Creates Poseidon 2 static objects.  
#	Called by Poseidon2.py when region is created
#
#	Created:	10/02/01 - Tony Evans
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

	# Planet and placement for "Poseidon 2" in Poseidon2 set
	pPlanet = App.Planet_Create(180.0, "data/models/environment/dryplanet.nif")
	pSet.AddObjectToSet(pPlanet, "Poseidon 2")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

