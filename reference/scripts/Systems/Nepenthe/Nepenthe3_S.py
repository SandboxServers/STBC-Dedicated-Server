###############################################################################
#	Filename:	Nepenthe3_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Nepenthe 3 static objects.  Called by Nepenthe3.py when region is created
#	
#	Created:	09/17/00 - Alberto Fonseca
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(750.0, 750, 500)
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for Nepenthe3
	pPlanet = App.Planet_Create(270.0, "data/models/environment/PinkGasPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Nepenthe 3")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
