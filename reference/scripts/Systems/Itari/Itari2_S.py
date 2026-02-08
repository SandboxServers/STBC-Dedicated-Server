###############################################################################
#	Filename:	Itari2_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Itari 2 static objects.  
#	Called by Itari2.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(5000.0, 6000, 500)
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Planet
	pPlanet = App.Planet_Create(360.0, "data/models/environment/PurplePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Itari 2")

	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Planet" )
	pPlanet.UpdateNodeOnly()


