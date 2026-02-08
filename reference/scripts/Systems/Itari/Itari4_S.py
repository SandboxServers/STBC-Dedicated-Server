###############################################################################
#	Filename:	Itari4_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Itari 4 static objects.  
#	Called by Itari4.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(3500.0, 3500, 500)
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Planet
	pPlanet = App.Planet_Create(220.0, "data/models/environment/BrownPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Itari 4")

	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Planet" )
	pPlanet.UpdateNodeOnly()


