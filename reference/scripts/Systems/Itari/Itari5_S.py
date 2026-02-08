###############################################################################
#	Filename:	Itari5_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Itari 5 static objects.  
#	Called by Itari5.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(3000.0, 3000, 500)
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	#Planet
	pPlanet = App.Planet_Create(360.0, "data/models/environment/dryplanet.nif")
	pSet.AddObjectToSet(pPlanet, "Itari 5")

	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Planet" )
	pPlanet.UpdateNodeOnly()

	#Moon2
	pMoon2 = App.Planet_Create(35.0, "data/models/environment/SnowPlanet.nif")
	pSet.AddObjectToSet(pMoon2, "Moon 1")

	# Place the object at the specified location.
	pMoon2.PlaceObjectByName( "Moon1" )
	pMoon2.UpdateNodeOnly()


