###############################################################################
#	Filename:	Ascella4_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Ascella 4 static objects.  Called by Ascella4.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(1000.0, 1000, 500, "data/Textures/SunRedOrange.tga", "data/Textures/Effects/SunFlaresRed.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAscella4 = App.Planet_Create(80.0, "data/models/environment/SnowPlanet.nif")
	pSet.AddObjectToSet(pAscella4, "Ascella 4")

	# Place the object at the specified location.
	pAscella4.PlaceObjectByName( "Planet1" )
	pAscella4.UpdateNodeOnly()

