###############################################################################
#	Filename:	Ascella2_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Ascella 2 static objects.  Called by Ascella2.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(4500.0, 4500, 500, "data/Textures/SunRedOrange.tga", "data/Textures/Effects/SunFlaresRed.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAscella2 = App.Planet_Create(90.0, "data/models/environment/BrownPlanet.nif")
	pSet.AddObjectToSet(pAscella2, "Ascella 2")

	# Place the object at the specified location.
	pAscella2.PlaceObjectByName( "Planet1" )
	pAscella2.UpdateNodeOnly()

