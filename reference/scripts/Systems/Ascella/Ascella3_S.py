###############################################################################
#	Filename:	Ascella3_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Ascella 3 static objects.  Called by Ascella3.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(2500.0, 2500, 500, "data/Textures/SunRedOrange.tga", "data/Textures/Effects/SunFlaresRed.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAscella3 = App.Planet_Create(120.0, "data/models/environment/GrayPlanet.nif")
	pSet.AddObjectToSet(pAscella3, "Ascella 3")

	# Place the object at the specified location.
	pAscella3.PlaceObjectByName( "Planet1" )
	pAscella3.UpdateNodeOnly()

