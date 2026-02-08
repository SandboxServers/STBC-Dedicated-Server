###############################################################################
#	Filename:	Ascella5_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Ascella 5 static objects.  Called by Ascella5.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(500.0, 500, 500, "data/Textures/SunRedOrange.tga", "data/Textures/Effects/SunFlaresRed.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAscella5 = App.Planet_Create(80.0, "data/models/environment/IcePlanet.nif")
	pSet.AddObjectToSet(pAscella5, "Ascella 5")

	# Place the object at the specified location.
	pAscella5.PlaceObjectByName( "Planet1" )
	pAscella5.UpdateNodeOnly()

