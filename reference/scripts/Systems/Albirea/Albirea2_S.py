###############################################################################
#	Filename:	Albirea2_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Albirea 2 static objects.  Called by Albirea2.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):

	# Add a sun, far far away
	pSun = App.Sun_Create(2000.0, 2000, 500, "data/Textures/SunRed.tga", "data/Textures/Effects/SunFlaresRed.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAlbirea2 = App.Planet_Create(120.0, "data/models/environment/RootBeerPlanet.nif")
	pSet.AddObjectToSet(pAlbirea2, "Albirea 2")

	# Place the object at the specified location.
	pAlbirea2.PlaceObjectByName( "Planet1" )
	pAlbirea2.UpdateNodeOnly()

	######
	# Create the Planet
	pAlbireaMoon = App.Planet_Create(30.0, "data/models/environment/Moon.nif")
	pSet.AddObjectToSet(pAlbireaMoon, "Albirea 2 Moon")

	# Place the object at the specified location.
	pAlbireaMoon.PlaceObjectByName( "Moon" )
	pAlbireaMoon.UpdateNodeOnly()