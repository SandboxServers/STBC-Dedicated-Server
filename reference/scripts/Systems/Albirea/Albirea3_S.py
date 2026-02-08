###############################################################################
#	Filename:	Albirea3_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Albirea 3 static objects.  Called by Albirea3.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):

	# Add a sun, far far away
	pSun = App.Sun_Create(1500.0, 1500, 500, "data/Textures/SunRed.tga", "data/Textures/Effects/SunFlaresRed.tga")
	pSet.AddObjectToSet(pSun, "Sun")

	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAlbirea1 = App.Planet_Create(150.0, "data/models/environment/PinkGasPlanet.nif")
	pSet.AddObjectToSet(pAlbirea1, "Albirea 3")

	# Place the object at the specified location.
	pAlbirea1.PlaceObjectByName( "Planet1" )
	pAlbirea1.UpdateNodeOnly()

	# Set the radius on the atmosphere
	pAlbirea1.SetAtmosphereRadius(100)