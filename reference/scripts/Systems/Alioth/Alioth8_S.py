###############################################################################
#	Filename:	Alioth8_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Alioth 8 static objects.  Called by Alioth8.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(500.0, 500, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAlioth8 = App.Planet_Create(90.0, "data/models/environment/SnowPlanet.nif")
	pSet.AddObjectToSet(pAlioth8, "Alioth 8")
	
	# Place the object at the specified location.
	pAlioth8.PlaceObjectByName( "Planet Location" )
	pAlioth8.UpdateNodeOnly()
