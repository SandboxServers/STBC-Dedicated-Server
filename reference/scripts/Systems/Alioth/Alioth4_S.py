###############################################################################
#	Filename:	Alioth4_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Alioth 4 static objects.  Called by Alioth4.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(2750.0, 2750, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAlioth4 = App.Planet_Create(90.0, "data/models/environment/RedPlanet.nif")
	pSet.AddObjectToSet(pAlioth4, "Alioth 4")

	# Place the object at the specified location.
	pAlioth4.PlaceObjectByName( "Planet Location" )
	pAlioth4.UpdateNodeOnly()
