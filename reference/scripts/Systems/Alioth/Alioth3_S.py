###############################################################################
#	Filename:	Alioth3_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Alioth 3 static objects.  Called by Alioth3.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):

	# Add a sun, far far away
	pSun = App.Sun_Create(3500.0, 3500, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAlioth3 = App.Planet_Create(90.0, "data/models/environment/PurplePlanet.nif")
	pSet.AddObjectToSet(pAlioth3, "Alioth 3")

	# Place the object at the specified location.
	pAlioth3.PlaceObjectByName( "Planet Location" )
	pAlioth3.UpdateNodeOnly()
