###############################################################################
#	Filename:	Alioth2_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Alioth 2 static objects.  Called by Alioth2.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):

	# Add a sun, far far away
	pSun = App.Sun_Create(4250.0, 4250, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAlioth2 = App.Planet_Create(90.0, "data/models/environment/SulfurPlanet.nif")
	pSet.AddObjectToSet(pAlioth2, "Alioth 2")

	# Place the object at the specified location.
	pAlioth2.PlaceObjectByName( "Planet Location" )
	pAlioth2.UpdateNodeOnly()
