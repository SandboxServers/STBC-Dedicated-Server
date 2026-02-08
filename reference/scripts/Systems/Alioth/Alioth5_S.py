###############################################################################
#	Filename:	Alioth5_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Alioth 5 static objects.  Called by Alioth5.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):

	# Add a sun, far far away
	pSun = App.Sun_Create(2000.0, 2000, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAlioth5 = App.Planet_Create(270.0, "data/models/environment/PinkGasPlanet.nif")
	pSet.AddObjectToSet(pAlioth5, "Alioth 5")
	
	# Place the object at the specified location.
	pAlioth5.PlaceObjectByName( "Planet Location" )
	pAlioth5.UpdateNodeOnly()
