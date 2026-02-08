###############################################################################
#	Filename:	Alioth7_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Alioth 7 static objects.  Called by Alioth7.py when region is created
#	
#	Created:	10/04/01 - Tony Evans (Added Header)
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(1250.0, 1250, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	######
	# Create the Planet
	pAlioth7 = App.Planet_Create(270.0, "data/models/environment/BlueWhiteGasPlanet.nif")
	pSet.AddObjectToSet(pAlioth7, "Alioth 7")
	
	# Place the object at the specified location.
	pAlioth7.PlaceObjectByName( "Planet Location" )
	pAlioth7.UpdateNodeOnly()
