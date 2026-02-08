###############################################################################
#	Filename:	Alioth6_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Alioth 6 static objects.  Called by Alioth6.py when region is created
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
	pAlioth6 = App.Planet_Create(360.0, "data/models/environment/TanGasPlanet.nif")
	pSet.AddObjectToSet(pAlioth6, "Alioth 6")

	# Place the object at the specified location.
	pAlioth6.PlaceObjectByName( "Planet Location" )
	pAlioth6.UpdateNodeOnly()
