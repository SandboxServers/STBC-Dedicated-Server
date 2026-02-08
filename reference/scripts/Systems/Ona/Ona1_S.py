###############################################################################
#	Filename:	Ona1_S.py
#
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#
#	Creates Ona 1 static objects.  Called by Ona1.py when region is created
#
#	Created:	01/16/01 - Jess VanDerwalker
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):

#	To create a colored sun:
#	pSun = App.Sun_Create(fRadius, fAtmosphereThickness, fDamagePerSec, fBaseTexture , fFlareTexture)
#
#	for fBaseTexture you can use:
#		data/Textures/SunBase.tga 
#		data/Textures/SunRed.tga
#		data/Textures/SunRedOrange.tga
#	for fFlareTexture you can use:
#		data/Textures/Effects/SunFlaresOrange.tga
#		data/Textures/Effects/SunFlaresRed.tga
#		data/Textures/Effects/SunFlaresRedOrange.tga

	# Add a sun, far far away
	pSun = App.Sun_Create(5000.0, 5000, 500, "data/Textures/SunRed.tga", "data/Textures/Effects/SunFlaresRedOrange.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	# Planet and placement for "Ona 1" in Ona1 set
	pPlanet = App.Planet_Create(90.0, "data/models/environment/RedPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Ona 1")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

