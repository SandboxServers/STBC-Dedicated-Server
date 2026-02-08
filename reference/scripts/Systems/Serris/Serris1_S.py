###############################################################################
#	Filename:	Serris1_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Serris 1 static objects.  Called by Serris1.py when region is created
#	
#	Created:	03/05/01 - Jess VanDerwalker
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
#		data/Textures/SunYellow.tga
#		data/Textures/SunBlueWhite.tga
#	for fFlareTexture you can use:
#		data/Textures/Effects/SunFlaresOrange.tga
#		data/Textures/Effects/SunFlaresRed.tga
#		data/Textures/Effects/SunFlaresRedOrange.tga
#		data/Textures/Effects/SunFlaresYellow.tga
#		data/Textures/Effects/SunFlaresBlue.tga
#		data/Textures/Effects/SunFlaresWhite.tga

	# Add a sun, far far away
	pSun = App.Sun_Create(5000.0, 5000, 500, "data/Textures/SunRed.tga", "data/Textures/Effects/SunFlaresRedOrange.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	# Model and placement for Serris 1 in Serris1 set
	pPlanet = App.Planet_Create(150.0, "data/models/environment/dryplanet.nif")
	pSet.AddObjectToSet(pPlanet, "Serris 1")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	
	# Model and placement for Moon in Serris1 set
	pMoon1 = App.Planet_Create(100.0, "data/models/environment/GreenPlanet.nif")
	pSet.AddObjectToSet(pMoon1, "Serris 1 Moon")
	
	# Place the object at the specified location.
	pMoon1.PlaceObjectByName("Moon1 Location")
	pMoon1.UpdateNodeOnly()