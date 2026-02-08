###############################################################################
#	Filename:	Biranu1_S.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Creates Biranu 1 static objects.  Called by Biranu1.py when region is created
#	
#	Created:	02/05/00 - Jess VanDerwalker
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
	pSun = App.Sun_Create(4000.0, 4000, 500)
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Model and placement for Biranu 1 in Biranu1 set
	pPlanet = App.Planet_Create(170.0, "data/models/environment/GreenPurplePlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Biranu 1")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()
	
	# Model and placement for the moon.
	pMoon = App.Planet_Create(110.0, "data/models/environment/SlimeGreenPlanet.nif")
	pSet.AddObjectToSet(pMoon, "Biranu 1 Moon")
	
	# Place the moon at the specified location
	pMoon.PlaceObjectByName("Moon1 Placement")
	pMoon.UpdateNodeOnly()
