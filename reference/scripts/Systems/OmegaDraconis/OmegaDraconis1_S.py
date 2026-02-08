###############################################################################
#	Filename:	OmegaDraconis1_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Omega Draconis 1 static objects.  
#	Called by OmegaDraconis1.py when region is created
#	
#	Created:	09/01/01 - Tony Evans
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App

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

	pSun = App.Sun_Create(360.0, 180, 360, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	pPlanet = App.Planet_Create(30.0, "data/models/environment/RedPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Omega Draconis 1")
	
	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Planet1" )
	pPlanet.UpdateNodeOnly()
