###############################################################################
#	Filename:	OmegaDraconis2_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Omega Draconis 2 static objects.  
#	Called by OmegaDraconis2.py when region is created
#	
#	Created:	09/01/01 - Tony Evans
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import Tactical.LensFlares

def Initialize(pSet):
	# Add a sun, far far away
	pSun = App.Sun_Create(5000.0, 5000, 500, "data/Textures/SunYellow.tga", "data/Textures/Effects/SunFlaresYellow.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a yellow lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	pPlanet = App.Planet_Create(60.0, "data/models/environment/BrownPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Omega Draconis 2")
	
	# Place the object at the specified location.
	pPlanet.PlaceObjectByName( "Planet1" )
	pPlanet.UpdateNodeOnly()

	# Keep the stars from showing in front of the sun backdrop
#	pBackdrop = App.BackdropSphere_Cast(pSet.GetObject("Backdrop sun2"))
#	pBackdrop.SetAlphaBlendModes(0, 7)
