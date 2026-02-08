###############################################################################
#	Filename:	Nepenthe1_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Nepenthe 1 static objects.  Called by Nepenthe1.py when region is created
#	
#	Created:	9/17/00 - Alberto Fonseca
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
	pSun = App.Sun_Create(5000.0, 5000, 500)
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.YellowLensFlare(pSet, pSun)

	# Create the Planet
#	print ("Putting in the planet.\n")
	pNepenthePlanet = App.Planet_Create(90.0, "data/models/environment/gasgiant.nif")
	pSet.AddObjectToSet(pNepenthePlanet, "Nepenthe 1")

	# Place the object at the specified location.
	pNepenthePlanet.PlaceObjectByName( "Nepenthe1" )
	pNepenthePlanet.UpdateNodeOnly()

	# Create Asteroid Field.

	# Asteroid Field Position "Asteroid Field 1"
	kThis = App.AsteroidFieldPlacement_Create("Asteroid Field 1", pSet.GetName(), None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-35.811958, -208.019333, 11.073367)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.575937, -0.054474, -0.815677)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.260074, -0.933729, 0.245992)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetFieldRadius(114.29)
	kThis.SetNumTilesPerAxis(2)
	kThis.SetNumAsteroidsPerTile(3)
	kThis.SetAsteroidSizeFactor(7.000000)
	kThis.UpdateNodeOnly()
	kThis.ConfigField()
	kThis.Update(0)
	kThis = None
	# End position "Asteroid Field 1"

