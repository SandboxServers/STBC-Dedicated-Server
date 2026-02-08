###############################################################################
#	Filename:	Cebalrai1_S.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Creates Cebalrai 1 static objects.  Called by Cebalrai1.py when region is created
#	
#	Created:	09/24/00 - Alberto Fonseca
#	Modified:	10/04/01 - Tony Evans
###############################################################################
import App
import loadspacehelper
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
	pSun = App.Sun_Create(5000.0, 5000, 500, "data/Textures/SunRed.tga", "data/Textures/Effects/SunFlaresRed.tga")
	pSet.AddObjectToSet(pSun, "Sun")
	
	# Place the object at the specified location.
	pSun.PlaceObjectByName( "Sun" )
	pSun.UpdateNodeOnly()

	# Builds a Red-Orange lens flare, attached to the sun
	Tactical.LensFlares.RedOrangeLensFlare(pSet, pSun)

	import Systems.Cebalrai.Cebalrai1
	pCebalrai1 = Systems.Cebalrai.Cebalrai1.GetSet()

	# Model and placement for Cebalrai1.
	pPlanet = App.Planet_Create(180.0, "data/models/environment/BlueWhiteGasPlanet.nif")
	pSet.AddObjectToSet(pPlanet, "Cebalrai 1")

	#Place the object at the specified location.
	pPlanet.PlaceObjectByName("Planet Location")
	pPlanet.UpdateNodeOnly()

	#########
	# Create the asteroids and make them rotate randomly
	#########

#	ships.Asteroid.LoadModel ()

#	App.g_kModelManager.LoadModel('data/models/misc/Asteroids/asteroid.nif', None)

	# Only create system stuff if not multiplayer or is the host in multiplayer
	if (App.g_kUtopiaModule.IsMultiplayer () == 0 or App.g_kUtopiaModule.IsHost () == 1):
#		print ("Placing asteroids.\n")
		#Create the asteroids for Cebalrai 1
		for sAsteroidName, sPlacementName in ( 
			("Asteroid 1", "Asteroid1"),
			("Asteroid 2", "Asteroid2"),
			("Asteroid 3", "Asteroid3"),
			("Asteroid 4", "Asteroid4")):
	#		pModel = App.g_kModelManager.CloneModel('data/models/misc/Asteroids/asteroid.nif' )
	#		pModel.SetScale(0.1) 
	#		if (pModel == None):
	#			print("Unable to create asteroid; couldn't load model.")
	#		else:
			pAsteroid = loadspacehelper.CreateShip("Asteroid", pCebalrai1, sAsteroidName, sPlacementName)

			if (pAsteroid):
				pAsteroid.SetHailable(0)
				pAsteroid.SetTargetable(0)
				pAsteroid.SetScannable(0)

				#Rotate the asteroid
				vVelocity = App.TGPoint3_GetModelForward()	# Get the vector to rotate around
				vVelocity.Scale( 10.0 * App.PI / 180.0 )		# Scale it to 10 degrees/second (converted to radians)
				pAsteroid.SetAngularVelocity(vVelocity, App.PhysicsObjectClass.DIRECTION_MODEL_SPACE)
