import App
import Tactical.LensFlares

def CreateMenus():
	import Systems.Utils
	return Systems.Utils.CreateSystemMenu("MRegion1", "Systems.Multi1.Multi1",
										  "Systems.Multi1.Multi1")
	
def Initialize():
	# Create the set ("Multi1")
	pSet = App.SetClass_Create()

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Multi1.Multi1")

	App.g_kSetManager.AddSet(pSet, "Multi1")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)


	# Load the placements and backdrops for this set.
	LoadPlacements()
	LoadBackdrops(pSet)

	# Add lights.

	sSetName = "Multi1"
	
	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.025000)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light 1"
	kThis = App.LightPlacement_Create("Directional Light 1", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.000000, 0.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 1"

	# Light position "Directional Light 2"
	kThis = App.LightPlacement_Create("Directional Light 2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-1.000000, 0.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 0.700000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 2"

	#Load and place the grid.
	pGrid = App.GridClass_Create ();
	pSet.AddObjectToSet(pGrid, "grid");
	pGrid.SetHidden(1);

	# Create static objects for this set:

	# Set flag that tells code not to use special client ID ranges
	# for creating these objects.  These objects don't need to be
	# in the special ID ranges since they aren't destroyable or movable.
	# Also, client's create these independantly, so they cannot use
	# the ID ranges or else it'd be the wrong ID.
	App.g_kUtopiaModule.SetIgnoreClientIDForObjectCreation (1)

	import ships.Asteroid
	ships.Asteroid.LoadModel()

	#pLODModel = App.g_kLODModelManager.Create("Asteroid")
	#pLODModel.AddLOD("data/Models/Misc/Asteroids/asteroid.NIF", 10, 
	#	10000.0, 0.0, 0.0, 0.0, 0.0, None, None, None)

	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")
	pString = pDatabase.GetString ("Asteroid")
	pcString = pString.GetCString ()

	App.g_kSystemWrapper.SetRandomSeed(42)
	for iCounter in range(54):
		fScale = 0
		while fScale == 0:
			fScale = float(App.g_kSystemWrapper.GetRandomNumber(40) + 80) / 25.0

		pAsteroid = App.DamageableObject_Create("Asteroid")

		pAsteroid.SetMass (400.0)
		pAsteroid.SetNetType(0)
		pAsteroid.SetStatic(1)
		pAsteroid.SetScale(fScale)

#		print "Asteroid " + str(iCounter) + " radius: " + str(pAsteroid.GetRadius())

		kPos = App.TGPoint3 ()
		x = App.g_kSystemWrapper.GetRandomNumber(150) - 75
		y = App.g_kSystemWrapper.GetRandomNumber(150) - 75
		z = App.g_kSystemWrapper.GetRandomNumber(150) - 75
		kPos.SetXYZ (x, y, z)

		# Randomly offset it in some direction in case of collisions.
		kOffsetDir = App.TGPoint3 ()
		while (1):
			x = App.g_kSystemWrapper.GetRandomNumber(5) - 2.5
			y = App.g_kSystemWrapper.GetRandomNumber(5) - 2.5
			z = App.g_kSystemWrapper.GetRandomNumber(5) - 2.5

			kOffsetDir.SetXYZ (x, y, z)
			if (kOffsetDir.Length () > 1):
				# Okay, the offset dir is sufficiently large.
				break

		while (1):
			if (pSet.IsLocationEmptyTG(kPos, pAsteroid.GetRadius(), 1)):
				# Okay, found a good location.  Place it here.
				break
			else:
				# Offset by the offset dir.
				kPos.Add(kOffsetDir)

		pAsteroid.SetTranslate(kPos)
		pAsteroid.RandomOrientation ()
		pAsteroid.UpdateNodeOnly()
		
		pcName = pcString % str (iCounter + 1)
		pName = App.TGString ()
		pName.SetString (pcName)

		pSet.AddObjectToSet(pAsteroid, "Asteroid " + str (iCounter + 1))
		pAsteroid.SetDisplayName (pName)

	# unload database after creating asteroids.
	App.g_kLocalizationManager.Unload (pDatabase)

	# Clear the flag now that we're done.
	App.g_kUtopiaModule.SetIgnoreClientIDForObjectCreation (0)

	# Done.

def GetSetName():
	return "Multi1"

def GetSet():
	return App.g_kSetManager.GetSet("Multi1")

def Terminate():
	App.g_kSetManager.DeleteSet("Multi1")

def LoadPlacements():
	# No static placements.
	pass

def LoadBackdrops(pSet):
	
	####
	# We don't want to use an actual Asteroid Field at the moment for performance reasons
	####
	## Asteroid Field Position "Asteroid Field 1"
	#kThis = App.AsteroidFieldPlacement_Create("Asteroid Field 1", pSet.GetName(), None)
	#kThis.SetStatic(0)
	#kThis.SetNavPoint(0)
	#kThis.SetTranslateXYZ(0.0, 0.0, 0.0)
	#kForward = App.TGPoint3()
	#kForward.SetXYZ(-0.000000, 0.997209, -0.074666)
	#kUp = App.TGPoint3()
	#kUp.SetXYZ(-0.000345, 0.074666, 0.997209)
	#kThis.AlignToVectors(kForward, kUp)
	#kThis.SetFieldRadius(150.000000)
	#kThis.SetNumTilesPerAxis(3)
	#kThis.SetNumAsteroidsPerTile(2)
	#kThis.SetAsteroidSizeFactor(10.000000)
	#kThis.UpdateNodeOnly()
	#kThis.ConfigField()
	#kThis.Update(0)
	#kThis = None
	## End position "Asteroid Field 1"
	#######

	#Draw order is implicit. First object gets drawn first

	# Star Sphere "Backdrop stars"
	kThis = App.StarSphere_Create()
	kThis.SetName("Backdrop stars")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.185766, 0.947862, -0.258937)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.049811, 0.254101, 0.965894)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/stars.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(1.000000)
	kThis.SetVerticalSpan(1.000000)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(22.000000)
	kThis.SetTextureVTile(11.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop stars")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop stars"

	# Backdrop Sphere "Backdrop nebula7"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop nebula7")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.852241, -0.240097, -0.464799)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.447384, -0.126039, 0.885416)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula7.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.1875000)
	kThis.SetVerticalSpan(0.375000)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop nebula7")
	kThis.Update(0)
	# End Backdrop Sphere "Backdrop nebula7"

	Tactical.LensFlares.WhiteLensFlare (pSet, kThis, 0)


