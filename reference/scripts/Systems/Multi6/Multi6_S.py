import App
import loadspacehelper


def Initialize(pSet):
#	print ("Creating Multi6 Nebulae")


	import Systems.Multi6.Multi6
	pSet = Systems.Multi6.Multi6.GetSet()

	################
	# Create the nebula
	################
	
	# MetaNebula_Create params are:
	# r, g, b : (floats [0.0 , 1.0]) 
	# visibility distance inside the nebula (float in world units)
	# scale factor for sensors in the nebula [0.0, 1.0] where 1.0 is normal range and 0.0 is no sensors
	# name of internal texture (needs alpha)
	# name of external texture (no need for alpha)
		
	####
	# First nebula
	####
	# Leave visible range at 75.0 for this nebula, it creates a good multiplayer experience
	# when you can't tell whether there's an asteroid around the corner.
	pNebula = App.MetaNebula_Create(0.125, 0.125, 0.75, 75.0, 0.5, 
		"data/Backgrounds/nebulaoverlayblue.tga", "data/Backgrounds/nebulaexternalblue.tga")
	# Adds a fuzzy sphere at x, y, z (in world coord) of specified size
	pNebula.AddNebulaSphere(50.0, 150.0, 150.0, 250.0)
	pNebula.AddNebulaSphere(50.0, -150.0, -150.0, 250.0)
	pNebula.AddNebulaSphere(50.0, -150.0, 150.0, 250.0)
	pNebula.AddNebulaSphere(50.0, 150.0, -150.0, 250.0)
	pNebula.SetupDamage(1.0)

	# Puts the nebula in the set
	pSet.AddObjectToSet(pNebula, "Nebula1")

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
		kPos.SetXYZ (x + 50.0, y, z)

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
			if (pSet.IsLocationEmptyTG(kPos, pAsteroid.GetRadius() * 1.5, 1)):
				# Okay, found a good location.  Place it here.
				break
			else:
				# Offset by the offset dir.
				kPos.Add(kOffsetDir)

		pAsteroid.SetTranslate(kPos)
		pAsteroid.RandomOrientation
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

	# Asteroid Field Position "Asteroid Field 1"
#	kThis = App.AsteroidFieldPlacement_Create("Asteroid Field 1", pSet.GetName(), None)
#	kThis.SetStatic(0)
#	kThis.SetNavPoint(0)
#	kThis.SetTranslateXYZ(50.0, 0.0, 0.0)
#	kForward = App.TGPoint3()
#	kForward.SetXYZ(-0.000000, 0.997209, -0.074666)
#	kUp = App.TGPoint3()
#	kUp.SetXYZ(-0.000345, 0.074666, 0.997209)
#	kThis.AlignToVectors(kForward, kUp)
#	kThis.SetFieldRadius(150.000000)
#	kThis.SetNumTilesPerAxis(3)
#	kThis.SetNumAsteroidsPerTile(2)
#	kThis.SetAsteroidSizeFactor(10.000000)
#	kThis.UpdateNodeOnly()
#	kThis.ConfigField()
#	kThis.Update(0)
#	kThis = None
	# End position "Asteroid Field 1"

