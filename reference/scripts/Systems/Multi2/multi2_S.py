import App
import loadspacehelper

g_kModelTable = [
"AquaPlanet.NIF",
"BlueRockyPlanet.NIF",
"BlueTanPlanet.NIF",
"BlueWhiteGasPlanet.NIF",
"earth.NIF",
"gasgiant.NIF",
"GreenPlanet.NIF",
"GreenPurplePlanet.NIF",
"IcePlanet.NIF",
"moon.NIF",
"planet.NIF",
"PurplePlanet.NIF",
"RedPlanet.NIF",
"RockyPlanet.NIF",
"RootBeerPlanet.NIF",
"SlimeGreenPlanet.NIF",
"SnowPlanet.NIF",
]


def Initialize(pSet):
#	print ("Creating Multi2 Planets")


	import Systems.Multi2.Multi2
	pSet = Systems.Multi2.Multi2.GetSet()

	################
	# Create the Planets
	################
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")
	pString = pDatabase.GetString ("Planet")
	pcString = pString.GetCString ()

	App.g_kSystemWrapper.SetRandomSeed(40)
	for iCounter in range(20):
		pcModelName = "data/models/environment/" + g_kModelTable[App.g_kSystemWrapper.GetRandomNumber(17)]
		fRadius = float(App.g_kSystemWrapper.GetRandomNumber(350) + 100)

		kPos = App.TGPoint3 ()
		x = App.g_kSystemWrapper.GetRandomNumber (2000) - 1000
		y = App.g_kSystemWrapper.GetRandomNumber (2000) - 1000
		z = App.g_kSystemWrapper.GetRandomNumber (2000) - 1000
		kPos.SetXYZ (x, y, z)

		# Randomly offset it in some direction in case of collisions.
		kOffsetDir = App.TGPoint3 ()
		while (1):
			x = App.g_kSystemWrapper.GetRandomNumber (200) - 100
			y = App.g_kSystemWrapper.GetRandomNumber (200) - 100
			z = App.g_kSystemWrapper.GetRandomNumber (200) - 100

			kOffsetDir.SetXYZ (x, y, z)
			if (kOffsetDir.Length () > 50):
				# Okay, the offset dir is sufficiently large.
				break

		while (1):
			if (pSet.IsLocationEmptyTG (kPos, fRadius, 1)):
				# Okay, found a good location.  Place it here.
				break
			else:
				# Offset by the offset dir.
				kPos.Add (kOffsetDir)
									
		pPlanet = App.Planet_Create(fRadius, pcModelName)
		pPlanet.SetTranslate (kPos)
		pPlanet.RandomOrientation()
		pPlanet.UpdateNodeOnly()

		pcName = pcString % str (iCounter + 1)
		pName = App.TGString ()
		pName.SetString (pcName)

		pSet.AddObjectToSet(pPlanet, "Planet " + str (iCounter + 1))
		pPlanet.SetDisplayName (pName)

	# unload database after finished creating planets.
	App.g_kLocalizationManager.Unload (pDatabase)

	################
	# Create some very large, very distant planets for visual effect
	################
#	App.g_kSystemWrapper.SetRandomSeed(7896643)
#	for iCounter in range(35):
#		pcModelName = "data/models/environment/" + g_kModelTable[App.g_kSystemWrapper.GetRandomNumber(17)]
#		fRadius = float(App.g_kSystemWrapper.GetRandomNumber(1000) + 500)
#
#		kPos = App.TGPoint3 ()
#		x, y, z = 0, 0, 0
#		while -3000 < x < 3000 and -3000 < y < 3000 and -3000 < z < 3000:
#			x = App.g_kSystemWrapper.GetRandomNumber (8000) - 4000
#			y = App.g_kSystemWrapper.GetRandomNumber (8000) - 4000
#			z = App.g_kSystemWrapper.GetRandomNumber (8000) - 4000
#		kPos.SetXYZ (x, y, z)
#
#		# Randomly offset it in some direction in case of collisions.
#		kOffsetDir = App.TGPoint3 ()
#		while (1):
#			x = App.g_kSystemWrapper.GetRandomNumber (500) - 250
#			y = App.g_kSystemWrapper.GetRandomNumber (500) - 250
#			z = App.g_kSystemWrapper.GetRandomNumber (500) - 250
#
#			kOffsetDir.SetXYZ (x, y, z)
#			if (kOffsetDir.Length () > 100):
#				# Okay, the offset dir is sufficiently large.
#				break
#
#		while (1):
#			if (pSet.IsLocationEmptyTG (kPos, fRadius, 1)):
#				# Okay, found a good location.  Place it here.
#				break
#
#				# Offset by the offset dir.
#				kPos.Add (kOffsetDir)
#									
#		pPlanet = App.Planet_Create(fRadius, pcModelName)
#		pPlanet.SetTranslate (kPos)
#		pPlanet.RandomOrientation()
#		pPlanet.UpdateNodeOnly()
#		pSet.AddObjectToSet(pPlanet, "Planet " + str(iCounter + 25))

