import App
import loadspacehelper


def Initialize(pSet):
#	print ("Creating Multi4 Planets")


	import Systems.Multi4.Multi4
	pSet = Systems.Multi4.Multi4.GetSet()

	################
	# Create the Planets
	################
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")
	pString = pDatabase.GetString ("Star")
	pcString = pString.GetCString ()

	App.g_kSystemWrapper.SetRandomSeed(42)
	for iCounter in range(10):
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
									
		pStar = App.Sun_Create(fRadius)
		pStar.SetEnvironmentalShieldDamage(10)
		pStar.SetEnvironmentalHullDamage(25)
		pStar.SetTranslate (kPos)
		pStar.UpdateNodeOnly()

		pcName = pcString % str (iCounter + 1)
		pName = App.TGString ()
		pName.SetString (pcName)

		pSet.AddObjectToSet(pStar, "Star " + str (iCounter + 1))

		pStar.SetDisplayName (pName)

	# unload database after finished creating planets.
	App.g_kLocalizationManager.Unload (pDatabase)



