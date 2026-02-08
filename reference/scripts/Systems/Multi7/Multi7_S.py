import App
import loadspacehelper

g_kModelTable = [
"AquaPlanet.NIF",
"BlueRockyPlanet.NIF",
"BlueRockyPlanet.NIF",
"BlueRockyPlanet.NIF",
"BlueTanPlanet.NIF",
"BlueWhiteGasPlanet.NIF",
"BrightGreenPlanet.NIF",
"BrightGreenPlanet.NIF",
"BrightGreenPlanet.NIF",
"BrownBluePlanet.NIF",
"BrownPlanet.NIF",
"dryplanet.NIF",
"earth.NIF",
"earth.NIF",
"earth.NIF",
"earth.NIF",
"earth.NIF",
"gasgiant.NIF",
"GrayPlanet.NIF",
"GreenPlanet.NIF",
"GreenPurplePlanet.NIF",
"IcePlanet.NIF",
"moon.NIF",
"PinkGasPlanet.NIF",
"planet.NIF",
"PurplePlanet.NIF",
"RedPlanet.NIF",
"RedPlanet.NIF",
"RedPlanet.NIF",
"RedPlanet.NIF",
"RedPlanet.NIF",
"RockyPlanet.NIF",
"RootBeerPlanet.NIF",
"SlimeGreenPlanet.NIF",
"SnowPlanet.NIF",
"SulfurPlanet.NIF",
"TanGasPlanet.NIF",
"TanPlanet.NIF",
"TurquoisePlanet.NIF"
]


def Initialize(pSet):
#	print ("Creating Multi7 stuff")


	import Systems.Multi7.Multi7
	pSet = Systems.Multi7.Multi7.GetSet()

	################
	# Create the sun
	################
	pStar = App.Sun_Create(700)
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Multiplayer.tgl")
	pString = pDatabase.GetString ("Sun")

	pcName = pString.GetCString ()
	pName = App.TGString ()
	pName.SetString (pcName)

	pSet.AddObjectToSet(pStar, "Sun385724")
	pStar.SetDisplayName (pName)


	pStar.PlaceObjectByName("Sun")
	pStar.UpdateNodeOnly()


	################
	# Create the Planets
	################
	pString = pDatabase.GetString ("Planet")
	pcString = pString.GetCString ()

	App.g_kSystemWrapper.SetRandomSeed(42)
	for iCounter in range(1,10):
		pcModelName = "data/models/environment/" + g_kModelTable[App.g_kSystemWrapper.GetRandomNumber(38)]
		fRadius = float(App.g_kSystemWrapper.GetRandomNumber(150) + 50)
		pPlanet = App.Planet_Create(fRadius, pcModelName)

		pcName = pcString % str (iCounter)
		pName = App.TGString ()
		pName.SetString (pcName)

		pSet.AddObjectToSet(pPlanet, "Planet " + str (iCounter))
		pPlanet.SetDisplayName (pName)

		pPlanet.PlaceObjectByName("Planet " + str(iCounter))
		pPlanet.UpdateNodeOnly()

	# unload database after creating planets
	App.g_kLocalizationManager.Unload (pDatabase)


	# Asteroid Field Position "Asteroid Field 1"
	kThis = App.AsteroidFieldPlacement_Create("Asteroid Field 1", pSet.GetName(), None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(2000.0, 0.0, 1250.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000000, 0.997209, -0.074666)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000345, 0.074666, 0.997209)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetFieldRadius(500.0000)
	kThis.SetNumTilesPerAxis(3)
	kThis.SetNumAsteroidsPerTile(2)
	kThis.SetAsteroidSizeFactor(10.000000)
	kThis.UpdateNodeOnly()
	kThis.ConfigField()
	kThis.Update(0)
	kThis = None
	# End position "Asteroid Field 1"

	# Asteroid Field Position "Asteroid Field 2"
	kThis = App.AsteroidFieldPlacement_Create("Asteroid Field 2", pSet.GetName(), None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-1000.0, 0.0, 1750.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000000, 0.997209, -0.074666)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000345, 0.074666, 0.997209)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetFieldRadius(500.0000)
	kThis.SetNumTilesPerAxis(3)
	kThis.SetNumAsteroidsPerTile(2)
	kThis.SetAsteroidSizeFactor(10.000000)
	kThis.UpdateNodeOnly()
	kThis.ConfigField()
	kThis.Update(0)
	kThis = None
	# End position "Asteroid Field 2"

	# Asteroid Field Position "Asteroid Field 3"
	kThis = App.AsteroidFieldPlacement_Create("Asteroid Field 3", pSet.GetName(), None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(2500.0, 0.0, -1750.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000000, 0.997209, -0.074666)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000345, 0.074666, 0.997209)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetFieldRadius(500.0000)
	kThis.SetNumTilesPerAxis(3)
	kThis.SetNumAsteroidsPerTile(2)
	kThis.SetAsteroidSizeFactor(10.000000)
	kThis.UpdateNodeOnly()
	kThis.ConfigField()
	kThis.Update(0)
	kThis = None
	# End position "Asteroid Field 3"

