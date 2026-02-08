import App

def Initialize():
	# Create the set ("Vesuvi1")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Vesuvi1")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Vesuvi.Vesuvi1")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)


	# Load the placements and backdrops for this set.
	LoadPlacements("Vesuvi1")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Vesuvi1_S.py" file with an Initialize function that creates them.
	try:
		import Vesuvi1_S
		Vesuvi1_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Vesuvi1"

def GetSet():
	return App.g_kSetManager.GetSet("Vesuvi1")

def Terminate():
	App.g_kSetManager.DeleteSet("Vesuvi1")

def LoadPlacements(sSetName):
	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.3)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light"
	kThis = App.LightPlacement_Create("Directional Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.000000, 0.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 0.500000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(29.296873, -238.414383, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Nebula Location"
	kThis = App.Waypoint_Create("Nebula Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(30.277174, 1845.220276, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nebula Location"

	# Position "Core Fragment Start 1"
	kThis = App.Waypoint_Create("Core Fragment Start 1", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(25.701721, 1052.806244, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Core Fragment Start 1"

	# Asteroid Field Position "Asteroid Field 1"
	kThis = App.AsteroidFieldPlacement_Create("Asteroid Field 1", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(27.061752, 1047.851898, 16.196598)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.090493, 0.290073, -0.952716)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.006574, 0.956447, 0.291833)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetFieldRadius(100.000000)
	kThis.SetNumTilesPerAxis(3)
	kThis.SetNumAsteroidsPerTile(2)
	kThis.SetAsteroidSizeFactor(10.000000)
	kThis.UpdateNodeOnly()
	kThis.ConfigField()
	kThis.Update(0)
	kThis = None
	# End position "Asteroid Field 1"

import App

def LoadBackdrops(pSet):

	#Draw order is implicit. First object gets drawn first

	# Star Sphere "Backdrop stars"
	kThis = App.StarSphere_Create()
	kThis.SetName("Backdrop stars")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.185766, 0.947862, -0.258937)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.049823, 0.254099, 0.965894)
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

	# Backdrop Sphere "Backdrop galaxy"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop galaxy")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.258736, -0.098798, 0.960882)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.904064, 0.325559, 0.276910)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/galaxy.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.067824)
	kThis.SetVerticalSpan(0.135650)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop galaxy")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop galaxy"

	# Backdrop Sphere "Backdrop treknebula3"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop treknebula3")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.999987, 0.000499, -0.005087)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.005087, 0.000012, 0.999987)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula3.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.164025)
	kThis.SetVerticalSpan(0.328050)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop treknebula3")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop treknebula3"

