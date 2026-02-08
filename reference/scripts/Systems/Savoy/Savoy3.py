import App

def Initialize():
	# Create the set ("Savoy3")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Savoy3")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Savoy.Savoy3")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)


	# Load the placements and backdrops for this set.
	LoadPlacements("Savoy3")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Savoy3_S.py" file with an Initialize function that creates them.
	try:
		import Savoy3_S
		Savoy3_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Savoy3"

def GetSet():
	return App.g_kSetManager.GetSet("Savoy3")

def Terminate():
	App.g_kSetManager.DeleteSet("Savoy3")

def LoadPlacements(sSetName):
	# Position "Asteroid5"
	kThis = App.Waypoint_Create("Asteroid5", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(86.315063, 93.331680, -38.443710)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.766231, -0.559547, -0.315909)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.164587, 0.646141, -0.745260)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid5"

	# Position "Asteroid4"
	kThis = App.Waypoint_Create("Asteroid4", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(79.305862, 72.854935, -38.945103)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.079776, 0.489618, -0.868280)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.103593, 0.862267, 0.495745)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid4"

	# Position "Asteroid6"
	kThis = App.Waypoint_Create("Asteroid6", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(61.562790, 102.873962, 20.634214)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.776621, 0.448400, 0.442490)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.428872, -0.138172, 0.892736)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid6"

	# Position "Asteroid1"
	kThis = App.Waypoint_Create("Asteroid1", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-129.957321, -2.410198, -78.988129)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.242857, 0.969994, 0.011493)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000257, -0.011783, 0.999931)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid1"

	# Position "Asteroid2"
	kThis = App.Waypoint_Create("Asteroid2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-122.561340, -23.728067, -83.241013)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.107793, 0.421311, -0.900488)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.114444, 0.894485, 0.432202)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid2"

	# Position "Asteroid3"
	kThis = App.Waypoint_Create("Asteroid3", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(98.013390, -77.675331, 118.381371)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.035471, 0.491475, -0.870169)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.012202, 0.870439, 0.492124)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid3"

	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.1)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light"
	kThis = App.LightPlacement_Create("Directional Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-1.000000, 0.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1, 1, .9, .3)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

	# Position "Sun"
	kThis = App.Waypoint_Create("Sun", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(70000.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Sun"

	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(290.019653, 576.257568, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.125435, 0.772707, -0.622246)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.010966, 0.628241, 0.777941)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

import App

def LoadBackdrops(pSet):

	#Draw order is implicit. First object gets drawn first

	# Star Sphere "Backdrop stars"
	kThis = App.StarSphere_Create()
	kThis.SetName("Backdrop stars")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.185765, 0.947862, -0.258937)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.049807, 0.254102, 0.965894)
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

	# Backdrop Sphere "Backdrop galaxy3"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop galaxy3")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.045324, 0.957260, -0.285654)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.013487, 0.285335, 0.958333)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/backgrounds/galaxy3.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.119574)
	kThis.SetVerticalSpan(0.239148)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop galaxy3")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop galaxy3"
