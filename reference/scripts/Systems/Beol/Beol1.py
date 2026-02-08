import App

def Initialize():
	# Create the set ("Beol1")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Beol1")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Beol.Beol1")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)

	# Load the placements and backdrops for this set.
	LoadPlacements("Beol1")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Beol1_S.py" file with an Initialize function that creates them.
	try:
		import Beol1_S
		Beol1_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Beol1"

def GetSet():
	return App.g_kSetManager.GetSet("Beol1")

def Terminate():
	App.g_kSetManager.DeleteSet("Beol1")

def LoadPlacements(sSetName):
	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
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
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.0, 0.0, 0.0)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.350176, -0.045736, 0.935567)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(.5, .5, 1, .9)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

	# Light position "Directional Light 2"
	kThis = App.LightPlacement_Create("Directional Light 2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-10.264078, 4.454040, -8.641300)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.637224, -0.172051, -0.751228)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.555090, -0.573732, 0.602251)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(0.700000, 0.700000, 0.500000, 0.300000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 2"

	# Position "Sun"
	kThis = App.Waypoint_Create("Sun", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-70000.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Sun"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(16.415028, 10.864594, 18.766428)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.020647, -0.480066, -0.876990)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.037678, -0.876180, 0.480509)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(35.000450, -274.912262, -206.616592)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.054298, -0.798143, -0.600017)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.048220, -0.602298, 0.796814)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

	# Position "Moon1 Location"
	kThis = App.Waypoint_Create("Moon1 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(726.886658, -540.691833, -246.589294)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.831706, 0.171092, -0.528198)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.546002, -0.424643, 0.722191)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon1 Location"

	# Position "Moon3 Location"
	kThis = App.Waypoint_Create("Moon3 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-2778.313965, -523.930054, -3824.562500)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.592902, -0.128925, -0.794887)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.016680, -0.988855, 0.147944)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon3 Location"

	# Position "Moon4 Location"
	kThis = App.Waypoint_Create("Moon4 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-4485.139160, 548.213440, -498.528046)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.506942, 0.684493, 0.523907)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.518926, 0.242967, -0.819563)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon4 Location"

	# Position "Moon2 Location"
	kThis = App.Waypoint_Create("Moon2 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-783.691956, -467.687805, 214.118042)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.097797, -0.560706, -0.822219)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.108333, -0.815273, 0.568854)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon2 Location"

import App

def LoadBackdrops(pSet):

	#Draw order is implicit. First object gets drawn first

	# Star Sphere "Backdrop stars"
	kThis = App.StarSphere_Create()
	kThis.SetName("Backdrop stars")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.185766, 0.947862, -0.258938)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.049825, 0.254099, 0.965894)
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

	# Backdrop Sphere "Backdrop galaxy4"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop galaxy4")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.619916, 0.784394, -0.020738)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.012776, 0.016335, 0.999785)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/galaxy4.tga")
	kThis.SetTargetPolyCount(208)
	kThis.SetHorizontalSpan(0.054938)
	kThis.SetVerticalSpan(0.080100)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop galaxy4")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop galaxy4"

	# Backdrop Sphere "Backdrop treknebula4"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop treknebula4")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.607304, 0.125438, 0.784505)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.323699, -0.862709, 0.388525)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula4.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.155986)
	kThis.SetVerticalSpan(0.156905)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop treknebula4")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop treknebula4"

