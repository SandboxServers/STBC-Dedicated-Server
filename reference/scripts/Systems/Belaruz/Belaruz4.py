import App

def Initialize():
	# Create the set ("Belaruz4")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Belaruz4")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Belaruz.Belaruz4")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)


	# Load the placements and backdrops for this set.
	LoadPlacements("Belaruz4")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create ();
	pSet.AddObjectToSet(pGrid, "grid");
	pGrid.SetHidden(1);

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Belaruz4_S.py" file with an Initialize function that creates them.
	try:
		import Belaruz4_S
		Belaruz4_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Belaruz4"

def GetSet():
	return App.g_kSetManager.GetSet("Belaruz4")

def Terminate():
	App.g_kSetManager.DeleteSet("Belaruz4")

def LoadPlacements(sSetName):
	# Position "Belaruz4"
	kThis = App.Waypoint_Create("Belaruz4", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(4.190668, -1091.235809, 98.311455)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.009445, 0.978200, 0.207452)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000040, -0.207461, 0.978243)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Belaruz4"

	# Position "Asteroid4"
	kThis = App.Waypoint_Create("Asteroid4", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(176.929749, -356.798096, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid4"

	# Position "Asteroid3"
	kThis = App.Waypoint_Create("Asteroid3", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(42.477436, -321.991089, 132.339569)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.538844, 0.055323, 0.840587)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.325479, -0.906680, 0.268317)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid3"

	# Position "Asteroid2"
	kThis = App.Waypoint_Create("Asteroid2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-68.030556, -367.673157, 75.663841)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.332994, -0.152055, 0.930588)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.733697, 0.661697, -0.154422)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid2"

	# Position "Asteroid1"
	kThis = App.Waypoint_Create("Asteroid1", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-177.658997, -468.166351, 54.412041)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.345780, -0.504008, 0.791462)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.835961, -0.217615, -0.503799)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid1"

	# Position "Asteroid5"
	kThis = App.Waypoint_Create("Asteroid5", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(217.403183, -539.113831, 180.299896)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.625494, 0.594017, -0.505866)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.171329, 0.527961, 0.831807)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid5"

	# Position "Asteroid6"
	kThis = App.Waypoint_Create("Asteroid6", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(71.046547, -642.367004, 129.088165)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.932804, -0.358856, -0.033164)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.341737, -0.909999, 0.234770)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid6"

	# Position "Asteroid7"
	kThis = App.Waypoint_Create("Asteroid7", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-123.657959, -600.021790, 78.748222)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.878742, 0.428178, -0.210896)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.006979, 0.430280, 0.902669)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Asteroid7"

	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.0, 1.0, 0.0)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.0, 0.0, 1.0)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.1)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light"
	kThis = App.LightPlacement_Create("Directional Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.0, 0.0, 0.0)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.0, 0.0, 1.0)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 0.600000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

	# Light position "Planet Light"
	kThis = App.LightPlacement_Create("Planet Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-25.449060, -295.613617, -102.861572)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.161948, -0.973652, 0.160543)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.050662, 0.154272, 0.986729)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 0.500000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Light"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-32.572227, -226.536850, -0.921197)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.858776, 0.441285, 0.260330)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.199461, -0.180069, 0.963219)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

import App

def LoadBackdrops(pSet):

	#Draw order is implicit. First object gets drawn first

	# Backdrop Sphere "Backdrop stars"
	kThis = App.StarSphere_Create()
	kThis.SetName("Backdrop stars")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.185765, 0.947862, -0.258937)
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

	# Backdrop Sphere "Backdrop nebula3"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop nebula3")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.860219, -0.122382, 0.495021)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.490086, 0.069723, 0.868881)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula3.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.302500)
	kThis.SetVerticalSpan(0.605000)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop nebula3")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop nebula3"

	# Backdrop Sphere "Backdrop nebula2"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop nebula2")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.852241, -0.240097, -0.464799)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.447384, -0.126039, 0.885416)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula2.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.250000)
	kThis.SetVerticalSpan(0.500000)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop nebula2")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop nebula2"

