import App

def Initialize():
	# Create the set ("Vesuvi5")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Vesuvi5")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Vesuvi.Vesuvi5")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)

	# Load the placements and backdrops for this set.
	LoadPlacements("Vesuvi5")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Vesuvi5_S.py" file with an Initialize function that creates them.
	try:
		import Vesuvi5_S
		Vesuvi5_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Vesuvi5"

def GetSet():
	return App.g_kSetManager.GetSet("Vesuvi5")

def Terminate():
	App.g_kSetManager.DeleteSet("Vesuvi5")

def LoadPlacements(sSetName):
	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.070287, 0.997501, 0.007130)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.104332, -0.014460, 0.994437)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(0.500000, 0.500000, 0.500000, 0.200000)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light"
	kThis = App.LightPlacement_Create("Directional Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.000000, 0.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(0.600000, 0.600000, 0.800000, 0.700000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

	# Light position "Directional Light 2"
	kThis = App.LightPlacement_Create("Directional Light 2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-6.584218, -7.751926, -14.339359)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.874157, 0.217178, -0.434377)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.444356, -0.003211, -0.895844)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 0.300000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 2"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(191.731476, -198.758667, 38.603584)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.923997, 0.061448, 0.377431)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.378971, 0.015253, 0.925283)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-473.638916, 71.203514, 246.083603)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.846890, 0.061070, 0.528250)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.451360, -0.442676, 0.774798)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

	# Position "Moon1 Location"
	kThis = App.Waypoint_Create("Moon1 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-696.999084, 211.777039, -181.304169)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.985775, 0.167783, -0.009786)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.006352, 0.095377, 0.995421)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon1 Location"

	# Position "Moon2 Location"
	kThis = App.Waypoint_Create("Moon2 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-1017.577332, -663.819824, -477.570831)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.754861, -0.427372, -0.497532)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.236646, -0.530004, 0.814306)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon2 Location"

	# Position "Station Location"
	kThis = App.Waypoint_Create("Station Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-536.516296, -197.625031, 146.134094)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.131780, 0.945730, 0.297033)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.990534, 0.114018, 0.076430)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Station Location"

	# Position "SatelliteStart1"
	kThis = App.Waypoint_Create("SatelliteStart1", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-625.617004, 32.166103, -50.680805)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.268826, 0.746476, -0.608692)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.962844, -0.225178, 0.149086)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SatelliteStart1"

	# Position "SatelliteStart2"
	kThis = App.Waypoint_Create("SatelliteStart2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-977.145752, -614.752747, -347.771179)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.539483, -0.717409, -0.440775)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.803810, 0.594673, 0.015922)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SatelliteStart2"

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

	# Backdrop Sphere "Backdrop galaxy"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop galaxy")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.258735, -0.098798, 0.960882)
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
	kUp.SetXYZ(-0.005087, -0.000057, 0.999987)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula3.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.198470)
	kThis.SetVerticalSpan(0.396940)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop treknebula3")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop treknebula3"

