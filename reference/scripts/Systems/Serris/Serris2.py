import App

def Initialize():
	# Create the set ("Serris2")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Serris2")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Serris.Serris2")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)

	# Load the placements and backdrops for this set.
	LoadPlacements("Serris2")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Serris2_S.py" file with an Initialize function that creates them.
	try:
		import Serris2_S
		Serris2_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Serris2"

def GetSet():
	return App.g_kSetManager.GetSet("Serris2")

def Terminate():
	App.g_kSetManager.DeleteSet("Serris2")

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
	kThis.ConfigAmbientLight(1.000000, 1.00000, 1.00000, 0.1)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light"
	kThis = App.LightPlacement_Create("Directional Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.185177, 0.968664, -0.165527)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.062116, 0.156565, 0.985712)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 0.800000, 0.600000, 0.400000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(598.711426, 986.351501, 503.686584)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.914784, 0.031532, 0.402712)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.333064, -0.505215, 0.796132)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1184.913452, 1141.186890, 828.265625)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.638483, 0.622840, 0.452117)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.340743, -0.297971, 0.891688)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

	# Position "Moon1 Location"
	kThis = App.Waypoint_Create("Moon1 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(974.404663, 157.949219, 584.336975)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.315536, 0.878200, 0.359447)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.380785, -0.229777, 0.895659)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon1 Location"

	# Light position "Second Directional"
	kThis = App.LightPlacement_Create("Second Directional", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(13.867895, 2.300561, 9.512250)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.715455, -0.343017, -0.608657)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.370567, -0.552232, 0.746806)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 0.900000, 0.400000, 0.300000)
	kThis.Update(0)
	kThis = None
	# End position "Second Directional"

	# Light position "SunLight"
	kThis = App.LightPlacement_Create("SunLight", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-151.722153, 535.102234, 57.373386)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.279084, -0.951069, -0.132585)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.349628, 0.027955, -0.936471)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1, .65, .65, .675)
	kThis.Update(0)
	kThis = None
	# End position "SunLight"

	# Position "Sun"
	kThis = App.Waypoint_Create("Sun", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-20000.0, 65000.0, 10000.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Sun"

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

	# Backdrop Sphere "Backdrop galaxy6"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop galaxy6")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.415693, -0.898427, -0.141521)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.059427, -0.128439, 0.989935)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/galaxy6.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.250000)
	kThis.SetVerticalSpan(0.500000)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop galaxy6")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop galaxy6"

	# Backdrop Sphere "Backdrop treknebula5"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop treknebula5")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.728431, 0.302645, 0.614650)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.567609, -0.235828, 0.788800)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula5.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.087170)
	kThis.SetVerticalSpan(0.174339)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop treknebula5")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop treknebula5"

