import App

def Initialize():
	# Create the set ("Vesuvi6")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Vesuvi6")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Vesuvi.Vesuvi6")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)

	# Load the placements and backdrops for this set.
	LoadPlacements("Vesuvi6")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Vesuvi6_S.py" file with an Initialize function that creates them.
	try:
		import Vesuvi6_S
		Vesuvi6_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Vesuvi6"

def GetSet():
	return App.g_kSetManager.GetSet("Vesuvi6")

def Terminate():
	App.g_kSetManager.DeleteSet("Vesuvi6")

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
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.15)
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

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(145.744888, -89.577583, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.955099, 0.291929, 0.050631)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043388, -0.031235, 0.998570)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(260.359619, 331.673492, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

	# Position "Moon1 Location"
	kThis = App.Waypoint_Create("Moon1 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-190.149048, 1042.806396, -214.851807)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.556916, -0.798693, 0.227890)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.331315, 0.037975, 0.942756)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon1 Location"

	# Position "Station Location"
	kThis = App.Waypoint_Create("Station Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(53.625935, 503.851105, -44.358799)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.999886, -0.003060, 0.014783)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.014414, 0.484456, -0.874697)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Station Location"

	# Light position "Directional Light 2"
	kThis = App.LightPlacement_Create("Directional Light 2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-6.584218, -7.751926, -14.339359)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.204929, 0.064101, -0.976676)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.954703, -0.206860, -0.213895)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 0.300000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 2"

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
	kUp.SetXYZ(-0.005087, -0.000011, 0.999987)
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

