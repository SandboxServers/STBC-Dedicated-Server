import App

def Initialize():
	# Create the set ("Starbase12")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Starbase12")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Starbase12.Starbase12")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)

	# Load the placements and backdrops for this set.
	LoadPlacements("Starbase12")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Starbase12_S.py" file with an Initialize function that creates them.
	try:
		import Starbase12_S
		Starbase12_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Starbase12"

def GetSet():
	return App.g_kSetManager.GetSet("Starbase12")

def Terminate():
	App.g_kSetManager.DeleteSet("Starbase12")

def LoadPlacements(sSetName):
	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-3.816000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.100000)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light"
	kThis = App.LightPlacement_Create("Directional Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.844013, 0.398183, 0.359295)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.510363, 0.390388, 0.766242)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(0.900000, 0.900000, 0.600000, 0.200000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

	# Light position "Sun Light"
	kThis = App.LightPlacement_Create("Sun Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(18.722118, 10.633283, 3.148508)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-1.0, 0.0, 0.0)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.049718, 0.036562, 0.998094)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(.9, .9, 1, .4)
	kThis.Update(0)
	kThis = None
	# End position "Sun Light"

	# Position "Sun"
	kThis = App.Waypoint_Create("Sun", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(70000.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.0, 0.0, 0.0)
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
	kThis.SetTranslateXYZ(-30.000000, -156.379730, 1.094367)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Starbase12 Location"
	kThis = App.Waypoint_Create("Starbase12 Location", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(10.895514, 143.301804, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Starbase12 Location"

	# Light position "Directional Light 2"
	kThis = App.LightPlacement_Create("Directional Light 2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-7.561178, -13.532564, -0.087336)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.808193, 0.132823, -0.573744)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.532103, 0.582186, -0.614757)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(0.800000, 0.700000, 0.700000, 0.600000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 2"

	# Position "Planet1"
	kThis = App.Waypoint_Create("Planet1", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(439.698242, 995.849182, -50.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.426991, -0.885227, -0.184533)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.102886, -0.155186, 0.982513)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet1"

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
	kUp.SetXYZ(0.049814, 0.254101, 0.965894)
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

	# Backdrop "Moon"
#	kThis = App.Backdrop_Create()
#	kThis.SetName("Moon")
#	kThis.SetModelName("data/models/environment/planet.nif")
#	kThis.SetTranslateXYZ(100.000000, 400.000000, -50.000000)
#	kForward = App.TGPoint3()
#	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
#	kUp = App.TGPoint3()
#	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
#	kThis.AlignToVectors(kForward, kUp)
#	pSet.AddBackdropToSet(kThis,"Moon")
#	kThis.Update(0)
#	kThis = None
	# End Backdrop "Moon"

	# Backdrop Sphere "Backdrop treknebula8"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop treknebula8")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.830335, -0.142027, 0.538862)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.364038, 0.593887, 0.717478)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula8.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.132860)
	kThis.SetVerticalSpan(0.265720)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop treknebula8")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop treknebula8"

