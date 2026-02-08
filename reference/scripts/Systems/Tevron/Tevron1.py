import App

def Initialize():
	# Create the set ("Tevron1")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Tevron1")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Tevron.Tevron1")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)

	# Load the placements and backdrops for this set.
	LoadPlacements("Tevron1")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Tevron1_S.py" file with an Initialize function that creates them.
	try:
		import Tevron1_S
		Tevron1_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Tevron1"

def GetSet():
	return App.g_kSetManager.GetSet("Tevron1")

def Terminate():
	App.g_kSetManager.DeleteSet("Tevron1")

def LoadPlacements(sSetName):
	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-4.771031, 14.230990, -1.135842)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.164746, 0.980862, -0.103767)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.012019, 0.103200, 0.994588)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.1)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light"
	kThis = App.LightPlacement_Create("Directional Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -7.688000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.634815, 0.506030, 0.583904)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.367942, -0.466537, 0.804340)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1, 1, .7, .6)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

	# Position "Sun"
	kThis = App.Waypoint_Create("Sun", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(64000.0, -54000.0, -580000.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Sun"

	# Light position "Directional Light 2"
	kThis = App.LightPlacement_Create("Directional Light 2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-9.411242, -7.832104, -1.947380)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.102187, -0.977342, 0.185364)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.913151, -0.018243, 0.407213)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 0.500000, 0.400000, 0.300000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 2"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.998133, -0.009134, -0.060386)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.060386, 0.295491, 0.953435)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Planet Placement"
	kThis = App.Waypoint_Create("Planet Placement", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(508.983734, -403.335663, 228.763855)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.737993, -0.586904, 0.333030)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.294566, 0.724199, 0.623511)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Placement"

	# Position "Moon1 Placement"
	kThis = App.Waypoint_Create("Moon1 Placement", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(641.903442, -16.760485, -272.286804)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.948195, 0.315438, 0.037763)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.267289, 0.727861, 0.631486)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon1 Placement"

	# Position "Moon2 Placement"
	kThis = App.Waypoint_Create("Moon2 Placement", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-7.756313, 260.585785, -119.240669)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.072196, -0.789897, 0.608975)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.267853, 0.572784, 0.774709)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Moon2 Placement"

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

	# Backdrop Sphere "Backdrop treknebula9"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop treknebula9")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.176811, 0.980780, -0.082514)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.051295, 0.092903, 0.994353)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula9.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.182250)
	kThis.SetVerticalSpan(0.364500)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop treknebula9")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop treknebula9"

	# Backdrop Sphere "Backdrop galaxy4"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop galaxy4")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.009662, -0.922186, 0.386626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.095781, 0.385720, 0.917631)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/galaxy4.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.127625)
	kThis.SetVerticalSpan(0.112108)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop galaxy4")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Backdrop galaxy4"

