import App

def CreateMenus():
	import Systems.Utils
	return Systems.Utils.CreateSystemMenu("MRegion6", "Systems.Multi6.Multi6",
										  "Systems.Multi6.Multi6")

def Initialize():
	# Create the set ("Multi6")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Multi6")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Multi6.Multi6")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)

	# Load the placements and backdrops for this set.
	LoadPlacements("Multi6")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Multi6_S.py" file with an Initialize function that creates them.
	try:
		import Multi6_S
		Multi6_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Multi6"

def GetSet():
	return App.g_kSetManager.GetSet("Multi6")

def Terminate():
	App.g_kSetManager.DeleteSet("Multi6")

def LoadPlacements(sSetName):

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.0, 0.0, 0.0)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.0, 1.0, 0.0)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Light position "Ambient Light"
	kThis = App.LightPlacement_Create("Ambient Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(0.900000, 0.900000, 1.000000, 0.025000)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light 1"
	kThis = App.LightPlacement_Create("Directional Light 1", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.000000, 0.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(0.200000, 0.200000, 1.000000, 1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 1"

	# Light position "Directional Light 2"
	kThis = App.LightPlacement_Create("Directional Light 2", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-1.000000, 0.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(0.400000, 0.400000, 1.000000, 0.700000)
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
	
	# Backdrop Sphere "Backdrop nebula8"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Backdrop nebula8")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.852241, -0.240097, -0.464799)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.447384, -0.126039, 0.885416)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/treknebula8.tga")
	kThis.SetTargetPolyCount(256)
	kThis.SetHorizontalSpan(0.1875000)
	kThis.SetVerticalSpan(0.375000)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Backdrop nebula8")
	kThis.Update(0)
	# End Backdrop Sphere "Backdrop nebula8"

