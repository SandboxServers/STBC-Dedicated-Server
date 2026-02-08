import App

def CreateMenus():
	import Systems.Utils
	return Systems.Utils.CreateSystemMenu("MRegion7", "Systems.Multi7.Multi7",
										  "Systems.Multi7.Multi7")

def Initialize():
	# Create the set ("Multi7")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "Multi7")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.Multi7.Multi7")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)

	# Load the placements and backdrops for this set.
	LoadPlacements("Multi7")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "Multi7_S.py" file with an Initialize function that creates them.
	try:
		import Multi7_S
		Multi7_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "Multi7"

def GetSet():
	return App.g_kSetManager.GetSet("Multi7")

def Terminate():
	App.g_kSetManager.DeleteSet("Multi7")

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
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.025000)
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
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 1.000000)
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
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 0.700000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light 2"

	# Position the sun
	kThis = App.Waypoint_Create("Sun", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(750.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	# Position the planets
	pcName = "Planet 1"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(1750.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	pcName = "Planet 2"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(2250.0, 0.0, 1500.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	pcName = "Planet 3"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(750.0, 0.0, 2000.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	pcName = "Planet 4"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-1750.0, 0.0, 2500.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	pcName = "Planet 5"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-2250.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	pcName = "Planet 6"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-2750.0, 0.0, -3500.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	pcName = "Planet 7"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(750.0, 0.0, -4000.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	pcName = "Planet 8"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(5250.0, 0.0, -4500.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None

	pcName = "Planet 9"
	kThis = App.Waypoint_Create(pcName, sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(5750.0, 0.0, 0.0)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.000000, -1000.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
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

