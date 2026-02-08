import App

def Initialize():
	# Create the set ("Deep Space")
	pSet = App.SetClass_Create()

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.DeepSpace.DeepSpace")

	App.g_kSetManager.AddSet(pSet, "DeepSpace")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)


	# Load the placements and backdrops for this set.
	LoadPlacements()
	LoadBackdrops(pSet)

	# Add lights.
	pSet.CreateAmbientLight(1, 1, 1, 0.3, "ambientlight")
	pSet.CreateDirectionalLight(1, 1, 1, 1, 1, 0, 0, "light1")

	#Load and place the grid.
	pGrid = App.GridClass_Create ();
	pSet.AddObjectToSet(pGrid, "grid");
	pGrid.SetHidden(1);

	# Create static objects for this set:
	# ***FIXME: For the moment, this needs to be filled in by hand.

	# Done.

def GetSetName():
	return "DeepSpace"

def GetSet():
	return App.g_kSetManager.GetSet("DeepSpace")

def Terminate():
	App.g_kSetManager.DeleteSet("DeepSpace")

def LoadPlacements():
	# No static placements.
	pass
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

	# Backdrop Sphere "Galaxy"
	kThis = App.BackdropSphere_Create()
	kThis.SetName("Galaxy")
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.860219, -0.122382, 0.495021)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.490086, 0.069723, 0.868881)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetTextureFileName("data/Backgrounds/Galaxy.tga")
	kThis.SetTargetPolyCount(188)
	kThis.SetHorizontalSpan(0.144685)
	kThis.SetVerticalSpan(0.289370)
	kThis.SetSphereRadius(300.000000)
	kThis.SetTextureHTile(1.000000)
	kThis.SetTextureVTile(1.000000)
	kThis.Rebuild()
	pSet.AddBackdropToSet(kThis,"Galaxy")
	kThis.Update(0)
	kThis = None
	# End Backdrop Sphere "Galaxy"

