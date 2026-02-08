import App

def Initialize():
	# Create the set ("QuickBattleRegion")
	pSet = App.SetClass_Create()
	App.g_kSetManager.AddSet(pSet, "QuickBattleRegion")

	# Save the name of the region file that's creating the set.
	pSet.SetRegionModule("Systems.QuickBattle.QuickBattleRegion")

	# Activate the proximity manager for our set.
	pSet.SetProximityManagerActive(1)


	# Load the placements and backdrops for this set.
	LoadPlacements("QuickBattleRegion")
	LoadBackdrops(pSet)

	#Load and place the grid.
	pGrid = App.GridClass_Create()
	pSet.AddObjectToSet(pGrid, "grid")
	pGrid.SetHidden(1)

	# Create static objects for this set:
	# If you want to create static objects for this region, make a
	# "QuickBattleRegion_S.py" file with an Initialize function that creates them.
	try:
		import QuickBattleRegion_S
		QuickBattleRegion_S.Initialize(pSet)
	except ImportError:
		# Couldn't find the file.  That's ok.  Do nothing...
		pass

	# Done.

def GetSetName():
	return "QuickBattleRegion"

def GetSet():
	return App.g_kSetManager.GetSet("QuickBattleRegion")

def Terminate():
	App.g_kSetManager.DeleteSet("QuickBattleRegion")

def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(-141.210709, -248.681992, 123.850250)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.549601, 0.385130, -0.741359)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.482282, 0.578335, 0.657977)
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
	kThis.ConfigAmbientLight(1.000000, 1.000000, 1.000000, 0.200000)
	kThis.Update(0)
	kThis = None
	# End position "Ambient Light"

	# Light position "Directional Light"
	kThis = App.LightPlacement_Create("Directional Light", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.000000, 0.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.000000, 0.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 1.000000, 1.000000, 0.600000)
	kThis.Update(0)
	kThis = None
	# End position "Directional Light"

import App

def LoadBackdrops(pSet):

	#Draw order is implicit. First object gets drawn first
#	print("No backdrops.  We be usin' nebulae")
	return