import App

def LoadPlacements(sSetName):
	# Position "Enterprise Start"
	kThis = App.Waypoint_Create("Enterprise Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(0.757632, -214.970963, 5.177235)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.118521, 0.990443, -0.070537)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.016954, 0.069009, 0.997472)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Start"

	# Position "Enterprise Turn 1"
	kThis = App.Waypoint_Create("Enterprise Turn 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-1.069499, -81.429382, -2.698445)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.118521, 0.990443, -0.070537)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.016954, 0.069009, 0.997472)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Turn 1"

	# Position "Enterprise Turn 2"
	kThis = App.Waypoint_Create("Enterprise Turn 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(29.564339, -83.182892, 0.800251)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.348790, -0.930773, -0.109576)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.251899, -0.205720, 0.945635)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Turn 2"

	# Position "Enterprise Warp Out"
	kThis = App.Waypoint_Create("Enterprise Warp Out", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-113.177368, -221.762848, 4.725410)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.777443, -0.623619, 0.081741)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.265715, -0.207865, 0.941375)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Warp Out"


	# Position "AMB Start"
	kThis = App.Waypoint_Create("AMB Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-226.368774, -169.790558, 14.517229)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.589097, 0.807626, 0.026547)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.388744, -0.312052, 0.866892)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "AMB Start"

	# Position "AMB 1"
	kThis = App.Waypoint_Create("AMB 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-133.328873, 1.310143, 19.772041)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.696513, 0.717158, 0.023539)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.495848, -0.504767, 0.706644)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(10.000000)
	kThis.Update(0)
	kThis = None
	# End position "AMB 1"

	# Position "AMB 2"
	kThis = App.Waypoint_Create("AMB 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-44.606262, 83.329765, 15.312896)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.737072, 0.666665, -0.110828)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.100830, 0.053675, 0.993455)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "AMB 2"

	# Position "AMB End"
	kThis = App.Waypoint_Create("AMB End", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-9.661390, 90.876526, 16.728098)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.626311, 0.779088, 0.027496)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.013862, -0.046395, 0.998827)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.000000)
	kThis.Update(0)
	kThis = None
	# End position "AMB End"

	# Position "Nebula Start"
	kThis = App.Waypoint_Create("Nebula Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(76.748604, 19.185289, 25.896635)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.653263, 0.749229, -0.109103)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.034457, 0.114532, 0.992822)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nebula Start"

	# Attaching object "Enterprise Turn 1" after "Enterprise Start"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Enterprise Start") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Enterprise Turn 1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Enterprise Turn 2" after "Enterprise Turn 1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Enterprise Turn 1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Enterprise Turn 2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Enterprise Warp Out" after "Enterprise Turn 2"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Enterprise Turn 2") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Enterprise Warp Out") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "AMB 1" after "AMB Start"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "AMB Start") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "AMB 1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "AMB 2" after "AMB 1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "AMB 1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "AMB 2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "AMB End" after "AMB 2"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "AMB 2") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "AMB End") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
