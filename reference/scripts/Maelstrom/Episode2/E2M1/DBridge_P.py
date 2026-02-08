import App

def LoadPlacements(sSetName):
	# Position "SaffiHead"
	kThis = App.Waypoint_Create("SaffiHead", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-48.324989, 73.738960, 51.353096)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.862507, -0.408165, -0.299136)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.229739, -0.210865, 0.950135)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiHead"

	# Position "SaffiPanEnd"
	kThis = App.Waypoint_Create("SaffiPanEnd", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-79.500244, 38.959629, 43.286018)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.666385, 0.745608, -0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiPanEnd"

	# Position "SaffiCamStatic"
	kThis = App.Waypoint_Create("SaffiCamStatic", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(34.515347, -199.420944, 62.484631)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.116344, 0.992350, -0.041310)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.0, 0.0, 1.0)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiCamStatic"

	# Position "SaffiPanStart"
	kThis = App.Waypoint_Create("SaffiPanStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(34.515347, -199.420944, 62.484631)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.933044, 0.359762, -0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiPanStart"

	# Attaching object "SaffiPanEnd" after "SaffiPanStart"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SaffiPanStart") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SaffiPanEnd") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
