import App

def LoadPlacements(sSetName):
	# Position "Geronimo Start"
	kThis = App.Waypoint_Create("Geronimo Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(241.683044, -153.002014, -60.282352)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.374011, 0.547830, -0.748331)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.856725, 0.104915, 0.504991)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Geronimo Start"

	# Position "Geronimo Stop"
	kThis = App.Waypoint_Create("Geronimo Stop", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-28.840858, -143.293640, 25.277626)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.056077, -0.982929, -0.175234)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.622155, -0.102868, 0.776107)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Geronimo Stop"

	# Position "Combat Start"
	kThis = App.Waypoint_Create("Combat Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-41.210709, -48.681992, 123.850250)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.549601, 0.385130, -0.741359)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.482283, 0.578334, 0.657977)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Combat Start"

	# Position "BOP1 Start"
	kThis = App.Waypoint_Create("BOP1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-10000.210709, -10000.681992, 10000.850250)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.549601, 0.385130, -0.741359)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.482283, 0.578334, 0.657977)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOP1 Start"

	# Position "BOP2 Start"
	kThis = App.Waypoint_Create("BOP2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-10000.210709, -10000.681992, 10000.850250)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.549601, 0.385130, -0.741359)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.482283, 0.578334, 0.657977)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOP2 Start"

	# Position "BOPCut1"
	kThis = App.Waypoint_Create("BOPCut1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-32.610344, -126.531754, 10.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.707206781, -0.707206781, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOPCut1"

	# Position "BOPCut2"
	kThis = App.Waypoint_Create("BOPCut2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-12.610344, -106.531754, 10.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.707206781, -0.707206781, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOPCut2"

	# Position "P Cam1"
	kThis = App.Waypoint_Create("P Cam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-33.490364, -218.539383, 0.841766)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.062668, -0.994724, -0.081219)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.234647, -0.064413, 0.969944)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "P Cam1"

	# Position "R Cam1"
	kThis = App.Waypoint_Create("R Cam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-26.453712, -133.928879, 10.135441)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.644865, 0.764075, 0.018425)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.001734, -0.022645, 0.999742)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "R Cam1"

	# Attaching object "Geronimo Stop" after "Geronimo Start"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Geronimo Start") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Geronimo Stop") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	pass
