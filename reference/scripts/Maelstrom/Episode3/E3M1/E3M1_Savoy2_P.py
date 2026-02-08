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

	# Attaching object "Geronimo Stop" after "Geronimo Start"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Geronimo Start") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Geronimo Stop") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
