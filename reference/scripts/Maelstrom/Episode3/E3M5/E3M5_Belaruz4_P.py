import App

def LoadPlacements(sSetName):
	# Position "JonKa Start"
	kThis = App.Waypoint_Create("JonKa Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(10.025375, -151.701675, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.456787, -0.889435, 0.015836)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017374, 0.026718, 0.999492)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "JonKa Start"

	# Position "Kahless Ro Start"
	kThis = App.Waypoint_Create("Kahless Ro Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1.324205, -131.253922, -19.613861)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.356150, -0.912032, 0.203359)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.118383, 0.259915, 0.958347)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kahless Ro Start"

	# Position "BOP3 Start"
	kThis = App.Waypoint_Create("BOP3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(20.901836, -130.383804, 38.411995)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.394595, -0.812804, -0.428538)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.336072, -0.306402, 0.890603)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOP3 Start"

	# Position "Matan Warp In"
	kThis = App.Waypoint_Create("Matan Warp In", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-129.810562, 60.615772, -44.262112)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.623464, -0.781778, -0.010758)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.606698, -0.492426, 0.624047)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Matan Warp In"

	# Position "Galor2 Warp In"
	kThis = App.Waypoint_Create("Galor2 Warp In", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-135.590134, 77.082542, -45.894157)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.745215, -0.664973, 0.049656)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.546704, -0.566640, 0.616469)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Warp In"

	# Position "Galor1 Warp In"
	kThis = App.Waypoint_Create("Galor1 Warp In", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-133.652908, 66.298103, -51.955124)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.601243, -0.794699, 0.083428)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.666847, -0.441491, 0.600334)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1 Warp In"

	# Position "Dead Ship"
	kThis = App.Waypoint_Create("Dead Ship", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-180.545837, -463.502380, 46.042030)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.293501, -0.469849, 0.832526)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.678281, -0.511336, -0.527703)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Dead Ship"

	# Position "MatanCam1"
	kThis = App.Waypoint_Create("MatanCam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-117.990654, 43.736118, -43.521587)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.507080, 0.854899, -0.109626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.708294, -0.340851, 0.618175)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "MatanCam1"

	# Light position "Light 1"
	kThis = App.LightPlacement_Create("Light 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-123.503746, 41.732899, -38.731567)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 0.600000, 0.000000, 0.600000)
	kThis.Update(0)
	kThis = None
	# End position "Light 1"

