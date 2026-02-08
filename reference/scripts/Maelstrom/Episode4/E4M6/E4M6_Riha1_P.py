import App

def LoadPlacements(sSetName):
	# Position "Freighter1 Start"
	kThis = App.Waypoint_Create("Freighter1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(76.653435, 385.001678, -28.288002)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter1 Start"

	# Position "Freighter2 Start"
	kThis = App.Waypoint_Create("Freighter2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(80.173424, 406.617676, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter2 Start"

	# Position "Freighter3 Start"
	kThis = App.Waypoint_Create("Freighter3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(64.301430, 392.001617, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter3 Start"

	# Position "Freighter4 Start"
	kThis = App.Waypoint_Create("Freighter4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(95.981415, 409.793549, -53.888008)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter4 Start"

	# Position "BOP1 Start"
	kThis = App.Waypoint_Create("BOP1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-132.111710, 29.225206, 117.080498)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.780042, 0.200461, -0.592747)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.451539, 0.475466, 0.755013)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOP1 Start"

	# Position "BOP2 Start"
	kThis = App.Waypoint_Create("BOP2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-117.407288, 42.114754, 93.231499)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.687940, 0.111108, -0.717212)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.367835, 0.798512, 0.476525)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOP2 Start"

	# Position "Galor1 Start"
	kThis = App.Waypoint_Create("Galor1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(12.949300, 25.234100, -0.303257)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.183748, 0.933080, -0.309189)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.090052, 0.329201, 0.939956)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1 Start"

	# Position "Galor2 Start"
	kThis = App.Waypoint_Create("Galor2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(12.949300, 45.234100, -0.303257)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.530691, 0.568274, -0.628833)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.355577, 0.524206, 0.773805)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Start"

	# Position "Galor3 Start"
	kThis = App.Waypoint_Create("Galor3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(14.060857, 94.035019, -2.861650)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.569316, -0.663020, 0.486089)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.821958, 0.470734, -0.320616)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor3 Start"

	# Position "Galor4 Start"
	kThis = App.Waypoint_Create("Galor4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(14.562794, 76.913979, -1.832135)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.634082, -0.438330, 0.637030)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.693350, 0.687021, -0.217414)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor4 Start"

	# Position "Galor5 Start"
	kThis = App.Waypoint_Create("Galor5 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(13.892182, 60.747185, -1.084106)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.674745, -0.435615, 0.595784)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.737094, 0.356628, -0.574029)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor5 Start"

	# Position "Player Start Riha1"
	kThis = App.Waypoint_Create("Player Start Riha1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-218.874634, 24.883142, 405.398712)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.526618, 0.049698, -0.848648)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.846709, 0.119773, -0.518400)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start Riha1"

