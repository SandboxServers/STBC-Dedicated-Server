import App

def LoadPlacements(sSetName):
	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-100.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.000000, 0.000000, 0.000011)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000011, -0.008944, 0.999960)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.999997, 0.002645, 0.000035)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000011, -0.008945, 0.999960)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -469.607880, -25.273634)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Attacker 1 Start"
	kThis = App.Waypoint_Create("Attacker 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(11.126637, 100.237946, 32.763859)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.030124, -0.999294, -0.022452)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.032000, -0.023415, 0.999214)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 1 Start"

	# Position "Attacker 2 Start"
	kThis = App.Waypoint_Create("Attacker 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.177231, 99.915833, 32.405682)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.030124, -0.999294, -0.022452)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.032000, -0.023415, 0.999214)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 2 Start"

	# Position "Attacker 3 Start"
	kThis = App.Waypoint_Create("Attacker 3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(26.990967, 168.634094, 30.711422)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.030124, -0.999294, -0.022452)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.032000, -0.023415, 0.999214)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 3 Start"

	# Position "Attacker 4 Start"
	kThis = App.Waypoint_Create("Attacker 4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(7.266040, 168.053864, 30.066116)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.030124, -0.999294, -0.022452)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.032000, -0.023415, 0.999214)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 4 Start"

	# Position "Attacker 5 Start"
	kThis = App.Waypoint_Create("Attacker 5 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-8.942280, 167.577148, 29.535862)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.030124, -0.999294, -0.022452)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.032000, -0.023415, 0.999214)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 5 Start"

	# Position "WarpIn(Warbird1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Warbird1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(25.217262, -866.128418, 22.763817)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Warbird1,player)"

	# Position "WarpIn(Klingon1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Klingon1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(16.086529, -347.802765, 17.298573)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Klingon1,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(21.873606, -308.293335, 2.885018)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

