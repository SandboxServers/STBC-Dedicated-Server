import App

def LoadPlacements(sSetName):
	# Position "Akira Start"
	kThis = App.Waypoint_Create("Akira Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(143.518600, 5602.644043, 10.723104)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.959056, -0.234192, -0.159267)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.173895, 0.043059, 0.983822)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Akira Start"

	# Position "Akira Way1"
	kThis = App.Waypoint_Create("Akira Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-95.103294, 5560.052734, -8.505226)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.978231, 0.200654, 0.052928)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.064735, 0.052741, 0.996508)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Akira Way1"

	# Position "Kessok Start"
	kThis = App.Waypoint_Create("Kessok Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(153.518600, 5612.644043, 10.723104)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.959056, -0.234192, -0.159267)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.173895, 0.043059, 0.983822)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kessok Start"

	# Position "Galor1 Start"
	kThis = App.Waypoint_Create("Galor1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(37.695801, 5587.070801, -6.828341)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.980040, -0.198080, -0.016898)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.032497, 0.075764, 0.996596)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1 Start"

	# Position "Galor2 Start"
	kThis = App.Waypoint_Create("Galor2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(133.518600, 5492.644043, 10.723104)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.959056, -0.234192, -0.159267)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.173895, 0.043059, 0.983822)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Start"

