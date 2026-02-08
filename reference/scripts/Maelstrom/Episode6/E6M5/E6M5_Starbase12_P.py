import App

def LoadPlacements(sSetName):
	# Position "ZhukovStart"
	kThis = App.Waypoint_Create("ZhukovStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-158.472336, 104.596413, -9.935953)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.879631, -0.475476, -0.013109)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.036942, -0.095766, 0.994718)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ZhukovStart"

	# Position "KhitomerStart"
	kThis = App.Waypoint_Create("KhitomerStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-90.564156, 73.949936, -7.457346)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.883476, -0.466004, 0.048061)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.032403, 0.041560, 0.998610)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitomerStart"

	# Position "FedStart"
	kThis = App.Waypoint_Create("FedStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-112.698929, 92.717216, -8.216973)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.865081, -0.491518, 0.100226)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.115058, 0.000054, 0.993359)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "FedStart"

