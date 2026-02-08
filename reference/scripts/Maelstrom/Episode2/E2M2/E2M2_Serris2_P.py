import App

def LoadPlacements(sSetName):
	# Position "MarauderStart"
	kThis = App.Waypoint_Create("MarauderStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1618.800781, 1272.794922, 1033.651855)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.750851, 0.175441, 0.636744)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.531396, -0.412052, 0.740157)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "MarauderStart"

	# Position "Galor1Start"
	kThis = App.Waypoint_Create("Galor1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1620.313354, 1279.210083, 1052.079590)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.636249, -0.328081, -0.698248)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.716161, -0.085389, 0.692692)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Start"

	# Position "Galor2Start"
	kThis = App.Waypoint_Create("Galor2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1631.376099, 1252.627808, 1051.211304)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.742062, -0.021420, -0.669989)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.651554, -0.211859, 0.728418)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Start"

	# Position "MarauderWarp"
	kThis = App.Waypoint_Create("MarauderWarp", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(626.721741, -803.070313, 652.935120)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.420080, -0.893429, -0.159113)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.678346, 0.192677, 0.709029)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(3.000000)
	kThis.Update(0)
	kThis = None
	# End position "MarauderWarp"

	# Position "Galor1Enter"
	kThis = App.Waypoint_Create("Galor1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(534.542847, -31.066656, -69.842369)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.632179, 0.586882, 0.505885)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.774812, 0.475527, 0.416582)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Enter"

	# Position "Galor2Enter"
	kThis = App.Waypoint_Create("Galor2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(504.822906, -69.363342, -81.396019)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.631761, 0.558294, 0.537760)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.774814, 0.475630, 0.416460)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Enter"

