import App

def LoadPlacements(sSetName):
	# Position "Circling Nebula"
	kThis = App.Waypoint_Create("Circling Nebula", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-34.326130, -23.886063, 5.916601)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.867540, 0.488582, 0.093068)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.054240, -0.093068, 0.994181)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Circling Nebula"

	# Position "Nightingale Docked"
	kThis = App.Waypoint_Create("Nightingale Docked", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-36.426445, 118.173058, 17.325975)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.882397, 0.470025, 0.021281)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.010759, -0.025062, 0.999628)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nightingale Docked"

	# Position "Berkeley Docked"
	kThis = App.Waypoint_Create("Berkeley Docked", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-15.815783, 100.082222, 16.639843)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.480894, -0.870034, 0.108543)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.059553, 0.091099, 0.994060)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Berkeley Docked"
