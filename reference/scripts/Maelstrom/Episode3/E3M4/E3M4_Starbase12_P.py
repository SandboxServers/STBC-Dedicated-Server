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

	# Position "Nightingale Start"
	kThis = App.Waypoint_Create("Nightingale Start", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-50.693661, -182.781647, 102.378326)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.803609, 0.591219, -0.068358)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.038691, 0.062718, 0.997281)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nightingale Start"