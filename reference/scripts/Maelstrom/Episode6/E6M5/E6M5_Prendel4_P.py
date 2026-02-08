import App

def LoadPlacements(sSetName):
	# Position "Galor2Start"
	kThis = App.Waypoint_Create("Galor2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(11.961557, 112.904625, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Start"

	# Position "Galor1Start"
	kThis = App.Waypoint_Create("Galor1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-4.402919, 123.814392, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Start"

