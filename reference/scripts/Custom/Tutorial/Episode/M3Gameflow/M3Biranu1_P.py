import App

def LoadPlacements(sSetName):
	# Position "Galaxy1Start"
	kThis = App.Waypoint_Create("Galaxy1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(157.791214, 105.691772, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.802961, -0.595512, -0.024877)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.060600, 0.040047, 0.997359)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galaxy1Start"

	# Position "Galaxy2Start"
	kThis = App.Waypoint_Create("Galaxy2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(24.614307, 407.666870, 21.618629)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.402822, -0.913068, -0.063569)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.091298, -0.029023, 0.995401)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galaxy2Start"
