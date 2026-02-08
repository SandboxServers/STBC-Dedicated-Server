import App

def LoadPlacements(sSetName):
	# Position "Buster Location"
	kThis = App.Waypoint_Create("Buster Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(0.683567, 401.914978, -0.139217)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.040128, -0.996885, 0.067897)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.029710, 0.069112, 0.997166)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Buster Location"

	# Position "Attacker 1 Start"
	kThis = App.Waypoint_Create("Attacker 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-30.660204, 528.578796, -12.930603)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027234, -0.994866, -0.097467)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000868, -0.097527, 0.995233)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 1 Start"

	# Position "Attacker 2 Start"
	kThis = App.Waypoint_Create("Attacker 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(42.856041, 511.744934, 0.325140)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.112251, -0.993149, -0.032477)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.279787, -0.062950, 0.957996)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 2 Start"

	# Position "Akira Start"
	kThis = App.Waypoint_Create("Akira Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(12.362000, -86.734779, 0.486929)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.003875, 0.999819, -0.018640)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.024821, 0.018538, 0.999520)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Akira Start"



