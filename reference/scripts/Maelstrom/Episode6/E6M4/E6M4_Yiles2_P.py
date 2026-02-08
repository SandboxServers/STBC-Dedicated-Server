import App

def LoadPlacements(sSetName):
	# Light position "ambientlight 1"
	kThis = App.LightPlacement_Create("ambientlight 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-0.160713, 5.402538, 739.369873)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000000, 0.000000, -1.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000345, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(1.000000, 0.800000, 0.800000, 0.400000)
	kThis.Update(0)
	kThis = None
	# End position "ambientlight 1"

	# Position "Galor1Start"
	kThis = App.Waypoint_Create("Galor1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(155.155228, 333.914917, 18.857105)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.014692, -0.982631, 0.184987)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.195670, 0.178604, 0.964269)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Start"

	# Position "Keldon1Start"
	kThis = App.Waypoint_Create("Keldon1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(174.098846, 328.737793, 28.538290)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.025768, -0.970358, 0.240293)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.083502, 0.237444, 0.967806)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon1Start"

