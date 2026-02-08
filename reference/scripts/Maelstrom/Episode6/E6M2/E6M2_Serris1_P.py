import App

def LoadPlacements(sSetName):
	# Position "NightEnter"
	kThis = App.Waypoint_Create("NightEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(95.631180, 28.921257, 0.407582)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.441124, 0.896514, 0.040904)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000637, -0.045265, 0.998975)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "NightEnter"

	# Position "Galor2Enter"
	kThis = App.Waypoint_Create("Galor2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(122.244553, -20.630306, -8.472235)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.042787, 0.000000, 0.999084)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Enter"

	# Position "Galor1Enter"
	kThis = App.Waypoint_Create("Galor1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(78.662071, -21.158308, -11.256001)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Enter"

	# Position "DauntlessStart"
	kThis = App.Waypoint_Create("DauntlessStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-21.772840, 244.609772, -49.897896)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.606505, 0.102192, 0.788485)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.531498, -0.685447, 0.497667)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DauntlessStart"

