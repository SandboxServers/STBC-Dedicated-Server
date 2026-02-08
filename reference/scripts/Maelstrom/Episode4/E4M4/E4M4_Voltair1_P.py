import App

def LoadPlacements(sSetName):
	# Position "Mavjop Start"
	kThis = App.Waypoint_Create("Mavjop Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(10.025375, -151.701675, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mavjop Start"

	# Position "Keldon1 Warp In"
	kThis = App.Waypoint_Create("Keldon1 Warp In", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-321.911285, 163.865173, 27.580957)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.742245, -0.650878, -0.159471)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.029094, -0.269045, 0.962688)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon1 Warp In"

	# Position "Keldon2 Warp In"
	kThis = App.Waypoint_Create("Keldon2 Warp In", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-374.661835, 118.702148, 115.125320)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.711113, -0.617588, -0.336010)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.353995, -0.098411, 0.930055)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon2 Warp In"

	# Position "Hybrid Start"
	kThis = App.Waypoint_Create("Hybrid Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-351.111206, 129.358627, 5.173337)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.778618, -0.625563, -0.049246)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.111502, 0.060697, 0.991909)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Hybrid Start"

	# Position "WarpIn(Mavjop,Player)"
	kThis = App.PlacementObject_Create("WarpIn(Mavjop,Player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-54.427795, -535.243225, -4.298451)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Mavjop,Player)"

	# Position "Galor1 Start"
	kThis = App.Waypoint_Create("Galor1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-42.061562, -780.892090, 28.758608)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.003130, 0.997507, -0.070498)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000110, 0.070498, 0.997512)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1 Start"

	# Position "Galor2 Start"
	kThis = App.Waypoint_Create("Galor2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(22.928116, -770.514465, 30.080055)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.997208, -0.074680)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.001036, 0.074680, 0.997207)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Start"

	# Position "WarpIn(Mavjop,Player)"
	kThis = App.PlacementObject_Create("WarpIn(Mavjop,Player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-31.710220, -444.296722, 20.394049)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Mavjop,Player)"

	# Position "WarpIn(Mavjop,Player)"
	kThis = App.PlacementObject_Create("WarpIn(Mavjop,Player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-34.033428, -272.163605, 20.670351)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Mavjop,Player)"

