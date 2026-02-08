import App

def LoadPlacements(sSetName):
	# Position "Buster Location"
	kThis = App.Waypoint_Create("Buster Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-17.139893, 844.691284, -30.296316)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.040128, -0.996885, 0.067897)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.029710, 0.069112, 0.997166)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Buster Location"

	# Position "Emitter Location"
	kThis = App.Waypoint_Create("Emitter Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-117.139893, 1044.691284, -100.296316)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.040128, -0.996885, 0.067897)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.029710, 0.069112, 0.997166)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Emitter Location"

	# Position "Attacker 1 Start"
	kThis = App.Waypoint_Create("Attacker 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-30.660204, 528.578796, -12.930603)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027235, -0.994866, -0.097467)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000869, -0.097527, 0.995233)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 1 Start"

	# Position "Attacker 2 Start"
	kThis = App.Waypoint_Create("Attacker 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(42.856041, 511.744934, 0.325140)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.112251, -0.993149, -0.032476)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.279787, -0.062950, 0.957996)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 2 Start"

	# Position "Attacker 3 Start"
	kThis = App.Waypoint_Create("Attacker 3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(122.856041, 490.744934, 12.325140)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.112251, -0.993149, -0.032476)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.279787, -0.062950, 0.957996)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 3 Start"

	# Position "Akira Start"
	kThis = App.Waypoint_Create("Akira Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(12.362000, -86.734779, 0.486929)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.003872, 0.999819, -0.018640)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.024821, 0.018538, 0.999520)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Akira Start"

	# Position "WarpIn(USS Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(USS Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(22.506639, 180.701050, -12.316648)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.038132, -0.999210, 0.011194)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.027243, 0.012238, 0.999554)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(USS Geronimo,player)"

	# Position "WarpIn(USS San Francisco,player)"
	kThis = App.PlacementObject_Create("WarpIn(USS San Francisco,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-25.604576, 48.701988, 1.325079)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.038132, -0.999210, 0.011194)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.027243, 0.012238, 0.999554)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(USS San Francisco,player)"

	# Position "Galor Start"
	kThis = App.Waypoint_Create("Galor Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-10.447950, 780.035461, -26.668562)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.066574, 0.997766, 0.005559)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.095290, 0.000812, 0.995449)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor Start"

	# Position "Kessok1 Start"
	kThis = App.Waypoint_Create("Kessok1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-37.663799, 663.972778, -17.796301)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.086908, 0.993227, -0.077123)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.090292, 0.069244, 0.993505)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kessok1 Start"

	# Position "Kessok2 Start"
	kThis = App.Waypoint_Create("Kessok2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-92.039337, 601.642334, -5.939822)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.304928, 0.942033, -0.139971)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.103319, 0.113382, 0.988165)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kessok2 Start"

	# Position "Kessok3 Start"
	kThis = App.Waypoint_Create("Kessok3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-166.103851, 574.268188, 9.281580)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.457858, 0.876590, -0.148175)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.111503, 0.108733, 0.987798)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kessok3 Start"

	# Position "Kessok4 Start"
	kThis = App.Waypoint_Create("Kessok4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(36.182053, 668.159058, -21.907513)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.402917, 0.914237, 0.042750)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.019319, -0.038204, 0.999083)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kessok4 Start"

	# Position "Kessok5 Start"
	kThis = App.Waypoint_Create("Kessok5 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(86.101433, 613.415649, -22.041222)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.484057, 0.873901, -0.044557)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.020985, 0.039312, 0.999007)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kessok5 Start"

	# Position "Kessok6 Start"
	kThis = App.Waypoint_Create("Kessok6 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(162.002213, 576.486572, -10.341310)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.643061, 0.759344, -0.099346)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.057460, 0.081518, 0.995014)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kessok6 Start"

