import App

def LoadPlacements(sSetName):
	# Position "Matan Start"
	kThis = App.Waypoint_Create("Matan Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(443.637573, -54.755764, 26.631081)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.411094, 0.907778, -0.083310)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.089324, 0.050837, 0.994704)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Matan Start"

	# Position "Keldon1 Start"
	kThis = App.Waypoint_Create("Keldon1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-770.316162, 832.661987, -63.628872)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.975992, 0.217377, 0.013638)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.025479, 0.051761, 0.998334)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon1 Start"

	# Position "Keldon2 Start"
	kThis = App.Waypoint_Create("Keldon2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(423.379150, 1660.791016, 2.154602)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.466130, -0.884556, 0.016843)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.076896, 0.059472, 0.995264)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon2 Start"

	# Position "Galor1 Start"
	kThis = App.Waypoint_Create("Galor1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1082.005005, 573.334351, 61.992863)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.929647, 0.352688, -0.106618)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.100248, 0.036336, 0.994299)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1 Start"

	# Position "Galor2 Start"
	kThis = App.Waypoint_Create("Galor2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(261.306183, 1894.551880, 76.516998)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.284392, -0.951324, -0.118759)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.129775, -0.084533, 0.987933)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Start"

	# Position "Galor3 Start"
	kThis = App.Waypoint_Create("Galor3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-674.959595, 1679.170288, 9.483944)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.722576, -0.690796, -0.026173)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.034764, -0.074125, 0.996643)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor3 Start"

	# Position "Galor4 Start"
	kThis = App.Waypoint_Create("Galor4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-460.609283, 320.470642, -73.639877)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.491854, 0.870633, -0.008812)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.209239, -0.108371, 0.971841)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor4 Start"

	# Position "Galor5 Start"
	kThis = App.Waypoint_Create("Galor5 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1096.205200, 1085.203369, 85.010582)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.988566, -0.088607, -0.122010)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.107588, -0.152460, 0.982436)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor5 Start"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(106.230408, -1709.395386, 81.737831)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.081894, 0.995771, -0.041636)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.098640, 0.033473, 0.994560)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Sat 1 Start"
	kThis = App.Waypoint_Create("Sat 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-438.940887, 610.550659, -68.123306)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.944004, -0.328995, -0.024867)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.015916, -0.029871, 0.999427)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Sat 1 Start"

	# Position "Sat 2 Start"
	kThis = App.Waypoint_Create("Sat 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(386.006165, 1366.801025, 60.633732)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.686052, 0.698950, 0.201995)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.223226, -0.062028, 0.972791)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Sat 2 Start"

	# Position "Nav Alpha"
	kThis = App.Waypoint_Create("Nav Alpha", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(0.00, -500.00, 0.00)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026836, 0.999594, -0.009591)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000129, 0.009591, 0.999954)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Alpha"

	# Position "Nav Beta"
	kThis = App.Waypoint_Create("Nav Beta", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(1500.00, 1000.00, 0.00)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026836, 0.999594, -0.009591)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000129, 0.009591, 0.999954)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Beta"

	# Position "Nav Gamma"
	kThis = App.Waypoint_Create("Nav Gamma", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(0.00, 2500.00, 0.00)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026836, 0.999594, -0.009591)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000129, 0.009591, 0.999954)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Gamma"

	# Position "Nav Delta"
	kThis = App.Waypoint_Create("Nav Delta", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(-1500.00, 1000.00, 0.00)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026836, 0.999594, -0.009591)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000129, 0.009591, 0.999954)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Delta"