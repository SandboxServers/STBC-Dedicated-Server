import App

def LoadPlacements(sSetName):
	# Position "Enterprise Start"
	kThis = App.Waypoint_Create("Enterprise Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(0.000000, -11.879730, 1.094367)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Start"

	# Position "Attacker 1 Start"
	kThis = App.Waypoint_Create("Attacker 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-178.119232, 376.162445, 217.418015)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.303428, -0.872461, -0.383070)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.129408, -0.360567, 0.923713)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 1 Start"

	# Position "Attacker 2 Start"
	kThis = App.Waypoint_Create("Attacker 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-256.469208, 349.724854, 218.075043)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.410373, -0.819565, -0.399884)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.136669, -0.378282, 0.915546)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 2 Start"

	# Position "Attacker 3 Start"
	kThis = App.Waypoint_Create("Attacker 3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-231.530594, 392.255890, 228.649704)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.343626, -0.882688, -0.320599)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.107941, -0.302000, 0.947177)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 3 Start"

	# Position "Freighter 1 Start"
	kThis = App.Waypoint_Create("Freighter 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -450.028381, 103.239349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.092510, 0.876380, -0.472651)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.028061, 0.472203, 0.881043)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 1 Start"

	# Position "Freighter 2 Start"
	kThis = App.Waypoint_Create("Freighter 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -550.028381, 103.239349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027723, 0.948730, -0.314869)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.055645, 0.313037, 0.948109)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 2 Start"

	# Position "Freighter 3 Start"
	kThis = App.Waypoint_Create("Freighter 3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -650.028381, 103.239349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.015144, 0.961733, -0.273569)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.041149, 0.272770, 0.961199)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 3 Start"

	# Position "Freighter 4 Start"
	kThis = App.Waypoint_Create("Freighter 4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -750.028381, 103.239349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.001878, 0.966975, -0.254865)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.032408, 0.254790, 0.966453)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 4 Start"

	# Position "Freighter 5 Start"
	kThis = App.Waypoint_Create("Freighter 5 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -850.028381, 103.239349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000040, 0.973497, -0.228701)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.012725, 0.228682, 0.973418)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 5 Start"

	# Position "Freighter 6 Start"
	kThis = App.Waypoint_Create("Freighter 6 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -950.028381, 103.239349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.014611, 0.975714, -0.218561)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.025380, 0.218152, 0.975585)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 6 Start"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(0.000000, 150.879730, 1.094367)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, -1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Starbase Location"
	kThis = App.Waypoint_Create("Starbase Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-4.125638, -220.868958, 2.297139)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.023081, 0.998023, -0.058461)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.018197, 0.058047, 0.998148)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Starbase Location"

	# Position "Akira Start"
	kThis = App.Waypoint_Create("Akira Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(136.805984, -302.028381, 103.239349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.381868, 0.918817, -0.099761)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.005291, 0.105766, 0.994377)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Akira Start"

	# Position "Nebula Start"
	kThis = App.Waypoint_Create("Nebula Start", sSetName, None)
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
	# End position "Nebula Start"

	# Position "Nebula Way1"
	kThis = App.Waypoint_Create("Nebula Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-141.648849, -107.774872, 94.191910)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.766277, 0.637842, -0.077309)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.062796, 0.045399, 0.996993)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nebula Way1"

