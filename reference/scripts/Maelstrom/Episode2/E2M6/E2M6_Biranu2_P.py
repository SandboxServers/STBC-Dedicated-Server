import App

def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(129.241714, -239.744888, 34.713299)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.517425, 0.829443, -0.210466)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.056594, 0.212242, 0.975577)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Galor1Start"
	kThis = App.Waypoint_Create("Galor1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-3.637241, 215.136276, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.831245, -0.555651, 0.016861)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.066646, 0.129722, 0.989308)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Start"

	# Position "Bird2Start"
	kThis = App.Waypoint_Create("Bird2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-85.451897, 48.850796, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.551231, 0.829900, -0.086086)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.029470, 0.083747, 0.996051)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Bird2Start"

	# Position "Bird1Start"
	kThis = App.Waypoint_Create("Bird1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-111.685883, 66.663307, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.552234, 0.833267, 0.026519)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.011762, -0.024019, 0.999642)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Bird1Start"

	# Position "Galor6Start"
	kThis = App.Waypoint_Create("Galor6Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-890.546082, 2563.237549, -335.033752)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.378990, -0.919908, 0.100677)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.666146, -0.195678, 0.719694)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor6Start"

	# Position "Galor2Start"
	kThis = App.Waypoint_Create("Galor2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-1.199428, 251.322540, -0.879682)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.625489, -0.778959, -0.044570)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.131981, 0.049331, 0.990024)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Start"

	# Position "Galor3Start"
	kThis = App.Waypoint_Create("Galor3Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(56.101540, 228.936401, 8.137798)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.768728, -0.633545, -0.087629)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.138242, 0.030818, 0.989919)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor3Start"

	# Position "Galor4Start"
	kThis = App.Waypoint_Create("Galor4Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(26.405731, 201.711609, 5.319317)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.888162, -0.441525, -0.127374)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.165731, 0.049238, 0.984941)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor4Start"

	# Position "BOP1Enter"
	kThis = App.Waypoint_Create("BOP1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(385.268250, 49.357853, 238.281830)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.870681, 0.194917, -0.451577)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.427731, 0.153198, 0.890829)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOP1Enter"

	# Position "BOP2Enter"
	kThis = App.Waypoint_Create("BOP2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(401.274811, 113.219940, 234.984879)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.870681, 0.194917, -0.451577)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.427731, 0.153198, 0.890829)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BOP2Enter"

	# Position "Galor5Way"
	kThis = App.Waypoint_Create("Galor5Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-282.316986, 641.310486, -95.418533)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.334488, -0.928641, 0.160449)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.229925, 0.084694, 0.969516)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor5Way"

	# Position "Galor6Way"
	kThis = App.Waypoint_Create("Galor6Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-229.024643, 628.764526, -85.033966)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.334488, -0.928641, 0.160449)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.241332, 0.080173, 0.967125)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor6Way"

	# Position "PlayerEnterBiranu2"
	kThis = App.Waypoint_Create("PlayerEnterBiranu2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(308.939331, -426.008636, 97.627693)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.625584, 0.746472, -0.226771)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.064741, 0.239998, 0.968612)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "PlayerEnterBiranu2"

	# Position "Galor5Start"
	kThis = App.Waypoint_Create("Galor5Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-801.652222, 2622.322510, -385.083740)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.316352, -0.943041, 0.102933)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.048264, 0.124365, 0.991062)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor5Start"

	# Position "GalorReturn1"
	kThis = App.Waypoint_Create("GalorReturn1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(168.118027, 284.589386, 69.772179)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.767225, -0.549400, -0.330947)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.394398, -0.002779, 0.918935)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "GalorReturn1"

	# Position "GalorReturn2"
	kThis = App.Waypoint_Create("GalorReturn2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(158.034683, 301.247040, 65.494949)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.767225, -0.549400, -0.330947)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.394398, -0.002779, 0.918935)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "GalorReturn2"

