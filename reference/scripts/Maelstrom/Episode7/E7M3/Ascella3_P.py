import App

def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -107.879730, 1.094367)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Station Start"
	kThis = App.Waypoint_Create("Station Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-15.877895, 813.733704, -26.893398)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.041898, -0.998889, 0.021571)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.042232, 0.019800, 0.998912)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Station Start"

	# Position "Attacker 1 Start"
	kThis = App.Waypoint_Create("Attacker 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-404.588615, 523.926453, 30.062788)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000768, -0.994441, -0.105293)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000393, -0.105293, 0.994441)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 1 Start"

	# Position "Attacker 2 Start"
	kThis = App.Waypoint_Create("Attacker 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-454.489613, 509.639954, 25.696476)
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
	kThis.SetTranslateXYZ(-500.032189, 518.459778, 24.986773)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.006078, -0.967386, 0.253233)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.073854, 0.252980, 0.964649)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 3 Start"

	# Position "Attacker 6 Start"
	kThis = App.Waypoint_Create("Attacker 6 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-500.615120, 631.117188, -34.168201)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027221, -0.984807, -0.171506)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.001156, -0.171538, 0.985177)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 6 Start"

	# Position "Attacker 5 Start"
	kThis = App.Waypoint_Create("Attacker 5 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-450.305363, 630.895325, -33.194187)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027221, -0.984807, -0.171506)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.001156, -0.171538, 0.985177)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 5 Start"

	# Position "Attacker 4 Start"
	kThis = App.Waypoint_Create("Attacker 4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-400.223186, 601.293945, -39.711323)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027221, -0.984807, -0.171506)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.001156, -0.171538, 0.985177)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 4 Start"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -133.524429, 1.094367)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "Defender 1 Start"
	kThis = App.Waypoint_Create("Defender 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-36.366062, 813.816345, -26.669556)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.999615, 0.018171, -0.020987)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.021169, -0.009895, 0.999727)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Defender 1 Start"

	# Position "Defender 2 Start"
	kThis = App.Waypoint_Create("Defender 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(4.751131, 808.227478, -28.143875)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.993619, 0.099931, -0.052290)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.050737, 0.018021, 0.998549)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Defender 2 Start"

	# Position "Freighter 1 Start"
	kThis = App.Waypoint_Create("Freighter 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-8.187950, 814.775513, -17.061169)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.994850, -0.101264, 0.004330)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.009234, -0.048014, 0.998804)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 1 Start"

	# Position "Freighter 2 Start"
	kThis = App.Waypoint_Create("Freighter 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-22.708088, 814.157410, -16.809805)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.999533, -0.021486, -0.021734)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023174, 0.069237, 0.997331)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 2 Start"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -134.408813, 1.056601)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "Reinforcement 1 Start"
	kThis = App.Waypoint_Create("Reinforcement 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(405.051567, 922.959473, -207.071566)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.162293, -0.984909, 0.060127)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.065303, 0.050081, 0.996608)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Reinforcement 1 Start"

	# Position "Reinforcement 2 Start"
	kThis = App.Waypoint_Create("Reinforcement 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(456.439369, 936.883789, -202.156460)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.009443, -0.999035, 0.042894)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.027413, 0.042621, 0.998715)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Reinforcement 2 Start"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -133.959213, 1.057241)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -134.963074, 1.055812)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -134.099609, 1.057041)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "Defender 1 Way"
	kThis = App.Waypoint_Create("Defender 1 Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-42.624134, 803.331909, -21.631437)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.125499, -0.989677, 0.069206)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.004512, 0.070326, 0.997514)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Defender 1 Way"

	# Position "Defender 2 Way"
	kThis = App.Waypoint_Create("Defender 2 Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(10.406601, 802.754822, -23.803421)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.044573, -0.992841, -0.110815)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.197797, -0.117500, 0.973175)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Defender 2 Way"

	# Position "Freighter 2 Way"
	kThis = App.Waypoint_Create("Freighter 2 Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-25.176704, 824.395508, -18.665239)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.447990, 0.833791, -0.322642)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.010979, 0.365985, 0.930556)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 2 Way"

	# Position "Freighter 1 Way"
	kThis = App.Waypoint_Create("Freighter 1 Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-9.421304, 824.910156, -18.302332)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.407485, 0.861398, -0.303232)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000147, 0.332112, 0.943240)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 1 Way"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -844.374207, 0.045913)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -135.059143, 1.055675)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -395.593262, 0.684786)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-21.926085, -155.021515, 4.822749)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "Freighter 3 Start"
	kThis = App.Waypoint_Create("Freighter 3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-21.267883, 813.954590, -38.073811)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.992429, -0.117423, -0.036020)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.049287, 0.112116, 0.992472)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 3 Start"

	# Position "Freighter 4 Start"
	kThis = App.Waypoint_Create("Freighter 4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-10.731849, 814.003296, -38.688568)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.967527, 0.245946, -0.058323)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.020884, 0.152168, 0.988134)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 4 Start"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(20.466187, -155.084274, 9.761812)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "Defender 3 Start"
	kThis = App.Waypoint_Create("Defender 3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-20.278038, 803.936523, -24.031494)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.336908, -0.940510, 0.043975)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.015561, 0.041137, 0.999032)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Defender 3 Start"

	# Position "Defender 3 Way"
	kThis = App.Waypoint_Create("Defender 3 Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-31.196918, 759.456665, -22.929098)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.056930, -0.998081, 0.024357)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.004360, 0.024645, 0.999687)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Defender 3 Way"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-15.710914, -155.099152, -14.731240)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(13.978365, -154.871017, 18.341171)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "Freighter 4 Way"
	kThis = App.Waypoint_Create("Freighter 4 Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-9.227180, 818.818787, -37.969707)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.043839, 0.986719, -0.156409)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.018448, 0.155733, 0.987627)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 4 Way"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(18.377691, -864.410645, 25.594938)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.999999, 0.001424)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, -0.001424, 0.999999)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "Freighter 3 Way"
	kThis = App.Waypoint_Create("Freighter 3 Way", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-21.248009, 818.791321, -36.403893)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 0.997314, -0.073247)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.073247, 0.997314)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 3 Way"

