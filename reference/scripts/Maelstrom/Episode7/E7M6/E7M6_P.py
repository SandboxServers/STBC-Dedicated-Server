import App

def LoadPlacements(sSetName):
	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.999997, 0.002645, 0.000035)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000011, -0.008945, 0.999960)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -760.167603, 1.094367)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "DS9 Start"
	kThis = App.Waypoint_Create("DS9 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.683567, 401.914978, -0.139217)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.040129, -0.996885, 0.067897)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.029710, 0.069112, 0.997166)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DS9 Start"

	# Position "Freighter 1 Start"
	kThis = App.Waypoint_Create("Freighter 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.683567, 380.914978, -0.139217)
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
	kThis.SetTranslateXYZ(16.427595, 382.769470, 24.717724)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.841936, 0.514610, -0.162236)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.014850, 0.278459, 0.960333)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 2 Start"

	# Position "Freighter 3 Start"
	kThis = App.Waypoint_Create("Freighter 3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(3.673252, 406.571411, 19.200527)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.826838, 0.551001, -0.112858)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.006273, 0.209678, 0.977750)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 3 Start"

	# Position "Freighter 4 Start"
	kThis = App.Waypoint_Create("Freighter 4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-20.683567, 400.914978, -0.139217)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.994850, -0.101264, 0.004330)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.009234, -0.048014, 0.998804)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter 4 Start"

	# Position "Freighter Way1"
	kThis = App.Waypoint_Create("Freighter Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-146.059158, 332.001831, 14.799413)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.918853, 0.387298, -0.075556)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023753, 0.245416, 0.969127)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter Way1"

	# Position "Freighter Way2"
	kThis = App.Waypoint_Create("Freighter Way2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-141.389023, 320.886749, 17.499643)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.918853, 0.387298, -0.075556)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023753, 0.245416, 0.969127)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter Way2"

	# Position "Freighter Way3"
	kThis = App.Waypoint_Create("Freighter Way3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-131.409164, 317.767090, 13.891102)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.908199, 0.383764, -0.167031)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.069672, 0.254891, 0.964456)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter Way3"

	# Position "Freighter Way4"
	kThis = App.Waypoint_Create("Freighter Way4", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-130.933517, 323.698761, 24.932814)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.908199, 0.383764, -0.167031)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.069672, 0.254891, 0.964456)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter Way4"

	# Position "Keldon 2 Start"
	kThis = App.Waypoint_Create("Keldon 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-74.164047, 529.754700, -12.777342)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027235, -0.994866, -0.097467)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000876, -0.097527, 0.995233)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon 2 Start"

	# Position "Galor 1 Start"
	kThis = App.Waypoint_Create("Galor 1 Start", sSetName, None)
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
	# End position "Galor 1 Start"

	# Position "Galor Start"
	kThis = App.Waypoint_Create("Galor Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-2.078336, 403.401031, 4.397809)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.949145, -0.241468, -0.202032)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.225668, 0.074316, 0.971366)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor Start"

	# Position "Keldon 1 Start"
	kThis = App.Waypoint_Create("Keldon 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-6.872293, 300.675201, -1.159772)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.189009, -0.974571, 0.120362)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.037478, 0.115323, 0.992621)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon 1 Start"

	# Position "Enemy Start 1"
	kThis = App.Waypoint_Create("Enemy Start 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-1463.171509, 670.452087, -357.859192)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.950406, -0.225460, 0.214234)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.206393, 0.058080, 0.976744)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy Start 1"

	# Position "Enemy Start 2"
	kThis = App.Waypoint_Create("Enemy Start 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-1440.607178, 651.355652, -344.223755)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.950406, -0.225460, 0.214234)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.206393, 0.058080, 0.976744)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy Start 2"

	# Position "Enemy Start 3"
	kThis = App.Waypoint_Create("Enemy Start 3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-1441.570679, 638.606384, -353.366699)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.950406, -0.225460, 0.214234)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.206393, 0.058080, 0.976744)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enemy Start 3"

	# Position "Escort 1 Start"
	kThis = App.Waypoint_Create("Escort 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1076.662720, 1134.825195, 8.689441)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.876930, -0.477570, 0.054038)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.053751, 0.014276, 0.998452)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Escort 1 Start"

	# Position "Escort 2 Start"
	kThis = App.Waypoint_Create("Escort 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1162.954956, 1181.889526, -1.300139)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.876930, -0.477570, 0.054038)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.053751, 0.014276, 0.998452)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Escort 2 Start"

	# Position "Random Start 2"
	kThis = App.Waypoint_Create("Random Start 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-147.948776, 694.056335, 250.401596)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.223176, -0.974697, -0.012578)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.053714, -0.000587, 0.998556)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 2"

	# Position "Random Start 3"
	kThis = App.Waypoint_Create("Random Start 3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-299.813171, 660.685242, 240.973480)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.223176, -0.974697, -0.012578)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.053714, -0.000587, 0.998556)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 3"

	# Position "Random Start 1"
	kThis = App.Waypoint_Create("Random Start 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-147.626602, 695.522644, 241.696747)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.223176, -0.974697, -0.012578)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.053714, -0.000587, 0.998556)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 1"

	# Position "Random Start 9"
	kThis = App.Waypoint_Create("Random Start 9", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(367.504852, -427.974762, -76.703255)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.680220, 0.723035, 0.120503)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.069709, -0.099841, 0.992558)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 9"

	# Position "Random Start 10"
	kThis = App.Waypoint_Create("Random Start 10", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(326.002594, -170.989929, -56.850502)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.688116, 0.712786, 0.135768)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.080452, -0.111009, 0.990558)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 10"

	# Position "Random Start 7"
	kThis = App.Waypoint_Create("Random Start 7", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(365.572388, -417.368408, -67.070854)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.638458, 0.758096, 0.132900)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.077395, -0.108561, 0.991072)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 7"

	# Position "Random Start 11"
	kThis = App.Waypoint_Create("Random Start 11", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(374.756317, -209.298096, -60.420258)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.493386, 0.861080, 0.122928)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.071383, -0.100766, 0.992346)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 11"

	# Position "Random Start 12"
	kThis = App.Waypoint_Create("Random Start 12", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(359.125763, -207.202667, -65.495369)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.658616, 0.738163, 0.146084)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.086598, -0.118493, 0.989172)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 12"

	# Position "Random Start 8"
	kThis = App.Waypoint_Create("Random Start 8", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(385.385193, -429.565643, -79.456642)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.679079, 0.724102, 0.120530)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.069716, -0.099835, 0.992559)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 8"

	# Position "Random Start 4"
	kThis = App.Waypoint_Create("Random Start 4", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-306.928497, 706.379761, 282.263306)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.251459, -0.913339, -0.320282)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.186248, -0.279068, 0.942037)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 4"

	# Position "Random Start 6"
	kThis = App.Waypoint_Create("Random Start 6", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-153.747833, 754.204041, 266.146027)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.251459, -0.913339, -0.320282)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.186248, -0.279068, 0.942037)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 6"

	# Position "Random Start 5"
	kThis = App.Waypoint_Create("Random Start 5", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-338.971924, 729.917847, 288.845306)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.314281, -0.888044, -0.335568)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.189021, -0.287864, 0.938832)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Random Start 5"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(16.215374, -155.122757, 16.333126)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Klingon1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Klingon1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(4.198962, -154.640320, 23.031208)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Klingon1,player)"

	# Position "WarpIn(Warbird1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Warbird1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-22.885746, -158.834549, -12.576447)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Warbird1,player)"

	# Position "WarpIn(Warbird1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Warbird1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-15.309295, -158.592392, 22.918072)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Warbird1,player)"

	# Position "WarpIn(Klingon1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Klingon1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-18.361778, -154.269501, -11.621831)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Klingon1,player)"

	# Position "Enterprise Start"
	kThis = App.Waypoint_Create("Enterprise Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-321.030884, -491.713684, 199.866608)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.324026, 0.937195, -0.129122)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.059822, 0.156510, 0.985863)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Start"

	# Position "WarpIn(Warbird1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Warbird1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-34.069313, -868.780823, 12.415565)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Warbird1,player)"

	# Position "WarpIn(Klingon1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Klingon1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(14.816725, -154.136139, 17.807270)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Klingon1,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-16.107744, -153.885117, 16.446863)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Klingon1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Klingon1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(8.110381, -1516.745605, 31.613148)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Klingon1,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.023510, -1146.173096, 27.822464)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Warbird1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Warbird1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(25.901749, -811.753784, 7.398955)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Warbird1,player)"

	# Position "WarpIn(Klingon1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Klingon1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-16.206863, -1116.561646, 20.318287)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Klingon1,player)"

	# Position "WarpIn(Warbird1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Warbird1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-24.633902, -811.807495, 11.283557)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Warbird1,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(16.906136, -807.362793, 15.562990)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "TargetPlanet"
	kThis = App.Waypoint_Create("TargetPlanet", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-9.075722, 643.777466, -42.552921)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.007041, -0.998742, -0.049646)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.039177, -0.049334, 0.998014)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "TargetPlanet"

	# Position "WarpIn(Klingon1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Klingon1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-31.538790, -1516.745728, -0.480365)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Klingon1,player)"

	# Position "WarpIn(Warbird1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Warbird1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-26.541275, -811.723816, -1.397700)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Warbird1,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-11.138983, -807.309998, 20.357819)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

	# Position "WarpIn(Warbird1,player)"
	kThis = App.PlacementObject_Create("WarpIn(Warbird1,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-25.109102, -811.671021, 10.048748)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Warbird1,player)"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-20.439753, -807.265198, -7.701956)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

