import App

def LoadPlacements(sSetName):
	# Position "NightEnter"
	kThis = App.Waypoint_Create("NightEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-69.946289, 30.118431, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "NightEnter"

	# Position "Galor1Enter"
	kThis = App.Waypoint_Create("Galor1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(250.067932, 275.484100, 100.134230)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.274271, -0.334839, -0.901476)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.247195, 0.930472, -0.270401)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Enter"

	# Position "Derelict1Start"
	kThis = App.Waypoint_Create("Derelict1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(440.435181, 295.632446, 416.472900)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.255369, 0.666479, -0.700423)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.233235, 0.745513, 0.624349)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Derelict1Start"

	# Position "Derelict2Start"
	kThis = App.Waypoint_Create("Derelict2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(200.359406, -50.016174, 200.467712)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.751825, -0.459336, 0.473043)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.143051, 0.813966, 0.563024)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Derelict2Start"

	# Position "Derelict3Start"
	kThis = App.Waypoint_Create("Derelict3Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.052887, 350.542725, 100.663361)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.041959, -0.989385, -0.139128)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.218782, -0.144970, 0.964945)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Derelict3Start"

	# Position "Pod5Start"
	kThis = App.Waypoint_Create("Pod5Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-19.661530, 409.689819, 126.800537)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.058156, -0.975799, -0.210795)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.215037, -0.218440, 0.951863)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod5Start"
	
	# Position "Pod 5"
	kThis = App.Waypoint_Create("Pod 5", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-1.661530, 419.689819, 146.800537)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.058156, -0.975799, -0.210795)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.215037, -0.218440, 0.951863)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod 5"

	# Position "Pod6Start"
	kThis = App.Waypoint_Create("Pod6Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(22.371124, 429.455444, 128.542236)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.058156, -0.975799, -0.210795)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.215037, -0.218440, 0.951863)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod6Start"
	
	# Position "Pod 6"
	kThis = App.Waypoint_Create("Pod 6", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(40.371124, 469.455444, 128.542236)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.058156, -0.975799, -0.210795)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.215037, -0.218440, 0.951863)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod 6"

	# Position "Galor1Returns"
	kThis = App.Waypoint_Create("Galor1Returns", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(250.194641, 175.837158, 200.423279)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.124726, -0.985040, 0.118910)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.256773, 0.083717, 0.962839)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Returns"

	# Position "Galor2Enters"
	kThis = App.Waypoint_Create("Galor2Enters", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(275.867279, 200.481201, 200.891449)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.090522, -0.973916, 0.208071)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.042062, 0.205003, 0.977857)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Enters"

	# Position "Pod3Start"
	kThis = App.Waypoint_Create("Pod3Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(175.332550, -25.628601, 150.257538)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.739045, -0.518830, 0.429684)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.198788, 0.777397, 0.596773)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod3Start"
	
	# Position "Pod 3"
	kThis = App.Waypoint_Create("Pod 3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(205.332550, -45.628601, 180.257538)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.739045, -0.518830, 0.429684)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.198788, 0.777397, 0.596773)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod 3"

	# Position "Pod4Start"
	kThis = App.Waypoint_Create("Pod4Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(225.527374, -20.666565, 200.799469)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.580177, -0.337566, 0.741245)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.472455, 0.601841, 0.643874)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod4Start"
	
	# Position "Pod 4"
	kThis = App.Waypoint_Create("Pod 4", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(145.527374, -50.666565, 215.799469)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.580177, -0.337566, 0.741245)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.472455, 0.601841, 0.643874)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod 4"

	# Position "Pod1Start"
	kThis = App.Waypoint_Create("Pod1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(556.757629, 346.392303, 300.355469)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.272071, 0.608955, -0.745085)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.213519, 0.793195, 0.570308)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod1Start"

	# Position "Pod 1"
	kThis = App.Waypoint_Create("Pod 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(520.757629, 326.392303, 280.355469)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.272071, 0.608955, -0.745085)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.213519, 0.793195, 0.570308)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod 1"

	# Position "Pod2Start"
	kThis = App.Waypoint_Create("Pod2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(485.293091, 394.850372, 296.207123)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.272071, 0.608955, -0.745085)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.213519, 0.793195, 0.570308)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod2Start"
	
	# Position "Pod 2"
	kThis = App.Waypoint_Create("Pod 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(465.293091, 420.850372, 276.207123)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.272071, 0.608955, -0.745085)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.213519, 0.793195, 0.570308)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Pod 2"

