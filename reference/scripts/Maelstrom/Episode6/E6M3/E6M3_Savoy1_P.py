import App

def LoadPlacements(sSetName):
	# Position "Keldon2Start"
	kThis = App.Waypoint_Create("Keldon2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(138.410446, -82.014030, 197.045425)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.915646, -0.127124, -0.381355)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.401252, 0.231766, 0.886161)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon2Start"

	# Position "Galor3Start"
	kThis = App.Waypoint_Create("Galor3Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(175.778702, -160.161987, 228.673279)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.982481, -0.073577, -0.171226)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.184659, 0.260321, 0.947699)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor3Start"

	# Position "Transport1Enter"
	kThis = App.Waypoint_Create("Transport1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(211.822250, 250.558838, 98.836594)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.046468, -0.943559, 0.327929)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.974701, -0.029021, -0.221619)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Transport1Enter"

	# Position "Keldon3Enter"
	kThis = App.Waypoint_Create("Keldon3Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(164.972366, 275.414063, 54.750477)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027167, -0.976763, -0.212594)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.828741, -0.096914, 0.551177)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon3Enter"

	# Position "Transport2Enter"
	kThis = App.Waypoint_Create("Transport2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(249.112259, 250.310364, 53.901990)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.066898, -0.997642, -0.015334)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.523780, -0.048195, 0.850489)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Transport2Enter"

	# Position "PlayerEnterSavoy1"
	kThis = App.Waypoint_Create("PlayerEnterSavoy1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-650.042847, -829.489136, -42.943996)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.258794, 0.929546, -0.262619)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.101462, 0.296538, 0.949616)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "PlayerEnterSavoy1"

	# Position "KhitEnter"
	kThis = App.Waypoint_Create("KhitEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-500.622559, -700.090454, -47.953625)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.685954, 0.645142, 0.336539)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.159310, -0.318130, 0.934566)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitEnter"

	# Position "FedEnter"
	kThis = App.Waypoint_Create("FedEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-591.801941, -879.721924, -39.355862)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.647086, 0.631062, 0.427833)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.305568, -0.299450, 0.903857)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "FedEnter"

	# Position "Keldon1Enter"
	kThis = App.Waypoint_Create("Keldon1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-99.790245, -252.405441, 3.500576)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.989264, -0.093194, -0.112571)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.107517, -0.057603, 0.992533)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon1Enter"

	# Position "Galor1Enter"
	kThis = App.Waypoint_Create("Galor1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-101.366386, -231.308594, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.995339, -0.000113, 0.096440)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.096293, -0.056438, 0.993752)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Enter"

	# Position "Galor2Enter"
	kThis = App.Waypoint_Create("Galor2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-98.802910, -275.620117, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.990424, -0.001083, 0.138055)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.137962, -0.045307, 0.989401)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Enter"

	# Position "Keldon4Enter"
	kThis = App.Waypoint_Create("Keldon4Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(292.278259, 250.432434, 48.532455)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.139655, -0.909510, -0.391520)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.812231, 0.331377, -0.480073)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon4Enter"

	# Position "Keldon5Enter"
	kThis = App.Waypoint_Create("Keldon5Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(292.278259, 250.432434, -10.532455)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.139655, -0.909510, -0.391520)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.812231, 0.331377, -0.480073)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon5Enter"

	# Position "Galor4Enter"
	kThis = App.Waypoint_Create("Galor4Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(249.159958, 175.534180, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.017103, -0.999835, 0.006119)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.239049, 0.001853, 0.971006)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor4Enter"

	# Position "ShuttleWatch"
	kThis = App.Waypoint_Create("ShuttleWatch", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(144.437744, -152.206894, 216.701752)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.499792, 0.864740, 0.049335)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.153724, -0.032504, -0.987579)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.000000)
	kThis.Update(0)
	kThis = None
	# End position "ShuttleWatch"

	# Position "ShuttleWay2"
	kThis = App.Waypoint_Create("ShuttleWay2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(161.602249, -130.389481, 217.157349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.978129, 0.099697, -0.182550)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.189681, 0.067397, -0.979530)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.000000)
	kThis.Update(0)
	kThis = None
	# End position "ShuttleWay2"

	# Position "ShuttleWay1"
	kThis = App.Waypoint_Create("ShuttleWay1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(156.265549, -130.767441, 216.730194)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.996234, 0.083662, 0.022760)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.014140, 0.102224, -0.994661)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ShuttleWay1"

	# Position "KhitLaunch2"
	kThis = App.Waypoint_Create("KhitLaunch2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(132.801163, -137.225891, 217.071350)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.949595, -0.002804, 0.313467)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.312802, 0.074183, -0.946917)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(2.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitLaunch2"

	# Position "KhitLaunch1"
	kThis = App.Waypoint_Create("KhitLaunch1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(59.193924, -131.038773, 198.255600)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.966540, -0.009376, 0.256343)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.256179, -0.015805, -0.966500)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitLaunch1"
	
	# Position "KhitLaunch0"
	kThis = App.Waypoint_Create("KhitLaunch0", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(59.193924, -131.038773, 198.255600)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.966540, -0.009376, 0.256343)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.256179, -0.015805, -0.966500)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitLaunch0"

	# Attaching object "ShuttleWay2" after "ShuttleWay1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "ShuttleWay1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "ShuttleWay2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "KhitLaunch2" after "KhitLaunch1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "KhitLaunch1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "KhitLaunch2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
