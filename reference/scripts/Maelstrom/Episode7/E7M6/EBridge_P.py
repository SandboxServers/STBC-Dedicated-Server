import App

def LoadPlacements(sSetName):
	# Position "Kiska Cam"
	kThis = App.Waypoint_Create("Kiska Cam", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(92.573601, -86.224724, 65.536186)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.904199, 0.374500, -0.205363)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.184135, 0.092042, 0.978582)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kiska Cam"

	# Position "Felix Cam"
	kThis = App.Waypoint_Create("Felix Cam", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-84.937317, -84.529060, 69.000374)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.900172, 0.383251, -0.206903)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.185586, 0.092241, 0.978289)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Felix Cam"

	# Position "Miguel Cam1"
	kThis = App.Waypoint_Create("Miguel Cam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-110.328079, -24.453890, 69.554047)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.980914, 0.139413, -0.135540)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.132468, 0.031127, 0.990698)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Miguel Cam1"

	# Position "Saffi Cam1"
	kThis = App.Waypoint_Create("Saffi Cam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-91.592323, 23.261969, 65.603882)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.090552, 0.984343, -0.151225)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.035763, 0.148537, 0.988260)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Saffi Cam1"

	# Position "Guest Cam1"
	kThis = App.Waypoint_Create("Guest Cam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(86.251808, 16.587458, 65.862099)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.060731, 0.985471, -0.158616)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000597, 0.158945, 0.987287)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Guest Cam1"

	# Position "Guest Cam2"
	kThis = App.Waypoint_Create("Guest Cam2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(14.980963, 56.911800, 67.273163)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.894753, 0.425779, -0.134644)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.119564, 0.062090, 0.990883)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Guest Cam2"

	# Position "Brex Cam1"
	kThis = App.Waypoint_Create("Brex Cam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(113.730728, -32.632023, 70.781898)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.909627, 0.363607, -0.200920)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.188086, 0.070770, 0.979599)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Brex Cam1"

	# Position "Player Cam"
	kThis = App.Waypoint_Create("Player Cam", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.683736, 129.585007, 70.678001)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000000, -1.000000, -0.000002)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000366, -0.000002, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Cam"

	# Position "View"
	kThis = App.Waypoint_Create("View", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.683737, -98.453148, 70.677628)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.209519, -0.977805, 0.000022)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000122, -0.000004, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "View"

	# Position "Felix Head"
	kThis = App.Waypoint_Create("Felix Head", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-25.610952, -60.614346, 59.983250)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.022897, -0.998269, -0.054166)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.001959, -0.054135, 0.998532)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Felix Head"

	# Position "Kiska Head"
	kThis = App.Waypoint_Create("Kiska Head", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(24.873796, -58.822765, 54.633335)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.023246, -0.999023, -0.037574)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.002903, -0.037651, 0.999287)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kiska Head"

	# Position "Miguel Head"
	kThis = App.Waypoint_Create("Miguel Head", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-175.414032, -10.269673, 64.996361)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.538769, -0.839264, -0.073247)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.031191, -0.067013, 0.997264)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Miguel Head"

	# Position "Saffi Head"
	kThis = App.Waypoint_Create("Saffi Head", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-86.852745, 87.651321, 59.621620)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.667924, -0.743733, -0.027172)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.022111, -0.016663, 0.999617)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Saffi Head"

	# Position "Brex Head"
	kThis = App.Waypoint_Create("Brex Head", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(177.147232, -5.502310, 65.817451)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.469891, -0.880621, -0.060901)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.021526, -0.057540, 0.998111)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Brex Head"

	# Position "Guest Head"
	kThis = App.Waypoint_Create("Guest Head", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(83.851746, 86.276299, 60.220104)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.542721, -0.830591, -0.124791)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.070719, -0.102860, 0.992179)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Guest Head"

