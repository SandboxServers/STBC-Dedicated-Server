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
	kForward.SetXYZ(-0.980914, 0.139413, -0.135541)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.132472, 0.031111, 0.990699)
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
	kForward.SetXYZ(-0.050196, 0.952791, -0.299448)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.052085, 0.301915, 0.951911)
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
	kForward.SetXYZ(-0.060731, 0.985471, -0.158615)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000608, 0.158945, 0.987287)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Guest Cam1"

	# Position "Brex Cam1"
	kThis = App.Waypoint_Create("Brex Cam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(110.582184, -34.743591, 71.538994)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.910780, 0.360703, -0.200931)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.188084, 0.070776, 0.979600)
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
	kForward.SetXYZ(-0.011404, -0.999935, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
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
	kForward.SetXYZ(0.209517, -0.977805, 0.000022)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000208, -0.000022, 1.000000)
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
	kForward.SetXYZ(0.022914, -0.998269, -0.054166)
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
	kForward.SetXYZ(0.023265, -0.999023, -0.037573)
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
	kForward.SetXYZ(0.538768, -0.839264, -0.073248)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.031187, -0.067017, 0.997264)
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
	kUp.SetXYZ(0.022129, -0.016648, 0.999617)
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
	kForward.SetXYZ(-0.542720, -0.830591, -0.124791)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.070719, -0.102860, 0.992179)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Guest Head"

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

	# Position "BrexCamRMed"
	kThis = App.Waypoint_Create("BrexCamRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(228.978302, -28.804018, 66.181992)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.982504, 0.144806, -0.117124)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.120565, -0.015193, 0.992589)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexCamRMed"

	# Position "BrexCamLMed"
	kThis = App.Waypoint_Create("BrexCamLMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(73.191353, -11.674706, 65.165527)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.991322, 0.046611, -0.122912)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.122156, 0.018755, 0.992334)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexCamLMed"

	# Position "SaffiCamLMed"
	kThis = App.Waypoint_Create("SaffiCamLMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-148.694595, 83.384819, 65.790817)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.980068, -0.133285, -0.147317)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.140854, -0.056731, 0.988404)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiCamLMed"

	# Position "KiskaCamRMed"
	kThis = App.Waypoint_Create("KiskaCamRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(77.813873, -96.967720, 58.076763)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.828257, 0.534853, -0.167099)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.130436, 0.105986, 0.985776)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KiskaCamRMed"

	# Position "BrexWatch 1"
	kThis = App.Waypoint_Create("BrexWatch 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(115.436020, -32.803421, 70.466904)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.909628, 0.363605, -0.200920)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.188084, 0.070776, 0.979600)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexWatch 1"

	# Position "BrexWatchRMed"
	kThis = App.Waypoint_Create("BrexWatchRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(222.965530, -27.917799, 65.465248)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.982504, 0.144807, -0.117123)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.120565, -0.015196, 0.992589)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexWatchRMed"

	# Position "KiskaWatchRMed"
	kThis = App.Waypoint_Create("KiskaWatchRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(71.300766, -92.726311, 58.406334)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.828257, 0.534853, -0.167100)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.130441, 0.105980, 0.985775)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KiskaWatchRMed"

	# Position "SaffiWatchLMed"
	kThis = App.Waypoint_Create("SaffiWatchLMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-141.159897, 82.360077, 64.658318)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.980068, -0.133285, -0.147315)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.145426, -0.023858, 0.989082)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiWatchLMed"

	# Position "MiguelWatch 1"
	kThis = App.Waypoint_Create("MiguelWatch 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-116.213562, -23.617405, 68.740784)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.980914, 0.139414, -0.135544)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.132473, 0.031120, 0.990698)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "MiguelWatch 1"

	# Position "BrexWatchLMed"
	kThis = App.Waypoint_Create("BrexWatchLMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(79.139290, -11.395042, 64.428070)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.991323, 0.046611, -0.122909)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.122153, 0.018747, 0.992334)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexWatchLMed"

