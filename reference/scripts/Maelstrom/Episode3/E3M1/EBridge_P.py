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
	kUp.SetXYZ(-0.184133, 0.092047, 0.978582)
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
	kForward.SetXYZ(0.900454, 0.381214, -0.209426)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.187927, 0.093245, 0.977747)
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
	kForward.SetXYZ(-0.980914, 0.139413, -0.135542)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.132474, 0.031106, 0.990698)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Miguel Cam1"

	# Position "SaffiCamLMed"
	kThis = App.Waypoint_Create("SaffiCamLMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-91.673820, 23.167482, 67.048317)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.143936, 0.966840, -0.210960)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.046504, 0.206335, 0.977376)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiCamLMed"

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

	# Position "Brex Cam1"
	kThis = App.Waypoint_Create("Brex Cam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(110.582184, -34.743591, 71.538994)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.910780, 0.360703, -0.200931)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.188079, 0.070789, 0.979600)
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
	kUp.SetXYZ(0.031183, -0.067020, 0.997264)
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
	kForward.SetXYZ(0.667924, -0.743733, -0.027173)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.022145, -0.016634, 0.999617)
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

	# Position "BrexCamRMed"
	kThis = App.Waypoint_Create("BrexCamRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(228.978302, -28.804018, 66.181992)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.982503, 0.144806, -0.117127)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.117127, 0.008551, 0.993080)
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
	kForward.SetXYZ(0.992525, 0.003019, -0.122006)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.121975, 0.008872, 0.992494)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexCamLMed"

	# Position "SaffiBrexCam"
	kThis = App.Waypoint_Create("SaffiBrexCam", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-140.361038, 81.744621, 63.299488)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.972796, -0.179646, -0.146273)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.143901, -0.026237, 0.989244)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiBrexCam"

	# Position "KiskaCamRMed"
	kThis = App.Waypoint_Create("KiskaCamRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(69.713158, -96.157433, 57.305107)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.818862, 0.565122, -0.100506)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.073886, 0.069866, 0.994816)
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
	kUp.SetXYZ(0.188079, 0.070789, 0.979599)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexWatch 1"

	# Position "BrexWatchRMed"
	kThis = App.Waypoint_Create("BrexWatchRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(222.690460, -27.877254, 65.432312)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.982503, 0.144807, -0.117128)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.117092, 0.008799, 0.993082)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexWatchRMed"

	# Position "KiskaWatchRMed"
	kThis = App.Waypoint_Create("KiskaWatchRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(64.734428, -92.721336, 56.693962)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.818862, 0.565123, -0.100505)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.073929, 0.069803, 0.994818)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KiskaWatchRMed"

	# Position "SaffiBrexWatch"
	kThis = App.Waypoint_Create("SaffiBrexWatch", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-134.557602, 80.672699, 62.426708)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.972795, -0.179648, -0.146273)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.143910, -0.026191, 0.989244)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiBrexWatch"

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
	kThis.SetTranslateXYZ(79.225906, -11.656351, 64.423706)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.992525, 0.003019, -0.122006)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.121975, 0.008878, 0.992494)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexWatchLMed"

	# Position "BrexCamRClose"
	kThis = App.Waypoint_Create("BrexCamRClose", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(182.806519, -52.718834, 51.210060)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.244531, 0.942763, 0.226721)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000797, -0.234015, 0.972233)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexCamRClose"

	# Position "BrexWatchRClose"
	kThis = App.Waypoint_Create("BrexWatchRClose", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(181.311996, -46.956676, 52.595764)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.244531, 0.942763, 0.226721)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000797, -0.234015, 0.972233)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "BrexWatchRClose"

	# Position "KiskaCamLMed"
	kThis = App.Waypoint_Create("KiskaCamLMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(7.610967, -102.812668, 49.111977)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.392570, 0.917455, 0.064535)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.003798, -0.068550, 0.997641)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KiskaCamLMed"

	# Position "KiskaWatchLMed"
	kThis = App.Waypoint_Create("KiskaWatchLMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(9.966388, -97.307938, 49.499187)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.392570, 0.917455, 0.064535)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.003798, -0.068550, 0.997641)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KiskaWatchLMed"

	# Position "FelixCamRMed"
	kThis = App.Waypoint_Create("FelixCamRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(9.486752, -108.718231, 51.636559)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.606044, 0.794454, 0.039420)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023594, -0.031582, 0.999223)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "FelixCamRMed"

	# Position "FelixWatchRMed"
	kThis = App.Waypoint_Create("FelixWatchRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(5.850486, -103.951508, 51.873077)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.606044, 0.794454, 0.039420)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023594, -0.031582, 0.999223)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "FelixWatchRMed"

	# Position "MiguelCamRMed"
	kThis = App.Waypoint_Create("MiguelCamRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-127.790329, -35.022076, 53.782047)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.889716, 0.433845, 0.142068)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.137085, -0.042937, 0.989628)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "MiguelCamRMed"

	# Position "MiguelWatchRMed"
	kThis = App.Waypoint_Create("MiguelWatchRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-133.128632, -32.419003, 54.634457)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.889716, 0.433845, 0.142068)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.137085, -0.042937, 0.989628)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "MiguelWatchRMed"

	# Position "SaffiCamRMed"
	kThis = App.Waypoint_Create("SaffiCamRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-31.787092, 64.741440, 62.105545)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.939507, 0.317686, -0.128072)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.122768, 0.036747, 0.991755)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiCamRMed"

	# Position "SaffiWatchRMed"
	kThis = App.Waypoint_Create("SaffiWatchRMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-37.672192, 66.731331, 61.303265)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.939507, 0.317686, -0.128072)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.122768, 0.036747, 0.991755)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiWatchRMed"

	# Position "SaffiWatchLMed"
	kThis = App.Waypoint_Create("SaffiWatchLMed", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-90.805183, 29.007309, 65.774170)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.143794, 0.966861, -0.210956)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.046549, 0.206327, 0.977375)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SaffiWatchLMed"

