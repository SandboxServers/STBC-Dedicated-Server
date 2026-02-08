import App

def LoadPlacements(sSetName):
	# Position "SovStart"
	kThis = App.Waypoint_Create("SovStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-51.728165, 177.127426, 64.487556)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.137943, -0.979831, -0.144579)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.087333, -0.133373, 0.987211)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SovStart"

	# Position "RanKufStart"
	kThis = App.Waypoint_Create("RanKufStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-68.756470, 200.341705, 70.887871)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.134550, -0.976761, -0.166836)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.086413, -0.156160, 0.983945)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "RanKufStart"

	# Position "TrayorStart"
	kThis = App.Waypoint_Create("TrayorStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-36.188236, 204.308990, 68.767746)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.017962, -0.997893, -0.062346)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.430873, -0.048543, 0.901106)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "TrayorStart"

	# Position "Warbird1Start"
	kThis = App.Waypoint_Create("Warbird1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-80.196548, 144.807678, 84.954376)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.546092, 0.691077, -0.473493)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.291315, 0.373280, 0.880794)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird1Start"

	# Position "Warbird2Start"
	kThis = App.Waypoint_Create("Warbird2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-38.320267, 149.490402, 71.533913)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.460997, 0.855903, -0.234333)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.076727, 0.224633, 0.971418)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird2Start"

	# Position "ZhukovStart"
	kThis = App.Waypoint_Create("ZhukovStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-219.204788, 96.271759, 66.362808)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.876954, 0.480537, 0.006015)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.116388, -0.224512, 0.967496)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ZhukovStart"

	# Position "WarbirdCam2"
	kThis = App.Waypoint_Create("WarbirdCam2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-36.674519, 141.036301, 73.730736)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.979817, -0.186685, 0.071461)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.084374, -0.062156, 0.994494)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.000000)
	kThis.Update(0)
	kThis = None
	# End position "WarbirdCam2"

	# Position "WarbirdCamStart"
	kThis = App.Waypoint_Create("WarbirdCamStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-51.903538, 179.583435, 63.347935)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.391506, -0.917695, 0.067518)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.026509, 0.062096, 0.997718)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(2.000000)
	kThis.Update(0)
	kThis = None
	# End position "WarbirdCamStart"

	# Position "WarbirdCamStatic"
	kThis = App.Waypoint_Create("WarbirdCamStatic", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-51.903538, 179.583435, 63.347935)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.391507, -0.917695, 0.067515)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.026394, 0.062142, 0.997718)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(3.000000)
	kThis.Update(0)
	kThis = None
	# End position "WarbirdCamStatic"

	# Position "CameraWatch"
	kThis = App.Waypoint_Create("CameraWatch", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-39.705490, 147.453934, 71.471931)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.364045, 0.901339, -0.234647)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.058934, 0.229137, 0.971608)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "CameraWatch"

	# Position "WarbirdCam1"
	kThis = App.Waypoint_Create("WarbirdCam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-31.442982, 155.131775, 71.391182)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.208068, -0.961632, 0.178806)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.160745, 0.146703, 0.976032)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(3.000000)
	kThis.Update(0)
	kThis = None
	# End position "WarbirdCam1"

	# Position "PlayerBail"
	kThis = App.Waypoint_Create("PlayerBail", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-48.714542, 125.224670, 57.515465)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.073641, 0.987697, 0.137956)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.113948, -0.129092, 0.985064)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "PlayerBail"

	# Position "WarbirdWay1"
	kThis = App.Waypoint_Create("WarbirdWay1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-191.485672, 183.159912, 86.626053)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.883691, 0.294825, 0.363550)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.449809, 0.320055, 0.833809)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "WarbirdWay1"

	# Position "WarbirdWay2"
	kThis = App.Waypoint_Create("WarbirdWay2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(84.652672, 158.204880, 96.330032)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.919530, 0.115294, 0.375729)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.393016, 0.274219, 0.877692)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "WarbirdWay2"

	# Attaching object "WarbirdCam1" after "WarbirdCamStart"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "WarbirdCamStart") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "WarbirdCam1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "WarbirdCam2" after "WarbirdCam1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "WarbirdCam1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "WarbirdCam2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
