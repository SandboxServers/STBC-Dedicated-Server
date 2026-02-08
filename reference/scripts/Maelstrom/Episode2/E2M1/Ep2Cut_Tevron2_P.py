import App

def LoadPlacements(sSetName):
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

	# Position "ZhukovStart"
	kThis = App.Waypoint_Create("ZhukovStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-43.621468, 156.714859, 57.705067)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.088870, -0.981383, -0.170263)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.081022, -0.163250, 0.983252)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ZhukovStart"

	# Position "SovCamStart"
	kThis = App.Waypoint_Create("SovCamStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-32.680111, 130.946793, 51.998764)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.590326, 0.786805, 0.180149)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.159597, -0.105003, 0.981582)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "SovCamStart"

	# Position "SovCam1"
	kThis = App.Waypoint_Create("SovCam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-42.983147, 151.612320, 57.189999)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.214881, 0.914233, 0.343517)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.167014, -0.312154, 0.935236)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "SovCam1"

	# Position "SovCam2"
	kThis = App.Waypoint_Create("SovCam2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-44.872242, 160.012436, 58.881763)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.276827, 0.949010, 0.150820)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.124004, -0.120360, 0.984955)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "SovCam2"

	# Position "SovCam3"
	kThis = App.Waypoint_Create("SovCam3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-50.580063, 171.362564, 62.288383)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.538505, 0.775473, 0.329626)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.184913, -0.272898, 0.944105)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "SovCam3"

	# Position "SovCam4"
	kThis = App.Waypoint_Create("SovCam4", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-54.290634, 182.000214, 67.427345)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.917734, 0.160211, 0.363452)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.323970, -0.227477, 0.918312)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "SovCam4"

	# Position "GalaxyStart"
	kThis = App.Waypoint_Create("GalaxyStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(66.701912, 175.749252, 106.750458)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.927838, -0.120631, -0.352939)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.284576, 0.840645, 0.460796)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(4.000000)
	kThis.Update(0)
	kThis = None
	# End position "GalaxyStart"

	# Position "GalaxyFlyby"
	kThis = App.Waypoint_Create("GalaxyFlyby", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-131.741241, 178.688873, 41.497658)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.947976, 0.003687, -0.318319)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.257727, 0.578060, 0.774224)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "GalaxyFlyby"

	# Position "GalaxyCamStart"
	kThis = App.Waypoint_Create("GalaxyCamStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-54.331440, 182.083435, 67.452393)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.836559, -0.414719, -0.358019)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.201353, -0.375011, 0.904889)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(2.000000)
	kThis.Update(0)
	kThis = None
	# End position "GalaxyCamStart"

	# Position "GalaxyCam1"
	kThis = App.Waypoint_Create("GalaxyCam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-71.441910, 173.869003, 62.037167)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.888267, -0.260710, -0.378169)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.036404, -0.780763, 0.623766)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.800000)
	kThis.Update(0)
	kThis = None
	# End position "GalaxyCam1"

	# Position "GalaxyCam2"
	kThis = App.Waypoint_Create("GalaxyCam2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-148.488663, 176.309982, 32.367676)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.936419, 0.043306, -0.348201)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.183676, -0.906030, 0.381277)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.200000)
	kThis.Update(0)
	kThis = None
	# End position "GalaxyCam2"

	# Attaching object "SovCam1" after "SovCamStart"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SovCamStart") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SovCam1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "SovCam2" after "SovCam1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SovCam1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SovCam2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "SovCam3" after "SovCam2"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SovCam2") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SovCam3") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "SovCam4" after "SovCam3"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SovCam3") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "SovCam4") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "GalaxyCam1" after "GalaxyCamStart"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "GalaxyCamStart") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "GalaxyCam1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "GalaxyCam2" after "GalaxyCam1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "GalaxyCam1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "GalaxyCam2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
