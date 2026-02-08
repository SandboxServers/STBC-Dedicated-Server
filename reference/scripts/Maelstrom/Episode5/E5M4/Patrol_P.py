import App

def LoadPlacements(sSetName):
	# Position "Planet Location"
	kThis = App.Waypoint_Create("Planet Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(1.000000, 0.000000, 0.000011)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000011, -0.008944, 0.999960)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Planet Location"

	# Position "Patrol Start"
	kThis = App.Waypoint_Create("Patrol Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(215.768921, 627.440002, -0.863451)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.705447, 0.701130, -0.103736)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.117843, 0.028296, 0.992629)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Patrol Start"

	# Position "Placement 1"
	kThis = App.Waypoint_Create("Placement 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(400.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.236268, 0.957308, 0.166549)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.252041, -0.105158, 0.961986)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 1"

	# Position "Placement 2"
	kThis = App.Waypoint_Create("Placement 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, 1400.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.998645, 0.027308, 0.044311)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043515, -0.029102, 0.998629)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 2"

	# Position "Placement 3"
	kThis = App.Waypoint_Create("Placement 3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-400.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.002970, -0.998047, -0.062392)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.094907, -0.062392, 0.993529)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 3"

	# Position "Nav Alpha"
	kThis = App.Waypoint_Create("Nav Alpha", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(0.000000, -500.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026831, 0.999591, -0.009929)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000198, 0.009928, 0.999951)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Alpha"

	# Position "Nav Beta"
	kThis = App.Waypoint_Create("Nav Beta", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(1500.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026831, 0.999591, -0.009929)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000198, 0.009928, 0.999951)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Beta"

	# Position "Nav Gamma"
	kThis = App.Waypoint_Create("Nav Gamma", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(0.000000, 2500.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026831, 0.999591, -0.009929)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000198, 0.009928, 0.999951)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Gamma"

	# Position "Nav Delta"
	kThis = App.Waypoint_Create("Nav Delta", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(-1500.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.026831, 0.999591, -0.009929)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000198, 0.009928, 0.999951)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Delta"

	# Attaching object "Placement 1" after "Patrol Start"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Patrol Start") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 2" after "Placement 1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 3" after "Placement 2"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 2") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 3") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
