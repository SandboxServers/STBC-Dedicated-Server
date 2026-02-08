import App

def LoadPlacements(sSetName):
	# Position "Way 1"
	kThis = App.Waypoint_Create("Way 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-0.525643, 48.990002, -2.173377)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.011860, 0.999063, 0.041612)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.006471, -0.041537, 0.999116)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Way 1"

	# Position "Placement 1"
	kThis = App.Waypoint_Create("Placement 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(19.516132, 300.987793, 10.266108)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.171503, 0.982935, 0.066525)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.525402, -0.148376, 0.837817)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 1"

	# Position "Cam Pos 1"
	kThis = App.Waypoint_Create("Cam Pos 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(7.408577, 24.750748, -2.753207)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.307990, -0.946974, 0.091555)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.012198, 0.092294, 0.995657)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Cam Pos 1"

	# Position "DryDock2"
	kThis = App.Waypoint_Create("DryDock2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(43.225746, 420.498810, 17.398169)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.052359, -0.980424, -0.189809)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.006971, -0.189706, 0.981816)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DryDock2"

	# Position "DryDock3"
	kThis = App.Waypoint_Create("DryDock3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-34.711842, -72.255119, -34.841240)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000067, 0.999953, -0.009720)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.013767, 0.009720, 0.999858)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DryDock3"

	# Position "StationPlacement"
	kThis = App.Waypoint_Create("StationPlacement", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(125.771446, 487.146667, 46.466923)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.448630, -0.869620, -0.206135)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.188687, -0.317614, 0.929257)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "StationPlacement"

	# Position "Shuttle1Start"
	kThis = App.Waypoint_Create("Shuttle1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(117.350334, -87.201202, -91.853821)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.732729, 0.557439, 0.390346)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.178705, -0.395855, 0.900757)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(3.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle1Start"

	# Position "Shuttle2Start"
	kThis = App.Waypoint_Create("Shuttle2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-10.398683, -34.224380, -37.425007)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.138461, 0.484012, 0.864038)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.252206, -0.860910, 0.441844)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(3.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle2Start"

	# Position "Shuttle3Start"
	kThis = App.Waypoint_Create("Shuttle3Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(23.956812, -0.896445, -29.291513)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.064733, 0.971649, 0.227394)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.830532, -0.073864, 0.552051)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle3Start"

	# Position "Shuttle3Way1"
	kThis = App.Waypoint_Create("Shuttle3Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(21.600298, 111.081398, -9.308134)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.029042, 0.999170, -0.028561)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.003654, 0.028679, 0.999582)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle3Way1"

	# Position "Shuttle1Way1"
	kThis = App.Waypoint_Create("Shuttle1Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(19.225666, -11.163023, 13.290357)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.745992, 0.665941, -0.004366)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.034021, 0.044656, 0.998423)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle1Way1"

	# Position "Shuttle1Way2"
	kThis = App.Waypoint_Create("Shuttle1Way2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(51.549545, 417.129395, 31.278450)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.998150, -0.056207, 0.023189)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.029295, -0.110377, 0.993458)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle1Way2"

	# Position "Shuttle2Way1"
	kThis = App.Waypoint_Create("Shuttle2Way1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(141.492783, 452.310883, 50.049179)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.359682, 0.931528, 0.053709)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.062276, -0.081400, 0.994734)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shuttle2Way1"

	# Attaching object "Placement 1" after "Way 1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Way 1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Shuttle3Way1" after "Shuttle3Start"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Shuttle3Start") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Shuttle3Way1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Shuttle1Way2" after "Shuttle1Way1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Shuttle1Way1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Shuttle1Way2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
