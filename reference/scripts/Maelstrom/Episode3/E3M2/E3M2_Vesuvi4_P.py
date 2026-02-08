import App

def LoadPlacements(sSetName):
	# Light position "Light 1"
	kThis = App.LightPlacement_Create("Light 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-15.645620, 12.937554, 26.240969)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.020303, -0.599671, -0.799989)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.040113, -0.799021, 0.599964)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigDirectionalLight(1.000000, 0.800000, 0.600000, 0.900000)
	kThis.Update(0)
	kThis = None
	# End position "Light 1"

	# Position "Berkeley Start"
	kThis = App.Waypoint_Create("Berkeley Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-17.990969, -52.041687, -11.675355)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.078520, -0.987887, 0.133842)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.010499, 0.135069, 0.990781)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Berkeley Start"

	# Position "Nightingale Leave"
	kThis = App.Waypoint_Create("Nightingale Leave", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-137.399948, -307.047699, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.936925, -0.025447, -0.348604)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.318841, 0.470892, 0.822558)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nightingale Leave"

	# Position "Nightingale Arrive"
	kThis = App.Waypoint_Create("Nightingale Arrive", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-20.129040, -364.440399, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nightingale Arrive"

	# Position "Nav Berkeley"
	kThis = App.Waypoint_Create("Nav Berkeley", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -50.450043, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Berkeley"

	# Position "Nav 1"
	kThis = App.Waypoint_Create("Nav 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-385.000000, 1015.000000, 100.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav 1"

	# Position "Nav 2"
	kThis = App.Waypoint_Create("Nav 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(385.000000, 1015.000000, 100.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav 2"

	# Position "Nav 3"
	kThis = App.Waypoint_Create("Nav 3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(285.000000, 1785.000000, -200.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav 3"

	# Position "Nav 4"
	kThis = App.Waypoint_Create("Nav 4", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-285.000000, 1785.000000, -200.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav 4"

	# Position "Nav Alpha"
	kThis = App.Waypoint_Create("Nav Alpha", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(673.215698, 318.305573, 4.707022)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.415038, 0.909420, -0.026436)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.652490, 0.277281, -0.705246)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Alpha"

	# Position "Kessok Probe"
	kThis = App.Waypoint_Create("Kessok Probe", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(700.524292, 374.794128, 0.476753)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.475626, -0.866998, 0.148641)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.634066, 0.220788, -0.741089)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Kessok Probe"

	# Position "Nav Beta"
	kThis = App.Waypoint_Create("Nav Beta", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1600.000000, 1000.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nav Beta"

	# Position "Dead Warbird Start"
	kThis = App.Waypoint_Create("Dead Warbird Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1650.000000, 1033.000000, 300.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.671737, -0.740790, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Dead Warbird Start"

	# Position "Warbird 1 Start"
	kThis = App.Waypoint_Create("Warbird 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1742.385254, 1102.076782, -12.259029)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.871583, -0.481442, 0.092499)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.079557, -0.047277, -0.995709)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird 1 Start"

	# Position "Warbird 2 Start"
	kThis = App.Waypoint_Create("Warbird 2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1769.625854, 1067.773682, -4.193887)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.912260, -0.399183, 0.091844)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.079560, -0.047272, -0.995709)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird 2 Start"

	# Position "Dust Cloud"
	kThis = App.Waypoint_Create("Dust Cloud", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(1323.505371, 1169.362305, 9.229272)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.809755, 0.515877, -0.279585)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.086990, -0.365673, -0.926669)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Dust Cloud"
