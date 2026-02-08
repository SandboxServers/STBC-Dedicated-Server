import App

def LoadPlacements(sSetName):
	# Position "ZhukovEnter"
	kThis = App.Waypoint_Create("ZhukovEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-226.775238, -105.734108, -7.435431)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.630055, -0.775376, 0.042693)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.045053, 0.018387, 0.998815)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ZhukovEnter"

	# Position "KhitEnter"
	kThis = App.Waypoint_Create("KhitEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-264.955292, -115.546936, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.716798, -0.694007, -0.067487)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.112271, 0.019349, 0.993489)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitEnter"

	# Position "FedEnter"
	kThis = App.Waypoint_Create("FedEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-265.405823, -156.543793, 7.731445)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.684500, -0.728776, -0.018601)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.051904, 0.023267, 0.998381)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "FedEnter"

	# Position "Galor4Start"
	kThis = App.Waypoint_Create("Galor4Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-53.182453, -306.760376, -27.840000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor4Start"

	# Position "Galor3Start"
	kThis = App.Waypoint_Create("Galor3Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-78.930107, -326.192596, -28.288002)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.002013, 0.999998, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor3Start"

	# Position "Galor2Enter"
	kThis = App.Waypoint_Create("Galor2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-24.897057, 16.951843, 10.173059)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.006739, -0.999740, -0.021783)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.010317, -0.021713, 0.999711)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Enter"

	# Position "Galor1Enter"
	kThis = App.Waypoint_Create("Galor1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(8.345535, 26.658899, 23.149830)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.041772, -0.998620, -0.031832)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.024875, -0.030810, 0.999216)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Enter"

	# Position "Keldon1Start"
	kThis = App.Waypoint_Create("Keldon1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-67.539841, -343.554688, -34.518749)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.081123, 0.996546, 0.017753)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.001410, -0.017697, 0.999842)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon1Start"

