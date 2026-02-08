import App

def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-25.543261, -23.293009, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.285973, 0.948242, -0.138048)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.005880, 0.142325, 0.989802)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "KhitEnter"
	kThis = App.Waypoint_Create("KhitEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-46.759529, -21.105309, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KhitEnter"

	# Position "DevoreEnter"
	kThis = App.Waypoint_Create("DevoreEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-71.992599, -18.111385, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DevoreEnter"

	# Position "FedEnter"
	kThis = App.Waypoint_Create("FedEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-91.303574, -18.310184, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "FedEnter"

	# Position "Galor2Start"
	kThis = App.Waypoint_Create("Galor2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(202.501053, 272.688965, -15.570793)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.725896, -0.687625, 0.015679)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.048941, -0.028899, 0.998384)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Start"

	# Position "Galor1Start"
	kThis = App.Waypoint_Create("Galor1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(251.023148, 274.235565, -18.870026)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.686998, -0.683270, 0.247336)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.311671, 0.030410, 0.949703)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Start"

	# Position "Keldon1Start"
	kThis = App.Waypoint_Create("Keldon1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(225.294067, 274.515503, 16.561438)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.709576, -0.680985, -0.181004)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.303579, 0.063637, 0.950679)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon1Start"

