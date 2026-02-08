import App

def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-29.925085, -605.485840, 1.094382)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.115372, 0.993322, -0.000063)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000701, 0.000145, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "Enterprise Start"
	kThis = App.Waypoint_Create("Enterprise Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(0.000000, -11.879730, 149.062378)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Start"

	# Position "Klingon 1 Start"
	kThis = App.Waypoint_Create("Klingon 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-112.940147, 16.668850, 9.395391)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.377326, 0.926043, 0.008333)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.018542, -0.001442, 0.999827)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Klingon 1 Start"

	# Position "Romulan 1 Start"
	kThis = App.Waypoint_Create("Romulan 1 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(140.962341, 73.111000, -32.637066)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.078828, 0.972515, -0.219091)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.014143, 0.218661, 0.975698)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Romulan 1 Start"

	# Position "WarpIn(Geronimo,player)"
	kThis = App.PlacementObject_Create("WarpIn(Geronimo,player)", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-14.686007, -652.272034, 17.238720)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.Update(0)
	kThis = None
	# End position "WarpIn(Geronimo,player)"

