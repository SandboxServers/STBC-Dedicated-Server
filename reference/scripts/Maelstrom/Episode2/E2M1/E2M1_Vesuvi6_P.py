import App

def LoadPlacements(sSetName):
	# Position "Freighter1Start"
	kThis = App.Waypoint_Create("Freighter1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(51.060944, 522.363647, -35.668026)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.823593, -0.549808, -0.139305)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.047273, 0.311296, -0.949137)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter1Start"

	# Position "Freighter2Start"
	kThis = App.Waypoint_Create("Freighter2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(7.650206, 442.660522, -60.010544)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.981044, -0.193157, -0.015592)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.041902, 0.290000, -0.956109)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter2Start"

