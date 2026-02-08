import App

def LoadPlacements(sSetName):
	# Position "NightEnter"
	kThis = App.Waypoint_Create("NightEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(26.827339, 46.373455, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.523095, 0.850959, -0.047336)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.012277, 0.048012, 0.998771)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "NightEnter"

	# Position "TransStart"
	kThis = App.Waypoint_Create("TransStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(325.130760, 225.622192, -11.750205)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.385425, -0.921799, -0.041630)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.027301, -0.033704, 0.999059)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "TransStart"

