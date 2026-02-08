import App

def LoadPlacements(sSetName):

	# Position "Warbird Start"
	kThis = App.Waypoint_Create("Warbird Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(400.0, 260.0, 50.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-1.0, 0.0, 0.0)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.043388, -0.031235, 0.998570)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird Start"
