import App

def LoadPlacements(sSetName = "Chambana2"):

	# Position "Enterprise Start"
	kThis = App.Waypoint_Create("Enterprise Start", "Chambana2", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(14.282213, -340.896179, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Start"

