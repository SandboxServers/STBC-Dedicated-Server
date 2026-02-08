import App

def LoadPlacements(sSetName):
	# Position "Base Location"
	kThis = App.Waypoint_Create("Base Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(513.768127, 6098.182129, 35.464722)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.061661, -0.997717, -0.027544)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.094957, -0.033335, 0.994923)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Base Location"


