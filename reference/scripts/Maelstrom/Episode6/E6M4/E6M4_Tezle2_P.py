import App

def LoadPlacements(sSetName):
	# Position "KessokStart"
	kThis = App.Waypoint_Create("KessokStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(321.604858, -138.007889, 35.137508)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.791508, 0.576368, -0.203262)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.109630, 0.193290, 0.974997)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KessokStart"


