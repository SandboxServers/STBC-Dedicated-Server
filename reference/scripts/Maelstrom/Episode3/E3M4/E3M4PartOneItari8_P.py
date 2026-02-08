import App

def LoadPlacements(sSetName):
	# Position "Warbird3 Start"
	kThis = App.Waypoint_Create("Warbird3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-37.461971, -153.761841, -3.648164)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.052110, -0.994599, 0.089758)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.019226, 0.090862, 0.995678)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird3 Start"

	# Position "Warbird4 Start"
	kThis = App.Waypoint_Create("Warbird4 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-24.752338, -138.282715, 2.866162)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.159718, -0.986624, -0.032621)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.095375, -0.048314, 0.994268)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Warbird4 Start"

