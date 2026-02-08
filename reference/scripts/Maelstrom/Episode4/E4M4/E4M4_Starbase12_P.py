import App

def LoadPlacements(sSetName):

	# Position "Nebula Start"
	kThis = App.Waypoint_Create("Nebula Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(76.748604, 19.185289, 25.896635)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.653262, 0.749229, -0.109103)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.034469, 0.114522, 0.992823)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nebula Start"
