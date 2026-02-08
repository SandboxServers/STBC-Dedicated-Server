import App


def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-173.131302, -178.074310, 49.230553)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.333561, 0.926046, -0.176567)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.167715, 0.126014, 0.977749)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(10.0)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"
