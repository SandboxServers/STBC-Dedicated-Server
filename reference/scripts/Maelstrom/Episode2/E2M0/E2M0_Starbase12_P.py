import App

def LoadPlacements(sSetName):
	# Position "SovEnter"
	kThis = App.Waypoint_Create("SovEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-54.519257, 110.754150, -8.324215)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.891449, 0.450256, -0.050885)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.044651, 0.024464, 0.998703)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SovEnter"

	# Position "ZhukovEnter"
	kThis = App.Waypoint_Create("ZhukovEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-48.471451, 102.583893, -8.406126)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.818056, 0.572275, -0.057314)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.051873, 0.025832, 0.998320)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ZhukovEnter"

