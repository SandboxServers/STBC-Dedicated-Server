import App

def LoadPlacements(sSetName):
	# Position "NightEnter"
	kThis = App.Waypoint_Create("NightEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(0.085934, 28.302416, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.670295, 0.738166, 0.076256)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "NightEnter"

