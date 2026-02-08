import App

def LoadPlacements(sSetName):
	# Position "Galor1Enter"
	kThis = App.Waypoint_Create("Galor1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(7.125332, 7.846817, 750.810608)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.670295, 0.738166, 0.076256)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.741153, -0.671077, -0.018683)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Enter"

	# Position "Galor2Enter"
	kThis = App.Waypoint_Create("Galor2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(11.340296, 15.631241, 638.405518)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.670295, 0.738166, 0.076256)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.741153, -0.671077, -0.018683)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Enter"
	
	# Position "Galor3Enter"
	kThis = App.Waypoint_Create("Galor3Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(50.340296, 15.631241, 638.405518)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.670295, 0.738166, 0.076256)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.741153, -0.671077, -0.018683)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor3Enter"

