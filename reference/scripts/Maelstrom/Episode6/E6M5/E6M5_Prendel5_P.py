import App

def LoadPlacements(sSetName):
	# Position "Galor2Enter"
	kThis = App.Waypoint_Create("Galor2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(80.636024, 255.504547, 7.287568)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.294811, -0.955548, 0.003706)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.199836, -0.057861, 0.978119)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Enter"

	# Position "Galor1Enter"
	kThis = App.Waypoint_Create("Galor1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(95.502068, 242.059891, -1.579138)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.430532, -0.902535, 0.008490)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.257737, -0.113921, 0.959476)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Enter"

