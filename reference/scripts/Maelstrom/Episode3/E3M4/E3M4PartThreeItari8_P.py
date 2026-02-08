import App

def LoadPlacements(sSetName):
	# Position "Chairo"
	kThis = App.Waypoint_Create("Chairo", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(20.036129, 103.948226, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.679576, 0.000000, 0.733605)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Chairo"

	# Position "Galor 3"
	kThis = App.Waypoint_Create("Galor 3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(41.51075, 136.174789, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.546690, -0.815563, -0.189705)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.149788, -0.318156, 0.936130)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor 3"

	# Position "Galor 2"
	kThis = App.Waypoint_Create("Galor 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(4.303711, 124.456039, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.214912, -0.931947, -0.292042)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.806941, 0.001000, 0.590632)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor 2"

	# Position "Galor 1"
	kThis = App.Waypoint_Create("Galor 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-12.102533, 93.108383, 67.391998)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.929755, 0.136669, -0.341872)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.288859, 0.304972, 0.907498)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor 1"

	# Position "Keldon 1"
	kThis = App.Waypoint_Create("Keldon 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(45.026367, 53.557601, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.764617, -0.602100, -0.229862)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.365715, 0.111672, 0.924003)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon 1"

	# Position "T'Awsun"
	kThis = App.Waypoint_Create("T'Awsun", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(62.604484, 99.553695, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.966905, 0.000000, -0.255136)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "T'Awsun"

