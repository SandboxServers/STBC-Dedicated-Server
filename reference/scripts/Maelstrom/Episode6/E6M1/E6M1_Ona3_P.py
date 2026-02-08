import App

def LoadPlacements(sSetName):
	# Position "VentureStart"
	kThis = App.Waypoint_Create("VentureStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-98.632645, 104.446800, 20.792694)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.923708, -0.168376, 0.344112)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.334291, 0.084467, 0.938677)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "VentureStart"

	# Position "DevoreStart"
	kThis = App.Waypoint_Create("DevoreStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-41.609753, 161.101944, -21.783457)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.830235, 0.528991, -0.175722)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.529165, -0.648891, 0.546740)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DevoreStart"

	# Position "SFEnter"
	kThis = App.Waypoint_Create("SFEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(38.452148, 11.286857, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SFEnter"

	# Position "Keldon2Start"
	kThis = App.Waypoint_Create("Keldon2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-281.445221, 154.570984, 26.904606)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.818130, -0.526940, -0.230211)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.210562, -0.098017, 0.972654)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon2Start"

	# Position "Galor7Start"
	kThis = App.Waypoint_Create("Galor7Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-224.514130, 122.844757, 57.534279)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.724155, -0.471577, 0.503204)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.107789, 0.643301, 0.757987)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor7Start"

	# Position "Galor6Start"
	kThis = App.Waypoint_Create("Galor6Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-150.783051, 163.240631, 20.492308)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.273893, -0.764371, 0.583713)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.237134, -0.534512, -0.811212)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor6Start"

	# Position "Galor5Start"
	kThis = App.Waypoint_Create("Galor5Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-44.211906, 190.876495, -19.492500)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.703915, -0.545739, -0.454613)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.162140, -0.746606, 0.645206)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor5Start"

	# Position "Card3Enter"
	kThis = App.Waypoint_Create("Card3Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-103.872490, -154.467651, 20.352001)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card3Enter"

	# Position "Card2Enter"
	kThis = App.Waypoint_Create("Card2Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-134.803665, -162.665207, 15.424000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card2Enter"

	# Position "Card1Enter"
	kThis = App.Waypoint_Create("Card1Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-160.272614, -165.149323, 18.816002)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Card1Enter"

	# Position "VentureWait"
	kThis = App.Waypoint_Create("VentureWait", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(119.931252, 224.892059, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.678119, -0.729482, 0.089509)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.077324, 0.050299, 0.995736)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "VentureWait"

	# Position "DevoreWait"
	kThis = App.Waypoint_Create("DevoreWait", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(130.478119, 192.665482, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.811957, -0.582854, 0.031716)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.021798, 0.024020, 0.999474)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DevoreWait"

