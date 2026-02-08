import App

def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-25.543261, -23.293009, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "VentureEnter"
	kThis = App.Waypoint_Create("VentureEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-50.550106, -2.221309, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "VentureEnter"

	# Position "SFEnter"
	kThis = App.Waypoint_Create("SFEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(19.848829, 3.884526, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SFEnter"

	# Position "DevoreEnter"
	kThis = App.Waypoint_Create("DevoreEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-7.824853, 49.131268, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DevoreEnter"

	# Position "Galor10Enter"
	kThis = App.Waypoint_Create("Galor10Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-504.561523, 103.826263, 68.566994)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.955560, -0.062363, -0.288123)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.294786, 0.194350, 0.935590)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor10Enter"

	# Position "Keldon4Enter"
	kThis = App.Waypoint_Create("Keldon4Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-450.485626, 57.724030, 63.716087)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.985281, 0.126056, -0.115459)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.097420, 0.140939, 0.985214)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon4Enter"

	# Position "Galor12Enter"
	kThis = App.Waypoint_Create("Galor12Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-300.437378, 331.106110, -17.638935)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.637212, -0.758291, 0.137681)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.063053, -0.229341, -0.971302)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor12Enter"

	# Position "Keldon5Enter"
	kThis = App.Waypoint_Create("Keldon5Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-291.656281, 364.063141, -8.903757)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.682741, -0.715898, 0.146133)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.149323, -0.332490, -0.931210)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon5Enter"

	# Position "Galor11Enter"
	kThis = App.Waypoint_Create("Galor11Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-292.819855, 406.424316, -9.167994)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.862984, -0.472852, 0.177960)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017848, -0.380547, -0.924589)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor11Enter"

