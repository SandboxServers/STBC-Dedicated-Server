import App

def LoadPlacements(sSetName):
	# Position "DevoreEnter"
	kThis = App.Waypoint_Create("DevoreEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(141.187653, -106.677841, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DevoreEnter"

	# Position "VentureEnter"
	kThis = App.Waypoint_Create("VentureEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(9.840824, -227.669540, 0.000000)
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
	kThis.SetTranslateXYZ(67.611633, -218.949432, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SFEnter"

	# Position "Galor12Enter"
	kThis = App.Waypoint_Create("Galor12Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-297.528717, -79.427475, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.991686, 0.019890, -0.127132)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.123078, 0.141697, 0.982229)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor12Enter"

	# Position "Keldon5Enter"
	kThis = App.Waypoint_Create("Keldon5Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-300.798767, -36.916878, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.837089, -0.005672, -0.547038)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.452698, 0.568618, 0.686832)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon5Enter"

	# Position "Galor11Enter"
	kThis = App.Waypoint_Create("Galor11Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-300.798767, 0.143650, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.933474, -0.032483, -0.357170)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.334798, 0.435999, 0.835353)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor11Enter"
		
	# Position "Galor10Enter"
	kThis = App.Waypoint_Create("Galor10Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-300.798767, 0.143650, 25.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.933474, -0.032483, -0.357170)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.334798, 0.435999, 0.835353)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor10Enter"
		
	# Position "Keldon4Enter"
	kThis = App.Waypoint_Create("Keldon4Enter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-300.798767, -36.916878, -25.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.837089, -0.005672, -0.547038)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.452698, 0.568618, 0.686832)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon4Enter"
	
	# Position "Transport1Start"
	kThis = App.Waypoint_Create("Transport1Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(177.528503, -122.208031, 210.336273)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.700835, -0.710134, -0.067379)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.175786, 0.080391, 0.981140)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Transport1Start"

	# Position "Transport2Start"
	kThis = App.Waypoint_Create("Transport2Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(173.691910, -133.776169, 211.971527)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.700835, -0.710134, -0.067379)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.175786, 0.080391, 0.981140)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Transport2Start"

	# Position "Transport3Start"
	kThis = App.Waypoint_Create("Transport3Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(169.751816, -145.026535, 213.599213)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.699487, -0.711495, -0.067029)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.175787, 0.080388, 0.981140)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Transport3Start"

