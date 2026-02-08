import App

def LoadPlacements(sSetName):
	# Position "Venture"
	kThis = App.Waypoint_Create("Venture", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-0.000000, 6.000000, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-1.000000, -0.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Venture"

	# Position "Devore"
	kThis = App.Waypoint_Create("Devore", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-0.015624, 6.038546, 19.740248)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.002604, 0.999995, -0.001956)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.999997, -0.002604, 0.000005)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Devore"

	# Position "San Francisco"
	kThis = App.Waypoint_Create("San Francisco", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-0.015624, 6.064156, 32.852230)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.002604, 0.999995, -0.001956)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.999997, -0.002604, 0.000005)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "San Francisco"

	# Position "Inverness"
	kThis = App.Waypoint_Create("Inverness", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-0.015624, 6.084140, 43.084198)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.002604, 0.999995, -0.001956)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.999997, -0.002604, 0.000005)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Inverness"

	# Position "Cambridge"
	kThis = App.Waypoint_Create("Cambridge", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-0.015624, 6.111780, 57.236149)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.002604, 0.999995, -0.001956)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.999997, -0.002604, 0.000005)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Cambridge"

	# Position "Shannon"
	kThis = App.Waypoint_Create("Shannon", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-0.015624, 6.148171, 75.867943)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.002604, 0.999995, -0.001956)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.999997, -0.002604, 0.000005)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Shannon"

