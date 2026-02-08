import App

def LoadPlacements(sSetName):
	# Position "DerelictStart"
	kThis = App.Waypoint_Create("DerelictStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(148.799515, 607.211426, 117.479866)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.919688, -0.135059, -0.368691)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.387628, 0.461986, 0.797692)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DerelictStart"

	# Position "KessokStart"
	kThis = App.Waypoint_Create("KessokStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(172.688400, 611.149475, 127.827614)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.618546, 0.600044, -0.507295)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.265822, 0.447751, 0.853732)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KessokStart"

