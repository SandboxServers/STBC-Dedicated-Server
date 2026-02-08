import App

def LoadPlacements(sSetName):
	# Light position "ambientlight 1"
	kThis = App.LightPlacement_Create("ambientlight 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-0.160713, 5.402538, 739.369873)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.000000, 0.000000, -1.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.000345, 1.000000, 0.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.ConfigAmbientLight(1.000000, 0.800000, 0.800000, 0.400000)
	kThis.Update(0)
	kThis = None
	# End position "ambientlight 1"

	# Position "CardEnter"
	kThis = App.Waypoint_Create("CardEnter", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(81.122421, 184.617722, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "CardEnter"

