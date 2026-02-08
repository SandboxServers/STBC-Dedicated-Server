import App

def LoadPlacements(sSetName):
	# Position "HulkStart"
	kThis = App.Waypoint_Create("HulkStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-61.421951, 84.341438, -7.323278)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.837339, -0.545103, 0.041543)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.031946, 0.027071, 0.999123)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "HulkStart"


