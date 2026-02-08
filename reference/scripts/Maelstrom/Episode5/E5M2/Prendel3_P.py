import App

def LoadPlacements(sSetName):

	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetTranslateXYZ(0.00, 2000.00, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-1.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"


	# Position "Base Location"
	kThis = App.Waypoint_Create("Base Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(513.768127, 6098.182129, 35.464722)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.061661, -0.997717, -0.027544)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.094957, -0.033335, 0.994923)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Base Location"

	# Position "Galor Start"
	kThis = App.Waypoint_Create("Galor Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(223.495392, 6288.851074, 6.998154)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.930259, -0.363801, 0.047620)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.060851, -0.024988, 0.997834)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor Start"

	# Position "Galor2 Start"
	kThis = App.Waypoint_Create("Galor2 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(290.771698, 6361.298340, 52.959106)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.734686, -0.672351, -0.090450)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.087143, -0.038693, 0.995444)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Start"

	# Position "Galor3 Start"
	kThis = App.Waypoint_Create("Galor3 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(195.600983, 6210.033691, 56.250618)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.835507, -0.534238, -0.128524)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.115485, -0.057949, 0.991617)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor3 Start"

	# Position "Second Moon"
	kThis = App.Waypoint_Create("Strange Readings", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(549.149109, 4642.061523, 7.734221)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.047009, 0.998469, 0.029165)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.019553, -0.028272, 0.999409)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Second Moon"

