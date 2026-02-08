import App

def LoadPlacements(sSetName):
	# Position "SFStart"
	kThis = App.Waypoint_Create("SFStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-859.076843, 25.426311, 171.603745)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.973912, 0.013004, -0.226552)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.226566, 0.000438, 0.973996)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SFStart"

	# Position "DockingCam"
	kThis = App.Waypoint_Create("DockingCam", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-40.944988, 65.102829, 24.236782)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.969573, -0.240287, -0.046802)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.150725, 0.435306, 0.887576)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DockingCam"

	# Position "PlayerDockCutStart"
	kThis = App.Waypoint_Create("PlayerDockCutStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-79.817299, 46.045429, 22.240540)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.660889, 0.744897, -0.091400)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.082156, 0.049247, 0.995402)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "PlayerDockCutStart"

	# Position "PlayerSpecialStart"
	kThis = App.Waypoint_Create("PlayerSpecialStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-1908.463501, 1004.497742, 433.924347)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.930604, -0.306675, -0.199816)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.014605, -0.514360, 0.857450)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "PlayerSpecialStart"

	# Position "Starbase Nav"
	kThis = App.Waypoint_Create("Starbase Nav", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(1)
	kThis.SetTranslateXYZ(-308.658600, 277.192963, 123.442696)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.955864, -0.270236, -0.115313)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.088778, -0.108478, 0.990127)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Starbase Nav"

