import App

def LoadPlacements(sSetName):
	# Position "Mavjop Start"
	kThis = App.Waypoint_Create("Mavjop Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(10.025375, -151.701675, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.649028, 0.742025, -0.167816)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.070693, 0.160810, 0.984450)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Mavjop Start"

