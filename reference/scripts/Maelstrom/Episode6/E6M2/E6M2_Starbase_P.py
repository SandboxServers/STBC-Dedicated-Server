import App

def LoadPlacements(sSetName):
	# Position "Starbase12 Location"
	kThis = App.Waypoint_Create("Starbase12 Location", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(10.895514, 143.301804, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Starbase12 Location"

	# Position "NightStart"
	kThis = App.Waypoint_Create("NightStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-116.254753, 144.016678, -27.680000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.357088, 0.890100, 0.283214)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.072263, -0.275970, 0.958446)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "NightStart"

	# Position "InvernessStart"
	kThis = App.Waypoint_Create("InvernessStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-53.339870, 138.544128, 17.406374)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.983927, 0.118146, -0.133897)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.136359, -0.012970, 0.990575)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "InvernessStart"

	# Position "ShannonStart"
	kThis = App.Waypoint_Create("ShannonStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-45.038593, 160.988037, 18.551184)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.937185, -0.311361, -0.157283)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.149716, -0.048219, 0.987553)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "ShannonStart"

	# Position "CambridgeStart"
	kThis = App.Waypoint_Create("CambridgeStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-196.128128, 160.905106, 42.265587)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.889289, -0.321940, -0.324838)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.317849, -0.075640, 0.945119)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "CambridgeStart"

	# Position "DevoreStart"
	kThis = App.Waypoint_Create("DevoreStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-17.185934, -76.146172, -33.926662)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.622797, 0.779936, -0.061844)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.065470, 0.130721, 0.989255)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "DevoreStart"

	# Position "SFStart"
	kThis = App.Waypoint_Create("SFStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(51.117424, -127.119568, -31.711342)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.622797, 0.779936, -0.061844)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.065470, 0.130721, 0.989255)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SFStart"

	# Position "VentureStart"
	kThis = App.Waypoint_Create("VentureStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-10.576074, -4.509115, -43.359905)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.561102, 0.827724, 0.006164)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.020981, 0.006778, 0.999757)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "VentureStart"

