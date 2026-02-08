import App

def LoadPlacements(TGObject = None, pEvent = None):
	# Position "Enterprise Start"
	kThis = App.Waypoint_Create("Enterprise Start", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(0.000000, -11.879730, 1.094367)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.000000, 1.000000, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Enterprise Start"

	# Position "Attacker 3 Start"
	kThis = App.Waypoint_Create("Attacker 3 Start", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(0.683567, 401.914978, -0.139217)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.212504, -0.972746, -0.092775)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.214970, -0.139156, 0.966656)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 3 Start"

	# Position "Attacker 1 Start"
	kThis = App.Waypoint_Create("Attacker 1 Start", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-30.660204, 528.578796, -12.930603)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.027235, -0.994866, -0.097467)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000869, -0.097527, 0.995233)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 1 Start"

	# Position "Attacker 2 Start"
	kThis = App.Waypoint_Create("Attacker 2 Start", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(42.856041, 511.744934, 0.325140)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.112251, -0.993149, -0.032477)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.279786, -0.062950, 0.957996)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Attacker 2 Start"

	# Position "Galor2 Return"
	kThis = App.Waypoint_Create("Galor2 Return", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(310.276245, 319.433044, 19.648497)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.989803, 0.121080, -0.075028)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.074362, 0.010014, 0.997181)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Return"

	# Position "Galor2 Return End"
	kThis = App.Waypoint_Create("Galor2 Return End", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-23.212973, 339.514679, 3.759209)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.996980, -0.074791, -0.020916)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.019562, -0.018794, 0.999632)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Return End"

	# Position "Akira Start"
	kThis = App.Waypoint_Create("Akira Start", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(136.805984, -802.028381, 103.239349)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.381868, 0.918817, -0.099761)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.005291, 0.105766, 0.994377)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Akira Start"

	# Position "Keldon Way1"
	kThis = App.Waypoint_Create("Keldon Way1", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-13.883398, 246.573242, -1.063836)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.077716, -0.996904, -0.011944)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.035006, -0.009244, 0.999344)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon Way1"

	# Position "Galor1 Way1"
	kThis = App.Waypoint_Create("Galor1 Way1", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-95.507584, 257.918579, -2.582456)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.297486, -0.954666, -0.010707)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.056825, -0.028900, 0.997966)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1 Way1"

	# Position "Placement 101"
	kThis = App.Waypoint_Create("Placement 101", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(2.781593, 49.312607, 0.262953)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.112186, -0.993546, 0.016752)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.530342, 0.074123, 0.844537)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 101"

	# Position "Placement 105"
	kThis = App.Waypoint_Create("Placement 105", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(74.723473, -159.393127, 27.709007)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.389722, -0.907760, 0.155204)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.689492, 0.399329, 0.604266)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 105"

	# Position "Placement 100"
	kThis = App.Waypoint_Create("Placement 100", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(73.642426, -380.806000, 75.448875)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.593842, -0.797143, 0.109153)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.277362, 0.330170, 0.902252)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 100"

	# Position "Placement 106"
	kThis = App.Waypoint_Create("Placement 106", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-122.841957, -373.091797, 75.391472)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.940884, 0.333577, -0.058848)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.023952, 0.238818, 0.970769)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 106"

	# Position "Placement 107"
	kThis = App.Waypoint_Create("Placement 107", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-144.019958, -276.092041, 62.104752)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.365066, 0.912007, -0.187004)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.078098, 0.170159, 0.982317)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 107"

	# Position "Nebula Start"
	kThis = App.Waypoint_Create("Nebula Start", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-50.693661, -182.781647, 102.378326)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.803609, 0.591219, -0.068358)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.038691, 0.062718, 0.997281)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nebula Start"

	# Position "Nebula Way1"
	kThis = App.Waypoint_Create("Nebula Way1", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-141.648849, -107.774872, 94.191910)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.766277, 0.637842, -0.077309)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.062796, 0.045399, 0.996993)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Nebula Way1"

	# Position "Placement 108"
	kThis = App.Waypoint_Create("Placement 108", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-305.331635, 14.007007, 64.895546)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.821189, 0.474628, -0.316822)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.241964, 0.213211, 0.946570)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 108"

	# Position "Placement 109"
	kThis = App.Waypoint_Create("Placement 109", "Starbase 12", None)
	kThis.SetStatic(0)
	kThis.SetTranslateXYZ(-498.622467, 59.774311, 46.263531)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.988323, -0.032882, 0.148781)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.152205, -0.258598, 0.953919)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 109"

	# Attaching object "Galor2 Return End" after "Galor2 Return"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Galor2 Return") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Galor2 Return End") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 101" after "Keldon Way1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Keldon Way1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 101") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 105" after "Placement 101"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 101") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 105") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 100" after "Placement 105"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 105") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 100") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 106" after "Placement 100"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 100") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 106") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 107" after "Placement 106"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 106") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 107") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 108" after "Nebula Way1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Nebula Way1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 108") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 109" after "Placement 108"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 108") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName("Starbase 12", "Placement 109") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None

	if TGObject:
		TGObject.CallNextHandler(pEvent)
