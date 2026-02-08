import App

def LoadPlacements(sSetName):
	# Position "Player At Starbase Start"
	kThis = App.Waypoint_Create("Player At Starbase Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-23.316389, 104.337196, 16.489988)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.709532, -0.704187, 0.026186)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.030394, 0.006544, 0.999517)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player At Starbase Start"

	# Position "Icarus Start"
	kThis = App.Waypoint_Create("Icarus Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-32.125381, 110.564919, 16.633854)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.718817, 0.694774, -0.024309)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.026460, 0.007600, 0.999621)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Icarus Start"

	# Position "Ambassador Start"
	kThis = App.Waypoint_Create("Ambassador Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-36.426445, 118.173058, 17.325975)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.882397, 0.470025, 0.021281)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.010759, -0.025062, 0.999628)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Ambassador Start"

	# Position "Akira Start"
	kThis = App.Waypoint_Create("Akira Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-15.815783, 100.082222, 16.639843)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.480894, -0.870034, 0.108543)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.059553, 0.091099, 0.994060)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Akira Start"

	# Position "Circling Nebula"
	kThis = App.Waypoint_Create("Circling Nebula", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-34.326130, -23.886063, 5.916601)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.867540, 0.488582, 0.093068)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.054535, -0.092549, 0.994214)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Circling Nebula"

	# Position "SB Camera"
	kThis = App.Waypoint_Create("SB Camera", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-47.325821, 58.830151, 12.064000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.071786, 0.996578, 0.040978)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.001473, -0.040978, 0.999159)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "SB Camera"

	# Position "EnterpriseCam1"
	kThis = App.Waypoint_Create("EnterpriseCam1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-18.429922, 115.567734, 19.249645)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.465470, -0.866097, -0.182246)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.118410, -0.143122, 0.982596)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "EnterpriseCam1"

	# Position "EnterpriseWatch1"
	kThis = App.Waypoint_Create("EnterpriseWatch1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-21.706825, 109.470451, 17.966639)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.465469, -0.866098, -0.182245)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.118407, -0.143123, 0.982596)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "EnterpriseWatch1"

	# Position "InsideDoors"
	kThis = App.Waypoint_Create("InsideDoors", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-47.529747, 80.230972, 17.014555)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.709532, -0.704186, 0.026186)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.030397, 0.006541, 0.999517)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "InsideDoors"

	# Position "CircleStarbase1"
	kThis = App.Waypoint_Create("CircleStarbase1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-50.516788, -388.640106, 116.893326)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.726774, 0.630129, -0.273380)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.060014, 0.338229, 0.939148)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(10.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase1"

	# Position "CircleStarbase2"
	kThis = App.Waypoint_Create("CircleStarbase2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-108.391647, -333.676117, 94.416573)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.617788, 0.733146, -0.284315)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.116622, 0.272142, 0.955164)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(10.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase2"

	# Position "CircleStarbase3"
	kThis = App.Waypoint_Create("CircleStarbase3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-169.497528, -262.937195, 66.826721)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.043804, 0.974235, -0.221239)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.048529, 0.223265, 0.973549)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(10.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase3"

	# Position "CircleStarbase4"
	kThis = App.Waypoint_Create("CircleStarbase4", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-173.131302, -178.074310, 49.230553)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.333561, 0.926046, -0.176566)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.167712, 0.126015, 0.977749)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(10.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase4"

	# Position "CircleStarbase4.5"
	kThis = App.Waypoint_Create("CircleStarbase4.5", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-117.465317, -46.229053, 30.545195)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.371146, 0.924638, -0.085410)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.049917, 0.071980, 0.996156)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(10.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase4.5"

	# Position "CircleStarbase5"
	kThis = App.Waypoint_Create("CircleStarbase5", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-64.402550, 63.108292, 17.756887)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.673985, 0.738663, 0.011021)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.004527, -0.010788, 0.999932)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase5"

	# Position "CircleStarbase6"
	kThis = App.Waypoint_Create("CircleStarbase6", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-28.921066, 99.320900, 15.120052)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.702650, 0.708596, 0.064616)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.050440, -0.040979, 0.997886)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase6"

	# Position "CircleStarbase7"
	kThis = App.Waypoint_Create("CircleStarbase7", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-24.894094, 113.615822, 18.466860)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.055142, -0.948867, -0.310823)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.021528, -0.310094, 0.950462)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase7"

	# Position "CircleStarbase8"
	kThis = App.Waypoint_Create("CircleStarbase8", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-22.552088, 104.551285, 17.295918)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.724751, -0.678620, -0.119208)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.062924, -0.107101, 0.992255)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "CircleStarbase8"

	# Position "Geronimo Start"
	kThis = App.Waypoint_Create("Geronimo Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-76.475578, 55.883705, 19.004251)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.685330, -0.718210, -0.120402)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.196536, 0.023212, 0.980222)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Geronimo Start"

	# Position "PlayerAIStart"
	kThis = App.Waypoint_Create("PlayerAIStart", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-33.892509, 94.249763, 16.755100)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.693374, -0.720578, 0.000000)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.000000, 0.000000, 1.000000)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "PlayerAIStart"

	# Attaching object "CircleStarbase2" after "CircleStarbase1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase2") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CircleStarbase3" after "CircleStarbase2"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase2") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase3") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CircleStarbase4" after "CircleStarbase3"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase3") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase4") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CircleStarbase4.5" after "CircleStarbase4"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase4") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase4.5") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CircleStarbase5" after "CircleStarbase4.5"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase4.5") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase5") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CircleStarbase6" after "CircleStarbase5"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase5") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase6") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CircleStarbase7" after "CircleStarbase6"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase6") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase7") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "CircleStarbase8" after "CircleStarbase7"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase7") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "CircleStarbase8") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
