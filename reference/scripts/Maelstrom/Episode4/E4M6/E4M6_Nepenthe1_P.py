import App

def LoadPlacements(sSetName):
	# Position "Player Start"
	kThis = App.Waypoint_Create("Player Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(115.703224, -320.128387, 4.634823)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.563385, 0.825911, 0.021640)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.117800, 0.054375, 0.991548)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Start"

	# Position "PathToCenter1"
	kThis = App.Waypoint_Create("PathToCenter1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(35.156334, -250.370163, 3.835229)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.819816, 0.572606, 0.004957)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.075174, 0.099038, 0.992240)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.000000)
	kThis.Update(0)
	kThis = None
	# End position "PathToCenter1"

	# Position "PathToCenter2"
	kThis = App.Waypoint_Create("PathToCenter2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(14.896800, -241.524323, -3.099698)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.819816, 0.572606, 0.004957)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.075174, 0.099038, 0.992240)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(0.000000)
	kThis.Update(0)
	kThis = None
	# End position "PathToCenter2"

	# Position "PathToCenter3"
	kThis = App.Waypoint_Create("PathToCenter3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(76.620338, -281.785156, 5.476120)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.820100, 0.572172, -0.007373)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.024143, 0.047473, 0.998581)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(4.000000)
	kThis.Update(0)
	kThis = None
	# End position "PathToCenter3"

	# Position "Freighter5 Start"
	kThis = App.Waypoint_Create("Freighter5 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-269.746857, 412.079742, -14.647771)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.886200, -0.290379, 0.361013)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.458417, -0.662447, 0.592467)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter5 Start"

	# Position "Freighter6 Start"
	kThis = App.Waypoint_Create("Freighter6 Start", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-283.242157, 421.480896, -14.577806)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.886200, -0.290379, 0.361013)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.458417, -0.662447, 0.592467)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Freighter6 Start"

	# Position "KessokAmbassador"
	kThis = App.Waypoint_Create("KessokAmbassador", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-172.753891, -11.524694, -36.604080)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.648564, -0.732147, 0.208147)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.222330, 0.079314, 0.971740)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "KessokAmbassador"

	# Position "Keldon1StopWarp"
	kThis = App.Waypoint_Create("Keldon1StopWarp", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-57.591255, -130.820389, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.999047, 0.042773, -0.008698)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.008057, 0.015133, 0.999853)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon1StopWarp"

	# Position "Galor2StopWarp"
	kThis = App.Waypoint_Create("Galor2StopWarp", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-74.415199, -112.650536, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.980158, 0.197734, -0.013846)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.026885, 0.201823, 0.979053)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2StopWarp"

	# Position "Galor1StopWarp"
	kThis = App.Waypoint_Create("Galor1StopWarp", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-74.415199, -139.568832, 0.000000)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.997194, 0.070570, -0.024990)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.016696, 0.115768, 0.993136)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1StopWarp"

	# Position "Keldon1 Warp"
	kThis = App.Waypoint_Create("Keldon1 Warp", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-232.201477, 58.176460, -69.749626)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.677720, -0.689667, 0.255060)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.256781, 0.103059, 0.960959)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Keldon1 Warp"

	# Position "Galor2 Warp"
	kThis = App.Waypoint_Create("Galor2 Warp", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-260.537262, 32.766132, -168.207336)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.686866, -0.537850, 0.488807)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.562879, 0.031787, 0.825928)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2 Warp"

	# Position "Galor1 Warp"
	kThis = App.Waypoint_Create("Galor1 Warp", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-370.547363, -123.909584, 6.858429)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.997973, -0.063385, 0.005771)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.006336, -0.008708, 0.999942)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1 Warp"

	# Position "Galor1FarLoop"
	kThis = App.Waypoint_Create("Galor1FarLoop", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-12.164483, -163.928299, 14.517506)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.750743, -0.619108, 0.230414)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.579021, 0.784614, 0.221622)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1FarLoop"

	# Position "Galor1Stop"
	kThis = App.Waypoint_Create("Galor1Stop", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-55.540909, -204.267807, -8.006806)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.612725, -0.781621, -0.116775)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.452307, -0.467997, 0.759208)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor1Stop"

	# Position "Galor2FarLoop"
	kThis = App.Waypoint_Create("Galor2FarLoop", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(49.512047, -93.376045, 19.764658)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.990027, 0.087375, 0.110506)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.140620, 0.660151, 0.737853)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2FarLoop"

	# Position "Galor2Stop"
	kThis = App.Waypoint_Create("Galor2Stop", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(72.139862, -164.500824, 17.932112)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.415206, -0.909692, 0.008003)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.397273, -0.173397, 0.901170)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Galor2Stop"

	# Position "Placement 1"
	kThis = App.Waypoint_Create("Placement 1", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-318.897003, -26.365654, 4.950252)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.872384, -0.488631, 0.013655)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017618, -0.003512, 0.999839)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 1"

	# Position "Placement 2"
	kThis = App.Waypoint_Create("Placement 2", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-293.548859, -47.898453, 5.321259)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.872384, -0.488631, 0.013655)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017618, -0.003512, 0.999839)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 2"

	# Position "Placement 3"
	kThis = App.Waypoint_Create("Placement 3", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-261.929108, -4.654782, 6.030324)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.872384, -0.488631, 0.013655)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017617, -0.003512, 0.999839)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(5.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 3"

	# Position "Placement 4"
	kThis = App.Waypoint_Create("Placement 4", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-310.961029, 14.006432, 5.231918)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.872384, -0.488631, 0.013655)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017617, -0.003511, 0.999839)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 4"

	# Position "Placement 5"
	kThis = App.Waypoint_Create("Placement 5", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-274.446381, -13.780845, 5.777711)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.872384, -0.488631, 0.013655)
	kUp = App.TGPoint3()
	kUp.SetXYZ(-0.017617, -0.003511, 0.999839)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(1.000000)
	kThis.Update(0)
	kThis = None
	# End position "Placement 5"

	# Position "Center of Asteroid Field"
	kThis = App.Waypoint_Create("Center of Asteroid Field", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-31.683466, -207.976181, 4.585726)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.820099, 0.572174, -0.007373)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.024140, 0.047468, 0.998581)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(9.000000)
	kThis.Update(0)
	kThis = None
	# End position "Center of Asteroid Field"

	# Position "Player Run"
	kThis = App.Waypoint_Create("Player Run", sSetName, None)
	kThis.SetStatic(0)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(-14.311193, -280.845123, 7.354759)
	kForward = App.TGPoint3()
	kForward.SetXYZ(0.316304, -0.909140, -0.270954)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.537933, -0.063372, 0.840602)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Player Run"
	
	# Position "Exit Asteroid Field"
	kThis = App.Waypoint_Create("Exit Asteroid Field", sSetName, None)
	kThis.SetStatic(1)
	kThis.SetNavPoint(0)
	kThis.SetTranslateXYZ(115.703224, -320.128387, 4.634823)
	kForward = App.TGPoint3()
	kForward.SetXYZ(-0.563385, 0.825911, 0.021641)
	kUp = App.TGPoint3()
	kUp.SetXYZ(0.117797, 0.054373, 0.991548)
	kThis.AlignToVectors(kForward, kUp)
	kThis.SetSpeed(25.000000)
	kThis.Update(0)
	kThis = None
	# End position "Exit Asteroid Field"

	# Attaching object "Galor2FarLoop" after "Galor2StopWarp"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor2StopWarp") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor2FarLoop") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 1" after "Galor1StopWarp"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor1StopWarp") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 1") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Keldon1StopWarp" after "Keldon1 Warp"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Keldon1 Warp") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Keldon1StopWarp") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Galor2StopWarp" after "Galor2 Warp"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor2 Warp") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor2StopWarp") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Galor1StopWarp" after "Galor1 Warp"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor1 Warp") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor1StopWarp") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Galor1Stop" after "Galor1FarLoop"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor1FarLoop") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor1Stop") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 4" after "Galor1Stop"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor1Stop") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 4") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Galor2Stop" after "Galor2FarLoop"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor2FarLoop") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor2Stop") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Placement 3" after "Placement 1"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 1") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 3") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
	# Attaching object "Galor1FarLoop" after "Placement 3"...
	kThis = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Placement 3") )
	kPrevious = App.Waypoint_Cast( App.PlacementObject_GetObjectBySetName(sSetName, "Galor1FarLoop") )
	kThis.InsertAfterObj( kPrevious )
	kThis = kPrevious = None
